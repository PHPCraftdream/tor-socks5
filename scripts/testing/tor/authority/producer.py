"""Private numeric-only relay producer for the isolated Tor CI operation."""

import base64
import binascii
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock


LIMIT = 1048576
REJECTION = b"descriptor(s) or extrainfo(s) not valid UTF-8 or had BOM."
ROLES = ("guard", "middle", "exit")


class ProducerError(RuntimeError):
    pass


def require(condition, label):
    if not condition:
        raise ProducerError(label)


def field(data, pattern):
    values = re.findall(pattern, data, re.MULTILINE)
    require(len(values) == 1, "producer-field")
    return values[0]


def encoded(data):
    return base64.b64encode(data).rstrip(b"=")


def decode(value, size):
    require(isinstance(value, bytes), "producer-base64")
    try:
        result = base64.b64decode(
            value + b"=" * (-len(value) % 4), validate=True
        )
    except (ValueError, binascii.Error):
        raise ProducerError("producer-base64") from None
    require(
        len(result) == size and encoded(result) == value,
        "producer-base64",
    )
    return result


def rows(data, micro=False):
    result = {}
    current = None
    for line in data.splitlines():
        if line.startswith(b"r "):
            parts = line.split()
            require(len(parts) == (8 if micro else 9), "producer-router")
            identity = decode(parts[2], 20).hex().upper()
            require(identity not in result, "producer-duplicate-router")
            offset = -1 if micro else 0
            current = {
                "name": parts[1],
                "address": parts[6 + offset],
                "or": parts[7 + offset],
                "dir": parts[8 + offset],
                "digest": None if micro else decode(parts[3], 20),
                "flags": None,
                "md": None,
                "bandwidth": None,
                "protocols": None,
            }
            result[identity] = current
        elif line.startswith(b"directory-footer"):
            current = None
        elif current is not None:
            if line.startswith(b"s "):
                require(current["flags"] is None, "producer-flags")
                flags = line.split()[1:]
                require(len(flags) == len(set(flags)), "producer-flags")
                current["flags"] = set(flags)
            elif line.startswith(b"m "):
                require(micro and current["md"] is None, "producer-md-line")
                parts = line.split()
                require(len(parts) == 2, "producer-md-line")
                current["md"] = decode(parts[1], 32)
            elif line.startswith(b"w "):
                require(
                    current["bandwidth"] is None, "producer-bandwidth"
                )
                value = field(
                    line, rb"(?:^w | )Bandwidth=([0-9]+)(?: |$)"
                )
                current["bandwidth"] = int(value)
            elif line.startswith(b"pr "):
                require(
                    current["protocols"] is None, "producer-protocols"
                )
                current["protocols"] = line[3:]
    require(len(result) <= 3, "producer-router-limit")
    return result


def check_row(row, node, role, micro, allow_initial_zero=False):
    require(
        row["name"] == node.name.encode("ascii")
        and row["address"] == b"127.0.0.1"
        and row["or"] == str(node.or_port).encode("ascii")
        and row["dir"] == str(node.dir_port).encode("ascii"),
        "producer-router-binding",
    )
    flags = row["flags"]
    require(
        flags is not None
        and {b"Running", b"Valid", b"Fast"} <= flags
        and not {b"BadExit", b"MiddleOnly", b"StaleDesc", b"Sybil"} & flags,
        "producer-router-eligibility",
    )
    require(
        (b"Guard" in flags) == (role == "guard")
        and (b"Exit" in flags) == (role == "exit"),
        "producer-role-binding",
    )
    require(
        type(row["bandwidth"]) is int and row["bandwidth"] >= 0,
        "producer-missing-bandwidth",
    )
    require(
        allow_initial_zero or row["bandwidth"] > 0,
        "producer-zero-bandwidth",
    )
    protocols = row["protocols"]
    require(
        protocols is not None
        and re.search(rb"(?:^| )Link=[0-9,-]+(?: |$)", protocols)
        and re.search(rb"(?:^| )Relay=[0-9,-]+(?: |$)", protocols),
        "producer-router-protocols",
    )
    require(not micro or row["md"] is not None, "producer-missing-md")


def descriptor(body, node, role, port):
    require(
        0 < len(body) <= LIMIT and body.startswith(b"router "),
        "producer-descriptor",
    )
    header = field(body, rb"^router ([^\n]+)$").split()
    require(
        header == [
            node.name.encode("ascii"), b"127.0.0.1",
            str(node.or_port).encode("ascii"), b"0",
            str(node.dir_port).encode("ascii"),
        ],
        "producer-descriptor-router",
    )
    fingerprint = field(
        body, rb"^fingerprint ([0-9A-F ]+)$"
    ).replace(b" ", b"")
    require(
        fingerprint == node.relay.fingerprint.encode("ascii"),
        "producer-descriptor-identity",
    )
    require(
        not re.search(
            rb"^(?:family|family-cert|family-ids|a) ", body, re.MULTILINE
        ),
        "producer-descriptor-family",
    )
    policies = [
        line for line in body.splitlines()
        if line.startswith(
            (b"accept ", b"reject ", b"accept6 ", b"reject6 ")
        )
    ]
    expected = (
        [b"accept *:" + str(port).encode("ascii"), b"reject *:*"]
        if role == "exit" else [b"reject *:*"]
    )
    require(policies == expected, "producer-port-only-policy")
    require(
        re.findall(rb"^ipv6-policy (.+)$", body, re.MULTILINE)
        in ([], [b"reject 1-65535"]),
        "producer-ipv6-policy",
    )
    marker = b"\nrouter-signature\n"
    require(body.count(marker) == 1, "producer-descriptor-signature")
    signed = body[:body.index(marker) + len(marker)]
    require(
        re.search(
            rb"\nrouter-signature\n-----BEGIN SIGNATURE-----\n"
            rb"[A-Za-z0-9+/=\n]+-----END SIGNATURE-----\n*\Z",
            body,
        ) is not None,
        "producer-descriptor-signature",
    )
    ed = field(body, rb"^master-key-ed25519 (\S+)$")
    ntor = field(body, rb"^ntor-onion-key (\S+)$")
    decode(ed, 32)
    decode(ntor, 32)
    return hashlib.sha1(signed).digest(), ed, ntor


def microdescriptor(body, digest, ed, ntor, role, port):
    require(
        0 < len(body) <= LIMIT
        and body.startswith(b"onion-key\n")
        and hashlib.sha256(body).digest() == digest,
        "producer-microdescriptor-digest",
    )
    require(
        field(body, rb"^id ed25519 (\S+)$") == ed
        and field(body, rb"^ntor-onion-key (\S+)$") == ntor,
        "producer-microdescriptor-keys",
    )
    require(
        not re.search(
            rb"^(?:family|family-ids|a) ", body, re.MULTILINE
        ),
        "producer-microdescriptor-family",
    )
    require(
        re.findall(rb"^p (.+)$", body, re.MULTILINE)
        == (
            [b"accept " + str(port).encode("ascii")]
            if role == "exit" else []
        ),
        "producer-microdescriptor-policy",
    )
    require(
        re.findall(rb"^p6 (.+)$", body, re.MULTILINE)
        in ([], [b"reject 1-65535"]),
        "producer-microdescriptor-ipv6",
    )


def implementation(c):
    class Node(c.VotingNode):
        def _write_config(self, data, control, cookie_path, config_path):
            super()._write_config(data, control, cookie_path, config_path)
            require(
                self.peers is not None and len(self.peers) == 3
                and all(
                    getattr(peer, "target_port", None) == self.target_port
                    for peer in self.peers
                ),
                "producer-topology",
            )
            resolver = Path(data) / "producer-resolv.conf"
            c.a._private_file(resolver, b"nameserver 127.0.0.1\n")
            text = self.config_path.read_text(encoding="utf-8")
            require(
                text.count("ExitRelay 0\n") == 1,
                "producer-baseline-config",
            )
            if self.role == "exit":
                text = text.replace("ExitRelay 0\n", "ExitRelay 1\n", 1)
                text += (
                    "ExitPolicy accept *4:" + str(self.target_port) + "\n"
                    "ExitPolicy reject *:*\n"
                )
            text += (
                "IPv6Exit 0\n"
                "ExitPolicyRejectPrivate 0\n"
                "ExitPolicyRejectLocalInterfaces 0\n"
                "ServerDNSResolvConfFile "
                + self._quote(str(resolver)) + "\n"
                "ServerDNSDetectHijacking 0\n"
                "ServerDNSAllowBrokenConfig 0\n"
                "TestingDirAuthVoteGuard $"
                + self.peers[0].relay.fingerprint + "\n"
                "TestingDirAuthVoteGuardIsStrict 1\n"
                "TestingDirAuthVoteExit $"
                + self.peers[2].relay.fingerprint + "\n"
                "TestingDirAuthVoteExitIsStrict 1\n"
                "TestingMinFastFlagThreshold 0 bytes\n"
                "TestingMinTimeToReportBandwidth 0 seconds\n"
            )
            self.config_path.write_text(text, encoding="utf-8")
            self._config_bytes = self.config_path.read_bytes()
            self._check()

        def artifact(self, path):
            require(
                re.fullmatch(
                    rb"/tor/(?:status-vote/current/consensus-microdesc"
                    rb"|server/(?:fp|d)/[0-9A-F]{40}"
                    rb"|micro/d/[A-Za-z0-9+/]{43})",
                    path,
                ) is not None,
                "producer-request-path",
            )
            return self._exchange(path)

        def reject_bom(self, body):
            require(
                body.startswith(b"router ") and len(body) <= LIMIT - 3,
                "producer-negative-input",
            )
            status, response = self._exchange(
                b"/tor/", b"\xef\xbb\xbf" + body
            )
            require(
                status == 400 and response == b""
                and self._last_reason == REJECTION,
                "producer-specific-admission-negative",
            )

    class Network(c.Network):
        node_type = Node

        def __init__(self, binary, gencert, deadline):
            super().__init__(binary, gencert, deadline)
            self.target = None
            self.target_port = None
            self.packet = None
            self.admission_checked = False

        def start(self):
            require(
                self.target is None and not self.closed
                and not self.materials,
                "producer-single-use",
            )
            self.check()
            self.target = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM
            )
            self.reservations.append(self.target)
            self.target.bind(("127.0.0.1", 0))
            self.target.listen(1)
            self.target_port = self.target.getsockname()[1]
            network = self

            class PreparedNode(Node):
                def __init__(
                    self, binary, deadline, relay, materials, index
                ):
                    super().__init__(
                        binary, deadline, relay, materials, index
                    )
                    self.role = ROLES[index]
                    self.target_port = network.target_port

            self.node_type = PreparedNode
            super().start()
            self.target_binding()

        def target_binding(self):
            self.check()
            require(
                self.target is not None and self.target.fileno() >= 0
                and self.target.getsockname()
                == ("127.0.0.1", self.target_port)
                and self.target.getsockopt(
                    socket.SOL_SOCKET, socket.SO_ACCEPTCONN
                ) == 1,
                "producer-target-listener",
            )

        def prove(self, inspect_initial=False):
            require(
                self.baseline is not None and self.metadata is not None,
                "producer-good-baseline",
            )
            self.stage = "producer"
            self.target_binding()
            c.require_window(c.next_round(self.metadata), time.time())
            require(
                all(
                    node.config_path.read_bytes() == node._config_bytes
                    for node in self.nodes
                ),
                "producer-config-changed",
            )
            require(
                c.consensus_metadata(
                    self.baseline, self.nodes, time.time()
                ) == self.metadata,
                "producer-ns-metadata",
            )
            expected = {
                node.relay.fingerprint for node in self.nodes
            }
            require(len(expected) == 3, "producer-distinct-identities")
            ns = rows(self.baseline)
            require(set(ns) == expected, "producer-ns-membership")
            md_bodies = []
            normalized_bodies = []
            for node in self.nodes:
                node._identity_and_listeners()
                status, current = node.request(
                    b"/tor/status-vote/current/consensus"
                )
                require(
                    status == 200 and current == self.baseline
                    and node.cached() == self.baseline,
                    "producer-ns-baseline",
                )
                status, body = node.artifact(
                    b"/tor/status-vote/current/consensus-microdesc"
                )
                require(status == 200, "producer-md-consensus")
                require(
                    c.bounded_file(
                        node.data / "cached-microdesc-consensus"
                    ) == body,
                    "producer-md-cache",
                )
                require(
                    body.startswith(
                        b"network-status-version 3 microdesc\n"
                    ),
                    "producer-md-flavor",
                )
                normalized = body.replace(
                    b"network-status-version 3 microdesc\n",
                    b"network-status-version 3\n", 1,
                )
                normalized = re.sub(
                    rb"(?m)^directory-signature sha256 ",
                    b"directory-signature ", normalized,
                )
                metadata = c.consensus_metadata(
                    normalized, self.nodes, time.time()
                )
                require(
                    metadata[:3] == self.metadata[:3],
                    "producer-md-period",
                )
                md_bodies.append(body)
                normalized_bodies.append(normalized)
            require(
                len({
                    c.signed_part(body)
                    for body in normalized_bodies
                }) == 1,
                "producer-md-disagreement",
            )
            md = rows(md_bodies[0], micro=True)
            require(set(md) == expected, "producer-md-membership")
            retained = []
            for index, node in enumerate(self.nodes):
                self.check()
                role = ROLES[index]
                identity = node.relay.fingerprint
                check_row(
                    ns[identity], node, role, False,
                    allow_initial_zero=inspect_initial,
                )
                check_row(
                    md[identity], node, role, True,
                    allow_initial_zero=inspect_initial,
                )
                require(
                    ns[identity]["flags"] == md[identity]["flags"],
                    "producer-flavor-flags",
                )
                path = (
                    b"/tor/server/d/"
                    + ns[identity]["digest"].hex().upper().encode("ascii")
                )
                served = []
                for receiver in self.nodes:
                    status, body = receiver.artifact(path)
                    require(
                        status == 200,
                        "producer-admitted-descriptor",
                    )
                    served.append(body)
                require(
                    len(set(served)) == 1,
                    "producer-descriptor-disagreement",
                )
                body = served[0]
                digest, ed, ntor = descriptor(
                    body, node, role, self.target_port
                )
                require(
                    digest == ns[identity]["digest"],
                    "producer-descriptor-digest",
                )
                status, owned = node.artifact(
                    b"/tor/server/fp/" + identity.encode("ascii")
                )
                require(status == 200, "producer-owned-http")
                owned_digest, owned_ed, _owned_ntor = descriptor(
                    owned, node, role, self.target_port
                )
                written_identity = c.bounded_file(
                    node.data / "fingerprint-ed25519"
                )
                require(
                    written_identity
                    == node.name.encode("ascii") + b" " + ed + b"\n"
                    and written_identity
                    == node.name.encode("ascii") + b" " + owned_ed + b"\n",
                    "producer-owned-ed25519",
                )
                owned = owned.rstrip(b"\n") + b"\n"
                status, _response = node._exchange(b"/tor/", owned)
                require(status == 200, "producer-owned-admission")
                owned_path = (
                    b"/tor/server/d/"
                    + owned_digest.hex().upper().encode("ascii")
                )
                require(
                    node.artifact(owned_path) == (200, owned),
                    "producer-owned-admitted",
                )
                md_path = (
                    b"/tor/micro/d/" + encoded(md[identity]["md"])
                )
                micro_bodies = []
                for receiver in self.nodes:
                    status, micro_body = receiver.artifact(md_path)
                    require(
                        status == 200,
                        "producer-served-microdescriptor",
                    )
                    microdescriptor(
                        micro_body, md[identity]["md"], ed, ntor,
                        role, self.target_port,
                    )
                    micro_bodies.append(micro_body)
                require(
                    len(set(micro_bodies)) == 1,
                    "producer-microdescriptor-disagreement",
                )
                node._identity_and_listeners()
                retained.append(
                    (path, body, md_path, micro_bodies[0])
                )
            self.target_binding()
            c.require_window(c.next_round(self.metadata), time.time())
            require(
                all(
                    ns[node.relay.fingerprint]["bandwidth"] > 0
                    and md[node.relay.fingerprint]["bandwidth"] > 0
                    for node in self.nodes
                ),
                "producer-zero-bandwidth",
            )
            self.packet = tuple(retained)
            return "owned-three-relay-producer"

        def inspect_advanced_cache(self, body, now):
            period = c.stamp(body, b"valid-after")
            require(
                period == c.next_round(self.metadata),
                "producer-readiness-unexpected-period",
            )
            c.consensus_metadata(body, self.nodes, max(now, period))
            footer = b"directory-footer\n"
            require(
                body.count(footer) == 1,
                "producer-readiness-framing",
            )
            unsigned, signatures = body.split(footer, 1)
            require(
                b"\ndirectory-signature " not in unsigned
                and b"\nbandwidth-weights " not in unsigned,
                "producer-readiness-framing",
            )
            if signatures.startswith(b"bandwidth-weights "):
                weights, separator, signatures = signatures.partition(b"\n")
                require(bool(separator), "producer-readiness-framing")
                keys = (
                    b"Wbd", b"Wbe", b"Wbg", b"Wbm", b"Wdb",
                    b"Web", b"Wed", b"Wee", b"Weg", b"Wem",
                    b"Wgb", b"Wgd", b"Wgg", b"Wgm",
                    b"Wmb", b"Wmd", b"Wme", b"Wmg", b"Wmm",
                )
                fields = weights.split(b" ")
                require(
                    len(fields) == len(keys) + 1
                    and fields[0] == b"bandwidth-weights",
                    "producer-readiness-framing",
                )
                for key, item in zip(keys, fields[1:]):
                    name, equals, value = item.partition(b"=")
                    require(
                        name == key and equals == b"="
                        and re.fullmatch(
                            rb"(?:0|-?[1-9][0-9]{0,9})", value
                        ) is not None,
                        "producer-readiness-framing",
                    )
                    require(
                        -2147483648 <= int(value) <= 2147483647,
                        "producer-readiness-framing",
                    )
            pattern = (
                rb"directory-signature [0-9A-F]{40} [0-9A-F]{40}\n"
                rb"-----BEGIN SIGNATURE-----\n"
                rb"((?:[A-Za-z0-9+/=]+\n)+)"
                rb"-----END SIGNATURE-----\n"
            )
            blocks = list(re.finditer(pattern, signatures))
            require(
                len(blocks) >= 2
                and b"".join(match[0] for match in blocks) == signatures,
                "producer-readiness-framing",
            )
            for match in blocks:
                value = match[1].replace(b"\n", b"")
                require(
                    0 < len(value) <= 1368,
                    "producer-readiness-framing",
                )
                try:
                    decoded = base64.b64decode(value, validate=True)
                except (ValueError, binascii.Error):
                    raise ProducerError(
                        "producer-readiness-framing"
                    ) from None
                require(
                    0 < len(decoded) <= 1024
                    and base64.b64encode(decoded) == value,
                    "producer-readiness-framing",
                )
            entries = rows(body)
            expected = {node.relay.fingerprint for node in self.nodes}
            require(
                len(expected) == 3 and set(entries) == expected,
                "producer-ns-membership",
            )
            for index, node in enumerate(self.nodes):
                check_row(
                    entries[node.relay.fingerprint],
                    node, ROLES[index], False,
                    allow_initial_zero=True,
                )
            return period

        def await_ready(self):
            require(self.packet is None, "producer-readiness-single-use")
            while True:
                self.check()
                require(
                    self.metadata is not None and self.baseline is not None,
                    "producer-good-baseline",
                )
                negative_period = c.next_round(self.metadata)
                require(
                    time.monotonic()
                    + max(0.0, negative_period - time.time())
                    < self.deadline,
                    "producer-readiness-budget",
                )
                try:
                    result = self.prove(inspect_initial=True)
                except ProducerError as error:
                    if (
                        type(error) is not ProducerError
                        or error.args != ("producer-zero-bandwidth",)
                    ):
                        raise
                else:
                    return result
                previous_period = self.metadata[0]
                previous = self.baseline
                self.stage = "producer-readiness"
                while True:
                    self.check()
                    cached = [node.cached() for node in self.nodes]
                    require(
                        all(body is not None for body in cached),
                        "producer-readiness-cache-missing",
                    )
                    periods = [
                        c.stamp(body, b"valid-after") for body in cached
                    ]
                    require(
                        all(period >= previous_period for period in periods),
                        "producer-readiness-regression",
                    )
                    now = time.time()
                    for body, period in zip(cached, periods):
                        if period == previous_period:
                            require(
                                body == previous,
                                "producer-readiness-same-period",
                            )
                        else:
                            self.inspect_advanced_cache(body, now)
                    if all(period > previous_period for period in periods):
                        require(
                            len(set(periods)) == 1,
                            "producer-readiness-disagreement",
                        )
                        if periods[0] > now:
                            self.pause()
                            continue
                        require(
                            c.Network.positive(self)
                            == "three-authority-consensus",
                            "producer-consensus-not-executed",
                        )
                        require(
                            self.metadata[0] > previous_period,
                            "producer-readiness-not-advanced",
                        )
                        break
                    self.pause()

        def producer_negative(self):
            require(
                self.packet is not None,
                "producer-good-baseline",
            )
            self.stage = "producer-negative"
            c.require_window(c.next_round(self.metadata), time.time())
            for node in self.nodes:
                node.reject_bom(self.packet[2][1])
                for path, body, md_path, micro_body in self.packet:
                    require(
                        node.artifact(path) == (200, body),
                        "producer-negative-descriptor-changed",
                    )
                    require(
                        node.artifact(md_path) == (200, micro_body),
                        "producer-negative-md-changed",
                    )
                require(
                    node.request(
                        b"/tor/status-vote/current/consensus"
                    ) == (200, self.baseline)
                    and node.cached() == self.baseline,
                    "producer-negative-consensus-changed",
                )
            self.target_binding()
            c.require_window(c.next_round(self.metadata), time.time())
            self.admission_checked = True
            return "bom-descriptor-admission-rejected"

    return Network


def run_live(network, c):
    with network:
        network.start()
        require(
            network.positive() == "three-authority-consensus",
            "producer-consensus-not-executed",
        )
        require(
            network.await_ready() == "owned-three-relay-producer"
            and network.packet is not None,
            "producer-positive-not-executed",
        )
        require(
            network.producer_negative()
            == "bom-descriptor-admission-rejected"
            and network.admission_checked,
            "producer-negative-not-executed",
        )
        require(
            network.negative() == "one-of-three-vote-quorum-rejected",
            "producer-quorum-not-executed",
        )
        witnesses = network.witnesses()
        target = network.target
    c.released(witnesses)
    require(
        target is not None and target.fileno() == -1,
        "producer-target-unreleased",
    )


def load_copy():
    path = Path(__file__).with_name("consensus.py")
    spec = importlib.util.spec_from_file_location(
        "producer_isolated_consensus", path
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def controls(c):
    Network = implementation(c)
    Node = Network.node_type

    class Wire:
        def __init__(self, response, receive=None):
            self.response = bytearray(response)
            self.sent = bytearray()
            self.closed = False
            self.endpoint = None
            self.receive = receive

        def settimeout(self, value):
            require(0 < value <= 0.05, "mechanism-socket-budget")

        def connect(self, endpoint):
            self.endpoint = endpoint

        def getpeername(self):
            return self.endpoint

        def send(self, payload):
            count = min(3, len(payload))
            self.sent.extend(payload[:count])
            return count

        def recv(self, count):
            if self.receive is not None:
                return self.receive(count)
            result = bytes(self.response[:min(count, 2)])
            del self.response[:len(result)]
            return result

        def close(self):
            self.closed = True

        def fileno(self):
            return -1 if self.closed else 1

    class Controls(unittest.TestCase):
        def node(self, index=0, module=c, node_class=Node):
            deadline = time.monotonic() + 60
            relay = SimpleNamespace(
                deadline=deadline,
                fingerprint="%040X" % (index + 1),
            )
            material = SimpleNamespace(
                deadline=deadline,
                metadata={
                    "v3_identity_fingerprint": "%040X" % (index + 101)
                },
            )
            node = node_class(
                "/fixture/tor", deadline, relay, material, index
            )
            node.or_port = 21001 + index * 2
            node.dir_port = 21002 + index * 2
            return node

        def body(self, node, role="exit", port=23456, key=7):
            ed = encoded(bytes([key]) * 32)
            ntor = encoded(bytes([key + 1]) * 32)
            policy = (
                b"accept *:" + str(port).encode("ascii")
                + b"\nreject *:*\n"
                if role == "exit" else b"reject *:*\n"
            )
            return (
                b"router " + node.name.encode("ascii")
                + b" 127.0.0.1 "
                + str(node.or_port).encode("ascii") + b" 0 "
                + str(node.dir_port).encode("ascii") + b"\n"
                b"fingerprint "
                + node.relay.fingerprint.encode("ascii") + b"\n"
                b"master-key-ed25519 " + ed + b"\n"
                b"ntor-onion-key " + ntor + b"\n"
                + policy
                + b"router-signature\n-----BEGIN SIGNATURE-----\n"
                b"bWVjaGFuaXNtLW9ubHk=\n-----END SIGNATURE-----\n"
            )

        def md(self, role="exit", port=23456, key=7):
            return (
                b"onion-key\nntor-onion-key "
                + encoded(bytes([key + 1]) * 32) + b"\n"
                b"id ed25519 " + encoded(bytes([key]) * 32) + b"\n"
                + (
                    b"p accept " + str(port).encode("ascii") + b"\n"
                    if role == "exit" else b""
                )
            )

        def process(self):
            process = mock.Mock(returncode=None)
            process.poll.side_effect = lambda: process.returncode
            process.terminate.side_effect = lambda: setattr(
                process, "returncode", -15
            )
            process.wait.side_effect = lambda **kwargs: process.returncode
            return process

        @contextmanager
        def fixture(self, operation_seconds=60):
            network = Network(
                "/fixture/tor", "/fixture/gencert",
                time.monotonic() + operation_seconds,
            )
            state = {
                "documents": {}, "overrides": {},
                "status": 400, "reason": REJECTION,
                "posts": [], "after_post": None,
                "ns_digests": {}, "md_digests": {},
                "md_flavor": b"microdesc",
                "md_period": 86400,
            }
            try:
                network.target = socket.socket(
                    socket.AF_INET, socket.SOCK_STREAM
                )
                network.reservations.append(network.target)
                network.target.bind(("127.0.0.1", 0))
                network.target.listen(1)
                network.target_port = network.target.getsockname()[1]
                for index in range(3):
                    node = self.node(index)
                    node.deadline = network.deadline
                    node.relay.deadline = network.deadline
                    node.materials.deadline = network.deadline
                    network.nodes.append(node)
                    node._temp = tempfile.TemporaryDirectory(
                        prefix="producer-central-"
                    )
                    node.data = Path(node._temp.name)
                    node._log = tempfile.TemporaryFile()
                    node.process = self.process()
                    node.config_path = node.data / "torrc"
                    node._config_bytes = b"mechanism-only-config\n"
                    node.config_path.write_bytes(node._config_bytes)
                    node._identity_and_listeners = mock.Mock(
                        return_value=("127.0.0.1", node.dir_port)
                    )
                    network.active.append(node)
                state["descriptors"] = [
                    self.body(
                        node, ROLES[index], network.target_port,
                        key=7 + index * 2,
                    )
                    for index, node in enumerate(network.nodes)
                ]
                state["microdescriptors"] = [
                    self.md(
                        ROLES[index], network.target_port,
                        key=7 + index * 2,
                    )
                    for index in range(3)
                ]

                def date(value):
                    return datetime.fromtimestamp(
                        value, timezone.utc
                    ).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ).encode("ascii")

                def document(micro):
                    period = state["md_period"] if micro else 86400
                    flavor = (
                        b" " + state["md_flavor"] if micro else b""
                    )
                    body = (
                        b"network-status-version 3" + flavor + b"\n"
                        b"vote-status consensus\nvalid-after "
                        + date(period) + b"\nfresh-until "
                        + date(period + 300) + b"\nvalid-until "
                        + date(period + 900) + b"\nvoting-delay 20 20\n"
                    )
                    for index, node in enumerate(network.nodes):
                        body += (
                            b"dir-source " + node.name.encode("ascii")
                            + b" " + node.identity.encode("ascii")
                            + b" 127.0.0.1 127.0.0.1 "
                            + str(node.dir_port).encode("ascii")
                            + b" " + str(node.or_port).encode("ascii")
                            + b"\nvote-digest "
                            + ("%040X" % (index + 1)).encode("ascii")
                            + b"\n"
                        )
                    for index, node in enumerate(network.nodes):
                        identity = encoded(bytes.fromhex(
                            node.relay.fingerprint
                        ))
                        digest = state["ns_digests"].get(
                            index,
                            descriptor(
                                state["descriptors"][index], node,
                                ROLES[index], network.target_port,
                            )[0],
                        )
                        md_digest = state["md_digests"].get(
                            index,
                            hashlib.sha256(
                                state["microdescriptors"][index]
                            ).digest(),
                        )
                        body += (
                            b"r " + node.name.encode("ascii")
                            + b" " + identity
                            + (b"" if micro else b" " + encoded(digest))
                            + b" " + date(86400)
                            + b" 127.0.0.1 "
                            + str(node.or_port).encode("ascii")
                            + b" " + str(node.dir_port).encode("ascii")
                            + b"\n"
                        )
                        if micro:
                            body += b"m " + encoded(md_digest) + b"\n"
                        body += (
                            b"s Fast Running Valid"
                            + (
                                b" Guard" if index == 0
                                else b" Exit" if index == 2 else b""
                            )
                            + b"\npr Link=1-5 Relay=1-4\n"
                            b"w Bandwidth=100\n"
                        )
                    body += b"directory-footer\n"
                    for node in network.nodes[:2]:
                        body += (
                            b"directory-signature "
                            + (b"sha256 " if micro else b"")
                            + node.identity.encode("ascii")
                            + b" " + b"F" * 40 + b"\n"
                            b"-----BEGIN SIGNATURE-----\n"
                            b"bWVjaGFuaXNtLW9ubHk=\n"
                            b"-----END SIGNATURE-----\n"
                        )
                    return body

                def rebuild():
                    network.baseline = document(False)
                    network.metadata = c.consensus_metadata(
                        network.baseline, network.nodes, 86401
                    )
                    md_consensus = document(True)
                    documents = {
                        b"/tor/status-vote/current/consensus":
                            network.baseline,
                        b"/tor/status-vote/current/consensus-microdesc":
                            md_consensus,
                    }
                    for index, node in enumerate(network.nodes):
                        desc = state["descriptors"][index]
                        actual = descriptor(
                            desc, node, ROLES[index],
                            network.target_port,
                        )[0]
                        selected = state["ns_digests"].get(index, actual)
                        documents[
                            b"/tor/server/d/"
                            + selected.hex().upper().encode("ascii")
                        ] = desc
                        documents[
                            b"/tor/server/fp/"
                            + node.relay.fingerprint.encode("ascii")
                        ] = desc
                        md_body = state["microdescriptors"][index]
                        selected_md = state["md_digests"].get(
                            index, hashlib.sha256(md_body).digest()
                        )
                        documents[
                            b"/tor/micro/d/" + encoded(selected_md)
                        ] = md_body
                        (node.data / "cached-consensus").write_bytes(
                            network.baseline
                        )
                        (
                            node.data / "cached-microdesc-consensus"
                        ).write_bytes(md_consensus)
                        ed = field(
                            desc, rb"^master-key-ed25519 (\S+)$"
                        )
                        (
                            node.data / "fingerprint-ed25519"
                        ).write_bytes(
                            node.name.encode("ascii") + b" " + ed + b"\n"
                        )
                    state["documents"] = documents

                state["rebuild"] = rebuild
                rebuild()

                def exchange(node, index, path, payload=None):
                    if payload is not None:
                        self.assertEqual(path, b"/tor/")
                        if payload.startswith(b"\xef\xbb\xbf"):
                            self.assertEqual(
                                payload,
                                b"\xef\xbb\xbf" + network.packet[2][1],
                            )
                            state["posts"].append(index)
                            node._last_reason = state["reason"]
                            if state["after_post"] is not None:
                                state["after_post"](index)
                            return state["status"], b""
                        latest_path = (
                            b"/tor/server/fp/"
                            + node.relay.fingerprint.encode("ascii")
                        )
                        latest = state["documents"][latest_path]
                        trailer = b"\n-----END SIGNATURE-----"
                        prefix, separator, suffix = latest.partition(trailer)
                        self.assertTrue(separator)
                        self.assertTrue(suffix)
                        self.assertEqual(suffix.replace(b"\n", b""), b"")
                        canonical = prefix + separator + b"\n"
                        self.assertIn(payload, (latest, canonical))
                        state.setdefault("generation_posts", []).append(index)
                        status = state.get("generation_status", 200)
                        rejected_ntor = state.get("rejected_generation_ntor")
                        if rejected_ntor is not None:
                            submitted_ntor = re.findall(
                                rb"^ntor-onion-key (\S+)$",
                                payload,
                                re.MULTILINE,
                            )
                            self.assertEqual(len(submitted_ntor), 1)
                            if submitted_ntor[0] == rejected_ntor:
                                status = 400
                        state.setdefault("generation_submissions", []).append((
                            index,
                            node.relay.fingerprint,
                            payload,
                            status,
                        ))
                        node._last_reason = (
                            b"Descriptor accepted" if status == 200
                            else b"Mechanism admission rejected"
                        )
                        if status == 200:
                            marker = b"\nrouter-signature\n"
                            self.assertEqual(payload.count(marker), 1)
                            signed = payload[
                                :payload.index(marker) + len(marker)
                            ]
                            digest = hashlib.sha1(signed).hexdigest().upper()
                            if state.get("generation_cache", True):
                                state["documents"][
                                    b"/tor/server/d/" + digest.encode("ascii")
                                ] = canonical
                        return status, b""
                    override = state["overrides"].get((index, path))
                    if override is not None:
                        return override
                    body = state["documents"].get(path)
                    return (404, b"") if body is None else (200, body)

                for index, node in enumerate(network.nodes):
                    node._exchange = mock.Mock(
                        side_effect=lambda path, payload=None,
                        owner=node, position=index: exchange(
                            owner, position, path, payload
                        )
                    )
                with mock.patch.object(time, "time", return_value=86401):
                    yield network, state
            finally:
                network.close()

        def test_descriptor_good_and_owned_identity(self):
            node = self.node()
            body = self.body(node)
            descriptor(body, node, "exit", 23456)
            changed = SimpleNamespace(
                name=node.name, or_port=node.or_port,
                dir_port=node.dir_port,
                relay=SimpleNamespace(fingerprint="F" * 40),
            )
            with self.assertRaisesRegex(
                ProducerError, "^producer-descriptor-identity$"
            ):
                descriptor(body, changed, "exit", 23456)

        def test_descriptor_router_endpoint_binding(self):
            node = self.node()
            body = self.body(node)
            for old, new in (
                (b"127.0.0.1", b"127.0.0.2"),
                (b"21001", b"21009"),
            ):
                with self.subTest(category="endpoint"):
                    with self.assertRaisesRegex(
                        ProducerError, "^producer-descriptor-router$"
                    ):
                        descriptor(
                            body.replace(old, new), node, "exit", 23456
                        )

        def test_port_only_policy_rejects_host_only_and_extra_ports(self):
            node = self.node()
            body = self.body(node)
            for changed in (
                body.replace(
                    b"accept *:23456", b"accept 127.0.0.1:23456"
                ),
                body.replace(
                    b"accept *:23456", b"accept *:23456-23457"
                ),
                body.replace(b"reject *:*", b"accept *:*"),
                body.replace(b"accept *:23456\n", b""),
            ):
                with self.assertRaisesRegex(
                    ProducerError, "^producer-port-only-policy$"
                ):
                    descriptor(changed, node, "exit", 23456)

        def test_nonexit_rejects_exit_permission(self):
            node = self.node()
            descriptor(
                self.body(node, "middle"), node, "middle", 23456
            )
            with self.assertRaisesRegex(
                ProducerError, "^producer-port-only-policy$"
            ):
                descriptor(self.body(node), node, "middle", 23456)

        def test_family_and_ipv6_are_rejected(self):
            node = self.node()
            body = self.body(node)
            for extra, label in (
                (b"family $AAAA\n", "producer-descriptor-family"),
                (
                    b"ipv6-policy accept 23456\n",
                    "producer-ipv6-policy",
                ),
            ):
                with self.assertRaisesRegex(
                    ProducerError, "^" + label + "$"
                ):
                    descriptor(body + extra, node, "exit", 23456)

        def test_microdescriptor_good_and_digest_mutation(self):
            body = self.md()
            digest = hashlib.sha256(body).digest()
            ed = encoded(bytes([7]) * 32)
            ntor = encoded(bytes([8]) * 32)
            microdescriptor(body, digest, ed, ntor, "exit", 23456)
            with self.assertRaisesRegex(
                ProducerError, "^producer-microdescriptor-digest$"
            ):
                microdescriptor(
                    body + b"\n", digest, ed, ntor, "exit", 23456
                )

        def test_microdescriptor_key_binding(self):
            body = self.md()
            digest = hashlib.sha256(body).digest()
            ed = encoded(bytes([7]) * 32)
            ntor = encoded(bytes([8]) * 32)
            for expected_ed, expected_ntor in (
                (ntor, ntor), (ed, ed),
            ):
                with self.assertRaisesRegex(
                    ProducerError, "^producer-microdescriptor-keys$"
                ):
                    microdescriptor(
                        body, digest, expected_ed, expected_ntor,
                        "exit", 23456,
                    )

        def test_forced_exit_reject_all_is_not_usable(self):
            body = self.md("middle")
            with self.assertRaisesRegex(
                ProducerError, "^producer-microdescriptor-policy$"
            ):
                microdescriptor(
                    body, hashlib.sha256(body).digest(),
                    encoded(bytes([7]) * 32),
                    encoded(bytes([8]) * 32), "exit", 23456,
                )

        def test_role_and_bandwidth_mutants(self):
            node = self.node()
            good = {
                "name": b"localA", "address": b"127.0.0.1",
                "or": b"21001", "dir": b"21002",
                "flags": {b"Running", b"Valid", b"Fast", b"Guard"},
                "bandwidth": 1,
                "protocols": b"Link=1-5 Relay=1-4",
                "md": bytes([1]) * 32,
            }
            check_row(good, node, "guard", True)
            for key, value in (
                ("flags", {b"Running", b"Valid", b"Guard"}),
                ("flags", good["flags"] | {b"Exit"}),
                ("flags", good["flags"] | {b"BadExit"}),
                ("bandwidth", 0),
                ("md", None),
            ):
                changed = dict(good)
                changed[key] = value
                with self.assertRaises(ProducerError):
                    check_row(changed, node, "guard", True)

        def test_rows_duplicate_and_flavor_binding(self):
            line = (
                b"r localA " + encoded(bytes(20)) + b" "
                + encoded(bytes([1]) * 20)
                + b" 2026-01-01 00:00:00 127.0.0.1 21001 21002\n"
            )
            self.assertEqual(len(rows(line)), 1)
            with self.assertRaisesRegex(
                ProducerError, "^producer-duplicate-router$"
            ):
                rows(line + line)
            with self.assertRaisesRegex(
                ProducerError, "^producer-router$"
            ):
                rows(line, micro=True)

        def test_target_owned_before_actual_generation_cancel(self):
            isolated = load_copy()
            network = implementation(isolated)(
                "/fixture/tor", "/fixture/gencert",
                time.monotonic() + 60,
            )
            process = self.process()
            witness = {}

            def launch(argv, **kwargs):
                owner = network.materials[0]
                witness["root"] = Path(owner._temp.name)
                witness["stream"] = owner._input
                witness["target"] = network.target
                self.assertIn(
                    network.target, network.reservations
                )
                self.assertTrue(witness["root"].is_dir())
                self.assertFalse(witness["stream"].closed)
                self.assertEqual(owner.deadline, network.deadline)
                return process

            def wait(*, timeout):
                self.assertGreaterEqual(timeout, 0)
                if process.returncode is None:
                    isolated.a.m.cancelled = True
                    isolated.a.s.cancelled = True
                    raise subprocess.TimeoutExpired(
                        "mechanism-only", timeout
                    )
                return process.returncode

            process.wait.side_effect = wait
            try:
                with mock.patch.object(
                    isolated.a.m.subprocess, "Popen",
                    side_effect=launch,
                ):
                    with self.assertRaises(isolated.a.m.Cancelled):
                        with network:
                            network.start()
                self.assertTrue(isolated.a.m.cancelled)
                self.assertTrue(isolated.a.s.cancelled)
                self.assertTrue(network.closed)
                self.assertEqual(witness["target"].fileno(), -1)
                self.assertFalse(witness["root"].exists())
                self.assertTrue(witness["stream"].closed)
                self.assertEqual(process.returncode, -15)
            finally:
                if not network.closed:
                    process.returncode = -15
                    network.close()

        def test_target_unreaped_owner_retains_resources(self):
            network = Network(
                "/fixture/tor", "/fixture/gencert",
                time.monotonic() + 60,
            )
            target = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM
            )
            network.target = target
            network.reservations.append(target)
            target.bind(("127.0.0.1", 0))
            target.listen(1)
            process = mock.Mock(returncode=None)
            process.poll.return_value = None
            process.wait.side_effect = subprocess.TimeoutExpired(
                "mechanism-only", 0
            )
            owner = SimpleNamespace(
                process=process, close=mock.Mock(),
                _socket=None, _http=None,
            )
            network.nodes.append(owner)
            try:
                with self.assertRaises(c.a.s.CleanupError):
                    network.close()
                self.assertGreaterEqual(target.fileno(), 0)
                owner.close.assert_not_called()
                self.assertFalse(network.closed)
            finally:
                process.returncode = -9
                process.poll.return_value = -9
                process.wait.side_effect = None
                process.wait.return_value = -9
                network.close()
                self.assertEqual(target.fileno(), -1)

        def test_actual_configuration_keeps_generated_bindings(self):
            network = Network(
                "/fixture/tor", "/fixture/gencert",
                time.monotonic() + 60,
            )
            with tempfile.TemporaryDirectory(
                prefix="producer-config-"
            ) as root_name:
                root = Path(root_name)
                candidates = []
                try:
                    for index in range(3):
                        relay_root = root / ("relay" + str(index))
                        (relay_root / "keys").mkdir(parents=True)
                        (
                            relay_root / "keys" / "secret_id_key"
                        ).write_bytes(b"mechanism-relay")
                        material_root = root / (
                            "material" + str(index)
                        )
                        material_root.mkdir()
                        for name, body in (
                            (
                                "authority_certificate",
                                b"mechanism-certificate\n",
                            ),
                            (
                                "authority_signing_key",
                                b"mechanism-online",
                            ),
                            (
                                "authority_identity_key",
                                b"mechanism-offline",
                            ),
                        ):
                            (material_root / name).write_bytes(body)
                        node = self.node(index)
                        node.deadline = network.deadline
                        node.relay.deadline = network.deadline
                        node.materials.deadline = network.deadline
                        node.relay.data = relay_root
                        node.relay._closed = False
                        node.relay.process = SimpleNamespace(
                            returncode=0
                        )
                        node.materials._closed = False
                        node.materials.process = SimpleNamespace(
                            returncode=0
                        )
                        node.materials._check_file = (
                            lambda name, base=material_root: base / name
                        )
                        node.role = ROLES[index]
                        node.target_port = 23456
                        node.candidates = []
                        network.nodes.append(node)
                        for kind in range(2):
                            candidate = socket.socket(
                                socket.AF_INET, socket.SOCK_STREAM
                            )
                            candidates.append(candidate)
                            candidate.bind(("127.0.0.1", 0))
                            node.candidates.append(candidate)
                        node.or_port, node.dir_port = [
                            item.getsockname()[1]
                            for item in node.candidates
                        ]
                    for index, node in enumerate(network.nodes):
                        node.peers = network.nodes
                        data = root / ("online" + str(index))
                        data.mkdir()
                        with mock.patch.object(
                            c.a.m, "certificate_metadata",
                            return_value=node.materials.metadata,
                        ):
                            node._write_config(
                                str(data),
                                str(root / ("control" + str(index))),
                                str(root / ("cookie" + str(index))),
                                str(root / ("torrc" + str(index))),
                            )
                        text = node.config_path.read_text(
                            encoding="utf-8"
                        )
                        self.assertIn(
                            "TestingDirAuthVoteGuard $"
                            + network.nodes[0].relay.fingerprint
                            + "\n", text,
                        )
                        self.assertIn(
                            "TestingDirAuthVoteExit $"
                            + network.nodes[2].relay.fingerprint
                            + "\n", text,
                        )
                        self.assertEqual(
                            text.count("DirAuthority "), 3
                        )
                        self.assertEqual(
                            "ExitRelay 1\n" in text, index == 2
                        )
                        self.assertEqual(
                            "ExitPolicy accept *4:23456\n" in text,
                            index == 2,
                        )
                        self.assertIn("IPv6Exit 0\n", text)
                        self.assertIn(
                            "ServerDNSDetectHijacking 0\n", text
                        )
                        self.assertEqual(
                            (
                                data / "producer-resolv.conf"
                            ).read_bytes(),
                            b"nameserver 127.0.0.1\n",
                        )
                        self.assertFalse(
                            (
                                data / "keys"
                                / "authority_identity_key"
                            ).exists()
                        )
                        self.assertEqual(
                            node._config_bytes,
                            node.config_path.read_bytes(),
                        )
                finally:
                    for node in network.nodes:
                        node.close()
                    for candidate in candidates:
                        candidate.close()

        def test_artifact_allowlist_before_exchange(self):
            owner = SimpleNamespace(
                _exchange=mock.Mock(return_value=(200, b"body"))
            )
            for path in (
                b"/arbitrary",
                b"/tor/server/fp/" + b"A" * 39,
                b"/tor/micro/d/" + b"A" * 44,
                b"/tor/status-vote/current/consensus-microdesc/extra",
            ):
                with self.assertRaisesRegex(
                    ProducerError, "^producer-request-path$"
                ):
                    Node.artifact(owner, path)
            owner._exchange.assert_not_called()
            path = b"/tor/server/fp/" + b"A" * 40
            self.assertEqual(
                Node.artifact(owner, path), (200, b"body")
            )
            owner._exchange.assert_called_once_with(path)

        def test_bom_negative_checks_exact_reason(self):
            owner = SimpleNamespace(
                _last_reason=REJECTION,
                _exchange=mock.Mock(return_value=(400, b"")),
            )
            Node.reject_bom(owner, b"router mechanism-only\n")
            self.assertEqual(
                owner._exchange.call_args,
                mock.call(
                    b"/tor/",
                    b"\xef\xbb\xbfrouter mechanism-only\n",
                ),
            )
            for status, reason in (
                (200, REJECTION), (400, b"Bad request"),
            ):
                owner._last_reason = reason
                owner._exchange.return_value = (status, b"")
                with self.assertRaisesRegex(
                    ProducerError,
                    "^producer-specific-admission-negative$",
                ):
                    Node.reject_bom(
                        owner, b"router mechanism-only\n"
                    )

        def test_central_good_proof_and_admission_negative(self):
            with self.fixture() as (network, state):
                self.assertEqual(
                    network.prove(), "owned-three-relay-producer"
                )
                self.assertEqual(len(network.packet), 3)
                self.assertEqual(
                    network.producer_negative(),
                    "bom-descriptor-admission-rejected",
                )
                self.assertEqual(state["posts"], [0, 1, 2])
                self.assertTrue(network.admission_checked)
                for node in network.nodes:
                    self.assertEqual(
                        node._identity_and_listeners.call_count, 2
                    )

        def test_central_descriptor_and_identity_counterfactuals(self):
            for variant in (
                "missing", "disagreement", "selected-digest",
                "owned-descriptor", "owned-ed", "identity",
                "policy", "role", "bandwidth",
            ):
                with self.subTest(category=variant):
                    with self.fixture() as (network, state):
                        node = network.nodes[0]
                        row = rows(network.baseline)[
                            node.relay.fingerprint
                        ]
                        path = (
                            b"/tor/server/d/"
                            + row["digest"].hex().upper().encode("ascii")
                        )
                        label = None
                        if variant == "missing":
                            state["overrides"][(1, path)] = (404, b"")
                            label = "producer-admitted-descriptor"
                        elif variant == "disagreement":
                            state["overrides"][(1, path)] = (
                                200, state["descriptors"][1]
                            )
                            label = "producer-descriptor-disagreement"
                        elif variant == "selected-digest":
                            state["ns_digests"][0] = bytes([99]) * 20
                            state["rebuild"]()
                            label = "producer-descriptor-digest"
                        elif variant == "owned-descriptor":
                            state["overrides"][(
                                0, b"/tor/server/fp/"
                                + node.relay.fingerprint.encode("ascii")
                            )] = (200, state["descriptors"][1])
                            label = "producer-descriptor-router"
                        elif variant == "owned-ed":
                            (
                                node.data / "fingerprint-ed25519"
                            ).write_bytes(b"changed\n")
                            label = "producer-owned-ed25519"
                        elif variant in ("identity", "policy"):
                            body = state["descriptors"][0]
                            if variant == "identity":
                                body = body.replace(
                                    node.relay.fingerprint.encode("ascii"),
                                    b"F" * 40,
                                )
                                label = "producer-descriptor-identity"
                            else:
                                body = body.replace(
                                    b"reject *:*", b"accept *:*"
                                )
                                label = "producer-port-only-policy"
                            state["documents"][path] = body
                        else:
                            old = (
                                b"s Fast Running Valid Guard"
                                if variant == "role"
                                else b"w Bandwidth=100"
                            )
                            new = (
                                b"s Fast Running Valid Exit"
                                if variant == "role"
                                else b"w Bandwidth=0"
                            )
                            network.baseline = (
                                network.baseline.replace(old, new, 1)
                            )
                            state["documents"][
                                b"/tor/status-vote/current/consensus"
                            ] = network.baseline
                            for receiver in network.nodes:
                                (
                                    receiver.data / "cached-consensus"
                                ).write_bytes(network.baseline)
                            md_path = (
                                b"/tor/status-vote/current/"
                                b"consensus-microdesc"
                            )
                            md = state["documents"][md_path].replace(
                                old, new, 1
                            )
                            state["documents"][md_path] = md
                            for receiver in network.nodes:
                                (
                                    receiver.data
                                    / "cached-microdesc-consensus"
                                ).write_bytes(md)
                            label = (
                                "producer-role-binding"
                                if variant == "role"
                                else "producer-zero-bandwidth"
                            )
                        with self.assertRaisesRegex(
                            ProducerError, "^" + label + "$"
                        ):
                            network.prove()

        def test_central_latest_generation_parser_terminal_framing(self):
            with self.fixture() as (network, state):
                selected = tuple(state["descriptors"])
                selected_md = tuple(state["microdescriptors"])
                expected = []
                for index, node in enumerate(network.nodes):
                    latest_path = (
                        b"/tor/server/fp/"
                        + node.relay.fingerprint.encode("ascii")
                    )
                    canonical = selected[index].replace(
                        b"\nrouter-signature\n",
                        b"\nuptime 2\nrouter-signature\n",
                        1,
                    )
                    generated = canonical + b"\n"
                    self.assertNotEqual(generated, canonical)
                    digest = descriptor(
                        canonical, node, ROLES[index], network.target_port
                    )[0]
                    self.assertEqual(
                        descriptor(
                            generated, node, ROLES[index],
                            network.target_port,
                        )[0],
                        digest,
                    )
                    digest_path = (
                        b"/tor/server/d/"
                        + digest.hex().upper().encode("ascii")
                    )
                    self.assertNotIn(digest_path, state["documents"])
                    state["documents"][latest_path] = generated
                    expected.append((digest_path, canonical))

                self.assertEqual(
                    network.prove(), "owned-three-relay-producer"
                )
                self.assertEqual(state["generation_posts"], [0, 1, 2])
                self.assertEqual(
                    state["generation_submissions"],
                    [
                        (
                            index,
                            node.relay.fingerprint,
                            expected[index][1],
                            200,
                        )
                        for index, node in enumerate(network.nodes)
                    ],
                )
                for index, entry in enumerate(network.packet):
                    self.assertEqual(entry[1], selected[index])
                    self.assertEqual(entry[3], selected_md[index])
                    path, canonical = expected[index]
                    self.assertEqual(state["documents"][path], canonical)
                    self.assertNotEqual(canonical, selected[index])

        def test_central_latest_generation_200_without_retention_fails(self):
            with self.fixture() as (network, state):
                state["generation_cache"] = False
                node = network.nodes[0]
                latest_path = (
                    b"/tor/server/fp/"
                    + node.relay.fingerprint.encode("ascii")
                )
                canonical = state["documents"][latest_path].replace(
                    b"\nrouter-signature\n",
                    b"\nuptime 2\nrouter-signature\n",
                    1,
                )
                state["documents"][latest_path] = canonical + b"\n"
                digest = descriptor(
                    canonical, node, ROLES[0], network.target_port
                )[0]
                digest_path = (
                    b"/tor/server/d/"
                    + digest.hex().upper().encode("ascii")
                )
                self.assertNotIn(digest_path, state["documents"])
                with self.assertRaisesRegex(
                    ProducerError, "^producer-owned-admitted$"
                ):
                    network.prove()
                self.assertIsNone(network.packet)
                self.assertEqual(state["generation_posts"], [0])
                self.assertEqual(
                    state["generation_submissions"],
                    [(0, node.relay.fingerprint, canonical, 200)],
                )
                self.assertNotIn(digest_path, state["documents"])

        def test_central_latest_generation_is_not_selected_generation(self):
            with self.fixture() as (network, state):
                selected = tuple(state["descriptors"])
                selected_md = tuple(state["microdescriptors"])
                selected_paths = []
                latest_paths = []
                latest_bodies = []
                for index, node in enumerate(network.nodes):
                    original = selected[index]
                    marker = b"\nrouter-signature\n"
                    signed_end = original.index(marker) + len(marker)
                    expected_selected = hashlib.sha1(
                        original[:signed_end]
                    ).digest()
                    selected_row = rows(network.baseline)[
                        node.relay.fingerprint
                    ]
                    self.assertEqual(
                        selected_row["digest"], expected_selected
                    )
                    selected_paths.append(
                        b"/tor/server/d/"
                        + expected_selected.hex().upper().encode("ascii")
                    )
                    latest = original.replace(
                        b"\nrouter-signature\n",
                        b"\npublished 1970-01-02 00:00:02\n"
                        b"uptime 2\n"
                        b"bandwidth 1000000 2000000 300000\n"
                        b"router-signature\n",
                        1,
                    )
                    if index == 2:
                        old_ntor = encoded(bytes([12]) * 32)
                        rotated_ntor = encoded(bytes([43]) * 32)
                        self.assertEqual(
                            latest.count(b"ntor-onion-key " + old_ntor + b"\n"),
                            1,
                        )
                        latest = latest.replace(
                            b"ntor-onion-key " + old_ntor + b"\n",
                            b"ntor-onion-key " + rotated_ntor + b"\n",
                            1,
                        )
                        self.assertNotEqual(old_ntor, rotated_ntor)
                    latest_signed_end = (
                        latest.index(marker) + len(marker)
                    )
                    expected_latest = hashlib.sha1(
                        latest[:latest_signed_end]
                    ).digest()
                    self.assertNotEqual(latest, original)
                    self.assertNotEqual(
                        expected_latest, expected_selected
                    )
                    latest_path = (
                        b"/tor/server/fp/"
                        + node.relay.fingerprint.encode("ascii")
                    )
                    state["documents"][latest_path] = latest
                    latest_bodies.append(latest)
                    latest_paths.append((
                        b"/tor/server/d/"
                        + expected_latest.hex().upper().encode("ascii"),
                        latest,
                    ))
                self.assertEqual(
                    network.prove(), "owned-three-relay-producer"
                )
                self.assertEqual(
                    state["generation_posts"], [0, 1, 2]
                )
                self.assertEqual(
                    state["generation_submissions"],
                    [
                        (
                            index,
                            node.relay.fingerprint,
                            latest_bodies[index],
                            200,
                        )
                        for index, node in enumerate(network.nodes)
                    ],
                )
                for index, entry in enumerate(network.packet):
                    self.assertEqual(entry[0], selected_paths[index])
                    self.assertEqual(entry[1], selected[index])
                    self.assertEqual(entry[3], selected_md[index])
                    self.assertEqual(
                        state["documents"][entry[0]], selected[index]
                    )
                    latest_path, latest = latest_paths[index]
                    self.assertEqual(
                        state["documents"][latest_path], latest
                    )
                self.assertEqual(
                    network.producer_negative(),
                    "bom-descriptor-admission-rejected",
                )
                self.assertEqual(state["posts"], [0, 1, 2])

        def test_central_latest_generation_rejects_invalid_witnesses(self):
            cases = (
                ("http", "producer-owned-http"),
                ("owner", "producer-descriptor-identity"),
                ("ed", "producer-owned-ed25519"),
                ("ntor", "producer-owned-admission"),
                ("endpoint", "producer-descriptor-router"),
                ("policy", "producer-port-only-policy"),
                ("algorithm", "producer-field"),
                ("admission", "producer-owned-admission"),
                ("cache", "producer-owned-admitted"),
            )
            for variant, label in cases:
                with self.subTest(category=variant):
                    with self.fixture() as (network, state):
                        node = network.nodes[2]
                        path = (
                            b"/tor/server/fp/"
                            + node.relay.fingerprint.encode("ascii")
                        )
                        body = state["documents"][path]
                        mutated = None
                        if variant == "http":
                            state["overrides"][(2, path)] = (404, b"")
                        elif variant == "owner":
                            state["documents"][path] = body.replace(
                                node.relay.fingerprint.encode("ascii"),
                                b"F" * 40,
                            )
                        elif variant == "ed":
                            state["documents"][path] = body.replace(
                                encoded(bytes([11]) * 32),
                                encoded(bytes([41]) * 32),
                            )
                        elif variant == "ntor":
                            original_ntor = encoded(bytes([12]) * 32)
                            rejected_ntor = encoded(bytes([42]) * 32)
                            original_line = (
                                b"ntor-onion-key " + original_ntor + b"\n"
                            )
                            rejected_line = (
                                b"ntor-onion-key " + rejected_ntor + b"\n"
                            )
                            self.assertEqual(body.count(original_line), 1)
                            mutated = body.replace(
                                original_line, rejected_line, 1
                            )
                            self.assertNotEqual(mutated, body)
                            self.assertEqual(
                                mutated.count(rejected_line), 1
                            )
                            state["documents"][path] = mutated
                            state["rejected_generation_ntor"] = rejected_ntor
                        elif variant == "endpoint":
                            state["documents"][path] = body.replace(
                                b"127.0.0.1", b"127.0.0.2", 1
                            )
                        elif variant == "policy":
                            state["documents"][path] = body.replace(
                                b"reject *:*", b"accept *:*"
                            )
                        elif variant == "algorithm":
                            state["documents"][path] = body.replace(
                                b"master-key-ed25519 ",
                                b"master-key-unsupported ",
                            )
                        elif variant == "admission":
                            state["generation_status"] = 400
                        else:
                            state["generation_cache"] = False
                            state["documents"][path] = body.replace(
                                b"\nrouter-signature\n",
                                b"\nuptime 2\nrouter-signature\n",
                                1,
                            )
                        with self.assertRaisesRegex(
                            ProducerError, "^" + label + "$"
                        ):
                            network.prove()
                        self.assertIsNone(network.packet)
                        if variant == "ntor":
                            self.assertNotIn(
                                "generation_status", state
                            )
                            self.assertEqual(
                                state["generation_posts"], [0, 1, 2]
                            )
                            self.assertEqual(
                                state["generation_submissions"],
                                [
                                    (
                                        0,
                                        network.nodes[0].relay.fingerprint,
                                        state["descriptors"][0],
                                        200,
                                    ),
                                    (
                                        1,
                                        network.nodes[1].relay.fingerprint,
                                        state["descriptors"][1],
                                        200,
                                    ),
                                    (
                                        2,
                                        node.relay.fingerprint,
                                        mutated,
                                        400,
                                    ),
                                ],
                            )
                            selected_path = (
                                b"/tor/server/d/"
                                + rows(network.baseline)[
                                    node.relay.fingerprint
                                ]["digest"].hex().upper().encode("ascii")
                            )
                            self.assertEqual(
                                state["documents"][selected_path],
                                state["descriptors"][2],
                            )

        def test_central_microdescriptor_counterfactuals(self):
            for variant in (
                "selected-digest", "missing", "bytes", "keys",
                "policy", "cache", "flavor", "period",
            ):
                with self.subTest(category=variant):
                    with self.fixture() as (network, state):
                        label = None
                        if variant == "selected-digest":
                            state["md_digests"][2] = bytes([77]) * 32
                            state["rebuild"]()
                            label = "producer-microdescriptor-digest"
                        elif variant in ("keys", "policy"):
                            body = state["microdescriptors"][2]
                            if variant == "keys":
                                body = body.replace(
                                    encoded(bytes([12]) * 32),
                                    encoded(bytes([44]) * 32),
                                )
                                label = "producer-microdescriptor-keys"
                            else:
                                body = re.sub(
                                    rb"(?m)^p accept [0-9]+\n",
                                    b"", body,
                                )
                                label = "producer-microdescriptor-policy"
                            state["microdescriptors"][2] = body
                            state["rebuild"]()
                        elif variant == "cache":
                            (
                                network.nodes[1].data
                                / "cached-microdesc-consensus"
                            ).write_bytes(b"changed\n")
                            label = "producer-md-cache"
                        elif variant == "flavor":
                            state["md_flavor"] = b"ns"
                            state["rebuild"]()
                            label = "producer-md-flavor"
                        elif variant == "period":
                            state["md_period"] = 86401
                            state["rebuild"]()
                            label = "producer-md-period"
                        else:
                            digest = hashlib.sha256(
                                state["microdescriptors"][2]
                            ).digest()
                            path = b"/tor/micro/d/" + encoded(digest)
                            state["overrides"][(1, path)] = (
                                (404, b"") if variant == "missing"
                                else (200, b"changed\n")
                            )
                            label = (
                                "producer-served-microdescriptor"
                                if variant == "missing"
                                else "producer-microdescriptor-digest"
                            )
                        with self.assertRaisesRegex(
                            ProducerError, "^" + label + "$"
                        ):
                            network.prove()

        def test_central_negative_counterfactuals(self):
            for variant in (
                "status", "reason", "descriptor",
                "microdescriptor", "consensus", "cache",
            ):
                with self.subTest(category=variant):
                    with self.fixture() as (network, state):
                        network.prove()
                        label = "producer-specific-admission-negative"
                        if variant == "status":
                            state["status"] = 200
                        elif variant == "reason":
                            state["reason"] = b"Bad request"
                        else:
                            def change(index):
                                if variant == "descriptor":
                                    state["documents"][
                                        network.packet[0][0]
                                    ] = b"changed\n"
                                elif variant == "microdescriptor":
                                    state["documents"][
                                        network.packet[0][2]
                                    ] = b"changed\n"
                                elif variant == "consensus":
                                    state["documents"][
                                        b"/tor/status-vote/current/consensus"
                                    ] = b"changed\n"
                                else:
                                    (
                                        network.nodes[index].data
                                        / "cached-consensus"
                                    ).write_bytes(b"changed\n")
                            state["after_post"] = change
                            label = {
                                "descriptor":
                                    "producer-negative-descriptor-changed",
                                "microdescriptor":
                                    "producer-negative-md-changed",
                                "consensus":
                                    "producer-negative-consensus-changed",
                                "cache":
                                    "producer-negative-consensus-changed",
                            }[variant]
                        with self.assertRaisesRegex(
                            ProducerError, "^" + label + "$"
                        ):
                            network.producer_negative()
                        self.assertFalse(network.admission_checked)

        def test_post_wire_partial_io_and_private_reason(self):
            with self.node() as node:
                wire = Wire(
                    b"HTTP/1.0 400 " + REJECTION
                    + b"\r\nContent-Length: 0\r\n\r\n"
                )
                body = b"router mechanism-only\n"
                payload = b"\xef\xbb\xbf" + body
                with mock.patch.object(
                    node, "_identity_and_listeners",
                    return_value=("127.0.0.1", node.dir_port),
                ):
                    with mock.patch.object(
                        c.socket, "socket", return_value=wire
                    ):
                        node.reject_bom(body)
                self.assertEqual(
                    bytes(wire.sent),
                    b"POST /tor/ HTTP/1.0\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"Accept-Encoding: identity\r\n"
                    b"Connection: close\r\n"
                    b"Content-Length: "
                    + str(len(payload)).encode("ascii")
                    + b"\r\n\r\n" + payload,
                )
                self.assertEqual(node._last_reason, REJECTION)
                self.assertTrue(wire.closed)

        def test_get_wire_allowlist_and_request_bounds(self):
            with self.node() as node:
                wire = Wire(b"HTTP/1.0 200 OK\r\n\r\nbody")
                path = b"/tor/status-vote/current/consensus"
                with mock.patch.object(
                    node, "_identity_and_listeners",
                    return_value=("127.0.0.1", node.dir_port),
                ):
                    with mock.patch.object(
                        c.socket, "socket", return_value=wire
                    ):
                        self.assertEqual(
                            node.request(path), (200, b"body")
                        )
                self.assertEqual(
                    bytes(wire.sent),
                    b"GET " + path + b" HTTP/1.0\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"Accept-Encoding: identity\r\n"
                    b"Connection: close\r\n\r\n",
                )
                self.assertTrue(wire.closed)
                with mock.patch.object(c.socket, "socket") as create:
                    with self.assertRaises(c.ConsensusError):
                        node.request(b"/arbitrary")
                    with self.assertRaises(c.ConsensusError):
                        node._exchange(b"/tor/", b"x" * (LIMIT + 1))
                    with self.assertRaises(ProducerError):
                        node.reject_bom(
                            b"router " + b"x" * (LIMIT - 9)
                        )
                    create.assert_not_called()

        def test_actual_post_cancellation_unwinds_owned_resources(self):
            isolated = load_copy()
            cls = implementation(isolated)
            network = cls(
                "/fixture/tor", "/fixture/gencert",
                time.monotonic() + 60,
            )
            node = self.node(
                module=isolated, node_class=cls.node_type
            )
            node.deadline = network.deadline
            network.nodes.append(node)
            network.active.append(node)
            node._temp = tempfile.TemporaryDirectory(
                prefix="producer-post-cancel-"
            )
            root = Path(node._temp.name)
            node.data = root
            node._log = tempfile.TemporaryFile()
            log = node._log
            control, peer = socket.socketpair()
            node._socket = control
            process = self.process()
            node.process = process
            events = []

            def retained():
                self.assertTrue(root.is_dir())
                self.assertFalse(log.closed)

            def receive(count):
                retained()
                events.append("cancel")
                isolated.a.s.cancelled = True
                raise socket.timeout()

            wire = Wire(b"", receive=receive)

            def terminate():
                retained()
                self.assertEqual(control.fileno(), -1)
                self.assertTrue(wire.closed)
                events.append("term")
                process.returncode = -15

            def wait(*, timeout):
                self.assertGreaterEqual(timeout, 0)
                if node._closed:
                    self.assertFalse(root.exists())
                    self.assertTrue(log.closed)
                else:
                    retained()
                if events[-1] == "term":
                    events.append("reap")
                return process.returncode

            process.terminate.side_effect = terminate
            process.wait.side_effect = wait
            try:
                with mock.patch.object(
                    node, "_identity_and_listeners",
                    return_value=("127.0.0.1", node.dir_port),
                ):
                    with mock.patch.object(
                        isolated.socket, "socket", return_value=wire
                    ):
                        with self.assertRaises(isolated.a.s.Cancelled):
                            with network:
                                node.reject_bom(
                                    b"router mechanism-only\n"
                                )
                self.assertEqual(
                    events, ["cancel", "term", "reap"]
                )
                self.assertTrue(isolated.a.s.cancelled)
                self.assertFalse(root.exists())
                self.assertTrue(log.closed)
                self.assertEqual(control.fileno(), -1)
                self.assertTrue(wire.closed)
            finally:
                peer.close()
                if not network.closed:
                    process.returncode = -15
                    network.close()

        @contextmanager
        def readiness_fixture(self):
            with self.fixture(operation_seconds=600) as (network, state):
                original_ns = network.baseline
                md_path = (
                    b"/tor/status-vote/current/consensus-microdesc"
                )
                original_md = state["documents"][md_path]
                clock = {
                    "wall": 86551.0,
                    "mono": time.monotonic(),
                }
                original_deadline = network.deadline

                def date(value):
                    return datetime.fromtimestamp(
                        value, timezone.utc
                    ).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ).encode("ascii")

                def render(body, period, zero=False, weights=False):
                    values = {
                        b"valid-after": date(period),
                        b"fresh-until": date(period + 300),
                        b"valid-until": date(period + 900),
                    }
                    result = re.sub(
                        rb"(?m)^(valid-after|fresh-until|valid-until) "
                        rb"[^\n]+$",
                        lambda match: (
                            match[1] + b" " + values[match[1]]
                        ),
                        body,
                    )
                    if zero:
                        result = result.replace(
                            b"w Bandwidth=100", b"w Bandwidth=0"
                        )
                    if weights:
                        result = result.replace(
                            b"directory-footer\n",
                            b"directory-footer\n"
                            + state["readiness_weights"],
                            1,
                        )
                    self.assertEqual(
                        c.stamp(result, b"valid-after"), period
                    )
                    self.assertEqual(
                        c.stamp(result, b"fresh-until"), period + 300
                    )
                    self.assertEqual(
                        c.stamp(result, b"valid-until"), period + 900
                    )
                    return result

                state["readiness_weights"] = (
                    b"bandwidth-weights "
                    b"Wbd=0 Wbe=0 Wbg=0 Wbm=10000 Wdb=10000 "
                    b"Web=10000 Wed=0 Wee=10000 Weg=0 Wem=10000 "
                    b"Wgb=10000 Wgd=0 Wgg=10000 Wgm=10000 "
                    b"Wmb=10000 Wmd=0 Wme=0 Wmg=0 Wmm=10000\n"
                )

                def publish(
                    period, zero=False, install_baseline=False,
                    weights=False,
                ):
                    ns = render(original_ns, period, zero, weights)
                    md = render(original_md, period, zero, weights)
                    state["documents"][
                        b"/tor/status-vote/current/consensus"
                    ] = ns
                    state["documents"][md_path] = md
                    entries = c.sources(ns)
                    for index, node in enumerate(network.nodes):
                        (
                            node.data / "cached-consensus"
                        ).write_bytes(ns)
                        (
                            node.data / "cached-microdesc-consensus"
                        ).write_bytes(md)
                        node.certificate = (
                            b"mechanism-certificate-"
                            + str(index).encode("ascii") + b"\n"
                        )
                        vote = (
                            b"network-status-version 3\n"
                            b"vote-status vote\n"
                            b"valid-after " + date(period) + b"\n"
                            + node.certificate
                            + b"dir-source "
                            + node.name.encode("ascii")
                            + b" " + node.identity.encode("ascii")
                            + b" 127.0.0.1 127.0.0.1 "
                            + str(node.dir_port).encode("ascii")
                            + b" " + str(node.or_port).encode("ascii")
                            + b"\ndirectory-signature "
                            + node.identity.encode("ascii")
                            + b" " + b"F" * 40 + b"\n"
                            b"-----BEGIN SIGNATURE-----\n"
                            b"bWVjaGFuaXNtLW9ubHk=\n"
                            b"-----END SIGNATURE-----\n"
                        )
                        state["documents"][
                            b"/tor/status-vote/current/d/"
                            + entries[node.identity][1]
                        ] = vote
                        state["overrides"][(
                            index,
                            b"/tor/status-vote/current/authority",
                        )] = (200, vote)
                    if install_baseline:
                        network.baseline = ns
                        network.metadata = c.consensus_metadata(
                            ns, network.nodes, clock["wall"]
                        )
                    return ns, md

                state["readiness_render"] = render
                state["readiness_publish"] = publish
                state["readiness_clock"] = clock
                state["readiness_deadline"] = original_deadline
                with mock.patch.object(
                    time, "time", side_effect=lambda: clock["wall"]
                ):
                    with mock.patch.object(
                        time, "monotonic",
                        side_effect=lambda: clock["mono"],
                    ):
                        publish(
                            86550, zero=True, install_baseline=True
                        )
                        yield network, state
                        self.assertEqual(
                            network.deadline, original_deadline
                        )

        def test_initial_zero_is_complete_inspection_not_success(self):
            with self.readiness_fixture() as (network, state):
                with self.assertRaisesRegex(
                    ProducerError, "^producer-zero-bandwidth$"
                ):
                    network.prove(inspect_initial=True)
                self.assertIsNone(network.packet)
                self.assertEqual(
                    state["generation_posts"], [0, 1, 2]
                )
                (
                    network.nodes[2].data / "fingerprint-ed25519"
                ).write_bytes(b"changed\n")
                with self.assertRaisesRegex(
                    ProducerError, "^producer-owned-ed25519$"
                ):
                    network.prove(inspect_initial=True)
            with self.readiness_fixture() as (network, state):
                path = b"/tor/status-vote/current/consensus"
                body = state["documents"][path].replace(
                    b"w Bandwidth=0\n", b"", 1
                )
                network.baseline = body
                state["documents"][path] = body
                for node in network.nodes:
                    (
                        node.data / "cached-consensus"
                    ).write_bytes(body)
                with mock.patch.object(network, "pause") as pause:
                    with self.assertRaisesRegex(
                        ProducerError, "^producer-missing-bandwidth$"
                    ):
                        network.await_ready()
                    pause.assert_not_called()
                self.assertIsNone(network.packet)

        def test_readiness_requires_new_verified_generation(self):
            with self.readiness_fixture() as (network, state):
                clock = state["readiness_clock"]
                events = []
                original_positive = c.Network.positive

                def advance():
                    network.check()
                    self.assertEqual(events, [])
                    clock["wall"] += 150
                    clock["mono"] += 150
                    state["readiness_publish"](86700)
                    events.append("published")

                with mock.patch.object(
                    network, "pause", side_effect=advance
                ):
                    with mock.patch.object(
                        c.Network, "positive",
                        autospec=True,
                        side_effect=original_positive,
                    ) as positive:
                        self.assertEqual(
                            network.await_ready(),
                            "owned-three-relay-producer",
                        )
                positive.assert_called_once_with(network)
                self.assertEqual(events, ["published"])
                self.assertEqual(network.metadata[0], 86700)
                self.assertEqual(
                    c.next_round(network.metadata), 87000
                )
                self.assertIsNotNone(network.packet)
                self.assertEqual(
                    network.deadline,
                    state["readiness_deadline"],
                )
                self.assertLess(
                    clock["mono"] + 87000 - clock["wall"],
                    network.deadline,
                )
                self.assertEqual(
                    network.producer_negative(),
                    "bom-descriptor-admission-rejected",
                )

        def test_readiness_cache_failures_are_not_retried(self):
            cases = (
                ("missing", "producer-readiness-cache-missing"),
                ("same-period", "producer-readiness-same-period"),
                ("regression", "producer-readiness-regression"),
                ("disagreement", "producer-readiness-unexpected-period"),
            )
            for variant, label in cases:
                with self.subTest(category=variant):
                    with self.readiness_fixture() as (network, state):
                        events = []

                        def advance():
                            network.check()
                            self.assertEqual(events, [])
                            events.append("changed")
                            render = state["readiness_render"]
                            for index, node in enumerate(network.nodes):
                                path = node.data / "cached-consensus"
                                body = path.read_bytes()
                                if variant == "missing" and index == 0:
                                    path.unlink()
                                elif variant == "same-period" and index == 0:
                                    path.write_bytes(body + b"\n")
                                elif variant == "regression" and index == 0:
                                    path.write_bytes(render(body, 86400))
                                elif variant == "disagreement":
                                    path.write_bytes(render(
                                        body, 86700 + index * 300
                                    ))

                        with mock.patch.object(
                            network, "pause", side_effect=advance
                        ):
                            with self.assertRaisesRegex(
                                ProducerError, "^" + label + "$"
                            ):
                                network.await_ready()
                        self.assertEqual(events, ["changed"])
                        self.assertIsNone(network.packet)

        def test_staggered_future_cache_is_validated_before_waiting(self):
            variants = (
                "validity", "voter", "signature", "router",
                "weight-value", "weight-range", "weight-duplicate",
                "weight-missing", "weight-order", "weight-unknown",
                "weight-line-duplicate", "footer-junk",
            )
            for variant in variants:
                with self.subTest(category=variant):
                    with self.readiness_fixture() as (network, state):
                        old = network.baseline
                        events = []

                        def advance():
                            network.check()
                            self.assertEqual(events, [])
                            events.append("published-one")
                            body = state["readiness_render"](
                                old, 86700, weights=True
                            )
                            weights = state["readiness_weights"]
                            if variant == "validity":
                                body = re.sub(
                                    rb"(?m)^fresh-until [^\n]+$",
                                    b"fresh-until 1970-01-02 00:05:00",
                                    body,
                                )
                            elif variant == "voter":
                                body = body.replace(
                                    network.nodes[1].identity.encode("ascii"),
                                    b"E" * 40,
                                )
                            elif variant == "signature":
                                body = body.replace(
                                    b"-----END SIGNATURE-----",
                                    b"-----END INVALID-----", 1,
                                )
                            elif variant == "router":
                                body = body.replace(
                                    b"pr Link=1-5 Relay=1-4",
                                    b"pr Link=1-5", 1,
                                )
                            elif variant == "weight-value":
                                body = body.replace(
                                    b"Wbd=0", b"Wbd=invalid", 1
                                )
                            elif variant == "weight-range":
                                body = body.replace(
                                    b"Wbd=0", b"Wbd=2147483648", 1
                                )
                            elif variant == "weight-duplicate":
                                body = body.replace(
                                    b"Wbe=0", b"Wbd=0", 1
                                )
                            elif variant == "weight-missing":
                                body = body.replace(b" Wbe=0", b"", 1)
                            elif variant == "weight-order":
                                body = body.replace(
                                    b"Wbd=0 Wbe=0", b"Wbe=0 Wbd=0", 1
                                )
                            elif variant == "weight-unknown":
                                body = body.replace(
                                    b"Wbe=0", b"Wxx=0", 1
                                )
                            elif variant == "weight-line-duplicate":
                                body = body.replace(
                                    weights, weights + weights, 1
                                )
                            else:
                                body = body.replace(
                                    weights, weights + b"unknown-footer 1\n",
                                    1,
                                )
                            (
                                network.nodes[0].data
                                / "cached-consensus"
                            ).write_bytes(body)
                            self.assertEqual(
                                state["readiness_clock"]["wall"], 86551
                            )
                            self.assertTrue(all(
                                node.cached() == old
                                for node in network.nodes[1:]
                            ))

                        with mock.patch.object(
                            network, "pause", side_effect=advance
                        ) as pause:
                            with mock.patch.object(
                                c.Network, "positive"
                            ) as positive:
                                error_type, label = {
                                    "validity": (
                                        c.ConsensusError, "consensus-not-current"
                                    ),
                                    "voter": (
                                        c.ConsensusError, "consensus-voters"
                                    ),
                                    "router": (
                                        ProducerError, "producer-router-protocols"
                                    ),
                                }.get(variant, (
                                    ProducerError, "producer-readiness-framing"
                                ))
                                with self.assertRaisesRegex(
                                    error_type, "^" + label + "$"
                                ):
                                    network.await_ready()
                        self.assertEqual(pause.call_count, 1)
                        positive.assert_not_called()
                        self.assertEqual(events, ["published-one"])
                        self.assertIsNone(network.packet)

        def test_legitimate_staggered_future_generation_progresses(self):
            for weights in (False, True):
                with self.subTest(weights=weights):
                    with self.readiness_fixture() as (network, state):
                        old = network.baseline
                        clock = state["readiness_clock"]
                        events = []
                        original_positive = c.Network.positive

                        def advance():
                            network.check()
                            if not events:
                                (
                                    network.nodes[0].data
                                    / "cached-consensus"
                                ).write_bytes(
                                    state["readiness_render"](
                                        old, 86700, weights=weights
                                    )
                                )
                                events.append("one-future")
                            elif events == ["one-future"]:
                                self.assertEqual(clock["wall"], 86551)
                                self.assertIsNone(network.packet)
                                state["readiness_publish"](
                                    86700, weights=weights
                                )
                                events.append("all-future")
                            elif events == ["one-future", "all-future"]:
                                self.assertIsNone(network.packet)
                                clock["wall"] += 150
                                clock["mono"] += 150
                                events.append("current")
                            else:
                                self.fail("unexpected-readiness-pause")

                        with mock.patch.object(
                            network, "pause", side_effect=advance
                        ):
                            with mock.patch.object(
                                c.Network, "positive",
                                autospec=True,
                                side_effect=original_positive,
                            ) as positive:
                                self.assertEqual(
                                    network.await_ready(),
                                    "owned-three-relay-producer",
                                )
                        self.assertEqual(
                            events,
                            ["one-future", "all-future", "current"],
                        )
                        positive.assert_called_once_with(network)
                        self.assertEqual(network.metadata[0], 86700)
                        self.assertIsNotNone(network.packet)
                        self.assertEqual(
                            network.deadline,
                            state["readiness_deadline"],
                        )

        def test_readiness_hard_error_and_budget_are_not_retried(self):
            with self.readiness_fixture() as (network, state):
                node = network.nodes[0]
                digest = rows(network.baseline)[
                    node.relay.fingerprint
                ]["digest"]
                path = (
                    b"/tor/server/d/"
                    + digest.hex().upper().encode("ascii")
                )
                state["overrides"][(1, path)] = (404, b"")
                with mock.patch.object(network, "pause") as pause:
                    with self.assertRaisesRegex(
                        ProducerError,
                        "^producer-admitted-descriptor$",
                    ):
                        network.await_ready()
                    pause.assert_not_called()
            with self.fixture() as (network, state):
                with mock.patch.object(network, "pause") as pause:
                    with self.assertRaisesRegex(
                        ProducerError, "^producer-readiness-budget$"
                    ):
                        network.await_ready()
                    pause.assert_not_called()
                self.assertIsNone(network.packet)

        def test_unchanged_zero_exhausts_original_deadline(self):
            isolated = load_copy()
            isolated_case = controls(isolated)(
                "test_initial_zero_is_complete_inspection_not_success"
            )
            with isolated_case.readiness_fixture() as (network, state):
                deadline = network.deadline
                clock = state["readiness_clock"]
                start_mono = clock["mono"]
                start_wall = clock["wall"]
                baseline = network.baseline
                roots = [node.data for node in network.nodes]
                streams = [node._log for node in network.nodes]
                processes = [node.process for node in network.nodes]
                target = network.target
                passes = []
                events = []

                def retained():
                    self.assertTrue(all(root.is_dir() for root in roots))
                    self.assertTrue(all(
                        not stream.closed for stream in streams
                    ))
                    self.assertGreaterEqual(target.fileno(), 0)

                for index, process in enumerate(processes):
                    def terminate(p=process, position=index):
                        retained()
                        events.append(("term", position))
                        p.returncode = -15

                    process.terminate.side_effect = terminate

                def advance():
                    retained()
                    self.assertIsNone(network.packet)
                    self.assertEqual(network.deadline, deadline)
                    self.assertTrue(all(
                        node.cached() == baseline
                        for node in network.nodes
                    ))
                    passes.append(len(passes) + 1)
                    self.assertLessEqual(len(passes), 4)
                    elapsed = (
                        deadline - start_mono
                    ) * len(passes) / 4
                    clock["mono"] = (
                        deadline if len(passes) == 4
                        else start_mono + elapsed
                    )
                    clock["wall"] = start_wall + elapsed
                    network.check()

                with mock.patch.object(
                    network, "pause", side_effect=advance
                ):
                    with mock.patch.object(
                        isolated.Network, "positive"
                    ) as positive:
                        with self.assertRaises(
                            isolated.a.s.DeadlineExceeded
                        ):
                            with network:
                                network.await_ready()
                positive.assert_not_called()
                self.assertEqual(passes, [1, 2, 3, 4])
                self.assertEqual(
                    events, [("term", 0), ("term", 1), ("term", 2)]
                )
                self.assertEqual(network.deadline, deadline)
                self.assertIsNone(network.packet)
                self.assertTrue(network.closed)
                self.assertTrue(all(
                    process.returncode == -15 for process in processes
                ))
                self.assertTrue(all(
                    not root.exists() for root in roots
                ))
                self.assertTrue(all(
                    stream.closed for stream in streams
                ))
                self.assertEqual(target.fileno(), -1)
                self.assertFalse(isolated.a.s.cancelled)

        def test_readiness_wait_cancel_and_deadline_release_owners(self):
            for variant in ("cancel", "deadline"):
                with self.subTest(category=variant):
                    isolated = load_copy()
                    isolated_case = controls(isolated)(
                        "test_initial_zero_is_complete_inspection_not_success"
                    )
                    with isolated_case.readiness_fixture() as (
                        network, state
                    ):
                        clock = state["readiness_clock"]
                        roots = [node.data for node in network.nodes]
                        streams = [node._log for node in network.nodes]
                        processes = [node.process for node in network.nodes]
                        target = network.target
                        events = []

                        def retained():
                            self.assertTrue(all(
                                root.is_dir() for root in roots
                            ))
                            self.assertTrue(all(
                                not stream.closed for stream in streams
                            ))
                            self.assertGreaterEqual(target.fileno(), 0)

                        for index, process in enumerate(processes):
                            def terminate(p=process, position=index):
                                retained()
                                events.append(("term", position))
                                p.returncode = -15

                            process.terminate.side_effect = terminate

                        def interrupt():
                            retained()
                            self.assertIsNone(network.packet)
                            events.append(("interrupt", variant))
                            if variant == "cancel":
                                isolated.a.s.cancelled = True
                            else:
                                clock["mono"] = network.deadline
                            network.check()

                        expected = (
                            isolated.a.s.Cancelled
                            if variant == "cancel"
                            else isolated.a.s.DeadlineExceeded
                        )
                        with mock.patch.object(
                            network, "pause", side_effect=interrupt
                        ):
                            with self.assertRaises(expected):
                                with network:
                                    network.await_ready()
                        self.assertEqual(
                            events,
                            [
                                ("interrupt", variant),
                                ("term", 0), ("term", 1), ("term", 2),
                            ],
                        )
                        self.assertTrue(network.closed)
                        self.assertTrue(all(
                            process.returncode == -15
                            for process in processes
                        ))
                        self.assertTrue(all(
                            not root.exists() for root in roots
                        ))
                        self.assertTrue(all(
                            stream.closed for stream in streams
                        ))
                        self.assertEqual(target.fileno(), -1)
                        if variant == "cancel":
                            self.assertTrue(isolated.a.s.cancelled)

        def test_live_sequence_uses_actual_producer_methods(self):
            with self.fixture(operation_seconds=600) as (network, state):
                events = []
                actual_prove = network.await_ready
                actual_negative = network.producer_negative
                network.start = mock.Mock(
                    side_effect=lambda: events.append("start")
                )

                def positive():
                    events.append("consensus")
                    return "three-authority-consensus"

                def prove():
                    events.append("producer")
                    return actual_prove()

                def admission():
                    events.append("admission")
                    return actual_negative()

                def quorum():
                    self.assertIsNotNone(network.packet)
                    self.assertTrue(network.admission_checked)
                    self.assertEqual(state["posts"], [0, 1, 2])
                    self.assertTrue(all(
                        node.process.returncode is None
                        for node in network.nodes
                    ))
                    events.append("quorum")
                    return "one-of-three-vote-quorum-rejected"

                network.positive = mock.Mock(side_effect=positive)
                network.await_ready = mock.Mock(side_effect=prove)
                network.producer_negative = mock.Mock(
                    side_effect=admission
                )
                network.negative = mock.Mock(side_effect=quorum)
                run_live(network, c)
                self.assertEqual(
                    events,
                    ["start", "consensus", "producer",
                     "admission", "quorum"],
                )
                network.start.assert_called_once_with()
                network.await_ready.assert_called_once_with()
                network.producer_negative.assert_called_once_with()
                network.negative.assert_called_once_with()
                self.assertTrue(network.closed)
                self.assertEqual(network.target.fileno(), -1)

    return Controls


def run_controls(c):
    case = controls(c)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(case)
    result = unittest.TextTestRunner(
        stream=io.StringIO()
    ).run(suite)
    allowed = set(unittest.defaultTestLoader.getTestCaseNames(case))
    failures = []
    for category, entries in (
        ("FAIL", result.failures), ("ERROR", result.errors)
    ):
        for test, traceback in entries:
            actual = getattr(test, "test_case", test)
            name = getattr(actual, "_testMethodName", None)
            identity = (
                "ProducerControls." + name
                if type(actual) is case and name in allowed
                else "<unknown-test>"
            )
            failures.append(category + " " + identity)
    return (
        result.testsRun == 35 and result.wasSuccessful(),
        tuple(failures),
    )
