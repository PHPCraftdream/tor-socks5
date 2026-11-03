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

_stream_path = Path(__file__).with_name("stream.py")
_stream_spec = importlib.util.spec_from_file_location(
    "producer_owned_stream", _stream_path
)
_stream = importlib.util.module_from_spec(_stream_spec)
_stream_spec.loader.exec_module(_stream)
StreamError = _stream.StreamError
STREAM_FAILURE_GATES = _stream.FAILURE_GATES


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
        and row["address"] == node.address.encode("ascii")
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
            node.name.encode("ascii"), node.address.encode("ascii"),
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
        def __init__(self, binary, deadline, relay, materials, index):
            require(
                type(index) is int and 0 <= index < 3,
                "producer-topology",
            )
            super().__init__(binary, deadline, relay, materials, index)
            self._address = (
                "127.0.0.2", "127.0.0.3", "127.0.0.4"
            )[index]

        @property
        def address(self):
            return self._address

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
                "CircuitsAvailableTimeout 60 seconds\n"
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

    return _stream.extend(Network, c)


def run_live(network, c, *, _consumer=None):
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
        if _consumer is not None:
            _consumer(network)
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
    path = Path(__file__).resolve().parent.parent / "consensus.py"
    spec = importlib.util.spec_from_file_location(
        "producer_isolated_consensus", path
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


from importlib.machinery import SourceFileLoader

_suite_loader = SourceFileLoader(
    "producer_control_suites",
    str(Path(__file__).with_name("controls") / "suite.py"),
)
exec(
    _suite_loader.get_code("producer_control_suites"),
    globals(),
)


def run_stream_live(network, c, binary):
    run_live(
        network, c,
        _consumer=lambda owned: owned.consume(binary),
    )
    network.stream.released()
    return network.stream
