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


def check_row(row, node, role, micro):
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
        row["bandwidth"] is not None and row["bandwidth"] > 0,
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

        def prove(self):
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
                check_row(ns[identity], node, role, False)
                check_row(md[identity], node, role, True)
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
                require(
                    status == 200 and owned == body,
                    "producer-owned-descriptor",
                )
                require(
                    c.bounded_file(
                        node.data / "fingerprint-ed25519"
                    ) == node.name.encode("ascii") + b" " + ed + b"\n",
                    "producer-owned-ed25519",
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
            self.packet = tuple(retained)
            return "owned-three-relay-producer"

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
            network.prove() == "owned-three-relay-producer"
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
        def fixture(self):
            network = Network(
                "/fixture/tor", "/fixture/gencert",
                time.monotonic() + 60,
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
                        self.assertEqual(
                            payload,
                            b"\xef\xbb\xbf" + network.packet[2][1],
                        )
                        state["posts"].append(index)
                        node._last_reason = state["reason"]
                        if state["after_post"] is not None:
                            state["after_post"](index)
                        return state["status"], b""
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
                            label = "producer-owned-descriptor"
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

        def test_live_sequence_uses_actual_producer_methods(self):
            with self.fixture() as (network, state):
                events = []
                actual_prove = network.prove
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
                network.prove = mock.Mock(side_effect=prove)
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
                network.prove.assert_called_once_with()
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
        result.testsRun == 23 and result.wasSuccessful(),
        tuple(failures),
    )
