import base64
import binascii
import importlib.util
import ipaddress
import os
from pathlib import Path
import re
import sys


TEST = "real_private_stream::owned_three_hop_round_trip"
VERIFIED = b"STREAM_VERIFIED\n"
ACK = b"TARGET_TERMINATED\n"
DONE = b"CONSUMER_DONE\n"

FAILURE_GATES = frozenset("""
stream-single-use stream-isolation stream-binary stream-producer
stream-address stream-identity stream-descriptor stream-frame
stream-child stream-peer stream-owner stream-endpoint stream-write
stream-request stream-target-eof stream-shutdown stream-receipt
stream-control-eof stream-trailing stream-witness stream-status
stream-incomplete stream-resource stream-controls
""".split())


class StreamError(RuntimeError):
    pass


def require(value, gate):
    if not value:
        raise StreamError(gate)


def load(name, path):
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def ownership():
    root = Path(__file__).resolve().parents[5]
    return load(
        "_tor_stream_ownership",
        root / ".github" / "pt_proxy" / "direct_domain.py",
    )


def address(value):
    require(type(value) is str, "stream-address")
    try:
        parsed = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        raise StreamError("stream-address") from None
    require(str(parsed) == value and parsed.is_loopback, "stream-address")
    return value


def capabilities(network, nonce):
    require(
        network.packet is not None and len(network.packet) == 3
        and len(network.nodes) == 3 and network.admission_checked,
        "stream-producer",
    )
    records = [
        b"TOR_OWNED_STREAM_V2",
        f"PARENT {os.getpid()} {os.geteuid()}".encode("ascii"),
    ]
    authorities = set()
    relays = set()
    addresses = set()
    for node, packet in zip(network.nodes, network.packet):
        node._check()
        host = address(node.address)
        addresses.add(host)
        require(
            re.fullmatch(r"[A-Za-z0-9]{1,19}", node.name) is not None
            and re.fullmatch(r"[0-9A-F]{40}", node.identity) is not None
            and node.identity
            == node.materials.metadata["v3_identity_fingerprint"]
            and re.fullmatch(
                r"[0-9A-F]{40}", node.relay.fingerprint
            ) is not None
            and type(node.or_port) is int and 0 < node.or_port < 65536,
            "stream-identity",
        )
        body = packet[1]
        require(type(body) is bytes and len(body) <= 1048576,
                "stream-descriptor")
        router = re.findall(rb"^router ([^\n]+)$", body, re.MULTILINE)
        require(
            router == [(
                f"{node.name} {host} {node.or_port} 0 {node.dir_port}"
            ).encode("ascii")],
            "stream-descriptor",
        )
        rsa = re.findall(
            rb"^fingerprint ([0-9A-F ]+)$", body, re.MULTILINE
        )
        ed = re.findall(
            rb"^master-key-ed25519 ([A-Za-z0-9+/]{43})$",
            body, re.MULTILINE,
        )
        require(
            len(rsa) == 1
            and rsa[0].replace(b" ", b"")
            == node.relay.fingerprint.encode("ascii")
            and len(ed) == 1,
            "stream-descriptor",
        )
        try:
            raw_ed = base64.b64decode(ed[0] + b"=", validate=True)
        except (ValueError, binascii.Error):
            raise StreamError("stream-descriptor") from None
        require(
            len(raw_ed) == 32
            and base64.b64encode(raw_ed).rstrip(b"=") == ed[0],
            "stream-descriptor",
        )
        authorities.add(node.identity)
        relays.add(node.relay.fingerprint)
        records.extend((
            f"AUTH {node.name} {node.identity}".encode("ascii"),
            (
                f"FALLBACK {node.relay.fingerprint} "
                f"{raw_ed.hex()} {host} {node.or_port}"
            ).encode("ascii"),
        ))
    require(
        len(authorities) == 3 and len(relays) == 3
        and authorities.isdisjoint(relays) and len(addresses) == 3,
        "stream-identity",
    )
    target = network.target.getsockname()
    address(target[0])
    require(target == ("127.0.0.1", network.target_port),
            "stream-endpoint")
    require(re.fullmatch(rb"[0-9a-f]{32}", nonce) is not None,
            "stream-frame")
    records.extend((
        f"TARGET {target[0]} {target[1]}".encode("ascii"),
        b"NONCE " + nonce,
        b"END",
    ))
    require(
        all(
            0 < len(line) + 1 <= 512
            and all(32 <= byte <= 126 for byte in line)
            for line in records
        ),
        "stream-frame",
    )
    result = b"\n".join(records) + b"\n"
    require(len(result) <= 4096, "stream-frame")
    return result


class SocketAnchor:
    def __init__(self, resource, owned=True):
        self._resource = resource
        self.owned = owned
        self.attempted = False
        self.closed = False
        self.error = None

    @property
    def resource(self):
        return self._resource

    def close_once(self):
        if not self.owned or self.closed:
            return
        require(not self.attempted, "stream-resource")
        self.attempted = True
        try:
            self.resource.close()
            require(self.resource.fileno() == -1, "stream-resource")
        except BaseException as error:
            self.error = error
            raise
        self.closed = True

    def released(self):
        require(
            self.resource.fileno() == -1
            and (not self.owned or (
                self.attempted and self.closed and self.error is None
            )),
            "stream-resource",
        )
