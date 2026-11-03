"""Private isolated-CI fixture for genuine three-authority consensus voting."""

from datetime import datetime, timezone
import importlib.util
import math
from pathlib import Path
import re
import socket
import subprocess
import time


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


a = _load("authority_consensus_startup", Path(__file__).with_name("startup.py"))

LIMIT = 1048576
HEX = rb"[0-9A-F]{40}"
OFFSET = 0
INTERVAL = 120
VALID_INTERVALS = 3
SHORTAGE = b"We don't have enough votes to generate a consensus: 1 of 2"


class ConsensusError(RuntimeError):
    pass


def require(condition, label):
    if not condition:
        raise ConsensusError(label)


def one(data, pattern):
    values = re.findall(pattern, data, re.MULTILINE)
    require(len(values) == 1, "document-field")
    return values[0]


def stamp(data, name):
    value = one(
        data,
        rb"^" + name + rb" (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)$",
    )
    return datetime.strptime(
        value.decode("ascii"), "%Y-%m-%d %H:%M:%S"
    ).replace(tzinfo=timezone.utc).timestamp()


def period_after(now, interval, offset):
    require(
        isinstance(now, int)
        and isinstance(interval, int)
        and isinstance(offset, int)
        and interval > 0
        and 0 <= offset <= interval,
        "schedule-input",
    )
    midnight = now - now % 86400
    tomorrow = midnight + 86400
    result = midnight + ((now - midnight) // interval + 1) * interval
    if result > tomorrow:
        result = tomorrow
    if result + interval // 2 > tomorrow:
        result = tomorrow
    result += offset
    if result - interval > now:
        result -= interval
    return result


def next_round(metadata):
    valid_after, fresh_until, _valid_until, _entries = metadata
    interval = fresh_until - valid_after
    require(interval == INTERVAL, "consensus-interval")
    return period_after(int(valid_after), int(interval), OFFSET)


def require_window(period, now):
    require(now < period - 40, "quorum-window-missed")


def signed_part(data):
    marker = b"\ndirectory-signature "
    require(data.startswith(b"network-status-version 3\n"), "document-version")
    require(marker in data, "document-signature")
    return data[:data.index(marker) + len(marker)]


def sources(data):
    result = {}
    current = None
    for line in data.splitlines():
        if line.startswith(b"dir-source "):
            fields = line.split()
            require(
                len(fields) == 7 and re.fullmatch(HEX, fields[2]) is not None,
                "document-source",
            )
            current = fields[2].decode("ascii")
            require(current not in result, "duplicate-source")
            result[current] = (fields, None)
        elif line.startswith(b"vote-digest "):
            require(current is not None, "document-vote-digest")
            digest = line[len(b"vote-digest "):]
            fields, previous = result[current]
            require(
                previous is None and re.fullmatch(HEX, digest) is not None,
                "document-vote-digest",
            )
            result[current] = (fields, digest)
    return result


def consensus_metadata(data, nodes, now):
    require(
        one(data, rb"^vote-status (\S+)$") == b"consensus",
        "document-type",
    )
    valid_after = stamp(data, b"valid-after")
    fresh_until = stamp(data, b"fresh-until")
    valid_until = stamp(data, b"valid-until")
    require(
        valid_after <= now < fresh_until < valid_until,
        "consensus-not-current",
    )
    require(
        fresh_until - valid_after == INTERVAL
        and valid_until - valid_after == INTERVAL * VALID_INTERVALS,
        "consensus-interval",
    )
    require(
        one(data, rb"^voting-delay (\d+ \d+)$") == b"20 20",
        "consensus-delays",
    )
    entries = sources(data)
    expected = {node.identity for node in nodes}
    require(len(expected) == 3 and set(entries) == expected, "consensus-voters")
    for node in nodes:
        fields, digest = entries[node.identity]
        require(
            fields[1] == node.name.encode("ascii")
            and fields[3] == b"127.0.0.1"
            and fields[4] == b"127.0.0.1"
            and fields[5] == str(node.dir_port).encode("ascii")
            and fields[6] == str(node.or_port).encode("ascii")
            and digest is not None,
            "consensus-binding",
        )
    signatures = re.findall(
        rb"^directory-signature (" + HEX + rb") (" + HEX + rb")$",
        data,
        re.MULTILINE,
    )
    signers = {identity.decode("ascii") for identity, _key in signatures}
    require(signers <= expected and len(signers) >= 2, "consensus-signers")
    signed_part(data)
    return valid_after, fresh_until, valid_until, entries


def vote_metadata(data, node, valid_after):
    require(
        one(data, rb"^vote-status (\S+)$") == b"vote",
        "vote-type",
    )
    require(stamp(data, b"valid-after") == valid_after, "vote-period")
    entries = sources(data)
    require(set(entries) == {node.identity}, "vote-identity")
    fields, _digest = entries[node.identity]
    require(
        fields[1] == node.name.encode("ascii")
        and fields[4] == b"127.0.0.1"
        and fields[5] == str(node.dir_port).encode("ascii")
        and fields[6] == str(node.or_port).encode("ascii"),
        "vote-binding",
    )
    require(
        node.certificate is not None and node.certificate in data,
        "vote-certificate",
    )
    signed_part(data)


def bounded_file(path):
    with path.open("rb") as source:
        data = source.read(LIMIT + 1)
    require(len(data) <= LIMIT, "file-limit")
    return data


class VotingNode(a.AuthorityNode):
    def __init__(self, binary, deadline, relay, materials, index):
        super().__init__(binary, deadline, relay, materials)
        self.name = ("localA", "localB", "localC")[index]
        self.identity = materials.metadata["v3_identity_fingerprint"]
        self.peers = None
        self.candidates = None

    def _write_config(self, data, control, cookie_path, config_path):
        super()._write_config(data, control, cookie_path, config_path)
        old_or, old_dir = self.or_port, self.dir_port
        for reservation in self._reservations:
            reservation.close()
        self._reservations.clear()
        require(
            self.peers is not None and self.candidates is not None,
            "topology-unprepared",
        )
        self.or_port, self.dir_port = [
            candidate.getsockname()[1] for candidate in self.candidates
        ]
        self._reservations.extend(self.candidates)
        text = self.config_path.read_text(encoding="utf-8")
        require(text.count("Nickname " + a.NICKNAME + "\n") == 1, "baseline-config")
        text = text.replace(
            "Nickname " + a.NICKNAME + "\n",
            "Nickname " + self.name + "\n",
            1,
        )
        text = text.replace(
            "ORPort 127.0.0.1:" + str(old_or) + "\n",
            "ORPort 127.0.0.1:" + str(self.or_port) + "\n",
            1,
        )
        text = text.replace(
            "DirPort 127.0.0.1:" + str(old_dir) + "\n",
            "DirPort 127.0.0.1:" + str(self.dir_port) + "\n",
            1,
        )
        lines = text.splitlines(keepends=True)
        require(
            sum(line.startswith("DirAuthority ") for line in lines) == 1,
            "baseline-authority-config",
        )
        authorities = "".join(
            "DirAuthority " + peer.name
            + " orport=" + str(peer.or_port)
            + " v3ident=" + peer.identity
            + " 127.0.0.1:" + str(peer.dir_port)
            + " " + peer.relay.fingerprint + "\n"
            for peer in self.peers
        )
        text = "".join(
            authorities if line.startswith("DirAuthority ") else line
            for line in lines
        )
        require(text.count("PublishServerDescriptor 0\n") == 1, "baseline-config")
        text = text.replace(
            "PublishServerDescriptor 0\n",
            "PublishServerDescriptor 1\n",
            1,
        )
        text += (
            "V3AuthUseLegacyKey 0\n"
            "V3AuthVotingInterval 120 seconds\n"
            "V3AuthNIntervalsValid 3\n"
            "V3AuthVoteDelay 20 seconds\n"
            "V3AuthDistDelay 20 seconds\n"
            "TestingV3AuthInitialVotingInterval 120 seconds\n"
            "TestingV3AuthInitialVoteDelay 20 seconds\n"
            "TestingV3AuthInitialDistDelay 20 seconds\n"
            "TestingV3AuthVotingStartOffset 0\n"
            "Log warn stdout\n"
        )
        self.config_path.write_text(text, encoding="utf-8")
        self._config_bytes = self.config_path.read_bytes()
        self._check()

    def _receive(self, count):
        while True:
            self._http.settimeout(min(0.05, self._remaining()))
            try:
                return self._http.recv(count)
            except socket.timeout:
                continue

    def request(self, path):
        require(
            re.fullmatch(
                rb"/tor/(?:keys/authority|status-vote/"
                rb"(?:current/(?:consensus|authority|d/[0-9A-F]{40})"
                rb"|next/(?:authority|consensus)))",
                path,
            ) is not None,
            "request-path",
        )
        return self._exchange(path)

    def _exchange(self, path, payload=None):
        require(
            payload is None
            or isinstance(payload, bytes) and len(payload) <= LIMIT,
            "request-limit",
        )
        self._check()
        endpoint = self._identity_and_listeners()
        self._http = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self._http.settimeout(min(0.05, self._remaining()))
            self._http.connect(endpoint)
            require(self._http.getpeername() == endpoint, "http-peer")
            method = b"GET" if payload is None else b"POST"
            length = (
                b"" if payload is None
                else b"Content-Length: "
                + str(len(payload)).encode("ascii") + b"\r\n"
            )
            self._http_send(
                method + b" " + path + b" HTTP/1.0\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Accept-Encoding: identity\r\n"
                b"Connection: close\r\n"
                + length + b"\r\n"
                + (b"" if payload is None else payload)
            )
            response = bytearray()
            while True:
                chunk = self._receive(min(4096, LIMIT + 8193 - len(response)))
                if not chunk:
                    break
                response.extend(chunk)
                require(len(response) <= LIMIT + 8192, "http-limit")
            header, separator, body = bytes(response).partition(b"\r\n\r\n")
            require(separator and len(header) <= 8192, "http-header")
            lines = header.split(b"\r\n")
            match = re.fullmatch(
                rb"HTTP/1\.0 ([0-9]{3}) ([^\r\n]*)", lines[0]
            )
            require(match is not None, "http-status")
            self._last_reason = match[2]
            fields = {}
            for line in lines[1:]:
                key, separator, value = line.partition(b":")
                key = key.lower()
                require(separator and key and key not in fields, "http-header")
                fields[key] = value.strip()
            require(
                fields.get(b"content-encoding", b"identity") == b"identity"
                and b"transfer-encoding" not in fields
                and len(body) <= LIMIT,
                "http-framing",
            )
            if b"content-length" in fields:
                require(
                    fields[b"content-length"] == str(len(body)).encode("ascii"),
                    "http-length",
                )
            require(
                self._identity_and_listeners() == endpoint,
                "listener-changed",
            )
            self._check()
            return int(match[1]), body
        finally:
            self._http.close()

    def cached(self):
        self._check()
        try:
            data = bounded_file(self.data / "cached-consensus")
        except FileNotFoundError:
            return None
        require(bool(data), "cached-empty")
        self._check()
        return data


class Network:
    node_type = VotingNode

    def __init__(self, binary, gencert, deadline):
        require(math.isfinite(deadline), "invalid-deadline")
        self.binary = binary
        self.gencert = gencert
        self.deadline = deadline
        self.materials = []
        self.relays = []
        self.nodes = []
        self.active = []
        self.reservations = []
        self.baseline = None
        self.metadata = None
        self.stage = "prepare"
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()
        return False

    def check(self):
        a._budget(self)
        for node in self.active:
            node._check()

    def pause(self):
        self.check()
        time.sleep(min(0.05, a._budget(self)))

    def start(self):
        require(not self.materials and not self.closed, "single-use")
        for _index in range(3):
            self.check()
            material = a.m.AuthorityMaterials(self.gencert, self.deadline)
            self.materials.append(material)
            material.generate()
            relay = a.RelayIdentity(self.binary, self.deadline)
            self.relays.append(relay)
            relay.generate()
        identities = {
            material.metadata["v3_identity_fingerprint"]
            for material in self.materials
        }
        relays = {relay.fingerprint for relay in self.relays}
        require(
            len(identities) == 3 and len(relays) == 3 and identities.isdisjoint(relays),
            "independent-identities",
        )
        for index in range(3):
            node = self.node_type(
                self.binary, self.deadline,
                self.relays[index], self.materials[index], index,
            )
            self.nodes.append(node)
            pair = []
            for _kind in range(2):
                self.check()
                reservation = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.reservations.append(reservation)
                pair.append(reservation)
                reservation.bind(("127.0.0.1", 0))
            node.candidates = pair
            node.or_port, node.dir_port = [
                reservation.getsockname()[1] for reservation in pair
            ]
        ports = [
            port for node in self.nodes for port in (node.or_port, node.dir_port)
        ]
        require(len(set(ports)) == 6, "candidate-ports")
        for node in self.nodes:
            node.peers = self.nodes
        self.stage = "launch"
        for node in self.nodes:
            self.check()
            node.start()
            self.active.append(node)
            require(
                node.prove_loaded_certificate() == "loaded-authority-certificate",
                "loaded-certificate",
            )
        self.check()

    def positive(self):
        self.stage = "consensus"
        while True:
            self.check()
            responses = [
                node.request(b"/tor/status-vote/current/consensus")
                for node in self.nodes
            ]
            require(
                all(status in (200, 404) for status, _body in responses),
                "consensus-http",
            )
            if all(status == 200 for status, _body in responses):
                bodies = [body for _status, body in responses]
                now = time.time()
                if any(stamp(body, b"valid-after") > now for body in bodies):
                    self.pause()
                    continue
                metadata = [
                    consensus_metadata(body, self.nodes, now)
                    for body in bodies
                ]
                require(
                    len({item[0] for item in metadata}) == 1
                    and len({signed_part(body) for body in bodies}) == 1,
                    "consensus-disagreement",
                )
                for node, body in zip(self.nodes, bodies):
                    require(node.cached() == body, "daemon-current-consensus")
                self.baseline = bodies[0]
                self.metadata = metadata[0]
                break
            self.pause()
        self.stage = "votes"
        valid_after, _fresh_until, _valid_until, entries = self.metadata
        require_window(next_round(self.metadata), time.time())
        for origin in self.nodes:
            digest = entries[origin.identity][1]
            path = b"/tor/status-vote/current/d/" + digest
            status, original = origin.request(b"/tor/status-vote/current/authority")
            require(status == 200, "origin-vote")
            vote_metadata(original, origin, valid_after)
            for receiver in self.nodes:
                status, admitted = receiver.request(path)
                require(
                    status == 200 and admitted == original,
                    "participating-vote",
                )
        self.check()
        return "three-authority-consensus"

    @staticmethod
    def stop_owned(owners, deadline):
        cleanup_end = min(deadline + 5.0, time.monotonic() + 5.0)
        term_end = min(cleanup_end, time.monotonic() + 2.0)
        failed = False
        for owner in owners:
            for name in ("_http", "_socket"):
                resource = getattr(owner, name, None)
                if resource is not None:
                    try:
                        resource.close()
                    except OSError:
                        failed = True
                    if name == "_socket":
                        owner._socket = None
            if hasattr(owner, "_cookie"):
                owner._cookie = None
        processes = [
            owner.process for owner in owners if owner.process is not None
        ]
        for process in processes:
            if process.poll() is None:
                try:
                    process.terminate()
                except ProcessLookupError:
                    pass
                except OSError:
                    failed = True
        for process in processes:
            if process.poll() is None:
                try:
                    process.wait(timeout=max(0.0, term_end - time.monotonic()))
                except subprocess.TimeoutExpired:
                    pass
                except OSError:
                    failed = True
        for process in processes:
            if process.poll() is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                except OSError:
                    failed = True
        for process in processes:
            try:
                process.wait(timeout=max(0.0, cleanup_end - time.monotonic()))
                if process.returncode is None:
                    failed = True
            except (OSError, subprocess.TimeoutExpired):
                failed = True
        if failed:
            raise a.s.CleanupError("authority group cleanup failed")

    def negative(self):
        require(self.baseline is not None and self.metadata is not None, "good-baseline")
        self.stage = "quorum"
        survivor = self.nodes[0]
        period = next_round(self.metadata)
        require_window(period, time.time())
        require(
            all(node.config_path.read_bytes() == node._config_bytes for node in self.nodes),
            "baseline-config-changed",
        )
        log_offset = len(a._private_log(survivor))
        self.stop_owned(self.nodes[1:], self.deadline)
        self.active = [survivor]
        require(
            all(node.process.returncode is not None for node in self.nodes[1:]),
            "removed-voters-not-reaped",
        )
        require_window(period, time.time())
        vote = None
        while True:
            self.check()
            status, body = survivor.request(b"/tor/status-vote/next/authority")
            require(status in (200, 404), "next-vote-http")
            if status == 200:
                vote_metadata(body, survivor, period)
                if vote is not None:
                    require(body == vote, "minority-vote-changed")
                vote = body
            log = a._private_log(survivor)
            require(len(log) >= log_offset, "log-truncated")
            shortage = SHORTAGE in log[log_offset:]
            if vote is not None and shortage and time.time() >= period:
                status, rotated = survivor.request(
                    b"/tor/status-vote/current/authority"
                )
                require(status in (200, 404), "rotated-vote-http")
                if status == 200 and rotated == vote:
                    break
            self.pause()
        require(
            bounded_file(survivor.data / "v3-status-votes") == vote,
            "quorum-admitted-votes",
        )
        status, _pending = survivor.request(b"/tor/status-vote/next/consensus")
        require(status == 404, "minority-pending-consensus")
        status, current = survivor.request(b"/tor/status-vote/current/consensus")
        require(
            status == 200
            and current == self.baseline
            and survivor.cached() == self.baseline,
            "minority-published-consensus",
        )
        require(
            survivor.config_path.read_bytes() == survivor._config_bytes,
            "quorum-config-changed",
        )
        self.check()
        return "one-of-three-vote-quorum-rejected"

    def witnesses(self):
        result = []
        for owner in self.nodes + self.relays:
            if owner._temp is not None:
                result.append((
                    owner.process,
                    owner._log,
                    Path(owner._temp.name),
                    owner._socket,
                    getattr(owner, "_http", None),
                ))
        for owner in self.materials:
            if owner._temp is not None:
                result.append((
                    owner.process, owner._input, Path(owner._temp.name), None, None,
                ))
        return result

    def close(self):
        if self.closed:
            return
        self.stop_owned(self.nodes + self.relays + self.materials, self.deadline)
        for reservation in self.reservations:
            reservation.close()
        for node in reversed(self.nodes):
            node.close()
        for relay in reversed(self.relays):
            relay.close()
        for material in reversed(self.materials):
            material.close()
        self.closed = True


def released(witnesses):
    for process, stream, root, control, http in witnesses:
        require(
            process is not None and process.returncode is not None,
            "child-unreaped",
        )
        require(stream is not None and stream.closed, "stream-unreleased")
        require(not root.exists(), "directory-unreleased")
        for resource in (control, http):
            require(
                resource is None or resource.fileno() == -1,
                "socket-unreleased",
            )
