"""Private CI fixture for live loading of one Tor authority certificate."""

import importlib.util
import math
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


s = _load(
    "authority_startup_supervisor",
    Path(__file__).resolve().parent.parent / "real_tor_supervisor.py",
)
m = _load(
    "authority_startup_materials",
    Path(__file__).with_name("materials.py"),
)

NICKNAME = "localAuthority"
MISMATCH = b"Stored signing key does not match signing key in certificate"
LOG_LIMIT = 65536


class StartupError(RuntimeError):
    pass


def _budget(owner):
    if s.cancelled:
        raise s.Cancelled("Tor operation cancelled")
    remaining = owner.deadline - time.monotonic()
    if remaining <= 0:
        raise s.DeadlineExceeded("Tor operation deadline expired")
    return remaining


def _wait_exit(owner):
    while True:
        budget = min(0.05, _budget(owner))
        try:
            status = owner.process.wait(timeout=budget)
        except subprocess.TimeoutExpired:
            continue
        _budget(owner)
        return status


def _private_log(owner):
    owner._log.flush()
    owner._log.seek(0)
    data = owner._log.read(LOG_LIMIT + 1)
    if len(data) > LOG_LIMIT:
        raise StartupError("log-limit")
    return data


def _fingerprint(data):
    pattern = re.compile(
        NICKNAME.encode("ascii")
        + rb" ((?:[0-9A-F]{4} ){9}[0-9A-F]{4})"
    )
    matches = [
        match[1].replace(b" ", b"").decode("ascii")
        for line in data.splitlines()
        if (match := pattern.fullmatch(line)) is not None
    ]
    if len(matches) != 1:
        raise StartupError("relay-fingerprint")
    return matches[0]


def _rejection(status, data):
    if status in (None, 0) or MISMATCH not in data:
        raise StartupError("specific-rejection-missing")
    return "signing-key-mismatch"


def _private_file(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)


class RelayIdentity(s.TorSupervisor):
    def __init__(self, binary, deadline):
        super().__init__(binary, deadline)
        if not math.isfinite(deadline):
            raise StartupError("invalid-deadline")
        self.data = None
        self.fingerprint = None

    def generate(self):
        if self.process is not None or self._temp is not None or self._closed:
            raise StartupError("single-use")
        self._check()
        self._temp = tempfile.TemporaryDirectory(
            prefix="tor-relay-identity-", dir="/tmp"
        )
        root = Path(self._temp.name)
        self.data = root / "data"
        self.data.mkdir(mode=0o700)
        config = root / "torrc"
        config.write_text(
            "RunAsDaemon 0\n"
            "DataDirectory " + self._quote(str(self.data)) + "\n"
            "Nickname " + NICKNAME + "\n"
            "SocksPort 0\n"
            "ControlPort 0\n"
            "ORPort 127.0.0.1:auto\n"
            "Address 127.0.0.1\n"
            "AddressDisableIPv6 1\n"
            "DirAllowPrivateAddresses 1\n"
            "ExitRelay 0\n"
            "PublishServerDescriptor 0\n"
            "UseDefaultFallbackDirs 0\n"
            "DisableNetwork 1\n",
            encoding="utf-8",
        )
        self._launch(
            str(config),
            ("--defaults-torrc", "/dev/null", "--list-fingerprint", "rsa"),
        )
        if _wait_exit(self) != 0:
            raise StartupError("relay-tool-exit")
        self.fingerprint = _fingerprint(_private_log(self))
        self._budget_check()
        return self

    def _budget_check(self):
        return _budget(self)


class AuthorityNode(s.TorSupervisor):
    def __init__(self, binary, deadline, relay, materials):
        super().__init__(binary, deadline)
        if not math.isfinite(deadline):
            raise StartupError("invalid-deadline")
        if relay.deadline != deadline or materials.deadline != deadline:
            raise StartupError("different-deadline")
        self.relay = relay
        self.materials = materials
        self.data = None
        self.config_path = None
        self.certificate = None
        self._config_bytes = None
        self._signing = None
        self.or_port = None
        self.dir_port = None
        self._reservations = []
        self._http = None
        self._proved = False
        self.rejection = None

    @property
    def address(self):
        return "127.0.0.1"

    def _write_config(self, data, control, cookie_path, config_path):
        self._check()
        if (
            self.relay._closed
            or self.materials._closed
            or self.relay.process.returncode != 0
            or self.materials.process.returncode != 0
            or re.fullmatch(r"[0-9A-F]{40}", self.relay.fingerprint or "") is None
        ):
            raise StartupError("preparation-unavailable")
        self.data = Path(data)
        keys = self.data / "keys"
        source = self.relay.data / "keys"
        if (source / "authority_identity_key").exists():
            raise StartupError("offline-identity-online")
        shutil.copytree(source, keys)
        self.certificate = self.materials._check_file(
            "authority_certificate"
        ).read_bytes()
        metadata = m.certificate_metadata(self.certificate)
        if metadata != self.materials.metadata:
            raise StartupError("certificate-metadata")
        self._signing = self.materials._check_file(
            "authority_signing_key"
        ).read_bytes()
        _private_file(keys / "authority_certificate", self.certificate)
        _private_file(keys / "authority_signing_key", self._signing)
        if (keys / "authority_identity_key").exists():
            raise StartupError("offline-identity-online")
        for _ in range(2):
            self._check()
            reservation = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._reservations.append(reservation)
            reservation.bind((self.address, 0))
        self.or_port, self.dir_port = [
            reservation.getsockname()[1]
            for reservation in self._reservations
        ]
        if (
            self.or_port == self.dir_port
            or not 1 <= self.or_port <= 65535
            or not 1 <= self.dir_port <= 65535
        ):
            raise StartupError("port-allocation")
        self.config_path = Path(config_path)
        self.config_path.write_text(
            "RunAsDaemon 0\n"
            "DataDirectory " + self._quote(data) + "\n"
            "Nickname " + NICKNAME + "\n"
            "ControlPort 0\n"
            "ControlSocket " + self._quote(control) + "\n"
            "CookieAuthentication 1\n"
            "CookieAuthFile " + self._quote(cookie_path) + "\n"
            "SocksPort 0\n"
            "Address " + self.address + "\n"
            "AddressDisableIPv6 1\n"
            "ORPort " + self.address + ":" + str(self.or_port) + "\n"
            "DirPort " + self.address + ":" + str(self.dir_port) + "\n"
            "TestingTorNetwork 1\n"
            "AuthoritativeDirectory 1\n"
            "V3AuthoritativeDirectory 1\n"
            "ClientOnly 0\n"
            "BridgeRelay 0\n"
            "DirCache 1\n"
            "ExitRelay 0\n"
            "PublishServerDescriptor 0\n"
            "UseDefaultFallbackDirs 0\n"
            "DirAuthority " + NICKNAME
            + " orport=" + str(self.or_port)
            + " v3ident=" + metadata["v3_identity_fingerprint"]
            + " " + self.address + ":" + str(self.dir_port)
            + " " + self.relay.fingerprint + "\n"
            "DisableNetwork 0\n",
            encoding="utf-8",
        )
        self._config_bytes = self.config_path.read_bytes()
        self._check()

    def _launch(self, config_path, extra=()):
        for reservation in self._reservations:
            reservation.close()
        self._reservations.clear()
        super()._launch(
            config_path, ("--defaults-torrc", "/dev/null", *extra)
        )

    def _info(self, name):
        self._send_line(b"GETINFO " + name)
        prefix = b"250-" + name + b"="
        line = self._read_line()
        if not line.startswith(prefix):
            raise s.ProtocolError("unexpected authority control response")
        value = line[len(prefix):]
        self._read_ok()
        self._check()
        return value

    def _listener(self, value, expected):
        if (
            type(value) is not bytes
            or type(expected) is not int
            or not 1 <= expected <= 65535
        ):
            raise StartupError("owned-listener")
        pattern = (
            rb'"' + re.escape(self.address.encode("ascii"))
            + rb':([1-9][0-9]{0,4})"'
        )
        match = re.fullmatch(pattern, value)
        if match is None or int(match[1]) != expected:
            raise StartupError("owned-listener")
        return self.address, expected

    def _identity_and_listeners(self):
        pid = self._info(b"process/pid")
        if pid != str(self.process.pid).encode("ascii"):
            raise StartupError("owned-process")
        fingerprint = self._info(b"fingerprint")
        if fingerprint != self.relay.fingerprint.encode("ascii"):
            raise StartupError("relay-identity")
        self._listener(self._info(b"net/listeners/or"), self.or_port)
        return self._listener(
            self._info(b"net/listeners/dir"), self.dir_port
        )

    def _http_send(self, payload):
        offset = 0
        while offset < len(payload):
            self._http.settimeout(min(0.05, self._remaining()))
            try:
                count = self._http.send(payload[offset:])
            except socket.timeout:
                continue
            if count <= 0:
                raise StartupError("http-eof")
            offset += count

    def _http_recv(self, count):
        while True:
            self._http.settimeout(min(0.05, self._remaining()))
            try:
                data = self._http.recv(count)
            except socket.timeout:
                continue
            if not data:
                raise StartupError("http-eof")
            return data

    def _http_body(self):
        header = bytearray()
        while not header.endswith(b"\r\n\r\n"):
            if len(header) >= 8192:
                raise StartupError("http-header-limit")
            header.extend(self._http_recv(1))
        lines = bytes(header[:-4]).split(b"\r\n")
        if lines[0] != b"HTTP/1.0 200 OK":
            raise StartupError("http-status")
        fields = {}
        for line in lines[1:]:
            name, separator, value = line.partition(b":")
            name = name.lower()
            if not separator or not name or name in fields:
                raise StartupError("http-header")
            fields[name] = value.strip()
        if (
            fields.get(b"content-length")
            != str(len(self.certificate)).encode("ascii")
            or fields.get(b"content-encoding", b"identity") != b"identity"
            or b"transfer-encoding" in fields
        ):
            raise StartupError("http-framing")
        body = bytearray()
        while len(body) < len(self.certificate):
            body.extend(
                self._http_recv(min(4096, len(self.certificate) - len(body)))
            )
        if bytes(body) != self.certificate:
            raise StartupError("served-certificate")
        self._check()

    def _fetch(self, endpoint):
        if endpoint != (self.address, self.dir_port):
            raise StartupError("owned-listener")
        self._http = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self._http.settimeout(min(0.05, self._remaining()))
            self._http.connect(endpoint)
            if self._http.getpeername() != endpoint:
                raise StartupError("http-peer")
            self._http_send(
                b"GET /tor/keys/authority HTTP/1.0\r\n"
                b"Host: " + self.address.encode("ascii") + b"\r\n"
                b"Accept-Encoding: identity\r\n"
                b"Connection: close\r\n\r\n"
            )
            self._http_body()
        finally:
            self._http.close()

    def prove_loaded_certificate(self):
        if self._proved:
            raise StartupError("single-proof")
        self.ready()
        endpoint = self._identity_and_listeners()
        self._fetch(endpoint)
        if self._identity_and_listeners() != endpoint:
            raise StartupError("listener-changed")
        self._check()
        self._proved = True
        return "loaded-authority-certificate"

    def reject_mismatched_signing_key(self, other):
        if not self._proved or self.rejection is not None:
            raise StartupError("good-baseline-required")
        if (
            other.deadline != self.deadline
            or other._closed
            or other.process.returncode != 0
        ):
            raise StartupError("preparation-unavailable")
        _budget(self)
        replacement = other._check_file("authority_signing_key").read_bytes()
        if replacement == self._signing:
            raise StartupError("different-signing-key-required")
        if self.config_path.read_bytes() != self._config_bytes:
            raise StartupError("baseline-config-changed")
        certificate_path = self.data / "keys" / "authority_certificate"
        if certificate_path.read_bytes() != self.certificate:
            raise StartupError("baseline-certificate-changed")
        if self._socket is not None:
            self._socket.close()
            self._socket = None
        self._cookie = None
        self._stop_child()
        _budget(self)
        root = self.config_path.parent
        (root / "control").unlink(missing_ok=True)
        (root / "cookie").unlink(missing_ok=True)
        signing_path = self.data / "keys" / "authority_signing_key"
        if signing_path.read_bytes() != self._signing:
            raise StartupError("baseline-signing-key-changed")
        signing_path.write_bytes(replacement)
        self.rejection = s.TorSupervisor(self.binary, self.deadline)
        self.rejection._launch(
            str(self.config_path), ("--defaults-torrc", "/dev/null")
        )
        status = _wait_exit(self.rejection)
        category = _rejection(status, _private_log(self.rejection))
        _budget(self)
        return category

    def close(self):
        socket_failed = False
        for reservation in self._reservations:
            try:
                reservation.close()
            except OSError:
                socket_failed = True
        self._reservations.clear()
        if self._http is not None:
            try:
                self._http.close()
            except OSError:
                socket_failed = True
        if self.rejection is not None:
            self.rejection.close()
        super().close()
        if socket_failed:
            raise s.CleanupError("authority socket cleanup failed")
