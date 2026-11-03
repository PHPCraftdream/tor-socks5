"""Retained ownership of one foreground Tor control fixture in isolated CI."""

import errno
import os
import re
import socket
import subprocess
import tempfile
import time


class SupervisorError(RuntimeError):
    pass


class DeadlineExceeded(SupervisorError):
    pass


class Cancelled(SupervisorError):
    pass


class ChildExit(SupervisorError):
    pass


class ProtocolError(SupervisorError):
    pass


class AuthError(ProtocolError):
    pass


class CleanupError(SupervisorError):
    pass


cancelled = False
VERSION = re.compile(rb"0\.4\.9\.15(?: \(git-[0-9a-fA-F]+\))?")


class TorSupervisor:
    def __init__(self, binary, deadline):
        if (
            os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("TOR_REAL_ISOLATED") != "yes"
        ):
            raise SupervisorError("isolated CI is required")
        if not os.path.isabs(binary):
            raise SupervisorError("an absolute Tor executable is required")
        self.binary = binary
        self.deadline = deadline
        self.process = None
        self._socket = None
        self._temp = None
        self._log = None
        self._cookie = None
        self._closed = False
        self.version = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()
        return False

    def _check(self):
        if cancelled:
            raise Cancelled("Tor operation cancelled")
        if self.process is not None and self.process.poll() is not None:
            raise ChildExit("owned Tor child exited")
        if time.monotonic() >= self.deadline:
            raise DeadlineExceeded("Tor operation deadline expired")

    def _remaining(self):
        self._check()
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise DeadlineExceeded("Tor operation deadline expired")
        return remaining

    @staticmethod
    def _quote(path):
        return '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'

    def start(self):
        if self.process is not None or self._closed:
            raise SupervisorError("Tor fixture cannot be restarted")
        self._check()
        self._temp = tempfile.TemporaryDirectory(prefix="tor-control-", dir="/tmp")
        root = self._temp.name
        data = os.path.join(root, "data")
        control = os.path.join(root, "control")
        cookie_path = os.path.join(root, "cookie")
        config_path = os.path.join(root, "torrc")
        os.mkdir(data, 0o700)
        with open(config_path, "w", encoding="utf-8") as config:
            config.write(
                "RunAsDaemon 0\n"
                "DataDirectory " + self._quote(data) + "\n"
                "ControlPort 0\n"
                "ControlSocket " + self._quote(control) + "\n"
                "CookieAuthentication 1\n"
                "CookieAuthFile " + self._quote(cookie_path) + "\n"
                "SocksPort 0\n"
                "DisableNetwork 1\n"
            )
        self._log = tempfile.TemporaryFile(mode="w+b")
        self._check()
        self.process = subprocess.Popen(
            [self.binary, "-f", config_path],
            stdin=subprocess.DEVNULL,
            stdout=self._log,
            stderr=self._log,
        )
        while True:
            self._check()
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                sock.settimeout(min(0.05, self._remaining()))
                sock.connect(control)
            except OSError as error:
                sock.close()
                if error.errno not in (
                    errno.ENOENT,
                    errno.ECONNREFUSED,
                    errno.EAGAIN,
                    errno.EINTR,
                ):
                    raise ProtocolError("control connection failed") from None
                time.sleep(min(0.02, self._remaining()))
            except BaseException:
                sock.close()
                raise
            else:
                self._socket = sock
                break
        while True:
            self._check()
            try:
                with open(cookie_path, "rb") as cookie_file:
                    cookie = cookie_file.read(33)
            except FileNotFoundError:
                cookie = b""
            if len(cookie) > 32:
                raise ProtocolError("invalid control cookie length")
            if len(cookie) == 32:
                self._cookie = cookie
                return self
            time.sleep(min(0.02, self._remaining()))

    def _send_line(self, command):
        if self._socket is None:
            raise ProtocolError("control connection is unavailable")
        payload = command + b"\r\n"
        offset = 0
        while offset < len(payload):
            self._socket.settimeout(min(0.05, self._remaining()))
            try:
                count = self._socket.send(payload[offset:])
            except socket.timeout:
                continue
            except OSError:
                self._check()
                raise ProtocolError("control write failed") from None
            if count == 0:
                raise ProtocolError("control connection closed")
            offset += count

    def _read_line(self):
        if self._socket is None:
            raise ProtocolError("control connection is unavailable")
        line = bytearray()
        while len(line) < 4096:
            self._socket.settimeout(min(0.05, self._remaining()))
            try:
                char = self._socket.recv(1)
            except socket.timeout:
                continue
            except OSError:
                self._check()
                raise ProtocolError("control read failed") from None
            if not char:
                self._check()
                raise ProtocolError("control connection closed")
            line.extend(char)
            if line.endswith(b"\r\n"):
                return bytes(line[:-2])
        raise ProtocolError("control response exceeds its line limit")

    def _read_ok(self):
        response = self._read_line()
        if response.startswith(b"515 "):
            raise AuthError("Tor rejected control authentication")
        if response != b"250 OK":
            raise ProtocolError("unexpected control response")

    def ready(self):
        if self._cookie is None:
            raise ProtocolError("control cookie is unavailable")
        self._send_line(b"AUTHENTICATE " + self._cookie.hex().encode("ascii"))
        self._read_ok()
        self._send_line(b"GETINFO version")
        response = self._read_line()
        if not response.startswith(b"250-version="):
            raise ProtocolError("unexpected version response")
        version = response[len(b"250-version="):]
        if VERSION.fullmatch(version) is None:
            raise ProtocolError("unexpected Tor version")
        self._read_ok()
        self._check()
        self.version = version.decode("ascii")
        return self.version

    def close(self):
        if self._closed:
            return
        socket_failed = False
        if self._socket is not None:
            sock, self._socket = self._socket, None
            try:
                sock.close()
            except OSError:
                socket_failed = True
        self._cookie = None
        cleanup_deadline = min(self.deadline + 5.0, time.monotonic() + 5.0)
        if self.process is not None:
            if self.process.poll() is None:
                try:
                    self.process.terminate()
                except ProcessLookupError:
                    pass
                try:
                    self.process.wait(
                        timeout=min(
                            2.0, max(0.0, cleanup_deadline - time.monotonic())
                        )
                    )
                except subprocess.TimeoutExpired:
                    try:
                        self.process.kill()
                    except ProcessLookupError:
                        pass
                    try:
                        self.process.wait(
                            timeout=max(0.0, cleanup_deadline - time.monotonic())
                        )
                    except subprocess.TimeoutExpired:
                        raise CleanupError("owned Tor child was not reaped") from None
            if self.process.poll() is None:
                raise CleanupError("owned Tor child remains alive")
            self.process.wait(timeout=0)
        if self._log is not None:
            self._log.close()
            self._log = None
        if self._temp is not None:
            self._temp.cleanup()
            self._temp = None
        self._closed = True
        if socket_failed:
            raise CleanupError("control connection cleanup failed")
