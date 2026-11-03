"""CI-only mechanisms and real Tor authority loading/rejection controls."""

import importlib.util
import io
import math
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


a = load("authority_startup_checks", Path(__file__).with_name("startup.py"))


class Wire:
    def __init__(self, replies=b""):
        self.replies = bytearray(replies)
        self.sent = bytearray()
        self.closed = False
        self.endpoint = None

    def settimeout(self, timeout):
        if not 0 < timeout <= 0.05:
            raise AssertionError("unbounded-socket")

    def connect(self, endpoint):
        self.endpoint = endpoint

    def getpeername(self):
        return self.endpoint

    def send(self, payload):
        count = min(3, len(payload))
        self.sent.extend(payload[:count])
        return count

    def recv(self, count):
        result = bytes(self.replies[:count])
        del self.replies[:count]
        return result

    def close(self):
        self.closed = True

    def fileno(self):
        return -1 if self.closed else 1


def response(body, headers=None, status=b"HTTP/1.0 200 OK"):
    if headers is None:
        headers = [
            b"Content-Length: " + str(len(body)).encode("ascii"),
            b"Content-Encoding: identity",
        ]
    return status + b"\r\n" + b"\r\n".join(headers) + b"\r\n\r\n" + body


class Controls(unittest.TestCase):
    def node(self):
        deadline = time.monotonic() + 60
        relay = SimpleNamespace(
            deadline=deadline,
            fingerprint=bytes(range(20)).hex().upper(),
        )
        materials = SimpleNamespace(deadline=deadline)
        owner = a.AuthorityNode("/fixture/tor", deadline, relay, materials)
        owner.or_port = 19001
        owner.dir_port = 19002
        owner.certificate = b"mechanism-only-public-body\n"
        return owner

    def test_configuration_uses_separate_prepared_identities(self):
        owner = self.node()
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            relay_data = root / "relay"
            (relay_data / "keys").mkdir(parents=True, mode=0o700)
            (relay_data / "keys" / "secret_id_key").write_bytes(
                b"mechanism-only-relay-key"
            )
            material_root = root / "materials"
            material_root.mkdir(mode=0o700)
            certificate = material_root / "authority_certificate"
            signing = material_root / "authority_signing_key"
            offline = material_root / "authority_identity_key"
            certificate.write_bytes(owner.certificate)
            signing.write_bytes(b"mechanism-only-signing-key")
            offline.write_bytes(b"mechanism-only-offline-key")
            metadata = {
                "v3_identity_fingerprint": bytes(range(20, 40)).hex().upper(),
                "published": "mechanism-only",
                "expires": "mechanism-only",
            }
            owner.relay.data = relay_data
            owner.relay._closed = False
            owner.relay.process = SimpleNamespace(returncode=0)
            owner.materials._closed = False
            owner.materials.process = SimpleNamespace(returncode=0)
            owner.materials.metadata = metadata
            owner.materials._check_file = lambda name: material_root / name
            data = root / "node"
            data.mkdir(mode=0o700)
            control = str(root / "control")
            cookie = str(root / "cookie")
            config = root / "torrc"
            try:
                with mock.patch.object(
                    a.m, "certificate_metadata", return_value=metadata
                ):
                    owner._write_config(str(data), control, cookie, str(config))
                text = config.read_text(encoding="utf-8")
                self.assertEqual(text.count("DirAuthority "), 1)
                self.assertIn(
                    "v3ident=" + metadata["v3_identity_fingerprint"], text
                )
                self.assertIn(
                    " " + owner.relay.fingerprint + "\n", text
                )
                self.assertIn("DisableNetwork 0\n", text)
                self.assertIn("TestingTorNetwork 1\n", text)
                self.assertIn("BridgeRelay 0\n", text)
                self.assertEqual(
                    (data / "keys" / "authority_certificate").read_bytes(),
                    owner.certificate,
                )
                self.assertEqual(
                    (data / "keys" / "secret_id_key").read_bytes(),
                    b"mechanism-only-relay-key",
                )
                self.assertFalse(
                    (data / "keys" / "authority_identity_key").exists()
                )
                self.assertEqual(len(owner._reservations), 2)
                self.assertNotEqual(owner.or_port, owner.dir_port)
            finally:
                owner.close()

    def test_fingerprint_requires_one_exact_real_tool_output_shape(self):
        fingerprint = bytes(range(20)).hex().upper()
        grouped = " ".join(
            fingerprint[index:index + 4] for index in range(0, 40, 4)
        )
        line = (a.NICKNAME + " " + grouped + "\n").encode("ascii")
        self.assertEqual(a._fingerprint(b"tool notice\n" + line), fingerprint)
        for data in (b"", line + line, line.replace(b" ", b"", 1)):
            with self.subTest(category="bad-output"):
                with self.assertRaises(a.StartupError):
                    a._fingerprint(data)

    def test_listener_parser_rejects_other_or_ambiguous_endpoints(self):
        with self.node() as owner:
            self.assertEqual(owner.address, "127.0.0.1")
            self.assertEqual(
                owner._listener(b'"127.0.0.1:19002"', 19002),
                ("127.0.0.1", 19002),
            )
            for value in (
                b"",
                b'"0.0.0.0:19002"',
                b'"127.0.0.2:19002"',
                b'"127.0.0.1:19003"',
                b'"127.0.0.1:19002" "127.0.0.1:19003"',
                b"127.0.0.1:19002",
                b'"127.0.0.1:0"',
                b'"127.0.0.1:019002"',
                b'"[::1]:19002"',
            ):
                with self.subTest(category="bad-listener"):
                    with self.assertRaisesRegex(
                        a.StartupError, "^owned-listener$"
                    ):
                        owner._listener(value, 19002)
            for expected in (0, 65536, True, "19002"):
                with self.assertRaisesRegex(
                    a.StartupError, "^owned-listener$"
                ):
                    owner._listener(b'"127.0.0.1:19002"', expected)

    def test_getinfo_requires_exact_key_and_terminator(self):
        with self.node() as owner:
            wire = Wire(b"250-process/pid=27\r\n250 OK\r\n")
            owner._socket = wire
            self.assertEqual(owner._info(b"process/pid"), b"27")
            self.assertEqual(wire.sent, b"GETINFO process/pid\r\n")
        for replies in (
            b"250-version=27\r\n250 OK\r\n",
            b"250-process/pid=27\r\n250-OK\r\n",
        ):
            with self.node() as owner:
                owner._socket = Wire(replies)
                with self.assertRaises(a.s.ProtocolError):
                    owner._info(b"process/pid")

    def test_pid_mismatch_prevents_http_oracle(self):
        with self.node() as owner:
            owner.process = mock.Mock(pid=27, returncode=None)
            owner.process.poll.return_value = None
            owner.process.terminate.side_effect = lambda: setattr(
                owner.process.poll, "return_value", 0
            )
            with mock.patch.object(owner, "ready"):
                with mock.patch.object(owner, "_info", return_value=b"28"):
                    with mock.patch.object(owner, "_fetch") as fetch:
                        with self.assertRaisesRegex(
                            a.StartupError, "^owned-process$"
                        ):
                            owner.prove_loaded_certificate()
                        fetch.assert_not_called()

    def test_listener_mismatch_prevents_http_oracle(self):
        with self.node() as owner:
            owner.process = mock.Mock(pid=27, returncode=None)
            owner.process.poll.return_value = None
            owner.process.terminate.side_effect = lambda: setattr(
                owner.process.poll, "return_value", 0
            )
            values = {
                b"process/pid": b"27",
                b"fingerprint": owner.relay.fingerprint.encode("ascii"),
                b"net/listeners/or": b'"127.0.0.1:19001"',
                b"net/listeners/dir": b'"127.0.0.1:19003"',
            }
            with mock.patch.object(owner, "ready"):
                with mock.patch.object(owner, "_info", side_effect=values.__getitem__):
                    with mock.patch.object(owner, "_fetch") as fetch:
                        with self.assertRaisesRegex(
                            a.StartupError, "^owned-listener$"
                        ):
                            owner.prove_loaded_certificate()
                        fetch.assert_not_called()

    def test_http_exchange_is_bounded_partial_and_owned(self):
        with self.node() as owner:
            wire = Wire(response(owner.certificate))
            with mock.patch.object(a.socket, "socket", return_value=wire):
                owner._fetch(("127.0.0.1", owner.dir_port))
            self.assertTrue(wire.closed)
            self.assertEqual(wire.endpoint, ("127.0.0.1", owner.dir_port))
            self.assertEqual(
                wire.sent,
                b"GET /tor/keys/authority HTTP/1.0\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Accept-Encoding: identity\r\n"
                b"Connection: close\r\n\r\n",
            )
            with mock.patch.object(a.socket, "socket") as create:
                with self.assertRaisesRegex(
                    a.StartupError, "^owned-listener$"
                ):
                    owner._fetch(("127.0.0.2", owner.dir_port))
                create.assert_not_called()

    def test_http_rejects_wrong_body_framing_status_and_eof(self):
        with self.node() as sample:
            body = sample.certificate
        cases = (
            response(body, status=b"HTTP/1.0 404 Not found"),
            response(body, headers=[]),
            response(body, headers=[
                b"Content-Length: " + str(len(body)).encode("ascii"),
                b"Content-Encoding: gzip",
            ]),
            response(body, headers=[
                b"Content-Length: " + str(len(body)).encode("ascii"),
                b"Content-Length: " + str(len(body)).encode("ascii"),
            ]),
            response(body, headers=[
                b"Content-Length: " + str(len(body)).encode("ascii"),
                b"Transfer-Encoding: chunked",
            ]),
            response(b"x" * len(body)),
            response(body)[:-1],
            b"x" * 8192,
        )
        for payload in cases:
            with self.subTest(category="bad-http"):
                with self.node() as owner:
                    wire = Wire(payload)
                    with mock.patch.object(a.socket, "socket", return_value=wire):
                        with self.assertRaises(a.StartupError):
                            owner._fetch(("127.0.0.1", owner.dir_port))
                    self.assertTrue(wire.closed)

    def test_finite_wait_preserves_original_deadline(self):
        owner = SimpleNamespace(deadline=12, process=mock.Mock())
        owner.process.wait.return_value = 0
        with mock.patch.object(a.time, "monotonic", return_value=10):
            self.assertEqual(a._wait_exit(owner), 0)
        self.assertEqual(owner.deadline, 12)
        with mock.patch.object(a.time, "monotonic", return_value=12):
            with self.assertRaises(a.s.DeadlineExceeded):
                a._wait_exit(owner)

    def test_cancellation_simulation_preserves_external_signal_flags(self):
        runner = load("authority_startup_signal_runner", Path(__file__))
        implementation = load(
            "authority_startup_cancelled_copy",
            Path(__file__).with_name("startup.py"),
        )
        owner = SimpleNamespace(deadline=time.monotonic() + 60)
        implementation.s.cancelled = True
        runner.cancel(None, None)
        with self.assertRaises(implementation.s.Cancelled):
            implementation._budget(owner)
        self.assertTrue(runner.a.s.cancelled)
        self.assertTrue(runner.a.m.cancelled)

    def _owned_cancellation_control(self, operation, on_cancel=None):
        implementation = load(
            "authority_startup_owned_cancellation",
            Path(__file__).with_name("startup.py"),
        )
        deadline = time.monotonic() + 60
        process = mock.Mock(returncode=None)
        process.poll.side_effect = lambda: process.returncode
        events = []
        resources = {}
        peers = []
        live_waits = 0
        sends = 0

        def cancel_operation():
            self.assertFalse(implementation.s.cancelled)
            implementation.s.cancelled = True
            if on_cancel is not None:
                on_cancel()
            self.assertTrue(implementation.s.cancelled)

        def assert_retained():
            self.assertTrue(resources["root"].is_dir())
            self.assertFalse(resources["log"].closed)
            self.assertIs(owner.process, process)
            self.assertEqual(owner.deadline, deadline)

        def terminate():
            assert_retained()
            self.assertEqual(events, ["cancel"])
            if operation == "node":
                self.assertEqual(resources["control"].fileno(), -1)
                self.assertEqual(resources["http"].fileno(), -1)
            events.append("terminate")
            process.returncode = -15

        def wait(*, timeout):
            nonlocal live_waits
            self.assertGreaterEqual(timeout, 0)
            if process.returncode is None:
                self.assertEqual(operation, "relay")
                live_waits += 1
                if live_waits != 1:
                    raise AssertionError("cancellation-guard-not-observed")
                self.assertGreater(timeout, 0)
                self.assertLessEqual(timeout, 0.05)
                assert_retained()
                events.append("cancel")
                cancel_operation()
                raise subprocess.TimeoutExpired("owned-preparation", timeout)
            assert_retained()
            self.assertLessEqual(timeout, 2.0)
            if events == ["cancel", "terminate"]:
                events.append("reap")
            else:
                self.assertEqual(events, ["cancel", "terminate", "reap"])
                self.assertEqual(timeout, 0)
            return process.returncode

        process.terminate.side_effect = terminate
        process.wait.side_effect = wait

        if operation == "relay":
            owner = implementation.RelayIdentity("/fixture/tor", deadline)

            def launch(argv, **kwargs):
                self.assertEqual(
                    argv[-4:],
                    ["--defaults-torrc", "/dev/null", "--list-fingerprint", "rsa"],
                )
                self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
                self.assertIs(kwargs["stdout"], owner._log)
                self.assertIs(kwargs["stderr"], owner._log)
                resources["root"] = Path(owner._temp.name)
                resources["log"] = owner._log
                self.assertTrue((resources["root"] / "torrc").is_file())
                self.assertTrue(owner.data.is_dir())
                return process

            try:
                with mock.patch.object(
                    implementation.s.subprocess, "Popen", side_effect=launch
                ):
                    with self.assertRaises(implementation.s.Cancelled):
                        with owner:
                            owner.generate()
                self.assertEqual(live_waits, 1)
                self.assertEqual(process.wait.call_count, 3)
                self.assertEqual(
                    events, ["cancel", "terminate", "reap"]
                )
                self.assertTrue(implementation.s.cancelled)
                self.assertEqual(owner.deadline, deadline)
                self.assertEqual(process.returncode, -15)
                process.terminate.assert_called_once()
                process.kill.assert_not_called()
                self.assertTrue(owner._closed)
                self.assertTrue(resources["log"].closed)
                self.assertFalse(resources["root"].exists())
                self.assertIsNone(owner._log)
                self.assertIsNone(owner._temp)
            finally:
                owner.close()
            return

        self.assertEqual(operation, "node")
        relay = SimpleNamespace(deadline=deadline)
        materials = SimpleNamespace(deadline=deadline)
        owner = implementation.AuthorityNode(
            "/fixture/tor", deadline, relay, materials
        )

        class CancelWire(Wire):
            def __init__(wire_self, retained_socket):
                super().__init__()
                wire_self.retained_socket = retained_socket

            def send(wire_self, payload):
                nonlocal sends
                sends += 1
                if sends != 1:
                    raise AssertionError("cancellation-guard-not-observed")
                assert_retained()
                self.assertNotEqual(resources["control"].fileno(), -1)
                self.assertNotEqual(wire_self.fileno(), -1)
                events.append("cancel")
                cancel_operation()
                return super().send(payload)

            def close(wire_self):
                wire_self.retained_socket.close()
                super().close()

            def fileno(wire_self):
                return wire_self.retained_socket.fileno()

        try:
            owner._temp = tempfile.TemporaryDirectory(
                prefix="authority-cancellation-test-"
            )
            owner._log = tempfile.TemporaryFile(mode="w+b")
            owner.process = process
            owner._cookie = bytes(32)
            resources["root"] = Path(owner._temp.name)
            resources["log"] = owner._log
            control, control_peer = socket.socketpair()
            owner._socket = control
            resources["control"] = control
            peers.append(control_peer)
            http_socket, http_peer = socket.socketpair()
            peers.extend((http_socket, http_peer))
            wire = CancelWire(http_socket)
            resources["http"] = wire
            owner.certificate = b"mechanism-only-public-body\n"
            owner.dir_port = 19002

            with mock.patch.object(
                implementation.socket, "socket", return_value=wire
            ):
                with self.assertRaises(implementation.s.Cancelled):
                    with owner:
                        owner._fetch(("127.0.0.1", 19002))

            self.assertEqual(sends, 1)
            self.assertEqual(process.wait.call_count, 2)
            self.assertEqual(events, ["cancel", "terminate", "reap"])
            self.assertTrue(implementation.s.cancelled)
            self.assertEqual(owner.deadline, deadline)
            self.assertEqual(process.returncode, -15)
            process.terminate.assert_called_once()
            process.kill.assert_not_called()
            self.assertTrue(owner._closed)
            self.assertTrue(wire.closed)
            self.assertEqual(wire.fileno(), -1)
            self.assertEqual(control.fileno(), -1)
            self.assertTrue(resources["log"].closed)
            self.assertFalse(resources["root"].exists())
            self.assertIsNone(owner._socket)
            self.assertIsNone(owner._cookie)
            self.assertIsNone(owner._log)
            self.assertIsNone(owner._temp)
        finally:
            try:
                owner.close()
            finally:
                for peer in peers:
                    peer.close()

    def test_relay_cancellation_unwinds_owned_preparation(self):
        self._owned_cancellation_control("relay")
        runner = load("authority_startup_relay_cancel_runner", Path(__file__))
        case = runner.Controls(
            "test_relay_cancellation_unwinds_owned_preparation"
        )
        self.assertFalse(runner.a.s.cancelled)
        self.assertFalse(runner.a.m.cancelled)
        case._owned_cancellation_control(
            "relay", on_cancel=lambda: runner.cancel(None, None)
        )
        self.assertTrue(runner.a.s.cancelled)
        self.assertTrue(runner.a.m.cancelled)

    def test_node_cancellation_unwinds_owned_http_control_and_child(self):
        self._owned_cancellation_control("node")
        runner = load("authority_startup_node_cancel_runner", Path(__file__))
        case = runner.Controls(
            "test_node_cancellation_unwinds_owned_http_control_and_child"
        )
        self.assertFalse(runner.a.s.cancelled)
        self.assertFalse(runner.a.m.cancelled)
        case._owned_cancellation_control(
            "node", on_cancel=lambda: runner.cancel(None, None)
        )
        self.assertTrue(runner.a.s.cancelled)
        self.assertTrue(runner.a.m.cancelled)


    def test_rejection_requires_nonzero_exit_and_specific_loader_marker(self):
        self.assertEqual(
            a._rejection(1, b"prefix " + a.MISMATCH + b"\n"),
            "signing-key-mismatch",
        )
        for status, log in (
            (0, a.MISMATCH),
            (None, a.MISMATCH),
            (1, b"unrelated configuration failure"),
            (1, b"unable to load authority keys"),
        ):
            with self.subTest(category="not-specific-rejection"):
                with self.assertRaises(a.StartupError):
                    a._rejection(status, log)

    def test_rejection_stops_baseline_before_replacing_and_classifying(self):
        owner = self.node()
        owner._proved = True
        owner.process = mock.Mock(returncode=0)
        owner.process.poll.return_value = 0
        owner._socket = Wire()
        control = owner._socket
        events = []
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            owner.data = root / "data"
            (owner.data / "keys").mkdir(parents=True)
            owner.config_path = root / "torrc"
            owner._config_bytes = b"unchanged-mechanism-config\n"
            owner.config_path.write_bytes(owner._config_bytes)
            certificate = owner.data / "keys" / "authority_certificate"
            certificate.write_bytes(owner.certificate)
            signing = owner.data / "keys" / "authority_signing_key"
            owner._signing = b"baseline-signing"
            signing.write_bytes(owner._signing)
            other_path = root / "other-signing"
            other_path.write_bytes(b"replacement-signing")
            other = SimpleNamespace(
                deadline=owner.deadline,
                _closed=False,
                process=SimpleNamespace(returncode=0),
                _check_file=lambda name: other_path,
            )
            rejected = mock.Mock()

            def stop():
                self.assertTrue(control.closed)
                self.assertEqual(signing.read_bytes(), b"baseline-signing")
                events.append("stop")

            def launch(config, extra):
                self.assertEqual(events, ["stop"])
                self.assertEqual(Path(config).read_bytes(), owner._config_bytes)
                self.assertEqual(certificate.read_bytes(), owner.certificate)
                self.assertEqual(signing.read_bytes(), b"replacement-signing")
                rejected.close.assert_not_called()
                events.append("launch")

            def log(_owner):
                self.assertEqual(events, ["stop", "launch"])
                rejected.close.assert_not_called()
                events.append("classify")
                return a.MISMATCH

            rejected._launch.side_effect = launch
            try:
                with mock.patch.object(owner, "_stop_child", side_effect=stop):
                    with mock.patch.object(
                        a.s, "TorSupervisor", return_value=rejected
                    ):
                        with mock.patch.object(a, "_wait_exit", return_value=1):
                            with mock.patch.object(a, "_private_log", side_effect=log):
                                self.assertEqual(
                                    owner.reject_mismatched_signing_key(other),
                                    "signing-key-mismatch",
                                )
                self.assertEqual(events, ["stop", "launch", "classify"])
                rejected.close.assert_not_called()
            finally:
                owner.close()
            rejected.close.assert_called_once()

    def test_unreaped_rejection_retains_baseline_resources(self):
        owner = self.node()
        owner._temp = tempfile.TemporaryDirectory(prefix="authority-cleanup-test-")
        root = Path(owner._temp.name)
        owner._log = tempfile.TemporaryFile()
        log = owner._log
        owner.rejection = mock.Mock()
        owner.rejection.close.side_effect = a.s.CleanupError("owned-child")
        try:
            with self.assertRaises(a.s.CleanupError):
                owner.close()
            self.assertTrue(root.is_dir())
            self.assertFalse(log.closed)
            self.assertFalse(owner._closed)
        finally:
            owner.rejection.close.side_effect = None
            owner.close()
        self.assertFalse(root.exists())
        self.assertTrue(log.closed)


def released_process(process, log, root):
    if process.returncode is None or not log.closed or Path(root).exists():
        raise AssertionError("owned-resources-remain")


def actual_controls(binary, gencert, deadline):
    with a.m.AuthorityMaterials(gencert, deadline) as good:
        good.generate()
        good_resources = good.process, good._input, good._temp.name
        with a.m.AuthorityMaterials(gencert, deadline) as other:
            other.generate()
            other_resources = other.process, other._input, other._temp.name
            with a.RelayIdentity(binary, deadline) as relay:
                relay.generate()
                relay_resources = relay.process, relay._log, relay._temp.name
                with a.AuthorityNode(binary, deadline, relay, good) as owner:
                    owner.start()
                    positive = (
                        owner.process, owner._socket, owner._log, owner._temp.name
                    )
                    if owner.prove_loaded_certificate() != "loaded-authority-certificate":
                        raise AssertionError("positive-not-executed")
                    http = owner._http
                    if http is None or http.fileno() != -1:
                        raise AssertionError("http-not-released")
                    if owner.process.poll() is not None:
                        raise AssertionError("positive-not-live")
                    if owner.reject_mismatched_signing_key(other) != "signing-key-mismatch":
                        raise AssertionError("negative-not-executed")
                    negative = owner.rejection.process, owner.rejection._log
                    if negative[0].returncode in (None, 0):
                        raise AssertionError("negative-not-rejected")
                released_process(positive[0], positive[2], positive[3])
                if positive[1].fileno() != -1 or http.fileno() != -1:
                    raise AssertionError("node-socket-remains")
                if negative[0].returncode is None or not negative[1].closed:
                    raise AssertionError("negative-resources-remain")
            released_process(*relay_resources)
        if (
            other_resources[0].returncode != 0
            or not other_resources[1].closed
            or Path(other_resources[2]).exists()
        ):
            raise AssertionError("other-materials-remain")
    if (
        good_resources[0].returncode != 0
        or not good_resources[1].closed
        or Path(good_resources[2]).exists()
    ):
        raise AssertionError("good-materials-remain")
    return 1, 1


def cancel(signum, frame):
    a.s.cancelled = True
    a.m.cancelled = True


def report_failures(result, stream):
    allowed = set(unittest.defaultTestLoader.getTestCaseNames(Controls))
    for category, entries in (
        ("FAIL", result.failures), ("ERROR", result.errors)
    ):
        for test, _traceback in entries:
            case = getattr(test, "test_case", test)
            method = getattr(case, "_testMethodName", None)
            identity = (
                "Controls." + method
                if type(case) is Controls and method in allowed
                else "<unknown-test>"
            )
            print(category + " " + identity, file=stream)


def main():
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("TOR_REAL_ISOLATED") != "yes"
    ):
        print("Tor authority startup requires isolated CI", file=sys.stderr)
        return 1
    try:
        deadline = float(os.environ["TOR_REAL_DEADLINE"])
        binary = os.environ["TOR_REAL_BINARY"]
        gencert = os.environ["TOR_REAL_GENCERT_BINARY"]
        if not math.isfinite(deadline) or deadline <= time.monotonic():
            raise ValueError()
    except (KeyError, ValueError):
        print("Tor authority startup has no valid operation input", file=sys.stderr)
        return 1
    previous = {
        sig: signal.signal(sig, cancel)
        for sig in (signal.SIGTERM, signal.SIGINT)
    }
    try:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(Controls)
        result = unittest.TextTestRunner(stream=io.StringIO()).run(suite)
        if result.testsRun != 15 or not result.wasSuccessful():
            print("Tor authority startup mechanism controls failed", file=sys.stderr)
            report_failures(result, sys.stderr)
            return 1
        print(f"Tor authority startup mechanism controls passed: {result.testsRun}")
        positive, rejection = actual_controls(binary, gencert, deadline)
        if (positive, rejection) != (1, 1):
            raise AssertionError("actual-control-count")
        print("Tor authority loaded certificate controls passed: " + str(positive))
        print("Tor authority signing-key-mismatch controls passed: " + str(rejection))
        return 0
    except (a.s.Cancelled, a.m.Cancelled):
        print("Tor authority startup cancelled", file=sys.stderr)
        return 143
    except (a.s.DeadlineExceeded, a.m.DeadlineExceeded):
        print("Tor authority startup deadline", file=sys.stderr)
        return 1
    except (a.s.CleanupError, a.m.CleanupError):
        print("Tor authority startup cleanup", file=sys.stderr)
        return 1
    except Exception:
        print("Tor authority startup failed", file=sys.stderr)
        return 1
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


if __name__ == "__main__":
    raise SystemExit(main())
