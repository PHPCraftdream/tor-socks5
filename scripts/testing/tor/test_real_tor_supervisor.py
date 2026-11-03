"""CI-only unit controls and actual pinned-Tor control readiness checks."""

import importlib.util
import io
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "real_tor_supervisor", Path(__file__).with_name("real_tor_supervisor.py")
)
s = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(s)


class Wire:
    def __init__(self, replies=b""):
        self.replies = bytearray(replies)
        self.sent = bytearray()
        self.closed = False
        self.reads = 0

    def settimeout(self, timeout):
        if timeout <= 0 or timeout > 0.05:
            raise AssertionError("unbounded socket operation")

    def send(self, payload):
        count = min(3, len(payload))
        self.sent.extend(payload[:count])
        return count

    def recv(self, count):
        self.reads += 1
        data = bytes(self.replies[:count])
        del self.replies[:count]
        return data

    def fileno(self):
        return -1 if self.closed else 1

    def close(self):
        self.closed = True


class Controls(unittest.TestCase):
    def owner(self):
        return s.TorSupervisor("/fixture/tor", time.monotonic() + 60)

    def test_exact_authentication_and_version_exchange(self):
        owner = self.owner()
        owner._cookie = bytes(range(32))
        wire = Wire(b"250 OK\r\n250-version=0.4.9.15\r\n250 OK\r\n")
        owner._socket = wire
        self.assertEqual(owner.ready(), "0.4.9.15")
        self.assertEqual(
            wire.sent,
            b"AUTHENTICATE " + bytes(range(32)).hex().encode("ascii")
            + b"\r\nGETINFO version\r\n",
        )
        owner.close()
        self.assertTrue(wire.closed)

    def test_actual_authentication_failure_shape(self):
        owner = self.owner()
        owner._socket = Wire(
            b"515 Authentication failed: Wrong length on authentication cookie.\r\n"
        )
        with self.assertRaises(s.AuthError):
            owner._read_ok()
        owner.close()

    def test_malformed_version_and_terminator(self):
        for response in (
            b"250 OK\r\n250-version=0.4.9.16\r\n250 OK\r\n",
            b"250 OK\r\n250-version=0.4.9.15x\r\n250 OK\r\n",
            b"250 OK\r\n250-version=0.4.9.15\r\n250-OK\r\n",
            b"250 OK\r\nnot-a-version\r\n",
        ):
            with self.subTest(response=response):
                with self.owner() as owner:
                    owner._cookie = bytes(32)
                    owner._socket = Wire(response)
                    with self.assertRaises(s.ProtocolError):
                        owner.ready()

    def test_bounded_line_and_eof(self):
        for response in (b"x" * 4096, b"250 OK\n", b""):
            with self.owner() as owner:
                owner._socket = Wire(response)
                with self.assertRaises(s.ProtocolError):
                    owner._read_line()

    def test_original_deadline_is_not_renewed(self):
        with mock.patch.object(s.time, "monotonic", return_value=10):
            owner = s.TorSupervisor("/fixture/tor", 12)
            self.assertEqual(owner._remaining(), 2)
        with mock.patch.object(s.time, "monotonic", return_value=12):
            with self.assertRaises(s.DeadlineExceeded):
                owner._remaining()
        self.assertEqual(owner.deadline, 12)

    def test_child_exit_is_observed_before_socket_io(self):
        owner = self.owner()
        owner.process = mock.Mock()
        owner.process.poll.return_value = 7
        owner._socket = Wire(b"250 OK\r\n")
        with self.assertRaises(s.ChildExit):
            owner._read_ok()
        self.assertEqual(owner._socket.reads, 0)
        owner.close()

    def test_configuration_and_no_unsolicited_greeting(self):
        owner = self.owner()
        process = mock.Mock()
        process.poll.return_value = None
        wire = Wire()

        def launch(argv, **kwargs):
            config = Path(argv[2]).read_text(encoding="utf-8")
            self.assertIn("RunAsDaemon 0\n", config)
            self.assertIn("DataDirectory ", config)
            self.assertIn("ControlSocket ", config)
            self.assertIn("CookieAuthentication 1\n", config)
            self.assertIn("DisableNetwork 1\n", config)
            cookie = Path(owner._temp.name) / "cookie"
            cookie.write_bytes(bytes(32))
            self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
            self.assertIs(kwargs["stdout"], owner._log)
            self.assertIs(kwargs["stderr"], owner._log)
            return process

        wire.connect = mock.Mock()
        process.wait.side_effect = lambda **kwargs: setattr(
            process.poll, "return_value", 0
        )
        with mock.patch.object(s.subprocess, "Popen", side_effect=launch):
            with mock.patch.object(s.socket, "socket", return_value=wire):
                with owner:
                    owner.start()
                    self.assertEqual(wire.reads, 0)

    def test_launch_failure_releases_actual_allocations(self):
        owner = self.owner()
        with mock.patch.object(s.subprocess, "Popen", side_effect=OSError()):
            with self.assertRaises(OSError):
                with owner:
                    owner.start()
        self.assertTrue(owner._closed)
        self.assertIsNone(owner._temp)
        self.assertIsNone(owner._log)

    def test_cleanup_escalates_and_reaps_retained_handle(self):
        owner = self.owner()
        process = mock.Mock()
        process.poll.side_effect = [None, 0]
        process.wait.side_effect = [
            subprocess.TimeoutExpired("fixture", 2), 0, 0
        ]
        owner.process = process
        owner._socket = Wire()
        wire = owner._socket
        owner._log = tempfile.TemporaryFile()
        log = owner._log
        owner.close()
        process.terminate.assert_called_once()
        process.kill.assert_called_once()
        self.assertEqual(process.wait.call_count, 3)
        self.assertLessEqual(process.wait.call_args_list[0].kwargs["timeout"], 2)
        self.assertLessEqual(process.wait.call_args_list[1].kwargs["timeout"], 5)
        self.assertTrue(wire.closed)
        self.assertTrue(log.closed)
        self.assertTrue(owner._closed)

    def test_unreaped_child_is_not_silently_discarded(self):
        owner = self.owner()
        owner.process = mock.Mock()
        owner.process.poll.return_value = None
        owner.process.wait.side_effect = subprocess.TimeoutExpired("fixture", 2)
        owner._temp = tempfile.TemporaryDirectory(prefix="tor-control-test-")
        root = owner._temp.name
        owner._log = tempfile.TemporaryFile()
        try:
            with self.assertRaises(s.CleanupError):
                owner.close()
            self.assertFalse(owner._closed)
            self.assertTrue(Path(root).is_dir())
            self.assertFalse(owner._log.closed)
        finally:
            owner.process.poll.return_value = 0
            owner.process.wait.side_effect = None
            owner.close()
        self.assertFalse(Path(root).exists())

    def test_actual_controls_accepts_synchronous_termination(self):
        owners = [self.owner() for _ in range(3)]
        transcripts = (
            b"250 OK\r\n250-version=0.4.9.15\r\n250 OK\r\n",
            b"515 Authentication failed: Wrong length on authentication cookie.\r\n",
            b"",
        )
        resources = []
        try:
            for owner, transcript in zip(owners, transcripts):
                process = mock.Mock(returncode=None)
                process.poll.side_effect = lambda p=process: p.returncode

                def terminate(p=process):
                    p.returncode = 0

                def wait(*, timeout, p=process):
                    self.assertIsNotNone(p.returncode)
                    return p.returncode

                process.terminate.side_effect = terminate
                process.wait.side_effect = wait
                owner.process = process
                owner._socket = Wire(transcript)
                owner._log = tempfile.TemporaryFile()
                owner._temp = tempfile.TemporaryDirectory()
                owner._cookie = bytes(32)
                owner.start = mock.Mock(return_value=owner)
                resources.append(owned_resources(owner))

            with mock.patch.object(s, "TorSupervisor", side_effect=owners) as factory:
                actual_controls("/fixture/tor", time.monotonic() + 60)

            self.assertEqual(factory.call_count, 3)
            for resource in resources:
                assert_released(resource)
                resource[0].terminate.assert_called_once()

            waits = owners[2].process.wait.call_args_list
            self.assertEqual(len(waits), 2)
            self.assertGreater(waits[0].kwargs["timeout"], 0)
            self.assertLessEqual(waits[0].kwargs["timeout"], 5)
            self.assertEqual(waits[1].kwargs["timeout"], 0)
            self.assertEqual(resources[2][1].reads, 0)
        finally:
            for owner in owners:
                owner.close()

    def test_report_unit_failures_uses_stable_names(self):
        subtest = mock.Mock(test_case=self)
        subtest.id.side_effect = AssertionError("must not call id")
        result = mock.Mock()
        result.failures = [(self, "secret failure")]
        result.errors = [
            (subtest, "secret subtest failure"),
            (object(), "secret unknown failure"),
        ]
        stream = io.StringIO()

        report_unit_failures(result, stream)

        identity = "Controls." + self._testMethodName
        self.assertEqual(
            stream.getvalue(),
            "FAIL " + identity + "\n"
            "ERROR " + identity + "\n"
            "ERROR <unknown-test>\n",
        )

    def _cancellation_control(self, on_check=None):
        spec = importlib.util.spec_from_file_location(
            "real_tor_supervisor_cancellation",
            Path(__file__).with_name("real_tor_supervisor.py"),
        )
        implementation = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(implementation)
        owner = implementation.TorSupervisor(
            "/fixture/tor", time.monotonic() + 60
        )
        owner._socket = Wire()
        wire = owner._socket
        implementation.cancelled = True
        with self.assertRaises(implementation.Cancelled):
            with owner:
                if on_check is not None:
                    on_check()
                owner._check()
        self.assertTrue(wire.closed)
        self.assertTrue(owner._closed)

    def test_cancellation_unwinds_context(self):
        self._cancellation_control()
        spec = importlib.util.spec_from_file_location(
            "real_tor_supervisor_cancellation_runner", Path(__file__)
        )
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        case = runner.Controls("test_cancellation_unwinds_context")
        self.assertFalse(runner.s.cancelled)
        case._cancellation_control(
            on_check=lambda: runner.cancel(None, None)
        )
        self.assertTrue(runner.s.cancelled)


def owned_resources(owner):
    return owner.process, owner._socket, owner._log, owner._temp.name


def assert_released(resources):
    process, sock, log, root = resources
    if (
        process.returncode is None
        or sock.fileno() != -1
        or not log.closed
        or Path(root).exists()
    ):
        raise s.CleanupError("owned fixture resources remain")


def actual_controls(binary, deadline):
    with s.TorSupervisor(binary, deadline) as owner:
        owner.start()
        resources = owned_resources(owner)
        owner.ready()
        if owner.version is None:
            raise AssertionError("authenticated version was not retained")
    assert_released(resources)

    with s.TorSupervisor(binary, deadline) as owner:
        owner.start()
        resources = owned_resources(owner)
        owner._send_line(b"AUTHENTICATE")
        try:
            owner._read_ok()
        except s.AuthError:
            pass
        else:
            raise AssertionError("Tor accepted missing authentication")
    assert_released(resources)

    with s.TorSupervisor(binary, deadline) as owner:
        owner.start()
        resources = owned_resources(owner)
        wait_budget = min(5.0, owner._remaining())
        owner.process.terminate()
        owner.process.wait(timeout=wait_budget)
        try:
            owner.ready()
        except s.ChildExit:
            pass
        else:
            raise AssertionError("owned child exit was not detected")
    assert_released(resources)


def cancel(signum, frame):
    s.cancelled = True


def report_unit_failures(result, stream):
    allowed_methods = set(unittest.defaultTestLoader.getTestCaseNames(Controls))
    for category, entries in (
        ("FAIL", result.failures),
        ("ERROR", result.errors),
    ):
        for test, _traceback in entries:
            case = getattr(test, "test_case", test)
            method = getattr(case, "_testMethodName", None)
            if type(case) is Controls and method in allowed_methods:
                identity = "Controls." + method
            else:
                identity = "<unknown-test>"
            print(category + " " + identity, file=stream)


def main():
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("TOR_REAL_ISOLATED") != "yes"
    ):
        print("Tor control checks require isolated CI", file=sys.stderr)
        return 1
    try:
        deadline = float(os.environ["TOR_REAL_DEADLINE"])
        if not math.isfinite(deadline) or deadline <= time.monotonic():
            raise ValueError()
        binary = os.environ["TOR_REAL_BINARY"]
    except (KeyError, ValueError):
        print("Tor control checks have no valid operation budget", file=sys.stderr)
        return 1
    previous = {
        sig: signal.signal(sig, cancel) for sig in (signal.SIGTERM, signal.SIGINT)
    }
    try:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(Controls)
        result = unittest.TextTestRunner(stream=io.StringIO()).run(suite)
        if result.testsRun == 0 or not result.wasSuccessful():
            print("Tor supervisor unit controls failed", file=sys.stderr)
            report_unit_failures(result, sys.stderr)
            return 1
        print(f"Tor supervisor unit controls passed: {result.testsRun}")
        actual_controls(binary, deadline)
        print("Tor authenticated control readiness and negative controls passed")
        return 0
    except s.Cancelled:
        print("Tor control checks cancelled", file=sys.stderr)
        return 143
    except Exception:
        print("Tor control checks failed", file=sys.stderr)
        return 1
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


if __name__ == "__main__":
    raise SystemExit(main())
