"""CI-only mechanism controls and genuine pinned-tool material checks."""

import importlib.util
import io
import math
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "authority_materials", Path(__file__).with_name("materials.py")
)
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def released(owner, root, input_file):
    if (
        owner.process is not None
        and owner.process.returncode is None
    ):
        raise AssertionError("child-not-reaped")
    if (
        not owner._closed
        or Path(root).exists()
        or not input_file.closed
        or owner.metadata is not None
    ):
        raise AssertionError("resources-not-released")


class Controls(unittest.TestCase):
    def owner(self):
        return m.AuthorityMaterials(
            "/fixture/tor-gencert", time.monotonic() + 60
        )

    def test_exact_launch_and_finite_stdin(self):
        owner = self.owner()
        process = mock.Mock(returncode=0)
        process.poll.return_value = 0
        process.wait.return_value = 0
        captured = {}

        def launch(argv, **kwargs):
            self.assertEqual(
                argv,
                [
                    "/fixture/tor-gencert",
                    "--create-identity-key",
                    "--passphrase-fd", "0",
                    "-i", "authority_identity_key",
                    "-s", "authority_signing_key",
                    "-c", "authority_certificate",
                    "-m", "1",
                ],
            )
            self.assertEqual(kwargs["cwd"], owner._temp.name)
            self.assertIs(kwargs["stdin"], owner._input)
            self.assertEqual(kwargs["stdout"], subprocess.DEVNULL)
            self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
            self.assertTrue(kwargs["close_fds"])
            self.assertNotIn("input", kwargs)
            stream = kwargs["stdin"]
            self.assertTrue(stat.S_ISREG(os.fstat(stream.fileno()).st_mode))
            self.assertEqual(stream.tell(), 0)
            payload = stream.read()
            self.assertEqual(len(payload), 65)
            self.assertEqual(payload[-1:], b"\n")
            self.assertEqual(stream.read(), b"")
            stream.seek(0)
            captured["root"] = owner._temp.name
            captured["input"] = stream
            return process

        with mock.patch.object(m.subprocess, "Popen", side_effect=launch):
            with mock.patch.object(owner, "_validate"):
                with owner:
                    self.assertIs(owner.generate(), owner)
                    self.assertIs(owner.process, process)
        released(owner, captured["root"], captured["input"])
        process.communicate.assert_not_called()

    def test_launch_error_cleans_allocations(self):
        owner = self.owner()
        captured = {}

        def launch(*args, **kwargs):
            captured["root"] = owner._temp.name
            captured["input"] = owner._input
            raise OSError("not-for-diagnostics")

        with mock.patch.object(m.subprocess, "Popen", side_effect=launch):
            with self.assertRaises(OSError):
                owner.generate()
        released(owner, captured["root"], captured["input"])

    def test_original_deadline_is_not_renewed(self):
        with mock.patch.object(m.time, "monotonic", return_value=10):
            owner = m.AuthorityMaterials("/fixture/tor-gencert", 12)
            self.assertEqual(owner._remaining(), 2)
        with mock.patch.object(m.time, "monotonic", return_value=12):
            with self.assertRaises(m.DeadlineExceeded):
                owner.generate()
        self.assertEqual(owner.deadline, 12)
        self.assertIsNone(owner.process)
        self.assertIsNone(owner._temp)
        owner.close()

    def run_interrupted(self, failure, on_wait=None):
        spec = importlib.util.spec_from_file_location(
            "authority_materials_interruption",
            Path(__file__).with_name("materials.py"),
        )
        implementation = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(implementation)
        simulate_cancellation = failure is m.Cancelled
        expected = (
            implementation.Cancelled
            if simulate_cancellation
            else implementation.DeadlineExceeded
        )
        owner = implementation.AuthorityMaterials(
            "/fixture/tor-gencert", time.monotonic() + 60
        )
        process = mock.Mock(returncode=None)
        process.poll.side_effect = lambda: process.returncode
        captured = {}

        def launch(*args, **kwargs):
            captured["root"] = owner._temp.name
            captured["input"] = owner._input
            return process

        def wait(*, timeout):
            if process.returncode is not None:
                return process.returncode
            if simulate_cancellation:
                implementation.cancelled = True
            else:
                owner.deadline = time.monotonic() - 0.01
            if on_wait is not None:
                on_wait()
            raise subprocess.TimeoutExpired("owned-tool", timeout)

        def terminate():
            process.returncode = -15

        process.wait.side_effect = wait
        process.terminate.side_effect = terminate
        try:
            with mock.patch.object(
                implementation.subprocess, "Popen", side_effect=launch
            ):
                with self.assertRaises(expected):
                    owner.generate()
            released(owner, captured["root"], captured["input"])
            process.terminate.assert_called_once()
            process.kill.assert_not_called()
        finally:
            owner.close()

    def test_cancellation_reaps_and_cleans(self):
        self.run_interrupted(m.Cancelled)

    def test_simulation_preserves_external_cancellation(self):
        spec = importlib.util.spec_from_file_location(
            "authority_materials_cancellation_runner", Path(__file__)
        )
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        case = runner.Controls("test_cancellation_reaps_and_cleans")
        self.assertFalse(runner.m.cancelled)
        case.run_interrupted(
            runner.m.Cancelled,
            on_wait=lambda: runner.cancel(None, None),
        )
        self.assertTrue(runner.m.cancelled)

    def test_deadline_reaps_and_cleans(self):
        self.run_interrupted(m.DeadlineExceeded)

    def test_cleanup_escalates_on_exact_handle(self):
        owner = self.owner()
        process = mock.Mock(returncode=None)
        process.poll.return_value = None
        process.wait.side_effect = [
            subprocess.TimeoutExpired("owned-tool", 2), 0, 0
        ]
        process.kill.side_effect = lambda: setattr(process, "returncode", -9)
        owner.process = process
        owner.close()
        process.terminate.assert_called_once()
        process.kill.assert_called_once()
        self.assertEqual(process.wait.call_count, 3)
        self.assertLessEqual(process.wait.call_args_list[0].kwargs["timeout"], 2)
        self.assertLessEqual(process.wait.call_args_list[1].kwargs["timeout"], 5)
        self.assertTrue(owner._closed)

    def test_unreaped_child_retains_private_resources(self):
        owner = self.owner()
        captured = {}
        process = mock.Mock(returncode=None)
        process.poll.return_value = None

        def launch(*args, **kwargs):
            captured["root"] = owner._temp.name
            captured["input"] = owner._input
            return process

        process.wait.side_effect = subprocess.TimeoutExpired("owned-tool", 0)
        try:
            with mock.patch.object(m.subprocess, "Popen", side_effect=launch):
                with mock.patch.object(
                    owner, "_remaining", side_effect=m.Cancelled("cancelled")
                ):
                    with self.assertRaises(m.Cancelled):
                        owner.generate()
            self.assertIsNone(owner.process)
            with mock.patch.object(m.subprocess, "Popen", side_effect=launch):
                with mock.patch.object(
                    owner,
                    "_remaining",
                    side_effect=[60, 60, m.Cancelled("cancelled")],
                ):
                    with self.assertRaises(m.CleanupError):
                        owner.generate()
            self.assertIs(owner.process, process)
            self.assertFalse(owner._closed)
            self.assertTrue(Path(captured["root"]).is_dir())
            self.assertFalse(captured["input"].closed)
        finally:
            process.poll.return_value = 0
            process.returncode = 0
            process.wait.side_effect = None
            owner.close()
        released(owner, captured["root"], captured["input"])

    def test_nonzero_exit_cannot_validate_or_succeed(self):
        owner = self.owner()
        process = mock.Mock(returncode=7)
        process.poll.return_value = 7
        process.wait.return_value = 7
        with mock.patch.object(m.subprocess, "Popen", return_value=process):
            with mock.patch.object(owner, "_validate") as validate:
                with self.assertRaisesRegex(m.MaterialsError, "^tool-exit$"):
                    owner.generate()
                validate.assert_not_called()
        self.assertTrue(owner._closed)

    def test_invalid_certificate_inputs_fail_closed(self):
        for data in (b"", b"fingerprint " + b"A" * 40, b"\xff", b"x" * 16385):
            with self.assertRaises(m.MaterialsError):
                m.certificate_metadata(data)

    def test_reporting_never_formats_exception_or_subtest(self):
        suite = unittest.TestSuite()
        suite.addTest(Controls("test_invalid_certificate_inputs_fail_closed"))
        case = suite._tests[0]
        result = unittest.TestResult()
        result.failures = [(case, "secret traceback")]
        result.errors = [(object(), "secret path")]
        stream = io.StringIO()
        report_failures(result, stream)
        self.assertEqual(
            stream.getvalue(),
            "FAIL Controls.test_invalid_certificate_inputs_fail_closed\n"
            "ERROR <unknown-test>\n",
        )


def actual_controls(binary, deadline):
    with m.AuthorityMaterials(binary, deadline) as owner:
        owner.generate()
        root = owner._temp.name
        input_file = owner._input
        process = owner.process
        if process.returncode != 0:
            raise AssertionError("genuine-tool-positive")
        if set(owner.metadata) != {
            "v3_identity_fingerprint", "published", "expires"
        }:
            raise AssertionError("metadata-contract")
        certificate_path = Path(root) / "authority_certificate"
        certificate = certificate_path.read_bytes()
        metadata = m.certificate_metadata(certificate)
        if metadata != owner.metadata:
            raise AssertionError("metadata-not-from-material")
        fingerprint = metadata["v3_identity_fingerprint"].encode("ascii")
        mutations = (
            certificate.replace(b"dir-key-certificate-version 3", b"dir-key-certificate-version 2", 1),
            certificate.replace(fingerprint, b"Z" * 40, 1),
            certificate.replace(b"dir-key-crosscert\n", b"", 1),
            certificate.replace(b"dir-key-certification\n", b"", 1),
            certificate.replace(b"-----END SIGNATURE-----\n", b"", 1),
            certificate.replace(
                metadata["expires"].encode("ascii"),
                metadata["published"].encode("ascii"),
                1,
            ),
            certificate + b"unexpected\n",
        )
        for malformed in mutations:
            try:
                m.certificate_metadata(malformed)
            except m.MaterialsError:
                pass
            else:
                raise AssertionError("malformed-certificate-accepted")
        certificate_path.write_bytes(b"malformed\n")
        try:
            owner._validate()
        except m.MaterialsError:
            pass
        else:
            raise AssertionError("malformed-output-accepted")
        certificate_path.write_bytes(certificate)
        signing = Path(root) / "authority_signing_key"
        signing.unlink()
        try:
            owner._validate()
        except (m.MaterialsError, OSError):
            pass
        else:
            raise AssertionError("missing-output-accepted")
    released(owner, root, input_file)
    print("Tor authority genuine production and output rejection passed: 1")

    real_popen = m.subprocess.Popen
    captured = {}
    owner = m.AuthorityMaterials(binary, deadline)

    def occupied_identity(argv, **kwargs):
        captured["root"] = owner._temp.name
        captured["input"] = owner._input
        path = Path(kwargs["cwd"]) / "authority_identity_key"
        path.write_bytes(b"occupied\n")
        path.chmod(0o400)
        return real_popen(argv, **kwargs)

    with mock.patch.object(m.subprocess, "Popen", side_effect=occupied_identity):
        try:
            owner.generate()
        except m.MaterialsError as error:
            if type(error) is not m.MaterialsError or str(error) != "tool-exit":
                raise
        else:
            raise AssertionError("existing-identity-accepted")
    if owner.process is None or owner.process.returncode in (None, 0):
        raise AssertionError("genuine-failure-not-observed")
    released(owner, captured["root"], captured["input"])
    print("Tor authority genuine tool failure and cleanup passed: 1")


def cancel(signum, frame):
    m.cancelled = True


def report_failures(result, stream):
    allowed = set(unittest.defaultTestLoader.getTestCaseNames(Controls))
    for category, entries in (
        ("FAIL", result.failures), ("ERROR", result.errors)
    ):
        for test, _traceback in entries:
            case = getattr(test, "test_case", test)
            method = getattr(case, "_testMethodName", None)
            if type(case) is Controls and method in allowed:
                identity = "Controls." + method
            else:
                identity = "<unknown-test>"
            print(category + " " + identity, file=stream)


def main():
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("TOR_REAL_ISOLATED") != "yes"
    ):
        print("Tor authority checks require isolated CI", file=sys.stderr)
        return 1
    try:
        deadline = float(os.environ["TOR_REAL_DEADLINE"])
        binary = os.environ["TOR_REAL_GENCERT_BINARY"]
        if not math.isfinite(deadline) or deadline <= time.monotonic():
            raise ValueError()
    except (KeyError, ValueError):
        print("Tor authority checks have no valid operation input", file=sys.stderr)
        return 1
    previous = {
        sig: signal.signal(sig, cancel)
        for sig in (signal.SIGTERM, signal.SIGINT)
    }
    try:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(Controls)
        result = unittest.TextTestRunner(stream=io.StringIO()).run(suite)
        if result.testsRun != 11 or not result.wasSuccessful():
            print("Tor authority mechanism controls failed", file=sys.stderr)
            report_failures(result, sys.stderr)
            return 1
        print(f"Tor authority mechanism controls passed: {result.testsRun}")
        actual_controls(binary, deadline)
        return 0
    except m.Cancelled:
        print("Tor authority checks cancelled", file=sys.stderr)
        return 143
    except m.DeadlineExceeded:
        print("Tor authority checks deadline", file=sys.stderr)
        return 1
    except m.CleanupError:
        print("Tor authority checks cleanup", file=sys.stderr)
        return 1
    except m.MaterialsError as error:
        label = error.args[0] if len(error.args) == 1 else None
        if type(label) is not str or label not in (
            "certificate-format", "isolated-ci-required", "absolute-tool-required",
            "invalid-deadline", "output-file", "private-directory",
            "private-key-format", "single-use", "tool-exit",
        ):
            label = "materials"
        print("Tor authority checks " + label, file=sys.stderr)
        return 1
    except Exception:
        print("Tor authority checks failed", file=sys.stderr)
        return 1
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


if __name__ == "__main__":
    raise SystemExit(main())
