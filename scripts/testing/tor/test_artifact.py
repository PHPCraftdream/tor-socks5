#!/usr/bin/env python3
"""CI-only controls for mandatory owned-stream artifact wiring."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest


if os.environ.get("GITHUB_ACTIONS") != "true":
    raise SystemExit("Tor artifact controls require CI")

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location(
    "tor_stream_artifact", Path(__file__).with_name("artifact.py")
)
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


class ArtifactControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.binary = self.root / "owned-stream-test"
        self.binary.write_bytes(b"fixture")
        self.binary.chmod(0o700)
        self.message = {
            "reason": "compiler-artifact",
            "manifest_path": str(
                self.root / "packages/arti-wrapper/Cargo.toml"
            ),
            "target": {
                "name": "owned_stream",
                "kind": ["test"],
                "crate_types": ["bin"],
                "src_path": str(
                    self.root / "packages/arti-wrapper/tests/owned_stream.rs"
                ),
            },
            "profile": {"test": True},
            "executable": str(self.binary),
        }
        self.finished = {"reason": "build-finished", "success": True}

    def select(self, messages):
        data = "".join(json.dumps(message) + "\n" for message in messages)
        return a.select(io.BytesIO(data.encode()), self.root)

    def test_exact_executable_and_unrelated_artifact(self):
        unrelated = copy.deepcopy(self.message)
        unrelated["target"]["name"] = "other"
        self.assertEqual(
            self.select([unrelated, self.message, self.finished]),
            str(self.binary),
        )

    def test_missing_duplicate_and_unsuccessful_build(self):
        cases = (
            [self.finished],
            [self.message],
            [self.message, self.message, self.finished],
            [self.message, self.finished, self.finished],
            [self.message, {"reason": "build-finished", "success": False}],
        )
        for messages in cases:
            with self.subTest(messages=messages):
                with self.assertRaises(ValueError):
                    self.select(messages)

    def test_wrong_target_profile_and_owner(self):
        changes = (
            ("manifest_path", str(self.root / "apps/socks5-proxy/Cargo.toml")),
            ("manifest_path", "packages/arti-wrapper/Cargo.toml"),
            ("executable", "relative-owned-stream"),
            ("executable", str(self.binary) + "\nforged=value"),
            ("executable", str(self.root / "missing")),
            ("profile", {"test": False}),
            ("profile", {"test": 1}),
            ("profile", []),
        )
        for key, value in changes:
            message = copy.deepcopy(self.message)
            message[key] = value
            with self.subTest(key=key, value=value):
                with self.assertRaises(ValueError):
                    self.select([message, self.finished])
        for key, value in (
            ("kind", ["bin"]),
            ("crate_types", ["lib"]),
            ("src_path", str(self.root / "packages/other/tests/owned_stream.rs")),
        ):
            message = copy.deepcopy(self.message)
            message["target"][key] = value
            with self.subTest(target_key=key):
                with self.assertRaises(ValueError):
                    self.select([message, self.finished])

    def test_duplicate_with_one_wrong_owner_is_not_ignored(self):
        wrong = copy.deepcopy(self.message)
        wrong["manifest_path"] = str(self.root / "packages/other/Cargo.toml")
        with self.assertRaises(ValueError):
            self.select([self.message, wrong, self.finished])

    def test_nonexecutable_and_symlink_rejected(self):
        self.binary.chmod(0o600)
        with self.assertRaises(ValueError):
            self.select([self.message, self.finished])
        self.binary.chmod(0o700)
        link = self.root / "linked-test"
        link.symlink_to(self.binary)
        self.message["executable"] = str(link)
        with self.assertRaises(ValueError):
            self.select([self.message, self.finished])

    def test_malformed_messages_and_limits(self):
        for data in (b"", b"{\n", b"[]\n", b"null\n", b"\xff\n"):
            with self.subTest(data=data):
                with self.assertRaises((ValueError, UnicodeError)):
                    a.select(io.BytesIO(data), self.root)
        with self.assertRaises(ValueError):
            a.select(io.BytesIO(b"x" * (a.LINE_LIMIT + 1)), self.root)

    def test_exact_ignored_inventory(self):
        good = (
            "real_private_stream::owned_three_hop_round_trip: test\n"
            "\n1 test, 0 benchmarks\n"
        )
        a.ignored(io.BytesIO(good.encode()))
        for bad in (
            "",
            "0 tests, 0 benchmarks\n",
            good.replace("owned_three_hop_round_trip", "other"),
            good.replace("1 test", "2 tests"),
            good + "other: test\n",
        ):
            with self.subTest(inventory=bad):
                with self.assertRaises(ValueError):
                    a.ignored(io.BytesIO(bad.encode()))

    def test_actual_mechanism_result_is_required(self):
        good = (
            "running 18 tests\n"
            "test result: ok. 17 passed; 0 failed; 1 ignored; "
            "0 measured; 0 filtered out; finished in 0.01s\n"
        )
        output = io.StringIO()
        a.mechanisms(io.BytesIO(good.encode()), output)
        self.assertIn(
            "Tor owned stream Rust mechanism controls passed: 17\n",
            output.getvalue(),
        )
        for bad in (
            "",
            "running 18 tests\n",
            good.replace("17 passed", "16 passed"),
            good.replace("0 failed", "1 failed"),
            good.replace("1 ignored", "0 ignored"),
            good.replace("0 filtered out", "1 filtered out"),
            good.replace("result: ok", "result: FAILED"),
            good + good,
        ):
            output = io.StringIO()
            with self.subTest(result=bad):
                with self.assertRaises(ValueError):
                    a.mechanisms(io.BytesIO(bad.encode()), output)
                self.assertNotIn(
                    "Tor owned stream Rust mechanism controls passed: 17\n",
                    output.getvalue(),
                )

    def test_actual_workflow_and_runner_wiring(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        job = workflow.split("\n  real-tor-channel:\n", 1)[1]
        job = job.split("\n  pt-proxy-contract:\n", 1)[0]
        self.assertIn("timeout-minutes: 50", job)
        self.assertIn(
            "cargo test -p arti-wrapper --test owned_stream "
            "--locked --no-run --message-format=json",
            job,
        )
        self.assertIn(
            'python3 -I scripts/testing/tor/artifact.py select '
            '"$work/stream-artifacts.json" > "$work/stream-path"',
            job,
        )
        self.assertIn('echo "stream=$(<"$work/stream-path")"', job)
        self.assertIn(
            'TOR_REAL_STREAM_BINARY="${{ steps.real-build.outputs.stream }}"',
            job,
        )
        self.assertIn(
            "TOR_REAL_STREAM_BINARY: ${{ steps.real-build.outputs.stream }}",
            job,
        )
        self.assertIn("--signal=TERM --kill-after=15s 10m", job)
        runner = (ROOT / "scripts/testing/tor/real-tor-channel.sh").read_text()
        self.assertIn(': "${TOR_REAL_STREAM_BINARY:?}"', runner)
        self.assertIn(
            '"$TOR_REAL_STREAM_BINARY" --ignored --list --format terse | '
            "python3 -I scripts/testing/tor/artifact.py ignored",
            runner,
        )
        mechanisms = (
            '"$TOR_REAL_STREAM_BINARY" --nocapture | '
            "python3 -I scripts/testing/tor/artifact.py mechanisms"
        )
        self.assertIn(mechanisms, runner)
        self.assertLess(
            runner.index(mechanisms),
            runner.index("python3 -I scripts/testing/tor/authority/test_consensus.py"),
        )
        self.assertIn(
            '"$TOR_REAL_TEST_BINARY" --ignored --exact "$test_name" --nocapture',
            runner,
        )
        mutations = (
            ROOT / "scripts/testing/tor/real-tor-mutations.sh"
        ).read_text()
        self.assertIn(': "${TOR_REAL_STREAM_BINARY:?}"', mutations)
        self.assertIn(
            'TOR_REAL_STREAM_BINARY="$TOR_REAL_STREAM_BINARY" \\',
            mutations,
        )
        self.assertIn("for mutation in terminate reconfigure", mutations)
        self.assertIn('[ "$status" -eq 101 ]', mutations)
        self.assertIn("исходный канал менеджера не закрыт", mutations)
        self.assertIn("Arti не выбрал новый мост", mutations)


if __name__ == "__main__":
    unittest.main()
