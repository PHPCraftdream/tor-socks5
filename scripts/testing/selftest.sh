#!/bin/sh
set -eu
[ "${GITHUB_ACTIONS:-}" = true ] || { echo 'selftest is CI-only' >&2; exit 1; }
exec python3 -I - <<'PY'
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SOURCE = Path.cwd()
GUARD = SOURCE / "scripts/check-line-limit.sh"


class LineLimit(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo"
        self.root.mkdir()
        self.env = {
            key: value for key, value in os.environ.items()
            if not key.startswith("GIT_")
        }
        self.env.update(
            GIT_CONFIG_NOSYSTEM="1",
            GIT_CONFIG_GLOBAL=os.devnull,
            LC_ALL="C",
        )
        self.git("init", "-q")
        self.shell = shutil.which("sh")
        self.assertIsNotNone(self.shell)

    def git(self, *args):
        result = subprocess.run(
            ["git", *args], cwd=self.root, env=self.env,
            capture_output=True, text=True, encoding="utf-8", timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def put(self, name, data):
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return target

    def guard(self, status, env=None):
        result = subprocess.run(
            [self.shell, str(GUARD)], cwd=self.root,
            env=self.env if env is None else env,
            capture_output=True, text=True, encoding="utf-8", timeout=15,
        )
        self.assertEqual(
            result.returncode, status, result.stdout + result.stderr,
        )
        self.assertEqual(result.stdout, "")
        if status:
            self.assertIn("line-limit: ERROR:", result.stderr)
        else:
            self.assertEqual(result.stderr, "")
        return result.stderr

    def test_language_boundaries_and_newlines(self):
        suffixes = ("rs", "py", "sh", "ps1", "c", "cs", "js", "go", "kt")
        for suffix in suffixes:
            name = "boundary." + suffix
            for newline in (b"\n", b"\r\n", b"\r"):
                for terminated in (False, True):
                    for count in (1000, 1001):
                        with self.subTest(
                            suffix=suffix, newline=newline,
                            terminated=terminated, count=count,
                        ):
                            data = newline.join([b"x"] * count)
                            if terminated:
                                data += newline
                            target = self.put(name, data)
                            error = self.guard(0 if count == 1000 else 1)
                            if count == 1001:
                                self.assertIn(ascii(name), error)
                                self.assertIn("1001 physical lines", error)
                                self.assertIn("1000-line limit", error)
                            target.unlink()

    def test_conventional_names(self):
        names = (
            "Makefile", "Dockerfile", "Dockerfile.ci", "Containerfile",
            "CMakeLists.txt", "Justfile", "meson.build", "BUILD.bazel",
        )
        for name in names:
            self.put(name, b"x\n" * 1000)
        self.guard(0)
        for name in names:
            self.put(name, b"x\n" * 1001)
        error = self.guard(1)
        for name in names:
            self.assertIn(ascii(name), error)

    def test_extensionless_owned_shebang(self):
        target = self.put("run tool", b"#!/bin/sh\n" + b"x\n" * 999)
        target.chmod(0o755)
        self.put("ordinary note", b"x\n" * 1001)
        self.guard(0)
        target.write_bytes(b"#!/bin/sh\n" + b"x\n" * 999 + b"x")
        error = self.guard(1)
        self.assertIn("'run tool'", error)
        self.assertIn("1001 physical lines", error)
        self.assertNotIn("ordinary note", error)
        self.git("add", "--", "run tool")
        self.guard(1)

    def test_tracked_untracked_case_and_path_framing(self):
        names = (
            "tracked.rs", "new.py", "space name.sh", "tab\tname.ps1",
            "line\nname.c", "Ünicode.CS", "mixed.PY",
        )
        for name in names:
            self.put(name, b"x\n" * 1001)
        self.git("add", "--", names[0])
        error = self.guard(1)
        for name in names:
            self.assertIn(ascii(name), error)
        self.assertEqual(error.count("line-limit: ERROR:"), len(names))

    def test_vendor_segments_are_excluded_before_inspection(self):
        names = (
            "vendor/root.rs", "vendors/root.py",
            "nested/vendor/child.sh", "nested/vendors/child.ps1",
            "nested/VENDOR/upper.c", "nested/VENDORS/upper.cs",
        )
        for name in names:
            self.put(name, b"x\n" * 1001)
        self.git("add", "-A")
        for index, name in enumerate(names):
            target = self.root / name
            target.unlink()
            if index % 2:
                os.mkfifo(target)
            else:
                target.symlink_to("missing-target")
        self.guard(0)
        self.put("vendorish/owned.rs", b"x\n" * 1001)
        error = self.guard(1)
        self.assertIn("'vendorish/owned.rs'", error)
        self.assertEqual(error.count("line-limit: ERROR:"), 1)

    def test_untracked_ignored_private_contents_are_not_opened(self):
        self.put(".gitignore", b"private/\n")
        target = self.root / "private/secret.rs"
        target.parent.mkdir(parents=True, exist_ok=True)
        os.mkfifo(target)
        self.put("ordinary.rs", b"x\n")
        self.guard(0)

    def test_tracked_source_matching_ignore_remains_enforced(self):
        target = self.put("tracked-private.py", b"x\n" * 1000)
        self.git("add", "--", "tracked-private.py")
        self.put(".gitignore", b"tracked-private.py\n")
        self.guard(0)
        target.write_bytes(b"x\n" * 1001)
        error = self.guard(1)
        self.assertIn("'tracked-private.py'", error)
        self.assertIn("1001 physical lines", error)

    def test_documentation_source_and_custom_suffix_shebang(self):
        readme = self.put("README.md", b"x\n" * 1001)
        self.guard(0)
        for name, data in (
            ("docs/example.py", b"x\n" * 1001),
            ("code.customshebang", b"#!/bin/sh\n" + b"x\n" * 1000),
        ):
            with self.subTest(name=name):
                target = self.put(name, data)
                error = self.guard(1)
                self.assertIn(ascii(name), error)
                self.assertIn("1001 physical lines", error)
                self.assertNotIn("'README.md'", error)
                target.unlink()
        self.assertTrue(readme.is_file())

    def test_source_symlink_and_fifo_fail_closed(self):
        target = self.put("owned.py", b"x\n")
        self.git("add", "--", "owned.py")
        target.unlink()
        target.symlink_to("missing-target")
        error = self.guard(2)
        self.assertIn("not a regular file 'owned.py'", error)
        target.unlink()
        os.mkfifo(target)
        error = self.guard(2)
        self.assertIn("not a regular file 'owned.py'", error)

    def test_symlink_parent_and_missing_tracked_source_fail_closed(self):
        target = self.put("owned/nested.py", b"x\n")
        self.git("add", "--", "owned/nested.py")
        target.unlink()
        self.assertIn("cannot inspect 'owned/nested.py'", self.guard(2))
        (self.root / "owned").rmdir()
        (self.root / "owned").symlink_to("missing-directory")
        self.assertIn("symlink parent", self.guard(2))

    def test_empty_and_staged_deleted_source(self):
        self.put("empty.rs", b"")
        self.git("add", "--", "empty.rs")
        self.guard(0)
        self.git("rm", "-f", "--", "empty.rs")
        self.guard(0)

    def test_nul_in_source_fails_closed(self):
        self.put("binary.py", b"first\n\0last")
        self.assertIn("NUL byte in source 'binary.py'", self.guard(2))

    def test_git_failure_is_not_a_clean_result(self):
        fake = Path(self.temp.name) / "bin"
        fake.mkdir()
        python = shutil.which("python3")
        self.assertIsNotNone(python)
        (fake / "python3").symlink_to(python)
        git = fake / "git"
        git.write_bytes(b"#!/bin/sh\nexit 77\n")
        git.chmod(0o755)
        env = dict(self.env, PATH=str(fake))
        self.assertIn("git enumeration failed", self.guard(2, env))

    def test_guard_test_runner_is_exactly_mapped_fast(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "line_limit_ci_planner",
            SOURCE / "scripts/testing/ci_planner.py",
        )
        planner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(planner)
        packages = [
            {
                "id": ident,
                "name": name,
                "manifest_path": str(self.root / directory / "Cargo.toml"),
                "targets": [{"kind": ["lib"]}],
            }
            for ident, name, directory in (
                ("proxy", "socks5-proxy", "apps/socks5-proxy"),
                ("ffi", "android-ffi", "packages/android-ffi"),
            )
        ]
        graph = planner.Graph(
            {
                "packages": packages,
                "workspace_members": ["proxy", "ffi"],
                "resolve": {
                    "nodes": [
                        {"id": ident, "deps": []}
                        for ident in ("proxy", "ffi")
                    ],
                },
            },
            self.root,
        )
        capabilities = {"license_stack": False, "real_tor_channel": True}
        for name in ("scripts/check-line-limit.sh", "scripts/testing/selftest.sh"):
            result = planner.plan(
                graph, [name], lambda path: ("", ""),
                capabilities=capabilities,
            )
            self.assertEqual(result["segments"], ["fast"])
            self.assertFalse(result["full"])
            self.assertEqual(result["packages"], [])
        for name in (
            "scripts/testing/selftest.sh.bak",
            "scripts/testing/nested/selftest.sh",
        ):
            with self.assertRaises(planner.MappingError):
                planner.plan(
                    graph, [name], lambda path: ("", ""),
                    capabilities=capabilities,
                )

if __name__ == "__main__":
    unittest.main()
PY
