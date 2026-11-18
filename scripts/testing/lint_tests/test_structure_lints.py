#!/usr/bin/env python3
"""Checks of the structure linters (scripts/check-line-limit.sh and
scripts/check-dir-entries.sh) in a throw-away git repository.

Run as `python -I scripts/testing/lint_tests/test_structure_lints.py`.
"""
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ("code-files.sh", "check-line-limit.sh", "check-dir-entries.sh")
SH = shutil.which("sh")


class StructureLints(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        self.git("init", "-q")
        (self.repo / "scripts").mkdir()
        for name in SCRIPTS:
            shutil.copy(ROOT / "scripts" / name, self.repo / "scripts" / name)

    def git(self, *args):
        subprocess.run(["git", *args], cwd=self.repo, check=True, capture_output=True)

    def write(self, path, lines=1, terminated=True):
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        body = "x\n" * lines
        target.write_bytes((body if terminated else body[:-1]).encode())

    def lint(self, script):
        done = subprocess.run([SH, f"scripts/{script}"], cwd=self.repo, capture_output=True, text=True)
        return done.returncode, done.stdout + done.stderr

    def assertPasses(self, script):
        code, out = self.lint(script)
        self.assertEqual(code, 0, out)

    def assertFails(self, script, *mentions):
        code, out = self.lint(script)
        self.assertNotEqual(code, 0, out)
        for text in mentions:
            self.assertIn(text, out)

    # -- line limit ---------------------------------------------------------

    def test_a_file_of_exactly_the_limit_passes_and_one_more_line_fails(self):
        self.write("ok.py", 1000)
        self.assertPasses("check-line-limit.sh")
        self.write("big.py", 1001)
        self.assertFails("check-line-limit.sh", "big.py", "1001 lines")

    def test_every_code_language_is_limited_not_only_rust(self):
        for name in ("a.rs", "b.py", "c.sh", "d.ps1", "e.c", "f.cs", "g.kt"):
            with self.subTest(name):
                self.write(name, 1001)
                self.assertFails("check-line-limit.sh", name)
                (self.repo / name).unlink()

    def test_a_last_line_without_a_newline_still_counts(self):
        self.write("tail.py", 1001, terminated=False)
        self.assertFails("check-line-limit.sh", "tail.py", "1001 lines")

    def test_blank_and_comment_lines_count_too(self):
        (self.repo / "mixed.py").write_text("# c\n\n" * 501)
        self.assertFails("check-line-limit.sh", "mixed.py", "1002 lines")

    def test_documentation_data_and_vendored_files_are_not_limited(self):
        self.write("README.md", 5000)
        self.write("Cargo.toml", 5000)
        self.write("data.json", 5000)
        self.write("vendor/arti/src/lib.rs", 5000)
        self.assertPasses("check-line-limit.sh")

    def test_a_tracked_file_deleted_in_the_working_tree_is_skipped(self):
        self.write("gone.py", 1001)
        self.git("add", "gone.py")
        (self.repo / "gone.py").unlink()
        self.assertPasses("check-line-limit.sh")

    # -- folder size --------------------------------------------------------

    def test_seven_code_files_pass_and_the_eighth_fails(self):
        for i in range(7):
            self.write(f"crate/src/m{i}.rs")
        self.assertPasses("check-dir-entries.sh")
        self.write("crate/src/m7.rs")
        self.assertFails("check-dir-entries.sh", "crate/src", "8 code files")

    def test_tests_count_as_code_files(self):
        for i in range(4):
            self.write(f"pkg/m{i}.py")
        for i in range(4):
            self.write(f"pkg/test_m{i}.py")
        self.assertFails("check-dir-entries.sh", "pkg", "8 code files")

    def test_only_code_files_count(self):
        for i in range(7):
            self.write(f"pkg/m{i}.rs")
        for name in ("README.md", "Cargo.toml", "data.json", "a.ktav", "notes.txt"):
            self.write(f"pkg/{name}")
        self.assertPasses("check-dir-entries.sh")

    def test_sub_folders_are_not_counted_as_entries(self):
        for i in range(7):
            self.write(f"pkg/m{i}.rs")
        for i in range(9):
            self.write(f"pkg/sub{i}/inner.rs")
        self.assertPasses("check-dir-entries.sh")

    def test_a_folder_is_counted_by_its_own_files_not_its_children(self):
        for i in range(8):
            self.write(f"pkg/deep/m{i}.rs")
        self.assertFails("check-dir-entries.sh", "pkg/deep")
        code, out = self.lint("check-dir-entries.sh")
        self.assertNotIn("pkg:", out)

    def test_the_root_folder_is_checked_like_any_other(self):
        for i in range(8):
            self.write(f"m{i}.py")
        self.assertFails("check-dir-entries.sh", ".: 8 code files")

    def test_vendored_folders_are_not_counted(self):
        for i in range(20):
            self.write(f"vendor/arti/src/m{i}.rs")
        self.assertPasses("check-dir-entries.sh")

    def test_tracked_and_untracked_files_are_both_counted(self):
        for i in range(4):
            self.write(f"pkg/tracked{i}.rs")
        self.git("add", "pkg")
        for i in range(4):
            self.write(f"pkg/untracked{i}.rs")
        self.assertFails("check-dir-entries.sh", "pkg", "8 code files")

    def test_ignored_files_are_not_counted(self):
        (self.repo / ".gitignore").write_text("generated_*.rs\n")
        for i in range(7):
            self.write(f"pkg/m{i}.rs")
        for i in range(5):
            self.write(f"pkg/generated_{i}.rs")
        self.assertPasses("check-dir-entries.sh")


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]] + sys.argv[1:], verbosity=2)
