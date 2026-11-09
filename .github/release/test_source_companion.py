# -*- coding: utf-8 -*-
"""Offline source-companion tests and reusable publisher fixtures."""

import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import unittest

_RELEASE_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_RELEASE_DIR))
_TEST_DIR = os.path.join(_ROOT, ".github", "install", "tests")
for _path in (_RELEASE_DIR, _TEST_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import fixtures as fx
import source_companion as companion

TAG = "v1.2.3"


def _write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as stream:
        stream.write(data)


def _checksum(data):
    return hashlib.sha256(data).hexdigest()


class SourceFixture:
    """Tiny committed project and complete Cargo-vendor-shaped test data."""

    def __init__(self, test_case):
        self.area = fx.TempArea(test_case)
        self.repo_root = self.area.subdir("checkout")
        self.vendor_root = self.area.subdir("cargo-vendor")
        self._make_project_and_vendor()
        self.cargo_reference_root = os.path.join(self.area.path, "cargo-reference")
        shutil.copytree(self.vendor_root, self.cargo_reference_root)
        self.expected_vendor_files = dict(companion.vendor_files(self.cargo_reference_root)[0])
        for command in (["git", "init", "-q"],
                        ["git", "add", "--all"],
                        ["git", "-c", "user.name=Release Fixture",
                         "-c", "user.email=fixture@example.invalid",
                         "commit", "-qm", "fixture source"]):
            subprocess.run(command, cwd=self.repo_root, check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo_root, check=True,
            stdout=subprocess.PIPE, text=True).stdout.strip()
        self.project = subprocess.run(
            ["git", "archive", "--format=tar", self.commit], cwd=self.repo_root,
            check=True, stdout=subprocess.PIPE).stdout

    def install_cargo_stub(self, bin_dir):
        """Install an offline fake Cargo command for synthetic CLI boundary tests."""
        os.makedirs(bin_dir, exist_ok=True)
        script = os.path.join(bin_dir, "cargo")
        reference = repr(self.cargo_reference_root)
        lines = [
            "#!/usr/bin/env python3",
            "import os, shutil, sys",
            "args = sys.argv[1:]",
            "expected = ['vendor', '--locked', '--versioned-dirs']",
            "if args[:3] != expected or len(args) != 4:",
            "    raise SystemExit('unexpected cargo invocation: ' + repr(args))",
            "destination = args[3]",
            "if os.path.exists(destination):",
            "    raise SystemExit('vendor destination already exists')",
            "shutil.copytree(%s, destination)" % reference,
        ]
        _write(script, ("\n".join(lines) + "\n").encode("utf-8"))
        os.chmod(script, 0o755)
        if os.name == "nt":
            command = os.path.join(bin_dir, "cargo.cmd")
            wrapper = '"%s" "%%~dp0cargo" %%*\r\n' % sys.executable
            _write(command, wrapper.encode("utf-8"))
        return bin_dir

    def _make_project_and_vendor(self):
        _write(os.path.join(self.repo_root, "LICENSE-APACHE"), b"Apache test license\n")
        _write(os.path.join(self.repo_root, "LICENSE-MIT"), b"MIT test license\n")
        _write(os.path.join(self.repo_root, "README.md"), b"Fixture project source\n")
        _write(os.path.join(self.repo_root, "NOTICE"), b"Fixture notice bytes\n")
        _write(os.path.join(self.repo_root, "COPYRIGHT"), b"Fixture copyright bytes\n")
        _write(os.path.join(self.repo_root, "Cargo.toml"),
               b"[package]\nname = \"fixture-project\"\nversion = \"0.1.0\"\nedition = \"2021\"\n")
        _write(os.path.join(self.repo_root, "src", "main.rs"),
               b"fn main() { println!(\"fixture source marker\"); }\n")
        packages = [
            ("priority-queue", "2.7.0", "a" * 64, "MPL-2.0",
             b"Mozilla Public License Version 2.0\nSYNTHETIC TEST FIXTURE; not legal text.\n"),
            ("webpki-roots", "0.26.11", "b" * 64, "CDLA-Permissive-2.0",
             b"Community Data License Agreement\nSYNTHETIC TEST FIXTURE; not legal text.\n"),
            ("webpki-roots", "1.0.7", "c" * 64, "CDLA-Permissive-2.0",
             b"Community Data License Agreement\nSYNTHETIC TEST FIXTURE; not legal text.\n"),
            ("ordinary-tiny", "0.1.0", "d" * 64, "MIT",
             b"MIT License\nSYNTHETIC TEST FIXTURE; not legal text.\n"),
        ]
        lock = ["version = 4", ""]
        for name, version, checksum, license_id, license_text in packages:
            lock.extend(("[[package]]", 'name = "%s"' % name,
                         'version = "%s"' % version,
                         'source = "registry+https://github.com/rust-lang/crates.io-index"',
                         'checksum = "%s"' % checksum, ""))
            root = os.path.join(self.vendor_root, "%s-%s" % (name, version))
            source = b"pub fn fixture_marker() {}\n"
            build_script = b"// fixture build script\n"
            manifest = ("[package]\nname = \"%s\"\nversion = \"%s\"\n"
                        "license = \"%s\"\nlicense-file = \"LICENSE\"\n"
                        % (name, version, license_id)).encode()
            _write(os.path.join(root, "Cargo.toml"), manifest)
            _write(os.path.join(root, "LICENSE"), license_text)
            notice = b"fixture %s notice\n" % license_id.split("-")[0].encode()
            _write(os.path.join(root, "NOTICE"), notice)
            _write(os.path.join(root, "src", "lib.rs"), source)
            build_path = os.path.join(root, "build.rs")
            _write(build_path, build_script)
            os.chmod(build_path, 0o755)
            expected = {"files": {"Cargo.toml": _checksum(manifest),
                                  "LICENSE": _checksum(license_text),
                                  "NOTICE": _checksum(notice),
                                  "src/lib.rs": _checksum(source),
                                  "build.rs": _checksum(build_script)},
                      "package": checksum}
            _write(os.path.join(root, ".cargo-checksum.json"),
                   json.dumps(expected, sort_keys=True).encode())
        self.lock_data = "\n".join(lock).encode()
        _write(os.path.join(self.repo_root, "Cargo.lock"), self.lock_data)
        _write(os.path.join(self.repo_root, "vendor", "PROVENANCE.md"),
               b"Offline fixture vendor source\n")

    def make_artifacts(self, artifacts_dir=None, tag=TAG, targets=None):
        artifacts_dir = artifacts_dir or self.area.subdir("artifacts")
        targets = tuple(targets or companion.TARGETS)
        os.makedirs(artifacts_dir, exist_ok=True)
        for target in targets:
            binary_name, _ = companion.names(tag, target)
            _write(os.path.join(artifacts_dir, binary_name),
                   ("fixture binary: " + target + "\n").encode())
            companion.create_companion(artifacts_dir, tag, self.commit, target,
                                       self.project, self.vendor_root)
        return artifacts_dir


def _bundle_members(path):
    with tarfile.open(path, "r:gz") as archive:
        return {item.name: archive.extractfile(item).read()
                for item in archive.getmembers()}


def _rewrite_bundle(path, members):
    with open(path, "wb") as output:
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            for name, data in sorted(members.items()):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o644
                archive.addfile(info, io.BytesIO(data))
    with open(path, "rb") as stream:
        digest = _checksum(stream.read())
    source_name = os.path.basename(path)
    with open(path + ".sha256", "w", encoding="ascii", newline="\n") as stream:
        stream.write("%s  %s\n" % (digest, source_name))


class SourceCompanionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = SourceFixture(self)
        self.expected_vendor_files = dict(self.fixture.expected_vendor_files)
        self.artifacts = self.fixture.make_artifacts()
        self.target = companion.TARGETS[0]
        self.binary_name, self.source_name = companion.names(TAG, self.target)
        self.bundle = os.path.join(self.artifacts, self.source_name)

    def test_complete_material_is_preserved_and_verifies(self):
        members = _bundle_members(self.bundle)
        self.assertEqual(members["project.tar"], self.fixture.project)
        self.assertIn(b"Fixture project source\n", self.fixture.project)
        self.assertIn(b"Fixture notice bytes\n", self.fixture.project)
        self.assertIn(b"Fixture copyright bytes\n", self.fixture.project)
        with tarfile.open(fileobj=io.BytesIO(members["project.tar"]), mode="r:") as project:
            project_files = {member.name: project.extractfile(member).read()
                             for member in project.getmembers() if member.isfile()}
        for name, data in (
                ("LICENSE-APACHE", b"Apache test license\n"),
                ("LICENSE-MIT", b"MIT test license\n"),
                ("README.md", b"Fixture project source\n"),
                ("NOTICE", b"Fixture notice bytes\n"),
                ("COPYRIGHT", b"Fixture copyright bytes\n"),
                ("Cargo.toml", b"[package]\nname = \"fixture-project\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"),
                ("Cargo.lock", self.fixture.lock_data),
                ("vendor/PROVENANCE.md", b"Offline fixture vendor source\n"),
                ("src/main.rs", b"fn main() { println!(\"fixture source marker\"); }\n")):
            self.assertEqual(project_files[name], data)
        # Synthetic fixture text is deliberately not a legal grant; production
        # verification compares every byte to an independently generated tree.
        expected = {
            "priority-queue-2.7.0": (b"Mozilla Public License Version 2.0\nSYNTHETIC TEST FIXTURE; not legal text.\n",
                                      b"fixture MPL notice\n"),
            "webpki-roots-0.26.11": (b"Community Data License Agreement\nSYNTHETIC TEST FIXTURE; not legal text.\n",
                                      b"fixture CDLA notice\n"),
            "webpki-roots-1.0.7": (b"Community Data License Agreement\nSYNTHETIC TEST FIXTURE; not legal text.\n",
                                    b"fixture CDLA notice\n"),
            "ordinary-tiny-0.1.0": (b"MIT License\nSYNTHETIC TEST FIXTURE; not legal text.\n",
                                    b"fixture MIT notice\n"),
        }
        for package, (license_bytes, notice_bytes) in expected.items():
            self.assertEqual(members["cargo-vendor/%s/LICENSE" % package],
                             license_bytes)
            self.assertEqual(members["cargo-vendor/%s/NOTICE" % package],
                             notice_bytes)
            self.assertEqual(members["cargo-vendor/%s/src/lib.rs" % package],
                             b"pub fn fixture_marker() {}\n")
            self.assertEqual(members["cargo-vendor/%s/build.rs" % package],
                             b"// fixture build script\n")
        vendor, modes = companion.vendor_files(self.fixture.vendor_root)
        packages = companion.lock_data(self.fixture.project)[1]
        companion.check_vendor(vendor, packages)
        with self.assertRaises(companion.Invalid):
            companion.check_vendor(vendor, [package for package in packages
                                            if package["name"] != "ordinary-tiny"])
        included = {name[len("cargo-vendor/"):]: data
                    for name, data in members.items()
                    if name.startswith("cargo-vendor/")}
        self.assertEqual(included, self.expected_vendor_files)
        with tarfile.open(self.bundle, "r:gz") as archive:
            archived_modes = {item.name[len("cargo-vendor/"):]: item.mode
                              for item in archive.getmembers()
                              if item.name.startswith("cargo-vendor/")}
        self.assertEqual(archived_modes, modes)
        self.assertEqual(archived_modes["priority-queue-2.7.0/build.rs"], 0o755)
        metadata = json.loads(members["SOURCE-MATERIALS.json"])
        self.assertEqual(metadata["commit"], self.fixture.commit)
        self.assertEqual(metadata["target"], self.target)
        self.assertEqual(metadata["lock_sha256"], _checksum(self.fixture.lock_data))
        self.assertEqual(metadata["project_archive_sha256"],
                         _checksum(self.fixture.project))
        self.assertEqual(metadata["binary_archive"], self.binary_name)
        self.assertEqual(metadata["binary_archive_sha256"],
                         _checksum(fx.file_bytes(os.path.join(self.artifacts,
                                                             self.binary_name))))
        companion.verify_bundle(self.bundle, TAG, self.target, self.fixture.commit,
                                self.fixture.project, self.artifacts,
                                self.expected_vendor_files)

    def test_cli_packages_and_verifies_synthetic_committed_checkout(self):
        artifacts = self.fixture.area.subdir("cli-artifacts")
        target = companion.TARGETS[0]
        binary_name, source_name = companion.names(TAG, target)
        binary_bytes = b"CLI fixture binary archive\n"
        _write(os.path.join(artifacts, binary_name), binary_bytes)
        script = os.path.join(_RELEASE_DIR, "source_companion.py")
        common = ["--repo-root", self.fixture.repo_root,
                  "--artifacts-dir", artifacts, "--tag", TAG,
                  "--commit", self.fixture.commit, "--target", target]
        packaged = subprocess.run(
            [sys.executable, "-I", script, "package", *common,
             "--vendor-root", self.fixture.vendor_root],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(packaged.returncode, 0, packaged.stderr.decode())

        bundle = os.path.join(artifacts, source_name)
        self.assertTrue(os.path.isfile(bundle))
        with open(bundle, "rb") as stream:
            bundle_bytes = stream.read()
        with open(bundle + ".sha256", "r", encoding="ascii") as stream:
            self.assertEqual(stream.read(), "%s  %s\n" % (_checksum(bundle_bytes),
                                                             source_name))
        members = _bundle_members(bundle)
        self.assertEqual(members["project.tar"], self.fixture.project)
        metadata = json.loads(members["SOURCE-MATERIALS.json"])
        self.assertEqual(metadata["commit"], self.fixture.commit)
        self.assertEqual(metadata["target"], target)
        self.assertEqual(metadata["project_archive_sha256"],
                         _checksum(self.fixture.project))
        self.assertEqual(metadata["binary_archive"], binary_name)
        self.assertEqual(metadata["binary_archive_sha256"], _checksum(binary_bytes))

        from unittest.mock import patch
        bin_dir = self.fixture.install_cargo_stub(
            self.fixture.area.subdir("fake-cargo-bin"))
        test_env = {"PATH": bin_dir + os.pathsep + os.environ.get("PATH", "")}
        with patch.dict(os.environ, test_env):
            self.assertEqual(companion.main(["verify", *common]), 0)
        with patch.object(companion, "trusted_vendor", return_value={}):
            with self.assertRaises(SystemExit) as failure:
                companion.main(["verify", *common])
        self.assertEqual(failure.exception.code, 1)

    def test_recomputed_project_digest_cannot_change_checkout_identity(self):
        members = _bundle_members(self.bundle)
        altered_project = self.fixture.project.replace(
            b"Fixture project source\n", b"Fixture project forged\n")
        self.assertNotEqual(altered_project, self.fixture.project)
        members["project.tar"] = altered_project
        metadata = json.loads(members["SOURCE-MATERIALS.json"])
        metadata["project_archive_sha256"] = _checksum(altered_project)
        members["SOURCE-MATERIALS.json"] = json.dumps(metadata).encode()
        _rewrite_bundle(self.bundle, members)
        with self.assertRaises(companion.Invalid):
            companion.verify_bundle(self.bundle, TAG, self.target,
                                    self.fixture.commit, self.fixture.project,
                                    self.artifacts, self.expected_vendor_files)

    def test_coordinated_vendor_edits_fail_against_frozen_reference(self):
        original = _bundle_members(self.bundle)
        packages = (
            ("ordinary-tiny-0.1.0", "src/lib.rs", None),
            ("priority-queue-2.7.0", "LICENSE",
             b"Mozilla Public License Version 2.0\n"),
            ("webpki-roots-0.26.11", "LICENSE",
             b"Community Data License Agreement\n"),
            ("webpki-roots-1.0.7", "LICENSE",
             b"Community Data License Agreement\n"),
        )
        for package, relative, replacement in packages:
            with self.subTest(package=package):
                changed = dict(original)
                checksum_path = "cargo-vendor/%s/.cargo-checksum.json" % package
                record = json.loads(changed[checksum_path])
                member_path = "cargo-vendor/%s/%s" % (package, relative)
                if replacement is None:
                    changed.pop(member_path)
                    record["files"].pop(relative)
                else:
                    changed[member_path] = replacement
                    record["files"][relative] = _checksum(replacement)
                changed[checksum_path] = json.dumps(record, sort_keys=True).encode()
                _rewrite_bundle(self.bundle, changed)
                with self.assertRaises(companion.Invalid):
                    companion.verify_bundle(self.bundle, TAG, self.target,
                                            self.fixture.commit, self.fixture.project,
                                            self.artifacts, self.expected_vendor_files)
                _rewrite_bundle(self.bundle, original)

    def test_vendor_self_checksum_map_is_not_authenticity_reference(self):
        _, packages = companion.lock_data(self.fixture.project)
        root = os.path.join(self.fixture.area.path, "mutated-vendor")
        shutil.copytree(self.fixture.vendor_root, root)
        source = os.path.join(root, "ordinary-tiny-0.1.0", "src", "lib.rs")
        os.remove(source)
        record_path = os.path.join(root, "ordinary-tiny-0.1.0", ".cargo-checksum.json")
        with open(record_path, encoding="utf-8") as stream:
            record = json.load(stream)
        record["files"].pop("src/lib.rs")
        _write(record_path, json.dumps(record).encode())
        mutable = companion.vendor_files(root)[0]
        # Self-reported hashes accept this internally consistent omission;
        # only the independent Cargo reference establishes completeness.
        companion.check_vendor(mutable, packages)
        with self.assertRaises(companion.Invalid):
            companion.compare_vendor(mutable, self.expected_vendor_files)

    def test_cargo_vendor_marker_inside_locked_package_is_retained(self):
        relative = "priority-queue-2.7.0/.cargo-ok"
        marker = b"standard Cargo vendor marker\n"
        _write(os.path.join(self.fixture.vendor_root, *relative.split("/")), marker)
        vendor, _ = companion.vendor_files(self.fixture.vendor_root)
        _, packages = companion.lock_data(self.fixture.project)
        companion.check_vendor(vendor, packages)
        companion.create_companion(self.artifacts, TAG, self.fixture.commit,
                                   self.target, self.fixture.project,
                                   self.fixture.vendor_root)
        members = _bundle_members(self.bundle)
        self.assertEqual(members["cargo-vendor/" + relative], marker)
        marker_reference = dict(self.expected_vendor_files)
        marker_reference[relative] = marker
        companion.verify_bundle(self.bundle, TAG, self.target, self.fixture.commit,
                                self.fixture.project, self.artifacts,
                                marker_reference)

    def test_wrong_commit_target_lock_and_binary_binding_are_rejected(self):
        original = _bundle_members(self.bundle)
        variants = {
            "commit": (lambda data: None,
                       TAG, self.target, "f" * 40),
            "tag": (lambda data: None,
                    "v9.9.9", self.target, self.fixture.commit),
            "target": (lambda data: data.update(
                {"SOURCE-MATERIALS.json": json.dumps(dict(
                    json.loads(data["SOURCE-MATERIALS.json"]),
                    target=companion.TARGETS[1])).encode()}),
                TAG, self.target, self.fixture.commit),
            "lock": (lambda data: data.update(
                {"SOURCE-MATERIALS.json": json.dumps(dict(
                    json.loads(data["SOURCE-MATERIALS.json"]), lock_sha256="0" * 64)).encode()}),
                TAG, self.target, self.fixture.commit),
            "binary": (lambda data: data.update(
                {"SOURCE-MATERIALS.json": json.dumps(dict(
                    json.loads(data["SOURCE-MATERIALS.json"]),
                    binary_archive_sha256="0" * 64)).encode()}),
                TAG, self.target, self.fixture.commit),
        }
        for label, (mutate, tag, target, commit) in variants.items():
            with self.subTest(case=label):
                changed = dict(original)
                mutate(changed)
                _rewrite_bundle(self.bundle, changed)
                with self.assertRaises(companion.Invalid):
                    companion.verify_bundle(self.bundle, tag, target, commit,
                                            self.fixture.project, self.artifacts,
                                            self.expected_vendor_files)
                _rewrite_bundle(self.bundle, original)

    def test_changed_vendor_content_fails_integrity_check(self):
        members = _bundle_members(self.bundle)
        path = "cargo-vendor/ordinary-tiny-0.1.0/src/lib.rs"
        members[path] += b"changed\n"
        _rewrite_bundle(self.bundle, members)
        with self.assertRaises(companion.Invalid):
            companion.verify_bundle(self.bundle, TAG, self.target, self.fixture.commit,
                                    self.fixture.project, self.artifacts,
                                    self.expected_vendor_files)


if __name__ == "__main__":
    unittest.main(verbosity=2)
