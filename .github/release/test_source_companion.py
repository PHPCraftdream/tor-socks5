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
from unittest.mock import Mock, patch

_RELEASE_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_RELEASE_DIR))
_TEST_DIR = os.path.join(_ROOT, ".github", "install", "tests")
for _path in (_RELEASE_DIR, _TEST_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import fixtures as fx
import native_material
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
        self.sysroots = {}
        for target in companion.TARGETS:
            self._make_native_sysroot(target)
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

    def install_rustc_stub(self, bin_dir):
        os.makedirs(bin_dir, exist_ok=True)
        roots = repr(self.sysroots)
        lines = [
            "#!/usr/bin/env python3", "import os, sys", "args = sys.argv[1:]",
            "roots = %s" % roots,
            "target = args[args.index('--target') + 1] if '--target' in args else None",
            "if args == ['--print', 'sysroot']:",
            "    print(roots[target] if target else next(iter(roots.values())))",
            "elif args == ['-vV']:",
            "    print('release: 1.92.0\\ncommit-hash: %s\\nhost: synthetic-host')" % ('1' * 40),
            "elif args == ['--print', 'target-libdir', '--target', target]:",
            "    print(os.path.join(roots[target], 'lib', 'rustlib', target, 'lib'))",
            "else:", "    raise SystemExit('unexpected rustc invocation: ' + repr(args))",
        ]
        script = os.path.join(bin_dir, "rustc")
        _write(script, ("\n".join(lines) + "\n").encode("utf-8"))
        os.chmod(script, 0o755)
        if os.name == "nt":
            _write(os.path.join(bin_dir, "rustc.cmd"),
                   ('"%s" "%%~dp0rustc" %%*\r\n' % sys.executable).encode())
        return bin_dir

    def native_material(self, target):
        root = self.sysroots[target]
        return native_material.collect(
            root, "release: 1.92.0\ncommit-hash: %s\nhost: synthetic-host\n" % ('1' * 40),
            os.path.join(root, "lib", "rustlib", target, "lib"), target)

    def _make_native_sysroot(self, target):
        root = self.area.subdir("rust-" + target)
        self.sysroots[target] = root
        doc_dir = os.path.join(root, "share", "doc", "rust")
        for name in native_material.REQUIRED_DOCS:
            _write(os.path.join(doc_dir, name),
                   ("SYNTHETIC RUST FIXTURE %s %s\n" % (target, name)).encode())
        _write(os.path.join(doc_dir, "licenses", "COPYING"),
               ("SYNTHETIC LICENSE FIXTURE %s\n" % target).encode())
        libdir = os.path.join(root, "lib", "rustlib", target, "lib")
        inputs = [
            ("libstd-0123456789abcdef.rlib", b"SYNTHETIC Rust std fixture " + target.encode()),
            ("libcompiler_builtins-abcdef0123456789.rlib",
             b"SYNTHETIC compiler builtins fixture " + target.encode()),
            ("libfixture_native.a", b"SYNTHETIC native archive fixture " + target.encode()),
        ]
        if target.endswith("-musl"):
            inputs.extend([
                ("self-contained/libc.a", b"SYNTHETIC Rust-distributed musl fixture " + target.encode()),
                ("self-contained/crt1.o", b"SYNTHETIC startup fixture " + target.encode()),
            ])
        manifest_lines = ["manifest-version: 2"]
        for name, data in inputs:
            _write(os.path.join(libdir, *name.split("/")), data)
            manifest_lines.append("file:lib/rustlib/%s/lib/%s" % (target, name))
        manifest_path = os.path.join(root, "lib", "rustlib", "manifest-rust-std-" + target)
        _write(manifest_path, ("\n".join(manifest_lines) + "\n").encode())

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
                                       self.project, self.vendor_root,
                                       self.native_material(target))
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
        native = {name: data for name, data in members.items()
                  if name.startswith(native_material.ROOT)}
        self.assertEqual(native, self.fixture.native_material(self.target))
        self.assertEqual(metadata["native_material_provenance_sha256"],
                         _checksum(native[native_material.PROVENANCE]))
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
        bin_dir = self.fixture.install_cargo_stub(
            self.fixture.area.subdir("fake-rust-tools"))
        self.fixture.install_rustc_stub(bin_dir)
        common = ["--repo-root", self.fixture.repo_root,
                  "--artifacts-dir", artifacts, "--tag", TAG,
                  "--commit", self.fixture.commit, "--target", target]
        from unittest.mock import patch
        with patch.dict(os.environ, {"PATH": bin_dir + os.pathsep + os.environ.get("PATH", "")}):
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
        native = {name: data for name, data in members.items()
                  if name.startswith(native_material.ROOT)}
        self.assertEqual(native, self.fixture.native_material(target))
        self.assertEqual(metadata["native_material_provenance_sha256"],
                         _checksum(native[native_material.PROVENANCE]))

        bin_dir = self.fixture.install_cargo_stub(
            self.fixture.area.subdir("fake-cargo-bin"))
        self.fixture.install_rustc_stub(bin_dir)
        test_env = {"PATH": bin_dir + os.pathsep + os.environ.get("PATH", "")}
        with patch.dict(os.environ, test_env):
            self.assertEqual(companion.main(["verify", *common, "--installed-native"]), 0)
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
                                   self.fixture.vendor_root,
                                   self.fixture.native_material(self.target))
        members = _bundle_members(self.bundle)
        self.assertEqual(members["cargo-vendor/" + relative], marker)
        marker_reference = dict(self.expected_vendor_files)
        marker_reference[relative] = marker
        companion.verify_bundle(self.bundle, TAG, self.target, self.fixture.commit,
                                self.fixture.project, self.artifacts,
                                marker_reference, self.fixture.native_material(self.target))

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

    def test_collect_rejects_missing_installed_native_material(self):
        target = "x86_64-unknown-linux-musl"
        pristine = self.fixture.sysroots[target]
        missing = (
            ("Apache document", "share/doc/rust/licenses/Apache-2.0.txt"),
            ("MIT document", "share/doc/rust/licenses/MIT.txt"),
            ("copyright document", "share/doc/rust/COPYRIGHT.html"),
            ("library copyright document", "share/doc/rust/COPYRIGHT-library.html"),
            ("component manifest", "lib/rustlib/manifest-rust-std-" + target),
            ("libstd", "lib/rustlib/%s/lib/libstd-0123456789abcdef.rlib" % target),
            ("compiler builtins", "lib/rustlib/%s/lib/libcompiler_builtins-abcdef0123456789.rlib" % target),
            ("musl libc", "lib/rustlib/%s/lib/self-contained/libc.a" % target),
            ("startup object", "lib/rustlib/%s/lib/self-contained/crt1.o" % target),
        )
        for label, relative in missing:
            with self.subTest(material=label):
                root = self.fixture.area.subdir("collect-missing-" + label.replace(" ", "-"))
                shutil.copytree(pristine, root, dirs_exist_ok=True)
                if relative.startswith("lib/rustlib/%s/lib/" % target):
                    _write(os.path.join(root, "lib", "rustlib", "manifest-rust-std-" + target),
                           ("dir:lib/rustlib/%s/lib\n" % target).encode())
                os.remove(os.path.join(root, *relative.split("/")))
                libdir = os.path.join(root, "lib", "rustlib", target, "lib")
                rustc_vv = ("release: 1.92.0\ncommit-hash: %s\nhost: synthetic-host\n"
                            % ("1" * 40))
                with self.assertRaises(native_material.Invalid):
                    native_material.collect(root, rustc_vv, libdir, target)

        root = self.fixture.area.subdir("collect-wrong-libdir")
        shutil.copytree(pristine, root, dirs_exist_ok=True)
        wrong_libdir = os.path.join(root, "lib", "rustlib",
                                    "x86_64-unknown-linux-gnu", "lib")
        with self.subTest(material="wrong target libdir"):
            with self.assertRaises(native_material.Invalid):
                native_material.collect(
                    root, "release: 1.92.0\ncommit-hash: %s\nhost: synthetic-host\n"
                    % ("1" * 40), wrong_libdir, target)

    def test_collect_accepts_component_directory_manifest(self):
        target = "x86_64-unknown-linux-gnu"
        root = self.fixture.area.subdir("collect-directory-manifest")
        shutil.copytree(self.fixture.sysroots[target], root, dirs_exist_ok=True)
        manifest = os.path.join(root, "lib", "rustlib",
                                "manifest-rust-std-" + target)
        _write(manifest, ("manifest-version: 2\n"
                          "dir:lib/rustlib/%s/lib\n" % target).encode())
        libdir = os.path.join(root, "lib", "rustlib", target, "lib")
        rustc_vv = ("release: 1.92.0\ncommit-hash: %s\nhost: synthetic-host\n"
                    % ("1" * 40))
        payload = native_material.collect(root, rustc_vv, libdir, target)
        record = json.loads(payload[native_material.PROVENANCE])
        hashed = {item["path"] for item in record["target_inputs"]}
        self.assertIn("lib/rustlib/%s/lib/libstd-0123456789abcdef.rlib" % target,
                      hashed)
        self.assertIn("lib/rustlib/%s/lib/libcompiler_builtins-abcdef0123456789.rlib" % target,
                      hashed)

    def _rewrite_native_provenance(self, members, update_metadata=True):
        path = native_material.PROVENANCE
        record = json.loads(members[path])
        record["material_sha256"] = {
            name: _checksum(data) for name, data in members.items()
            if name.startswith(native_material.ROOT) and name != path}
        members[path] = json.dumps(record, sort_keys=True, indent=2).encode() + b"\n"
        metadata = json.loads(members["SOURCE-MATERIALS.json"])
        if update_metadata:
            metadata["native_material_provenance_sha256"] = _checksum(members[path])
        members["SOURCE-MATERIALS.json"] = json.dumps(metadata).encode()

    def _verify_native_members(self, target, members, installed=None):
        path = os.path.join(self.artifacts, companion.names(TAG, target)[1])
        _rewrite_bundle(path, members)
        companion.verify_bundle(path, TAG, target, self.fixture.commit,
                                self.fixture.project, self.artifacts,
                                self.expected_vendor_files, installed)

    def test_native_missing_material_and_malformed_provenance_are_rejected(self):
        def remove_input(members, marker):
            record = json.loads(members[native_material.PROVENANCE])
            record["target_inputs"] = [item for item in record["target_inputs"]
                                        if marker not in item["path"]]
            members[native_material.PROVENANCE] = json.dumps(record).encode()

        original = _bundle_members(self.bundle)
        cases = [
            ("missing document", lambda m, t: m.pop(
                native_material.DOC_ROOT + native_material.REQUIRED_DOCS[0])),
            ("missing manifest", lambda m, t: m.pop(
                native_material.MANIFEST_ROOT + "manifest-rust-std-" + t)),
            ("missing std-lib", lambda m, t: remove_input(m, "libstd-")),
            ("missing per-file-manifest input", lambda m, t: remove_input(m, "libfixture_native.a")),
            ("malformed provenance", lambda m, t: m.update(
                {native_material.PROVENANCE: b"{"})),
            ("missing native payload", lambda m, t: [
                m.pop(k) for k in list(m) if k.startswith(native_material.ROOT)]),
        ]
        for label, mutate in cases:
            with self.subTest(case=label):
                target = self.target
                members = dict(original)
                mutate(members, target)
                if label == "missing std-lib":
                    members[native_material.MANIFEST_ROOT + "manifest-rust-std-" + target] = (
                        "dir:lib/rustlib/%s/lib\n" % target).encode()
                if label in ("missing std-lib", "missing per-file-manifest input"):
                    self._rewrite_native_provenance(members)
                with self.assertRaises(companion.Invalid):
                    self._verify_native_members(target, members)

    def test_manifest_requires_compiler_builtins_and_exact_input_paths(self):
        members = _bundle_members(self.bundle)
        members[native_material.MANIFEST_ROOT + "manifest-rust-std-" + self.target] = (
            "dir:lib/rustlib/%s/lib\n" % self.target).encode()
        record = json.loads(members[native_material.PROVENANCE])
        record["target_inputs"] = [item for item in record["target_inputs"]
                                    if "libcompiler_builtins-" not in item["path"]]
        members[native_material.PROVENANCE] = json.dumps(record).encode()
        self._rewrite_native_provenance(members)
        with self.assertRaises(companion.Invalid):
            self._verify_native_members(self.target, members)

    def test_native_manifest_wrong_target_or_libdir_is_rejected(self):
        original = _bundle_members(self.bundle)
        for key, value in (("target", companion.TARGETS[1]),
                           ("target_libdir", "lib/rustlib/wrong-target/lib")):
            with self.subTest(field=key):
                members = dict(original)
                record = json.loads(members[native_material.PROVENANCE])
                record[key] = value
                members[native_material.PROVENANCE] = json.dumps(record).encode()
                self._rewrite_native_provenance(members)
                with self.assertRaises(companion.Invalid):
                    self._verify_native_members(self.target, members)

    def test_native_document_self_hash_and_provenance_digest_are_checked(self):
        original = _bundle_members(self.bundle)
        for field in ("self-hash", "companion digest"):
            with self.subTest(field=field):
                members = dict(original)
                if field == "self-hash":
                    path = native_material.DOC_ROOT + native_material.REQUIRED_DOCS[0]
                    members[path] += b"changed\n"
                else:
                    metadata = json.loads(members["SOURCE-MATERIALS.json"])
                    metadata["native_material_provenance_sha256"] = "0" * 64
                    members["SOURCE-MATERIALS.json"] = json.dumps(metadata).encode()
                with self.assertRaises(companion.Invalid):
                    self._verify_native_members(self.target, members)

    def test_musl_native_material_requires_distributed_libc_and_startup(self):
        target = "x86_64-unknown-linux-musl"
        original = _bundle_members(os.path.join(
            self.artifacts, companion.names(TAG, target)[1]))
        for missing in ("libc.a", "crt1.o"):
            with self.subTest(missing=missing):
                members = dict(original)
                members[native_material.MANIFEST_ROOT + "manifest-rust-std-" + target] = (
                    "dir:lib/rustlib/%s/lib\n" % target).encode()
                record = json.loads(members[native_material.PROVENANCE])
                record["target_inputs"] = [item for item in record["target_inputs"]
                                            if not item["path"].endswith(missing)]
                members[native_material.PROVENANCE] = json.dumps(record).encode()
                self._rewrite_native_provenance(members)
                with self.assertRaises(companion.Invalid):
                    self._verify_native_members(target, members)

    def test_rewritten_native_material_is_structural_not_authenticity(self):
        original = _bundle_members(self.bundle)
        altered = dict(original)
        doc = native_material.DOC_ROOT + native_material.REQUIRED_DOCS[0]
        altered[doc] += b"coordinated rewrite\n"
        self._rewrite_native_provenance(altered)
        self._verify_native_members(self.target, dict(altered))
        with self.assertRaises(companion.Invalid):
            self._verify_native_members(self.target, dict(altered),
                                        self.fixture.native_material(self.target))

    def test_installed_native_requires_explicit_target(self):
        with self.assertRaises(SystemExit) as failure:
            companion.main(["verify", "--repo-root", self.fixture.repo_root,
                            "--artifacts-dir", self.artifacts, "--tag", TAG,
                            "--commit", self.fixture.commit, "--installed-native"])
        self.assertEqual(failure.exception.code, 2)

    def test_release_workflow_native_verification_contract(self):
        path = os.path.join(_ROOT, ".github", "workflows", "release.yml")
        with open(path, encoding="utf-8") as stream:
            workflow = stream.read()

        def assert_contract(text):
            self.assertIn("- uses: dtolnay/rust-toolchain@stable\n        with:\n          targets: ${{ matrix.target }}", text)
            verify_line = next(line for line in text.splitlines()
                               if "source_companion.py verify" in line)
            self.assertIn("--installed-native", verify_line)

        assert_contract(workflow)
        with self.assertRaises(AssertionError):
            assert_contract(workflow.replace("--installed-native", "", 1))
        with self.assertRaises(AssertionError):
            assert_contract(workflow.replace("targets: ${{ matrix.target }}", "targets: wrong", 1))


class NativeMuslSourceTests(unittest.TestCase):
    """Focused offline coverage for the reviewed musl source pins."""

    TARGET = "x86_64-unknown-linux-musl"
    GNU_TARGET = "x86_64-unknown-linux-gnu"
    SOURCES = {
        name: ("SYNTHETIC MUSL SOURCE TEST BYTES: " + name).encode("ascii")
        for name in native_material.MUSL_SOURCE_PINS
    }

    def setUp(self):
        self.area = fx.TempArea(self)
        self.root = self._make_sysroot(self.TARGET)
        self.pins = {
            name: ("https://synthetic.invalid/" + name, _checksum(data))
            for name, data in self.SOURCES.items()
        }

    def _make_sysroot(self, target):
        root = self.area.subdir("sysroot-" + target)
        docdir = os.path.join(root, "share", "doc", "rust")
        for name in native_material.REQUIRED_DOCS:
            _write(os.path.join(docdir, name), b"SYNTHETIC native material doc\n")
        libdir = os.path.join(root, "lib", "rustlib", target, "lib")
        files = [("libstd-0123456789abcdef.rlib", b"SYNTHETIC libstd"),
                 ("libcompiler_builtins-abcdef0123456789.rlib", b"SYNTHETIC builtins")]
        if target.endswith("-musl"):
            files += [("self-contained/libc.a", b"SYNTHETIC musl libc"),
                      ("self-contained/crt1.o", b"SYNTHETIC musl startup")]
        lines = ["manifest-version: 2"]
        for name, data in files:
            _write(os.path.join(libdir, *name.split("/")), data)
            lines.append("file:lib/rustlib/%s/lib/%s" % (target, name))
        _write(os.path.join(root, "lib", "rustlib", "manifest-rust-std-" + target),
               ("\n".join(lines) + "\n").encode())
        return root

    def _collect_reviewed(self):
        rustc = "release: %s\ncommit-hash: %s\nhost: synthetic-host\n" % (
            native_material.RUST_MUSL_RELEASE, native_material.RUST_MUSL_COMMIT)
        with patch.object(native_material, "_fetch_musl_sources",
                          return_value={native_material.MUSL_ROOT + name: data
                                        for name, data in self.SOURCES.items()}) as fetch:
            payload = native_material.collect(
                self.root, rustc,
                os.path.join(self.root, "lib", "rustlib", self.TARGET, "lib"),
                self.TARGET)
        fetch.assert_called_once_with()
        return payload

    @staticmethod
    def _rewrite_material_hashes(payload):
        record = json.loads(payload[native_material.PROVENANCE])
        record["material_sha256"] = {
            path: _checksum(data) for path, data in payload.items()
            if path != native_material.PROVENANCE}
        payload[native_material.PROVENANCE] = (
            json.dumps(record, sort_keys=True, indent=2) + "\n").encode()

    def test_production_critical_source_pins_and_immutable_urls(self):
        expected = {
            "musl-1.2.5.tar.gz": "a9a118bbe84d8764da0ea0d28b3ab3fae8477fc7e4085d90102b8596fc7c75e4",
            "0001-cve-2025-26519-p1.diff": "89ec5af152afb9c0ba8e37ecdca63a7a7fd13b60247f1a2d8024a59baa18e7dc",
            "0002-cve-2025-26519-p2.diff": "d5b88fe87f9554238bdd69235694b0d50bb909f38149a7be417a0240a490e813",
            "musl-cve-2026-6042.diff": "444fa70e52ca158fb7d4bad560637790bbf8f72e80b82fff840dd66fa83091e3",
            "musl-cve-2026-40200.diff": "1ee29f64f9ca8e8ad7c349779d661ff6b52126a27575d3586981357a52c406fb",
            "mcm-musl-1.2.5.tar.gz.sha1": "5c5d074634ed2dedef96c21d52040bfdf056e17d8ec0ccae96e7bf0eb86c3026",
        }
        pins = native_material.MUSL_SOURCE_PINS
        self.assertTrue(all(pins[name][1] == digest
                            for name, digest in expected.items()))
        for url, _ in pins.values():
            self.assertTrue(url.startswith("https://"), url)
            if "github" in url:
                self.assertRegex(
                    url, r"(?:github\.com|githubusercontent\.com)/.+/[0-9a-f]{40}/")

    def test_collect_rejects_missing_required_pinned_source(self):
        missing = next(iter(self.SOURCES))
        fetched = {native_material.MUSL_ROOT + name: data
                   for name, data in self.SOURCES.items() if name != missing}
        with patch.dict(native_material.MUSL_SOURCE_PINS, self.pins, clear=True), \
                patch.object(native_material, "_fetch_musl_sources", return_value=fetched):
            rustc = "release: %s\ncommit-hash: %s\nhost: synthetic-host\n" % (
                native_material.RUST_MUSL_RELEASE, native_material.RUST_MUSL_COMMIT)
            with self.assertRaisesRegex(native_material.Invalid, "exact pinned source set"):
                native_material.collect(
                    self.root, rustc,
                    os.path.join(self.root, "lib", "rustlib", self.TARGET, "lib"),
                    self.TARGET)

    def test_unreviewed_musl_collect_keeps_original_scope_offline(self):
        rustc = "release: 1.92.0\ncommit-hash: %s\nhost: synthetic-host\n" % ("1" * 40)
        with patch.object(native_material, "_fetch_musl_sources") as fetch:
            payload = native_material.collect(
                self.root, rustc,
                os.path.join(self.root, "lib", "rustlib", self.TARGET, "lib"),
                self.TARGET)
        fetch.assert_not_called()
        self.assertFalse(any(path.startswith(native_material.MUSL_ROOT) for path in payload))
        record = native_material.validate(payload, self.TARGET)
        self.assertIn(native_material.MUSL_UNESTABLISHED_SCOPE,
                      record["unestablished_scope"])
        self.assertNotIn(native_material.MUSL_SOURCE_LINKAGE_SCOPE,
                         record["unestablished_scope"])

    def test_reviewed_collect_preserves_exact_pinned_bytes(self):
        with patch.dict(native_material.MUSL_SOURCE_PINS, self.pins, clear=True):
            payload = self._collect_reviewed()
            provenance = native_material.validate(payload, self.TARGET)
        self.assertEqual(provenance["rustc"]["release"], native_material.RUST_MUSL_RELEASE)
        self.assertEqual({path: payload[path] for path in payload
                          if path.startswith(native_material.MUSL_ROOT)},
                         {native_material.MUSL_ROOT + name: data
                          for name, data in self.SOURCES.items()})

    def test_each_pinned_file_rejects_removal_or_corruption_after_rehash(self):
        with patch.dict(native_material.MUSL_SOURCE_PINS, self.pins, clear=True):
            original = self._collect_reviewed()
            for name, data in self.SOURCES.items():
                path = native_material.MUSL_ROOT + name
                for action in ("missing", "corrupt"):
                    with self.subTest(source=name, action=action):
                        changed = dict(original)
                        if action == "missing":
                            changed.pop(path)
                        else:
                            changed[path] = data + b"tampered"
                        self._rewrite_material_hashes(changed)
                        with self.assertRaises(native_material.Invalid):
                            native_material.validate(changed, self.TARGET)

    def test_extra_or_unreviewed_identity_cannot_claim_pinned_sources(self):
        with patch.dict(native_material.MUSL_SOURCE_PINS, self.pins, clear=True):
            original = self._collect_reviewed()
            for field, value in (("release", "1.99.2"),
                                 ("commit-hash", "f" * 40)):
                changed = dict(original)
                record = json.loads(changed[native_material.PROVENANCE])
                record["rustc"][field] = value
                record["unestablished_scope"] = native_material.unestablished_scope(
                    self.TARGET, record["rustc"])
                changed[native_material.PROVENANCE] = json.dumps(record).encode()
                self._rewrite_material_hashes(changed)
                with self.subTest(identity=field), self.assertRaises(native_material.Invalid):
                    native_material.validate(changed, self.TARGET)

            extra = dict(original)
            extra[native_material.MUSL_ROOT + "extra.diff"] = b"SYNTHETIC extra"
            self._rewrite_material_hashes(extra)
            with self.assertRaises(native_material.Invalid):
                native_material.validate(extra, self.TARGET)

            gnu_root = self._make_sysroot(self.GNU_TARGET)
            gnu_payload = native_material.collect(
                gnu_root,
                "release: %s\ncommit-hash: %s\nhost: synthetic-host\n" % (
                    native_material.RUST_MUSL_RELEASE, native_material.RUST_MUSL_COMMIT),
                os.path.join(gnu_root, "lib", "rustlib", self.GNU_TARGET, "lib"),
                self.GNU_TARGET)
            gnu_payload[native_material.MUSL_ROOT + next(iter(self.SOURCES))] = next(
                iter(self.SOURCES.values()))
            self._rewrite_material_hashes(gnu_payload)
            with self.assertRaises(native_material.Invalid):
                native_material.validate(gnu_payload, self.GNU_TARGET)

    def test_installed_rejects_unsupported_target_and_new_rustc_before_fetch(self):
        with patch.object(native_material.subprocess, "run") as run, \
                patch.object(native_material, "_fetch_musl_sources") as fetch:
            with self.assertRaises(native_material.Invalid):
                native_material.installed("riscv64-unknown-linux-musl")
            run.assert_not_called()
            fetch.assert_not_called()

        outputs = [Mock(stdout="/synthetic/sysroot"), Mock(stdout=(
            "release: 1.99.2\ncommit-hash: %s\nhost: synthetic-host\n" % ("f" * 40))),
            Mock(stdout="/synthetic/sysroot/lib/rustlib/%s/lib" % self.TARGET)]
        with patch.object(native_material.subprocess, "run", side_effect=outputs) as run, \
                patch.object(native_material, "_fetch_musl_sources") as fetch:
            with self.assertRaises(native_material.Invalid):
                native_material.installed(self.TARGET)
            self.assertEqual(run.call_count, 3)
            fetch.assert_not_called()

    def test_fetch_checks_bytes_limits_redirects_and_network_errors(self):
        class Response:
            def __init__(self, body, length=None, url="https://synthetic.invalid/source"):
                self.body, self.offset, self.url = body, 0, url
                self.read_sizes = []
                self.headers = {} if length is None else {"Content-Length": str(length)}
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def geturl(self):
                return self.url
            def read(self, size):
                self.read_sizes.append(size)
                chunk = self.body[self.offset:self.offset + size]
                self.offset += len(chunk)
                return chunk

        cases = (("good", b"abc", None, "https://synthetic.invalid/source", None, True),
                 ("empty", b"", None, "https://synthetic.invalid/source", None, False),
                 ("wrong hash", b"abc", None, "https://synthetic.invalid/source", "0" * 64, False),
                 ("header too large", b"abc", 4, "https://synthetic.invalid/source", None, False),
                 ("read too large", b"abcd", None, "https://synthetic.invalid/source", None, False),
                 ("redirect", b"abc", None, "https://other.invalid/source", None, False),
                 ("network error", None, None, None, None, False))
        for label, body, length, url, digest, succeeds in cases:
            with self.subTest(case=label):
                response = Response(body or b"", length, url or "https://synthetic.invalid/source")
                opener = Mock()
                if label == "network error":
                    opener.open.side_effect = OSError("synthetic offline failure")
                else:
                    opener.open.return_value = response
                expected = digest or _checksum(b"abc")
                with patch.dict(native_material.MUSL_SOURCE_PINS,
                                {"source.bin": ("https://synthetic.invalid/source", expected)},
                                clear=True), \
                        patch.object(native_material, "MUSL_SOURCE_MAX_BYTES", 3), \
                        patch.object(native_material.urllib.request, "build_opener",
                                     return_value=opener) as build_opener:
                    if succeeds:
                        self.assertEqual(native_material._fetch_musl_sources(),
                                         {native_material.MUSL_ROOT + "source.bin": b"abc"})
                    else:
                        with self.assertRaises(native_material.Invalid):
                            native_material._fetch_musl_sources()
                    opener.open.assert_called_once_with(
                        "https://synthetic.invalid/source", timeout=30)
                    build_opener.assert_called_once()
                    handler = build_opener.call_args.args[0]
                    self.assertIsInstance(handler, native_material._NoRedirect)
                    self.assertIsNone(handler.redirect_request(
                        Mock(), Mock(), 302, "Found", {}, "https://other.invalid/source"))
                if label == "header too large":
                    self.assertEqual(response.read_sizes, [])
                if label == "read too large":
                    self.assertEqual(response.read_sizes, [4])


if __name__ == "__main__":
    unittest.main(verbosity=2)
