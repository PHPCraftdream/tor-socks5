#!/usr/bin/env python3
import hashlib
import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
from unittest import mock
from pathlib import Path

spec = importlib.util.spec_from_file_location("evidence", Path(__file__).with_name("cargo_evidence.py"))
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cache = self.root / "cache" / "index"
        self.cache.mkdir(parents=True)
        self.lock = self.root / "Cargo.lock"
        self.out = self.root / "output"

    def archive(self, entries):
        path = self.cache / "demo-1.0.0.crate"
        with tarfile.open(path, "w:gz") as tar:
            for name, kind, data in entries:
                info = tarfile.TarInfo(name)
                info.type = kind
                info.size = len(data) if kind == tarfile.REGTYPE else 0
                if kind == tarfile.SYMTYPE:
                    info.linkname = "../outside"
                tar.addfile(info, io.BytesIO(data) if info.size else None)
        checksum = hashlib.sha256(path.read_bytes()).hexdigest()
        self.lock.write_text('[[package]]\nname = "demo"\nversion = "1.0.0"\n'
                             f'source = "{evidence.SOURCE}"\nchecksum = "{checksum}"\n')

    def test_verified_archive_and_primary_file(self):
        self.archive([("demo-1.0.0/LICENSE", tarfile.REGTYPE, b"license")])
        evidence.collect(self.lock, self.cache.parent, self.out)
        self.assertEqual((self.out / "files/demo-1.0.0/000000").read_bytes(), b"license")
        self.assertTrue((self.out / "archives/demo-1.0.0.crate").is_file())
        with self.assertRaises(FileExistsError):
            evidence.collect(self.lock, self.cache.parent, self.out)

    def test_checksum_mismatch_and_missing(self):
        self.archive([])
        (self.cache / "demo-1.0.0.crate").write_bytes(b"changed")
        with self.assertRaises(ValueError):
            evidence.collect(self.lock, self.cache.parent, self.out)
        with tempfile.TemporaryDirectory() as other:
            with self.assertRaises(ValueError):
                evidence.collect(self.lock, Path(other), Path(other) / "new")

    def test_rejects_unsafe_members(self):
        for name, kind in [("demo-1.0.0/../../escape", tarfile.REGTYPE),
                           ("/demo-1.0.0/LICENSE", tarfile.REGTYPE),
                           ("demo-1.0.0/link", tarfile.SYMTYPE),
                           ("demo-1.0.0/link", tarfile.LNKTYPE),
                           ("demo-1.0.0/../LICENSE", tarfile.REGTYPE)]:
            with self.subTest(name=name, kind=kind), tempfile.TemporaryDirectory() as output:
                self.archive([(name, kind, b"x")])
                with self.assertRaises(ValueError):
                    evidence.collect(self.lock, self.cache.parent, Path(output) / "new")

    def test_nested_candidates_preserve_archive_path(self):
        self.archive([("demo-1.0.0/vendor/nested/NOTICE.txt", tarfile.REGTYPE, b"notice"),
                      ("demo-1.0.0/LICENSE", tarfile.REGTYPE, b"license")])
        evidence.collect(self.lock, self.cache.parent, self.out)
        import json
        candidates = json.loads((self.out / "manifest.json").read_text())["packages"][0]["license_candidates"]
        self.assertEqual(candidates[0]["archive_path"], "demo-1.0.0/vendor/nested/NOTICE.txt")
        self.assertEqual((self.out / candidates[0]["path"]).read_bytes(), b"notice")

    def test_collisions_and_unsafe_paths(self):
        cases = [
            [("demo-1.0.0/LICENSE", tarfile.REGTYPE, b"x"), ("demo-1.0.0/license", tarfile.REGTYPE, b"y")],
            [("demo-1.0.0/foo", tarfile.REGTYPE, b"x"), ("demo-1.0.0/foo/NOTICE", tarfile.REGTYPE, b"y")],
            [("demo-1.0.0/foo/NOTICE", tarfile.REGTYPE, b"x"), ("demo-1.0.0/foo", tarfile.REGTYPE, b"y")],
            [("demo-1.0.0/a\\\\LICENSE", tarfile.REGTYPE, b"x")],
            [("demo-1.0.0/C:/LICENSE", tarfile.REGTYPE, b"x")],
        ]
        for entries in cases:
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as output:
                self.archive(entries)
                with self.assertRaises(ValueError):
                    evidence.collect(self.lock, self.cache.parent, Path(output) / "new")

    def test_resource_limits(self):
        self.archive([("demo-1.0.0/LICENSE", tarfile.REGTYPE, b"abc"),
                      ("demo-1.0.0/NOTICE", tarfile.REGTYPE, b"def")])
        for constant, limit in [("MAX_ENTRIES", 1), ("MAX_ALL_CONTENT", 5),
                                ("MAX_TOTAL", 5), ("MAX_FILE", 2),
                                ("MAX_ALL_ARCHIVES", 1), ("MAX_PACKAGES", 0)]:
            with self.subTest(constant=constant), tempfile.TemporaryDirectory() as output:
                with mock.patch.object(evidence, constant, limit):
                    with self.assertRaises(ValueError):
                        evidence.collect(self.lock, self.cache.parent, Path(output) / "new")

    def test_pax_stream_limit_and_valid_pax(self):
        self.archive([("demo-1.0.0/" + "x" * 150 + "/NOTICE", tarfile.REGTYPE, b"ok")])
        with tempfile.TemporaryDirectory() as other:
            evidence.collect(self.lock, self.cache.parent, Path(other) / "out")
            manifest = json.loads((Path(other) / "out/manifest.json").read_text())
            self.assertTrue(manifest["packages"][0]["license_candidates"][0]["archive_path"].endswith("/NOTICE"))
        # An ordinary archive succeeds under the same limit as the PAX rejection.
        self.archive([("demo-1.0.0/LICENSE", tarfile.REGTYPE, b"ok")])
        with mock.patch.object(evidence, "MAX_TAR_STREAM", 16384), tempfile.TemporaryDirectory() as other:
            evidence.collect(self.lock, self.cache.parent, Path(other) / "out")
        # A PAX extension's payload is parsed before tarfile returns a member.
        path = self.cache / "demo-1.0.0.crate"
        with tarfile.open(path, "w:gz", format=tarfile.PAX_FORMAT) as tar:
            info = tarfile.TarInfo("demo-1.0.0/LICENSE")
            info.pax_headers = {"comment": "x" * 50000}
            info.size = 1
            tar.addfile(info, io.BytesIO(b"x"))
        checksum = hashlib.sha256(path.read_bytes()).hexdigest()
        self.lock.write_text('[[package]]\nname = "demo"\nversion = "1.0.0"\n'
                             f'source = "{evidence.SOURCE}"\nchecksum = "{checksum}"\n')
        with mock.patch.object(evidence, "MAX_TAR_STREAM", 16384), \
                mock.patch.object(tarfile.TarInfo, "_decode_pax_field", side_effect=AssertionError("PAX parsed")) as parse:
            with self.assertRaisesRegex(ValueError, "decompressed tar stream too large"):
                evidence.collect(self.lock, self.cache.parent, self.out)
            parse.assert_not_called()

    def test_manifest_hashes_and_missing_candidates_and_path(self):
        self.archive([("demo-1.0.0/src/lib.rs", tarfile.REGTYPE, b"code")])
        with self.lock.open("a") as lock:
            lock.write('\n[[package]]\nname = "local"\nversion = "0.1.0"\n')
        evidence.collect(self.lock, self.cache.parent, self.out)
        manifest = json.loads((self.out / "manifest.json").read_text())
        self.assertEqual(manifest["lock_sha256"], hashlib.sha256(self.lock.read_bytes()).hexdigest())
        package, local = manifest["packages"]
        self.assertEqual(package["checksum"], hashlib.sha256((self.out / package["archive"]).read_bytes()).hexdigest())
        self.assertEqual(package["status"], "no-candidates")
        self.assertEqual(package["license_candidates"], [])
        self.assertEqual(local["status"], "path-unverified")
        self.assertIsNone(local["source"])

    def test_candidate_manifest_hash(self):
        self.archive([("demo-1.0.0/NOTICE", tarfile.REGTYPE, b"notice")])
        evidence.collect(self.lock, self.cache.parent, self.out)
        candidate = json.loads((self.out / "manifest.json").read_text())["packages"][0]["license_candidates"][0]
        self.assertEqual(candidate["sha256"], hashlib.sha256((self.out / candidate["path"]).read_bytes()).hexdigest())

    def test_license_file_before_and_after_manifest(self):
        manifest = ("demo-1.0.0/Cargo.toml", tarfile.REGTYPE,
                    b'[package]\nname = "demo"\nlicense-file = "legal/terms.txt"\n')
        license_entry = ("demo-1.0.0/legal/terms.txt", tarfile.REGTYPE, b"terms")
        for entries in ([manifest, license_entry], [license_entry, manifest]):
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as other:
                self.archive(entries)
                out = Path(other) / "out"
                evidence.collect(self.lock, self.cache.parent, out)
                candidates = json.loads((out / "manifest.json").read_text())["packages"][0]["license_candidates"]
                self.assertEqual(len(candidates), 1)
                self.assertEqual(candidates[0]["archive_path"], license_entry[0])
                self.assertEqual((out / candidates[0]["path"]).read_bytes(), b"terms")

    def test_license_file_invalid_or_missing(self):
        for value in ('"../outside"', '"/absolute"', '"a/../LICENSE"', '"missing"', '123', '{ workspace = true }'):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as other:
                self.archive([("demo-1.0.0/Cargo.toml", tarfile.REGTYPE,
                               f'[package]\nlicense-file = {value}\n'.encode())])
                with self.assertRaises(ValueError):
                    evidence.collect(self.lock, self.cache.parent, Path(other) / "out")

    def test_path_limits(self):
        for constant, limit, path in [("MAX_PATH_LENGTH", 20, "demo-1.0.0/" + "x" * 20),
                                      ("MAX_PATH_DEPTH", 3, "demo-1.0.0/a/b/c")]:
            with self.subTest(constant=constant), tempfile.TemporaryDirectory() as other:
                self.archive([(path, tarfile.REGTYPE, b"x")])
                with mock.patch.object(evidence, constant, limit):
                    with self.assertRaisesRegex(ValueError, "oversized path"):
                        evidence.collect(self.lock, self.cache.parent, Path(other) / "out")

    def test_duplicate_member(self):
        self.archive([("demo-1.0.0/LICENSE", tarfile.REGTYPE, b"a"),
                      ("demo-1.0.0/LICENSE", tarfile.REGTYPE, b"b")])
        with self.assertRaises(ValueError):
            evidence.collect(self.lock, self.cache.parent, self.out)


if __name__ == "__main__":
    unittest.main()
