import hashlib
import io
import os
import sys
import tarfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import check_vendor_notices as check  # noqa: E402

MIT = b"Copyright 2019-2025, The Tor Project, Inc.\n\nPermission is hereby granted\n"
APACHE = b"Apache License\nVersion 2.0\n"
LICENSES = {
    "LICENSE-MIT": (len(MIT), check.git_blob_id(MIT), hashlib.sha256(MIT).hexdigest()),
    "LICENSE-APACHE": (len(APACHE), check.git_blob_id(APACHE), hashlib.sha256(APACHE).hexdigest()),
}
MANIFEST = b'[package]\nname = "demo"\nauthors = [\n    "The Tor Project, Inc.",\n]\nlicense = "MIT OR Apache-2.0"\n'
SOURCE = b"fn main() {}\n"


def pristine():
    return {"Cargo.toml": MANIFEST, "README.md": b"# demo\n\nLicense: MIT OR Apache-2.0\n", "src/lib.rs": SOURCE}


def vendor(**changes):
    files = dict(pristine())
    files["LICENSE-MIT"] = MIT
    files["LICENSE-APACHE"] = APACHE
    files.update(changes)
    return {path: data for path, data in files.items() if data is not None}


def problems(vendored, original=None):
    return check.check_crate("demo 1.0.0", original or pristine(), vendored, LICENSES)


class CheckCrate(unittest.TestCase):
    def test_untouched_vendor_copy_is_clean(self):
        self.assertEqual(problems(vendor()), [])

    def test_modified_file_needs_a_change_notice(self):
        edited = SOURCE + b"// tor-socks5 local patch: fix\n"
        self.assertEqual(problems(vendor(**{"src/lib.rs": edited})), [])
        self.assertEqual(problems(vendor(**{"src/lib.rs": SOURCE + b"fn extra() {}\n"})),
                         ["demo 1.0.0: src/lib.rs is modified or added without a change notice"])

    def test_a_pointer_to_the_provenance_record_is_a_notice(self):
        manifest = MANIFEST + b"# Modified, see vendor/PROVENANCE.md\n"
        self.assertEqual(problems(vendor(**{"Cargo.toml": manifest})), [])

    def test_added_file_needs_a_change_notice(self):
        self.assertEqual(problems(vendor(**{"src/new.rs": b"fn new() {}\n"})),
                         ["demo 1.0.0: src/new.rs is modified or added without a change notice"])
        self.assertEqual(problems(vendor(**{"src/new.rs": b"// tor-socks5 local patch: new\n"})), [])

    def test_cargo_marker_and_license_files_are_exempt(self):
        self.assertEqual(problems(vendor(**{".cargo-ok": b"{}"})), [])

    def test_binary_file_cannot_carry_a_notice(self):
        found = problems(vendor(**{"data.bin": b"\xff\xfe\x00"}))
        self.assertEqual(len(found), 1)
        self.assertIn("not a text file", found[0])

    def test_removed_or_changed_notice_lines_are_reported(self):
        changed = MANIFEST.replace(b'license = "MIT OR Apache-2.0"', b'license = "MIT"') + b"# tor-socks5 local patch\n"
        found = problems(vendor(**{"Cargo.toml": changed}))
        self.assertEqual(found, ["demo 1.0.0: Cargo.toml: notice line removed or changed: 'license = \"MIT OR Apache-2.0\"'"])
        readme = b"# demo\n<!-- tor-socks5 local patch -->\n"
        self.assertIn("README.md: notice line removed or changed: 'License: MIT OR Apache-2.0'",
                      problems(vendor(**{"README.md": readme}))[0])

    def test_a_duplicated_notice_does_not_stand_in_for_a_missing_one(self):
        original = {"NOTICE.txt": b"Copyright A\nCopyright A\n"}
        ours = vendor(**{"NOTICE.txt": b"Copyright A\n# tor-socks5 local patch\n"})
        ours.pop("Cargo.toml"), ours.pop("README.md"), ours.pop("src/lib.rs")
        self.assertEqual(len(problems(ours, original)), 1)

    def test_a_file_with_upstream_notices_must_not_disappear(self):
        found = problems(vendor(**{"Cargo.toml": None}))
        self.assertEqual(found, ["demo 1.0.0: Cargo.toml carries notice lines upstream but is missing from vendor/"])
        self.assertEqual(problems(vendor(**{"src/lib.rs": None})), [])

    def test_license_files_must_match_their_recorded_blob(self):
        self.assertEqual(problems(vendor(**{"LICENSE-MIT": MIT + b"x"})),
                         ["demo 1.0.0: LICENSE-MIT does not match the recorded blob id " + LICENSES["LICENSE-MIT"][1]])
        self.assertEqual(problems(vendor(**{"LICENSE-APACHE": None})), ["demo 1.0.0: LICENSE-APACHE is missing"])


class Archives(unittest.TestCase):
    @staticmethod
    def crate(members):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, data in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return buffer.getvalue()

    def test_archive_is_read_after_its_checksum_matches(self):
        data = self.crate({"demo-1.0.0/Cargo.toml": MANIFEST, "demo-1.0.0/src/lib.rs": SOURCE})
        files = check.read_archive(data, hashlib.sha256(data).hexdigest(), "demo")
        self.assertEqual(files, {"Cargo.toml": MANIFEST, "src/lib.rs": SOURCE})
        with self.assertRaises(check.CheckError):
            check.read_archive(data, "0" * 64, "demo")

    def test_unsafe_members_are_rejected(self):
        for name in ("../evil", "/abs/path", "toplevel-only"):
            data = self.crate({name: b"x"})
            with self.assertRaises(check.CheckError, msg=name):
                check.read_archive(data, hashlib.sha256(data).hexdigest(), "demo")


class Provenance(unittest.TestCase):
    TEXT = (
        "Current baseline (synced 2026-11-10):\n\n"
        "| Crate | Version | VCS path | SHA-256 of downloaded `.crate.gz` |\n|---|---:|---|---|\n"
        "| `demo` | 1.0.0 | `crates/demo` | `" + "a" * 64 + "` |\n\n"
        "Previous baseline (synced 2026-10-13):\n| `old` | 0.9.0 | `crates/old` | `" + "b" * 64 + "` |\n\n"
        "| File | Bytes | Git blob id | SHA-256 |\n|---|---:|---|---|\n"
        "| `LICENSE-MIT` | 1067 | `" + "c" * 40 + "` | `" + "d" * 64 + "` |\n"
        "| `LICENSE-APACHE` | 11358 | `" + "e" * 40 + "` | `" + "f" * 64 + "` |\n"
    )

    def test_tables_are_parsed_and_the_previous_baseline_is_ignored(self):
        crates, licenses = check.parse_provenance(self.TEXT)
        self.assertEqual(crates, {"demo": ("1.0.0", "a" * 64)})
        self.assertEqual(licenses["LICENSE-MIT"], (1067, "c" * 40, "d" * 64))

    def test_missing_tables_fail_closed(self):
        for text in ("no tables here", self.TEXT.split("| File |")[0]):
            with self.assertRaises(check.CheckError):
                check.parse_provenance(text)

    def test_the_real_provenance_record_parses(self):
        root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        with open(os.path.join(root, "vendor", "PROVENANCE.md"), encoding="utf8") as handle:
            crates, licenses = check.parse_provenance(handle.read())
        self.assertEqual(len(crates), 8)
        self.assertEqual(sorted(licenses), ["LICENSE-APACHE", "LICENSE-MIT"])


if __name__ == "__main__":
    unittest.main()
