"""Check the pinned, defaults-disabled local SDK integration."""

import argparse
import copy
import json
import subprocess
import tomllib
import unittest
from pathlib import Path

COMMIT = "1375fef64f029db24dc7d604051e0dd557570f30"
NAME = "resocks5-net"
VERSION = "0.4.0"
DEPENDENCIES = {"base64", "socket2", "tokio"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def single(items, message):
    require(len(items) == 1, message)
    return items[0]


def check(root, sdk, lock, metadata, sdk_head, expected_manifest):
    require(sdk_head == COMMIT, "SDK checkout commit mismatch")
    require(root["workspace"]["package"]["rust-version"] == "1.92",
            "project MSRV changed")
    require(root["workspace"]["dependencies"]["ktav"] == "0.8.0",
            "project ktav requirement changed")
    require(
        root["workspace"]["dependencies"][NAME] == {
            "path": "../resocks5/crates/resocks5-net",
            "version": "=0.4.0",
            "default-features": False,
        },
        "workspace SDK dependency contract mismatch",
    )
    require(sdk["workspace"]["package"]["version"] == VERSION,
            "SDK workspace version mismatch")
    require(sdk["workspace"]["package"]["rust-version"] == "1.88",
            "SDK workspace MSRV mismatch")

    entry = single(
        [p for p in lock["package"] if p["name"] == NAME],
        "expected exactly one SDK lock package",
    )
    require(entry["version"] == VERSION, "SDK lock version mismatch")
    require("source" not in entry and "checksum" not in entry,
            "SDK lock package must remain path-sourced")
    require(set(entry["dependencies"]) == DEPENDENCIES,
            "SDK lock dependencies changed")

    package = single(
        [p for p in metadata["packages"] if p["name"] == NAME],
        "expected exactly one SDK metadata package",
    )
    require(package["version"] == VERSION, "resolved SDK version mismatch")
    require(package["source"] is None, "resolved SDK is not path-sourced")
    require(Path(package["manifest_path"]).resolve() == expected_manifest,
            "resolved SDK manifest path mismatch")
    require(package["rust_version"] == "1.88",
            "resolved SDK inherited MSRV mismatch")
    node = single(
        [n for n in metadata["resolve"]["nodes"]
         if n["id"] == package["id"]],
        "expected exactly one SDK resolve node",
    )
    require(node["features"] == [], "optional SDK features activated")
    by_id = {p["id"]: p for p in metadata["packages"]}
    dependencies = [by_id[d["pkg"]]["name"] for d in node["deps"]]
    require(set(dependencies) == DEPENDENCIES
            and len(dependencies) == len(DEPENDENCIES),
            "resolved SDK dependencies changed")


def read_toml(path):
    with path.open("rb") as stream:
        return tomllib.load(stream)


def verify_checkout(root):
    root = root.resolve()
    sdk_root = root.parent / "resocks5"
    sdk_manifest = sdk_root / "crates" / NAME / "Cargo.toml"
    package = read_toml(sdk_manifest)["package"]
    require(package["name"] == NAME, "SDK manifest package name mismatch")
    require(package["version"] == {"workspace": True},
            "SDK version inheritance changed")
    require(package["rust-version"] == {"workspace": True},
            "SDK MSRV inheritance changed")
    sdk_head = subprocess.check_output(
        ["git", "-C", str(sdk_root), "rev-parse", "HEAD"],
        text=True,
    ).strip()
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--format-version", "1", "--locked"],
        cwd=root,
        text=True,
    ))
    check(
        read_toml(root / "Cargo.toml"),
        read_toml(sdk_root / "Cargo.toml"),
        read_toml(root / "Cargo.lock"),
        metadata,
        sdk_head,
        sdk_manifest.resolve(),
    )


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.manifest = (Path.cwd() / "sdk-contract-fixture"
                         / "Cargo.toml").resolve()
        self.root = {
            "workspace": {
                "package": {"rust-version": "1.92"},
                "dependencies": {
                    "ktav": "0.8.0",
                    NAME: {
                        "path": "../resocks5/crates/resocks5-net",
                        "version": "=0.4.0",
                        "default-features": False,
                    },
                },
            },
        }
        self.sdk = {
            "workspace": {
                "package": {"version": VERSION, "rust-version": "1.88"},
            },
        }
        self.lock = {
            "package": [{
                "name": NAME,
                "version": VERSION,
                "dependencies": sorted(DEPENDENCIES),
            }],
        }
        self.metadata = {
            "packages": [{
                "id": "sdk",
                "name": NAME,
                "version": VERSION,
                "source": None,
                "manifest_path": str(self.manifest),
                "rust_version": "1.88",
            }] + [{"id": name, "name": name} for name in sorted(DEPENDENCIES)],
            "resolve": {
                "nodes": [{
                    "id": "sdk",
                    "features": [],
                    "deps": [{"pkg": name}
                             for name in sorted(DEPENDENCIES)],
                }],
            },
        }

    def validate(self, root=None, sdk=None, lock=None, metadata=None,
                 head=COMMIT):
        check(
            self.root if root is None else root,
            self.sdk if sdk is None else sdk,
            self.lock if lock is None else lock,
            self.metadata if metadata is None else metadata,
            head,
            self.manifest,
        )

    def test_accepts_matching_contract(self):
        self.validate()

    def test_rejects_wrong_checkout(self):
        with self.assertRaisesRegex(ValueError, "commit"):
            self.validate(head="0" * 40)

    def test_rejects_old_lock_and_registry_source(self):
        for field, value, message in (
            ("version", "0.3.0", "version"),
            ("source", "registry+unexpected", "path-sourced"),
            ("checksum", "unexpected", "path-sourced"),
        ):
            with self.subTest(field=field):
                lock = copy.deepcopy(self.lock)
                lock["package"][0][field] = value
                with self.assertRaisesRegex(ValueError, message):
                    self.validate(lock=lock)

    def test_rejects_changed_resolution(self):
        mutations = (
            ("version", "0.3.0", "version"),
            ("source", "git+unexpected", "path-sourced"),
            ("manifest_path", str(self.manifest.parent / "other.toml"),
             "path mismatch"),
            ("rust_version", "1.93", "MSRV"),
        )
        for field, value, message in mutations:
            with self.subTest(field=field):
                metadata = copy.deepcopy(self.metadata)
                metadata["packages"][0][field] = value
                with self.assertRaisesRegex(ValueError, message):
                    self.validate(metadata=metadata)

    def test_rejects_duplicate_sdk(self):
        metadata = copy.deepcopy(self.metadata)
        metadata["packages"].append(dict(metadata["packages"][0]))
        with self.assertRaisesRegex(ValueError, "exactly one"):
            self.validate(metadata=metadata)

    def test_rejects_optional_features(self):
        for feature in ("default", "pool", "tls", "serde", "rating", "rotator"):
            with self.subTest(feature=feature):
                metadata = copy.deepcopy(self.metadata)
                metadata["resolve"]["nodes"][0]["features"] = [feature]
                with self.assertRaisesRegex(ValueError, "features"):
                    self.validate(metadata=metadata)

    def test_rejects_missing_dependency(self):
        metadata = copy.deepcopy(self.metadata)
        metadata["resolve"]["nodes"][0]["deps"].pop()
        with self.assertRaisesRegex(ValueError, "dependencies"):
            self.validate(metadata=metadata)

    def test_rejects_enabled_defaults(self):
        root = copy.deepcopy(self.root)
        root["workspace"]["dependencies"][NAME]["default-features"] = True
        with self.assertRaisesRegex(ValueError, "dependency contract"):
            self.validate(root=root)

    def test_rejects_project_msrv_change(self):
        root = copy.deepcopy(self.root)
        root["workspace"]["package"]["rust-version"] = "1.88"
        with self.assertRaisesRegex(ValueError, "project MSRV"):
            self.validate(root=root)

    def test_rejects_wrong_sdk_version(self):
        sdk = copy.deepcopy(self.sdk)
        sdk["workspace"]["package"]["version"] = "0.3.0"
        with self.assertRaisesRegex(ValueError, "workspace version"):
            self.validate(sdk=sdk)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(ContractTests)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        raise SystemExit(0 if result.wasSuccessful() else 1)
    verify_checkout(Path.cwd())


if __name__ == "__main__":
    main()
