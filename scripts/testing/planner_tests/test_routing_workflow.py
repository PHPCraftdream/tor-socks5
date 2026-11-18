"""Маршрутизация: workflow, native, контракты, точечные правки."""
import unittest

from support import ROOT, p, RoutingCase


class RoutingWorkflow(RoutingCase):
    def test_rename_delete_unknown(self):
        result = self.route("packages/auth/src/old.rs", "packages/bridge-probe/src/new.rs")
        self.assertIn("tor-socks5-auth", result["packages"])
        self.assertIn("bridge-probe", result["packages"])
        self.assertIn("tor-socks5-auth", self.route("packages/auth/src/deleted.rs")["packages"])
        with self.assertRaises(p.MappingError):
            self.route("unmapped.file")

    def test_workflow(self):
        old = "name: CI\njobs:\n  msrv:\n    x: 1\n"
        new = old.replace("x: 1", "x: 2")
        self.assertIn("msrv", self.route(".github/workflows/ci.yml", blobs={".github/workflows/ci.yml": (old, new)})["segments"])
        with self.assertRaises(p.MappingError):
            self.route(".github/workflows/ci.yml", blobs={".github/workflows/ci.yml": (old, new.replace("msrv", "mystery"))})

    def test_added_workflow_has_no_base_jobs(self):
        path = ".github/workflows/license-promote.yml"
        new = "name: Promote\njobs:\n  promote:\n    runs-on: ubuntu-latest\n"
        caps = {"license_policy": True, "real_tor_channel": False}
        result = self.route(path, blobs={path: ("", new)}, capabilities=caps)
        self.assertIn("license-offline", result["segments"])
        self.assertFalse(result["full"])
        for invalid in ("", "name: Promote\n"):
            with self.subTest(invalid=invalid), self.assertRaises(p.MappingError):
                self.route(path, blobs={path: (new, invalid)}, capabilities=caps)

    def test_legacy_license_portability_migration(self):
        old = ("name: CI\njobs:\n  portability-diagnostics:\n"
               "    strategy:\n      matrix:\n        include:\n"
               "          - target: x86_64-unknown-linux-musl\n"
               "          - target: aarch64-unknown-linux-musl\n"
               "          - target: aarch64-unknown-linux-gnu\n")
        new = "name: CI\njobs:\n  native-portability:\n    runs-on: ${{ matrix.runner }}\n"
        result = self.route(".github/workflows/ci.yml",
                            blobs={".github/workflows/ci.yml": (old, new)},
                            capabilities={"license_policy": True, "real_tor_channel": False})
        self.assertFalse(result["full"])
        self.assertIn("native-portability", result["segments"])
        self.assertEqual({row["target"] for row in result["native_rows"]},
                         {"x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl",
                          "aarch64-unknown-linux-gnu"})
        self.assertNotIn("tor", result["segments"])

    def test_sdk_facade_selects_the_feature_matrix(self):
        facade = self.route("apps/sdk/src/lib.rs")
        self.assertEqual(facade["packages"], ["tor-socks5"])
        self.assertIn("features", facade["segments"])
        example = self.route("apps/sdk/examples/embedded_server.rs")
        self.assertEqual(example["packages"], ["tor-socks5"])
        self.assertIn("features", example["segments"])
        self.assertNotIn("features", self.route("packages/auth/src/lib.rs")["segments"])

    def test_sdk_facade_feature_matrix_is_manifest_driven(self):
        root = ROOT
        manifest = p.tomllib.loads((root / "apps/sdk/Cargo.toml").read_text(encoding="utf-8"))
        entries = p.feature_entries(manifest)
        feature_rows = [entry["feature"] for entry in entries if entry["kind"] == "feature"]
        self.assertEqual(feature_rows[0], None)
        self.assertEqual(set(feature_rows[1:]), {
            "acl", "socks5", "auth", "config", "bridges", "route", "tor", "fetch", "dns",
            "onion", "onion-keys", "onion-host", "onion-service", "runtime", "pt", "server", "full",
        })
        example_rows = [entry for entry in entries if entry["kind"] == "example"]
        self.assertEqual(example_rows, [
            {"kind": "example", "name": example["name"],
             "required_features": example.get("required-features", [])}
            for example in manifest["example"]
        ])
        embedded = next(entry for entry in example_rows if entry["name"] == "embedded_server")
        self.assertEqual(embedded["required_features"], ["server"])

    def test_contracts_and_native(self):
        self.assertNotIn("tor", self.route("apps/socks5-proxy/src/commands/auth.rs")["segments"])
        self.assertIn("tor", self.route("apps/socks5-proxy/src/tor/channel.rs")["segments"])
        self.assertIn("tor", self.route("apps/sdk/crates/runtime/src/tor/conn_health.rs")["segments"])
        self.assertIn("tor", self.route("apps/sdk/crates/runtime/src/bridges/bridge_verifier.rs")["segments"])
        self.assertNotIn("tor", self.route("apps/sdk/crates/runtime/src/fetch/seed.rs")["segments"])
        self.assertNotIn("tor", self.route("apps/sdk/crates/runtime/src/lib.rs")["segments"])
        self.assertIn("tor", self.route("apps/sdk/crates/server/src/tor/channel.rs")["segments"])
        self.assertIn("tor", self.route("apps/sdk/crates/server/src/bridges/bridge_verifier.rs")["segments"])
        self.assertNotIn("tor", self.route("apps/sdk/crates/server/src/commands/auth.rs")["segments"])
        self.assertNotIn("tor", self.route("apps/sdk/crates/server/src/lib.rs")["segments"])
        self.assertIn("license-offline", self.route(".github/release/license/check.py")["segments"])
        self.assertEqual(self.route("LICENSE-MIT")["segments"], ["fast"])
        self.assertEqual(self.route("Cargo.toml", blobs={"Cargo.toml": ("[workspace]\nresolver='2'", "[workspace]\nresolver='2'")})["segments"],
                         ["fast"])
        result = self.route("Cargo.toml", blobs={"Cargo.toml": ("[workspace]\nresolver='2'", "[workspace]\nresolver='2'")},
                            capabilities={"license_policy": True})
        self.assertEqual(result["segments"], ["fast", "license-audit"])
        self.assertEqual(self.route("Cargo.lock", blobs={"Cargo.lock": ("version=4", "version=4")},
                                    capabilities={"license_policy": True})["segments"], ["fast", "license-audit"])
        self.assertNotIn("license-audit", self.route("Cargo.lock", blobs={"Cargo.lock": ("version=4", "version=4")})["segments"])
        self.assertEqual(self.route("vendor/README.md", capabilities={"license_policy": True})["segments"], ["fast"])
        self.assertEqual(self.route("vendor/PROVENANCE.md", capabilities={"license_policy": True})["segments"], ["fast", "vendor-notices"])
        with self.assertRaisesRegex(p.MappingError, "missing mapping"):
            self.route("vendor/NOTICE", capabilities={"license_policy": True})
        full_without_license = self.route(mode="sprint-full", capabilities={"license_policy": False,
                                                                                "real_tor_channel": False})
        self.assertFalse({"license-offline", "license-audit"} & set(full_without_license["segments"]))
        license_root = self.route("LICENSE-MIT", capabilities={"license_policy": True})
        self.assertEqual(license_root["segments"], ["fast", "license-audit", "license-offline"])
        self.assertEqual(self.route(".github/release/license/README.md", capabilities={"license_policy": True})["segments"], ["fast"])
        self.assertEqual(self.route(".github/license/README.md", capabilities={"license_policy": True})["segments"], ["fast"])
        with self.assertRaisesRegex(p.MappingError, "missing mapping"):
            self.route(".github/deny.toml")
        with self.assertRaisesRegex(p.MappingError, "missing mapping: путь: deny.toml"):
            self.route("deny.toml")
        result = self.route("apps/socks5-proxy/build.rs")
        self.assertNotIn("license-offline", result["segments"])
        self.assertIn({"runner": "ubuntu-latest", "target": "x86_64-unknown-linux-musl", "musl": True}, result["native_rows"])
        cfg = {".cargo/config.toml": ("", '[target.x86_64-unknown-linux-musl]\nlinker="musl-gcc"')}
        self.assertEqual(len(self.route(".cargo/config.toml", blobs=cfg)["native_rows"]), 1)
        with self.assertRaisesRegex(p.MappingError, "missing mapping"):
            self.route("scripts/testing/unknown.sh")
        with self.assertRaisesRegex(p.MappingError, "missing mapping"):
            self.route(".cargo/unknown")

    def test_workflow_command_packages(self):
        path = ".github/workflows/ci.yml"
        for job in ("clippy-affected", "msrv", "android", "real-tor-channel", "plan"):
            old = "name: CI\non:\n  push:\njobs:\n  " + job + ":\n    x: 1\n"
            result = self.route(path, blobs={path: (old, old.replace("x: 1", "x: 2"))})
            if job == "plan":
                self.assertEqual(result["segments"], ["fast"])
            elif job == "real-tor-channel":
                self.assertIn("tor", result["segments"])
                self.assertNotIn("rust", result["segments"])
            else:
                segment = "rust" if job == "clippy-affected" else job
                self.assertTrue(result["command_packages"][segment])
        old = "name: CI\non:\n  push:\njobs:\n  plan:\n    x: 1\n"
        self.assertEqual(self.route(path, blobs={path: (old, old.replace("push:", "pull_request:"))})["segments"], ["fast"])
        with self.assertRaisesRegex(p.MappingError, "missing mapping"):
            self.route(path, blobs={path: (old, old.replace("name: CI", "unknown: CI"))})

    def test_graph_validation_and_checkout(self):
        with self.assertRaises(p.MappingError):
            p.Graph({"packages": [], "workspace_members": [], "resolve": None}, "/repo")
        def mismatch(*args):
            return b"checkout" if args[-1] == "HEAD^{commit}" else b"requested"
        with self.assertRaisesRegex(p.MappingError, "HEAD"):
            p.comparison("push", "affected", "base", "head", "", mismatch)
        result = self.route(mode="sprint-full")
        expected = sorted(self.g.packages[i]["name"] for i in self.g.members)
        self.assertEqual(result["packages"], expected)
        self.assertEqual(result["command_packages"]["rust"], expected)
        self.assertIn({"segment": "rust", "target": "macos-latest"}, result["target_rows"])
        self.assertIn("features", result["segments"])
        self.assertIn("stress", result["segments"])
        self.assertTrue(result["native_rows"])
        self.assertIn("tor-socks5-auth", result["library_packages"])

    def test_ci_workflow_consumers(self):
        workflow = ROOT / ".github/workflows/ci.yml"
        blocks = p.workflow_blocks(workflow.read_text(encoding="utf-8"))
        for job in ("rust", "msrv", "android", "docs-contract", "native-portability", "vendor-extra", "features", "stress", "license-offline", "license-audit", "vendor-notices", "real-tor-channel", "installer-sh", "installer-windows", "release-scripts"):
            self.assertIn(job, blocks)
            self.assertIn("contains(fromJSON(needs.plan.outputs.plan).segments", blocks[job])
            self.assertIn(job, blocks["required"])
        self.assertNotIn("license-lifecycle", blocks)
        self.assertIn("always()", blocks["required"])
        self.assertIn("planner.feature_entries(manifest)", blocks["features"])
        self.assertIn('"--no-default-features"', blocks["features"])
        self.assertIn('"clippy", *args, "--all-targets"', blocks["features"])
        self.assertIn('"--test", "surface"', blocks["features"])
        self.assertIn('"--example", entry["name"]', blocks["features"])
        self.assertIn("cargo deny --locked --config .github/deny.toml check licenses", blocks["license-audit"])
        self.assertIn("cargo fetch --locked", blocks["license-audit"])
        self.assertNotIn("python", blocks["license-audit"])
        self.assertNotIn("artifact", blocks["license-audit"])
        self.assertIn("test -s LICENSE-MIT && test -s LICENSE-APACHE && test -s .github/deny.toml", blocks["license-offline"])
        self.assertNotIn("python", blocks["license-offline"])
        policy_change = self.route(".github/deny.toml", capabilities={"license_policy": True})
        self.assertEqual(policy_change["segments"], ["fast", "license-audit", "license-offline"])
        full = self.route(mode="sprint-full", capabilities={"license_policy": True,
                                                             "real_tor_channel": False})
        self.assertTrue({"license-offline", "license-audit"} <= set(full["segments"]))

    def test_macos_loopback_fixtures(self):
        root = ROOT
        alias = "sudo ifconfig lo0 alias 127.0.0.2 up"
        for name, job in (("ci.yml", "rust"), ("nightly.yml", "flaky-hunt")):
            with self.subTest(workflow=name):
                blocks = p.workflow_blocks((root / ".github/workflows" / name).read_text(encoding="utf-8"))
                self.assertIn("if: runner.os == 'macOS'", blocks[job])
                self.assertIn(alias, blocks[job])
                self.assertLess(blocks[job].index(alias), blocks[job].index("cargo nextest run"))

    def test_specific_corrections(self):
        path = ".github/workflows/ci.yml"
        old = """name: CI
on:
  push:
permissions:
  contents: read
env:
  CARGO_BUILD_JOBS: '2'
jobs:
  rust:
    x: 1
"""
        def workflow(new):
            return self.route(path, blobs={path: (old, new)})
        self.assertEqual(workflow(old.replace("contents: read", "contents: write"))["segments"], ["fast"])
        self.assertEqual(workflow(old.replace("'2'", "'3'"))["segments"], ["fast"])
        self.assertIn("rust", workflow(old.replace("x: 1", "x: 2"))["segments"])
        for new in (old.replace("CARGO_BUILD_JOBS", "UNKNOWN"), old.replace("push:", "schedule:")):
            with self.assertRaisesRegex(p.MappingError, "missing mapping"):
                workflow(new)
        night = ".github/workflows/nightly.yml"
        before = """name: Night
jobs:
  full:
    x: 1
  report:
    x: 1
"""
        after = """name: Night
jobs:
  report:
    x: 1
"""
        result = self.route(night, blobs={night: (before, after)})
        self.assertIn("rust", result["segments"])
        self.assertIn("regression", result["segments"])
        self.assertNotIn("stress", result["segments"])
        self.assertNotIn("features", result["segments"])
        with self.assertRaisesRegex(p.MappingError, "missing mapping"):
            self.route(night, blobs={night: (after, after + "  mystery:\n    x: 1\n")})
        example = self.route("packages/proxy-config/examples/sample.ktav")
        self.assertEqual(example["segments"], ["docs-contract", "fast"])
        self.assertEqual(example["packages"], [])
        caps = {"license_policy": True}
        readme = self.route("README.md", capabilities=caps)
        self.assertFalse(set(readme["segments"]) & {"license-offline", "license-audit", "native-portability"})
        bundle = ".github/workflows/license-bundle.yml"
        before = "name: Bundle\njobs:\n  guard:\n    x: 1\n  build:\n    x: 1\n"
        changed = self.route(bundle, blobs={bundle: (before, before.replace("x: 1", "x: 2"))}, capabilities=caps)
        self.assertEqual(changed["segments"], ["fast", "license-offline"])
        interface = self.route(".github/release/license/check.py", capabilities=caps)
        self.assertEqual(interface["segments"], ["fast", "license-audit", "license-offline"])
        self.assertEqual(interface["command_packages"]["android"], [])
        full = self.route(mode="sprint-full", capabilities={"license_policy": True})
        self.assertIn("license-audit", full["segments"])
        release = ".github/workflows/release.yml"
        a = """name: Release
jobs:
  build:
    x: 1
"""
        self.assertIn("license-offline", self.route(release, blobs={release: (a, a.replace("1", "2"))}, capabilities=caps)["segments"])
        with self.assertRaisesRegex(p.MappingError, "missing mapping"):
            self.route(release, blobs={release: (a, a.replace("build", "unknown"))})
        native = {"Cargo.toml": ('[workspace.dependencies]\nopenssl-sys="1"', '[workspace.dependencies]\nopenssl-sys="2"')}
        result = self.route("Cargo.toml", blobs=native, capabilities=caps)
        self.assertEqual(result["packages"], ["socks5-proxy"])
        self.assertIn("aarch64-unknown-linux-musl", [row["target"] for row in result["native_rows"]])
        self.assertIn("x86_64-pc-windows-msvc", [row["target"] for row in result["native_rows"]])
        with self.assertRaisesRegex(p.MappingError, "missing mapping"):
            self.route("Cargo.toml", blobs={"Cargo.toml": (native["Cargo.toml"][0], "[workspace.dependencies]\n")})
        member = "packages/auth/Cargo.toml"
        with self.assertRaisesRegex(p.MappingError, "missing mapping"):
            self.route(member, blobs={member: ("[dev-dependencies]\nfoo='1'", "[dev-dependencies]\n")})
        nextest = ".config/nextest.toml"
        result = self.route(nextest, blobs={nextest: ("[profile.ci]\nretries=0", "[profile.ci]\nretries=1")})
        self.assertIn("rust", result["segments"])
        self.assertNotIn("stress", result["segments"])
        with self.assertRaisesRegex(p.MappingError, "missing mapping"):
            self.route("rust-toolchain.toml")
        self.assertEqual(set(result["segments"]), set(result["reasons"]))


if __name__ == "__main__":
    unittest.main()
