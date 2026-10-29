#!/usr/bin/env python3
"""Изолированные проверки маршрутизации без git и cargo."""
import importlib.util
import os
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("ci_planner", Path(__file__).with_name("ci_planner.py"))
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


def graph():
    names = {
        "proxy": ("socks5-proxy", "apps/socks5-proxy"),
        "auth": ("tor-socks5-auth", "packages/auth"),
        "config": ("tor-socks5-config", "packages/proxy-config"),
        "acl": ("tor-socks5-client-acl", "packages/proxy-config/client-acl"),
        "arti": ("arti-wrapper", "packages/arti-wrapper"),
        "bridge": ("bridge-probe", "packages/bridge-probe"),
        "ffi": ("android-ffi", "packages/android-ffi"),
        "sdk": ("resocks5-net", "external/sdk"),
        "vendor": ("tor-dirclient", "vendor/tor-dirclient"),
        "middle": ("middle", "external/middle"),
        "native": ("openssl-sys", "external/openssl-sys"),
    }
    root = Path(__file__).resolve().parent / "fixture-repo"
    packages = [{"id": i, "name": name, "manifest_path": str(root / path / "Cargo.toml"), "targets": [{"kind": ["lib"]}]} for i, (name, path) in names.items()]
    edges = {"proxy": ["auth", "config", "bridge", "arti", "sdk", "native"], "ffi": ["config", "auth"], "bridge": ["middle"], "arti": [], "middle": ["vendor"], "acl": [], "auth": ["acl"], "config": ["acl"], "sdk": [], "vendor": [], "native": []}
    nodes = [{"id": i, "deps": [{"pkg": d, "name": "alias_" + d, "dep_kinds": [{"kind": "build" if d == "middle" else "dev" if d == "auth" else None, "target": "cfg(unix)" if d == "vendor" else None}]} for d in deps]} for i, deps in edges.items()]
    return p.Graph({"packages": packages, "workspace_members": ["proxy", "auth", "config", "acl", "bridge", "arti", "ffi"], "resolve": {"nodes": nodes}}, root)


class Routing(unittest.TestCase):
    def setUp(self):
        self.g = graph()

    def route(self, *paths, blobs=None, mode="affected", capabilities=None, event="pull_request"):
        return p.plan(self.g, paths, lambda path: blobs[path], mode, capabilities, event)

    def test_proxy_auth_config(self):
        self.assertEqual(self.route("apps/socks5-proxy/src/main.rs")["packages"], ["socks5-proxy"])
        auth = self.route("packages/auth/src/lib.rs")
        self.assertEqual(auth["packages"], ["android-ffi", "socks5-proxy", "tor-socks5-auth"])
        self.assertNotIn("tor", auth["segments"])
        self.assertIn("android", self.route("packages/proxy-config/src/lib.rs")["segments"])
        self.assertEqual(self.route("packages/proxy-config/src/lib.rs")["packages"], ["android-ffi", "socks5-proxy", "tor-socks5-config"])
        self.assertEqual(self.route("packages/proxy-config/client-acl/src/lib.rs")["packages"], ["android-ffi", "socks5-proxy", "tor-socks5-auth", "tor-socks5-client-acl", "tor-socks5-config"])
        self.assertEqual(self.route("packages/arti-wrapper/src/lib.rs")["packages"], ["arti-wrapper", "socks5-proxy"])
        self.assertEqual(self.g.owner("packages/proxy-config/client-acl/src/lib.rs"), "acl")
        for path in ("packages/proxy-config/src/lib.rs", "packages/proxy-config/src/bridges.rs",
                     "packages/proxy-config/client-acl/src/lib.rs"):
            self.assertIn("tor", self.route(path)["segments"])
        self.assertNotIn("tor", self.route("docs/guide/auth.md")["segments"])

    def test_documentation(self):
        for path in ("README.md", "docs/guide/auth.md", "tor-socks5.example.ktav"):
            result = self.route(path)
            self.assertIn("docs-contract", result["segments"])
            self.assertNotIn("android", result["segments"])
        self.assertEqual(self.route("packages/auth/README.md")["segments"], ["fast"])
        self.assertEqual(self.route("apps/socks5-proxy/src/main.rs")["command_packages"]["android"], ["socks5-proxy"])
        self.assertIn("tor", self.route("packages/arti-wrapper/src/lib.rs")["segments"])
        self.assertEqual(self.route("docs/plans/note.md")["segments"], ["fast"])

    def test_install_license_tor_native(self):
        self.assertIn("installer-sh", self.route(".github/install/install.sh")["segments"])
        self.assertIn("installer-windows", self.route(".github/install/install.ps1")["segments"])
        self.assertIn("release", self.route(".github/release/publish.sh")["segments"])
        self.assertIn("license-offline", self.route("LICENSE-MIT")["segments"])
        self.assertIn("tor", self.route("packages/bridge-probe/src/lib.rs")["segments"])
        self.assertIn({"segment": "rust", "target": "windows-latest"}, self.route("packages/auth/src/lib.rs")["target_rows"])

    def test_graph_vendor_sdk(self):
        result = self.route("vendor/tor-dirclient/src/lib.rs")
        self.assertIn("vendor", result["segments"])
        self.assertIn("bridge-probe", result["packages"])
        self.assertEqual(self.route(".github/actions/setup-local-sdk/action.yml")["packages"], ["socks5-proxy"])

    def test_manifest_and_lock(self):
        blobs = {"Cargo.toml": ('[workspace.dependencies]\nresocks5-net = "1"', '[workspace.dependencies]\nresocks5-net = "2"')}
        self.assertIn("socks5-proxy", self.route("Cargo.toml", blobs=blobs)["packages"])
        blobs = {"Cargo.lock": ('version = 3\n[[package]]\nname = "resocks5-net"\nversion = "1"', 'version = 3\n[[package]]\nname = "resocks5-net"\nversion = "2"')}
        self.assertIn("socks5-proxy", self.route("Cargo.lock", blobs=blobs)["packages"])
        with self.assertRaises(p.MappingError):
            self.route("Cargo.toml", blobs={"Cargo.toml": ("[workspace]\nresolver='1'", "[workspace]\nresolver='2'")})

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

    def test_contracts_and_native(self):
        self.assertNotIn("tor", self.route("apps/socks5-proxy/src/commands/auth.rs")["segments"])
        self.assertIn("tor", self.route("apps/socks5-proxy/src/tor/channel.rs")["segments"])
        self.assertIn("license-offline", self.route(".github/release/license/check.py")["segments"])
        self.assertIn("license-audit", self.route(".github/deny.toml")["segments"])
        with self.assertRaisesRegex(p.MappingError, "missing mapping"):
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
        workflow = Path(__file__).resolve().parents[2] / ".github/workflows/ci.yml"
        blocks = p.workflow_blocks(workflow.read_text(encoding="utf-8"))
        for job in ("rust", "msrv", "android", "docs-contract", "native-portability", "vendor-extra", "features", "stress", "license-offline", "license-audit", "license-lifecycle", "real-tor-channel", "installer-sh", "installer-windows", "release-scripts"):
            self.assertIn(job, blocks)
            self.assertIn("contains(fromJSON(needs.plan.outputs.plan).segments", blocks[job])
            self.assertIn(job, blocks["required"])
        self.assertIn("github.event_name == 'pull_request' && contains(fromJSON(needs.plan.outputs.plan).segments", blocks["license-lifecycle"])
        self.assertIn("if: github.event_name == 'pull_request'", blocks["license-lifecycle"])
        self.assertIn("always()", blocks["required"])
        self.assertIn("cargo deny", blocks["license-audit"])
        self.assertNotIn("license-audit", self.route(mode="sprint-full")["segments"])

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
        caps = {"license_stack": True}
        readme = self.route("README.md", capabilities=caps)
        self.assertTrue(readme["license_stack"])
        self.assertFalse(set(readme["segments"]) & {"license-offline", "license-audit", "license-lifecycle", "native-portability"})
        for event in ("push", "workflow_dispatch"):
            result = self.route("apps/socks5-proxy/build.rs", capabilities=caps, event=event)
            self.assertNotIn("license-lifecycle", result["segments"])
            for segment in ("license-offline", "license-audit", "rust", "native-portability"):
                self.assertIn(segment, result["segments"])
        bundle = ".github/workflows/license-bundle.yml"
        before = "name: Bundle\njobs:\n  guard:\n    x: 1\n  build:\n    x: 1\n"
        changed = self.route(bundle, blobs={bundle: (before, before.replace("x: 1", "x: 2"))}, capabilities=caps)
        self.assertIn("license-offline", changed["segments"])
        self.assertIn("license-lifecycle", changed["segments"])
        self.assertIn("license-lifecycle", self.route("apps/socks5-proxy/build.rs", capabilities=caps)["segments"])
        interface = self.route(".github/release/license/check.py", capabilities=caps)
        self.assertIn("license-lifecycle", interface["segments"])
        self.assertIn("android", interface["segments"])
        self.assertEqual(interface["command_packages"]["android"], ["socks5-proxy"])
        full = self.route(mode="sprint-full", capabilities=caps)
        self.assertIn("license-audit", full["segments"])
        self.assertNotIn("license-lifecycle", full["segments"])
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
        self.assertIn("license-lifecycle", result["segments"])
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

    def test_targeted_mappings(self):
        for job, expected in (("report", ["fast", "regression"]),
                              ("vendor-extra", ["fast", "regression", "vendor-extra"]),
                              ("features", ["fast", "features", "regression"])):
            path = ".github/workflows/nightly.yml"
            old = "name: Night\njobs:\n  " + job + ":\n    x: 1\n"
            result = self.route(path, blobs={path: (old, old.replace("x: 1", "x: 2"))})
            self.assertEqual(result["segments"], expected)
            needs = {name: {"result": "success" if any(s in result["segments"] for s in selections) else "skipped"} for name, selections in p.RESULT_JOBS.items()}
            needs["plan"] = {"result": "success"}
            self.assertEqual(needs["stress"]["result"], "skipped")
            p.validate_results(result, needs)
        for filename in ("test_release.py", "gh_mock.py"):
            path = ".github/install/tests/" + filename
            self.assertEqual(self.route(path)["segments"], ["fast", "release"])
            self.assertEqual(self.route(path, capabilities={"license_stack": True})["segments"], ["fast", "license-offline", "release"])
        path = ".github/install/tests/fixtures.py"
        self.assertEqual(self.route(path)["segments"], ["fast", "installer-sh", "installer-windows", "release"])
        self.assertEqual(self.route(path, capabilities={"license_stack": True})["segments"], ["fast", "installer-sh", "installer-windows", "license-offline", "release"])
        self.assertEqual(self.route(".github/install/install.sh")["segments"], ["fast", "installer-sh"])
        for path, old, new in (("Cargo.toml", '[workspace.dependencies]\nold="1"', '[workspace.dependencies]\nnew="1"'),
                               ("Cargo.lock", 'version=3\n[[package]]\nname="old"\nversion="1"', 'version=3\n')):
            with self.assertRaisesRegex(p.MappingError, "missing mapping"):
                self.route(path, blobs={path: (old, new)}, capabilities={"license_stack": True})
        workflow = Path(__file__).resolve().parents[2] / ".github/workflows/ci.yml"
        blocks = p.workflow_blocks(workflow.read_text(encoding="utf-8"))
        self.assertNotIn("'regression'", blocks["stress"])
        self.assertIn("name: CI required", blocks["required"])

    def test_required_results(self):
        plan = {"segments": ["fast", "rust"]}
        needs = {job: {"result": "success" if any(s in plan["segments"] for s in selections) else "skipped"} for job, selections in p.RESULT_JOBS.items()}
        needs["plan"] = {"result": "success"}
        p.validate_results(plan, needs)
        for result in ("failure", "cancelled", "skipped"):
            needs["rust"]["result"] = result
            with self.assertRaises(p.MappingError):
                p.validate_results(plan, needs)
        needs["rust"]["result"] = "success"
        needs["android"]["result"] = "success"
        with self.assertRaises(p.MappingError):
            p.validate_results(plan, needs)
        needs["android"]["result"] = "skipped"
        p.validate_results(plan, needs)
        lifecycle_plan = {"segments": ["fast", "rust", "license-lifecycle"]}
        with self.assertRaises(p.MappingError):
            p.validate_results(lifecycle_plan, needs)
        needs["license-lifecycle"]["result"] = "success"
        p.validate_results(lifecycle_plan, needs)
        needs["license-lifecycle"]["result"] = "skipped"
        with self.assertRaisesRegex(p.MappingError, "нет потребителя"):
            p.validate_results({"segments": ["fast", "rust", "unknown-segment"]}, needs)
        del needs["android"]
        with self.assertRaises(p.MappingError):
            p.validate_results(plan, needs)

    def test_events(self):
        calls = []
        def git(*args):
            calls.append(args)
            return b"ancestor\n"
        self.assertEqual(p.comparison("pull_request", "affected", "base", "head", "", git), "ancestor")
        self.assertEqual(p.comparison("push", "affected", "before", "head", "", git), "before")
        self.assertEqual(p.comparison("workflow_dispatch", "affected", "", "head", "main", git), "main")
        with self.assertRaises(p.MappingError):
            p.comparison("workflow_dispatch", "affected", "", "head", "", git)
        with self.assertRaises(p.MappingError):
            p.comparison("push", "sprint-full", "base", "head", "", git)
        self.assertIsNone(p.comparison("workflow_dispatch", "sprint-full", "", "head", "", git))
        self.assertTrue(self.route(mode="sprint-full")["full"])
        def failed(*args):
            raise p.MappingError("git")
        with self.assertRaises(p.MappingError):
            p.comparison("push", "affected", "base", "head", "", failed)


if __name__ == "__main__":
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("Проверки планировщика разрешены только в CI")
    unittest.main()
