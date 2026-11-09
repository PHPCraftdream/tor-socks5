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
    packages = [{"id": i, "name": name, "version": "2.0.0" if i == "sdk" else "1.0.0",
                 **({"source": "registry+https://github.com/rust-lang/crates.io-index"} if i == "sdk" else {}),
                 "manifest_path": str(root / path / "Cargo.toml"), "targets": [{"kind": ["lib"]}]}
                for i, (name, path) in names.items()]
    edges = {"proxy": ["auth", "config", "bridge", "arti", "sdk", "native"], "ffi": ["config", "auth"], "bridge": ["middle"], "arti": [], "middle": ["vendor"], "acl": [], "auth": ["acl"], "config": ["acl"], "sdk": [], "vendor": [], "native": []}
    nodes = [{"id": i, "deps": [{"pkg": d, "name": "alias_" + d, "dep_kinds": [{"kind": "build" if d == "middle" else "dev" if d == "auth" else None, "target": "cfg(unix)" if d == "vendor" else None}]} for d in deps]} for i, deps in edges.items()]
    return p.Graph({"packages": packages, "workspace_members": ["proxy", "auth", "config", "acl", "bridge", "arti", "ffi"], "resolve": {"nodes": nodes}}, root)


def lock_graph(extra_packages=(), lyrebird_versions=("0.8.0",), extra_members=()):
    root = Path(__file__).resolve().parent / "fixture-repo"
    registry = "registry+https://github.com/rust-lang/crates.io-index"
    definitions = [
        ("proxy", "socks5-proxy", "0.2.0", None, "apps/socks5-proxy", "bin"),
        ("pt-helper", "pt-helper", "0.2.0", None, "apps/pt-helper", "bin"),
        ("android", "android-ffi", "0.2.0", None, "packages/android-ffi", "lib"),
        ("unrelated", "bridge-probe", "0.2.0", None, "packages/bridge-probe", "lib"),
    ]
    definitions.extend(("lyrebird-" + version, "ptrs-gesher-lyrebird", version, registry,
                        "external/ptrs-gesher-lyrebird", "lib") for version in lyrebird_versions)
    definitions.append(("sdk", "resocks5-net", "0.5.1", registry, "external/resocks5-net", "lib"))
    definitions.extend(extra_packages)
    definitions.extend(extra_members)
    packages = []
    for ident, name, version, source, path, kind in definitions:
        package = {"id": ident, "name": name, "version": version,
                   "manifest_path": str(root / path / "Cargo.toml"), "targets": [{"kind": [kind]}]}
        if source is not None:
            package["source"] = source
        packages.append(package)
    edges = {ident: [] for ident, *_ in definitions}
    edges["proxy"] = ["lyrebird-" + lyrebird_versions[0]]
    edges["pt-helper"] = ["lyrebird-" + lyrebird_versions[0]]
    edges["lyrebird-" + lyrebird_versions[0]] = ["sdk"]
    nodes = [{"id": ident, "deps": [{"pkg": dep, "name": next(p["name"] for p in packages if p["id"] == dep),
                                        "dep_kinds": [{"kind": None, "target": None}]}
                                       for dep in deps]} for ident, deps in edges.items()]
    members = ["proxy", "pt-helper", "android", "unrelated"] + [item[0] for item in extra_members]
    return p.Graph({"packages": packages, "workspace_members": members,
                    "resolve": {"nodes": nodes}}, root)


def lock_package(name, version, source=None, dependencies=()):
    lines = ["[[package]]", "name = " + repr(name), "version = " + repr(version)]
    if source is not None:
        lines.append("source = " + repr(source))
    if dependencies:
        lines.append("dependencies = [" + ", ".join(repr(item) for item in dependencies) + "]")
    return "\n".join(lines) + "\n"


def lock_text(*packages):
    return "version = 4\n\n" + "\n".join(packages)


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
        self.assertEqual(self.route("vendor/README.md")["segments"], ["fast"])
        with self.assertRaises(p.MappingError):
            self.route("vendor/unknown-control.txt")
        caps = {"license_stack": True, "real_tor_channel": False}
        for path in (".github/release/license/README.md", "docs/project/licensing.md", "packages/auth/README.md", "vendor/README.md"):
            result = self.route(path, capabilities=caps)
            self.assertEqual(result["segments"], ["fast"])
            self.assertEqual(result["packages"], [])
            self.assertEqual(result["native_rows"], [])
        for path in (".github/release/license/bundle.py", ".github/release/license/reviews/evidence.md"):
            result = self.route(path, capabilities=caps)
            for segment in ("rust", "native-portability", "license-offline", "license-audit", "license-lifecycle"):
                self.assertIn(segment, result["segments"])
            self.assertNotIn("tor", result["segments"])

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
        registry = "registry+https://github.com/rust-lang/crates.io-index"
        old = lock_text(lock_package("resocks5-net", "1.0.0", registry))
        new = lock_text(lock_package("resocks5-net", "2.0.0", registry))
        blobs = {"Cargo.lock": (old, new)}
        self.assertIn("socks5-proxy", self.route("Cargo.lock", blobs=blobs)["packages"])
        with self.assertRaises(p.MappingError):
            self.route("Cargo.toml", blobs={"Cargo.toml": ("[workspace]\nresolver='1'", "[workspace]\nresolver='2'")})

    def test_workspace_member_addition_mapping(self):
        old = '[workspace]\nresolver = "2"\nmembers = ["packages/*", "apps/*"]\n'
        new = old.replace('"apps/*"]', '"apps/*", "vendor/tor-ptmgr"]')
        graph = lock_graph(extra_members=(
            ("tor-ptmgr", "tor-ptmgr", "0.47.0", None, "vendor/tor-ptmgr", "lib"),))
        seeds = p.manifest_seeds(old, new, graph)
        self.assertEqual(seeds, {"tor-ptmgr"})
        result = p.plan(graph, ["Cargo.toml"], lambda path: (old, new))
        self.assertEqual(result["packages"], ["tor-ptmgr"])
        self.assertIn("rust", result["segments"])
        self.assertIn("msrv", result["segments"])
        registry = "registry+https://github.com/rust-lang/crates.io-index"
        lock_before = lock_text(lock_package("resocks5-net", "0.5.0", registry))
        lock_after = lock_text(lock_package("resocks5-net", "0.5.1", registry))
        combined_blobs = {"Cargo.toml": (old, new), "Cargo.lock": (lock_before, lock_after)}
        combined = p.plan(graph, ["Cargo.toml", "Cargo.lock"], lambda path: combined_blobs[path])
        self.assertFalse(combined["full"])
        self.assertIsNone(combined["full_trigger"])
        self.assertEqual(combined["packages"], ["pt-helper", "socks5-proxy", "tor-ptmgr"])
        self.assertNotIn("bridge-probe", combined["packages"])
        for invalid_old, invalid_new in (
                (new, old),
                (old, old.replace('"apps/*"]', '"apps/*", "vendor/*"]')),
                (old, old.replace('"apps/*"]', '"apps/*", "../outside"]')),
                (old, old.replace('"apps/*"]', '"apps/*", "/absolute/member"]')),
                (old, old.replace('"apps/*"]', '"apps/*", "vendor/missing"]')),
                (old, old.replace('"apps/*"]', '"apps/*", "vendor\\\\tor-ptmgr"]')),
                (old, old.replace('"apps/*"]', '"apps/*", "C:/outside/member"]')),
                (old.replace('"packages/*", ', ''), new)):
            with self.subTest(member=invalid_new), self.assertRaisesRegex(p.MappingError, "missing mapping"):
                p.manifest_seeds(invalid_old, invalid_new, graph)
        duplicate_member = old.replace('"apps/*"]', '"apps/*", "vendor/tor-ptmgr", "vendor/tor-ptmgr"]')
        with self.assertRaisesRegex(p.MappingError, "missing mapping"):
            p.manifest_seeds(old, duplicate_member, graph)
        with self.assertRaisesRegex(p.MappingError, "missing mapping"):
            p.manifest_seeds(old.replace('"packages/*", ', ''), new, graph)
        ambiguous_graph = lock_graph(extra_members=(
            ("tor-ptmgr-a", "tor-ptmgr", "0.47.0", None, "vendor/tor-ptmgr", "lib"),
            ("tor-ptmgr-b", "tor-ptmgr", "0.47.0", None, "vendor/tor-ptmgr", "lib")))
        with self.assertRaisesRegex(p.MappingError, "missing mapping"):
            p.manifest_seeds(old, new, ambiguous_graph)

    def test_removed_lock_transitives_reach_current_consumers(self):
        registry = "registry+https://github.com/rust-lang/crates.io-index"
        before = lock_text(
            lock_package("socks5-proxy", "0.2.0", dependencies=("ptrs-gesher-lyrebird 0.7.0 (" + registry + ")",)),
            lock_package("pt-helper", "0.2.0", dependencies=("ptrs-gesher-lyrebird 0.7.0 (" + registry + ")",)),
            lock_package("ptrs-gesher-lyrebird", "0.7.0", registry,
                         ("fast-socks5",)),
            lock_package("fast-socks5", "0.10.0", registry,
                         ("tokio-stream",)),
            lock_package("tokio-stream", "0.1.18", registry),
        )
        after = lock_text(
            lock_package("socks5-proxy", "0.2.0", dependencies=("ptrs-gesher-lyrebird 0.8.0 (" + registry + ")",)),
            lock_package("pt-helper", "0.2.0", dependencies=("ptrs-gesher-lyrebird 0.8.0 (" + registry + ")",)),
            lock_package("ptrs-gesher-lyrebird", "0.8.0", registry,
                         ("resocks5-net 0.5.1 (" + registry + ")",)),
            lock_package("resocks5-net", "0.5.1", registry),
        )
        graph = lock_graph()
        blobs = {"Cargo.lock": (before, after)}
        self.assertEqual(p.lock_seeds(before, after, graph),
                         {"proxy", "pt-helper", "lyrebird-0.8.0", "sdk"})
        current_lyrebird_before = lock_text(
            lock_package("socks5-proxy", "0.2.0", dependencies=("ptrs-gesher-lyrebird 0.8.0 (" + registry + ")",)),
            lock_package("pt-helper", "0.2.0", dependencies=("ptrs-gesher-lyrebird 0.8.0 (" + registry + ")",)),
            lock_package("ptrs-gesher-lyrebird", "0.8.0", registry, ("fast-socks5",)),
            lock_package("fast-socks5", "0.10.0", registry, ("tokio-stream",)),
            lock_package("tokio-stream", "0.1.18", registry),
        )
        current_lyrebird_after = lock_text(
            lock_package("socks5-proxy", "0.2.0", dependencies=("ptrs-gesher-lyrebird 0.8.0 (" + registry + ")",)),
            lock_package("pt-helper", "0.2.0", dependencies=("ptrs-gesher-lyrebird 0.8.0 (" + registry + ")",)),
            lock_package("ptrs-gesher-lyrebird", "0.8.0", registry,
                         ("resocks5-net 0.5.1 (" + registry + ")",)),
            lock_package("resocks5-net", "0.5.1", registry),
        )
        self.assertEqual(p.lock_seeds(current_lyrebird_before, current_lyrebird_after, graph),
                         {"lyrebird-0.8.0", "sdk"})
        first = p.plan(graph, ["Cargo.lock"], lambda path: blobs[path])
        second = p.plan(graph, ["Cargo.lock"], lambda path: blobs[path])
        self.assertEqual(first, second)
        self.assertFalse(first["full"])
        self.assertIsNone(first["full_trigger"])
        self.assertEqual(first["packages"], ["pt-helper", "socks5-proxy"])
        self.assertEqual(first["command_packages"]["rust"], ["pt-helper", "socks5-proxy"])
        self.assertEqual(first["command_packages"]["msrv"], ["pt-helper", "socks5-proxy"])
        self.assertIn("rust", first["segments"])
        self.assertIn("msrv", first["segments"])
        self.assertNotIn("android-ffi", first["packages"])
        self.assertNotIn("bridge-probe", first["packages"])
        needs = {job: {"result": "success" if any(segment in first["segments"] for segment in selections) else "skipped"}
                 for job, selections in p.RESULT_JOBS.items()}
        needs["plan"] = {"result": "success"}
        p.validate_results(first, needs)

    def test_lock_removed_identity_fail_closed(self):
        graph = lock_graph()
        with self.assertRaisesRegex(p.MappingError, "missing mapping"):
            p.lock_seeds(lock_text(lock_package("orphan", "1.0.0")), lock_text(), graph)
        registry = "registry+https://github.com/rust-lang/crates.io-index"
        ambiguous = lock_text(
            lock_package("ptrs-gesher-lyrebird", "0.7.0", registry, ("fast-socks5",)),
            lock_package("fast-socks5", "0.10.0", registry),
            lock_package("fast-socks5", "0.11.0", registry),
        )
        with self.assertRaisesRegex(p.MappingError, "missing mapping"):
            p.lock_seeds(ambiguous, lock_text(), graph)
        mixed = lock_text(
            lock_package("socks5-proxy", "0.2.0", dependencies=("middle 1.0.0 (" + registry + ")",)),
            lock_package("middle", "1.0.0", registry, ("leaf 1.0.0 (" + registry + ")",)),
            lock_package("leaf", "1.0.0", registry),
            lock_package("orphan", "1.0.0"),
        )
        mixed_new = lock_text(
            lock_package("socks5-proxy", "0.2.0", dependencies=("middle 2.0.0 (" + registry + ")",)),
            lock_package("middle", "2.0.0", registry),
        )
        with self.assertRaisesRegex(p.MappingError, "missing mapping"):
            p.lock_seeds(mixed, mixed_new, lock_graph(extra_packages=(
                ("middle-new", "middle", "2.0.0", registry, "external/middle", "lib"),)))
        orphan_branch = lock_text(
            lock_package("middle", "1.0.0", registry, ("leaf 1.0.0 (" + registry + ")",)),
            lock_package("orphan-parent", "1.0.0", registry, ("leaf 1.0.0 (" + registry + ")",)),
            lock_package("leaf", "1.0.0", registry),
        )
        orphan_branch_new = lock_text(lock_package("middle", "2.0.0", registry))
        with self.assertRaisesRegex(p.MappingError, "missing mapping"):
            p.lock_seeds(orphan_branch, orphan_branch_new, lock_graph(extra_packages=(
                ("middle-new", "middle", "2.0.0", registry, "external/middle", "lib"),)))
        cyclic = lock_text(
            lock_package("cycle-a", "1.0.0", dependencies=("cycle-b 1.0.0",)),
            lock_package("cycle-b", "1.0.0", dependencies=("cycle-a 1.0.0",)),
        )
        with self.assertRaisesRegex(p.MappingError, "missing mapping"):
            p.lock_seeds(cyclic, lock_text(), graph)

    def test_lock_source_qualified_reverse_mapping(self):
        registry_a = "registry+https://example.invalid/a"
        registry_b = "registry+https://example.invalid/b"
        old = lock_text(
            lock_package("middle", "1.0.0", registry_a, ("leaf 1.0.0 (" + registry_a + ")",)),
            lock_package("other", "1.0.0", registry_a, ("leaf 1.0.0 (" + registry_b + ")",)),
            lock_package("leaf", "1.0.0", registry_a),
            lock_package("leaf", "1.0.0", registry_b),
        )
        new = lock_text(
            lock_package("middle", "2.0.0", registry_a),
            lock_package("other", "1.0.0", registry_a, ("leaf 1.0.0 (" + registry_b + ")",)),
            lock_package("leaf", "1.0.0", registry_b),
        )
        graph = lock_graph(extra_packages=(
            ("middle-new", "middle", "2.0.0", registry_a, "external/middle", "lib"),
            ("other-current", "other", "1.0.0", registry_a, "external/other", "lib"),
            ("leaf-b", "leaf", "1.0.0", registry_b, "external/leaf-b", "lib")))
        self.assertEqual(p.lock_seeds(old, new, graph), {"middle-new"})
        registry = "registry+https://github.com/rust-lang/crates.io-index"
        local_to_registry_old = lock_text(
            lock_package("socks5-proxy", "0.2.0", dependencies=("resocks5-net 0.3.0",)),
            lock_package("resocks5-net", "0.3.0"),
        )
        local_to_registry_new = lock_text(
            lock_package("socks5-proxy", "0.2.0", dependencies=("resocks5-net 0.5.1 (" + registry + ")",)),
            lock_package("resocks5-net", "0.5.1", registry),
        )
        self.assertEqual(p.lock_seeds(local_to_registry_old, local_to_registry_new, lock_graph()),
                         {"proxy", "sdk"})
        version_only_old = lock_text(
            lock_package("middle", "1.0.0", registry_a, ("leaf 1.0.0",)),
            lock_package("leaf", "1.0.0", registry_a),
        )
        version_only_new = lock_text(lock_package("middle", "2.0.0", registry_a))
        version_only_graph = lock_graph(extra_packages=(
            ("middle-new", "middle", "2.0.0", registry_a, "external/middle", "lib"),))
        self.assertEqual(p.lock_seeds(version_only_old, version_only_new, version_only_graph),
                         {"middle-new"})
        wrong_source_old = lock_text(
            lock_package("middle", "1.0.0", registry_a, ("leaf 1.0.0 (" + registry_a + ")",)),
            lock_package("leaf", "1.0.0", registry_a),
            lock_package("leaf", "1.0.0", registry_b),
        )
        wrong_source_new = lock_text(
            lock_package("middle", "1.0.0", registry_a),
            lock_package("leaf", "2.0.0", registry_b),
        )
        wrong_source_graph = lock_graph(extra_packages=(
            ("middle-current", "middle", "1.0.0", registry_a, "external/middle", "lib"),
            ("leaf-current", "leaf", "2.0.0", registry_b, "external/leaf", "lib")))
        self.assertEqual(p.lock_seeds(wrong_source_old, wrong_source_new, wrong_source_graph),
                         {"middle-current", "leaf-current"})
        without_b = lock_text(lock_package("leaf", "1.0.0", registry_b))
        leaf_graph = lock_graph(extra_packages=(
            ("leaf-b", "leaf", "1.0.0", registry_b, "external/leaf-b", "lib"),))
        with self.assertRaisesRegex(p.MappingError, "missing mapping"):
            p.lock_seeds(lock_text(lock_package("leaf", "1.0.0", registry_a)), without_b, leaf_graph)
        unresolved = lock_text(
            lock_package("middle", "1.0.0", registry_a, ("leaf",)),
            lock_package("leaf", "1.0.0", registry_a),
            lock_package("leaf", "1.0.0", registry_b),
        )
        with self.assertRaisesRegex(p.MappingError, "missing mapping"):
            p.lock_seeds(unresolved, lock_text(), graph)

    def test_lock_rejects_ambiguous_replacements_and_graph_mismatch(self):
        registry = "registry+https://github.com/rust-lang/crates.io-index"
        old = lock_text(lock_package("changed", "1.0.0", registry))
        replacements = lock_text(lock_package("changed", "2.0.0", registry),
                                 lock_package("changed", "3.0.0", registry))
        graph = lock_graph(extra_packages=(
            ("changed-2", "changed", "2.0.0", registry, "external/changed", "lib"),
            ("changed-3", "changed", "3.0.0", registry, "external/changed", "lib")))
        with self.assertRaisesRegex(p.MappingError, "missing mapping"):
            p.lock_seeds(old, replacements, graph)
        unknown_new = lock_text(lock_package("not-in-graph", "1.0.0", registry))
        with self.assertRaisesRegex(p.MappingError, "missing mapping"):
            p.lock_seeds(lock_text(), unknown_new, graph)
        wrong_graph_version = lock_graph(extra_packages=(
            ("changed-current", "changed", "2.1.0", registry, "external/changed", "lib"),))
        with self.assertRaisesRegex(p.MappingError, "missing mapping"):
            p.lock_seeds(lock_text(), lock_text(lock_package("changed", "2.0.0", registry)),
                         wrong_graph_version)

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
        caps = {"license_stack": True, "real_tor_channel": False}
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
                            capabilities={"license_stack": True, "real_tor_channel": False})
        self.assertFalse(result["full"])
        self.assertIn("native-portability", result["segments"])
        self.assertEqual({row["target"] for row in result["native_rows"]},
                         {"x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl",
                          "aarch64-unknown-linux-gnu"})
        self.assertNotIn("tor", result["segments"])
        self.assertNotIn("license-lifecycle", result["segments"])

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

    def test_macos_loopback_fixtures(self):
        root = Path(__file__).resolve().parents[2]
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
        plan = {"segments": ["fast", "rust"], "capabilities": {"real_tor_channel": True}}
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
        lifecycle_plan = {"segments": ["fast", "rust", "license-lifecycle"], "capabilities": {"real_tor_channel": True}}
        with self.assertRaises(p.MappingError):
            p.validate_results(lifecycle_plan, needs)
        needs["license-lifecycle"]["result"] = "success"
        p.validate_results(lifecycle_plan, needs)
        needs["license-lifecycle"]["result"] = "skipped"
        with self.assertRaisesRegex(p.MappingError, "нет потребителя"):
            p.validate_results({"segments": ["fast", "rust", "unknown-segment"], "capabilities": {"real_tor_channel": True}}, needs)
        del needs["android"]
        with self.assertRaises(p.MappingError):
            p.validate_results(plan, needs)

    def test_capability_contract(self):
        absent = {p.CONTRACT_MANIFEST: 'real_tor_channel = false\n'}
        read = lambda data: lambda path: data.get(path, '')
        self.assertFalse(p.contract_capability(read({}), read(absent)))
        for path in p.TOR_ANCHORS:
            with self.assertRaisesRegex(p.MappingError, 'missing mapping'):
                p.contract_capability(read({path: 'evidence'}), read(absent))
        manifest_route = self.route(p.CONTRACT_MANIFEST, capabilities={'real_tor_channel': False})
        self.assertEqual(manifest_route['segments'], ['fast', 'regression'])
        self.assertEqual(manifest_route['capability_reasons']['real_tor_channel'], 'контракт не установлен')
        for path in ('packages/proxy-config/src/lib.rs', 'packages/proxy-config/client-acl/src/lib.rs', 'packages/bridge-probe/src/lib.rs'):
            result = self.route(path, capabilities={'real_tor_channel': False})
            self.assertNotIn('tor', result['segments'])
            self.assertIn('rust', result['segments'])
            self.assertFalse(result['capabilities']['real_tor_channel'])
        self.assertNotIn('tor', self.route(mode='sprint-full', capabilities={'real_tor_channel': False})['segments'])
        installed = {path: '\n'.join(markers) for path, markers in p.TOR_MARKERS.items()}
        installed[p.CONTRACT_MANIFEST] = 'real_tor_channel = true\n'
        self.assertTrue(p.contract_capability(read({}), read(installed)))
        manifest = Path(__file__).resolve().parents[2] / p.CONTRACT_MANIFEST
        if p.tomllib.loads(manifest.read_text(encoding='utf-8'))['real_tor_channel']:
            workflow = (Path(__file__).resolve().parents[2] / '.github/workflows/ci.yml').read_text(encoding='utf-8')
            for marker in p.TOR_MARKERS['.github/workflows/ci.yml']:
                self.assertIn(marker, workflow)
        for path in p.TOR_MARKERS:
            broken = dict(installed, **{path: ''})
            with self.assertRaisesRegex(p.MappingError, 'missing mapping'):
                p.contract_capability(read(installed), read(broken))
        for broken in (absent, {}, dict(installed, **{p.CONTRACT_MANIFEST: 'unknown = true\n'})):
            with self.assertRaisesRegex(p.MappingError, 'missing mapping'):
                p.contract_capability(read(installed), read(broken))
        needs = {job: {'result': 'skipped'} for job in p.RESULT_JOBS}
        needs['plan'] = {'result': 'success'}
        with self.assertRaisesRegex(p.MappingError, 'missing mapping'):
            p.validate_results({'segments': ['tor'], 'capabilities': {'real_tor_channel': False}}, needs)

    def test_events(self):
        calls = []
        checkout = "merge"
        def git(*args):
            calls.append(args)
            if args[0] == "rev-list":
                return b"merge base head\n"
            if args[0] == "merge-base":
                return b"" if "--is-ancestor" in args else b"ancestor\n"
            ref = args[-1].removesuffix("^{commit}")
            return ((checkout if ref == "HEAD" else ref) + "\n").encode()
        self.assertEqual(p.comparison("pull_request", "affected", "base", "head", "", git), "ancestor")
        checkout = "head"
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


class CommitFooter(unittest.TestCase):
    def matches(self, message):
        return any(p.FULL_FOOTER_RE.match(line) for line in message.split("\n"))
    def test_exact_footer(self):
        self.assertTrue(self.matches("заголовок\n\nCI-Full: sprint-end"))
        self.assertTrue(self.matches("CI-Full: sprint-end"))
        self.assertTrue(self.matches("CI-Full: sprint-end\r\nвторой\r\n"))
    def test_negatives(self):
        for message in ("  CI-Full: sprint-end", "CI-Full: sprint-end ", "CI-Full:  sprint-end",
                        "CI-Full:sprint-end", "ci-full: sprint-end", "CI-Full: sprint-end.",
                        "упоминание CI-Full: sprint-end в тексте", "CI-Full: sprint-full",
                        "CI-Full: sprint-end\r \n", "X"):
            self.assertFalse(self.matches(message), message)


class PullRequestSource(unittest.TestCase):
    def git_merge(self, parents_line):
        def git(*args):
            if args[0] == "rev-list":
                return parents_line
            if args[0] == "merge-base":
                return b"mb\n"
            if args[-1] == "HEAD^{commit}":
                return b"merge\n"
            return (args[-1].removesuffix("^{commit}") + "\n").encode()
        return git
    def test_merge_checkout_parents_prove_source_and_base(self):
        git = self.git_merge(b"merge base source\n")
        self.assertEqual(p.comparison("pull_request", "affected", "base", "source", "", git), "mb")
    def test_parent_mismatch_is_rejected(self):
        for line in (b"merge other source\n", b"merge base other\n", b"merge\n"):
            with self.subTest(parents=line):
                with self.assertRaises(p.MappingError):
                    p.comparison("pull_request", "affected", "base", "source", "", self.git_merge(line))
    def test_non_pr_still_requires_exact_checkout(self):
        def git(*args):
            if args[0] == "rev-list":
                return b"merge base source\n"
            if args[-1] == "HEAD^{commit}":
                return b"other\n"
            return b"resolved\n"
        with self.assertRaises(p.MappingError):
            p.comparison("push", "affected", "before", "source", "", git)
        with self.assertRaises(p.MappingError):
            p.comparison("workflow_dispatch", "affected", "", "source", "main", git)


class WorkflowWiring(unittest.TestCase):
    def test_head_and_base_event_sources(self):
        text = (Path(__file__).resolve().parents[2] / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        def expression(prefix):
            line = next(line for line in text.splitlines() if line.strip().startswith(prefix + ": ${{"))
            return line.split("${{", 1)[1].rsplit("}}", 1)[0].strip()
        payloads = {
            "pull_request": {"github.event.pull_request.head.sha": "SRC", "github.event.pull_request.base.sha": "BASE",
                             "github.sha": "SHA", "github.event.before": "BEFORE"},
            "push": {"github.sha": "SHA", "github.event.before": "BEFORE"},
            "workflow_dispatch": {"github.sha": "SHA"},
        }
        def evaluate(expr, payload):
            for part in (item.strip() for item in expr.split("||")):
                if payload.get(part):
                    return payload[part]
            return ""
        head_expr, base_expr = expression("HEAD"), expression("BASE")
        self.assertEqual(evaluate(head_expr, payloads["pull_request"]), "SRC")
        self.assertEqual(evaluate(head_expr, payloads["push"]), "SHA")
        self.assertEqual(evaluate(head_expr, payloads["workflow_dispatch"]), "SHA")
        self.assertEqual(evaluate(base_expr, payloads["pull_request"]), "BASE")
        self.assertEqual(evaluate(base_expr, payloads["push"]), "BEFORE")
        self.assertNotIn("github.event.before", head_expr)


if __name__ == "__main__":
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("Проверки планировщика разрешены только в CI")
    unittest.main()
