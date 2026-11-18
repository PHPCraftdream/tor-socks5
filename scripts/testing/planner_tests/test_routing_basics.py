"""Маршрутизация: пакеты, документация, граф, манифесты."""
import unittest

from support import p, graph, lock_graph, lock_package, lock_text, RoutingCase


class RoutingBasics(RoutingCase):
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
        self.assertEqual(self.route("docs/project/licensing.md")["segments"], ["fast"])
        self.assertEqual(self.route("docs/project/license-policy.md")["segments"], ["fast"])
        self.assertEqual(self.route("vendor/README.md")["segments"], ["fast"])
        self.assertEqual(self.route("vendor/PROVENANCE.md")["segments"], ["fast", "vendor-notices"])
        with self.assertRaises(p.MappingError):
            self.route("vendor/unknown-control.txt")
        with self.assertRaisesRegex(p.MappingError, "missing mapping: путь: deny.toml"):
            self.route("deny.toml")
        caps = {"license_policy": True, "real_tor_channel": False}
        for path in (".github/release/license/README.md", "docs/project/licensing.md", "packages/auth/README.md", "vendor/README.md"):
            result = self.route(path, capabilities=caps)
            self.assertEqual(result["segments"], ["fast"])
            self.assertEqual(result["packages"], [])
            self.assertEqual(result["native_rows"], [])
        for path in (".github/release/license/bundle.py", ".github/release/license/reviews/evidence.md"):
            result = self.route(path, capabilities=caps)
            self.assertEqual(result["segments"], ["fast", "license-audit", "license-offline"])
            self.assertEqual(result["packages"], [])
            self.assertEqual(result["native_rows"], [])

    def test_install_license_tor_native(self):
        self.assertIn("installer-sh", self.route(".github/install/install.sh")["segments"])
        self.assertIn("installer-windows", self.route(".github/install/install.ps1")["segments"])
        self.assertIn("release", self.route(".github/release/publish.sh")["segments"])
        self.assertEqual(self.route("LICENSE-MIT", capabilities={"license_policy": True})["segments"],
                         ["fast", "license-audit", "license-offline"])
        self.assertIn("tor", self.route("packages/bridge-probe/src/lib.rs")["segments"])
        self.assertIn({"segment": "rust", "target": "windows-latest"}, self.route("packages/auth/src/lib.rs")["target_rows"])

    def test_graph_vendor_sdk(self):
        result = self.route("vendor/tor-dirclient/src/lib.rs")
        self.assertIn("vendor", result["segments"])
        self.assertIn("vendor-notices", result["segments"])
        self.assertNotIn("license-audit", result["segments"])
        for path in (".github/license/check_vendor_notices.py", ".github/license/test_check_vendor_notices.py"):
            self.assertEqual(self.route(path)["segments"], ["fast", "vendor-notices"])
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

    def test_profile_package_override_mapping(self):
        graph = lock_graph()
        old = "[profile.dev.package.resocks5-net]\nopt-level = 1\n"
        new = "[profile.dev.package.resocks5-net]\nopt-level = 3\n"
        self.assertEqual(p.manifest_seeds(old, new, graph), {"sdk"})
        self.assertEqual(p.manifest_seeds("", new, graph), {"sdk"})
        for bad_old, bad_new in (
                ("[profile.release]\nlto = 'thin'\n", "[profile.release]\nlto = 'fat'\n"),
                ("[profile.dev]\nopt-level = 0\n", "[profile.dev]\nopt-level = 1\n"),
                ("", '[profile.dev.package."*"]\nopt-level = 3\n'),
                ("", "[profile.dev.package.not-in-graph]\nopt-level = 3\n")):
            with self.subTest(change=bad_new), self.assertRaisesRegex(p.MappingError, "missing mapping"):
                p.manifest_seeds(bad_old, bad_new, graph)

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
        glob_new = old.replace('"apps/*"]', '"apps/*", "apps/sdk/crates/*"]')
        glob_graph = lock_graph(extra_members=(
            ("tor-onion", "tor-socks5-onion", "0.2.0", None, "apps/sdk/crates/onion", "lib"),))
        self.assertEqual(p.manifest_seeds(old, glob_new, glob_graph), {"tor-onion"})
        glob_result = p.plan(glob_graph, ["Cargo.toml"], lambda path: (old, glob_new))
        self.assertEqual(glob_result["packages"], ["tor-socks5-onion"])
        self.assertIn("rust", glob_result["segments"])
        self.assertIn("msrv", glob_result["segments"])
        multi_graph = lock_graph(extra_members=(
            ("tor-onion", "tor-socks5-onion", "0.2.0", None, "apps/sdk/crates/onion", "lib"),
            ("tor-runtime", "tor-socks5-runtime", "0.2.0", None, "apps/sdk/crates/runtime", "lib")))
        self.assertEqual(p.manifest_seeds(old, glob_new, multi_graph),
                         {"tor-onion", "tor-runtime"})
        for invalid_old, invalid_new in (
                (new, old),
                (old, old.replace('"apps/*"]', '"apps/*", "nowhere/*"]')),
                (old, old.replace('"apps/*"]', '"apps/*", "../outside"]')),
                (old, old.replace('"apps/*"]', '"apps/*", "/absolute/member"]')),
                (old, old.replace('"apps/*"]', '"apps/*", "vendor/missing"]')),
                (old, old.replace('"apps/*"]', '"apps/*", "vendor\\\\tor-ptmgr"]')),
                (old, old.replace('"apps/*"]', '"apps/*", "C:/outside/member"]')),
                (new, new.replace('"packages/*", ', ''))):
            with self.subTest(member=invalid_new), self.assertRaisesRegex(p.MappingError, "missing mapping"):
                p.manifest_seeds(invalid_old, invalid_new, graph)
        duplicate_member = old.replace('"apps/*"]', '"apps/*", "vendor/tor-ptmgr", "vendor/tor-ptmgr"]')
        with self.assertRaisesRegex(p.MappingError, "missing mapping"):
            p.manifest_seeds(old, duplicate_member, graph)
        with self.assertRaisesRegex(p.MappingError, "missing mapping"):
            p.manifest_seeds(new, new.replace('"packages/*", ', ''), graph)
        ambiguous_graph = lock_graph(extra_members=(
            ("tor-ptmgr-a", "tor-ptmgr", "0.47.0", None, "vendor/tor-ptmgr", "lib"),
            ("tor-ptmgr-b", "tor-ptmgr", "0.47.0", None, "vendor/tor-ptmgr", "lib")))
        with self.assertRaisesRegex(p.MappingError, "missing mapping"):
            p.manifest_seeds(old, new, ambiguous_graph)


if __name__ == "__main__":
    unittest.main()
