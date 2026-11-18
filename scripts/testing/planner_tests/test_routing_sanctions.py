"""Маршрутизация: адресные сопоставления, санкции, capability, события."""
import unittest

from support import ROOT, p, RoutingCase


class RoutingSanctions(RoutingCase):
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
            self.assertEqual(self.route(path, capabilities={"license_policy": True})["segments"], ["fast", "release"])
        path = ".github/install/tests/fixtures.py"
        self.assertEqual(self.route(path)["segments"], ["fast", "installer-sh", "installer-windows", "release"])
        self.assertEqual(self.route(path, capabilities={"license_policy": True})["segments"], ["fast", "installer-sh", "installer-windows", "release"])
        self.assertEqual(self.route(".github/install/install.sh")["segments"], ["fast", "installer-sh"])
        path, old, new = "Cargo.toml", '[workspace.dependencies]\nold="1"', '[workspace.dependencies]\nnew="1"'
        with self.assertRaisesRegex(p.MappingError, "missing mapping"):
            self.route(path, blobs={path: (old, new)}, capabilities={"license_policy": True})
        # A lock package that only disappears touches nothing that is left.
        before, after = 'version=3\n[[package]]\nname="old"\nversion="1"', 'version=3\n'
        removed = self.route("Cargo.lock", blobs={"Cargo.lock": (before, after)},
                             capabilities={"license_policy": True})
        self.assertEqual(removed["packages"], [])
        workflow = ROOT / ".github/workflows/ci.yml"
        blocks = p.workflow_blocks(workflow.read_text(encoding="utf-8"))
        self.assertNotIn("'regression'", blocks["stress"])
        self.assertIn("name: CI required", blocks["required"])

    def test_sanctioned_dependency_removal(self):
        old = '[dependencies]\nanyhow = { workspace = true }\ntokio = { workspace = true }\n'
        new = '[dependencies]\ntokio = { workspace = true }\n'
        p.check_removed_dependencies("packages/arti-wrapper/Cargo.toml", old, new)
        with self.assertRaisesRegex(p.MappingError, "missing mapping: удалена зависимость пакета"):
            p.check_removed_dependencies("packages/auth/Cargo.toml", old, new)
        other = '[dependencies]\nanyhow = { workspace = true }\n'
        with self.assertRaisesRegex(p.MappingError, "missing mapping: удалена зависимость пакета"):
            p.check_removed_dependencies("packages/arti-wrapper/Cargo.toml", old, other)
        dev = '[dependencies]\nanyhow = { workspace = true }\n[dev-dependencies]\ntempfile = "3"\n'
        with self.assertRaisesRegex(p.MappingError, "missing mapping: удалена зависимость пакета"):
            p.check_removed_dependencies("packages/arti-wrapper/Cargo.toml", dev, dev.replace('[dev-dependencies]\ntempfile = "3"\n', ''))
        result = self.route("packages/arti-wrapper/Cargo.toml",
                            blobs={"packages/arti-wrapper/Cargo.toml": (old, new)})
        self.assertIn("arti-wrapper", result["packages"])

        # SDK-4: the eight sanctioned removals from the binary's manifest.
        old_sdk4 = '[dependencies]\n' + ''.join(
            f'{name} = "{ver}"\n' for name, ver in [
                ("data-encoding", "2.11.0"), ("ed25519-dalek", "2.2.0"), ("sha2", "0.10.9"),
                ("sha3", "0.10.9"), ("zeroize", "1.9.1"), ("fs-mistrust", "0.16"),
                ("tor-keymgr", "0.48"), ("tor-llcrypto", "0.48"), ("some-unsanctioned-crate", "1")])
        new_sdk4 = '[dependencies]\nsome-unsanctioned-crate = "1"\n'
        p.check_removed_dependencies("apps/socks5-proxy/Cargo.toml", old_sdk4, new_sdk4)
        # An unsanctioned removal from the same manifest is refused.
        with self.assertRaisesRegex(p.MappingError, "missing mapping: удалена зависимость пакета"):
            p.check_removed_dependencies("apps/socks5-proxy/Cargo.toml", new_sdk4, '[dependencies]\n')
        # The same sanctioned name in another table of the same manifest is refused.
        dev_sdk4 = new_sdk4 + '[dev-dependencies]\ntor-keymgr = "0.48"\n'
        with self.assertRaisesRegex(p.MappingError, "missing mapping: удалена зависимость пакета"):
            p.check_removed_dependencies(
                "apps/socks5-proxy/Cargo.toml", dev_sdk4,
                dev_sdk4.replace('[dev-dependencies]\ntor-keymgr = "0.48"\n', ''))

        # SDK-5: the four sanctioned removals from the binary's manifest.
        old_sdk5 = '[dependencies]\n' + ''.join(
            f'{name} = "{ver}"\n' for name, ver in [
                ("tor-hscrypto", "0.48"), ("safelog", "0.4"), ("tor-cell", "0.48"),
                ("tor-proto", "0.48"), ("some-unsanctioned-crate", "1")])
        new_sdk5 = '[dependencies]\nsome-unsanctioned-crate = "1"\n'
        p.check_removed_dependencies("apps/socks5-proxy/Cargo.toml", old_sdk5, new_sdk5)
        # An unsanctioned removal from the same manifest is refused.
        with self.assertRaisesRegex(p.MappingError, "missing mapping: удалена зависимость пакета"):
            p.check_removed_dependencies("apps/socks5-proxy/Cargo.toml", new_sdk5, '[dependencies]\n')

        # H18: HsNickname comes through tor-socks5-onion (facade re-export).
        old_h18 = '[dependencies]\ntor-hsservice = "0.48"\nkeep-me = "1"\n'
        p.check_removed_dependencies(
            "apps/socks5-proxy/Cargo.toml", old_h18, '[dependencies]\nkeep-me = "1"\n')
        # Removing an unsanctioned dependency alongside it is still refused.
        with self.assertRaisesRegex(p.MappingError, "missing mapping: удалена зависимость пакета"):
            p.check_removed_dependencies("apps/socks5-proxy/Cargo.toml", old_h18, '[dependencies]\n')

        # H20: 7 unused deps removed; bridge-fetcher/bridge-line/tempfile
        # moved to dev-dependencies (removed from [dependencies]).
        old_h20 = '[dependencies]\n' + ''.join(
            f'{name} = "{ver}"\n' for name, ver in [
                ("tor-error", "0.48"), ("serde", "1"), ("serde_json", "1"),
                ("indexmap", "2"), ("time", "0.3"), ("thiserror", "2"),
                ("getrandom", "0.3"), ("bridge-line", "0.2"),
                ("bridge-fetcher", "0.2"), ("tempfile", "3")]) + 'keep-me = "1"\n'
        new_h20 = '[dependencies]\nkeep-me = "1"\n'
        p.check_removed_dependencies("apps/socks5-proxy/Cargo.toml", old_h20, new_h20)
        # Removing an unsanctioned dependency alongside them is still refused.
        with self.assertRaisesRegex(p.MappingError, "missing mapping: удалена зависимость пакета"):
            p.check_removed_dependencies(
                "apps/socks5-proxy/Cargo.toml",
                old_h20.replace('keep-me = "1"\n', 'some-unsanctioned-crate = "1"\n'),
                '[dependencies]\n')

        # H20 (server): bridge-line/bridge-store/time/tracing-subscriber no
        # longer live in [dependencies] of the tor-socks5-server manifest.
        old_srv = '[dependencies]\nbridge-line = "0.2"\nbridge-store = "0.2"\n' \
                  'time = "0.3"\ntracing-subscriber = "0.3"\nkeep-me = "1"\n'
        p.check_removed_dependencies(
            "apps/sdk/crates/server/Cargo.toml", old_srv, '[dependencies]\nkeep-me = "1"\n')
        # Removing an unsanctioned dependency alongside them is still refused.
        with self.assertRaisesRegex(p.MappingError, "missing mapping: удалена зависимость пакета"):
            p.check_removed_dependencies(
                "apps/sdk/crates/server/Cargo.toml",
                old_srv.replace('keep-me = "1"\n', 'some-other-unsanctioned = "1"\n'),
                '[dependencies]\n')

        # H21: the binary links the SDK through the tor-socks5 facade;
        # the six direct SDK/internal deps are gone from [dependencies].
        old_h21 = '[dependencies]\n' + ''.join(
            f'{name} = "0.2"\n' for name in [
                "arti-wrapper", "auth", "persist-lock", "proxy-config",
                "tor-socks5-onion", "tor-socks5-runtime"]) + 'keep-me = "1"\n'
        p.check_removed_dependencies(
            "apps/socks5-proxy/Cargo.toml", old_h21, '[dependencies]\nkeep-me = "1"\n')
        # Removing an unsanctioned dependency alongside them is still refused.
        with self.assertRaisesRegex(p.MappingError, "missing mapping: удалена зависимость пакета"):
            p.check_removed_dependencies(
                "apps/socks5-proxy/Cargo.toml",
                old_h21.replace('keep-me = "1"\n', 'some-unsanctioned-crate = "1"\n'),
                '[dependencies]\n')

    def test_deps1_proxy_dependency_removals(self):
        path = "apps/socks5-proxy/Cargo.toml"
        dependencies = (
            "dns-server", "resocks5-net", "socks5-proto", "bridge-store",
            "bridge-probe", "bridge-verify-core", "route-pool", "futures",
            "ktav", "rusqlite",
        )
        old = '[dependencies]\n' + ''.join(f'{name} = "1"\n' for name in dependencies)
        for name in dependencies:
            with self.subTest(dependency=name):
                new = '[dependencies]\n' + ''.join(
                    f'{other} = "1"\n' for other in dependencies if other != name)
                p.check_removed_dependencies(path, old, new)
                result = self.route(path, blobs={path: (old, new)})
                self.assertIn("socks5-proxy", result["packages"])

        dependency = "dns-server"
        other_package = '[dependencies]\n' + f'{dependency} = "1"\n'
        with self.assertRaisesRegex(p.MappingError, "missing mapping: удалена зависимость пакета"):
            p.check_removed_dependencies(
                "packages/auth/Cargo.toml", other_package, '[dependencies]\n')
        for table in ("dev-dependencies", "build-dependencies"):
            with self.subTest(table=table):
                old_table = f'[{table}]\n{dependency} = "1"\n'
                with self.assertRaisesRegex(p.MappingError, "missing mapping: удалена зависимость пакета"):
                    p.check_removed_dependencies(path, old_table, f'[{table}]\n')

        retained = '[dependencies]\nsome-unsanctioned-crate = "1"\n'
        with self.assertRaisesRegex(p.MappingError, "missing mapping: удалена зависимость пакета"):
            p.check_removed_dependencies(path, retained, '[dependencies]\n')

    def test_required_results(self):
        plan = {"segments": ["fast", "rust"], "capabilities": {"real_tor_channel": True, "license_policy": False}, "full": False}
        needs = {job: {"result": "success" if any(s in plan["segments"] for s in selections) else "skipped"} for job, selections in p.RESULT_JOBS.items()}
        needs["plan"] = {"result": "success"}
        with self.assertRaisesRegex(p.MappingError, "license policy capability"):
            p.validate_results({"segments": ["fast", "rust"], "capabilities": {"real_tor_channel": True}}, needs)
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
        with self.assertRaisesRegex(p.MappingError, "нет потребителя"):
            p.validate_results({"segments": ["fast", "rust", "unknown-segment"], "capabilities": {"real_tor_channel": True, "license_policy": False}, "full": False}, needs)
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
        manifest_route = self.route(p.CONTRACT_MANIFEST, capabilities={'real_tor_channel': False,
                                                                        'license_policy': False})
        self.assertEqual(manifest_route['segments'], ['fast', 'regression'])
        self.assertEqual(manifest_route['capability_reasons']['real_tor_channel'], 'контракт не установлен')
        for path in ('packages/proxy-config/src/lib.rs', 'packages/proxy-config/client-acl/src/lib.rs', 'packages/bridge-probe/src/lib.rs'):
            result = self.route(path, capabilities={'real_tor_channel': False, 'license_policy': False})
            self.assertNotIn('tor', result['segments'])
            self.assertIn('rust', result['segments'])
            self.assertFalse(result['capabilities']['real_tor_channel'])
        self.assertNotIn('tor', self.route(mode='sprint-full', capabilities={'real_tor_channel': False,
                                                                              'license_policy': False})['segments'])
        installed = {path: '\n'.join(markers) for path, markers in p.TOR_MARKERS.items()}
        installed[p.CONTRACT_MANIFEST] = 'real_tor_channel = true\n'
        self.assertTrue(p.contract_capability(read({}), read(installed)))
        manifest = ROOT / p.CONTRACT_MANIFEST
        if p.tomllib.loads(manifest.read_text(encoding='utf-8'))['real_tor_channel']:
            workflow = (ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8')
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
            p.validate_results({'segments': ['tor'], 'capabilities': {'real_tor_channel': False,
                                'license_policy': False}}, needs)

    def test_license_policy_capability_and_routing(self):
        read = lambda data: lambda path: data.get(path)
        self.assertFalse(p.license_policy_capability(read({}), read({})))
        self.assertTrue(p.license_policy_capability(read({}), read({'.github/deny.toml': 'policy bytes'})))
        with self.assertRaisesRegex(p.MappingError, 'empty license-policy identity file'):
            p.license_policy_capability(read({}), read({'.github/deny.toml': '  \n'}))
        with self.assertRaisesRegex(p.MappingError, 'license-policy identity removed'):
            p.license_policy_capability(read({'.github/deny.toml': 'policy bytes'}), read({}))
        caps = {'license_policy': True, 'real_tor_channel': False}
        with self.assertRaisesRegex(p.MappingError, 'missing mapping: путь: deny.toml'):
            self.route('deny.toml')
        self.assertEqual(self.route('vendor/README.md', capabilities=caps)['segments'], ['fast'])
        self.assertEqual(self.route('vendor/PROVENANCE.md', capabilities=caps)['segments'], ['fast', 'vendor-notices'])
        with self.assertRaisesRegex(p.MappingError, 'missing mapping'):
            self.route('vendor/NOTICE', capabilities=caps)
        for path in (".github/deny.toml", ".github/license/README.md"):
            with self.subTest(path=path):
                result = self.route(path, capabilities=caps)
                expected = ['fast', 'license-audit', 'license-offline'] if path == '.github/deny.toml' else ['fast']
                self.assertEqual(result['segments'], expected)
                if path == '.github/deny.toml':
                    self.assertEqual(result['packages'], [])
                    self.assertEqual(result['native_rows'], [])
                    needs = {job: {'result': 'success' if any(s in result['segments'] for s in selections) else 'skipped'}
                             for job, selections in p.RESULT_JOBS.items()}
                    needs['plan'] = {'result': 'success'}
                    p.validate_results(result, needs)
                    for outcome in ('skipped', 'failure', 'cancelled'):
                        needs['license-audit']['result'] = outcome
                        with self.assertRaisesRegex(p.MappingError, 'license-audit: expected success'):
                            p.validate_results(result, needs)
        full = self.route(mode='sprint-full', capabilities=caps)
        self.assertTrue({'license-offline', 'license-audit'} <= set(full['segments']))
        full_needs = {job: {'result': 'success' if any(s in full['segments'] for s in selections) else 'skipped'}
                      for job, selections in p.RESULT_JOBS.items()}
        full_needs['plan'] = {'result': 'success'}
        p.validate_results(full, full_needs)
        for job in ('license-offline', 'license-audit'):
            for outcome in ('skipped', 'failure', 'cancelled'):
                full_needs[job]['result'] = outcome
                with self.assertRaisesRegex(p.MappingError, job + ': expected success'):
                    p.validate_results(full, full_needs)
            full_needs[job]['result'] = 'success'

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

    def test_structure_lint_scripts_and_the_planner_split_map_to_the_fast_tier(self):
        for path in (
            "scripts/code-files.sh",
            "scripts/check-line-limit.sh",
            "scripts/check-dir-entries.sh",
            "scripts/testing/lint_tests/test_structure_lints.py",
            "scripts/testing/planner_lib/policy.py",
            "scripts/testing/planner_tests/support.py",
        ):
            with self.subTest(path):
                self.assertIn("fast", self.route(path)["segments"])


if __name__ == "__main__":
    unittest.main()
