def domain_sources():
    return {
        ".github/pt_proxy/contract.py": (
            "assert_failed\ntrap.assert_idle()\nassert_audit_clean()\n"
            "audit_counts('iptables')[0] > 0\n"
            "audit_counts('ip6tables')[2] > 0\nPROXY DONE\n"
        ),
        "apps/socks5-proxy/tests/pt_owner_contract.rs": (
            "TOR_PT_MANAGED_TRANSPORT_VER\nPT_PROXY_ISOLATED\nlyrebird::run()\n"
        ),
        "apps/socks5-proxy/tests/pt_owner/owner_contract.rs": (
            "run_pt_owner_contract\nOwnerRegistry::new\nproxy_connection\n"
        ),
        ".github/pt_proxy/artifact.py": (
            "compiler-artifact\npt_owner_contract\n4 * 1024 * 1024\nlen(found) != 1\n"
        ),
        ".github/workflows/ci.yml": (
            "pt-proxy-contract:\n.github/pt_proxy/contract.py\n"
            "ip -6 addr add ::2/128 dev lo\nPT_AUDIT\n"
            "cargo test --locked -p socks5-proxy --test pt_owner_contract "
            "--no-run --message-format=json\n"
            ".github/pt_proxy/artifact.py\n"
            'exec unshare --net --pid --fork --mount-proc env '
            'GITHUB_ACTIONS=true PT_PROXY_ISOLATED=yes python3 -I '
            '.github/pt_proxy/owner_audit.py "$(<"$1/target/pt-owner-path")"\n'
            "-p tor-ptmgr --features managed-pts,tor-channel-factory lifecycle_tests\n"
            "-p tor-ptmgr --features managed-pts,tor-channel-factory process_tests\n"
            "-p arti-client --features pt-client pt_shutdown_\n"
        ),
        ".github/pt_proxy/owner_audit.py": (
            "direct_domain.py\nDirectDomain(\n"
            "def audit(tool):\n"
            "command(tool + '-save', '-c', '-t', 'filter')\n"
            "def protocol_complete():\ndef packet_audits(traffic=False):\n"
            "signal.pidfd_send_signal(handle, signal.SIGKILL)\n"
            "status, cleanup_ok, error = execute(listener, [sys.argv[1]])\n"
            "results = packet_audits(traffic=True)\n"
            "setup_ok and status == 0 and cleanup_ok and protocol_ok "
            "and audit_ok and domain_ok\n"
        ),
        ".github/pt_proxy/direct_domain.py": (
            "class DirectDomain:\ndef authorize(\ndef bind(\ndef handle(\n"
            "def rules(\ndef counts(\ndef setup(\ndef begin(\n"
            "def finish(\ndef complete(\ndef dispose(\ndef regression(\n"
        ),
    }


class PTGenerations(unittest.TestCase):
    def read(self, data):
        return lambda path: data.get(path, "")

    def sources(self):
        domain = domain_sources()
        audited = dict(domain)
        del audited[".github/pt_proxy/direct_domain.py"]
        audit = ".github/pt_proxy/owner_audit.py"
        audited[audit] = audited[audit].replace(
            "direct_domain.py\nDirectDomain(\n", ""
        ).replace(" and domain_ok", "")
        direct = {path: "\n".join(markers) for path, markers in p.PT_MARKERS.items()}
        legacy = {path: "\n".join(markers) for path, markers in p.PT_LEGACY_MARKERS.items()}
        split = {
            path: "\n".join(markers)
            for path, markers in p.PT_DOMAIN_SPLIT_MARKERS.items()
        }
        return ({}, legacy, direct, audited, domain, split)

    def test_generation_transitions(self):
        sources = self.sources()
        for generation, source in enumerate(sources):
            with self.subTest(generation=generation):
                self.assertEqual(p.pt_generation(self.read(source)), generation)
        for before, base in enumerate(sources):
            for after, head in enumerate(sources):
                with self.subTest(before=before, after=after):
                    if after < before:
                        with self.assertRaisesRegex(p.MappingError, "missing mapping: контракт PT"):
                            p.pt_contract(self.read(base), self.read(head))
                    else:
                        self.assertEqual(
                            p.pt_contract(self.read(base), self.read(head)), bool(after))

    def test_domain_interface_markers_are_required(self):
        domain = domain_sources()
        module = ".github/pt_proxy/direct_domain.py"
        expected = (
            "class DirectDomain:", "def authorize(", "def bind(", "def handle(",
            "def rules(", "def counts(", "def setup(", "def begin(",
            "def finish(", "def complete(", "def dispose(", "def regression(",
        )
        for marker in expected:
            with self.subTest(marker=marker):
                self.assertIn(marker, p.PT_DOMAIN_MARKERS[module])
                broken = dict(domain)
                broken[module] = broken[module].replace(marker, "")
                for base, head in ((domain, broken), (broken, domain)):
                    with self.assertRaisesRegex(p.MappingError, "missing mapping: контракт PT"):
                        p.pt_contract(self.read(base), self.read(head))

    def test_domain_partials_and_required_marker_loss(self):
        absent, legacy, direct, audited, domain = self.sources()[:5]
        module = ".github/pt_proxy/direct_domain.py"
        audit = ".github/pt_proxy/owner_audit.py"
        workflow = ".github/workflows/ci.yml"
        partials = [{module: domain[module]}, dict(audited, **{module: domain[module]})]
        for path in (audit, workflow):
            for reference in ("direct_domain.py", "DirectDomain(", "domain_ok"):
                partial = dict(audited)
                partial[path] = partial.get(path, "") + "\n" + reference + "\n"
                partials.append(partial)
        for marker in ("direct_domain.py", "DirectDomain(", " and domain_ok"):
            partial = dict(domain)
            partial[audit] = partial[audit].replace(marker, "")
            partials.append(partial)
        for path in domain:
            partial = dict(domain)
            del partial[path]
            partials.append(partial)
        for number, partial in enumerate(partials):
            with self.subTest(partial=number):
                self.assertEqual(p.pt_generation(self.read(partial)), 4)
                for base, head in ((absent, partial), (audited, partial), (partial, domain)):
                    with self.assertRaisesRegex(p.MappingError, "missing mapping: контракт PT"):
                        p.pt_contract(self.read(base), self.read(head))
        for path, markers in p.PT_DOMAIN_MARKERS.items():
            for marker in markers:
                broken = dict(domain)
                broken[path] = broken[path].replace(marker, "")
                with self.subTest(path=path, marker=marker):
                    for base, head in ((domain, broken), (broken, domain)):
                        with self.assertRaisesRegex(p.MappingError, "missing mapping: контракт PT"):
                            p.pt_contract(self.read(base), self.read(head))

        split = self.sources()[5]
        partials = [
            {path: split[path]} for path in p.PT_DOMAIN_SPLIT_PATHS
        ] + [{module: p.PT_DOMAIN_SPLIT_ANCHOR}]
        for number, partial in enumerate(partials):
            with self.subTest(split_partial=number):
                self.assertEqual(p.pt_generation(self.read(partial)), 5)
                for base, head in (
                    (absent, partial), (domain, partial), (partial, split)
                ):
                    with self.assertRaisesRegex(
                        p.MappingError, "missing mapping: контракт PT"
                    ):
                        p.pt_contract(self.read(base), self.read(head))
        for path, markers in p.PT_DOMAIN_SPLIT_MARKERS.items():
            for marker in markers:
                broken = dict(split)
                broken[path] = broken[path].replace(marker, "")
                with self.subTest(split_path=path, split_marker=marker):
                    for base, head in ((split, broken), (broken, split)):
                        with self.assertRaisesRegex(
                            p.MappingError, "missing mapping: контракт PT"
                        ):
                            p.pt_contract(self.read(base), self.read(head))
        for path in split:
            broken = dict(split)
            del broken[path]
            with self.subTest(split_missing=path):
                for base, head in ((split, broken), (broken, split)):
                    with self.assertRaisesRegex(
                        p.MappingError, "missing mapping: контракт PT"
                    ):
                        p.pt_contract(self.read(base), self.read(head))


    def test_historical_audited_upgrade(self):
        _, _, direct, audited, domain = self.sources()[:5]
        self.assertNotIn(".github/pt_proxy/direct_domain.py", audited)
        self.assertEqual(p.pt_generation(self.read(audited)), 3)
        self.assertTrue(p.pt_contract(self.read(audited), self.read(audited)))
        self.assertTrue(p.pt_contract(self.read(direct), self.read(audited)))
        self.assertTrue(p.pt_contract(self.read(audited), self.read(domain)))




class TorStreamRouting(unittest.TestCase):
    def test_exact_stream_helpers_select_tor(self):
        paths = (
            "scripts/testing/tor/artifact.py",
            "scripts/testing/tor/test_artifact.py",
            "scripts/testing/tor/authority/producer/stream.py",
            "scripts/testing/tor/authority/producer/stream_wire.py",
            "scripts/testing/tor/authority/producer/operation.py",
            "scripts/testing/tor/authority/producer/controls/suite.py",
            "scripts/testing/tor/authority/producer/controls/stream.py",
            "scripts/testing/tor/authority/producer/controls/stream_lifecycle.py",
        )
        for path in paths:
            with self.subTest(path=path):
                result = p.plan(graph(), [path], lambda name: ("", "source\n"))
                self.assertEqual(result["segments"], ["fast", "tor"])
                self.assertEqual(result["packages"], [])
                self.assertFalse(result["full"])

    def test_similarly_named_stream_helpers_fail_closed(self):
        paths = (
            "scripts/testing/tor/artifact.py.bak",
            "scripts/testing/tor/test_artifact_extra.py",
            "scripts/testing/tor/authority/producer/stream_extra.py",
            "scripts/testing/tor/authority/producer/operation.py.bak",
            "scripts/testing/tor/authority/producer/controls/suite_extra.py",
            "scripts/testing/tor/authority/producer/nested/stream.py",
            "scripts/testing/tor/authority/producer/controls/stream.py.bak",
            "scripts/testing/tor/authority/producer/controls/stream_lifecycle_extra.py",
        )
        for path in paths:
            with self.subTest(path=path):
                with self.assertRaises(p.MappingError):
                    p.plan(graph(), [path], lambda name: ("", "source\n"))

    def test_owned_stream_rust_paths_select_existing_tor_job(self):
        for suffix in (
            "owned_stream.rs",
            "owned_stream/consumer.rs",
            "owned_stream/protocol.rs",
            "owned_stream/mechanisms.rs",
        ):
            path = "packages/arti-wrapper/tests/" + suffix
            with self.subTest(path=path):
                result = p.plan(graph(), [path], lambda name: ("", "source\n"))
                self.assertIn("tor", result["segments"])
                self.assertIn("arti-wrapper", result["packages"])
                self.assertFalse(result["full"])

    def test_enabled_capability_requires_every_stream_source(self):
        installed = {
            path: "\n".join(markers) + "\n"
            for path, markers in p.TOR_MARKERS.items()
        }
        installed[p.CONTRACT_MANIFEST] = "real_tor_channel = true\n"
        for path in p.TOR_STREAM_SOURCES:
            installed[path] = "source\n"
        read = lambda data: lambda path: data.get(path, "")
        self.assertTrue(p.contract_capability(read({}), read(installed)))
        for path in p.TOR_STREAM_SOURCES:
            broken = dict(installed)
            del broken[path]
            with self.subTest(missing=path):
                with self.assertRaises(p.MappingError):
                    p.contract_capability(read(installed), read(broken))
        for path in (
            ".github/workflows/ci.yml",
            "scripts/testing/tor/real-tor-channel.sh",
            "scripts/testing/tor/real-tor-mutations.sh",
        ):
            broken = dict(installed)
            broken[path] = broken[path].replace("TOR_REAL_STREAM_BINARY", "")
            with self.subTest(disconnected=path):
                with self.assertRaises(p.MappingError):
                    p.contract_capability(read(installed), read(broken))
