"""Маршрутизация: Cargo.lock — сиды, удаления, транзитивы."""
import unittest

from support import p, graph, lock_graph, lock_package, lock_text, RoutingCase


class RoutingLock(RoutingCase):
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

    def test_lock_removals_need_no_mapping(self):
        registry = "registry+https://github.com/rust-lang/crates.io-index"
        graph = lock_graph()
        # A package nobody uses any more leaves no seed of its own.
        self.assertEqual(p.lock_seeds(lock_text(lock_package("orphan", "1.0.0")), lock_text(), graph), set())
        # One of several locked versions goes away: the consumer that moved is the seed.
        old = lock_text(lock_package("changed", "0.10.0", registry),
                        lock_package("changed", "0.14.0", registry),
                        lock_package("changed", "0.15.0", registry),
                        lock_package("socks5-proxy", "0.2.0", None, ("changed 0.14.0",)))
        new = lock_text(lock_package("changed", "0.10.0", registry),
                        lock_package("changed", "0.15.0", registry),
                        lock_package("socks5-proxy", "0.2.0", None, ("changed 0.15.0",)))
        self.assertEqual(p.lock_seeds(old, new, graph), {"proxy"})
        # A dependency that is only dropped: its consumer is the seed.
        old = lock_text(lock_package("socks5-proxy", "0.2.0", None, ("leaf 1.0.0",)),
                        lock_package("leaf", "1.0.0", registry))
        new = lock_text(lock_package("socks5-proxy", "0.2.0"))
        self.assertEqual(p.lock_seeds(old, new, graph), {"proxy"})

    def test_lock_that_does_not_resolve_its_own_dependencies_fails_closed(self):
        registry = "registry+https://github.com/rust-lang/crates.io-index"
        graph = lock_graph()
        ghost = lock_text(lock_package("socks5-proxy", "0.2.0", None, ("ghost 1.0.0",)))
        two_versions = lock_text(lock_package("socks5-proxy", "0.2.0", None, ("leaf",)),
                                 lock_package("leaf", "1.0.0", registry),
                                 lock_package("leaf", "2.0.0", registry))
        source_without_version = lock_text(
            lock_package("socks5-proxy", "0.2.0", None, ("leaf (" + registry + ")",)),
            lock_package("leaf", "1.0.0", registry))
        for bad in (ghost, two_versions, source_without_version):
            with self.assertRaisesRegex(p.MappingError, "missing mapping"):
                p.lock_seeds(lock_text(), bad, graph)

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
        with_b = lock_text(lock_package("leaf", "1.0.0", registry_b))
        leaf_graph = lock_graph(extra_packages=(
            ("leaf-b", "leaf", "1.0.0", registry_b, "external/leaf-b", "lib"),))
        self.assertEqual(
            p.lock_seeds(lock_text(lock_package("leaf", "1.0.0", registry_a)), with_b, leaf_graph),
            {"leaf-b"})
        unresolved = lock_text(
            lock_package("middle", "1.0.0", registry_a, ("leaf",)),
            lock_package("leaf", "1.0.0", registry_a),
            lock_package("leaf", "1.0.0", registry_b),
        )
        with self.assertRaisesRegex(p.MappingError, "missing mapping"):
            p.lock_seeds(lock_text(), unresolved, graph)

    def test_lock_seeds_must_map_to_the_graph(self):
        registry = "registry+https://github.com/rust-lang/crates.io-index"
        old = lock_text(lock_package("changed", "1.0.0", registry))
        replacements = lock_text(lock_package("changed", "2.0.0", registry),
                                 lock_package("changed", "3.0.0", registry))
        graph = lock_graph(extra_packages=(
            ("changed-2", "changed", "2.0.0", registry, "external/changed", "lib"),
            ("changed-3", "changed", "3.0.0", registry, "external/changed", "lib")))
        # Every new package is a seed; nothing is guessed about the removed one.
        self.assertEqual(p.lock_seeds(old, replacements, graph), {"changed-2", "changed-3"})
        unknown_new = lock_text(lock_package("not-in-graph", "1.0.0", registry))
        with self.assertRaisesRegex(p.MappingError, "missing mapping"):
            p.lock_seeds(lock_text(), unknown_new, graph)
        wrong_graph_version = lock_graph(extra_packages=(
            ("changed-current", "changed", "2.1.0", registry, "external/changed", "lib"),))
        with self.assertRaisesRegex(p.MappingError, "missing mapping"):
            p.lock_seeds(lock_text(), lock_text(lock_package("changed", "2.0.0", registry)),
                         wrong_graph_version)

    def test_lock_seeds_are_only_the_new_and_changed_entries(self):
        registry = "registry+https://github.com/rust-lang/crates.io-index"
        old = lock_text(lock_package("changed", "1.0.0", registry),
                        lock_package("changed", "2.0.0", registry))
        new = lock_text(lock_package("changed", "2.0.0", registry),
                        lock_package("changed", "3.0.0", registry))
        graph = lock_graph(extra_packages=(
            ("changed-2", "changed", "2.0.0", registry, "external/changed-2", "lib"),
            ("changed-3", "changed", "3.0.0", registry, "external/changed-3", "lib")))
        self.assertEqual(p.lock_seeds(old, new, graph), {"changed-3"})
        both_new = lock_text(lock_package("changed", "3.0.0", registry),
                             lock_package("changed", "4.0.0", registry))
        both_graph = lock_graph(extra_packages=(
            ("changed-3", "changed", "3.0.0", registry, "external/changed-3", "lib"),
            ("changed-4", "changed", "4.0.0", registry, "external/changed-4", "lib")))
        self.assertEqual(p.lock_seeds(lock_text(lock_package("changed", "1.0.0", registry)), both_new, both_graph),
                         {"changed-3", "changed-4"})


if __name__ == "__main__":
    unittest.main()
