"""Планировщик: вывод, спецификация lock, footer, источник PR, проводка workflow."""
import io
import random
import types
import unittest

from support import ROOT, p, graph, lock_package, lock_text


class PlannerOutput(unittest.TestCase):
    """Вывод планировщика не зависит от кодовой страницы консоли: байты UTF-8 мимо текстового слоя."""

    PAYLOAD = {"reasons": {"fast": ["всегда"], "rust": ["обратное замыкание графа"]}}

    def cp1252_stream(self):
        # Имитация Windows-канала: текстовый слой cp1252, .buffer — исходный BytesIO.
        return io.TextIOWrapper(io.BytesIO(), encoding="cp1252")

    def test_emit_plan_writes_utf8_bytes(self):
        stream = self.cp1252_stream()
        p.emit_plan(self.PAYLOAD, stream)
        expected = p.json.dumps(self.PAYLOAD, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"
        # Точное равенство байтов гарантирует запись через .buffer: кириллица
        # в cp1252 текстовом слое не кодируется (см. регрессию ниже).
        self.assertEqual(stream.buffer.getvalue(), expected)

    def test_emit_error_prefix_and_utf8_bytes(self):
        for message, expected in (
                ("команда не выполнена: git", "planner: missing mapping: команда не выполнена: git\n"),
                ("missing mapping: неизвестное событие", "planner: missing mapping: неизвестное событие\n")):
            with self.subTest(message=message):
                stream = self.cp1252_stream()
                p.emit_error(message, stream)
                self.assertEqual(stream.buffer.getvalue(), expected.encode("utf-8"))

    def test_plain_print_regresses_on_cp1252(self):
        # Регрессия прежнего дефекта: обычный print() того же payload на cp1252
        # поднимает UnicodeEncodeError — поэтому требуется запись в buffer.
        stream = self.cp1252_stream()
        with self.assertRaises(UnicodeEncodeError):
            print(self.PAYLOAD, file=stream)


class LockSpecification(unittest.TestCase):
    """lock_seeds against the definition: a member is affected iff its dependency closure changed."""

    REGISTRY = "registry+https://example.invalid/index"

    @classmethod
    def universe(cls, rng):
        members = [("m%d" % i, "0.1.0", None) for i in range(rng.randint(1, 3))]
        crates = [("c%d" % n, version, cls.REGISTRY) for n in range(rng.randint(2, 7))
                  for version in rng.sample(["1.0.0", "2.0.0", "3.0.0"], rng.randint(1, 2))]
        lock = {}
        for position, ident in enumerate(members + crates):
            later = [c for c in crates if crates.index(c) > position - len(members) and c[0] != ident[0]]
            deps = {}
            for target in rng.sample(later, min(len(later), rng.randint(0, 3))):
                deps.setdefault(target[0], target)
            lock[ident] = {"checksum": "sum-%s-%s" % ident[:2], "deps": list(deps.values())}
        return cls.reachable(lock)

    @staticmethod
    def reachable(lock):
        keep = {ident for ident in lock if ident[2] is None}
        stack = list(keep)
        while stack:
            for dep in lock[stack.pop()]["deps"]:
                if dep in lock and dep not in keep:
                    keep.add(dep)
                    stack.append(dep)
        return {ident: entry for ident, entry in lock.items() if ident in keep}

    @classmethod
    def mutate(cls, rng, lock):
        new = {ident: {"checksum": entry["checksum"], "deps": list(entry["deps"])} for ident, entry in lock.items()}
        for _ in range(rng.randint(1, 3)):
            crates = [ident for ident in new if ident[2] is not None]
            if not crates:
                break
            kind, crate = rng.choice(("bump", "drop_dep", "checksum", "drop_crate")), rng.choice(crates)
            if kind == "bump":
                bumped = (crate[0], rng.choice(("4.0.0", "5.0.0")), cls.REGISTRY)
                if bumped not in new:
                    new[bumped] = {"checksum": "sum-%s-%s" % bumped[:2], "deps": list(new.pop(crate)["deps"])}
                    for entry in new.values():
                        entry["deps"] = [bumped if dep == crate else dep for dep in entry["deps"]]
            elif kind == "drop_dep":
                holder = rng.choice(list(new))
                if new[holder]["deps"]:
                    new[holder]["deps"].pop(rng.randrange(len(new[holder]["deps"])))
            elif kind == "checksum":
                new[crate]["checksum"] += "-changed"
            else:
                del new[crate]
                for entry in new.values():
                    entry["deps"] = [dep for dep in entry["deps"] if dep != crate]
        return cls.reachable(new)

    @staticmethod
    def text(lock):
        versions = {}
        for ident in lock:
            versions.setdefault(ident[0], []).append(ident)
        packages = []
        for ident, entry in lock.items():
            deps = tuple(dep[0] if len(versions[dep[0]]) == 1 else "%s %s" % dep[:2] for dep in entry["deps"])
            packages.append(lock_package(ident[0], ident[1], ident[2], deps) +
                            ('checksum = "%s"\n' % entry["checksum"] if ident[2] else ""))
        return lock_text(*packages)

    @staticmethod
    def closure(lock, root):
        seen, stack = {}, [root]
        while stack:
            ident = stack.pop()
            if ident not in seen:
                seen[ident] = (ident, lock[ident]["checksum"], tuple(sorted(lock[ident]["deps"])))
                stack.extend(lock[ident]["deps"])
        return set(seen.values())

    def test_planner_matches_the_closure_definition(self):
        rng = random.Random(20261111)
        for case in range(300):
            old = self.universe(rng)
            new = self.universe(rng) if case % 4 == 0 else self.mutate(rng, old)
            graph = types.SimpleNamespace(packages={i: {"name": i[0], "version": i[1], "source": i[2]} for i in new})
            seeds = p.lock_seeds(self.text(old), self.text(new), graph)
            consumers = {}
            for ident, entry in new.items():
                for dep in entry["deps"]:
                    consumers.setdefault(dep, set()).add(ident)
            affected, stack = set(), list(seeds)
            while stack:
                ident = stack.pop()
                if ident not in affected:
                    affected.add(ident)
                    stack.extend(consumers.get(ident, ()))
            expected = {m for m in new if m[2] is None and (m not in old or self.closure(old, m) != self.closure(new, m))}
            self.assertEqual({i for i in affected if i[2] is None}, expected, "case %d" % case)


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
        text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
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
    unittest.main()
