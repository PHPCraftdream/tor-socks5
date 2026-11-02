#!/usr/bin/env python3
"""Внешние регрессии с настоящим Git и поддельным cargo, только в CI."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

if os.environ.get("GITHUB_ACTIONS") != "true":
    raise SystemExit("Интеграционные проверки разрешены только в CI")

SOURCE = Path(__file__).resolve().parents[2]
DOCS = ("README.md", "tor-socks5.example.ktav",
        "packages/proxy-config/examples/tor-socks5.bridges.example.ktav",
        "docs/architecture.md", "docs/guide/bridges.md", "docs/guide/webtunnel.md",
        "docs/guide/auth.md", "docs/guide/upstream.md", "docs/guide/dns-server.md",
        "docs/guide/ops/logging.md", "docs/guide/ops/onion-service.md", "docs/guide/service.md")
ZERO = "0" * 40
spec = importlib.util.spec_from_file_location("ci_planner", SOURCE / "scripts/testing/ci_planner.py")
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class External(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo"
        self.root.mkdir()
        self.bin = Path(self.temp.name) / "bin"
        self.bin.mkdir()
        self.log = Path(self.temp.name) / "cargo.log"
        self.metadata = Path(self.temp.name) / "metadata.json"
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                        TEST_AFFECTED_DRY="1", CARGO_LOG=str(self.log),
                        FAKE_METADATA=str(self.metadata), GIT_CONFIG_NOSYSTEM="1",
                        GIT_CONFIG_GLOBAL=os.devnull, GIT_AUTHOR_NAME="CI", GIT_AUTHOR_EMAIL="ci@example.invalid",
                        GIT_COMMITTER_NAME="CI", GIT_COMMITTER_EMAIL="ci@example.invalid")
        cargo = self.bin / "cargo"
        cargo.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$CARGO_LOG"\n[ "$*" = "metadata --locked --all-features --format-version 1" ] || exit 99\nexec cat "$FAKE_METADATA"\n', encoding="utf-8")
        cargo.chmod(0o755)
        names = {"proxy": ("socks5-proxy", "apps/socks5-proxy", "bin"),
                 "auth": ("tor-socks5-auth", "packages/auth", "lib"),
                 "config": ("tor-socks5-config", "packages/proxy-config", "lib"),
                 "acl": ("tor-socks5-client-acl", "packages/proxy-config/client-acl", "lib"),
                 "bridge": ("bridge-probe", "packages/bridge-probe", "lib"),
                 "arti": ("arti-wrapper", "packages/arti-wrapper", "lib"),
                 "ffi": ("android-ffi", "packages/android-ffi", "lib")}
        edges = {"proxy": ["auth", "config", "bridge", "arti"], "config": ["acl"], "ffi": ["config", "auth"],
                 "auth": ["acl"], "acl": [], "bridge": [], "arti": []}
        packages = [{"id": i, "name": name, "manifest_path": str(self.root / path / "Cargo.toml"),
                     "targets": [{"kind": [kind]}]} for i, (name, path, kind) in names.items()]
        nodes = [{"id": i, "deps": [{"pkg": d, "name": d, "dep_kinds": [{"kind": None, "target": None}]} for d in deps]} for i, deps in edges.items()]
        self.metadata.write_text(json.dumps({"packages": packages, "workspace_members": list(names), "resolve": {"nodes": nodes}}), encoding="utf-8")
        for path in ("scripts/testing/ci_planner.py", "scripts/testing/test-affected.sh", ".githooks/pre-push"):
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(SOURCE / path, target)
        for path in DOCS:
            self.put(path, "документ\n")
        for _, path, _ in names.values():
            self.put(path + "/Cargo.toml", "[package]\nname='fixture'\nversion='0.1.0'\n")
            self.put(path + "/src/lib.rs", "начало\n")
        # Маркеры — только данные: синтетические скрипты и Rust-код не исполняются.
        self.put(p.CONTRACT_MANIFEST, "real_tor_channel = true\n")
        for path, markers in p.TOR_MARKERS.items():
            self.put(path, "\n".join(markers) + "\n")
        self.git("init", "-q")
        self.commit("начало")
        self.base = self.git("rev-parse", "HEAD").strip()

    def put(self, path, text):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    def cmd(self, *args, input=None, env=None):
        return subprocess.run(args, cwd=self.root, env=env or self.env, input=input,
                              text=True, encoding="utf-8", capture_output=True)

    def git(self, *args):
        result = self.cmd("git", *args)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def commit(self, message):
        self.git("add", "-A")
        self.git("-c", "core.hooksPath=/dev/null", "commit", "-qm", message)

    def head(self):
        return self.git("rev-parse", "HEAD").strip()

    def planner(self, *args, ok=True):
        result = self.cmd(sys.executable, "-I", "scripts/testing/ci_planner.py", *args)
        if ok:
            self.assertEqual(result.returncode, 0, result.stderr)
            plan = json.loads(result.stdout)
            self.assertTrue(plan["segments"])
            return plan
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing mapping:", result.stderr)
        self.assertEqual(result.stdout.strip(), "")
        return result

    def push(self, base=None, head=None, **kwargs):
        return self.planner("--event", "push", "--base", base or self.base,
                            "--head", head or self.head(), **kwargs)

    def hook(self, refs, full=False, ok=True):
        env = dict(self.env, FULL="1" if full else "0")
        result = self.cmd("sh", ".githooks/pre-push", "origin", "unused", input=refs, env=env)
        self.assertEqual(result.returncode == 0, ok, result.stdout + result.stderr)
        if self.log.exists():
            self.assertTrue(all(line == "metadata --locked --all-features --format-version 1"
                                for line in self.log.read_text().splitlines()))
        return result

    def ref(self, local, remote):
        return f"refs/heads/topic {local} refs/heads/topic {remote}\n"

    def test_git_events_and_fail_closed(self):
        self.put("packages/auth/src/lib.rs", "изменено\n")
        self.commit("auth")
        first = self.head()
        self.put("packages/proxy-config/src/lib.rs", "config\n")
        self.commit("config")
        result = self.push()
        self.assertEqual(result["paths"], ["packages/auth/src/lib.rs", "packages/proxy-config/src/lib.rs"])
        self.assertIn("tor", result["segments"])
        self.assertFalse(result["full"])
        main_head = self.head()
        self.git("branch", "side-base", first)
        self.git("checkout", "-q", "side-base")
        self.put("docs/side.md", "другая ветка\n")
        self.commit("другая ветка")
        side = self.head()
        # Synthetic PR checkout: настоящий merge с родителями (side, main_head).
        self.git("merge", "--no-ff", "-q", "-m", "PR merge checkout", main_head)
        pr = self.planner("--event", "pull_request", "--base", side, "--head", main_head)
        self.assertEqual(pr["paths"], sorted(["docs/side.md", "packages/proxy-config/src/lib.rs"]))
        self.git("checkout", "-q", "-")
        self.assertEqual(self.push(base=first)["paths"], ["packages/proxy-config/src/lib.rs"])
        manual = self.planner("--event", "workflow_dispatch", "--mode", "affected",
                              "--base-ref", first, "--head", self.head())
        self.assertFalse(manual["full"])
        self.assertEqual(manual["paths"], ["packages/proxy-config/src/lib.rs"])
        for base in ("", "missing-ref"):
            self.planner("--event", "workflow_dispatch", "--base-ref", base, "--head", self.head(), ok=False)
        self.planner("--event", "push", "--base", self.base, "--head", first, ok=False)
        self.planner("--event", "push", "--mode", "sprint-full", "--head", self.head(), ok=False)
        full = self.planner("--event", "workflow_dispatch", "--mode", "sprint-full", "--head", self.head())
        self.assertTrue(full["full"])
        self.assertEqual(full["library_packages"], ["android-ffi", "arti-wrapper", "bridge-probe", "tor-socks5-auth", "tor-socks5-client-acl", "tor-socks5-config"])
        self.metadata.write_text('{}', encoding="utf-8")
        self.push(ok=False)

    def test_commit_footer_full_trigger(self):
        members = sorted(["socks5-proxy", "android-ffi", "tor-socks5-auth", "tor-socks5-config",
                          "tor-socks5-client-acl", "bridge-probe", "arti-wrapper"])
        self.put("packages/auth/src/lib.rs", "auth\n")
        self.commit("auth")
        early = self.head()
        self.put("packages/proxy-config/src/lib.rs", "config\n")
        self.commit("config\n\nCI-Full: sprint-end")
        self.put("packages/bridge-probe/src/lib.rs", "bridge\n")
        self.commit("bridge после footer")
        result = self.push()
        self.assertTrue(result["full"])
        self.assertEqual(result["full_trigger"], "commit_footer")
        self.assertEqual(result["packages"], members)
        self.assertIn({"segment": "rust", "target": "macos-latest"}, result["target_rows"])
        self.assertIn("footer коммита CI-Full: sprint-end", result["reasons"]["rust"])
        self.assertEqual(result["segments"], sorted(["fast", "rust", "msrv", "android", "tor", "vendor", "vendor-extra", "docs-contract", "installer-sh", "installer-windows", "release", "features", "stress", "regression", "native-portability", "required"]))
        self.assertEqual(result["command_packages"]["android"], ["android-ffi", "socks5-proxy"])
        self.assertEqual(result["shipping_packages"], ["android-ffi", "socks5-proxy"])
        self.assertEqual(result["library_packages"], sorted(["android-ffi", "arti-wrapper", "bridge-probe", "tor-socks5-auth", "tor-socks5-client-acl", "tor-socks5-config"]))
        self.assertEqual(result["native_rows"], [
            {"runner": "macos-15", "target": "aarch64-apple-darwin", "musl": False},
            {"runner": "ubuntu-latest", "target": "aarch64-linux-android", "musl": False},
            {"runner": "ubuntu-24.04-arm", "target": "aarch64-unknown-linux-gnu", "musl": False},
            {"runner": "ubuntu-24.04-arm", "target": "aarch64-unknown-linux-musl", "musl": True},
            {"runner": "macos-15-intel", "target": "x86_64-apple-darwin", "musl": False},
            {"runner": "windows-latest", "target": "x86_64-pc-windows-msvc", "musl": False},
            {"runner": "ubuntu-latest", "target": "x86_64-unknown-linux-gnu", "musl": False},
            {"runner": "ubuntu-latest", "target": "x86_64-unknown-linux-musl", "musl": True},
        ])
        # Полный прогон (sprint-full): командные пакеты rust/msrv — все члены, матрица rust — три ОС.
        self.assertEqual(result["command_packages"]["rust"], members)
        self.assertEqual(result["command_packages"]["msrv"], members)
        self.assertEqual([row["target"] for row in result["target_rows"] if row["segment"] == "rust"],
                         ["ubuntu-latest", "macos-latest", "windows-latest"])
        expected_consumers = {
            "fmt": ("fast", "regression"), "line-limit": ("fast",),
            "dir-entries": ("fast",), "publish-guard": ("fast",),
            "packageability": ("fast",), "real-tor-channel": ("tor",),
            "rust": ("rust",), "msrv": ("msrv",), "android": ("android",),
            "docs-contract": ("docs-contract",), "installer-sh": ("installer-sh",),
            "installer-windows": ("installer-windows",), "release-scripts": ("release",),
            "native-portability": ("native-portability",),
            "vendor-extra": ("vendor-extra", "vendor"), "features": ("features",),
            "stress": ("stress",), "license-offline": ("license-offline",),
            "license-audit": ("license-audit",), "license-lifecycle": ("license-lifecycle",),
        }
        self.assertEqual(expected_consumers, dict(p.RESULT_JOBS))  # Независимый literal-контракт потребителей.
        needs = {job: {"result": "success" if any(s in result["segments"] for s in selections) else "skipped"} for job, selections in expected_consumers.items()}
        needs["plan"] = {"result": "success"}
        p.validate_results(result, needs)
        # Footer в содержимом файла триггером не является.
        self.git("reset", "--hard", self.base)
        self.put("packages/auth/src/lib.rs", "auth\n\nCI-Full: sprint-end\n")
        self.commit("файл с текстом footer")
        result = self.push()
        self.assertFalse(result["full"])
        self.assertIsNone(result["full_trigger"])
        self.assertLess(len(result["packages"]), 7)
        # Footer в prose сообщения коммита не триггер.
        self.put("packages/auth/src/lib.rs", "auth\n")
        self.commit("план: добавить CI-Full: sprint-end позже")
        result = self.push()
        self.assertFalse(result["full"])
        # Ручной affected игнорирует footer: ручной выбор режима главнее.
        self.put("packages/proxy-config/src/lib.rs", "config\n")
        self.commit("config\n\nCI-Full: sprint-end")
        manual = self.planner("--event", "workflow_dispatch", "--mode", "affected",
                              "--base-ref", self.base, "--head", self.head())
        self.assertFalse(manual["full"])
        self.assertIsNone(manual["full_trigger"])
        # PR-семантика: merge-base исходных веток, footer в не последнем коммите.
        self.put("packages/arti-wrapper/src/lib.rs", "\n".join(p.TOR_MARKERS["packages/arti-wrapper/src/lib.rs"]) + "\narti\n")
        self.commit("arti после footer")
        pr_head = self.head()
        # Synthetic PR checkout: merge с родителями (early, pr_head).
        self.git("checkout", "-q", "-b", "pr-checkout", early)
        self.git("merge", "--no-ff", "-q", "-m", "PR merge checkout", pr_head)
        pr = self.planner("--event", "pull_request", "--base", early, "--head", pr_head)
        self.assertTrue(pr["full"])
        self.assertEqual(pr["full_trigger"], "commit_footer")
        self.git("checkout", "-q", "-")
        # База-не-предок (side-ветка) = ошибка плана, а не FULL и не пустой план.
        self.git("branch", "side", self.base)
        self.git("checkout", "-q", "side")
        self.put("docs/side.md", "другая ветка\n")
        self.commit("другая ветка")
        side = self.head()
        self.git("checkout", "-q", "-")
        self.planner("--event", "push", "--base", side, "--head", self.head(), ok=False)

    def test_pr_synthetic_merge_not_scanned(self):
        self.put("packages/auth/src/lib.rs", "auth\n")
        self.commit("auth")
        target = self.head()
        self.git("checkout", "-q", "-b", "pr-branch", self.base)
        self.put("packages/proxy-config/src/lib.rs", "config pr\n")
        self.commit("config pr без marker")
        source = self.head()
        # Настоящий двухродительский merge имитирует synthetic PR checkout.
        self.git("checkout", "-q", target)
        self.git("merge", "--no-ff", "-q", "-m", "PR merge\n\nCI-Full: sprint-end", "pr-branch")
        merge = self.head()
        self.assertNotEqual(merge, source)
        # --head = исходный source; checkout = synthetic merge; marker только в его message.
        result = self.planner("--event", "pull_request", "--base", target, "--head", source)
        self.assertFalse(result["full"])
        self.assertIsNone(result["full_trigger"])
        # paths — из merge-дерева: тесты исполняются в нём.
        self.assertEqual(result["paths"], sorted(["packages/auth/src/lib.rs", "packages/proxy-config/src/lib.rs"]))
        # Негативы: base не первый родитель; head=checkout (не проходит merge-proof); push head≠checkout.
        self.planner("--event", "pull_request", "--base", self.base, "--head", source, ok=False)
        self.planner("--event", "pull_request", "--base", target, "--head", merge, ok=False)
        self.planner("--event", "push", "--base", target, "--head", source, ok=False)

    def test_plan_uses_merge_checkout_tree(self):
        # Контрпример: target уже установил guarded capability, source — на старой декларации (старое чтение
        # source упало бы на несогласованных anchors, а не отключило бы tor тихо).
        self.put(p.CONTRACT_MANIFEST, "real_tor_channel = false\n")
        self.commit("временное понижение контракта")
        downgrade = self.head()
        self.put(p.CONTRACT_MANIFEST, "real_tor_channel = true\n")
        self.commit("target устанавливает контракт")
        target = self.head()
        self.git("checkout", "-q", "-b", "old-source", downgrade)
        self.put("packages/proxy-config/src/lib.rs", "config source\n")
        self.commit("source изменение config")
        source = self.head()
        self.git("checkout", "-q", target)
        self.git("merge", "--no-ff", "-q", "-m", "PR merge checkout", source)
        # План обязан видеть capability из merge-дерева (true): tor обязателен.
        result = self.planner("--event", "pull_request", "--base", target, "--head", source)
        self.assertTrue(result["capabilities"]["real_tor_channel"])
        self.assertIn("tor", result["segments"])

    def test_graph_follows_merge_checkout_manifests(self):
        # Target меняет настоящие dependency/target declarations; source остаётся со старым manifest.
        original = json.loads(self.metadata.read_text(encoding="utf-8"))
        merged = json.loads(json.dumps(original))
        next(node for node in merged["resolve"]["nodes"] if node["id"] == "arti")["deps"].append(
            {"pkg": "config", "name": "tor_socks5_config", "dep_kinds": [{"kind": None, "target": None}]})
        next(package for package in merged["packages"] if package["id"] == "arti")["targets"] = [{"kind": ["cdylib"]}]
        meta_b = self.metadata.with_name("metadata-b.json")
        meta_b.write_text(json.dumps(merged), encoding="utf-8")
        cargo = self.bin / "cargo"
        cargo.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$CARGO_LOG"\n[ "$*" = "metadata --locked --all-features --format-version 1" ] || exit 99\ngrep -Fq \'tor-socks5-config = { path = "../proxy-config" }\' packages/arti-wrapper/Cargo.toml && exec cat "$FAKE_METADATA_ALT"\nexec cat "$FAKE_METADATA"\n', encoding="utf-8")
        cargo.chmod(0o755)
        self.env["FAKE_METADATA_ALT"] = str(meta_b)
        manifest = "[package]\nname='arti-wrapper'\nversion='0.1.0'\n"
        self.put("packages/arti-wrapper/Cargo.toml", manifest)
        self.put("packages/proxy-config/Cargo.toml", "[package]\nname='tor-socks5-config'\nversion='0.1.0'\n")
        self.commit("базовые манифесты графа")
        common = self.head()
        self.git("checkout", "-q", "-b", "graph-source")
        self.put("packages/proxy-config/src/lib.rs", "config source\n")
        self.commit("source меняет config со старым графом")
        source = self.head()
        self.git("checkout", "-q", common)
        dependency = 'tor-socks5-config = { path = "../proxy-config" }\n'
        self.put("packages/arti-wrapper/Cargo.toml", manifest + '[lib]\ncrate-type=["cdylib"]\n[dependencies]\n' + dependency)
        self.commit("target меняет dependency и тип target")
        target = self.head()
        self.git("merge", "--no-ff", "-q", "-m", "PR merge checkout", source)
        self.assertNotIn(dependency, self.git("show", source + ":packages/arti-wrapper/Cargo.toml"))
        self.assertIn(dependency, (self.root / "packages/arti-wrapper/Cargo.toml").read_text(encoding="utf-8"))
        result = self.planner("--event", "pull_request", "--base", target, "--head", source)
        expected = ["android-ffi", "arti-wrapper", "socks5-proxy", "tor-socks5-config"]
        self.assertEqual(result["packages"], expected)
        self.assertEqual(result["command_packages"]["rust"], expected)
        # Старый source graph включил бы arti-wrapper в library_packages; merge содержит только cdylib.
        self.assertEqual(result["library_packages"], ["android-ffi", "tor-socks5-config"])
        self.assertEqual(result["paths"], ["packages/arti-wrapper/Cargo.toml", "packages/proxy-config/src/lib.rs"])

    def test_plan_uses_merge_checkout_tree_legacy(self):
        # Валидный legacy: declaration false и anchors отсутствуют — совместимое состояние.
        # Source — наследник legacy без контрактных изменений; только merge-дерево
        # восстанавливает контракт. Чтение source тихо отключило бы tor.
        self.git("rm", "-q", *p.TOR_ANCHORS)
        self.put(p.CONTRACT_MANIFEST, "real_tor_channel = false\n")
        self.commit("downgrade без контракта")
        downgrade = self.head()
        self.git("checkout", "-q", "HEAD~1", "--", p.CONTRACT_MANIFEST, *p.TOR_ANCHORS)
        self.commit("target восстанавливает контракт")
        target = self.head()
        self.git("checkout", "-q", "-b", "legacy-source", downgrade)
        self.put("packages/proxy-config/src/lib.rs", "config legacy\n")
        self.commit("source изменение config")
        source = self.head()
        self.git("checkout", "-q", target)
        self.git("merge", "--no-ff", "-q", "-m", "PR merge checkout", "legacy-source")
        result = self.planner("--event", "pull_request", "--base", target, "--head", source)
        self.assertTrue(result["capabilities"]["real_tor_channel"])
        self.assertIn("tor", result["segments"])

    def test_event_wiring_end_to_end(self):
        # Параметры вычисляются из workflow-выражений и передаются CLI как есть — не руками.
        text = (Path(__file__).resolve().parents[2] / ".github/workflows/ci.yml").read_text(encoding="utf-8")

        def expression(prefix):
            line = next(item for item in text.splitlines() if item.strip().startswith(prefix + ": ${{"))
            return line.split("${{", 1)[1].rsplit("}}", 1)[0].strip()

        def evaluate(expr, payload):
            for part in (chunk.strip() for chunk in expr.split("||")):
                if payload.get(part):
                    return payload[part]
            return ""

        self.put("packages/auth/src/lib.rs", "auth wiring\n")
        self.commit("auth wiring")
        target = self.head()
        self.git("checkout", "-q", "-b", "wiring-pr", self.base)
        self.put("packages/proxy-config/src/lib.rs", "config wiring\n")
        self.commit("config wiring")
        source = self.head()
        self.git("checkout", "-q", target)
        self.git("merge", "--no-ff", "-q", "-m", "PR merge checkout", source)
        # github.sha — merge checkout: assert проверяет приоритет head.sha над github.sha.
        payload = {"github.event.pull_request.head.sha": source, "github.event.pull_request.base.sha": target,
                   "github.sha": self.head(), "github.event.before": ""}
        base = evaluate(expression("BASE"), payload)
        head = evaluate(expression("HEAD"), payload)
        self.assertEqual((base, head), (target, source))
        invocation = next(line.strip() for line in text.splitlines()
                          if line.strip().startswith("python -I scripts/testing/ci_planner.py --event "))
        env = dict(self.env, EVENT="pull_request", BASE=base, HEAD=head, BASE_REF="", MODE="affected")
        executed = self.cmd("bash", "-c", "set -euo pipefail\n" + invocation, env=env)
        self.assertEqual(executed.returncode, 0, executed.stderr)
        result = json.loads((self.root / "plan.json").read_text(encoding="utf-8"))
        self.assertFalse(result["full"])
        self.assertEqual(result["paths"], sorted(["packages/auth/src/lib.rs", "packages/proxy-config/src/lib.rs"]))

    def test_license_bundle_wiring_end_to_end(self):
        # license-bundle.yml — отдельный caller планировщика: он передаёт BASE/HEAD
        # из собственных выражений и пишет план в $RUNNER_TEMP/license-plan.json.
        # Если HEAD в этом workflow откатят к github.sha (merge checkout), план
        # снова увидит не тот head — этот тест ловит потерю merge-proof.
        text = (Path(__file__).resolve().parents[2] / ".github/workflows/license-bundle.yml").read_text(encoding="utf-8")

        def expression(prefix):
            line = next(item for item in text.splitlines() if item.strip().startswith(prefix + ": ${{"))
            return line.split("${{", 1)[1].rsplit("}}", 1)[0].strip()

        def evaluate(expr, payload):
            for part in (chunk.strip() for chunk in expr.split("||")):
                if payload.get(part):
                    return payload[part]
            return ""

        self.put("packages/auth/src/lib.rs", "auth bundle wiring\n")
        self.commit("auth bundle wiring")
        target = self.head()
        self.git("checkout", "-q", "-b", "bundle-pr", self.base)
        self.put("packages/proxy-config/src/lib.rs", "config bundle wiring\n")
        self.commit("config bundle wiring")
        source = self.head()
        self.git("checkout", "-q", target)
        self.git("merge", "--no-ff", "-q", "-m", "PR merge checkout", source)
        # github.sha — merge checkout: assert проверяет приоритет head.sha над github.sha.
        payload = {"github.event.pull_request.head.sha": source, "github.event.pull_request.base.sha": target,
                   "github.sha": self.head(), "github.event.before": ""}
        base = evaluate(expression("BASE"), payload)
        head = evaluate(expression("HEAD"), payload)
        self.assertEqual((base, head), (target, source))
        invocation = next(line.strip() for line in text.splitlines()
                          if line.strip().startswith("python3 -I scripts/testing/ci_planner.py --event "))
        env = dict(self.env, EVENT="pull_request", BASE=base, HEAD=head, BASE_REF="", MODE="affected",
                   RUNNER_TEMP=str(self.root))
        executed = self.cmd("bash", "-c", "set -euo pipefail\n" + invocation, env=env)
        self.assertEqual(executed.returncode, 0, executed.stderr)
        result = json.loads((self.root / "license-plan.json").read_text(encoding="utf-8"))
        self.assertFalse(result["full"])
        self.assertEqual(result["paths"], sorted(["packages/auth/src/lib.rs", "packages/proxy-config/src/lib.rs"]))

    def test_main_squash_push_semantics(self):
        self.put("packages/auth/src/lib.rs", "auth base\n")
        self.commit("auth base")
        base1 = self.head()
        self.git("checkout", "-q", "-b", "topic")
        self.put("packages/auth/src/lib.rs", "auth topic\n")
        self.commit("auth topic")
        self.git("checkout", "-q", "-")
        # Реальный squash на main: итоговый коммит один, его message и есть Git message диапазона.
        self.git("merge", "--squash", "-q", "topic")
        self.commit("squash auth\n\nCI-Full: sprint-end")
        squashed = self.head()
        result = self.push(base=base1, head=squashed)
        self.assertTrue(result["full"])
        self.assertEqual(result["full_trigger"], "commit_footer")
        # Негатив: footer был в исходных PR-коммитах, но squash-коммит его не содержит.
        self.git("checkout", "-q", "-b", "topic2")
        self.put("packages/proxy-config/src/lib.rs", "config pr\n")
        self.commit("config часть 1\n\nCI-Full: sprint-end")
        self.put("packages/proxy-config/src/lib.rs", "config pr 2\n")
        self.commit("config часть 2")
        self.git("checkout", "-q", "-")
        self.git("merge", "--squash", "-q", "topic2")
        self.commit("squash config без footer")
        result = self.push(base=squashed)
        self.assertFalse(result["full"])
        self.assertIsNone(result["full_trigger"])

    def test_main_merge_push_semantics(self):
        self.put("packages/auth/src/lib.rs", "auth base\n")
        self.commit("auth base")
        base1 = self.head()
        self.git("checkout", "-q", "-b", "topic")
        self.put("packages/auth/src/lib.rs", "auth topic\n")
        self.commit("auth topic\n\nCI-Full: sprint-end")
        self.git("checkout", "-q", "-")
        # Реальный merge-push на main: footer в исходном коммите топика, НЕ в merge message.
        self.git("merge", "--no-ff", "-q", "-m", "Merge topic без footer", "topic")
        result = self.push(base=base1)
        self.assertTrue(result["full"])
        self.assertEqual(result["full_trigger"], "commit_footer")

    def test_manual_affected_base_not_ancestor(self):
        self.git("branch", "side", self.base)
        self.git("checkout", "-q", "side")
        self.put("docs/side.md", "side\n")
        self.commit("side ветка")
        side = self.head()
        self.git("checkout", "-q", "-")
        manual = self.planner("--event", "workflow_dispatch", "--mode", "affected",
                              "--base-ref", side, "--head", self.head())
        self.assertFalse(manual["full"])
        self.assertIn("docs/side.md", manual["paths"])

    def test_real_rename_delete_and_unknown(self):
        self.git("mv", "packages/auth/src/lib.rs", "packages/bridge-probe/src/переименован файл.rs")
        self.commit("переименование")
        plan = self.push()
        self.assertEqual(plan["paths"], ["packages/auth/src/lib.rs", "packages/bridge-probe/src/переименован файл.rs"])
        self.assertIn("tor-socks5-auth", plan["packages"])
        self.assertIn("bridge-probe", plan["packages"])
        self.git("rm", "tor-socks5.example.ktav")
        self.commit("удаление")
        self.push(ok=False)
        self.git("reset", "--hard", "HEAD~1")
        self.put("unmapped.file", "unknown")
        self.commit("неизвестное")
        self.push(ok=False)

    def test_capability_git_removal_and_absence(self):
        anchors = ("scripts/testing/real-tor-channel.sh", "scripts/testing/real-tor-mutations.sh",
                   "apps/socks5-proxy/src/bridges/bridge_maintenance/real_channel_tests.rs")
        self.git("rm", anchors[0])
        self.commit("remove one anchor")
        self.push(ok=False)
        self.git("reset", "--hard", self.base)
        self.git("rm", *anchors)
        self.put(".config/ci-contracts.toml", "real_tor_channel = false\n")
        self.commit("remove all and downgrade")
        self.push(ok=False)
        self.planner("--event", "workflow_dispatch", "--mode", "sprint-full", "--head", self.head(), ok=False)
        self.git("reset", "--hard", self.base)
        self.git("rm", ".config/ci-contracts.toml")
        self.commit("remove declaration")
        self.push(ok=False)
        self.git("reset", "--hard", self.base)
        self.git("rm", *anchors)
        self.put(".config/ci-contracts.toml", "real_tor_channel = false\n")
        self.commit("legacy branch")
        legacy = self.head()
        self.put("packages/proxy-config/client-acl/src/lib.rs", "changed\n")
        self.commit("legacy acl")
        result = self.push(base=legacy)
        self.assertFalse(result["capabilities"]["real_tor_channel"])
        self.assertNotIn("tor", result["segments"])
        self.assertIn("rust", result["segments"])
        self.assertIn("tor-socks5-client-acl", result["packages"])
        self.git("rm", ".config/ci-contracts.toml")
        self.commit("legacy without manifest")
        legacy_without_manifest = self.head()
        self.put(".config/ci-contracts.toml", "real_tor_channel = false\n")
        self.commit("declare absent capability")
        result = self.push(base=legacy_without_manifest)
        self.assertFalse(result["capabilities"]["real_tor_channel"])
        self.assertEqual(result["segments"], ["fast", "regression"])
        self.assertEqual(result["capability_reasons"]["real_tor_channel"], "контракт не установлен")

    def test_doc_rename_missing_mapping(self):
        self.git("mv", "tor-socks5.example.ktav", "renamed.ktav")
        self.commit("rename required example")
        result = self.push(ok=False)
        self.assertIn("missing mapping: отсутствует обязательный документ: tor-socks5.example.ktav", result.stderr)

    def test_wrapper_list_and_args(self):
        self.put("packages/auth/src/lib.rs", "auth\n")
        self.commit("auth")
        auth = self.head()
        self.put("apps/socks5-proxy/src/lib.rs", "proxy\n")
        self.commit("proxy")
        for base, names in ((self.base, ["android-ffi", "socks5-proxy", "tor-socks5-auth"]),
                            (auth, ["socks5-proxy"])):
            for mode, expected in (("list", "\n".join(names)),
                                   ("args", " ".join("-p " + name for name in names))):
                result = self.cmd("sh", "scripts/testing/test-affected.sh", "--base", base, "--mode", mode)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, expected + "\n")
        self.assertTrue(all(line == "metadata --locked --all-features --format-version 1"
                            for line in self.log.read_text().splitlines()))

    def test_hook_real_stdin_and_dry_commands(self):
        self.put("packages/auth/src/lib.rs", "изменено\n")
        self.commit("auth")
        first = self.head()
        self.put("packages/auth/src/lib.rs", "ещё\n")
        self.commit("auth again")
        head = self.head()
        result = self.hook(self.ref(head, self.base))
        self.assertIn("dry-run: cargo clippy --locked -p android-ffi -p socks5-proxy -p tor-socks5-auth --all-targets -- -D warnings", result.stdout)
        self.assertIn("dry-run: cargo test --doc --locked -p android-ffi -p tor-socks5-auth", result.stdout)
        self.assertNotIn("cargo test --doc --locked -p socks5-proxy", result.stdout)
        self.hook(self.ref(first, self.base), ok=False)
        self.hook(self.ref(head, self.base) + self.ref(first, self.base), ok=False)
        result = self.hook(self.ref(ZERO, head))
        self.assertNotIn("dry-run: cargo", result.stdout)
        self.hook(self.ref(head, ZERO), ok=False)
        self.git("update-ref", "refs/remotes/origin/main", self.base)
        self.hook(self.ref(head, ZERO))
        result = self.hook(self.ref(head, "1" * 40), ok=False)
        self.assertIn("missing mapping:", result.stderr)
        self.assertNotIn("dry-run: cargo clippy", result.stdout)
        self.assertNotIn("dry-run: cargo test", result.stdout)
        self.assertNotIn("dry-run: cargo nextest", result.stdout)
        self.git("update-ref", "-d", "refs/remotes/origin/main")
        result = self.hook(self.ref(head, ZERO), full=True)
        self.assertIn("-p tor-socks5-client-acl", result.stdout)
        self.assertNotIn("-p tor-socks5-client-acl", self.hook(self.ref(head, self.base)).stdout)
        self.git("tag", "-a", "fixture-tag", "-m", "fixture tag")
        tagged = self.planner("--event", "push", "--base", self.base, "--head", "fixture-tag")
        self.assertEqual(tagged["paths"], ["packages/auth/src/lib.rs"])
        self.git("tag", "-a", "fixture-base", self.base, "-m", "fixture base")
        tag_object = self.git("rev-parse", "fixture-tag").strip()
        base_object = self.git("rev-parse", "fixture-base").strip()
        self.assertNotEqual(tag_object, head)
        tagged_hook = self.hook(
            f"refs/tags/fixture-tag {tag_object} refs/tags/fixture-tag {base_object}\n")
        self.assertIn("dry-run: cargo clippy --locked -p android-ffi -p socks5-proxy -p tor-socks5-auth --all-targets -- -D warnings", tagged_hook.stdout)
        self.assertNotIn("--workspace", tagged_hook.stdout)
        self.metadata.write_text('{}', encoding="utf-8")
        failed = self.hook(self.ref(head, self.base), ok=False)
        self.assertIn("missing mapping:", failed.stderr)
        self.assertNotIn("dry-run: cargo clippy", failed.stdout)
        self.assertNotIn("dry-run: cargo test", failed.stdout)
        self.assertNotIn("dry-run: cargo nextest", failed.stdout)


if __name__ == "__main__":
    unittest.main()
