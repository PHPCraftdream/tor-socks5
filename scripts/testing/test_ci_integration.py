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
        self.git("branch", "side-base", first)
        self.git("checkout", "-q", "side-base")
        self.put("docs/side.md", "другая ветка\n")
        self.commit("другая ветка")
        side = self.head()
        self.git("checkout", "-q", "-")
        pr = self.planner("--event", "pull_request", "--base", side, "--head", self.head())
        self.assertEqual(pr["paths"], ["packages/proxy-config/src/lib.rs"])
        self.assertEqual(self.push(base=first)["paths"], pr["paths"])
        manual = self.planner("--event", "workflow_dispatch", "--mode", "affected",
                              "--base-ref", first, "--head", self.head())
        self.assertFalse(manual["full"])
        self.assertEqual(manual["paths"], pr["paths"])
        self.assertEqual(manual["packages"], pr["packages"])
        self.assertEqual(manual["segments"], pr["segments"])
        for base in ("", "missing-ref"):
            self.planner("--event", "workflow_dispatch", "--base-ref", base, "--head", self.head(), ok=False)
        self.planner("--event", "push", "--base", self.base, "--head", first, ok=False)
        self.planner("--event", "push", "--mode", "sprint-full", "--head", self.head(), ok=False)
        full = self.planner("--event", "workflow_dispatch", "--mode", "sprint-full", "--head", self.head())
        self.assertTrue(full["full"])
        self.assertEqual(full["library_packages"], ["android-ffi", "arti-wrapper", "bridge-probe", "tor-socks5-auth", "tor-socks5-client-acl", "tor-socks5-config"])
        self.metadata.write_text('{}', encoding="utf-8")
        self.push(ok=False)

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
