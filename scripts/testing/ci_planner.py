#!/usr/bin/env python3
"""Детерминированный план CI; ошибки входных данных не превращаются в FULL."""
import argparse
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path


REQUIRED_DOCS = ("README.md", "tor-socks5.example.ktav",
                 "packages/proxy-config/examples/tor-socks5.bridges.example.ktav",
                 "docs/architecture.md", "docs/guide/bridges.md", "docs/guide/webtunnel.md",
                 "docs/guide/auth.md", "docs/guide/upstream.md", "docs/guide/dns-server.md",
                 "docs/guide/ops/logging.md", "docs/guide/ops/onion-service.md", "docs/guide/service.md")


CONTRACT_MANIFEST = ".config/ci-contracts.toml"
LICENSE_DOCS = frozenset({".github/release/license/README.md"})
TOR_ANCHORS = ("scripts/testing/real-tor-channel.sh", "scripts/testing/real-tor-mutations.sh",
               "apps/socks5-proxy/src/bridges/bridge_maintenance/real_channel_tests.rs")
TOR_MARKERS = {
    "apps/socks5-proxy/src/bridges/bridge_maintenance.rs": ('#[cfg(test)]\n#[path = "bridge_maintenance/real_channel_tests.rs"]\nmod real_channel_tests;',),
    "packages/arti-wrapper/src/lib.rs": ('pub use arti_client::config::BridgeConfigBuilder;', 'pub use tor_chanmgr::ChannelUsage;', '        chanmgr.terminate_all_channels();\n', '        self.inner\n            .reconfigure(&config, Reconfigure::AllOrNothing)\n            .map_err(TorError::Reconfigure)?;\n'),
    TOR_ANCHORS[0]: ('TOR_REAL_ISOLATED', 'real_channel_heal_and_config_selection', '--ignored --exact'),
    TOR_ANCHORS[1]: ('for mutation in terminate reconfigure', 'scripts/testing/real-tor-channel.sh', 'GITHUB_ACTIONS'),
    TOR_ANCHORS[2]: ('#[ignore', 'async fn real_channel_heal_and_config_selection()', 'ChannelUsage::UserTraffic'),
    ".github/workflows/ci.yml": ("capabilities.real_tor_channel", "scripts/testing/real-tor-channel.sh", "scripts/testing/real-tor-mutations.sh"),
}


def contract_capability(base_read, head_read):
    def declaration(read):
        text = read(CONTRACT_MANIFEST)
        if not text:
            return None
        try:
            data = tomllib.loads(text)
        except ValueError as exc:
            raise MappingError("missing mapping: capability declaration") from exc
        if set(data) != {"real_tor_channel"} or type(data["real_tor_channel"]) is not bool:
            raise MappingError("missing mapping: capability declaration")
        return data["real_tor_channel"]
    before, after = declaration(base_read), declaration(head_read)
    evidence = any(read(path) for read in (base_read, head_read) for path in TOR_ANCHORS)
    if after is None or (before is True and after is not True) or (evidence and not after):
        raise MappingError("missing mapping: real Tor capability declaration removed or inconsistent")
    if after:
        for path, markers in TOR_MARKERS.items():
            text = head_read(path)
            if not text or any(marker not in text for marker in markers):
                raise MappingError("missing mapping: real Tor contract: " + path)
    return after


class MappingError(Exception):
    pass


def run(*args):
    try:
        return subprocess.check_output(args, stderr=subprocess.PIPE)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise MappingError(f"команда не выполнена: {args[0]}: {exc}") from exc


def comparison(event, mode, base, head, base_ref, git):
    if event not in {"pull_request", "push", "workflow_dispatch"}:
        raise MappingError("неизвестное событие")
    if mode == "sprint-full" and event != "workflow_dispatch":
        raise MappingError("sprint-full разрешён только вручную")
    requested = git("rev-parse", "--verify", head + "^{commit}").decode().strip()
    checkout = git("rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    if not requested or requested != checkout:
        raise MappingError("checkout HEAD не совпадает с --head")
    if mode == "sprint-full":
        return None
    chosen = base_ref if event == "workflow_dispatch" else base
    if not chosen or not chosen.strip("0"):
        raise MappingError("не задана база сравнения")
    git("rev-parse", "--verify", chosen + "^{commit}")
    if event == "pull_request":
        chosen = git("merge-base", chosen, head).decode().strip()
        if not chosen:
            raise MappingError("merge-base не найден")
    return chosen


class Graph:
    def __init__(self, metadata, root):
        self.root = Path(root)
        self.packages = {p["id"]: p for p in metadata["packages"]}
        self.members = set(metadata["workspace_members"])
        resolve = metadata.get("resolve")
        nodes = resolve.get("nodes", []) if isinstance(resolve, dict) else []
        if not self.members or not nodes or not self.members <= self.packages.keys():
            raise MappingError("неполный граф cargo metadata")
        self.reverse = {p: set() for p in self.packages}
        self.forward = {p: set() for p in self.packages}
        seen = set()
        for node in nodes:
            ident = node.get("id")
            if ident not in self.packages or ident in seen or not isinstance(node.get("deps"), list):
                raise MappingError("неизвестный или повторный узел графа")
            seen.add(ident)
            for dep in node["deps"]:
                target = dep.get("pkg")
                kinds = dep.get("dep_kinds")
                if target not in self.packages or not isinstance(dep.get("name"), str) or not isinstance(kinds, list) or not kinds:
                    raise MappingError("неполная зависимость графа")
                for kind in kinds:
                    if not isinstance(kind, dict) or kind.get("kind") not in (None, "dev", "build") or "target" not in kind or (kind["target"] is not None and not isinstance(kind["target"], str)):
                        raise MappingError("неизвестный вид зависимости графа")
                self.reverse[target].add(ident)
                self.forward[ident].add(target)
        if seen != self.packages.keys():
            raise MappingError("неполный граф cargo metadata: отсутствуют узлы")
        self.paths = {}
        for ident, package in self.packages.items():
            try:
                rel = Path(package["manifest_path"]).resolve().relative_to(Path(root).resolve())
            except ValueError:
                continue
            self.paths[ident] = rel.parent.as_posix()

    def closure(self, seeds, edges=None):
        edges = self.reverse if edges is None else edges
        selected = set(seeds)
        todo = list(seeds)
        while todo:
            for item in edges[todo.pop()] - selected:
                selected.add(item)
                todo.append(item)
        return selected

    def owner(self, path):
        matches = [(len(prefix), ident) for ident, prefix in self.paths.items()
                   if prefix != "." and (path == prefix or path.startswith(prefix + "/"))]
        return max(matches)[1] if matches else None

    def named(self, names):
        return {i for i, p in self.packages.items() if p["name"] in names}


JOB_SEGMENTS = {
    "plan": "fast", "fmt": "fast", "line-limit": "fast", "dir-entries": "fast",
    "clippy-full": "rust", "clippy-affected": "rust", "test-full": "rust",
    "test-affected": "rust", "msrv": "msrv", "android": "android",
    "real-tor-channel": "tor", "installer-sh": "installer-sh",
    "installer-windows": "installer-windows", "publish-guard": "release",
    "packageability": "release", "release-scripts": "release",
    "required": "fast", "regression": "fast", "rust": "rust", "docs-contract": "docs-contract",
    "vendor-extra": "vendor-extra", "features": "features", "native-portability": "native-portability",
    "portability-diagnostics": "native-portability",
    "license-offline": "license-offline", "license-audit": "license-audit",
    "license-lifecycle": "license-lifecycle", "license-producer": "fast", "stress": "stress",
}


def workflow_blocks(text):
    lines = text.splitlines(keepends=True)
    start = next((i for i, line in enumerate(lines) if line.rstrip() == "jobs:"), None)
    if start is None:
        raise MappingError("missing mapping: не найден jobs в workflow")
    blocks = {}
    key = None
    for line in lines[:start]:
        match = re.match(r"^([A-Za-z0-9_-]+):", line)
        if match:
            key = "@" + match.group(1)
            if key in blocks:
                raise MappingError("missing mapping: повторный блок workflow " + key)
            blocks[key] = ""
        if key is not None:
            blocks[key] += line
        elif line.strip() and not line.lstrip().startswith("#"):
            raise MappingError("missing mapping: заголовок workflow")
    key = None
    for line in lines[start + 1:]:
        match = re.match(r"^  ([A-Za-z0-9_-]+):\s*(?:#.*)?$", line.rstrip())
        if match:
            key = match.group(1)
            if key in blocks:
                raise MappingError("missing mapping: повторный job " + key)
            blocks[key] = ""
        if key is None:
            if line.strip() and not line.lstrip().startswith("#"):
                raise MappingError("missing mapping: блок jobs")
        else:
            blocks[key] += line
    return blocks


def changed_keys(a, b):
    return {key for key in a.keys() | b.keys() if a.get(key) != b.get(key)}


def manifest_seeds(old, new, graph):
    a, b = tomllib.loads(old), tomllib.loads(new)
    seeds = set()
    for key in changed_keys(a, b):
        if key == "workspace":
            wa, wb = a.get(key, {}), b.get(key, {})
            for sub in changed_keys(wa, wb):
                if sub != "dependencies":
                    raise MappingError("missing mapping: workspace." + sub)
                da, db = wa.get(sub, {}), wb.get(sub, {})
                for name in changed_keys(da, db):
                    if name in da and name not in db:
                        raise MappingError("missing mapping: удалена зависимость workspace: " + name)
                    names = {name}
                    for value in (da.get(name), db.get(name)):
                        if isinstance(value, dict):
                            names.add(value.get("package", name))
                    found = graph.named(names)
                    if not found:
                        raise MappingError("missing mapping: зависимость отсутствует в текущем графе (возможно удалена): " + name)
                    seeds |= found
        elif key == "patch":
            for registry in changed_keys(a.get(key, {}), b.get(key, {})):
                names = changed_keys(a.get(key, {}).get(registry, {}), b.get(key, {}).get(registry, {}))
                found = graph.named(names)
                if {graph.packages[i]["name"] for i in found} != names:
                    raise MappingError("missing mapping: patch отсутствует в текущем графе (возможно удалён)")
                seeds |= found
        else:
            raise MappingError("missing mapping: Cargo.toml: " + key)
    return seeds


def lock_seeds(old, new, graph):
    a, b = tomllib.loads(old), tomllib.loads(new)
    if changed_keys({k: v for k, v in a.items() if k != "package"},
                    {k: v for k, v in b.items() if k != "package"}):
        raise MappingError("missing mapping: Cargo.lock")
    def index(data):
        return {json.dumps(p, sort_keys=True): p for p in data.get("package", [])}
    ia, ib = index(a), index(b)
    names = {p["name"] for k, p in (ia | ib).items() if k in ia.keys() ^ ib.keys()}
    found = graph.named(names)
    if {graph.packages[i]["name"] for i in found} != names:
        raise MappingError("missing mapping: пакет lock отсутствует в текущем графе (возможно удалён)")
    return found


def check_removed_dependencies(old, new):
    def dependencies(data):
        result = set()
        def visit(value, prefix=()):
            if not isinstance(value, dict):
                return
            for key, child in value.items():
                if key in ("dependencies", "dev-dependencies", "build-dependencies") and isinstance(child, dict):
                    result.update(prefix + (key, name) for name in child)
                elif key == "target" or prefix:
                    visit(child, prefix + (key,))
        visit(data)
        return result
    if dependencies(tomllib.loads(old)) - dependencies(tomllib.loads(new)):
        raise MappingError("missing mapping: удалена зависимость пакета")


def header_check(key, old, new):
    def lines(text):
        return [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if lines(old) == lines(new):
        return
    if key == "@env":
        for text in (old, new):
            for line in lines(text)[1:]:
                match = re.match(r"^  ([A-Za-z_][A-Za-z0-9_]*):\s*[^\[\]{ }].*$", line)
                if not match or match.group(1) not in {"CARGO_BUILD_JOBS", "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG", "CARGO_TERM_COLOR"}:
                    raise MappingError("missing mapping: workflow env")
    elif key == "@on":
        for text in (old, new):
            for line in lines(text)[1:]:
                if re.match(r"^  [A-Za-z_-]+:", line):
                    event = line.strip().split(":", 1)[0]
                    if event not in {"push", "pull_request", "workflow_dispatch"}:
                        raise MappingError("missing mapping: событие workflow: " + event)
                elif not line.startswith("    "):
                    raise MappingError("missing mapping: схема событий workflow")
            if lines(text) and lines(text)[0].strip() != "on:":
                raise MappingError("missing mapping: схема событий workflow")


def nextest_segments(old, new):
    a, b = tomllib.loads(old), tomllib.loads(new)
    if changed_keys(a, b) - {"profile", "test-groups"}:
        raise MappingError("missing mapping: конфигурация nextest")
    profiles = changed_keys(a.get("profile", {}), b.get("profile", {}))
    if profiles - {"default", "ci", "flaky-hunt"}:
        raise MappingError("missing mapping: профиль nextest")
    result = set()
    if profiles & {"default", "ci"} or a.get("test-groups") != b.get("test-groups"):
        result.add("rust")
    if "flaky-hunt" in profiles or a.get("test-groups") != b.get("test-groups"):
        result.add("stress")
    return result


NATIVE_TARGETS = {
    "x86_64-unknown-linux-gnu": ("ubuntu-latest", False),
    "x86_64-unknown-linux-musl": ("ubuntu-latest", True),
    "aarch64-linux-android": ("ubuntu-latest", False),
    "x86_64-pc-windows-msvc": ("windows-latest", False),
    "aarch64-unknown-linux-gnu": ("ubuntu-24.04-arm", False),
    "aarch64-unknown-linux-musl": ("ubuntu-24.04-arm", True),
    "aarch64-apple-darwin": ("macos-15", False),
    "x86_64-apple-darwin": ("macos-15-intel", False),
}


def config_targets(old, new):
    a, b = tomllib.loads(old), tomllib.loads(new)
    if changed_keys({k: v for k, v in a.items() if k != "target"}, {k: v for k, v in b.items() if k != "target"}):
        raise MappingError("missing mapping: .cargo/config.toml вне target")
    targets = changed_keys(a.get("target", {}), b.get("target", {}))
    if targets - NATIVE_TARGETS.keys():
        raise MappingError("missing mapping: неизвестный target .cargo/config.toml")
    return targets


def plan(graph, paths, blobs, mode="affected", capabilities=None, event="pull_request"):
    if capabilities is None:
        capabilities = {"license_stack": (graph.root / ".github/deny.toml").is_file() and (graph.root / ".github/release/license").is_dir()}
    license_stack = bool(capabilities.get("license_stack", False))
    real_tor = capabilities.get("real_tor_channel", True)
    if type(real_tor) is not bool:
        raise MappingError("missing mapping: real Tor capability")
    segments = {"fast"}
    reasons = {"fast": {"всегда"}}
    seeds = set()
    native = set()
    dependency_seeds = set()
    def add(segment, reason):
        if segment == "tor" and not real_tor:
            return
        if segment == "license-lifecycle" and (event != "pull_request" or mode == "sprint-full"):
            return
        segments.add(segment)
        reasons.setdefault(segment, set()).add(reason)
    def seed(ids, path):
        seeds.update(ids)
        if ids:
            reasons.setdefault("rust", set()).add(path)
    def required(names):
        ids = graph.named(names) & graph.members
        if {graph.packages[i]["name"] for i in ids} != set(names):
            raise MappingError("missing mapping: отсутствуют необходимые workspace packages: " + ", ".join(sorted(names)))
        return ids
    for path in sorted(set(paths)):
        if path in ("Cargo.toml", "Cargo.lock"):
            old, new = blobs(path)
            try:
                ids = (manifest_seeds if path == "Cargo.toml" else lock_seeds)(old, new, graph)
                dependency_seeds.update(ids)
                seed(ids, path)
            except (ValueError, KeyError) as exc:
                raise MappingError("missing mapping: ошибка TOML: " + path) from exc
        elif path in (".github/workflows/ci.yml", ".github/workflows/nightly.yml", ".github/workflows/release.yml", ".github/workflows/license-bundle.yml", ".github/workflows/license-promote.yml"):
            old, new = blobs(path)
            a = workflow_blocks(old) if old else {}
            b = workflow_blocks(new)
            nightly = {"full": "rust", "flaky-hunt": "stress", "vendor-extra": "vendor-extra", "features": "features", "report": "fast"}
            release = {"validate": "release", "build": "release", "release": "release", "license-audit": "license-audit", "origin": "license-offline"}
            license_jobs = {"offline-tests": "license-offline", "build": "license-lifecycle", "aggregate": "license-offline", "promote": "license-offline", "plan": "fast", "required": "fast", "guard": "fast", "pr-lifecycle": "license-lifecycle", "license-producer": "license-lifecycle"}
            mapping = JOB_SEGMENTS if path.endswith("/ci.yml") else nightly if path.endswith("/nightly.yml") else license_jobs if path.endswith(("/license-bundle.yml", "/license-promote.yml")) else release
            for job in sorted(changed_keys(a, b)):
                if job in ("@name", "@on", "@concurrency", "@env", "@permissions"):
                    if job == "@on" and path.endswith(("/nightly.yml", "/license-bundle.yml", "/license-promote.yml")):
                        # Ночной schedule не используется планировщиком событий CI.
                        pass
                    elif not (job == "@env" and path.endswith(("/license-bundle.yml", "/license-promote.yml"))):
                        header_check(job, a.get(job, ""), b.get(job, ""))
                    if job == "@env" and path.endswith(("/license-bundle.yml", "/license-promote.yml")):
                        add("license-offline", path + ":" + job)
                        add("license-lifecycle", path + ":" + job)
                    add("fast", path + ":" + job)
                elif job in mapping:
                    if job in ("license-audit", "license-offline", "license-lifecycle") and not license_stack and job not in a:
                        add("fast", path + ":" + job)
                    elif job == "full" and job not in b:
                        add("rust", path + ":" + job)
                    else:
                        add(mapping[job], path + ":" + job)
                    if job == "portability-diagnostics" and path.endswith("/ci.yml"):
                        # При переходе сохраняются все цели прежнего portability-контракта.
                        native.update(("x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl",
                                       "aarch64-unknown-linux-gnu"))
                    if job == "build" and path.endswith("/license-bundle.yml"):
                        add("license-offline", path + ":" + job)
                    if path.endswith("/nightly.yml"):
                        add("regression", path + ":" + job)
                    if path.endswith("/release.yml") and license_stack:
                        add("license-offline", path + ":" + job)
                else:
                    raise MappingError("missing mapping: блок workflow: " + job)
        elif path == ".cargo/config.toml":
            try:
                native.update(config_targets(*blobs(path)))
            except (ValueError, KeyError, TypeError) as exc:
                raise MappingError("missing mapping: .cargo/config.toml") from exc
            if native:
                add("native-portability", path)
        elif path == CONTRACT_MANIFEST:
            add("fast", path)
            add("regression", path)
        elif path == ".config/nextest.toml":
            try:
                for segment in nextest_segments(*blobs(path)):
                    add(segment, path)
            except (ValueError, TypeError) as exc:
                raise MappingError("missing mapping: nextest") from exc
        elif path.startswith(".config/") or path in ("rust-toolchain", "rust-toolchain.toml"):
            raise MappingError("missing mapping: " + path)
        elif path.startswith(".cargo/"):
            raise MappingError("missing mapping: " + path)
        elif path.startswith(".github/actions/setup-local-sdk/"):
            sdk = {i for i, p in graph.packages.items() if p["name"].startswith("resocks5-")}
            if not sdk:
                raise MappingError("missing mapping: SDK отсутствует в графе")
            seed(sdk, path)
        elif path in ("scripts/testing/ci_planner.py", "scripts/testing/test_ci_planner.py", "scripts/testing/test_ci_integration.py", "scripts/testing/selftest.sh", "scripts/testing/test-affected.sh", "scripts/check-line-limit.sh", "scripts/check-dir-entries.sh", ".githooks/pre-push"):
            add("fast", path)
        elif path in ("scripts/testing/real-tor-channel.sh", "scripts/testing/real-tor-mutations.sh"):
            add("tor", path)
        elif path.startswith("scripts/testing/"):
            raise MappingError("missing mapping: " + path)
        elif path == "scripts/build-android.ps1":
            add("android", path)
            native.add("aarch64-linux-android")
            add("native-portability", path)
        elif path.startswith("packages/proxy-config/examples/") or path == "README.md" or path == "tor-socks5.example.ktav" or path == "docs/architecture.md" or path.startswith("docs/guide/"):
            add("docs-contract", path)
        elif path.startswith("docs/") or path in ("CHANGELOG.md", ".gitignore", ".gitattributes"):
            add("fast", path)
        elif path in (".github/install/tests/test_release.py", ".github/install/tests/gh_mock.py", ".github/install/tests/fixtures.py"):
            add("release", path)
            if license_stack:
                add("license-offline", path)
            if path.endswith("/fixtures.py"):
                add("installer-sh", path)
                add("installer-windows", path)
        elif path.startswith(".github/install/"):
            if path.endswith(".sh") or "Sh" in path:
                add("installer-sh", path)
            elif path.endswith(".ps1"):
                add("installer-windows", path)
            else:
                add("installer-sh", path)
                add("installer-windows", path)
        elif path in LICENSE_DOCS:
            add("fast", path)
        elif path.startswith("scripts/license/") or path.startswith(".github/release/license/") or path.startswith("LICENSE"):
            add("license-offline", path)
        elif path == ".github/deny.toml":
            add("license-audit", path)
        elif path.startswith(".github/release/") or path in ("scripts/check-publish-guard.sh", "scripts/check-packageability.sh", "scripts/publishable-crates.sh"):
            add("release", path)
        elif path.endswith('/README.md') and graph.owner(path) and path == graph.paths[graph.owner(path)] + '/README.md':
            add("fast", path)
        else:
            owner = graph.owner(path)
            if not owner:
                raise MappingError("missing mapping: путь: " + path)
            if path.endswith("/Cargo.toml"):
                try:
                    check_removed_dependencies(*blobs(path))
                except (ValueError, TypeError) as exc:
                    raise MappingError("missing mapping: ошибка TOML: " + path) from exc
            seed({owner}, path)
            if path.startswith("vendor/") and owner not in graph.members:
                add("vendor", path)
    selected = graph.closure(seeds) & graph.members
    # Tor зависит от контрактных компонентов, а не от любого потребителя proxy.
    tor_roots = {i for i, package in graph.packages.items() if package["name"] in {"bridge-probe", "arti-wrapper", "tor-socks5-config", "tor-socks5-client-acl"}}
    tor_upstream = graph.closure(tor_roots, graph.forward) if tor_roots else set()
    if seeds & tor_upstream:
        add("tor", "изменена зависимость контракта Tor")
    if any(path.startswith("apps/socks5-proxy/") and any(part in {"tor", "arti", "bridge", "bridges"} or part.startswith(("tor_", "arti_", "bridge_", "bridges_")) for part in path.split("/")) for path in paths):
        add("tor", "изменён код контракта Tor proxy")
    if mode == "sprint-full":
        selected = set(graph.members)
        for segment in ("rust", "msrv", "android", "tor", "vendor", "vendor-extra", "docs-contract", "installer-sh", "installer-windows", "release", "features", "stress", "regression", "native-portability", "required"):
            add(segment, "ручной sprint-full")
        if license_stack:
            add("license-offline", "лицензионный стек")
            add("license-audit", "лицензионный стек")
        native.update(NATIVE_TARGETS)
    if selected:
        add("rust", "обратное замыкание графа")
        add("msrv", "обратное замыкание графа")
        if {graph.packages[i]["name"] for i in selected} & {"socks5-proxy", "android-ffi"}:
            add("android", "затронут поставляемый пакет")
    proxy = graph.named({"socks5-proxy"}) & graph.members
    native_names = {graph.packages[i]["name"] for i in dependency_seeds}
    if proxy & selected and native_names & {"openssl-sys", "libsqlite3-sys", "zstd-sys", "ring", "cc", "cmake", "windows-sys"}:
        if native_names - {"windows-sys"}:
            native.update(("x86_64-unknown-linux-gnu", "x86_64-unknown-linux-musl", "aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl"))
        if native_names & {"windows-sys", "ring", "cc", "cmake", "openssl-sys", "libsqlite3-sys", "zstd-sys"}:
            native.add("x86_64-pc-windows-msvc")
        add("native-portability", "изменена native-зависимость proxy")
    if license_stack and mode != "sprint-full":
        interfaces = any((path not in LICENSE_DOCS and path.startswith((".github/release/license/", "scripts/license/"))) or
                         (path.startswith("apps/socks5-proxy/") and (path.endswith("/build.rs") or "license" in path.lower() or "recipient_information" in path or path in ("apps/socks5-proxy/src/main.rs", "apps/socks5-proxy/src/args.rs", "apps/socks5-proxy/src/cli.rs")))
                         for path in paths)
        dependency_change = proxy & selected and any(path == "Cargo.toml" or path == "Cargo.lock" or path.endswith("/Cargo.toml") for path in paths)
        if any(path in ("Cargo.toml", "Cargo.lock") or path.endswith("/Cargo.toml") for path in paths):
            add("license-audit", "изменены зависимости")
        if any(path.endswith("/build.rs") for path in paths):
            add("license-offline", "изменён build.rs")
        if interfaces or dependency_change:
            add("license-offline", "изменён интерфейс или зависимости лицензирования proxy")
            add("license-audit", "изменён интерфейс или зависимости лицензирования proxy")
            seed(proxy, "изменён интерфейс лицензирования proxy")
            native.update(("x86_64-unknown-linux-gnu", "x86_64-unknown-linux-musl"))
            add("native-portability", "изменён интерфейс лицензирования proxy")
            add("license-lifecycle", "изменён интерфейс или зависимости лицензирования proxy")
    if license_stack and proxy & selected and any(path.startswith((".github/actions/setup-local-sdk/", "vendor/")) for path in paths):
        add("license-lifecycle", "изменены SDK или vendor зависимости proxy")
        add("license-audit", "изменены SDK или vendor зависимости")
        native.update(("x86_64-unknown-linux-gnu", "x86_64-unknown-linux-musl"))
        add("native-portability", "изменены SDK или vendor зависимости proxy")
    if proxy & selected and any(path.endswith("/build.rs") for path in paths):
        native.update(("x86_64-unknown-linux-gnu", "x86_64-unknown-linux-musl"))
        add("native-portability", "build.rs в замыкании proxy")
    # Интерфейсы лицензирования могут выбрать proxy после первоначального замыкания.
    selected = set(graph.members) if mode == "sprint-full" else graph.closure(seeds) & graph.members
    if selected:
        add("rust", "обратное замыкание графа")
        add("msrv", "обратное замыкание графа")
        if {graph.packages[i]["name"] for i in selected} & {"socks5-proxy", "android-ffi"}:
            add("android", "затронут поставляемый пакет")
    # Пустые списки команд недопустимы для включённых сегментов.
    representative = {"socks5-proxy", "tor-socks5-auth", "tor-socks5-config"}
    shipping = {"socks5-proxy", "android-ffi"}
    commands = {}
    for segment in ("rust", "msrv"):
        ids = selected if selected else (required(representative) if segment in segments else set())
        commands[segment] = sorted({graph.packages[i]["name"] for i in ids}) if segment in segments else []
    android_ids = selected & required(shipping)
    commands["android"] = sorted(graph.packages[i]["name"] for i in (android_ids or required(shipping))) if "android" in segments else []
    commands["native-portability"] = sorted(graph.packages[i]["name"] for i in required({"socks5-proxy"})) if "native-portability" in segments else []
    if "native-portability" in segments and not native:
        native.update(("x86_64-unknown-linux-gnu", "x86_64-unknown-linux-musl"))
    names = sorted({graph.packages[i]["name"] for i in selected})
    lib_ids = graph.named(commands["rust"]) & graph.members
    libs = sorted(graph.packages[i]["name"] for i in lib_ids if graph.packages[i]["name"] != "saturating-time" and any(set(t.get("kind", [])) & {"lib", "rlib", "proc-macro"} for t in graph.packages[i].get("targets", [])))
    rows = []
    for segment in sorted(segments):
        targets = ["ubuntu-latest"]
        if segment == "rust":
            targets = ["ubuntu-latest", "macos-latest", "windows-latest"] if mode == "sprint-full" else ["ubuntu-latest", "windows-latest"]
        elif segment == "installer-sh":
            targets = ["ubuntu-latest", "macos-latest"]
        elif segment == "installer-windows":
            targets = ["windows-latest"]
        for target in targets:
            rows.append({"segment": segment, "target": target})
    native_rows = [{"runner": NATIVE_TARGETS[t][0], "target": t, "musl": NATIVE_TARGETS[t][1]} for t in sorted(native)]
    return {"packages": names, "command_packages": commands, "library_packages": libs,
            "shipping_packages": sorted(graph.packages[i]["name"] for i in required(shipping)),
            "segments": sorted(segments), "target_rows": rows, "native_rows": native_rows,
            "paths": sorted(set(paths)), "reasons": {k: sorted(reasons[k]) for k in sorted(segments)}, "full": mode == "sprint-full",
            "capabilities": {"license_stack": license_stack, "real_tor_channel": real_tor},
            "capability_reasons": {"real_tor_channel": "установлен контракт" if real_tor else "контракт не установлен"},
            "license_stack": license_stack}


RESULT_JOBS = {
    "fmt": ("fast", "regression"), "line-limit": ("fast",), "dir-entries": ("fast",),
    "publish-guard": ("fast",), "packageability": ("fast",),
    "real-tor-channel": ("tor",), "rust": ("rust",), "msrv": ("msrv",),
    "android": ("android",), "docs-contract": ("docs-contract",),
    "installer-sh": ("installer-sh",), "installer-windows": ("installer-windows",),
    "release-scripts": ("release",), "native-portability": ("native-portability",),
    "vendor-extra": ("vendor-extra", "vendor"), "features": ("features",),
    "stress": ("stress",), "license-offline": ("license-offline",),
    "license-audit": ("license-audit",), "license-lifecycle": ("license-lifecycle",),
}


def validate_results(plan, needs):
    if not isinstance(needs, dict) or set(needs) != set(RESULT_JOBS) | {"plan"}:
        raise MappingError("missing mapping: неполный набор потребителей CI")
    if needs["plan"].get("result") != "success":
        raise MappingError("plan failed")
    segments = plan["segments"]
    if not isinstance(segments, list) or not all(isinstance(x, str) for x in segments):
        raise MappingError("missing mapping: неверные сегменты")
    capabilities = plan.get("capabilities")
    if not isinstance(capabilities, dict) or type(capabilities.get("real_tor_channel")) is not bool:
        raise MappingError("missing mapping: real Tor capability")
    if "tor" in segments and not capabilities["real_tor_channel"]:
        raise MappingError("missing mapping: real Tor selected without capability")
    unsupported = set(segments) - {s for values in RESULT_JOBS.values() for s in values} - {"required"}
    if unsupported:
        raise MappingError("missing mapping: нет потребителя: " + ", ".join(sorted(unsupported)))
    for job, selections in RESULT_JOBS.items():
        expected = "success" if any(s in segments for s in selections) else "skipped"
        actual = needs[job].get("result")
        if actual != expected:
            raise MappingError(f"{job}: expected {expected}, got {actual}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="")
    parser.add_argument("--head", required=True)
    parser.add_argument("--event", required=True)
    parser.add_argument("--mode", choices=("affected", "sprint-full"), default="affected")
    parser.add_argument("--base-ref", default="")
    args = parser.parse_args()
    try:
        git = lambda *a: run("git", *a)
        base = comparison(args.event, args.mode, args.base, args.head, args.base_ref, git)
        root = git("rev-parse", "--show-toplevel").decode().strip()
        # Граф и проверяемые исходники должны соответствовать выбранному коммиту.
        dirty = git("status", "--porcelain=v1", "-z", "--untracked-files=all").decode().split("\0")
        for entry in dirty:
            if entry and (entry.endswith((".rs", "Cargo.toml", "Cargo.lock")) or entry.startswith((" R", "R ", " C", "C "))):
                raise MappingError("незакоммиченные исходники или манифесты: " + entry)
        # Контракт поставляемых документов проверяется по дереву коммита, не по рабочему каталогу.
        for path in REQUIRED_DOCS:
            entries = git("ls-tree", "-z", "--name-only", args.head, "--", path).decode().split("\0")
            if path not in entries:
                raise MappingError("missing mapping: отсутствует обязательный документ: " + path)
        metadata = json.loads(run("cargo", "metadata", "--locked", "--all-features", "--format-version", "1"))
        graph = Graph(metadata, root)
        paths = [] if base is None else git("diff", "--name-only", "--no-renames", "-z", base, args.head).decode().split("\0")
        paths = [p for p in paths if p]
        def blobs(path):
            def read(ref):
                entry = git("ls-tree", "--name-only", ref, "--", path).decode().strip()
                return git("show", ref + ":" + path).decode() if entry == path else ""
            return tuple(read(ref) for ref in (base, args.head))
        def tree_read(ref, path):
            if ref is None:
                return ""
            entry = git("ls-tree", "--name-only", ref, "--", path).decode().strip()
            return git("show", ref + ":" + path).decode() if entry == path else ""
        # Ручной полный запуск также проверяет первого родителя на удаление контракта в HEAD.
        parent = base
        if parent is None:
            parents = git("rev-list", "--parents", "-n", "1", args.head).decode().split()
            parent = parents[1] if len(parents) > 1 else None
        real_tor = contract_capability(lambda p: tree_read(parent, p), lambda p: tree_read(args.head, p))
        capabilities = {"real_tor_channel": real_tor,
                        "license_stack": (Path(root) / ".github/deny.toml").is_file() and (Path(root) / ".github/release/license").is_dir()}
        result = plan(graph, paths, blobs, args.mode, capabilities=capabilities, event=args.event)
        supported = {s for values in RESULT_JOBS.values() for s in values} | {"required"}
        unsupported = set(result["segments"]) - supported
        if unsupported:
            raise MappingError("missing mapping: нет потребителя: " + ", ".join(sorted(unsupported)))
        print(json.dumps(result, sort_keys=True, ensure_ascii=False))
    except (MappingError, ValueError, KeyError, OSError, TypeError) as exc:
        message = str(exc)
        print("planner: " + (message if message.startswith("missing mapping:") else "missing mapping: " + message), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
