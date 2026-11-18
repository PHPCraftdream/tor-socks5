"""Общий каркас проверок планировщика: загрузка ci_planner и тестовые графы."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]

spec = importlib.util.spec_from_file_location("ci_planner", Path(__file__).resolve().parents[1] / "ci_planner.py")
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
        "facade": ("tor-socks5", "apps/sdk"),
        "ffi": ("android-ffi", "packages/android-ffi"),
        "runtime": ("tor-socks5-runtime", "apps/sdk/crates/runtime"),
        "server": ("tor-socks5-server", "apps/sdk/crates/server"),
        "onion": ("tor-socks5-onion", "apps/sdk/crates/onion"),
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
    edges = {"proxy": ["auth", "config", "bridge", "arti", "sdk", "native", "server"], "ffi": ["config", "auth"], "bridge": ["middle"], "arti": [], "middle": ["vendor"], "acl": [], "auth": ["acl"], "config": ["acl"], "sdk": [], "vendor": [], "native": [], "facade": ["server", "runtime", "onion"], "runtime": [], "server": ["runtime", "onion"], "onion": []}
    nodes = [{"id": i, "deps": [{"pkg": d, "name": "alias_" + d, "dep_kinds": [{"kind": "build" if d == "middle" else "dev" if d == "auth" else None, "target": "cfg(unix)" if d == "vendor" else None}]} for d in deps]} for i, deps in edges.items()]
    return p.Graph({"packages": packages, "workspace_members": ["proxy", "auth", "config", "acl", "bridge", "arti", "ffi", "facade", "runtime", "server", "onion"], "resolve": {"nodes": nodes}}, root)


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


class RoutingCase(unittest.TestCase):
    """Routing checks over the sample workspace graph."""

    def setUp(self):
        self.g = graph()

    def route(self, *paths, blobs=None, mode="affected", capabilities=None, event="pull_request"):
        return p.plan(self.g, paths, lambda path: blobs[path], mode, capabilities, event)
