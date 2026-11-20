"""Политика планировщика CI: константы, санкции и проверки capability.

Выделена из ci_planner.py, чтобы файл планировщика оставался меньше лимита
строк; сам планировщик реэкспортирует все эти имена.
"""
import tomllib
from pathlib import Path


class MappingError(Exception):
    pass


REQUIRED_DOCS = ("README.md", "tor-socks5.example.ktav",
                 "packages/proxy-config/examples/tor-socks5.bridges.example.ktav",
                 "docs/architecture.md", "docs/guide/bridges.md", "docs/guide/webtunnel.md",
                 "docs/guide/auth.md", "docs/guide/upstream.md", "docs/guide/dns-server.md",
                 "docs/guide/ops/logging.md", "docs/guide/ops/onion-service.md", "docs/guide/service.md")


CONTRACT_MANIFEST = ".config/ci-contracts.toml"
LICENSE_DOCS = frozenset({".github/release/license/README.md"})
LICENSE_POLICY_FILES = (".github/deny.toml",)

# Одноразовое сопоставление удаления неиспользуемой зависимости (по аналогии
# с удалённым заданием в JOB_SEGMENTS): запись остаётся, пока из старых баз
# возможен diff с этим удалением.
SANCTIONED_DEPENDENCY_REMOVALS = frozenset({
    ("packages/arti-wrapper/Cargo.toml", "dependencies", "anyhow"),
    # SDK-4: onion keystore/identity code moved to tor-socks5-onion
    # (apps/sdk/crates/onion); the binary no longer links these directly.
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "data-encoding"),
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "ed25519-dalek"),
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "sha2"),
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "sha3"),
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "zeroize"),
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "fs-mistrust"),
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "tor-keymgr"),
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "tor-llcrypto"),
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "dns-server"),
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "resocks5-net"),
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "socks5-proto"),
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "bridge-store"),
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "bridge-probe"),
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "bridge-verify-core"),
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "route-pool"),
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "futures"),
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "ktav"),
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "rusqlite"),
    # H12: the PT busybox dispatcher moved to tor-socks5-runtime (feature pt).
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "lyrebird"),
    # H12: rustls is now a normal dependency of tor-socks5-runtime (crypto provider helper).
    ("apps/sdk/crates/runtime/Cargo.toml", "dev-dependencies", "rustls"),
    # H18: HsNickname comes through tor-socks5-onion (facade re-export).
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "tor-hsservice"),
    # H20: 7 unused deps removed; bridge-fetcher/bridge-line/tempfile moved
    # to dev-dependencies (so they are also removed from [dependencies]).
    # SDK-5: onion-service hosting moved to tor-socks5-onion
    # (apps/sdk/crates/onion); the binary no longer links these directly.
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "tor-hscrypto"),
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "safelog"),
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "tor-cell"),
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "tor-proto"),
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "tor-error"),
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "serde"),
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "serde_json"),
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "indexmap"),
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "time"),
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "thiserror"),
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "getrandom"),
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "bridge-line"),
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "bridge-fetcher"),
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "tempfile"),
    # H20: server-side deps moved to dev-dependencies (or removed) in the
    # tor-socks5-server manifest, so they disappear from [dependencies].
    ("apps/sdk/crates/server/Cargo.toml", "dependencies", "bridge-line"),
    ("apps/sdk/crates/server/Cargo.toml", "dependencies", "bridge-store"),
    ("apps/sdk/crates/server/Cargo.toml", "dependencies", "time"),
    ("apps/sdk/crates/server/Cargo.toml", "dependencies", "tracing-subscriber"),
    # Bridge groups: bridge-line is a normal dependency of tor-socks5-server.
    ("apps/sdk/crates/server/Cargo.toml", "dev-dependencies", "bridge-line"),
    # H21: the binary now links the SDK through the tor-socks5 facade
    # (features `pt` + `auth`; `onion-service` maps to facade
    # `onion-service`/`onion-keys`). persist-lock comes via the facade's
    # always-on `persist` module; tor-socks5-onion/tor-socks5-runtime remain
    # only in [dev-dependencies] for the test seams.
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "arti-wrapper"),
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "auth"),
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "persist-lock"),
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "proxy-config"),
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "tor-socks5-onion"),
    ("apps/socks5-proxy/Cargo.toml", "dependencies", "tor-socks5-runtime"),
})


TOR_ANCHORS = ("scripts/testing/real-tor-channel.sh", "scripts/testing/real-tor-mutations.sh",
               "apps/sdk/crates/runtime/src/bridges/bridge_maintenance/real_channel_tests.rs")
TOR_MARKERS = {
    "apps/sdk/crates/runtime/src/bridges/bridge_maintenance.rs": ('#[cfg(test)]\n#[path = "bridge_maintenance/real_channel_tests.rs"]\nmod real_channel_tests;',),
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


def license_policy_capability(base_read, head_read):
    """Require a present, nonempty deny policy and reject removal."""
    def installed(read):
        text = read(".github/deny.toml")
        if text is not None and not text.strip():
            raise MappingError("missing mapping: empty license-policy identity file")
        return text is not None

    before, after = installed(base_read), installed(head_read)
    if before and not after:
        raise MappingError("missing mapping: license-policy identity removed")
    return after


def license_policy_checkout_capability(root, head_read, enabled):
    root = Path(root)
    for path in LICENSE_POLICY_FILES:
        expected = head_read(path)
        target = root
        for part in path.split("/")[:-1]:
            target /= part
            if target.is_symlink():
                raise MappingError("missing mapping: license policy checkout differs from Git: " + path)
            if not target.is_dir():
                target = None
                break
        actual = None
        if target is not None:
            target /= path.rsplit("/", 1)[-1]
            if target.is_symlink():
                raise MappingError("missing mapping: license policy checkout differs from Git: " + path)
            if target.exists():
                if not target.is_file():
                    raise MappingError("missing mapping: license policy checkout differs from Git: " + path)
                actual = target.read_bytes()
        if expected is None:
            if actual is not None:
                raise MappingError("missing mapping: license policy checkout differs from Git: " + path)
            continue
        if actual is None:
            raise MappingError("missing mapping: license policy checkout input missing: " + path)
        if not actual or actual != expected.encode("utf-8"):
            raise MappingError("missing mapping: license policy checkout differs from Git: " + path)
    return enabled
