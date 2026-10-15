# tor-socks5-config

The Ktav startup configuration schema for the tor-socks5 proxy: a typed `Config` in which every section has defaults, loaded from a file — `TOR_SOCKS5_CONFIG` env var, then `tor-socks5.ktav` in the working directory, then built-in defaults — with an explicit override (a CLI flag) winning over all of that.

For hosts of the proxy — the CLI daemon and the Android JNI engine share this crate — and for any tool that needs to read or rewrite the same configuration format: bridge lists, DNS policy, watchdog, warm pool, upstream chaining, SOCKS5 user accounts, security toggles.

The main configuration includes `tor.circuit_hops`, permitted values `2` and `3` (default `3`). This setting affects client-side onion-service circuits only when vanguards are disabled; with `2`, those stems omit the middle relay. Ordinary exit circuits remain three hops. Onion-service circuits are configured per service with `onion_services[].circuit_hops` (default `4`); HsDir upload circuits never use fewer than three hops. Shorter paths reduce anonymity and are intended for censorship circumvention, not anonymity.

## Usage

The crate publishes as `tor-socks5-config`, while the library target keeps the in-tree name `proxy_config`.

```rust
use proxy_config::{BridgesConfig, Config};

let cfg = Config {
    listen: vec!["127.0.0.1:9050".into()],
    tor: proxy_config::TorConfig { circuit_hops: 2 },
    bridges: BridgesConfig {
        lines: vec![
            "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=ZZZ iat-mode=0"
                .to_string(),
            "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=ZZZ iat-mode=0"
                .to_string(), // duplicates are dropped at parse time
        ],
        ..Default::default()
    },
    ..Default::default()
};

cfg.write(&path)?;                                  // atomic Ktav write
let cfg = Config::load_with_override(Some(&path))?.into_config();

let parsed = cfg.bridges.parsed()?;                 // parse + dedupe bridge lines
// parsed.bridges / parsed.duplicates / parsed.rejected / parsed.dns_hints
```

`Config::load_with_override` returns a `Loaded` that tells you which source won (`FromFile` vs `Defaults`). Config sections redact secrets when printed — e.g. the upstream proxy password in `Debug`.

## Example

`cargo run --example config_walkthrough` builds a config, writes and reloads it, and walks every section, including duplicate bridge removal and DNS-hint extraction.
