# tor-socks5 — SDK facade

One dependency for the libraries of this repository. The crate is a thin
facade: each module is a workspace crate re-exported whole, so nothing is
copied or wrapped, the crates keep their own tests and docs, and a fix in one
of them reaches the facade at once.

It is **not published to crates.io**. The Tor stack needs the vendored Arti
forks, and a crates.io package cannot carry them (`[patch]` is dropped on
publish and never reaches a consumer). Take the facade from git and, if you
link Tor, add the patch-kit.

## Add it

```toml
[dependencies]
# Pin a commit; a release tag works as well once a release contains this crate.
tor-socks5 = { git = "https://github.com/PHPCraftdream/tor-socks5", rev = "<commit>" }
```

Rust 1.92 or newer. The default features are Tor-free:

```toml
tor-socks5 = { git = "…", rev = "<commit>", default-features = false, features = ["auth", "config"] }
```

```rust
use tor_socks5::auth::{compute_hash, verify_hash};
use tor_socks5::config::Config;
```

## Features

| Feature | Module | Crate | Implies |
|---|---|---|---|
| *(always)* | `persist` | `persist-lock` | |
| `socks5` | `proto` | `tor-socks5-proto` | |
| `acl` | `acl` | `tor-socks5-client-acl` | |
| `route` | `route` | `tor-socks5-route-pool` | `acl` |
| `auth` | `auth` | `tor-socks5-auth` | `acl` |
| `config` | `config` | `tor-socks5-config` | `acl`, `bridges` |
| `bridges` | `probe`, `store`, `verify` | `bridge-probe`, `bridge-store`, `bridge-verify-core` | |
| `tor` | `tor` | `arti-wrapper` | `socks5`, `acl` |
| `fetch` | `fetch` | `bridge-fetcher` | `tor`, `bridges` |
| `dns` | `dns` | `tor-socks5-dns` | `tor`, `acl` |
| `onion-service` | | `arti-wrapper/onion-service` | `tor` |
| `full` | all of the above | | |

`default = ["socks5", "auth", "config", "bridges"]`. The bridge modules work
without Tor: probing, health storage and verification do not link Arti.

## Using the Tor features

`tor`, `fetch`, `dns`, `onion-service` and `full` link Arti. Cargo resolves
stock Arti from crates.io unless the **final binary's or workspace's root**
`Cargo.toml` carries the `[patch.crates-io]` block of the patch-kit, and stock
Arti silently lacks our fixes (bridge descriptor fetch hangs, a poisoned
netdir, stale channels after a network change, the Windows `saturating-time`
loop). The block, its tag and the caveats are in
[`vendor/README.md`](../../vendor/README.md#using-these-patches-in-your-own-project).

Check the result with `cargo tree -i tor-dirclient`: the source must be this
repository's git URL, not `crates.io`. Nothing in the facade can detect a
missing patch, so this check is yours to make.

## Tor client settings

With `tor` and `config`, the circuit knobs of the config file are plain
fields on both sides: `tor.circuit_hops` and `tor.guard_spread` in
`config::Config`, and `circuit_hops`, `service_circuit_hops` and
`guard_spread` in `tor::Settings`. `guard_spread` (1..=3, default 1) is how
many primary guards (bridges) the client circuits spread over; the default is
stock Arti behavior. Raise it only to isolate the failure of one bridge, and
note that more bridges then see your traffic (see
[Many services](../../docs/guide/ops/onion-service.md) for what was measured).

```rust
use tor_socks5::config::Config;
use tor_socks5::tor::Settings;

let cfg = Config::default();
let settings = Settings {
    guard_spread: cfg.tor.guard_spread,
    ..Settings::default()
};
```

## Accounts and config migration

With `auth`, `auth::Registry` edits the users file the way the `users`
command does. Each call is one transaction (the registry lock, bounded wait,
atomic save); nothing prompts or prints, so the password is an argument. With
`config`, `config::migrate_config` converts a config in the old layout to the
current one.

```rust
use tor_socks5::auth::{Hop, NewUser, Registry, UsersConfig};

let registry = Registry::new(UsersConfig::resolve_path(None));
registry.add(
    NewUser { name: "alice".into(), ..NewUser::default() },
    "alice-pass",
)?;
registry.set_onion("alice", true)?;
registry.set_proxies("alice", Hop::Post, None)?; // inherit the global pool
```

## What is not here

The facade re-exports the libraries under `packages/`. The logic that runs
the proxy lives in the `socks5-proxy` binary and is **not** available as a
library yet:

- the proxy server (listeners, egress, pre/post pools, startup and shutdown);
- hosting onion services (start gate, stream limits, statuses) and the
  onion key store and vanity search; the `onion-service` feature only turns
  on the onion support of `arti-wrapper`;
- the bridge manager (verifier, warmer, health writer, maintenance) and the
  Tor watchdog.

To use these today, run the binary. Taking them into library crates is
planned in [`docs/plans/sdk-coverage-plan.md`](../../docs/plans/sdk-coverage-plan.md).
Also outside the facade by design: the Android `cdylib`, `pt-helper`, the OS
service installer and the command-line parser. The vendored crates are never
exposed through it.
