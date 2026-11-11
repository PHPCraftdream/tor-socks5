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

## What is not here

The `socks5-proxy` binary, the Android `cdylib` and `pt-helper` are not
libraries and stay out of the facade. The vendored crates are never exposed
through it.
