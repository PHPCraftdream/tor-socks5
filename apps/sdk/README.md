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
| `runtime` | `runtime` | `tor-socks5-runtime` | `tor`, `config`, `bridges` |
| `onion` | `onion` | `tor-socks5-onion` | |
| `onion-keys` | `onion` (keys) | `tor-socks5-onion/keys` | |
| `onion-service` | | `arti-wrapper/onion-service` | `tor`, `onion-host` |
| `onion-host` | `onion` (host) | `tor-socks5-onion/host` | |
| `full` | all of the above | | |

`default = ["socks5", "auth", "config", "bridges"]`. The bridge modules work
without Tor: probing, health storage and verification do not link Arti.

## Using the Tor features

`tor`, `fetch`, `dns`, `runtime`, `onion-service`, `onion-host` and `full` link
Arti; `onion-keys`
does **not** join this list (its `tor-keymgr` and `tor-hscrypto` are only
the crypto and keystore part — no Tor client is linked). Cargo resolves
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

## Onion service addresses, vanity and keys

With `onion`, `onion::address` prints and parses v3 onion addresses and
`onion::vanity` searches for a vanity prefix, with a progress callback and
a cancellation flag.

Behind `onion-keys`, `onion::keys` covers the service identities of the
Arti native keystore: `new`, `list`, `show`, `export`, `import` and
`remove` as plain functions, without printing or prompting — the keystore
directory is an explicit argument (typically `<state>/keystore` next to the
config). Export produces the keystore file itself (an OpenSSH-format
ed25519-expanded key) and import accepts the same file. Confirmations (the
`--yes` analog), passwords and all output stay with the application.
`onion-keys` does not pull in a Tor client — no patch-kit is needed for it
— and the keystore files are compatible with `arti`.

```rust
use tor_socks5::onion::keys::{create_service, NewIdentity};

// `state` — the arti state directory your launch uses.
let recorded = create_service(
    &config_path,            // the main config (`<stem>.onion.ktav` lives next to it)
    &state.join("keystore"), // the keystore directory: an explicit argument
    "web", None, false, NewIdentity::Random,
)?;
println!("created {}", recorded.address);
```

## Hosting onion services (`onion-host` feature)

Behind `onion-host`, `onion::host` is the server-side hosting that used to
live only in the binary: identity settlement, the gradual launch (at most 4
services at a time), per-service (256) and process-wide (512) forwarded-
stream caps, lifecycle logging and a `watch` status snapshot. The keystore
directory and the onion services file location are explicit arguments;
nothing prints and no process state is installed — shutdown is the
cancellation token, and dropping the handle only cancels that token
(`shutdown().await` additionally joins the producer). One live host per
keystore: the keystore lock makes concurrent hosting of the same keystore
fail loudly but non-fatally (status `Failed`/`KeystoreLockHeld`); a
sequential restart works because a new `start()` reacquires the lock.

```text
use tor_socks5_onion::host::{OnionHost, OnionHostConfig};
// handle: the runtime's TorHandle; token: a tokio_util CancellationToken.
let host_handle = OnionHost::new(
    OnionHostConfig::new(handle, keystore_dir, token)
        .with_entries(cfg.onion_services)
        .with_config_path(Some(config_path)),
)
.start();
let status = host_handle.subscribe();          // watch::Receiver<OnionHostStatus>
// ... in the shutdown choreography:
host_handle.shutdown().await;
```

This feature links Arti — the patch-kit applies (see
[Using the Tor features](#using-the-tor-features)).

## Tor client (runtime feature)

The `runtime` feature is the SDK-9 Tor client surface of
`tor-socks5-runtime` (`apps/sdk/crates/runtime`), exposed through the
`tor_socks5::runtime` module. The flow of an embedding host:

- **Build settings** from the ktav config:

  ```rust
  let settings = tor_socks5::runtime::tor_setup::build_tor_settings(
      &cfg, Some(&config_path)).await?;
  ```

  This probes bridges, falls back over the preferred pool and the built-in
  seeds, updates the bridge health store and prunes dead bridges.
  `build_tor_settings_with_pt` lets you choose the pluggable-transport
  binary.
- **The PT entry point.** With bridges that need a transport, the CLI
  binary resolves `TOR_PT_BINARY` or spawns itself (busybox dispatch on
  `TOR_PT_MANAGED_TRANSPORT_VER`). An embedding host without such dispatch
  passes `tor_socks5::runtime::pt::PtBinary::Explicit(path)` pointing at
  its own dispatcher or the repository's `pt-helper` build.
- **Run.** Wrap the bootstrapped `tor_socks5::tor::TorTunnel` in
  `runtime::tor_watchdog::TorHandle` (`tunnel()`, `health()`, `drain()`
  for shutdown), feed connect outcomes via `TorHealth`/`classify_and_record`
  and arm the watchdogs: `spawn_tor_watchdog` returns `None` when disabled
  or a `WatchdogRun` whose `join` you join at shutdown and whose `status`
  (`watch::Receiver<WatchdogStatus>`) reports checks started, consecutive
  heal failures and the last `HealOutcome`; `spawn_bridge_failover_watchdog`
  for the soft-failover signals.
- **Observe.** `runtime::conn_health::ConnHealthCounters` with
  `snapshot_and_reset()` windowed `ConnHealthSnapshot`s and the optional
  periodic summary via `spawn_conn_health_logger`.
- **The restart contract:** one live Tor client per process; sequential
  stop-then-start works.

Note: the `runtime` feature links Arti — the patch-kit `[patch.crates-io]`
block from [`vendor/README.md`](../../vendor/README.md) in your final
binary/workspace root is **required**. The facade is a git dependency, not
a crates.io release (the vendored forks cannot travel with a published
package).

## Bridge health writer and guard observations

With `runtime`, the SDK-7 surface of `tor-socks5-runtime` is exposed: the
single writer of the bridge health store and the observation layer for
arti's guard events. Neither installs process state on its own: the
writer runs where you start and stop it, and the observation layer is
wired into your own `tracing_subscriber` registry — the proxy binary
does exactly this in its startup.

```rust
use tor_socks5::runtime::{close_global, init_global, observation_layer, ObservationSink};
use tracing_subscriber::layer::SubscriberExt;

// Start the process-wide writer (one live instance per process; after a
// close, the next init starts a fresh writer, never the closed one).
// `config_path` is the main config; the store is its sibling file.
let writer = init_global(Some(config_path));

let sink = ObservationSink::new();
tracing_subscriber::registry()
    .with(fmt_layer)                  // your own log layer
    .with(observation_layer(&sink))   // carries the tor_guardmgr=trace filter
    .init();

// One health mutation; `Ok` once absorbed — a slow or failing disk is
// the writer's retry problem. At shutdown, stop and get the final
// flush result:
writer
    .apply(|store| store.note_circuit_success_at(&bridge, now))
    .await?;
let flush = close_global().await; // Some(Ok(())) when a writer was running
```

`StoreWriter` is cheap to clone — hand it to every producer task — and
`close` returns the final flush outcome. Guard observations land in the
`ObservationSink`; match them to your bridges and apply them to a store
with `ObservationSink::drain_into_store` (`drain` returns the raw
observations). The retrying maintenance loop around them, the verifier
and the warmer are the bridge manager (SDK-8 in the plan) and are not
part of the facade yet.

## What is not here

The facade re-exports the libraries under `packages/` and `apps/sdk/crates/`. The logic that runs
the proxy lives in the `socks5-proxy` binary and is **not** available as a
library yet:

- the proxy server (listeners, egress, pre/post pools, startup and shutdown);
- the bridge manager (verifier, warmer, maintenance loop).

The bridge health writer, the guard-event observation and the Tor client
and watchdog surface are available behind the `runtime` feature (see
[Tor client (runtime feature)](#tor-client-runtime-feature) and
[Bridge health writer and guard observations](#bridge-health-writer-and-guard-observations)).

To use these today, run the binary. Taking them into library crates is
planned in [`docs/plans/sdk-coverage-plan.md`](../../docs/plans/sdk-coverage-plan.md).
Also outside the facade by design: the Android `cdylib`, `pt-helper`, the OS
service installer and the command-line parser. The vendored crates are never
exposed through it.
