# tor-socks5 — SDK facade

One dependency for the libraries of this repository. The crate is a thin
facade: most leaf-library modules re-export their workspace crate, while the
runtime and embedded-server modules expose curated APIs. Runtime functions and
types are re-exported directly from `tor_socks5::runtime`; the facade does not
expose the runtime crate's internal module tree. Features select which crates
are linked.

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
| `runtime` | `runtime` (curated flat exports) | `tor-socks5-runtime` | `tor`, `config`, `bridges` |
| `server` | `server` | `tor-socks5-server` | `runtime`, `onion-service` |
| `onion` | `onion` | `tor-socks5-onion` | |
| `onion-keys` | `onion` (keys) | `tor-socks5-onion/keys` | |
| `onion-service` | | `arti-wrapper/onion-service` | `tor`, `onion-host` |
| `onion-host` | `onion` (host) | `tor-socks5-onion/host` | |
| `full` | all of the above | | |

`default = ["socks5", "auth", "config", "bridges"]`. The bridge modules work
without Tor: probing, health storage and verification do not link Arti.

## Using the Tor features

`tor`, `fetch`, `dns`, `runtime`, `server`, `onion-service`, `onion-host` and
`full` link Arti; `onion-keys`
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

## Host process initialisation

An embedding host sets up the process itself before any Tor client bootstraps;
the SDK never installs process-wide state on its own (R1).

- `tor_socks5::install_crypto_provider()` (feature `runtime`): installs the
  process-wide rustls crypto provider. rustls 0.23 requires an explicit
  provider — call this exactly once, before bootstrapping; a fresh state dir
  fails its TLS setup without it.
- `tor_socks5::runtime::bind_child_processes_to_self()`: on Windows, puts the
  process in a `KILL_ON_JOB_CLOSE` Job Object so spawned children (the
  lyrebird PT) die with the host even on hard termination; a documented no-op
  elsewhere.
- `tor_socks5::runtime::log_layer(&LogConfig)`: builds the tracing fmt layer
  from a `tor_socks5::config::LogConfig` and returns it together with the
  non-blocking writer's guard — without installing a global subscriber. Keep
  the guard alive for the lifetime of the program.

```rust
let (layer, _guard) = tor_socks5::runtime::log_layer(&log_config);
tracing_subscriber::registry().with(layer).init();
```

With the `pt` feature, `tor_socks5::pt::run_if_managed_transport()` runs the
in-process lyrebird PT loop when arti spawns this process as a managed
transport.

## Tor client (runtime feature)

`runtime` exposes selected Tor-client functions and types as flat exports from
`tor_socks5::runtime`, not as the runtime crate's internal module tree. The
host can build settings, choose a PT binary, operate the Tor handle and arm the
watchdogs using these facade exports. `build_tor_settings` probes bridges,
falls back over the preferred pool and built-in seeds, updates the bridge
health store and prunes dead bridges; `build_tor_settings_with_pt` accepts a
`PtBinary` for a host-provided dispatcher.

The runtime exports include the settings/path helpers, `PtBinary`, `TorHandle`,
`TorHealth`, `BridgeRefresh`, `classify_and_record`, watchdog status and spawn
APIs, plus connection-health counters and snapshots. These names are available
at the flat `tor_socks5::runtime::*` level; no `tor_setup`, `tor_watchdog`,
`conn_health` or `pt` submodule path is part of the facade API.

After bootstrapping, wrap the tunnel with `TorHandle::new_with_settings(tunnel,
&settings)`. In addition to holding the tunnel, it seeds the handle's active
bridge set from `settings.bridges`; bridge verification selects due candidates
only from that active set. The proxy server and the runtime examples use this
constructor. `TorHandle::new(tunnel)` remains available when settings are not
at hand, but does not perform that initialization.

`PtBinary::Environment` remains the default policy, matching the CLI: it uses
`TOR_PT_BINARY` when set, otherwise the current executable (the CLI busybox PT
dispatch). For bridge-manager producers this policy is captured for the
manager's lifetime in `BridgeManagerConfig`; passing `Settings` directly to
`start` or `start_with_parent_token` converts it to a config with
`PtBinary::Environment`. This preserves the policy, not a resolved path or
snapshot of environment variables; the environment policy is still resolved
when a producer needs a PT binary. Hosts using an explicit PT dispatcher should
pass the same policy used to build settings, for example:

```rust
use tor_socks5::runtime::{start, BridgeManagerConfig, PtBinary};

let manager_config = BridgeManagerConfig {
    settings,
    pt_binary: PtBinary::Explicit(pt_path),
};
let manager = start(handle, config_path, &cfg, sink, manager_config);
```

The facade intentionally retains these health counters, failure
classification, watchdogs, settings builders, PT helper and bridge-manager
start helpers: custom egress, reporting and pluggable-transport setup need
them. Runtime maintenance, worker and owner implementation modules are not
re-exported.

The restart contract is one live Tor client per process; sequential
stop-then-start is supported. This documents the API contract; no live runtime
verification is claimed here.

Note: the `runtime` feature links Arti — the patch-kit `[patch.crates-io]`
block from [`vendor/README.md`](../../vendor/README.md) in your final
binary/workspace root is **required**. The facade is a git dependency, not
a crates.io release (the vendored forks cannot travel with a published
package).

## Bridge health writer and guard observations

With `runtime`, the facade exports the bridge-health writer and observation
APIs directly from `tor_socks5::runtime`. Neither installs process state on
its own: the writer runs where you start and stop it, and the observation
layer is wired into your own `tracing_subscriber` registry — the proxy
binary does exactly this in its startup.

```rust
use tor_socks5::runtime::{close_global, init_global, observation_layer, ObservationSink};
use tracing_subscriber::layer::SubscriberExt;

// Start the process-wide writer (one live instance per process; after a
// close, the next init starts a fresh writer, never the closed one).
// `config_path` is the main config; the store is its sibling file.
let writer = init_global(&config_path);

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
observations).

## Bridge manager and `bridges fetch` (SDK-8)

With `runtime`, use the facade's flat bridge-manager exports. `start` owns its
background bridge producers; one live manager per process (D5), so stop it
before starting another. At shutdown, cancel and join the producers before
closing the bridge-store writer:

```rust
use tor_socks5::runtime::{close_global, start, ObservationSink};

let manager = start(handle, config_path, &cfg, sink, settings);
println!("running: {:?}", manager.status().producers);
let outcomes = manager.shutdown_with_timeout(std::time::Duration::from_secs(30)).await;
for outcome in &outcomes {
    println!("{outcome:?}");
}
let flush = close_global().await;
```

For a host with a parent cancellation token, `start_with_parent_token` makes
the manager's producer token its child. `BridgeManagerHandle::transfer_tasks`
can move join handles into the host's own task owner; after transfer that owner
must arrange cancellation and join or abort every task. Dropping an untransferred
manager cancels its token and aborts its owned joins. Cancelling a polled
`shutdown()` future also drops the manager and aborts any remaining joins;
await shutdown to let cooperative producer work finish normally.

`fetch_bridges` is the core of the CLI's `bridges fetch` command: it bootstraps
Tor from configured bridges (built-in seeds as fallback), refreshes the
candidate pool from configured HTTPS sources and, unless `probe` is `false`,
probes candidates and promotes reachable ones into the working config. The
application keeps config loading, validation, tracing and printing; the result
is `Result<FetchBridgesOutcome { added, promoted, pool_len }, FetchBridgesError>`.
`FetchBridgesError` variants: `NoConfigFile` (`config_path` is required; a
path to a nonexistent config file errors before any file I/O — the SDK never
creates a default config file; run the server once or pass an explicit path),
`PreProxies` (a global `pre_proxies` pool is rejected by the
SDK itself: fetching runs over the host network and cannot honour it),
`NoBridgeSources`, `Cancelled`, and `Other` (everything else, with the root
cause as `source()`). `FetchBridgesParams.pt_binary` (a `PtBinary` policy)
is used for the bootstrap settings and the admission/drain checks; hosts that
cannot be re-spawned as a PT dispatcher must pass `PtBinary::Explicit`.

It is not cancel-safe: cancellation is observed at every stage (pre-flight,
settings build, bootstrap, pool refresh, drain) and returns
`FetchBridgesError::Cancelled`. Once the Tor tunnel exists, any error or
cancellation drops the tunnel and then runs the trailing 200 ms cleanup sleep
before returning — that tail is deliberately not cancellable, so arti's
reactor releases the PT children and the state-dir lock. A cancellation
during (or before) the final pause after a *successful* fetch skips the rest
of the pause but never loses the already-recorded outcome: the call still
returns `Ok`.

## Embedded SOCKS5 server (`server` feature)

With `server`, `tor_socks5::server` exposes `Server`, `ServerBuilder`,
`ServerHandle`, `ServerError`, `ServerStage`, `ServerStatus` and
`DnsStartupPolicy`. The builder accepts the
facade's `config::Config`; for upstream SOCKS5 egress, configure it explicitly
with `.upstream(Some(address), username, password)`. Starting the server does
not connect to or validate the upstream proxy; that proxy must already be
available when client connections need egress. `ServerBuilder::run_until`
drives startup and serving until a supplied shutdown future resolves, then
requests shutdown through a server-owned child token and awaits cleanup. It
never cancels a caller-owned parent token.

```rust,no_run
use tor_socks5::config::Config;
use tor_socks5::server::Server;

# async fn run() -> Result<(), tor_socks5::server::ServerError> {
let cfg = Config {
    listen: vec!["127.0.0.1:0".into()],
    ..Config::default()
};
let server = Server::builder(cfg)
    // Required: sibling files (users registry, bridge store, DNS cache,
    // keystore) are resolved from this path; startup fails with
    // `ServerError::Config` when it is missing, and nothing is written to
    // the current directory. The supplied config is a startup snapshot:
    // it is read once and never re-read live.
    .config_path(std::path::PathBuf::from("tor-socks5.ktav"))
    .dns_startup_policy(tor_socks5::server::DnsStartupPolicy::Required)
    .upstream(Some("127.0.0.1:9050".into()), None, None)
    .start()
    .await?;
server.shutdown().await?;
# Ok(())
# }
```

When the users file next to the config is absent, the server logs a warning at
startup and accepts anonymous SOCKS5 clients (an existing-but-empty file logs
an informational line instead).

The embedded-server contract is one live server per process: await
`shutdown()` before starting another; sequential restart is supported. Embedded
startup requires at least one configured DNS UDP/TCP pair to bind
(`DnsStartupPolicy::Required`) by default; unavailable pairs are skipped
(`AddrInUse`, `PermissionDenied`, or `AddrNotAvailable`, the latter queued for
retry). Set the builder to `DnsStartupPolicy::Background` for the proxy CLI's
legacy optional/non-fatal DNS behavior; the CLI sets this policy explicitly.
`Running` addresses include only successfully bound sockets. Startup returns
`ServerError::Bind` only when no pair binds.
Each run that allocates owner storage consumes one of the 15 process-lifetime
quarantine slots, so repeated restarts that use owner storage can exhaust that
limit. The handle's `Drop` only cancels its token and never blocks, so use
explicit `shutdown().await` to finish the cleanup attempt. Settings/global-init/owner
recovery uses explicit deadlines; producer and handler joins have their own budgets
(normal producer grace is 120 seconds). The final blocking-worker join has a
five-second timeout. Closing the bridge-store writer is awaited without a deadline.
`Stopped` means that attempt completed (successfully or with an error;
`ServerError::Cleanup` preserves a secondary cleanup failure), not that every task
handle was provably joined; timed-out handles remain retained in process slots for
recovery by the next start. SDK-14 does not change embedded-server `Drop` or
shutdown semantics. The server library does not install a tracing subscriber or crypto provider, bind child processes,
load process config, or handle OS signals; those remain the host application's
responsibility.

This Tor-linked feature requires the patch-kit (see
[Using the Tor features](#using-the-tor-features)). The seven facade examples
are [embedded_server.rs](examples/embedded_server.rs),
[onion_address.rs](examples/onion_address.rs),
[onion_keys.rs](examples/onion_keys.rs),
[accounts_config.rs](examples/accounts_config.rs),
[tor_runtime.rs](examples/tor_runtime.rs),
[onion_host.rs](examples/onion_host.rs) and
[bridge_fetch.rs](examples/bridge_fetch.rs). Their manifest-declared required
features, respectively, are `server`, `onion`, `onion-keys`, `auth` + `config`,
`runtime`, `runtime` + `onion-host`, and `runtime`; CI derives example feature
checks from those declarations. The embedded-server example does not start or
require a Tor bootstrap, but client egress still needs the configured upstream
proxy.

## CLI capability mapping

The facade exposes library functions, not a replacement executable. Host
configuration and validation, `tracing`/crypto installation and result
printing remain in the CLI; unsupported-pool validation is private there. The
facade export checker parses only public `use` trees rooted at the literal
`tor_socks5_runtime` name. Its bounded syntax is ASCII identifiers, `::`,
aliases, nested brace groups, `self` and globs. It does not perform Rust name
resolution or follow private import aliases/re-export chains.

| CLI capability | Facade API | Feature |
|---|---|---|
| `users` account operations | `auth::Registry` | `auth` |
| SOCKS5 framing and HTTP CONNECT protocol | `proto` | `socks5` |
| Client access rules and ACL types | `acl` | `acl` |
| Proxy route pools and rotation | `route` | `route` |
| `config migrate` and config schema | `config::migrate_config`, `config::Config` | `config` |
| Bridge reachability probing | `probe` | `bridges` |
| Bridge health storage | `store` | `bridges` |
| Pluggable-transport verification state | `verify` | `bridges` |
| Tor tunnel | `tor::TorTunnel`, `tor::Settings` | `tor` |
| Bridge-list retrieval | `fetch` | `fetch` |
| DNS resolver and server APIs | `dns` | `dns` |
| `bridges fetch` core | `runtime::fetch_bridges` | `runtime` |
| Bridge maintenance and health writer | `runtime::start`, `runtime::StoreWriter`, `runtime::ObservationSink` | `runtime` |
| Tor settings, PT policy, health and watchdog | flat `runtime` exports | `runtime` |
| Onion address and vanity operations | `onion::address`, `onion::vanity` | `onion` |
| Onion identity/keystore operations | `onion::keys` | `onion-keys` |
| Onion service hosting | `onion::host` | `onion-host` |
| Embedded SOCKS5 server | `server::Server` and builder | `server` |
| Process shell, `clap` commands, help, signals, angel and OS service management | Not provided | — |
| Android FFI / `cdylib` | Not provided; SDK-13 is pending | — |
| `pt-helper` executable | Not provided; separate workspace app | — |

CI compiles the facade surface test and runs clippy for the no-default build and
each manifest feature (including `acl`); it checks example compilation with
each manifest-declared required feature set. These are configured checks, not
a claim that CI has run for this change.

The host application still owns process initialization and configuration
loading, signals, CLI parsing/printing and operating-system service
management. Vendored crates are never exposed through the facade.
