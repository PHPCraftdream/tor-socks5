# Architecture

A local same-port SOCKS5 / HTTP CONNECT → Tor gateway built on `arti-client`, with pure-Rust
**obfs4 + webtunnel** pluggable-transport support. The user-facing
artifact is a single binary (the `socks5-proxy` crate): it acts as the
SOCKS5 proxy when invoked normally and as the PT process when re-invoked
by arti's `tor-ptmgr` (see `docs/guide/bridges.md` for the busybox dispatch).

## Workspace layout

```
tor-socks5/
├── Cargo.toml                  # workspace root + [patch.crates-io] overrides
├── tor-socks5.ktav             # startup config (Ktav format), gitignored
├── tor-socks5.example.ktav     # committed template
├── docs/
├── packages/                   # in-house libraries
│   ├── android-ffi/            # Android JNI cdylib crate (libtorsocks5.so)
│   ├── arti-wrapper/           # bootstrap & connect facade over arti-client
│   ├── auth/                   # SOCKS5 user accounts + Argon2id authenticator
│   ├── bridge-fetcher/         # HTTPS-over-Tor bridge list fetching
│   ├── bridge-probe/           # parallel TCP reachability probe + latency sort
│   ├── dns-server/             # optional local DNS/DoH-over-Tor resolver + per-mask overrides
│   ├── proxy-config/           # Ktav Config schema, shared by the CLI and android-ffi
│   └── socks5-proto/           # shared host auth adapter over resocks5-net framing
├── apps/
│   └── socks5-proxy/           # the binary (SOCKS5 proxy + busybox PT dispatch)
└── vendor/                     # locally-patched forks of 7 upstream crates
    ├── arti-client/            # 0.47.0
    ├── saturating-time/        # 0.5.0
    ├── tor-chanmgr/            # 0.47.0
    ├── tor-circmgr/            # 0.47.0
    ├── tor-dirclient/          # 0.47.0
    ├── tor-dirmgr/             # 0.47.0
    └── tor-guardmgr/           # 0.47.0
```

The torrc `Bridge` line grammar is parsed by the external
`ptrs-gesher-bridge-line` crate — there is no local `bridge-line`
package, and `ptrs-gesher` is **not** vendored. The workspace consumes
`ptrs-gesher-bridge-line` and `ptrs-gesher-lyrebird` 0.7 through the root
`Cargo.toml` workspace dependencies; no sibling checkout is patched in.

## Crates and their responsibilities

### `packages/arti-wrapper`

A thin facade over `arti-client`. Three responsibilities:

* Build a `TorClientConfig` from our `Settings` (bridges + PT binary
  path + an app-local `state_dir`/`cache_dir`).
* `TorTunnel::bootstrap_with(settings)` returns a cheap-to-clone client.
* `TorTunnel::connect(host, port)` returning an
  `arti_client::DataStream` for use in the SOCKS5 hand-off.

Workspace-pinned `arti-client` features: `bridge-client`, `pt-client`,
`onion-service-client`, `static-sqlite`, `rustls`, `tokio`. The caller
passes `current_exe()` as `pt_binary` so arti spawns *us* for the PT
child (busybox dispatch). `Settings::state_dir` pins arti's on-disk
state and cache under an app-local directory so a stale guard sample
or cached consensus from another arti instance can never shadow the
configured bridges — see `docs/guide/webtunnel.md` for the failure mode this
prevents.

### `packages/auth`

SOCKS5 user accounts and password authentication for the proxy's
listener (RFC 1929 USERNAME/PASSWORD). Mirrors the `resocks5` design:

* Users live in a separate Ktav file (`tor-socks5.users.ktav`) next to
  the main config.
* Passwords are hashed with **Argon2id** (per-user random salt, PHC
  serialisation).
* A process-local **HMAC-SHA256** success cache lets repeated logins
  skip the expensive Argon2 step without giving brute-force attackers
  an equivalent speed-up (failures are not cached).
* An account whose stored hash is the `init` sentinel adopts the first
  non-empty password presented at login (**trust-on-first-use**) and
  the real hash is written back to disk.
* Per-account `.onion` gating: a user without `allowed_onion` is refused
  a circuit to a `.onion` destination.

Consumed directly by both hosts, which implement `socks5_proto::PasswordVerifier`
for their credential store. The adapter does not depend on `auth`. SDK framing
supplies RFC 1929 or HTTP Basic credentials to the same verification path. See
`docs/guide/auth.md`, including the Android-specific `Config.auth` section.

### `packages/proxy-config`

The Ktav `Config` schema (`listen` / `log` / `bridges` / `watchdog` /
`warm_pool` / `conn_health` / `upstream` / `auth` / `security` / `dns` /
`dns_server`), shared verbatim by
`apps/socks5-proxy` (via the `crate::config` re-export shim) and
`packages/android-ffi` (loaded directly from the `configPath` argument to
`nativeStart`). Depends only on `ktav`/`serde`/`indexmap`/`bridge-line` — no
crypto or filesystem-registry logic lives here, that's `packages/auth`.

### `packages/socks5-proto`

Shared host authentication adapter, not a protocol implementation. Both CLI and
JNI accept SOCKS5 CONNECT and HTTP CONNECT on the same port; ordinary HTTP
forwarding, SOCKS5 BIND, and UDP ASSOCIATE are unsupported. `resocks5_net::server`
owns detection, framing, auth responses, request identity/pipeline, and replies.

`accept(stream, deadline: tokio::time::Instant,
auth: Option<Arc<dyn PasswordVerifier>>)` returns SDK `IncomingRequest` / `ServerError`.
Hosts supply one absolute 30-second deadline from handshake start. `None` enables
anonymous access only; `Some(verifier)` requires passwords with no anonymous
downgrade. Verification is awaited on the blocking pool with a process-wide cap
of 256 queued/running calls, matching the host connection cap. Full admission
rejects immediately; the owned slot
stays in the blocking closure across timeout/cancellation until it exits. Connection
caps cannot bound detached verification work. Errors, deadlines, and cancellation
are terminal: discard the stream and any buffered wrapper.

The shared `is_onion` predicate matches the final DNS label case-insensitively,
tolerating trailing dots. Hosts pass a parsed host, not a target authority with a
port. CLI policy uses the SDK's authenticated username for account permissions;
JNI applies the global destination policy.

### `packages/android-ffi`

The Android JNI cdylib crate (`libtorsocks5.so`, JNI symbols under
`Java_org_torproject_android_service_TorSocks5Bridge_*`; see the crate's
`lib.rs` module docs for the full Kotlin-side contract). Structurally it is
a second front end over the same engine pieces the CLI uses:

* `lib.rs` — `nativeStart` / `nativeStop` / `nativeGetStatus`. `nativeStart`
  loads `proxy_config::Config` from the `configPath` argument (there is no
  env-var/CWD fallback on Android — an explicit path is required), resolves
  local SOCKS5 authentication from `cfg.auth` (see `docs/guide/auth.md`), builds
  `arti_wrapper::Settings`, and spawns a dedicated engine thread so the
  Android main/JNI-calling thread never blocks on Tor bootstrap.
* `engine.rs` — the engine thread body: bridge probing, Tor bootstrap,
  binding the same-port SOCKS5/HTTP CONNECT listener, and the bounded accept loop.
  Each connection calls `socks5_proto::accept` with an absolute 30-second deadline
  and the host verifier selected at startup; framing and replies remain SDK-owned.
* `callback.rs` — wraps the Java `BootstrapCallback` object (`GlobalRef` +
  `JavaVM`) so Tokio worker threads can attach to the JVM and dispatch
  `onProgress`/`onReady`/`onBlocked`/`onFailed`.

### `packages/bridge-fetcher`

Fetches Tor bridge lines from HTTPS collectors **over a Tor circuit**
(used by `bridges fetch` and the background auto-fetch). Modules:
`error`, `url_parse` (`https://` URL parsing), `http` (the
HTTPS-over-Tor GET client), `parse` (extracting `BridgeLine`s from a
body), `dedup`, `fetch` (parallel multi-source batch).

### `packages/bridge-probe`

Parallel TCP reachability check for a `Vec<BridgeLine>`. Arti's guard
manager tries bridges roughly in list order with long back-offs per
failed bridge — fine for stability, terrible for cold start when half
the configured bridges are dead. We `TcpStream::connect` every bridge
concurrently with a short timeout (5 s), then sort the responders by
latency and hand that pre-filtered list to arti.

Transport-agnostic at the TCP layer, with one special case: a
**webtunnel** bridge's `<addr>:<port>` is cosmetic — the real target
lives in the `url=` parameter (with an optional `addr=` override), so
`resolve_probe_target` computes the correct `(host, port)` pair before
the handshake. A bridge that completes TCP can still fail the PT
handshake later; we accept this as the cost of a fast first filter.

### `packages/dns-server`

The optional local DNS server (default OFF; the `dns_server.*` config
section): plain UDP/TCP DNS listeners answered via a pool of public
DoH providers, with every DoH exchange tunnelled through the live Tor
circuit. Modules: `server` (the UDP+TCP listeners), `doh_client`
(the HTTPS exchange over Tor), `providers` (the built-in pool),
`overrides` (per-mask hostname exceptions resolved outside the
tunnel), `cache` (TTL-aware disk cache in a `.dns-cache` file next to
the config). Requires the Tor egress — combined with an upstream SOCKS5
proxy it is a fail-fast startup error. Wired into the binary by
`apps/socks5-proxy/src/server/dns_wiring.rs`. See `docs/guide/dns-server.md`.

### `apps/socks5-proxy`

The user-facing binary. Source modules under `src/`:

* `main.rs` — startup glue. Three entry paths, in order:
  1. **Windows-service dispatch** (`#[cfg(windows)]`): when the Service
     Control Manager starts us with the marker argument, hand control
     to `service::windows_runtime::dispatch()` *before* building a
     runtime or parsing clap.
  2. **Busybox PT dispatch**: if `TOR_PT_MANAGED_TRANSPORT_VER` is set,
     skip the proxy startup entirely and run `lyrebird::run()` (same
     binary, two modes, no second executable). This runs before clap
     parsing because arti passes weird argv to PT subprocesses.
  3. **Normal startup**: parse clap, optionally `--daemon`-ise (Unix
     only), build the multi-thread Tokio runtime, dispatch a
     subcommand (`users` / `bridges` / `service` / `config` / `help`, and
     `onion` when built with `onion-service`) or run the foreground server.
* `commands/cli.rs` — clap derive. Global flags: `--config`, `--upstream` /
  `--upstream-user` / `--upstream-pass` / `--no-upstream`, `--daemon` /
  `--pid-file`. Subcommands: `users`, `bridges` (with `fetch`),
  `service`, `config` (including `migrate`), `help`, and (when built with
  `onion-service`) `onion`.
* `config.rs` — Ktav loader over the shared `proxy_config::Config`
  schema (see `packages/proxy-config` and the canonical reference in
  `README.md`). Writes a default `tor-socks5.ktav` on first run.
* `commands/config_cmd.rs` — the `config` subcommands, including legacy-layout
  migration.
* `server/server.rs` — the same-port SOCKS5/HTTP CONNECT listener runtime: egress
  selection (Tor vs. upstream), bounded accept loop (256 connections), host
  authentication and destination policy, SDK replies, and byte forwarding.
* `auth` integration — when at least one user exists in
  `tor-socks5.users.ktav`, the CLI requires RFC 1929 or HTTP Basic credentials;
  otherwise it permits anonymous access.
* `server/upstream.rs` — optional upstream SOCKS5 egress
  (`client → tor-socks5 → upstream → target`). When active, Tor is not
  started.
* `server/dns_wiring.rs` — startup glue for the optional local DNS server
  (`dns_server.*`): converts the config into the resolver pool plus
  the per-mask override engine and binds the UDP/TCP listeners.
  Requires the Tor egress; a DNS-listener runtime error is logged,
  not fatal — the SOCKS5 proxy path keeps running.
* `bridges/bridge_store_writer.rs` — dedup-upsert log of bridges that completed a
  TCP probe, stored as `<config_stem>.alive-bridges.log` next to the
  active config. Carries the health counters (`fails`, `seen`,
  `cfails`, …) described in `docs/guide/bridges.md`.
* `bridges/candidate_pool.rs` / `fetch/fetch_merge/fetch_merge.rs` — the candidate pool and the
  lazy drain-and-promote path backing `bridges fetch` and auto-fetch.
* `fetch/bridges_cmd.rs` — the `tor-socks5 bridges fetch` subcommand.
* `tor/arti_observability.rs` — a passive `tracing_subscriber::Layer` on
  arti's `tor_guardmgr` events that feeds per-guard usability
  observations into the bridge health store (circuit-layer pruning;
  see `docs/guide/bridges.md`).
* `tor/tor_setup.rs` — parse configured bridges, probe them, persist the
  live ones, and assemble `arti_wrapper::Settings` (including pointing
  the PT manager at our own binary via `current_exe()`). The PT binary
  defaults to our own executable (busybox dispatch) but the `TOR_PT_BINARY`
  env var overrides it, for embedding hosts (Android JNI) where
  `current_exe()` is the app process.
* `fetch/seed.rs` — bundled seed bridges (`*.seeds`), the fallback when no
  configured bridge is reachable at startup and `use_seeds`
  is on.
* `commands/service.rs` — install/start/stop/status/uninstall across systemd,
  OpenRC, launchd, Windows SCM, BSD `rc.d` (via `service-manager`).
* `commands/daemon.rs` — `--daemon` mode (Unix only): double-fork via the
  `daemonize` crate, stdio to `/dev/null`, optional PID file.
* `server/shutdown.rs` — Windows Job Object (`KILL_ON_JOB_CLOSE`) so the PT
  child dies with us, plus cross-platform Ctrl+C / SIGTERM handling.
* `commands/users_cli.rs` — the `tor-socks5 users` subcommand (add / set-password
  / list / disable / allow-onion).
* `server/startup.rs` — server startup orchestration.
* `bridges/bridge_maintenance.rs` — bridge maintenance and verification.

### `vendor/` — locally-patched forks

Seven upstream crates (the Arti 0.47.0 / arti 2.7.0 line, plus
`saturating-time` 0.5.0) are vendored as full source copies and wired in
via `[patch.crates-io]` in the workspace `Cargo.toml`, so the build is
self-contained and does **not** depend on these fixes being accepted
upstream. The full patch table, per-crate rationale and the next-sync
procedure live in `vendor/README.md`. In short:

* **`saturating-time` (0.5.0)** — the root-cause fix:
  lazy `saturating_add`/`saturating_sub` limits instead of the eager
  non-terminating min/max search on Windows `SystemTime`, which left every
  bridge "unsuitable to purpose" so no circuit could be built.
* **`arti-client`, `tor-chanmgr`, `tor-circmgr`, `tor-dirclient`,
  `tor-dirmgr`, `tor-guardmgr` (all 0.47.0)** — the full seven-fork set,
  carrying our local stability/observability patches (idle body timeouts,
  descriptor-fetch and channel-build budgets, poison recovery, channel
  termination, guard readiness signals, exit-stream retry, opt-in
  bandwidth floor, and more — see `vendor/README.md`).

The obfs4 + webtunnel PT client is **not** vendored. It comes from the
`ptrs-gesher-lyrebird` 0.7 workspace dependency declared in the root
`Cargo.toml`.

## Pluggable-transport dispatch (busybox)

The PT runs in-process — there is no second executable to ship. Tor's
PT spec is process-based (`arti`'s `tor-ptmgr` spawns the PT as a child
and talks to it over stdio + a local SOCKS port), but the child can be
the *same* binary. The first statement of proxy `main()` is:

```rust
if std::env::var_os("TOR_PT_MANAGED_TRANSPORT_VER").is_some() {
    // build a Tokio runtime and:
    return rt.block_on(lyrebird::run());
}
```

`arti-wrapper` points arti at `current_exe()` as the PT binary
(`Settings.pt_binary`), so the child is always our own executable. The
bundled `lyrebird` library (from `ptrs-gesher`) provides **both** the
`obfs4` and `webtunnel` client transports behind one entrypoint.

## Configuration

Startup configuration is read from a [Ktav](https://github.com/ktav-lang/rust)
file. Resolution order (matches `README.md` and `Config::load_with_override`):

1. `--config <path>` CLI flag, then
2. `$TOR_SOCKS5_CONFIG` env var, then
3. `tor-socks5.ktav` in the current working directory
   (`tor-socks5.example.ktav` is the committed template; the default
   file is auto-created on first run if missing).

Auxiliary files live next to the resolved config: `tor-socks5.bridges.ktav`
(the bridge pool: `lines`, `sources`, health thresholds — the only config file
the program rewrites at run time, via `Config::write_bridges`),
`tor-socks5.users.ktav` (accounts) and `tor-socks5.alive-bridges.log`
(probed-alive cache), plus `tor-socks5.candidates.log` and the pinned
`arti-data/` state directory. A main config in the old layout (a `bridges`
section, or `pattern` instead of `patterns` in `dns_server.overrides`) is
rejected at load by `packages/proxy-config/src/layout/legacy.rs`;
`tor-socks5 config migrate` (`layout/migrate.rs`) converts it.

Schema (defaults):

```ktav
listen: [
    127.0.0.1:1080
]

log.default: info
log.targets.socks5_proxy: debug
log.targets.arti_wrapper: debug
log.targets.bridge_line: debug
log.targets.tor_: warn
log.targets.arti_: warn

dns_server.enabled: false
dns_server.listen: [
    127.0.0.1:15353
]
dns_server.overrides: []
```

No `pt_binary` field: the proxy uses its own `current_exe()` for the
PT child. See `README.md` for the canonical complete configuration reference
(every section and field with its default, for both the main config and the
bridges file) and `docs/guide/bridges.md` for the bridge-health knobs. See
`docs/guide/auth.md` for `auth.enabled` / `auth.users_file` — the
Android-facing knobs for RFC 1929 local authentication. The legacy
scalar form `listen: addr` is still parsed for compatibility (a
one-element list); an empty list parses but fails at startup.

## Request flow

```
client app                        socks5-proxy (proxy mode)               arti-client                    socks5-proxy (PT mode, child)         bridge (obfs4 / webtunnel)
    |                                       |                                  |                                        |                              |
    | SOCKS5 or HTTP CONNECT (+ auth)       |                                  |                                        |                              |
    |-------------------------------------->|                                  |                                        |                              |
    |                                       | TorClient::connect((host, port)) |                                        |                              |
    |                                       |--------------------------------->|                                        |                              |
    |                                       |                                  | spawn current_exe() with TOR_PT_* env  |                              |
    |                                       |                                  |--------------------------------------->| busybox dispatch →           |
    |                                       |                                  |                                        | lyrebird::run()              |
    |                                       |                                  | PT-protocol stdin/stdout               |                              |
    |                                       |                                  |<-------------------------------------->|                              |
    |                                       |                                  | local SOCKS5 conn with args            | PT handshake (obfs4/webtunnel)|
    |                                       |                                  |--------------------------------------->|----------------------------->|
    |                                       |                                  |                                        |<-----------------------------|
    |                                       |                                  | Tor circuit through bridge → middle → exit                            |
    |                                       |                                  |======================================================================>|
    | SDK success reply + bidi bytes                                                                                                                  |
    |<======================================|<==========================================================================|<=============================|
```

## Runtime / IO model

Hosts apply destination policy and establish real Tor/upstream egress before
sending SDK `Reply::Established`. After the success reply, forward
`IncomingRequest::take_pipeline()` exactly once to egress, before unread client
bytes, then relay bidirectionally. Never send success for an unconnected target.

Tor egress failures use SDK `Reply::GeneralFailure` (SOCKS REP 1 / HTTP 502).
`Reply::UpstreamUnavailable` maps to SOCKS REP 4 / HTTP 502; `Reply::Overloaded`
is admission overload (SOCKS REP 1 / HTTP 503), not an egress-failure substitute.

* `tokio` multi-thread runtime, pinned to 16 worker threads. arti's
  circuit manager can churn hard over flaky bridges; a generous pool
  keeps workers available so bridge-descriptor fetches and their
  timeouts actually make progress.
* `rustls` (`ring` crypto provider), installed explicitly at startup,
  for any TLS arti negotiates.
* SQLite for arti's directory cache is statically linked
  (`static-sqlite` feature) — no system `libsqlite3` needed.
* Windows Job Object with `KILL_ON_JOB_CLOSE` ensures the PT child
  process dies with the parent on any termination — clean exit,
  Ctrl+C, panic, or `taskkill /F`.
* `tokio::signal::ctrl_c` (and `ctrl_break` on Windows) for the
  clean-exit path: drops the `TorTunnel`, which lets arti tear down
  the PT subprocess gracefully and release its state-directory lock.

## What is not implemented

* **BIND and UDP ASSOCIATE** SOCKS5 commands — refused with
  `CommandNotSupported` (only `CONNECT` is handled).
* **utls TLS fingerprint emulation** for webtunnel (`utls=` bridge-line
  param) — accepted by the parser but ignored by the Rust PT client,
  which uses `tokio-rustls`'s default ClientHello. See
  `docs/guide/webtunnel.md`.
