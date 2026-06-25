# Architecture

A local SOCKS5 → Tor gateway built on `arti-client`, with pure-Rust
**obfs4 + webtunnel** pluggable-transport support. The user-facing
artifact is a single binary (the `socks5-proxy` crate): it acts as the
SOCKS5 proxy when invoked normally and as the PT process when re-invoked
by arti's `tor-ptmgr` (see `docs/bridges.md` for the busybox dispatch).

## Workspace layout

```
tor-socks5/
├── Cargo.toml                  # workspace root + [patch.crates-io] overrides
├── tor-socks5.ktav             # startup config (Ktav format), gitignored
├── tor-socks5.example.ktav     # committed template
├── docs/
├── packages/                   # in-house libraries
│   ├── arti-wrapper/           # bootstrap & connect facade over arti-client
│   ├── auth/                   # SOCKS5 user accounts + Argon2id authenticator
│   ├── bridge-fetcher/         # HTTPS-over-Tor bridge list fetching
│   └── bridge-probe/           # parallel TCP reachability probe + latency sort
├── apps/
│   └── socks5-proxy/           # the binary (SOCKS5 proxy + busybox PT dispatch)
└── vendor/                     # locally-patched forks of 3 upstream crates
    ├── saturating-time/        # 0.3.0 — see [patch.crates-io] for the why
    ├── tor-dirclient/          # 0.43.0
    └── tor-dirmgr/             # 0.43.0
```

The torrc `Bridge` line grammar is parsed by the external
`ptrs-gesher-bridge-line` crate (`bridge-line = { version = "0.5",
package = "ptrs-gesher-bridge-line" }` in `Cargo.toml`) — there is no
local `bridge-line` package. Likewise the obfs4 + webtunnel PT client
comes from the published `ptrs-gesher-lyrebird` crate (`lyrebird` 0.5);
it is **not** vendored.

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
configured bridges — see `docs/webtunnel.md` for the failure mode this
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
     subcommand (`users` / `bridges` / `service` / `help`) or run the
     foreground server.
* `cli.rs` — clap derive. Global flags: `--config`, `--upstream` /
  `--upstream-user` / `--upstream-pass` / `--no-upstream`, `--daemon` /
  `--pid-file`. Subcommands: `users`, `bridges` (with `fetch`),
  `service`, `help`.
* `config.rs` — Ktav loader, schema (`listen` / `log` / `bridges` /
  `upstream`). Writes a default `tor-socks5.ktav` on first run.
* `server.rs` — the SOCKS5 listener runtime: egress selection (Tor vs.
  upstream), accept loop, per-connection handler. Bounded to 256
  concurrent connections (each may run an Argon2id verify).
* `socks5.rs` — RFC 1928 server, CONNECT only. Supports either
  NO_AUTH (method `0x00`) or RFC 1929 USERNAME/PASSWORD (method
  `0x02`), depending on whether the caller passes an `AuthState`.
  BIND and UDP ASSOCIATE are refused with `CommandNotSupported`.
* `auth` integration — when at least one user exists in
  `tor-socks5.users.ktav`, the listener insists on USER/PASS;
  otherwise it falls back to anonymous NO_AUTH.
* `upstream.rs` — optional upstream SOCKS5 egress
  (`client → tor-socks5 → upstream → target`). When active, Tor is not
  started.
* `bridge_store.rs` — dedup-upsert log of bridges that completed a
  TCP probe, stored as `<config_stem>.alive-bridges.log` next to the
  active config. Carries the health counters (`fails`, `seen`,
  `cfails`, …) described in `docs/bridges.md`.
* `candidate_pool.rs` / `fetch_merge.rs` — the candidate pool and the
  lazy drain-and-promote path backing `bridges fetch` and auto-fetch.
* `bridges_cmd.rs` — the `tor-socks5 bridges fetch` subcommand.
* `arti_observability.rs` — a passive `tracing_subscriber::Layer` on
  arti's `tor_guardmgr` events that feeds per-guard usability
  observations into the bridge health store (circuit-layer pruning;
  see `docs/bridges.md`).
* `tor_setup.rs` — parse configured bridges, probe them, persist the
  live ones, and assemble `arti_wrapper::Settings` (including pointing
  the PT manager at our own binary via `current_exe()`).
* `seed.rs` — bundled seed bridges (`*.seeds`), the fallback when no
  configured bridge is reachable at startup and `bridges.use_seeds`
  is on.
* `service.rs` — install/start/stop/status/uninstall across systemd,
  OpenRC, launchd, Windows SCM, BSD `rc.d` (via `service-manager`).
* `daemon.rs` — `--daemon` mode (Unix only): double-fork via the
  `daemonize` crate, stdio to `/dev/null`, optional PID file.
* `shutdown.rs` — Windows Job Object (`KILL_ON_JOB_CLOSE`) so the PT
  child dies with us, plus cross-platform Ctrl+C / SIGTERM handling.
* `users_cli.rs` — the `tor-socks5 users` subcommand (add / set-password
  / list / disable / allow-onion).
* `help_cmd.rs` — the `tor-socks5 help` subcommand; prints the
  `docs/` manuals that are embedded in the binary at build time.

### `vendor/` — locally-patched forks

Three upstream crates are vendored as full source copies and wired in
via `[patch.crates-io]` in the workspace `Cargo.toml`, so the build is
self-contained and does **not** depend on these fixes being accepted
upstream. Same-version overrides of the exact crates.io releases we
depend on — bump alongside any arti upgrade.

* **`saturating-time` (0.3.0)** — the root-cause fix.
  `saturating_add`/`saturating_sub` eagerly forced a non-terminating
  min/max search on Windows `SystemTime` — the cause of an infinite
  loop in `tor_netdoc::RouterDesc::parse` (used only for bridge
  descriptors), which left every bridge "unsuitable to purpose" so no
  circuit could be built. Vendored with a lazy unwrap + a
  `find_limit` termination guard.
* **`tor-dirclient` (0.43.0)** — idle (not total) read timeout for
  slow obfs4 bridges, so a healthy-but-slow consensus download is not
  truncated.
* **`tor-dirmgr` (0.43.0)** — hard timeout on the bridge-descriptor
  fetch (it used to hang forever) plus patient, gentle
  retry/parallelism for the bridge pool.

The obfs4 + webtunnel PT client is **not** vendored. It comes from the
published `ptrs-gesher` crates on crates.io (`lyrebird` =
`ptrs-gesher-lyrebird` 0.5); our obfs4 fixes (handshake-residual,
decode-eof, TCP keepalive) are part of that published release.

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

Auxiliary files live next to the resolved config: `tor-socks5.users.ktav`
(accounts) and `tor-socks5.alive-bridges.log` (probed-alive cache), plus
`tor-socks5.candidates.log` and the pinned `arti-data/` state directory.

Schema (defaults):

```ktav
listen: 127.0.0.1:1080

log.default: info
log.targets.socks5_proxy: debug
log.targets.arti_wrapper: debug
log.targets.bridge_line: debug
log.targets.tor_: warn
log.targets.arti_: warn

bridges.lines: []
```

No `pt_binary` field: the proxy uses its own `current_exe()` for the
PT child. See `README.md` for the full schema (`upstream.*`,
`bridges.*`) and `docs/bridges.md` for the bridge-health knobs.

## Request flow

```
client app                        socks5-proxy (proxy mode)               arti-client                    socks5-proxy (PT mode, child)         bridge (obfs4 / webtunnel)
    |                                       |                                  |                                        |                              |
    | SOCKS5 negotiate (+ RFC 1929 if auth) |                                  |                                        |                              |
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
    | SOCKS5 success reply + bidi bytes                                                                                                                  |
    |<======================================|<==========================================================================|<=============================|
```

## Runtime / IO model

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
  `docs/webtunnel.md`.
