# Architecture

A local SOCKS5 → Tor gateway built on `arti-client`, with pure-Rust
obfs4 pluggable-transport support. The user-facing artifact is a
single `.exe`: same binary acts as the SOCKS5 proxy when invoked
normally and as the PT process when invoked by arti's `tor-ptmgr`
(see `docs/bridges.md` for the busybox dispatch).

## Workspace layout

```
tor-socks5/
├── Cargo.toml                  # workspace root
├── tor-socks5.ktav             # startup config (Ktav format)
├── tor-socks5.alive-bridges.log # auto-managed log of reachable bridges
├── docs/
├── packages/                   # in-house libraries
│   ├── arti-wrapper/           # bootstrap & connect facade over arti-client
│   ├── bridge-line/            # parser for torrc Bridge directives
│   └── bridge-probe/           # parallel TCP reachability probe for bridges
├── apps/
│   └── socks5-proxy/           # the binary (SOCKS5 proxy + busybox PT dispatch)
└── vendor/
    └── ptrs/                   # https://github.com/jmwample/ptrs (patched)
        └── crates/
            ├── lyrebird/       # PT client (lib + thin bin) — pure Rust obfs4
            ├── obfs4/          # obfs4 protocol implementation
            └── ptrs/           # PT helpers shared by lyrebird/obfs4
```

The two unused vendor crates (`o5`, `o7`) live on disk under
`vendor/ptrs/crates/` but are deliberately not listed as workspace
members — cargo never compiles them.

## Crates and their responsibilities

### `packages/bridge-line`

Pure parser/formatter for the torrc Bridge line grammar
(`["Bridge"] [TRANSPORT] HOST:PORT [FINGERPRINT] (KEY=VALUE)*`).
Round-trips via `Display`. Independent of `arti-client`; only depends
on `std` + `thiserror`. Unit-tested.

### `packages/bridge-probe`

Parallel TCP reachability check for a `Vec<BridgeLine>`. Arti's
guard manager tries bridges roughly in list order with 30 s+
back-offs per failed bridge — fine for stability, terrible for cold
start when half of the configured bridges are dead. We
`TcpStream::connect` every bridge concurrently with a short timeout
(5 s), then sort the responders by latency and hand that
pre-filtered list to arti.

This is a transport-agnostic check: a bridge that completes a TCP
handshake can still fail the obfs4 handshake later. We accept this
as the cost of a fast first filter.

### `packages/arti-wrapper`

A thin facade over `arti-client`. Two responsibilities:

* Build a `TorClientConfig` from our `Settings` (bridges + optional
  PT binary path).
* `TorTunnel::connect(host, port)` returning an
  `arti_client::DataStream` for use in the SOCKS5 hand-off.

Workspace-pinned features: `bridge-client`, `pt-client`,
`onion-service-client`, `static-sqlite`, `rustls`, `tokio`. The
caller is expected to pass `current_exe()` as `pt_binary` so arti
spawns *us* for the PT child (busybox dispatch).

### `apps/socks5-proxy`

The user-facing binary. Modules:

* `config.rs` — Ktav loader, schema (listen / log / bridges).
* `socks5.rs` — RFC 1928 server, CONNECT only, no auth.
* `bridge_store.rs` — dedup-upsert log of bridges that completed a
  TCP probe at least once. Stored as
  `<config_stem>.alive-bridges.log` next to the active config.
* `shutdown.rs` — Windows Job Object (so children die with us) plus
  cross-platform Ctrl+C / SIGTERM handling.
* `main.rs` — startup glue. First statement of `main()` is:
  ```rust
  if std::env::var_os("TOR_PT_MANAGED_TRANSPORT_VER").is_some() {
      return lyrebird::run().await;     // busybox dispatch
  }
  ```
  Then in proxy mode:
  1. Install `rustls::crypto::ring::default_provider`.
  2. Bind the Job Object that ensures child PT processes die with us.
  3. Load config, init tracing.
  4. Parse bridge strings, probe them in parallel, keep the
     responders, persist to the alive-bridges log.
  5. If any surviving bridge needs a PT, set `Settings.pt_binary =
     Some(current_exe()?)` so arti respawns us as the PT child.
  6. `TorTunnel::bootstrap_with(settings)`.
  7. Listen on `cfg.listen`, spawn a task per accepted SOCKS5
     connection; loop until Ctrl+C.

### `vendor/ptrs/crates/lyrebird`

The pure-Rust obfs4 pluggable-transport client (patched from
`jmwample/ptrs` upstream — see `docs/bridges.md` for the patch
inventory). Lib + thin bin layout:

* `src/lib.rs` exports `pub async fn run() -> anyhow::Result<()>` —
  this is what `socks5-proxy` dispatches into.
* `src/main.rs` is a 4-line `#[tokio::main]` wrapper so the crate
  still produces a standalone `lyrebird.exe` (handy for debugging).

The library implements the PT-managed-transport protocol on
stdin/stdout, exposes a local SOCKS5 listener that accepts
`USERNAME/PASSWORD` auth carrying the PT args (`cert=…`,
`iat-mode=…`), and tunnels through to the bridge using the
`vendor/ptrs/crates/obfs4` client.

## Configuration

Startup configuration is read from a Ktav file
(`https://github.com/ktav-lang/rust`). Resolution order:

1. `TOR_SOCKS5_CONFIG` env var (full path).
2. `./tor-socks5.ktav` in the working directory.
3. Built-in defaults.

`RUST_LOG`, if set, overrides the log filter derived from
`log.default` + `log.targets.*`.

Schema (defaults):

```ktav
listen: 127.0.0.1:1080

log.default: info
log.targets.socks5_proxy: debug
log.targets.arti_wrapper: debug
log.targets.bridge_line: debug
log.targets.tor_: warn
log.targets.arti_: warn

## bridges.lines: array of torrc-format Bridge lines
bridges.lines: []
```

No `pt_binary` field: the proxy uses its own `current_exe()` for
the PT child.

## Request flow

```
client app                        socks5-proxy (proxy mode)               arti-client                    socks5-proxy (PT mode, child)         obfs4 bridge
    |                                       |                                  |                                        |                              |
    | SOCKS5 negotiate + CONNECT host:port  |                                  |                                        |                              |
    |-------------------------------------->|                                  |                                        |                              |
    |                                       | TorClient::connect((host, port)) |                                        |                              |
    |                                       |--------------------------------->|                                        |                              |
    |                                       |                                  | spawn current_exe() with TOR_PT_* env  |                              |
    |                                       |                                  |--------------------------------------->| busybox dispatch →           |
    |                                       |                                  |                                        | lyrebird::run()              |
    |                                       |                                  | PT-protocol stdin/stdout               |                              |
    |                                       |                                  |<-------------------------------------->|                              |
    |                                       |                                  | local SOCKS5 conn with args            | obfs4 handshake              |
    |                                       |                                  |--------------------------------------->|----------------------------->|
    |                                       |                                  |                                        |<-----------------------------|
    |                                       |                                  | Tor circuit through bridge → middle → exit                            |
    |                                       |                                  |======================================================================>|
    | SOCKS5 success reply + bidi bytes                                                                                                                  |
    |<======================================|<==========================================================================|<=============================|
```

## Runtime / IO model

* `tokio` multi-thread runtime.
* `rustls` (`ring` crypto provider) for any TLS arti negotiates.
* SQLite for arti's directory cache is statically linked
  (`static-sqlite` feature) — no system `libsqlite3` needed.
* Windows Job Object with `KILL_ON_JOB_CLOSE` ensures the PT child
  process dies with the parent on any termination — clean exit,
  Ctrl+C, panic, or `taskkill /F`.
* `tokio::signal::ctrl_c` (and `ctrl_break` on Windows) for the
  clean-exit path: drops the `TorTunnel`, which lets arti tear down
  the PT subprocess gracefully and release its state-directory lock.

## What is not in here yet

* Cross-platform PT support. The vendored ptrs builds on Windows and
  Unix; the busybox dispatch is portable; we just haven't been
  exercising the Unix target. The shutdown / Job Object module has a
  TODO for `prctl(PR_SET_PDEATHSIG)` on Linux.
* IPv6 listen addresses (parser supports IPv6 destinations in CONNECT
  but we have never tested binding on `[::1]`).
* Username/password SOCKS5 auth and BIND / UDP ASSOCIATE.
