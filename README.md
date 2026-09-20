# tor-socks5

[![CI](https://github.com/PHPCraftdream/tor-socks5/actions/workflows/ci.yml/badge.svg)](https://github.com/PHPCraftdream/tor-socks5/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/PHPCraftdream/tor-socks5/blob/main/LICENSE-MIT)
[![MSRV](https://img.shields.io/badge/MSRV-1.89%2B-blue.svg)](https://www.rust-lang.org)
![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows-informational.svg)
[![Release](https://img.shields.io/github/v/release/PHPCraftdream/tor-socks5?sort=semver&display_name=tag)](https://github.com/PHPCraftdream/tor-socks5/releases)

A local **SOCKS5 proxy that tunnels TCP through Tor** — and **fetches and probes its own
bridges** so it keeps working on censored networks without manual bridge wrangling.

By default it bootstraps an embedded Tor client ([arti](https://gitlab.torproject.org/tpo/core/arti))
over pluggable-transport bridges (**obfs4** / **webtunnel**) and forwards every SOCKS5 `CONNECT`
through the Tor network. It can also authenticate SOCKS5 clients, egress through an upstream
SOCKS5 proxy instead of Tor, and install itself as an OS service.

## Features

- **SOCKS5 (RFC 1928) `CONNECT`** listener, tunnelled through Tor.
- **Self-managing bridges:**
  - configured bridges are **probed** for reachability at startup — dead ones are skipped,
    live ones are sorted fastest-first and cached to `tor-socks5.alive-bridges.log`;
  - `tor-socks5 bridges fetch` **pulls fresh bridges** from public collectors *over Tor* and
    merges the working ones into the config;
  - **active health observation** — a tracing layer on top of arti catches per-guard usability
    events and prunes bridges that pass TCP but fail at the circuit layer (descriptor or
    fingerprint mismatch). See [`docs/bridges.md`](docs/bridges.md).
- **obfs4 + webtunnel** pluggable transports, run in-process (the binary re-execs itself as the
  PT — no second executable to ship).
- **User authentication** (RFC 1929 username/password), Argon2id-hashed, with an HMAC success
  cache and **trust-on-first-use** account provisioning.
- **Upstream SOCKS5 egress** — chain `client → tor-socks5 → upstream → target` instead of using
  Tor, with optional upstream auth.
- **Local DNS server (optional)** — answers clients' plain DNS queries through public DoH
  providers with every exchange tunnelled through Tor; per-host `dns_server.overrides` masks can
  opt selected names out to the OS resolver or a plain DNS server.
  See [`docs/dns-server.md`](docs/dns-server.md).
- **Install as a service** — systemd, OpenRC, launchd, Windows SCM, BSD `rc.d`.
- **Non-blocking logging** to stderr / stdout / file, configurable level and per-target filters.

## Build

Requires a recent stable Rust toolchain (edition 2021).

```bash
cargo build --release
# binary: target/release/socks5-proxy   (invoked as `tor-socks5`)
```

## Quick start

```bash
# 1. Copy the example config and fill in your bridges:
cp tor-socks5.example.ktav tor-socks5.ktav   # Windows: copy tor-socks5.example.ktav tor-socks5.ktav

# 2. Edit tor-socks5.ktav and add at least one working bridge under bridges.lines,
#    then start the proxy. The proxy listens on 127.0.0.1:1080 by default.
#    (tor-socks5.ktav is .gitignore'd — your local edits stay out of version control.)
tor-socks5

# 3. Send traffic through it:
curl --socks5-hostname 127.0.0.1:1080 https://check.torproject.org/
```

> A working bridge is required to bootstrap. Once Tor is up, `tor-socks5 bridges fetch` can
> discover more bridges for you.

## Configuration

Config is a [Ktav](https://github.com/ktav-lang/rust) file. Resolution order:

1. `--config <path>` flag, then
2. `$TOR_SOCKS5_CONFIG`, then
3. `tor-socks5.ktav` in the current directory (copy from `tor-socks5.example.ktav`).

The block below is the **canonical complete reference**: every configuration section and every
field, shown at its built-in default (mirroring `packages/proxy-config/src/lib.rs`). The committed
starter template `tor-socks5.example.ktav` — a bare default `tor-socks5.ktav` is also auto-created
on first run — is a shorter, ready-to-edit subset of the same defaults; any key you omit keeps the
default shown here.

```ktav
## Canonical complete configuration reference: every section and field
## at its built-in default (mirrors packages/proxy-config/src/lib.rs).
## Any key you omit keeps the default shown here.

## Addresses to listen on — one SOCKS5 listener per address.
## A single scalar (`listen: 127.0.0.1:1080`) is also accepted.
listen: [
    127.0.0.1:1080
]

## Logging: default level, per-target overrides, sink, ANSI color.
log.default: info
log.targets.socks5_proxy: debug
log.targets.arti_wrapper: debug
log.targets.bridge_line: debug
log.targets.tor_: warn
log.targets.arti_: warn
## stderr (default) | stdout | file
log.output: stderr
## Path used when output: file (empty falls back to stderr)
log.file:
## Colorize on a real terminal; forced off for file/pipe output
log.ansi: true

## Bridge lines in torrc format (obfs4 / webtunnel).
bridges.lines: [
    obfs4 198.51.100.7:9001 FINGERPRINT cert=... iat-mode=0
]

## Where `tor-socks5 bridges fetch` pulls fresh bridge lists from. A
## source is at minimum { url: ... }; label, headers (full Name: Value
## lines) and cookies (name=value) are optional, for collectors that
## need an API token or session cookie. allow_credentials_cross_origin
## (default false) opts in to sending those headers/cookies to redirect
## targets on a different origin. Omit the key for the built-in pool.
bridges.sources: [
    {
        label: private-collector
        url: https://api.example.org/bridges
        headers: [
            Authorization: Bearer SECRET
        ]
        cookies: [
            session=abc123
        ]
        allow_credentials_cross_origin: false
    }
]

## Fall back to built-in seed bridges when no configured line is reachable
bridges.use_seeds: true
## Background-fetch from sources after bootstrap when fewer than
## bridges.min_alive bridges are usable
bridges.auto_fetch: true
## auto_fetch threshold: fetch when fewer than this many are usable
bridges.min_alive: 8
## Reject a bridge-list response larger than this many MiB
bridges.max_body_mib: 64
## TCP-probe failures before a bridge is pruned from the config
bridges.max_fails: 24
## Rate-limit window for that counter, in minutes
bridges.fail_window_mins: 60
## Cadence of the background re-probe/fetch task, in minutes (0 = off)
bridges.recheck_interval_mins: 60
## Circuit-layer failures before a TCP-alive bridge is pruned
bridges.max_circuit_fails: 5
## Rate-limit window for that counter, in minutes
bridges.circuit_observation_window_mins: 30
## Override iat-mode on every obfs4 line: 0 keeps published values,
## 1 on, 2 paranoid (costs latency and throughput)
bridges.iat_mode: 0
## Preferred transport: any | obfs4 | webtunnel — a preference; the
## rest of the pool stays available as fallback
bridges.transport: any

## Stale-channel watchdog: rebuilds the Tor client when connects keep
## failing against channels left half-open by a silent network change.
watchdog.enabled: true
## Seconds between watchdog checks
watchdog.check_interval_secs: 45
## Seconds without a successful connect before a rebuild
watchdog.stale_after_secs: 180
## Minimum seconds between two rebuilds
watchdog.rebuild_cooldown_secs: 300
## Soft failover: consecutive circuit failures before the watchdog
## steers arti's guard manager away from a degraded bridge
watchdog.failover_min_circuit_fails: 3
## A replacement must be this many circuit-failures healthier
watchdog.failover_min_margin: 2
## Minimum seconds between failover signals for the same bridge
watchdog.failover_signal_cooldown_secs: 600

## Background warm pool of bridge channels (opt-in; prep only — it does
## not choose which bridge carries traffic).
warm_pool.enabled: false
warm_pool.pool_size: 3
warm_pool.refresh_interval_secs: 60

## Periodic connection-health summary line (pure observation).
conn_health.enabled: true
conn_health.interval_secs: 60

## Optional: egress through an upstream SOCKS5 proxy instead of Tor.
## When enabled, Tor is not started and dns_server must stay off.
upstream.enabled: false
upstream.address: 127.0.0.1:9050
upstream.username:
upstream.password:

## Local SOCKS5 (RFC 1929) authentication. The CLI needs neither field
## set — it auto-detects tor-socks5.users.ktav next to this config.
## Both exist mainly for the Android JNI FFI crate. See docs/auth.md.
auth.enabled: true
auth.users_file:

## Destination policy: refuse .onion targets at the listener.
security.block_onion: true

## Bridge hostname resolution (used while probing bridges, before Tor
## is up). DoH races a built-in pool of public providers with pinned
## IP bootstrap addresses; system DNS is opt-in because carrier DNS
## may be blocked. Not to be confused with dns_server.* below.
dns.doh_enabled: true
dns.system_fallback: false

## Optional local DNS server (default OFF): clients send plain UDP/TCP
## DNS queries; each is answered via public DoH providers with every
## exchange tunnelled through Tor. Requires the Tor egress (a startup
## error when upstream.* is enabled). The TTL cache lands in a
## .dns-cache file next to this config. Details: tor-socks5 help
## dns-server.
dns_server.enabled: false
## Bind addresses; one UDP+TCP listener pair per address. Deliberately
## not 53 (privileged). A single scalar is also accepted, as with listen.
dns_server.listen: [
    127.0.0.1:15353
]
## Drop the built-in provider pool; keep only the custom entries
dns_server.disable_builtin_providers: false
## Operator-added DoH providers, merged after the built-ins. `ip` is
## the address the DoH TCP connection opens to THROUGH Tor; hostname
## is only TLS SNI + the HTTP Host header.
dns_server.custom_doh_providers: [
    {
        ip: 9.9.9.9
        hostname: dns.quad9.net
        path: /dns-query
    }
]
## Per-mask exceptions: hosts matching a glob pattern skip the
## DoH-over-Tor pool and resolve via the OS resolver (resolver: system)
## or one plain DNS server (resolver: dns + server ip:port). First
## match wins. A matching host LEAVES the Tor tunnel — see the warning
## in docs/dns-server.md.
dns_server.overrides: [
    {
        pattern: *.lan
        resolver: system
        server:
    }
    {
        pattern: ns.home.arpa
        resolver: dns
        server: 192.168.1.1:53
    }
]
```

> **Ktav comments are `##` at the start of a line** (a single `#` is content, and there are no
> trailing/inline comments — a value runs verbatim to end of line).

Auxiliary files live next to the main config: `tor-socks5.users.ktav` (accounts) and
`tor-socks5.alive-bridges.log` (probed-alive cache).

These manuals are also embedded in the binary — run `tor-socks5 help` to
list them, `tor-socks5 help <topic>` for one, or `tor-socks5 help --all`
to print them all. See [`docs/`](docs/) for the source:

- [bridges](docs/bridges.md) — transports, health, candidate pool, sources, `bridges fetch`
- [webtunnel](docs/webtunnel.md) — the webtunnel transport
- [authentication](docs/auth.md) — users, trust-on-first-use, `.onion` gating
- [upstream SOCKS5](docs/upstream.md) — chaining through another proxy
- [local DNS server](docs/dns-server.md) — DNS-over-Tor resolver for client queries
- [service](docs/service.md) — install/start/stop/status on each OS
- [logging](docs/logging.md) — sinks, levels, non-blocking writer
- [architecture](docs/architecture.md) — workspace layout and data flow

## Authentication (optional)

```bash
tor-socks5 users add alice          # prompts for a password (Argon2id-hashed)
tor-socks5 users add --init bob     # no password now; bob's first login sets it (TOFU)
tor-socks5 users set-password alice
tor-socks5 users list
tor-socks5 users disable alice
```

When at least one user exists, the listener requires RFC 1929 username/password. See
[docs/auth.md](docs/auth.md).

## Upstream SOCKS5 egress (optional)

Enable in config (`upstream.enabled: true`) or via flags (flags win):

```bash
tor-socks5 --upstream 127.0.0.1:9050 --upstream-user u --upstream-pass p
tor-socks5 --no-upstream            # force the Tor egress even if enabled in config
```

When active, Tor is **not** started. See [docs/upstream.md](docs/upstream.md).

## Run as a service

```bash
tor-socks5 service install          # pins an absolute --config and enables start-on-boot
tor-socks5 service start
tor-socks5 service status
tor-socks5 service stop
tor-socks5 service uninstall
tor-socks5 service install --user   # per-user service where supported
```

See [docs/service.md](docs/service.md).

## Development

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

A git pre-push hook running the same checks lives in [`.githooks/`](.githooks/). Enable it once:

```bash
git config core.hooksPath .githooks
```

### Layout

```
apps/socks5-proxy/        the binary (cli, server, bridges_cmd, service, socks5, upstream, …)
packages/arti-wrapper/    thin wrapper over arti-client (TorTunnel)
packages/auth/            user accounts, Argon2id, the live authenticator
packages/bridge-fetcher/  HTTPS-over-Tor bridge fetching (error/http/parse/dedup/fetch)
packages/bridge-probe/    parallel TCP reachability probing + latency sort
```

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
