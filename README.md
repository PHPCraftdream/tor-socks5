# tor-socks5

[![CI](https://github.com/PHPCraftdream/tor-socks5/actions/workflows/ci.yml/badge.svg)](https://github.com/PHPCraftdream/tor-socks5/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/PHPCraftdream/tor-socks5/blob/main/LICENSE-MIT)
[![MSRV](https://img.shields.io/badge/MSRV-1.92%2B-blue.svg)](https://www.rust-lang.org)
![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows-informational.svg)
[![Release](https://img.shields.io/github/v/release/PHPCraftdream/tor-socks5?sort=semver&display_name=tag)](https://github.com/PHPCraftdream/tor-socks5/releases)

A local **SOCKS5 and HTTP CONNECT proxy that tunnels TCP through Tor** — and **fetches and probes its own
bridges** so it keeps working on censored networks without manual bridge wrangling.

By default it bootstraps an embedded Tor client ([arti](https://gitlab.torproject.org/tpo/core/arti))
over pluggable-transport bridges (**obfs4** / **webtunnel**) and forwards every inbound `CONNECT`
through the Tor network. SOCKS5 and HTTP CONNECT share the same listener port in both
the CLI and Android JNI; ordinary HTTP forwarding is not supported. It can authenticate clients,
egress through an upstream SOCKS5 proxy instead of Tor, and install itself as an OS service.

## Features

- **Same-port SOCKS5 (RFC 1928) and HTTP CONNECT** listeners, tunnelled through Tor.
- **Self-managing bridges:**
  - configured bridges are **probed** for reachability at startup — dead ones are skipped,
    live ones are sorted fastest-first and cached to `tor-socks5.alive-bridges.log`;
  - `tor-socks5 bridges fetch` **pulls fresh bridges** from public collectors *over Tor* and
    merges the working ones into the config;
  - **active health observation** — a tracing layer on top of arti catches per-guard usability
    events and prunes bridges that pass TCP but fail at the circuit layer (descriptor or
    fingerprint mismatch). See [`docs/guide/bridges.md`](docs/guide/bridges.md).
- **obfs4 + webtunnel** pluggable transports, run in-process (the binary re-execs itself as the
  PT — no second executable to ship).
- **User authentication** (RFC 1929 or HTTP Proxy-Authorization Basic), Argon2id-hashed, with an HMAC success
  cache and **trust-on-first-use** account provisioning.
- **Upstream SOCKS5 egress** — chain `client → tor-socks5 → upstream → target` instead of using
  Tor, with optional upstream auth.
- **Local DNS server (optional)** — preserves typed DNS packets and negative answers
  through public DoH providers tunnelled through Tor; `dns_server.overrides` masks can
  opt selected names out to the OS resolver or plain DNS. Localhost/loopback policy
  runs without upstream work, as does own-IP PTR (including wildcard coverage
  derived from actual UDP/TCP socket options) unless explicitly overridden.
  Local/cache answers bypass the shared
  64-miss admission cap; TCP has a separate 64-connection cap. System resolver
  callers wait for bounded capacity within the query budget; overload and the
  absolute 30-second miss deadline produce SERVFAIL. Payload-free query statistics
  persist popular names and observed types/classes; startup/two-hour background
  refresh uses existing routes with foreground headroom and never counts itself.
  Statistics are sensitive local browsing metadata; protect the cache directory.
  See [`docs/guide/dns-server.md`](docs/guide/dns-server.md).
- **Install as a service** — systemd, OpenRC, launchd, Windows SCM, BSD `rc.d`.
- **Non-blocking logging** to stderr / stdout / file, configurable level and per-target filters.

## Build

Requires a recent stable Rust toolchain (edition 2021).

The workspace needs `resocks5-net` 0.3 (the inbound server API) and takes it from
the local SDK at `../resocks5/crates/resocks5-net`. Keep a sibling `resocks5`
checkout at tag `v0.3.0` or newer beside `tor-socks5`. To build without the
checkout, remove the `path` from the `resocks5-net` dependency in the root
`Cargo.toml` so that Cargo takes the crates.io release.

CI and release builds provision the sibling SDK with
`.github/actions/setup-local-sdk/action.yml`, pinned to the `v0.3.0` tag rather
than a moving branch.

```bash
cargo build --release
# binary: target/release/socks5-proxy   (invoked as `tor-socks5`)
```

### Code structure rules (checked in CI)

- A Rust file has at most **1000 lines** (`scripts/check-line-limit.sh`).
- A directory has at most **7 entries**, files and sub-directories together
  (`scripts/check-dir-entries.sh`; counts what git tracks).

`vendor/` (upstream Arti forks) is exempt. Directories that were already over
the limit when the rule was introduced are listed in the script's `BASELINE`
with their current size: they may not grow, new ones may not appear, and an
entry is lowered or deleted as the directory is split.

## Quick start

```bash
# 1. Copy the example config (the bridge pool lives in its own file, created on first run):
cp tor-socks5.example.ktav tor-socks5.ktav   # Windows: copy tor-socks5.example.ktav tor-socks5.ktav

# 2. Start the proxy once: it creates tor-socks5.bridges.ktav next to the config.
#    Add at least one working bridge under `lines` there, then start it again.
#    The proxy listens on 127.0.0.1:1080 by default.
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

The configuration is **two files** next to each other:

- `tor-socks5.ktav` — the main config, edited by hand; the program never rewrites it while running;
- `tor-socks5.bridges.ktav` — the bridge pool (`lines`, `sources`, health thresholds), which the
  program rewrites as the pool changes (new bridges merged in, dead ones pruned). It is created
  with defaults on first run; its path is always `<main config stem>.bridges.ktav`.

The block below is the **canonical complete reference of the main config**: every section and
field, shown at its built-in default (mirroring `packages/proxy-config/src/lib.rs`); the bridges
file has its own reference further down. The committed starter template
`tor-socks5.example.ktav` — a bare default `tor-socks5.ktav` is also auto-created on first run — is
a shorter, ready-to-edit subset of the same defaults; any key you omit keeps the default shown here.

```ktav
## Canonical complete configuration reference: every section and field
## at its built-in default (mirrors packages/proxy-config/src/lib.rs).
## Any key you omit keeps the default shown here.

## Onion-service circuit length: 2 or 3 hops (default 3). Applies only to the
## client's onion circuits (rendezvous, introduction, HsDir); 2 drops the middle
## relay and reduces anonymity. Ordinary exit circuits are always 3 hops: exit
## relays refuse streams from a 2-hop circuit that starts at a bridge.
tor.circuit_hops: 3

## Addresses to listen on — one SOCKS5 + HTTP CONNECT listener per address.
## Accepts a scalar or list; each value also accepts host1,host2:port.
## Example: listen: 127.0.0.1,[::1]:1080 (IPv6 must be bracketed).
## Expanded addresses are deduplicated, keeping the first occurrence;
## config writeback uses the expanded list.
## AddrInUse, PermissionDenied and AddrNotAvailable are skipped with
## WARN and a reason. At least one bound listener serves; all failing
## is an error. Other bind errors remain hard failures.
## An address skipped because it was unavailable at startup is retried
## every fixed 30 seconds; if it binds, it serves SOCKS5 and HTTP CONNECT.
## Occupied or permission-denied addresses are not retried periodically;
## ports are never seized or reused. Retry is server-scoped and stops at
## shutdown. Startup still fails if every address fails. Already-bound
## addresses are not monitored or rebound.
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

## Local proxy authentication (RFC 1929 / HTTP Basic). The CLI needs neither field
## set — it auto-detects tor-socks5.users.ktav next to this config.
## Both exist mainly for the Android JNI FFI crate. See docs/guide/auth.md.
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
## Bind addresses; one atomic UDP+TCP pair per successful address.
## Deliberately not 53 (privileged). Accepts a scalar or list, as with listen.
## Each value accepts host1,host2:port; IPv6 must be bracketed:
## dns_server.listen: 127.0.0.1,[::1]:15353
## Expand/deduplicate keeping the first occurrence; writeback uses a list.
## An unavailable address is retried every fixed 30 seconds; if it binds,
## serve an atomic UDP+TCP pair. Occupied or permission-denied addresses
## are not periodically retried. No port seizure or reuse tricks; retry is
## server-scoped and stops at shutdown. Startup still fails if every address
## fails. Already-bound addresses are not monitored or rebound.
## Local policy and recursion guards use only successfully bound endpoints.
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
## Per-mask exceptions: hosts matching any glob in `patterns` skip the
## DoH-over-Tor pool and resolve via the OS resolver (resolver: system)
## or one plain DNS server (resolver: dns + server ip:port). One entry
## takes a whole list of masks (a lone string is read as a one-element
## list). First match wins, in list order. A matching host LEAVES the
## Tor tunnel — see the warning in docs/guide/dns-server.md.
dns_server.overrides: [
    {
        patterns: [
            *.lan
            *.home.arpa
        ]
        resolver: system
        server:
    }
    {
        patterns: [
            ns.home.arpa
        ]
        resolver: dns
        server: 192.168.1.1:53
    }
]

## Onion services published by this proxy (default empty). Each entry
## launches one onion service at startup: `nickname` names it (only
## A-Z a-z 0-9 _ -, max 25 chars) and every `ports` entry maps an onion
## port to a local target as `onion_port=host:port` (an IPv6 target must
## be bracketed; because Ktav reads `[` as an inline compound, an IPv6
## target needs the block-list form with the `::` literal marker:
## ports: [
##     80=127.0.0.1:8080
##     :: 443=[::1]:8443
## ]). At least one port per entry; an
## onion port may not repeat within one entry and nicknames must be
## unique. `enabled` defaults to true. The service's v3 key lives in
## the keystore, which is locked against CLI mutations while the server
## runs. `circuit_hops` (2..=4, default 4) sets the length of the
## server-side onion circuits (HsDir uploads never go below 3); all
## enabled services must use the same value. Example (not part of the default):
## onion_services: [
##     {
##         nickname: web
##         enabled: true
##         ports: [ 80=127.0.0.1:8080, 443=127.0.0.1:8443 ]
##         circuit_hops: 4
##     }
## ]
onion_services: []
```

> **Ktav comments are `##` at the start of a line** (a single `#` is content, and there are no
> trailing/inline comments — a value runs verbatim to end of line).


### Onion services

The optional `onion_services` section publishes onion services through the running proxy. Each
entry launches one service at startup and forwards its onion ports to local `host:port`
targets — for example `ports: [ 80=127.0.0.1:8080 ]` publishes an onion address whose port 80
reaches a local web server. `nickname` must match `A-Za-z0-9_-` (max 25 chars); `enabled`
defaults to `true`, so a service can be paused by setting it to `false`. An IPv6 target must be
bracketed (`443=[::1]:8443`), and because Ktav reads an unquoted `[` as the start of an inline
compound, such a mapping needs the block-list form with the `::` literal marker:

```ktav
onion_services: [
    {
        nickname: web6
        ports: [
            80=127.0.0.1:8080
            :: 443=[::1]:8443
        ]
    }
]
``` The services' v3 keys
are kept in the keystore, which is locked against CLI mutations while the server runs.

Keys are managed from the CLI (stop the server first — it holds the keystore lock while
services run):

```bash
tor-socks5 onion new <NICK> [--vanity PREFIX] [--threads N] [--timeout DURATION]
tor-socks5 onion list
tor-socks5 onion show <NICK>
tor-socks5 onion export <NICK> --out <FILE>
tor-socks5 onion import <NICK> <FILE>
tor-socks5 onion remove <NICK> --yes
```

`--vanity` mines an address starting with the given base32 prefix (a-z, 2-7, up to 8 chars);
the full guide — quick start, vanity tables, security and diagnostics — is in
[docs/guide/ops/onion-service.md](docs/guide/ops/onion-service.md).

```ktav
onion_services: [
    {
        nickname: web
        enabled: true
        ports: [ 80=127.0.0.1:8080, 443=127.0.0.1:8443 ]
    }
]
```

Setting `circuit_hops` (2..=4, default `4`) shortens the server-side
onion circuits — a latency-for-anonymity trade intended for censorship
circumvention; all enabled services must use the same value. With `2`,
introduction and rendezvous circuits are `[bridge, target]`; descriptor
uploads keep three hops, because HsDirs reject posts from a bridge-adjacent
circuit.

```ktav
onion_services: [
    {
        nickname: web
        enabled: true
        ports: [ 80=127.0.0.1:8080, 443=127.0.0.1:8443 ]
        circuit_hops: 2
    }
]
```


### The bridges file

`tor-socks5.bridges.ktav` holds the bridge pool. It is the **canonical complete reference** of
that file (every key at its built-in default); the keys are top level — there is no `bridges.`
prefix and no wrapping section. The program rewrites the file whenever the pool changes (comments
are not kept), so hand edits are best made while the service is stopped. A missing file means
"built-in defaults"; it is created on the first run.

```ktav
## Bridge lines in torrc format (obfs4 / webtunnel).
lines: [
    obfs4 198.51.100.7:9001 FINGERPRINT cert=... iat-mode=0
]

## Where `tor-socks5 bridges fetch` pulls fresh bridge lists from. A
## source is at minimum { url: ... }; label, headers (full Name: Value
## lines) and cookies (name=value) are optional, for collectors that
## need an API token or session cookie. allow_credentials_cross_origin
## (default false) opts in to sending those headers/cookies to redirect
## targets on a different origin. Omit the key for the built-in pool.
sources: [
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
use_seeds: true
## Background-fetch from sources after bootstrap when fewer than
## min_alive bridges are usable
auto_fetch: true
## auto_fetch threshold: fetch when fewer than this many are usable
min_alive: 8
## Reject a bridge-list response larger than this many MiB
max_body_mib: 64
## TCP-probe failures before a bridge is pruned from the pool
max_fails: 24
## Rate-limit window for that counter, in minutes
fail_window_mins: 60
## Cadence of the background re-probe/fetch task, in minutes (0 = off)
recheck_interval_mins: 60
## Circuit-layer failures before a TCP-alive bridge is pruned
max_circuit_fails: 5
## Rate-limit window for that counter, in minutes
circuit_observation_window_mins: 30
## Override iat-mode on every obfs4 line: 0 keeps published values,
## 1 on, 2 paranoid (costs latency and throughput)
iat_mode: 0
## Preferred transport: any | obfs4 | webtunnel — a preference; the
## rest of the pool stays available as fallback
transport: any
```

### Upgrading from the old layout

Earlier versions kept the bridge pool as a `bridges` section inside `tor-socks5.ktav` and wrote
each DNS exception mask as `pattern: <mask>`. Such a config is **rejected at start** with an error
naming each difference. Convert it with the service stopped:

```bash
tor-socks5 config migrate --config /path/to/tor-socks5.ktav
```

The `bridges` section moves into `tor-socks5.bridges.ktav`, every `pattern: X` becomes
`patterns: [X]`, and the old file is kept as `tor-socks5.ktav.bak-N`. Nothing is written unless
the converted result is valid, and a config that is already current is left untouched.

Other auxiliary files live next to the main config: `tor-socks5.users.ktav` (accounts) and
`tor-socks5.alive-bridges.log` (probed-alive cache).

These manuals are also embedded in the binary — run `tor-socks5 help` to
list them, `tor-socks5 help <topic>` for one, or `tor-socks5 help --all`
to print them all. See [`docs/`](docs/) for the source:

- [bridges](docs/guide/bridges.md) — transports, health, candidate pool, sources, `bridges fetch`
- [webtunnel](docs/guide/webtunnel.md) — the webtunnel transport
- [authentication](docs/guide/auth.md) — users, trust-on-first-use, `.onion` gating
- [upstream SOCKS5](docs/guide/upstream.md) — chaining through another proxy
- [local DNS server](docs/guide/dns-server.md) — DNS-over-Tor resolver for client queries
- [service](docs/guide/service.md) — install/start/stop/status on each OS
- [onion services](docs/guide/ops/onion-service.md) — publish a local site through Tor
- [logging](docs/guide/ops/logging.md) — sinks, levels, non-blocking writer
- [architecture](docs/architecture.md) — workspace layout and data flow

## Authentication (optional)

```bash
tor-socks5 users add alice          # prompts for a password (Argon2id-hashed)
tor-socks5 users add --init bob     # no password now; bob's first login sets it (TOFU)
tor-socks5 users set-password alice
tor-socks5 users list
tor-socks5 users disable alice
```

When at least one user exists, the CLI listener requires RFC 1929 username/password
or HTTP Proxy-Authorization Basic, with no anonymous downgrade. The authenticated
username drives CLI account policy; JNI uses the global destination policy. See
[docs/guide/auth.md](docs/guide/auth.md).

Inbound framing and replies belong to `resocks5-net`; `socks5_proto` supplies the
shared host authentication adapter. Each handshake has one absolute 30-second
deadline and a process-wide limit of 256 queued/running blocking verifications,
matching the host connection cap. Verification slots remain held across cancellation
until the blocking work exits.
Hosts send success only after real egress is established, then forward SDK-buffered
pipeline bytes exactly once before unread client bytes.

Tor egress failures use SDK `Reply::GeneralFailure` (SOCKS REP 1 / HTTP 502).
`Reply::UpstreamUnavailable` maps to SOCKS REP 4 / HTTP 502; `Reply::Overloaded`
is admission overload (SOCKS REP 1 / HTTP 503), not an egress failure.

## Upstream SOCKS5 egress (optional)

Enable in config (`upstream.enabled: true`) or via flags (flags win):

```bash
tor-socks5 --upstream 127.0.0.1:9050 --upstream-user u --upstream-pass p
tor-socks5 --no-upstream            # force the Tor egress even if enabled in config
```

When active, Tor is **not** started. See [docs/guide/upstream.md](docs/guide/upstream.md).

## Run as a service

```bash
tor-socks5 service install          # pins an absolute --config and enables start-on-boot
tor-socks5 service start
tor-socks5 service status
tor-socks5 service stop
tor-socks5 service uninstall
tor-socks5 service install --user   # per-user service where supported
```

See [docs/guide/service.md](docs/guide/service.md).

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

### Testing

Tests are tiered: cheap structural checks always run, the pre-push hook and CI test
only the packages affected by a change (plus their reverse dependencies), and the full
workspace runs on `main`, tags and nightly. See [docs/project/testing.md](docs/project/testing.md).

### Layout

```
apps/socks5-proxy/        the binary (cli, server, bridges_cmd, service, upstream, …)
packages/socks5-proto/    shared host auth adapter over resocks5-net inbound framing
packages/arti-wrapper/    thin wrapper over arti-client (TorTunnel)
packages/auth/            user accounts, Argon2id, the live authenticator
packages/bridge-fetcher/  HTTPS-over-Tor bridge fetching (error/http/parse/dedup/fetch)
packages/bridge-probe/    parallel TCP reachability probing + latency sort
```

## Security

See [SECURITY.md](.github/SECURITY.md) for vulnerability reporting.

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
