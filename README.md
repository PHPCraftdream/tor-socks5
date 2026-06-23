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

```ktav
listen: 127.0.0.1:1080

log.default: info
## log.output: stderr (default) | stdout | file
log.output: stderr
## log.file: path used when output: file
log.file:
log.ansi: true
log.targets.socks5_proxy: debug
log.targets.tor_: warn

bridges.lines: [
    obfs4 1.2.3.4:443 FINGERPRINT cert=... iat-mode=0
]

## Where to fetch fresh bridges from. A source is at minimum `{ url: ... }`;
## `label`, `headers` (full `Name: Value` lines) and `cookies` (`name=value`)
## are optional, for collectors that need an API token or session cookie.
bridges.sources: [
    { url: https://example.com/bridges-obfs4 }
    {
        label: private-collector
        url: https://api.example.org/bridges
        headers: [
            Authorization: Bearer SECRET
        ]
        cookies: [
            session=abc123
        ]
    }
]

## Optional: egress through an upstream SOCKS5 proxy instead of Tor.
upstream.enabled: false
upstream.address: 127.0.0.1:9050
upstream.username:
upstream.password:
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
