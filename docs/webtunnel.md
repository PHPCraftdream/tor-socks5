# The webtunnel pluggable transport

WebTunnel is a Tor pluggable transport (PT) that disguises Tor
connections as ordinary HTTPS/WebSocket traffic. Where obfs4 is the
workhorse transport, webtunnel is the one to reach for when a bridge
sits behind a CDN or reverse proxy, or on networks where obfs4 is
actively blocked — its traffic looks like a normal TLS'd WebSocket
session to a passive observer.

tor-socks5 supports webtunnel alongside obfs4, and the two may be
mixed freely in the same `bridges.lines` list. See `docs/bridges.md`
for the bridge-management machinery (probing, health, candidate pool)
shared by both transports.

## What it looks like on the wire

The client opens a TLS connection to the bridge's fronting web server,
then issues an HTTP/1.1 GET with WebSocket upgrade headers. The server
(or a reverse proxy in front of it) replies `101 Switching Protocols`,
and from that point on the TCP stream carries **raw bidirectional Tor
cell bytes** — there is no WebSocket framing layer, the Upgrade dance
is purely for camouflage. Certificate verification is standard WebPKI;
the bridge sits behind a real web server (typically with a Let's
Encrypt certificate), and no cert is pinned in the bridge line.

## Single binary, in-process PT

The PT runs in-process — there is no second executable to ship. Tor's
PT spec is process-based (`arti`'s `tor-ptmgr` spawns the PT as a
child and talks to it over stdio + a local SOCKS port), but the child
can be the *same* binary. `main()` starts with:

```text
if env has TOR_PT_MANAGED_TRANSPORT_VER  ->  run the lyrebird PT loop
otherwise                                ->  run the SOCKS5 proxy
```

`arti` is pointed at `current_exe()` as the PT binary, so the child is
always our own executable. The bundled Rust `lyrebird` (from the
published `ptrs-gesher-lyrebird` crate) provides **both** the `obfs4`
and `webtunnel` client transports behind one entrypoint — no separate
webtunnel binary, no extra build step.

## Configuring a webtunnel bridge

Webtunnel bridges live in the main config under `bridges.lines`, one
standard torrc bridge line each, alongside any obfs4 bridges:

```ktav
bridges.lines: [
    obfs4 198.51.100.7:9001 FINGERPRINT cert=... iat-mode=0
    webtunnel 192.0.2.3:1 2852538D49D7D73C1A6694FC492104983A9C4FA2 url=https://example.com/K2A2utQIMou4Ia2WjVseyDjV ver=0.0.3
]
```

### Bridge-line shape

```text
webtunnel <addr>:<port> <fingerprint> url=<URL> [ver=<version>]
```

| Field | Required | Notes |
|-------|----------|-------|
| `<addr>:<port>` | yes (syntactically) | **Cosmetic.** The real TCP target comes from `url=` (or `addr=`). It must parse as a socket address but is not dialled. |
| `<fingerprint>` | yes | The bridge's RSA identity, 40 hex chars. |
| `url=` | **yes** | Full HTTPS (or HTTP) URL of the webtunnel endpoint. Host and port from this URL are the real TLS/network target; the path is the bridge operator's secret route. |
| `ver=` | no | Server protocol version string (e.g. `0.0.3`). |

Because the `<addr>:<port>` is cosmetic, both the startup reachability
probe (`packages/bridge-probe`) and the transport itself resolve the
real target from `url=`. Don't be surprised if a webtunnel line
appears unreachable on a raw TCP scan of its listed address — that's
expected.

A practical example mixing both transports, with a webtunnel bridge
fronted by a CDN:

```ktav
bridges.lines: [
    webtunnel [2001:db8::1]:443 1696D0A7C5994460B73E9A0FD853B3887388F6B0 url=https://fronted.example.com/secretpath ver=0.0.3
]
```

## Startup and bootstrap

At startup every configured bridge — obfs4 and webtunnel together — is
**probed for reachability** in parallel (for webtunnel, the probe
resolves and dials the `url=` host). Dead ones are skipped; the
reachable ones are ordered (stability first, ping second) and handed
to arti. arti launches the managed PT and builds a circuit through the
first usable guard. See `docs/bridges.md` for the full probe/order/
health lifecycle — it is identical for both transports.

> arti's own state/cache is pinned to an app-local directory
> (`<config-dir>/arti-data/{state,cache}`) via `arti-wrapper`'s
> `Settings::state_dir`. This matters for webtunnel in particular: a
> stale guard sample or cached consensus in arti's OS-default (shared,
> persistent) state dir can keep arti in direct mode and shadow the
> configured bridges. The app-local pin makes state predictable and
> wipeable — delete `arti-data/` to start clean.

## Limitations

* **`utls=` TLS fingerprint emulation is not implemented.** The
  `utls=` bridge-line parameter (which selects a TLS ClientHello
  fingerprint in the Go client) is accepted by the parser but ignored
  by the Rust PT client, which uses `tokio-rustls`'s default
  ClientHello. This is rarely the difference between working and not;
  if a specific CDN rejects the default fingerprint, that is the place
  to look.
* **`http://` URL scheme is supported in code** (plain TCP + HTTP
  Upgrade, no TLS) but is an uncommon configuration and not exercised
  against a live server.
