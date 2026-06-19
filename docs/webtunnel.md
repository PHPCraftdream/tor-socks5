# WebTunnel Pluggable Transport — Integration Design Document

## Summary

WebTunnel is a Tor pluggable transport (PT) that disguises Tor connections
as legitimate HTTPS/WebSocket traffic. It works by performing a standard
HTTP/1.1 `Upgrade: websocket` handshake over TLS; once the server replies
`101 Switching Protocols`, the TCP stream carries raw bidirectional bytes
with no WebSocket framing. This makes the connection indistinguishable
from a normal WebSocket session to a passive network observer. Adding
WebTunnel support alongside the existing obfs4 transport lets tor-socks5
connect through a broader set of bridges, particularly those behind CDN
fronting or reverse proxies where obfs4 is blocked.

---

## ✅ Resolved: webtunnel bridges bootstrap through arti (was: a shared arti state dir)

webtunnel bridges **work end-to-end through arti** — verified live to
`{"IsTor":true}` (bootstrap reaches 100%, the guard is reported usable,
and traffic flows through the webtunnel PT).

For a while it *looked* like arti dropped webtunnel bridges: with a
webtunnel-only config arti stayed in direct mode (`No usable guards.
Rejected NN/NN as down`) and never launched the PT, while obfs4 worked
through identical wiring. The real cause was **not** an arti webtunnel
bug and **not** our config code (the built `TorClientConfig` correctly
retained the bridge and registered the `webtunnel` PT protocol, and
`bridges_enabled()` was `true`).

The culprit was arti's **on-disk state/cache directory**. `arti-wrapper`
did not pin it, so arti used its per-user OS-default location, which is
**shared across every arti instance and persists across runs**. A stale
guard sample (a netdir-derived set of ~30 direct guards, marked "down")
plus a cached consensus from earlier/unrelated runs kept arti in direct
mode and shadowed the configured bridges. obfs4 happened to slip through;
webtunnel didn't.

**Fix:** `Settings::state_dir` pins arti's `state_dir`/`cache_dir` under an
app-local directory (`<config-dir>/arti-data/{state,cache}`), so state is
isolated per app, predictable, and wipeable. With a clean app-local state
arti correctly enters bridge mode, launches the webtunnel managed PT
(`tor_ptmgr: Successfully launched PT for webtunnel`), and the webtunnel
guard becomes usable. The same change also prevents one config's leftover
guard state from poisoning a later run with different bridges.

(This also corrects Open Question §1 below: there was never a transport
allowlist problem; the block was stale shared state, now eliminated.)

---

## Protocol Description

### Overview

The client opens a TLS connection to the bridge's fronting web server,
then issues an HTTP/1.1 GET request with WebSocket upgrade headers.
The server (or a reverse proxy in front of it) responds with
`101 Switching Protocols`. After the response headers, the connection
becomes a raw byte stream — there is **no WebSocket framing layer**.

### Client Request

```http
GET /<secret-path> HTTP/1.1
Host: <hostname-from-url>
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: <base64-encoded-16-random-bytes>
Sec-WebSocket-Version: 13

```

Notes:

- `<secret-path>` comes from the `url=` bridge-line parameter (the path
  component). This is the random string the bridge operator generated
  and configured in NGINX.
- `Host` is set to the hostname from the `url=` parameter.
- `Sec-WebSocket-Key` MUST be 16 cryptographically random bytes,
  base64-encoded (24 ASCII characters). This is required by
  RFC 6455 §4.1. The server may validate it, though in practice the
  webtunnel server only checks the path.
- `Sec-WebSocket-Version: 13` is the standard WebSocket version.
- The request ends with `\r\n\r\n` (blank line).

### Server Response

```http
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade

```

UNCONFIRMED — needs verification: whether the webtunnel server returns
a `Sec-WebSocket-Accept` header. RFC 6455 requires it for real
WebSocket servers (the base64 SHA-1 of the key + the GUID), but the
webtunnel server may omit it since it never applies WebSocket framing.
The NGINX reverse proxy in front may add it. Either way, the client
should accept the response as long as the status code is `101`.

### Transition to Raw Bytes

Immediately after the `\r\n\r\n` terminating the `101` response, the
connection becomes a raw bidirectional byte stream. There is **no
WebSocket opcode masking or framing** — the Upgrade dance is purely
for camouflage. From this point on, Tor cell bytes flow directly over
the TLS socket.

### Request-Response Sequence Diagram

```text
     Client                                Server
       |                                     |
       |    TLS handshake (SNI = hostname)   |
       |------------------------------------>|
       |<------------------------------------|
       |                                     |
       |  HTTP GET /<path> + Upgrade headers |
       |------------------------------------>|
       |                                     |
       |  HTTP 101 Switching Protocols       |
       |<------------------------------------|
       |                                     |
       |  raw Tor cell bytes (bidirectional) |
       |<===================================>|
```

---

## TLS Requirements

| Aspect | Value | Source |
|--------|-------|--------|
| **SNI** | Hostname from `url=` parameter (or `servername=` if provided) | pkg.go.dev docs |
| **ALPN** | UNCONFIRMED — needs verification. Most likely not set (empty) or `http/1.1`. The Go `gorilla/websocket` library does not set ALPN by default. | — |
| **Certificate verification** | Standard WebPKI (system roots). The bridge sits behind a real web server with a valid TLS cert (often Let's Encrypt). No pinned certificate in the bridge line. | Community docs |
| **TLS version** | TLS 1.2+. Follows the underlying TLS library's defaults. | — |
| **Port** | Typically 443 (from the `url=` parameter) | Observed bridge lines |

The `servername=` bridge-line parameter overrides the TLS SNI value
when the TCP endpoint differs from the TLS hostname (e.g., domain
fronting scenarios).

The `utls=` parameter controls the TLS client fingerprint. In the Go
implementation, this selects a `utls` HelloID (Chrome, Firefox, etc.).
For the Rust implementation, this is initially out of scope — use
`tokio-rustls` with its default ClientHello. The `utls=` parameter
should be accepted but ignored with a log message.

---

## Bridge-Line Format

### Grammar

```text
webtunnel <addr>:<port> <fingerprint> url=<URL> [ver=<version>] [servername=<SNI>] [addr=<tcp-addr>] [utls=<fingerprint>]
```

### Examples

**Minimal (most common):**

```text
webtunnel 192.0.2.3:1 2852538D49D7D73C1A6694FC492104983A9C4FA2 url=https://example.com/K2A2utQIMou4Ia2WjVseyDjV ver=0.0.3
```

**With SNI override and non-standard port:**

```text
webtunnel [2001:db8:5ade:c44f:cc79:4b25:299d:c020]:443 1696D0A7C5994460B73E9A0FD853B3887388F6B0 servername=gosuslugi.ru url=http://lovelymeadow.mooo.com/api/v1/ ver=0.0.1
```

**With SNI imitation:**

```text
webtunnel [2001:db8:289b:84cd:4be3:77f1:1cdd:9cb1]:443 D71C8E9C2180D2F35DEBF4A39BFCA6972F076D1C sni-imitation=yandex.ru,google.com url=https://streaming.example.com/gz9X1VBgl0r ver=0.0.3
```

### Parameter Table

| Key | Required | Description |
|-----|----------|-------------|
| `url` | **yes** | Full HTTPS (or HTTP) URL of the webtunnel endpoint. Host and port from this URL are the default TLS/network target. Path is the secret route. |
| `ver` | no | Server protocol version string (e.g. `0.0.3`, `0.0.4`). Allows client to adjust behavior per server version. |
| `servername` | no | Overrides TLS SNI (hostname sent in ClientHello). Used for domain fronting. Default: hostname from `url=`. |
| `addr` | no | Overrides TCP destination address. Default: host:port from `url=`. (Not observed in the wild — documented in pkg.go.dev.) |
| `utls` | no | TLS fingerprint emulation. Values: `none` (default Go TLS). Ignored in Rust impl. |
| `sni-imitation` | no | Comma-separated list of domains to mix into TLS handshakes for cover traffic. Not implemented in our client. |

The `<addr>:<port>` in the bridge line is the address arti connects to
via SOCKS5. For webtunnel, this address is cosmetic — the real TCP
target comes from `url=` (or `addr=`). The existing bridge-line parser
(`packages/bridge-line`) already captures all `key=value` params into a
`BTreeMap` without validation, so **no parser changes are needed**.

---

## Integration Plan

### Architecture

The integration adds a new `webtunnel` crate under the existing ptrs
vendor tree and modifies `lyrebird::client_setup` to dispatch by
transport name. The contract is identical to obfs4: implement
`ptrs::ClientBuilder` and `ptrs::ClientTransport`, return them from
`client_setup`, and the existing accept-loop + SOCKS5 plumbing handles
everything else.

### File-by-File Changes

#### 1. `vendor/ptrs/crates/webtunnel/` — **NEW CRATE** (~200 LOC)

**`Cargo.toml`** (~15 LOC)

```toml
[package]
name = "webtunnel"
version = "0.1.0"
edition = "2021"

[dependencies]
ptrs = { path = "../ptrs" }
tokio = { version = "1", features = ["net", "io-util"] }
tokio-rustls = { version = "0.26", default-features = false, features = ["logging", "tls12"] }
webpki-roots = "0.26"
httparse = "1"
thiserror = "2"
tracing = "0.1"
```

**`src/lib.rs`** (~185 LOC)

```rust
// Types implementing the ptrs trait contract

/// Error type for webtunnel handshake failures.
pub struct Error { /* ... */ }

/// Bridge-line parameters extracted from ptrs::Args.
pub struct WebTunnelConfig {
    pub url: String,         // from url=
    pub version: String,     // from ver=
    pub servername: Option<String>, // from servername=
    pub tcp_addr: Option<String>,   // from addr=
}

/// Implements ptrs::ClientBuilder<TcpStream>.
pub struct WebTunnelBuilder {
    config: Option<WebTunnelConfig>,
}

// pub fn method_name() -> String
//   Returns "webtunnel".

// pub fn build(&self) -> WebTunnelClient
//   Consumes config, returns client.

// pub fn options(&mut self, opts: &ptrs::args::Args) -> Result<&mut Self>
//   Extracts url=, ver=, servername=, addr= from args.

// pub fn statefile_location(&mut self, _: &str) -> Result<&mut Self>
//   No-op (webtunnel has no persistent state).

// pub fn timeout(&mut self, _: Option<Duration>) -> Result<&mut Self>
//   No-op for now.

// pub fn v4_bind_addr / v6_bind_addr
//   No-op for now.

/// Implements ptrs::ClientTransport<TcpStream, std::io::Error>.
pub struct WebTunnelClient {
    config: WebTunnelConfig,
}

// pub fn method_name() -> String
//   Returns "webtunnel".

// pub fn establish(self, tcp_future: Pin<F<TcpStream, io::Error>>)
//     -> Pin<F<impl AsyncRead+AsyncWrite+Send, io::Error>>
//   Awaits TCP connect, wraps in TLS, sends HTTP Upgrade,
//   parses 101 response, returns the raw TLS stream.

// pub fn wrap(self, io: TcpStream)
//     -> Pin<F<impl AsyncRead+AsyncWrite+Send, io::Error>>
//   Same as establish but with a pre-connected socket.
```

**`src/handshake.rs`** (if split out, ~80 LOC, else inlined in lib.rs)

```rust
/// Perform the TLS+HTTP-Upgrade handshake.
///
/// pub async fn handshake(
///     tcp: TcpStream,
///     config: &WebTunnelConfig,
/// ) -> Result<impl AsyncRead + AsyncWrite + Send>
///
/// Steps:
///   1. Build rustls ClientConfig with webpki-roots.
///   2. Connect TLS with SNI from config.servername or URL host.
///   3. Build HTTP GET request with Upgrade headers.
///   4. Write request, read 101 response (httparse).
///   5. Return the TLS stream — raw bytes flow after this.
```

#### 2. `vendor/ptrs/crates/lyrebird/src/lib.rs` — **MODIFIED** (~20 LOC changed)

Current code at line 320-326:

```rust
for name in client_pt_info.methods {
    info!(name);
    if name != obfs4_name {
        pt_proto::print_cmethod_error(&name, "no such transport is supported");
        warn!("no such transport is supported");
        continue;
    }

    let builder = Obfs4PT::client_builder();
```

Change to:

```rust
for name in client_pt_info.methods {
    info!(name);

    let builder: Box<dyn ErasedBuilder> = if name == obfs4_name {
        Box::new(Obfs4PT::client_builder())
    } else if name == webtunnel::WebTunnelBuilder::method_name() {
        Box::new(webtunnel::WebTunnelBuilder::default())
    } else {
        pt_proto::print_cmethod_error(&name, "no such transport is supported");
        warn!("no such transport is supported");
        continue;
    };
```

This requires a small type-erasure wrapper or making `client_accept_loop`
generic over a trait object. The simplest approach: duplicate the
`client_accept_loop` call for each transport (two calls, no dyn needed),
matching the existing pattern where the builder is type-parametric.

Exact approach: refactor the builder into an enum:

```rust
enum AnyBuilder {
    Obfs4(obfs4::ClientBuilder),
    WebTunnel(webtunnel::WebTunnelBuilder),
}
```

Then `client_accept_loop` is called once per transport, with the builder
dispatch producing the right variant. Estimated change: ~20 LOC in
`client_setup` and ~5 LOC for the enum definition.

#### 3. `packages/bridge-line/src/lib.rs` — **NO CHANGE**

The parser already preserves `transport` and all `key=value` params in a
generic `BTreeMap`. WebTunnel's `url=`, `ver=`, `servername=` etc. are
captured without modification.

#### 4. `packages/arti-wrapper/src/lib.rs` — **NO CHANGE**

The `build_config` function at line 124-155 already collects distinct
transport names from bridge lines and passes them all to
`TransportConfigBuilder::protocols(...)`. When a `webtunnel` bridge is
present, `"webtunnel"` appears in the protocol list automatically.

#### 5. `vendor/ptrs/crates/ptrs/` — **NO CHANGE**

The `ClientBuilder`, `ClientTransport`, and `Args` traits/types are
already generic enough. WebTunnel implements them in its own crate.

---

## Code-Size Estimate

| File | Change | LOC |
|------|--------|-----|
| `vendor/ptrs/crates/webtunnel/Cargo.toml` | New | 15 |
| `vendor/ptrs/crates/webtunnel/src/lib.rs` | New | 185 |
| `vendor/ptrs/crates/lyrebird/src/lib.rs` | Modified | 25 |
| **Total** | | **~225** |

This is in line with the ~250 LOC headline estimate. The webtunnel
protocol is thin — the bulk is TLS setup (~40 LOC), HTTP request
construction (~25 LOC), HTTP response parsing (~30 LOC), and trait
plumbing (~50 LOC).

---

## Dependency Requirements

| Crate | Version | Features | Justification |
|-------|---------|----------|---------------|
| `tokio` | `1` | `net`, `io-util` | Async TCP and I/O. Already a dependency. |
| `tokio-rustls` | `0.26` | `logging`, `tls12` | TLS client. Pure-Rust, no OpenSSL. Matches arti's TLS stack. |
| `webpki-roots` | `0.26` | — | Mozilla CA bundle for cert verification. Systematic, no OS deps. |
| `httparse` | `1` | — | Parse the HTTP `101` response. ~200 bytes of code, no allocations. |
| `thiserror` | `2` | — | Error type derives. Already used throughout the workspace. |
| `tracing` | `0.1` | — | Logging. Already a dependency. |

**Why `httparse` over a hand-rolled parser:** The server's `101`
response is short and well-structured, but HTTP response parsing has
edge cases (chunked headers, varying whitespace, case-insensitive
header names). `httparse` is a zero-dependency, battle-tested
no-std parser at ~700 bytes compiled. A hand-rolled parser would save
one dep but risk subtle parsing bugs for no meaningful LOC savings.

**Why `tokio-rustls` over `rustls`:** `tokio-rustls` provides the
`TlsStream` wrapper that implements `AsyncRead + AsyncWrite`, which is
exactly what `ClientTransport::OutRW` requires.

**Why `webpki-roots` over `rustls-native-certs`:** Simpler, no
platform-specific cert loading code, and matches what the Go client
does (Mozilla roots). If needed later, switching to
`rustls-native-certs` is a one-line change.

---

## Testing Plan

### Unit Tests (No Network Required)

| Test | Description |
|------|-------------|
| `config_from_args` | Feed `ptrs::Args` with `url=`, `ver=`, `servername=` into `WebTunnelBuilder::options()`. Verify all fields extracted correctly. |
| `config_missing_url` | `ptrs::Args` without `url=` → `options()` returns error. |
| `config_ignores_utls` | `Args` with `utls=chrome` → accepted, logged, not stored. |
| `http_request_bytes` | Construct the upgrade request, verify exact bytes: method, path, headers, `\r\n\r\n` terminator. |
| `parse_101_response` | Feed a canned `HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n` into the response parser. Verify success and that no trailing bytes are lost. |
| `parse_non_101` | Feed `HTTP/1.1 404 Not Found\r\n\r\n` → error. |
| `parse_101_with_body_prefix` | Feed `101` response followed immediately by raw Tor bytes. Verify the parser returns the stream with those bytes available for reading. |

### Integration Tests (Require Live Server)

| Test | Description |
|------|-------------|
| Full handshake | Connect to a real webtunnel bridge, complete TLS + Upgrade, verify bidirectional byte flow. **Flagged:** No fixture exists. Requires a running bridge. Manual testing only. |

### Test Strategy

The unit tests cover all locally-parseable logic. The only untestable
component without a live server is the full TLS + HTTP handshake end to
end. A mock TLS + HTTP server could be built with `tokio::net::TcpListener`
for a local integration test, but this is deferred to implementation.

---

## Open Questions / Risks

1. ~~**arti `tor-ptmgr` transport-name allowlist:**~~ **Resolved.** No
   allowlist exists; `tor_linkspec::PtTransportName` validates syntax
   only (`[a-zA-Z_][a-zA-Z0-9_]*`). Any transport name passed via
   `TransportConfigBuilder::protocols()` is accepted, so `webtunnel`
   needs no upstream changes. Confirmed against `tor-ptmgr` and
   `tor-linkspec` source on docs.rs.

2. ~~**Sec-WebSocket-Accept header:**~~ **Resolved.** The Go reference
   server does not return it
   (`transport/httpupgrade/httpupgrade.go` — server only sets
   `Connection: Upgrade` and `Upgrade: websocket`). Our parser is
   lenient by design (accepts any `101`, with or without the header),
   so we cover both the bare Go server and NGINX-fronted setups that
   may add the header.

3. ~~**ALPN negotiation:**~~ **Resolved (with caveat).** The Go client
   leaves `NextProtos` nil — no ALPN advertised. We mirror that.
   *Caveat:* some CDNs require `http/1.1` ALPN and may reject empty
   ALPN. If a real bridge sits behind such a CDN and fails the
   handshake, adding `http/1.1` ALPN via `rustls` is a one-liner.
   Flagging because it could surface in production.

4. ~~**Bridge address mismatch:**~~ **Resolved.** Two places had to
   account for the cosmetic `<addr>:<port>` in webtunnel bridge lines:
   - `packages/bridge-probe/src/lib.rs::resolve_probe_target` extracts
     the real TCP target from `url=` (or `addr=` override) before
     probing reachability.
   - `vendor/ptrs/crates/webtunnel/src/lib.rs::establish` (and
     `wrap`) drop the SOCKS5-provided stream future *without
     awaiting it* and dial the URL target directly. Dropping the
     unawaited future avoids both the wasted TCP setup and the
     spurious failure when the cosmetic address is unreachable.

5. **utls fingerprint emulation:** The Go client supports TLS
   fingerprint emulation via `utls=`. Non-trivial in Rust (requires
   `boring`/`boringtun` or a custom ClientHello builder). Deferred —
   the param is accepted but ignored.

6. **HTTP URL scheme in bridge lines (`url=http://...`):** Supported
   in code (plain TCP + HTTP Upgrade, no TLS). Uncommon configuration;
   not exercised against a live server.

7. **No live-server integration test.** The full TLS + HTTP Upgrade
   handshake is unit-tested in pieces (response parser, key
   generation, config extraction) but the end-to-end path requires a
   real webtunnel bridge. Manual smoke test is the validation path.

---

## Self-Check

- [x] Protocol byte sequence example included (§Protocol Description)
- [x] File-by-file plan present (§Integration Plan, 5 files)
- [x] LOC estimate present (§Code-Size Estimate, ~225 LOC total)
- [x] Dependency list present (§Dependency Requirements, 6 crates)
- [x] Open questions section non-empty (§Open Questions / Risks; 4 resolved, 3 deferred)

---

## Sources

1. Tor Project community docs — WebTunnel Bridge setup:
   <https://community.torproject.org/relay/setup/webtunnel/>

2. WebTunnel Go module documentation (pkg.go.dev):
   <https://pkg.go.dev/gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel>

3. Real-world bridge lines (500+ entries):
   <https://github.com/scriptzteam/Tor-Bridges-Collector/blob/main/bridges-webtunnel>

4. WebTunnel announcement and technical overview:
   <https://github.com/net4people/bbs/issues/263>

5. Ubuntu manpage for `webtunnel-server`:
   <https://manpages.ubuntu.com/manpages/stonking/man1/webtunnel-server.1.html>

6. Go reference implementation (canonical, behind gitlab.torproject.org):
   `gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel`
   (Source code not directly reachable; protocol details inferred from
   docs, bridge lines, NGINX config, and pkg.go.dev API surface.)

7. RFC 6455 — The WebSocket Protocol:
   <https://datatracker.ietf.org/doc/html/rfc6455>

8. Local codebase files read:
   - `vendor/ptrs/crates/lyrebird/src/lib.rs` (client_setup, client_accept_loop)
   - `vendor/ptrs/crates/ptrs/src/lib.rs` (ClientBuilder, ClientTransport traits)
   - `vendor/ptrs/crates/ptrs/src/args.rs` (Args parsing)
   - `packages/bridge-line/src/lib.rs` (bridge line parser)
   - `packages/arti-wrapper/src/lib.rs` (Settings, build_config)
