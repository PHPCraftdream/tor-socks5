# ptrs-gesher-webtunnel

<p>
  <a href="https://crates.io/crates/ptrs-gesher-webtunnel">
    <img src="https://img.shields.io/crates/v/ptrs-gesher-webtunnel.svg">
  </a>
  <a href="https://docs.rs/ptrs-gesher-webtunnel">
    <img src="https://docs.rs/ptrs-gesher-webtunnel/badge.svg">
  </a>
  <a href="https://github.com/PHPCraftdream/ptrs-gesher">
    <img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue" alt="License: MIT/Apache 2.0">
  </a>
</p>

TLS + HTTP/1.1 Upgrade pluggable transport for Tor, implementing the
WebTunnel protocol with a raw bidirectional byte stream after the 101
response.

## What this crate does

`ptrs-gesher-webtunnel` implements the client side of the WebTunnel
pluggable transport. The protocol performs a TLS handshake (via
`tokio-rustls`) followed by an HTTP/1.1 WebSocket Upgrade request. Once
the server responds with `101 Switching Protocols`, the connection
transitions to a raw byte stream — **no WebSocket framing** is applied
after the upgrade. The result is an `AsyncRead + AsyncWrite` tunnel that
can carry Tor cells.

The crate integrates with the `ptrs-gesher-core` trait framework
(`ClientBuilder`, `ClientTransport`). Configuration is provided via the
standard `Args` key-value bag — the only required parameter is `url=`. A
`WebTunnelConfig` struct extracts and validates all recognised parameters
(`url`, `ver`, `servername`, `addr`, `utls`) from the bridge line.

This transport is designed to make Tor traffic blend in with ordinary
HTTPS traffic to a web server, resisting deep-packet-inspection by
censoring middleboxes.

## Status

The current crate requires Rust 1.92 or newer. See the
[migration guide](https://github.com/PHPCraftdream/ptrs-gesher/blob/v0.6.0/docs/MIGRATING-0.6.md).
Not production ready; do not rely on this for security-critical
applications.

## Example

```rust ignore
use ptrs::args::Args;
use ptrs::ClientBuilder;
use webtunnel::WebTunnelBuilder;
use tokio::net::TcpStream;

// Build configuration from bridge-line key=value args.
let mut args = Args::new();
args.add("url", "https://example.com/secretPath");

// Configure the builder.
let mut builder = WebTunnelBuilder::default();
<WebTunnelBuilder as ClientBuilder<TcpStream>>::options(&mut builder, &args)?;

// Build the client transport.
let client = <WebTunnelBuilder as ClientBuilder<TcpStream>>::build(&builder);

let tunnel = client.connect_url().await?;
// Alternatively, ClientTransport::wrap/establish use a supplied carrier.
```

## License

Dual-licensed under either:

- Apache License, Version 2.0
- MIT license

at your option.
