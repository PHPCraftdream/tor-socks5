# tor-socks5-proto

Minimal async SOCKS5 server-side protocol implementation: RFC 1928 CONNECT command only, with either no authentication or RFC 1929 USERNAME/PASSWORD — chosen by whether the caller passes a credential verifier.

It frames the handshake and stops there: the crate never dials the destination, so the host application routes the parsed CONNECT request wherever it wants — through Tor, a plain TCP dial, or a test double. Built for anyone embedding a SOCKS5 front-end (the tor-socks5 CLI daemon and its Android engine both sit on it), it stays a small leaf: `tokio` for async I/O is the entire dependency list.

## Usage

The crate publishes as `tor-socks5-proto`, while the library target keeps the in-tree name `socks5_proto`.

```rust
use socks5_proto::{handshake, reply, Reply};

let (mut sock, peer) = listener.accept().await?;

// `auth: None` is the NO_AUTH path. To require RFC 1929 instead,
// pass `Some(Arc::new(verifier))` for a `PasswordVerifier` impl.
let request = handshake(&mut sock, None).await?;
println!("CONNECT {}:{}", request.host, request.port);

// Dial `request.host:request.port` and proxy bytes both ways,
// then acknowledge the request:
reply(&mut sock, Reply::Success).await?;
```

`request.is_onion()` flags `*.onion` destinations so hosts can route them differently; `Reply` carries the RFC 1928 reply codes.

## Example

`cargo run --example minimal_server -p tor-socks5-proto` runs a client and server in one process: NO_AUTH negotiation, a CONNECT to `example.com:443`, and a success reply.
