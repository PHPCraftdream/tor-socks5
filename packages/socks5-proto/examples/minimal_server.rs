//! A minimal SOCKS5 server: accept one loopback connection, run
//! [`socks5_proto::handshake`] with `auth: None` (the NO_AUTH path), and
//! reply [`Reply::Success`]. Demonstrates the whole crate end to end
//! without pulling in a real user database or a real upstream connection.
//!
//! Run with: `cargo run --example minimal_server -p tor-socks5-proto`

use anyhow::Result;
use socks5_proto::{handshake, reply, Reply};
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    println!("listening on {addr}");

    // A real client in another task: negotiate NO_AUTH, then ask to CONNECT
    // to example.com:443. `socks5-proto` only frames the request -- it
    // never dials the destination itself, so the server side below is free
    // to route the parsed `ConnectRequest` however the host application
    // wants (Tor, a plain TCP dial, a test double, ...).
    let client = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut sock = TcpStream::connect(addr).await.unwrap();

        // Method negotiation: VER=5, 1 method, NO_AUTH.
        sock.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method_reply = [0u8; 2];
        sock.read_exact(&mut method_reply).await.unwrap();
        println!("client: server selected method 0x{:02x}", method_reply[1]);

        // CONNECT request: VER | CMD=1 | RSV=0 | ATYP=DOMAIN | len | host | port.
        let host = b"example.com";
        let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        req.extend_from_slice(host);
        req.extend_from_slice(&443u16.to_be_bytes());
        sock.write_all(&req).await.unwrap();

        let mut conn_reply = [0u8; 10];
        sock.read_exact(&mut conn_reply).await.unwrap();
        println!("client: reply code 0x{:02x}", conn_reply[1]);
    });

    let (mut server_sock, peer) = listener.accept().await?;
    println!("server: accepted from {peer}");

    // `auth: None` is the NO_AUTH path -- pass `Some(verifier)` (a
    // `PasswordVerifier` impl) to require RFC 1929 USERNAME/PASSWORD
    // instead; see the trait's doc comment for the host-side wiring this
    // workspace uses (`apps/socks5-proxy`, `packages/android-ffi`).
    let request = handshake(&mut server_sock, None).await?;
    println!(
        "server: parsed CONNECT to {}:{} (onion: {})",
        request.host,
        request.port,
        request.is_onion()
    );

    // A real server would dial `request.host:request.port` here and proxy
    // bytes both ways; this example just acknowledges the request.
    reply(&mut server_sock, Reply::Success).await?;

    client.await?;
    Ok(())
}
