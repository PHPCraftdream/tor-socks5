//! Real loopback UDP/TCP fixtures sharing one selected endpoint.
use std::io;
use std::net::SocketAddr;
use tokio::net::{TcpListener, UdpSocket};

/// The production `bind_pair` on an ephemeral loopback port: a port collision
/// on either protocol (e.g. Windows ranges reserved for one protocol only,
/// `WSAEACCES`) is retried on a random dynamic port.
/// cancel-safe: yes — each attempt owns its sockets and drops them on failure
/// or cancellation; no detached work.
pub(super) async fn udp_tcp_pair() -> io::Result<(UdpSocket, TcpListener, SocketAddr)> {
    let (udp, tcp) = crate::server::bind_pair("127.0.0.1:0")
        .await
        .map_err(io::Error::other)?;
    let endpoint = udp.local_addr()?;
    Ok((udp, tcp, endpoint))
}
