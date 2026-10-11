//! Real loopback UDP/TCP fixtures sharing one selected endpoint.
use std::io;
use std::net::SocketAddr;
use tokio::net::{TcpListener, UdpSocket};

/// UDP selects first: a TCP ephemeral port may be excluded for UDP on Windows.
/// Only matching-port collisions are retried; UDP allocation and other errors
/// propagate. Windows WSAEACCES (10013) maps to PermissionDenied, not AddrInUse,
/// and can report an exclusive/reserved matching TCP port.
/// cancel-safe: yes — each attempt owns its sockets and drops them on failure
/// or cancellation; no detached work and at most sixteen allocations.
pub(super) async fn udp_tcp_pair() -> io::Result<(UdpSocket, TcpListener, SocketAddr)> {
    for attempt in 0..16 {
        let udp = UdpSocket::bind("127.0.0.1:0").await?;
        let endpoint = udp.local_addr()?;
        match TcpListener::bind(endpoint).await {
            Ok(tcp) => return Ok((udp, tcp, endpoint)),
            Err(error) => {
                let collision = error.kind() == io::ErrorKind::AddrInUse
                    || (cfg!(windows) && error.raw_os_error() == Some(10013));
                if !collision || attempt == 15 {
                    return Err(error);
                }
            }
        }
    }
    unreachable!("the final failed allocation returns its original error")
}
