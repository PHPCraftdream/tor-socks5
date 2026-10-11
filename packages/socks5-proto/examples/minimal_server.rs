//! Accept one inbound SOCKS5 or HTTP CONNECT request using SDK framing.
//! No real egress is opened: report SDK UpstreamUnavailable rather than success.

use std::error::Error;
use std::time::Duration;

use resocks5_net::server::Reply;
use socks5_proto::accept;
use tokio::net::TcpListener;
use tokio::time::{timeout_at, Instant};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:1080").await?;
    let (mut socket, _) = listener.accept().await?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let request = accept(&mut socket, deadline, None).await?;
    // A real host parses request.target(), applies policy, opens egress, replies
    // Established, then forwards take_pipeline() before unread socket bytes.
    // Do not log the request wholesale: it can contain an authenticated identity.
    // cancel-safe: NO — timeout or reply failure is terminal; main drops socket.
    timeout_at(
        Instant::now() + Duration::from_secs(5),
        request.reply(&mut socket, Reply::UpstreamUnavailable),
    )
    .await??;
    Ok(())
}
