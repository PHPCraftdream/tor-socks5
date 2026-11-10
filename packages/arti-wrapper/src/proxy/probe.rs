use std::time::Instant;

use futures::{AsyncReadExt, AsyncWriteExt};
use resocks5_net::types::{ProxyConfig, ProxyProtocol};

use crate::blame::{blame_dial, PostBlame};
use crate::TorTunnel;

/// Result of a handshake-only check of a post proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostProbe {
    /// The proxy answered like a SOCKS5 or HTTP proxy.
    Alive,
    /// The proxy is unreachable through Tor or does not speak its protocol.
    Dead,
    /// The check could not tell: Tor itself failed or ran out of time.
    Inconclusive,
}

/// Checks that a post proxy is alive without sending any target.
///
/// The only network operation is a stream opened through `tunnel` to the
/// proxy address, so nothing is resolved or dialed locally. SOCKS5 gets a
/// greeting that offers only the methods the proxy was configured for and no
/// request; HTTP gets a CONNECT to a closed loopback port of the proxy host.
/// Neither carries user data, credentials or the real target.
///
/// cancel-safe: NO — cancellation drops the probe stream.
pub async fn probe_post_proxy(
    tunnel: &TorTunnel,
    proxy: &ProxyConfig,
    deadline: Instant,
) -> PostProbe {
    let deadline = tokio::time::Instant::from_std(deadline);
    let stream =
        match tokio::time::timeout_at(deadline, tunnel.connect(&proxy.host, proxy.port)).await {
            Err(_) => return PostProbe::Inconclusive,
            Ok(Err(error)) => {
                return match blame_dial(&error) {
                    PostBlame::NotProxy => PostProbe::Inconclusive,
                    PostBlame::ProxyHard | PostBlame::ProxySoft => PostProbe::Dead,
                }
            }
            Ok(Ok(stream)) => stream,
        };
    match tokio::time::timeout_at(deadline, greet(stream, proxy)).await {
        Ok(true) => PostProbe::Alive,
        Ok(false) | Err(_) => PostProbe::Dead,
    }
}

async fn greet<S>(mut stream: S, proxy: &ProxyConfig) -> bool
where
    S: futures::AsyncRead + futures::AsyncWrite + Unpin,
{
    match proxy.protocol {
        ProxyProtocol::Socks5 => {
            let greeting: &[u8] = if proxy.user.is_some() {
                &[5, 2, 0, 2]
            } else {
                &[5, 1, 0]
            };
            let mut reply = [0u8; 2];
            let exchange = async {
                stream.write_all(greeting).await?;
                stream.flush().await?;
                stream.read_exact(&mut reply).await
            };
            exchange.await.is_ok() && reply[0] == 5 && reply[1] != 0xff
        }
        ProxyProtocol::Http => {
            let request = b"CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n";
            let mut reply = [0u8; 7];
            let exchange = async {
                stream.write_all(request).await?;
                stream.flush().await?;
                stream.read_exact(&mut reply).await
            };
            exchange.await.is_ok() && reply.starts_with(b"HTTP/1.")
        }
        ProxyProtocol::Https => false,
    }
}

#[cfg(test)]
mod tests {
    use futures::io::Cursor;
    use tokio_util::compat::TokioAsyncReadCompatExt;

    use super::*;

    async fn answer(proxy: &ProxyConfig, reply: &'static [u8]) -> bool {
        let (client, mut peer) = tokio::io::duplex(256);
        let server = async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buffer = [0u8; 64];
            let _ = peer.read(&mut buffer).await;
            let _ = peer.write_all(reply).await;
            let _ = peer.shutdown().await;
        };
        let (alive, ()) = tokio::join!(greet(client.compat(), proxy), server);
        alive
    }

    #[tokio::test]
    async fn socks5_greeting_is_judged_by_the_method_reply() {
        let proxy = ProxyConfig::new(ProxyProtocol::Socks5, "192.0.2.1", 1080);
        assert!(answer(&proxy, &[5, 0]).await);
        assert!(answer(&proxy, &[5, 2]).await);
        assert!(!answer(&proxy, &[5, 0xff]).await);
        assert!(!answer(&proxy, &[4, 0]).await);
        assert!(!answer(&proxy, b"HT").await);
    }

    #[tokio::test]
    async fn http_probe_accepts_any_well_formed_status_line() {
        let proxy = ProxyConfig::new(ProxyProtocol::Http, "192.0.2.1", 8080);
        assert!(
            answer(
                &proxy,
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"
            )
            .await
        );
        assert!(answer(&proxy, b"HTTP/1.0 502 Bad Gateway\r\n\r\n").await);
        assert!(!answer(&proxy, b"\x05\x00garbage garbage").await);
    }

    #[tokio::test]
    async fn an_unanswered_greeting_is_not_alive() {
        let proxy = ProxyConfig::new(ProxyProtocol::Socks5, "192.0.2.1", 1080);
        assert!(!greet(Cursor::new(Vec::new()), &proxy).await);
    }
}
