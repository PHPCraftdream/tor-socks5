use std::time::Instant;

use futures::{AsyncReadExt, AsyncWriteExt};
use resocks5_net::types::{ProxyConfig, ProxyProtocol};

use crate::blame::{blame_dial, PostBlame};
use crate::TorTunnel;

/// Result of a handshake-only check of a pre or post proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyProbe {
    /// The proxy answered like a SOCKS5 or HTTP proxy.
    Alive,
    /// The proxy is unreachable or does not speak its protocol.
    Dead,
    /// The check could not tell: Tor itself failed or ran out of time.
    Inconclusive,
}

/// Checks that a pre proxy is alive over a direct TCP connection.
///
/// A pre proxy is reached without Tor, so this is the path real traffic takes.
/// The exchange is the handshake-only one of [`probe_post_proxy`]; it never
/// carries a target, user data or credentials, and never answers
/// [`ProxyProbe::Inconclusive`].
///
/// cancel-safe: NO — cancellation drops the probe connection.
pub async fn probe_proxy_direct(proxy: &ProxyConfig, deadline: Instant) -> ProxyProbe {
    use tokio_util::compat::TokioAsyncReadCompatExt;
    let deadline = tokio::time::Instant::from_std(deadline);
    let connect = tokio::net::TcpStream::connect((proxy.host.as_str(), proxy.port));
    let stream = match tokio::time::timeout_at(deadline, connect).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(_)) | Err(_) => return ProxyProbe::Dead,
    };
    match tokio::time::timeout_at(deadline, greet(stream.compat(), proxy)).await {
        Ok(true) => ProxyProbe::Alive,
        Ok(false) | Err(_) => ProxyProbe::Dead,
    }
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
) -> ProxyProbe {
    let deadline = tokio::time::Instant::from_std(deadline);
    let stream =
        match tokio::time::timeout_at(deadline, tunnel.connect(&proxy.host, proxy.port)).await {
            Err(_) => return ProxyProbe::Inconclusive,
            Ok(Err(error)) => {
                return match blame_dial(&error) {
                    PostBlame::NotProxy => ProxyProbe::Inconclusive,
                    PostBlame::ProxyHard | PostBlame::ProxySoft => ProxyProbe::Dead,
                }
            }
            Ok(Ok(stream)) => stream,
        };
    match tokio::time::timeout_at(deadline, greet(stream, proxy)).await {
        Ok(true) => ProxyProbe::Alive,
        Ok(false) | Err(_) => ProxyProbe::Dead,
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

    async fn direct_probe_against(reply: &'static [u8]) -> ProxyProbe {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 64];
            let _ = peer.read(&mut buffer).await;
            let _ = peer.write_all(reply).await;
            let _ = peer.shutdown().await;
        });
        let proxy = ProxyConfig::new(ProxyProtocol::Socks5, "127.0.0.1", port);
        let deadline = Instant::now() + std::time::Duration::from_secs(10);
        let probe = probe_proxy_direct(&proxy, deadline).await;
        server.await.unwrap();
        probe
    }

    #[tokio::test]
    async fn direct_probe_reports_a_live_socks5_server() {
        assert_eq!(direct_probe_against(&[5, 0]).await, ProxyProbe::Alive);
    }

    #[tokio::test]
    async fn direct_probe_rejects_a_server_that_is_not_a_proxy() {
        assert_eq!(direct_probe_against(b"HT").await, ProxyProbe::Dead);
        assert_eq!(direct_probe_against(&[]).await, ProxyProbe::Dead);
    }

    #[tokio::test]
    async fn an_unanswered_greeting_is_not_alive() {
        let proxy = ProxyConfig::new(ProxyProtocol::Socks5, "192.0.2.1", 1080);
        assert!(!greet(Cursor::new(Vec::new()), &proxy).await);
    }
}
