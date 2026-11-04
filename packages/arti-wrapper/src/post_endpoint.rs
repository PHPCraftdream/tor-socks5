use std::time::Instant;

use arti_client::DataStream;
use socks5_proto::client::{self, Credentials};
use tokio_util::compat::FuturesAsyncReadCompatExt;

use crate::{TorError, TorTunnel};

/// Открыть поток к SOCKS5 через Tor и запросить конечный адрес.
///
/// `target_host` передаётся в SOCKS5 CONNECT без локального DNS. Единый
/// deadline ограничивает открытие Tor-потока и handshake; ошибка не запускает
/// другой маршрут.
///
/// cancel-safe: NO — при отмене частично открытый поток отбрасывается.
pub async fn connect_post_socks(
    tunnel: &TorTunnel,
    proxy_host: &str,
    proxy_port: u16,
    target_host: &str,
    target_port: u16,
    credentials: Option<&Credentials>,
    deadline: Instant,
) -> Result<DataStream, TorError> {
    connect_post_over_dial(
        tunnel.connect(proxy_host, proxy_port),
        target_host,
        target_port,
        credentials,
        deadline,
    )
    .await
}

/// Connect through one configured SOCKS5 or HTTP CONNECT post endpoint.
/// cancel-safe: NO — cancellation discards the owned, partially negotiated stream.
pub async fn connect_post_proxy(
    tunnel: &TorTunnel,
    proxy: &resocks5_net::types::ProxyConfig,
    target_host: &str,
    target_port: u16,
    deadline: Instant,
) -> Result<DataStream, TorError> {
    use resocks5_net::types::ProxyProtocol;
    if proxy.gate.is_some() || proxy.host.is_empty() || proxy.port == 0 {
        return Err(TorError::BuildConfig(
            "post endpoint must be one valid proxy".to_owned(),
        ));
    }
    let credentials = match (&proxy.user, &proxy.password) {
        (None, None) => None,
        (Some(user), Some(password))
            if !user.is_empty()
                && !password.is_empty()
                && user.len() <= 255
                && password.len() <= 255
                && (proxy.protocol != ProxyProtocol::Http
                    || (!user.contains(':')
                        && !user.bytes().any(|byte| byte.is_ascii_control())
                        && !password.bytes().any(|byte| byte.is_ascii_control()))) =>
        {
            Some((user.as_str(), password.as_str()))
        }
        _ => return Err(TorError::BuildConfig("invalid post credentials".to_owned())),
    };
    if tokio::time::Instant::now() >= deadline.into() {
        return Err(match proxy.protocol {
            ProxyProtocol::Socks5 => TorError::PostSocksTimeout,
            ProxyProtocol::Http => TorError::PostHttpTimeout,
            ProxyProtocol::Https => TorError::BuildConfig("unsupported post protocol".to_owned()),
        });
    }
    match proxy.protocol {
        ProxyProtocol::Socks5 => {
            let credentials = credentials
                .map(|(user, password)| Credentials::new(user, password))
                .transpose()
                .map_err(TorError::PostSocks)?;
            connect_post_socks(
                tunnel,
                &proxy.host,
                proxy.port,
                target_host,
                target_port,
                credentials.as_ref(),
                deadline,
            )
            .await
        }
        ProxyProtocol::Http => {
            connect_post_http(
                tunnel,
                &proxy.host,
                proxy.port,
                target_host,
                target_port,
                credentials,
                deadline,
            )
            .await
        }
        ProxyProtocol::Https => Err(TorError::BuildConfig(
            "post protocol must be SOCKS5 or HTTP CONNECT".to_owned(),
        )),
    }
}

/// Open an HTTP CONNECT proxy through Tor without local target DNS or fallback.
/// cancel-safe: NO — cancellation discards the owned, partially negotiated stream.
async fn connect_post_http(
    tunnel: &TorTunnel,
    proxy_host: &str,
    proxy_port: u16,
    target_host: &str,
    target_port: u16,
    credentials: Option<(&str, &str)>,
    deadline: Instant,
) -> Result<DataStream, TorError> {
    use resocks5_net::types::{ProxyConfig, ProxyProtocol};
    let mut proxy = ProxyConfig::new(ProxyProtocol::Http, proxy_host, proxy_port);
    if let Some((username, password)) = credentials {
        proxy.user = Some(username.to_owned());
        proxy.password = Some(password.to_owned());
    }
    connect_http_over_dial(
        tunnel.connect(proxy_host, proxy_port),
        &proxy,
        target_host,
        target_port,
        deadline,
    )
    .await
}

async fn connect_http_over_dial<S, F>(
    dial: F,
    proxy: &resocks5_net::types::ProxyConfig,
    target_host: &str,
    target_port: u16,
    deadline: Instant,
) -> Result<S, TorError>
where
    S: futures::AsyncRead + futures::AsyncWrite + Unpin,
    F: std::future::Future<Output = Result<S, TorError>>,
{
    if tokio::time::Instant::now() >= deadline.into() {
        return Err(TorError::PostHttpTimeout);
    }
    let stream = tokio::time::timeout_at(deadline.into(), dial)
        .await
        .map_err(|_| TorError::PostHttpTimeout)??;
    let mut stream = stream.compat();
    let target = resocks5_net::connect::HostPort::format(target_host, target_port);
    if tokio::time::Instant::now() >= deadline.into() {
        return Err(TorError::PostHttpTimeout);
    }
    tokio::time::timeout_at(
        deadline.into(),
        resocks5_net::connect::http_connect_handshake(&mut stream, &target, proxy),
    )
    .await
    .map_err(|_| TorError::PostHttpTimeout)?
    .map_err(TorError::PostHttp)?;
    Ok(stream.into_inner())
}

async fn connect_post_over_dial<S, F>(
    dial: F,
    target_host: &str,
    target_port: u16,
    credentials: Option<&Credentials>,
    deadline: Instant,
) -> Result<S, TorError>
where
    S: futures::AsyncRead + futures::AsyncWrite + Unpin,
    F: std::future::Future<Output = Result<S, TorError>>,
{
    tracing::info!(
        post_protocol = "socks5",
        post_stage = "dial",
        "post proxy setup"
    );
    let stream = tokio::time::timeout_at(deadline.into(), dial)
        .await
        .map_err(|_| TorError::PostSocksTimeout)??;
    tracing::info!(
        post_protocol = "socks5",
        post_stage = "handshake",
        "post proxy setup"
    );
    connect_stream(stream, target_host, target_port, credentials, deadline).await
}

async fn connect_stream<S>(
    stream: S,
    target_host: &str,
    target_port: u16,
    credentials: Option<&Credentials>,
    deadline: Instant,
) -> Result<S, TorError>
where
    S: futures::AsyncRead + futures::AsyncWrite + Unpin,
{
    let mut compat = stream.compat();
    client::connect(
        &mut compat,
        target_host,
        target_port,
        credentials,
        deadline.into(),
    )
    .await
    .map_err(|error| match error {
        client::Error::Timeout => TorError::PostSocksTimeout,
        error => TorError::PostSocks(error),
    })?;
    tracing::info!(
        post_protocol = "socks5",
        post_stage = "established",
        "post proxy setup"
    );
    Ok(compat.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::io::{AsyncReadExt as FuturesAsyncReadExt, AsyncWriteExt as FuturesAsyncWriteExt};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::compat::TokioAsyncReadCompatExt;

    #[tokio::test]
    async fn http_post_uses_unresolved_authority_and_preserves_payload() {
        use resocks5_net::server::{accept, Protocol, Reply, ServerOptions};
        use resocks5_net::types::{ProxyConfig, ProxyProtocol};
        let (client, mut peer) = tokio::io::duplex(4096);
        let mut proxy = ProxyConfig::new(ProxyProtocol::Http, "192.0.2.1", 8080);
        proxy.user = Some("user".to_owned());
        proxy.password = Some("password".to_owned());
        let server = async {
            let options = ServerOptions::new(
                tokio::time::Instant::now() + Duration::from_secs(5),
                false,
                true,
            );
            let request = accept(&mut peer, &options, |credentials| {
                std::future::ready(
                    credentials.username() == "user" && credentials.password() == "password",
                )
            })
            .await
            .unwrap();
            assert_eq!(request.protocol(), Protocol::Http);
            assert_eq!(request.target(), "target.invalid:443");
            request.reply(&mut peer, Reply::Established).await.unwrap();
            peer.write_all(b"payload").await.unwrap();
        };
        let client = async {
            let mut stream = connect_http_over_dial(
                async { Ok(client.compat()) },
                &proxy,
                "target.invalid",
                443,
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .unwrap();
            let mut payload = [0; 7];
            FuturesAsyncReadExt::read_exact(&mut stream, &mut payload)
                .await
                .unwrap();
            assert_eq!(&payload, b"payload");
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(server, client)
        })
        .await
        .expect("HTTP post exchange must finish");
    }

    #[tokio::test]
    async fn http_post_rejection_is_not_success() {
        use resocks5_net::types::{ProxyConfig, ProxyProtocol};
        let (client, mut peer) = tokio::io::duplex(4096);
        let proxy = ProxyConfig::new(ProxyProtocol::Http, "192.0.2.1", 8080);
        let server = async {
            let options = resocks5_net::server::ServerOptions::new(
                tokio::time::Instant::now() + Duration::from_secs(5),
                true,
                false,
            );
            let request =
                resocks5_net::server::accept(&mut peer, &options, |_| std::future::ready(false))
                    .await
                    .unwrap();
            request
                .reply(&mut peer, resocks5_net::server::Reply::Forbidden)
                .await
                .unwrap();
        };
        let client = connect_http_over_dial(
            async { Ok(client.compat()) },
            &proxy,
            "target.invalid",
            443,
            Instant::now() + Duration::from_secs(5),
        );
        let ((), result) = tokio::join!(server, client);
        assert!(matches!(
            result,
            Err(TorError::PostHttp(
                resocks5_net::ConnectError::ProxyRejected {
                    protocol: ProxyProtocol::Http,
                    code: Some(403),
                    ..
                }
            ))
        ));
    }

    #[tokio::test]
    async fn expired_http_post_deadline_never_polls_dial() {
        use resocks5_net::types::{ProxyConfig, ProxyProtocol};
        let proxy = ProxyConfig::new(ProxyProtocol::Http, "192.0.2.1", 8080);
        let polls = std::sync::atomic::AtomicUsize::new(0);
        let dial = std::future::poll_fn(|_| {
            polls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::task::Poll::Ready(
                Err::<tokio_util::compat::Compat<tokio::io::DuplexStream>, _>(
                    TorError::PostHttpTimeout,
                ),
            )
        });
        let result =
            connect_http_over_dial(dial, &proxy, "target.invalid", 443, Instant::now()).await;
        assert!(matches!(result, Err(TorError::PostHttpTimeout)));
        assert_eq!(polls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn buffered_socks_stream_flushes_each_handshake_phase() {
        use resocks5_net::server::{accept, Reply, ServerError, ServerOptions};
        let (client, mut peer) = tokio::io::duplex(4096);
        let deadline = (tokio::time::Instant::now() + Duration::from_secs(5)).into_std();
        let credentials = Credentials::new("user", "password").unwrap();
        let server = async {
            let options = ServerOptions::new(deadline.into(), false, true);
            let request = accept(&mut peer, &options, |credentials| {
                std::future::ready(
                    credentials.username() == "user" && credentials.password() == "password",
                )
            })
            .await?;
            assert_eq!(request.target(), "target.invalid:443");
            request.reply(&mut peer, Reply::Established).await?;
            peer.write_all(b"ready").await.map_err(ServerError::Io)?;
            Ok::<(), ServerError>(())
        };
        let buffered = tokio::io::BufStream::new(client).compat();
        let client = connect_stream(
            buffered,
            "target.invalid",
            443,
            Some(&credentials),
            deadline,
        );
        let (server_result, client_result) = tokio::join!(server, client);
        let mut stream = client_result
            .expect("SOCKS handshake must flush buffered writes before reading replies");
        server_result.unwrap();
        let mut payload = [0; 5];
        FuturesAsyncReadExt::read_exact(&mut stream, &mut payload)
            .await
            .unwrap();
        assert_eq!(&payload, b"ready");
    }

    #[tokio::test]
    async fn connect_stream_uses_socks_domain_request_and_preserves_payload() {
        let (client, mut peer) = tokio::io::duplex(256);
        let stream = client.compat();
        let peer_task = tokio::spawn(async move {
            let mut greeting = [0; 3];
            peer.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            peer.write_all(&[5, 0]).await.unwrap();

            let expected = [
                5, 1, 0, 3, 16, b'p', b'r', b'o', b'x', b'y', b'.', b'o', b'n', b'i', b'o', b'n',
                b'.', b'e', b'x', b'a', b'm', 0x01, 0xbb,
            ];
            assert_eq!(expected.len(), 3 + 1 + 1 + "proxy.onion.exam".len() + 2);
            assert_eq!(expected[4] as usize, "proxy.onion.exam".len());
            let mut request = vec![0; expected.len()];
            peer.read_exact(&mut request).await.unwrap();
            assert_eq!(request, expected);
            peer.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80])
                .await
                .unwrap();
            let mut payload = [0; 7];
            peer.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"payload");
            peer.write_all(b"reply").await.unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        tokio::time::timeout_at(deadline.into(), async {
            let mut stream = connect_post_over_dial(
                async { Ok(stream) },
                "proxy.onion.exam",
                443,
                None,
                deadline,
            )
            .await
            .unwrap();
            stream.write_all(b"payload").await.unwrap();
            let mut response = [0; 5];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"reply");
            peer_task.await.unwrap();
        })
        .await
        .expect("scenario deadline");
    }

    #[tokio::test]
    async fn dial_failure_is_returned_without_socks_handshake() {
        type TestStream = tokio_util::compat::Compat<tokio::io::DuplexStream>;
        let result = connect_post_over_dial(
            async { Err::<TestStream, _>(TorError::InvalidBridge("fixture".into())) },
            "target.example",
            443,
            None,
            Instant::now() + Duration::from_secs(2),
        )
        .await;
        assert!(matches!(result, Err(TorError::InvalidBridge(_))));
    }

    #[tokio::test]
    async fn dial_timeout_returns_post_socks_timeout() {
        type TestStream = tokio_util::compat::Compat<tokio::io::DuplexStream>;
        let result = connect_post_over_dial(
            std::future::pending::<Result<TestStream, TorError>>(),
            "target.example",
            443,
            None,
            Instant::now() - Duration::from_secs(1),
        )
        .await;
        assert!(matches!(result, Err(TorError::PostSocksTimeout)));
    }

    #[tokio::test]
    async fn dialled_stream_uses_credentials_and_preserves_target_domain() {
        let (client, mut peer) = tokio::io::duplex(256);
        let credentials = Credentials::new("user", "pass").unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        tokio::time::timeout_at(deadline.into(), async {
            let server = async {
                let mut greeting = [0; 3];
                peer.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [5, 1, 2]);
                peer.write_all(&[5, 2]).await.unwrap();
                let mut auth = [0; 11];
                peer.read_exact(&mut auth).await.unwrap();
                assert_eq!(
                    &auth,
                    &[1, 4, b'u', b's', b'e', b'r', 4, b'p', b'a', b's', b's']
                );
                peer.write_all(&[1, 0]).await.unwrap();
                let mut request = [0; 18];
                peer.read_exact(&mut request).await.unwrap();
                assert_eq!(
                    &request,
                    &[
                        5, 1, 0, 3, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'o', b'r',
                        b'g', 1, 187
                    ]
                );
                peer.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80])
                    .await
                    .unwrap();
            };
            let client = connect_post_over_dial(
                async { Ok(client.compat()) },
                "example.org",
                443,
                Some(&credentials),
                deadline,
            );
            let (result, ()) = tokio::join!(client, server);
            assert!(result.is_ok());
        })
        .await
        .expect("scenario deadline");
    }

    #[tokio::test]
    async fn connect_stream_failure_closes_owned_stream_without_fallback() {
        let (client, mut peer) = tokio::io::duplex(64);
        let stream = client.compat();
        let peer_task = tokio::spawn(async move {
            let mut greeting = [0; 3];
            peer.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            peer.write_all(&[5, 0]).await.unwrap();
            let mut request = [0; 25];
            peer.read_exact(&mut request).await.unwrap();
            assert_eq!(
                request,
                [
                    5, 1, 0, 3, 18, b'u', b'n', b'r', b'e', b's', b'o', b'l', b'v', b'e', b'd',
                    b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0, 80,
                ]
            );
            peer.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut byte = [0; 1];
            assert_eq!(peer.read(&mut byte).await.unwrap(), 0);
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        let (result, peer_result) = tokio::time::timeout_at(deadline.into(), async {
            tokio::join!(
                connect_stream(stream, "unresolved.example", 80, None, deadline),
                peer_task
            )
        })
        .await
        .expect("scenario deadline");
        peer_result.unwrap();
        assert!(matches!(result, Err(TorError::PostSocks(_))));
    }

    #[tokio::test]
    async fn connect_stream_timeout_closes_owned_stream() {
        let (client, mut peer) = tokio::io::duplex(64);
        let stream = client.compat();
        let peer_task = tokio::spawn(async move {
            let mut greeting = [0; 3];
            peer.read_exact(&mut greeting).await.unwrap();
            let mut byte = [0; 1];
            assert_eq!(peer.read(&mut byte).await.unwrap(), 0);
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        let handshake_deadline = Instant::now() + Duration::from_millis(10);
        let (result, peer_result) = tokio::time::timeout_at(deadline.into(), async {
            tokio::join!(
                connect_stream(stream, "proxy.example", 80, None, handshake_deadline),
                peer_task
            )
        })
        .await
        .expect("scenario deadline");
        peer_result.unwrap();
        assert!(matches!(result, Err(TorError::PostSocksTimeout)));
    }
}
