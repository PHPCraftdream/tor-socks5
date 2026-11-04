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
    let stream = tokio::time::timeout_at(deadline.into(), dial)
        .await
        .map_err(|_| TorError::PostSocksTimeout)??;
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
