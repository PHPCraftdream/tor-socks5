use std::net::IpAddr;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

/// Необязательные учётные данные RFC 1929.
///
/// Значения не выводятся в форматируемые представления и ошибки.
pub struct Credentials {
    username: String,
    password: String,
}

impl Credentials {
    /// Создать учётные данные; длина каждого UTF-8 значения должна быть от 1 до 255 байт.
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Result<Self, Error> {
        let username = username.into();
        let password = password.into();
        if username.is_empty()
            || password.is_empty()
            || username.len() > u8::MAX as usize
            || password.len() > u8::MAX as usize
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self { username, password })
    }
}

/// Ошибка SOCKS5 handshake без раскрытия данных peer или учётных данных.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Имя узла или учётные данные не представимы в wire-формате SOCKS5.
    InvalidInput,
    /// Ошибка ввода-вывода или усечённый ответ peer.
    Io,
    /// Истёк абсолютный deadline; stream следует отбросить.
    Timeout,
    /// Peer нарушил протокол или отклонил handshake.
    Protocol,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "invalid SOCKS5 client input",
            Self::Io => "SOCKS5 stream I/O failed or response was truncated",
            Self::Timeout => "SOCKS5 handshake deadline elapsed",
            Self::Protocol => "SOCKS5 peer rejected or violated the protocol",
        })
    }
}

impl std::error::Error for Error {}

/// Выполнить CONNECT handshake поверх уже предоставленного stream.
///
/// Функция не открывает сокет и не разрешает `host`. Абсолютный `deadline`
/// ограничивает весь handshake. При ошибке или timeout stream следует отбросить.
///
/// cancel-safe: NO — ввод-вывод мог быть частичным; при отмене отбросьте stream.
pub async fn connect<S>(
    stream: &mut S,
    host: &str,
    port: u16,
    credentials: Option<&Credentials>,
    deadline: Instant,
) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if host.is_empty() || host.len() > u8::MAX as usize || host.as_bytes().contains(&0) {
        return Err(Error::InvalidInput);
    }
    let mut request = Vec::with_capacity(host.len() + 7);
    request.extend_from_slice(&[5, 1, 0]);
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            request[2] = 1;
            request.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            request[2] = 4;
            request.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            request.push(3);
            request.push(u8::try_from(host.len()).map_err(|_| Error::InvalidInput)?);
            request.extend_from_slice(host.as_bytes());
        }
    }
    request.extend_from_slice(&port.to_be_bytes());

    let exchange = async {
        let methods: &[u8] = if credentials.is_some() { &[2] } else { &[0] };
        stream
            .write_all(&[5, methods.len() as u8])
            .await
            .map_err(|_| Error::Io)?;
        stream.write_all(methods).await.map_err(|_| Error::Io)?;
        let mut choice = [0; 2];
        stream
            .read_exact(&mut choice)
            .await
            .map_err(|_| Error::Io)?;
        if choice[0] != 5 || choice[1] != methods[0] {
            return Err(Error::Protocol);
        }
        if choice[1] == 2 {
            let credentials = credentials.ok_or(Error::Protocol)?;
            let mut auth =
                Vec::with_capacity(credentials.username.len() + credentials.password.len() + 3);
            auth.extend_from_slice(&[1, credentials.username.len() as u8]);
            auth.extend_from_slice(credentials.username.as_bytes());
            auth.push(credentials.password.len() as u8);
            auth.extend_from_slice(credentials.password.as_bytes());
            stream.write_all(&auth).await.map_err(|_| Error::Io)?;
            let mut result = [0; 2];
            stream
                .read_exact(&mut result)
                .await
                .map_err(|_| Error::Io)?;
            if result != [1, 0] {
                return Err(Error::Protocol);
            }
        }
        stream.write_all(&request).await.map_err(|_| Error::Io)?;
        let mut header = [0; 4];
        stream
            .read_exact(&mut header)
            .await
            .map_err(|_| Error::Io)?;
        if header[0] != 5 || header[2] != 0 {
            return Err(Error::Protocol);
        }
        let tail_len = match header[3] {
            1 => 4,
            4 => 16,
            3 => {
                let mut n = [0];
                stream.read_exact(&mut n).await.map_err(|_| Error::Io)?;
                n[0] as usize
            }
            _ => return Err(Error::Protocol),
        };
        let mut tail = vec![0; tail_len + 2];
        stream.read_exact(&mut tail).await.map_err(|_| Error::Io)?;
        if header[1] != 0 {
            return Err(Error::Protocol);
        }
        Ok(())
    };
    match tokio::time::timeout_at(deadline, exchange).await {
        Ok(result) => result,
        Err(_) => Err(Error::Timeout),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::duplex;

    async fn successful_case(
        host: &str,
        credentials: Option<&Credentials>,
        expected: &[u8],
        reply: &[u8],
    ) {
        tokio::time::timeout(Duration::from_secs(2), async {
            let (mut client, mut peer) = duplex(512);
            let peer_task = async {
                let mut greeting = [0; 2];
                peer.read_exact(&mut greeting).await.unwrap();
                let mut methods = vec![0; greeting[1] as usize];
                peer.read_exact(&mut methods).await.unwrap();
                assert_eq!(greeting, [5, 1]);
                assert_eq!(
                    methods,
                    if credentials.is_some() {
                        vec![2]
                    } else {
                        vec![0]
                    }
                );
                peer.write_all(&[5, methods[0]]).await.unwrap();
                if let Some(credentials) = credentials {
                    let mut head = [0; 2];
                    peer.read_exact(&mut head).await.unwrap();
                    let mut user = vec![0; head[1] as usize];
                    peer.read_exact(&mut user).await.unwrap();
                    let mut plen = [0];
                    peer.read_exact(&mut plen).await.unwrap();
                    let mut pass = vec![0; plen[0] as usize];
                    peer.read_exact(&mut pass).await.unwrap();
                    assert_eq!(user, credentials.username.as_bytes());
                    assert_eq!(pass, credentials.password.as_bytes());
                    peer.write_all(&[1, 0]).await.unwrap();
                }
                let mut req = vec![0; expected.len()];
                peer.read_exact(&mut req).await.unwrap();
                assert_eq!(req, expected);
                let (address_len, length_prefix) = match reply[3] {
                    1 => (4, 0),
                    4 => (16, 0),
                    3 => (reply[4] as usize, 1),
                    _ => unreachable!(),
                };
                assert_eq!(reply.len(), 4 + length_prefix + address_len + 2);
                for byte in reply {
                    peer.write_all(&[*byte]).await.unwrap();
                }
                peer.shutdown().await.unwrap();
            };
            let result = connect(
                &mut client,
                host,
                80,
                credentials,
                Instant::now() + Duration::from_secs(1),
            );
            let (result, ()) = tokio::join!(result, peer_task);
            assert_eq!(result, Ok(()));
        })
        .await
        .expect("case deadline");
    }

    async fn failing_reply(reply: &[u8], expected_error: Error) {
        tokio::time::timeout(Duration::from_secs(2), async {
            let (mut client, mut peer) = duplex(64);
            let server = async {
                let mut greeting = [0; 2];
                peer.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [5, 1]);
                let mut methods = [0; 1];
                peer.read_exact(&mut methods).await.unwrap();
                assert_eq!(methods, [0]);
                peer.write_all(&[5, 0]).await.unwrap();
                let mut request = [0; 10];
                peer.read_exact(&mut request).await.unwrap();
                assert_eq!(request, [5, 1, 0, 1, 1, 2, 3, 4, 0, 80]);
                peer.write_all(reply).await.unwrap();
                drop(peer);
            };
            let (result, ()) = tokio::join!(
                connect(
                    &mut client,
                    "1.2.3.4",
                    80,
                    None,
                    Instant::now() + Duration::from_secs(1)
                ),
                server
            );
            assert_eq!(result, Err(expected_error));
        })
        .await
        .expect("failure case deadline");
    }

    #[tokio::test]
    async fn no_auth_domain_and_ipv4_ipv6_consume_bind_address() {
        successful_case(
            "example.org",
            None,
            &[
                5, 1, 0, 3, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'o', b'r', b'g',
                0, 80,
            ],
            &[5, 0, 0, 3, 3, b'b', b'n', b'd', 0, 1],
        )
        .await;
        successful_case(
            "127.0.0.1",
            None,
            &[5, 1, 0, 1, 127, 0, 0, 1, 0, 80],
            &[5, 0, 0, 1, 127, 0, 0, 1, 0, 1],
        )
        .await;
        let ipv6 = std::net::Ipv6Addr::LOCALHOST.octets();
        let mut ipv6_request = vec![5, 1, 0, 4];
        ipv6_request.extend_from_slice(&ipv6);
        ipv6_request.extend_from_slice(&80_u16.to_be_bytes());
        let mut ipv6_reply = vec![5, 0, 0, 4];
        ipv6_reply.extend_from_slice(&ipv6);
        ipv6_reply.extend_from_slice(&1_u16.to_be_bytes());
        successful_case("::1", None, &ipv6_request, &ipv6_reply).await;
    }

    #[tokio::test]
    async fn rfc1929_auth_wire_request() {
        let credentials = Credentials::new("user", "pass").unwrap();
        successful_case(
            "target.test",
            Some(&credentials),
            &[
                5, 1, 0, 3, 11, b't', b'a', b'r', b'g', b'e', b't', b'.', b't', b'e', b's', b't',
                0, 80,
            ],
            &[5, 0, 0, 1, 0, 0, 0, 0, 0, 0],
        )
        .await;
    }

    #[tokio::test]
    async fn credential_mode_rejects_no_auth_downgrade() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let credentials = Credentials::new("user", "pass").unwrap();
            let (mut client, mut peer) = duplex(16);
            let server = async {
                let mut greeting = [0; 3];
                peer.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [5, 1, 2]);
                peer.write_all(&[5, 0]).await.unwrap();
            };
            let (result, ()) = tokio::join!(
                connect(
                    &mut client,
                    "target",
                    80,
                    Some(&credentials),
                    Instant::now() + Duration::from_secs(1)
                ),
                server
            );
            assert_eq!(result, Err(Error::Protocol));
        })
        .await
        .expect("downgrade case deadline");
    }

    #[tokio::test]
    async fn rejects_invalid_reply_header_status_atyp_and_truncation() {
        failing_reply(&[4, 0, 0, 1, 0, 0, 0, 0, 0, 0], Error::Protocol).await;
        failing_reply(&[5, 0, 1, 1, 0, 0, 0, 0, 0, 0], Error::Protocol).await;
        failing_reply(&[5, 1, 0, 9], Error::Protocol).await;
        failing_reply(&[5, 0, 0, 1, 127, 0], Error::Io).await;
        failing_reply(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0], Error::Protocol).await;
    }

    #[tokio::test]
    async fn rejects_oversized_domain_and_credentials() {
        assert_eq!(Credentials::new("", "p").err(), Some(Error::InvalidInput));
        assert_eq!(Credentials::new("u", "").err(), Some(Error::InvalidInput));
        assert_eq!(
            Credentials::new("u".repeat(256), "p").err(),
            Some(Error::InvalidInput)
        );
        assert_eq!(
            Credentials::new("u", "p".repeat(256)).err(),
            Some(Error::InvalidInput)
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            let (mut client, _peer) = duplex(16);
            assert_eq!(
                connect(
                    &mut client,
                    &"x".repeat(256),
                    80,
                    None,
                    Instant::now() + Duration::from_secs(1)
                )
                .await,
                Err(Error::InvalidInput)
            );
        })
        .await
        .expect("input validation deadline");
    }

    #[tokio::test]
    async fn malformed_method_and_auth_responses_are_rejected() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let (mut client, mut peer) = duplex(16);
            let server = async {
                let mut greeting = [0; 3];
                peer.read_exact(&mut greeting).await.unwrap();
                peer.write_all(&[4, 0]).await.unwrap();
            };
            let (result, ()) = tokio::join!(
                connect(
                    &mut client,
                    "x",
                    1,
                    None,
                    Instant::now() + Duration::from_secs(1)
                ),
                server
            );
            assert_eq!(result, Err(Error::Protocol));

            let credentials = Credentials::new("user", "pass").unwrap();
            let (mut client, mut peer) = duplex(32);
            let server = async {
                let mut greeting = [0; 3];
                peer.read_exact(&mut greeting).await.unwrap();
                peer.write_all(&[5, 2]).await.unwrap();
                let mut auth = [0; 11];
                peer.read_exact(&mut auth).await.unwrap();
                peer.write_all(&[1, 1]).await.unwrap();
            };
            let (result, ()) = tokio::join!(
                connect(
                    &mut client,
                    "x",
                    1,
                    Some(&credentials),
                    Instant::now() + Duration::from_secs(1)
                ),
                server
            );
            assert_eq!(result, Err(Error::Protocol));
        })
        .await
        .expect("malformed method deadline");
    }

    #[tokio::test]
    async fn absolute_deadline_is_terminal() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let (mut client, mut peer) = duplex(16);
            let server = async {
                let mut greeting = [0; 3];
                peer.read_exact(&mut greeting).await.unwrap();
            };
            let (result, ()) = tokio::join!(
                connect(
                    &mut client,
                    "x",
                    1,
                    None,
                    Instant::now() + Duration::from_millis(10)
                ),
                server
            );
            assert_eq!(result, Err(Error::Timeout));
        })
        .await
        .expect("timeout case deadline");
    }
}
