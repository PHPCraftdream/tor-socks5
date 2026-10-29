//! Тесты глобального ingress-ACL на FFI `accept_loop`: deny до handshake и
//! без резервирования egress-connector'а, allow — полный handshake до
//! Established (positive control).

use super::*;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Фейковый egress: считает open_egress и отдаёт duplex-сторону релея,
/// вторую половину кладёт в общий слот для проверок из теста.
#[derive(Clone)]
struct RecordingConnector {
    connects: Arc<AtomicUsize>,
    peer: Arc<Mutex<Option<tokio::io::DuplexStream>>>,
}

impl RecordingConnector {
    fn new() -> Self {
        Self {
            connects: Arc::new(AtomicUsize::new(0)),
            peer: Arc::new(Mutex::new(None)),
        }
    }

    fn take_peer(&self) -> tokio::io::DuplexStream {
        self.peer
            .lock()
            .unwrap()
            .take()
            .expect("egress peer half not created yet")
    }
}

impl EgressConnector for RecordingConnector {
    async fn open_egress(
        self,
        _target: HostPort<'_>,
    ) -> Result<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static> {
        self.connects.fetch_add(1, Ordering::Relaxed);
        let (server_side, peer) = tokio::io::duplex(64);
        *self.peer.lock().unwrap() = Some(peer);
        Ok(server_side)
    }
}

fn loopback_policy() -> ConnectionPolicy {
    ConnectionPolicy {
        auth_state: None,
        block_onion: false,
        allowed_clients: AllowedClients::default(),
    }
}

fn deny_policy() -> ConnectionPolicy {
    ConnectionPolicy {
        auth_state: None,
        block_onion: false,
        allowed_clients: "192.0.2.1".parse::<AllowedClients>().unwrap(),
    }
}

/// Политика, разрешающая только 127.0.0.1 (для denied-then-allowed теста).
fn strict_loopback_policy() -> ConnectionPolicy {
    ConnectionPolicy {
        auth_state: None,
        block_onion: false,
        allowed_clients: "127.0.0.1".parse::<AllowedClients>().unwrap(),
    }
}

async fn spawn_accept_loop(
    listener: TcpListener,
    connector: RecordingConnector,
    policy: ConnectionPolicy,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move {
        accept_loop(&listener, connector, Arc::new(Semaphore::new(8)), policy).await
    })
}

/// Deny-кадр: шлём greeting + полный CONNECT-запрос и ждём закрытия.
/// Контрфактический: без gate клиент получил бы method-reply, а connector
/// был бы вызван (connects > 0) — оба assert'а поймали бы регрессию.
async fn send_denied_frame(client: &mut TcpStream, socks5: bool) {
    let _ = client.set_nodelay(true);
    if socks5 {
        // Reset может прийти раньше записи — это не ошибка deny-теста.
        let _ = client.write_all(&[5, 1, 0]).await;
        let _ = client.write_all(&[5, 1, 0, 1, 1, 2, 3, 4, 0, 80]).await;
    } else {
        let _ = client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
            .await;
    }
}

/// Deny-read: подтверждение — 0 байт (FIN) или Err (RST/закрытие).
/// Ok(n > 0) или таймаут — падаем: сервер ответил или висит.
async fn expect_no_bytes(client: &mut TcpStream) {
    let mut buf = [0; 16];
    let read = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf)).await;
    match read {
        Ok(Ok(0)) => {}
        Ok(Err(error)) => assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::NotConnected
                    | std::io::ErrorKind::UnexpectedEof
            ),
            "неожиданная ошибка вместо закрытия: {error}"
        ),
        Ok(Ok(n)) => panic!("denied peer received reply bytes: {n}"),
        Err(_) => panic!("timed out waiting for server close"),
    }
}

/// Deny-кадр на уже открытом соединении.
async fn expect_denied(mut client: TcpStream, connector: &RecordingConnector, socks5: bool) {
    send_denied_frame(&mut client, socks5).await;
    expect_no_bytes(&mut client).await;
    assert_eq!(connector.connects.load(Ordering::Relaxed), 0);
}

/// Соединение с явным source-адресом 127.0.0.2 (тоже 127/8 loopback),
/// чтобы попасть под strict-политику "только 127.0.0.1".
async fn connect_from_127_0_0_2(addr: SocketAddr) -> TcpStream {
    let sock = tokio::net::TcpSocket::new_v4().unwrap();
    sock.bind("127.0.0.2:0".parse::<SocketAddr>().unwrap())
        .unwrap();
    sock.connect(addr).await.unwrap()
}

#[tokio::test]
async fn acl_denies_before_handshake_and_connector() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connector = RecordingConnector::new();
        let handle = spawn_accept_loop(listener, connector.clone(), deny_policy()).await;

        // SOCKS5: greeting+request -> EOF/ошибка, connector не вызван.
        expect_denied(TcpStream::connect(addr).await.unwrap(), &connector, true).await;

        // Loop жив: второе соединение — тот же deny.
        expect_denied(TcpStream::connect(addr).await.unwrap(), &connector, true).await;

        // HTTP CONNECT тоже режется на уровне accept(), до какого-либо парсинга.
        expect_denied(TcpStream::connect(addr).await.unwrap(), &connector, false).await;

        handle.abort();
        assert!(handle
            .await
            .expect_err("accept loop не должен завершаться сам")
            .is_cancelled());
    })
    .await
    .expect("acl deny test timed out");
}

/// Denied-then-allowed на одном accept loop: gate — `continue`, а не `return`.
#[tokio::test]
async fn acl_denied_peer_does_not_stop_accept_loop() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connector = RecordingConnector::new();
        let handle = spawn_accept_loop(listener, connector.clone(), strict_loopback_policy()).await;

        // Denied: peer 127.0.0.2 не входит в allowlist 127.0.0.1.
        expect_denied(connect_from_127_0_0_2(addr).await, &connector, true).await;

        // Allowed: обычный 127.0.0.1 проходит полный SOCKS5 до Established.
        let mut client = TcpStream::connect(addr).await.unwrap();
        let _ = client.set_nodelay(true);
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0], "loop must accept after a denied peer");
        client
            .write_all(&[5, 1, 0, 1, 1, 2, 3, 4, 0, 80])
            .await
            .unwrap();
        let mut reply = [0; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply[..3], &[5, 0, 0], "expected Established reply");
        assert_eq!(connector.connects.load(Ordering::Relaxed), 1);

        handle.abort();
        assert!(handle
            .await
            .expect_err("accept loop не должен завершаться сам")
            .is_cancelled());
    })
    .await
    .expect("denied-then-allowed test timed out");
}

#[tokio::test]
async fn acl_default_allows_socks5_and_http_connect() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connector = RecordingConnector::new();
        let handle = spawn_accept_loop(listener, connector.clone(), loopback_policy()).await;

        // SOCKS5: greeting -> [5,0], CONNECT -> Established -> relay.
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.set_nodelay(true).unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        client
            .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80])
            .await
            .unwrap();
        let mut reply = [0; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply[..3], &[5, 0, 0], "expected Established reply");
        assert_eq!(connector.connects.load(Ordering::Relaxed), 1);
        // Релей: duplex-партнёр пишет, клиент получает.
        let mut peer = connector.take_peer();
        peer.write_all(b"pong").await.unwrap();
        let mut echoed = [0; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"pong");
        drop(peer);
        drop(client);

        // HTTP CONNECT через тот же loop: Established-ответ и connector == 2.
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.set_nodelay(true).unwrap();
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        // HTTP-ответ читаем до конца заголовков: TCP не гарантирует один полный read.
        let mut response: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 16];
        let deadline = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let n = client
                    .read(&mut chunk)
                    .await
                    .expect("http reply read failed");
                assert!(n > 0, "server closed before sending an HTTP reply");
                response.extend_from_slice(&chunk[..n]);
                if response.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
        })
        .await;
        assert!(deadline.is_ok(), "timed out waiting for HTTP reply");
        assert!(
            response.starts_with(b"HTTP/1.1 200"),
            "unexpected reply: {response:?}"
        );
        assert_eq!(connector.connects.load(Ordering::Relaxed), 2);

        handle.abort();
        assert!(handle
            .await
            .expect_err("accept loop не должен завершаться сам")
            .is_cancelled());
    })
    .await
    .expect("acl allow test timed out");
}

// ---------- Per-user ACL (ConnectionPolicy.auth_state) ----------

/// Учётка alice с per-user ACL (`None` — поле опущено, поведение как раньше).
fn user_acl_state(acl: Option<&str>) -> Arc<auth::AuthState> {
    let user = auth::User {
        name: "alice".into(),
        hash: auth::compute_hash("pw").unwrap(),
        is_enabled: true,
        allowed_onion: false,
        allowed_clients: acl.map(|s| s.parse().expect("valid allow-list")),
        pre_socks5: None,
        post_socks5: None,
    };
    Arc::new(auth::AuthState::build(&auth::UsersConfig { users: vec![user] }).unwrap())
}

fn policy(auth: Option<Arc<auth::AuthState>>, allowed_clients: &str) -> ConnectionPolicy {
    ConnectionPolicy {
        auth_state: auth,
        block_onion: false,
        allowed_clients: allowed_clients.parse::<AllowedClients>().unwrap(),
    }
}

/// RFC1929 sub-negotiation frame.
fn rfc1929_frame(user: &str, passwd: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + user.len() + passwd.len());
    out.push(0x01);
    out.push(user.len() as u8);
    out.extend_from_slice(user.as_bytes());
    out.push(passwd.len() as u8);
    out.extend_from_slice(passwd.as_bytes());
    out
}

/// Полный SOCKS5 handshake (RFC1929 + CONNECT) по реальному сокету.
async fn socks5_auth_then_connect(client: &mut TcpStream, target: [u8; 6]) {
    let _ = client.set_nodelay(true);
    client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    let mut method = [0u8; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, 0x02], "server must select USER/PASS");
    client
        .write_all(&rfc1929_frame("alice", "pw"))
        .await
        .unwrap();
    let mut auth_reply = [0u8; 2];
    client.read_exact(&mut auth_reply).await.unwrap();
    assert_eq!(auth_reply, [0x01, 0x00], "RFC1929 auth must succeed");
    let mut frame = vec![0x05, 0x01, 0x00, 0x01];
    frame.extend_from_slice(&target);
    client.write_all(&frame).await.unwrap();
}

/// Читает HTTP-ответ до конца заголовков (`\r\n\r\n`), bounded по таймауту.
async fn read_http_headers(client: &mut TcpStream) -> Vec<u8> {
    let mut response = Vec::new();
    let mut chunk = [0u8; 16];
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let n = client.read(&mut chunk).await.expect("http read failed");
            assert!(n > 0, "server closed before a complete HTTP reply");
            response.extend_from_slice(&chunk[..n]);
            assert!(
                response.len() <= 1024,
                "HTTP-заголовок превышает лимит теста"
            );
            if response.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
    })
    .await
    .expect("timed out waiting for HTTP reply");
    response
}

/// a) global deny + user policy `*`: отказ на global gate до handshake,
/// connector не вызван.
#[tokio::test]
async fn user_acl_global_deny_wins_before_handshake() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connector = RecordingConnector::new();
        let handle = spawn_accept_loop(
            listener,
            connector.clone(),
            policy(Some(user_acl_state(Some("*"))), "192.0.2.1"),
        )
        .await;

        let mut client = TcpStream::connect(addr).await.unwrap();
        let _ = client.write_all(&[5, 1, 2]).await;
        let mut buf = [0; 16];
        let read = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf)).await;
        match read {
            Ok(Ok(0)) => {}
            Ok(Err(error)) => assert!(
                matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::NotConnected
                        | std::io::ErrorKind::UnexpectedEof
                ),
                "неожиданная ошибка вместо закрытия: {error}"
            ),
            Ok(Ok(n)) => panic!("global deny must drop before handshake: {n}"),
            Err(_) => panic!("timed out waiting for server close"),
        }
        drop(client);
        assert_eq!(connector.connects.load(Ordering::Relaxed), 0);

        handle.abort();
        assert!(handle
            .await
            .expect_err("accept loop не должен завершаться сам")
            .is_cancelled());
    })
    .await
    .expect("global deny + user allow-all test timed out");
}

/// b) global allow (127.0.0.1,127.0.0.2) + user policy "127.0.0.1", клиент
/// с 127.0.0.2: RFC1929 auth успешна, затем CONNECT -> Forbidden (REP=0x02),
/// egress 0; HTTP Basic CONNECT -> 403, egress 0.
#[tokio::test]
async fn user_acl_denied_peer_gets_forbidden_after_auth() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connector = RecordingConnector::new();
        let handle = spawn_accept_loop(
            listener,
            connector.clone(),
            policy(
                Some(user_acl_state(Some("127.0.0.1"))),
                "127.0.0.1,127.0.0.2",
            ),
        )
        .await;

        // SOCKS5: auth успешна, CONNECT отклонён Forbidden, egress == 0.
        let mut client = connect_from_127_0_0_2(addr).await;
        socks5_auth_then_connect(&mut client, [1, 2, 3, 4, 0, 80]).await;
        let mut reply = [0; 10];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut reply))
            .await
            .expect("timed out waiting for CONNECT reply")
            .unwrap();
        // REP=0x02 (Forbidden), RSV=0, ATYP=1, bnd 6 нулей — тот же framing,
        // что в engine_tests (Forbidden-assert), дискриминант из socks5-proto.
        assert_eq!(reply[0], 0x05);
        assert_eq!(reply[1], 0x02, "user-denied CONNECT must be Forbidden");
        assert_eq!(reply[2], 0x00);
        assert_eq!(reply[3], 0x01);
        assert_eq!(&reply[4..], &[0, 0, 0, 0, 0, 0]);
        assert_eq!(connector.connects.load(Ordering::Relaxed), 0);
        drop(client);

        // HTTP Basic CONNECT: 403, egress == 0.
        let mut http = connect_from_127_0_0_2(addr).await;
        http.write_all(
            b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic YWxpY2U6cHc=\r\n\r\n",
        )
        .await
        .unwrap();
        let response = read_http_headers(&mut http).await;
        assert!(
            response.starts_with(b"HTTP/1.1 403 "),
            "user-denied HTTP CONNECT must be 403: {response:?}"
        );
        assert_eq!(connector.connects.load(Ordering::Relaxed), 0);
        drop(http);

        handle.abort();
        assert!(handle
            .await
            .expect_err("accept loop не должен завершаться сам")
            .is_cancelled());
    })
    .await
    .expect("user deny after auth test timed out");
}

/// c) global allow + user `*`: полный CONNECT до Established, egress == 1,
/// релеёт байты; HTTP CONNECT -> 200 Established, egress == 2.
#[tokio::test]
async fn user_acl_allowed_user_full_connect_and_http() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connector = RecordingConnector::new();
        let handle = spawn_accept_loop(
            listener,
            connector.clone(),
            policy(Some(user_acl_state(Some("*"))), "127.0.0.1,127.0.0.2"),
        )
        .await;

        // SOCKS5 до Established + релей через duplex-peer.
        let mut client = TcpStream::connect(addr).await.unwrap();
        socks5_auth_then_connect(&mut client, [127, 0, 0, 1, 0, 80]).await;
        let mut reply = [0; 10];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut reply))
            .await
            .expect("timed out waiting for Established reply")
            .unwrap();
        assert_eq!(&reply[..3], &[5, 0, 0], "expected Established reply");
        assert_eq!(connector.connects.load(Ordering::Relaxed), 1);
        let mut peer = connector.take_peer();
        peer.write_all(b"pong").await.unwrap();
        let mut echoed = [0; 4];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut echoed))
            .await
            .expect("timed out waiting for relayed bytes")
            .unwrap();
        assert_eq!(&echoed, b"pong");
        drop(peer);
        drop(client);

        // HTTP CONNECT -> точный 200-ответ (формат из engine_tests-оракула).
        let mut http = TcpStream::connect(addr).await.unwrap();
        http.write_all(
            b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic YWxpY2U6cHc=\r\n\r\n",
        )
        .await
        .unwrap();
        let response = read_http_headers(&mut http).await;
        assert_eq!(
            response, b"HTTP/1.1 200 Connection Established\r\n\r\n",
            "unexpected HTTP established reply"
        );
        assert_eq!(connector.connects.load(Ordering::Relaxed), 2);
        drop(http);

        handle.abort();
        assert!(handle
            .await
            .expect_err("accept loop не должен завершаться сам")
            .is_cancelled());
    })
    .await
    .expect("user allow-all full connect test timed out");
}

/// d) У аутентифицированного пользователя ACL опущен: действует только глобальный.
#[tokio::test]
async fn user_acl_omitted_policy_keeps_previous_behaviour() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connector = RecordingConnector::new();
        let handle = spawn_accept_loop(
            listener,
            connector.clone(),
            policy(Some(user_acl_state(None)), "127.0.0.1,127.0.0.2"),
        )
        .await;

        let mut client = connect_from_127_0_0_2(addr).await;
        socks5_auth_then_connect(&mut client, [127, 0, 0, 1, 0, 80]).await;
        let mut reply = [0; 10];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut reply))
            .await
            .expect("timed out waiting for Established reply")
            .unwrap();
        assert_eq!(&reply[..3], &[5, 0, 0]);
        assert_eq!(connector.connects.load(Ordering::Relaxed), 1);
        drop(client);

        handle.abort();
        assert!(handle
            .await
            .expect_err("accept loop не должен завершаться сам")
            .is_cancelled());
    })
    .await
    .expect("omitted policy test timed out");
}

/// e) auth включён + клиент предлагает только NO_AUTH: handshake fail
/// (NO_ACCEPTABLE_METHODS), egress == 0 (fail-closed caller-семантика).
#[tokio::test]
async fn user_acl_no_auth_offer_fails_handshake_closed() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connector = RecordingConnector::new();
        let handle = spawn_accept_loop(
            listener,
            connector.clone(),
            policy(Some(user_acl_state(Some("*"))), "127.0.0.1"),
        )
        .await;

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0; 2];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut method))
            .await
            .expect("timed out waiting for method reply")
            .unwrap();
        assert_eq!(method, [0x05, 0xFF], "NO_AUTH offer must be rejected");
        // Сервер закрывает соединение после отказа в методе.
        let mut buf = [0; 1];
        let read = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf)).await;
        match read {
            Ok(Ok(0)) => {}
            Ok(Err(_)) => {}
            Ok(Ok(n)) => panic!("unexpected bytes after method rejection: {n}"),
            Err(_) => panic!("timed out waiting for server close"),
        }
        drop(client);
        assert_eq!(connector.connects.load(Ordering::Relaxed), 0);

        handle.abort();
        assert!(handle
            .await
            .expect_err("accept loop не должен завершаться сам")
            .is_cancelled());
    })
    .await
    .expect("NO_AUTH fail-closed test timed out");
}
