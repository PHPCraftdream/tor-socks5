//! Тесты глобального ingress-ACL (`security.client_access.allowed_clients`)
//! на production-границе `accept_loop`: deny до handshake/backend, allow —
//! полный SOCKS5 roundtrip.

use super::*;

use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Запускает реальный `accept_loop` с заданной политикой и (опционально)
/// реальным `AuthState` поверх upstream-egress.
async fn spawn_loop_with_policy(
    listener: TcpListener,
    upstream_addr: SocketAddr,
    policy: AllowedClients,
    auth: Option<Arc<AuthState>>,
) -> (
    Arc<tokio::sync::Semaphore>,
    ConnHealthCounters,
    tokio::task::JoinHandle<()>,
) {
    let egress = Egress::Upstream(Arc::new(upstream::Upstream::new(
        upstream_addr.to_string(),
        None,
    )));
    let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    let conn_health = ConnHealthCounters::default();
    let handle = tokio::spawn(accept_loop(
        listener,
        egress,
        auth,
        permits.clone(),
        conn_health.clone(),
        Arc::new(AtomicU64::new(1)),
        false,
        policy,
    ));
    (permits, conn_health, handle)
}

/// Останавливает accept loop, глотая ожидаемый Cancelled.
async fn stop_loop(handle: tokio::task::JoinHandle<()>) {
    handle.abort();
    assert!(handle
        .await
        .expect_err("accept loop не должен завершаться сам")
        .is_cancelled());
}

/// Deny-кадр: greeting + полный CONNECT-запрос; контрфактический — без gate
/// клиент получил бы method-reply [5,0], а сервер пошёл бы в upstream.
async fn expect_denied(addr: SocketAddr, upstream_listener: &TcpListener, socks5: bool) {
    let mut client = TcpStream::connect(addr).await.unwrap();
    let _ = client.set_nodelay(true);
    // Reset может прийти раньше записи.
    if socks5 {
        let _ = client.write_all(&[5, 1, 0]).await;
        let _ = client.write_all(&[5, 1, 0, 1, 1, 2, 3, 4, 0, 80]).await;
    } else {
        let _ = client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
            .await;
    }
    // Подтверждение deny — 0 байт (FIN) или Err (RST/закрытие);
    // Ok(n > 0) или таймаут — падаем.
    let mut buf = [0; 8];
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
        Ok(Ok(n)) => panic!("denied peer must not receive any bytes, got {n}"),
        Err(_) => panic!("timed out waiting for server close"),
    }

    // Бэкенд не тронут: соединения не было.
    let upstream = upstream_listener.accept();
    assert!(
        tokio::time::timeout(Duration::from_millis(200), upstream)
            .await
            .is_err(),
        "denied peer must never reach the upstream"
    );
}

#[tokio::test]
async fn acl_denies_peer_before_handshake_and_backend() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (_permits, conn_health, handle) = spawn_loop_with_policy(
            listener,
            upstream_listener.local_addr().unwrap(),
            "192.0.2.1".parse::<AllowedClients>().unwrap(),
            None,
        )
        .await;

        // Оба протокола отклоняются до handshake и бэкенда.
        expect_denied(addr, &upstream_listener, true).await;
        expect_denied(addr, &upstream_listener, false).await;

        // Ни одного started/pending: gate сработал до резервирования permit.
        let snapshot = conn_health.snapshot_and_reset();
        assert_eq!(snapshot.started, 0);
        assert_eq!(snapshot.pending, 0);

        stop_loop(handle).await;
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
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (_permits, _conn_health, handle) = spawn_loop_with_policy(
            listener,
            upstream_listener.local_addr().unwrap(),
            "127.0.0.1".parse::<AllowedClients>().unwrap(),
            None,
        )
        .await;

        // Denied: source 127.0.0.2 (loopback 127/8) не входит в allowlist.
        let sock = tokio::net::TcpSocket::new_v4().unwrap();
        sock.bind("127.0.0.2:0".parse::<SocketAddr>().unwrap())
            .unwrap();
        let denied_client = sock.connect(addr).await.unwrap();
        drop(denied_client); // gate должен закрыть сокет до handshake
                             // Подтверждаем deny повторным кадром через тот же механизм.
        let sock = tokio::net::TcpSocket::new_v4().unwrap();
        sock.bind("127.0.0.2:0".parse::<SocketAddr>().unwrap())
            .unwrap();
        let mut client = sock.connect(addr).await.unwrap();
        let _ = client.set_nodelay(true);
        let _ = client.write_all(&[5, 1, 0]).await;
        let _ = client.write_all(&[5, 1, 0, 1, 1, 2, 3, 4, 0, 80]).await;
        let mut buf = [0; 8];
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
            Ok(Ok(n)) => panic!("denied peer must not receive any bytes, got {n}"),
            Err(_) => panic!("timed out waiting for server close"),
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(200), upstream_listener.accept())
                .await
                .is_err(),
            "denied peer must never reach the upstream"
        );

        // Allowed: обычный 127.0.0.1 — method reply, т.е. loop жив и пропустил.
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.set_nodelay(true).unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0], "loop must accept after a denied peer");

        stop_loop(handle).await;
    })
    .await
    .expect("denied-then-allowed test timed out");
}

/// Полный SOCKS5 roundtrip через реальный handshake при политике по умолчанию
/// (positive control: тот же accept_loop, но gate пропускает loopback).
#[tokio::test]
async fn acl_default_allows_loopback_full_handshake() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = destination.local_addr().unwrap();
        let (_permits, _conn_health, handle) = spawn_loop_with_policy(
            listener,
            upstream_listener.local_addr().unwrap(),
            AllowedClients::default(),
            None,
        )
        .await;

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.set_nodelay(true).unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0], "default policy must allow loopback");

        let upstream = async {
            let (mut socket, _) = upstream_listener.accept().await.unwrap();
            let mut greeting = [0; 2];
            socket.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting[0], 5);
            let mut methods = vec![0; usize::from(greeting[1])];
            socket.read_exact(&mut methods).await.unwrap();
            assert!(methods.contains(&0));
            socket.write_all(&[5, 0]).await.unwrap();
            let mut request = [0; 10];
            socket.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[..8], &[5, 1, 0, 1, 127, 0, 0, 1]);
            assert_eq!(u16::from_be_bytes([request[8], request[9]]), target.port());
            let mut remote = TcpStream::connect(target).await.unwrap();
            socket
                .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            tokio::io::copy_bidirectional(&mut socket, &mut remote)
                .await
                .unwrap();
        };
        let remote = async {
            let (mut remote, _) = destination.accept().await.unwrap();
            let mut data = Vec::new();
            remote.read_to_end(&mut data).await.unwrap();
            assert_eq!(data, b"ping");
            remote.write_all(b"pong").await.unwrap();
            remote.shutdown().await.unwrap();
        };
        let relay = async {
            // CONNECT-запрос к destination.
            let mut request = vec![5, 1, 0, 1];
            request.extend_from_slice(&[127, 0, 0, 1]);
            request.extend_from_slice(&target.port().to_be_bytes());
            client.write_all(&request).await.unwrap();
            let mut reply = [0; 10];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply[..4], &[5, 0, 0, 1]);
            // Relay данных до destination и обратно.
            client.write_all(b"ping").await.unwrap();
            client.shutdown().await.unwrap();
            let mut echoed = Vec::new();
            client.read_to_end(&mut echoed).await.unwrap();
            assert_eq!(echoed, b"pong");
        };
        tokio::join!(relay, upstream, remote);

        stop_loop(handle).await;
    })
    .await
    .expect("acl allow test timed out");
}

// --- Per-user client ACL (`User.allowed_clients`) на user-gate в
// `handle_client`: после успешного RFC1929/Basic, до любого egress. ---

/// Учётка с реальным Argon2id-хешем «pw» и опциональной per-user политикой.
fn acl_user(name: &str, policy: Option<&str>) -> auth::User {
    auth::User {
        name: name.into(),
        hash: auth::compute_hash("pw").unwrap(),
        is_enabled: true,
        allowed_onion: false,
        allowed_clients: policy.map(|p| p.parse().unwrap()),
    }
}

fn acl_auth(users: Vec<auth::User>) -> Arc<AuthState> {
    Arc::new(AuthState::build(&UsersConfig { users }).unwrap())
}

/// Полный SOCKS5 handshake с RFC1929 (alice/pw) до и включая успешную
/// аутентификацию. Возвращает сокет, готовый к CONNECT-запросу.
async fn socks5_authenticate(addr: SocketAddr) -> TcpStream {
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.set_nodelay(true).unwrap();
    client.write_all(&[5, 1, 2]).await.unwrap();
    let mut method = [0; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 2], "server must select RFC1929");
    let mut creds = vec![1u8, 5];
    creds.extend_from_slice(b"alice");
    creds.push(2);
    creds.extend_from_slice(b"pw");
    client.write_all(&creds).await.unwrap();
    let mut auth_reply = [0; 2];
    client.read_exact(&mut auth_reply).await.unwrap();
    assert_eq!(auth_reply, [1, 0], "RFC1929 auth must succeed");
    client
}

/// CONNECT 1.2.3.4:80 поверх уже аутентифицированного сокета; возвращает
/// REP-код из ответа сервера.
async fn socks5_connect(client: &mut TcpStream) -> u8 {
    let request = vec![5u8, 1, 0, 1, 1, 2, 3, 4, 0, 80];
    client.write_all(&request).await.unwrap();
    let mut reply = [0; 10];
    client.read_exact(&mut reply).await.unwrap();
    reply[1]
}

/// Отрицательный контроль для user-gate: gate убран — сервер пошёл бы в
/// upstream; поэтому каждый deny-тест ассертит именно отсутствие egress.

/// Тест 1: глобальный deny + per-user `*`. Отказ происходит на ГЛОБАЛЬНОМ
/// gate: 0 байт (FIN/RST) до handshake, RFC1929 даже не начинается,
/// соединение никогда не доходит до per-connection handler'а.
#[tokio::test]
async fn user_gate_not_reached_when_global_gate_denies_first() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let auth = acl_auth(vec![acl_user("alice", Some("*"))]);
        let (_permits, conn_health, handle) = spawn_loop_with_policy(
            listener,
            upstream_listener.local_addr().unwrap(),
            "192.0.2.1".parse::<AllowedClients>().unwrap(),
            Some(auth),
        )
        .await;

        expect_denied(addr, &upstream_listener, true).await;

        // Ни одного started: глобальный gate сработал до spawn задачи
        // handler'а, per-user policy не участвовала вовсе.
        let snapshot = conn_health.snapshot_and_reset();
        assert_eq!(snapshot.started, 0);
        assert_eq!(snapshot.connect_ok, 0);

        stop_loop(handle).await;
    })
    .await
    .expect("global-gate-first test timed out");
}

/// Тест 2: глобальный allow + per-user deny (политика `192.0.2.1`, коннект
/// с 127.0.0.1). RFC1929-аутентификация УСПЕШНА (сервер не выдаёт отказ
/// авторизации), затем CONNECT получает REP=0x02 Forbidden, egress == 0.
#[tokio::test]
async fn user_acl_denies_after_successful_rfc1929_before_egress() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let auth = acl_auth(vec![acl_user("alice", Some("192.0.2.1"))]);
        let (_permits, conn_health, handle) = spawn_loop_with_policy(
            listener,
            upstream_listener.local_addr().unwrap(),
            "127.0.0.1".parse::<AllowedClients>().unwrap(),
            Some(auth),
        )
        .await;

        let mut client = socks5_authenticate(addr).await;
        let rep = socks5_connect(&mut client).await;
        assert_eq!(rep, 0x02, "CONNECT must be answered with Forbidden");

        // Отказ — конец соединения: сервер закрыл сокет без relay.
        let mut rest = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut rest))
            .await
            .unwrap()
            .unwrap();

        // Egress не тронут: ни соединения с upstream, ни счётчика.
        assert!(
            tokio::time::timeout(Duration::from_millis(200), upstream_listener.accept())
                .await
                .is_err(),
            "denied user must never reach the upstream"
        );
        let snapshot = conn_health.snapshot_and_reset();
        assert_eq!(snapshot.started, 1, "handler ran (post-auth gate)");
        assert_eq!(snapshot.connect_ok, 0, "egress must not be dialed");

        stop_loop(handle).await;
    })
    .await
    .expect("user deny test timed out");
}

/// Каркас тестов 3/5: полный CONNECT через реальный upstream до
/// egress-заглушки; возвращает число upstream-соединений (ожидаем 1).
async fn full_connect_reaches_egress_once(user_policy: Option<&str>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // Клон для контрольного accept: tokio TcpListener не умеет try_clone,
    // дублируем слушающий сокет через std до move в задачу — проверка
    // «ровно одно egress-соединение» остаётся доступной после move.
    let std_upstream = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = std_upstream.local_addr().unwrap();
    let probe_std = std_upstream.try_clone().unwrap();
    std_upstream.set_nonblocking(true).unwrap();
    probe_std.set_nonblocking(true).unwrap();
    let upstream_listener = TcpListener::from_std(std_upstream).unwrap();
    let upstream_probe = TcpListener::from_std(probe_std).unwrap();

    let destination = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = destination.local_addr().unwrap();
    let auth = acl_auth(vec![acl_user("alice", user_policy)]);
    let (_permits, conn_health, handle) = spawn_loop_with_policy(
        listener,
        upstream_addr,
        "127.0.0.1".parse::<AllowedClients>().unwrap(),
        Some(auth),
    )
    .await;

    let upstream = tokio::spawn(async move {
        let (mut socket, _) = upstream_listener.accept().await.unwrap();
        let mut greeting = [0; 2];
        socket.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting[0], 5);
        let mut methods = vec![0; usize::from(greeting[1])];
        socket.read_exact(&mut methods).await.unwrap();
        assert!(methods.contains(&0));
        socket.write_all(&[5, 0]).await.unwrap();
        let mut request = [0; 10];
        socket.read_exact(&mut request).await.unwrap();
        assert_eq!(&request[..8], &[5, 1, 0, 1, 127, 0, 0, 1]);
        assert_eq!(u16::from_be_bytes([request[8], request[9]]), target.port());
        socket
            .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
    });

    let mut client = socks5_authenticate(addr).await;
    let mut request = vec![5u8, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&target.port().to_be_bytes());
    client.write_all(&request).await.unwrap();
    let mut reply = [0; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply[..4], &[5, 0, 0, 1], "CONNECT must be established");

    // Дождаться фактического egress-соединения (ровно одного).
    tokio::time::timeout(Duration::from_secs(5), upstream)
        .await
        .unwrap()
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(200), upstream_probe.accept())
            .await
            .is_err(),
        "exactly one egress connection expected"
    );
    let snapshot = conn_health.snapshot_and_reset();
    assert_eq!(snapshot.connect_ok, 1, "egress counter must be exactly 1");

    stop_loop(handle).await;
}

/// Тест 3: глобальный allow + per-user allow (точный `127.0.0.1`) —
/// настоящий CONNECT до egress-заглушки, egress == 1.
#[tokio::test]
async fn user_acl_allows_listed_peer_full_connect() {
    tokio::time::timeout(Duration::from_secs(15), async {
        full_connect_reaches_egress_once(Some("127.0.0.1")).await;
    })
    .await
    .expect("user allow test timed out");
}

/// Тест 5: политика omitted (`None`) — поведение как до введения gate:
/// CONNECT проходит, egress == 1.
#[tokio::test]
async fn user_acl_absent_keeps_pre_gate_behavior() {
    tokio::time::timeout(Duration::from_secs(15), async {
        full_connect_reaches_egress_once(None).await;
    })
    .await
    .expect("user-none test timed out");
}

/// Тест 4: HTTP Basic CONNECT с той же верифицированной личностью
/// (глобально allow, per-user deny): CONNECT отклоняется 403 после
/// успешной Basic-аутентификации, egress == 0. Ответ читается bounded —
/// до конца заголовков, не одним TCP-read.
#[tokio::test]
async fn http_connect_user_acl_denies_after_basic_auth() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let auth = acl_auth(vec![acl_user("alice", Some("192.0.2.1"))]);
        let (_permits, conn_health, handle) = spawn_loop_with_policy(
            listener,
            upstream_listener.local_addr().unwrap(),
            "127.0.0.1".parse::<AllowedClients>().unwrap(),
            Some(auth),
        )
        .await;

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.set_nodelay(true).unwrap();
        // Base64("alice:pw") — валидные креды: личность верифицируется.
        client
            .write_all(
                b"CONNECT example.com:443 HTTP/1.1\r\n\
                  Proxy-Authorization: Basic YWxpY2U6cHc=\r\n\r\n",
            )
            .await
            .unwrap();

        // Bounded-чтение: накапливаем заголовки до пустой строки-разделителя.
        let mut raw = Vec::new();
        let mut chunk = [0u8; 64];
        loop {
            assert!(raw.len() < 1024, "HTTP response exceeded header bound");
            let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut chunk))
                .await
                .unwrap()
                .unwrap();
            assert!(n > 0, "server closed before a complete HTTP response");
            raw.extend_from_slice(&chunk[..n]);
            if raw.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        assert!(
            raw.starts_with(b"HTTP/1.1 403 "),
            "HTTP CONNECT must be refused with 403, got: {:?}",
            raw
        );

        assert!(
            tokio::time::timeout(Duration::from_millis(200), upstream_listener.accept())
                .await
                .is_err(),
            "denied user must never reach the upstream"
        );
        let snapshot = conn_health.snapshot_and_reset();
        assert_eq!(snapshot.started, 1, "handler ran (post-auth gate)");
        assert_eq!(snapshot.connect_ok, 0, "egress must not be dialed");

        stop_loop(handle).await;
    })
    .await
    .expect("http user deny test timed out");
}

/// Тест 6: HTTP CONNECT, per-user allow (точный `127.0.0.1`): после
/// успешной Basic-аутентификации сервер отвечает
/// `HTTP/1.1 200 Connection Established\r\n\r\n` (формат Established на
/// HTTP-пути, см. production `req.reply(Reply::Established)`) и идёт в
/// upstream-заглушку до конца; egress == 1.
#[tokio::test]
async fn http_connect_user_acl_allows_listed_peer_full_connect() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Клон слушающего сокета до move: контроль «ровно один egress».
        let std_upstream = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let probe_std = std_upstream.try_clone().unwrap();
        std_upstream.set_nonblocking(true).unwrap();
        probe_std.set_nonblocking(true).unwrap();
        let upstream_listener = TcpListener::from_std(std_upstream).unwrap();
        let upstream_probe = TcpListener::from_std(probe_std).unwrap();

        let auth = acl_auth(vec![acl_user("alice", Some("127.0.0.1"))]);
        let (_permits, conn_health, handle) = spawn_loop_with_policy(
            listener,
            upstream_listener.local_addr().unwrap(),
            AllowedClients::default(),
            Some(auth),
        )
        .await;

        // Полный upstream-заглушка: greeting, CONNECT, фиктивный reply.
        let upstream = tokio::spawn(async move {
            let (mut socket, _) = upstream_listener.accept().await.unwrap();
            let mut greeting = [0; 2];
            socket.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting[0], 5);
            let mut methods = vec![0; usize::from(greeting[1])];
            socket.read_exact(&mut methods).await.unwrap();
            assert!(methods.contains(&0));
            socket.write_all(&[5, 0]).await.unwrap();
            // Заголовок запроса: VER CMD RSV ATYP (цель — домен example.com).
            let mut head = [0; 4];
            socket.read_exact(&mut head).await.unwrap();
            assert_eq!(&head[..3], &[5, 1, 0]);
            match head[3] {
                3 => {
                    let mut len = [0; 1];
                    socket.read_exact(&mut len).await.unwrap();
                    let mut domain = vec![0; usize::from(len[0])];
                    socket.read_exact(&mut domain).await.unwrap();
                    assert_eq!(domain, b"example.com");
                    let mut port = [0; 2];
                    socket.read_exact(&mut port).await.unwrap();
                    assert_eq!(port, 443u16.to_be_bytes());
                }
                other => panic!("unexpected upstream ATYP: {other}"),
            }
            socket
                .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.set_nodelay(true).unwrap();
        // Base64("alice:pw") — валидные креды: личность верифицируется.
        client
            .write_all(
                b"CONNECT example.com:443 HTTP/1.1\r\n\
                  Proxy-Authorization: Basic YWxpY2U6cHc=\r\n\r\n",
            )
            .await
            .unwrap();

        // Bounded-чтение ответа до конца заголовков.
        let mut raw = Vec::new();
        let mut chunk = [0u8; 64];
        loop {
            assert!(raw.len() < 1024, "HTTP response exceeded header bound");
            let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut chunk))
                .await
                .unwrap()
                .unwrap();
            assert!(n > 0, "server closed before a complete HTTP response");
            raw.extend_from_slice(&chunk[..n]);
            if raw.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let expected = b"HTTP/1.1 200 Connection Established\r\n\r\n";
        assert_eq!(
            &raw[..],
            &expected[..],
            "HTTP CONNECT must be established with the production reply"
        );

        // Дождаться фактического egress-соединения (ровно одного).
        tokio::time::timeout(Duration::from_secs(5), upstream)
            .await
            .unwrap()
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(200), upstream_probe.accept())
                .await
                .is_err(),
            "exactly one egress connection expected"
        );
        let snapshot = conn_health.snapshot_and_reset();
        assert_eq!(snapshot.connect_ok, 1, "egress counter must be exactly 1");

        // Корректно закрываем клиентский сокет, затем останавливаем loop.
        client.shutdown().await.unwrap();
        drop(client);
        stop_loop(handle).await;
    })
    .await
    .expect("http user allow test timed out");
}
