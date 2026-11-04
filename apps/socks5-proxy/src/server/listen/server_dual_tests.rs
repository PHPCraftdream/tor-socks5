use super::*;

// -- same-port consumer migration ------------------------------------------

async fn assert_no_upstream_connection(listener: &TcpListener) {
    // Handler has completed: every accidental dial would already be queued.
    assert!(
        std::future::poll_fn(|cx| {
            std::task::Poll::Ready(listener.poll_accept(cx).is_pending())
        })
        .await,
        "rejected request must not dial upstream"
    );
}

fn test_egress(listener: &TcpListener) -> Egress {
    Egress::Upstream(Arc::new(upstream::Upstream::new(
        listener.local_addr().unwrap().to_string(),
        None,
    )))
}

/// Real handle_client, not parser coverage. Bypassing either policy or auth
/// creates a queued upstream connection and makes the final poll fail.
#[tokio::test]
async fn http_auth_and_onion_refusals_never_dial_upstream() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let enabled = Arc::new(onion_state("alice", true, false));
    let disabled = Arc::new(onion_state("alice", false, true));
    // alice:pw and alice:wrong are public test credentials.
    for (auth, block, target, header, status, authentication) in [
        (
            Some(enabled.clone()),
            false,
            "example.com:443",
            "",
            407,
            true,
        ),
        (
            Some(enabled.clone()),
            false,
            "example.com:443",
            "Proxy-Authorization: Basic YWxpY2U6d3Jvbmc=\r\n",
            407,
            true,
        ),
        (
            Some(disabled),
            false,
            "example.com:443",
            "Proxy-Authorization: Basic YWxpY2U6cHc=\r\n",
            407,
            true,
        ),
        (
            None,
            false,
            "example.com:443",
            "Proxy-Authorization: Basic YWxpY2U6cHc=\r\n",
            407,
            true,
        ),
        (None, true, "example.ONION.:443", "", 403, false),
        (
            Some(enabled),
            false,
            "example.ONION.:443",
            "Proxy-Authorization: Basic YWxpY2U6cHc=\r\n",
            403,
            false,
        ),
    ] {
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        client
            .write_all(format!("CONNECT {target} HTTP/1.1\r\n{header}\r\n").as_bytes())
            .await
            .unwrap();
        // Complete before inspecting the still-open upstream listener. A bypass
        // would stall in setup and hit this safety bound instead of passing.
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            handle_client(
                server,
                test_egress(&upstream),
                auth,
                ConnHealthCounters::default(),
                block,
                1,
            ),
        )
        .await
        .expect("refusal must complete without egress");
        if authentication {
            let error = result.unwrap_err();
            assert!(
                matches!(
                    error.downcast_ref::<ServerError>(),
                    Some(ServerError::Authentication(_))
                ),
                "{error:?}"
            );
        } else {
            result.unwrap();
        }
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(
            response.starts_with(format!("HTTP/1.1 {status} ").as_bytes()),
            "{response:?}"
        );
        assert_no_upstream_connection(&upstream).await;
    }
}

/// Both protocols traverse the very same bound listener and real SOCKS upstream
/// to a real egress socket. Removing prefix forwarding loses binary bytes;
/// replaying it duplicates them; replying before egress bypasses the ready gate.
#[tokio::test]
async fn same_listener_http_and_socks_wait_for_egress_and_relay_exactly_once() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        for http in [true, false] {
            let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let destination = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target = destination.local_addr().unwrap();
            let egress = test_egress(&upstream_listener);
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = tokio::sync::oneshot::channel();
            let upstream = tokio::spawn(async move {
                let (mut socket, _) = upstream_listener.accept().await.unwrap();
                let mut head = [0; 2];
                socket.read_exact(&mut head).await.unwrap();
                assert_eq!(head[0], 5);
                let mut methods = vec![0; usize::from(head[1])];
                socket.read_exact(&mut methods).await.unwrap();
                assert!(methods.contains(&0));
                socket.write_all(&[5, 0]).await.unwrap();
                let mut request = [0; 10];
                socket.read_exact(&mut request).await.unwrap();
                assert_eq!(&request[..8], &[5, 1, 0, 1, 127, 0, 0, 1]);
                assert_eq!(u16::from_be_bytes([request[8], request[9]]), target.port());
                ready_tx.send(()).unwrap();
                release_rx.await.unwrap();
                let mut remote = TcpStream::connect(target).await.unwrap();
                socket
                    .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
                tokio::io::copy_bidirectional(&mut socket, &mut remote)
                    .await
                    .unwrap();
            });
            let mut client = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (server, _) = listener.accept().await.unwrap();
            let prefix = b"\x00\xff\r\n\x80prefix";
            let later = b"later\x00\xfe";
            let mut input = if http {
                format!("CONNECT {target} HTTP/1.1\r\n\r\n").into_bytes()
            } else {
                vec![
                    5,
                    1,
                    0,
                    5,
                    1,
                    0,
                    1,
                    127,
                    0,
                    0,
                    1,
                    (target.port() >> 8) as u8,
                    target.port() as u8,
                ]
            };
            input.extend_from_slice(prefix);
            client.write_all(&input).await.unwrap();
            if http {
                let mut queued = vec![0; input.len()];
                loop {
                    let n = server.peek(&mut queued).await.unwrap();
                    assert_ne!(n, 0, "client closed before queuing HTTP pipeline");
                    if n == input.len() {
                        assert_eq!(queued, input);
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            }
            let handler = tokio::spawn(handle_client(
                server,
                egress,
                None,
                ConnHealthCounters::default(),
                false,
                1,
            ));
            if !http {
                let mut method = [0; 2];
                client.read_exact(&mut method).await.unwrap();
                assert_eq!(method, [5, 0]);
            }
            ready_rx.await.unwrap();
            // Upstream CONNECT is parsed but no egress has been dialed or REP
            // sent. The closed readiness gate makes this a bounded negative I/O check.
            let mut byte = [0];
            assert!(
                tokio::time::timeout(Duration::from_secs(1), client.read(&mut byte))
                    .await
                    .is_err(),
                "no response while the egress readiness gate is held"
            );
            assert_no_upstream_connection(&destination).await;
            release_tx.send(()).unwrap();
            let (mut remote, _) = destination.accept().await.unwrap();
            if http {
                let expected = b"HTTP/1.1 200 Connection Established\r\n\r\n";
                let mut response = vec![0; expected.len()];
                client.read_exact(&mut response).await.unwrap();
                assert_eq!(response, expected);
            } else {
                let mut response = [0; 10];
                client.read_exact(&mut response).await.unwrap();
                assert_eq!(response, [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
            }
            client.write_all(later).await.unwrap();
            client.shutdown().await.unwrap();
            let mut received = Vec::new();
            remote.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, [prefix.as_slice(), later.as_slice()].concat());
            remote.write_all(b"egress-response\x00\xff").await.unwrap();
            remote.shutdown().await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"egress-response\x00\xff");
            handler.await.unwrap().unwrap();
            upstream.await.unwrap();
        }
    })
    .await
    .expect("same-port relay must finish");
}

#[tokio::test]
async fn egress_rejection_uses_general_failure_rep1_without_success_or_payload_replay() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        for http in [true, false] {
            let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let egress = test_egress(&upstream_listener);
            let upstream = tokio::spawn(async move {
                let (mut socket, _) = upstream_listener.accept().await.unwrap();
                let mut head = [0; 2];
                socket.read_exact(&mut head).await.unwrap();
                let mut methods = vec![0; usize::from(head[1])];
                socket.read_exact(&mut methods).await.unwrap();
                socket.write_all(&[5, 0]).await.unwrap();
                let mut request = [0; 10];
                socket.read_exact(&mut request).await.unwrap();
                socket
                    .write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
                let mut payload = Vec::new();
                // Rejecting the four-byte reply header leaves its address unread;
                // closing that client socket may produce a reset rather than FIN.
                let closure = socket.read_to_end(&mut payload).await;
                assert!(
                    closure.is_ok()
                        || matches!(&closure, Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset),
                    "unexpected upstream close: {closure:?}"
                );
                assert!(payload.is_empty(), "failed setup must not receive payload");
            });
            let mut client = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (server, _) = listener.accept().await.unwrap();
            let input: &[u8] = if http {
                b"CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n\x00\xffpayload"
            } else {
                &[5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, 1, 187]
            };
            client.write_all(input).await.unwrap();
            let error = handle_client(
                server,
                egress,
                None,
                ConnHealthCounters::default(),
                false,
                1,
            )
            .await
            .unwrap_err();
            assert_eq!(
                classify_conn_failure(&error),
                (ConnStage::Connect, ConnErrorKind::Other)
            );
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            if http {
                assert!(response.starts_with(b"HTTP/1.1 502 "), "{response:?}");
            } else {
                assert_eq!(response, [5, 0, 5, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
            }
            upstream.await.unwrap();
        }
    })
    .await
    .expect("egress refusal must finish");
}

#[tokio::test(start_paused = true)]
async fn handle_client_silent_and_partial_socks_deadlines_are_typed() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    for input in [b"".as_slice(), b"\x05".as_slice()] {
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        client.write_all(input).await.unwrap();
        let mut handler = Box::pin(handle_client(
            server,
            test_egress(&upstream),
            None,
            ConnHealthCounters::default(),
            false,
            1,
        ));
        assert!(
            std::future::poll_fn(|cx| {
                std::task::Poll::Ready(handler.as_mut().poll(cx).is_pending())
            })
            .await
        );
        tokio::time::advance(HANDSHAKE_DEADLINE).await;
        let error = handler.await.unwrap_err();
        assert!(
            matches!(
                error.downcast_ref::<ServerError>(),
                Some(ServerError::Deadline)
            ),
            "{error:?}"
        );
        assert_eq!(
            classify_conn_failure(&error),
            (ConnStage::Handshake, ConnErrorKind::Client)
        );
        assert_no_upstream_connection(&upstream).await;
    }
}

#[tokio::test(start_paused = true)]
async fn handle_client_partial_http_deadline_is_typed_and_terminal() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    client
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n")
        .await
        .unwrap();
    let deadline = tokio::time::Instant::now() + HANDSHAKE_DEADLINE;
    let mut handler = Box::pin(handle_client(
        server,
        test_egress(&upstream),
        None,
        ConnHealthCounters::default(),
        false,
        1,
    ));
    assert!(
        std::future::poll_fn(|cx| std::task::Poll::Ready(handler.as_mut().poll(cx).is_pending()))
            .await
    );
    tokio::time::advance(HANDSHAKE_DEADLINE - Duration::from_secs(1)).await;
    client.write_all(b"X-Trickle: yes\r\n").await.unwrap();
    assert!(
        std::future::poll_fn(|cx| std::task::Poll::Ready(handler.as_mut().poll(cx).is_pending()))
            .await
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    let error = handler.await.unwrap_err();
    assert!(
        matches!(
            error.downcast_ref::<ServerError>(),
            Some(ServerError::Deadline)
        ),
        "{error:?}"
    );
    assert_eq!(tokio::time::Instant::now(), deadline);
    assert_eq!(
        classify_conn_failure(&error),
        (ConnStage::Handshake, ConnErrorKind::Client)
    );
    assert_no_upstream_connection(&upstream).await;
}

// Реальный registry нужен для проверки публикации между стадиями handshake.
fn persistent_state(
    post: Option<proxy_config::EndpointOverride>,
) -> (
    tempfile::TempDir,
    std::path::PathBuf,
    Arc<AuthState>,
    UsersConfig,
) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("users.ktav");
    let users = UsersConfig {
        users: vec![auth::User {
            name: "alice".into(),
            hash: auth::compute_hash("pw").unwrap(),
            is_enabled: true,
            allowed_onion: false,
            allowed_clients: None,
            pre_socks5: None,
            post_socks5: post,
        }],
    };
    users.save(&path).unwrap();
    let state = Arc::new(AuthState::build_persistent(&users, path.clone()).unwrap());
    (dir, path, state, users)
}

/// cancel-safe: NO — частичный handshake требует закрыть сокет.
async fn socks_auth(client: &mut TcpStream, password: &[u8]) {
    client.write_all(&[5, 1, 2]).await.unwrap();
    let mut response = [0; 2];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [5, 2]);
    let mut auth = vec![1, 5, b'a', b'l', b'i', b'c', b'e', password.len() as u8];
    auth.extend_from_slice(password);
    client.write_all(&auth).await.unwrap();
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [1, 0]);
}

/// cancel-safe: NO — блокирующая публикация продолжается после отмены.
async fn reload(state: Arc<AuthState>) {
    tokio::task::spawn_blocking(move || state.reload())
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn stale_rfc1929_proof_is_refused_before_any_dial() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (_dir, path, state, mut users) = persistent_state(None);
        let incoming = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(incoming.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = incoming.accept().await.unwrap();
        let handler = tokio::spawn(handle_client(
            server,
            test_egress(&upstream),
            Some(state.clone()),
            ConnHealthCounters::default(),
            false,
            1,
        ));
        socks_auth(&mut client, b"pw").await;
        users.users[0].allowed_onion = true;
        users.save(&path).unwrap();
        reload(state).await;
        client
            .write_all(&[5, 1, 0, 1, 1, 2, 3, 4, 0, 80])
            .await
            .unwrap();
        let mut reply = [0; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply[..2], &[5, 2]);
        handler.await.unwrap().unwrap();
        assert_no_upstream_connection(&upstream).await;
    })
    .await
    .expect("stale proof test timed out");
}

#[tokio::test]
async fn malformed_authenticated_connect_never_dials() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (_dir, _path, state, _users) = persistent_state(None);
        let incoming = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(incoming.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = incoming.accept().await.unwrap();
        let handler = tokio::spawn(handle_client(
            server,
            test_egress(&upstream),
            Some(state),
            ConnHealthCounters::default(),
            false,
            1,
        ));
        socks_auth(&mut client, b"pw").await;
        client.write_all(&[5, 1, 0, 0xff]).await.unwrap();
        client.shutdown().await.unwrap();
        assert!(handler.await.unwrap().is_err());
        assert_no_upstream_connection(&upstream).await;
    })
    .await
    .expect("malformed request test timed out");
}

#[tokio::test]
async fn lease_blocks_reload_until_upstream_connect_is_cancelled() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (_dir, path, state, mut users) = persistent_state(None);
        let proof = state.verify_proof("alice", "pw").unwrap();
        let incoming = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(incoming.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = incoming.accept().await.unwrap();
        let handler = tokio::spawn(handle_client(
            server,
            test_egress(&upstream),
            Some(state.clone()),
            ConnHealthCounters::default(),
            false,
            1,
        ));
        socks_auth(&mut client, b"pw").await;
        client
            .write_all(&[5, 1, 0, 1, 1, 2, 3, 4, 0, 80])
            .await
            .unwrap();
        let (mut parked, _) = upstream.accept().await.unwrap();
        let mut greeting = [0; 2];
        parked.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting[0], 5);
        let mut methods = vec![0; usize::from(greeting[1])];
        parked.read_exact(&mut methods).await.unwrap();
        users.users[0].allowed_onion = true;
        users.save(&path).unwrap();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let reload_state = state.clone();
        let publication = tokio::task::spawn_blocking(move || {
            let _ = started_tx.send(());
            reload_state.reload()
        });
        started_rx.await.unwrap();
        // Pending нового читателя означает, что writer уже в очереди gate.
        loop {
            let mut admission = Box::pin(state.admit(&proof));
            let queued = std::future::poll_fn(|cx| {
                std::task::Poll::Ready(match admission.as_mut().poll(cx) {
                    std::task::Poll::Pending => true,
                    std::task::Poll::Ready(Some(lease)) => {
                        drop(lease);
                        false
                    }
                    std::task::Poll::Ready(None) => panic!("proof устарел до освобождения lease"),
                })
            })
            .await;
            drop(admission);
            if queued {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(!publication.is_finished());
        handler.abort();
        assert!(handler.await.unwrap_err().is_cancelled());
        publication.await.unwrap().unwrap();
        assert!(state.admit(&proof).await.is_none());
    })
    .await
    .expect("lease cancellation test timed out");
}

// Проверяет общий resolver после настоящего handshake, без подмены Tor.
#[tokio::test]
async fn verified_handshakes_resolve_admitted_post_independently() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for http in [true, false] {
            for mode in 0..3 {
                let global = proxy_config::EndpointOverride::Endpoint("127.0.0.1:1080".parse().unwrap());
                let account = proxy_config::EndpointOverride::Endpoint("127.0.0.1:1081".parse().unwrap());
                let override_value = match mode { 0 => None, 1 => Some(account.clone()), _ => Some(proxy_config::EndpointOverride::Disabled) };
                let (_dir, _path, state, _users) = persistent_state(override_value);
                let incoming = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let mut client = TcpStream::connect(incoming.local_addr().unwrap()).await.unwrap();
                let (mut server, _) = incoming.accept().await.unwrap();
                let verifier = Arc::new(AuthStateVerifier(state.clone()));
                let handshake = tokio::spawn(async move {
                    socks5_proto::accept_verified(&mut server, tokio::time::Instant::now() + HANDSHAKE_DEADLINE, Some(verifier)).await.unwrap().into_parts()
                });
                if http {
                    client.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic YWxpY2U6cHc=\r\n\r\n").await.unwrap();
                } else {
                    socks_auth(&mut client, b"pw").await;
                    client.write_all(&[5, 1, 0, 1, 1, 2, 3, 4, 0, 80]).await.unwrap();
                }
                let (_request, proof) = handshake.await.unwrap();
                let lease = state.admit(&proof.unwrap()).await.unwrap();
                let selected = resolve_admitted_route(None, Some(&global), Some(&lease), false, false).unwrap();
                assert_eq!(selected.post, match mode { 0 => Some(global), 1 => Some(account), _ => None });
            }
        }
    }).await.expect("route admission test timed out");
}

#[tokio::test]
async fn wrong_socks_password_never_dials() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (_dir, _path, state, _users) = persistent_state(None);
        let incoming = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(incoming.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = incoming.accept().await.unwrap();
        let handler = tokio::spawn(handle_client(
            server,
            test_egress(&upstream),
            Some(state),
            ConnHealthCounters::default(),
            false,
            1,
        ));
        client.write_all(&[5, 1, 2]).await.unwrap();
        let mut reply = [0; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 2]);
        client.write_all(b"\x01\x05alice\x05wrong").await.unwrap();
        client.read_exact(&mut reply).await.unwrap();
        assert_ne!(reply[1], 0);
        assert!(handler.await.unwrap().is_err());
        assert_no_upstream_connection(&upstream).await;
    })
    .await
    .expect("wrong password test timed out");
}

struct ParkedTorConnector {
    observed:
        Option<tokio::sync::oneshot::Sender<(Option<proxy_config::EndpointOverride>, String, u16)>>,
    release: Option<tokio::sync::oneshot::Receiver<()>>,
    calls: Arc<AtomicUsize>,
}

impl TorConnector for ParkedTorConnector {
    /// cancel-safe: NO — отмена отбрасывает ожидающий oneshot без повтора.
    async fn connect<'a>(
        &'a mut self,
        _tor: &'a TorTunnel,
        post: Option<&'a proxy_config::EndpointOverride>,
        host: &'a str,
        port: u16,
    ) -> arti_wrapper::Result<arti_wrapper::DataStream> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.observed
            .take()
            .unwrap()
            .send((post.cloned(), host.to_owned(), port))
            .unwrap();
        self.release.take().unwrap().await.unwrap();
        Err(arti_wrapper::TorError::PostSocks(
            socks5_proto::client::Error::InvalidInput,
        ))
    }
}

// При панике или таймауте задача не остаётся отсоединённой.
struct AbortHandler(tokio::task::JoinHandle<Result<()>>);
impl Drop for AbortHandler {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// cancel-safe: yes — отмена удаляет ожидающего читателя из очереди.
async fn observe_queued_writer(state: &AuthState, proof: &auth::CredentialProof) {
    loop {
        let mut admission = Box::pin(state.admit(proof));
        let queued = std::future::poll_fn(|cx| {
            std::task::Poll::Ready(match admission.as_mut().poll(cx) {
                std::task::Poll::Pending => true,
                std::task::Poll::Ready(Some(lease)) => {
                    drop(lease);
                    false
                }
                std::task::Poll::Ready(None) => panic!("proof устарел до освобождения lease"),
            })
        })
        .await;
        drop(admission);
        if queued {
            break;
        }
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn tor_handler_enforces_global_pre_before_connector_after_reload() {
    tokio::time::timeout(Duration::from_secs(60), async {
        ensure_crypto_provider();
        let tor_dir = tempfile::tempdir().unwrap();
        let tor = TorHandle::new(TorTunnel::create_unbootstrapped_with(arti_wrapper::Settings {
            state_dir: Some(tor_dir.path().to_path_buf()),
            ..Default::default()
        }).unwrap());
        let pre = proxy_config::EndpointOverride::Endpoint("127.0.0.1:1080|alice:secret".parse().unwrap());
        let other = proxy_config::EndpointOverride::Endpoint("127.0.0.1:1080|alice:other".parse().unwrap());
        let global_post = proxy_config::EndpointOverride::Endpoint("127.0.0.1:1082".parse().unwrap());
        let account_post = proxy_config::EndpointOverride::Endpoint("127.0.0.1:1083".parse().unwrap());
        for http in [false, true] {
            for mode in 0..4 {
                for after_reload in [false, true] {
                    let account_pre = match mode {
                        0 => None,
                        1 => Some(pre.clone()),
                        2 => Some(other.clone()),
                        _ => Some(proxy_config::EndpointOverride::Disabled),
                    };
                    let post = if mode == 1 { Some(account_post.clone()) } else { None };
                    let (_dir, path, state, mut users) = persistent_state(post);
                    users.users[0].pre_socks5 = account_pre;
                    users.save(&path).unwrap();
                    let state = if after_reload {
                        reload(state.clone()).await;
                        state
                    } else {
                        Arc::new(AuthState::build_persistent(&users, path).unwrap())
                    };
                    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let mut client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
                    let (server, _) = listener.accept().await.unwrap();
                    let (observed_tx, observed_rx) = tokio::sync::oneshot::channel();
                    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
                    let calls = Arc::new(AtomicUsize::new(0));
                    let connector = ParkedTorConnector { observed: Some(observed_tx), release: Some(release_rx), calls: calls.clone() };
                    let mut handler = AbortHandler(tokio::spawn(handle_client_with_connector(
                        server, Egress::Tor(tor.clone(), Some(Arc::new(pre.clone())), Some(Arc::new(global_post.clone())), false, None),
                        Some(state), ConnHealthCounters::default(), false, 1, connector,
                    )));
                    if http {
                        client.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic YWxpY2U6cHc=\r\n\r\n").await.unwrap();
                    } else {
                        socks_auth(&mut client, b"pw").await;
                        client.write_all(&[5, 1, 0, 1, 1, 2, 3, 4, 0, 80]).await.unwrap();
                    }
                    if mode < 2 {
                        let (post, host, port) = observed_rx.await.unwrap();
                        assert_eq!(post, Some(if mode == 0 { global_post.clone() } else { account_post.clone() }));
                        assert_eq!((host.as_str(), port), if http { ("example.com", 443) } else { ("1.2.3.4", 80) });
                        release_tx.send(()).unwrap();
                        let error = (&mut handler.0).await.unwrap().unwrap_err();
                        assert!(matches!(error.downcast_ref::<arti_wrapper::TorError>(), Some(arti_wrapper::TorError::PostSocks(socks5_proto::client::Error::InvalidInput))));
                        assert_eq!(calls.load(Ordering::SeqCst), 1);
                    } else {
                        (&mut handler.0).await.unwrap().unwrap();
                        assert!(observed_rx.await.is_err());
                        assert_eq!(calls.load(Ordering::SeqCst), 0);
                        let mut response = Vec::new();
                        client.read_to_end(&mut response).await.unwrap();
                        if http { assert!(response.starts_with(b"HTTP/1.1 403 "), "{response:?}"); }
                        else { assert_eq!(response, [5, 2, 0, 1, 0, 0, 0, 0, 0, 0]); }
                    }
                }
            }
        }
    }).await.expect("global pre handler regression timed out");
}

// Проверяется граница ошибки, а не успешный Tor-поток или e2e.
#[tokio::test]
async fn tor_handler_routes_and_releases_admission_on_error_or_cancel() {
    tokio::time::timeout(Duration::from_secs(60), async {
        ensure_crypto_provider();
        let tor_dir = tempfile::tempdir().unwrap();
        let tor = TorTunnel::create_unbootstrapped_with(arti_wrapper::Settings {
            state_dir: Some(tor_dir.path().to_path_buf()),
            ..Default::default()
        }).unwrap();
        let tor = TorHandle::new(tor);
        for http in [false, true] {
            for mode in 0..3 {
                for cancel in [false, true] {
                    let global = proxy_config::EndpointOverride::Endpoint("127.0.0.1:1080".parse().unwrap());
                    let account = proxy_config::EndpointOverride::Endpoint("127.0.0.1:1081".parse().unwrap());
                    let override_value = match mode {
                        0 => None,
                        1 => Some(account.clone()),
                        _ => Some(proxy_config::EndpointOverride::Disabled),
                    };
                    let expected = match mode { 0 => Some(global.clone()), 1 => Some(account), _ => None };
                    let (_dir, path, state, mut users) = persistent_state(override_value);
                    let proof = state.verify_proof("alice", "pw").unwrap();
                    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let mut client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
                    let (server, _) = listener.accept().await.unwrap();
                    let (observed_tx, observed_rx) = tokio::sync::oneshot::channel();
                    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
                    let calls = Arc::new(AtomicUsize::new(0));
                    let connector = ParkedTorConnector { observed: Some(observed_tx), release: Some(release_rx), calls: calls.clone() };
                    let mut handler = AbortHandler(tokio::spawn(handle_client_with_connector(
                        server, Egress::Tor(tor.clone(), None, Some(Arc::new(global)), false, None),
                        Some(state.clone()), ConnHealthCounters::default(), false, 1, connector,
                    )));
                    if http {
                        client.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic YWxpY2U6cHc=\r\n\r\n").await.unwrap();
                    } else {
                        socks_auth(&mut client, b"pw").await;
                        client.write_all(&[5, 1, 0, 1, 1, 2, 3, 4, 0, 80]).await.unwrap();
                    }
                    let (route, host, port) = observed_rx.await.unwrap();
                    assert_eq!(route, expected);
                    assert_eq!((host.as_str(), port), if http { ("example.com", 443) } else { ("1.2.3.4", 80) });
                    users.users[0].allowed_onion = true;
                    users.save(&path).unwrap();
                    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
                    let reload_state = state.clone();
                    let publication = tokio::task::spawn_blocking(move || {
                        // При отмене теста наблюдатель больше не нужен.
                        let _ = started_tx.send(());
                        reload_state.reload()
                    });
                    started_rx.await.unwrap();
                    observe_queued_writer(&state, &proof).await;
                    assert!(!publication.is_finished());
                    if cancel {
                        handler.0.abort();
                        assert!((&mut handler.0).await.unwrap_err().is_cancelled());
                    } else {
                        release_tx.send(()).unwrap();
                        let error = (&mut handler.0).await.unwrap().unwrap_err();
                        assert_eq!(classify_conn_failure(&error), (ConnStage::Connect, ConnErrorKind::Other));
                        assert!(matches!(error.downcast_ref::<arti_wrapper::TorError>(), Some(arti_wrapper::TorError::PostSocks(socks5_proto::client::Error::InvalidInput))));
                        let mut response = Vec::new();
                        client.read_to_end(&mut response).await.unwrap();
                        if http { assert!(response.starts_with(b"HTTP/1.1 502 "), "{response:?}"); }
                        else { assert_eq!(response, [5, 1, 0, 1, 0, 0, 0, 0, 0, 0]); }
                    }
                    publication.await.unwrap().unwrap();
                    assert!(state.admit(&proof).await.is_none());
                    assert_eq!(calls.load(Ordering::SeqCst), 1);
                }
            }
        }
    }).await.expect("Tor route regression timed out");
}
