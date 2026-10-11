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
