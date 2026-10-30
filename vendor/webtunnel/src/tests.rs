use super::*;
use base64::Engine;
use ptrs::ClientBuilder;
use std::future::Future;
use std::sync::Arc;
use tokio::net::TcpStream;

#[test]
fn release_ipv6_targets_have_unbracketed_socket_hosts() {
    let from_url =
        WebTunnelConfig::from_args(&make_args(&[("url", "https://[::1]:8443/path")])).unwrap();
    assert_eq!(
        from_url.connect_host_and_port().unwrap(),
        ("::1".into(), 8443)
    );
    assert_eq!(from_url.tls_sni().unwrap(), "::1");
    let from_addr = WebTunnelConfig::from_args(&make_args(&[
        ("url", "https://example.com/path"),
        ("addr", "[::1]:8443"),
    ]))
    .unwrap();
    assert_eq!(
        from_addr.connect_host_and_port().unwrap(),
        ("::1".into(), 8443)
    );
}

#[test]
fn release_host_header_preserves_nondefault_port_and_ipv6_brackets() {
    for (url, host) in [
        ("https://example.com:8443/path", "example.com:8443"),
        ("http://[::1]:8080/path", "[::1]:8080"),
    ] {
        let config = WebTunnelConfig::from_args(&make_args(&[("url", url)])).unwrap();
        assert!(handshake::build_upgrade_request(&config).contains(&format!("Host: {host}\r\n")));
    }
}

#[test]
fn release_non_http_urls_are_rejected() {
    assert!(WebTunnelConfig::from_args(&make_args(&[("url", "ftp://example.com/path")])).is_err());
}

#[test]
fn release_invalid_servername_cannot_inject_an_http_header() {
    assert!(WebTunnelConfig::from_args(&make_args(&[
        ("url", "https://example.com/path"),
        ("servername", "example.com\r\nX-Injected: true"),
    ]))
    .is_err());
}

#[tokio::test]
async fn release_builder_timeout_closes_a_stalled_upgrade_socket() {
    use tokio::io::AsyncReadExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/path", listener.local_addr().unwrap());
    let mut builder = WebTunnelBuilder::default();
    <WebTunnelBuilder as ClientBuilder<TcpStream>>::options(
        &mut builder,
        &make_args(&[("url", &url), ("doh-mode", "off")]),
    )
    .unwrap();
    <WebTunnelBuilder as ClientBuilder<TcpStream>>::timeout(
        &mut builder,
        Some(Duration::from_secs(10)),
    )
    .unwrap();
    let client = <WebTunnelBuilder as ClientBuilder<TcpStream>>::build(&builder);
    let mut connection = Box::pin(client.connect_url());
    let (mut peer, _) = tokio::select! {
        _ = &mut connection => panic!("handshake ended before TCP accept"),
        accepted = listener.accept() => accepted.unwrap(),
    };
    let request = async {
        let mut byte = [0u8; 1];
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            peer.read_exact(&mut byte).await.unwrap();
            request.push(byte[0]);
        }
    };
    tokio::select! {
        _ = &mut connection => panic!("handshake ended before Upgrade request"),
        _ = request => {},
    }
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(11)).await;
    let result =
        std::future::poll_fn(|cx| std::task::Poll::Ready(connection.as_mut().poll(cx))).await;
    assert!(
        matches!(result, std::task::Poll::Ready(Err(Error::Io(ref error))) if error.kind() == io::ErrorKind::TimedOut)
    );
    tokio::time::resume();
    let mut byte = [0u8; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), peer.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

fn make_args(pairs: &[(&str, &str)]) -> Args {
    let mut args = Args::new();
    for (k, v) in pairs {
        args.add(k, v);
    }
    args
}

// -- Config parsing tests -------------------------------------------------

#[test]
fn webtunnel_config_from_bridge_args() {
    let args = make_args(&[
        ("url", "https://example.com/secretRoute"),
        ("ver", "0.0.3"),
        ("servername", "cdn.example.com"),
    ]);
    let cfg = WebTunnelConfig::from_args(&args).unwrap();
    assert_eq!(cfg.url, "https://example.com/secretRoute");
    assert_eq!(cfg.version.as_deref(), Some("0.0.3"));
    assert_eq!(cfg.servername.as_deref(), Some("cdn.example.com"));
    assert!(cfg.tcp_addr.is_none());
}

#[test]
fn config_missing_url_is_error() {
    let args = make_args(&[("ver", "0.0.3")]);
    let err = WebTunnelConfig::from_args(&args).unwrap_err();
    assert!(matches!(err, Error::MissingUrl));
}

#[test]
fn config_servername_falls_back_to_url_host() {
    let args = make_args(&[("url", "https://myhost.example.com:443/path")]);
    let cfg = WebTunnelConfig::from_args(&args).unwrap();
    assert_eq!(cfg.tls_sni().unwrap(), "myhost.example.com");
}

#[test]
fn config_addr_overrides_url_host_port() {
    let args = make_args(&[
        ("url", "https://example.com/secret"),
        ("addr", "1.2.3.4:8443"),
    ]);
    let cfg = WebTunnelConfig::from_args(&args).unwrap();
    assert_eq!(cfg.connect_host_port().unwrap(), "1.2.3.4:8443");
}

#[test]
fn config_connect_host_port_defaults_to_url() {
    let args = make_args(&[("url", "https://example.com:443/secret")]);
    let cfg = WebTunnelConfig::from_args(&args).unwrap();
    assert_eq!(cfg.connect_host_port().unwrap(), "example.com:443");
}

#[test]
fn config_ignores_utls_param() {
    let args = make_args(&[("url", "https://example.com/secret"), ("utls", "chrome")]);
    let cfg = WebTunnelConfig::from_args(&args).unwrap();
    // utls is not stored; config should succeed.
    assert_eq!(cfg.url, "https://example.com/secret");
}

#[test]
fn config_http_scheme_means_no_tls() {
    let args = make_args(&[("url", "http://example.com:80/secret")]);
    let cfg = WebTunnelConfig::from_args(&args).unwrap();
    assert!(!cfg.use_tls());
}

#[test]
fn config_https_scheme_means_tls() {
    let args = make_args(&[("url", "https://example.com:443/secret")]);
    let cfg = WebTunnelConfig::from_args(&args).unwrap();
    assert!(cfg.use_tls());
}

// -- HTTP request construction tests --------------------------------------

#[test]
fn request_line_contains_path_from_url() {
    let cfg = WebTunnelConfig::from_args(&make_args(&[("url", "https://example.com/secretRoute")]))
        .unwrap();
    let req = handshake::build_upgrade_request(&cfg);
    assert!(req.starts_with("GET /secretRoute HTTP/1.1\r\n"));
}

#[test]
fn host_header_uses_url_hostname() {
    let cfg = WebTunnelConfig::from_args(&make_args(&[("url", "https://myhost.example.com/path")]))
        .unwrap();
    let req = handshake::build_upgrade_request(&cfg);
    assert!(req.contains("Host: myhost.example.com\r\n"));
}

#[test]
fn host_header_uses_servername_when_set() {
    let cfg = WebTunnelConfig::from_args(&make_args(&[
        ("url", "https://real.example.com/path"),
        ("servername", "front.example.com"),
    ]))
    .unwrap();
    let req = handshake::build_upgrade_request(&cfg);
    assert!(req.contains("Host: front.example.com\r\n"));
}

#[test]
fn request_includes_websocket_headers() {
    let cfg =
        WebTunnelConfig::from_args(&make_args(&[("url", "https://example.com/path")])).unwrap();
    let req = handshake::build_upgrade_request(&cfg);
    assert!(req.contains("Upgrade: websocket\r\n"));
    assert!(req.contains("Connection: Upgrade\r\n"));
    assert!(req.contains("Sec-WebSocket-Version: 13\r\n"));
}

// -- Sec-WebSocket-Key generation tests -----------------------------------

#[test]
fn sec_websocket_key_is_valid_base64_of_16_bytes() {
    let key_b64 = handshake::generate_websocket_key();
    let engine = base64::engine::general_purpose::STANDARD;
    let decoded = engine.decode(&key_b64).expect("key must be valid base64");
    assert_eq!(decoded.len(), 16, "key must decode to exactly 16 bytes");
    // 16 bytes base64-encoded → 24 chars (no padding).
    assert_eq!(key_b64.len(), 24);
}

#[test]
fn sec_websocket_key_differs_across_calls() {
    let k1 = handshake::generate_websocket_key();
    let k2 = handshake::generate_websocket_key();
    // Not guaranteed by the type system but overwhelmingly likely
    // with 128 bits of randomness.
    assert_ne!(k1, k2, "two generated keys should differ");
}

// -- HTTP response parsing tests ------------------------------------------

#[test]
fn parse_101_response() {
    let response =
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
    let (status, _leftover) = handshake::parse_response(response).unwrap();
    assert_eq!(status, 101);
    assert!(status != 0);
}

#[test]
fn parse_101_with_trailing_body_bytes() {
    let response = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n\xAB\xCD\xEF";
    let (status, leftover) = handshake::parse_response(response).unwrap();
    assert_eq!(status, 101);
    assert_eq!(leftover, b"\xAB\xCD\xEF");
}

#[test]
fn parse_101_with_sec_websocket_accept() {
    let response = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    let (status, _leftover) = handshake::parse_response(response).unwrap();
    assert_eq!(status, 101);
}

#[test]
fn parse_non_101_rejects() {
    let response = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
    let err = handshake::parse_response(response).unwrap_err();
    assert!(
        matches!(err, Error::Non101(ref msg) if msg.contains("404")),
        "expected Non101 error, got {err:?}"
    );
}

#[test]
fn parse_empty_response_is_error() {
    let response = b"";
    let err = handshake::parse_response(response).unwrap_err();
    assert!(matches!(err, Error::HttpParse(_)));
}

// -- Builder trait tests --------------------------------------------------

#[test]
fn builder_method_name() {
    assert_eq!(
        <WebTunnelBuilder as ClientBuilder<TcpStream>>::method_name(),
        "webtunnel"
    );
}

#[test]
fn persistent_state_setter_reports_unsupported() {
    let mut builder = WebTunnelBuilder::default();
    assert!(matches!(
        <WebTunnelBuilder as ClientBuilder<TcpStream>>::statefile_location(&mut builder, "state"),
        Err(Error::Unsupported(_))
    ));
}

#[test]
fn builder_rejects_missing_url() {
    let mut builder = WebTunnelBuilder::default();
    let args = Args::new();
    let result = <WebTunnelBuilder as ptrs::ClientBuilder<TcpStream>>::options(&mut builder, &args);
    assert!(result.is_err());
}

#[tokio::test]
async fn build_without_options_fails_gracefully_on_wrap() {
    // The `ClientBuilder` trait requires an infallible `build`. Building an
    // un-configured builder must NOT panic; the missing config has to
    // surface as a typed error at connect time. (On the previous code
    // path `build` called `.expect(..)` and this test would panic.)
    let builder = WebTunnelBuilder::default();
    let client =
        <WebTunnelBuilder as ptrs::ClientBuilder<tokio::io::DuplexStream>>::build(&builder);

    // `wrap` drops its socket argument before checking config, so the
    // duplex stream is never driven and no network access occurs.
    let (a, b) = tokio::io::duplex(64);
    drop(a);
    let result =
        <WebTunnelClient as ptrs::ClientTransport<tokio::io::DuplexStream, io::Error>>::wrap(
            client, b,
        )
        .await;

    assert!(matches!(result, Err(Error::MissingUrl)));
}

#[tokio::test]
async fn wrap_uses_supplied_carrier_for_upgrade_and_payload() {
    use ptrs::ClientTransport;

    let mut builder = WebTunnelBuilder::default();
    <WebTunnelBuilder as ClientBuilder<tokio::io::DuplexStream>>::options(
        &mut builder,
        &make_args(&[("url", "http://example.invalid/path")]),
    )
    .unwrap();
    let client = <WebTunnelBuilder as ClientBuilder<tokio::io::DuplexStream>>::build(&builder);
    let (mut server, carrier) = tokio::io::duplex(4096);
    let server_task = tokio::spawn(async move {
        let mut request = Vec::new();
        let mut byte = [0u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            server.read_exact(&mut byte).await.unwrap();
            request.push(byte[0]);
        }
        assert!(request.starts_with(b"GET /path HTTP/1.1\r\n"));
        server
            .write_all(b"HTTP/1.1 101 Switching Protocols\r\n\r\nreply")
            .await
            .unwrap();
        let mut payload = [0u8; 7];
        server.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"request");
    });

    let mut stream = tokio::time::timeout(
        Duration::from_secs(2),
        <WebTunnelClient as ClientTransport<tokio::io::DuplexStream, io::Error>>::wrap(
            client, carrier,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let mut reply = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"reply");
    stream.write_all(b"request").await.unwrap();
    stream.flush().await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), server_task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn establish_awaits_supplied_dial_after_validation() {
    use ptrs::ClientTransport;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let polls = Arc::new(AtomicUsize::new(0));
    let dial_polls = Arc::clone(&polls);
    let builder = WebTunnelBuilder::default();
    let client = <WebTunnelBuilder as ClientBuilder<tokio::io::DuplexStream>>::build(&builder);
    let dial = Box::pin(async move {
        dial_polls.fetch_add(1, Ordering::SeqCst);
        Err::<tokio::io::DuplexStream, io::Error>(io::Error::other("dial should not run"))
    });
    let result =
        <WebTunnelClient as ClientTransport<tokio::io::DuplexStream, io::Error>>::establish(
            client, dial,
        )
        .await;
    assert!(matches!(result, Err(Error::MissingUrl)));
    assert_eq!(polls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn establish_uses_supplied_dial_and_preserves_failure() {
    use ptrs::ClientTransport;

    let mut builder = WebTunnelBuilder::default();
    <WebTunnelBuilder as ClientBuilder<tokio::io::DuplexStream>>::options(
        &mut builder,
        &make_args(&[("url", "http://example.invalid/path")]),
    )
    .unwrap();
    let client = <WebTunnelBuilder as ClientBuilder<tokio::io::DuplexStream>>::build(&builder);
    let dial = Box::pin(async {
        Err::<tokio::io::DuplexStream, io::Error>(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "carrier refused",
        ))
    });
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        <WebTunnelClient as ClientTransport<tokio::io::DuplexStream, io::Error>>::establish(
            client, dial,
        ),
    )
    .await
    .unwrap();
    assert!(
        matches!(result, Err(Error::Io(error)) if error.to_string().contains("carrier refused"))
    );
}

#[tokio::test(start_paused = true)]
async fn establish_pending_dial_is_bounded_by_transport_timeout() {
    use ptrs::ClientTransport;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let mut builder = WebTunnelBuilder::default();
    <WebTunnelBuilder as ClientBuilder<tokio::io::DuplexStream>>::options(
        &mut builder,
        &make_args(&[("url", "http://example.invalid/path")]),
    )
    .unwrap();
    <WebTunnelBuilder as ClientBuilder<tokio::io::DuplexStream>>::timeout(
        &mut builder,
        Some(Duration::from_secs(3)),
    )
    .unwrap();
    let client = <WebTunnelBuilder as ClientBuilder<tokio::io::DuplexStream>>::build(&builder);
    let polls = Arc::new(AtomicUsize::new(0));
    let dial_polls = Arc::clone(&polls);
    let dial = Box::pin(std::future::poll_fn(
        move |_| -> std::task::Poll<Result<tokio::io::DuplexStream, io::Error>> {
            dial_polls.fetch_add(1, Ordering::SeqCst);
            std::task::Poll::Pending
        },
    ));
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        <WebTunnelClient as ClientTransport<tokio::io::DuplexStream, io::Error>>::establish(
            client, dial,
        ),
    )
    .await;
    assert!(matches!(result, Ok(Err(Error::Io(error))) if error.kind() == io::ErrorKind::TimedOut));
    assert!(polls.load(Ordering::SeqCst) > 0);
}

#[tokio::test]
async fn supplied_carrier_rejects_configured_bind_before_dial_poll() {
    use ptrs::ClientTransport;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::sync::atomic::{AtomicUsize, Ordering};

    let mut builder = WebTunnelBuilder::default();
    <WebTunnelBuilder as ClientBuilder<tokio::io::DuplexStream>>::options(
        &mut builder,
        &make_args(&[("url", "http://example.invalid/path")]),
    )
    .unwrap();
    <WebTunnelBuilder as ClientBuilder<tokio::io::DuplexStream>>::v4_bind_addr(
        &mut builder,
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
    )
    .unwrap();
    let client = <WebTunnelBuilder as ClientBuilder<tokio::io::DuplexStream>>::build(&builder);
    let polls = Arc::new(AtomicUsize::new(0));
    let dial_polls = Arc::clone(&polls);
    let dial = Box::pin(async move {
        dial_polls.fetch_add(1, Ordering::SeqCst);
        Err::<tokio::io::DuplexStream, io::Error>(io::Error::other("dial should not run"))
    });
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        <WebTunnelClient as ClientTransport<tokio::io::DuplexStream, io::Error>>::establish(
            client, dial,
        ),
    )
    .await
    .unwrap();
    assert!(matches!(result, Err(Error::Unsupported(_))));
    assert_eq!(polls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn handshake_timeout_overflow_is_rejected_before_connect() {
    let mut builder = WebTunnelBuilder::default();
    <WebTunnelBuilder as ClientBuilder<TcpStream>>::options(
        &mut builder,
        &make_args(&[("url", "http://127.0.0.1:1/path")]),
    )
    .unwrap();
    <WebTunnelBuilder as ClientBuilder<TcpStream>>::timeout(&mut builder, Some(Duration::MAX))
        .unwrap();
    let client = <WebTunnelBuilder as ClientBuilder<TcpStream>>::build(&builder);
    let result = client.connect_url().await;
    assert!(matches!(result, Err(Error::Io(error)) if error.kind() == io::ErrorKind::InvalidInput));
}

#[tokio::test]
async fn supplied_dial_is_not_polled_when_deadline_overflows() {
    let mut builder = WebTunnelBuilder::default();
    <WebTunnelBuilder as ClientBuilder<tokio::io::DuplexStream>>::options(
        &mut builder,
        &make_args(&[("url", "https://example.invalid/path")]),
    )
    .unwrap();
    builder.timeout = Duration::MAX;
    let client = <WebTunnelBuilder as ClientBuilder<tokio::io::DuplexStream>>::build(&builder);
    let dial = Box::pin(std::future::poll_fn(
        |_| -> std::task::Poll<io::Result<tokio::io::DuplexStream>> {
            panic!("invalid timeout must be rejected before polling the carrier")
        },
    ));
    let result =
        <WebTunnelClient as ptrs::ClientTransport<_, io::Error>>::establish(client, dial).await;
    assert!(matches!(result, Err(Error::Io(error)) if error.kind() == io::ErrorKind::InvalidInput));
}

#[tokio::test]
async fn tls_client_hello_uses_supplied_carrier() {
    let mut builder = WebTunnelBuilder::default();
    <WebTunnelBuilder as ClientBuilder<tokio::io::DuplexStream>>::options(
        &mut builder,
        &make_args(&[("url", "https://example.invalid/path")]),
    )
    .unwrap();
    let client = <WebTunnelBuilder as ClientBuilder<tokio::io::DuplexStream>>::build(&builder);
    let (carrier, mut peer) = tokio::io::duplex(16_384);
    let handshake = <WebTunnelClient as ptrs::ClientTransport<_, io::Error>>::wrap(client, carrier);
    let peer = async move {
        let mut header = [0; 5];
        peer.read_exact(&mut header).await.unwrap();
        assert_eq!(&header[..2], &[22, 3], "expected a TLS handshake record");
    };
    let (result, ()) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(handshake, peer)
    })
    .await
    .unwrap();
    assert!(matches!(result, Err(Error::Tls(_))));
}

#[tokio::test]
async fn url_connect_applies_v4_bind_to_tcp_socket() {
    use ptrs::ClientBuilder;
    use std::net::{Ipv4Addr, SocketAddrV4};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/path", listener.local_addr().unwrap());
    let mut builder = WebTunnelBuilder::default();
    <WebTunnelBuilder as ClientBuilder<TcpStream>>::options(
        &mut builder,
        &make_args(&[("url", &url), ("doh-mode", "off")]),
    )
    .unwrap();
    <WebTunnelBuilder as ClientBuilder<TcpStream>>::v4_bind_addr(
        &mut builder,
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
    )
    .unwrap();
    let client = <WebTunnelBuilder as ClientBuilder<TcpStream>>::build(&builder);
    let server = tokio::spawn(async move {
        let (mut stream, peer) = listener.accept().await.unwrap();
        assert_eq!(peer.ip(), Ipv4Addr::LOCALHOST);
        assert_ne!(peer.port(), 0);
        let mut request = Vec::new();
        let mut byte = [0u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            request.push(byte[0]);
        }
        stream
            .write_all(b"HTTP/1.1 101 Switching Protocols\r\n\r\n")
            .await
            .unwrap();
    });
    client.connect_url().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn url_connect_v4_bind_reports_occupied_source_port() {
    use ptrs::ClientBuilder;
    use std::net::{Ipv4Addr, SocketAddrV4};

    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let occupied_addr = occupied.local_addr().unwrap();
    let url = format!("http://{occupied_addr}/path");
    let mut builder = WebTunnelBuilder::default();
    <WebTunnelBuilder as ClientBuilder<TcpStream>>::options(
        &mut builder,
        &make_args(&[("url", &url), ("doh-mode", "off")]),
    )
    .unwrap();
    <WebTunnelBuilder as ClientBuilder<TcpStream>>::v4_bind_addr(
        &mut builder,
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, occupied_addr.port()),
    )
    .unwrap();
    <WebTunnelBuilder as ClientBuilder<TcpStream>>::timeout(
        &mut builder,
        Some(Duration::from_secs(2)),
    )
    .unwrap();
    let result = <WebTunnelBuilder as ClientBuilder<TcpStream>>::build(&builder)
        .connect_url()
        .await;
    assert!(matches!(result, Err(Error::Io(error)) if error.kind() == io::ErrorKind::AddrInUse));
}

#[tokio::test]
async fn url_connect_v6_bind_reports_occupied_source_port() {
    use ptrs::ClientBuilder;
    use std::net::{Ipv6Addr, SocketAddrV6};

    let Ok(occupied) = tokio::net::TcpListener::bind("[::1]:0").await else {
        return;
    };
    let occupied_addr = occupied.local_addr().unwrap();
    let url = format!("http://[::1]:{}/path", occupied_addr.port());
    let mut builder = WebTunnelBuilder::default();
    <WebTunnelBuilder as ClientBuilder<TcpStream>>::options(
        &mut builder,
        &make_args(&[("url", &url), ("doh-mode", "off")]),
    )
    .unwrap();
    <WebTunnelBuilder as ClientBuilder<TcpStream>>::v6_bind_addr(
        &mut builder,
        SocketAddrV6::new(Ipv6Addr::LOCALHOST, occupied_addr.port(), 0, 0),
    )
    .unwrap();
    <WebTunnelBuilder as ClientBuilder<TcpStream>>::timeout(
        &mut builder,
        Some(Duration::from_secs(2)),
    )
    .unwrap();
    let result = <WebTunnelBuilder as ClientBuilder<TcpStream>>::build(&builder)
        .connect_url()
        .await;
    assert!(matches!(result, Err(Error::Io(error)) if error.kind() == io::ErrorKind::AddrInUse));
}

#[test]
fn builder_accepts_valid_args() {
    let mut builder = WebTunnelBuilder::default();
    let args = make_args(&[("url", "https://example.com/secret")]);
    <WebTunnelBuilder as ptrs::ClientBuilder<TcpStream>>::options(&mut builder, &args).unwrap();
}

#[test]
fn built_clients_share_immutable_connection_context() {
    let builder = WebTunnelBuilder::default();
    let first = <WebTunnelBuilder as ClientBuilder<TcpStream>>::build(&builder);
    let second = <WebTunnelBuilder as ClientBuilder<TcpStream>>::build(&builder);
    assert!(Arc::ptr_eq(&first.tls, &second.tls));
    assert!(Arc::ptr_eq(&first.resolver, &second.resolver));
}

#[test]
fn request_has_no_obs_fold_whitespace() {
    let cfg =
        WebTunnelConfig::from_args(&make_args(&[("url", "https://example.com/path")])).unwrap();
    let req = handshake::build_upgrade_request(&cfg);
    assert!(
        !req.contains("\r\n "),
        "request must not contain obs-fold (CRLF followed by leading whitespace): {req:?}"
    );
}

// -- PrefixStream tests ---------------------------------------------------

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[tokio::test]
async fn trailing_bytes_after_101_are_preserved() {
    // Simulate leftover bytes fused into the HTTP read: the prefix
    // should be the first thing returned by the wrapper.
    let (_mock_server, mock_client) = tokio::io::duplex(64);
    // We don't need the mock_server side for this test — the prefix
    // is read first, before the inner stream is ever polled.
    drop(_mock_server);

    let mut wrapped = PrefixStream::new(mock_client, vec![0xAB, 0xCD, 0xEF]);
    let mut buf = [0u8; 3];
    wrapped.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"\xAB\xCD\xEF");
}

#[tokio::test]
async fn trailing_bytes_followed_by_live_stream_bytes() {
    let (mut mock_server, mock_client) = tokio::io::duplex(64);

    let mut wrapped = PrefixStream::new(mock_client, vec![0xAB, 0xCD, 0xEF]);

    // Read the prefix first.
    let mut buf = [0u8; 3];
    wrapped.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"\xAB\xCD\xEF");

    // Now write data to the server side — the wrapper should read it.
    mock_server.write_all(b"\x01\x02\x03\x04").await.unwrap();

    let mut buf2 = [0u8; 4];
    wrapped.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, b"\x01\x02\x03\x04");
}

// -- Config validation edge cases -----------------------------------------

#[test]
fn config_invalid_url_format() {
    let args = make_args(&[("url", "not a url at all")]);
    let err = WebTunnelConfig::from_args(&args).unwrap_err();
    assert!(matches!(err, Error::InvalidUrl(_)));
}

#[test]
fn config_url_without_path_defaults_to_slash() {
    let args = make_args(&[("url", "https://example.com")]);
    let cfg = WebTunnelConfig::from_args(&args).unwrap();
    let req = handshake::build_upgrade_request(&cfg);
    assert!(req.starts_with("GET / HTTP/1.1\r\n"));
}

#[test]
fn config_url_with_query_string() {
    let args = make_args(&[("url", "https://example.com/path?token=abc&v=1")]);
    let cfg = WebTunnelConfig::from_args(&args).unwrap();
    let req = handshake::build_upgrade_request(&cfg);
    // The GET request-target MUST include path AND query — the Go
    // reference sends path?query.  Auth tokens / routing hints live
    // in the query; dropping it silently breaks the handshake.
    assert!(
        req.starts_with("GET /path?token=abc&v=1 HTTP/1.1\r\n"),
        "query string must appear in request-target, got: {req}"
    );
}

#[test]
fn query_string_absent_means_plain_path() {
    // URL without a query must produce a bare path (no trailing '?').
    let args = make_args(&[("url", "https://example.com/secret")]);
    let cfg = WebTunnelConfig::from_args(&args).unwrap();
    let req = handshake::build_upgrade_request(&cfg);
    assert!(
        req.starts_with("GET /secret HTTP/1.1\r\n"),
        "path-only URL must not grow a query part, got: {req}"
    );
}

#[test]
fn query_only_no_path() {
    // Edge case: root path with a query string.
    let args = make_args(&[("url", "https://example.com/?k=v")]);
    let cfg = WebTunnelConfig::from_args(&args).unwrap();
    let req = handshake::build_upgrade_request(&cfg);
    assert!(
        req.starts_with("GET /?k=v HTTP/1.1\r\n"),
        "root path with query must be preserved, got: {req}"
    );
}

// -- DoH config parsing tests ----------------------------------------

#[test]
fn config_doh_mode_defaults_to_fallback() {
    let args = make_args(&[("url", "https://example.com/x")]);
    let cfg = WebTunnelConfig::from_args(&args).unwrap();
    assert_eq!(cfg.doh_mode, DohMode::Fallback);
}

#[test]
fn config_doh_mode_parses_off_strict_fallback() {
    for (raw, expected) in [
        ("off", DohMode::Off),
        ("strict", DohMode::Strict),
        ("fallback", DohMode::Fallback),
        ("STRICT", DohMode::Strict),
    ] {
        let args = make_args(&[("url", "https://example.com/x"), ("doh-mode", raw)]);
        let cfg = WebTunnelConfig::from_args(&args).unwrap();
        assert_eq!(cfg.doh_mode, expected, "doh-mode={raw}");
    }
}

#[test]
fn config_doh_mode_rejects_garbage() {
    let args = make_args(&[("url", "https://example.com/x"), ("doh-mode", "dnsstrict")]);
    let err = WebTunnelConfig::from_args(&args).unwrap_err();
    assert!(matches!(err, Error::InvalidUrl(_)), "{err:?}");
}

#[test]
fn config_with_doh_mode_overrides() {
    let args = make_args(&[("url", "https://example.com/x")]);
    let cfg = WebTunnelConfig::from_args(&args)
        .unwrap()
        .with_doh_mode(DohMode::Strict);
    assert_eq!(cfg.doh_mode, DohMode::Strict);
}

#[test]
fn config_connect_host_and_port_from_url() {
    let args = make_args(&[("url", "https://example.com:8443/x")]);
    let cfg = WebTunnelConfig::from_args(&args).unwrap();
    assert_eq!(
        cfg.connect_host_and_port().unwrap(),
        ("example.com".to_string(), 8443)
    );
}

#[test]
fn config_connect_host_and_port_from_tcp_addr() {
    let args = make_args(&[("url", "https://example.com/x"), ("addr", "192.0.2.1:8443")]);
    let cfg = WebTunnelConfig::from_args(&args).unwrap();
    assert_eq!(
        cfg.connect_host_and_port().unwrap(),
        ("192.0.2.1".to_string(), 8443)
    );
}

#[test]
fn config_connect_host_and_port_rejects_bad_addr() {
    let args = make_args(&[("url", "https://example.com/x"), ("addr", "noport")]);
    assert!(WebTunnelConfig::from_args(&args).is_err());
}

#[test]
fn config_connect_host_port_http_defaults_to_80() {
    let args = make_args(&[("url", "http://example.com/path")]);
    let cfg = WebTunnelConfig::from_args(&args).unwrap();
    assert_eq!(cfg.connect_host_port().unwrap(), "example.com:80");
}

#[test]
fn config_use_tls_ftp_scheme_is_false() {
    let cfg = WebTunnelConfig {
        url: "ftp://example.com/x".into(),
        version: None,
        servername: None,
        tcp_addr: None,
        doh_mode: DohMode::default(),
    };
    assert!(!cfg.use_tls());
}

// -- use_tls scheme-parsing correctness tests --------------------------------

#[test]
fn use_tls_https_lowercase_is_true() {
    let cfg = WebTunnelConfig {
        url: "https://example.com/path".into(),
        version: None,
        servername: None,
        tcp_addr: None,
        doh_mode: DohMode::default(),
    };
    assert!(cfg.use_tls());
}

#[test]
fn use_tls_http_lowercase_is_false() {
    let cfg = WebTunnelConfig {
        url: "http://example.com/path".into(),
        version: None,
        servername: None,
        tcp_addr: None,
        doh_mode: DohMode::default(),
    };
    assert!(!cfg.use_tls());
}

#[test]
fn use_tls_https_uppercase_is_true() {
    // The url crate normalises the scheme to lowercase during parsing,
    // so Url::parse("HTTPS://...").scheme() == "https".  The raw
    // starts_with("https") check would have returned false here.
    let cfg = WebTunnelConfig {
        url: "HTTPS://example.com/path".into(),
        version: None,
        servername: None,
        tcp_addr: None,
        doh_mode: DohMode::default(),
    };
    assert!(cfg.use_tls());
}

#[test]
fn use_tls_httpsx_garbage_scheme_is_false() {
    // "httpsx://" starts with "https" but is not the https scheme.
    // Parsed scheme would be "httpsx", not "https".
    let cfg = WebTunnelConfig {
        url: "httpsx://example.com".into(),
        version: None,
        servername: None,
        tcp_addr: None,
        doh_mode: DohMode::default(),
    };
    assert!(!cfg.use_tls());
}

// -- PrefixStream edge cases ---

#[tokio::test]
async fn prefix_stream_empty_prefix_is_transparent() {
    let (mut mock_server, mock_client) = tokio::io::duplex(64);
    let mut wrapped = PrefixStream::new(mock_client, vec![]);
    mock_server.write_all(b"hello").await.unwrap();
    let mut buf = [0u8; 5];
    wrapped.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello");
}

#[tokio::test]
async fn prefix_stream_write_passes_through() {
    let (mut mock_server, mock_client) = tokio::io::duplex(64);
    let mut wrapped = PrefixStream::new(mock_client, vec![0xAA]);
    wrapped.write_all(b"data").await.unwrap();
    let mut buf = [0u8; 4];
    mock_server.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"data");
}
