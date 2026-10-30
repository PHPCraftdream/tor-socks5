use super::*;
use crate::WebTunnelConfig;
use ptrs::args::Args;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};

#[test]
fn fragmented_header_boundary_matches_http_parser() {
    for response in [
        b"HTTP/1.1 101 Switching Protocols\r\n\r\nbody".as_slice(),
        b"HTTP/1.1 101 Switching Protocols\n\nbody",
        b"\r\n\r\nHTTP/1.1 101 Switching Protocols\r\nX-Test: value\r\n\r\nbody",
        b"\nHTTP/1.1 101 Switching Protocols\nX-Test: value\n\nbody",
    ] {
        let (_, leftover) = parse_response(response).unwrap();
        assert_eq!(leftover, b"body");
        let expected_end = response.len() - leftover.len();
        let mut scanner = HeaderBoundary::default();
        for end in 0..expected_end {
            assert_eq!(scanner.find(&response[..end]), None);
        }
        assert_eq!(scanner.find(response), Some(expected_end));
    }
}

fn make_config(url: &str) -> WebTunnelConfig {
    let mut args = Args::new();
    args.add("url", url);
    WebTunnelConfig::from_args(&args).unwrap()
}

#[test]
fn websocket_key_is_base64_24_chars() {
    let key = generate_websocket_key();
    assert_eq!(key.len(), 24);
    assert!(base64::engine::general_purpose::STANDARD
        .decode(&key)
        .is_ok());
}

#[test]
fn websocket_key_is_random() {
    let k1 = generate_websocket_key();
    let k2 = generate_websocket_key();
    assert_ne!(k1, k2);
}

#[test]
fn build_upgrade_request_format() {
    let config = make_config("https://example.com/secret");
    let req = build_upgrade_request(&config);
    assert!(req.starts_with("GET /secret HTTP/1.1\r\n"));
    assert!(req.contains("Host: example.com\r\n"));
    assert!(req.contains("Upgrade: websocket\r\n"));
    assert!(req.contains("Connection: Upgrade\r\n"));
    assert!(req.contains("Sec-WebSocket-Key: "));
    assert!(req.contains("Sec-WebSocket-Version: 13\r\n"));
    assert!(req.ends_with("\r\n\r\n"));
}

#[test]
fn build_upgrade_request_root_path() {
    let config = make_config("https://example.com");
    let req = build_upgrade_request(&config);
    assert!(req.starts_with("GET / HTTP/1.1\r\n"));
}

#[test]
fn parse_response_101_ok() {
    let resp =
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n";
    let (code, leftover) = parse_response(resp).unwrap();
    assert_eq!(code, 101);
    assert!(leftover.is_empty());
}

#[test]
fn parse_response_101_with_leftover() {
    let resp = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\nEXTRADATA";
    let (code, leftover) = parse_response(resp).unwrap();
    assert_eq!(code, 101);
    assert_eq!(leftover, b"EXTRADATA");
}

#[test]
fn parse_response_non_101() {
    let resp = b"HTTP/1.1 404 Not Found\r\n\r\n";
    let err = parse_response(resp).unwrap_err();
    assert!(matches!(err, Error::Non101(_)));
}

#[test]
fn parse_response_incomplete() {
    let resp = b"HTTP/1.1 101 Switch";
    let err = parse_response(resp).unwrap_err();
    assert!(matches!(err, Error::HttpParse(_)));
}

#[test]
fn parse_response_malformed() {
    let resp = b"NOT HTTP AT ALL\r\n\r\n";
    let err = parse_response(resp).unwrap_err();
    assert!(matches!(err, Error::HttpParse(_)));
}

// -- DoH connect-path tests ------------------------------------------------
//
// These tests exercise the strict-vs-fallback decision logic without
// touching the network. The "unreachable" DoH pool uses 127.0.0.1 as
// its bootstrap IP: hickory will dial 127.0.0.1:443 to perform the DoH
// TLS handshake, which fails immediately with `ConnectionRefused` on a
// host with no service on that port — fast enough that the test never
// hangs and never has to talk to the real internet.
//
// The DoH-resolver build itself is fallible. Production memoizes only a
// successful build in one client context, so a transient build error is
// retried and fallback can continue with system resolution.

use std::net::{IpAddr, Ipv4Addr};

use crate::dns::endpoints::DohEndpoint;

/// A DoH pool whose only "endpoint" dials 127.0.0.1 — no TLS listener
/// on :443 there, so every lookup terminates with a connection error
/// without involving the network. Pinned `localhost.invalid` SNI
/// ensures `rustls` rejects the (non-existent) certificate.
const UNREACHABLE_ENDPOINT: DohEndpoint = DohEndpoint {
    name: "unreachable-test",
    sni: "localhost.invalid",
    path: Some("/dns-query"),
    bootstrap: &[IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))],
};

/// Hickory handles localhost locally; this checks the resulting connection,
/// while the injected policy tests below verify actual fallback selection.
#[tokio::test]
async fn fallback_mode_accepts_locally_resolved_localhost() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let resolver =
        DohResolver::from_endpoints(&[UNREACHABLE_ENDPOINT]).expect("unreachable pool builds");

    let stream = connect_via_doh_fallback(Some(&resolver), "localhost", port)
        .await
        .expect("localhost must remain reachable");
    // Sanity: stream is connected to the listener.
    assert_eq!(stream.peer_addr().unwrap().port(), port);
}

/// `Fallback` with `resolver = None` (resolver-build failed) must
/// still try the system resolver. Same end behaviour as the case
/// above, exercising the resolver-absent branch.
#[tokio::test]
async fn fallback_with_no_resolver_still_uses_system_resolver() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let stream = connect_via_doh_fallback(None, "localhost", port)
        .await
        .expect("fallback with None resolver must use system DNS");
    assert_eq!(stream.peer_addr().unwrap().port(), port);
}

/// `connect_first` picks the first reachable address, skipping
/// unreachable ones. Two-element list where the first refuses and
/// the second accepts — must succeed and report the second port.
#[tokio::test]
async fn connect_first_picks_reachable_after_skipping_dead() {
    let good = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let good_port = good.local_addr().unwrap().port();

    // Port 1 on 127.0.0.1 is almost certainly closed; if it isn't,
    // the test would skip past it via the "second succeeds" path.
    let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let alive: SocketAddr = format!("127.0.0.1:{good_port}").parse().unwrap();

    let stream = connect_first(&[dead, alive]).await.expect("alive must win");
    assert_eq!(stream.peer_addr().unwrap().port(), good_port);
}

#[tokio::test]
async fn connect_first_times_out_pending_address_and_dials_later_one() {
    struct DropProbe(Arc<AtomicBool>);
    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let alive = listener.local_addr().unwrap();
    let connected = TcpStream::connect(alive).await.unwrap();
    let pending: SocketAddr = "192.0.2.1:443".parse().unwrap();
    let dropped = Arc::new(AtomicBool::new(false));
    let probe = Arc::clone(&dropped);
    let deadline = Instant::now() + Duration::from_secs(30);
    let addresses = vec![pending, alive];
    tokio::time::pause();
    let mut connected = Some(connected);
    let operation = connect_first_until(&addresses, deadline, move |addr| {
        let probe = Arc::clone(&probe);
        let available = if addr == pending {
            None
        } else {
            Some(
                connected
                    .take()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::AlreadyExists, format!("{addr}"))),
            )
        };
        async move {
            if addr == pending {
                let _guard = DropProbe(probe);
                std::future::pending::<io::Result<TcpStream>>().await
            } else {
                Ok(available.expect("one preconnected stream").unwrap())
            }
        }
    });
    tokio::pin!(operation);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(operation.as_mut().poll(&mut context).is_pending());
    tokio::time::advance(CONNECT_ATTEMPT_TIMEOUT).await;
    let stream = tokio::time::timeout(Duration::from_millis(1), operation)
        .await
        .expect("later address must be tried immediately after attempt timeout")
        .expect("later address must connect");
    assert_eq!(stream.peer_addr().unwrap(), alive);
    assert!(
        dropped.load(Ordering::Acquire),
        "timed-out dial must be dropped"
    );
    tokio::time::resume();
}

#[tokio::test]
async fn strict_resolution_never_invokes_system_fallback() {
    let system_called = Arc::new(AtomicBool::new(false));
    let system_probe = Arc::clone(&system_called);
    let doh = connect_strict_with(
        || async { Err(io::Error::other("DoH unavailable")) },
        move || {
            system_probe.store(true, Ordering::Release);
            async { Ok::<_, io::Error>(Vec::new()) }
        },
        Instant::now() + Duration::from_secs(10),
        TcpStream::connect,
    )
    .await;
    assert!(doh.is_err());
    assert!(!system_called.load(Ordering::Acquire));
}

#[tokio::test]
async fn fallback_resolution_calls_system_only_after_doh_failure() {
    let doh_called = Arc::new(AtomicBool::new(false));
    let system_called = Arc::new(AtomicBool::new(false));
    let doh_probe = Arc::clone(&doh_called);
    let system_probe = Arc::clone(&system_called);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let expected = listener.local_addr().unwrap();
    let connected = TcpStream::connect(expected).await.unwrap();
    let mut connected = Some(connected);
    let result = connect_fallback_with(
        Some(move || {
            doh_probe.store(true, Ordering::Release);
            async { Err::<Vec<SocketAddr>, _>(io::Error::other("DoH unavailable")) }
        }),
        move || {
            system_probe.store(true, Ordering::Release);
            async move { Ok::<_, io::Error>(vec![expected]) }
        },
        Instant::now() + Duration::from_secs(10),
        move |_| {
            let result = connected
                .take()
                .ok_or_else(|| io::Error::other("dial called twice"));
            async move { result }
        },
    )
    .await
    .unwrap();
    assert_eq!(result.peer_addr().unwrap(), expected);
    assert!(doh_called.load(Ordering::Acquire));
    assert!(system_called.load(Ordering::Acquire));
}

#[tokio::test]
async fn fallback_retries_system_after_doh_dial_error() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let expected = listener.local_addr().unwrap();
    let connected = TcpStream::connect(expected).await.unwrap();
    let mut connected = Some(connected);
    let mut attempts = 0;
    let result = connect_fallback_with(
        Some(move || async move { Ok::<_, io::Error>(vec![expected]) }),
        move || async move { Ok::<_, io::Error>(vec![expected]) },
        Instant::now() + Duration::from_secs(10),
        |_| {
            attempts += 1;
            let result = if attempts == 1 {
                Err(io::Error::new(io::ErrorKind::ConnectionRefused, "DoH dial"))
            } else {
                connected
                    .take()
                    .ok_or_else(|| io::Error::other("missing system stream"))
            };
            async move { result }
        },
    )
    .await
    .unwrap();
    assert_eq!(result.peer_addr().unwrap(), expected);
    assert_eq!(attempts, 2);
}

#[test]
fn tls_context_reuses_config_and_isolates_clients() {
    let shared = crate::tls_context();
    let first = tls_config(&shared);
    let second = tls_config(&shared);
    assert!(Arc::ptr_eq(&first, &second));

    let isolated = crate::tls_context();
    let other = tls_config(&isolated);
    assert!(!Arc::ptr_eq(&first, &other));
    assert!(format!("{:?}", first.resumption).contains("Disabled"));
}

#[test]
fn resolver_context_reuses_success_and_does_not_cross_contexts() {
    let shared = crate::resolver_cache();
    let first = get_resolver(&shared).expect("default resolver builds");
    let second = get_resolver(&shared).expect("cached resolver remains available");
    assert!(Arc::ptr_eq(&first, &second));

    let isolated = crate::resolver_cache();
    let other = get_resolver(&isolated).expect("isolated resolver builds");
    assert!(!Arc::ptr_eq(&first, &other));
}

#[test]
fn resolver_init_errors_are_retryable() {
    let cache = crate::resolver_cache();
    let attempts = std::cell::Cell::new(0);
    let first = get_resolver_with(&cache, || {
        attempts.set(attempts.get() + 1);
        Err(io::Error::other("transient initialization failure"))
    });
    assert!(first.is_err());

    let second = get_resolver_with(&cache, || {
        attempts.set(attempts.get() + 1);
        DohResolver::with_default_pool().map(Arc::new)
    });
    assert!(second.is_ok());
    assert_eq!(attempts.get(), 2);
    get_resolver_with(&cache, || {
        panic!("successful initialization must be reused")
    })
    .unwrap();
}

#[test]
fn client_cache_recovers_after_initialization_panics() {
    let cache = crate::ClientCache::<usize>::new();
    assert!(std::panic::catch_unwind(|| cache.get_or_init(|| panic!("initialization"))).is_err());
    assert_eq!(*cache.get_or_init(|| Arc::new(42)), 42);
    assert_eq!(
        *cache.get_or_init(|| panic!("must reuse initialized value")),
        42
    );
}

#[test]
fn public_clients_preserve_auto_traits() {
    fn compatible<T: Send + Sync + std::panic::UnwindSafe + std::panic::RefUnwindSafe>() {}
    compatible::<crate::WebTunnelBuilder>();
    compatible::<crate::WebTunnelClient>();
}

/// `connect_first` returns the last error when no address is
/// reachable (and `AddrNotAvailable` for an empty input). The
/// empty-input shape is the regression guard for the helper's
/// "no addresses to connect to" branch.
#[tokio::test]
async fn connect_first_returns_error_on_empty_input() {
    let err = connect_first(&[]).await.expect_err("empty must fail");
    assert_eq!(err.kind(), io::ErrorKind::AddrNotAvailable);
}

#[tokio::test(start_paused = true)]
async fn single_address_uses_remaining_handshake_budget() {
    let started = Instant::now();
    let error = connect_first_until(
        &["192.0.2.1:443".parse().unwrap()],
        started + Duration::from_secs(12),
        |_| std::future::pending::<io::Result<TcpStream>>(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(started.elapsed(), Duration::from_secs(12));
}

#[tokio::test(start_paused = true)]
async fn short_budget_still_attempts_doh_before_system() {
    let doh_called = std::cell::Cell::new(false);
    let system_called = std::cell::Cell::new(false);
    let result = connect_fallback_with(
        Some(|| {
            doh_called.set(true);
            std::future::ready(Err::<Vec<SocketAddr>, _>(io::Error::other("DoH failure")))
        }),
        || {
            system_called.set(true);
            std::future::ready(Err::<Vec<SocketAddr>, _>(io::Error::from(
                io::ErrorKind::NotFound,
            )))
        },
        Instant::now() + Duration::from_secs(1),
        |_| std::future::ready(Err(io::Error::other("no address was resolved"))),
    )
    .await;
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotFound);
    assert!(doh_called.get());
    assert!(system_called.get());
}

#[tokio::test(start_paused = true)]
async fn stalled_doh_leaves_time_for_system_fallback() {
    let started = Instant::now();
    let system_called = std::cell::Cell::new(false);
    let result = connect_fallback_with(
        Some(std::future::pending::<io::Result<Vec<SocketAddr>>>),
        || {
            system_called.set(true);
            std::future::ready(Err::<Vec<SocketAddr>, _>(io::Error::from(
                io::ErrorKind::NotFound,
            )))
        },
        started + Duration::from_secs(10),
        |_| std::future::ready(Err(io::Error::other("no address was resolved"))),
    )
    .await;
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotFound);
    assert!(system_called.get());
    assert_eq!(started.elapsed(), Duration::from_secs(5));
}
