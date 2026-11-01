use super::*;

#[test]
fn arg_string_uname_only_when_passwd_is_nul() {
    let creds = Some(("cert=AAA;iat-mode=0".to_string(), "\0".to_string()));
    assert_eq!(arg_string_from_creds(creds), "cert=AAA;iat-mode=0");
}

#[test]
fn arg_string_concat_when_passwd_nonempty() {
    let creds = Some(("cert=".to_string(), "AAA;iat-mode=0".to_string()));
    assert_eq!(arg_string_from_creds(creds), "cert=AAA;iat-mode=0");
}

#[test]
fn arg_string_empty_when_no_creds() {
    assert_eq!(arg_string_from_creds(None), "");
}

#[test]
fn arg_string_then_parse_yields_kv_map() {
    // 300-char value split across the two SOCKS5 fields (uname=255,
    // passwd=remainder) — the canonical case the spec is written for.
    let big = "cert=".to_string() + &"A".repeat(250);
    let tail = ";iat-mode=0".to_string();
    let creds = Some((big.clone(), tail.clone()));
    let arg_string = arg_string_from_creds(creds);
    assert_eq!(arg_string, big + &tail);

    let args = ptrs::args::Args::from_str(&arg_string).expect("parse");
    assert!(args.retrieve("cert").is_some());
    assert_eq!(args.retrieve("iat-mode").as_deref(), Some("0"));
}

#[test]
fn accept_error_policy_retries_transient_failures() {
    assert!(is_transient_accept_error(&std::io::Error::from(
        std::io::ErrorKind::WouldBlock,
    )));
    assert!(is_transient_accept_error(&std::io::Error::from(
        std::io::ErrorKind::ConnectionAborted,
    )));
    assert!(!is_transient_accept_error(&std::io::Error::from(
        std::io::ErrorKind::PermissionDenied,
    )));
    assert!(!is_transient_accept_error(&std::io::Error::from(
        std::io::ErrorKind::Other,
    )));

    #[cfg(unix)]
    assert!(is_transient_accept_error(
        &std::io::Error::from_raw_os_error(libc::EMFILE,)
    ));

    assert!(accept_retry_delay(0) < accept_retry_delay(1));
    assert_eq!(accept_retry_delay(100), std::time::Duration::from_secs(1));
}

#[tokio::test]
async fn pt_args_auth_propagates_creds() {
    use fast_socks5::server::Authentication;
    let auth = PtArgsAuth;
    let got = auth
        .authenticate(Some(("u".to_string(), "p".to_string())))
        .await;
    assert_eq!(got, Some(("u".to_string(), "p".to_string())));
}

#[tokio::test]
async fn pt_args_auth_accepts_no_creds() {
    use fast_socks5::server::Authentication;
    let auth = PtArgsAuth;
    let got = auth.authenticate(None).await;
    assert_eq!(got, Some((String::new(), String::new())));
}

#[tokio::test]
async fn webtunnel_managed_path_ignores_socks_target() {
    let client = <webtunnel::WebTunnelBuilder as ptrs::ClientBuilder<TcpStream>>::build(
        &webtunnel::WebTunnelBuilder::default(),
    );
    let result = client
        .managed_connect(
            TargetAddr::Domain("invalid.example".into(), 443),
            "127.0.0.1:1".parse().unwrap(),
            None,
        )
        .await;
    let error = match result {
        Ok(_) => panic!("unconfigured WebTunnel must fail before dialing"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("missing required parameter: url"));
}

// -- dial_bridge socket options ----------------------------------------
//
// The carrier-resilience options (TCP_NODELAY + TCP keepalive) are silent
// safeguards: if the `set_*` lines disappear, nothing breaks at build or
// unit-test time, but the bridge channel becomes susceptible to the same
// mid-bootstrap 10053/10054 tear-downs that motivated `dial_bridge` in
// the first place. These compliance tests catch a regression that drops
// either option.

#[tokio::test]
async fn dial_bridge_sets_tcp_nodelay() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _accept = tokio::spawn(async move { listener.accept().await });

    let stream = dial_bridge(addr).await.expect("dial_bridge");
    assert!(
        stream.nodelay().expect("nodelay() readback"),
        "dial_bridge must enable TCP_NODELAY on the carrier socket"
    );
}

#[tokio::test]
async fn dial_bridge_arms_tcp_keepalive() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _accept = tokio::spawn(async move { listener.accept().await });

    let stream = dial_bridge(addr).await.expect("dial_bridge");
    // `keepalive()` returns whether SO_KEEPALIVE is on. Setting the
    // per-keepalive intervals via `socket2::TcpKeepalive` also flips
    // the SO_KEEPALIVE flag, so its presence is the read-back signal
    // that `set_tcp_keepalive(&keepalive)` was actually called.
    let sock = socket2::SockRef::from(&stream);
    assert!(
        sock.keepalive().expect("SO_KEEPALIVE readback"),
        "dial_bridge must arm TCP keepalive on the carrier socket"
    );
}

// -- resolve_target_addr --

#[test]
fn resolve_target_addr_ip() {
    let addr = TargetAddr::Ip("127.0.0.1:9050".parse().unwrap());
    let resolved = resolve_target_addr(&addr).unwrap();
    assert_eq!(resolved.to_string(), "127.0.0.1:9050");
}

#[test]
fn resolve_target_addr_ipv6() {
    let addr = TargetAddr::Ip("[::1]:443".parse().unwrap());
    let resolved = resolve_target_addr(&addr).unwrap();
    assert_eq!(resolved.to_string(), "[::1]:443");
}

#[test]
fn resolve_target_addr_domain_fails() {
    let addr = TargetAddr::Domain("example.com".into(), 443);
    let err = resolve_target_addr(&addr);
    assert!(
        err.is_err(),
        "domain resolution should fail (PT doesn't do DNS)"
    );
}

// -- arg_string edge cases --

#[test]
fn arg_string_empty_uname_and_passwd() {
    let creds = Some((String::new(), String::new()));
    assert_eq!(arg_string_from_creds(creds), "");
}

#[test]
fn arg_string_passwd_is_nul_only() {
    let creds = Some((String::new(), "\0".to_string()));
    assert_eq!(arg_string_from_creds(creds), "");
}

// -- establish_pt_conn (outgoing-dial seam) --
//
// These exercise the client outgoing-connection path
// (`client_handle_connection` → `establish_pt_conn`) that was previously
// unreachable in tests because it created a real `TcpStream::connect`
// inline. The dial is now an injectable `Pin<FutureResult<_, _>>`, so a
// `tokio::io::duplex()` half (or a deliberately-failing future) stands in
// for the OR-port socket. We drive the *ptrs trait* surface end to end:
// build an obfs4 client from a bridge-line arg string exactly the way
// `client_handle_connection` does (`Args` → `ClientBuilder::options` →
// `build`), then run the real obfs4 handshake over the duplex against a
// matching obfs4 `Server`.

use tokio::io::DuplexStream;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite};

/// Build an obfs4 client transport from a bridge-line arg string via the
/// same `ptrs` builder path lyrebird uses for a real SOCKS connection:
/// parse the args, apply them through `ptrs::ClientBuilder::options`, then
/// `build`. The obfs4 builder/transport impls are generic over the socket
/// type, so we pin `InRW = DuplexStream` here (an in-memory stand-in for
/// the OR-port `TcpStream`).
fn obfs4_client_from_args(arg_string: &str) -> obfs4::Client {
    let smethod_args =
        ptrs::args::Args::parse_smethod_args(arg_string).expect("parse SMETHOD bridge-line args");
    let socks_args = smethod_args.encode_client_parameters();
    let args = ptrs::args::Args::parse_client_parameters(&socks_args)
        .expect("parse SOCKS bridge-line args");
    let mut builder = obfs4::ClientBuilder::default();
    <obfs4::ClientBuilder as ptrs::ClientBuilder<DuplexStream>>::options(&mut builder, &args)
        .expect("apply obfs4 args to builder");
    <obfs4::ClientBuilder as ptrs::ClientBuilder<DuplexStream>>::build(&builder)
}

#[tokio::test]
async fn establish_pt_conn_obfs4_handshake_and_proxies_bytes() {
    // A fresh obfs4 server with a random identity and the bridge-line
    // arg string that a client must present to reach it.
    let server_builder = obfs4::ServerBuilder::<DuplexStream>::default();
    let arg_string = server_builder.client_params();
    let server = server_builder.build();

    // In-memory stand-in for the OR-port socket.
    let (client_side, server_side) = tokio::io::duplex(65_536);

    // Server peer: complete the obfs4 handshake, then echo one message.
    let server_task = tokio::spawn(async move {
        let mut s = server.wrap(server_side).await.expect("server handshake");
        let mut buf = [0u8; 64];
        let n = s.read(&mut buf).await.expect("server read");
        s.write_all(&buf[..n]).await.expect("server echo write");
        s.flush().await.expect("server flush");
    });

    // Client: build through the ptrs trait, then drive the seam with a
    // dial future that yields the duplex half instead of a TcpStream.
    let client = obfs4_client_from_args(&arg_string);
    let dial: Pin<ptrs::FutureResult<DuplexStream, std::io::Error>> =
        Box::pin(async move { Ok(client_side) });
    let client_addr: SocketAddr = "127.0.0.1:9050".parse().unwrap();

    let mut tunnel = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        establish_pt_conn(client, dial, client_addr),
    )
    .await
    .expect("establish_pt_conn timed out")
    .expect("establish_pt_conn should complete the obfs4 handshake");

    // Bytes written into the obfs4 tunnel must come back through the
    // server echo — proving `establish` consumed the injected dial
    // stream and a real encrypted session is in place.
    let msg = b"through-the-obfs4-tunnel";
    tunnel.write_all(msg).await.expect("client write");
    tunnel.flush().await.expect("client flush");

    let mut got = vec![0u8; msg.len()];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tunnel.read_exact(&mut got),
    )
    .await
    .expect("client read timed out")
    .expect("client read");
    assert_eq!(&got, msg, "data must round-trip through the obfs4 tunnel");

    tokio::time::timeout(std::time::Duration::from_secs(5), server_task)
        .await
        .expect("server task timed out")
        .expect("server task panicked");
}

#[tokio::test]
async fn establish_pt_conn_dial_failure_is_error_not_panic() {
    // The dial future itself fails (e.g. OR-port connection refused).
    // `establish` must surface this as an `Err` without panicking — this
    // path is reachable from the network, so a regression to `unwrap`
    // would be a remote DoS.
    let server_builder = obfs4::ServerBuilder::<DuplexStream>::default();
    let arg_string = server_builder.client_params();
    let client = obfs4_client_from_args(&arg_string);

    let dial: Pin<ptrs::FutureResult<DuplexStream, std::io::Error>> = Box::pin(async {
        Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "dial refused",
        ))
    });
    let client_addr: SocketAddr = "127.0.0.1:9050".parse().unwrap();

    let result = establish_pt_conn(client, dial, client_addr).await;
    assert!(
        result.is_err(),
        "a failed dial must produce an error, not a tunnel"
    );
}

#[tokio::test]
async fn establish_pt_conn_handshake_eof_is_error_not_panic() {
    // The dial succeeds (a socket is produced) but the OR-port peer
    // immediately closes — e.g. the bridge dropped the connection during
    // the handshake. The obfs4 client's first handshake read then hits
    // EOF, which must surface as an `Err` from `establish_pt_conn`,
    // promptly and without panicking. (The client returns `UnexpectedEof`
    // on a 0-byte read rather than blocking until its handshake timeout.)
    // This complements the positive end-to-end test: that one proves the
    // bridge-line args reach the handshake crypto (a wrong/empty cert
    // would make it fail); this one proves the failure branch is handled.
    let server_builder = obfs4::ServerBuilder::<DuplexStream>::default();
    let arg_string = server_builder.client_params();
    let client = obfs4_client_from_args(&arg_string);

    let (client_side, server_side) = tokio::io::duplex(65_536);
    // Close the peer half before the handshake reads anything.
    drop(server_side);

    let dial: Pin<ptrs::FutureResult<DuplexStream, std::io::Error>> =
        Box::pin(async move { Ok(client_side) });
    let client_addr: SocketAddr = "127.0.0.1:9050".parse().unwrap();

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        establish_pt_conn(client, dial, client_addr),
    )
    .await
    .expect("establish_pt_conn should fail fast on EOF, not block until timeout");

    assert!(
        result.is_err(),
        "a peer that closes mid-handshake must produce an error, not a tunnel"
    );
}

// -- Bug 2 regression: cancel arm must break the accept loop --

/// Verify that `client_accept_loop` exits promptly when the
/// `CancellationToken` is already cancelled before the loop starts.
/// Without the `break` in the cancel arm, `cancelled()` is
/// immediately ready on every iteration and the loop spins forever,
/// causing this test to hit the timeout and fail.
#[tokio::test]
async fn client_accept_loop_exits_on_pre_cancelled_token() {
    // Bind a real listener so the function signature is satisfied.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener for test");

    // Cancel BEFORE entering the loop — simulates shutdown race. Only the
    // phase-1 (`accept`) token needs to be pre-cancelled: that is the one
    // `client_accept_loop`'s accept arm watches.
    let ctx = RunTasks::new();
    ctx.accept.cancel();

    let builder = Obfs4PT::client_builder();
    // The loop must return within 2 s.  On the old code (no break)
    // it would spin indefinitely and the timeout would fire.
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client_accept_loop(listener, builder, ctx),
    )
    .await;

    assert!(
        result.is_ok(),
        "client_accept_loop must exit promptly when the token is cancelled, not spin"
    );
    assert!(
        result.unwrap().is_ok(),
        "client_accept_loop should return Ok(()) on graceful cancel"
    );
}

// -- Bridge-connection regression (fast_socks5 `execute_command`) --
//
// `client_handle_connection` must use fast-socks5 only to *parse* the
// request, never to execute it. With the default `execute_command = true`,
// `upgrade_to_socks5()` would itself open a *plain* TCP connection to the
// bridge and send the SOCKS reply — bypassing obfs4, so no bridge could
// ever be reached through the transport. The fix sets
// `execute_command(false)` and has lyrebird dial obfs4 itself, replying to
// the parent only once the tunnel is up. These tests drive the real SOCKS5
// client protocol against `client_handle_connection` pointed at a real
// loopback "bridge".

/// Play the SOCKS5 client (as arti/tor would) over `parent`: user/pass
/// auth carrying the PT arg string, then a CONNECT to `bridge`. Returns
/// after the CONNECT request is sent; the caller asserts on the reply.
async fn socks5_client_connect<S>(parent: &mut S, arg_string: &str, bridge: SocketAddr)
where
    // Both the in-memory duplex (handshake unit tests) and a real
    // TcpStream (lifecycle tests below) drive the same protocol.
    S: AsyncRead + AsyncWrite + Unpin,
{
    let socks_args = ptrs::args::Args::parse_smethod_args(arg_string)
        .expect("parse SMETHOD bridge-line args")
        .encode_client_parameters();
    // greeting: VER=5, 1 method, user/pass (0x02)
    parent.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    parent.flush().await.unwrap();
    let mut sel = [0u8; 2];
    parent.read_exact(&mut sel).await.unwrap();
    assert_eq!(sel, [0x05, 0x02], "server must select user/pass auth");

    // RFC 1929 user/pass: pack the arg string into UNAME, PASSWD = single
    // NUL (the `arg_string_from_creds` "uname only" form).
    let uname = socks_args.as_bytes();
    assert!(
        uname.len() <= 255,
        "this test packs the arg string into one SOCKS field"
    );
    let mut auth = vec![0x01, uname.len() as u8];
    auth.extend_from_slice(uname);
    auth.extend_from_slice(&[0x01, 0x00]); // PLEN=1, PASSWD=0x00
    parent.write_all(&auth).await.unwrap();
    parent.flush().await.unwrap();
    let mut authresp = [0u8; 2];
    parent.read_exact(&mut authresp).await.unwrap();
    assert_eq!(authresp, [0x01, 0x00], "user/pass auth must succeed");

    // CONNECT: VER=5, CMD=1, RSV=0, ATYP=1 (IPv4), addr, port.
    let (octets, port) = match bridge {
        SocketAddr::V4(v4) => (v4.ip().octets(), v4.port()),
        SocketAddr::V6(_) => unreachable!("test binds IPv4 loopback"),
    };
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&octets);
    req.extend_from_slice(&port.to_be_bytes());
    parent.write_all(&req).await.unwrap();
    parent.flush().await.unwrap();
}

#[tokio::test]
async fn client_handle_connection_tunnels_through_obfs4_and_replies_itself() {
    // A real loopback "bridge" running an obfs4 *server*. `server.wrap()`
    // completes only if an obfs4 *client* handshake arrives — i.e. the
    // connection that reached the bridge was obfs4, not a plain TCP proxy.
    // On the buggy `execute_command = true` path the bridge would instead
    // receive fast-socks5's plain relay and `wrap()` would never complete,
    // failing this test.
    let server_builder = obfs4::ServerBuilder::<TcpStream>::default();
    let arg_string = server_builder.client_params();
    let server = server_builder.build();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_addr = listener.local_addr().unwrap();

    let bridge = tokio::spawn(async move {
        let (sock, _peer) = listener.accept().await.expect("bridge accept");
        let mut s = server.wrap(sock).await.expect("bridge obfs4 handshake");
        let mut buf = [0u8; 64];
        let n = s.read(&mut buf).await.expect("bridge read");
        s.write_all(&buf[..n]).await.expect("bridge echo");
        s.flush().await.expect("bridge flush");
    });

    // Parent (arti/tor) side over an in-memory duplex; `lyrebird_side` is
    // the connection `client_handle_connection` serves SOCKS on.
    let (mut parent, lyrebird_side) = tokio::io::duplex(65_536);
    let builder = Obfs4PT::client_builder();
    let client_addr: SocketAddr = "127.0.0.1:9050".parse().unwrap();
    let handler = tokio::spawn(client_handle_connection(
        lyrebird_side,
        builder,
        client_addr,
    ));

    socks5_client_connect(&mut parent, &arg_string, bridge_addr).await;

    // The reply is the canonical success frame lyrebird writes itself
    // (fast-socks5 sends nothing — execute_command is disabled), and it
    // arrives only because the obfs4 tunnel to the bridge came up.
    let mut reply = [0u8; 10];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        parent.read_exact(&mut reply),
    )
    .await
    .expect("SOCKS5 reply timed out")
    .expect("read SOCKS5 reply");
    assert_eq!(
        reply,
        [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0],
        "lyrebird must send the SOCKS5 success reply itself after the obfs4 handshake"
    );

    // End-to-end: a probe must round-trip through the obfs4 tunnel.
    let probe = b"bridge-tunnel-probe";
    parent.write_all(probe).await.unwrap();
    parent.flush().await.unwrap();
    let mut got = vec![0u8; probe.len()];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        parent.read_exact(&mut got),
    )
    .await
    .expect("probe round-trip timed out")
    .expect("read probe echo");
    assert_eq!(
        &got, probe,
        "probe must round-trip through the obfs4 tunnel"
    );

    tokio::time::timeout(std::time::Duration::from_secs(5), bridge)
        .await
        .expect("bridge task timed out")
        .expect("bridge task panicked");
    drop(parent); // let copy_bidirectional see EOF and the handler finish
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handler).await;
}

#[tokio::test]
async fn client_handle_connection_no_success_reply_when_bridge_not_obfs4() {
    // The bridge accepts the TCP connection but is NOT an obfs4 server: it
    // closes immediately, so the obfs4 client handshake fails. lyrebird
    // must therefore NOT report CONNECT success to the parent. The old
    // `execute_command = true` path replied success on the bare TCP
    // connect regardless of whether obfs4 could be established, which is
    // exactly the bug — so this test would fail on it.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_addr = listener.local_addr().unwrap();
    let bridge = tokio::spawn(async move {
        let (sock, _peer) = listener.accept().await.expect("bridge accept");
        drop(sock); // not obfs4 — close before any handshake byte
    });

    // A well-formed cert so `options()` succeeds and the failure is the
    // handshake, not arg parsing; this throwaway identity is never honored.
    let arg_string = obfs4::ServerBuilder::<TcpStream>::default().client_params();

    let (mut parent, lyrebird_side) = tokio::io::duplex(65_536);
    let builder = Obfs4PT::client_builder();
    let client_addr: SocketAddr = "127.0.0.1:9050".parse().unwrap();
    let handler = tokio::spawn(client_handle_connection(
        lyrebird_side,
        builder,
        client_addr,
    ));

    socks5_client_connect(&mut parent, &arg_string, bridge_addr).await;

    // No success reply: the handler returns Err before writing one, so its
    // side of the duplex drops and the parent's read hits EOF rather than a
    // 10-byte success frame.
    let mut reply = [0u8; 10];
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        parent.read_exact(&mut reply),
    )
    .await
    .expect("the read should resolve (EOF), not hang");
    assert!(
        read.is_err(),
        "no SOCKS5 success reply must be sent when the obfs4 handshake fails"
    );

    let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), handler)
        .await
        .expect("handler should finish")
        .expect("handler task panicked");
    assert!(
        outcome.is_err(),
        "client_handle_connection must surface the failed obfs4 dial as an error"
    );

    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), bridge).await;
}

// Неподдерживаемая схема отклоняется до открытия listener; ответ проверяется
// также на границе процесса в tests/proxy_error.rs.

/// Serialize the env-mutating tests below: `TOR_PT_*` variables are
/// process-global state, and `ClientInfo::new()` reads them. A tokio
/// mutex is used because the guarded region spans the awaits of
/// `client_setup` (a std `MutexGuard` held across `.await` is a lint
/// error and a deadlock hazard).
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn set_client_env(proxy: Option<&str>) {
    std::env::set_var("TOR_PT_MANAGED_TRANSPORT_VER", "1");
    std::env::set_var("TOR_PT_CLIENT_TRANSPORTS", "obfs4");
    match proxy {
        Some(uri) => std::env::set_var("TOR_PT_PROXY", uri),
        None => std::env::remove_var("TOR_PT_PROXY"),
    }
}

fn clear_client_env() {
    std::env::remove_var("TOR_PT_MANAGED_TRANSPORT_VER");
    std::env::remove_var("TOR_PT_CLIENT_TRANSPORTS");
    std::env::remove_var("TOR_PT_PROXY");
}

#[tokio::test]
async fn client_setup_rejects_configured_upstream_proxy() {
    let _guard = ENV_LOCK.lock().await;
    set_client_env(Some("http://user:pass@127.0.0.1:9050"));

    let outcome = client_setup("unused-test-state-dir", RunTasks::new()).await;

    clear_client_env();

    // The setup must fail closed without copying proxy credentials or URI
    // data into a returned error.
    let err = outcome.expect_err("unsupported TOR_PT_PROXY must abort client_setup");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("invalid or unsupported upstream proxy")
            && !msg.contains("127.0.0.1:9050")
            && !msg.contains("user:pass"),
        "the refusal must be actionable without echoing proxy data, got: {msg}"
    );
}

#[tokio::test]
async fn client_setup_without_proxy_spawns_owned_listener_tasks() {
    let _guard = ENV_LOCK.lock().await;
    set_client_env(None);

    // Without TOR_PT_PROXY the fail-closed path must not trigger: the
    // normal setup runs (listener bound, CMETHOD announced upstream) and
    // hands its accept loops back to the caller as an owned task set.
    let ctx = RunTasks::new();
    let outcome = client_setup("unused-test-state-dir", ctx.clone()).await;
    let mut listeners = outcome.expect("without TOR_PT_PROXY, client_setup must proceed normally");
    assert!(
        !listeners.is_empty(),
        "client_setup must return its accept loops for run() to own"
    );

    // Shutdown stops every accept loop, and each one exits CLEANLY: the
    // join surface now carries each listener's own Result plus the outer
    // JoinError, so neither error level can be lost silently.
    ctx.accept.cancel();
    loop {
        let next = tokio::time::timeout(TEST_STEP, listeners.join_next())
            .await
            .expect("accept loops must exit promptly after cancel");
        match next {
            None => break,
            Some(res) => assert!(
                matches!(res, Ok(Ok(()))),
                "accept loops must exit cleanly on cancel, got {res:?}"
            ),
        }
    }

    // No connection task can remain: every lifecycle permit is back.
    assert_no_connection_tasks(&ctx);

    clear_client_env();
}

// -- run() task-lifecycle regression (unified ownership + cancel paths) --
//
// `run()` must own every task it spawns and never return while any of them
// is still alive in the caller's runtime. `run()` itself cannot be called
// from a test (it parses argv), so these tests exercise the exact helpers
// run()'s exit paths use — `stop_accepting`, `join_accept_loops`,
// `drain_connections`, `cancel_connections` — against a REAL accept loop
// serving a REAL obfs4 tunnel, and assert lifecycle facts explicitly:
// the lifecycle-permit counter (an exact in-flight-connection count), the
// listener JoinSet being drained, and connect-refused on the bound port.
// Nothing here guesses by sleeping.

/// How long the lifecycle tests allow for a step that must be prompt.
const TEST_STEP: std::time::Duration = std::time::Duration::from_secs(5);

/// All lifecycle permits must be back: zero connection tasks in flight.
fn assert_no_connection_tasks(ctx: &RunTasks) {
    assert_eq!(
        ctx.lifecycle.available_permits(),
        MAX_CONCURRENT_CONNS,
        "connection tasks are still holding lifecycle permits"
    );
}

/// The port must refuse new connections: the listener task is gone, so
/// the socket is closed — the "ports are closed after run() returns"
/// property, asserted through the actual connect outcome.
async fn assert_port_closed(addr: SocketAddr) {
    assert!(addr.is_ipv4(), "test helper expects an IPv4 listener");
    let reservation = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve source port");
    let source = reservation.local_addr().expect("source address");
    assert_ne!(
        source.port(),
        addr.port(),
        "source and target ports must differ to avoid Linux self-connect"
    );
    drop(reservation);
    let socket = tokio::net::TcpSocket::new_v4().expect("create source socket");
    socket.bind(source).expect("bind reserved source port");
    match tokio::time::timeout(TEST_STEP, socket.connect(addr)).await {
        Err(_) => panic!("connect to {addr} timed out — port looks open"),
        Ok(Ok(_)) => panic!("connect to {addr} succeeded — port is still open"),
        Ok(Err(_)) => {} // refused: the listener socket is gone
    }
}

/// Write `msg` into the tunnel and read the echo back.
async fn roundtrip_through_tunnel(parent: &mut TcpStream, msg: &[u8]) {
    parent.write_all(msg).await.expect("tunnel write");
    parent.flush().await.expect("tunnel flush");
    let mut got = vec![0u8; msg.len()];
    tokio::time::timeout(TEST_STEP, parent.read_exact(&mut got))
        .await
        .expect("tunnel echo timed out")
        .expect("read tunnel echo");
    assert_eq!(&got, msg, "probe must round-trip through the tunnel");
}

/// Build one "listener + in-flight tunnel" stack: a real obfs4 echo
/// bridge, a `client_accept_loop` owned by `ctx` and registered in
/// `listeners` exactly the way run() owns it, and a parent TCP connection
/// that has completed SOCKS5 and round-tripped one probe through the
/// tunnel. Returns the parent stream and the accept-loop port.
async fn spawn_stack_with_active_tunnel(
    ctx: &RunTasks,
    listeners: &mut JoinSet<Result<()>>,
) -> (TcpStream, SocketAddr) {
    // The bridge: a real obfs4 server echoing everything it receives.
    let server_builder = obfs4::ServerBuilder::<TcpStream>::default();
    let arg_string = server_builder.client_params();
    let server = server_builder.build();
    let bridge_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_addr = bridge_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (sock, _peer) = bridge_listener.accept().await.expect("bridge accept");
        let mut s = server.wrap(sock).await.expect("bridge obfs4 handshake");
        let mut buf = [0u8; 512];
        loop {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    let _ = s.flush().await;
                }
            }
        }
    });

    // The accept loop, owned exactly the way run() owns it.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = listener.local_addr().unwrap();
    let builder = Obfs4PT::client_builder();
    listeners.spawn(client_accept_loop(listener, builder, ctx.clone()));

    // The parent (arti/tor stand-in) connects over real TCP and drives
    // the SOCKS5 handshake with the bridge-line args packed as user/pass.
    let mut parent = TcpStream::connect(socks_addr)
        .await
        .expect("connect to accept loop");
    socks5_client_connect(&mut parent, &arg_string, bridge_addr).await;

    // The success reply arrives only after the obfs4 tunnel is up —
    // proof that the connection task is alive and serving.
    let mut reply = [0u8; 10];
    tokio::time::timeout(TEST_STEP, parent.read_exact(&mut reply))
        .await
        .expect("SOCKS5 reply timed out")
        .expect("read SOCKS5 reply");
    assert_eq!(
        reply,
        [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0],
        "expected the SOCKS5 success frame written by the connection task"
    );

    // One round-trip proves the tunnel is actively relaying.
    roundtrip_through_tunnel(&mut parent, b"pre-shutdown-probe").await;
    (parent, socks_addr)
}

#[tokio::test]
async fn parent_eof_during_interrupt_drain_cancels_active_connection() {
    let ctx = RunTasks::new();
    let mut listeners = JoinSet::new();
    let (mut parent, socks_addr) = spawn_stack_with_active_tunnel(&ctx, &mut listeners).await;

    let (stdin_tx, mut stdin_rx) = tokio::sync::oneshot::channel();
    let (draining_tx, draining_rx) = tokio::sync::oneshot::channel();
    let mut draining_tx = Some(draining_tx);
    let accept = ctx.accept.clone();
    let stdin_wait = std::future::poll_fn(move |cx| {
        if accept.is_cancelled() {
            if let Some(tx) = draining_tx.take() {
                let _ = tx.send(());
            }
        }
        Pin::new(&mut stdin_rx)
            .poll(cx)
            .map(|result| result.expect("stdin test event"))
    });

    let (signal_tx, signal_rx) = tokio::sync::mpsc::channel(1);
    let signal_rx = Arc::new(tokio::sync::Mutex::new(signal_rx));
    let signal = move || {
        let rx = Arc::clone(&signal_rx);
        async move { rx.lock().await.recv().await.expect("signal test event") }
    };

    let run = drive(ctx.clone(), listeners, stdin_wait, signal);
    let events = async {
        signal_tx
            .send(Shutdown::Interrupt)
            .await
            .expect("send interrupt");
        draining_rx
            .await
            .expect("stdin must remain watched during drain");
        assert_port_closed(socks_addr).await;
        roundtrip_through_tunnel(&mut parent, b"draining-probe").await;
        stdin_tx.send(Ok(())).expect("send parent EOF event");
        // Keep the signal source alive until shutdown completes.
        signal_tx
    };
    let (result, _signals) = tokio::time::timeout(TEST_STEP, async { tokio::join!(run, events) })
        .await
        .expect("parent EOF must escalate the drain before 15 seconds");
    result.expect("lifecycle returned an error");
    assert_no_connection_tasks(&ctx);

    let mut buf = [0u8; 8];
    let n = tokio::time::timeout(TEST_STEP, parent.read(&mut buf))
        .await
        .expect("cancelled tunnel must reach EOF")
        .expect("read after parent EOF");
    assert_eq!(n, 0);
}

#[tokio::test]
async fn terminate_path_closes_ports_and_leaves_no_tasks() {
    let ctx = RunTasks::new();
    let mut listeners = JoinSet::new();
    let (mut parent, socks_addr) = spawn_stack_with_active_tunnel(&ctx, &mut listeners).await;

    // Exactly the terminate/EOF teardown run() performs: stop accepting,
    // cancel in-flight connections immediately, await them (bounded), and
    // join the accept loops.
    ctx.stop_accepting();
    tokio::time::timeout(TEST_STEP, cancel_connections(&ctx))
        .await
        .expect("forced teardown must be prompt, not stall out");
    join_accept_loops(&mut listeners).await;

    // The explicit zero-active-tasks signal: every lifecycle permit is
    // back, so no connection task survives run()'s shutdown.
    assert_no_connection_tasks(&ctx);

    // run()'s ports are closed: new connects are refused.
    assert_port_closed(socks_addr).await;

    // The in-flight tunnel was really torn down mid-transfer: the parent
    // sees EOF instead of a live connection.
    let mut buf = [0u8; 8];
    let n = tokio::time::timeout(TEST_STEP, parent.read(&mut buf))
        .await
        .expect("EOF read should resolve")
        .expect("read after teardown");
    assert_eq!(
        n, 0,
        "terminate must drop the in-flight tunnel (parent sees EOF)"
    );

    // The listener JoinSet is fully drained: no owned task remains.
    let leftover =
        tokio::time::timeout(std::time::Duration::from_millis(100), listeners.join_next())
            .await
            .expect("joining an empty set must resolve immediately");
    assert!(leftover.is_none(), "no accept-loop task may remain");
}

#[tokio::test]
async fn soft_interrupt_lets_inflight_transfer_finish() {
    let ctx = RunTasks::new();
    let mut listeners = JoinSet::new();
    let (mut parent, socks_addr) = spawn_stack_with_active_tunnel(&ctx, &mut listeners).await;

    // Soft interrupt, exactly run()'s sequence: phase 1 stops accepting,
    // then the accept loops are joined (so the port really closes).
    ctx.stop_accepting();
    join_accept_loops(&mut listeners).await;

    // No new connections: the port is closed...
    assert_port_closed(socks_addr).await;

    // ...but the CURRENT transfer must keep flowing, not be cut off.
    roundtrip_through_tunnel(&mut parent, b"post-shutdown-probe").await;
    assert!(
        !ctx.conns.is_cancelled(),
        "graceful drain must not force-cancel in-flight connections"
    );

    // The parent goes away on its own; the connection task must finish
    // within the drain budget (well under it here) and release its
    // lifecycle permit — the explicit zero-tasks signal.
    drop(parent);
    let drained = tokio::time::timeout(TEST_STEP, drain_connections(&ctx, TEST_STEP))
        .await
        .expect("drain must resolve");
    assert!(drained, "drain_connections must report graceful completion");
    assert_no_connection_tasks(&ctx);

    let leftover =
        tokio::time::timeout(std::time::Duration::from_millis(100), listeners.join_next())
            .await
            .expect("joining an empty set must resolve immediately");
    assert!(leftover.is_none(), "no owned task may remain");
}

#[tokio::test]
async fn drain_budget_expiry_cancels_inflight_connections() {
    let ctx = RunTasks::new();
    let mut listeners = JoinSet::new();
    let (mut parent, socks_addr) = spawn_stack_with_active_tunnel(&ctx, &mut listeners).await;

    ctx.stop_accepting();
    join_accept_loops(&mut listeners).await;

    // The parent keeps the tunnel open, so it cannot finish on its own.
    // A 150 ms budget must expire and report "not drained" — without
    // force-cancelling anything yet.
    let drained = drain_connections(&ctx, std::time::Duration::from_millis(150)).await;
    assert!(
        !drained,
        "an open tunnel cannot finish within a 150 ms budget"
    );
    assert!(
        !ctx.conns.is_cancelled(),
        "the budget phase alone must not force-cancel"
    );

    // run() then cancels the remainder and awaits them (bounded) — this
    // must be prompt, proving the forced teardown cannot hang run().
    tokio::time::timeout(TEST_STEP, cancel_connections(&ctx))
        .await
        .expect("forced teardown must be prompt");
    assert!(ctx.conns.is_cancelled());
    assert_no_connection_tasks(&ctx);
    assert_port_closed(socks_addr).await;

    // The in-flight tunnel was really cancelled mid-transfer: the parent
    // sees EOF.
    let mut buf = [0u8; 8];
    let n = tokio::time::timeout(TEST_STEP, parent.read(&mut buf))
        .await
        .expect("EOF read should resolve")
        .expect("read after forced teardown");
    assert_eq!(
        n, 0,
        "forced teardown must drop the tunnel (parent sees EOF)"
    );
}
