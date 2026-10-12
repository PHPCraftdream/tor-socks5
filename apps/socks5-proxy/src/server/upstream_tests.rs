//! Tests for the upstream SOCKS5 egress.
//!
//! The SOCKS5 stubs below speak the wire protocol directly — no client
//! code is reused — so they keep checking what our side puts on the wire
//! regardless of which library implements the client. Failures are
//! asserted on the typed `ConnectError` from the chain, not on rendered
//! message text.

use std::net::Ipv6Addr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::{Upstream, UPSTREAM_SETUP_DEADLINE};
use resocks5_net::{ConnectError, ProtocolViolation, Stage};

const VER: u8 = 0x05;
const RFC1929_VER: u8 = 0x01;
const M_NO_AUTH: u8 = 0x00;
const M_USER_PASS: u8 = 0x02;
const M_NONE: u8 = 0xFF;
const REP_SUCCESS: u8 = 0x00;
const ATYP_V4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_V6: u8 = 0x04;

/// BND.ADDR shape of the stub's CONNECT reply. Every ATYP is exercised,
/// since the client must fully drain BND.ADDR to leave the returned
/// stream positioned at the tunnelled payload.
#[derive(Clone, Copy)]
enum Bnd {
    V4,
    V6,
    Domain,
}

impl Bnd {
    fn reply(self) -> Vec<u8> {
        match self {
            Bnd::V4 => vec![ATYP_V4, 0, 0, 0, 0, 0, 0],
            Bnd::V6 => {
                let mut v = vec![ATYP_V6];
                v.extend_from_slice(&[0u8; 16]);
                v.extend_from_slice(&[0, 0]);
                v
            }
            Bnd::Domain => vec![ATYP_DOMAIN, 0, 0, 0],
        }
    }
}

/// One-shot SOCKS5 upstream: greeting (plus RFC 1929 auth when
/// `require_auth`), the CONNECT target, then a reply made of `rep`,
/// `bnd` and `payload` written as ONE segment, so a payload coalesced
/// with the reply still arrives intact. Returns the dial address and a
/// task yielding the `(host, port)` the client asked for, or `None` when
/// the exchange aborted before CONNECT.
async fn fake_upstream(
    require_auth: bool,
    accept_creds: bool,
    rep: u8,
    bnd: Bnd,
    payload: &'static [u8],
) -> (String, tokio::task::JoinHandle<Option<(String, u16)>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();

        let mut head = [0u8; 2];
        s.read_exact(&mut head).await.unwrap();
        let mut methods = vec![0u8; head[1] as usize];
        s.read_exact(&mut methods).await.unwrap();

        if require_auth {
            if !methods.contains(&M_USER_PASS) {
                s.write_all(&[VER, M_NONE]).await.unwrap();
                return None;
            }
            s.write_all(&[VER, M_USER_PASS]).await.unwrap();
            let mut h = [0u8; 2];
            s.read_exact(&mut h).await.unwrap();
            let mut user = vec![0u8; h[1] as usize];
            s.read_exact(&mut user).await.unwrap();
            let mut pl = [0u8; 1];
            s.read_exact(&mut pl).await.unwrap();
            let mut pass = vec![0u8; pl[0] as usize];
            s.read_exact(&mut pass).await.unwrap();
            s.write_all(&[RFC1929_VER, if accept_creds { 0x00 } else { 0x01 }])
                .await
                .unwrap();
            if !accept_creds {
                return None;
            }
        } else {
            if !methods.contains(&M_NO_AUTH) {
                s.write_all(&[VER, M_NONE]).await.unwrap();
                return None;
            }
            s.write_all(&[VER, M_NO_AUTH]).await.unwrap();
        }

        let mut req = [0u8; 4];
        s.read_exact(&mut req).await.unwrap();
        let host = match req[3] {
            ATYP_V4 => {
                let mut a = [0u8; 4];
                s.read_exact(&mut a).await.unwrap();
                format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
            }
            ATYP_DOMAIN => {
                let mut l = [0u8; 1];
                s.read_exact(&mut l).await.unwrap();
                let mut b = vec![0u8; l[0] as usize];
                s.read_exact(&mut b).await.unwrap();
                String::from_utf8(b).unwrap()
            }
            ATYP_V6 => {
                let mut a = [0u8; 16];
                s.read_exact(&mut a).await.unwrap();
                Ipv6Addr::from(a).to_string()
            }
            other => panic!("unexpected ATYP {other}"),
        };
        let mut port = [0u8; 2];
        s.read_exact(&mut port).await.unwrap();

        let mut reply = vec![VER, rep, 0x00];
        reply.extend_from_slice(&bnd.reply());
        reply.extend_from_slice(payload);
        s.write_all(&reply).await.unwrap();
        Some((host, u16::from_be_bytes(port)))
    });
    (addr, handle)
}

/// The typed failure behind a `connect` error: every branch of the error
/// mapping keeps the `ConnectError` in the anyhow chain.
fn typed(err: &anyhow::Error) -> &ConnectError {
    err.downcast_ref::<ConnectError>()
        .unwrap_or_else(|| panic!("ConnectError missing from the chain of {err:#}"))
}

/// `connect` must fail — and the returned stream (`AnyUpstream`) has no
/// `Debug`, so `Result::expect_err` is not available here.
fn failure(result: anyhow::Result<resocks5_net::connect::AnyUpstream>) -> anyhow::Error {
    match result {
        Ok(_) => panic!("connect must fail"),
        Err(e) => e,
    }
}

#[tokio::test]
async fn no_auth_connect_domain_succeeds() {
    let (addr, handle) = fake_upstream(false, false, REP_SUCCESS, Bnd::V4, b"ok").await;
    let up = Upstream::new(addr, None);
    let mut s = up.connect("example.com", 443).await.expect("connect ok");
    assert_eq!(
        handle.await.unwrap(),
        Some(("example.com".to_string(), 443))
    );
    let mut payload = [0u8; 2];
    s.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"ok");
}

#[tokio::test]
async fn no_auth_connect_ipv4_uses_v4_atyp() {
    let (addr, handle) = fake_upstream(false, false, REP_SUCCESS, Bnd::V4, b"").await;
    let up = Upstream::new(addr, None);
    let _s = up.connect("1.2.3.4", 80).await.expect("connect ok");
    assert_eq!(handle.await.unwrap(), Some(("1.2.3.4".to_string(), 80)));
}

#[tokio::test]
async fn connect_ipv6_literal_uses_v6_atyp() {
    let (addr, handle) = fake_upstream(false, false, REP_SUCCESS, Bnd::V4, b"").await;
    let up = Upstream::new(addr, None);
    let _s = up.connect("::1", 443).await.expect("connect ok");
    assert_eq!(
        handle.await.unwrap(),
        Some(("::1".to_string(), 443)),
        "IPv6 literal must be sent as ATYP 4, not a domain"
    );
}

#[tokio::test]
async fn auth_connect_succeeds_with_good_credentials() {
    let (addr, handle) = fake_upstream(true, true, REP_SUCCESS, Bnd::V4, b"").await;
    let up = Upstream::new(addr, Some(("alice".into(), "secret".into())));
    let _s = up.connect("example.com", 8080).await.expect("connect ok");
    assert_eq!(
        handle.await.unwrap(),
        Some(("example.com".to_string(), 8080))
    );
}

/// A BND.ADDR that is NOT drained would leave those bytes in the stream
/// and the payload assertion below would fail.
#[tokio::test]
async fn bnd_addr_v6_is_drained() {
    let (addr, handle) = fake_upstream(false, false, REP_SUCCESS, Bnd::V6, b"tail").await;
    let up = Upstream::new(addr, None);
    let mut s = up.connect("example.com", 443).await.expect("connect ok");
    handle.await.unwrap().expect("stub reached CONNECT");
    let mut payload = [0u8; 4];
    s.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"tail");
}

#[tokio::test]
async fn bnd_addr_domain_is_drained() {
    let (addr, handle) = fake_upstream(false, false, REP_SUCCESS, Bnd::Domain, b"tail").await;
    let up = Upstream::new(addr, None);
    let mut s = up.connect("example.com", 443).await.expect("connect ok");
    handle.await.unwrap().expect("stub reached CONNECT");
    let mut payload = [0u8; 4];
    s.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"tail");
}

#[tokio::test]
async fn payload_coalesced_with_reply_passes_through_untouched() {
    let (addr, handle) =
        fake_upstream(false, false, REP_SUCCESS, Bnd::Domain, b"hello world").await;
    let up = Upstream::new(addr, None);
    let mut s = up.connect("example.com", 443).await.expect("connect ok");
    handle.await.unwrap().expect("stub reached CONNECT");
    let mut payload = Vec::new();
    s.read_to_end(&mut payload)
        .await
        .unwrap_or_else(|e| panic!("read_to_end failed: {e}"));
    assert_eq!(payload, b"hello world");
}

#[tokio::test]
async fn auth_rejected_credentials_errors() {
    let (addr, handle) = fake_upstream(true, false, REP_SUCCESS, Bnd::V4, b"").await;
    let up = Upstream::new(addr, Some(("alice".into(), "WRONG".into())));
    let err = failure(up.connect("example.com", 80).await);
    match typed(&err) {
        ConnectError::AuthFailed { status } => assert_eq!(*status, 0x01),
        other => panic!("unexpected: {other:?}"),
    }
    assert!(err.to_string().contains("rejected our credentials"));
    let _ = handle.await;
}

#[tokio::test]
async fn server_without_acceptable_method_errors() {
    // Server insists on USER/PASS but we offer only NO_AUTH.
    let (addr, handle) = fake_upstream(true, true, REP_SUCCESS, Bnd::V4, b"").await;
    let up = Upstream::new(addr, None);
    let err = failure(up.connect("example.com", 80).await);
    match typed(&err) {
        ConnectError::MethodUnsupported { got, with_auth } => {
            assert_eq!(*got, M_NONE);
            assert!(!*with_auth);
        }
        other => panic!("unexpected: {other:?}"),
    }
    assert!(err
        .to_string()
        .contains("rejected all offered auth methods"));
    let _ = handle.await;
}

#[tokio::test]
async fn connect_failure_reply_is_surfaced() {
    // 0x05 = connection refused.
    let (addr, handle) = fake_upstream(false, false, 0x05, Bnd::V4, b"").await;
    let up = Upstream::new(addr, None);
    let err = failure(up.connect("example.com", 80).await);
    match typed(&err) {
        ConnectError::ProxyRejected { code, .. } => assert_eq!(*code, Some(0x05)),
        other => panic!("unexpected: {other:?}"),
    }
    let msg = err.to_string();
    assert!(msg.contains("REP 0x5"), "unexpected: {msg}");
    assert!(msg.contains("connection refused"), "unexpected: {msg}");
    let _ = handle.await;
}

#[tokio::test]
async fn other_failure_reply_is_surfaced() {
    // 0x02 = connection not allowed by ruleset: a non-refused REP must be
    // reported just as explicitly.
    let (addr, handle) = fake_upstream(false, false, 0x02, Bnd::V4, b"").await;
    let up = Upstream::new(addr, None);
    let err = failure(up.connect("example.com", 80).await);
    match typed(&err) {
        ConnectError::ProxyRejected { code, .. } => assert_eq!(*code, Some(0x02)),
        other => panic!("unexpected: {other:?}"),
    }
    assert!(err.to_string().contains("REP 0x2"));
    let _ = handle.await;
}

/// A domain longer than the 255-byte SOCKS5 limit is rejected by the
/// client before the CONNECT request is written.
#[tokio::test]
async fn too_long_domain_is_rejected() {
    let (addr, handle) = fake_upstream(false, false, REP_SUCCESS, Bnd::V4, b"").await;
    let up = Upstream::new(addr, None);
    let long = "a".repeat(256);
    let err = failure(up.connect(&long, 80).await);
    match typed(&err) {
        ConnectError::Protocol(ProtocolViolation::Socks5DomainTooLong { len }) => {
            assert_eq!(*len, 256)
        }
        other => panic!("unexpected: {other:?}"),
    }
    handle.abort();
}

/// RFC 1929 credentials over 255 bytes are rejected, not truncated.
#[tokio::test]
async fn too_long_credentials_are_rejected() {
    let (addr, handle) = fake_upstream(true, true, REP_SUCCESS, Bnd::V4, b"").await;
    let up = Upstream::new(addr, Some(("a".repeat(256), "b".repeat(256))));
    let err = failure(up.connect("example.com", 80).await);
    match typed(&err) {
        ConnectError::Protocol(ProtocolViolation::Socks5CredentialsTooLong {
            username_len,
            password_len,
        }) => {
            assert_eq!(*username_len, 256);
            assert_eq!(*password_len, 256);
        }
        other => panic!("unexpected: {other:?}"),
    }
    handle.abort();
}

/// A proxy answering with something that is not SOCKS5 at all.
#[tokio::test]
async fn non_socks5_version_is_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let stub = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut head = [0u8; 2];
        s.read_exact(&mut head).await.unwrap();
        let mut methods = vec![0u8; head[1] as usize];
        s.read_exact(&mut methods).await.unwrap();
        // Version 0x04 instead of 0x05.
        s.write_all(&[0x04, M_NO_AUTH]).await.unwrap();
    });

    let up = Upstream::new(addr, None);
    let err = failure(up.connect("example.com", 80).await);
    match typed(&err) {
        ConnectError::Protocol(ProtocolViolation::Socks5BadVersion { got }) => {
            assert_eq!(*got, 0x04)
        }
        other => panic!("unexpected: {other:?}"),
    }
    stub.abort();
}

/// An address that is not `host:port` must be refused, never dialed.
#[tokio::test]
async fn malformed_address_is_rejected() {
    let up = Upstream::new("not-an-address".to_string(), None);
    assert!(!up.is_valid_address());
    let err = failure(up.connect("example.com", 80).await);
    assert!(
        err.to_string().contains("not a valid host:port"),
        "unexpected: {err}"
    );
}

/// A dial failure keeps the socket `io::Error` reachable in the chain:
/// `classify_conn_failure` in `server.rs` downcasts to it.
#[tokio::test]
async fn dial_failure_keeps_io_error_in_chain() {
    // Port 0 is refused immediately on every platform.
    let up = Upstream::new("127.0.0.1:0".to_string(), None);
    let err = failure(up.connect("example.com", 80).await);
    assert!(matches!(
        typed(&err),
        ConnectError::Io {
            stage: Stage::Connect,
            ..
        }
    ));
    assert!(
        err.chain()
            .any(|c| c.downcast_ref::<std::io::Error>().is_some()),
        "io::Error missing from the chain of {err:#}"
    );
}

// -- unoffered method selection ------------------------------------------

#[tokio::test]
async fn unoffered_no_auth_rejected_and_no_connect_sent() {
    // Client offers USER/PASS; server wrongly selects NO_AUTH and then
    // waits for a CONNECT that must never arrive.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut head = [0u8; 2];
        s.read_exact(&mut head).await.unwrap();
        let mut methods = vec![0u8; head[1] as usize];
        s.read_exact(&mut methods).await.unwrap();
        s.write_all(&[VER, M_NO_AUTH]).await.unwrap();
        // Wait for a CONNECT that must NOT be sent; resolve via EOF.
        let mut buf = [0u8; 64];
        let n = s.read(&mut buf).await.unwrap_or(0);
        n
    });

    let up = Upstream::new(addr, Some(("alice".into(), "secret".into())));
    let err = failure(up.connect("example.com", 80).await);
    match typed(&err) {
        ConnectError::MethodUnsupported { got, with_auth } => {
            assert_eq!(*got, M_NO_AUTH);
            assert!(*with_auth);
        }
        other => panic!("unexpected: {other:?}"),
    }
    assert!(err.to_string().contains("not offered"));
    // The client socket is dropped, so the fake's read hits EOF: 0
    // bytes received means no CONNECT reached the upstream.
    let n = server.await.unwrap();
    assert_eq!(n, 0, "no CONNECT bytes must reach the upstream");
}

#[tokio::test]
async fn unoffered_user_pass_rejected_without_auth() {
    // Client offers NO_AUTH; server wrongly selects USER/PASS — the
    // client must fail instead of running an unoffered auth exchange.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut head = [0u8; 2];
        s.read_exact(&mut head).await.unwrap();
        let mut methods = vec![0u8; head[1] as usize];
        s.read_exact(&mut methods).await.unwrap();
        s.write_all(&[VER, M_USER_PASS]).await.unwrap();
        // No RFC 1929 credentials may follow; resolve via EOF.
        let mut buf = [0u8; 64];
        s.read(&mut buf).await.unwrap_or(0)
    });

    let up = Upstream::new(addr, None);
    let err = failure(up.connect("example.com", 80).await);
    match typed(&err) {
        ConnectError::MethodUnsupported { got, with_auth } => {
            assert_eq!(*got, M_USER_PASS);
            assert!(!*with_auth);
        }
        other => panic!("unexpected: {other:?}"),
    }
    assert!(err.to_string().contains("not offered"));
    let n = server.await.unwrap();
    assert_eq!(n, 0, "no credential bytes must reach the upstream");
}

// -- upstream setup deadline ----------------------------------------------

/// Where the stalling upstream stops responding.
#[derive(Clone, Copy)]
enum Stall {
    /// Accept TCP, then never reply to the greeting.
    Accept,
    /// Reply `05 02`, then never reply to the credentials.
    MethodSelection,
    /// Complete the full auth exchange, then never reply to CONNECT.
    Auth,
}

/// An upstream that accepts and then stalls forever at `stall`
/// (parked via `pending()`, which never resolves — under paused time
/// a `sleep` would auto-advance).
async fn stalling_upstream(
    stall: Stall,
    require_auth: bool,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        async fn read_greeting(s: &mut tokio::net::TcpStream) -> Vec<u8> {
            let mut head = [0u8; 2];
            s.read_exact(&mut head).await.unwrap();
            let mut methods = vec![0u8; head[1] as usize];
            s.read_exact(&mut methods).await.unwrap();
            methods
        }
        let mut buf = [0u8; 1];
        match stall {
            Stall::Accept => {
                let _ = s.read(&mut buf).await; // ignore any EOF
                std::future::pending::<()>().await;
            }
            Stall::MethodSelection => {
                let _ = read_greeting(&mut s).await;
                let want = if require_auth { M_USER_PASS } else { M_NO_AUTH };
                s.write_all(&[VER, want]).await.unwrap();
                let _ = s.read(&mut buf).await;
                std::future::pending::<()>().await;
            }
            Stall::Auth => {
                let _ = read_greeting(&mut s).await;
                s.write_all(&[VER, M_USER_PASS]).await.unwrap();
                let mut h = [0u8; 2];
                s.read_exact(&mut h).await.unwrap();
                let mut user = vec![0u8; h[1] as usize];
                s.read_exact(&mut user).await.unwrap();
                let mut pl = [0u8; 1];
                s.read_exact(&mut pl).await.unwrap();
                let mut pass = vec![0u8; pl[0] as usize];
                s.read_exact(&mut pass).await.unwrap();
                s.write_all(&[RFC1929_VER, 0x00]).await.unwrap();
                let _ = s.read(&mut buf).await;
                std::future::pending::<()>().await;
            }
        }
    });
    (addr, handle)
}

/// Every stall point must end as `Stage::Total`, the whole-setup budget,
/// and never as a per-stage one: the per-stage budgets are set above the
/// total on purpose.
fn assert_setup_deadline(err: &anyhow::Error) {
    match typed(err) {
        ConnectError::Timeout {
            stage: Stage::Total,
            kind,
            after,
            ..
        } => {
            assert_eq!(*kind, resocks5_net::TimeoutKind::Total);
            assert_eq!(*after, UPSTREAM_SETUP_DEADLINE);
        }
        other => panic!("unexpected: {other:?}"),
    }
    assert!(err.to_string().contains("upstream setup deadline"));
}

#[tokio::test(start_paused = true)]
async fn stall_after_accept_hits_setup_deadline() {
    // With credentials configured (exercises the longest path).
    let (addr, handle) = stalling_upstream(Stall::Accept, true).await;
    let up = Upstream::new(addr, Some(("alice".into(), "secret".into())));
    let err = failure(up.connect("example.com", 80).await);
    assert_setup_deadline(&err);
    handle.abort();
}

#[tokio::test(start_paused = true)]
async fn stall_after_method_selection_hits_setup_deadline() {
    let (addr, handle) = stalling_upstream(Stall::MethodSelection, true).await;
    let up = Upstream::new(addr, Some(("alice".into(), "secret".into())));
    let err = failure(up.connect("example.com", 80).await);
    assert_setup_deadline(&err);
    handle.abort();
}

#[tokio::test(start_paused = true)]
async fn stall_after_auth_hits_setup_deadline() {
    let (addr, handle) = stalling_upstream(Stall::Auth, true).await;
    let up = Upstream::new(addr, Some(("alice".into(), "secret".into())));
    let err = failure(up.connect("example.com", 80).await);
    assert_setup_deadline(&err);
    handle.abort();
}

#[tokio::test(start_paused = true)]
async fn stall_after_accept_no_auth_hits_setup_deadline() {
    let (addr, handle) = stalling_upstream(Stall::Accept, false).await;
    let up = Upstream::new(addr, None);
    let err = failure(up.connect("example.com", 80).await);
    assert_setup_deadline(&err);
    handle.abort();
}

#[tokio::test]
async fn established_relay_survives_setup_deadline() {
    // Real time (not `start_paused`) for the handshake below: it is
    // several real-socket round trips between this task and the
    // spawned server task, and under a paused clock the time driver
    // can fast-forward past a pending deadline before those loopback
    // bytes are actually delivered, failing the setup spuriously.
    // Only the "prove the elapsed deadline is irrelevant" step needs
    // simulated time, so the clock is paused (and jumped forward via
    // `advance`) AFTER the real handshake has genuinely completed.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        // Greeting + CONNECT reply, then echo until the peer goes away.
        let mut head = [0u8; 2];
        s.read_exact(&mut head).await.unwrap();
        let mut methods = vec![0u8; head[1] as usize];
        s.read_exact(&mut methods).await.unwrap();
        s.write_all(&[VER, M_NO_AUTH]).await.unwrap();
        let mut req = [0u8; 4];
        s.read_exact(&mut req).await.unwrap();
        let mut tail = vec![0u8; 6];
        s.read_exact(&mut tail).await.unwrap();
        s.write_all(&[VER, REP_SUCCESS, 0x00, ATYP_V4, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut buf = [0u8; 64];
        loop {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let up = Upstream::new(addr, None);
    // An IPv4 literal, not a domain: the fake server above drains a
    // fixed 6-byte tail (BND.ADDR + BND.PORT-shaped), which only
    // matches ATYP_V4's wire size (4 + 2 bytes). A domain name would
    // leave its own trailing bytes (LEN + name + port) unread in the
    // server's receive buffer, which the echo loop below would then
    // read and reflect back before ever seeing "ping".
    let mut s = up.connect("93.184.216.34", 80).await.expect("connect ok");
    // Let the setup deadline elapse; the relay must not be affected.
    // `pause` + `advance` (not `sleep` under a pre-paused runtime)
    // jumps the clock instantly without racing the handshake above.
    tokio::time::pause();
    tokio::time::advance(UPSTREAM_SETUP_DEADLINE + Duration::from_secs(1)).await;
    tokio::time::resume();
    s.write_all(b"ping").await.unwrap();
    let mut echo = [0u8; 4];
    s.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"ping");
    server.abort();
}
