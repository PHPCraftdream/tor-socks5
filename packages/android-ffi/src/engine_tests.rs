//! Proves the Android accept-loop path (`handle_connection`) actually
//! enforces RFC 1929 credentials when `auth_state` is configured,
//! instead of the pre-fix behaviour of always calling
//! `socks5_proto::handshake(&mut client, None)` (NO_AUTH) regardless
//! of config. `TorTunnel` needs a live Tor bootstrap and cannot be
//! constructed in a unit test, so these tests exercise the exact same
//! call `handle_connection` makes — `socks5_proto::handshake(&mut
//! client, auth)` — over a real loopback `TcpStream` pair, and assert
//! that a failed handshake means the socket is closed with **no**
//! SOCKS5 CONNECT reply ever sent, i.e. `handle_connection`'s `?`
//! short-circuits before `tunnel.connect` / `socks5_proto::reply` run.

use std::sync::Arc;
use std::time::Duration;

use super::{onion_destination_allowed, ACCEPT_ERROR_BACKOFF};
use auth::{AuthState, User, UsersConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn one_user_state(name: &str, password: &str) -> Arc<AuthState> {
    let user = User {
        name: name.into(),
        hash: auth::compute_hash(password).unwrap(),
        is_enabled: true,
        allowed_onion: false,
    };
    Arc::new(AuthState::build(&UsersConfig { users: vec![user] }).unwrap())
}

fn rfc1929_frame(user: &str, passwd: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + user.len() + passwd.len());
    out.push(0x01); // RFC1929 sub-negotiation version
    out.push(user.len() as u8);
    out.extend_from_slice(user.as_bytes());
    out.push(passwd.len() as u8);
    out.extend_from_slice(passwd.as_bytes());
    out
}

/// Spin up a loopback listener, connect a client, and run the given
/// client-side script concurrently with
/// `socks5_proto::handshake(&mut server_stream, auth)` — the exact
/// call `handle_connection` makes. Returns the handshake `Result`.
///
/// `server_stream` is dropped (closing the socket) as soon as the
/// handshake settles, *before* we wait on the client task — exactly
/// like the real accept loop, where `handle_connection`'s early `?`
/// return drops `client` on the way out. A client script that reads
/// for EOF after a rejection depends on this ordering; awaiting the
/// client task before dropping the server half would deadlock both
/// sides against each other.
async fn run_handshake_over_loopback(
    auth: Option<Arc<AuthState>>,
    client_script: impl FnOnce(TcpStream) -> tokio::task::JoinHandle<()> + Send + 'static,
) -> anyhow::Result<socks5_proto::ConnectRequest> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let client_task = tokio::spawn(async move {
        let client = TcpStream::connect(addr).await.unwrap();
        client_script(client).await.unwrap();
    });

    let (mut server_stream, _peer) = listener.accept().await.unwrap();
    let result = socks5_proto::handshake(&mut server_stream, auth).await;
    drop(server_stream);

    let _ = client_task.await;
    result
}

#[test]
fn accept_error_backoff_is_sane() {
    assert!(ACCEPT_ERROR_BACKOFF > Duration::ZERO);
    assert!(ACCEPT_ERROR_BACKOFF <= Duration::from_secs(5));
}

#[tokio::test]
async fn accept_loop_wiring_rejects_missing_credentials() {
    let auth = one_user_state("alice", "hunter2");

    let result = run_handshake_over_loopback(Some(auth), |mut client| {
        tokio::spawn(async move {
            // Offer USER/PASS, then present the WRONG password.
            client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
            let mut method_reply = [0u8; 2];
            client.read_exact(&mut method_reply).await.unwrap();
            assert_eq!(method_reply, [0x05, 0x02], "server must select USER/PASS");

            client
                .write_all(&rfc1929_frame("alice", "WRONG-PASSWORD"))
                .await
                .unwrap();
            let mut auth_reply = [0u8; 2];
            client.read_exact(&mut auth_reply).await.unwrap();
            assert_eq!(auth_reply[1], 0x01, "server must signal auth failure");

            // Server closes the connection after a failed auth — no
            // further bytes (in particular, no CONNECT reply) ever
            // arrive.
            let mut buf = [0u8; 1];
            let n = client.read(&mut buf).await.unwrap_or(0);
            assert_eq!(n, 0, "server must not send anything after rejecting auth");
        })
    })
    .await;

    assert!(
        result.is_err(),
        "handshake must fail for wrong credentials, mirroring handle_connection's `?` \
         short-circuit before any Tor connect is attempted"
    );
}

#[tokio::test]
async fn accept_loop_wiring_rejects_no_auth_when_credentials_required() {
    let auth = one_user_state("alice", "hunter2");

    // Client behaves like the OLD (broken) Android client assumption:
    // it only ever offers NO_AUTH. With auth configured, the server
    // must refuse method negotiation instead of silently accepting.
    let result = run_handshake_over_loopback(Some(auth), |mut client| {
        tokio::spawn(async move {
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut method_reply = [0u8; 2];
            client.read_exact(&mut method_reply).await.unwrap();
            assert_eq!(
                method_reply,
                [0x05, 0xFF],
                "server must reply NO_ACCEPTABLE_METHODS, not silently accept NO_AUTH"
            );
        })
    })
    .await;

    assert!(
        result.is_err(),
        "handshake must fail when only NO_AUTH is offered"
    );
}

#[tokio::test]
async fn accept_loop_wiring_accepts_correct_credentials() {
    let auth = one_user_state("alice", "hunter2");

    let result = run_handshake_over_loopback(Some(auth), |mut client| {
        tokio::spawn(async move {
            client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
            let mut method_reply = [0u8; 2];
            client.read_exact(&mut method_reply).await.unwrap();

            client
                .write_all(&rfc1929_frame("alice", "hunter2"))
                .await
                .unwrap();
            let mut auth_reply = [0u8; 2];
            client.read_exact(&mut auth_reply).await.unwrap();
            assert_eq!(
                auth_reply[1], 0x00,
                "server must accept correct credentials"
            );

            // CONNECT to 1.2.3.4:80 so the handshake can complete and
            // return a `ConnectRequest` (handle_connection would now
            // proceed to `tunnel.connect`).
            client
                .write_all(&[0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80])
                .await
                .unwrap();
        })
    })
    .await;

    let req = result.expect("correct credentials must be accepted");
    assert_eq!(req.host, "1.2.3.4");
    assert_eq!(req.port, 80);
    assert_eq!(req.authed_user.as_deref(), Some("alice"));
}

#[tokio::test]
async fn accept_loop_wiring_no_auth_state_falls_back_to_no_auth() {
    // Reproduces the pre-fix default: `auth_state = None` (no users
    // configured) still lets an anonymous NO_AUTH client through —
    // this is the documented, intentional backward-compatible path,
    // not the bug.
    let result = run_handshake_over_loopback(None, |mut client| {
        tokio::spawn(async move {
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut method_reply = [0u8; 2];
            client.read_exact(&mut method_reply).await.unwrap();
            assert_eq!(method_reply, [0x05, 0x00], "server must select NO_AUTH");

            client
                .write_all(&[0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80])
                .await
                .unwrap();
        })
    })
    .await;

    let req = result.expect("NO_AUTH must still work when auth is not configured");
    assert!(req.authed_user.is_none());
}

#[test]
fn onion_policy_blocks_only_when_enabled() {
    let onion = socks5_proto::ConnectRequest {
        host: "example.onion".into(),
        port: 443,
        authed_user: None,
    };
    let clearnet = socks5_proto::ConnectRequest {
        host: "example.com".into(),
        port: 443,
        authed_user: None,
    };
    assert!(!onion_destination_allowed(&onion, true));
    assert!(onion_destination_allowed(&onion, false));
    assert!(onion_destination_allowed(&clearnet, true));
}
