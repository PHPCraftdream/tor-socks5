//! JNI consumer tests. Adapter/auth tests below use real loopback sockets;
//! handler tests use the production internal egress seam without phone/live Tor.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use super::{onion_destination_allowed, AuthStateVerifier, ACCEPT_ERROR_BACKOFF};
use resocks5_net::server::{IncomingRequest, ServerError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::bridges::{accept_with_deadline, handle_connection_with_egress, EgressConnector};
use auth::{AuthState, User, UsersConfig};
use resocks5_net::connect::HostPort;

/// Синтетический peer для duplex-тестов (реальный адрес приходит из accept_loop).
fn loopback_peer() -> IpAddr {
    Ipv4Addr::LOCALHOST.into()
}

struct GatedLoopbackConnector {
    address: std::net::SocketAddr,
    entered: tokio::sync::oneshot::Sender<()>,
    release: tokio::sync::oneshot::Receiver<()>,
}

impl EgressConnector for GatedLoopbackConnector {
    async fn open_egress(
        self,
        target: HostPort<'_>,
    ) -> anyhow::Result<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>
    {
        assert_eq!(target.host, "127.0.0.1");
        assert_eq!(target.port, self.address.port());
        self.entered.send(()).unwrap();
        self.release.await.unwrap();
        Ok(TcpStream::connect(self.address).await?)
    }
}

struct FailingConnector {
    dialed: Arc<std::sync::atomic::AtomicBool>,
    expected: Option<(&'static str, u16)>,
}

impl EgressConnector for FailingConnector {
    async fn open_egress(
        self,
        target: HostPort<'_>,
    ) -> anyhow::Result<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>
    {
        self.dialed.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(expected) = self.expected {
            assert_eq!((target.host, target.port), expected);
        }
        Err::<TcpStream, _>(anyhow::anyhow!("injected egress failure"))
    }
}

struct PrefixConnector<S> {
    stream: S,
    delivered: Arc<std::sync::atomic::AtomicUsize>,
    input_len: usize,
}

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static> EgressConnector
    for PrefixConnector<S>
{
    async fn open_egress(
        self,
        target: HostPort<'_>,
    ) -> anyhow::Result<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>
    {
        assert_eq!((target.host, target.port), ("example.com", 443));
        // All prefix bytes left the client transport before egress, so only
        // the handler's pipeline path can deliver them upstream.
        assert_eq!(
            self.delivered.load(std::sync::atomic::Ordering::SeqCst),
            self.input_len
        );
        Ok(self.stream)
    }
}

fn one_user_state(name: &str, password: &str) -> Arc<AuthState> {
    let user = User {
        name: name.into(),
        hash: auth::compute_hash(password).unwrap(),
        is_enabled: true,
        allowed_onion: false,
        allowed_clients: None,
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

/// Runs the JNI adapter/auth wiring over loopback; closes on terminal errors.
async fn run_handshake_over_loopback(
    auth: Option<Arc<AuthState>>,
    client_script: impl FnOnce(TcpStream) -> tokio::task::JoinHandle<()> + Send + 'static,
) -> std::result::Result<IncomingRequest, ServerError> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let client_task = tokio::spawn(async move {
        let client = TcpStream::connect(addr).await.unwrap();
        client_script(client).await.unwrap();
    });

    let (mut server_stream, _peer) = listener.accept().await.unwrap();
    let auth = auth
        .map(|state| Arc::new(AuthStateVerifier(state)) as Arc<dyn socks5_proto::PasswordVerifier>);
    let result = accept_with_deadline(&mut server_stream, auth).await;
    drop(server_stream);

    client_task.await.unwrap();
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
            // return a SDK request (handle_connection would now
            // proceed to `tunnel.connect`).
            client
                .write_all(&[0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80])
                .await
                .unwrap();
        })
    })
    .await;

    let req = result.expect("correct credentials must be accepted");
    assert_eq!(req.target(), "1.2.3.4:80");
    assert_eq!(req.username(), Some("alice"));
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
    assert!(req.username().is_none());
}

#[test]
fn onion_policy_blocks_only_when_enabled() {
    for host in ["example.onion", "example.ONION."] {
        assert!(!onion_destination_allowed(host, true));
        assert!(onion_destination_allowed(host, false));
    }
    assert!(onion_destination_allowed("example.com", true));
}

/// Egress is gated so neither protocol may advertise success before readiness.
#[tokio::test]
async fn jni_same_port_protocols_wait_for_egress_and_relay_exact_payload() {
    use std::future::Future;
    use std::task::Poll;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    for http in [false, true] {
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let handler = tokio::spawn(handle_connection_with_egress(
            server,
            loopback_peer(),
            http.then(|| one_user_state("alice", "hunter2")),
            false,
            GatedLoopbackConnector {
                address: upstream_addr,
                entered: entered_tx,
                release: release_rx,
            },
        ));
        if http {
            client
                .write_all(
                    format!("CONNECT {upstream_addr} HTTP/1.1\r\nProxy-Authorization: Basic YWxpY2U6aHVudGVyMg==\r\n\r\nprefix").as_bytes(),
                )
                .await
                .unwrap();
        } else {
            client.write_all(&[5, 1, 0]).await.unwrap();
            let mut method = [0; 2];
            client.read_exact(&mut method).await.unwrap();
            assert_eq!(method, [5, 0]);
            let mut frame = vec![5, 1, 0, 1, 127, 0, 0, 1];
            frame.extend_from_slice(&upstream_addr.port().to_be_bytes());
            client.write_all(&frame).await.unwrap();
            client.write_all(b"prefix").await.unwrap();
        }
        entered_rx.await.unwrap();
        let mut first = [0];
        let mut reading = Box::pin(client.read_exact(&mut first));
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(reading.as_mut().poll(cx).is_pending())).await,
            "no tunnel response before egress readiness"
        );
        drop(reading);
        release_tx.send(()).unwrap();
        let (mut upstream, _) = upstream_listener.accept().await.unwrap();
        if http {
            let mut reply = vec![0; b"HTTP/1.1 200 Connection Established\r\n\r\n".len()];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, b"HTTP/1.1 200 Connection Established\r\n\r\n");
        } else {
            let mut reply = [0; 10];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[1], 0);
        }
        client.write_all(b"suffix").await.unwrap();
        client.shutdown().await.unwrap();
        let mut received = Vec::new();
        upstream.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"prefixsuffix");
        upstream.write_all(b"egress-response").await.unwrap();
        upstream.shutdown().await.unwrap();
        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"egress-response");
        handler.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn jni_http_auth_policy_and_upstream_failure_replies() {
    for (input, configured, block, expected, dials, success) in [
        ("CONNECT example.com:443 HTTP/1.1\r\n\r\n", true, false, 407, false, false),
        ("CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic YWxpY2U6V1JPTkc=\r\n\r\n", true, false, 407, false, false),
        ("CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic YWxpY2U6aHVudGVyMg==\r\n\r\n", false, false, 407, false, false),
        ("CONNECT example.ONION.:443 HTTP/1.1\r\nProxy-Authorization: Basic YWxpY2U6aHVudGVyMg==\r\n\r\n", true, true, 403, false, true),
        ("CONNECT example.onion:443 HTTP/1.1\r\n\r\n", false, false, 502, true, false),
        ("CONNECT example.onion.evil.com:443 HTTP/1.1\r\n\r\n", false, true, 502, true, false),
    ] {
        let (server, mut client) = tokio::io::duplex(2048);
        client.write_all(input.as_bytes()).await.unwrap();
        let dialed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = dialed.clone();
        let result = handle_connection_with_egress(
            server,
            loopback_peer(),
            configured.then(|| one_user_state("alice", "hunter2")),
            block,
            FailingConnector {
                dialed: observed,
                expected: None,
            },
        )
        .await;
        assert_eq!(result.is_ok(), success);
        assert_eq!(dialed.load(std::sync::atomic::Ordering::SeqCst), dials);
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await.unwrap();
        assert!(
            reply.starts_with(format!("HTTP/1.1 {expected} ").as_bytes()),
            "{reply:?}"
        );
        assert!(!reply.windows(b"HTTP/1.1 200".len()).any(|w| w == b"HTTP/1.1 200"));
    }
}

#[tokio::test]
async fn jni_http_ipv6_authority_passes_unbracketed_host_to_egress() {
    let (server, mut client) = tokio::io::duplex(1024);
    client
        .write_all(b"CONNECT [::1]:8443 HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let result = handle_connection_with_egress(
        server,
        loopback_peer(),
        None,
        false,
        FailingConnector {
            dialed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            expected: Some(("::1", 8443)),
        },
    )
    .await;
    assert!(result.is_err());
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).await.unwrap();
    assert!(reply.starts_with(b"HTTP/1.1 502 "));
}

#[tokio::test]
async fn jni_socks_egress_failure_uses_general_failure_rep1() {
    let (server, mut client) = tokio::io::duplex(256);
    client
        .write_all(&[5, 1, 0, 5, 1, 0, 1, 1, 2, 3, 4, 0, 80])
        .await
        .unwrap();
    let result = handle_connection_with_egress(
        server,
        loopback_peer(),
        None,
        false,
        FailingConnector {
            dialed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            expected: Some(("1.2.3.4", 80)),
        },
    )
    .await;
    assert!(result.is_err());
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 0, 5, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
}

struct ControlledPrefix<S> {
    inner: S,
    input: Vec<u8>,
    delivered: Arc<std::sync::atomic::AtomicUsize>,
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for ControlledPrefix<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let offset = self.delivered.load(std::sync::atomic::Ordering::SeqCst);
        if offset < self.input.len() {
            let n = buf.remaining().min(self.input.len() - offset);
            buf.put_slice(&self.input[offset..offset + n]);
            self.delivered
                .fetch_add(n, std::sync::atomic::Ordering::SeqCst);
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for ControlledPrefix<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn jni_http_buffered_binary_prefix_precedes_relay_exactly_once() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let prefix = b"\x00\xff\x80\r\n\x05";
        let suffix = b"\xfe\x00tail";
        let mut input = b"CONNECT example.com:443 HTTP/1.1\r\n\r\n".to_vec();
        input.extend_from_slice(prefix);
        let input_len = input.len();
        let delivered = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = delivered.clone();
        let (server, mut client) = tokio::io::duplex(2048);
        let server = ControlledPrefix {
            inner: server,
            input,
            delivered,
        };
        let (upstream, mut peer) = tokio::io::duplex(2048);
        let handler = tokio::spawn(handle_connection_with_egress(
            server,
            loopback_peer(),
            None,
            false,
            PrefixConnector {
                stream: upstream,
                delivered: observed,
                input_len,
            },
        ));
        let mut reply = vec![0; b"HTTP/1.1 200 Connection Established\r\n\r\n".len()];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, b"HTTP/1.1 200 Connection Established\r\n\r\n");
        let mut received_prefix = vec![0; prefix.len()];
        peer.read_exact(&mut received_prefix).await.unwrap();
        assert_eq!(received_prefix, prefix);
        client.write_all(suffix).await.unwrap();
        client.shutdown().await.unwrap();
        let mut remainder = Vec::new();
        peer.read_to_end(&mut remainder).await.unwrap();
        assert_eq!(remainder, suffix);
        peer.write_all(b"\x00\xffresponse").await.unwrap();
        peer.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"\x00\xffresponse");
        handler.await.unwrap().unwrap();
    })
    .await
    .expect("buffered prefix must be forwarded before waiting for relay input");
}

/// Fault injection after a confirmed short write. No retry, second response,
/// or bidirectional-copy read may occur after either reply or pipeline failure.
struct PartialFailure<S> {
    inner: S,
    remaining: usize,
    reads: Arc<std::sync::atomic::AtomicUsize>,
}
impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for PartialFailure<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for PartialFailure<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.remaining == 0 {
            return std::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        let len = buf.len().min(self.remaining);
        match std::pin::Pin::new(&mut self.inner).poll_write(cx, &buf[..len]) {
            std::task::Poll::Ready(Ok(n)) => {
                self.remaining -= n;
                std::task::Poll::Ready(Ok(n))
            }
            other => other,
        }
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn jni_partial_reply_and_pipeline_errors_are_terminal() {
    for fail_reply in [true, false] {
        let (server, mut client) = tokio::io::duplex(2048);
        let (upstream, mut peer) = tokio::io::duplex(2048);
        let input = b"CONNECT example.com:443 HTTP/1.1\r\n\r\npayload".to_vec();
        let input_len = input.len();
        let delivered = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = delivered.clone();
        let server = ControlledPrefix {
            inner: server,
            input,
            delivered,
        };
        let upstream_reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let egress = PartialFailure {
            inner: upstream,
            remaining: if fail_reply { usize::MAX } else { 3 },
            reads: upstream_reads.clone(),
        };
        let server = PartialFailure {
            inner: server,
            remaining: if fail_reply { 5 } else { usize::MAX },
            reads: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        };
        let result = handle_connection_with_egress(
            server,
            loopback_peer(),
            None,
            false,
            PrefixConnector {
                stream: egress,
                delivered: observed,
                input_len,
            },
        )
        .await;
        assert!(result.is_err());
        assert_eq!(
            upstream_reads.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "copy must not start after partial failure"
        );
        let mut received = Vec::new();
        peer.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, if fail_reply { &b""[..] } else { &b"pay"[..] });
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await.unwrap();
        assert_eq!(
            reply,
            if fail_reply {
                &b"HTTP/"[..]
            } else {
                &b"HTTP/1.1 200 Connection Established\r\n\r\n"[..]
            }
        );
    }
}
