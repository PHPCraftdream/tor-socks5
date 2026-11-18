use super::*;
use crate::config::Config;
use crate::upstream::pick_upstream;
use auth::UsersConfig;

fn onion_state(name: &str, enabled: bool, allowed_onion: bool) -> AuthState {
    let user = auth::User {
        name: name.into(),
        hash: auth::compute_hash("pw").unwrap(),
        is_enabled: enabled,
        allowed_onion,
        allowed_clients: None,
        pre_proxies: None,
        post_proxies: None,
    };
    AuthState::build(&UsersConfig { users: vec![user] }).unwrap()
}

#[test]
fn enabled_onion_services_with_upstream_emit_an_explicit_warning() {
    use std::sync::Mutex;

    struct LogBuffer(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for LogBuffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let logs = Arc::new(Mutex::new(Vec::new()));
    let output = Arc::clone(&logs);
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_target(false)
        .with_max_level(tracing::Level::WARN)
        .with_writer(move || LogBuffer(Arc::clone(&output)))
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let mut cfg = crate::config::Config::default();
    cfg.onion_services.push(proxy_config::OnionServiceEntry {
        nickname: "web".into(),
        enabled: true,
        address: None,
        key: None,
        circuit_hops: 4,
        ports: vec![proxy_config::OnionServicePort {
            onion_port: 80,
            target: "127.0.0.1:8080".into(),
        }],
    });
    crate::startup::warn_enabled_onion_services_with_upstream(&cfg);
    let logged = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
    assert!(
        logged.contains(
            "onion services are configured but are not started with upstream SOCKS5 egress"
        ),
        "expected explicit upstream warning, got: {logged}"
    );
    assert!(
        logged.contains("enabled=1"),
        "expected the enabled count: {logged}"
    );

    logs.lock().unwrap().clear();
    cfg.onion_services[0].enabled = false;
    crate::startup::warn_enabled_onion_services_with_upstream(&cfg);
    assert!(
        logs.lock().unwrap().is_empty(),
        "disabled services must not warn"
    );
}

#[tokio::test]
async fn shutdown_is_polled_before_validating_config() {
    let _serial = owners::TEST_LIFECYCLE.lock().await;
    // pre_proxies together with the DNS listener fails
    // `validate_pre_compatibility`, which runs right after the shutdown poll.
    let mut config = Config {
        pre_proxies: Some(
            "127.0.0.1:1080"
                .parse::<proxy_config::Socks5Endpoint>()
                .unwrap()
                .into(),
        ),
        ..Default::default()
    };
    config.dns_server.enabled = true;
    let args = ServerArgs {
        config,
        // The shutdown future resolves before any config-file access; the
        // path is required by `ServerArgs` but never touched here.
        config_path: std::path::PathBuf::from("shutdown-first.ktav"),
        obs_sink: ObservationSink::new(),
        upstream_addr: None,
        upstream_user: None,
        upstream_pass: None,
        no_upstream: false,
        pt_binary: tor_socks5_runtime::pt::PtBinary::Environment,
        dns_startup_policy: crate::api::DnsStartupPolicy::Required,
        test_hooks: None,
    };
    assert!(run_server(args, std::future::ready(())).await.is_ok());
}
use crate::config::UpstreamConfig;
use crate::config::{AllowedClients, ClientAccessConfig, SecurityConfig};
use resocks5_net::server::ServerError;
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use std::path::Path;

use bridge_line::BridgeLine;
use bridge_store::BridgeStore;
use time::OffsetDateTime;

fn disabled_cfg() -> UpstreamConfig {
    UpstreamConfig::default()
}

#[test]
fn pick_upstream_disabled_by_default() {
    let up = pick_upstream(&disabled_cfg(), None, None, None, false).unwrap();
    assert!(up.is_none(), "no config, no CLI → Tor egress");
}

#[test]
fn pick_upstream_cli_address_enables_and_overrides() {
    let cfg = disabled_cfg();
    let up = pick_upstream(&cfg, Some("127.0.0.1:9050"), None, None, false)
        .unwrap()
        .expect("CLI --upstream should enable");
    assert_eq!(up.address(), "127.0.0.1:9050");
    assert!(!up.has_auth());
}

#[test]
fn pick_upstream_config_enabled_is_used() {
    let cfg = UpstreamConfig {
        enabled: true,
        address: "10.0.0.1:1080".into(),
        username: String::new(),
        password: String::new(),
    };
    let up = pick_upstream(&cfg, None, None, None, false)
        .unwrap()
        .unwrap();
    assert_eq!(up.address(), "10.0.0.1:1080");
    assert!(!up.has_auth());
}

#[test]
fn pick_upstream_no_upstream_flag_forces_tor() {
    let cfg = UpstreamConfig {
        enabled: true,
        address: "10.0.0.1:1080".into(),
        username: String::new(),
        password: String::new(),
    };
    let up = pick_upstream(&cfg, Some("1.2.3.4:1080"), None, None, true).unwrap();
    assert!(up.is_none(), "--no-upstream wins over everything");
}

#[test]
fn pick_upstream_cli_credentials_override_config() {
    let cfg = UpstreamConfig {
        enabled: true,
        address: "10.0.0.1:1080".into(),
        username: "cfg-user".into(),
        password: "cfg-pass".into(),
    };
    let up = pick_upstream(&cfg, None, Some("cli-user"), Some("cli-pass"), false)
        .unwrap()
        .unwrap();
    assert!(up.has_auth());
}

#[test]
fn pick_upstream_enabled_without_address_errors() {
    let cfg = UpstreamConfig {
        enabled: true,
        address: String::new(),
        username: String::new(),
        password: String::new(),
    };
    let err = pick_upstream(&cfg, None, None, None, false).unwrap_err();
    assert!(format!("{err}").contains("no address"));
}

#[test]
fn pick_upstream_rejects_malformed_address_at_startup() {
    let cfg = UpstreamConfig {
        enabled: true,
        address: "127.0.0.1".into(),
        username: String::new(),
        password: String::new(),
    };
    let err = pick_upstream(&cfg, None, None, None, false).unwrap_err();
    assert!(format!("{err}").contains("HOST:PORT"), "got: {err}");

    // A valid address still passes (guard on the check itself).
    let cfg = UpstreamConfig {
        enabled: true,
        address: "127.0.0.1:9050".into(),
        username: String::new(),
        password: String::new(),
    };
    assert!(pick_upstream(&cfg, None, None, None, false)
        .unwrap()
        .is_some());
}

// -- classify_conn_failure -------------------------------------------------

/// Install rustls's process-wide `CryptoProvider` exactly once for this
/// test binary — mirrors the same helper in `tor_watchdog.rs` /
/// `arti-wrapper`'s own tests. Needed because
/// `real_tor_connect_error_downcasts_as_tor` below builds a real,
/// unbootstrapped `TorTunnel` against a fresh tempdir state dir, which
/// reaches far enough into arti's directory-manager setup to expect a
/// crypto provider already installed. `install_default()` errors if
/// called twice in the same process, so the error is intentionally
/// discarded.
fn ensure_crypto_provider() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// A real `arti_wrapper::TorError::Connect` wrapping a real
/// `arti_client::Error`, without any network activity: an unbootstrapped
/// `TorTunnel`'s `connect()` parses its target address (`IntoTorAddr`)
/// before ever touching the bootstrap state, and an invalid hostname
/// (embedded space — not a valid IP, `.onion`, or DNS hostname) fails
/// that parse synchronously, surfacing as `arti_client::Error`
/// (`TorAddrError::InvalidHostname` via its public `From` impl) wrapped
/// in `TorError::Connect` by `TorTunnel::connect`. This is a genuine
/// instance of the error type this classifier cares about, not a mock.
async fn real_tor_connect_error() -> arti_wrapper::TorError {
    ensure_crypto_provider();
    let dir = tempfile::tempdir().unwrap();
    let settings = arti_wrapper::Settings {
        state_dir: Some(dir.path().to_path_buf()),
        ..Default::default()
    };
    let tor = arti_wrapper::TorTunnel::create_unbootstrapped_with(settings)
        .expect("synchronous, no-I/O construction must succeed");
    tor.connect("not a valid host", 443)
        .await
        .expect_err("an invalid hostname must fail address parsing before any network I/O")
}

#[tokio::test]
async fn classify_conn_failure_tor_connect_is_other_stage_tor_kind() {
    let tor_err = real_tor_connect_error().await;
    assert!(matches!(tor_err, arti_wrapper::TorError::Connect { .. }));
    let err = anyhow::Error::new(tor_err);
    // Bare: no stage tag in the chain → Other stage; the kind is Tor.
    assert_eq!(
        classify_conn_failure(&err),
        (ConnStage::Other, ConnErrorKind::Tor)
    );
}

#[tokio::test]
async fn classify_conn_failure_tor_connect_wrapped_in_context_is_still_tor() {
    // A `.context(...)` call anywhere above the real cause must not
    // shadow the underlying Tor error — `classify_conn_failure` walks
    // the whole chain, not just the top frame. "tunneling through Tor"
    // is not a stage const, so the stage stays Other; the kind must stay
    // Tor.
    let tor_err = real_tor_connect_error().await;
    let err = anyhow::Error::new(tor_err).context("tunneling through Tor");
    assert_eq!(
        classify_conn_failure(&err),
        (ConnStage::Other, ConnErrorKind::Tor)
    );
}

#[test]
fn classify_conn_failure_io_reset_during_handshake_is_client() {
    let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "peer reset");
    let err = anyhow::Error::new(io_err).context(STAGE_HANDSHAKE);
    assert_eq!(
        classify_conn_failure(&err),
        (ConnStage::Handshake, ConnErrorKind::Client)
    );
}

#[test]
fn classify_conn_failure_unexpected_eof_during_handshake_is_client() {
    let io_err = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof");
    let err = anyhow::Error::new(io_err).context(STAGE_HANDSHAKE);
    assert_eq!(
        classify_conn_failure(&err),
        (ConnStage::Handshake, ConnErrorKind::Client)
    );
}

#[test]
fn classify_conn_failure_broken_pipe_without_stage_context_is_client() {
    // After the stage tags, the only untagged I/O escape path is the
    // SOCKS reply writes — which are client-side — so a bare drop-ish
    // io::Error still classifies Client.
    let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe closed");
    let err = anyhow::Error::new(io_err);
    assert_eq!(
        classify_conn_failure(&err),
        (ConnStage::Other, ConnErrorKind::Client)
    );
}

#[test]
fn classify_conn_failure_other_io_kind_is_other() {
    // An I/O error whose kind is unrelated to a client disconnect (and
    // with no stage context) must not be misclassified as Client.
    let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
    let err = anyhow::Error::new(io_err);
    assert_eq!(
        classify_conn_failure(&err),
        (ConnStage::Other, ConnErrorKind::Other)
    );
}

#[test]
fn classify_conn_failure_arbitrary_other_is_other() {
    let err = anyhow::anyhow!("some unrelated failure");
    assert_eq!(
        classify_conn_failure(&err),
        (ConnStage::Other, ConnErrorKind::Other)
    );
}

#[test]
fn relay_stage_reset_is_relay_not_client() {
    // The heart of the P2 fix: a Tor-side reset during data transfer is
    // no longer counted as client misbehavior — it lands in relay_errors
    // instead of client_errors.
    let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "peer reset");
    let err = anyhow::Error::new(io_err).context(STAGE_RELAY);
    assert_eq!(
        classify_conn_failure(&err),
        (ConnStage::Relay, ConnErrorKind::Relay)
    );
}

#[test]
fn relay_stage_non_io_error_is_other() {
    let err = anyhow::anyhow!("mid-relay failure").context(STAGE_RELAY);
    assert_eq!(
        classify_conn_failure(&err),
        (ConnStage::Relay, ConnErrorKind::Other)
    );
}

#[test]
fn connect_stage_upstream_reset_is_connect_other() {
    // A reset during the upstream connect is not attributable to the
    // SOCKS client; the connect_failed counter carries the stage signal.
    let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "peer reset");
    let err = anyhow::Error::new(io_err).context(STAGE_CONNECT_UPSTREAM);
    assert_eq!(
        classify_conn_failure(&err),
        (ConnStage::Connect, ConnErrorKind::Other)
    );
}

#[tokio::test]
async fn connect_stage_tor_error_is_connect_tor() {
    let tor_err = real_tor_connect_error().await;
    let err = anyhow::Error::new(tor_err).context(STAGE_CONNECT_TOR);
    assert_eq!(
        classify_conn_failure(&err),
        (ConnStage::Connect, ConnErrorKind::Tor)
    );
}

#[test]
fn same_reset_different_stage_classifies_differently() {
    // The stage-discrimination regression test: the IDENTICAL
    // io::ErrorKind::ConnectionReset classifies Client at the handshake
    // stage and Relay mid-transfer. A client-end-vs-Tor-end
    // discrimination test is deliberately NOT written here:
    // `tokio::io::copy_bidirectional` does not report WHICH side of the
    // relay errored, so that split is indeterminate by design (see
    // `ConnErrorKind::Relay`'s doc).
    let handshake_err = anyhow::Error::new(std::io::Error::new(
        std::io::ErrorKind::ConnectionReset,
        "peer reset",
    ))
    .context(STAGE_HANDSHAKE);
    assert_eq!(
        classify_conn_failure(&handshake_err),
        (ConnStage::Handshake, ConnErrorKind::Client)
    );

    let relay_err = anyhow::Error::new(std::io::Error::new(
        std::io::ErrorKind::ConnectionReset,
        "peer reset",
    ))
    .context(STAGE_RELAY);
    assert_eq!(
        classify_conn_failure(&relay_err),
        (ConnStage::Relay, ConnErrorKind::Relay)
    );
}

// -- absolute handshake deadline ------------------------------------------

/// Server-under-test driving the REAL `accept_loop` over a loopback
/// listener, with a caller-chosen permit cap so the number of in-flight
/// handlers is observable via `available_permits() == 0`.
async fn spawn_test_server() -> (
    std::net::SocketAddr,
    Arc<tokio::sync::Semaphore>,
    tokio::task::JoinHandle<()>,
) {
    spawn_test_server_with_upstream("127.0.0.1:1".to_string(), 1).await
}

/// Like `spawn_test_server`, but with a caller-chosen egress upstream
/// and permit cap.
async fn spawn_test_server_with_upstream(
    upstream_addr: String,
    cap: usize,
) -> (
    std::net::SocketAddr,
    Arc<tokio::sync::Semaphore>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let permits = Arc::new(tokio::sync::Semaphore::new(cap));
    // The egress never gets used: the deadline always fires first.
    let egress = Egress::Upstream(Arc::new(upstream::Upstream::new(upstream_addr, None)));
    let handle = tokio::spawn(accept_loop(
        listener,
        egress,
        None,
        permits.clone(),
        ConnHealthCounters::default(),
        Arc::new(AtomicU64::new(1)),
        SecurityConfig {
            block_onion: false,
            client_access: ClientAccessConfig {
                allowed_clients: AllowedClients::default(),
            },
        },
    ));
    (addr, permits, handle)
}

/// Deterministic (clock-free) wait for the server task to take the
/// permit: the current-thread runtime only makes progress via yields.
async fn wait_for_permit_taken(permits: &Arc<tokio::sync::Semaphore>) {
    for _ in 0..200 {
        if permits.available_permits() == 0 {
            return;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        permits.available_permits(),
        0,
        "server must hold the permit"
    );
}

/// Awaits real socket I/O without letting the paused clock auto-advance:
/// parking on a not-yet-signalled socket would jump the clock to the next
/// timer and fire a server deadline before the peer's bytes arrive.
async fn without_auto_advance<F: std::future::Future>(fut: F) -> F::Output {
    let mut fut = std::pin::pin!(fut);
    loop {
        tokio::select! {
            r = &mut fut => return r,
            _ = tokio::task::yield_now() => {}
        }
    }
}

// -- upstream setup deadline ----------------------------------------------

#[tokio::test(start_paused = true)]
async fn upstream_setup_stall_releases_permit_at_deadline() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Stalling upstream: answers the greeting with NO_AUTH, then parks
    // forever before any CONNECT reply.
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap().to_string();
    let (stalled_tx, stalled_rx) = tokio::sync::oneshot::channel::<()>();
    let upstream = tokio::spawn(async move {
        let (mut s, _) = upstream_listener.accept().await.unwrap();
        let mut head = [0u8; 2];
        s.read_exact(&mut head).await.unwrap();
        let mut methods = vec![0u8; head[1] as usize];
        s.read_exact(&mut methods).await.unwrap();
        s.write_all(&[0x05, 0x00]).await.unwrap();
        stalled_tx.send(()).ok();
        std::future::pending::<()>().await;
    });

    let (addr, permits, server) = spawn_test_server_with_upstream(upstream_addr, 1).await;

    // Drive a real client through a complete SOCKS5 handshake; the
    // server then parks in the upstream setup, holding the permit.
    let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut sel = [0u8; 2];
    without_auto_advance(client.read_exact(&mut sel))
        .await
        .unwrap();
    assert_eq!(sel, [0x05, 0x00]);
    // CONNECT 93.184.216.34:443 (example.com, IP literal — no DNS).
    client
        .write_all(&[0x05, 0x01, 0x00, 0x01, 93, 184, 216, 34, 0x01, 0xBB])
        .await
        .unwrap();

    // The dial (and its setup deadline) has started only once the upstream
    // has seen the greeting; jumping the clock earlier would arm the
    // deadline after the jump.
    without_auto_advance(stalled_rx).await.unwrap();
    wait_for_permit_taken(&permits).await;
    assert_eq!(
        permits.available_permits(),
        0,
        "permit must be held while the upstream setup stalls"
    );

    // The per-stage fallback timeouts sit 5s above the total deadline, so
    // releasing inside this window proves the total deadline fired.
    tokio::time::sleep(upstream::UPSTREAM_SETUP_DEADLINE - Duration::from_secs(1)).await;
    assert_eq!(
        permits.available_permits(),
        0,
        "permit must still be held before the setup deadline"
    );
    tokio::time::sleep(Duration::from_secs(2)).await;
    let _permit = tokio::time::timeout(Duration::from_secs(2), permits.acquire())
        .await
        .expect("permit must be released by the upstream setup deadline");
    server.abort();
    upstream.abort();
}

/// The production accept loop must hold one admission permit per
/// in-flight connection and return it when the handler ends: with a
/// two-permit cap, two silent clients exhaust the semaphore, and past
/// the handshake deadline both permits are released again. Removing
/// either the acquire or the release from `accept_loop` fails this.
#[tokio::test]
async fn accept_loop_holds_and_releases_an_admission_permit_per_connection() {
    let (addr, permits, server) =
        spawn_test_server_with_upstream("127.0.0.1:1".to_string(), 2).await;
    // Two silent clients: the server spawns a handler per connection,
    // each holding one of the two permits.
    let _c1 = tokio::net::TcpStream::connect(addr).await.unwrap();
    let _c2 = tokio::net::TcpStream::connect(addr).await.unwrap();
    // REAL time while the accept loop picks the sockets up: counting yields
    // under a paused clock races the kernel delivering the connections (a
    // yield loop finishes in microseconds) and a paused-clock timeout can
    // never fire, so neither bound is deterministic.
    let started = std::time::Instant::now();
    while permits.available_permits() != 0 {
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "both handlers must spawn and take their permits"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(
        permits.available_permits(),
        0,
        "two in-flight handlers must hold both permits"
    );

    // Only now freeze the clock: the absolute handshake deadline bounds each
    // stuck handler, so both permits come back once the handlers end.
    tokio::time::pause();
    tokio::time::sleep(HANDSHAKE_DEADLINE + Duration::from_secs(5)).await;
    let _both = tokio::time::timeout(Duration::from_secs(10), permits.acquire_many_owned(2))
        .await
        .expect("both permits must be released after the handshake deadline")
        .expect("semaphore not closed");
    server.abort();
}

#[tokio::test(start_paused = true)]
async fn silent_client_permit_released_at_handshake_deadline() {
    let (addr, permits, server) = spawn_test_server().await;
    // Connects and then sends nothing at all, holding the stream open.
    let _client = tokio::net::TcpStream::connect(addr).await.unwrap();
    wait_for_permit_taken(&permits).await;
    assert_eq!(
        permits.available_permits(),
        0,
        "permit must be held before the deadline"
    );

    tokio::time::sleep(HANDSHAKE_DEADLINE + Duration::from_secs(5)).await;
    let _permit = tokio::time::timeout(Duration::from_secs(10), permits.acquire())
        .await
        .expect("permit must be released by the absolute handshake deadline");
    server.abort();
}

#[tokio::test(start_paused = true)]
async fn partial_handshake_header_permit_released_at_deadline() {
    use tokio::io::AsyncWriteExt;
    let (addr, permits, server) = spawn_test_server().await;
    let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
    // Only the VER byte — an incomplete method-negotiation header.
    client.write_all(&[0x05]).await.unwrap();
    wait_for_permit_taken(&permits).await;
    assert_eq!(
        permits.available_permits(),
        0,
        "permit must be held before the deadline"
    );

    tokio::time::sleep(HANDSHAKE_DEADLINE + Duration::from_secs(5)).await;
    let _permit = tokio::time::timeout(Duration::from_secs(10), permits.acquire())
        .await
        .expect("permit must be released by the absolute handshake deadline");
    server.abort();
}

#[tokio::test(start_paused = true)]
async fn trickling_client_permit_released_despite_valid_bytes() {
    use tokio::io::AsyncWriteExt;
    let (addr, permits, server) = spawn_test_server().await;
    let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();

    // Trickle valid handshake bytes, each gap half the deadline, then
    // hang forever — the client never finishes the handshake and never
    // closes. Write errors are ignored: the server may drop the socket
    // mid-trickle once the deadline fires.
    let client_task = tokio::spawn(async move {
        client.write_all(&[0x05]).await.ok();
        tokio::time::sleep(HANDSHAKE_DEADLINE / 2).await;
        client.write_all(&[0x01]).await.ok();
        tokio::time::sleep(HANDSHAKE_DEADLINE / 2).await;
        client.write_all(&[0x00]).await.ok();
        tokio::time::sleep(Duration::from_secs(3600)).await;
    });

    wait_for_permit_taken(&permits).await;
    tokio::time::sleep(HANDSHAKE_DEADLINE * 2 / 3).await;
    assert_eq!(
        permits.available_permits(),
        0,
        "permit must still be held mid-trickle, before the deadline"
    );

    // Now past the deadline while the client is still alive and
    // mid-handshake — a per-read renewal would keep the permit held.
    tokio::time::sleep(HANDSHAKE_DEADLINE * 2 / 3).await;
    let _permit = tokio::time::timeout(Duration::from_secs(10), permits.acquire())
        .await
        .expect("permit must be released despite valid trickling bytes");
    server.abort();
    client_task.abort();
}

#[test]
fn handshake_deadline_error_is_classified_as_client() {
    // The SDK's typed deadline cause is retained beneath the stage tag.
    let err = anyhow::Error::new(ServerError::Deadline).context(STAGE_HANDSHAKE);
    assert!(matches!(
        err.downcast_ref::<ServerError>(),
        Some(ServerError::Deadline)
    ));
    assert_eq!(
        classify_conn_failure(&err),
        (ConnStage::Handshake, ConnErrorKind::Client),
        "a deadline expiry is client-side misbehavior, not Other"
    );
}

#[path = "server_dual_tests.rs"]
mod dual_port;

#[path = "tests/shutdown_tests.rs"]
mod shutdown_tests;
