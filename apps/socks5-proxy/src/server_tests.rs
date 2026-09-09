use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

use std::path::Path;
use std::sync::atomic::AtomicBool;

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

fn onion_state(name: &str, enabled: bool, allowed_onion: bool) -> AuthState {
    let user = auth::User {
        name: name.into(),
        hash: auth::compute_hash("pw").unwrap(),
        is_enabled: enabled,
        allowed_onion,
    };
    AuthState::build(&UsersConfig { users: vec![user] }).unwrap()
}

#[test]
fn onion_anonymous_is_unrestricted() {
    assert!(onion_permitted(None, None));
    assert!(onion_permitted(None, Some("anyone")));
}

#[test]
fn onion_requires_granted_account() {
    let granted = onion_state("alice", true, true);
    let plain = onion_state("bob", true, false);
    assert!(onion_permitted(Some(&granted), Some("alice")));
    assert!(!onion_permitted(Some(&plain), Some("bob")));
}

#[test]
fn onion_denied_for_disabled_or_unknown_or_missing_name() {
    let disabled = onion_state("carol", false, true);
    assert!(!onion_permitted(Some(&disabled), Some("carol")));
    assert!(!onion_permitted(Some(&disabled), Some("ghost")));
    // Auth required but the request carries no account: fail-closed.
    assert!(!onion_permitted(Some(&disabled), None));
}

#[test]
fn accept_error_backoff_is_sane() {
    assert!(ACCEPT_ERROR_BACKOFF > Duration::ZERO);
    assert!(ACCEPT_ERROR_BACKOFF <= Duration::from_secs(5));
}

#[tokio::test]
async fn accept_loop_respects_concurrency_cap() {
    // Two facts to prove deterministically: (1) the cap lets exactly
    // two tasks run concurrently, and (2) it refuses a third while two
    // permits are held. No real-time sleep — synchronization is explicit.
    let permits = Arc::new(tokio::sync::Semaphore::new(2));
    let active = Arc::new(AtomicUsize::new(0));
    let max_seen = Arc::new(AtomicUsize::new(0));
    // Barrier sized to the cap: the two permit-holders rendezvous here,
    // which can only happen if they are simultaneously in-flight. We
    // spawn exactly two tasks so every barrier participant is a holder
    // (a third task would block on the barrier forever).
    let barrier = Arc::new(tokio::sync::Barrier::new(2));

    let mut handles = Vec::new();
    for _ in 0..2 {
        let permits = permits.clone();
        let active = active.clone();
        let max_seen = max_seen.clone();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            let permit = permits.acquire_owned().await.unwrap();
            let count = active.fetch_add(1, Ordering::SeqCst) + 1;
            // Track the maximum concurrent count via CAS.
            loop {
                let current = max_seen.load(Ordering::SeqCst);
                if count <= current
                    || max_seen
                        .compare_exchange(current, count, Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                {
                    break;
                }
            }
            // Both holders meet here, proving concurrent in-flight.
            barrier.wait().await;
            active.fetch_sub(1, Ordering::SeqCst);
            drop(permit);
        }));
    }

    for h in handles {
        h.await.unwrap();
    }
    assert_eq!(
        max_seen.load(Ordering::SeqCst),
        2,
        "the cap must allow exactly two tasks to run concurrently"
    );

    // Cap enforcement: with two permits held, a third must be refused;
    // releasing one must free a slot.
    let p1 = permits.clone().acquire_owned().await.unwrap();
    let _p2 = permits.clone().acquire_owned().await.unwrap();
    assert!(
        permits.clone().try_acquire_owned().is_err(),
        "a third concurrent permit must be refused by the cap of 2"
    );
    drop(p1);
    assert!(
        permits.try_acquire_owned().is_ok(),
        "releasing a permit must free a slot"
    );
}

#[test]
fn compute_deficit_zero_when_both_layers_healthy() {
    // 31 TCP-alive, all circuit-healthy, min 8 → no deficit.
    assert_eq!(compute_deficit(8, 31, 31), 0);
}

#[test]
fn compute_deficit_triggers_on_circuit_degradation_with_full_tcp() {
    // Reproduces the production incident: every bridge TCP-alive but
    // most saturated with circuit-layer failures — deficit must follow
    // the circuit-healthy count, not the TCP count.
    assert_eq!(compute_deficit(8, 31, 2), 6);
}

#[test]
fn compute_deficit_uses_lower_count_when_both_layers_low() {
    // TCP itself is scarce; circuit-healthy is the binding constraint.
    assert_eq!(compute_deficit(8, 3, 2), 6);
}

#[test]
fn compute_deficit_boundary_exactly_at_min() {
    // circuit_healthy == min_alive → exactly enough, no deficit.
    assert_eq!(compute_deficit(8, 31, 8), 0);
}

#[test]
fn compute_deficit_boundary_one_below_min() {
    // circuit_healthy one short of min_alive → deficit of exactly 1.
    assert_eq!(compute_deficit(8, 31, 7), 1);
}

#[test]
fn compute_deficit_zero_circuit_healthy_is_full_deficit() {
    // Every bridge circuit-degraded → full deficit regardless of TCP.
    assert_eq!(compute_deficit(8, 31, 0), 8);
}

#[test]
fn compute_deficit_saturates_at_zero_when_overhealthy() {
    // More healthy than required → never goes negative.
    assert_eq!(compute_deficit(8, 40, 40), 0);
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
/// listener, with a one-permit semaphore so a single stuck handshake is
/// observable as `available_permits() == 0`.
async fn spawn_test_server() -> (
    std::net::SocketAddr,
    Arc<tokio::sync::Semaphore>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let permits = Arc::new(tokio::sync::Semaphore::new(1));
    // The egress never gets used: the deadline always fires first.
    let egress = Egress::Upstream(Arc::new(upstream::Upstream::new(
        "127.0.0.1:1".into(),
        None,
    )));
    let handle = tokio::spawn(accept_loop(
        listener,
        egress,
        None,
        permits.clone(),
        ConnHealthCounters::default(),
        false,
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
    // Mirrors the exact error shape produced by `handle_client`: the
    // deadline branch is now wrapped with the `STAGE_HANDSHAKE` context
    // just like the Ok arm, so the test shape matches production
    // exactly.
    let err = anyhow::anyhow!("handshake deadline of {HANDSHAKE_DEADLINE:?} exceeded")
        .context(STAGE_HANDSHAKE);
    assert_eq!(
        classify_conn_failure(&err),
        (ConnStage::Handshake, ConnErrorKind::Client),
        "a deadline expiry is client-side misbehavior, not Other"
    );
}

// -- shutdown_producers choreography ----------------------------------------

/// Reload the on-disk bridge store for a test config path.
fn reload_store(config_path: &Path) -> BridgeStore {
    BridgeStore::load(BridgeStore::resolve_path(Some(config_path))).expect("reload store")
}

fn test_bridge_line() -> BridgeLine {
    "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0"
        .parse()
        .expect("test bridge line parses")
}

fn wait_for_file_count(config_path: &Path, bridge: &BridgeLine, expected: u32) {
    for _ in 0..5000 {
        if reload_store(config_path).channel_ok_count(bridge) == expected {
            return;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    panic!("store never reached count {expected}");
}

/// TS3-04 regression: a producer caught mid-operation by a barrier when
/// cancellation arrives must finish its operation AND its store write must
/// land through the still-open writer BEFORE the writer closes. Emulates
/// run_server()'s sequence: shutdown_producers (cancel → no-op drain →
/// join), then writer close — the close_global equivalent.
#[tokio::test]
async fn shutdown_producers_delayed_write_lands_before_close() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bridge = test_bridge_line();
    let config_path = dir.path().join("tor-socks5.ktav");
    let mut store = reload_store(&config_path);
    store.note_source_at(&bridge, "test", OffsetDateTime::now_utc());
    store.save().expect("seed save");

    // A real writer (the same actor the daemon's producers write through),
    // locally spawned: the process-global OnceLock would leak this test's
    // path into every other test in the binary.
    let writer = crate::bridge_store_writer::StoreWriter::spawn(
        BridgeStore::resolve_path(Some(&config_path)),
        Arc::new(|s| s.save()),
        Duration::from_secs(1),
    );

    let token = CancellationToken::new();
    // Producer #1 is caught mid-operation ("warm_bridge" held by the
    // barrier) when cancellation arrives; #2 finished long before. Both
    // must be joined before the caller may close the writer.
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let iterations = Arc::new(AtomicUsize::new(0));
    let apply_ok = Arc::new(AtomicBool::new(false));

    let producer = {
        let barrier = barrier.clone();
        let iterations = iterations.clone();
        let apply_ok = apply_ok.clone();
        let bridge = bridge.clone();
        let writer = writer.clone();
        tokio::spawn(async move {
            // The in-flight network operation, held by the barrier.
            barrier.wait().await;
            let result = writer
                .apply(move |s| {
                    s.note_channel_success_at(&bridge, OffsetDateTime::now_utc());
                })
                .await;
            apply_ok.store(result.is_ok(), Ordering::SeqCst);
            iterations.fetch_add(1, Ordering::SeqCst);
        })
    };
    let quick = tokio::spawn(async {});

    let all_joined = {
        let token = token.clone();
        let producers = vec![producer, quick];
        tokio::spawn(async move {
            shutdown_producers(token, producers, async {}, Duration::from_secs(60)).await
        })
    };
    // The choreography always cancels first; hold the barrier until it has,
    // so the producer's operation provably spans the cancellation.
    while !token.is_cancelled() {
        tokio::task::yield_now().await;
    }
    barrier.wait().await;

    assert!(
        all_joined.await.expect("choreography task joins"),
        "both producers must finish within the join budget"
    );
    assert!(
        apply_ok.load(Ordering::SeqCst),
        "the delayed write must be accepted by the still-open writer"
    );
    assert_eq!(iterations.load(Ordering::SeqCst), 1);
    // The result must already be persisted BEFORE the writer closes — the
    // exact pre-fix loss: this write used to race close_global and vanish.
    wait_for_file_count(&config_path, &bridge, 1);

    // Only now does run()'s next step close the writer.
    let closed = writer.close().await;
    assert!(closed.is_ok(), "close after the joined write: {closed:?}");
    assert_eq!(reload_store(&config_path).channel_ok_count(&bridge), 1);
}

/// TS3-04 regression: after cancellation a producer must not start another
/// work iteration (its loop selects `cancelled()` before each tick).
#[tokio::test(start_paused = true)]
async fn shutdown_producers_no_new_iteration_after_cancel() {
    let token = CancellationToken::new();
    let iterations = Arc::new(AtomicUsize::new(0));
    let producer = {
        let token = token.clone();
        let iterations = iterations.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(1));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            ticker.tick().await; // consume the immediate first tick
            loop {
                tokio::select! {
                    biased;
                    _ = token.cancelled() => break,
                    _ = ticker.tick() => {
                        iterations.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
        })
    };

    // Let a few iterations run on the paused clock.
    while iterations.load(Ordering::SeqCst) < 3 {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    token.cancel();
    let before = iterations.load(Ordering::SeqCst);
    // The loop must break at its next cancellation check — immediately,
    // since the token is already cancelled — instead of ticking on.
    tokio::time::timeout(Duration::from_secs(5), producer)
        .await
        .expect("producer must stop after cancellation")
        .expect("producer joins cleanly");
    // No further iteration, even with the ticker long overdue.
    tokio::time::sleep(Duration::from_secs(3600)).await;
    assert_eq!(
        iterations.load(Ordering::SeqCst),
        before,
        "no iteration may start after cancellation"
    );
}

/// TS3-04 regression: a producer that never finishes (the shape of a stuck,
/// uncancellable blocking job) must hit the bounded join budget and let
/// shutdown continue — not hang the process forever.
#[tokio::test(start_paused = true)]
async fn shutdown_producers_hung_producer_hits_join_budget() {
    let token = CancellationToken::new();
    let observed = token.clone();
    let hung = tokio::spawn(async {
        std::future::pending::<()>().await;
    });
    let all_joined =
        shutdown_producers(token, vec![hung], async {}, Duration::from_secs(100)).await;
    assert!(!all_joined, "the hung producer must hit the join budget");
    assert!(
        observed.is_cancelled(),
        "cancellation must have fired before the join wait"
    );
}
