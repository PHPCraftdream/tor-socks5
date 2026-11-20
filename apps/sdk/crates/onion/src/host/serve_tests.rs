use super::*;
use crate::host::status;

fn ports(entries: &[(u16, &str)]) -> HashMap<u16, String> {
    entries.iter().map(|(p, t)| (*p, t.to_string())).collect()
}

fn addr_map(entries: &[(u16, &str)]) -> HashMap<u16, SocketAddr> {
    entries
        .iter()
        .map(|(p, t)| (*p, t.parse().expect("parse")))
        .collect()
}

#[test]
fn target_for_port_finds_known_ports_and_misses_unknown_or_non_begin_ones() {
    let map = addr_map(&[(80, "127.0.0.1:8080")]);
    assert_eq!(target_for_port(&map, Some(80)), map.get(&80).copied());
    assert_eq!(target_for_port(&map, Some(443)), None);
    // Non-BEGIN requests carry no port and must be rejected.
    assert_eq!(target_for_port(&map, None), None);
}

#[test]
fn the_global_stream_budget_is_divided_fairly() {
    // min(256, max(32, 512/n)).
    assert_eq!(per_service_stream_cap(1), 256);
    assert_eq!(per_service_stream_cap(2), 256);
    assert_eq!(per_service_stream_cap(3), 512 / 3); // 170
    assert_eq!(per_service_stream_cap(4), 128);
    assert_eq!(per_service_stream_cap(16), 32);
    assert_eq!(per_service_stream_cap(100), 32);
}

// AcceptGate (the production gate): capacity, release, cancellation.

#[tokio::test(start_paused = true)]
async fn the_accept_gate_caps_releases_and_cancels_waiters() {
    let gate = AcceptGate::new(1);
    let first = gate
        .acquire(&CancellationToken::new())
        .await
        .expect("first permit");
    assert_eq!(gate.available_permits(), 0, "capacity is exhausted");

    // No slot while the first permit is held; released by dropping it.
    let (done_tx, mut done_rx) = tokio::sync::oneshot::channel::<bool>();
    tokio::spawn({
        let gate = gate.clone();
        async move {
            let _ = done_tx.send(gate.acquire(&CancellationToken::new()).await.is_some());
        }
    });
    tokio::time::advance(Duration::from_secs(5)).await;
    assert!(
        done_rx.try_recv().is_err(),
        "no slot while the first permit is held"
    );
    drop(first);
    assert!(
        done_rx.await.expect("oneshot"),
        "the permit is released by dropping it"
    );
    assert_eq!(gate.available_permits(), 1);

    // With no slot left, a waiter gets None when cancelled.
    let held = gate
        .acquire(&CancellationToken::new())
        .await
        .expect("hold the slot");
    let token = CancellationToken::new();
    let (done_tx, mut done_rx) = tokio::sync::oneshot::channel::<bool>();
    tokio::spawn({
        let gate = gate.clone();
        let token = token.clone();
        async move {
            let _ = done_tx.send(gate.acquire(&token).await.is_some());
        }
    });
    tokio::time::advance(Duration::from_secs(5)).await;
    assert!(done_rx.try_recv().is_err(), "still waiting");
    token.cancel();
    assert!(
        !done_rx.await.expect("oneshot"),
        "a cancelled waiter gets None"
    );
    drop(held);
}

// supervise_children: all four outcomes of interest (paused clock).
#[tokio::test(start_paused = true)]
async fn supervision_restarts_exits_broken_reports_and_cancellation() {
    let token = CancellationToken::new();
    // (a) A serving task that returns on its own triggers a restart.
    let mut children = tokio::task::JoinSet::new();
    children.spawn(async {});
    let (_broken_tx, broken_rx) = tokio::sync::oneshot::channel::<()>();
    assert!(matches!(
        supervise_children(&mut children, &token, broken_rx).await,
        SupervisionOutcome::Restart("serving task exited unexpectedly")
    ));

    // (b) A broken report triggers a restart with the exact reason string.
    let mut children = tokio::task::JoinSet::new();
    children.spawn(std::future::pending::<()>()); // a live serving task
    let (broken_tx, broken_rx) = tokio::sync::oneshot::channel();
    broken_tx.send(()).expect("send broken");
    assert!(matches!(
        supervise_children(&mut children, &token, broken_rx).await,
        SupervisionOutcome::Restart("service reports a broken state")
    ));

    // (c) A cancelled token wins over everything else.
    let token = CancellationToken::new();
    token.cancel();
    let mut children = tokio::task::JoinSet::new();
    children.spawn(std::future::pending::<()>());
    let (_broken_tx, broken_rx) = tokio::sync::oneshot::channel::<()>();
    assert!(matches!(
        supervise_children(&mut children, &token, broken_rx).await,
        SupervisionOutcome::Cancelled
    ));

    // (d) Dropping the sender without sending: the status stream ended.
    let token = CancellationToken::new();
    let mut children = tokio::task::JoinSet::new();
    children.spawn(std::future::pending::<()>());
    let (broken_tx, broken_rx) = tokio::sync::oneshot::channel::<()>();
    drop(broken_tx);
    assert!(matches!(
        supervise_children(&mut children, &token, broken_rx).await,
        SupervisionOutcome::Restart("service status stream ended")
    ));
}

// "127.0.0.1:8080" needs no DNS; the bad target fails `lookup_host` locally.
#[tokio::test]
async fn resolve_targets_keeps_resolvable_and_drops_unresolvable_targets() {
    let map = ports(&[(80, "127.0.0.1:8080"), (443, "not a socket addr::")]);
    let targets = resolve_targets(&map).await;
    assert_eq!(
        targets.get(&80),
        Some(&"127.0.0.1:8080".parse::<SocketAddr>().expect("parse"))
    );
    assert!(!targets.contains_key(&443), "unresolvable target omitted");
}

#[tokio::test]
async fn connect_to_target_reaches_a_real_listener_and_refuses_dead_ports() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    connect_to_target(addr, Duration::from_secs(1))
        .await
        .expect("connects");

    // Bound a moment ago, now free: connect must be refused.
    drop(listener);
    connect_to_target(addr, Duration::from_secs(1))
        .await
        .expect_err("the port has no listener anymore");
}

// StreamRequest cannot be constructed outside arti, so the permit
// ordering is exercised through `acquire_stream_permits` directly.
// Deterministic: paused clock, explicit `advance`, sync `try_recv`.

#[tokio::test(start_paused = true)]
async fn stream_permits_take_the_per_service_cap_before_the_global_one() {
    // Scenario 1: two per-service caps of 1 sum above the global cap of
    // 1 — the process-wide limit holds the second stream back.
    let per_a = Arc::new(Semaphore::new(1));
    let per_b = Arc::new(Semaphore::new(1));
    let global = Arc::new(Semaphore::new(1));
    let first = acquire_stream_permits(&per_a, &global)
        .await
        .expect("A admitted");

    // B's per-service permit is free, but no global permit is left.
    let (done_tx, mut done_rx) = tokio::sync::oneshot::channel::<bool>();
    tokio::spawn(async move {
        let _ = done_tx.send(acquire_stream_permits(&per_b, &global).await.is_some());
    });
    tokio::time::advance(Duration::from_secs(60)).await;
    assert!(
        done_rx.try_recv().is_err(),
        "B must still wait: the global permit is held"
    );
    drop(first);
    assert!(
        done_rx.await.expect("oneshot"),
        "B is admitted once a global permit frees"
    );

    // Scenario 2: A holds one of two global permits. While B is parked
    // behind its own service's cap, the other global permit must stay
    // free — a global-first implementation would have taken it.
    let per = Arc::new(Semaphore::new(1));
    let global = Arc::new(Semaphore::new(2));
    let first = acquire_stream_permits(&per, &global)
        .await
        .expect("A admitted");

    // B targets the SAME service.
    let (done_tx, mut done_rx) = tokio::sync::oneshot::channel::<bool>();
    tokio::spawn({
        let global = global.clone();
        async move {
            let _ = done_tx.send(acquire_stream_permits(&per, &global).await.is_some());
        }
    });
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(
        done_rx.try_recv().is_err(),
        "B must wait behind its own service's cap"
    );
    assert!(global.try_acquire().is_ok(), "the global permit stays free");
    drop(first); // frees both permits
    assert!(
        done_rx.await.expect("oneshot"),
        "B is admitted once its service frees a permit"
    );
}

// --- production-chain tests: service_manager end to end ---

/// Install rustls's process-wide `CryptoProvider` exactly once (same
/// pattern as `host::tests`; the helper is kept local because test
/// binaries may differ between modules).
fn ensure_crypto_provider() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn test_handle(state_dir: &std::path::Path) -> TorHandle {
    ensure_crypto_provider();
    let settings = arti_wrapper::Settings {
        state_dir: Some(state_dir.to_path_buf()),
        ..Default::default()
    };
    let tor = arti_wrapper::TorTunnel::create_unbootstrapped_with(settings)
        .expect("unbootstrapped tunnel");
    TorHandle::new(tor)
}

fn service_entry(nickname: &str) -> OnionServiceEntry {
    OnionServiceEntry {
        nickname: nickname.to_owned(),
        enabled: true,
        address: None,
        key: None,
        circuit_hops: 4,
        bridge_group: None,
        bridges: None,
        ports: vec![proxy_config::OnionServicePort {
            onion_port: 80,
            target: "127.0.0.1:8080".to_owned(),
        }],
    }
}

/// Wait on the tracker's `watch` channel until `nickname` reaches `wanted`.
async fn wait_for(
    rx: &mut tokio::sync::watch::Receiver<status::OnionHostStatus>,
    nickname: &str,
    wanted: status::ServiceStatus,
) -> status::ServiceState {
    loop {
        let snapshot = rx.borrow_and_update().clone();
        if let Some(state) = snapshot.services.get(nickname) {
            if state.status == wanted {
                return state.clone();
            }
        }
        rx.changed()
            .await
            .expect("status tracker sender is never dropped");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_matching_identity_is_served_and_stops_on_cancellation() {
    let tmp = tempfile::tempdir().expect("temp dir");
    // Arti's native keystore lives at `<state_dir>/state/keystore`; settle
    // the identity there through the real `keys::prepare_all` path.
    let keystore = tmp.path().join("state").join("keystore");
    let settled = keys::prepare_all(None, &keystore, &[service_entry("web")]);
    let entry = settled[0].entry.clone();
    let address = settled[0]
        .address
        .clone()
        .expect("prepare_all settles the address");

    let tracker = status::StatusTracker::new(vec!["web".to_string()]);
    let mut rx = tracker.subscribe();
    let token = tokio_util::sync::CancellationToken::new();

    let service_weak = Arc::new(std::sync::Mutex::new(
        None::<std::sync::Weak<RunningOnionService>>,
    ));
    let captured_service = service_weak.clone();
    let served = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let served_count = served.clone();
    let (serve_tx, serve_rx) = tokio::sync::oneshot::channel::<()>();
    let serve_tx = std::sync::Mutex::new(Some(serve_tx));

    let manager = tokio::spawn(service_manager(
        test_handle(tmp.path()),
        entry,
        address.clone(),
        start_gate::StartGate::new(),
        per_service_stream_cap(1),
        Arc::new(Semaphore::new(MAX_TOTAL_CONCURRENT_STREAMS)),
        token.clone(),
        tracker,
        Some(Arc::new(move |service: &Arc<RunningOnionService>| {
            *captured_service.lock().expect("capture mutex") = Some(Arc::downgrade(service));
        })),
        Some(Arc::new(move || {
            served_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if let Some(sender) = serve_tx.lock().expect("oneshot mutex").take() {
                let _ = sender.send(());
            }
        })),
    ));

    // The serve hook only fires after `wait_for_address` returned Available
    // AND the expected address matched, so receiving proves both.
    let served_result = tokio::time::timeout(Duration::from_secs(120), serve_rx).await;
    if served_result.is_err() || matches!(&served_result, Ok(Err(_))) {
        panic!(
            "manager did not reach serving: address={address:?} status={:?}",
            rx.borrow_and_update()
        );
    }
    served_result
        .expect("real tunnel serves within 120 s")
        .expect("serve_started fires exactly once");
    assert_eq!(
        served.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the manager went on to supervise the serving tasks"
    );

    let weak = service_weak
        .lock()
        .expect("capture mutex")
        .clone()
        .expect("service was launched");
    assert!(weak.upgrade().is_some(), "the service stays alive");

    token.cancel();
    let state = tokio::time::timeout(
        Duration::from_secs(30),
        wait_for(&mut rx, "web", status::ServiceStatus::Stopped),
    )
    .await
    .expect("manager reaches Stopped within 30 s of cancellation");
    assert_eq!(state.failure, None);
    manager.await.expect("manager task does not panic");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_invalid_nickname_fails_before_any_launch() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let tracker = status::StatusTracker::new(vec!["not a nickname".to_string()]);
    let mut rx = tracker.subscribe();
    let launches = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let launch_count = launches.clone();

    let manager = tokio::spawn(service_manager(
        test_handle(tmp.path()),
        service_entry("not a nickname"),
        "irrelevant-address".to_owned(),
        start_gate::StartGate::new(),
        per_service_stream_cap(1),
        Arc::new(Semaphore::new(MAX_TOTAL_CONCURRENT_STREAMS)),
        tokio_util::sync::CancellationToken::new(),
        tracker,
        Some(Arc::new(move |_service: &Arc<RunningOnionService>| {
            launch_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        })),
        None,
    ));

    let state = tokio::time::timeout(
        Duration::from_secs(30),
        wait_for(&mut rx, "not a nickname", status::ServiceStatus::Failed),
    )
    .await
    .expect("invalid nickname fails within 30 s");
    assert_eq!(state.failure, Some(status::ServiceFailure::InvalidNickname));
    assert_eq!(
        launches.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "no service is launched for an invalid nickname"
    );
    manager.await.expect("manager task does not panic");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_manager_stops_without_launching() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let tracker = status::StatusTracker::new(vec!["web".to_string()]);
    let mut rx = tracker.subscribe();
    let token = tokio_util::sync::CancellationToken::new();
    token.cancel();
    let launches = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let launch_count = launches.clone();

    let manager = tokio::spawn(service_manager(
        test_handle(tmp.path()),
        service_entry("web"),
        "irrelevant-address".to_owned(),
        start_gate::StartGate::new(),
        per_service_stream_cap(1),
        Arc::new(Semaphore::new(MAX_TOTAL_CONCURRENT_STREAMS)),
        token,
        tracker,
        Some(Arc::new(move |_service: &Arc<RunningOnionService>| {
            launch_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        })),
        None,
    ));

    let state = tokio::time::timeout(
        Duration::from_secs(30),
        wait_for(&mut rx, "web", status::ServiceStatus::Stopped),
    )
    .await
    .expect("pre-cancelled manager stops within 30 s");
    assert_eq!(state.failure, None);
    assert_eq!(
        launches.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "nothing is launched after cancellation"
    );
    manager.await.expect("manager task does not panic");
}

/// ROLLBACK THAT FAILS THIS: returning after a fixed number of polls, or
/// polling less often than `ADDRESS_POLL_INTERVAL`, changes the elapsed
/// virtual time or the call count.
#[tokio::test(start_paused = true)]
async fn the_address_is_returned_on_the_poll_that_finds_it() {
    let token = CancellationToken::new();
    let started = tokio::time::Instant::now();
    let mut calls = 0;
    let outcome = wait_for_address_with(
        || {
            calls += 1;
            (calls == 4).then_some("address")
        },
        &token,
        "svc",
    )
    .await;
    assert!(matches!(outcome, AddressWait::Available("address")));
    assert_eq!(calls, 4);
    assert_eq!(started.elapsed(), 3 * ADDRESS_POLL_INTERVAL);
}

/// ROLLBACK THAT FAILS THIS: dropping the deadline check makes the wait
/// endless; the outer timeout then fires first and the test fails.
#[tokio::test(start_paused = true)]
async fn an_address_that_never_appears_times_out_at_the_limit() {
    let token = CancellationToken::new();
    let started = tokio::time::Instant::now();
    let outcome = tokio::time::timeout(
        ADDRESS_WAIT_LIMIT * 2,
        wait_for_address_with(|| None::<()>, &token, "svc"),
    )
    .await
    .expect("the wait is bounded by its own limit");
    assert!(matches!(outcome, AddressWait::TimedOut));
    let waited = started.elapsed();
    assert!(waited >= ADDRESS_WAIT_LIMIT, "{waited:?}");
    assert!(
        waited <= ADDRESS_WAIT_LIMIT + ADDRESS_POLL_INTERVAL,
        "{waited:?}"
    );
}

/// ROLLBACK THAT FAILS THIS: dropping the cancellation arm leaves the wait
/// running to the limit, so it ends as `TimedOut` instead of `Cancelled`.
#[tokio::test(start_paused = true)]
async fn cancellation_ends_the_address_wait_early() {
    let token = CancellationToken::new();
    let waiter = {
        let token = token.clone();
        tokio::spawn(async move { wait_for_address_with(|| None::<()>, &token, "svc").await })
    };
    tokio::time::sleep(5 * ADDRESS_POLL_INTERVAL).await;
    let cancelled_at = tokio::time::Instant::now();
    token.cancel();
    let outcome = waiter.await.expect("join");
    assert!(matches!(outcome, AddressWait::Cancelled));
    assert!(cancelled_at.elapsed() < ADDRESS_POLL_INTERVAL);
}
