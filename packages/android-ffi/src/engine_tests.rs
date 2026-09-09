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

/// Regression test for the lost-update race on the shared bridge-health store:
/// `persist_warm_results` (writer A) and `persist_bridge_sources` (writer B)
/// used to each run load→mutate→save on their own `BridgeStore::load`
/// snapshot, so the last `save()` silently dropped the other writer's
/// observations.
///
/// Counterfactual: with the shared `BRIDGE_STORE_WRITE_LOCK` removed, the
/// choreography below freezes writer A right after its load (holding its stale
/// snapshot), lets writer B load the *pre-A* snapshot and fully publish, then
/// releases A last (GATE_B strictly before GATE_A). A's stale-save therefore
/// lands after B's save and wipes B's `src-B` attribution — assertion 2 fails.
/// With the lock in place, B's load only happens after A's save, so both
/// writers' updates (plus the seeded baseline) are present.
///
/// Residual: in the reverted (buggy) world the failure relies on the OS
/// scheduling B's load while A is frozen between load and save (the normal
/// case); the fixed world passes deterministically.
#[test]
fn concurrent_store_writers_do_not_lose_each_others_updates() {
    use std::sync::mpsc;
    use std::sync::Arc;

    // Items living in the parent `engine` module (including its private
    // imports and the `bridges` submodule, visible from this child module).
    use super::bridges::{persist_bridge_sources, persist_warm_results, set_store_test_hook};
    use super::BridgeHealthContext;
    use super::BridgeLine;
    use super::BridgeStore;
    use super::BridgesConfig;
    use super::WarmPool;

    struct HookGuard;
    impl Drop for HookGuard {
        fn drop(&mut self) {
            set_store_test_hook(None);
        }
    }

    fn unique_temp_dir(tag: &str) -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "engine-store-lock-test-{}-{}-{}-{tag}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir temp dir");
        dir
    }

    let dir = unique_temp_dir("lost-update");
    let cfg_path = dir.join("cfg.ktav");
    let ctx = BridgeHealthContext {
        config_path: Some(cfg_path.clone()),
        bridges_cfg: BridgesConfig::default(),
        resolver_policy: bridge_probe::ResolverPolicy::default(),
    };
    let store_path = BridgeStore::resolve_path(Some(cfg_path.as_path()));

    let parse = |ip: &str, fp: &str, url: &str| {
        format!("webtunnel {ip}:443 {fp} url={url}")
            .parse::<BridgeLine>()
            .expect("well-formed bridge line")
    };
    let baseline_bridge = parse(
        "192.0.2.10",
        "AAAA0000AAAA0000AAAA0000AAAA0000AAAA0000",
        "https://baseline.example.test/x",
    );
    let warm_bridge = parse(
        "192.0.2.11",
        "BBBB1111BBBB1111BBBB1111BBBB1111BBBB1111",
        "https://warm.example.test/x",
    );
    let source_bridge = parse(
        "192.0.2.12",
        "CCCC2222CCCC2222CCCC2222CCCC2222CCCC2222",
        "https://source.example.test/x",
    );

    // Seed entries via `note_source_at` -- the only mutator that creates an
    // entry for a bridge the store does not already track
    // (`note_channel_success_at` is a no-op for unknown bridges, so seeding
    // through it would silently write an empty store and the baseline
    // assertion would fail against an entry that never existed). Seeding
    // `warm_bridge` is what makes writer A's
    // `note_channel_success_at(&warm_bridge, ..)` observable: it bumps an
    // existing entry's counter from 0 to 1.
    let mut store = BridgeStore::load(store_path.clone()).expect("load empty store");
    let now = time::OffsetDateTime::now_utc();
    store.note_source_at(&baseline_bridge, "seed-source", now);
    store.note_source_at(&warm_bridge, "seed-source", now);
    store.save().expect("seed baseline store");

    // Receivers aren't `Sync`, but the hook must be — mutex-wrap the gate
    // receivers the closure blocks on.
    let (a_frozen_tx, a_frozen_rx) = mpsc::channel::<()>();
    let (b_loaded_tx, b_loaded_rx) = mpsc::channel::<()>();
    let (gate_a_tx, gate_a_rx) = mpsc::channel::<()>();
    let (gate_b_tx, gate_b_rx) = mpsc::channel::<()>();
    let gate_a_rx = std::sync::Mutex::new(gate_a_rx);
    let gate_b_rx = std::sync::Mutex::new(gate_b_rx);

    set_store_test_hook(Some(Arc::new(move |site| match site {
        "persist_warm_results:after_load" => {
            a_frozen_tx.send(()).expect("signal writer A frozen");
            gate_a_rx
                .lock()
                .expect("gate A mutex")
                .recv()
                .expect("gate A released");
        }
        "persist_bridge_sources:after_load" => {
            b_loaded_tx.send(()).expect("signal writer B loaded");
        }
        "persist_bridge_sources:before_save" => {
            gate_b_rx
                .lock()
                .expect("gate B mutex")
                .recv()
                .expect("gate B released");
        }
        _ => {}
    })));
    let _hook_guard = HookGuard;

    let warm_bridge_for_a = warm_bridge.clone();
    let a_handle = std::thread::spawn(move || {
        persist_warm_results(
            &WarmPool {
                warmed: vec![(warm_bridge_for_a, Duration::from_millis(1))],
                retired: Vec::new(),
            },
            &ctx,
        );
    });

    // Writer A is frozen after its load (post-fix, holding the store lock).
    // Only NOW spawn writer B. The mutex is unfair: a B spawned earlier could
    // win the lock race, block on GATE_B at its before-save hook *while
    // holding the lock*, and dead-lock the harness — A waits for the lock,
    // this thread waits for A's frozen signal — until the fail-fast timeout.
    // Spawned after A is confirmed frozen, B can only ever block ON the
    // lock, never hold it while gated.
    a_frozen_rx
        .recv_timeout(Duration::from_secs(60))
        .expect("writer A froze after load");
    let ctx_b = BridgeHealthContext {
        config_path: Some(cfg_path.clone()),
        bridges_cfg: BridgesConfig::default(),
        resolver_policy: bridge_probe::ResolverPolicy::default(),
    };
    let source_bridge = source_bridge.clone();
    let b_handle = std::thread::spawn(move || {
        persist_bridge_sources(
            &[bridge_fetcher::FetchOutcome {
                label: "src-B".into(),
                bridges_extracted: 1,
                error: None,
                bridges: vec![source_bridge],
            }],
            &ctx_b,
        );
    });

    // GATE_B strictly before GATE_A: with the lock removed (counterfactual),
    // B's save lands before A's stale-save, and A's stale snapshot wipes B's
    // attribution — assertion 2 fails. Post-fix, B consumes GATE_B only
    // after A has released the store lock, so both worlds are deadlock-free.
    // The timeouts are only fail-fast guards against a regression-induced
    // hang.
    gate_b_tx.send(()).expect("release writer B");
    gate_a_tx.send(()).expect("release writer A");
    b_loaded_rx
        .recv_timeout(Duration::from_secs(60))
        .expect("writer B loaded");
    a_handle.join().expect("writer A panicked");
    b_handle.join().expect("writer B panicked");

    let store = BridgeStore::load(store_path).expect("reload store");
    // 1. Writer A's warm result survived B's publication.
    let warm_channel_oks = store.channel_ok_count(&warm_bridge);
    // 2. Writer B's attribution survived A's publication.
    assert!(
        store
            .source_summary()
            .iter()
            .any(|s| s.label == "src-B" && s.offered >= 1),
        "writer B's source attribution was lost to writer A's save"
    );
    // 3. Pre-existing seeded entries not wiped: both must still credit
    // "seed-source" (`baseline_bridge` + `warm_bridge` => offered == 2).
    // A stale-snapshot save from either writer would drop entries it never
    // touched, driving `offered` below 2.
    assert!(
        store
            .source_summary()
            .iter()
            .any(|s| s.label == "seed-source" && s.offered >= 2),
        "pre-existing seeded entries were wiped"
    );
    assert!(
        warm_channel_oks >= 1,
        "writer A's warm result was lost to writer B's save"
    );
}

/// TS3-06 regression: a failed background circuit-verify batch must still advance the
/// verification queue. Before the fix, `persist_circuit_verify_results` recorded only
/// successes (`note_circuit_verified_at`), so the first B channel-proven, never-verified
/// bridges with persistently failing checks stayed the first B candidates on every
/// watchdog tick, starving the rest of the pool. The re-load from disk before the second
/// selection covers the review's "survives re-reading the store" requirement.
///
/// Counterfactual: with the `note_verification_attempt_at` call in
/// `persist_circuit_verify_results` removed (the pre-fix behaviour), batch 2 is batch 1
/// again and the disjointness assertion below fails.
#[test]
fn failed_circuit_verify_batch_advances_the_due_queue() {
    use super::bridges::persist_circuit_verify_results;
    use super::{BridgeHealthContext, BridgeLine, BridgeStore, BridgesConfig};

    fn unique_temp_dir(tag: &str) -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "engine-circuit-verify-test-{}-{}-{}-{tag}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir temp dir");
        dir
    }

    let dir = unique_temp_dir("failed-batch-advances");
    let cfg_path = dir.join("cfg.ktav");
    let ctx = BridgeHealthContext {
        config_path: Some(cfg_path.clone()),
        bridges_cfg: BridgesConfig::default(),
        resolver_policy: bridge_probe::ResolverPolicy::default(),
    };
    let store_path = BridgeStore::resolve_path(Some(cfg_path.as_path()));

    let parse = |ip: &str, fp: &str, url: &str| {
        format!("webtunnel {ip}:443 {fp} url={url}")
            .parse::<BridgeLine>()
            .expect("well-formed bridge line")
    };
    let fingerprints = [
        "1111111111111111111111111111111111111111",
        "2222222222222222222222222222222222222222",
        "3333333333333333333333333333333333333333",
        "4444444444444444444444444444444444444444",
    ];
    let bridges: Vec<BridgeLine> = fingerprints
        .iter()
        .enumerate()
        .map(|(i, fp)| {
            parse(
                &format!("192.0.2.2{i}"),
                fp,
                &format!("https://bridge-{i}.example.test/x"),
            )
        })
        .collect();

    // Seed four channel-proven, never-verified bridges: every one of them is due.
    let t0 = time::OffsetDateTime::from_unix_timestamp(1_000_000).unwrap();
    let mut store = BridgeStore::load(store_path.clone()).expect("load empty store");
    for bridge in &bridges {
        store.note_source_at(bridge, "seed", t0);
        store.note_channel_success_at(bridge, t0);
    }
    store.save().expect("seed store");

    let max_age = Duration::from_secs(24 * 60 * 60);
    let batch1 = store.needing_circuit_verification(t0, max_age, 2, |_| true);
    assert_eq!(
        batch1.len(),
        2,
        "batch limit selects two of the four due bridges"
    );

    // The tick runs the batch, every check fails: persist all-false results.
    let results: Vec<(BridgeLine, bool)> = batch1.iter().map(|b| (b.clone(), false)).collect();
    persist_circuit_verify_results(&results, &ctx);

    // Next tick re-reads the store from disk: the failed batch must no longer be
    // ahead of the never-attempted bridges, and a failed attempt is neither a
    // verification success nor a live outage.
    let reloaded = BridgeStore::load(store_path).expect("reload store");
    let batch2 = reloaded.needing_circuit_verification(t0, max_age, 2, |_| true);
    assert_eq!(batch2.len(), 2, "the rest of the pool takes the next batch");
    for attempted in &batch1 {
        assert!(
            !batch2.contains(attempted),
            "a failed check must not stay ahead of never-attempted bridges"
        );
        assert_eq!(
            reloaded.verified_count(attempted),
            0,
            "an attempt is not a verification success"
        );
        assert_eq!(
            reloaded.circuit_fails(attempted),
            0,
            "an isolated check failure is not a live outage"
        );
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// Serializes the generation-guard tests below: they touch the process-global
/// `STATUS` and `ENGINE_GENERATION` statics, so they must not interleave with
/// each other.
static GENERATION_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// TS3-05 regression -- "поздний статус не затрагивает новое поколение": a
/// stale engine generation's teardown (`clear_shared_state` +
/// `publish_final_status`) must be silently skipped once a newer generation
/// has been issued, so the NEW engine's live state (active-bridges file,
/// final status) is never wiped by the OLD engine exiting late.
///
/// HOW the counterfactual fails: without the `current_engine_generation()
/// != generation` guard, step 6 would clear the active-bridges file the new
/// engine wrote in step 4 and overwrite its `On(..)` status with `Off` --
/// both assertions in step 7 fail.
#[test]
fn stale_generation_teardown_does_not_touch_new_engine_state() {
    use super::BridgeLine;
    use crate::EngineStatus;

    let _serial = GENERATION_TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());

    fn unique_temp_dir(tag: &str) -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "engine-stale-generation-test-{}-{}-{}-{tag}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir temp dir");
        dir
    }

    let dir = unique_temp_dir("stale-teardown");
    let cfg_path = dir.join("cfg.ktav");
    let bridges_file = crate::active_bridges_path(Some(cfg_path.as_path()));

    // `stale` becomes a genuinely superseded generation the moment the next
    // one is issued; `_current` is the live generation that stands in for the
    // "new engine" in this choreography.
    let stale = crate::next_engine_generation();
    let _current = crate::next_engine_generation();

    let parse = |ip: &str, fp: &str, url: &str| {
        format!("webtunnel {ip}:443 {fp} url={url}")
            .parse::<BridgeLine>()
            .expect("well-formed bridge line")
    };
    let bridge = parse(
        "192.0.2.20",
        "DDDD3333DDDD3333DDDD3333DDDD3333DDDD3333",
        "https://stale-gen.example.test/x",
    );

    // Play the NEW engine: publish its state under the current generation.
    crate::set_active_bridges(Some(cfg_path.as_path()), &[bridge]);
    let on_status = EngineStatus::On("127.0.0.1:1080".parse().unwrap());
    super::set_final_status(on_status.clone());

    // Sanity: the preconditions the stale teardown must not disturb.
    let before = std::fs::read_to_string(&bridges_file).expect("read bridges file");
    assert!(!before.is_empty(), "active-bridges file must be non-empty");
    let observed = crate::get_status()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    assert_eq!(
        observed, on_status,
        "status must be On before the stale teardown"
    );

    // The OLD generation's thread finally exits late: its teardown must be
    // a no-op against the new engine's state.
    super::clear_shared_state(stale, Some(cfg_path.as_path()));
    super::publish_final_status(stale, EngineStatus::Off);

    // Nothing changed: the file still carries the new engine's bridges and
    // the status is still On.
    let after = std::fs::read_to_string(&bridges_file).expect("read bridges file");
    assert!(
        !after.is_empty(),
        "stale teardown wiped the active-bridges file"
    );
    assert_eq!(
        after, before,
        "stale teardown modified the active-bridges file"
    );
    let observed = crate::get_status()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    assert_eq!(
        observed, on_status,
        "stale teardown overwrote the new engine's status"
    );

    // `CURRENT_TUNNEL` sits behind the same single generation check inside
    // `clear_shared_state`, but `TorTunnel` cannot be constructed without a
    // live bootstrap, so the file + status observables stand in for it.

    // Tidy: restore the status via the CURRENT generation so the test does
    // not leave `On` behind for the rest of the suite.
    super::publish_final_status(_current, EngineStatus::Off);
    let _ = std::fs::remove_dir_all(dir);
}

/// The generation guard must not swallow the NORMAL teardown path: when the
/// generation still matches, `clear_shared_state` + `publish_final_status`
/// really do clear the shared state (active-bridges file, status, tunnel).
///
/// Counterfactual: an over-broad guard (e.g. comparing against the wrong
/// generation source, or skipping unconditionally after a refactor) would
/// leave the active-bridges file non-empty and the status stale -- the file
/// emptiness and `Off` assertions below fail. (The file is the real
/// observable here: the tunnel slot was `None` before the call, so its
/// clearing is only checked for absence of panic.)
#[test]
fn current_generation_teardown_still_clears_shared_state() {
    use super::BridgeLine;
    use crate::EngineStatus;

    let _serial = GENERATION_TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());

    fn unique_temp_dir(tag: &str) -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "engine-current-generation-test-{}-{}-{}-{tag}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir temp dir");
        dir
    }

    let dir = unique_temp_dir("current-teardown");
    let cfg_path = dir.join("cfg.ktav");
    let bridges_file = crate::active_bridges_path(Some(cfg_path.as_path()));

    let parse = |ip: &str, fp: &str, url: &str| {
        format!("webtunnel {ip}:443 {fp} url={url}")
            .parse::<BridgeLine>()
            .expect("well-formed bridge line")
    };
    let bridge = parse(
        "192.0.2.21",
        "EEEE4444EEEE4444EEEE4444EEEE4444EEEE4444",
        "https://current-gen.example.test/x",
    );

    crate::set_active_bridges(Some(cfg_path.as_path()), &[bridge]);
    let before = std::fs::read_to_string(&bridges_file).expect("read bridges file");
    assert!(!before.is_empty(), "active-bridges file must be non-empty");

    // The live generation; the teardown below must recognise it as current.
    let gen = crate::current_engine_generation();

    super::clear_shared_state(gen, Some(cfg_path.as_path()));
    let after = std::fs::read_to_string(&bridges_file).expect("read bridges file");
    assert_eq!(
        after, "",
        "current-generation teardown must clear the active-bridges file"
    );

    super::publish_final_status(gen, EngineStatus::Off);
    let observed = crate::get_status()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    assert_eq!(
        observed,
        EngineStatus::Off,
        "status must be Off after teardown"
    );

    // The cleared `set_current_tunnel(None)` ran without panic; it was
    // `None` before, so the file above is the real observable.
    assert!(
        super::get_current_tunnel().is_none(),
        "tunnel slot must be None after teardown"
    );
    let _ = std::fs::remove_dir_all(dir);
}
