//! Tests for the bridge replenishment pipeline in [`super`]: source
//! migration, admission decisions, the lazy pool drain and its
//! cross-process transaction behaviour.

use super::*;
use crate::bridge_verifier::AdmissionWorkers;
use crate::test_seams::{HANG_GUARD, UNBLOCK_GUARD};
use bridge_store::BridgeStore;

/// Fresh worker registry for a test drain call (keeps the arg lists short).
fn aw() -> AdmissionWorkers {
    AdmissionWorkers::default()
}

#[test]
fn source_migration_only_changes_the_known_legacy_webtunnel_list() {
    let old = "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/main/bridges-webtunnel";
    let current = current_source_url(old);
    assert!(current.ends_with("Tor-Bridges-Collector-v2/main/bridges/webtunnel_tested.txt"));
    assert_eq!(current_source_url(current), current);
    let custom = "https://private.example/bridges-webtunnel";
    assert_eq!(current_source_url(custom), custom);
}

fn discovery_fixture() -> (tempfile::TempDir, std::path::PathBuf, BridgeLine) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("proxy.ktav");
    let mut cfg = Config::default();
    cfg.bridges.transport = "webtunnel".into();
    cfg.bridges.lines = vec![bridge().to_string()];
    cfg.write(&path).unwrap();
    let wt: BridgeLine = "webtunnel [2001:db8::1]:443 0123456789ABCDEF0123456789ABCDEF01234567 url=https://example.com/bridge"
        .parse().unwrap();
    let mut pool = CandidatePool::load(CandidatePool::resolve_path(Some(&path))).unwrap();
    let obfs = (1..=100).map(|i| {
        format!("obfs4 1.2.4.{i}:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA")
            .parse::<BridgeLine>()
            .unwrap()
    });
    pool.merge(obfs.chain([wt.clone()]), &HashSet::new());
    pool.save().unwrap();
    (dir, path, wt)
}

/// Single-candidate fixture for the TS17-08 promotion tests: a config with
/// one working obfs4 bridge and a pool holding exactly one webtunnel
/// candidate. Returns the guard (keep alive), the config path and the
/// candidate.
fn promotion_fixture() -> (tempfile::TempDir, std::path::PathBuf, BridgeLine) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("proxy.ktav");
    let mut cfg = Config::default();
    cfg.bridges.transport = "webtunnel".into();
    cfg.bridges.lines = vec![bridge().to_string()];
    cfg.write(&path).unwrap();
    let wt: BridgeLine = "webtunnel [2001:db8::1]:443 0123456789ABCDEF0123456789ABCDEF01234567 url=https://example.com/bridge"
        .parse().unwrap();
    let mut pool = CandidatePool::load(CandidatePool::resolve_path(Some(&path))).unwrap();
    assert_eq!(pool.merge([wt.clone()], &HashSet::new()), 1);
    pool.save().unwrap();
    (dir, path, wt)
}

fn reachable_probe() -> ProbeCheck<'static> {
    Box::new(|bridge| {
        assert_eq!(bridge.transport.as_deref(), Some("webtunnel"));
        Box::pin(async {
            bridge_probe::Outcome::Reachable {
                latency: Duration::from_millis(10),
            }
        })
    })
}

#[test]
fn working_set_with_stale_cert_does_not_exclude_fresh_cert() {
    // The server rotated its obfs4 key: the working config holds the old
    // cert, the source brings the fresh one. working_keys is built with
    // candidate_pool::key_of, which includes the cert, so the fresh
    // candidate must not be excluded — a pool merge keeps it.
    let stale: BridgeLine =
        "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=ZZZ iat-mode=0"
            .parse()
            .unwrap();
    let fresh: BridgeLine =
        "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=YYY iat-mode=0"
            .parse()
            .unwrap();
    let mut cfg = Config::default();
    cfg.bridges.lines = vec![stale.to_string()];
    let exclude = working_keys(&cfg);
    assert!(exclude.contains(&key_of(&stale)));
    assert!(
        !exclude.contains(&key_of(&fresh)),
        "fresh cert on the same relay must not be excluded by the stale one"
    );
    let dir = tempfile::tempdir().unwrap();
    let mut pool =
        CandidatePool::load(CandidatePool::resolve_path(Some(&dir.path().join("c.log")))).unwrap();
    assert_eq!(pool.merge([fresh], &exclude), 1);
}

#[tokio::test]
async fn discovery_promotes_webtunnel_and_records_channel_evidence() {
    let (_dir, path, wt) = discovery_fixture();
    let added = drain_pool_with(
        Some(&path),
        1,
        Some(&check(true)),
        &reachable_probe(),
        &aw(),
    )
    .await
    .unwrap();
    assert_eq!(added, 1);
    let cfg = Config::load_with_override(Some(&path))
        .unwrap()
        .into_config();
    assert!(cfg.bridges.parsed().unwrap().bridges.contains(&wt));
    let store = BridgeStore::load(BridgeStore::resolve_path(Some(&path))).unwrap();
    assert_eq!(store.channel_ok_count(&wt), 1);
    assert_eq!(store.ok_count(&wt), 1);
    let mut pool = CandidatePool::load(CandidatePool::resolve_path(Some(&path))).unwrap();
    assert_eq!(pool.len(), 100);
    assert!(pool
        .take(100)
        .iter()
        .all(|b| b.transport.as_deref() == Some("obfs4")));
}

#[tokio::test]
async fn resolver_failure_keeps_webtunnel_for_a_later_successful_attempt() {
    let (_dir, path, wt) = discovery_fixture();
    let unavailable: ProbeCheck<'static> = Box::new(|_| {
        Box::pin(async {
            bridge_probe::Outcome::Unmeasured {
                reason: "resolver unavailable".into(),
            }
        })
    });
    assert_eq!(
        drain_pool_with(Some(&path), 1, Some(&check(true)), &unavailable, &aw())
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        CandidatePool::load(CandidatePool::resolve_path(Some(&path)))
            .unwrap()
            .len(),
        101
    );
    assert_eq!(
        drain_pool_with(
            Some(&path),
            1,
            Some(&check(true)),
            &reachable_probe(),
            &aw()
        )
        .await
        .unwrap(),
        1
    );
    let cfg = Config::load_with_override(Some(&path))
        .unwrap()
        .into_config();
    assert!(cfg.bridges.parsed().unwrap().bridges.contains(&wt));
}

#[tokio::test]
async fn transient_channel_failure_does_not_discard_a_candidate() {
    let (_dir, path, _) = discovery_fixture();
    assert_eq!(
        drain_pool_with(
            Some(&path),
            1,
            Some(&check(false)),
            &reachable_probe(),
            &aw()
        )
        .await
        .unwrap(),
        0
    );
    assert_eq!(
        drain_pool_with(
            Some(&path),
            1,
            Some(&check(true)),
            &reachable_probe(),
            &aw()
        )
        .await
        .unwrap(),
        1
    );
}

fn check(ok: bool) -> ChannelCheck<'static> {
    Box::new(move |_: &BridgeLine, _: Duration| Box::pin(async move { ok }))
}

fn bridge() -> BridgeLine {
    "obfs4 1.2.3.4:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0"
        .parse()
        .expect("valid bridge line")
}

#[tokio::test]
async fn tcp_ok_and_channel_ok_promotes() {
    let b = bridge();
    assert!(
        admits_candidate(
            Some(Duration::from_millis(120)),
            &b,
            Some(&check(true)),
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
    );
}

#[tokio::test]
async fn tcp_ok_but_channel_fails_rejects() {
    let b = bridge();
    assert!(
        !admits_candidate(
            Some(Duration::from_millis(120)),
            &b,
            Some(&check(false)),
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
    );
}

#[tokio::test]
async fn tcp_ok_with_no_channel_check_falls_back_to_tcp_only() {
    // Documented cold-start fallback: no live tunnel to warm through.
    let b = bridge();
    assert!(
        admits_candidate(
            Some(Duration::from_millis(120)),
            &b,
            None,
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
    );
}

#[tokio::test]
async fn tcp_dead_rejects_without_consulting_channel_check() {
    let consulted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = consulted.clone();
    let spy: ChannelCheck<'static> = Box::new(move |_: &BridgeLine, _: Duration| {
        let flag = flag.clone();
        Box::pin(async move {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
            true
        })
    });
    let b = bridge();
    assert!(
        !admits_candidate(
            None,
            &b,
            Some(&spy),
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
    );
    assert!(!consulted.load(std::sync::atomic::Ordering::SeqCst));
}

/// TS17-02, the core assertion the review demanded: the drain must not
/// return while a verification worker its decision outlived is still
/// running, and completion must be observed from INSIDE the worker.
///
/// Scope of this test: it drives `drain_pool_with` end to end, but the
/// worker itself is a stand-in registered through the same
/// `AdmissionWorkers::track` the real `verify_for_admission` uses. The
/// real one cannot run here — it resolves a PT binary and builds a Tor
/// circuit — so what is pinned is the ownership contract (track, decide,
/// join outside the pool lock), not the verifier's internals. The
/// verifier's own side of the seam (`park_if_armed` under VERIFY_LOCK,
/// `mark_worker_done` after the guard drops) is exercised by the
/// stand-in calling the same two functions in the same order.
#[tokio::test(start_paused = true)]
async fn drain_joins_an_outlived_verification_worker_before_returning() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("proxy.ktav");
    let mut cfg = Config::default();
    cfg.bridges.transport = "webtunnel".into();
    cfg.write(&path).unwrap();
    let candidate: BridgeLine =
        "webtunnel [2001:db8::1]:443 0123456789ABCDEF0123456789ABCDEF01234567 url=https://example.com/bridge"
            .parse()
            .unwrap();
    let pool_path = CandidatePool::resolve_path(Some(&path));
    let mut pool = CandidatePool::load(pool_path.clone()).unwrap();
    assert_eq!(pool.merge([candidate], &HashSet::new()), 1);
    pool.save().unwrap();

    // The worker parks here while it "holds VERIFY_LOCK"; the site and
    // path are the ones the real verifier uses.
    let worker_site = crate::test_seams::Site::AdmissionVerifyPostLock;
    let live_cache = crate::tor_setup::arti_base_dir(Some(&path)).join("cache");
    let gate = crate::test_seams::ParkedGate::arm(worker_site, &live_cache);
    assert_eq!(
        crate::test_seams::worker_done_count(worker_site, &live_cache),
        0,
        "a fresh live-cache path starts with no completions"
    );

    // The same Arc the drain joins, so the stand-in worker lands in the
    // registry `drain_pool_with` actually waits on.
    let workers = std::sync::Arc::new(AdmissionWorkers::default());
    let checker: ChannelCheck<'static> = {
        let live_cache = live_cache.clone();
        let workers = workers.clone();
        Box::new(move |_: &BridgeLine, _: Duration| {
            let live_cache = live_cache.clone();
            let workers = workers.clone();
            Box::pin(async move {
                // Exactly what verify_for_admission does: spawn the
                // blocking worker, hand its handle to the registry
                // synchronously (before any await, so cancellation
                // cannot orphan it), then wait for a decision that never
                // arrives before the drain budget expires.
                let handle = tokio::task::spawn_blocking(move || {
                    crate::test_seams::park_if_armed(worker_site, &live_cache);
                    crate::test_seams::mark_worker_done(worker_site, &live_cache);
                    Ok(false)
                });
                workers.track(handle);
                std::future::pending::<bool>().await
            })
        })
    };

    let drain_path = path.clone();
    let drain_workers = workers.clone();
    // The parking happens on the blocking pool, which keeps this runtime
    // free to advance its paused clock.
    let drain = async move {
        let probe = reachable_probe();
        drain_pool_with(Some(&drain_path), 1, Some(&checker), &probe, &drain_workers).await
    };
    tokio::pin!(drain);

    // Let the worker reach its park, then expire the decision deadline.
    let gate_wait = gate.clone();
    let parked = tokio::task::spawn_blocking(move || gate_wait.wait_parked(HANG_GUARD));
    // Poll the drain so the checker actually starts.
    tokio::select! {
        _ = &mut drain => panic!("the drain returned before the worker was even parked"),
        result = parked => result.unwrap(),
    }
    tokio::time::advance(DRAIN_BUDGET).await;

    // THE KEY ASSERTION. The decision has expired, so the candidate is
    // deferred and the pool transaction can close — but the worker is
    // still parked, and `join_all` must hold the drain here. Without it
    // the drain returns now and the worker runs on detached.
    //
    // The guard sleeps on a blocking thread, on the real clock: the
    // paused clock cannot be used here, because tokio only auto-advances
    // it while nothing is running, and the parked worker keeps a
    // blocking task alive for exactly as long as this assertion needs.
    let guard = tokio::task::spawn_blocking(|| std::thread::sleep(UNBLOCK_GUARD));
    tokio::select! {
        _ = &mut drain => panic!(
            "the drain returned while an outlived verification worker was still running"
        ),
        result = guard => result.unwrap(),
    }
    assert_eq!(
        crate::test_seams::worker_done_count(worker_site, &live_cache),
        0,
        "the parked worker cannot have completed yet"
    );

    gate.release();
    let added = drain.await.unwrap();
    assert_eq!(
        added, 0,
        "the timed-out candidate is deferred, not promoted"
    );
    assert_eq!(
        crate::test_seams::worker_done_count(worker_site, &live_cache),
        1,
        "the worker marked ITSELF done, and the drain waited for that"
    );
}

#[tokio::test(start_paused = true)]
async fn admission_timeout_returns_candidate_and_releases_pool_lock() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("proxy.ktav");
    let mut cfg = Config::default();
    cfg.bridges.transport = "webtunnel".into();
    cfg.write(&path).unwrap();
    let candidate: BridgeLine =
        "webtunnel [2001:db8::1]:443 0123456789ABCDEF0123456789ABCDEF01234567 url=https://example.com/bridge"
            .parse()
            .unwrap();
    let pool_path = CandidatePool::resolve_path(Some(&path));
    let mut pool = CandidatePool::load(pool_path.clone()).unwrap();
    assert_eq!(pool.merge([candidate.clone()], &HashSet::new()), 1);
    pool.save().unwrap();

    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let started_tx = std::sync::Arc::new(std::sync::Mutex::new(Some(started_tx)));
    let started_for_checker = started_tx.clone();
    let checker: ChannelCheck<'static> = Box::new(move |_: &BridgeLine, _: Duration| {
        if let Some(sender) = started_for_checker.lock().unwrap().take() {
            let _ = sender.send(());
        }
        Box::pin(std::future::pending::<bool>())
    });
    let probe: ProbeCheck<'static> = Box::new(|_| {
        Box::pin(async {
            bridge_probe::Outcome::Reachable {
                latency: Duration::from_millis(1),
            }
        })
    });
    let task_path = path.clone();
    let task = tokio::spawn(async move {
        drain_pool_with(Some(&task_path), 1, Some(&checker), &probe, &aw()).await
    });
    started_rx.await.unwrap();
    tokio::time::advance(DRAIN_BUDGET).await;
    assert_eq!(task.await.unwrap().unwrap(), 0);

    // The timed-out admission is deferred, and the pool transaction has
    // completed, so another writer can acquire the lock immediately.
    let added = tokio::task::spawn_blocking(move || {
        CandidatePool::transaction(&pool_path, |pool| {
            assert_eq!(pool.len(), 1);
            pool.merge([], &HashSet::new())
        })
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(added, 0);
    let restored = CandidatePool::load(CandidatePool::resolve_path(Some(&path)))
        .unwrap()
        .take(1);
    assert_eq!(restored, vec![candidate]);
}

/// Actual-caller overlap: a pool transaction (the refresh path) parked
/// mid-flight owns the pool lock, so `drain_pool_with` — the
/// maintenance/CLI drain — must wait and then build on its published
/// state. Forcing: the drain is parked before its acquisition and
/// released only while the transaction provably owns the lock (parked
/// after its load, unreleased). The transaction's gate is released when
/// the drain completes, or — when the drain is correctly still blocked —
/// after a guard timeout; the timeout only picks the releaser, the lock
/// itself orders the correct-mode outcome.
#[tokio::test]
async fn drain_waits_for_a_concurrent_pool_transaction_and_both_effects_survive() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("proxy.ktav");
    let mut cfg = Config::default();
    cfg.bridges.transport = "webtunnel".into();
    cfg.write(&path).unwrap();

    let wt: BridgeLine =
        "webtunnel [2001:db8::1]:443 0123456789ABCDEF0123456789ABCDEF01234567 url=https://example.com/bridge"
            .parse()
            .unwrap();
    let other: BridgeLine =
        "obfs4 1.2.3.4:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0"
            .parse()
            .unwrap();
    let newcomer: BridgeLine =
        "obfs4 1.2.3.9:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=CCC iat-mode=0"
            .parse()
            .unwrap();

    let pool_path = CandidatePool::resolve_path(Some(&path));
    let mut seed = CandidatePool::load(pool_path.clone()).unwrap();
    assert_eq!(
        seed.merge(vec![other.clone(), wt.clone()], &HashSet::new()),
        2
    );
    seed.save().unwrap();

    let pre = crate::test_seams::ParkedGate::arm(crate::test_seams::Site::PreAcquire, &pool_path);
    let post = crate::test_seams::ParkedGate::arm(crate::test_seams::Site::PostLoad, &pool_path);
    let post_for_drain = post.clone();
    let (drain_done_tx, drain_done_rx) = std::sync::mpsc::channel();
    let drain_path = path.clone();
    let drain_task = tokio::spawn(async move {
        let checker = check(true);
        let probe = reachable_probe();
        let out = drain_pool_with(Some(&drain_path), 1, Some(&checker), &probe, &aw()).await;
        post_for_drain.release();
        let _ = drain_done_tx.send(());
        out
    });
    let pre_wait = pre.clone();
    tokio::task::spawn_blocking(move || pre_wait.wait_parked(HANG_GUARD))
        .await
        .unwrap();

    let tx_path = pool_path.clone();
    let newcomer_for_tx = newcomer.clone();
    let tx = std::thread::spawn(move || {
        CandidatePool::transaction(&tx_path, |p| {
            p.merge([newcomer_for_tx.clone()], &HashSet::new())
        })
    });
    let post_wait = post.clone();
    tokio::task::spawn_blocking(move || post_wait.wait_parked(HANG_GUARD))
        .await
        .unwrap();

    // The drain now reaches its acquisition while the transaction owns
    // the lock.
    pre.release();
    let drain_finished =
        tokio::task::spawn_blocking(move || drain_done_rx.recv_timeout(UNBLOCK_GUARD).is_ok())
            .await
            .unwrap();
    let _drain_finished = drain_finished;
    // Release the transaction in both modes. Correct locking leaves the
    // drain blocked; bypassing it lets the final assertions fail.
    post.release();

    let added = tx.join().unwrap().unwrap();
    let promoted = drain_task.await.unwrap().unwrap();
    assert_eq!(added, 1, "the parked transaction adds the newcomer");
    assert_eq!(promoted, 1, "the drain promotes the webtunnel candidate");

    let latest = Config::load_with_override(Some(&path))
        .unwrap()
        .into_config();
    assert!(
        latest.bridges.parsed().unwrap().bridges.contains(&wt),
        "the drain promoted the webtunnel candidate into the working config"
    );

    let mut pool = CandidatePool::load(pool_path).unwrap();
    assert_eq!(
        pool.take(10),
        vec![other, newcomer],
        "the parked transaction's addition survives; the consumed webtunnel candidate stays removed"
    );
}

/// TS17-08 regression, exactly as the review demands: a verified candidate
/// whose config write fails must survive in the pool, and the next drain —
/// with no new fetch — must return and promote it once the write works.
#[tokio::test]
async fn failed_config_promotion_keeps_the_verified_candidate_pooled() {
    let (_dir, path, wt) = promotion_fixture();
    let pool_path = CandidatePool::resolve_path(Some(&path));

    crate::test_seams::arm_failure(crate::test_seams::Site::ConfigPromotion, &path);
    let first = drain_pool_with(
        Some(&path),
        1,
        Some(&check(true)),
        &reachable_probe(),
        &aw(),
    )
    .await
    .expect_err("the injected config-write failure must surface");
    // `{:#}`, not `to_string()`: anyhow's plain Display shows only the
    // outermost context ("promoting bridges in config"), so the injected
    // cause would never match.
    assert!(
        format!("{first:#}").contains("injected config promotion failure"),
        "the failure must be the config promotion, not an earlier step: {first:#}"
    );

    // THE core assertion: the verified candidate is still pooled — it was
    // never written off before the config write confirmed it.
    let mut pooled = CandidatePool::load(pool_path.clone()).unwrap();
    assert_eq!(
        pooled.take(10),
        vec![wt.clone()],
        "the verified candidate must survive a failed config promotion"
    );
    let cfg = Config::load_with_override(Some(&path))
        .unwrap()
        .into_config();
    assert!(!cfg.bridges.parsed().unwrap().bridges.contains(&wt));

    // Retry drain, still no fetch: the same candidate is returned, promoted
    // (the injection was one-shot and is consumed) and only then shed.
    let added = drain_pool_with(
        Some(&path),
        1,
        Some(&check(true)),
        &reachable_probe(),
        &aw(),
    )
    .await
    .unwrap();
    assert_eq!(added, 1);
    let cfg = Config::load_with_override(Some(&path))
        .unwrap()
        .into_config();
    assert!(cfg.bridges.parsed().unwrap().bridges.contains(&wt));
    assert_eq!(
        CandidatePool::load(pool_path).unwrap().len(),
        0,
        "the confirmed candidate is shed from the pool"
    );
}

/// TS17-08, the unchanged-success-path guard: on a working config write the
/// drain still promotes, still sheds the candidate from the pool, and a
/// repeat drain without any fetch sees nothing left to do. Also pins the
/// idempotency the confirm-after-success relies on: promoting a line that
/// is already present adds nothing.
#[tokio::test]
async fn successful_drain_promotes_sheds_and_a_repeat_drain_sees_nothing() {
    let (_dir, path, wt) = promotion_fixture();
    let pool_path = CandidatePool::resolve_path(Some(&path));

    let added = drain_pool_with(
        Some(&path),
        1,
        Some(&check(true)),
        &reachable_probe(),
        &aw(),
    )
    .await
    .unwrap();
    assert_eq!(added, 1);
    let cfg = Config::load_with_override(Some(&path))
        .unwrap()
        .into_config();
    assert!(cfg.bridges.parsed().unwrap().bridges.contains(&wt));
    assert_eq!(
        CandidatePool::load(pool_path.clone()).unwrap().len(),
        0,
        "the promoted candidate is removed from the pool"
    );

    // Second drain without any fetch: the pool is empty, nothing to do.
    let again = drain_pool_with(
        Some(&path),
        1,
        Some(&check(true)),
        &reachable_probe(),
        &aw(),
    )
    .await
    .unwrap();
    assert_eq!(again, 0);

    // Idempotent promotion: the same line again adds nothing.
    // (anyhow::Error is not PartialEq, so compare the Ok payload.)
    assert_eq!(
        promote_bridges_in_config(&path, &[wt]).expect("repeat promotion succeeds"),
        0
    );
}

/// TS17-08, the concurrency guard: the confirm transaction must merge with
/// the pool as it exists AFTER the config write, never write back the
/// drain's stale snapshot. A refresh that merges a newcomer while the drain
/// sits between its take and its confirm must survive the promoted
/// candidate's removal.
#[tokio::test]
async fn confirm_removals_merge_with_a_concurrent_refresh_instead_of_clobbering_it() {
    let (_dir, path, wt) = promotion_fixture();
    let pool_path = CandidatePool::resolve_path(Some(&path));
    let newcomer: BridgeLine =
        "obfs4 1.2.3.9:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=CCC iat-mode=0"
            .parse()
            .unwrap();

    // Park the drain right before its confirm transaction: the config
    // promotion has already succeeded and the pool lock is NOT held.
    let gate = crate::test_seams::ParkedGate::arm(crate::test_seams::Site::PreRestore, &pool_path);
    let drain_path = path.clone();
    let drain = tokio::spawn(async move {
        drain_pool_with(
            Some(&drain_path),
            1,
            Some(&check(true)),
            &reachable_probe(),
            &aw(),
        )
        .await
    });
    let wait = gate.clone();
    tokio::task::spawn_blocking(move || wait.wait_parked(HANG_GUARD))
        .await
        .unwrap();

    // While the drain is parked, a concurrent refresh merges a newcomer.
    let tx_path = pool_path.clone();
    let newcomer_for_tx = newcomer.clone();
    let added = tokio::task::spawn_blocking(move || {
        CandidatePool::transaction(&tx_path, |p| p.merge([newcomer_for_tx], &HashSet::new()))
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(added, 1);

    gate.release();
    assert_eq!(drain.await.unwrap().unwrap(), 1);

    // The newcomer survives; the promoted candidate is shed. A stale
    // snapshot write-back would have erased the newcomer (and kept the
    // promoted candidate, which by then lives in the config).
    let mut pool = CandidatePool::load(pool_path).unwrap();
    assert_eq!(pool.take(10), vec![newcomer]);
    let cfg = Config::load_with_override(Some(&path))
        .unwrap()
        .into_config();
    assert!(cfg.bridges.parsed().unwrap().bridges.contains(&wt));
}
