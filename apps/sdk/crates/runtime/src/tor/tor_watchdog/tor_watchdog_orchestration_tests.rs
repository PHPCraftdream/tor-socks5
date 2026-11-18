//! H19.3 orchestration tests for the stale-channel watchdog loop
//! ([`spawn_tor_watchdog`]): the per-tick status publication on the
//! `tokio::sync::watch` channel, and the rebuild cooldown — a failure that
//! performs a heal must not re-trigger on the immediately following ticks,
//! while after the cooldown expires the next qualifying tick acts again.
//!
//! Both tests run on tokio's paused clock (virtual `check_interval` ticks,
//! no wall-clock waiting) against a real `TorTunnel` that never bootstraps:
//! its `terminate_all_channels` fails (no live `ChanMgr`), which surfaces as
//! `HealOutcome::TerminateFailed` — the observable "action" per tick. All
//! assertions read the status watch channel and the handle's health
//! counters; no logs are parsed.

use super::runtime::*;
use super::*;
use std::sync::Once;

/// Install rustls's process-wide `CryptoProvider` once (same rationale as
/// `tor_watchdog_tests::ensure_crypto_provider`: a fresh empty `state_dir`
/// reaches arti's directory-manager setup).
fn ensure_crypto_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// A real handle over an unbootstrapped tunnel (synchronous, no I/O) plus a
/// seeded health store naming one proven-alive bridge, so trigger condition
/// 3 (`alive > 0`) holds on every tick.
fn handle_with_seeded_alive_bridge(dir: &tempfile::TempDir, config_path: &Path) -> TorHandle {
    ensure_crypto_provider();
    let bridge: BridgeLine = "10.0.4.1:443 5555555555555555555555555555555555555555"
        .parse()
        .expect("valid bridge line");
    let mut store =
        BridgeStore::load(bridge_store::BridgeStore::resolve_path(config_path)).expect("load");
    store.note_probe_round(
        std::slice::from_ref(&bridge),
        &[(bridge.clone(), std::time::Duration::from_millis(1))],
        time::OffsetDateTime::now_utc(),
        std::time::Duration::ZERO,
        u32::MAX,
        u32::MAX,
    );
    store.save().expect("seed alive bridge");
    assert_eq!(store.alive_count(), 1, "seeded bridge must be proven alive");

    let settings = arti_wrapper::Settings {
        state_dir: Some(dir.path().join("arti-state")),
        ..Default::default()
    };
    let tor = TorTunnel::create_unbootstrapped_with(settings.clone())
        .expect("synchronous, no-I/O construction");
    TorHandle::new_with_settings(tor, &settings)
}

/// Record a last-success target on the handle's health: the heal's verify
/// stage then attempts a REAL connect through the (unbootstrapped) client,
/// which cannot succeed offline — so every performed heal deterministically
/// ends in a failure outcome (`StillUnhealthy`, or `TerminateFailed` when
/// termination itself fails) and bumps `consecutive_failures`.
fn arm_failing_heal_canary(handle: &TorHandle) {
    handle.health().record_success_target("10.255.255.1", 1);
}

/// Await status publications until `predicate` holds on the latest snapshot,
/// bounded so a regression cannot hang the test (each wake is one tick).
async fn wait_for(
    run: &mut WatchdogRun,
    predicate: impl Fn(&WatchdogStatus) -> bool,
) -> WatchdogStatus {
    for _ in 0..50 {
        run.status.changed().await.expect("status sender alive");
        let snapshot = run.status.borrow().clone();
        if predicate(&snapshot) {
            return snapshot;
        }
    }
    panic!("watchdog status never reached the expected state");
}

/// Record enough connect attempts since the previous tick for trigger
/// condition 2 (`MIN_ATTEMPTS_TO_TRIGGER`) to hold.
fn record_three_attempts(handle: &TorHandle) {
    for _ in 0..MIN_ATTEMPTS_TO_TRIGGER {
        handle.health().record_attempt();
    }
}

/// H19.3 (status through `watch`): every loop tick publishes a snapshot on
/// the `WatchdogRun::status` watch channel; with the trigger conditions
/// unsatisfied (no attempts recorded) the loop only bumps `checks_started`
/// and never acts, all without any real time passing (paused clock).
///
/// ROLLBACK THAT FAILS THIS: removing the per-tick `status_tx` publication
/// (or the whole `checks_started` counter) leaves the channel quiescent and
/// `changed()` never resolves; a regression that heals on every tick without
/// attempts makes `last_heal` non-`None` here.
#[tokio::test(start_paused = true)]
async fn watchdog_publishes_one_status_snapshot_per_tick() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("proxy.ktav");
    let handle = handle_with_seeded_alive_bridge(&dir, &config_path);
    let token = CancellationToken::new();
    let watchdog_cfg = WatchdogConfig {
        check_interval_secs: 1,
        ..Default::default()
    };
    // The config file is never read: condition 2 (fresh attempts) never
    // holds, so the loop exits at condition 2 before any file access.
    let mut run = spawn_tor_watchdog(handle.clone(), config_path, watchdog_cfg, token.clone())
        .expect("enabled config must arm the watchdog");

    for expected in 1..=4u64 {
        run.status.changed().await.expect("status sender alive");
        let snapshot = run.status.borrow().clone();
        assert_eq!(snapshot.checks_started, expected, "one publish per tick");
        assert_eq!(snapshot.consecutive_failures, 0);
        assert_eq!(snapshot.last_heal, None);
    }

    token.cancel();
    run.join.await.expect("watchdog joins after cancel");
}

/// H19.3 (cooldown): the first tick with all trigger conditions holding
/// performs exactly one heal (failed on the unbootstrapped client); the
/// immediately following qualifying ticks — attempts still flowing, bridge
/// still alive — must NOT re-trigger while the cooldown lasts (exactly one
/// action total), and after the cooldown expires the next qualifying tick
/// acts again (`consecutive_failures` moves to 2).
///
/// The cooldown compares `std::time::Instant`, which tokio's paused clock
/// cannot move; the expiry leg therefore advances REAL time by 3 s on a
/// blocking thread (cooldown 1 s — a 3x margin) while the executor keeps
/// running suppressed virtual ticks.
///
/// ROLLBACK THAT FAILS THIS: losing the `last_rebuild` cooldown gate makes
/// every qualifying tick heal again (`consecutive_failures` reaches 2+ on
/// the second tick instead of staying 1); skipping the counter bump on a
/// performed heal keeps it at 1 forever and the expiry leg fails.
#[tokio::test(start_paused = true)]
async fn cooldown_suppresses_repeat_heals_until_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("proxy.ktav");
    let handle = handle_with_seeded_alive_bridge(&dir, &config_path);
    let token = CancellationToken::new();
    let watchdog_cfg = WatchdogConfig {
        check_interval_secs: 1,
        stale_after_secs: 0,
        rebuild_cooldown_secs: 1,
        ..Default::default()
    };
    arm_failing_heal_canary(&handle);
    let mut run = spawn_tor_watchdog(
        handle.clone(),
        config_path.clone(),
        watchdog_cfg,
        token.clone(),
    )
    .expect("enabled config must arm the watchdog");

    // First tick: stale (0 s window), 3 fresh attempts, bridge alive, no
    // classified failures (signature gate passes), no cooldown yet — the
    // heal runs and fails to terminate the dormant client's channels.
    // Start the loop first (its `prev_attempts` baseline is snapshotted on
    // the task's first poll, not at spawn), THEN record attempts so the
    // next tick sees a fresh >= MIN_ATTEMPTS_TO_TRIGGER delta.
    let _first_tick = wait_for(&mut run, |s| s.checks_started >= 1).await;
    record_three_attempts(&handle);
    let snapshot = wait_for(&mut run, |s| s.last_heal.is_some()).await;
    assert_eq!(
        snapshot.consecutive_failures, 1,
        "the failed heal must bump the consecutive-failure counter"
    );
    assert!(matches!(
        snapshot.last_heal,
        Some(HealOutcome::TerminateFailed(_)) | Some(HealOutcome::StillUnhealthy)
    ));

    // Inside the cooldown: more fully-qualifying ticks must not act. Ticks
    // publish `checks_started` without touching the heal state, so the
    // heal-related fields stay frozen at their post-heal values.
    for _ in 0..3 {
        record_three_attempts(&handle);
        let snapshot = wait_for(&mut run, |s| s.checks_started > snapshot.checks_started).await;
        assert_eq!(
            snapshot.consecutive_failures, 1,
            "cooldown must suppress repeat heals"
        );
        assert!(matches!(
            snapshot.last_heal,
            Some(HealOutcome::TerminateFailed(_)) | Some(HealOutcome::StillUnhealthy)
        ));
    }

    // Cooldown expiry: real time (3 s) past the 1 s cooldown, with the
    // executor free to run suppressed virtual ticks meanwhile.
    tokio::task::spawn_blocking(|| std::thread::sleep(Duration::from_secs(3)))
        .await
        .expect("blocking sleep joined");
    record_three_attempts(&handle);
    let snapshot = wait_for(&mut run, |s| s.consecutive_failures >= 2).await;
    assert_eq!(
        snapshot.consecutive_failures, 2,
        "after cooldown expiry the next qualifying tick must act again"
    );

    token.cancel();
    run.join.await.expect("watchdog joins after cancel");
}
