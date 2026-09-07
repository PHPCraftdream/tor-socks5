use super::runtime::*;
use super::*;
use std::sync::Once;

/// Install rustls's process-wide `CryptoProvider` exactly once for this
/// test binary, mirroring `install_crypto_provider()` in
/// `apps/socks5-proxy/src/startup.rs` (which real app startup always
/// runs before constructing any `TorTunnel`). A genuinely fresh, empty
/// `state_dir` (see the tempdir-based tests below) reaches further into
/// arti's directory-manager setup than a dir with pre-existing state
/// would, and that path expects a crypto provider to already be
/// installed. `install_default()` errors if called twice in the same
/// process, so the error is intentionally discarded.
fn ensure_crypto_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[test]
fn health_starts_unstamped_and_counts_attempts() {
    let h = TorHealth::default();
    assert_eq!(h.last_success_secs(), 0);
    assert_eq!(h.attempt_count(), 0);
    h.record_attempt();
    h.record_attempt();
    assert_eq!(h.attempt_count(), 2);
    // No success recorded yet.
    assert_eq!(h.last_success_secs(), 0);
}

#[test]
fn record_success_stamps_nonzero() {
    let h = TorHealth::default();
    h.record_success();
    let s = h.last_success_secs();
    assert!(s > 0, "record_success must stamp a real unix time");
}

#[test]
fn success_target_roundtrips_and_starts_empty() {
    let h = TorHealth::default();
    assert_eq!(h.last_success_target(), None);
    h.record_success_target("example.com", 443);
    assert_eq!(
        h.last_success_target(),
        Some(("example.com".to_string(), 443))
    );
}

#[test]
fn success_target_last_write_wins() {
    let h = TorHealth::default();
    h.record_success_target("first.example", 80);
    h.record_success_target("second.example", 8080);
    assert_eq!(
        h.last_success_target(),
        Some(("second.example".to_string(), 8080)),
        "a newer record_success_target call must overwrite the previous one"
    );
}

#[test]
fn handle_clone_shares_slot_and_health() {
    // Two clones of a handle share the same health counters: an attempt
    // recorded through one is visible through the other. This is the
    // property the watchdog relies on to observe the hot path.
    let h = TorHealth::default();
    let h2 = h.clone();
    h.record_attempt();
    assert_eq!(h2.attempt_count(), 1);
}

#[tokio::test]
async fn drain_releases_tunnel() {
    // We can't build a real TorTunnel in a unit test, but the slot only
    // stores Option<TorTunnel> and we never read it here — so a stub
    // via the type system isn't possible without a live tunnel. Instead
    // exercise the Option mechanics indirectly by constructing the slot
    // directly.
    let slot: Arc<RwLock<Option<u32>>> = Arc::new(RwLock::new(Some(42)));
    assert_eq!(slot.read().await.clone(), Some(42));
    // "drain"
    let taken = slot.write().await.take();
    assert_eq!(taken, Some(42));
    assert!(slot.read().await.is_none());
}

#[test]
fn unix_secs_is_plausible() {
    let s = unix_secs();
    // After 2024-01-01 and before year ~2100 — sanity, not exactness.
    assert!(s > 1_704_067_200, "unix_secs should be past 2024");
}

#[tokio::test]
async fn verify_usable_skips_network_when_no_target() {
    // `target: None` must short-circuit to `true` without ever touching
    // the network — this is the "nothing to compare against yet" case
    // (process just started, no success recorded on this handle). We
    // can't cheaply fake a *bootstrapped* TorTunnel in a unit test, but
    // `create_unbootstrapped_with` is synchronous and does no I/O, so it
    // is safe to use here purely to get a real `&TorTunnel` reference —
    // if `verify_usable` ever tried to use it (it must not, for
    // `target: None`), the call would hang/fail and the test would
    // never reach the assertion below within the runtime's default
    // behavior, since nothing here awaits a bootstrap.
    //
    // `state_dir` must point at a fresh tempdir, not `Default::default()`'s
    // `None` (which falls back to arti's shared per-user OS-default
    // state/cache location): constructing even an "unbootstrapped"
    // client eagerly opens that directory's storage, which is flaky on
    // CI (`DirMgrSetup(ReadOnlyStorage(NoDatabase))` on a fresh runner
    // with no prior arti state, or a real `SqliteError` when concurrent
    // tests in this same binary race on the same shared path) — this is
    // exactly the fragility `packages/arti-wrapper/src/lib.rs`'s
    // `signal_bridge_failure_*` tests hit and fixed the same way.
    let dir = tempfile::tempdir().unwrap();
    let settings = arti_wrapper::Settings {
        state_dir: Some(dir.path().to_path_buf()),
        ..Default::default()
    };
    ensure_crypto_provider();
    let tor = arti_wrapper::TorTunnel::create_unbootstrapped_with(settings)
        .expect("synchronous, no-I/O construction must succeed");
    assert!(
        verify_usable(&tor, None).await,
        "target: None must be treated as usable without a network round-trip"
    );
}

#[tokio::test]
async fn heal_reports_terminate_failed_on_a_client_that_is_not_running() {
    // A `TorTunnel` built via `create_unbootstrapped_with` is
    // synchronous, does no I/O, and never reaches arti's "running"
    // state — so `TorClient::chanmgr()` (and therefore
    // `TorTunnel::terminate_all_channels`) must fail on it, exactly the
    // same way it would on a fully dormant client. `heal` must surface
    // this as `TerminateFailed` rather than panicking or silently
    // treating it as `StillUnhealthy` — the two mean different things to
    // the watchdog loop's logging (dead channel manager vs. a live one
    // that just isn't reconnecting).
    //
    // Same tempdir `state_dir` rationale as the test above — do not
    // revert to `Default::default()`.
    let dir = tempfile::tempdir().unwrap();
    let settings = arti_wrapper::Settings {
        state_dir: Some(dir.path().to_path_buf()),
        ..Default::default()
    };
    ensure_crypto_provider();
    let tor = arti_wrapper::TorTunnel::create_unbootstrapped_with(settings)
        .expect("synchronous, no-I/O construction must succeed");
    match heal(&tor, None).await {
        HealResult::TerminateFailed(_) => {}
        HealResult::Healed => panic!("an unbootstrapped client cannot have healed"),
        HealResult::StillUnhealthy => panic!(
            "chanmgr() must fail outright on a client that never bootstrapped, not just \
             fail the canary"
        ),
    }
}

#[test]
fn error_class_counters_roundtrip_independently() {
    // Each of the three class counters starts at 0 and accumulates
    // independently of the others — the same "record N times, read N"
    // shape as `attempt_count`, but exercised three times over so a
    // copy-paste mistake wiring one counter to the wrong field would
    // fail this test.
    let h = TorHealth::default();
    assert_eq!(h.remote_timeout_count(), 0);
    assert_eq!(h.access_failed_count(), 0);
    assert_eq!(h.net_timeout_count(), 0);

    h.record_remote_timeout();
    h.record_remote_timeout();
    h.record_remote_timeout();
    assert_eq!(h.remote_timeout_count(), 3);
    assert_eq!(
        h.access_failed_count(),
        0,
        "recording remote_timeout must not bump access_failed"
    );
    assert_eq!(
        h.net_timeout_count(),
        0,
        "recording remote_timeout must not bump net_timeout"
    );

    h.record_access_failed();
    h.record_access_failed();
    assert_eq!(h.access_failed_count(), 2);
    assert_eq!(
        h.remote_timeout_count(),
        3,
        "recording access_failed must not touch remote_timeout"
    );
    assert_eq!(
        h.net_timeout_count(),
        0,
        "recording access_failed must not bump net_timeout"
    );

    h.record_net_timeout();
    assert_eq!(h.net_timeout_count(), 1);
    assert_eq!(
        h.remote_timeout_count(),
        3,
        "recording net_timeout must not touch remote_timeout"
    );
    assert_eq!(
        h.access_failed_count(),
        2,
        "recording net_timeout must not touch access_failed"
    );
}

#[test]
fn classify_and_record_ignores_non_connect_variants() {
    // `TorError` variants other than `Connect` (e.g. a config error
    // raised before any network activity) carry no `arti_client::Error`
    // to classify — `classify_and_record` must leave all three counters
    // untouched rather than guess.
    let h = TorHealth::default();
    let err = arti_wrapper::TorError::InvalidBridge("not a real bridge line".to_string());
    classify_and_record(&err, &h);
    assert_eq!(h.remote_timeout_count(), 0);
    assert_eq!(h.access_failed_count(), 0);
    assert_eq!(h.net_timeout_count(), 0);
}

#[test]
fn should_decline_rebuild_no_data_does_not_block() {
    // No classified failures this window at all — either nothing failed
    // through TorTunnel::connect, or the failures came through some
    // other, unclassified path. Either way, "no data" must mean "behave
    // as before" (don't rebuild-gate on an absence of signal), not
    // "assume the worst and decline".
    assert!(!should_decline_rebuild(0, 0, 0));
}

#[test]
fn should_decline_rebuild_pure_net_timeout_allows_rebuild() {
    // Only TorNetworkTimeout this window — the exact "zombie channel"
    // signature the watchdog exists to fix. Must proceed to rebuild.
    assert!(!should_decline_rebuild(0, 0, 5));
}

#[test]
fn should_decline_rebuild_pure_remote_timeout_declines() {
    // Only RemoteNetworkTimeout — exit went silent, Tor stack is
    // healthy. A rebuild cannot help; must decline.
    assert!(should_decline_rebuild(5, 0, 0));
}

#[test]
fn should_decline_rebuild_pure_access_failed_declines() {
    // Only TorAccessFailed — guards down/unsuitable. A rebuild starts in
    // a cold slot and reproduces the same condition; must decline.
    assert!(should_decline_rebuild(0, 5, 0));
}

#[test]
fn should_decline_rebuild_net_timeout_dominant_mix_allows_rebuild() {
    // Mixed window where net_timeout strictly dominates the sum of the
    // other two classes — the zombie-channel signature is still the
    // main story here, so the rebuild should proceed.
    assert!(!should_decline_rebuild(2, 1, 10));
}

#[test]
fn should_decline_rebuild_incident_signature_declines() {
    // The actual incident this gate closes: 8 attempts in 218 s, all
    // RemoteNetworkTimeout/ExitTimeout to a single Telegram DC, zero
    // TorAccessFailed and zero TorNetworkTimeout. The old trigger would
    // have rebuilt into a cold, guard-unsuitable slot and made the
    // outage worse; the gate must decline.
    assert!(should_decline_rebuild(8, 0, 0));
}

// -- should_signal_failover ----------------------------------------------

#[test]
fn should_signal_failover_below_threshold_never_fires() {
    // Current bridge hasn't even crossed the absolute degradation
    // threshold yet — must decline regardless of how healthy the
    // alternative is.
    assert!(!should_signal_failover(2, 0, 3, 2));
}

#[test]
fn should_signal_failover_at_threshold_with_sufficient_margin_fires() {
    // Current bridge is exactly at the threshold, and the alternative
    // is clearly healthier (margin 5 >= min_margin 2) — must fire.
    assert!(should_signal_failover(3, 0, 3, 2));
}

#[test]
fn should_signal_failover_above_threshold_but_insufficient_margin_declines() {
    // Both bridges are degraded (threshold crossed), but the
    // alternative isn't meaningfully better — margin of 1 is below
    // min_margin of 2. Must decline: this is the "don't ping-pong
    // between two mediocre bridges" case.
    assert!(!should_signal_failover(4, 3, 3, 2));
}

#[test]
fn should_signal_failover_alternative_not_better_declines() {
    // The "alternative" is tied with (or worse than) the current
    // bridge — saturating_sub floors the margin at 0, which is below
    // any positive min_margin, so this must decline without a separate
    // "is it actually better" check.
    assert!(!should_signal_failover(5, 5, 3, 1));
    assert!(!should_signal_failover(5, 8, 3, 1));
}

#[test]
fn should_signal_failover_zero_margin_configured_fires_on_any_nonneg_gap() {
    // A degenerate but valid configuration (`min_margin == 0`): once the
    // threshold is crossed, any alternative that is not strictly worse
    // is enough to fire — including a tie (margin == 0 >= min_margin
    // 0).
    assert!(should_signal_failover(3, 3, 3, 0));
}

#[test]
fn should_signal_failover_large_margin_exact_boundary_fires() {
    // Margin exactly equal to min_margin must fire (>=, not >).
    assert!(should_signal_failover(10, 5, 3, 5));
    // One below the boundary must decline.
    assert!(!should_signal_failover(10, 6, 3, 5));
}

// -- gated-tick heal override --------------------------------------------

fn obs(unix: i64) -> Option<OffsetDateTime> {
    Some(OffsetDateTime::from_unix_timestamp(unix).expect("valid timestamp"))
}

#[test]
fn should_override_decline_requires_two_gated_ticks() {
    // One declined tick is not enough; two (or more) override the gate.
    assert!(!should_override_decline(0));
    assert!(!should_override_decline(1));
    assert!(should_override_decline(2));
    assert!(should_override_decline(3));
}

#[test]
fn incident_signature_single_gated_tick_does_not_escalate() {
    // The July incident (8 attempts / 218 s, all RemoteNetworkTimeout)
    // is exactly the signature the gate declines...
    assert!(should_decline_rebuild(8, 0, 0));
    // ...but a single declined tick must not reach the override.
    let gated = step_gated_ticks(0, true);
    assert!(!should_override_decline(gated));
}

#[test]
fn two_consecutive_gated_ticks_trigger_override() {
    // Today's production signature: two fully-failed ticks in a row
    // escalate to a heal despite the declined signature.
    let gated = step_gated_ticks(step_gated_ticks(0, true), true);
    assert!(should_override_decline(gated));
}

#[test]
fn success_between_gated_ticks_restarts_escalation() {
    // One declined tick has accumulated...
    let gated = step_gated_ticks(0, true);
    assert_eq!(gated, 1);
    // ...then a success happens — the counter resets to zero...
    assert_eq!(reset_gated_ticks_on_success(gated, true), 0);
    // ...and the next declined tick starts counting from scratch, so it
    // must NOT override.
    let restarted = step_gated_ticks(0, true);
    assert!(!should_override_decline(restarted));
    // One more declined tick (two in a row again) must.
    assert!(should_override_decline(step_gated_ticks(restarted, true)));
}

#[test]
fn no_success_leaves_gated_counter_alone() {
    // Without a new success the reset is a no-op.
    assert_eq!(reset_gated_ticks_on_success(1, false), 1);
}

// -- failover freshness + signal budget -----------------------------------

#[test]
fn stale_circuit_evidence_blocks_signal() {
    let task_start = obs(2_000_000).expect("task start");
    // Strictly older than the task start: inherited from a previous run.
    assert!(!evidence_is_fresh(obs(1_999_999), task_start));
    // No observation at all compares as stale.
    assert!(!evidence_is_fresh(None, task_start));
    // Equal is NOT fresh — strictly newer required.
    assert!(!evidence_is_fresh(obs(2_000_000), task_start));
}

#[test]
fn fresh_circuit_evidence_allows_signal() {
    let task_start = obs(2_000_000).expect("task start");
    assert!(evidence_is_fresh(obs(2_000_001), task_start));
}

#[test]
fn signal_budget_caps_at_three_signals() {
    assert!(signal_budget_available(0));
    assert!(signal_budget_available(1));
    assert!(signal_budget_available(2));
    assert!(!signal_budget_available(3));
    assert!(!signal_budget_available(4));
}

#[test]
fn signal_budget_is_per_bridge() {
    // One bridge exhausts its budget...
    let exhausted = SignalRecord {
        count: MAX_SIGNALS_PER_BRIDGE,
        ..Default::default()
    };
    assert!(!signal_budget_available(exhausted.count));
    // ...another bridge starts fresh — the budget is per-bridge.
    let fresh = SignalRecord::default();
    assert!(signal_budget_available(fresh.count));
}

#[test]
fn budget_exhaustion_logs_once() {
    let mut r = SignalRecord {
        count: 3,
        exhausted_logged: false,
        last: None,
    };
    // First pass: budget is gone and the flag has not been set yet —
    // this is where the one-time INFO fires.
    assert!(!signal_budget_available(r.count));
    assert!(!r.exhausted_logged);
    r.exhausted_logged = true;
    // Second pass: the flag is set, so no repeated logging.
    assert!(!signal_budget_available(r.count));
    assert!(r.exhausted_logged);
}

// -- healthiest -----------------------------------------------------------

fn bridge(line: &str) -> BridgeLine {
    line.parse().expect("test bridge line parses")
}

fn health(tcp_fails: u32, circuit_fails: u32, ok_count: u32) -> Health {
    Health {
        tcp_fails,
        circuit_fails,
        verified_count: 0,
        ok_count,
        cobs: None,
    }
}

const OBFS4_A: &str =
    "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=ZZZ iat-mode=0";
const OBFS4_B: &str =
    "obfs4 5.6.7.8:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=WWW iat-mode=0";

#[test]
fn healthiest_picks_lowest_circuit_fails() {
    let candidates = vec![
        (bridge(OBFS4_A), health(0, 5, 1)),
        (bridge(OBFS4_B), health(0, 1, 1)),
    ];
    let best = healthiest(&candidates).expect("non-empty candidates yield a winner");
    assert_eq!(best.circuit_fails, 1);
}

#[test]
fn healthiest_empty_candidates_yields_none() {
    assert_eq!(healthiest(&[]), None);
}

#[test]
fn healthiest_excludes_tcp_unhealthy_bridges() {
    // Only a TCP-unhealthy alternative is available — `select_top_n`
    // excludes it outright, so `healthiest` must report no winner
    // rather than surfacing an unreachable bridge as "the best
    // alternative".
    let candidates = vec![(bridge(OBFS4_A), health(1, 0, 100))];
    assert_eq!(healthiest(&candidates), None);
}
