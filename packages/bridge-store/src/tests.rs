use super::*;

fn tmp_dir() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "tor-socks5-bridge-store-test-{}-{}",
        std::process::id(),
        seq
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn bridge(line: &str) -> BridgeLine {
    line.parse().expect("test bridge line parses")
}

const OBFS4_A: &str =
    "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=ZZZ iat-mode=0";
const OBFS4_A_NEW_PARAMS: &str =
    "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=YYY iat-mode=1";
const OBFS4_B: &str =
    "obfs4 5.6.7.8:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=WWW iat-mode=0";

const HOUR: Duration = Duration::from_secs(3600);
const MAX_FAILS: u32 = 24;

fn empty() -> BridgeStore {
    BridgeStore {
        path: PathBuf::from("mem.log"),
        entries: BTreeMap::new(),
    }
}

#[test]
fn resolve_path_uses_config_dir_and_stem() {
    let p = BridgeStore::resolve_path(Some(Path::new("/etc/tor-socks5.ktav")));
    assert_eq!(
        p.file_name().unwrap().to_string_lossy(),
        "tor-socks5.alive-bridges.log"
    );
}

#[test]
fn load_missing_file_is_empty() {
    let dir = tmp_dir();
    let store = BridgeStore::load(dir.join("does-not-exist.log")).expect("load");
    assert_eq!(store.len(), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn record_save_load_roundtrip_with_health() {
    let dir = tmp_dir();
    let path = dir.join("alive.log");
    let mut s = BridgeStore::load(path.clone()).unwrap();
    s.record(bridge(OBFS4_A), Duration::from_millis(42));
    s.record(bridge(OBFS4_B), Duration::from_millis(11));
    s.save().unwrap();

    let loaded = BridgeStore::load(path.clone()).unwrap();
    assert_eq!(loaded.len(), 2);
    assert_eq!(loaded.fails_of(&bridge(OBFS4_A)), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ok_count_accumulates_and_persists() {
    let dir = tmp_dir();
    let path = dir.join("ok.log");
    let mut s = BridgeStore::load(path.clone()).unwrap();
    let b = bridge(OBFS4_A);
    s.record(b.clone(), Duration::from_millis(10));
    s.record(b.clone(), Duration::from_millis(20));
    s.note_channel_success_at(&b, OffsetDateTime::now_utc());
    assert_eq!(s.channel_ok_count(&b), 1);
    assert_eq!(s.ok_count(&b), 2, "two successes accumulate");
    s.save().unwrap();
    let loaded = BridgeStore::load(path).unwrap();
    assert_eq!(
        loaded.ok_count(&bridge(OBFS4_A)),
        2,
        "seen= count persisted across save/load"
    );
    assert_eq!(loaded.channel_ok_count(&bridge(OBFS4_A)), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn healthiest_bridges_prefers_channel_warm_history() {
    let mut s = empty();
    let a = bridge(OBFS4_A);
    let b = bridge(OBFS4_B);
    s.record(a.clone(), Duration::from_millis(5));
    s.record(b.clone(), Duration::from_millis(1));
    let now = OffsetDateTime::now_utc();
    s.note_channel_success_at(&a, now);
    s.note_channel_success_at(&a, now);
    let ranked = s.healthiest_bridges(2);
    assert_eq!(ranked.first(), Some(&a));
    assert_eq!(ranked.get(1), Some(&b));
}

#[test]
fn circuit_verified_is_noop_for_unknown_bridge() {
    let mut s = empty();
    let b = bridge(OBFS4_A);
    s.note_circuit_verified_at(&b, OffsetDateTime::now_utc());
    assert_eq!(
        s.verified_count(&b),
        0,
        "no entry to attach the verification to"
    );
}

#[test]
fn circuit_verified_accumulates_and_stamps_last_verified() {
    let mut s = empty();
    let b = bridge(OBFS4_A);
    s.record(b.clone(), Duration::from_millis(5));
    let t0 = OffsetDateTime::from_unix_timestamp(1_000_000).unwrap();
    s.note_circuit_verified_at(&b, t0);
    s.note_circuit_verified_at(&b, t0 + HOUR);
    assert_eq!(s.verified_count(&b), 2);
    assert_eq!(s.last_verified(&b), Some(t0 + HOUR));
}

#[test]
fn healthiest_bridges_prefers_end_to_end_verified_over_merely_channel_warm() {
    let mut s = empty();
    let a = bridge(OBFS4_A);
    let b = bridge(OBFS4_B);
    s.record(a.clone(), Duration::from_millis(5));
    s.record(b.clone(), Duration::from_millis(1));
    let now = OffsetDateTime::now_utc();
    // b has more/better channel history, but a is the one actually proven to reach
    // the open internet -- a must still rank first.
    s.note_channel_success_at(&b, now);
    s.note_channel_success_at(&b, now);
    s.note_channel_success_at(&a, now);
    s.note_circuit_verified_at(&a, now);
    let ranked = s.healthiest_bridges(2);
    assert_eq!(
        ranked.first(),
        Some(&a),
        "end-to-end verified outranks merely channel-warm"
    );
    assert_eq!(ranked.get(1), Some(&b));
}

#[test]
fn needing_circuit_verification_excludes_fresh_and_unproven_and_retired() {
    let mut s = empty();
    let never_verified = bridge(OBFS4_A);
    let freshly_verified = bridge(OBFS4_B);
    let stale_verified =
        bridge("obfs4 9.9.9.9:443 1111111111111111111111111111111111111111 cert=VVV iat-mode=0");
    let not_channel_proven =
        bridge("obfs4 8.8.8.8:443 2222222222222222222222222222222222222222 cert=UUU iat-mode=0");
    let retired =
        bridge("obfs4 7.7.7.7:443 3333333333333333333333333333333333333333 cert=TTT iat-mode=0");

    for b in [
        &never_verified,
        &freshly_verified,
        &stale_verified,
        &not_channel_proven,
    ] {
        s.record((*b).clone(), Duration::from_millis(5));
    }
    s.record(retired.clone(), Duration::from_millis(5));

    let now = OffsetDateTime::from_unix_timestamp(1_000_000).unwrap();
    s.note_channel_success_at(&never_verified, now);
    s.note_channel_success_at(&freshly_verified, now);
    s.note_channel_success_at(&stale_verified, now);
    s.note_channel_success_at(&retired, now);
    // not_channel_proven deliberately gets no note_channel_success_at.

    s.note_circuit_verified_at(&freshly_verified, now);
    s.note_circuit_verified_at(&stale_verified, now - 2 * HOUR);
    s.note_permanent_failure_at(&retired, now);

    let due = s.needing_circuit_verification(now, HOUR, 10);
    assert!(due.contains(&never_verified), "never verified is due");
    assert!(
        due.contains(&stale_verified),
        "verified longer ago than max_age is due"
    );
    assert!(
        !due.contains(&freshly_verified),
        "verified within max_age is not due"
    );
    assert!(
        !due.contains(&not_channel_proven),
        "not even channel-proven yet"
    );
    assert!(!due.contains(&retired), "retired bridges are excluded");
}

#[test]
fn failed_verification_rotates_the_queue_and_survives_reload() {
    let dir = tmp_dir();
    let path = dir.join("health.log");
    let mut store = BridgeStore::load(path.clone()).unwrap();
    let now = OffsetDateTime::from_unix_timestamp(3_000_000).unwrap();
    let bridges = [bridge(OBFS4_A), bridge(OBFS4_B)];
    for bridge in &bridges {
        store.record(bridge.clone(), Duration::from_millis(10));
        store.note_channel_success_at(bridge, now);
    }
    let first = store.needing_circuit_verification(now, HOUR, 1).remove(0);
    store.note_verification_attempt_at(&first, now);
    store.save().unwrap();
    let loaded = BridgeStore::load(path).unwrap();
    let next = loaded.needing_circuit_verification(now + HOUR, HOUR, 1);
    assert_eq!(next.len(), 1);
    assert_ne!(
        next[0], first,
        "an unsuccessful check must not starve other bridges"
    );
    assert_eq!(
        loaded.verified_count(&first),
        0,
        "an attempt is not a verification success"
    );
    assert_eq!(
        loaded.circuit_fails(&first),
        0,
        "an isolated check failure is not a live outage"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn circuit_verified_metadata_persists_across_save_load() {
    let dir = tmp_dir();
    let path = dir.join("bridges.log");
    let mut s = BridgeStore::load(path.clone()).unwrap();
    let b = bridge(OBFS4_A);
    s.record(b.clone(), Duration::from_millis(5));
    let now = OffsetDateTime::from_unix_timestamp(1_000_000).unwrap();
    s.note_circuit_verified_at(&b, now);
    s.save().unwrap();

    let loaded = BridgeStore::load(path).unwrap();
    assert_eq!(loaded.verified_count(&b), 1);
    assert_eq!(loaded.last_verified(&b), Some(now));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn dedup_key_is_transport_addr_fingerprint() {
    let mut s = empty();
    s.record(bridge(OBFS4_A), Duration::from_millis(100));
    s.record(bridge(OBFS4_A_NEW_PARAMS), Duration::from_millis(50));
    assert_eq!(s.len(), 1, "same key upserts");
}

#[test]
fn tcp_fails_mirrors_fails_of_and_defaults_to_zero() {
    let mut s = empty();
    let b = bridge(OBFS4_A);
    assert_eq!(s.tcp_fails(&b), 0, "unknown bridge reports 0");
    let t0 = OffsetDateTime::from_unix_timestamp(1_000_000).unwrap();
    s.note_failure_at(&b, t0, HOUR);
    assert_eq!(s.tcp_fails(&b), 1);
    s.record_at(b.clone(), Duration::from_millis(5), t0 + HOUR);
    assert_eq!(s.tcp_fails(&b), 0, "a TCP success resets it");
}

#[test]
fn failure_increments_then_rate_limited_within_window() {
    let mut s = empty();
    let b = bridge(OBFS4_A);
    let t0 = OffsetDateTime::from_unix_timestamp(1_000_000).unwrap();

    // First failure → counts (new entry).
    assert!(s.note_failure_at(&b, t0, HOUR));
    assert_eq!(s.fails_of(&b), 1);
    // Another failure 10 min later → within window → no increment.
    assert!(!s.note_failure_at(&b, t0 + Duration::from_secs(600), HOUR));
    assert_eq!(s.fails_of(&b), 1);
    // A failure just past the window → increments.
    assert!(s.note_failure_at(&b, t0 + HOUR + Duration::from_secs(1), HOUR));
    assert_eq!(s.fails_of(&b), 2);
}

#[test]
fn success_resets_failure_counter() {
    let mut s = empty();
    let b = bridge(OBFS4_A);
    let t0 = OffsetDateTime::from_unix_timestamp(1_000_000).unwrap();
    s.note_failure_at(&b, t0, HOUR);
    s.note_failure_at(&b, t0 + HOUR + Duration::from_secs(1), HOUR);
    assert_eq!(s.fails_of(&b), 2);
    s.record_at(b.clone(), Duration::from_millis(5), t0 + 3 * HOUR);
    assert_eq!(s.fails_of(&b), 0, "success clears fails");
}

#[test]
fn note_probe_round_prunes_after_max_fails() {
    let mut s = empty();
    let b = bridge(OBFS4_A);
    let probed = vec![b.clone()];
    let alive: Vec<(BridgeLine, Duration)> = vec![]; // always dead
    let mut now = OffsetDateTime::from_unix_timestamp(2_000_000).unwrap();

    // 23 failed rounds, one per window+ → fails climbs to 23, no prune.
    for _ in 0..(MAX_FAILS - 1) {
        let pruned = s.note_probe_round(&probed, &alive, now, HOUR, MAX_FAILS, u32::MAX);
        assert!(pruned.is_empty());
        now += HOUR + Duration::from_secs(1);
    }
    assert_eq!(s.fails_of(&b), MAX_FAILS - 1);
    // The 24th failure → prune.
    let pruned = s.note_probe_round(&probed, &alive, now, HOUR, MAX_FAILS, u32::MAX);
    assert_eq!(pruned.len(), 1, "bridge removed at max_fails");
    assert_eq!(s.len(), 0);
}

#[test]
fn note_probe_round_alive_resets_and_dead_bumps() {
    let mut s = empty();
    let a = bridge(OBFS4_A);
    let d = bridge(OBFS4_B);
    let now = OffsetDateTime::from_unix_timestamp(3_000_000).unwrap();
    let probed = vec![a.clone(), d.clone()];
    let alive = vec![(a.clone(), Duration::from_millis(50))];
    let pruned = s.note_probe_round(&probed, &alive, now, HOUR, MAX_FAILS, u32::MAX);
    assert!(pruned.is_empty());
    assert_eq!(s.fails_of(&a), 0, "alive stays healthy");
    assert_eq!(s.fails_of(&d), 1, "dead bumped");
}

#[test]
fn failed_today_is_false_for_unknown_bridge() {
    let s = empty();
    let now = OffsetDateTime::from_unix_timestamp(3_000_000).unwrap();
    assert!(!s.failed_today(&bridge(OBFS4_A), now));
}

#[test]
fn failed_today_true_after_same_day_failure() {
    let mut s = empty();
    let d = bridge(OBFS4_A);
    let now = OffsetDateTime::from_unix_timestamp(3_000_000).unwrap();
    s.note_probe_round(
        std::slice::from_ref(&d),
        &[],
        now,
        HOUR,
        MAX_FAILS,
        u32::MAX,
    );
    assert!(s.failed_today(&d, now));
}

#[test]
fn failed_today_false_once_a_later_probe_succeeds() {
    let mut s = empty();
    let d = bridge(OBFS4_A);
    let now = OffsetDateTime::from_unix_timestamp(3_000_000).unwrap();
    s.note_probe_round(
        std::slice::from_ref(&d),
        &[],
        now,
        HOUR,
        MAX_FAILS,
        u32::MAX,
    );
    let later = now + HOUR;
    let alive = (d.clone(), Duration::from_millis(50));
    s.note_probe_round(
        std::slice::from_ref(&d),
        std::slice::from_ref(&alive),
        later,
        HOUR,
        MAX_FAILS,
        u32::MAX,
    );
    assert!(
        !s.failed_today(&d, later),
        "a reset fails counter is not a failure"
    );
}

#[test]
fn failed_today_false_when_the_failure_was_a_different_day() {
    let mut s = empty();
    let d = bridge(OBFS4_A);
    let now = OffsetDateTime::from_unix_timestamp(3_000_000).unwrap();
    s.note_probe_round(
        std::slice::from_ref(&d),
        &[],
        now,
        HOUR,
        MAX_FAILS,
        u32::MAX,
    );
    let next_day = now + Duration::from_secs(24 * 3600);
    assert!(
        !s.failed_today(&d, next_day),
        "yesterday's failure is not today's"
    );
}

#[test]
fn legacy_format_loads_as_healthy() {
    let dir = tmp_dir();
    let path = dir.join("legacy.log");
    std::fs::write(
        &path,
        format!("# 2026-05-18T12:00:00Z latency=42ms\n{OBFS4_A}\n"),
    )
    .unwrap();
    let loaded = BridgeStore::load(path).unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded.fails_of(&bridge(OBFS4_A)), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn health_format_roundtrips() {
    let dir = tmp_dir();
    let path = dir.join("h.log");
    let mut s = BridgeStore::load(path.clone()).unwrap();
    let b = bridge(OBFS4_A);
    let t0 = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
    s.note_failure_at(&b, t0, HOUR);
    s.note_failure_at(&b, t0 + HOUR + Duration::from_secs(1), HOUR);
    s.save().unwrap();
    let loaded = BridgeStore::load(path).unwrap();
    assert_eq!(loaded.fails_of(&b), 2, "fails persisted across save/load");
    let _ = std::fs::remove_dir_all(&dir);
}

// -- Circuit-layer observation tests -------------------------------------

const HALF_HOUR: Duration = Duration::from_secs(30 * 60);
const MAX_CIRCUIT_FAILS: u32 = 5;

#[test]
fn circuit_failure_bumps_outside_window_rate_limits_inside() {
    let mut s = empty();
    let b = bridge(OBFS4_A);
    let t0 = OffsetDateTime::from_unix_timestamp(2_500_000).unwrap();

    // First observation creates the entry with circuit_fails=1.
    assert!(s.note_circuit_failure_at(&b, t0, HALF_HOUR));
    assert_eq!(s.circuit_fails(&b), 1);
    // Within the rate-limit window — no increment.
    assert!(!s.note_circuit_failure_at(&b, t0 + Duration::from_secs(60), HALF_HOUR));
    assert_eq!(s.circuit_fails(&b), 1);
    // Past the window — increments.
    assert!(s.note_circuit_failure_at(&b, t0 + HALF_HOUR + Duration::from_secs(1), HALF_HOUR));
    assert_eq!(s.circuit_fails(&b), 2);
}

#[test]
fn circuit_success_resets_circuit_fails() {
    let mut s = empty();
    let b = bridge(OBFS4_A);
    let t0 = OffsetDateTime::from_unix_timestamp(2_500_000).unwrap();
    s.note_circuit_failure_at(&b, t0, HALF_HOUR);
    s.note_circuit_failure_at(&b, t0 + HALF_HOUR + Duration::from_secs(1), HALF_HOUR);
    assert_eq!(s.circuit_fails(&b), 2);
    s.note_circuit_success_at(&b, t0 + 2 * HALF_HOUR);
    assert_eq!(s.circuit_fails(&b), 0, "success clears circuit_fails");
}

#[test]
fn circuit_success_is_noop_for_unknown_bridge() {
    let mut s = empty();
    let b = bridge(OBFS4_A);
    let now = OffsetDateTime::from_unix_timestamp(2_500_000).unwrap();
    s.note_circuit_success_at(&b, now);
    assert_eq!(s.len(), 0, "no entry created from a success-only signal");
    assert_eq!(s.circuit_fails(&b), 0);
}

#[test]
fn last_circuit_observation_unknown_bridge_is_none() {
    let s = empty();
    let b = bridge(OBFS4_A);
    assert!(s.last_circuit_observation(&b).is_none());
}

#[test]
fn last_circuit_observation_reflects_last_touch() {
    let mut s = empty();
    let b = bridge(OBFS4_A);
    let t0 = OffsetDateTime::from_unix_timestamp(2_500_000).unwrap();
    assert!(s.note_circuit_failure_at(&b, t0, HALF_HOUR));
    assert_eq!(s.last_circuit_observation(&b), Some(t0));
    let t1 = t0 + HALF_HOUR + Duration::from_secs(1);
    assert!(s.note_circuit_failure_at(&b, t1, HALF_HOUR));
    assert_eq!(s.last_circuit_observation(&b), Some(t1));
    let t2 = t1 + HALF_HOUR;
    s.note_circuit_success_at(&b, t2);
    assert_eq!(
        s.last_circuit_observation(&b),
        Some(t2),
        "success resets also count as a touch"
    );
}

#[test]
fn note_probe_round_prunes_after_max_circuit_fails() {
    let mut s = empty();
    let b = bridge(OBFS4_A);
    let probed = vec![b.clone()];
    // TCP probe says alive — so `fails` stays 0 throughout.
    let alive = vec![(b.clone(), Duration::from_millis(50))];
    let mut now = OffsetDateTime::from_unix_timestamp(2_600_000).unwrap();

    // Drive circuit_fails up to (MAX_CIRCUIT_FAILS - 1).
    for _ in 0..(MAX_CIRCUIT_FAILS - 1) {
        s.note_circuit_failure_at(&b, now, HALF_HOUR);
        now += HALF_HOUR + Duration::from_secs(1);
    }
    // probe round with full health on TCP side, but circuit_fails close
    // to the threshold — still no prune yet.
    let pruned = s.note_probe_round(&probed, &alive, now, HOUR, MAX_FAILS, MAX_CIRCUIT_FAILS);
    assert!(pruned.is_empty());
    // ...but wait — note_probe_round resets `fails` and records success
    // on TCP. It does NOT touch circuit_fails (TCP and circuit layers are
    // independent). So circuit_fails is still MAX-1 here.
    assert_eq!(s.circuit_fails(&b), MAX_CIRCUIT_FAILS - 1);

    // One more circuit failure → reaches MAX_CIRCUIT_FAILS.
    s.note_circuit_failure_at(&b, now + HALF_HOUR + Duration::from_secs(1), HALF_HOUR);
    assert_eq!(s.circuit_fails(&b), MAX_CIRCUIT_FAILS);
    // Next probe round prunes despite TCP-healthy state.
    let pruned = s.note_probe_round(
        &probed,
        &alive,
        now + 2 * HOUR,
        HOUR,
        MAX_FAILS,
        MAX_CIRCUIT_FAILS,
    );
    assert_eq!(pruned.len(), 1, "TCP-alive bridge pruned on circuit_fails");
    assert_eq!(s.len(), 0);
}

#[test]
fn healthiest_bridges_ranks_by_ok_count_then_latency() {
    let mut s = empty();
    let a = bridge(OBFS4_A);
    let b = bridge(OBFS4_B);
    s.record(a.clone(), Duration::from_millis(10)); // ok_count 1
    s.record(b.clone(), Duration::from_millis(50));
    s.record(b.clone(), Duration::from_millis(20)); // ok_count 2, latest latency 20ms
    assert_eq!(
        s.healthiest_bridges(10),
        vec![b, a],
        "higher ok_count ranks first"
    );
}

#[test]
fn healthiest_bridges_excludes_unhealthy_and_never_probed_ok() {
    let mut s = empty();
    let a = bridge(OBFS4_A);
    let d = bridge(OBFS4_B);
    let t0 = OffsetDateTime::from_unix_timestamp(1_000_000).unwrap();
    s.record_at(a.clone(), Duration::from_millis(5), t0);
    s.note_failure_at(&d, t0, HOUR); // fails=1, ok_count=0 -- never proven reachable
    assert_eq!(s.healthiest_bridges(10), vec![a]);
}

#[test]
fn healthiest_bridges_excludes_a_retired_bridge_despite_perfect_probes() {
    // The case this guards: a retired bridge is retired precisely because it
    // answers. Its probe record stays spotless and its latency excellent, so
    // any filter that looks only at reachability re-promotes it forever.
    let mut s = empty();
    let good = bridge(OBFS4_A);
    let retired = bridge(OBFS4_B);
    let t0 = OffsetDateTime::from_unix_timestamp(1_000_000).unwrap();
    s.record_at(good.clone(), Duration::from_millis(50), t0);
    s.record_at(retired.clone(), Duration::from_millis(1), t0);
    s.note_permanent_failure_at(&retired, t0);

    assert!(s.is_retired(&retired));
    assert!(!s.is_retired(&good));
    // Retired one is faster, so ordering alone would put it first.
    assert_eq!(s.healthiest_bridges(10), vec![good]);
}

#[test]
fn transport_summary_separates_reachable_from_channel_proven() {
    let mut s = empty();
    let reachable_only = bridge(OBFS4_A);
    let proven = bridge(OBFS4_B);
    let t0 = OffsetDateTime::from_unix_timestamp(1_000_000).unwrap();
    s.record_at(reachable_only.clone(), Duration::from_millis(10), t0);
    s.record_at(proven.clone(), Duration::from_millis(10), t0);
    s.note_channel_success_at(&proven, t0);

    let summary = s.transport_summary();
    assert_eq!(summary.len(), 1);
    let obfs4 = &summary[0];
    assert_eq!(obfs4.transport, "obfs4");
    assert_eq!(obfs4.known, 2);
    // Both answer a probe; only one ever completed a channel. Collapsing
    // these two into one number is what made a dead pool look healthy.
    assert_eq!(obfs4.alive, 2);
    assert_eq!(obfs4.channel_proven, 1);
    assert_eq!(obfs4.retired, 0);
    assert_eq!(obfs4.last_channel_ok, Some(t0));
}

#[test]
fn transport_summary_counts_a_retired_bridge_as_neither_alive_nor_proven() {
    let mut s = empty();
    let retired = bridge(OBFS4_A);
    let t0 = OffsetDateTime::from_unix_timestamp(1_000_000).unwrap();
    s.record_at(retired.clone(), Duration::from_millis(1), t0);
    s.note_channel_success_at(&retired, t0);
    s.note_permanent_failure_at(&retired, t0);

    let summary = s.transport_summary();
    assert_eq!(summary[0].known, 1);
    assert_eq!(summary[0].retired, 1);
    assert_eq!(summary[0].alive, 0);
    assert_eq!(summary[0].channel_proven, 0);
}

#[test]
fn source_attribution_credits_every_collector_and_survives_a_round_trip() {
    let dir = tmp_dir();
    let path = dir.join("t.alive-bridges.log");
    let b = bridge(OBFS4_A);
    let t0 = OffsetDateTime::from_unix_timestamp(1_000_000).unwrap();

    let mut s = BridgeStore::load(path.clone()).unwrap();
    s.record_at(b.clone(), Duration::from_millis(10), t0);
    // Same line published by two collectors: crediting only the first would
    // make the second look barren for a bridge it genuinely supplies.
    s.note_source_at(&b, "delta", t0);
    s.note_source_at(&b, "onionhop", t0);
    s.save().unwrap();

    let reloaded = BridgeStore::load(path).unwrap();
    assert_eq!(reloaded.sources_of(&b), vec!["delta", "onionhop"]);
}

#[test]
fn source_summary_scores_by_yield_not_by_fetch_success() {
    let mut s = empty();
    let works = bridge(OBFS4_A);
    let dead = bridge(OBFS4_B);
    let t0 = OffsetDateTime::from_unix_timestamp(1_000_000).unwrap();

    // "stale" supplied only a bridge that never came up; "fresh" supplied
    // both. Both sources fetched fine -- the difference is what they yielded.
    s.note_source_at(&dead, "stale", t0);
    s.note_source_at(&dead, "fresh", t0);
    s.note_source_at(&works, "fresh", t0);
    s.record_at(works.clone(), Duration::from_millis(10), t0);
    s.note_failure_at(&dead, t0, HOUR);

    let by_label: std::collections::HashMap<_, _> = s
        .source_summary()
        .into_iter()
        .map(|st| (st.label.clone(), st))
        .collect();
    assert_eq!(by_label["stale"].offered, 1);
    assert_eq!(by_label["stale"].alive, 0);
    assert_eq!(by_label["fresh"].offered, 2);
    assert_eq!(by_label["fresh"].alive, 1);
    // With a sample floor of 1, only the barren one is barren.
    assert!(by_label["stale"].is_barren(1));
    assert!(!by_label["fresh"].is_barren(1));
    // A floor above the sample size withholds judgement.
    assert!(!by_label["stale"].is_barren(2));
}

#[test]
fn channel_proven_bridges_excludes_merely_reachable_ones() {
    let mut s = empty();
    let reachable = bridge(OBFS4_A);
    let proven = bridge(OBFS4_B);
    let t0 = OffsetDateTime::from_unix_timestamp(1_000_000).unwrap();
    s.record_at(reachable.clone(), Duration::from_millis(1), t0);
    s.record_at(proven.clone(), Duration::from_millis(900), t0);
    s.note_channel_success_at(&proven, t0);

    // The merely-reachable one is far faster, so any latency-led ranking
    // would prefer it. Sharing has to prefer proof instead.
    assert_eq!(s.channel_proven_bridges(10), vec![proven]);
}

#[test]
fn healthiest_bridges_respects_limit() {
    let mut s = empty();
    s.record(bridge(OBFS4_A), Duration::from_millis(10));
    s.record(bridge(OBFS4_B), Duration::from_millis(20));
    assert_eq!(s.healthiest_bridges(1).len(), 1);
    assert_eq!(s.healthiest_bridges(0).len(), 0);
}

/// Regression test for the bug behind a persistently thin warm pool on a real device: a
/// caller that wanted "the healthiest of my (small, single-transport) candidate set" was
/// getting the global top N intersected with that set, so a much larger transport's history
/// crowded the small one out before its own candidates were even considered.
#[test]
fn healthiest_among_ranks_within_the_candidate_set_not_globally() {
    let mut s = empty();
    let obfs4 = bridge(OBFS4_A);
    let webtunnel = bridge(
        "webtunnel [2001:db8::1]:443 0123456789ABCDEF0123456789ABCDEF01234567 \
         url=https://example.test/secret",
    );
    s.record(obfs4.clone(), Duration::from_millis(5));
    let now = OffsetDateTime::now_utc();
    s.note_channel_success_at(&obfs4, now);
    // Merely reachable, no channel history at all -- ranks far below the obfs4 entry
    // in any global comparison.
    s.record(webtunnel.clone(), Duration::from_millis(50));

    assert_eq!(
        s.healthiest_bridges(1),
        vec![obfs4],
        "sanity check: obfs4 does dominate the global ranking here"
    );
    assert_eq!(
        s.healthiest_among(std::slice::from_ref(&webtunnel), 1),
        vec![webtunnel],
        "restricted to a candidate set that excludes the obfs4 entry, the webtunnel \
         bridge must still come back rather than an empty result"
    );
}

#[test]
fn circuit_metadata_persists_across_save_load() {
    let dir = tmp_dir();
    let path = dir.join("c.log");
    let mut s = BridgeStore::load(path.clone()).unwrap();
    let b = bridge(OBFS4_A);
    let t0 = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
    // Make a TCP-healthy entry first so the bridge survives without
    // also crossing `fails` thresholds. Use `record_at` (not `record`)
    // so the entry's `last_circuit_observation` is in the same time
    // frame as the failures below — otherwise the rate-limit window
    // (last_circuit_observation = now_utc()) eats every bump that
    // happens "in the past" relative to wall time.
    s.record_at(b.clone(), Duration::from_millis(10), t0);
    s.note_circuit_failure_at(&b, t0 + HALF_HOUR + Duration::from_secs(1), HALF_HOUR);
    s.note_circuit_failure_at(&b, t0 + 2 * HALF_HOUR + Duration::from_secs(2), HALF_HOUR);
    assert_eq!(s.circuit_fails(&b), 2);
    s.save().unwrap();

    let loaded = BridgeStore::load(path).unwrap();
    assert_eq!(
        loaded.circuit_fails(&b),
        2,
        "cfails= persisted across save/load"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
