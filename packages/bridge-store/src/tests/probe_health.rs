use super::*;

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
fn dedup_key_includes_obfs4_certificate() {
    let mut s = empty();
    s.record(bridge(OBFS4_A), Duration::from_millis(100));
    s.record(bridge(OBFS4_A_NEW_PARAMS), Duration::from_millis(50));
    assert_eq!(s.len(), 2, "rotated certificate is a distinct endpoint");
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
