use super::*;

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

    let due = s.needing_circuit_verification(now, HOUR, 10, |_| true);
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
    let first = store
        .needing_circuit_verification(now, HOUR, 1, |_| true)
        .remove(0);
    store.note_verification_attempt_at(&first, now);
    store.save().unwrap();
    let loaded = BridgeStore::load(path).unwrap();
    let next = loaded.needing_circuit_verification(now + HOUR, HOUR, 1, |_| true);
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
/// TS2-06 regression: the verification queue's order (never-attempted first
/// in store-key order among ties, attempted-but-unverified last) survives
/// the bounded-heap selection at limits 0, 1, k < N and k >= N.
#[test]
fn needing_circuit_verification_order_and_limits() {
    let mut s = empty();
    let t0 = OffsetDateTime::from_unix_timestamp(1_000_000).unwrap();
    let a = bridge(OBFS4_A); // map key order: A (1.2.3.4) before B (5.6.7.8)
    let b = bridge(OBFS4_B);
    let c = bridge(OBFS4_C);
    for bridge_ref in [&a, &b, &c] {
        s.record((*bridge_ref).clone(), Duration::from_millis(10));
        s.note_channel_success_at(bridge_ref, t0);
    }
    // An attempt is not a verification: `c` stays due, but sorts after the
    // never-attempted pair (Some(t0) after None under the due key).
    s.note_verification_attempt_at(&c, t0);

    let now = t0 + HOUR;
    assert_eq!(
        s.needing_circuit_verification(now, HOUR, 0, |_| true),
        Vec::<BridgeLine>::new()
    );
    assert_eq!(
        s.needing_circuit_verification(now, HOUR, 1, |_| true),
        vec![a.clone()],
        "k=1 takes the head of the same order"
    );
    assert_eq!(
        s.needing_circuit_verification(now, HOUR, 2, |_| true),
        vec![a.clone(), b.clone()]
    );
    assert_eq!(
        s.needing_circuit_verification(now, HOUR, 10, |_| true),
        vec![a, b, c],
        "k >= N: attempted-but-unverified still due, ranked last"
    );
}
/// TS3-10 regression: the pre-ranking `filter` restricts the candidate pool
/// BEFORE bounded selection. Ranking the whole due pool down to `limit` first
/// and only then filtering (the old caller-side shape) lets unrelated
/// higher-ranked entries fill the batch and starve the subset entirely.
#[test]
fn needing_circuit_verification_filters_before_bounded_selection() {
    let mut s = empty();
    let t0 = OffsetDateTime::from_unix_timestamp(1_000_000).unwrap();
    let mk = |ip: &str| {
        bridge(&format!(
            "obfs4 {ip}:443 1111111111111111111111111111111111111111 cert=VVV iat-mode=0"
        ))
    };
    // Five channel-proven, never-attempted bridges first: `None` due keys,
    // and earlier store positions rank first among ties.
    let inactive: Vec<BridgeLine> = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"]
        .iter()
        .map(|ip| mk(ip))
        .collect();
    // Two active bridges, attempted at t0: `Some(t0)` due keys rank strictly
    // after all five inactives under the due ordering.
    let active: Vec<BridgeLine> = ["10.0.0.6", "10.0.0.7"].iter().map(|ip| mk(ip)).collect();
    for b in inactive.iter().chain(active.iter()) {
        s.record(b.clone(), Duration::from_millis(10));
        s.note_channel_success_at(b, t0);
    }
    for b in &active {
        s.note_verification_attempt_at(b, t0);
    }

    let now = t0 + HOUR;
    // Top-3 overall would be all inactive; the filter must run first so the
    // actives survive bounded selection.
    let due = s.needing_circuit_verification(now, HOUR, 3, |b| active.iter().any(|a| a == b));
    assert_eq!(due, active, "actives must not be starved out of the batch");
    assert_eq!(
        s.needing_circuit_verification(now, HOUR, 1, |b| active.iter().any(|a| a == b)),
        vec![active[0].clone()],
        "limit 1 takes the first active in store-key order"
    );
}
/// TS3-10: limit 0 must not even walk the candidate set. The old
/// caller-side `.collect()` materialized every due entry before `take_best`
/// even at limit 0; the Cell-captured counter proves the whole chain is
/// skipped.
#[test]
fn needing_circuit_verification_zero_limit_never_walks_the_candidates() {
    let mut s = empty();
    let t0 = OffsetDateTime::from_unix_timestamp(1_000_000).unwrap();
    let a = bridge(OBFS4_A);
    let b = bridge(OBFS4_B);
    for bridge_ref in [&a, &b] {
        s.record((*bridge_ref).clone(), Duration::from_millis(10));
        s.note_channel_success_at(bridge_ref, t0);
    }
    let calls = std::cell::Cell::new(0usize);
    let due = s.needing_circuit_verification(t0 + HOUR, HOUR, 0, |_b| {
        calls.set(calls.get() + 1);
        true
    });
    assert!(due.is_empty());
    assert_eq!(calls.get(), 0, "filter must never run at limit 0");
}
