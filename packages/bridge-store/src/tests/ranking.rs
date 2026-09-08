use super::*;

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
fn alive_count_requires_probe_proof_and_excludes_retired_or_failed() {
    let mut s = empty();
    let fresh = bridge(OBFS4_A);
    let good = bridge(OBFS4_B);
    let t0 = OffsetDateTime::from_unix_timestamp(1_000_000).unwrap();

    // 1. Source-attributed entry, never probed: `fails == 0` alone must not
    //    count as alive.
    s.note_source_at(&fresh, "source", t0);
    assert_eq!(s.alive_count(), 0, "unprobed source entry is not alive");

    // 2. A successful probe proves the bridge alive.
    s.record_at(fresh.clone(), Duration::from_millis(5), t0);
    assert_eq!(s.alive_count(), 1, "probed bridge counts as alive");

    // 3a. Retirement despite a spotless probe record removes it.
    s.note_permanent_failure_at(&fresh, t0);
    assert_eq!(
        s.alive_count(),
        0,
        "retired bridge with perfect TCP record is not alive"
    );

    // 3b. A failed probe after success un-proves reachability. `t0 + HOUR`
    //     passes the failure rate-limit window, so `fails` becomes 1.
    s.record_at(good.clone(), Duration::from_millis(5), t0);
    assert_eq!(s.alive_count(), 1);
    s.note_failure_at(&good, t0 + HOUR, HOUR);
    assert_eq!(
        s.alive_count(),
        0,
        "bridge with a failure since its last success is not alive"
    );
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
/// TS2-05 regression: the one-lookup snapshot must report exactly what the
/// per-field getters report, for every degree of entry completeness, and
/// `None` for an untracked bridge where the getters fall back to zero/None.
#[test]
fn health_snapshot_matches_the_individual_getters() {
    let mut s = empty();
    let t0 = OffsetDateTime::from_unix_timestamp(1_000_000).unwrap();

    // Fully populated: probes, channel warm-up, verification, circuit failure.
    let full = bridge(OBFS4_A);
    s.record_at(full.clone(), Duration::from_millis(7), t0);
    s.record_at(full.clone(), Duration::from_millis(11), t0 + HOUR);
    s.note_channel_success_at(&full, t0 + HOUR);
    s.note_circuit_verified_at(&full, t0 + HOUR);
    s.note_circuit_failure_at(&full, t0 + 2 * HOUR, HOUR);

    // Partial: probed only.
    let probed_only = bridge(OBFS4_B);
    s.record_at(probed_only.clone(), Duration::from_millis(3), t0);

    // Bare: source-attributed, never probed.
    let bare = bridge(
        "webtunnel [2001:db8::1]:443 0123456789ABCDEF0123456789ABCDEF01234567 \
         url=https://example.test/secret",
    );
    s.note_source_at(&bare, "test", t0);

    for b in [&full, &probed_only, &bare] {
        let snap = s.health_snapshot(b).expect("entry is tracked");
        assert_eq!(snap.tcp_fails, s.tcp_fails(b), "tcp_fails mismatch");
        assert_eq!(
            snap.circuit_fails,
            s.circuit_fails(b),
            "circuit_fails mismatch"
        );
        assert_eq!(
            snap.verified_count,
            s.verified_count(b),
            "verified_count mismatch"
        );
        assert_eq!(snap.ok_count, s.ok_count(b), "ok_count mismatch");
        assert_eq!(
            snap.last_circuit_observation,
            s.last_circuit_observation(b),
            "last_circuit_observation mismatch"
        );
    }

    // The fully populated entry really did produce non-trivial values, so
    // the per-field comparisons above are not vacuous zero == zero checks.
    let snap = s.health_snapshot(&full).unwrap();
    assert_eq!(snap.ok_count, 2);
    assert_eq!(snap.verified_count, 1);
    assert_eq!(snap.circuit_fails, 1);
    assert_eq!(snap.tcp_fails, 0);
    assert_eq!(snap.last_circuit_observation, Some(t0 + 2 * HOUR));

    // Untracked bridge: the snapshot is None while the getters each report
    // their zero/None fallback -- both shapes agree on "nothing recorded".
    let unknown = bridge(OBFS4_C);
    assert!(s.health_snapshot(&unknown).is_none());
    assert_eq!(s.tcp_fails(&unknown), 0);
    assert_eq!(s.circuit_fails(&unknown), 0);
    assert_eq!(s.verified_count(&unknown), 0);
    assert_eq!(s.ok_count(&unknown), 0);
    assert_eq!(s.last_circuit_observation(&unknown), None);
}
/// TS2-06 regression: entries tied under the ranking keep the store's key
/// order -- the order the previous stable sort gave them -- at every limit.
#[test]
fn healthiest_bridges_keeps_map_order_for_equal_scores() {
    let mut s = empty();
    // Identical ranking fields (same ok_count, latency, no channel or
    // verification history); map keys order by address: A < B < C.
    for line in [OBFS4_A, OBFS4_B, OBFS4_C] {
        s.record(bridge(line), Duration::from_millis(10));
    }
    let a = bridge(OBFS4_A);
    let b = bridge(OBFS4_B);
    let c = bridge(OBFS4_C);

    assert_eq!(s.healthiest_bridges(0), Vec::<BridgeLine>::new());
    assert_eq!(
        s.healthiest_bridges(1),
        vec![a.clone()],
        "k=1 takes the head"
    );
    assert_eq!(s.healthiest_bridges(2), vec![a.clone(), b.clone()]);
    assert_eq!(
        s.healthiest_bridges(3),
        vec![a.clone(), b.clone(), c.clone()],
        "k == N"
    );
    assert_eq!(
        s.healthiest_bridges(50),
        vec![a, b, c],
        "k >= N returns everything"
    );
}
/// TS2-06 regression: at every limit (0, 1, mid-boundary, N, k >= N) the
/// selected prefix is the same the old full stable sort produced: the
/// ranking tiers (verified > channel-proven > merely reachable) in full,
/// ties inside a tier in store-key order, never-probed entries excluded.
#[test]
fn healthiest_bridges_top_k_matches_full_ranking_at_every_limit() {
    let mut s = empty();
    let t0 = OffsetDateTime::from_unix_timestamp(1_000_000).unwrap();

    let v1 = bridge(OBFS4_A);
    s.record_at(v1.clone(), Duration::from_millis(10), t0);
    s.note_circuit_verified_at(&v1, t0 + 2 * HOUR); // verified most recently -> first
    let v2 = bridge(OBFS4_B);
    s.record_at(v2.clone(), Duration::from_millis(10), t0);
    s.note_circuit_verified_at(&v2, t0 + HOUR);
    // Channel-proven pair, fully tied: map key order is 2.2.2.2 then 9.9.9.9.
    let c1 =
        bridge("obfs4 2.2.2.2:443 3333333333333333333333333333333333333333 cert=CCC iat-mode=0");
    let c2 = bridge(OBFS4_C);
    for b in [&c1, &c2] {
        s.record_at((*b).clone(), Duration::from_millis(10), t0);
        s.note_channel_success_at(b, t0);
    }
    // Merely reachable, no channel history.
    let r1 =
        bridge("obfs4 3.3.3.3:443 4444444444444444444444444444444444444444 cert=DDD iat-mode=0");
    s.record_at(r1.clone(), Duration::from_millis(10), t0);
    // Never probed: excluded from the ranking entirely.
    let unproven =
        bridge("obfs4 4.4.4.4:443 5555555555555555555555555555555555555555 cert=EEE iat-mode=0");
    s.note_source_at(&unproven, "test", t0);

    assert_eq!(s.healthiest_bridges(0), Vec::<BridgeLine>::new());
    assert_eq!(s.healthiest_bridges(1), vec![v1.clone()]);
    assert_eq!(s.healthiest_bridges(2), vec![v1.clone(), v2.clone()]);
    assert_eq!(
        s.healthiest_bridges(3),
        vec![v1.clone(), v2.clone(), c1.clone()],
        "the tie inside the channel-proven tier resolves by store key order"
    );
    assert_eq!(
        s.healthiest_bridges(4),
        vec![v1.clone(), v2.clone(), c1.clone(), c2.clone()]
    );
    let expected = vec![v1, v2, c1, c2, r1];
    assert_eq!(s.healthiest_bridges(5), expected, "k == N");
    assert_eq!(s.healthiest_bridges(50), expected, "k >= N");
}
