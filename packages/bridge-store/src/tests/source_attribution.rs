use super::*;

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
