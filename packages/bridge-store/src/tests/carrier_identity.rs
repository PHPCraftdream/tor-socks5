use super::*;

// Two webtunnel carriers behind one relay: same transport, addr, and
// fingerprint, different `url=` (hence different carrier identity).
const WEBTUNNEL_OLD: &str =
    "webtunnel 9.9.9.9:443 1111111111111111111111111111111111111111 url=https://e.com/old ver=0.0.3";
const WEBTUNNEL_NEW: &str =
    "webtunnel 9.9.9.9:443 1111111111111111111111111111111111111111 url=https://e.com/new ver=0.0.3";

const CERT_OLD: &str = "EREREREREREREREREREREREREREiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIg";
const CERT_NEW: &str = "EREREREREREREREREREREREREREzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMw";

fn obfs4_rotation(cert: &str) -> BridgeLine {
    bridge(&format!(
        "obfs4 9.9.9.9:443 1111111111111111111111111111111111111111 cert={cert} iat-mode=0"
    ))
}

#[test]
fn channel_success_on_one_carrier_does_not_prove_the_other() {
    let mut s = empty();
    let old = bridge(WEBTUNNEL_OLD);
    let new = bridge(WEBTUNNEL_NEW);
    let t0 = OffsetDateTime::from_unix_timestamp(1_000_000).unwrap();
    s.record_at(old.clone(), Duration::from_millis(50), t0);
    s.record_at(new.clone(), Duration::from_millis(50), t0);
    s.note_channel_success_at(&old, t0);
    assert_eq!(s.len(), 2, "distinct carriers must be distinct entries");
    assert_eq!(s.channel_ok_count(&old), 1);
    assert_eq!(
        s.channel_ok_count(&new),
        0,
        "/old's channel warm-up must not credit /new"
    );
}

#[test]
fn retiring_one_carrier_does_not_retire_the_other() {
    let mut s = empty();
    let old = bridge(WEBTUNNEL_OLD);
    let new = bridge(WEBTUNNEL_NEW);
    let t0 = OffsetDateTime::from_unix_timestamp(2_000_000).unwrap();
    s.record_at(old.clone(), Duration::from_millis(50), t0);
    s.record_at(new.clone(), Duration::from_millis(50), t0);
    s.note_permanent_failure_at(&old, t0);
    assert_eq!(s.len(), 2, "distinct carriers must be distinct entries");
    assert!(s.is_retired(&old));
    assert!(!s.is_retired(&new), "retiring /old must not retire /new");
}

#[test]
fn one_probe_round_keeps_split_outcomes_separate() {
    let mut s = empty();
    let old = bridge(WEBTUNNEL_OLD);
    let new = bridge(WEBTUNNEL_NEW);
    let now = OffsetDateTime::from_unix_timestamp(3_000_000).unwrap();
    let probed = vec![old.clone(), new.clone()];
    let alive = vec![(old.clone(), Duration::from_millis(50))];
    let pruned = s.note_probe_round(&probed, &alive, now, HOUR, MAX_FAILS, u32::MAX);
    assert!(pruned.is_empty());
    assert_eq!(s.fails_of(&old), 0, "alive stays healthy");
    assert!(
        s.fails_of(&new) > 0,
        "/new's failure must count even though /old answered the same round"
    );
}

#[test]
fn carrier_separation_survives_save_load() {
    let dir = tmp_dir();
    let path = dir.join("carriers.log");
    let mut s = BridgeStore::load(path.clone()).unwrap();
    let old = bridge(WEBTUNNEL_OLD);
    let new = bridge(WEBTUNNEL_NEW);
    let t0 = OffsetDateTime::from_unix_timestamp(4_000_000).unwrap();

    // Both carriers answered the same round; only /old then warmed a
    // channel, and only /new later failed. /old is retired last, after the
    // final probe round — prune would remove a retired entry.
    let alive = vec![
        (old.clone(), Duration::from_millis(50)),
        (new.clone(), Duration::from_millis(50)),
    ];
    s.note_probe_round(
        &[old.clone(), new.clone()],
        &alive,
        t0,
        HOUR,
        MAX_FAILS,
        u32::MAX,
    );
    s.note_channel_success_at(&old, t0);
    s.note_probe_round(
        std::slice::from_ref(&new),
        &[],
        t0 + 2 * HOUR,
        HOUR,
        MAX_FAILS,
        u32::MAX,
    );
    s.note_permanent_failure_at(&old, t0 + 2 * HOUR);
    s.save().unwrap();

    let loaded = BridgeStore::load(path).unwrap();
    assert_eq!(
        loaded.len(),
        2,
        "both carriers must survive as separate entries"
    );
    assert_eq!(
        loaded.channel_ok_count(&old),
        1,
        "/old's channel proof persists under its own carrier key"
    );
    assert!(loaded.is_retired(&old), "/old's retirement persists");
    assert_eq!(loaded.fails_of(&new), 1, "/new's own failure persists");
    assert_eq!(
        loaded.channel_ok_count(&new),
        0,
        "/new stays channel-unproven after reload"
    );
    assert!(!loaded.is_retired(&new), "/new is not retired after reload");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn obfs4_rotation_separates_source_health_and_persistence() {
    let dir = tmp_dir();
    let path = dir.join("obfs4-rotation.log");
    let mut s = BridgeStore::load(path.clone()).unwrap();
    let old = obfs4_rotation(CERT_OLD);
    let fresh = obfs4_rotation(CERT_NEW);
    let t0 = OffsetDateTime::from_unix_timestamp(5_000_000).unwrap();

    s.record_at(old.clone(), Duration::from_millis(50), t0);
    s.note_source_at(&old, "old-source", t0);
    s.note_channel_success_at(&old, t0);
    s.note_circuit_verified_at(&old, t0);
    s.note_failure_at(&old, t0 + HOUR, HOUR);

    // The fresh source creates a second row even though addr and fingerprint
    // are unchanged; it must not inherit the old row's state.
    s.note_source_at(&fresh, "fresh-source", t0 + HOUR);
    assert_eq!(s.len(), 2);
    assert_eq!(s.channel_ok_count(&fresh), 0);
    assert_eq!(s.verified_count(&fresh), 0);
    assert_eq!(s.fails_of(&fresh), 0);

    let fresh_summary = s
        .source_summary()
        .into_iter()
        .find(|summary| summary.label == "fresh-source")
        .expect("fresh source row");
    assert_eq!(fresh_summary.offered, 1);
    assert_eq!(fresh_summary.alive, 0);
    assert_eq!(fresh_summary.channel_proven, 0);

    // A TCP success and channel warm-up prove only the fresh certificate.
    s.record_at(fresh.clone(), Duration::from_millis(40), t0 + 2 * HOUR);
    s.note_channel_success_at(&fresh, t0 + 2 * HOUR);
    assert_eq!(s.channel_ok_count(&fresh), 1);
    assert_eq!(s.verified_count(&fresh), 0);
    assert_eq!(s.fails_of(&fresh), 0);
    assert_eq!(s.channel_ok_count(&old), 1);
    assert_eq!(s.verified_count(&old), 1);
    assert_eq!(s.fails_of(&old), 1);

    s.note_permanent_failure_at(&old, t0 + 3 * HOUR);
    assert!(s.is_retired(&old));
    assert!(!s.is_retired(&fresh));
    assert_eq!(
        s.channel_proven_bridges(10),
        vec![fresh.clone()],
        "retiring old certificate must not remove fresh channel proof"
    );

    s.save().unwrap();
    let loaded = BridgeStore::load(path).unwrap();
    assert_eq!(loaded.len(), 2);
    assert_eq!(loaded.channel_ok_count(&old), 1);
    assert_eq!(loaded.verified_count(&old), 1);
    assert_eq!(loaded.fails_of(&old), 1);
    assert!(loaded.is_retired(&old));
    assert_eq!(loaded.channel_ok_count(&fresh), 1);
    assert_eq!(loaded.verified_count(&fresh), 0);
    assert_eq!(loaded.fails_of(&fresh), 0);
    assert!(!loaded.is_retired(&fresh));
    let _ = std::fs::remove_dir_all(&dir);
}
