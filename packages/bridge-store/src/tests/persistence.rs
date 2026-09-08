use super::*;

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
#[test]
fn temp_path_is_unique_per_call() {
    let dir = tmp_dir();
    let path = dir.join("alive.log");
    let store = BridgeStore::load(path.clone()).unwrap();
    let t0 = store.temp_path(0);
    let t1 = store.temp_path(1);
    assert_ne!(t0, t1, "different seqs must yield different temp paths");
    let pid = std::process::id().to_string();
    for t in [&t0, &t1] {
        let name = t.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            name.contains(&pid),
            "temp file name {name} must embed the pid"
        );
        assert_eq!(t.parent(), Some(dir.as_path()), "sibling of the store file");
        assert!(
            name.starts_with(".alive.log."),
            "temp file name {name} must keep the dot + original name prefix"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
#[test]
fn concurrent_saves_do_not_share_a_temp_file() {
    let dir = tmp_dir();
    let path = dir.join("alive.log");
    let b = bridge(OBFS4_A);
    // Seed one entry so every thread can make its store dirty via
    // `note_channel_success_at`, which needs an existing entry.
    let mut seed = BridgeStore::load(path.clone()).unwrap();
    seed.record(b.clone(), Duration::from_millis(10));
    seed.save().unwrap();

    std::thread::scope(|scope| {
        for _ in 0..8 {
            let path = &path;
            let b = &b;
            scope.spawn(move || {
                let mut s = BridgeStore::load(path.clone()).unwrap();
                for _ in 0..10 {
                    s.note_channel_success_at(b, OffsetDateTime::now_utc());
                    s.save().expect("concurrent save must succeed");
                }
            });
        }
    });

    let loaded = BridgeStore::load(path).unwrap();
    // Cross-writer accumulation is deliberately NOT asserted here: with
    // whole-file atomic renames, concurrent read-modify-write writers are
    // last-writer-wins per snapshot. What must hold is that every save
    // succeeded above, the file still loads, the seeded probe record is
    // intact, and some channel successes landed. Additive application of
    // concurrent updates is the single-writer actor's contract (tested in
    // apps/socks5-proxy).
    assert_eq!(loaded.ok_count(&b), 1, "seeded probe record intact");
    assert!(
        loaded.channel_ok_count(&b) >= 2,
        "at least the last-finishing thread's channel successes landed"
    );
    // No leftover temp files.
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
        .collect();
    assert!(leftovers.is_empty(), "leftover temp files: {leftovers:?}");
    let _ = std::fs::remove_dir_all(&dir);
}
