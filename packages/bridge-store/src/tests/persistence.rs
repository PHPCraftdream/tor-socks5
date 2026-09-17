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
fn load_removes_own_stale_temp_files() {
    let dir = tmp_dir();
    let path = dir.join("alive.log");
    let stale = dir.join(".alive.log.1.42.tmp");
    std::fs::write(&stale, "partial").unwrap();
    BridgeStore::load(path).expect("load");
    assert!(!stale.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cached_identity_keeps_carrier_distinctions_across_save_load() {
    let dir = tmp_dir();
    let path = dir.join("carrier-cache.log");
    let first = bridge(
        "webtunnel 192.0.2.10:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 url=https://a.example/tor ver=0.0.3",
    );
    let second = bridge(
        "webtunnel 192.0.2.10:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 url=https://b.example/tor ver=0.0.3",
    );
    let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();

    let mut store = BridgeStore::load(path.clone()).unwrap();
    store.record_at(first.clone(), Duration::from_millis(20), now);
    store.record_at(second.clone(), Duration::from_millis(30), now);
    assert_eq!(store.len(), 2, "carrier endpoints remain distinct keys");
    assert_eq!(store.ok_count(&first), 1);
    assert_eq!(store.ok_count(&second), 1);

    store.save().unwrap();
    let loaded = BridgeStore::load(path).unwrap();
    assert_eq!(loaded.len(), 2, "both canonical identities survive reload");
    assert_eq!(loaded.ok_count(&first), 1);
    assert_eq!(loaded.ok_count(&second), 1);
    assert_eq!(loaded.health_snapshot(&first).unwrap().ok_count, 1);
    assert_eq!(loaded.health_snapshot(&second).unwrap().ok_count, 1);
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
fn source_labels_round_trip_through_save_load() {
    let dir = tmp_dir();
    let path = dir.join("src.log");
    let mut s = BridgeStore::load(path.clone()).unwrap();
    let b = bridge(OBFS4_A);
    let t0 = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
    s.record_at(b.clone(), Duration::from_millis(10), t0);
    let labels = [
        "Tor Project",
        "A,B",
        "раздача 5, зеркало №2",
        "line1\nline2",
        "cr\r\nlf",
        "tab\there",
        "feed cfails=42",
        "100%",
    ];
    for (i, label) in labels.iter().enumerate() {
        s.note_source_at(&b, label, t0 + Duration::from_secs(i as u64));
    }
    s.save().unwrap();

    let loaded = BridgeStore::load(path).unwrap();
    let mut expected: Vec<String> = labels.iter().map(|s| s.to_string()).collect();
    expected.sort();
    assert_eq!(
        loaded.sources_of(&b),
        expected,
        "labels must survive save/load byte-identical"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
#[test]
fn source_label_cannot_forge_health_metadata() {
    let dir = tmp_dir();
    let path = dir.join("forge.log");
    let mut s = BridgeStore::load(path.clone()).unwrap();
    let b = bridge(OBFS4_A);
    let t0 = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
    s.record_at(b.clone(), Duration::from_millis(10), t0);
    // Rate-limited to one bump per window, so space the bumps just past
    // HALF_HOUR apart (see circuit_metadata test).
    for i in 0..7 {
        s.note_circuit_failure_at(
            &b,
            t0 + (i as u32 + 1) * HALF_HOUR + Duration::from_secs(i as u64 + 1),
            HALF_HOUR,
        );
    }
    assert_eq!(s.circuit_fails(&b), 7);
    s.note_source_at(&b, "feed cfails=42", t0);
    s.save().unwrap();

    let loaded = BridgeStore::load(path).unwrap();
    assert_eq!(
        loaded.circuit_fails(&b),
        7,
        "label must not overwrite cfails"
    );
    assert_eq!(loaded.sources_of(&b), vec!["feed cfails=42".to_string()]);
    assert_eq!(loaded.ok_count(&b), 1);
    assert_eq!(loaded.fails_of(&b), 0);
    let _ = std::fs::remove_dir_all(&dir);
}
#[test]
fn legacy_plain_sources_round_trip_unescaped() {
    let dir = tmp_dir();
    let path = dir.join("legacy-src.log");
    std::fs::write(
        &path,
        format!(
            "# fails=1 seen=3 attempt=2026-05-18T12:00:00Z ok=2026-05-18T12:00:00Z \
             latency=42ms chseen=0 chok=- evseen=0 evok=- cfails=2 \
             cobs=2026-05-18T12:00:00Z src=delta,onionhop\n{OBFS4_A}\n"
        ),
    )
    .unwrap();
    let loaded = BridgeStore::load(path.clone()).unwrap();
    assert_eq!(
        loaded.sources_of(&bridge(OBFS4_A)),
        vec!["delta".to_string(), "onionhop".to_string()]
    );
    loaded.save().unwrap();
    let reloaded = BridgeStore::load(path).unwrap();
    assert_eq!(
        reloaded.sources_of(&bridge(OBFS4_A)),
        vec!["delta".to_string(), "onionhop".to_string()],
        "plain legacy labels must survive the new writer unchanged"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
#[test]
fn legacy_literal_percent_loads_without_panicking() {
    let dir = tmp_dir();
    let path = dir.join("legacy-pct.log");
    std::fs::write(
        &path,
        format!(
            "# fails=0 seen=1 attempt=2026-05-18T12:00:00Z ok=2026-05-18T12:00:00Z \
             latency=10ms chseen=0 chok=- evseen=0 evok=- cfails=0 \
             cobs=2026-05-18T12:00:00Z src=100%,c2\n{OBFS4_A}\n"
        ),
    )
    .unwrap();
    let loaded = BridgeStore::load(path.clone()).unwrap();
    assert_eq!(
        loaded.sources_of(&bridge(OBFS4_A)),
        vec!["100%".to_string(), "c2".to_string()],
        "trailing lone % must be kept literally"
    );
    loaded.save().unwrap();
    let reloaded = BridgeStore::load(path).unwrap();
    assert_eq!(
        reloaded.sources_of(&bridge(OBFS4_A)),
        vec!["100%".to_string(), "c2".to_string()],
        "labels must stay stable after re-encode/decode"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
#[test]
fn legacy_unmarked_percent_sequences_are_never_decoded() {
    // TS7-07: `src=` (the old, unmarked field) must be read byte-for-byte
    // literal -- a `%HH` sequence in an old file is old data, not an
    // escape. Before the fix, `decode_source` ran unconditionally and
    // silently rewrote these into a comma, a space, a bare `%`, and a
    // UTF-8 replacement character respectively.
    let dir = tmp_dir();
    let path = dir.join("legacy-ambiguous.log");
    std::fs::write(
        &path,
        format!(
            "# fails=0 seen=1 attempt=2026-05-18T12:00:00Z ok=2026-05-18T12:00:00Z \
             latency=10ms chseen=0 chok=- evseen=0 evok=- cfails=0 \
             cobs=2026-05-18T12:00:00Z src=feed%2Cbackup,feed%20one,%25,%FF\n{OBFS4_A}\n"
        ),
    )
    .unwrap();
    let loaded = BridgeStore::load(path).unwrap();
    let mut got = loaded.sources_of(&bridge(OBFS4_A));
    got.sort();
    let mut expected = vec![
        "%25".to_string(),
        "%FF".to_string(),
        "feed%20one".to_string(),
        "feed%2Cbackup".to_string(),
    ];
    expected.sort();
    assert_eq!(
        got, expected,
        "every %HH sequence in an old unmarked src= file must survive \
         literally, not be percent-decoded"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
#[test]
fn marked_format_round_trips_delimiters_and_unicode() {
    // TS7-07: the NEW, marked (`srcenc=`) format must still correctly
    // restore every delimiter character and Unicode content -- only the
    // OLD unmarked `src=` field skips decoding.
    let dir = tmp_dir();
    let path = dir.join("marked.log");
    let mut s = BridgeStore::load(path.clone()).unwrap();
    let b = bridge(OBFS4_A);
    let t0 = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
    s.record_at(b.clone(), Duration::from_millis(10), t0);
    let labels = ["feed,backup", "feed one", "100%", "раздача №2"];
    for (i, label) in labels.iter().enumerate() {
        s.note_source_at(&b, label, t0 + Duration::from_secs(i as u64));
    }
    s.save().unwrap();

    let raw = std::fs::read_to_string(&path).unwrap();
    assert!(
        raw.contains("srcenc="),
        "the writer must emit the marked field name, not the legacy src="
    );
    assert!(
        !raw.contains(" src="),
        "the writer must never emit the unmarked legacy field"
    );

    let loaded = BridgeStore::load(path).unwrap();
    let mut expected: Vec<String> = labels.iter().map(|s| s.to_string()).collect();
    expected.sort();
    assert_eq!(
        loaded.sources_of(&b),
        expected,
        "comma, space, percent and Unicode must all round-trip through srcenc="
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
