use crate::dns::*;
use crate::*;
use std::sync::atomic::{AtomicU64, Ordering};

/// Process-local counter making every temp directory name unique even when
/// two tests start within the same `now_unix()` SECOND: the suite runs
/// tests in parallel, and two same-second directories would collide.
fn unique_dir_suffix() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

#[tokio::test]
async fn save_preserves_an_unexpired_disk_fallback_entry() {
    let _dns_serial = super::DNS_GLOBAL_STORE_LOCK.lock().await;
    let host = "save-keeps-disk.test.invalid";
    let ip: IpAddr = "203.0.113.70".parse().unwrap();
    let stamp = now_unix() - 3600;
    {
        let mut store = disk_fallback_store().lock().unwrap();
        store.insert(
            host.to_owned(),
            PersistedAnswer {
                addrs: vec![ip],
                resolved_at_unix: stamp,
            },
        );
    }
    let dir = std::env::temp_dir().join(format!(
        "save-keeps-disk-{}-{}-{}",
        host,
        now_unix(),
        unique_dir_suffix()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("dns-cache.txt");
    save_persisted_dns_cache(&path)
        .await
        .expect("save must succeed");
    let file_text = std::fs::read_to_string(&path).unwrap();
    assert!(
        file_text.contains(&stamp.to_string()),
        "saved file must carry the ORIGINAL stamp, got: {file_text}"
    );

    // Simulate the next cold start: wipe this test's own key (not the
    // whole store -- it's process-wide and shared by other tests running
    // concurrently, so a blanket `clear()` here would race their inserts),
    // then reload.
    disk_fallback_store().lock().unwrap().remove(host);
    forget_dns_answer(host);
    load_persisted_dns_cache(&path);

    assert_eq!(disk_fallback_answer(host), Some(vec![ip]));
    let reloaded_stamp = {
        let store = disk_fallback_store().lock().unwrap();
        let entry = store.get(host).expect("host must survive save/wipe/load");
        entry.resolved_at_unix
    };
    assert_eq!(
        reloaded_stamp, stamp,
        "save must not refresh the persisted stamp"
    );

    let _ = std::fs::remove_dir_all(&dir);
    disk_fallback_store().lock().unwrap().remove(host);
}

#[tokio::test]
async fn save_drops_a_genuinely_expired_disk_fallback_entry() {
    let _dns_serial = super::DNS_GLOBAL_STORE_LOCK.lock().await;
    let host = "save-drops-expired.test.invalid";
    let ip: IpAddr = "203.0.113.71".parse().unwrap();
    {
        let mut store = disk_fallback_store().lock().unwrap();
        store.insert(
            host.to_owned(),
            PersistedAnswer {
                addrs: vec![ip],
                resolved_at_unix: now_unix() - DNS_STALE_FALLBACK_WINDOW.as_secs() - 1,
            },
        );
    }
    let dir = std::env::temp_dir().join(format!(
        "save-drops-expired-{}-{}-{}",
        host,
        now_unix(),
        unique_dir_suffix()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("dns-cache.txt");
    save_persisted_dns_cache(&path)
        .await
        .expect("save must succeed");
    let file_text = std::fs::read_to_string(&path).unwrap();
    assert!(
        !file_text.contains(host),
        "expired entry must not be written, got: {file_text}"
    );

    // Wipe only this test's own key: the store is process-wide and shared
    // by other tests running concurrently, so a blanket `clear()` here
    // would race their inserts.
    disk_fallback_store().lock().unwrap().remove(host);
    load_persisted_dns_cache(&path);

    assert_eq!(disk_fallback_answer(host), None);
    assert!(!disk_fallback_store().lock().unwrap().contains_key(host));

    let _ = std::fs::remove_dir_all(&dir);
    disk_fallback_store().lock().unwrap().remove(host);
}

#[tokio::test]
async fn save_prefers_the_live_answer_for_a_host() {
    let _dns_serial = super::DNS_GLOBAL_STORE_LOCK.lock().await;
    let host = "save-live-wins.test.invalid";
    let live_ip: IpAddr = "203.0.113.72".parse().unwrap();
    let disk_ip: IpAddr = "203.0.113.73".parse().unwrap();
    remember_doh_answer(host, &[live_ip], Duration::from_secs(300));
    {
        let mut store = disk_fallback_store().lock().unwrap();
        store.insert(
            host.to_owned(),
            PersistedAnswer {
                addrs: vec![disk_ip],
                resolved_at_unix: now_unix() - 3600,
            },
        );
    }
    let dir = std::env::temp_dir().join(format!(
        "save-live-wins-{}-{}-{}",
        host,
        now_unix(),
        unique_dir_suffix()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("dns-cache.txt");
    save_persisted_dns_cache(&path)
        .await
        .expect("save must succeed");
    let file_text = std::fs::read_to_string(&path).unwrap();
    assert!(
        file_text.contains(&live_ip.to_string()),
        "live answer must be written, got: {file_text}"
    );
    assert!(
        !file_text.contains(&disk_ip.to_string()),
        "persisted answer must be superseded, got: {file_text}"
    );

    forget_dns_answer(host);
    // Wipe only this test's own key: the store is process-wide and shared
    // by other tests running concurrently, so a blanket `clear()` here
    // would race their inserts.
    disk_fallback_store().lock().unwrap().remove(host);
    load_persisted_dns_cache(&path);

    assert_eq!(disk_fallback_answer(host), Some(vec![live_ip]));

    let _ = std::fs::remove_dir_all(&dir);
    disk_fallback_store().lock().unwrap().remove(host);
}

#[tokio::test]
async fn save_keeps_the_fallback_when_the_live_cache_only_remembers_a_failure() {
    let _dns_serial = super::DNS_GLOBAL_STORE_LOCK.lock().await;
    let host = "save-failure-keeps-disk.test.invalid";
    let ip: IpAddr = "203.0.113.74".parse().unwrap();
    remember_doh_failure(host);
    {
        let mut store = disk_fallback_store().lock().unwrap();
        store.insert(
            host.to_owned(),
            PersistedAnswer {
                addrs: vec![ip],
                resolved_at_unix: now_unix() - 3600,
            },
        );
    }
    let dir = std::env::temp_dir().join(format!(
        "save-failure-keeps-disk-{}-{}-{}",
        host,
        now_unix(),
        unique_dir_suffix()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("dns-cache.txt");
    save_persisted_dns_cache(&path)
        .await
        .expect("save must succeed");
    let file_text = std::fs::read_to_string(&path).unwrap();
    assert!(
        file_text.contains(&ip.to_string()),
        "a remembered failure must not displace the persisted fallback, got: {file_text}"
    );

    forget_dns_answer(host);
    // Wipe only this test's own key: the store is process-wide and shared
    // by other tests running concurrently, so a blanket `clear()` here
    // would race their inserts.
    disk_fallback_store().lock().unwrap().remove(host);
    load_persisted_dns_cache(&path);

    assert_eq!(disk_fallback_answer(host), Some(vec![ip]));

    let _ = std::fs::remove_dir_all(&dir);
    disk_fallback_store().lock().unwrap().remove(host);
}

/// TS5-04 regression: a resident live answer that expired beyond the
/// stale-fallback window must not be exported by a periodic save. Under the
/// old filter (`!addrs.is_empty()` only) it was written with
/// `resolved_at_unix = now`, so the next cold start accepted a day-stale
/// address as freshly resolved.
#[tokio::test]
async fn save_drops_a_resident_live_answer_past_the_stale_window() {
    let _dns_serial = super::DNS_GLOBAL_STORE_LOCK.lock().await;
    let host = "save-drops-stale-live.test.invalid";
    let ip: IpAddr = "203.0.113.80".parse().unwrap();
    // Straight into the map with an expiry past the stale-fallback window --
    // `remember_doh_answer` clamps TTLs, so it cannot express this. The
    // stamp is consistent with that expiry: the answer was resolved even
    // earlier than it expired.
    store_cached(
        host,
        CachedAnswer {
            addrs: vec![ip],
            expires_at: Instant::now() - DNS_STALE_FALLBACK_WINDOW - Duration::from_secs(1),
            resolved_at_unix: now_unix() - DNS_STALE_FALLBACK_WINDOW.as_secs() - 61,
            generation: 0,
            version: 0,
        },
    );
    let dir = std::env::temp_dir().join(format!(
        "save-drops-stale-live-{}-{}-{}",
        host,
        now_unix(),
        unique_dir_suffix()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("dns-cache.txt");
    save_persisted_dns_cache(&path)
        .await
        .expect("save must succeed");
    let file_text = std::fs::read_to_string(&path).unwrap();
    assert!(
        !file_text.contains(host),
        "a resident answer past the stale-fallback window must not be \
         persisted as freshly resolved, got: {file_text}"
    );

    forget_dns_answer(host);
    let _ = std::fs::remove_dir_all(&dir);
}

/// TS5-04 regression, priority half: the same unusable live answer must not
/// win the save's live-over-disk priority check either -- a valid, fresh
/// disk entry for the same host survives with its ORIGINAL stamp instead of
/// being dropped in favour of a day-stale resident answer.
#[tokio::test]
async fn save_keeps_a_valid_disk_answer_when_the_live_answer_is_past_the_stale_window() {
    let _dns_serial = super::DNS_GLOBAL_STORE_LOCK.lock().await;
    let host = "save-disk-beats-stale-live.test.invalid";
    let stale_live_ip: IpAddr = "203.0.113.81".parse().unwrap();
    let disk_ip: IpAddr = "203.0.113.82".parse().unwrap();
    let disk_stamp = now_unix() - 3600;
    store_cached(
        host,
        CachedAnswer {
            addrs: vec![stale_live_ip],
            expires_at: Instant::now() - DNS_STALE_FALLBACK_WINDOW - Duration::from_secs(1),
            resolved_at_unix: now_unix() - DNS_STALE_FALLBACK_WINDOW.as_secs() - 61,
            generation: 0,
            version: 0,
        },
    );
    {
        let mut store = disk_fallback_store().lock().unwrap();
        store.insert(
            host.to_owned(),
            PersistedAnswer {
                addrs: vec![disk_ip],
                resolved_at_unix: disk_stamp,
            },
        );
    }
    let dir = std::env::temp_dir().join(format!(
        "save-disk-beats-stale-live-{}-{}-{}",
        host,
        now_unix(),
        unique_dir_suffix()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("dns-cache.txt");
    save_persisted_dns_cache(&path)
        .await
        .expect("save must succeed");
    let file_text = std::fs::read_to_string(&path).unwrap();
    assert!(
        !file_text.contains(&stale_live_ip.to_string()),
        "the unusable live answer must not be persisted, got: {file_text}"
    );
    assert!(
        file_text.contains(&disk_ip.to_string()),
        "the valid disk answer must survive the stale live one, got: {file_text}"
    );
    assert!(
        file_text.contains(&disk_stamp.to_string()),
        "the disk answer must keep its ORIGINAL stamp, got: {file_text}"
    );

    // Simulate the next cold start: wipe only this test's own keys (the
    // stores are process-wide and shared by other tests running
    // concurrently), then reload.
    forget_dns_answer(host);
    disk_fallback_store().lock().unwrap().remove(host);
    load_persisted_dns_cache(&path);

    assert_eq!(disk_fallback_answer(host), Some(vec![disk_ip]));

    let _ = std::fs::remove_dir_all(&dir);
    disk_fallback_store().lock().unwrap().remove(host);
}

/// A blocked save must leave the executor and cache available.
#[tokio::test]
async fn save_persisted_dns_cache_does_not_block_the_async_worker() {
    let _dns_serial = super::DNS_GLOBAL_STORE_LOCK.lock().await;
    let host = "save-off-worker.test.invalid";
    let ip: IpAddr = "203.0.113.83".parse().unwrap();
    remember_doh_answer(host, &[ip], Duration::from_secs(300));

    let dir = std::env::temp_dir().join(format!(
        "save-off-worker-{}-{}-{}",
        host,
        now_unix(),
        unique_dir_suffix()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("dns-cache.txt");

    let executor_thread = std::thread::current().id();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let save = {
        let path = path.clone();
        tokio::spawn(async move {
            save_persisted_dns_cache_with_writer(&path, move |path, contents| {
                assert_ne!(std::thread::current().id(), executor_thread);
                let _ = entered_tx.send(());
                release_rx
                    .recv_timeout(Duration::from_secs(10))
                    .map_err(std::io::Error::other)?;
                std::fs::write(path, contents)
            })
            .await
        })
    };

    tokio::time::timeout(Duration::from_secs(10), entered_rx)
        .await
        .expect("save reaches its blocking phase")
        .expect("writer signals entry");
    let lookup = tokio::spawn(async move { cached_doh_answer(host) });
    let hit = tokio::time::timeout(Duration::from_secs(10), lookup)
        .await
        .expect("cache lookup progresses during save")
        .expect("lookup task joins");
    assert!(matches!(hit, Some(CacheHit::Addrs(addrs)) if addrs == vec![ip]));
    assert!(!save.is_finished(), "writer still awaits release");
    release_tx.send(()).expect("release this writer");
    tokio::time::timeout(Duration::from_secs(10), save)
        .await
        .expect("released save completes")
        .expect("save task joins")
        .expect("save succeeds");

    // Semantics unchanged: the held save still landed everything it should.
    let file_text = std::fs::read_to_string(&path).unwrap();
    assert!(
        file_text.contains(host),
        "the saved file must contain the host, got: {file_text}"
    );

    forget_dns_answer(host);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A save whose job is still mid-flight when a newer save completes must
/// skip publication entirely: the newer snapshot stays on disk, nothing is
/// interleaved, and no temp file is left behind.
#[tokio::test]
async fn superseded_save_must_not_publish_stale_snapshot() {
    // Holds the whole body: the dropped host must not be re-seeded into the
    // process-global disk fallback store by a parallel test's save/load
    // while it is still live here (`forget_dns_answer` forgets only the
    // live cache, and every save merges the WHOLE store into the file).
    let _dns_serial = super::DNS_GLOBAL_STORE_LOCK.lock().await;
    let host_b = "superseded-b.test.invalid";
    let host_extra = "superseded-extra.test.invalid";
    let ip1: IpAddr = "203.0.113.91".parse().unwrap();
    let extra_ip: IpAddr = "203.0.113.92".parse().unwrap();
    let ip2: IpAddr = "203.0.113.93".parse().unwrap();

    // A's snapshot: long (two entries), seeded with an older stamp.
    remember_doh_answer(host_b, &[ip1], Duration::from_secs(3000));
    remember_doh_answer(host_extra, &[extra_ip], Duration::from_secs(3000));

    let dir = std::env::temp_dir().join(format!(
        "superseded-save-{}-{}-{}",
        std::process::id(),
        now_unix(),
        unique_dir_suffix()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("dns-cache.txt");

    // Save A: held mid-write by the writer until we release it.
    let executor_thread = std::thread::current().id();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let save_a = {
        let path = path.clone();
        tokio::spawn(async move {
            save_persisted_dns_cache_with_writer(&path, move |path, contents| {
                assert_ne!(std::thread::current().id(), executor_thread);
                let _ = entered_tx.send(());
                release_rx
                    .recv_timeout(Duration::from_secs(10))
                    .map_err(std::io::Error::other)?;
                std::fs::write(path, contents)?;
                Ok(())
            })
            .await
        })
    };
    tokio::time::timeout(Duration::from_secs(10), entered_rx)
        .await
        .expect("save A reaches its blocking phase")
        .expect("writer A signals entry");

    // Now the state changes under A: B's snapshot is short and different.
    forget_dns_answer(host_extra);
    remember_doh_answer(host_b, &[ip2], Duration::from_secs(3000));
    save_persisted_dns_cache(&path)
        .await
        .expect("save B must succeed");

    // Release A: it must detect it was superseded and skip publication.
    release_tx.send(()).expect("release writer A");
    let result_a = tokio::time::timeout(Duration::from_secs(10), save_a)
        .await
        .expect("released save A completes")
        .expect("save A task joins");
    assert!(
        result_a.is_ok(),
        "a superseded save skips publication and returns Ok, got: {result_a:?}"
    );

    let file_text = std::fs::read_to_string(&path).unwrap();
    assert!(
        file_text.contains(&format!("{host_b}	{ip2}")),
        "the newer snapshot must be published, got: {file_text}"
    );
    assert!(
        !file_text.contains(&ip1.to_string()),
        "the stale IP must not survive, got: {file_text}"
    );
    assert!(
        // Exact-line match: a substring check would false-positive on
        // another test's host whose name merely contains ours (tests run
        // in parallel and share the process-global stores).
        !file_text
            .lines()
            .any(|line| line.starts_with(&format!("{host_extra}	"))),
        "the dropped host must not survive, got: {file_text}"
    );
    // Other tests running in parallel share the process-wide disk fallback
    // store, so foreign hosts may legitimately appear in the snapshot; every
    // line for OUR hosts must parse (no mixture/tail residue).
    let our_hosts = [host_b, host_extra];
    for line in file_text.lines() {
        let foreign = !our_hosts.iter().any(|host| line.starts_with(host));
        assert!(
            foreign || parse_persisted_line(line).is_some(),
            "every own line must parse, got: {line}"
        );
    }
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "tmp"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "superseded saves must remove their temp files, found: {leftovers:?}"
    );

    forget_dns_answer(host_b);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Snapshot capture and generation allocation must happen in ONE
/// per-path critical section: a second capture started while the first
/// one's data is still live must block behind the snapshot gate, and its
/// generation must strictly order after the first (TS7-01).
#[test]
fn snapshot_capture_and_generation_allocation_are_serialized_per_path() {
    // Sync test: no ambient runtime, so acquire the async lock through a
    // throwaway one. Same serialization duty as in the async tests above.
    let _dns_serial = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("test runtime builds")
        .block_on(super::DNS_GLOBAL_STORE_LOCK.lock());
    let host = "ts701-gate.test.invalid";
    let ip1: IpAddr = "203.0.113.101".parse().unwrap();
    let ip2: IpAddr = "203.0.113.102".parse().unwrap();

    remember_doh_answer(host, &[ip1], Duration::from_secs(300));

    let dir = std::env::temp_dir().join(format!(
        "ts701-gate-{}-{}-{}",
        std::process::id(),
        now_unix(),
        unique_dir_suffix()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("dns-cache.txt");

    let (live1, _disk1, gen1) = capture_persist_snapshots_with_generation(&path);
    assert!(
        live1.iter().any(|s| s.host == host && s.addrs == vec![ip1]),
        "first capture must see ip1, got: {live1:?}"
    );

    // Hold the capture gate while mutating the store: the second capture
    // must not be able to snapshot under the gate.
    let state = persist_path_generation_slot(&path);
    let gate = state.lock_snapshot_gate();
    remember_doh_answer(host, &[ip2], Duration::from_secs(300));

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = capture_persist_snapshots_with_generation(&path);
        tx.send(result).expect("send captured snapshot");
    });
    assert!(
        rx.recv_timeout(Duration::from_millis(150)).is_err(),
        "a concurrent capture must block behind the snapshot gate"
    );

    drop(gate);
    let (live2, _disk2, gen2) = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("capture completes after the gate is released");
    assert!(
        live2.iter().any(|s| s.host == host && s.addrs == vec![ip2]),
        "the gated capture must see the mutated data, got: {live2:?}"
    );
    assert!(
        !live2
            .iter()
            .any(|s| s.host == host && s.addrs.contains(&ip1)),
        "the gated capture must not see the pre-gate data, got: {live2:?}"
    );
    assert!(
        gen2 > gen1,
        "the later capture must get a strictly greater generation, got {gen2} vs {gen1}"
    );

    forget_dns_answer(host);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A save whose snapshot was captured EARLIER but which publishes LATER
/// (after a full newer save has landed) must not roll the file back to
/// its older data: its lower generation loses against the already
/// published newer one (TS7-01 end-to-end).
#[tokio::test]
async fn older_snapshot_paused_behind_full_newer_publish_keeps_newer_state() {
    let _dns_serial = super::DNS_GLOBAL_STORE_LOCK.lock().await;
    let host = "ts701-superseded.test.invalid";
    let host_extra = "ts701-superseded-extra.test.invalid";
    let ip1: IpAddr = "203.0.113.103".parse().unwrap();
    let ip2: IpAddr = "203.0.113.104".parse().unwrap();
    let extra_ip: IpAddr = "203.0.113.108".parse().unwrap();

    remember_doh_answer(host, &[ip1], Duration::from_secs(3000));
    remember_doh_answer(host_extra, &[extra_ip], Duration::from_secs(3000));

    let dir = std::env::temp_dir().join(format!(
        "ts701-superseded-{}-{}",
        std::process::id(),
        now_unix()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("dns-cache.txt");

    // Save A: captured first, held mid-write until released.
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let save_a = {
        let path = path.clone();
        tokio::spawn(async move {
            save_persisted_dns_cache_with_writer(&path, move |path, contents| {
                let _ = entered_tx.send(());
                release_rx
                    .recv_timeout(Duration::from_secs(10))
                    .map_err(std::io::Error::other)?;
                std::fs::write(path, contents)?;
                Ok(())
            })
            .await
        })
    };
    tokio::time::timeout(Duration::from_secs(10), entered_rx)
        .await
        .expect("save A reaches its blocking phase")
        .expect("writer A signals entry");

    // Mutate, then let B capture a fresher snapshot and publish fully.
    forget_dns_answer(host_extra);
    remember_doh_answer(host, &[ip2], Duration::from_secs(3000));
    save_persisted_dns_cache(&path)
        .await
        .expect("save B must succeed");

    // Release A: its older generation must lose the publication race.
    release_tx.send(()).expect("release writer A");
    let result_a = tokio::time::timeout(Duration::from_secs(10), save_a)
        .await
        .expect("released save A completes")
        .expect("save A task joins");
    assert!(
        result_a.is_ok(),
        "a superseded save skips publication and returns Ok, got: {result_a:?}"
    );

    let file_text = std::fs::read_to_string(&path).unwrap();
    assert!(
        file_text.contains(&format!("{host}\t{ip2}")),
        "the newer snapshot must stay on disk, got: {file_text}"
    );
    assert!(
        !file_text.contains(&ip1.to_string()),
        "A's stale IP must not roll the file back, got: {file_text}"
    );
    assert!(
        // Exact-line match: a substring check would false-positive on
        // another test's host whose name merely contains ours (tests run
        // in parallel and share the process-global stores).
        !file_text
            .lines()
            .any(|line| line.starts_with(&format!("{host_extra}	"))),
        "the dropped host must not survive, got: {file_text}"
    );
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "tmp"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "superseded saves must remove their temp files, found: {leftovers:?}"
    );

    forget_dns_answer(host);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A NEWER save that fails at the temp write must not veto an older
/// in-flight save's publication: the older save must publish its own data
/// and return Ok, so Ok never means "nothing is on disk" (TS7-02).
#[tokio::test]
async fn failed_newer_write_lets_older_save_publish_and_report_ok() {
    let _dns_serial = super::DNS_GLOBAL_STORE_LOCK.lock().await;
    let host = "ts702-write-fail.test.invalid";
    let ip1: IpAddr = "203.0.113.105".parse().unwrap();
    let ip2: IpAddr = "203.0.113.106".parse().unwrap();

    remember_doh_answer(host, &[ip1], Duration::from_secs(300));

    let dir = std::env::temp_dir().join(format!(
        "ts702-write-fail-{}-{}-{}",
        std::process::id(),
        now_unix(),
        unique_dir_suffix()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("dns-cache.txt");

    // Save A: captured first, held mid-write until released.
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let save_a = {
        let path = path.clone();
        tokio::spawn(async move {
            save_persisted_dns_cache_with_writer(&path, move |path, contents| {
                let _ = entered_tx.send(());
                release_rx
                    .recv_timeout(Duration::from_secs(10))
                    .map_err(std::io::Error::other)?;
                std::fs::write(path, contents)
            })
            .await
        })
    };
    tokio::time::timeout(Duration::from_secs(10), entered_rx)
        .await
        .expect("save A reaches its blocking phase")
        .expect("writer A signals entry");

    // Mutate, then run a NEWER save whose write fails.
    remember_doh_answer(host, &[ip2], Duration::from_secs(300));
    let result_b = save_persisted_dns_cache_with_writer(&path, |_path, _contents| {
        Err(std::io::Error::other("injected write failure"))
    })
    .await;
    assert!(result_b.is_err(), "save B's write failure must surface");

    // Nothing published yet -- which must NOT stop A from publishing.
    assert!(!path.exists(), "no file may be published before A runs");

    release_tx.send(()).expect("release writer A");
    let result_a = tokio::time::timeout(Duration::from_secs(10), save_a)
        .await
        .expect("released save A completes")
        .expect("save A task joins");
    assert!(
        result_a.is_ok(),
        "the older save must publish despite B's failure, got: {result_a:?}"
    );
    let file_text = std::fs::read_to_string(&path).unwrap();
    assert!(
        file_text.contains(&format!("{host}\t{ip1}")),
        "A's data must reach the disk, got: {file_text}"
    );
    assert!(
        !file_text.contains(&ip2.to_string()),
        "B's mutated data must not appear (its write failed), got: {file_text}"
    );
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "tmp"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "failed writes must remove their temp files, found: {leftovers:?}"
    );

    forget_dns_answer(host);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A NEWER save that fails at the RENAME must not make an older save
/// return a FALSE Ok: with nothing ever published, the older save must
/// attempt publication and surface its own rename failure as Err (TS7-02).
#[tokio::test]
async fn failed_newer_rename_makes_older_save_err_not_false_ok() {
    let _dns_serial = super::DNS_GLOBAL_STORE_LOCK.lock().await;
    let host = "ts702-rename-fail.test.invalid";
    let ip1: IpAddr = "203.0.113.107".parse().unwrap();
    let ip2: IpAddr = "203.0.113.109".parse().unwrap();

    remember_doh_answer(host, &[ip1], Duration::from_secs(300));

    let dir = std::env::temp_dir().join(format!(
        "ts702-rename-fail-{}-{}-{}",
        std::process::id(),
        now_unix(),
        unique_dir_suffix()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    // The FINAL path is itself a directory: temp writes succeed, but every
    // rename onto the final path fails (MoveFileEx on Windows, EISDIR on
    // Unix).
    let path = dir.join("dns-cache.txt");
    std::fs::create_dir_all(&path).unwrap();

    // Save A: captured first, held mid-write until released.
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let save_a = {
        let path = path.clone();
        tokio::spawn(async move {
            save_persisted_dns_cache_with_writer(&path, move |path, contents| {
                let _ = entered_tx.send(());
                release_rx
                    .recv_timeout(Duration::from_secs(10))
                    .map_err(std::io::Error::other)?;
                std::fs::write(path, contents)
            })
            .await
        })
    };
    tokio::time::timeout(Duration::from_secs(10), entered_rx)
        .await
        .expect("save A reaches its blocking phase")
        .expect("writer A signals entry");

    // Mutate, then run a NEWER save whose rename fails.
    remember_doh_answer(host, &[ip2], Duration::from_secs(300));
    let result_b = save_persisted_dns_cache(&path).await;
    assert!(result_b.is_err(), "save B's rename failure must surface");

    // Nothing was ever published, so A is strictly newer than anything on
    // disk: it must attempt publication, and its rename must fail too.
    release_tx.send(()).expect("release writer A");
    let result_a = tokio::time::timeout(Duration::from_secs(10), save_a)
        .await
        .expect("released save A completes")
        .expect("save A task joins");
    assert!(
        result_a.is_err(),
        "A must surface its rename failure, not a false Ok, got: {result_a:?}"
    );
    assert!(
        path.is_dir(),
        "no regular file may have been published over the directory"
    );
    // TS7-08: a failed rename must clean up its own temp file, for A and
    // B alike.
    let leftover_tmp = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
        .count();
    assert_eq!(
        leftover_tmp, 0,
        "a failed rename must not leave its temp file behind"
    );

    forget_dns_answer(host);
    let _ = std::fs::remove_dir_all(&dir);
}

/// TS7-08: repeated rename failures must not leak one temp file per
/// attempt -- the cleanup guard disarms only after a successful rename,
/// so every failed attempt removes its own temp file. Once the
/// destination obstruction is cleared, the next attempt must succeed
/// normally and the original rename error must have been the one
/// surfaced by every failed attempt in between.
#[tokio::test]
async fn repeated_rename_failures_leave_no_orphaned_temp_files() {
    let _dns_serial = super::DNS_GLOBAL_STORE_LOCK.lock().await;
    let host = "ts708-rename-leak.test.invalid";
    let ip: IpAddr = "203.0.113.201".parse().unwrap();
    remember_doh_answer(host, &[ip], Duration::from_secs(300));

    let dir = std::env::temp_dir().join(format!(
        "ts708-rename-leak-{}-{}-{}",
        std::process::id(),
        now_unix(),
        unique_dir_suffix()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("dns-cache.txt");
    // The FINAL path is itself a directory: every rename onto it fails
    // (MoveFileEx on Windows, EISDIR on Unix), while the temp write next
    // to it still succeeds.
    std::fs::create_dir_all(&path).unwrap();

    let count_tmp_files = || -> usize {
        std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .count()
    };

    for attempt in 0..3 {
        let result = save_persisted_dns_cache(&path).await;
        assert!(
            result.is_err(),
            "attempt {attempt}: rename onto a directory must fail"
        );
        assert_eq!(
            count_tmp_files(),
            0,
            "attempt {attempt}: a failed rename must not leave its temp file behind"
        );
    }

    // Clear the obstruction: the destination is no longer a directory.
    std::fs::remove_dir(&path).unwrap();
    let result = save_persisted_dns_cache(&path).await;
    assert!(
        result.is_ok(),
        "once unblocked, the next attempt must succeed: {result:?}"
    );
    assert!(path.is_file(), "the destination must now be a regular file");
    assert_eq!(
        count_tmp_files(),
        0,
        "a successful publish leaves no temp file behind either"
    );

    forget_dns_answer(host);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A cancelled caller cannot stop its already-dispatched blocking job; the
/// generation check must keep that detached job from clobbering the newer
/// snapshot a subsequent save published.
#[tokio::test]
async fn cancelled_caller_leaves_latest_snapshot_intact() {
    let _dns_serial = super::DNS_GLOBAL_STORE_LOCK.lock().await;
    let host_b = "cancel-b.test.invalid";
    let host_extra = "cancel-extra.test.invalid";
    let ip1: IpAddr = "203.0.113.94".parse().unwrap();
    let extra_ip: IpAddr = "203.0.113.95".parse().unwrap();
    let ip2: IpAddr = "203.0.113.96".parse().unwrap();

    remember_doh_answer(host_b, &[ip1], Duration::from_secs(3000));
    remember_doh_answer(host_extra, &[extra_ip], Duration::from_secs(3000));

    let dir = std::env::temp_dir().join(format!(
        "cancelled-save-{}-{}-{}",
        std::process::id(),
        now_unix(),
        unique_dir_suffix()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("dns-cache.txt");

    // Save A: held mid-write, and its caller is aborted while it waits.
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (written_tx, written_rx) = tokio::sync::oneshot::channel();
    let save_a = {
        let path = path.clone();
        tokio::spawn(async move {
            save_persisted_dns_cache_with_writer(&path, move |path, contents| {
                let _ = entered_tx.send(());
                release_rx
                    .recv_timeout(Duration::from_secs(10))
                    .map_err(std::io::Error::other)?;
                std::fs::write(path, contents)?;
                let _ = written_tx.send(());
                Ok(())
            })
            .await
        })
    };
    tokio::time::timeout(Duration::from_secs(10), entered_rx)
        .await
        .expect("save A reaches its blocking phase")
        .expect("writer A signals entry");
    save_a.abort(); // caller future cancelled while job A runs detached

    // B wins the race and publishes the fresh, short snapshot.
    forget_dns_answer(host_extra);
    remember_doh_answer(host_b, &[ip2], Duration::from_secs(3000));
    save_persisted_dns_cache(&path)
        .await
        .expect("save B must succeed");

    // Release A: its job still finishes the temp write (the point of the
    // test), then must skip publication.
    release_tx.send(()).expect("release writer A");
    tokio::time::timeout(Duration::from_secs(10), written_rx)
        .await
        .expect("detached job A resumes after release")
        .expect("writer A signals the temp write");

    let file_text = std::fs::read_to_string(&path).unwrap();
    // Other tests running in parallel share the process-wide disk fallback
    // store, so foreign hosts may legitimately appear; OUR host must appear
    // exactly once, fully parsed, with nothing stale alongside it.
    for line in file_text.lines() {
        assert!(
            !line.starts_with(host_b) || parse_persisted_line(line).is_some(),
            "every own line must parse, got: {line}"
        );
    }
    assert_eq!(
        file_text
            .lines()
            .filter(|line| line.starts_with(host_b))
            .count(),
        1,
        "exactly B's snapshot line must survive for the host, got: {file_text}"
    );
    assert!(
        file_text.contains(&format!("{host_b}	{ip2}")),
        "the newer snapshot must be published, got: {file_text}"
    );
    assert!(
        !file_text.contains(&ip1.to_string()) && !file_text.contains(host_extra),
        "the stale snapshot must not survive, got: {file_text}"
    );
    forget_dns_answer(host_b);
    forget_dns_answer(host_extra);
    let _ = std::fs::remove_dir_all(&dir);
}
