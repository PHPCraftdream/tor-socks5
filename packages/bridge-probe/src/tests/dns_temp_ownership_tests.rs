use crate::dns::*;
use std::sync::atomic::{AtomicU64, Ordering};

static TEST_SEQ: AtomicU64 = AtomicU64::new(0);

fn unique_dir(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "{label}-{}-{}",
        std::process::id(),
        TEST_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A temp file whose advisory lock is still held by a live owner must survive
/// a `load_persisted_dns_cache` cleanup sweep, and be removed afterwards once
/// the owner is gone (TS17-01).
#[tokio::test]
async fn load_spares_persist_temp_of_live_owner() {
    let _dns_serial = super::DNS_GLOBAL_TEST_LOCK.lock().await;
    let dir = unique_dir("dns-temp-live-owner");
    let path = dir.join("dns-cache.txt");
    std::fs::write(&path, "").unwrap();

    // Exercises the writer's own creation path: exact canonical temp name plus
    // the advisory lock that models a live writer. The cross-process aspect of
    // the lock discipline is proven by persist-lock's own
    // cross_process_ownership test.
    let guard = persist_lock::TempFileGuard::create(&path, 42).unwrap();
    load_persisted_dns_cache(&path);
    assert!(
        guard.temp_path().exists(),
        "a live writer's temp file must not be swept by load"
    );

    drop(guard);
    load_persisted_dns_cache(&path);
    assert!(
        !persist_lock::temp_path_for(&path, 42).unwrap().exists(),
        "a dead owner's temp file must be swept by a later load"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// TS17-04 regression: crash leftovers -- both the canonical persist-lock
/// temp shape (derived from THE shared generator, not hardcoded) and the
/// legacy no-leading-dot `{file}.{pid}.{gen}.tmp` shape -- must all be swept
/// by `load_persisted_dns_cache`.
#[tokio::test]
async fn load_cleans_dead_owner_temp_created_by_the_real_generator() {
    let _dns_serial = super::DNS_GLOBAL_TEST_LOCK.lock().await;
    let dir = unique_dir("dns-temp-dead-owner");
    let path = dir.join("dns-cache.txt");
    std::fs::write(&path, "").unwrap();

    let canonical = persist_lock::temp_path_for(&path, 7).unwrap();
    std::fs::write(&canonical, b"partial").unwrap();
    let legacy_small_pid = dir.join("dns-cache.txt.1.42.tmp");
    std::fs::write(&legacy_small_pid, b"partial").unwrap();
    let legacy_max_pid = dir.join("dns-cache.txt.4294967295.42.tmp");
    std::fs::write(&legacy_max_pid, b"partial").unwrap();

    load_persisted_dns_cache(&path);

    for leftover in [&canonical, &legacy_small_pid, &legacy_max_pid] {
        assert!(
            !leftover.exists(),
            "dead-owner crash leftover must be swept, found: {}",
            leftover.display()
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// The cleanup must be conservative: names that do not EXACTLY match a known
/// temp shape -- canonical or legacy -- are never touched (TS17-01).
#[tokio::test]
async fn load_never_touches_malformed_persist_temp_names() {
    let _dns_serial = super::DNS_GLOBAL_TEST_LOCK.lock().await;
    let dir = unique_dir("dns-temp-malformed");
    let path = dir.join("dns-cache.txt");
    std::fs::write(&path, "").unwrap();

    let malformed = [
        ".dns-cache.txt.notapid.42.tmp",
        ".dns-cache.txt.99999999999.42.tmp",
        "dns-cache.txt.notapid.42.tmp",
        ".dns-cache.txt.1.tmp",
    ];
    for name in malformed {
        std::fs::write(dir.join(name), b"keep me").unwrap();
    }

    load_persisted_dns_cache(&path);

    for name in malformed {
        assert!(
            dir.join(name).exists(),
            "malformed temp name must never be deleted: {name}"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}
