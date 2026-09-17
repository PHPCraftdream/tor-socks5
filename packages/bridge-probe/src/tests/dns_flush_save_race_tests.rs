//! TS17-03 regressions: `flush_dns_cache`'s live→fallback transition
//! (clear the live cache, then merge the preserved answers into the disk
//! fallback store) must be indivisible relative to a persist snapshot.

use crate::dns::*;
use crate::dns_publish_pause::*;
use crate::*;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static TEST_SEQ: AtomicU64 = AtomicU64::new(0);

/// TS17-03. Invariant under test: a save that STARTS while
/// `flush_dns_cache` is inside its live→fallback transition -- live
/// already cleared, preserved answers not yet merged into the fallback
/// store -- must observe either the pre-flush or the post-flush state,
/// never two empty stores. Publishing the empty state would also burn a
/// fresh save generation, and by the TS7-01/02 generation protocol that
/// empty publication would veto every older non-empty save, leaving the
/// disk without a single persisted answer until the next save.
#[tokio::test]
async fn save_started_inside_flush_transition_never_publishes_an_empty_file() {
    let _dns_serial = super::DNS_GLOBAL_TEST_LOCK.lock().await;
    let host = "ts1703-window-save.test.invalid";
    let ip: IpAddr = "203.0.113.210".parse().unwrap();
    forget_dns_answer(host);
    disk_fallback_store().lock().unwrap().remove(host);
    disarm_flush_merge_pause();
    disarm_capture_pause();
    remember_doh_answer(host, &[ip], Duration::from_secs(3000));

    let dir = std::env::temp_dir().join(format!(
        "ts1703-window-save-{}-{}",
        std::process::id(),
        TEST_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("dns-cache.txt");

    // Park flush AFTER the live clear, BEFORE the fallback merge.
    let gate = arm_flush_merge_pause();
    let (flush_tx, flush_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        flush_dns_cache();
        let _ = flush_tx.send(());
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !flush_merge_pause_parked() {
        assert!(
            std::time::Instant::now() < deadline,
            "flush must reach the live→fallback window"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // The window is open: both stores are empty for this host right now.
    assert!(
        cached_doh_answer(host).is_none(),
        "window precondition: the live cache is already cleared"
    );
    assert!(
        disk_fallback_answer(host).is_none(),
        "window precondition: the fallback merge has not run yet"
    );

    // A save started INSIDE the window must block behind the transition
    // gate instead of capturing the empty state. It runs on its own thread
    // + throwaway runtime: its capture parks on the flush gate, which must
    // never block this test's executor.
    let (save_tx, save_rx) = std::sync::mpsc::channel();
    let save_thread_path = path.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("save runtime builds");
        let result = rt.block_on(save_persisted_dns_cache(&save_thread_path));
        let _ = save_tx.send(result);
    });
    assert!(
        save_rx.recv_timeout(Duration::from_millis(150)).is_err(),
        "a save started in the window must wait for the transition to finish"
    );

    // Let flush finish its merge; the save must then proceed and publish
    // the merged fallback -- not an empty file.
    gate.release();
    let flush_ok =
        tokio::task::spawn_blocking(move || flush_rx.recv_timeout(Duration::from_secs(10)).is_ok());
    assert!(
        tokio::time::timeout(Duration::from_secs(10), flush_ok)
            .await
            .expect("flush must finish after the gate is released")
            .expect("flush watcher joins"),
        "flush completed its fallback merge"
    );
    let save_result = save_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("save completes after the transition");
    assert!(save_result.is_ok(), "save succeeds: {save_result:?}");

    let file_text = std::fs::read_to_string(&path).unwrap();
    assert!(
        file_text.contains(&format!("{host}\t{ip}")),
        "the published file must not be empty and must carry the preserved answer, got: {file_text:?}"
    );
    assert_eq!(
        disk_fallback_answer(host),
        Some(vec![ip]),
        "flush's merge must have landed in the fallback store"
    );

    disarm_flush_merge_pause();
    forget_dns_answer(host);
    disk_fallback_store().lock().unwrap().remove(host);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The ordinary sequential order -- flush, then save, as the watchdog runs
/// them -- must keep publishing the preserved answer unchanged.
#[tokio::test]
async fn sequential_flush_then_save_still_persists_the_preserved_answer() {
    let _dns_serial = super::DNS_GLOBAL_TEST_LOCK.lock().await;
    let host = "ts1703-sequential.test.invalid";
    let ip: IpAddr = "203.0.113.211".parse().unwrap();
    forget_dns_answer(host);
    disk_fallback_store().lock().unwrap().remove(host);
    disarm_flush_merge_pause();
    disarm_capture_pause();
    remember_doh_answer(host, &[ip], Duration::from_secs(3000));

    let dir = std::env::temp_dir().join(format!(
        "ts1703-sequential-{}-{}",
        std::process::id(),
        TEST_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("dns-cache.txt");

    flush_dns_cache();
    assert!(
        cached_doh_answer(host).is_none(),
        "flush must clear the live cache"
    );
    assert_eq!(
        disk_fallback_answer(host),
        Some(vec![ip]),
        "flush must preserve the usable answer in the fallback store"
    );
    save_persisted_dns_cache(&path)
        .await
        .expect("sequential save must succeed");
    let file_text = std::fs::read_to_string(&path).unwrap();
    assert!(
        file_text.contains(&format!("{host}\t{ip}")),
        "the sequential save must publish the preserved answer, got: {file_text:?}"
    );

    // Cold-start round trip still works.
    disk_fallback_store().lock().unwrap().remove(host);
    load_persisted_dns_cache(&path);
    assert_eq!(disk_fallback_answer(host), Some(vec![ip]));

    forget_dns_answer(host);
    disk_fallback_store().lock().unwrap().remove(host);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Reverse order: a save parked INSIDE its capture section (holding the
/// per-path `snapshot_lock` AND the flush transition gate, no store locks)
/// must not deadlock a flush. Flush must wait behind the gate -- alive, not
/// wedged -- and complete once the capture releases it; both sides
/// finishing is the no-deadlock proof, and the negative wait only shows
/// the gate actually excludes flush during the capture.
#[tokio::test]
async fn flush_blocked_behind_a_parked_save_completes_without_deadlock() {
    let _dns_serial = super::DNS_GLOBAL_TEST_LOCK.lock().await;
    let host = "ts1703-reverse.test.invalid";
    let ip: IpAddr = "203.0.113.212".parse().unwrap();
    forget_dns_answer(host);
    disk_fallback_store().lock().unwrap().remove(host);
    disarm_flush_merge_pause();
    disarm_capture_pause();
    remember_doh_answer(host, &[ip], Duration::from_secs(3000));

    let dir = std::env::temp_dir().join(format!(
        "ts1703-reverse-{}-{}",
        std::process::id(),
        TEST_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("dns-cache.txt");

    // Park the save between its two store reads. It runs on its own thread
    // + throwaway runtime: the parked capture holds snapshot_lock + the
    // flush gate, which must never block this test's executor.
    let gate = arm_capture_pause();
    let (save_tx, save_rx) = std::sync::mpsc::channel();
    let save_thread_path = path.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("save runtime builds");
        let result = rt.block_on(save_persisted_dns_cache(&save_thread_path));
        let _ = save_tx.send(result);
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !capture_pause_parked() {
        assert!(
            std::time::Instant::now() < deadline,
            "the save must reach its capture section"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let flush_done = std::sync::Arc::new(AtomicBool::new(false));
    let flush_done_flag = flush_done.clone();
    std::thread::spawn(move || {
        flush_dns_cache();
        flush_done_flag.store(true, Ordering::SeqCst);
    });
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        !flush_done.load(Ordering::SeqCst),
        "flush must wait behind the gate held by the parked capture"
    );

    gate.release();
    let save_result = save_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("parked save completes after release");
    assert!(save_result.is_ok(), "save succeeds: {save_result:?}");
    let flush_deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !flush_done.load(Ordering::SeqCst) {
        assert!(
            std::time::Instant::now() < flush_deadline,
            "flush must complete once the capture releases the gate"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // The parked save captured the PRE-flush live answer and published it;
    // the delayed flush still cleared the live cache and merged its own
    // preserved copy.
    let file_text = std::fs::read_to_string(&path).unwrap();
    assert!(
        file_text.contains(&format!("{host}\t{ip}")),
        "the parked save must publish the answer it captured, got: {file_text:?}"
    );
    assert!(
        cached_doh_answer(host).is_none(),
        "the (delayed) flush must still clear the live cache"
    );
    assert_eq!(
        disk_fallback_answer(host),
        Some(vec![ip]),
        "the (delayed) flush must still merge its preserved copy"
    );

    disarm_capture_pause();
    disarm_flush_merge_pause();
    forget_dns_answer(host);
    disk_fallback_store().lock().unwrap().remove(host);
    let _ = std::fs::remove_dir_all(&dir);
}
