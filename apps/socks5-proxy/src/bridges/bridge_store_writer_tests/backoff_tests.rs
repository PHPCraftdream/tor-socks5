use super::super::*;
use super::{
    config_path, fail_first_publisher, leftover_tmp_files, reload, seed_store, test_bridge,
    wait_for_calls, wait_for_file_count,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use time::OffsetDateTime;
#[tokio::test(start_paused = true)]
async fn publish_failure_retains_absorbed_updates_until_next_op() {
    let dir = tempfile::tempdir().expect("tempdir");
    let b = test_bridge();
    let path = config_path(dir.path());
    seed_store(&path, &b);

    let calls = Arc::new(AtomicUsize::new(0));
    let writer = StoreWriter::spawn(
        BridgeStore::resolve_path(Some(&path)),
        fail_first_publisher(calls.clone()),
        INITIAL_BACKOFF,
    );
    let b1 = b.clone();
    writer
        .apply(move |s| s.note_channel_success_at(&b1, OffsetDateTime::now_utc()))
        .await
        .expect("absorbed");
    wait_for_calls(&calls, 1, "failed publish attempted").await;
    assert_eq!(
        reload(&path).channel_ok_count(&b),
        0,
        "failed publish left the file untouched"
    );

    // A second mutation while the backoff is pending must NOT publish:
    // the retry timer governs all attempts, absorbed updates just ride
    // along in memory.
    let b2 = b.clone();
    writer
        .apply(move |s| s.note_channel_success_at(&b2, OffsetDateTime::now_utc()))
        .await
        .expect("absorbed");
    // Well under the 1s backoff, but enough paused time for the actor to
    // (not) act on the absorption.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "pending backoff must gate publishes; no attempt until the timer"
    );
    assert_eq!(
        reload(&path).channel_ok_count(&b),
        0,
        "absorbed update waits in memory behind the backoff"
    );

    // Closing flushes both retained updates regardless of the deadline.
    let closed = writer.close().await;
    assert!(closed.is_ok(), "close flushes: {closed:?}");
    assert_eq!(
        reload(&path).channel_ok_count(&b),
        2,
        "final flush wrote both absorbed observations"
    );
    assert!(
        leftover_tmp_files(dir.path()).is_empty(),
        "no leftover temp files"
    );
}

#[tokio::test(start_paused = true)]
async fn backoff_gates_publish_attempts_under_a_continuous_mutation_stream() {
    let dir = tempfile::tempdir().expect("tempdir");
    let b = test_bridge();
    let path = config_path(dir.path());
    seed_store(&path, &b);

    let calls = Arc::new(AtomicUsize::new(0));
    let writer = StoreWriter::spawn(
        BridgeStore::resolve_path(Some(&path)),
        fail_first_publisher(calls.clone()),
        Duration::from_secs(1),
    );

    // A continuous stream of mutations must not produce a publish per
    // mutation, nor bypass the pending backoff: after the first failure
    // only the retry timer may attempt a publish.
    for _ in 0..10u32 {
        let b = b.clone();
        writer
            .apply(move |s| s.note_channel_success_at(&b, OffsetDateTime::now_utc()))
            .await
            .expect("absorbed");
        // Yield so the actor can process ops/completions; the virtual
        // clock barely moves, staying inside the 1s backoff.
        tokio::time::sleep(Duration::ZERO).await;
    }
    wait_for_calls(&calls, 1, "first (failing) publish attempted").await;
    // Stay under the 1s backoff; paused time only moved milliseconds.
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "backoff must gate the continuous mutation stream"
    );

    // Sleep past the backoff (plain sleep is the robust way to drive
    // paused time; see the comment in
    // publish_failure_is_retried_by_the_backoff_timer). The retry
    // publishes the coalesced snapshot once.
    tokio::time::sleep(Duration::from_secs(2)).await;
    wait_for_calls(&calls, 2, "backoff retry fired").await;
    wait_for_file_count(&path, &b, 10, "retry persisted the coalesced snapshot").await;
    assert!(
        calls.load(Ordering::SeqCst) <= 3,
        "10 mutations must not cost 10 publishes, got {}",
        calls.load(Ordering::SeqCst)
    );

    let closed = writer.close().await;
    assert!(closed.is_ok(), "close after a clean retry: {closed:?}");
    assert!(
        leftover_tmp_files(dir.path()).is_empty(),
        "no leftover temp files"
    );
}

#[tokio::test(start_paused = true)]
async fn close_flushes_absorbed_updates_before_the_retry_deadline() {
    let dir = tempfile::tempdir().expect("tempdir");
    let b = test_bridge();
    let path = config_path(dir.path());
    seed_store(&path, &b);

    let calls = Arc::new(AtomicUsize::new(0));
    let writer = StoreWriter::spawn(
        BridgeStore::resolve_path(Some(&path)),
        fail_first_publisher(calls.clone()),
        Duration::from_secs(1),
    );

    // m1 fails to publish, snapshot retained, backoff armed.
    let b1 = b.clone();
    writer
        .apply(move |s| s.note_channel_success_at(&b1, OffsetDateTime::now_utc()))
        .await
        .expect("absorbed");
    wait_for_calls(&calls, 1, "first (failing) publish attempted").await;
    assert_eq!(reload(&path).channel_ok_count(&b), 0, "file still stale");

    // m2 arrives while the backoff is pending: absorbed, no publish.
    let b2 = b.clone();
    writer
        .apply(move |s| s.note_channel_success_at(&b2, OffsetDateTime::now_utc()))
        .await
        .expect("absorbed");

    // Shutdown BEFORE the retry deadline: close must still flush both
    // mutations (this is the TS2-03 regression — the old design lost
    // them when the runtime dropped the pending timer).
    let closed = writer.close().await;
    assert!(
        closed.is_ok(),
        "close must flush retained updates: {closed:?}"
    );
    assert_eq!(
        reload(&path).channel_ok_count(&b),
        2,
        "final flush ran before the backoff deadline and wrote both mutations"
    );

    // The actor has exited: a further apply is rejected by a closed
    // channel ("writer is not running"). The test completing is also the
    // proof that close() joined the actor task without hanging.
    let rejected = writer.apply(|_| {}).await;
    assert!(rejected.is_err(), "apply after close must fail");
    assert!(
        leftover_tmp_files(dir.path()).is_empty(),
        "no leftover temp files"
    );
}

#[tokio::test(start_paused = true)]
async fn close_reports_a_persistent_publish_failure() {
    let dir = tempfile::tempdir().expect("tempdir");
    let b = test_bridge();
    let path = config_path(dir.path());
    seed_store(&path, &b);

    let writer = StoreWriter::spawn(
        BridgeStore::resolve_path(Some(&path)),
        Arc::new(|_s: &BridgeStore| Err(anyhow!("disk is full"))),
        INITIAL_BACKOFF,
    );
    let b1 = b.clone();
    writer
        .apply(move |s| s.note_channel_success_at(&b1, OffsetDateTime::now_utc()))
        .await
        .expect("absorbed");

    // Persistent failure: close returns the flush error promptly (no
    // hang), the file stays untouched, and save's own temp-file cleanup
    // left nothing behind.
    let closed = writer.close().await;
    assert!(closed.is_err(), "persistent failure must surface via close");
    assert_eq!(
        reload(&path).channel_ok_count(&b),
        0,
        "failed flush left the file untouched"
    );
    assert!(
        leftover_tmp_files(dir.path()).is_empty(),
        "no leftover temp files after the failed save"
    );
}

#[tokio::test(start_paused = true)]
async fn publish_failure_is_retried_by_the_backoff_timer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let b = test_bridge();
    let path = config_path(dir.path());
    seed_store(&path, &b);

    let calls = Arc::new(AtomicUsize::new(0));
    let writer = StoreWriter::spawn(
        BridgeStore::resolve_path(Some(&path)),
        fail_first_publisher(calls.clone()),
        Duration::from_secs(1),
    );
    let b1 = b.clone();
    writer
        .apply(move |s| s.note_channel_success_at(&b1, OffsetDateTime::now_utc()))
        .await
        .expect("absorbed");
    assert_eq!(reload(&path).channel_ok_count(&b), 0, "file still stale");

    // Let the actor arm its timer, then sleep past the 1s backoff.
    // `sleep(...).await` (not manual `advance()` + `sleep(ZERO)`) is the
    // robust way to drive paused time here: it fast-forwards the clock
    // AND cooperatively polls the runtime until quiescent at each due
    // timer, so the actor's own `sleep_until` is guaranteed to fire.
    // The publish itself runs on the blocking pool, so the on-disk
    // assertion below polls in real time (wait_for_file_count).
    tokio::time::sleep(Duration::from_secs(2)).await;
    wait_for_calls(&calls, 2, "backoff retry fired").await;
    wait_for_file_count(
        &path,
        &b,
        1,
        "backoff timer republished the retained snapshot",
    )
    .await;

    let closed = writer.close().await;
    assert!(closed.is_ok(), "close after a successful retry: {closed:?}");
    assert!(
        leftover_tmp_files(dir.path()).is_empty(),
        "no leftover temp files"
    );
}
