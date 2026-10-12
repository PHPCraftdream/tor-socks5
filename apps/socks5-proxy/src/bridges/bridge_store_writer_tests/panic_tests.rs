use super::super::*;
use super::{
    config_path, fail_first_publisher, leftover_tmp_files, reload, seed_store, test_bridge,
    wait_for_calls, wait_for_file_count,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use time::OffsetDateTime;
/// TS4-09 panic branch (updated by TS5-06): a mutation closure that
/// panics must not kill the actor. The panicked op's ack resolves `Err`
/// (the caller must assume THAT mutation did not land), nothing is
/// published for it, and the NEXT mutation succeeds. With the TS5-06 fix
/// the actor RETAINS the loaded snapshot rather than dropping it, so the
/// next mutation does not reload from disk — observably equivalent here
/// because nothing external wrote between the load and the panic.
#[tokio::test]
async fn mutation_panic_rejects_the_ack_and_the_next_mutation_succeeds() {
    let dir = tempfile::tempdir().expect("tempdir");
    let b = test_bridge();
    let path = config_path(dir.path());
    seed_store(&path, &b);

    let writer = StoreWriter::spawn(
        BridgeStore::resolve_path(Some(&path)),
        Arc::new(|s| s.save()),
        INITIAL_BACKOFF,
    );

    let result = writer
        .apply(|_s: &mut BridgeStore| panic!("injected mutation panic"))
        .await;
    let error = result.expect_err("a panicking closure must reject its ack");
    assert!(
        error.to_string().contains("panicked"),
        "the ack error must report the panic: {error:#}"
    );
    assert_eq!(
        reload(&path).channel_ok_count(&b),
        0,
        "the panicked mutation must not have published anything"
    );

    // The actor survived the panic; the next mutation is absorbed into
    // the RETAINED snapshot (no reload under TS5-06) and publishes.
    let b1 = b.clone();
    writer
        .apply(move |s| s.note_channel_success_at(&b1, OffsetDateTime::now_utc()))
        .await
        .expect("actor still alive: next mutation is absorbed");
    wait_for_file_count(&path, &b, 1, "post-panic mutation published").await;

    let closed = writer.close().await;
    assert!(closed.is_ok(), "close after recovery: {closed:?}");
    assert!(
        leftover_tmp_files(dir.path()).is_empty(),
        "no leftover temp files"
    );
}

/// TS5-06 regression (the core scenario): a confirmed but UNPUBLISHED
/// mutation (publish failed, snapshot retained for backoff retry) followed
/// by a panicking mutation must not lose the confirmed one. With the old
/// `store.take()` the panic destroyed the actor's whole snapshot
/// (`store = None`), `try_start_publish` then blocked every retry, and the
/// next mutation reloaded the STALE file — mutation A was gone for good.
#[tokio::test(start_paused = true)]
async fn panic_after_a_failed_publish_keeps_the_confirmed_mutation() {
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

    // Mutation A: acked (absorbed), publish #1 fails, snapshot retained.
    let b_a = b.clone();
    writer
        .apply(move |s| s.note_channel_success_at(&b_a, OffsetDateTime::now_utc()))
        .await
        .expect("absorbed");
    wait_for_calls(&calls, 1, "publish #1 attempted and failed").await;
    assert_eq!(
        reload(&path).channel_ok_count(&b),
        0,
        "the failed publish left the file untouched"
    );

    // Mutation B panics: its own ack rejects, and it must not have
    // published anything.
    let result = writer
        .apply(move |_s: &mut BridgeStore| panic!("injected mutation panic"))
        .await;
    let error = result.expect_err("a panicking closure must reject its ack");
    assert!(
        error.to_string().contains("panicked"),
        "the ack error must report the panic: {error:#}"
    );
    assert_eq!(
        reload(&path).channel_ok_count(&b),
        0,
        "the panicked mutation must not have published anything"
    );

    // THE KEY ASSERTION: the disk file still holds count 0, so the only
    // copy of mutation A anywhere is the actor's retained in-memory
    // snapshot. If the actor had dropped it (the old `take()` bug), the
    // retry could never publish (`store.is_none()` blocks
    // `try_start_publish`) and A would be unrecoverable. Prove A survived
    // WITHOUT a reload by letting the backoff retry succeed.
    tokio::time::sleep(Duration::from_secs(2)).await;
    wait_for_calls(&calls, 2, "the backoff retry fired").await;
    wait_for_file_count(
        &path,
        &b,
        1,
        "the backoff retry published the retained snapshot: mutation A survived mutation B's panic without a reload",
    )
    .await;

    // The next successful op must build on the surviving state: its
    // publish carries BOTH the retained A and the new C.
    let b_c = b.clone();
    writer
        .apply(move |s| s.note_source_at(&b_c, "after-panic", OffsetDateTime::now_utc()))
        .await
        .expect("absorbed");
    wait_for_calls(&calls, 3, "mutation C's publish fired").await;
    // The call counter bumps before save() finishes writing, so poll the
    // file (see wait_for_file_count) instead of reloading immediately.
    let mut store = None;
    for _ in 0..5000 {
        let reloaded = reload(&path);
        if reloaded.sources_of(&b).contains(&"after-panic".to_string()) {
            store = Some(reloaded);
            break;
        }
        tokio::task::yield_now().await;
        std::thread::sleep(Duration::from_millis(2));
    }
    let store = store.expect("mutation C's source must reach disk");
    assert_eq!(
        store.channel_ok_count(&b),
        1,
        "mutation A survived B's panic and reached disk via C's publish"
    );
    assert!(
        store.sources_of(&b).contains(&"after-panic".to_string()),
        "mutation C applied on top of the surviving state"
    );

    let closed = writer.close().await;
    assert!(closed.is_ok(), "close after a clean publish: {closed:?}");
    assert!(
        leftover_tmp_files(dir.path()).is_empty(),
        "no leftover temp files"
    );
}

/// TS5-06 regression (anti-busy-loop): with the old `store.take()` bug a
/// panicking mutation left `store = None` while `retry.dirty` stayed true;
/// the expired `retry_at` fired `try_start_publish`, which returned early
/// without touching `RetryState`, so the same deadline was instantly ready
/// again — a zero-delay busy loop. After a panic the retry attempts must
/// keep following the exponential backoff schedule exactly.
#[tokio::test(start_paused = true)]
async fn retries_stay_on_the_backoff_schedule_after_a_panicking_mutation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let b = test_bridge();
    let path = config_path(dir.path());
    seed_store(&path, &b);

    // Fail the first THREE publish calls, succeed from the 4th.
    let calls = Arc::new(AtomicUsize::new(0));
    let publisher: Publisher = {
        let counter = calls.clone();
        Arc::new(move |s: &BridgeStore| {
            if counter.fetch_add(1, Ordering::SeqCst) < 3 {
                Err(anyhow!("injected publish failure"))
            } else {
                s.save()
            }
        })
    };
    let writer = StoreWriter::spawn(
        BridgeStore::resolve_path(Some(&path)),
        publisher,
        INITIAL_BACKOFF,
    );

    // Mutation A: acked, publish call 1 fails at t≈0, backoff 1s→2s.
    let b_a = b.clone();
    writer
        .apply(move |s| s.note_channel_success_at(&b_a, OffsetDateTime::now_utc()))
        .await
        .expect("absorbed");
    wait_for_calls(&calls, 1, "publish #1 attempted and failed").await;

    // Mutation B panics. With the fix, B leaves retry.dirty, retry_at and
    // the retained snapshot exactly as they were before B.
    let result = writer
        .apply(move |_s: &mut BridgeStore| panic!("injected mutation panic"))
        .await;
    let error = result.expect_err("a panicking closure must reject its ack");
    assert!(
        error.to_string().contains("panicked"),
        "the ack error must report the panic: {error:#}"
    );

    // t=5s: the 1s/2s schedule puts retries at t=1s (call 2, fails → next
    // at t=3s) and t=3s (call 3, fails → next at t=7s). Exactly 3 attempts
    // means the attempts follow the exponential schedule — no flood of
    // immediate retries through the expired timer (the old store=None
    // busy-loop would either spin without ever publishing or, worse,
    // hammer the publisher).
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "retries must follow the exponential backoff schedule, not a busy loop"
    );

    // t=9s: the t=7s retry is call 4 and SUCCEEDS.
    tokio::time::sleep(Duration::from_secs(4)).await;
    wait_for_calls(&calls, 4, "the successful retry fired").await;
    wait_for_file_count(
        &path,
        &b,
        1,
        "the successful retry persisted the retained snapshot with mutation A",
    )
    .await;

    // t=11s: a successful publish ends the retry streak; nothing keeps
    // attempting.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        4,
        "a successful publish must end the retry streak"
    );

    let closed = writer.close().await;
    assert!(closed.is_ok(), "close after a clean retry: {closed:?}");
    assert!(
        leftover_tmp_files(dir.path()).is_empty(),
        "no leftover temp files"
    );
}

/// TS5-06 regression: close after a confirmed, unpublished mutation plus a
/// panicking one must flush the RETAINED snapshot (containing A) — the
/// final flush ignores the backoff deadline. With the old bug the panic
/// left `store = None`, so close's flush arm hit `None => Ok(())` and
/// reported a false success while losing A.
#[tokio::test(start_paused = true)]
async fn close_after_a_panicking_mutation_flushes_the_retained_snapshot() {
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

    // Mutation A: acked, publish fails, snapshot retained, backoff armed.
    let b_a = b.clone();
    writer
        .apply(move |s| s.note_channel_success_at(&b_a, OffsetDateTime::now_utc()))
        .await
        .expect("absorbed");
    wait_for_calls(&calls, 1, "publish #1 attempted and failed").await;

    // Mutation B panics; its ack rejects.
    let result = writer
        .apply(move |_s: &mut BridgeStore| panic!("injected mutation panic"))
        .await;
    assert!(
        result.is_err(),
        "the panicking mutation must reject its ack"
    );

    // Close must flush the snapshot that still contains A and report Ok.
    let closed = writer.close().await;
    assert!(
        closed.is_ok(),
        "close must flush the retained snapshot: {closed:?}"
    );
    assert_eq!(
        reload(&path).channel_ok_count(&b),
        1,
        "the final flush wrote the retained mutation A"
    );
    assert!(
        leftover_tmp_files(dir.path()).is_empty(),
        "no leftover temp files"
    );
}

/// TS5-06 regression: if the underlying publish keeps failing, close after
/// a confirmed, unpublished mutation plus a panicking one must return Err
/// — NOT the false `Ok(())` the old `None => Ok(())` close arm produced
/// when `retry.dirty` was true but the panicking mutation had taken the
/// snapshot away.
#[tokio::test(start_paused = true)]
async fn close_after_a_panicking_mutation_reports_a_persistent_failure() {
    let dir = tempfile::tempdir().expect("tempdir");
    let b = test_bridge();
    let path = config_path(dir.path());
    seed_store(&path, &b);

    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let writer = StoreWriter::spawn(
        BridgeStore::resolve_path(Some(&path)),
        Arc::new(move |_s: &BridgeStore| {
            counter.fetch_add(1, Ordering::SeqCst);
            Err(anyhow!("disk is full"))
        }),
        INITIAL_BACKOFF,
    );

    // Mutation A: acked, publish fails, snapshot retained.
    let b_a = b.clone();
    writer
        .apply(move |s| s.note_channel_success_at(&b_a, OffsetDateTime::now_utc()))
        .await
        .expect("absorbed");
    wait_for_calls(&calls, 1, "publish #1 attempted and failed").await;

    // Mutation B panics; its ack rejects.
    let result = writer
        .apply(move |_s: &mut BridgeStore| panic!("injected mutation panic"))
        .await;
    assert!(
        result.is_err(),
        "the panicking mutation must reject its ack"
    );

    // The persistent publish failure must surface via close — never a
    // false Ok.
    let closed = writer.close().await;
    assert!(
        closed.is_err(),
        "a failing final flush must be reported: {closed:?}"
    );
    assert_eq!(
        reload(&path).channel_ok_count(&b),
        0,
        "the failing publisher left the file untouched"
    );
    assert!(
        leftover_tmp_files(dir.path()).is_empty(),
        "no leftover temp files after the failed save"
    );
}
