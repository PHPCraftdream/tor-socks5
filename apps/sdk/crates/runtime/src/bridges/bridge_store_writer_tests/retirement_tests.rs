use super::super::*;
use super::{config_path, leftover_tmp_files, seed_store, test_bridge, wait_for_file_count};
use time::OffsetDateTime;

/// TS6-04 regression: both retirement sites -- the post-mutation snapshot
/// swap and the clean-publish retirement inside `absorb_publish_result` --
/// must drop the old `Arc<BridgeStore>` on the blocking pool, never inline
/// in the actor's `select!` loop. The test runtime is current-thread, so
/// the actor's loop is polled on THIS test thread; `drop_off_worker`
/// records the thread each retirement runs on, and every recorded thread
/// id must differ from the actor's (= this test thread's). On the pre-fix
/// code both drops ran inline and their recorded ids would equal the
/// actor's.
#[tokio::test]
async fn retired_snapshots_are_dropped_off_the_async_worker() {
    let actor_thread = std::thread::current().id();
    let dir = tempfile::tempdir().expect("tempdir");
    let b = test_bridge();
    let path = config_path(dir.path());
    seed_store(&path, &b);

    let writer = StoreWriter::spawn(
        BridgeStore::resolve_path(Some(&path)),
        Arc::new(|s| s.save()),
        INITIAL_BACKOFF,
    );

    // Site 1: the first mutation loads the file, and swapping the mutated
    // snapshot in retires the loaded one (after the mutation job returned,
    // the actor's Arc was its last strong reference).
    let b1 = b.clone();
    writer
        .apply(move |s| s.note_channel_success_at(&b1, OffsetDateTime::now_utc()))
        .await
        .expect("absorbed");

    // Site 2: the publish succeeds with no tail mutations, so
    // `absorb_publish_result` retires the mutated snapshot. The file write
    // completes slightly before the actor absorbs the result, so poll.
    wait_for_file_count(&path, &b, 1, "publish completed").await;

    // Exactly two retirements must be recorded, each on a non-actor
    // thread. The recorder is per-writer, so no other test can pollute
    // it. Thread ids are globally unique and never reused, so a
    // blocking-pool thread can never collide with the test's own thread.
    for _ in 0..5000 {
        let threads = writer
            .retirements
            .lock()
            .expect("retirement recorder poisoned")
            .clone();
        if threads.len() >= 2 {
            assert!(
                threads.iter().all(|t| *t != actor_thread),
                "a retired snapshot was dropped on the actor's async worker \
                 thread: {threads:?} (actor thread: {actor_thread:?})"
            );
            break;
        }
        tokio::task::yield_now().await;
        std::thread::sleep(Duration::from_millis(2));
    }
    let threads = writer
        .retirements
        .lock()
        .expect("retirement recorder poisoned")
        .clone();
    assert_eq!(
        threads.len(),
        2,
        "both retirement sites must have retired a snapshot: {threads:?}"
    );

    let closed = writer.close().await;
    assert!(closed.is_ok(), "close after a clean publish: {closed:?}");
    assert!(
        leftover_tmp_files(dir.path()).is_empty(),
        "no leftover temp files"
    );
}
