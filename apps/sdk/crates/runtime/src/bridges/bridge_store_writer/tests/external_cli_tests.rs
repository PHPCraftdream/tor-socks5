use super::super::*;
use super::{
    config_path, fail_first_publisher, leftover_tmp_files, reload, seed_store, test_bridge,
    wait_calls, wait_settled,
};
use bridge_line::BridgeLine;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use time::OffsetDateTime;

#[tokio::test]
async fn load_failure_rejects_the_op_without_running_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Loading a directory path errors (not NotFound), exercising the
    // unreadable-store rejection path.
    let writer = StoreWriter::spawn(
        dir.path().to_path_buf(),
        Arc::new(|s: &BridgeStore| s.save()),
        INITIAL_BACKOFF,
    );
    let ran = Arc::new(AtomicBool::new(false));
    let ran_closure = ran.clone();
    let result = writer
        .apply(move |_s| {
            ran_closure.store(true, Ordering::SeqCst);
        })
        .await;
    assert!(result.is_err(), "apply must reject when load fails");
    assert!(!ran.load(Ordering::SeqCst), "closure must not run");
}

#[tokio::test]
async fn apply_falls_back_to_inline_write_without_a_global_writer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let b = test_bridge();
    let config_path = config_path(dir.path());
    seed_store(&config_path, &b);

    let b1 = b.clone();
    apply(config_path.as_ref(), move |s| {
        s.note_channel_success_at(&b1, OffsetDateTime::now_utc())
    })
    .await
    .expect("inline fallback write succeeds");
    assert_eq!(reload(&config_path).channel_ok_count(&b), 1);
    assert!(
        leftover_tmp_files(dir.path()).is_empty(),
        "no leftover temp files"
    );
}

#[tokio::test]
async fn external_cli_write_between_angel_mutations_survives() {
    let dir = tempfile::tempdir().expect("tempdir");
    let b = test_bridge();
    let cli_bridge: BridgeLine =
        "obfs4 5.6.7.8:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=BBB iat-mode=0"
            .parse()
            .expect("CLI bridge line parses");
    let path = config_path(dir.path());
    seed_store(&path, &b);

    let writer = StoreWriter::spawn(
        BridgeStore::resolve_path(&path),
        Arc::new(|s| s.save()),
        INITIAL_BACKOFF,
    );
    let mut settled = writer.settled_watch();

    // Angel mutation #1 publishes cleanly. Awaiting the settle epoch proves
    // the write is on disk AND the actor retired its snapshot (next op
    // re-reads the file) — the old wait_for_file_count + wait_a_real_moment
    // pair in one deterministic step.
    let b1 = b.clone();
    writer
        .apply(move |s| s.note_channel_success_at(&b1, OffsetDateTime::now_utc()))
        .await
        .expect("absorbed");
    wait_settled(&mut settled, 1, "first angel mutation published").await;

    // A separate CLI process (sequential, not concurrent) loads, adds a
    // new bridge and bumps the angel bridge's counter, then saves.
    let mut external = reload(&path);
    external.note_source_at(&cli_bridge, "cli", OffsetDateTime::now_utc());
    external.note_channel_success_at(&b, OffsetDateTime::now_utc());
    external.save().expect("external save");

    // Angel mutation #2 must build on the CLI's version, not the
    // angel's stale pre-CLI snapshot.
    let b2 = b.clone();
    writer
        .apply(move |s| s.note_channel_success_at(&b2, OffsetDateTime::now_utc()))
        .await
        .expect("absorbed");

    wait_settled(&mut settled, 2, "angel's second mutation published").await;
    let store = reload(&path);
    assert_eq!(
        store.channel_ok_count(&b),
        3,
        "angel's second mutation published"
    );
    assert_eq!(
        store.channel_ok_count(&b),
        3,
        "angel's second mutation must build on the CLI's counter (1 angel + 1 CLI + 1 angel)"
    );
    assert_eq!(
        store.sources_of(&cli_bridge),
        vec!["cli"],
        "CLI's new bridge must survive the angel's next publish"
    );
    assert!(
        leftover_tmp_files(dir.path()).is_empty(),
        "no leftover temp files"
    );
}

#[tokio::test(start_paused = true)]
async fn external_cli_write_after_successful_retry_survives() {
    let dir = tempfile::tempdir().expect("tempdir");
    let b = test_bridge();
    let cli_bridge: BridgeLine =
        "obfs4 5.6.7.8:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=BBB iat-mode=0"
            .parse()
            .expect("CLI bridge line parses");
    let path = config_path(dir.path());
    seed_store(&path, &b);

    let calls = Arc::new(AtomicUsize::new(0));
    let (calls_tx, mut calls_rx) = super::entry_signal();
    let writer = StoreWriter::spawn(
        BridgeStore::resolve_path(&path),
        fail_first_publisher(calls.clone(), calls_tx),
        Duration::from_secs(1),
    );
    let mut settled = writer.settled_watch();

    // Angel mutation #1: publish fails, snapshot retained, retry armed.
    let b1 = b.clone();
    writer
        .apply(move |s| s.note_channel_success_at(&b1, OffsetDateTime::now_utc()))
        .await
        .expect("absorbed");
    assert_eq!(reload(&path).channel_ok_count(&b), 0, "file still stale");

    // Paused clock: sleep fast-forwards AND polls the runtime to
    // quiescence, so the actor's retry fires (see the comment in
    // publish_failure_is_retried_by_the_backoff_timer).
    tokio::time::sleep(Duration::from_secs(2)).await;
    wait_calls(&mut calls_rx, 2, "retry fired").await;
    // The retry is the first clean publish; epoch 1 also proves the actor
    // retired its snapshot before the external write.
    wait_settled(&mut settled, 1, "retry published").await;
    assert_eq!(reload(&path).channel_ok_count(&b), 1, "retry published");

    // External CLI write lands after the successful retry.
    let mut external = reload(&path);
    external.note_source_at(&cli_bridge, "cli", OffsetDateTime::now_utc());
    external.note_channel_success_at(&b, OffsetDateTime::now_utc());
    external.save().expect("external save");

    // Angel mutation #2 must build on the CLI's version.
    let b2 = b.clone();
    writer
        .apply(move |s| s.note_channel_success_at(&b2, OffsetDateTime::now_utc()))
        .await
        .expect("absorbed");

    wait_settled(&mut settled, 2, "post-retry mutation published").await;
    let store = reload(&path);
    assert_eq!(
        store.channel_ok_count(&b),
        3,
        "post-retry mutation published"
    );
    assert_eq!(
        store.channel_ok_count(&b),
        3,
        "mutation after a successful retry must build on the CLI's counter (1 retry + 1 CLI + 1 angel)"
    );
    assert_eq!(
        store.sources_of(&cli_bridge),
        vec!["cli"],
        "CLI's new bridge must survive a post-retry angel publish"
    );
    assert!(
        leftover_tmp_files(dir.path()).is_empty(),
        "no leftover temp files"
    );
}

/// init_global → close_global → init_global must hand out a fresh, live
/// writer (the engine restart path runs in one process), never the closed
/// one. Serialized with the other global-slot test via the shared test
/// lock; each side clears a writer left behind by a failed predecessor
/// before initializing.
#[tokio::test]
async fn init_close_init_gets_a_fresh_live_writer() {
    let _lifecycle = crate::bridge_store_writer::GLOBAL_WRITER_TEST_LOCK
        .lock()
        .await;
    let dir = tempfile::tempdir().expect("tempdir");
    let b = test_bridge();
    let path = config_path(dir.path());
    seed_store(&path, &b);

    // Clear any writer a panicked predecessor may have left behind.
    drop(close_global().await);

    let first = init_global(path.as_path());
    // Re-init without close returns the existing writer, not a second one.
    let again = init_global(path.as_path());
    assert!(
        Arc::ptr_eq(&first.actor, &again.actor),
        "re-init without close must return the existing writer"
    );

    close_global()
        .await
        .expect("close runs when a writer is up")
        .expect("close succeeds");

    // The closed writer is dead: it must reject mutations.
    let b1 = b.clone();
    assert!(
        first
            .apply(move |s| s.note_channel_success_at(&b1, OffsetDateTime::now_utc()))
            .await
            .is_err(),
        "the closed writer must reject mutations"
    );

    // Re-init after close must NOT hand back the closed writer.
    let second = init_global(path.as_path());
    assert!(
        !Arc::ptr_eq(&first.actor, &second.actor),
        "init after close must start a fresh writer"
    );

    // The fresh writer accepts and publishes records end to end.
    let mut settled = second.settled_watch();
    let b2 = b.clone();
    second
        .apply(move |s| s.note_channel_success_at(&b2, OffsetDateTime::now_utc()))
        .await
        .expect("fresh writer absorbs the mutation");
    wait_settled(&mut settled, 1, "fresh writer publishes").await;
    assert_eq!(
        reload(&path).channel_ok_count(&b),
        1,
        "fresh writer publishes"
    );

    // Stopping again empties the slot: a second close reports None.
    close_global()
        .await
        .expect("close runs when a writer is up")
        .expect("close succeeds");
    assert!(
        close_global().await.is_none(),
        "close without a running writer returns None"
    );
    assert!(
        leftover_tmp_files(dir.path()).is_empty(),
        "no leftover temp files"
    );
}

/// The public handle constructor `StoreWriter::open` (SDK-7) runs the
/// same actor without the process-global slot: it accepts mutations,
/// publishes them, and `close` reports the final flush result; a closed
/// handle rejects further mutations.
#[tokio::test]
async fn open_starts_a_live_writer_and_close_reports_the_flush_result() {
    let dir = tempfile::tempdir().expect("tempdir");
    let b = test_bridge();
    let path = config_path(dir.path());
    seed_store(&path, &b);

    let writer = StoreWriter::open(path.as_path());
    let mut settled = writer.settled_watch();
    let b1 = b.clone();
    writer
        .apply(move |s| s.note_channel_success_at(&b1, OffsetDateTime::now_utc()))
        .await
        .expect("open writer absorbs the mutation");
    wait_settled(&mut settled, 1, "open writer publishes").await;
    assert_eq!(
        reload(&path).channel_ok_count(&b),
        1,
        "open writer publishes"
    );

    writer
        .close()
        .await
        .expect("close reports the flush result");
    assert!(
        writer.apply(|_| {}).await.is_err(),
        "a closed writer must reject mutations"
    );
    assert!(
        leftover_tmp_files(dir.path()).is_empty(),
        "no leftover temp files"
    );
}
