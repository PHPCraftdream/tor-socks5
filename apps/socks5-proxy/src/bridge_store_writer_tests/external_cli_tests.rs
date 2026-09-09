use super::super::*;
use super::{
    config_path, fail_first_publisher, leftover_tmp_files, reload, seed_store, test_bridge,
    wait_a_real_moment, wait_for_calls, wait_for_file_count,
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
    apply(Some(config_path.as_ref()), move |s| {
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
async fn external_cli_write_between_daemon_mutations_survives() {
    let dir = tempfile::tempdir().expect("tempdir");
    let b = test_bridge();
    let cli_bridge: BridgeLine =
        "obfs4 5.6.7.8:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=BBB iat-mode=0"
            .parse()
            .expect("CLI bridge line parses");
    let path = config_path(dir.path());
    seed_store(&path, &b);

    let writer = StoreWriter::spawn(
        BridgeStore::resolve_path(Some(&path)),
        Arc::new(|s| s.save()),
        INITIAL_BACKOFF,
    );

    // Daemon mutation #1 publishes cleanly. Acks now precede the disk
    // write, so wait for the publish to land AND for the actor to retire
    // the completion (dropping its snapshot) before the external write.
    let b1 = b.clone();
    writer
        .apply(move |s| s.note_channel_success_at(&b1, OffsetDateTime::now_utc()))
        .await
        .expect("absorbed");
    wait_for_file_count(&path, &b, 1, "first daemon mutation published").await;
    wait_a_real_moment().await;

    // A separate CLI process (sequential, not concurrent) loads, adds a
    // new bridge and bumps the daemon bridge's counter, then saves.
    let mut external = reload(&path);
    external.note_source_at(&cli_bridge, "cli", OffsetDateTime::now_utc());
    external.note_channel_success_at(&b, OffsetDateTime::now_utc());
    external.save().expect("external save");

    // Daemon mutation #2 must build on the CLI's version, not the
    // daemon's stale pre-CLI snapshot.
    let b2 = b.clone();
    writer
        .apply(move |s| s.note_channel_success_at(&b2, OffsetDateTime::now_utc()))
        .await
        .expect("absorbed");

    wait_for_file_count(&path, &b, 3, "daemon's second mutation published").await;
    let store = reload(&path);
    assert_eq!(
        store.channel_ok_count(&b),
        3,
        "daemon's second mutation must build on the CLI's counter (1 daemon + 1 CLI + 1 daemon)"
    );
    assert_eq!(
        store.sources_of(&cli_bridge),
        vec!["cli"],
        "CLI's new bridge must survive the daemon's next publish"
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
    let writer = StoreWriter::spawn(
        BridgeStore::resolve_path(Some(&path)),
        fail_first_publisher(calls.clone()),
        Duration::from_secs(1),
    );

    // Daemon mutation #1: publish fails, snapshot retained, retry armed.
    let b1 = b.clone();
    writer
        .apply(move |s| s.note_channel_success_at(&b1, OffsetDateTime::now_utc()))
        .await
        .expect("absorbed");
    assert_eq!(reload(&path).channel_ok_count(&b), 0, "file still stale");

    // Paused clock: sleep fast-forwards AND polls the runtime to
    // quiescence, so the actor's retry fires (see the comment in
    // publish_failure_is_retried_by_the_backoff_timer); the publish runs
    // on the blocking pool, hence the real-time polls below.
    tokio::time::sleep(Duration::from_secs(2)).await;
    wait_for_calls(&calls, 2, "retry fired").await;
    wait_for_file_count(&path, &b, 1, "retry published").await;

    // External CLI write lands after the successful retry.
    let mut external = reload(&path);
    external.note_source_at(&cli_bridge, "cli", OffsetDateTime::now_utc());
    external.note_channel_success_at(&b, OffsetDateTime::now_utc());
    external.save().expect("external save");

    // Daemon mutation #2 must build on the CLI's version.
    let b2 = b.clone();
    writer
        .apply(move |s| s.note_channel_success_at(&b2, OffsetDateTime::now_utc()))
        .await
        .expect("absorbed");

    wait_for_file_count(&path, &b, 3, "post-retry mutation published").await;
    let store = reload(&path);
    assert_eq!(
        store.channel_ok_count(&b),
        3,
        "mutation after a successful retry must build on the CLI's counter (1 retry + 1 CLI + 1 daemon)"
    );
    assert_eq!(
        store.sources_of(&cli_bridge),
        vec!["cli"],
        "CLI's new bridge must survive a post-retry daemon publish"
    );
    assert!(
        leftover_tmp_files(dir.path()).is_empty(),
        "no leftover temp files"
    );
}
