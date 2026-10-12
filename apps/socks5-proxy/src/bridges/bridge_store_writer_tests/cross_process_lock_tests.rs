use super::super::*;
use super::{config_path, leftover_tmp_files, reload, seed_store, test_bridge};
use bridge_line::BridgeLine;
use std::sync::{Arc, Condvar, Mutex};
use time::OffsetDateTime;

use crate::test_seams::{ParkedGate, Site, HANG_GUARD, UNBLOCK_GUARD};

/// Await a std synchronization call without pinning the runtime thread.
async fn sync_wait<T: Send + 'static>(wait: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(wait)
        .await
        .expect("sync wait joined")
}

/// A publish the test controls: signals started, parks until released,
/// saves, signals published — a rename in flight while the actor holds the
/// store's cross-process write lock.
fn gated_publisher(
    started_tx: std::sync::mpsc::Sender<()>,
    published_tx: std::sync::mpsc::Sender<()>,
    release: Arc<(Mutex<bool>, Condvar)>,
) -> Publisher {
    Arc::new(move |s: &BridgeStore| {
        let _ = started_tx.send(());
        let (gate, cvar) = &*release;
        let mut done = gate.lock().expect("publisher gate");
        while !*done {
            done = cvar.wait(done).expect("publisher gate wait");
        }
        let saved = s.save();
        let _ = published_tx.send(());
        saved
    })
}

/// A CLI read-modify-write overlapping a daemon publish in flight must wait
/// on the store's cross-process lock and build on the published state; a
/// stale snapshot would be buried by the daemon's rename with no self-heal.
/// Forcing: the CLI is parked before its acquisition and released only
/// while the publish is provably in flight (publisher parked, lock held,
/// file unpublished). The completion wait only picks who releases the
/// daemon: the CLI itself (lock bypassed — its save then precedes the
/// daemon's and the assertions below fail) or a guard timeout (correct
/// protocol).
#[tokio::test]
async fn concurrent_cli_transaction_waits_out_the_locked_publish_and_both_survive() {
    let dir = tempfile::tempdir().expect("tempdir");
    let b = test_bridge();
    let cli_bridge: BridgeLine =
        "obfs4 5.6.7.8:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=BBB iat-mode=0"
            .parse()
            .expect("CLI bridge line parses");
    let path = config_path(dir.path());
    seed_store(&path, &b);
    let store_path = BridgeStore::resolve_path(Some(&path));

    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (published_tx, published_rx) = std::sync::mpsc::channel::<()>();
    let published_rx = Arc::new(Mutex::new(published_rx));
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let writer = StoreWriter::spawn(
        BridgeStore::resolve_path(Some(&path)),
        gated_publisher(started_tx, published_tx, release.clone()),
        INITIAL_BACKOFF,
    );

    let b1 = b.clone();
    writer
        .apply(move |s| s.note_channel_success_at(&b1, OffsetDateTime::now_utc()))
        .await
        .expect("absorbed");
    let started = sync_wait(move || started_rx.recv_timeout(HANG_GUARD).is_ok()).await;
    assert!(
        started,
        "publisher must start (lock held, file unpublished)"
    );

    let pre = ParkedGate::arm(Site::PreAcquire, &store_path);
    let post = ParkedGate::arm(Site::PostLoad, &store_path);
    let post_for_cli = post.clone();
    let (cli_done_tx, cli_done_rx) = std::sync::mpsc::channel();
    let cli_path = path.clone();
    let cli_bridge_for_cli = cli_bridge.clone();
    let cli_task = tokio::spawn(async move {
        let out = crate::bridge_store_writer::apply(Some(cli_path.as_ref()), move |s| {
            s.note_source_at(&cli_bridge_for_cli, "cli", OffsetDateTime::now_utc())
        })
        .await;
        post_for_cli.release();
        let _ = cli_done_tx.send(());
        out
    });
    let pre_wait = pre.clone();
    sync_wait(move || pre_wait.wait_parked(HANG_GUARD)).await;

    // The CLI now reaches its acquisition while the daemon owns the lock.
    pre.release();
    let _cli_finished = sync_wait(move || cli_done_rx.recv_timeout(UNBLOCK_GUARD).is_ok()).await;
    {
        let (gate, cvar) = &*release;
        *gate.lock().expect("publisher gate") = true;
        cvar.notify_all();
    }
    let published_rx_for_second = Arc::clone(&published_rx);
    let published = sync_wait(move || {
        published_rx_for_second
            .lock()
            .expect("published rx")
            .recv_timeout(HANG_GUARD)
            .is_ok()
    })
    .await;
    assert!(published, "daemon publish must land");
    // Release the post-load gate in both modes. With the lock working the
    // CLI is still blocked before it; with the lock bypassed this lets the
    // test reach the final loss-detection assertions instead of hanging.
    post.release();

    cli_task
        .await
        .expect("cli task joined")
        .expect("cli transaction ok");

    let store = reload(&path);
    assert_eq!(
        store.channel_ok_count(&b),
        1,
        "the CLI must build on the daemon's published state"
    );
    assert_eq!(
        store.sources_of(&cli_bridge),
        vec!["cli"],
        "the CLI's mutation must survive the in-flight publish"
    );

    let b2 = b.clone();
    writer
        .apply(move |s| s.note_channel_success_at(&b2, OffsetDateTime::now_utc()))
        .await
        .expect("absorbed");
    let published_rx_for_third = Arc::clone(&published_rx);
    let published_twice = sync_wait(move || {
        published_rx_for_third
            .lock()
            .expect("published rx")
            .recv_timeout(HANG_GUARD)
            .is_ok()
    })
    .await;
    assert!(published_twice, "post-CLI daemon publish must land");
    let store = reload(&path);
    assert_eq!(store.channel_ok_count(&b), 2);
    assert_eq!(
        store.sources_of(&cli_bridge),
        vec!["cli"],
        "the CLI's bridge must survive the daemon's next publish"
    );

    writer.close().await.expect("writer closes");
    assert!(
        leftover_tmp_files(dir.path()).is_empty(),
        "no leftover temp files"
    );
}
