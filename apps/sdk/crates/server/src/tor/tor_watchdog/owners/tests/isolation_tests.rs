// H16: the server must stay isolated from the application's process-global
// state. The app's global bridge-store writer slot and blocking workers
// spawned before a server run ("foreign" workers) are never touched by
// start/stop: start/stop neither consume nor wait on them.
//
// These tests are serialized by TEST_LIFECYCLE; the first one is the only
// user of the process-global writer slot in this binary, so its cleanup
// (close_global) is safe even though a panic on an earlier assert would
// skip it (the slot leaks only into this same test).

use super::*;
use tor_socks5_runtime::{bridge_store_writer, workers};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn app_global_writer_survives_server_start_and_stop() {
    let _serial = TEST_LIFECYCLE.lock().await;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let app_path = dir.path().join("app.ktav");
    // The app opens its own process-global writer before any server run.
    let app_writer = bridge_store_writer::init_global(Some(&app_path));
    assert!(!bridge_store_writer::global_is_idle());
    // Benign mutation through the app's own writer.
    app_writer.apply(|_| {}).await.unwrap();

    // The server runs against its own config path and uses init_run, never
    // the app's global writer slot.
    let (config_path, config) = test_config(dir.path(), 0);
    let handle = start_server(config, config_path, test_settings(dir.path()), false)
        .await
        .expect("server start with an open app writer must succeed");
    assert_running_at(&handle, None);
    handle.shutdown().await.unwrap();

    assert!(
        bridge_store_writer::run_is_idle(),
        "the server's run slot must be empty after stop"
    );
    assert!(
        !bridge_store_writer::global_is_idle(),
        "the app's global writer must survive the server run"
    );
    app_writer
        .apply(|_| {})
        .await
        .expect("app writer must stay usable after the server run");

    // Cleanup as the app would.
    bridge_store_writer::close_global().await;
    assert!(bridge_store_writer::global_is_idle());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn foreign_blocking_worker_does_not_delay_start_or_stop() {
    let _serial = TEST_LIFECYCLE.lock().await;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    // Spawned before the server installs its run group, so this worker is
    // foreign: it lands only in the process registry.
    let worker = tokio::spawn(workers::run_fallible_blocking(move || {
        let _ = started_tx.send(());
        let _ = release_rx.recv();
        Ok(())
    }));
    started_rx.await.unwrap();

    let (config_path, config) = test_config(dir.path(), 0);
    let handle = tokio::time::timeout(
        Duration::from_secs(30),
        start_server(config, config_path, test_settings(dir.path()), true),
    )
    .await
    .expect("start must not wait for the foreign parked worker")
    .expect("start with a parked foreign worker must succeed");
    assert_running_at(&handle, None);

    tokio::time::timeout(Duration::from_secs(30), handle.shutdown())
        .await
        .expect("shutdown must not wait for the foreign parked worker")
        .expect("shutdown with a parked foreign worker must succeed");

    // Drain the process registry the app owns.
    release_tx.send(()).unwrap();
    worker.await.unwrap().unwrap().unwrap();
    workers::join_blocking_workers()
        .await
        .expect("process registry must drain after releasing the worker");
    assert_slots_free().await;
}
