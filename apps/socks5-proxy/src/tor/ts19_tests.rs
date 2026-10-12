//! TS19-01 part 2 tests: blocking config/store file reads must run on
//! Tokio's blocking pool, never on the async worker that awaits them.
//!
//! The discriminator is thread identity, recorded by the seam in
//! `test_seams`: an inline call has no `.await` between the async fn's entry
//! and the blocking work, so it necessarily runs on the caller's own thread,
//! while `spawn_blocking` cannot. Tokio's `task::try_id()` would NOT work —
//! `spawn_blocking` polls its closure inside a real `BlockingTask` task, so
//! a task id is present on both sides.

use crate::bridge_maintenance::load_config_off_worker;
use crate::bridge_verifier::run_circuit_verify_tick;
use crate::config::Config;
use crate::test_seams::{ran_on_thread, Site};

#[tokio::test]
async fn config_load_runs_off_the_async_worker() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ts19-proxy.ktav");
    Config::default().write(&path).unwrap();

    let caller_thread = std::thread::current().id();
    let result = load_config_off_worker(Some(path.as_path())).await;
    assert!(result.is_ok(), "config load failed: {:?}", result.err());

    let ran_on = ran_on_thread(Site::MaintenanceConfigLoad).expect("the load must have run");
    assert_ne!(
        ran_on, caller_thread,
        "config load ran on the caller's async thread"
    );
}

#[tokio::test]
async fn circuit_verify_store_load_runs_off_the_async_worker() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing-store-dir").join("proxy.ktav");

    let caller_thread = std::thread::current().id();
    // Missing file -> empty store -> cheap early return.
    run_circuit_verify_tick(Some(path.as_path()), &[]).await;

    let ran_on = ran_on_thread(Site::CircuitVerifyStoreLoad).expect("the load must have run");
    assert_ne!(
        ran_on, caller_thread,
        "bridge-store load ran on the caller's async thread"
    );
}
