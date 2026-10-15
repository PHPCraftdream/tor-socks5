//! Unit tests for the server-side onion-service launcher that need the
//! `onion-service` feature (keystore lock contention).

use std::time::Duration;

use crate::onion::store;

/// While any holder owns the keystore lock, a bounded `store::lock_with` must
/// fail with the user-facing hint (stop the server first) — this is what a
/// CLI command sees while the server publishes its services.
#[test]
fn keystore_lock_is_exclusive_and_names_the_hint() {
    let dir = tempfile::tempdir().expect("temp dir");
    let keystore = dir.path().join("state").join("keystore");

    // First holder: what the running server takes for its services' lifetime.
    let _server_guard = persist_lock::PathLock::acquire_bounded(&keystore, Duration::from_secs(1))
        .expect("first holder acquires");

    // A CLI-style bounded acquisition must fail fast with the hint.
    let error = match store::lock_with(&keystore, Duration::from_millis(150)) {
        Ok(_) => panic!("second holder must be excluded"),
        Err(error) => error,
    };
    let message = format!("{error:#}");
    assert!(
        message.contains("stop tor-socks5 first"),
        "hint missing from: {message}"
    );

    // Released: acquisition succeeds again.
    drop(_server_guard);
    store::lock_with(&keystore, Duration::from_secs(1)).expect("acquire after release");
}
