//! Regression tests for the users-registry cross-process transaction
//! lock (TS17-07).
//!
//! These tests live inside the crate because they drive the daemon-side
//! TOFU path at its `pub(crate)` test-only seams (`save_hook` /
//! `lock_hook`). The competing writer in the cross-process test is a
//! real second OS process spawned from this same test binary, following
//! the pattern of `packages/persist-lock/tests/cross_process_ownership.rs`:
//! in-process parking uses channels — never sleeps; only the file-marker
//! handshake with the child polls (cross-process, same idiom as that
//! sample).

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use persist_lock::PathLock;

use crate::compute_hash::compute_hash;
use crate::{verify_hash, AuthState, User, UsersConfig, INIT_SENTINEL};

/// Env var that turns a spawned copy of this test binary into the
/// daemon-role child. Without it the helper test is a no-op.
const CHILD_ENV: &str = "AUTH_REGISTRY_LOCK_CHILD";
/// Exact test path of the child helper, for `--exact`.
const CHILD_TEST: &str = "registry_lock_tests::cross_process_child_parks_in_save_hook_helper";

fn unique_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "tor-socks5-auth-registry-lock-{}-{}-{}",
        tag,
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn init_user(name: &str) -> User {
    User {
        name: name.into(),
        hash: INIT_SENTINEL.into(),
        is_enabled: true,
        allowed_onion: false,
    }
}

fn enabled_user(name: &str, password: &str) -> User {
    User {
        name: name.into(),
        hash: compute_hash(password).unwrap(),
        is_enabled: true,
        allowed_onion: false,
    }
}

fn wait_for(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn child_output(child: &mut ChildGuard) -> String {
    let mut out = String::new();
    if let Some(mut stdout) = child.0.stdout.take() {
        let _ = stdout.read_to_string(&mut out);
    }
    if let Some(mut stderr) = child.0.stderr.take() {
        let _ = stderr.read_to_string(&mut out);
    }
    out
}

fn wait_for_exit(child: &mut ChildGuard, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.0.try_wait().expect("try_wait child") {
            return status;
        }
        assert!(Instant::now() < deadline, "child did not exit in time");
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Daemon-role child for
/// `tofu_provision_survives_concurrent_cli_disable_across_processes`:
/// provisions `alice` through the real TOFU path and parks inside the
/// `save_hook` — i.e. after the registry re-read, holding the registry's
/// transaction lock, before the save — until the parent writes the
/// release marker. Without `CHILD_ENV` this is a no-op test.
#[test]
fn cross_process_child_parks_in_save_hook_helper() {
    let Some(users_path) = std::env::var(CHILD_ENV).ok() else {
        return;
    };
    let users_path = PathBuf::from(users_path);
    let dir = users_path
        .parent()
        .expect("users path has a parent")
        .to_path_buf();

    let cfg = UsersConfig::load(&users_path).expect("child loads the registry");
    let state =
        AuthState::build_persistent(&cfg, users_path.clone()).expect("child builds AuthState");

    let ready = dir.join("child-ready");
    let release = dir.join("child-release");
    let released = AtomicBool::new(false);
    let ready_writer = ready.clone();
    state.set_save_hook(Box::new(move || {
        if !released.swap(true, Ordering::SeqCst) {
            fs::write(&ready_writer, b"").expect("child writes ready marker");
            let deadline = Instant::now() + Duration::from_secs(30);
            while !release.exists() {
                assert!(
                    Instant::now() < deadline,
                    "child: timed out waiting for the release marker"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        Ok(())
    }));

    assert!(
        state.verify("alice", "pwA"),
        "child: TOFU provisioning must be accepted"
    );
}

/// TS17-07 subprocess regression: a daemon parked between its registry
/// read and its save (transaction lock held) must not let a concurrent
/// CLI process interleave a mutation into that window, and both
/// mutations must survive. Before the fix the CLI's whole transaction
/// ran inside that window and the daemon's stale snapshot clobbered the
/// CLI's disable (or the CLI resurrected the `init` sentinel).
#[test]
fn tofu_provision_survives_concurrent_cli_disable_across_processes() {
    let dir = unique_dir("tofu-vs-cli");
    let users_path = dir.join("users.ktav");
    UsersConfig {
        users: vec![init_user("alice"), enabled_user("bob", "bobpw")],
    }
    .save(&users_path)
    .expect("seed registry");

    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", CHILD_TEST, "--test-threads", "1"])
        .env(CHILD_ENV, users_path.as_os_str())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn daemon-role child");
    let mut child = ChildGuard(child);

    assert!(
        wait_for(&dir.join("child-ready"), Duration::from_secs(15)),
        "child never parked in its save hook; output:\n{}",
        child_output(&mut child)
    );

    // The parked child holds the registry's transaction lock: a
    // CLI-style bounded acquire must fail with the clear busy error.
    // This is exactly the window the pre-fix code let a CLI mutation
    // interleave into.
    let busy = PathLock::acquire_bounded(&users_path, Duration::from_millis(300))
        .err()
        .expect("TS17-07: the parked daemon's transaction lock must exclude a CLI writer");
    let busy_msg = format!("{busy:#}");
    assert!(busy_msg.contains("busy"), "clear busy error: {busy_msg}");

    // The failed attempt must not have touched the registry.
    let on_disk = UsersConfig::load(&users_path).expect("registry still loads");
    assert_eq!(
        on_disk.find("alice").expect("alice present").hash,
        INIT_SENTINEL,
        "the child has not published its provisioning yet"
    );
    assert!(on_disk.find("bob").expect("bob present").is_enabled);

    // Let the daemon finish; its provisioning publishes.
    fs::write(dir.join("child-release"), b"").expect("write release marker");
    let status = wait_for_exit(&mut child, Duration::from_secs(30));
    assert!(
        status.success(),
        "child failed: {status:?}; output:\n{}",
        child_output(&mut child)
    );

    // Now the CLI mutation lands — on the daemon's published state, under
    // the same transaction lock (users_cli does exactly this).
    let lock = PathLock::acquire_bounded(&users_path, Duration::from_secs(10))
        .expect("registry lock is free after the daemon finished");
    let mut cfg = UsersConfig::load(&users_path).expect("load under the lock");
    cfg.find_mut("bob").expect("bob present").is_enabled = false;
    cfg.save(&users_path).expect("publish the disable");
    drop(lock);

    // Restart simulation: BOTH mutations survived.
    let final_cfg = UsersConfig::load(&users_path).expect("final load");
    let alice_hash = &final_cfg.find("alice").expect("alice present").hash;
    assert_ne!(*alice_hash, INIT_SENTINEL, "alice was provisioned");
    assert!(
        verify_hash(alice_hash, "pwA").expect("verify alice hash"),
        "the daemon's provisioning survived"
    );
    assert!(
        !final_cfg.find("bob").expect("bob present").is_enabled,
        "the CLI disable survived"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// Lock-ordering contract: the Argon2id hash is computed BEFORE the
/// registry transaction lock is taken, and the authoritative re-read
/// happens UNDER it. The `lock_hook` seam fires after hashing and
/// immediately before `PathLock::acquire`; at that moment the lock must
/// still be free (the bounded acquire below succeeds — a regression to
/// lock-before-hash fails this assertion with the busy error instead of
/// hanging the test), and an edit published in that window must be
/// incorporated by the re-read rather than clobbered.
#[test]
fn registry_lock_is_taken_after_hashing_and_spans_the_reread() {
    let dir = unique_dir("lock-order");
    let users_path = dir.join("users.ktav");
    UsersConfig {
        users: vec![init_user("alice"), enabled_user("bob", "bobpw")],
    }
    .save(&users_path)
    .expect("seed registry");
    let state = AuthState::build_persistent(
        &UsersConfig::load(&users_path).expect("load"),
        users_path.clone(),
    )
    .expect("build AuthState");

    // One-shot seam hook: signal the main thread, then block until
    // released (5s fail-safe timeout; later invocations pass through).
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let release_rx = Arc::new(Mutex::new(release_rx));
    let release_rx_hook = release_rx.clone();
    let fired = AtomicBool::new(false);
    state.set_lock_hook(Box::new(move || {
        if !fired.swap(true, Ordering::SeqCst) {
            tx.send(()).ok();
            let _ = release_rx_hook
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5));
        }
    }));

    let state = Arc::new(state);
    let resolver_state = Arc::clone(&state);
    let resolver = std::thread::spawn(move || resolver_state.verify("alice", "pwA"));

    rx.recv_timeout(Duration::from_secs(5))
        .expect("lock hook fired: the resolver hashed and is at the seam");

    // The transaction lock must STILL be free here (hashing happened
    // outside it). Bounded, so a lock-before-hash regression fails this
    // assertion cleanly instead of deadlocking.
    let lock = PathLock::acquire_bounded(&users_path, Duration::from_secs(2))
        .expect("TS17-07: hashing runs BEFORE the lock — the registry must still be unlocked at the pre-lock seam");

    // CLI-style edit published in the seam window, under the same lock.
    let mut cfg = UsersConfig::load(&users_path).expect("load under the lock");
    cfg.find_mut("bob").expect("bob present").is_enabled = false;
    cfg.save(&users_path).expect("publish the disable");
    drop(lock);

    release_tx.send(()).ok();
    assert!(
        resolver.join().expect("resolver thread"),
        "resolver's provisioning must be accepted"
    );

    // The re-read under the lock incorporated the edit instead of
    // clobbering it with the stale snapshot.
    let final_cfg = UsersConfig::load(&users_path).expect("final load");
    assert!(
        !final_cfg.find("bob").expect("bob present").is_enabled,
        "an edit published between the seam and the lock must survive the re-read"
    );
    let alice_hash = &final_cfg.find("alice").expect("alice present").hash;
    assert_ne!(*alice_hash, INIT_SENTINEL);
    assert!(verify_hash(alice_hash, "pwA").expect("verify alice"));

    let _ = fs::remove_dir_all(&dir);
}

/// Moved from `state.rs` tests (same assertions): two TOFU resolutions
/// racing INSIDE one process cannot write an older snapshot over a
/// newer one — the in-process half of the registry serialisation
/// contract. Keep distinct from the cross-process test above: different
/// mechanism, both must hold.
#[test]
fn concurrent_inits_cannot_write_older_snapshot_over_newer() {
    let dir = unique_dir("conc");
    let path = dir.join("users.ktav");
    let cfg = UsersConfig {
        users: vec![init_user("alice"), init_user("bob")],
    };
    cfg.save(&path).unwrap();
    let st = Arc::new(
        AuthState::build_persistent(&UsersConfig::load(&path).unwrap(), path.clone()).unwrap(),
    );

    // One-shot save hook: on its first invocation signal the main
    // thread, then block until it releases us (or 5s pass — the
    // timeout is a fail-safe so a regression degrades to a normal
    // pass-through instead of a deadlock). Later invocations are
    // no-ops.
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let rx_hook = Arc::new(Mutex::new(rx));
    let rx_main = rx_hook.clone();
    let fired = AtomicBool::new(false);
    st.set_save_hook(Box::new(move || {
        if !fired.swap(true, Ordering::SeqCst) {
            tx.send(()).ok();
            let _ = rx_hook.lock().unwrap().recv_timeout(Duration::from_secs(5));
        }
        Ok(())
    }));

    // Thread A claims alice; it blocks inside save() while holding
    // the write lock.
    let st_a = Arc::clone(&st);
    let a = std::thread::spawn(move || st_a.verify("alice", "pwA"));
    rx_main
        .lock()
        .unwrap()
        .recv_timeout(Duration::from_secs(5))
        .expect("hook fired: A is blocked in save under the write lock");

    // Thread B claims bob. With the fix, B's transition+save can only
    // run after A committed; the old code would let A's stale save
    // later regress bob to the sentinel.
    let st_b = Arc::clone(&st);
    let b = std::thread::spawn(move || st_b.verify("bob", "pwB"));

    assert!(a.join().unwrap(), "alice's init accepted");
    assert!(b.join().unwrap(), "bob's init accepted");

    // Restart simulation: both passwords survived, neither hash is
    // the sentinel.
    let reloaded = UsersConfig::load(&path).unwrap();
    let ha = &reloaded.find("alice").unwrap().hash;
    let hb = &reloaded.find("bob").unwrap().hash;
    assert_ne!(*ha, INIT_SENTINEL);
    assert_ne!(*hb, INIT_SENTINEL);
    assert!(verify_hash(ha, "pwA").unwrap());
    assert!(verify_hash(hb, "pwB").unwrap());

    let _ = fs::remove_dir_all(&dir);
}
