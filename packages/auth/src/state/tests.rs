use super::*;
use crate::compute_hash::compute_hash;
use crate::user::User;

fn mk_user(name: &str, password: &str, enabled: bool) -> User {
    User {
        name: name.into(),
        hash: compute_hash(password).unwrap(),
        is_enabled: enabled,
        allowed_onion: false,
        allowed_clients: None,
        pre_socks5: None,
        post_socks5: None,
    }
}

fn init_user(name: &str) -> User {
    User {
        name: name.into(),
        hash: INIT_SENTINEL.into(),
        is_enabled: true,
        allowed_onion: false,
        allowed_clients: None,
        pre_socks5: None,
        post_socks5: None,
    }
}

fn state(users: Vec<User>) -> AuthState {
    AuthState::build(&UsersConfig { users }).unwrap()
}

fn tmp_path(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "tor-socks5-auth-state-test-{}-{}-{}",
        tag,
        std::process::id(),
        seq
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("users.ktav")
}

#[test]
fn accepts_correct_password() {
    let s = state(vec![mk_user("alice", "secret", true)]);
    assert!(s.verify("alice", "secret"));
}

#[test]
fn rejects_wrong_password() {
    let s = state(vec![mk_user("alice", "secret", true)]);
    assert!(!s.verify("alice", "WRONG"));
}

#[test]
fn rejects_unknown_user() {
    let s = state(vec![mk_user("alice", "secret", true)]);
    assert!(!s.verify("mallory", "anything"));
}

#[test]
fn rejects_disabled_user_silently() {
    let s = state(vec![mk_user("alice", "secret", false)]);
    assert!(
        !s.verify("alice", "secret"),
        "disabled even with right password"
    );
}

#[test]
fn require_auth_is_false_for_empty_registry() {
    let s = state(vec![]);
    assert!(!s.require_auth());
}

#[test]
fn require_auth_is_true_when_users_present() {
    let s = state(vec![mk_user("alice", "secret", true)]);
    assert!(s.require_auth());
}

#[test]
fn first_successful_login_populates_cache_subsequent_hits_cache() {
    let s = state(vec![mk_user("alice", "secret", true)]);
    assert_eq!(s.cache_len(), 0);
    assert!(s.verify("alice", "secret"));
    assert_eq!(s.cache_len(), 1, "cache populated after first verify");
    // Second call should still succeed and not bump cache size.
    assert!(s.verify("alice", "secret"));
    assert_eq!(s.cache_len(), 1);
}

#[test]
fn failed_logins_are_not_cached() {
    let s = state(vec![mk_user("alice", "secret", true)]);
    assert!(!s.verify("alice", "wrong-1"));
    assert!(!s.verify("alice", "wrong-2"));
    assert_eq!(s.cache_len(), 0, "failed attempts must not populate cache");
}

#[test]
fn disabled_user_does_not_populate_cache() {
    let s = state(vec![mk_user("alice", "secret", false)]);
    assert!(!s.verify("alice", "secret"));
    assert_eq!(s.cache_len(), 0);
}

#[test]
fn rotated_password_invalidates_cache_on_next_attempt() {
    let mut cfg = UsersConfig {
        users: vec![mk_user("alice", "secret", true)],
    };
    let s = AuthState::build(&cfg).unwrap();
    assert!(s.verify("alice", "secret"));
    assert_eq!(s.cache_len(), 1);

    // Simulate a password rotation and rebuild (the real proxy
    // re-builds on restart). The fresh server_secret means the same
    // plaintext computes a different HMAC anyway, but the key point
    // is that the old password must no longer be accepted.
    cfg.users[0].hash = compute_hash("rotated").unwrap();
    let s2 = AuthState::build(&cfg).unwrap();
    assert!(!s2.verify("alice", "secret"));
    assert!(s2.verify("alice", "rotated"));
}

#[test]
fn empty_user_list_means_require_auth_false() {
    let s = state(vec![]);
    assert!(s.is_empty());
    assert!(!s.require_auth());
}

#[test]
fn each_authstate_uses_a_distinct_server_secret() {
    let cfg = UsersConfig {
        users: vec![mk_user("alice", "secret", true)],
    };
    let s1 = AuthState::build(&cfg).unwrap();
    let s2 = AuthState::build(&cfg).unwrap();
    assert!(s1.verify("alice", "secret"));
    assert!(s2.verify("alice", "secret"));
    let v1 = s1.cache.get("alice").unwrap().hmac;
    let v2 = s2.cache.get("alice").unwrap().hmac;
    assert_ne!(
        v1, v2,
        "server_secret should not be deterministic across builds"
    );
}

// ------------------------------ TOFU init ------------------------------

#[test]
fn init_account_accepts_first_password_and_sets_real_hash() {
    let s = state(vec![init_user("alice")]);
    assert!(s.verify("alice", "chosen-pw"));
    // In-memory hash is now a real Argon2id PHC, not the sentinel.
    let stored = s.users.read().unwrap().find("alice").unwrap().hash.clone();
    assert!(
        stored.starts_with("$argon2id$"),
        "hash should be real now: {stored}"
    );
    assert!(verify_hash(&stored, "chosen-pw").unwrap());
    // And the credential is cached.
    assert_eq!(s.cache_len(), 1);
}

#[test]
fn init_account_rejects_empty_password() {
    let s = state(vec![init_user("alice")]);
    assert!(
        !s.verify("alice", ""),
        "empty password must not claim the account"
    );
    let stored = s.users.read().unwrap().find("alice").unwrap().hash.clone();
    assert_eq!(stored, INIT_SENTINEL);
}

#[test]
fn init_first_password_wins_second_different_password_rejected() {
    let s = state(vec![init_user("alice")]);
    assert!(s.verify("alice", "first"));
    // The account is now provisioned with "first"; a different
    // password must be rejected, the same one accepted.
    assert!(!s.verify("alice", "second"));
    assert!(s.verify("alice", "first"));
}

#[test]
fn init_account_persists_real_hash_to_disk() {
    let path = tmp_path("persist");
    UsersConfig {
        users: vec![init_user("alice")],
    }
    .save(&path)
    .unwrap();

    let cfg = UsersConfig::load(&path).unwrap();
    let s = AuthState::build_persistent(&cfg, path.clone()).unwrap();
    assert!(s.verify("alice", "chosen-pw"));

    // Reload from disk: the sentinel must have been replaced by a
    // real hash that verifies the chosen password.
    let reloaded = UsersConfig::load(&path).unwrap();
    let stored = &reloaded.find("alice").unwrap().hash;
    assert_ne!(stored, INIT_SENTINEL);
    assert!(stored.starts_with("$argon2id$"));
    assert!(verify_hash(stored, "chosen-pw").unwrap());

    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn save_failure_does_not_confirm_init() {
    let path = tmp_path("savefail");
    // Real registry on disk with alice still in init.
    UsersConfig {
        users: vec![init_user("alice")],
    }
    .save(&path)
    .unwrap();
    let s = AuthState::build_persistent(&UsersConfig::load(&path).unwrap(), path.clone()).unwrap();

    // Hook: the first TWO invocations inject a save failure (both
    // pw1 attempts must be rejected), later ones pass through so
    // pw2 can claim the account.
    let fails = std::sync::atomic::AtomicU32::new(2);
    s.set_save_hook(Box::new(move || {
        if fails.fetch_sub(1, std::sync::atomic::Ordering::SeqCst) > 0 {
            Err(anyhow::anyhow!("injected save failure"))
        } else {
            Ok(())
        }
    }));

    // TOFU path: injected save failure -> login refused, nothing cached.
    assert!(!s.verify("alice", "pw1"));
    assert_eq!(
        s.cache_len(),
        0,
        "failed save must not populate success cache"
    );
    // Still in init: the second attempt takes the TOFU path again.
    assert!(!s.verify("alice", "pw1"));
    assert_eq!(s.cache_len(), 0);

    // A DIFFERENT password now succeeds (hook passes through): this
    // proves the account was still in init — had pw1 been committed
    // despite the failure, this would be a lost-race verify against
    // pw1's hash and would return false. Note resolve_init re-reads
    // the disk file, which must STILL hold the init sentinel because
    // the failed attempts never wrote anything — that is exactly why
    // pw2 can claim the account.
    assert!(s.verify("alice", "pw2"));

    // Restart simulation: pw2 — never pw1 — is what landed on disk.
    let reloaded = UsersConfig::load(&path).unwrap();
    let hash = &reloaded.find("alice").unwrap().hash;
    assert_ne!(*hash, INIT_SENTINEL);
    assert!(verify_hash(hash, "pw2").unwrap());
    assert!(!verify_hash(hash, "pw1").unwrap());

    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn init_rejected_when_registry_unreadable_or_vanished() {
    // Part A: registry vanished/unreadable — a plain FILE where the
    // registry's parent directory should be, so load cannot see the
    // account on disk.
    let dir = tmp_path("vanished").parent().unwrap().to_path_buf();
    let blocker = dir.join("blocker");
    std::fs::File::create(&blocker).unwrap();
    let users_path = blocker.join("users.ktav");

    let s = AuthState::build_persistent(
        &UsersConfig {
            users: vec![init_user("alice")],
        },
        users_path.clone(),
    )
    .unwrap();
    // The registry cannot be read as containing the account, so the
    // login is refused (memory is not consulted for the transition).
    assert!(!s.verify("alice", "pw1"));
    assert_eq!(s.cache_len(), 0);
    let _ = std::fs::remove_dir_all(&dir);

    // Part B: registry present but corrupt — load() errors, so the
    // init transition must refuse rather than clobber the file.
    let path = tmp_path("corrupt");
    std::fs::write(&path, "not a ktav file {{{").unwrap();
    let s = AuthState::build_persistent(
        &UsersConfig {
            users: vec![init_user("alice")],
        },
        path.clone(),
    )
    .unwrap();
    assert!(!s.verify("alice", "pw1"));
    assert_eq!(s.cache_len(), 0);

    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn init_transition_incorporates_cli_edits() {
    let path = tmp_path("cli");
    UsersConfig {
        users: vec![init_user("alice")],
    }
    .save(&path)
    .unwrap();
    let st = AuthState::build_persistent(&UsersConfig::load(&path).unwrap(), path.clone()).unwrap();

    // Simulate a concurrent CLI process (users_cli does
    // load -> mutate -> save in its own process): add "bob" with a
    // real hash after the angel built its in-memory snapshot.
    let mut cli_cfg = UsersConfig::load(&path).unwrap();
    cli_cfg.users.push(mk_user("bob", "bobpw", true));
    cli_cfg.save(&path).unwrap();

    // The angel's TOFU transition for alice must re-read the disk
    // registry and merge, not clobber.
    assert!(st.verify("alice", "alipw"));

    // Restart simulation: bob is intact, alice is resolved.
    let reloaded = UsersConfig::load(&path).unwrap();
    let bob = reloaded.find("bob").unwrap();
    assert!(
        verify_hash(&bob.hash, "bobpw").unwrap(),
        "bob not clobbered"
    );
    let alice = reloaded.find("alice").unwrap();
    assert_ne!(alice.hash, INIT_SENTINEL);
    assert!(verify_hash(&alice.hash, "alipw").unwrap());
    // Memory was refreshed to the merged disk state.
    assert_eq!(st.len(), 2);

    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

// ------------------------------ allowed_onion ------------------------------

fn onion_user(name: &str, enabled: bool, allowed_onion: bool) -> User {
    User {
        name: name.into(),
        hash: compute_hash("pw").unwrap(),
        is_enabled: enabled,
        allowed_onion,
        allowed_clients: None,
        pre_socks5: None,
        post_socks5: None,
    }
}

#[test]
fn allowed_onion_true_only_for_enabled_and_granted() {
    let s = state(vec![onion_user("alice", true, true)]);
    assert!(s.allowed_onion("alice"));
}

#[test]
fn allowed_onion_false_when_not_granted() {
    let s = state(vec![onion_user("bob", true, false)]);
    assert!(!s.allowed_onion("bob"));
}

#[test]
fn allowed_onion_false_for_disabled_even_if_granted() {
    let s = state(vec![onion_user("carol", false, true)]);
    assert!(
        !s.allowed_onion("carol"),
        "a disabled account must not reach onion even with the flag"
    );
}

#[test]
fn allowed_onion_false_for_unknown_user() {
    let s = state(vec![onion_user("alice", true, true)]);
    assert!(!s.allowed_onion("nobody"));
}

#[test]
fn init_account_disabled_is_not_provisioned() {
    let s = state(vec![User {
        name: "alice".into(),
        hash: INIT_SENTINEL.into(),
        is_enabled: false,
        allowed_onion: false,
        allowed_clients: None,
        pre_socks5: None,
        post_socks5: None,
    }]);
    assert!(!s.verify("alice", "chosen-pw"));
    let stored = s.users.read().unwrap().find("alice").unwrap().hash.clone();
    assert_eq!(
        stored, INIT_SENTINEL,
        "disabled init account stays unprovisioned"
    );
}

// --------------------------- cache snapshot binding ---------------------------

#[test]
fn stale_cache_rejected_after_tofu_reload_brings_rotated_hash() {
    let path = tmp_path("ts301-scenario");
    UsersConfig {
        users: vec![mk_user("alice", "oldpw", true), init_user("bob")],
    }
    .save(&path)
    .unwrap();
    let s = std::sync::Arc::new(
        AuthState::build_persistent(&UsersConfig::load(&path).unwrap(), path.clone()).unwrap(),
    );

    // Prime the cache with alice's old credential.
    assert!(s.verify("alice", "oldpw"));
    assert_eq!(s.cache_len(), 1);

    // Simulate the CLI process rotating alice's password on disk.
    let mut cli_cfg = UsersConfig::load(&path).unwrap();
    cli_cfg.find_mut("alice").unwrap().hash = compute_hash("newpw").unwrap();
    cli_cfg.save(&path).unwrap();

    // TOFU login of bob pulls the rotated registry into memory.
    assert!(s.verify("bob", "bobpw"));

    // The stale cache entry must not resurrect the old password.
    assert!(
        !s.verify("alice", "oldpw"),
        "old password must be rejected after hash rotation"
    );
    assert!(s.verify("alice", "newpw"));

    // Disk state matches: the rotated hash verifies newpw only.
    let reloaded = UsersConfig::load(&path).unwrap();
    let alice = &reloaded.find("alice").unwrap().hash;
    assert!(verify_hash(alice, "newpw").unwrap());
    assert!(!verify_hash(alice, "oldpw").unwrap());

    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn late_in_flight_verify_cannot_reinstate_old_password_after_rotation() {
    let path = tmp_path("ts301-inflight");
    UsersConfig {
        users: vec![mk_user("alice", "oldpw", true), init_user("bob")],
    }
    .save(&path)
    .unwrap();
    let s = std::sync::Arc::new(
        AuthState::build_persistent(&UsersConfig::load(&path).unwrap(), path.clone()).unwrap(),
    );

    // One-shot verify hook: on its first invocation signal the main
    // thread, then block until released (5s fail-safe timeout).
    // Later invocations pass through.
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let release_rx = std::sync::Arc::new(std::sync::Mutex::new(release_rx));
    let release_rx_hook = release_rx.clone();
    let fired = std::sync::atomic::AtomicBool::new(false);
    s.set_verify_hook(Box::new(move || {
        if !fired.swap(true, std::sync::atomic::Ordering::SeqCst) {
            tx.send(()).ok();
            let _ = release_rx_hook
                .lock()
                .unwrap()
                .recv_timeout(std::time::Duration::from_secs(5));
        }
    }));

    // Thread A verifies against the OLD hash; it parks inside the
    // hook before the Argon2id work, holding no registry lock.
    let s_a = s.clone();
    let a = std::thread::spawn(move || s_a.verify("alice", "oldpw"));
    rx.recv_timeout(std::time::Duration::from_secs(5))
        .expect("hook fired: A is parked in verify");

    // While A is parked: CLI rotates alice on disk, then bob's TOFU
    // pulls the new registry into memory (bob takes the write lock
    // fine because A holds no lock).
    let mut cli_cfg = UsersConfig::load(&path).unwrap();
    cli_cfg.find_mut("alice").unwrap().hash = compute_hash("newpw").unwrap();
    cli_cfg.save(&path).unwrap();
    assert!(s.verify("bob", "bobpw"));

    // Release A: its check against the OLD hash legitimately
    // succeeds and publishes a cache entry with the OLD snapshot.
    release_tx.send(()).ok();
    assert!(
        a.join().unwrap(),
        "A's verification against the old hash snapshot succeeds"
    );

    // But the late-published entry must not accept the old password
    // now that the authoritative hash has rotated.
    assert!(
        !s.verify("alice", "oldpw"),
        "late-published cache entry must not accept the old password after rotation"
    );
    assert!(s.verify("alice", "newpw"));

    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}
