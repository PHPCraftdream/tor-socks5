use super::*;

struct FixedPrompt {
    password: String,
    confirm: String,
}

impl PasswordPrompt for FixedPrompt {
    fn read_password(&mut self) -> Result<String> {
        Ok(self.password.clone())
    }
    fn read_password_confirm(&mut self) -> Result<String> {
        Ok(self.confirm.clone())
    }
}

fn fixed_prompt(pw: &str) -> FixedPrompt {
    FixedPrompt {
        password: pw.to_string(),
        confirm: pw.to_string(),
    }
}

fn mismatch_prompt(pw: &str, confirm: &str) -> FixedPrompt {
    FixedPrompt {
        password: pw.to_string(),
        confirm: confirm.to_string(),
    }
}

fn tmp_users_path(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join("test.users.ktav")
}

#[test]
fn add_happy_path() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_users_path(dir.path());
    let mut prompt = fixed_prompt("secret123");

    cmd_add(
        &path,
        "alice",
        &mut prompt,
        false,
        Some("127.0.0.1:1080"),
        Some("none"),
    )
    .unwrap();

    let loaded = UsersConfig::load(&path).unwrap();
    assert_eq!(loaded.users.len(), 1);
    assert_eq!(loaded.users[0].name, "alice");
    assert!(loaded.users[0].is_enabled);
    assert!(!loaded.users[0].hash.is_empty());
    assert!(verify_hash(&loaded.users[0].hash, "secret123").unwrap());
    assert_eq!(
        loaded.users[0].pre_socks5,
        Some(EndpointOverride::Endpoint(
            "127.0.0.1:1080".parse().unwrap()
        ))
    );
    assert_eq!(
        loaded.users[0].post_socks5,
        Some(EndpointOverride::Disabled)
    );
}

#[test]
fn add_rejects_invalid_socks5_without_saving() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_users_path(dir.path());
    let mut prompt = fixed_prompt("secret123");

    let err = cmd_add(
        &path,
        "alice",
        &mut prompt,
        false,
        Some("127.0.0.1:1080"),
        Some("not-an-endpoint"),
    )
    .unwrap_err();

    assert!(format!("{err}").contains("invalid SOCKS5 endpoint"));
    assert!(!path.exists(), "invalid endpoint must not create registry");
}

#[test]
fn add_init_preserves_socks5_overrides() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_users_path(dir.path());

    cmd_add_init(&path, "alice", false, Some("127.0.0.1:1080"), Some("none")).unwrap();

    let loaded = UsersConfig::load(&path).unwrap();
    let alice = loaded.find("alice").unwrap();
    assert_eq!(
        alice.pre_socks5,
        Some(EndpointOverride::Endpoint(
            "127.0.0.1:1080".parse().unwrap()
        ))
    );
    assert_eq!(alice.post_socks5, Some(EndpointOverride::Disabled));
}

#[test]
fn add_init_rejects_invalid_socks5_without_saving() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_users_path(dir.path());

    let err = cmd_add_init(
        &path,
        "alice",
        false,
        Some("127.0.0.1:1080"),
        Some("not-an-endpoint"),
    )
    .unwrap_err();

    assert!(format!("{err}").contains("invalid SOCKS5 endpoint"));
    assert!(!path.exists(), "invalid endpoint must not create registry");
}

#[test]
fn add_defaults_to_onion_denied() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_users_path(dir.path());
    let mut prompt = fixed_prompt("secret123");
    cmd_add(&path, "alice", &mut prompt, false, None, None).unwrap();
    let loaded = UsersConfig::load(&path).unwrap();
    assert!(
        !loaded.find("alice").unwrap().allowed_onion,
        "onion must be denied unless --allow-onion is passed"
    );
}

#[test]
fn add_with_allow_onion_grants_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_users_path(dir.path());
    let mut prompt = fixed_prompt("secret123");
    cmd_add(&path, "alice", &mut prompt, true, None, None).unwrap();
    assert!(
        UsersConfig::load(&path)
            .unwrap()
            .find("alice")
            .unwrap()
            .allowed_onion
    );
}

#[test]
fn add_init_with_allow_onion_grants_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_users_path(dir.path());
    cmd_add_init(&path, "alice", true, None, None).unwrap();
    let u = UsersConfig::load(&path).unwrap();
    let u = u.find("alice").unwrap();
    assert_eq!(u.hash, INIT_SENTINEL);
    assert!(
        u.allowed_onion,
        "init account can be granted onion up front"
    );
}

#[test]
fn set_onion_toggles_flag() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_users_path(dir.path());
    let mut prompt = fixed_prompt("pw");
    cmd_add(&path, "alice", &mut prompt, false, None, None).unwrap();

    cmd_set_onion(&path, "alice", true).unwrap();
    assert!(
        UsersConfig::load(&path)
            .unwrap()
            .find("alice")
            .unwrap()
            .allowed_onion
    );

    cmd_set_onion(&path, "alice", false).unwrap();
    assert!(
        !UsersConfig::load(&path)
            .unwrap()
            .find("alice")
            .unwrap()
            .allowed_onion
    );
}

#[test]
fn set_onion_errors_on_missing() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_users_path(dir.path());
    let err = cmd_set_onion(&path, "ghost", true).unwrap_err();
    assert!(format!("{err}").contains("does not exist"));
}

#[test]
fn add_init_stores_sentinel_hash() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_users_path(dir.path());

    cmd_add_init(&path, "alice", false, None, None).unwrap();

    let loaded = UsersConfig::load(&path).unwrap();
    assert_eq!(loaded.users.len(), 1);
    assert_eq!(loaded.users[0].name, "alice");
    assert!(loaded.users[0].is_enabled);
    assert_eq!(loaded.users[0].hash, INIT_SENTINEL);
}

#[test]
fn add_init_rejects_duplicate() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_users_path(dir.path());
    cmd_add_init(&path, "alice", false, None, None).unwrap();
    let err = cmd_add_init(&path, "alice", false, None, None).unwrap_err();
    assert!(format!("{err}").contains("already exists"));
}

#[test]
fn set_password_on_init_account_succeeds() {
    // Provisioning a real password over an `init` sentinel must not
    // trip the "old password still verifies" sanity check.
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_users_path(dir.path());
    cmd_add_init(&path, "alice", false, None, None).unwrap();

    let mut prompt = fixed_prompt("real-pass");
    cmd_set_password(&path, "alice", &mut prompt).unwrap();

    let loaded = UsersConfig::load(&path).unwrap();
    let hash = &loaded.find("alice").unwrap().hash;
    assert_ne!(hash, INIT_SENTINEL);
    assert!(verify_hash(hash, "real-pass").unwrap());
}

#[test]
fn add_rejects_duplicate() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_users_path(dir.path());
    let mut prompt = fixed_prompt("secret");

    cmd_add(&path, "alice", &mut prompt, false, None, None).unwrap();
    let err = cmd_add(&path, "alice", &mut prompt, false, None, None).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("set-password"),
        "error should mention set-password: {msg}"
    );
}

#[test]
fn add_rejects_mismatched_confirm() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_users_path(dir.path());
    let mut prompt = mismatch_prompt("secret123", "different");

    let err = cmd_add(&path, "alice", &mut prompt, false, None, None).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("do not match"),
        "error should mention mismatch: {msg}"
    );
}

#[test]
fn add_rejects_empty_password() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_users_path(dir.path());
    let mut prompt = fixed_prompt("");

    let err = cmd_add(&path, "alice", &mut prompt, false, None, None).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("empty"), "error should mention empty: {msg}");
}

#[test]
fn remove_deletes_existing() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_users_path(dir.path());
    let mut prompt = fixed_prompt("pw");

    cmd_add(&path, "alice", &mut prompt, false, None, None).unwrap();
    cmd_remove(&path, "alice").unwrap();

    let loaded = UsersConfig::load(&path).unwrap();
    assert!(loaded.users.is_empty());
}

#[test]
fn remove_errors_on_missing() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_users_path(dir.path());
    let err = cmd_remove(&path, "nobody").unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("does not exist"),
        "error should mention missing: {msg}"
    );
}

#[test]
fn enable_disable_toggles_flag() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_users_path(dir.path());
    let mut prompt = fixed_prompt("pw");

    cmd_add(&path, "alice", &mut prompt, false, None, None).unwrap();
    cmd_disable(&path, "alice").unwrap();
    let loaded = UsersConfig::load(&path).unwrap();
    assert!(!loaded.find("alice").unwrap().is_enabled);

    cmd_enable(&path, "alice").unwrap();
    let loaded = UsersConfig::load(&path).unwrap();
    assert!(loaded.find("alice").unwrap().is_enabled);
}

#[test]
fn set_password_changes_hash_and_old_no_longer_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_users_path(dir.path());
    let mut prompt = fixed_prompt("old-pass");

    cmd_add(&path, "alice", &mut prompt, false, None, None).unwrap();
    let old_hash = UsersConfig::load(&path)
        .unwrap()
        .find("alice")
        .unwrap()
        .hash
        .clone();

    let mut prompt2 = fixed_prompt("new-pass");
    cmd_set_password(&path, "alice", &mut prompt2).unwrap();

    let loaded = UsersConfig::load(&path).unwrap();
    let new_hash = &loaded.find("alice").unwrap().hash;
    assert_ne!(old_hash, *new_hash, "hash must have changed");
    assert!(
        !verify_hash(&old_hash, "new-pass").unwrap(),
        "old hash must not verify new password"
    );
    assert!(
        verify_hash(new_hash, "new-pass").unwrap(),
        "new hash must verify new password"
    );
}

#[test]
fn list_returns_rows_in_insertion_order() {
    let users = UsersConfig {
            users: vec![
                User {
                    name: "charlie".into(),
                    hash: "$argon2id$v=19$m=5120,t=2,p=1$AAAAAAAAAAAAAAAAAAAA$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".into(),
                    is_enabled: true,
                    allowed_onion: false,
                    allowed_clients: None,
                    pre_socks5: None,
                    post_socks5: None,
                },
                User {
                    name: "alice".into(),
                    hash: "$argon2id$v=19$m=5120,t=2,p=1$CCCCCCCCCCCCCCCCCCCC$DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD".into(),
                    is_enabled: false,
                    allowed_onion: true,
                    allowed_clients: None,
                    pre_socks5: None,
                    post_socks5: None,
                },
            ],
        };

    let table = render_list(&users);
    let lines: Vec<&str> = table.lines().collect();
    assert_eq!(lines.len(), 3, "header + 2 users");
    assert!(lines[0].contains("NAME"));
    assert!(lines[0].contains("ENABLED"));
    assert!(lines[0].contains("ONION"));
    assert!(lines[0].contains("HASH-PREVIEW"));
    assert!(lines[1].contains("charlie"));
    assert!(lines[1].contains("yes"));
    assert!(lines[2].contains("alice"));
    assert!(lines[2].contains("no"));
}

#[test]
fn enable_errors_on_missing() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_users_path(dir.path());
    let err = cmd_enable(&path, "ghost").unwrap_err();
    assert!(format!("{err}").contains("does not exist"));
}

#[test]
fn disable_errors_on_missing() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_users_path(dir.path());
    let err = cmd_disable(&path, "ghost").unwrap_err();
    assert!(format!("{err}").contains("does not exist"));
}

#[test]
fn set_password_errors_on_missing() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_users_path(dir.path());
    let mut prompt = fixed_prompt("pw");
    let err = cmd_set_password(&path, "ghost", &mut prompt).unwrap_err();
    assert!(format!("{err}").contains("does not exist"));
}

// -- render_list edge cases ---

#[test]
fn render_list_long_username() {
    let users = UsersConfig {
        users: vec![User {
            name: "a_very_long_username_that_exceeds_twenty_chars".into(),
            hash: "$argon2id$v=19$m=5120,t=2,p=1$salt$hash_value_here".into(),
            is_enabled: true,
            allowed_onion: false,
            allowed_clients: None,
            pre_socks5: None,
            post_socks5: None,
        }],
    };
    let table = render_list(&users);
    assert!(table.contains("a_very_long_username_that_exceeds_twenty_chars"));
}

#[test]
fn render_list_short_hash_no_truncation() {
    let users = UsersConfig {
        users: vec![User {
            name: "bob".into(),
            hash: "short".into(),
            is_enabled: true,
            allowed_onion: false,
            allowed_clients: None,
            pre_socks5: None,
            post_socks5: None,
        }],
    };
    let table = render_list(&users);
    assert!(table.contains("short"));
    assert!(!table.contains('…'));
}

#[test]
fn render_list_disabled_user_shows_no() {
    let users = UsersConfig {
        users: vec![User {
            name: "eve".into(),
            hash: "$argon2id$v=19$m=5120,t=2,p=1$AAAA$BBBB_enough_length_for_preview".into(),
            is_enabled: false,
            allowed_onion: false,
            allowed_clients: None,
            pre_socks5: None,
            post_socks5: None,
        }],
    };
    let table = render_list(&users);
    let user_line = table.lines().nth(1).expect("should have user line");
    assert!(user_line.contains("no"));
}

#[test]
fn render_list_empty_config() {
    let users = UsersConfig { users: vec![] };
    let table = render_list(&users);
    assert!(table.contains("NAME"));
    assert_eq!(table.lines().count(), 1, "only header, no user rows");
}

#[test]
fn add_mismatch_error_does_not_leak_password() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_users_path(dir.path());
    let mut prompt = mismatch_prompt("s3cret", "0ther");

    let err = cmd_add(&path, "alice", &mut prompt, false, None, None).unwrap_err();
    let msg = format!("{err}");
    assert!(!msg.contains("s3cret"), "error must not contain password");
    assert!(!msg.contains("0ther"), "error must not contain confirm");
}

/// TS17-07: when the registry's transaction lock is held longer than
/// the CLI wait, the command must fail with the clear busy error —
/// not hang behind the holder.
#[test]
fn set_password_fails_with_busy_error_when_lock_is_held_too_long() {
    use std::sync::{Arc, Mutex};

    let dir = tempfile::tempdir().unwrap();
    let path = tmp_users_path(dir.path());
    UsersConfig {
        users: vec![User {
            name: "alice".into(),
            hash: compute_hash("pw").unwrap(),
            is_enabled: true,
            allowed_onion: false,
            allowed_clients: None,
            pre_socks5: None,
            post_socks5: None,
        }],
    }
    .save(&path)
    .unwrap();

    // Park a lock holder deterministically: it signals only after
    // `PathLock::acquire` returned, and parks until released. The
    // parked flag lives in the channel, never in the guard itself.
    let (acq_tx, acq_rx) = std::sync::mpsc::channel::<()>();
    let (rel_tx, rel_rx) = std::sync::mpsc::channel::<()>();
    let rel_rx = Arc::new(Mutex::new(rel_rx));
    let rel_rx_holder = Arc::clone(&rel_rx);
    let holder_path = path.clone();
    let holder = std::thread::spawn(move || {
        let lock = persist_lock::PathLock::acquire(&holder_path).unwrap();
        acq_tx.send(()).ok();
        let _ = rel_rx_holder
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(10));
        drop(lock);
    });
    acq_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("holder took the registry lock");

    LOCK_WAIT_OVERRIDE_MS.store(150, Ordering::Relaxed);
    let mut prompt = fixed_prompt("new-pass");
    let err = cmd_set_password(&path, "alice", &mut prompt).unwrap_err();
    LOCK_WAIT_OVERRIDE_MS.store(0, Ordering::Relaxed);
    rel_tx.send(()).ok();
    holder.join().unwrap();

    let msg = format!("{err}");
    assert!(
        msg.contains("busy"),
        "expected the clear busy error, got: {msg}"
    );
    assert!(
        msg.contains(".lock"),
        "error must name the lock file, got: {msg}"
    );
    // The failed transaction must not have touched the registry.
    let loaded = UsersConfig::load(&path).unwrap();
    assert!(verify_hash(&loaded.find("alice").unwrap().hash, "pw").unwrap());
}

#[test]
fn set_socks5_updates_only_selected_hop_and_round_trips_inherit_and_none() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_users_path(dir.path());
    cmd_add_init(&path, "alice", false, None, None).unwrap();
    cmd_set_socks5(&path, "alice", "pre", "127.0.0.1:1080").unwrap();
    cmd_set_socks5(&path, "alice", "post", "none").unwrap();

    let loaded = UsersConfig::load(&path).unwrap();
    let alice = loaded.find("alice").unwrap();
    assert_eq!(
        alice.pre_socks5,
        Some(EndpointOverride::Endpoint(
            "127.0.0.1:1080".parse().unwrap()
        ))
    );
    assert_eq!(alice.post_socks5, Some(EndpointOverride::Disabled));

    cmd_set_socks5(&path, "alice", "pre", "inherit").unwrap();
    cmd_set_socks5(&path, "alice", "post", "inherit").unwrap();
    let loaded = UsersConfig::load(&path).unwrap();
    let alice = loaded.find("alice").unwrap();
    assert_eq!(alice.pre_socks5, None);
    assert_eq!(alice.post_socks5, None);
}

#[test]
fn set_socks5_invalid_endpoint_preserves_saved_data() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_users_path(dir.path());
    cmd_add_init(&path, "alice", false, None, None).unwrap();
    cmd_set_socks5(&path, "alice", "pre", "127.0.0.1:1080").unwrap();
    cmd_set_socks5(&path, "alice", "post", "none").unwrap();
    let before = std::fs::read(&path).unwrap();

    let err = cmd_set_socks5(&path, "alice", "pre", "not-an-endpoint").unwrap_err();

    assert!(format!("{err}").contains("invalid SOCKS5 endpoint"));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let loaded = UsersConfig::load(&path).unwrap();
    let alice = loaded.find("alice").unwrap();
    assert_eq!(
        alice.pre_socks5,
        Some(EndpointOverride::Endpoint(
            "127.0.0.1:1080".parse().unwrap()
        ))
    );
    assert_eq!(alice.post_socks5, Some(EndpointOverride::Disabled));
}

#[test]
fn set_socks5_rejects_unknown_hop_without_changing_saved_data() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_users_path(dir.path());
    cmd_add_init(&path, "alice", false, None, None).unwrap();
    let before = std::fs::read(&path).unwrap();
    assert!(cmd_set_socks5(&path, "alice", "middle", "none").is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn real_cli_writers_preserve_allowed_clients() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_users_path(dir.path());
    let mut prompt = fixed_prompt("secret123");
    cmd_add(&path, "alice", &mut prompt, false, None, None).unwrap();
    // Ручная правка users.ktav: оператор задаёт per-user ACL.
    let mut cfg = UsersConfig::load(&path).unwrap();
    cfg.find_mut("alice").unwrap().allowed_clients =
        Some("loopback".parse().expect("valid allow-list"));
    cfg.save(&path).unwrap();
    // Реальные CLI-мутации не должны терять поле.
    cmd_set_onion(&path, "alice", true).unwrap();
    cmd_set_password(&path, "alice", &mut fixed_prompt("newpass456")).unwrap();
    cmd_disable(&path, "alice").unwrap();
    let reloaded = UsersConfig::load(&path).unwrap();
    let alice = reloaded.find("alice").unwrap();
    assert_eq!(
        alice
            .allowed_clients
            .as_ref()
            .expect("ACL пережил CLI-мутации")
            .as_str(),
        "loopback"
    );
    assert!(alice.allowed_onion);
    assert!(!alice.is_enabled);
    assert!(verify_hash(&alice.hash, "newpass456").unwrap());
}
