//! End-to-end login flow with the `auth` crate: hash a password with
//! Argon2id, build a user registry, and run login attempts through
//! [`auth::AuthState`] — including a disabled account, an unknown one,
//! and a trust-on-first-use `init` account that adopts its first
//! password.
//!
//! Run with: `cargo run --example auth_flow -p tor-socks5-auth`

use std::fs;
use std::path::Path;

use anyhow::Result;
use auth::{compute_hash, verify_hash, AuthState, User, UsersConfig, INIT_SENTINEL};

fn main() -> Result<()> {
    // 1. Hashing primitives: a PHC string in, a constant-work verify out.
    let alice_hash = compute_hash("alice-pass")?;
    println!(
        "alice's hash is an argon2id PHC string: {}",
        alice_hash.starts_with("$argon2id$")
    );
    println!(
        "verify(alice, correct): {}",
        verify_hash(&alice_hash, "alice-pass")?
    );
    println!(
        "verify(alice, wrong):   {}",
        verify_hash(&alice_hash, "wrong")?
    );

    // 2. The on-disk registry schema: enabled, disabled, and
    //    not-yet-provisioned (`init` sentinel) accounts.
    let registry = UsersConfig {
        users: vec![
            User {
                name: "alice".into(),
                hash: alice_hash,
                is_enabled: true,
                allowed_onion: false,
            },
            User {
                name: "bob".into(),
                hash: compute_hash("bob-pass")?,
                is_enabled: false,
                allowed_onion: false,
            },
            User {
                name: "carol".into(),
                hash: INIT_SENTINEL.into(),
                is_enabled: true,
                allowed_onion: false,
            },
        ],
    };

    // 3. The runtime verifier. `build` = no TOFU write-back; a live
    //    daemon would use `AuthState::build_persistent(cfg, users_path)`
    //    so a provisioned `init` password is persisted to the registry.
    let state = AuthState::build(&registry)?;
    println!(
        "\nlistener requires auth: {} ({} user(s))",
        state.require_auth(),
        state.len()
    );

    // 4. Login matrix. A successful verify populates a process-local HMAC
    //    cache bound to the PHC hash snapshot, so the second correct alice
    //    login is answered at HMAC speed instead of another Argon2id pass;
    //    failures are never cached (no brute-force speed-up).
    for (name, password) in [
        ("alice", "alice-pass"),            // correct
        ("alice", "wrong"),                 // mismatch
        ("alice", "alice-pass"),            // correct again: HMAC-cache hit
        ("bob", "bob-pass"),                // disabled: fails like an unknown user
        ("mallory", "x"),                   // unknown user
        ("carol", "carols-first-password"), // TOFU: first password is adopted
        ("carol", "different"),             // too late: carol is provisioned now
        ("carol", "carols-first-password"), // the adopted password works
    ] {
        println!(
            "verify({name:7}, {password:22}) = {}",
            state.verify(name, password)
        );
    }

    // 5. Persistence: the registry saves atomically (temp-file guard +
    //    rename) and the users file lives next to the main config,
    //    sharing its stem.
    let path = std::env::temp_dir().join(format!("auth-example-users-{}.ktav", std::process::id()));
    registry.save(&path)?;
    let reloaded = UsersConfig::load(&path)?;
    println!(
        "\nregistry saved + reloaded: {} user(s)",
        reloaded.users.len()
    );
    println!(
        "next to a config at cfg/myapp.ktav the registry is: {}",
        UsersConfig::resolve_path(Some(Path::new("cfg/myapp.ktav"))).display()
    );
    fs::remove_file(&path)?;
    Ok(())
}
