//! User accounts and password authentication for the proxy's SOCKS5
//! listener. The on-disk format and the runtime verifier mirror the
//! design used by `resocks5`:
//!
//! * Users live in a separate Ktav file next to the main config.
//! * Passwords are hashed with Argon2id (per-user random salt, PHC
//!   serialisation).
//! * A process-local HMAC-SHA256 cache lets repeated successful
//!   logins skip the expensive Argon2 step without giving brute-force
//!   attackers any equivalent speed-up (failures are not cached).
//! * An account whose stored hash is the `init` sentinel adopts the
//!   first non-empty password presented at login (trust-on-first-use)
//!   and the real hash is written back to disk.

mod compute_hash;
mod params;
mod state;
mod user;
mod users_config;

pub use compute_hash::{compute_hash, verify_hash};
pub use params::{argon2_instance, ARGON_M_KIB, ARGON_P, ARGON_T};
pub use state::{AuthState, INIT_SENTINEL};
pub use user::User;
pub use users_config::UsersConfig;

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn argon2_instance_uses_canonical_params() {
        use argon2::password_hash::PasswordHasher;
        let a = argon2_instance();
        let salt = argon2::password_hash::SaltString::from_b64("AAAAAAAAAAAAAAAAAAAAAA")
            .expect("test salt");
        let hash = a.hash_password(b"test", &salt).expect("hash");
        let phc = hash.to_string();
        assert!(phc.contains("argon2id"), "algorithm must be argon2id");
        assert!(phc.contains("v=19"), "version must be 0x13 (19)");
        assert!(
            phc.contains(&format!("m={ARGON_M_KIB}")),
            "memory cost mismatch"
        );
        assert!(phc.contains(&format!("t={ARGON_T}")), "time cost mismatch");
        assert!(
            phc.contains(&format!("p={ARGON_P}")),
            "parallelism mismatch"
        );
    }

    #[test]
    fn user_serde_deny_unknown_fields() {
        let raw = r#"
name: alice
hash: $argon2id$v=19$m=5120,t=2,p=1$salt$hash
is_enabled: true
extra_field: boom
"#;
        let result = ktav::from_str::<User>(raw);
        assert!(result.is_err(), "unknown fields must be rejected");
    }

    #[test]
    fn user_is_enabled_defaults_to_true() {
        let raw = r#"
name: alice
hash: $argon2id$v=19$m=5120,t=2,p=1$salt$hash
"#;
        let user: User = ktav::from_str(raw).expect("parse without is_enabled");
        assert!(user.is_enabled);
    }

    #[test]
    fn user_allowed_onion_defaults_to_false() {
        // A registry written before `allowed_onion` existed must load,
        // with the field defaulting to the conservative `false`.
        let raw = r#"
name: alice
hash: $argon2id$v=19$m=5120,t=2,p=1$salt$hash
is_enabled: true
"#;
        let user: User = ktav::from_str(raw).expect("parse without allowed_onion");
        assert!(!user.allowed_onion);
    }

    #[test]
    fn user_allowed_onion_roundtrips_when_set() {
        let raw = r#"
name: alice
hash: $argon2id$v=19$m=5120,t=2,p=1$salt$hash
is_enabled: true
allowed_onion: true
"#;
        let user: User = ktav::from_str(raw).expect("parse with allowed_onion");
        assert!(user.allowed_onion);
    }

    #[test]
    fn auth_state_empty_config_requires_no_auth() {
        let cfg = UsersConfig { users: vec![] };
        let state = AuthState::build(&cfg).unwrap();
        assert!(!state.require_auth());
        assert!(state.is_empty());
    }

    #[test]
    fn auth_state_verify_nonexistent_user_returns_false() {
        let user = User {
            name: "alice".into(),
            hash: compute_hash("secret").unwrap(),
            is_enabled: true,
            allowed_onion: false,
        };
        let state = AuthState::build(&UsersConfig { users: vec![user] }).unwrap();
        assert!(!state.verify("mallory", "anything"));
    }
}
