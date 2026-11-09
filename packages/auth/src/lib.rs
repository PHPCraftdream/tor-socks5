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
#![warn(missing_docs)]

mod compute_hash;
mod params;
mod state;
mod user;
mod users_config;

#[cfg(test)]
mod registry_lock_tests;

pub use compute_hash::{compute_hash, verify_hash};
pub use params::{argon2_instance, ARGON_M_KIB, ARGON_P, ARGON_T};
pub use state::{AdmissionLease, AuthState, CredentialProof, INIT_SENTINEL};
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
    fn user_pre_and_post_overrides_resolve_independently_of_global_values() {
        use client_acl::{resolve_endpoint, EndpointOverride};

        let global_pre = Some(EndpointOverride::Endpoint(
            "192.0.2.1:1080".parse().unwrap(),
        ));
        let global_post = Some(EndpointOverride::Endpoint(
            "192.0.2.2:1080".parse().unwrap(),
        ));
        let user_pre = Some(EndpointOverride::Disabled);
        let user_post = Some(EndpointOverride::Endpoint(
            "198.51.100.2:1080".parse().unwrap(),
        ));

        let resolved_pre = resolve_endpoint(global_pre.as_ref(), user_pre.as_ref());
        let resolved_post = resolve_endpoint(global_post.as_ref(), user_post.as_ref());
        assert!(resolved_pre.is_none());
        assert_eq!(
            resolved_post.unwrap().address().to_string(),
            "198.51.100.2:1080"
        );

        let inherited_pre = resolve_endpoint(global_pre.as_ref(), None).unwrap();
        let inherited_post = resolve_endpoint(global_post.as_ref(), None).unwrap();
        assert_eq!(inherited_pre.address().to_string(), "192.0.2.1:1080");
        assert_eq!(inherited_post.address().to_string(), "192.0.2.2:1080");
        assert!(resolve_endpoint(global_post.as_ref(), user_pre.as_ref()).is_none());
        assert_eq!(
            resolve_endpoint(global_pre.as_ref(), user_post.as_ref())
                .unwrap()
                .address()
                .to_string(),
            "198.51.100.2:1080"
        );
    }

    #[test]
    fn user_socks_chain_states_roundtrip_and_fail_closed() {
        let old = r#"
name: alice
hash: $argon2id$v=19$m=5120,t=2,p=1$salt$hash
"#;
        let inherited: User = ktav::from_str(old).expect("legacy account");
        assert!(inherited.pre_socks5.is_none());
        let explicit = r#"
name: alice
hash: $argon2id$v=19$m=5120,t=2,p=1$salt$hash
pre_socks5: none
post_socks5: 192.0.2.1:1080|u:p
"#;
        let user: User = ktav::from_str(explicit).expect("overrides");
        assert_eq!(
            user.pre_socks5,
            Some(client_acl::EndpointOverride::Disabled)
        );
        let saved = ktav::to_string(&user).expect("serialize");
        assert!(saved.contains("pre_socks5: none"));
        let restored: User = ktav::from_str(&saved).expect("roundtrip");
        assert_eq!(restored.pre_socks5, user.pre_socks5);
        assert_eq!(restored.post_socks5, user.post_socks5);
        assert!(ktav::from_str::<User>(
            &explicit.replace("192.0.2.1:1080|u:p", "proxy.invalid:1080")
        )
        .is_err());
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
            allowed_clients: None,
            pre_socks5: None,
            post_socks5: None,
        };
        let state = AuthState::build(&UsersConfig { users: vec![user] }).unwrap();
        assert!(!state.verify("mallory", "anything"));
    }
}

/// Тесты per-user ACL (`AuthState::client_allowed`). Живут здесь, а не в
/// новом файле: лимит <=7 записей .rs в src/ уже исчерпан.
#[cfg(test)]
mod user_acl_tests {
    use std::net::IpAddr;

    use super::*;
    use crate::compute_hash::compute_hash;

    fn acl_user(name: &str, acl: &str) -> User {
        User {
            name: name.into(),
            hash: compute_hash("pw").unwrap(),
            is_enabled: true,
            allowed_onion: false,
            allowed_clients: Some(acl.parse().expect("valid allow-list")),
            pre_socks5: None,
            post_socks5: None,
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn tmp_dir() -> std::path::PathBuf {
        // Уникальный каталог + cleanup только своего артефакта (как в
        // users_config::tests::tmp_dir).
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        for _ in 0..64 {
            let seq = SEQ.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "tor-socks5-auth-acl-test-{}-{seq}",
                std::process::id()
            ));
            match std::fs::create_dir(&dir) {
                Ok(()) => return dir,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("не удалось создать каталог теста: {error}"),
            }
        }
        panic!("не удалось выделить свободный каталог теста");
    }

    #[test]
    fn wildcard_policy_allows_any_peer() {
        let s = AuthState::build(&UsersConfig {
            users: vec![acl_user("alice", "*")],
        })
        .unwrap();
        assert!(s.client_allowed("alice", ip("192.0.2.1")));
        assert!(s.client_allowed("alice", ip("2001:db8::1")));
        assert!(s.client_allowed("alice", ip("::ffff:10.0.0.1")));
    }

    #[test]
    fn exact_policy_denies_other_peer() {
        let s = AuthState::build(&UsersConfig {
            users: vec![acl_user("alice", "192.0.2.1")],
        })
        .unwrap();
        assert!(s.client_allowed("alice", ip("192.0.2.1")));
        assert!(!s.client_allowed("alice", ip("192.0.2.2")));
    }

    #[test]
    fn none_policy_allows_everyone() {
        let s = AuthState::build(&UsersConfig {
            users: vec![User {
                name: "alice".into(),
                hash: compute_hash("pw").unwrap(),
                is_enabled: true,
                allowed_onion: false,
                allowed_clients: None,
                pre_socks5: None,
                post_socks5: None,
            }],
        })
        .unwrap();
        assert!(s.client_allowed("alice", ip("192.0.2.1")));
        assert!(s.client_allowed("alice", ip("2001:db8::1")));
    }

    #[test]
    fn unknown_or_disabled_user_is_denied() {
        // Неизвестный/выключенный пользователь НЕ означает unrestricted.
        let s = AuthState::build(&UsersConfig {
            users: vec![User {
                name: "alice".into(),
                hash: compute_hash("pw").unwrap(),
                is_enabled: false,
                allowed_onion: false,
                allowed_clients: None,
                pre_socks5: None,
                post_socks5: None,
            }],
        })
        .unwrap();
        assert!(!s.client_allowed("alice", ip("192.0.2.1")), "disabled");
        assert!(!s.client_allowed("nobody", ip("192.0.2.1")), "unknown");
    }

    #[test]
    fn empty_registry_unknown_user_is_denied() {
        // Пустой snapshot НЕ даёт allow: fail-closed даже когда auth
        // формально «выключен»; no-auth-исключение — забота CALLER'а.
        let s = AuthState::build(&UsersConfig { users: vec![] }).unwrap();
        assert!(!s.require_auth(), "auth выключен (факт)");
        assert!(
            !s.client_allowed("anyone", ip("192.0.2.1")),
            "пустой реестр => deny"
        );
    }

    #[test]
    fn mapped_ipv4_peer_is_normalized() {
        // Нормализацию ::ffff:a.b.c.d делает AllowedClients::allows;
        // проверяем это через реальный путь client_allowed.
        let s = AuthState::build(&UsersConfig {
            users: vec![acl_user("alice", "192.0.2.5")],
        })
        .unwrap();
        assert!(s.client_allowed("alice", ip("::ffff:192.0.2.5")));
        assert!(!s.client_allowed("alice", ip("::ffff:192.0.2.6")));
    }

    #[test]
    fn resolve_init_reload_swaps_acl_snapshot_atomically() {
        // Реальный reload-путь: resolve_init перечитывает диск, и после
        // `*guard = current` политика берётся из НОВОГО User — compiled
        // ACL старого снапшота не остаются в памяти.
        //
        // Дизайн: resolve_init срабатывает только при hash==INIT_SENTINEL
        // В ПАМЯТИ (verify берёт решение по памяти), поэтому каждый reload
        // триггерит свой init-юзер из ИСХОДНОГО снапшота: reload #1 — bob,
        // reload #2 — carol (bob после TOFU уже провижинен в памяти и
        // больше не пойдёт в resolve_init). CLI-правки вносятся на диск
        // синхронно ДО verify — без sleep: re-read внутри resolve_init
        // детерминированно их подхватывает.
        let dir = tmp_dir();
        let path = dir.join("users.ktav");

        let initial = UsersConfig {
            users: vec![
                acl_user("alice", "192.0.2.*"),
                // bob — init с ЯВНЫМ ACL: после TOFU persist поле должно
                // сохраниться (resolve_init пишет current.save целиком).
                User {
                    name: "bob".into(),
                    hash: INIT_SENTINEL.into(),
                    is_enabled: true,
                    allowed_onion: false,
                    allowed_clients: Some("203.0.113.*".parse().expect("valid allow-list")),
                    pre_socks5: None,
                    post_socks5: None,
                },
                User {
                    name: "carol".into(),
                    hash: INIT_SENTINEL.into(),
                    is_enabled: true,
                    allowed_onion: false,
                    allowed_clients: None,
                    pre_socks5: None,
                    post_socks5: None,
                },
            ],
        };
        initial.save(&path).unwrap();
        // Загружаем из файла: bob и carol (INIT_SENTINEL) уже в памяти.
        let s =
            AuthState::build_persistent(&UsersConfig::load(&path).unwrap(), path.clone()).unwrap();
        assert!(s.client_allowed("alice", ip("192.0.2.1")));

        // «CLI-процесс» меняет политику alice на жёсткую на диске.
        let mut cli = UsersConfig::load(&path).unwrap();
        cli.find_mut("alice").unwrap().allowed_clients =
            Some("10.0.0.1".parse().expect("valid allow-list"));
        cli.save(&path).unwrap();

        // Reload #1: TOFU-логин bob'а (init в памяти) проходит через
        // resolve_init: авторитетный re-read коммитит новый снапшот.
        assert!(s.verify("bob", "bob-pw"));

        // Новая политика alice активна, старой уже нет.
        assert!(
            !s.client_allowed("alice", ip("192.0.2.1")),
            "старая политика ушла"
        );
        assert!(
            s.client_allowed("alice", ip("10.0.0.1")),
            "новая политика активна"
        );
        // Явный ACL bob'а пережил persist: resolve_init записал current.save
        // вместе с полем, и в памяти bob тоже с политикой.
        assert!(
            s.client_allowed("bob", ip("203.0.113.7")),
            "ACL bob сохранён"
        );
        assert!(
            !s.client_allowed("bob", ip("198.51.100.1")),
            "ACL bob не стал None"
        );
        let persisted = UsersConfig::load(&path).unwrap();
        assert_eq!(
            persisted
                .find("bob")
                .unwrap()
                .allowed_clients
                .as_ref()
                .unwrap()
                .as_str(),
            "203.0.113.*"
        );

        // «CLI-процесс» удаляет alice на диске.
        let mut cli = UsersConfig::load(&path).unwrap();
        cli.users.retain(|u| u.name != "alice");
        cli.save(&path).unwrap();

        // Reload #2: триггер — carol, ЕЩЁ init в исходном снапшоте памяти
        // (bob уже провижинен: реальный хеш в памяти => verify больше не
        // идёт в resolve_init; verify("carol", ..) — единственный путь).
        assert!(s.verify("carol", "carol-pw"));
        assert!(
            !s.client_allowed("alice", ip("10.0.0.1")),
            "alice удалена => false"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
