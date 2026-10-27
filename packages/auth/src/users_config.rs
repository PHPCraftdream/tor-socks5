//! On-disk users registry.
//!
//! Stored as a single Ktav file next to the active main config — the
//! file name mirrors the main config stem, e.g.:
//!
//! ```text
//! tor-socks5.ktav         (main config)
//! tor-socks5.users.ktav   (users registry — this module)
//! ```
//!
//! Schema (single top-level field, an array of user records):
//!
//! ```ktav
//! users: [
//!     { name: alice, hash: $argon2id$..., is_enabled: true }
//!     { name: bob,   hash: $argon2id$..., is_enabled: false }
//! ]
//! ```

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::user::User;

const DEFAULT_FILE: &str = "tor-socks5.users.ktav";

/// Monotonic counter giving every save() call a unique temp-file name, even
/// when saves run concurrently within one process.
static SAVE_SEQ: AtomicU64 = AtomicU64::new(0);

/// The on-disk users registry: the account list backed by a single
/// Ktav file. Read with [`load`](Self::load), written back atomically
/// with [`save`](Self::save); see the module docs for the file layout.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UsersConfig {
    /// The known accounts, in the order they appear in the file.
    /// Lookups by name ([`find`](Self::find) / [`find_mut`](Self::find_mut))
    /// scan this vector linearly, so a duplicate `name` means only the
    /// first record ever matches.
    pub users: Vec<User>,
}

impl UsersConfig {
    /// Resolve the users-file path given the main config path. The
    /// rule mirrors `bridge_store` and `alive-bridges.log`: same
    /// directory, same stem, fixed `.users.ktav` suffix. Falls back to
    /// `./tor-socks5.users.ktav` when the main config came from
    /// built-in defaults (no path on disk).
    pub fn resolve_path(config_path: Option<&Path>) -> PathBuf {
        match config_path {
            Some(cfg) => {
                let dir = cfg.parent().unwrap_or_else(|| Path::new("."));
                let stem = cfg
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "tor-socks5".to_string());
                dir.join(format!("{stem}.users.ktav"))
            }
            None => PathBuf::from(DEFAULT_FILE),
        }
    }

    /// Load the registry from disk. A missing file is **not** an error
    /// — it means "no users configured" and yields an empty registry.
    pub fn load(path: &Path) -> Result<Self> {
        match fs::read_to_string(path) {
            Ok(src) => {
                let cfg: UsersConfig = ktav::from_str(&src)
                    .with_context(|| format!("parsing Ktav users file {}", path.display()))?;
                Ok(cfg)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(UsersConfig::default()),
            Err(e) => Err(e).with_context(|| format!("reading users file {}", path.display())),
        }
    }

    /// Atomic write via [`persist_lock::TempFileGuard`]: a sibling temp
    /// whose canonical name is built and recognised by the one
    /// builder/recogniser pair (`persist_lock::temp_file_name` /
    /// `parse_temp_name`), owned for the whole create→rename span by an
    /// advisory exclusive lock on a companion `<temp>.lock` file, so a
    /// concurrent reader's stale-temp cleanup only deletes a temp whose
    /// owner provably died (TS17-01/04 class). The final rename is
    /// atomic: readers see the old or the new full file, never a torn
    /// one. Creates the parent directory if missing.
    pub fn save(&self, path: &Path) -> Result<()> {
        let body = ktav::to_string(self).context("serialise users config")?;
        let seq = SAVE_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut guard = persist_lock::TempFileGuard::create(path, seq)?;
        guard
            .write_all(body.as_bytes())
            .with_context(|| format!("write {}", guard.temp_path().display()))?;
        guard
            .finish()
            .with_context(|| format!("publish {}", path.display()))?;
        Ok(())
    }

    /// Locate a user by name. Returns `None` if no such record exists.
    pub fn find(&self, name: &str) -> Option<&User> {
        self.users.iter().find(|u| u.name == name)
    }

    /// Locate a user by name (mutable). Returns `None` if no such
    /// record exists.
    pub fn find_mut(&mut self, name: &str) -> Option<&mut User> {
        self.users.iter_mut().find(|u| u.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "tor-socks5-auth-users-test-{}-{}",
            std::process::id(),
            seq
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn user(name: &str, enabled: bool) -> User {
        User {
            name: name.into(),
            hash: "$argon2id$v=19$m=5120,t=2,p=1$AAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            is_enabled: enabled,
            allowed_onion: false,
            allowed_clients: None,
            pre_socks5: None,
            post_socks5: None,
        }
    }

    #[test]
    fn allowed_clients_absent_defaults_to_none() {
        // Старый ktav-формат без поля: ограничения нет (None), а не `*`.
        let raw = r#"
name: alice
hash: $argon2id$v=19$m=5120,t=2,p=1$salt$hash
is_enabled: true
"#;
        let user: User = ktav::from_str(raw).expect("parse without allowed_clients");
        assert!(user.allowed_clients.is_none());
    }

    #[test]
    fn allowed_clients_scalar_parses_and_allows() {
        // Явный скаляр (грамматика client-acl: без CIDR), compile-эквивалент:
        // allows() разрешает адрес из списка и отвергает соседний.
        let raw = r#"
name: alice
hash: $argon2id$v=19$m=5120,t=2,p=1$salt$hash
allowed_clients: 192.0.2.*
"#;
        let user: User = ktav::from_str(raw).expect("parse with allowed_clients");
        let policy = user.allowed_clients.as_ref().expect("policy loaded");
        assert_eq!(policy.as_str(), "192.0.2.*");
        assert!(policy.allows("192.0.2.7".parse().unwrap()));
        assert!(!policy.allows("192.0.3.7".parse().unwrap()));
    }

    #[test]
    fn allowed_clients_roundtrips_through_save_load() {
        let dir = tmp_dir();
        let path = dir.join("users-acl.ktav");
        let mut u = user("alice", true);
        u.allowed_clients = Some("192.0.2.*".parse().expect("valid allow-list"));
        UsersConfig { users: vec![u] }.save(&path).unwrap();

        let reloaded = UsersConfig::load(&path).unwrap();
        let policy = reloaded
            .find("alice")
            .unwrap()
            .allowed_clients
            .as_ref()
            .expect("policy survives roundtrip");
        assert_eq!(policy.as_str(), "192.0.2.*");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn allowed_clients_empty_string_is_acl_error_not_ktav_syntax() {
        // `key::` — ktav-маркер литеральной пустой строки: она доходит до
        // AllowedClients::from_str, и ошибка — именно ACL-причина
        // («invalid `allowed_clients` token … list is empty»), а не
        // синтаксическая ошибка ktav. Различаем по подстрокам причины.
        let raw = r#"
name: alice
hash: $argon2id$v=19$m=5120,t=2,p=1$salt$hash
allowed_clients::
"#;
        let error = ktav::from_str::<User>(raw).unwrap_err().to_string();
        assert!(
            error.contains("allowed_clients") && error.contains("list is empty"),
            "ожидалась ACL-ошибка пустого списка, получено: {error}"
        );

        // Невалидный токен — тоже ACL-ошибка с причиной токена.
        let bad = r#"
name: alice
hash: $argon2id$v=19$m=5120,t=2,p=1$salt$hash
allowed_clients: 192.168.1*
"#;
        let error = ktav::from_str::<User>(bad).unwrap_err().to_string();
        assert!(
            error.contains("allowed_clients"),
            "ожидалась ACL-ошибка токена, получено: {error}"
        );
    }

    #[test]
    fn resolve_path_uses_config_dir_and_stem() {
        let p = UsersConfig::resolve_path(Some(Path::new("/etc/tor-socks5.ktav")));
        assert_eq!(
            p.file_name().unwrap().to_string_lossy(),
            "tor-socks5.users.ktav"
        );
        assert_eq!(
            p.parent().unwrap().to_string_lossy().replace('\\', "/"),
            "/etc"
        );
    }

    #[test]
    fn resolve_path_falls_back_for_defaults() {
        let p = UsersConfig::resolve_path(None);
        assert_eq!(p, PathBuf::from(DEFAULT_FILE));
    }

    #[test]
    fn missing_file_loads_as_empty_registry() {
        let dir = tmp_dir();
        let cfg = UsersConfig::load(&dir.join("nope.ktav")).unwrap();
        assert!(cfg.users.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn socks5_overrides_omitted_disabled_and_endpoint_survive_registry_save_load() {
        use client_acl::{EndpointOverride, Socks5Endpoint};

        let dir = tmp_dir();
        let path = dir.join("users-socks5.ktav");
        fs::write(
            &path,
            "users: [{ name: legacy, hash: old-hash }]\n",
        )
        .unwrap();
        let legacy = UsersConfig::load(&path).unwrap();
        assert!(legacy.find("legacy").unwrap().pre_socks5.is_none());
        assert!(legacy.find("legacy").unwrap().post_socks5.is_none());
        assert!(legacy.find("missing").is_none());

        let mut legacy = legacy;
        let legacy_user = legacy.find_mut("legacy").unwrap();
        legacy_user.pre_socks5 = Some(EndpointOverride::Disabled);
        legacy_user.post_socks5 = Some(EndpointOverride::Endpoint(
            "[2001:db8::5]:1081|user:pass".parse::<Socks5Endpoint>().unwrap(),
        ));
        legacy.save(&path).unwrap();

        let loaded = UsersConfig::load(&path).unwrap();
        let user = loaded.find("legacy").unwrap();
        assert_eq!(user.pre_socks5, Some(EndpointOverride::Disabled));
        let Some(EndpointOverride::Endpoint(endpoint)) = &user.post_socks5 else {
            panic!("post SOCKS endpoint must survive registry persistence");
        };
        assert_eq!(endpoint.address().to_string(), "[2001:db8::5]:1081");
        assert_eq!(endpoint.credentials(), Some(("user", "pass")));
        assert!(loaded.find("other").is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_then_load_roundtrip() {
        let dir = tmp_dir();
        let path = dir.join("users.ktav");
        let cfg = UsersConfig {
            users: vec![user("alice", true), user("bob", false)],
        };
        cfg.save(&path).unwrap();

        let reloaded = UsersConfig::load(&path).unwrap();
        assert_eq!(reloaded.users.len(), 2);
        assert_eq!(reloaded.users[0].name, "alice");
        assert!(reloaded.users[0].is_enabled);
        assert_eq!(reloaded.users[1].name, "bob");
        assert!(!reloaded.users[1].is_enabled);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn writer_mutation_preserves_allowed_clients_through_save_load() {
        // Существующий writer (password/onion/enabled) через find_mut НЕ
        // теряет allowed_clients остальных/той же записи: реальный
        // UsersConfig roundtrip, не derive-clone в памяти.
        let dir = tmp_dir();
        let path = dir.join("users-writer-acl.ktav");
        let mut alice = user("alice", true);
        alice.allowed_clients = Some("192.0.2.*".parse().expect("valid allow-list"));
        UsersConfig {
            users: vec![alice, user("bob", true)],
        }
        .save(&path)
        .unwrap();

        // CLI-стиль правки: смена hash/onion/enabled через find_mut.
        let mut cfg = UsersConfig::load(&path).unwrap();
        cfg.find_mut("alice").unwrap().allowed_onion = true;
        cfg.find_mut("alice").unwrap().is_enabled = false;
        cfg.find_mut("alice").unwrap().hash =
            "$argon2id$v=19$m=5120,t=2,p=1$BBBBBBBBBBBBBBBBBBBB$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".into();
        cfg.save(&path).unwrap();

        let reloaded = UsersConfig::load(&path).unwrap();
        let alice = reloaded.find("alice").unwrap();
        assert!(alice.allowed_onion);
        assert_eq!(
            alice
                .allowed_clients
                .as_ref()
                .expect("ACL alice на месте")
                .as_str(),
            "192.0.2.*"
        );
        assert!(!alice.is_enabled);
        assert_eq!(
            alice.hash,
            "$argon2id$v=19$m=5120,t=2,p=1$BBBBBBBBBBBBBBBBBBBB$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        );
        let bob = reloaded.find("bob").unwrap();
        assert!(bob.is_enabled);
        assert!(bob.allowed_clients.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn find_returns_match_or_none() {
        let cfg = UsersConfig {
            users: vec![user("alice", true), user("bob", true)],
        };
        assert!(cfg.find("alice").is_some());
        assert!(cfg.find("nobody").is_none());
    }

    #[test]
    fn save_overwrites_existing_file_atomically() {
        let dir = tmp_dir();
        let path = dir.join("users.ktav");

        UsersConfig {
            users: vec![user("alice", true)],
        }
        .save(&path)
        .unwrap();

        UsersConfig {
            users: vec![user("bob", true)],
        }
        .save(&path)
        .unwrap();

        let reloaded = UsersConfig::load(&path).unwrap();
        assert_eq!(reloaded.users.len(), 1);
        assert_eq!(reloaded.users[0].name, "bob");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_concurrent_calls_all_succeed_and_leave_no_temp_files() {
        let dir = tmp_dir();
        let path = dir.join("users.ktav");

        let handles: Vec<_> = (0..8)
            .map(|i| {
                let path = path.clone();
                std::thread::spawn(move || {
                    UsersConfig {
                        users: vec![user(&format!("t{i}"), true)],
                    }
                    .save(&path)
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap().expect("every concurrent save succeeds");
        }

        let loaded = UsersConfig::load(&path).unwrap();
        assert_eq!(loaded.users.len(), 1, "last writer wins, file loads fine");

        // No leftover temp files.
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "leftover temp files: {leftovers:?}");

        let _ = fs::remove_dir_all(&dir);
    }
}
