use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use client_acl::PoolOverride;
use persist_lock::PathLock;

use super::*;
use crate::compute_hash::verify_hash;
use crate::state::INIT_SENTINEL;

/// A scratch directory removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "tor-socks5-auth-registry-ops-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn registry(&self) -> Registry {
        Registry::new(self.0.join("t.users.ktav"))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn new_user(name: &str) -> NewUser {
    NewUser {
        name: name.to_string(),
        ..NewUser::default()
    }
}

#[test]
fn add_stores_a_verifiable_hash_and_rejects_a_duplicate() {
    let dir = Scratch::new("add");
    let registry = dir.registry();
    registry.add(new_user("alice"), "secret").unwrap();

    let users = registry.load().unwrap();
    let alice = users.find("alice").unwrap();
    assert!(alice.is_enabled && !alice.allowed_onion);
    assert!(verify_hash(&alice.hash, "secret").unwrap());

    let err = registry.add(new_user("alice"), "other").unwrap_err();
    assert!(matches!(err, RegistryError::AlreadyExists(ref n) if n == "alice"));
    assert!(matches!(
        registry.ensure_absent("alice"),
        Err(RegistryError::AlreadyExists(_))
    ));
    assert!(registry.ensure_absent("bob").is_ok());
}

#[test]
fn add_rejects_an_empty_password() {
    let dir = Scratch::new("empty");
    let registry = dir.registry();
    let err = registry.add(new_user("alice"), "").unwrap_err();
    assert!(matches!(err, RegistryError::EmptyPassword));
    assert!(registry.load().unwrap().users.is_empty());
}

#[test]
fn init_account_gets_a_real_password_later() {
    let dir = Scratch::new("init");
    let registry = dir.registry();
    registry.add_init(new_user("alice")).unwrap();
    assert_eq!(
        registry.load().unwrap().find("alice").unwrap().hash,
        INIT_SENTINEL
    );

    registry.set_password("alice", "real-pass").unwrap();
    let hash = registry.load().unwrap().find("alice").unwrap().hash.clone();
    assert_ne!(hash, INIT_SENTINEL);
    assert!(verify_hash(&hash, "real-pass").unwrap());
}

#[test]
fn unknown_account_is_not_found_by_every_mutation() {
    let dir = Scratch::new("missing");
    let registry = dir.registry();
    assert!(matches!(
        registry.remove("ghost"),
        Err(RegistryError::NotFound(_))
    ));
    assert!(matches!(
        registry.set_enabled("ghost", false),
        Err(RegistryError::NotFound(_))
    ));
    assert!(matches!(
        registry.set_onion("ghost", true),
        Err(RegistryError::NotFound(_))
    ));
    assert!(matches!(
        registry.set_proxies("ghost", Hop::Pre, None),
        Err(RegistryError::NotFound(_))
    ));
    assert!(matches!(
        registry.ensure_present("ghost"),
        Err(RegistryError::NotFound(_))
    ));
}

#[test]
fn flags_and_one_hop_change_independently_and_remove_deletes() {
    let dir = Scratch::new("flags");
    let registry = dir.registry();
    registry.add_init(new_user("alice")).unwrap();

    registry.set_enabled("alice", false).unwrap();
    registry.set_onion("alice", true).unwrap();
    registry
        .set_proxies("alice", Hop::Pre, Some(PoolOverride::Disabled))
        .unwrap();

    let users = registry.load().unwrap();
    let alice = users.find("alice").unwrap();
    assert!(!alice.is_enabled && alice.allowed_onion);
    assert!(matches!(alice.pre_proxies, Some(PoolOverride::Disabled)));
    assert!(alice.post_proxies.is_none());

    registry.remove("alice").unwrap();
    assert!(registry.load().unwrap().users.is_empty());
}

#[test]
fn busy_lock_is_reported_and_leaves_the_registry_untouched() {
    let dir = Scratch::new("busy");
    let registry = dir.registry().with_lock_wait(Duration::from_millis(150));
    registry.add_init(new_user("alice")).unwrap();

    let held = PathLock::acquire(registry.path()).unwrap();
    let err = registry.set_enabled("alice", false).unwrap_err();
    drop(held);

    assert!(matches!(err, RegistryError::Storage(_)));
    assert!(err.to_string().contains("busy"), "got: {err}");
    assert!(registry.load().unwrap().find("alice").unwrap().is_enabled);
}

#[test]
fn pool_text_form_and_hop_names_parse() {
    assert!(matches!(parse_pool_override(&[]), Ok(None)));
    assert!(matches!(
        parse_pool_override(&["inherit".to_string()]),
        Ok(None)
    ));
    assert!(matches!(
        parse_pool_override(&["none".to_string()]),
        Ok(Some(PoolOverride::Disabled))
    ));
    assert!(matches!(
        parse_pool_override(&["127.0.0.1:1080".to_string()]),
        Ok(Some(PoolOverride::Pool(_)))
    ));
    assert!(matches!(
        parse_pool_override(&["not an endpoint".to_string()]),
        Err(RegistryError::InvalidEndpoint)
    ));

    assert_eq!("pre".parse::<Hop>().unwrap(), Hop::Pre);
    assert_eq!("post".parse::<Hop>().unwrap(), Hop::Post);
    assert!(matches!(
        "middle".parse::<Hop>(),
        Err(RegistryError::InvalidHop)
    ));
}
