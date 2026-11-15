//! Tests for the onion command cores and identity settlement.
//!
//! Pure-library API: every test makes its own temp dir, with the config
//! path and a separate keystore directory inside it (how the directories
//! relate to each other is of no concern to the functions under test).

use std::path::{Path, PathBuf};
use std::time::Duration;

use proxy_config::{Config, IdentityKey, OnionServiceEntry, OnionServicePort};

use super::identity;
use super::ops::{self, NewIdentity};
use super::specifier::{HsIdKeypairSpecifier, HsIdPublicKeySpecifier};
use super::store::{self, KeysError};

/// A temp dir: the config path and the keystore directory live inside it.
struct Temp {
    #[allow(dead_code)]
    dir: tempfile::TempDir,
    config: PathBuf,
    keystore: PathBuf,
}

fn temp() -> Temp {
    let dir = tempfile::tempdir().expect("temp dir");
    Temp {
        config: dir.path().join("tor-socks5.ktav"),
        keystore: dir.path().join("keystore"),
        dir,
    }
}

fn entry(nickname: &str) -> OnionServiceEntry {
    OnionServiceEntry {
        nickname: nickname.to_owned(),
        enabled: true,
        address: None,
        key: None,
        circuit_hops: 4,
        ports: vec![OnionServicePort {
            onion_port: 80,
            target: "127.0.0.1:8080".to_owned(),
        }],
    }
}

fn new_plain(
    config: &Path,
    keystore: &Path,
    nick: &str,
    force: bool,
) -> Result<ops::Recorded, KeysError> {
    ops::create_service(config, keystore, nick, None, force, NewIdentity::Random)
}

fn stored(t: &Temp) -> Vec<OnionServiceEntry> {
    Config::read_onion_services(&t.config).expect("read the file")
}

fn service(t: &Temp, nick: &str) -> OnionServiceEntry {
    stored(t)
        .into_iter()
        .find(|entry| entry.nickname == nick)
        .unwrap_or_else(|| panic!("no service {nick} in the file"))
}

fn address_of(t: &Temp, nick: &str) -> String {
    service(t, nick)
        .address
        .expect("the service has an address")
}

fn keystore_address(t: &Temp, nick: &str) -> Option<String> {
    let keymgr = store::open(&t.keystore).expect("keystore");
    store::address(&keymgr, &store::nickname(nick).expect("nickname")).expect("address")
}

#[test]
fn new_list_show_export_remove_import_roundtrip() {
    let t = temp();

    let recorded = new_plain(&t.config, &t.keystore, "svc", false).expect("new");
    assert!(!recorded.ports_enabled, "no ports: disabled");
    let address_before = address_of(&t, "svc");
    assert!(service(&t, "svc").key.is_some(), "the key is in the file");
    assert_eq!(ops::list_services(&t.config).expect("list").len(), 1);
    assert_eq!(
        ops::show_service(&t.config, "svc").expect("show").address,
        Some(address_before.clone())
    );

    let export = t.dir.path().join("svc.id");
    ops::export_identity(&t.config, "svc", &export, false).expect("export");
    let bytes = std::fs::read(&export).expect("export bytes");
    assert!(!bytes.is_empty());

    // remove, then import restores the same address
    // The library remove has no confirmation guard: `--yes` is the CLI's
    // concern (the CLI shell keeps that guard and tests it there).
    ops::remove_service(&t.config, &t.keystore, "svc").expect("remove");
    assert!(stored(&t).is_empty());
    let recorded =
        ops::import_identity(&t.config, &t.keystore, "svc", &export, None, false).expect("import");
    assert!(!recorded.ports_enabled);
    assert_eq!(address_of(&t, "svc"), address_before);
    ops::show_service(&t.config, "svc").expect("show after import");
}

#[test]
fn re_creating_refuses_without_force_and_forces_to_a_new_address() {
    let t = temp();
    new_plain(&t.config, &t.keystore, "dup", false).expect("first new");
    let address = address_of(&t, "dup");
    let error = new_plain(&t.config, &t.keystore, "dup", false).expect_err("must refuse");
    assert!(
        error
            .to_string()
            .contains("already has an identity; pass --force to replace it"),
        "{error}"
    );
    assert_eq!(address_of(&t, "dup"), address, "address unchanged");
    new_plain(&t.config, &t.keystore, "dup", true).expect("forced new");
    assert_ne!(address_of(&t, "dup"), address);
}

#[test]
fn a_key_left_in_the_keystore_counts_as_an_existing_identity() {
    let t = temp();
    let nick = store::nickname("old").expect("nickname");
    let keymgr = store::open(&t.keystore).expect("keystore");
    store::generate(&keymgr, &nick, false).expect("generate");
    drop(keymgr);
    assert!(
        new_plain(&t.config, &t.keystore, "old", false).is_err(),
        "must refuse"
    );
    new_plain(&t.config, &t.keystore, "old", true).expect("forced new");
    assert!(
        store::identity_file(&t.keystore, &nick).is_none(),
        "the stale keystore copy is dropped: the file is the source"
    );
}

#[test]
fn removing_an_unknown_service_is_typed_not_found_and_creates_nothing() {
    let t = temp();
    let error = ops::remove_service(&t.config, &t.keystore, "nosuch").expect_err("refused");
    assert!(
        matches!(error, KeysError::NotFound(ref name) if name == "nosuch"),
        "{error}"
    );
    assert!(error
        .to_string()
        .contains("no onion service named \"nosuch\""));
    assert!(
        !Config::onion_path(&t.config).exists(),
        "the failed removal must not create the file"
    );
    // And after a real creation, removing a second unknown one must not
    // touch the existing entries (no needless rewrite).
    new_plain(&t.config, &t.keystore, "keep", false).expect("new");
    assert!(ops::remove_service(&t.config, &t.keystore, "nosuch").is_err());
    assert_eq!(stored(&t).len(), 1);
}

#[test]
fn import_of_garbage_records_nothing() {
    let t = temp();
    let garbage = t.dir.path().join("garbage.id");
    std::fs::write(&garbage, b"definitely not an ssh key").expect("write garbage");
    let error = ops::import_identity(&t.config, &t.keystore, "svc", &garbage, None, false)
        .expect_err("refused");
    assert!(
        format!("{error:#}").contains("parsing the identity key file"),
        "{error:#}"
    );
    assert!(!Config::onion_path(&t.config).exists(), "nothing recorded");
}

#[test]
fn export_refuses_to_overwrite_without_force() {
    let t = temp();
    new_plain(&t.config, &t.keystore, "exp", false).expect("new");
    let out = t.dir.path().join("existing.id");
    std::fs::write(&out, b"old").expect("seed output file");
    let error = ops::export_identity(&t.config, "exp", &out, false).expect_err("refused");
    assert!(
        error
            .to_string()
            .contains("already exists; pass --force to overwrite it"),
        "{error}"
    );
    assert_eq!(std::fs::read(&out).unwrap(), b"old");
    ops::export_identity(&t.config, "exp", &out, true).expect("forced export");
    assert_ne!(std::fs::read(&out).unwrap(), b"old");
}

#[cfg(unix)]
#[test]
fn export_file_has_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let t = temp();
    new_plain(&t.config, &t.keystore, "perm", false).expect("new");
    let out = t.dir.path().join("perm.id");
    ops::export_identity(&t.config, "perm", &out, false).expect("export");
    let mode = std::fs::metadata(&out).expect("meta").permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn export_of_a_service_without_a_key_explains_itself() {
    let t = temp();
    Config::write_onion_services(&t.config, &[entry("fresh")]).expect("write");
    let error = ops::export_identity(&t.config, "fresh", &t.dir.path().join("x.id"), false)
        .expect_err("no key yet");
    assert!(error.to_string().contains("no key yet"), "{error}");
}

#[test]
fn one_identity_cannot_serve_under_two_nicknames() {
    let t = temp();
    new_plain(&t.config, &t.keystore, "src", false).expect("new");
    let export = t.dir.path().join("src.id");
    ops::export_identity(&t.config, "src", &export, false).expect("export");
    let error = ops::import_identity(&t.config, &t.keystore, "twin", &export, None, false)
        .expect_err("refused");
    assert!(
        format!("{error:#}").contains("duplicate address"),
        "{error:#}"
    );
    assert!(
        stored(&t).iter().all(|entry| entry.nickname != "twin"),
        "nothing was recorded"
    );
}

#[test]
fn vanity_prefix_found_end_to_end_through_supplied() {
    let t = temp();
    let target = crate::vanity::VanityTarget::new("a").expect("prefix");
    let opts = crate::vanity::SearchOptions {
        threads: 2,
        time_limit: Some(std::time::Duration::from_secs(10)),
        ..Default::default()
    };
    let mut mine = || -> anyhow::Result<crate::address::Keypair> {
        match crate::vanity::search(&target, &opts) {
            crate::vanity::SearchOutcome::Found(keypair) => Ok(keypair),
            outcome => anyhow::bail!("vanity search did not find a key: {:?}", outcome),
        }
    };
    let recorded = ops::create_service(
        &t.config,
        &t.keystore,
        "van",
        None,
        false,
        NewIdentity::Supplied(&mut mine),
    )
    .expect("vanity new");
    assert!(recorded.address.starts_with('a'), "{}", recorded.address);
    assert_eq!(address_of(&t, "van"), recorded.address);
}

#[test]
fn vanity_search_timing_out_saves_nothing() {
    let t = temp();
    let target = crate::vanity::VanityTarget::new("abcdefgh").expect("prefix");
    let opts = crate::vanity::SearchOptions {
        threads: 2,
        time_limit: Some(std::time::Duration::from_millis(200)),
        ..Default::default()
    };
    let mut mine = || -> anyhow::Result<crate::address::Keypair> {
        match crate::vanity::search(&target, &opts) {
            crate::vanity::SearchOutcome::Found(keypair) => Ok(keypair),
            _ => anyhow::bail!("vanity search timed out"),
        }
    };
    let error = ops::create_service(
        &t.config,
        &t.keystore,
        "slow",
        None,
        false,
        NewIdentity::Supplied(&mut mine),
    )
    .expect_err("must time out");
    assert!(format!("{error:#}").contains("timed out"), "{error:#}");
    assert!(!Config::onion_path(&t.config).exists(), "nothing saved");
}

#[test]
fn an_address_that_does_not_match_the_key_is_refused() {
    // Through the public API an honest key source always agrees with the
    // address the library derives from its key, so the typed mismatch error
    // is asserted directly on its Display text (the CLI-visible message),
    // and the equivalent end-to-end refusal — a stated address the key does
    // not give, with the keystore left untouched — is covered by
    // `a_stated_address_that_the_key_does_not_give_is_refused` below.
    assert_eq!(
        KeysError::AddressMismatch.to_string(),
        "address mismatch; key not saved"
    );
}

// --- identity settlement (ensure / prepare_all) ---

fn ensure(t: &Temp, service: &OnionServiceEntry) -> anyhow::Result<String> {
    identity::ensure(Some(&t.config), &t.keystore, service).map_err(anyhow::Error::new)
}

#[test]
fn a_key_in_the_file_reaches_the_keystore_and_the_address_is_recorded() {
    let t = temp();
    let (key, address) = identity::fresh_identity("web");
    let mut service = entry("web");
    service.key = Some(IdentityKey::new(key.clone()).expect("key text"));
    Config::write_onion_services(&t.config, std::slice::from_ref(&service)).expect("write");

    let got = ensure(&t, &service).expect("ensure");

    assert_eq!(got, address);
    assert_eq!(
        keystore_address(&t, "web").as_deref(),
        Some(address.as_str())
    );
    let file = stored(&t);
    assert_eq!(file[0].address.as_deref(), Some(address.as_str()));
    assert_eq!(
        file[0].key.as_ref().map(IdentityKey::as_str),
        Some(key.as_str())
    );
}

#[test]
fn a_stated_address_that_the_key_does_not_give_is_refused() {
    let t = temp();
    let (key, _address) = identity::fresh_identity("web");
    let (_other_key, other_address) = identity::fresh_identity("web");
    let mut service = entry("web");
    service.key = Some(IdentityKey::new(key).expect("key text"));
    service.address = Some(other_address);
    Config::write_onion_services(&t.config, std::slice::from_ref(&service)).expect("write");

    let error = ensure(&t, &service).expect_err("refused");
    assert!(format!("{error:#}").contains("its key gives"), "{error:#}");
    assert_eq!(keystore_address(&t, "web"), None, "keystore untouched");
}

#[test]
fn a_service_without_a_key_gets_one_and_the_file_is_completed() {
    let t = temp();
    let service = entry("web");
    Config::write_onion_services(&t.config, std::slice::from_ref(&service)).expect("write");

    let address = ensure(&t, &service).expect("ensure");

    let file = stored(&t);
    assert_eq!(file[0].address.as_deref(), Some(address.as_str()));
    let key = file[0].key.as_ref().expect("the key is recorded");
    // The recorded key is the identity the keystore holds.
    let nick = store::nickname("web").expect("nickname");
    let bytes = store::decode_key(key.as_str()).expect("base64");
    let keypair = store::parse_identity_file(&bytes, &nick).expect("key file");
    assert_eq!(store::address_of(&keypair), address);
    assert_eq!(keystore_address(&t, "web"), Some(address));
}

#[test]
fn a_second_launch_keeps_the_same_identity() {
    let t = temp();
    Config::write_onion_services(&t.config, &[entry("web")]).expect("write");
    let first = ensure(&t, &entry("web")).expect("first");
    let recorded = stored(&t).remove(0);
    let second = ensure(&t, &recorded).expect("second");
    assert_eq!(first, second);
    assert_eq!(
        stored(&t)[0],
        recorded,
        "nothing to complete the second time"
    );
}

#[test]
fn a_key_left_in_the_keystore_by_an_older_version_is_adopted() {
    let t = temp();
    let nick = store::nickname("web").expect("nickname");
    let keymgr = store::open(&t.keystore).expect("keystore");
    store::generate(&keymgr, &nick, false).expect("generate");
    let existing = store::address(&keymgr, &nick)
        .expect("address")
        .expect("present");
    drop(keymgr);
    Config::write_onion_services(&t.config, &[entry("web")]).expect("write");

    let address = ensure(&t, &entry("web")).expect("ensure");

    assert_eq!(address, existing, "the address does not change");
    assert!(
        stored(&t)[0].key.is_some(),
        "and the key moves into the file"
    );
}

#[test]
fn an_address_without_any_key_is_refused_and_nothing_is_generated() {
    let t = temp();
    let mut service = entry("web");
    service.address = Some(identity::fresh_identity("web").1);
    Config::write_onion_services(&t.config, std::slice::from_ref(&service)).expect("write");

    let error = ensure(&t, &service).expect_err("refused");
    assert!(format!("{error:#}").contains("has no key"), "{error:#}");
    assert_eq!(keystore_address(&t, "web"), None);
}

#[test]
fn a_key_that_is_not_an_identity_key_is_refused() {
    let t = temp();
    let mut service = entry("web");
    service.key = Some(IdentityKey::new(store::encode_key(b"not a key")).expect("key text"));
    Config::write_onion_services(&t.config, std::slice::from_ref(&service)).expect("write");
    let error = ensure(&t, &service).expect_err("refused");
    assert!(
        format!("{error:#}").contains("not a valid identity key"),
        "{error:#}"
    );
}

#[test]
fn all_identities_are_settled_and_recorded_in_one_batch() {
    let t = temp();
    let (key, address) = identity::fresh_identity("whole");
    let mut whole = entry("whole");
    whole.key = Some(IdentityKey::new(key).expect("key text"));
    whole.address = Some(address.clone());
    let entries = vec![entry("first"), entry("second"), whole];
    Config::write_onion_services(&t.config, &entries).expect("write");

    let prepared = identity::prepare_all(Some(&t.config), &t.keystore, &entries);

    assert_eq!(prepared.len(), entries.len(), "one result per entry");
    // The already complete service keeps exactly its identity.
    assert_eq!(prepared[2].address.as_deref(), Some(address.as_str()));
    for (idx, nickname) in [(0, "first"), (1, "second"), (2, "whole")] {
        let service_address = prepared[idx]
            .address
            .as_ref()
            .expect("every service may start");
        assert_eq!(
            keystore_address(&t, nickname).as_deref(),
            Some(service_address.as_str()),
            "{nickname}: the keystore holds its identity"
        );
    }
    // The file holds every key and address, and each recorded key gives
    // exactly the address recorded next to it.
    let file = stored(&t);
    assert_eq!(file.len(), 3);
    for (idx, nickname) in [(0, "first"), (1, "second"), (2, "whole")] {
        assert_eq!(file[idx].nickname, nickname);
        assert_eq!(
            file[idx].address.as_deref(),
            prepared[idx].address.as_deref(),
            "{nickname}: its address is recorded"
        );
        let key_text = file[idx]
            .key
            .as_ref()
            .unwrap_or_else(|| panic!("{nickname}: its key is recorded"));
        let bytes = store::decode_key(key_text.as_str()).expect("base64");
        let nick = store::nickname(nickname).expect("nickname");
        let keypair = store::parse_identity_file(&bytes, &nick).expect("key file");
        let file_address = file[idx].address.as_deref().expect("the recorded address");
        assert_eq!(store::address_of(&keypair), file_address);
    }
}

#[test]
fn one_unusable_service_does_not_stop_the_others() {
    let t = temp();
    let (key, _address) = identity::fresh_identity("middle");
    let mut middle = entry("middle");
    middle.key = Some(IdentityKey::new(key).expect("key text"));
    middle.address = Some(identity::fresh_identity("middle").1);
    let entries = vec![entry("before"), middle.clone(), entry("after")];
    Config::write_onion_services(&t.config, &entries).expect("write");

    let prepared = identity::prepare_all(Some(&t.config), &t.keystore, &entries);

    // The middle service is refused and publishes nothing; the others start.
    assert_eq!(prepared[1].address, None);
    assert_eq!(keystore_address(&t, "middle"), None);
    for (idx, nickname) in [(0, "before"), (2, "after")] {
        let address = prepared[idx].address.as_ref().expect("the service starts");
        assert_eq!(
            keystore_address(&t, nickname).as_deref(),
            Some(address.as_str())
        );
    }
    // The refused entry is left exactly as it was; the others are completed
    // in the file.
    let file = stored(&t);
    assert_eq!(file.len(), 3);
    assert_eq!(file[1].nickname, "middle");
    assert_eq!(file[1], middle, "the refused entry is untouched");
    for (idx, nickname) in [(0, "before"), (2, "after")] {
        assert!(file[idx].key.is_some(), "{nickname}: its key is recorded");
        assert_eq!(
            file[idx].address.as_deref(),
            prepared[idx].address.as_deref(),
            "{nickname}: its address is recorded"
        );
    }
}

#[test]
fn a_service_missing_from_the_file_does_not_start_but_the_others_do() {
    let t = temp();
    let present = entry("present");
    let stale = entry("stale");
    Config::write_onion_services(&t.config, std::slice::from_ref(&present)).expect("write");

    let prepared = identity::prepare_all(Some(&t.config), &t.keystore, &[present, stale]);

    let address = prepared[0]
        .address
        .as_ref()
        .expect("the present service starts");
    assert_eq!(
        keystore_address(&t, "present").as_deref(),
        Some(address.as_str())
    );
    assert_eq!(
        prepared[1].address, None,
        "the stale service does not start"
    );
    // Only `present` is in the file, completed; the stale entry is not
    // appended.
    let file = stored(&t);
    assert_eq!(file.len(), 1);
    assert_eq!(file[0].nickname, "present");
    assert_eq!(file[0].address.as_deref(), Some(address.as_str()));
    assert!(file[0].key.is_some(), "the key is recorded");
}

#[test]
fn a_failed_file_write_starts_only_services_whose_entry_was_complete() {
    let t = temp();
    let (key, address) = identity::fresh_identity("whole");
    let mut whole = entry("whole");
    whole.key = Some(IdentityKey::new(key).expect("key text"));
    whole.address = Some(address.clone());
    // Garbage instead of the onion services file: the whole write fails.
    std::fs::write(Config::onion_path(&t.config), "not a ktav document").expect("write garbage");

    let prepared = identity::prepare_all(Some(&t.config), &t.keystore, &[entry("fresh"), whole]);

    // `fresh` settled before the write: its generated key is in the
    // keystore, but it does not start — its new key is recorded nowhere.
    assert_eq!(prepared[0].address, None);
    assert!(
        keystore_address(&t, "fresh").is_some(),
        "the key was still placed into the keystore by settlement"
    );
    // `whole` starts: its entry was already complete.
    assert_eq!(prepared[1].address.as_deref(), Some(address.as_str()));
    assert_eq!(
        keystore_address(&t, "whole").as_deref(),
        Some(address.as_str())
    );
}

#[test]
fn a_keyed_service_missing_only_its_address_starts_even_when_the_write_fails() {
    let t = temp();
    let (key, _address) = identity::fresh_identity("keyed");
    let mut keyed = entry("keyed");
    keyed.key = Some(IdentityKey::new(key.clone()).expect("key text"));
    std::fs::write(Config::onion_path(&t.config), "not a ktav document").expect("write garbage");

    let prepared = identity::prepare_all(Some(&t.config), &t.keystore, &[keyed, entry("fresh")]);

    // The keyed service starts: the failed write hides nothing, its address
    // derives from the key its entry already carries.
    let address = prepared[0]
        .address
        .as_ref()
        .expect("the keyed service starts");
    let bytes = store::decode_key(key.as_str()).expect("base64");
    let nick = store::nickname("keyed").expect("nickname");
    let keypair = store::parse_identity_file(&bytes, &nick).expect("key file");
    assert_eq!(address, &store::address_of(&keypair));
    // The keyless service does not start: its new key could not be recorded.
    assert_eq!(prepared[1].address, None);
}

// --- key specifier paths ---

#[test]
fn specifier_paths_match_the_tor_hsservice_layout() {
    let nick = store::nickname("web").expect("nickname");
    use tor_keymgr::KeySpecifier as _;
    assert_eq!(
        HsIdKeypairSpecifier::new(nick.clone())
            .arti_path()
            .expect("arti path")
            .as_str(),
        "hss/web/ks_hs_id"
    );
    assert_eq!(
        HsIdPublicKeySpecifier::new(nick)
            .arti_path()
            .expect("arti path")
            .as_str(),
        "hss/web/kp_hs_id"
    );
    // The public specifier must carry the keypair link: KeyMgr derives the
    // public part from the pair through it (`KeyMgr::get_from_store`);
    // without it `store::address` returns None even though the pair is
    // stored (this exact regression shipped once).
    let keypair = HsIdPublicKeySpecifier::new(store::nickname("web").expect("nickname"))
        .keypair_specifier()
        .expect("the public specifier must know its keypair");
    assert_eq!(
        keypair.arti_path().expect("arti path").as_str(),
        "hss/web/ks_hs_id"
    );
}

// --- Keystore lock contention (moved verbatim from the binary's
// lock_tests.rs): the lock makes concurrent hosting/mutation of the same
// keystore fail loudly, non-fatally.

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
