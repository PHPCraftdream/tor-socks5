//! The identity of a configured onion service at launch.
//!
//! The onion services file (`<stem>.onion.ktav`) is the source of truth: the
//! `key` of a service is its identity and `address` the address that key
//! gives. Arti reads the identity from its keystore, so a launch makes the
//! keystore hold exactly the key of the file. A service without a key gets
//! one (the keystore's, if an older `onion new` left one there, else a fresh
//! one) and the file is completed with the key and the address, so after the
//! first start everything about the service is in the file.

use std::path::Path;

use anyhow::{bail, Context, Result};
use proxy_config::{Config, IdentityKey, OnionServiceEntry};
use tor_keymgr::KeyMgr;
use tracing::{error, info, warn};

use super::store;

/// The identity of one entry as settled in the keystore, before anything is
/// written back to the onion services file.
struct Settled {
    address: String,
    /// A key created during settlement: it still must be recorded in the file.
    new_key: Option<String>,
}

/// Settle the identity of `entry` in the keystore at `keystore_dir`: take its
/// key from the onion services file's data, or adopt/generate one in the
/// keystore, check the stated address against the key and make the keystore
/// hold the key. Nothing is written back; the caller records the settlement
/// (see [`apply_settlement`]).
///
/// Refuses (`Err`, nothing changed in the keystore) when the entry states an
/// address that its key does not give, or an address without any key to
/// check it against.
fn settle(keymgr: &KeyMgr, keystore_dir: &Path, entry: &OnionServiceEntry) -> Result<Settled> {
    let nick = store::nickname(&entry.nickname)?;

    let (keypair, new_key) = match &entry.key {
        Some(key) => {
            let bytes = store::decode_key(key.as_str())?;
            let keypair = store::parse_identity_file(&bytes, &nick)
                .context("the key in the onion services file is not a valid identity key")?;
            (keypair, None)
        }
        None => {
            let bytes = match store::identity_file(keystore_dir, &nick) {
                Some(file) => {
                    std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?
                }
                None => {
                    if let Some(address) = &entry.address {
                        bail!(
                            "service {:?} states the address {address} but has no key: \
                             add its key to the onion services file, or remove the address \
                             to get a new one",
                            entry.nickname
                        );
                    }
                    store::generate(keymgr, &nick, false)?;
                    let file = store::identity_file(keystore_dir, &nick)
                        .context("the generated identity file")?;
                    std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?
                }
            };
            let keypair = store::parse_identity_file(&bytes, &nick)
                .context("the identity key in the keystore is not valid")?;
            (keypair, Some(store::encode_key(&bytes)))
        }
    };

    let address = store::address_of(&keypair);
    if let Some(stated) = &entry.address {
        if *stated != address {
            bail!(
                "service {:?}: the onion services file states the address {stated}, \
                 but its key gives {address}",
                entry.nickname
            );
        }
    }
    // The keystore is the copy arti reads: bring it to the file's key.
    if store::address(keymgr, &nick)?.as_deref() != Some(address.as_str()) {
        store::insert(keymgr, keypair, &nick, true)?;
    }
    Ok(Settled { address, new_key })
}

// Single-service form kept for parity and tests; the server settles every
// service in one batch through `prepare_all`.
/// Make the keystore hold the identity that `entry` names, creating and
/// recording it when the file has none, and return the service's address.
///
/// Refuses (`Err`, nothing changed in the keystore) when the file states an
/// address that its key does not give, or an address without any key to
/// check it against. `config_path` is where the onion services file belongs
/// to; without it (built-in defaults) there is no file to complete.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn ensure(config_path: Option<&Path>, entry: &OnionServiceEntry) -> Result<String> {
    let dir = store::keystore_dir(config_path);
    let keymgr = store::open(&dir)?;
    let settled = settle(&keymgr, &dir, entry)?;
    if settled.new_key.is_some() || entry.address.is_none() {
        record(
            config_path,
            &entry.nickname,
            settled.new_key,
            &settled.address,
        )?;
    }
    Ok(settled.address)
}

/// Complete the file's entry of `nickname`: its `address`, and its `key` when
/// one was just created.
#[cfg_attr(not(test), allow(dead_code))]
fn record(
    config_path: Option<&Path>,
    nickname: &str,
    key_text: Option<String>,
    address: &str,
) -> Result<()> {
    let Some(config_path) = config_path else {
        return Ok(());
    };
    Config::update_onion_services(config_path, |services| {
        apply_settlement(services, nickname, key_text, address)
    })
}

/// Set the file's entry of `nickname`: its `address`, and its `key` when one
/// was created. `Err` when the entry is no longer in the file (same message
/// as today).
fn apply_settlement(
    services: &mut [OnionServiceEntry],
    nickname: &str,
    key_text: Option<String>,
    address: &str,
) -> Result<()> {
    let Some(entry) = services.iter_mut().find(|entry| entry.nickname == nickname) else {
        bail!("service {nickname:?} is no longer in the onion services file");
    };
    entry.address = Some(address.to_owned());
    if let Some(key_text) = key_text {
        entry.key = Some(IdentityKey::new(key_text).map_err(anyhow::Error::msg)?);
    }
    Ok(())
}

/// One service handed to the launch phase: `address` is `None` when the
/// service must not start; the reason is logged (never any key material).
pub(crate) struct PreparedService {
    pub(crate) entry: OnionServiceEntry,
    pub(crate) address: Option<String>,
}

/// Settle the identities of all `entries` (in order) and record everything
/// that must be recorded in ONE `update_onion_services` write. Never panics
/// on per-service failure: a service whose identity cannot be settled or
/// recorded is skipped (logged) without affecting the others.
pub(crate) fn prepare_all(
    config_path: Option<&Path>,
    entries: &[OnionServiceEntry],
) -> Vec<PreparedService> {
    // One keystore for the whole batch; without it nothing can be settled.
    let dir = store::keystore_dir(config_path);
    let keymgr = match store::open(&dir) {
        Ok(keymgr) => keymgr,
        Err(error) => {
            error!(
                %error,
                "onion services not started: the onion keystore cannot be opened"
            );
            return entries
                .iter()
                .cloned()
                .map(|entry| PreparedService {
                    entry,
                    address: None,
                })
                .collect();
        }
    };

    // Settle every identity in order; one unusable service does not stop the
    // others.
    let mut settled: Vec<Option<Settled>> = Vec::with_capacity(entries.len());
    let mut to_record = Vec::new();
    for (idx, entry) in entries.iter().enumerate() {
        match settle(&keymgr, &dir, entry) {
            Ok(one) => {
                // Same rule as the single-service form: record when a key
                // was created or the entry lacks its address.
                if one.new_key.is_some() || entry.address.is_none() {
                    to_record.push(idx);
                }
                settled.push(Some(one));
            }
            Err(error) => {
                error!(
                    nickname = %entry.nickname,
                    error = %format!("{error:#}"),
                    "onion service identity is not usable; service not started"
                );
                settled.push(None);
            }
        }
    }

    // ONE full re-read + rewrite of the file for the whole batch, where the
    // single-service form rewrote once per pending entry.
    let write = match config_path {
        Some(config_path) if !to_record.is_empty() => {
            Some(Config::update_onion_services(config_path, |services| {
                let mut vanished = Vec::new();
                for &idx in &to_record {
                    let entry = &entries[idx];
                    let one = settled[idx]
                        .as_ref()
                        .expect("every recorded entry is settled");
                    if apply_settlement(
                        services,
                        &entry.nickname,
                        one.new_key.clone(),
                        &one.address,
                    )
                    .is_err()
                    {
                        // An entry no longer in the file cannot be completed;
                        // the others still are.
                        vanished.push(entry.nickname.clone());
                    }
                }
                Ok(vanished)
            }))
        }
        _ => None,
    };
    let (vanished, write_failed) = match write {
        None => (Vec::new(), false),
        Some(Ok(vanished)) => {
            for nickname in &vanished {
                warn!(
                    nickname = %nickname,
                    "onion service is no longer in the onion services file; service not started"
                );
            }
            (vanished, false)
        }
        Some(Err(error)) => {
            error!(%error, "the onion services file could not be updated");
            (Vec::new(), true)
        }
    };

    let mut prepared = Vec::with_capacity(entries.len());
    for (idx, entry) in entries.iter().enumerate() {
        let address = settled[idx].as_ref().and_then(|one| {
            // The write failed wholesale: an entry with a new key must not
            // start — its key and address would exist nowhere in the file.
            // The others start: their key is already in the file (only the
            // address was missing, and it derives from the key), or their
            // entry was already complete.
            if write_failed && one.new_key.is_some() {
                error!(
                    nickname = %entry.nickname,
                    "its new key could not be recorded in the onion services file; service not started"
                );
                return None;
            }
            if !write_failed && vanished.contains(&entry.nickname) {
                return None; // already logged when the write succeeded
            }
            info!(
                nickname = %entry.nickname,
                %one.address,
                "onion service: identity ready (the onion services file holds its key)"
            );
            Some(one.address.clone())
        });
        prepared.push(PreparedService {
            entry: entry.clone(),
            address,
        });
    }
    prepared
}

/// A fresh identity as the services file stores it: (key text, address).
#[cfg(test)]
pub(crate) fn fresh_identity(nickname: &str) -> (String, String) {
    use tor_hscrypto::pk::HsIdKeypair;
    use tor_llcrypto::pk::ed25519::ExpandedKeypair;

    let generated = super::address::generate();
    let expanded = ExpandedKeypair::from_secret_key_bytes(generated.to_expanded_bytes())
        .expect("expanded keypair");
    let keypair = HsIdKeypair::from(expanded);
    let nick = store::nickname(nickname).expect("nickname");
    let bytes = store::identity_file_bytes(keypair, &nick).expect("key file bytes");
    (store::encode_key(&bytes), generated.address().to_owned())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use proxy_config::OnionServicePort;

    use super::*;

    fn temp_config() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("temp dir");
        let config = dir.path().join("tor-socks5.ktav");
        (dir, config)
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

    fn stored(config: &Path) -> Vec<OnionServiceEntry> {
        Config::read_onion_services(config).expect("read the file")
    }

    fn keystore_address(config: &Path, nickname: &str) -> Option<String> {
        let keymgr = store::open(&store::keystore_dir(Some(config))).expect("keystore");
        store::address(&keymgr, &store::nickname(nickname).expect("nickname")).expect("address")
    }

    #[test]
    fn a_key_in_the_file_reaches_the_keystore_and_the_address_is_recorded() {
        let (_tmp, config) = temp_config();
        let (key, address) = fresh_identity("web");
        let mut service = entry("web");
        service.key = Some(IdentityKey::new(key.clone()).expect("key text"));
        Config::write_onion_services(&config, std::slice::from_ref(&service)).expect("write");

        let got = ensure(Some(&config), &service).expect("ensure");

        assert_eq!(got, address);
        assert_eq!(
            keystore_address(&config, "web").as_deref(),
            Some(address.as_str())
        );
        let file = stored(&config);
        assert_eq!(file[0].address.as_deref(), Some(address.as_str()));
        assert_eq!(
            file[0].key.as_ref().map(IdentityKey::as_str),
            Some(key.as_str())
        );
    }

    #[test]
    fn a_stated_address_that_the_key_does_not_give_is_refused() {
        let (_tmp, config) = temp_config();
        let (key, _address) = fresh_identity("web");
        let (_other_key, other_address) = fresh_identity("web");
        let mut service = entry("web");
        service.key = Some(IdentityKey::new(key).expect("key text"));
        service.address = Some(other_address);
        Config::write_onion_services(&config, std::slice::from_ref(&service)).expect("write");

        let error = ensure(Some(&config), &service).expect_err("refused");
        assert!(error.to_string().contains("its key gives"), "{error:#}");
        assert_eq!(keystore_address(&config, "web"), None, "keystore untouched");
    }

    #[test]
    fn a_service_without_a_key_gets_one_and_the_file_is_completed() {
        let (_tmp, config) = temp_config();
        let service = entry("web");
        Config::write_onion_services(&config, std::slice::from_ref(&service)).expect("write");

        let address = ensure(Some(&config), &service).expect("ensure");

        let file = stored(&config);
        assert_eq!(file[0].address.as_deref(), Some(address.as_str()));
        let key = file[0].key.as_ref().expect("the key is recorded");
        // The recorded key is the identity the keystore holds.
        let nick = store::nickname("web").expect("nickname");
        let bytes = store::decode_key(key.as_str()).expect("base64");
        let keypair = store::parse_identity_file(&bytes, &nick).expect("key file");
        assert_eq!(store::address_of(&keypair), address);
        assert_eq!(keystore_address(&config, "web"), Some(address));
    }

    #[test]
    fn a_second_launch_keeps_the_same_identity() {
        let (_tmp, config) = temp_config();
        Config::write_onion_services(&config, &[entry("web")]).expect("write");
        let first = ensure(Some(&config), &entry("web")).expect("first");
        let recorded = stored(&config).remove(0);
        let second = ensure(Some(&config), &recorded).expect("second");
        assert_eq!(first, second);
        assert_eq!(
            stored(&config)[0],
            recorded,
            "nothing to complete the second time"
        );
    }

    #[test]
    fn a_key_left_in_the_keystore_by_an_older_version_is_adopted() {
        let (_tmp, config) = temp_config();
        let nick = store::nickname("web").expect("nickname");
        let dir = store::keystore_dir(Some(&config));
        let keymgr = store::open(&dir).expect("keystore");
        store::generate(&keymgr, &nick, false).expect("generate");
        let existing = store::address(&keymgr, &nick)
            .expect("address")
            .expect("present");
        drop(keymgr);
        Config::write_onion_services(&config, &[entry("web")]).expect("write");

        let address = ensure(Some(&config), &entry("web")).expect("ensure");

        assert_eq!(address, existing, "the address does not change");
        assert!(
            stored(&config)[0].key.is_some(),
            "and the key moves into the file"
        );
    }

    #[test]
    fn an_address_without_any_key_is_refused_and_nothing_is_generated() {
        let (_tmp, config) = temp_config();
        let mut service = entry("web");
        service.address = Some(fresh_identity("web").1);
        Config::write_onion_services(&config, std::slice::from_ref(&service)).expect("write");

        let error = ensure(Some(&config), &service).expect_err("refused");
        assert!(error.to_string().contains("has no key"), "{error:#}");
        assert_eq!(keystore_address(&config, "web"), None);
    }

    #[test]
    fn a_key_that_is_not_an_identity_key_is_refused() {
        let (_tmp, config) = temp_config();
        let mut service = entry("web");
        service.key = Some(IdentityKey::new(store::encode_key(b"not a key")).expect("key text"));
        Config::write_onion_services(&config, std::slice::from_ref(&service)).expect("write");
        let error = ensure(Some(&config), &service).expect_err("refused");
        assert!(
            format!("{error:#}").contains("not a valid identity key"),
            "{error:#}"
        );
    }

    #[test]
    fn all_identities_are_settled_and_recorded_in_one_batch() {
        let (_tmp, config) = temp_config();
        let (key, address) = fresh_identity("whole");
        let mut whole = entry("whole");
        whole.key = Some(IdentityKey::new(key).expect("key text"));
        whole.address = Some(address.clone());
        let entries = vec![entry("first"), entry("second"), whole];
        Config::write_onion_services(&config, &entries).expect("write");

        let prepared = prepare_all(Some(&config), &entries);

        assert_eq!(prepared.len(), entries.len(), "one result per entry");
        // The already complete service keeps exactly its identity.
        assert_eq!(prepared[2].address.as_deref(), Some(address.as_str()));
        for (idx, nickname) in [(0, "first"), (1, "second"), (2, "whole")] {
            let service_address = prepared[idx]
                .address
                .as_ref()
                .expect("every service may start");
            assert_eq!(
                keystore_address(&config, nickname).as_deref(),
                Some(service_address.as_str()),
                "{nickname}: the keystore holds its identity"
            );
        }
        // The file holds every key and address, and each recorded key gives
        // exactly the address recorded next to it.
        let file = stored(&config);
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
        let (_tmp, config) = temp_config();
        let (key, _address) = fresh_identity("middle");
        let mut middle = entry("middle");
        middle.key = Some(IdentityKey::new(key).expect("key text"));
        middle.address = Some(fresh_identity("middle").1);
        let entries = vec![entry("before"), middle.clone(), entry("after")];
        Config::write_onion_services(&config, &entries).expect("write");

        let prepared = prepare_all(Some(&config), &entries);

        // The middle service is refused and publishes nothing; the others
        // start.
        assert_eq!(prepared[1].address, None);
        assert_eq!(keystore_address(&config, "middle"), None);
        for (idx, nickname) in [(0, "before"), (2, "after")] {
            let address = prepared[idx].address.as_ref().expect("the service starts");
            assert_eq!(
                keystore_address(&config, nickname).as_deref(),
                Some(address.as_str())
            );
        }
        // The refused entry is left exactly as it was; the others are
        // completed in the file.
        let file = stored(&config);
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
        let (_tmp, config) = temp_config();
        let present = entry("present");
        let stale = entry("stale");
        Config::write_onion_services(&config, std::slice::from_ref(&present)).expect("write");

        let prepared = prepare_all(Some(&config), &[present, stale]);

        let address = prepared[0]
            .address
            .as_ref()
            .expect("the present service starts");
        assert_eq!(
            keystore_address(&config, "present").as_deref(),
            Some(address.as_str())
        );
        assert_eq!(
            prepared[1].address, None,
            "the stale service does not start"
        );
        // Only `present` is in the file, completed; the stale entry is not
        // appended.
        let file = stored(&config);
        assert_eq!(file.len(), 1);
        assert_eq!(file[0].nickname, "present");
        assert_eq!(file[0].address.as_deref(), Some(address.as_str()));
        assert!(file[0].key.is_some(), "the key is recorded");
    }

    #[test]
    fn a_failed_file_write_starts_only_services_whose_entry_was_complete() {
        let (_tmp, config) = temp_config();
        let (key, address) = fresh_identity("whole");
        let mut whole = entry("whole");
        whole.key = Some(IdentityKey::new(key).expect("key text"));
        whole.address = Some(address.clone());
        // Garbage instead of the onion services file: the whole write fails.
        std::fs::write(Config::onion_path(&config), "not a ktav document").expect("write garbage");

        let prepared = prepare_all(Some(&config), &[entry("fresh"), whole]);

        // `fresh` settled before the write: its generated key is in the
        // keystore, but it does not start — its new key is recorded nowhere.
        assert_eq!(prepared[0].address, None);
        assert!(
            keystore_address(&config, "fresh").is_some(),
            "the key was still placed into the keystore by settlement"
        );
        // `whole` starts: its entry was already complete.
        assert_eq!(prepared[1].address.as_deref(), Some(address.as_str()));
        assert_eq!(
            keystore_address(&config, "whole").as_deref(),
            Some(address.as_str())
        );
    }

    #[test]
    fn a_keyed_service_missing_only_its_address_starts_even_when_the_write_fails() {
        let (_tmp, config) = temp_config();
        let (key, _address) = fresh_identity("keyed");
        let mut keyed = entry("keyed");
        keyed.key = Some(IdentityKey::new(key.clone()).expect("key text"));
        std::fs::write(Config::onion_path(&config), "not a ktav document").expect("write garbage");

        let prepared = prepare_all(Some(&config), &[keyed, entry("fresh")]);

        // The keyed service starts: the failed write hides nothing, its
        // address derives from the key its entry already carries.
        let address = prepared[0]
            .address
            .as_ref()
            .expect("the keyed service starts");
        let bytes = store::decode_key(key.as_str()).expect("base64");
        let nick = store::nickname("keyed").expect("nickname");
        let keypair = store::parse_identity_file(&bytes, &nick).expect("key file");
        assert_eq!(address, &store::address_of(&keypair));
        // The keyless service does not start: its new key could not be
        // recorded.
        assert_eq!(prepared[1].address, None);
    }
}
