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

use anyhow::{bail, Context};
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
fn settle(
    keymgr: &KeyMgr,
    keystore_dir: &Path,
    entry: &OnionServiceEntry,
) -> Result<Settled, store::KeysError> {
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
                        return Err(anyhow::anyhow!(
                            "service {:?} states the address {address} but has no key: \
                             add its key to the onion services file, or remove the address \
                             to get a new one",
                            entry.nickname
                        )
                        .into());
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
            return Err(anyhow::anyhow!(
                "service {:?}: the onion services file states the address {stated}, \
                 but its key gives {address}",
                entry.nickname
            )
            .into());
        }
    }
    // The keystore is the copy arti reads: bring it to the file's key.
    if store::address(keymgr, &nick)?.as_deref() != Some(address.as_str()) {
        store::insert(keymgr, keypair, &nick, true)?;
    }
    Ok(Settled { address, new_key })
}

/// Set the file's entry of `nickname`: its `address`, and its `key` when one
/// was created. `Err` when the entry is no longer in the file (same message
/// as today).
fn apply_settlement(
    services: &mut [OnionServiceEntry],
    nickname: &str,
    key_text: Option<String>,
    address: &str,
) -> Result<(), anyhow::Error> {
    let Some(entry) = services.iter_mut().find(|entry| entry.nickname == nickname) else {
        bail!("service {nickname:?} is no longer in the onion services file");
    };
    entry.address = Some(address.to_owned());
    if let Some(key_text) = key_text {
        entry.key = Some(IdentityKey::new(key_text).map_err(anyhow::Error::msg)?);
    }
    Ok(())
}

/// Make the keystore hold the identity that `entry` names, creating and
/// recording it when the file has none, and return the service's address.
///
/// Refuses (`Err`, nothing changed in the keystore) when the file states an
/// address that its key does not give, or an address without any key to
/// check it against. `config_path` is where the onion services file belongs
/// to; without it (built-in defaults) there is no file to complete.
pub fn ensure(
    config_path: Option<&Path>,
    keystore_dir: &Path,
    entry: &OnionServiceEntry,
) -> Result<String, store::KeysError> {
    let keymgr = store::open(keystore_dir)?;
    let settled = settle(&keymgr, keystore_dir, entry)?;
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
fn record(
    config_path: Option<&Path>,
    nickname: &str,
    key_text: Option<String>,
    address: &str,
) -> Result<(), store::KeysError> {
    let Some(config_path) = config_path else {
        return Ok(());
    };
    Config::update_onion_services(config_path, |services| {
        apply_settlement(services, nickname, key_text, address)
    })?;
    Ok(())
}

/// One service handed to the launch phase: `address` is `None` when the
/// service must not start; the reason is logged (never any key material).
pub struct PreparedService {
    /// The entry as it was handed over (never modified).
    pub entry: OnionServiceEntry,
    /// The service's address, or `None` when it must not start.
    pub address: Option<String>,
}

/// Settle the identities of all `entries` (in order) and record everything
/// that must be recorded in ONE `update_onion_services` write. Never panics
/// on per-service failure: a service whose identity cannot be settled or
/// recorded is skipped (logged) without affecting the others.
pub fn prepare_all(
    config_path: Option<&Path>,
    keystore_dir: &Path,
    entries: &[OnionServiceEntry],
) -> Vec<PreparedService> {
    // One keystore for the whole batch; without it nothing can be settled.
    let keymgr = match store::open(keystore_dir) {
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
        match settle(&keymgr, keystore_dir, entry) {
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
///
/// Test helper only (R10): never in default/full, exposed to dependent
/// crates' tests only behind the `test-seams` feature.
#[cfg(any(test, feature = "test-seams"))]
pub fn fresh_identity(nickname: &str) -> (String, String) {
    use tor_hscrypto::pk::HsIdKeypair;
    use tor_llcrypto::pk::ed25519::ExpandedKeypair;

    let generated = crate::address::generate();
    let expanded = ExpandedKeypair::from_secret_key_bytes(generated.to_expanded_bytes())
        .expect("expanded keypair");
    let keypair = HsIdKeypair::from(expanded);
    let nick = store::nickname(nickname).expect("nickname");
    let bytes = store::identity_file_bytes(keypair, &nick).expect("key file bytes");
    (store::encode_key(&bytes), generated.address().to_owned())
}
