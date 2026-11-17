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

use zeroize::Zeroizing;

use super::store;

/// The identity of one entry as settled in the keystore, before anything is
/// written back to the onion services file.
struct Settled {
    address: String,
    /// A key created during settlement: it still must be recorded in the file.
    new_key: Option<String>,
}

/// A typed outcome that prevents identity preparation from launching a service.
/// These reasons contain no key material; detailed causes are kept out of logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PreparationFailure {
    /// The configured nickname is not a valid Tor hidden-service nickname.
    #[error("onion service nickname is invalid")]
    InvalidNickname,
    /// The enabled snapshot entry no longer exists in the onion services file.
    #[error("onion service is no longer in the onion services file")]
    EntryMissingFromFile,
    /// The entry's key changed after the host read its configuration snapshot.
    #[error("onion service identity changed after configuration was loaded")]
    IdentityChanged,
    /// The configured address is not derived from the configured key.
    #[error("onion service address does not match its identity key")]
    AddressMismatch,
    /// The onion keystore could not be opened.
    #[error("the onion keystore is unavailable")]
    KeystoreUnavailable,
    /// An unexpected preparation or persistence error occurred.
    #[error("internal onion service preparation failure")]
    Internal,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SettlementError {
    #[error("onion service nickname is invalid")]
    InvalidNickname,
    #[error("service {nickname:?}: the onion services file states the address {stated}, but its key gives {actual}")]
    AddressMismatch {
        nickname: String,
        stated: String,
        actual: String,
    },
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl From<store::KeysError> for SettlementError {
    fn from(error: store::KeysError) -> Self {
        Self::Internal(anyhow::Error::new(error))
    }
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
) -> Result<Settled, SettlementError> {
    let nick = store::nickname(&entry.nickname).map_err(|_| SettlementError::InvalidNickname)?;

    let (keypair, new_key) = match &entry.key {
        Some(key) => {
            let bytes = store::decode_key(key.as_str())?;
            let keypair = store::parse_identity_file(&bytes, &nick, keystore_dir)
                .context("the key in the onion services file is not a valid identity key")?;
            (keypair, None)
        }
        None => {
            let bytes = match store::identity_file(keystore_dir, &nick) {
                Some(file) => Zeroizing::new(
                    std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?,
                ),
                None => {
                    if let Some(address) = &entry.address {
                        return Err(SettlementError::Internal(anyhow::anyhow!(
                            "service {:?} states the address {address} but has no key: \
                             add its key to the onion services file, or remove the address \
                             to get a new one",
                            entry.nickname
                        )));
                    }
                    store::generate(keymgr, &nick, false)?;
                    let file = store::identity_file(keystore_dir, &nick)
                        .context("the generated identity file")?;
                    Zeroizing::new(
                        std::fs::read(&file)
                            .with_context(|| format!("reading {}", file.display()))?,
                    )
                }
            };
            let keypair = store::parse_identity_file(&bytes, &nick, keystore_dir)
                .context("the identity key in the keystore is not valid")?;
            (keypair, Some(store::encode_key(&bytes)))
        }
    };

    let address = store::address_of(&keypair);
    if let Some(stated) = &entry.address {
        if *stated != address {
            return Err(SettlementError::AddressMismatch {
                nickname: entry.nickname.clone(),
                stated: stated.clone(),
                actual: address,
            });
        }
    }
    // The keystore is the copy arti reads: bring it to the file's key.
    let old_address = store::address(keymgr, &nick)?;
    if old_address.as_deref() != Some(address.as_str()) {
        if let Some(old_address) = old_address {
            warn!(
                nickname = %entry.nickname,
                old_address = %old_address,
                new_address = %address,
                "replacing onion service identity in the keystore"
            );
        }
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
#[cfg(test)]
pub(crate) fn ensure(
    config_path: Option<&Path>,
    keystore_dir: &Path,
    entry: &OnionServiceEntry,
) -> Result<String, SettlementError> {
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
#[cfg(test)]
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

/// One service handed to the launch phase: its `entry` reflects the current
/// services file when one is configured; `address` is `None` if it must not
/// start, and `failure` contains the typed preparation reason when available.
pub struct PreparedService {
    /// The resolved service entry (current file entry when a path is set).
    pub entry: OnionServiceEntry,
    /// This service's settled address, or `None` when it must not start.
    pub address: Option<String>,
    /// Why identity preparation refused the service, if it was refused.
    pub failure: Option<PreparationFailure>,
}

/// Settle the identities of all snapshot-enabled `entries`. When a config
/// path is available, its current contents are read before the keystore is
/// opened; only entries still present with the same key are considered, and
/// all other fields (including ports and `enabled`) come from that current
/// file. Without a path, retain the legacy snapshot-only behavior.
///
/// Settlements and any required file updates are performed as one batch.
pub fn prepare_all(
    config_path: Option<&Path>,
    keystore_dir: &Path,
    entries: &[OnionServiceEntry],
) -> Vec<PreparedService> {
    // Read first, before opening or settling any keystore identity. The host
    // calls this under its externally-held keystore lock.
    let current_file = config_path.map(Config::read_onion_services);
    let mut prepared = Vec::with_capacity(entries.len());
    let mut candidates = Vec::new();

    for snapshot in entries {
        if !snapshot.enabled {
            prepared.push(PreparedService {
                entry: snapshot.clone(),
                address: None,
                failure: None,
            });
            continue;
        }

        let current = match &current_file {
            None => snapshot.clone(),
            Some(Err(error)) => {
                error!(%error, "the current onion services file could not be read");
                let failure = PreparationFailure::Internal;
                warn_preparation_failure(&snapshot.nickname, failure);
                prepared.push(PreparedService {
                    entry: snapshot.clone(),
                    address: None,
                    failure: Some(failure),
                });
                continue;
            }
            Some(Ok(services)) => {
                let Some(current) = services
                    .iter()
                    .find(|service| service.nickname == snapshot.nickname)
                else {
                    let failure = PreparationFailure::EntryMissingFromFile;
                    warn_preparation_failure(&snapshot.nickname, failure);
                    prepared.push(PreparedService {
                        entry: snapshot.clone(),
                        address: None,
                        failure: Some(failure),
                    });
                    continue;
                };
                if !current.enabled {
                    prepared.push(PreparedService {
                        entry: current.clone(),
                        address: None,
                        failure: None,
                    });
                    continue;
                }
                if current.enabled && current.key != snapshot.key {
                    let failure = PreparationFailure::IdentityChanged;
                    warn_preparation_failure(&current.nickname, failure);
                    prepared.push(PreparedService {
                        entry: current.clone(),
                        address: None,
                        failure: Some(failure),
                    });
                    continue;
                }
                current.clone()
            }
        };

        let index = prepared.len();
        prepared.push(PreparedService {
            entry: current.clone(),
            address: None,
            failure: None,
        });
        candidates.push((index, current));
    }

    if candidates.is_empty() {
        return prepared;
    }

    // One keystore for the whole batch; if it cannot be opened, type the
    // failure for each otherwise-eligible service.
    let keymgr = match store::open(keystore_dir) {
        Ok(keymgr) => keymgr,
        Err(_) => {
            for (index, _) in candidates {
                let failure = PreparationFailure::KeystoreUnavailable;
                warn_preparation_failure(&prepared[index].entry.nickname, failure);
                prepared[index].failure = Some(failure);
            }
            return prepared;
        }
    };

    let mut settled: Vec<Option<Settled>> = std::iter::repeat_with(|| None)
        .take(prepared.len())
        .collect();
    let mut to_record = Vec::new();
    for (idx, entry) in candidates {
        match settle(&keymgr, keystore_dir, &entry) {
            Ok(one) => {
                if one.new_key.is_some() || entry.address.is_none() {
                    to_record.push(idx);
                }
                settled[idx] = Some(one);
            }
            Err(error) => {
                let failure = match error {
                    SettlementError::InvalidNickname => PreparationFailure::InvalidNickname,
                    SettlementError::AddressMismatch { .. } => PreparationFailure::AddressMismatch,
                    SettlementError::Internal(_) => PreparationFailure::Internal,
                };
                warn_preparation_failure(&entry.nickname, failure);
                prepared[idx].failure = Some(failure);
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
                    let entry = &prepared[idx].entry;
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
        Some(Ok(vanished)) => (vanished, false),
        Some(Err(error)) => {
            error!(%error, "the onion services file could not be updated");
            (Vec::new(), true)
        }
    };

    for (idx, one) in settled.into_iter().enumerate() {
        let Some(one) = one else {
            continue;
        };
        let entry = &prepared[idx].entry;
        if vanished.contains(&entry.nickname) {
            let failure = PreparationFailure::EntryMissingFromFile;
            warn_preparation_failure(&entry.nickname, failure);
            prepared[idx].failure = Some(failure);
            continue;
        }
        if write_failed && one.new_key.is_some() {
            let failure = PreparationFailure::Internal;
            warn_preparation_failure(&entry.nickname, failure);
            prepared[idx].failure = Some(failure);
            continue;
        }
        info!(
            nickname = %entry.nickname,
            address = %one.address,
            "onion service: identity ready (the onion services file holds its key)"
        );
        prepared[idx].address = Some(one.address);
    }
    prepared
}

fn warn_preparation_failure(nickname: &str, failure: PreparationFailure) {
    warn!(
        nickname,
        %failure,
        "onion service identity is not usable; service not started"
    );
}

/// A fresh identity as the services file stores it: (key text, address).
///
/// Test helper only (R10): never in default/full, exposed to dependent
/// crates' tests only behind the `test-seams` feature.
#[cfg(any(test, feature = "test-seams"))]
pub fn fresh_identity(nickname: &str, staging_parent: &Path) -> (String, String) {
    use tor_hscrypto::pk::HsIdKeypair;
    use tor_llcrypto::pk::ed25519::ExpandedKeypair;

    let generated = crate::address::generate();
    let expanded = ExpandedKeypair::from_secret_key_bytes(*generated.to_expanded_bytes())
        .expect("expanded keypair");
    let keypair = HsIdKeypair::from(expanded);
    let nick = store::nickname(nickname).expect("nickname");
    let bytes = store::identity_file_bytes(keypair, &nick, staging_parent).expect("key file bytes");
    (store::encode_key(&bytes), generated.address().to_owned())
}
