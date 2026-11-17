//! Onion command cores: `new`, `list`, `show`, `export`, `import`, `remove`.
//!
//! The services live in the onion services file next to the main config
//! (`<stem>.onion.ktav`): this is where `new` and `import` record a service
//! with its key and address and where `list`, `show`, `export` and `remove`
//! read and change it. Nothing here starts Tor or opens the network, prints
//! or prompts: formatting, `--force`/`--yes` confirmations and port-string
//! parsing stay with the application. The Arti keystore is only a copy that
//! a launch refreshes from the file; the operations that change a service
//! still take its lock, so they refuse while the server runs (the server
//! writes the same file).

use std::path::Path;

use anyhow::Context as _;
use proxy_config::{Config, IdentityKey, OnionServiceEntry, OnionServicePort};
use tor_hscrypto::pk::HsIdKeypair;
use tor_llcrypto::pk::ed25519::ExpandedKeypair;
use tor_persist::hsnickname::HsNickname;
use zeroize::Zeroizing;

use super::store::{self, KeysError};

/// Circuit length a new entry starts with (the config default).
const DEFAULT_CIRCUIT_HOPS: u8 = 4;

/// What a creation operation recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recorded {
    /// The service's `.onion` address.
    pub address: String,
    /// Whether the service ended up with ports and thus enabled.
    pub ports_enabled: bool,
}

/// Where a new identity key comes from.
pub enum NewIdentity<'a> {
    /// A fresh random key: [`crate::address::generate`].
    Random,
    /// A key the caller provides: the closure is invoked before the keystore
    /// lock is taken (it may run minutes for a vanity search) and may print
    /// progress (this is how a CLI keeps its vanity-search output alive
    /// during the search).
    Supplied(&'a mut dyn FnMut() -> anyhow::Result<crate::address::Keypair>),
}

/// Whether `nick` already has an identity: a key in the onion services file,
/// or a keypair left in the keystore by an older version.
///
/// The keystore check does not create the keystore: when the directory does
/// not exist yet there is no identity to find, and the check leaves it that
/// way.
pub fn identity_exists(
    config_path: &Path,
    keystore_dir: &Path,
    nick: &HsNickname,
) -> Result<bool, KeysError> {
    let in_file = Config::read_onion_services(config_path)?
        .iter()
        .any(|entry| entry.nickname == nick.to_string() && entry.key.is_some());
    let in_keystore = keystore_dir.is_dir() && {
        let keymgr = store::open(keystore_dir)?;
        store::exists(&keymgr, nick)?
    };
    Ok(in_file || in_keystore)
}

/// Create a new onion service: a fresh identity key, its address and the
/// given ports recorded in the onion services file (updating the entry when
/// it already exists).
///
/// `ports`, when given, replace the service's ports and enable it; without
/// them a new service is created disabled and an existing one keeps its
/// ports. `force` replaces an existing identity (the old address is lost).
/// The keystore copy of the key is dropped: the file is the source, and the
/// next launch writes the key it holds back into the keystore.
///
/// The identity (possibly a minutes-long vanity search) is generated BEFORE
/// the keystore lock is taken; the replace check runs both before it and
/// again under the lock.
pub fn create_service(
    config_path: &Path,
    keystore_dir: &Path,
    nick: &str,
    ports: Option<Vec<OnionServicePort>>,
    force: bool,
    identity: NewIdentity,
) -> Result<Recorded, KeysError> {
    let nick = store::nickname(nick)?;
    if identity_exists(config_path, keystore_dir, &nick)? && !force {
        return Err(KeysError::IdentityExists(nick.to_string()));
    }
    let generated = match identity {
        NewIdentity::Random => crate::address::generate(),
        NewIdentity::Supplied(source) => source()?,
    };
    let key = hs_keypair(&generated)?;
    // Only the short tail runs under the lock: re-check under it, then
    // compute and record.
    let _lock = store::lock(keystore_dir)?;
    if identity_exists(config_path, keystore_dir, &nick)? && !force {
        return Err(KeysError::IdentityExists(nick.to_string()));
    }
    let address = store::address_of(&key);
    let bytes = store::identity_file_bytes(key, &nick, keystore_dir)?;
    let ports_enabled = record_identity(config_path, keystore_dir, &nick, &bytes, &address, ports)?;
    Ok(Recorded {
        address,
        ports_enabled,
    })
}

/// All the onion services of the file (an empty list when there is no file).
pub fn list_services(config_path: &Path) -> Result<Vec<OnionServiceEntry>, KeysError> {
    Ok(Config::read_onion_services(config_path)?)
}

/// The entry of `nick`, or [`KeysError::NotFound`].
pub fn show_service(config_path: &Path, nick: &str) -> Result<OnionServiceEntry, KeysError> {
    let nick = store::nickname(nick)?;
    list_services(config_path)?
        .into_iter()
        .find(|entry| entry.nickname == nick.to_string())
        .ok_or_else(|| KeysError::NotFound(nick.to_string()))
}

/// Export a service's identity key to a portable file.
///
/// The key file's own bytes ARE the portable format: the Arti native
/// keystore stores the identity as an OpenSSH-format file with the custom
/// ed25519-expanded algorithm, which `import` (and arti itself) parse back
/// through the same keystore code. `force` allows overwriting `out`.
pub fn export_identity(
    config_path: &Path,
    nick: &str,
    out: &Path,
    force: bool,
) -> Result<(), KeysError> {
    let nick = store::nickname(nick)?;
    let service = show_service(config_path, nick.as_ref())?;
    let Some(key) = service.key else {
        return Err(KeysError::NoKey(nick.to_string()));
    };
    // No exists() pre-check: `write_secret_file` refuses an existing path
    // atomically (dangling symlinks included) unless `force`.
    let bytes = store::decode_key(key.as_str())?;
    store::write_secret_file(out, &bytes, force)?;
    Ok(())
}

/// Import an identity key from an exported file into the onion services
/// file, registering it under `nick`.
///
/// Like [`create_service`]: `ports` replace and enable, `force` replaces.
/// The service ends up enabled when ports were given, or when it already
/// has non-empty ports in the file.
pub fn import_identity(
    config_path: &Path,
    keystore_dir: &Path,
    nick: &str,
    file: &Path,
    ports: Option<Vec<OnionServicePort>>,
    force: bool,
) -> Result<Recorded, KeysError> {
    let nick = store::nickname(nick)?;
    let bytes =
        Zeroizing::new(std::fs::read(file).with_context(|| format!("reading {}", file.display()))?);
    let key = store::parse_identity_file(&bytes, &nick, keystore_dir)?;
    let _lock = store::lock(keystore_dir)?;
    if identity_exists(config_path, keystore_dir, &nick)? && !force {
        return Err(KeysError::IdentityExists(nick.to_string()));
    }
    let address = store::address_of(&key);
    let ports_enabled = record_identity(config_path, keystore_dir, &nick, &bytes, &address, ports)?;
    Ok(Recorded {
        address,
        ports_enabled,
    })
}

/// Delete a service with its key from the onion services file and drop the
/// keystore copy (irreversible for the identity unless it was exported
/// first). Confirmation (`--yes`) is the application's concern.
pub fn remove_service(
    config_path: &Path,
    keystore_dir: &Path,
    nick: &str,
) -> Result<(), KeysError> {
    let nick = store::nickname(nick)?;
    let _lock = store::lock(keystore_dir)?;
    // Without the file there is nothing to remove: the transaction below
    // would otherwise create an empty file.
    if !Config::onion_path(config_path).exists() {
        return Err(KeysError::NotFound(nick.to_string()));
    }
    let name = nick.to_string();
    let removed = Config::update_onion_services(config_path, |services| {
        let before = services.len();
        services.retain(|entry| entry.nickname != name);
        Ok(services.len() != before)
    })?;
    if !removed {
        return Err(KeysError::NotFound(name));
    }
    forget_keystore_copy(keystore_dir, &nick)?;
    Ok(())
}

/// The keystore keypair of a generated or searched key, checked against the
/// address the generator computed.
fn hs_keypair(generated: &crate::address::Keypair) -> Result<HsIdKeypair, KeysError> {
    let expanded = ExpandedKeypair::from_secret_key_bytes(*generated.to_expanded_bytes())
        .context("invalid expanded secret key")?;
    let key = HsIdKeypair::from(expanded);
    if store::address_of(&key) != generated.address() {
        return Err(KeysError::AddressMismatch);
    }
    Ok(key)
}

/// Record `key_bytes` (a keystore key file) as the identity of `nick` and
/// drop the keystore's copy. See [`create_service`] for the ports/enabled
/// rule. Returns whether the entry ended up enabled (its state as written).
fn record_identity(
    config_path: &Path,
    keystore_dir: &Path,
    nick: &HsNickname,
    key_bytes: &[u8],
    address: &str,
    ports: Option<Vec<OnionServicePort>>,
) -> Result<bool, KeysError> {
    let key = IdentityKey::new(store::encode_key(key_bytes)).map_err(anyhow::Error::msg)?;
    let name = nick.to_string();
    let address = address.to_owned();
    let ports_enabled = Config::update_onion_services(config_path, |services| {
        let service = services.iter_mut().find(|entry| entry.nickname == name);
        match service {
            Some(entry) => {
                entry.address = Some(address.clone());
                entry.key = Some(key);
                if let Some(ports) = ports {
                    entry.ports = ports;
                    entry.enabled = true;
                }
                Ok(entry.enabled && !entry.ports.is_empty())
            }
            None => {
                let entry = OnionServiceEntry {
                    nickname: name,
                    enabled: ports.is_some(),
                    address: Some(address.clone()),
                    key: Some(key),
                    circuit_hops: DEFAULT_CIRCUIT_HOPS,
                    ports: ports.unwrap_or_default(),
                };
                let enabled = entry.enabled && !entry.ports.is_empty();
                services.push(entry);
                Ok(enabled)
            }
        }
    })?;
    forget_keystore_copy(keystore_dir, nick)?;
    Ok(ports_enabled)
}

/// Drop the keystore's copy of `nick`: the file is the source, and the next
/// launch writes the key it holds back into the keystore.
fn forget_keystore_copy(keystore_dir: &Path, nick: &HsNickname) -> Result<(), KeysError> {
    if store::identity_file(keystore_dir, nick).is_some() {
        store::remove_all(keystore_dir, nick)?;
    }
    Ok(())
}
