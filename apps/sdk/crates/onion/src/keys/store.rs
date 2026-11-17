//! Arti native keystore access for onion-service identity keys.
//!
//! Keys are read and written exclusively through the tor-keymgr API
//! ([`ArtiNativeKeystore`] + [`KeyMgr`]); the on-disk format is never
//! hand-rolled. The onion address is derived from the identity key by
//! `HsId`'s own `Display` (tor-hscrypto), never locally.
//!
//! The keystore directory is always an explicit argument (the caller decides
//! where it lives); a typical layout is
//! `<config dir>/arti-data/state/keystore/hss/<nickname>/`, where the
//! identity keypair lives in `ks_hs_id.ed25519_expanded_private`
//! (OpenSSH-format file with the custom `ed25519-expanded@spec.torproject.org`
//! algorithm — that file *is* the portable export format).
//!
//! The keystore is a copy: the onion services file (`<stem>.onion.ktav`)
//! is where the services and their keys are kept, and a launch puts the
//! key from there into the keystore, which is what arti reads. The key
//! text in the file is the base64 of that same key file.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use data_encoding::BASE64;
use fs_mistrust::Mistrust;
use safelog::DisplayRedacted as _;
use tor_hscrypto::pk::{HsIdKey, HsIdKeypair};
use tor_keymgr::{ArtiNativeKeystore, KeyMgr, KeyMgrBuilder, KeystoreSelector};
use tor_llcrypto::rng::CautiousRng;
use zeroize::Zeroizing;

use super::specifier::{HsIdKeypairSpecifier, HsIdPublicKeySpecifier};
use tor_persist::hsnickname::{HsNickname, InvalidNickname};

/// Errors of the onion identity keystore operations.
///
/// The `Display` texts of the typed variants match the messages the
/// `socks5-proxy` onion commands printed before this module existed, so the
/// CLI output does not change. Everything else (I/O, tor-keymgr internals,
/// settlement refusals) arrives as [`KeysError::Storage`] wrapping the
/// original `anyhow` chain.
#[derive(Debug, thiserror::Error)]
pub enum KeysError {
    /// The service nickname is not valid.
    #[error("invalid service nickname")]
    InvalidNickname(#[from] InvalidNickname),
    /// An identity already exists for the nickname.
    #[error("nickname {0:?} already has an identity")]
    IdentityExists(String),
    /// No service with this nickname.
    #[error("no onion service named {0:?}")]
    NotFound(String),
    /// The service exists but has no identity key yet.
    #[error("service {0:?} has no key yet: it is created at the first start")]
    NoKey(String),
    /// The export output file already exists.
    #[error("{0} already exists")]
    ExportExists(String),
    /// The derived address does not match the address the key source claimed.
    #[error("address mismatch; key not saved")]
    AddressMismatch,
    /// Anything else, with its original context chain.
    #[error(transparent)]
    Storage(#[from] anyhow::Error),
}

/// File-name prefix of the identity keypair inside `hss/<nickname>/`.
const IDENTITY_FILE_PREFIX: &str = "ks_hs_id.";
/// Extension the Arti native keystore uses for expanded ed25519 keypairs.
const EXPANDED_PRIVATE_EXT: &str = "ed25519_expanded_private";

/// Create `dir` (and missing parents) owner-only on Unix. The staging parent is
/// the keystore directory, which Arti's permission check requires to be private;
/// a default-mode `create_dir_all` here would make the later `open` refuse it.
fn ensure_private_dir(dir: &Path) -> Result<(), KeysError> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir).context("creating the staging parent")?;
    Ok(())
}

/// Parse and validate a service nickname.
pub fn nickname(s: &str) -> Result<HsNickname, KeysError> {
    HsNickname::new(s.to_owned()).map_err(KeysError::InvalidNickname)
}

/// Cross-process mutation lock (sibling `<keystore>.lock`).
///
/// Serialises onion mutations with each other AND with the running server:
/// the server holds this lock for the whole time its configured onion
/// services are published, so key mutations cannot race a live service. A
/// caller that hits the busy lock must wait or retry on its own.
pub fn lock(dir: &Path) -> Result<persist_lock::PathLock, KeysError> {
    lock_with(dir, persist_lock::CLI_LOCK_WAIT)
}

/// [`lock`] with an explicit wait bound (tests use a short one).
pub fn lock_with(dir: &Path, wait: Duration) -> Result<persist_lock::PathLock, KeysError> {
    Ok(persist_lock::PathLock::acquire_bounded(dir, wait).context(
        "onion keystore lock is busy (a running server or another onion operation holds it)",
    )?)
}

/// Open (creating if absent) the Arti native keystore at `dir`.
pub fn open(dir: &Path) -> Result<KeyMgr, KeysError> {
    let store = ArtiNativeKeystore::from_path_and_mistrust(dir, &Mistrust::new())
        .context("opening the onion keystore")?;
    Ok(KeyMgrBuilder::default()
        .primary_store(Box::new(store))
        .build()
        .context("building the key manager")?)
}

/// Onion address of `nick`, or `None` if the keystore holds no identity.
pub fn address(keymgr: &KeyMgr, nick: &HsNickname) -> Result<Option<String>, KeysError> {
    let spec = HsIdPublicKeySpecifier::new(nick.clone());
    Ok(keymgr
        .get::<HsIdKey>(&spec)
        .context("reading the onion identity")?
        .map(|key| key.id().display_unredacted().to_string()))
}

/// Whether an identity keypair for `nick` exists in the keystore.
pub fn exists(keymgr: &KeyMgr, nick: &HsNickname) -> Result<bool, KeysError> {
    let spec = HsIdKeypairSpecifier::new(nick.clone());
    Ok(keymgr
        .get::<HsIdKeypair>(&spec)
        .context("reading the onion identity key")?
        .is_some())
}

/// The `.onion` address of an identity keypair.
pub fn address_of(key: &HsIdKeypair) -> String {
    HsIdKey::from(key).id().display_unredacted().to_string()
}

/// The key text of the onion services file: base64 of a keystore key file.
pub fn encode_key(file_bytes: &[u8]) -> String {
    BASE64.encode(file_bytes)
}

/// The keystore key file bytes behind a key text of the onion services file.
pub fn decode_key(text: &str) -> Result<Zeroizing<Vec<u8>>, KeysError> {
    Ok(Zeroizing::new(
        BASE64
            .decode(text.as_bytes())
            .context("the key is not valid base64")?,
    ))
}

/// Generate a fresh random identity keypair for `nick`.
///
/// `overwrite` replaces any existing key — and thus the old .onion address;
/// the caller owns warning the user about that.
pub fn generate(
    keymgr: &KeyMgr,
    nick: &HsNickname,
    overwrite: bool,
) -> Result<HsIdKeypair, KeysError> {
    let spec = HsIdKeypairSpecifier::new(nick.clone());
    Ok(keymgr
        .generate::<HsIdKeypair>(
            &spec,
            KeystoreSelector::Primary,
            &mut CautiousRng,
            overwrite,
        )
        .context("generating the onion identity key")?)
}

/// Store `key` as the identity keypair of `nick`.
pub fn insert(
    keymgr: &KeyMgr,
    key: HsIdKeypair,
    nick: &HsNickname,
    overwrite: bool,
) -> Result<(), KeysError> {
    let spec = HsIdKeypairSpecifier::new(nick.clone());
    keymgr
        .insert(key, &spec, KeystoreSelector::Primary, overwrite)
        .context("storing the onion identity key")?;
    Ok(())
}

/// Path of the on-disk identity key file for `nick`, if present.
pub fn identity_file(keystore_dir: &Path, nick: &HsNickname) -> Option<PathBuf> {
    let dir = service_dir(keystore_dir, nick)?;
    std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(IDENTITY_FILE_PREFIX))
        })
}

/// Remove every key of `nick` (the whole `hss/<nickname>` directory).
pub fn remove_all(keystore_dir: &Path, nick: &HsNickname) -> Result<(), KeysError> {
    let dir = service_dir(keystore_dir, nick).context("reading the keystore directory")?;
    if !dir.is_dir() {
        return Err(anyhow::anyhow!("no keys found for nickname {:?}", nick.to_string()).into());
    }
    Ok(std::fs::remove_dir_all(&dir)
        .with_context(|| format!("removing keystore entry {}", dir.display()))?)
}

/// Parse `bytes` as an Arti-keystore identity key file.
///
/// Validation goes through the keystore's own OpenSSH parser: the bytes are
/// staged in a throwaway keystore under the target nickname's path and read
/// back as an [`HsIdKeypair`]. Anything that does not parse as a valid
/// expanded ed25519 keypair is rejected.
pub fn parse_identity_file(
    bytes: &[u8],
    nick: &HsNickname,
    staging_parent: &Path,
) -> Result<HsIdKeypair, KeysError> {
    // The caller chose the staging parent (the keystore dir): create it when
    // it does not exist yet.
    ensure_private_dir(staging_parent)?;
    let staging = tempfile::tempdir_in(staging_parent).context("creating a staging keystore")?;
    // Throwaway directory we just created: its parent must not fail the
    // permission check.
    let store = ArtiNativeKeystore::from_path_and_mistrust(
        staging.path(),
        &Mistrust::new_dangerously_trust_everyone(),
    )
    .context("creating a staging keystore")?;
    let rel = format!("hss/{}/ks_hs_id.{EXPANDED_PRIVATE_EXT}", nick);
    let path = staging.path().join(&rel);
    std::fs::create_dir_all(path.parent().expect("keystaging parent"))
        .context("creating the staging directory")?;
    std::fs::write(&path, bytes).with_context(|| format!("staging {}", path.display()))?;
    let keymgr = KeyMgrBuilder::default()
        .primary_store(Box::new(store))
        .build()
        .context("building the staging key manager")?;
    let spec = HsIdKeypairSpecifier::new(nick.clone());
    Ok(keymgr
        .get::<HsIdKeypair>(&spec)
        .context("parsing the identity key file")?
        .ok_or_else(|| anyhow::anyhow!("file does not contain an onion identity key"))?)
}

/// The bytes of the key file the keystore stores for `key` under `nick`:
/// the portable format, produced by the keystore's own writer in a
/// throwaway keystore (the mirror of [`parse_identity_file`]).
pub fn identity_file_bytes(
    key: HsIdKeypair,
    nick: &HsNickname,
    staging_parent: &Path,
) -> Result<Zeroizing<Vec<u8>>, KeysError> {
    ensure_private_dir(staging_parent)?;
    let staging = tempfile::tempdir_in(staging_parent).context("creating a staging keystore")?;
    let store = ArtiNativeKeystore::from_path_and_mistrust(
        staging.path(),
        &Mistrust::new_dangerously_trust_everyone(),
    )
    .context("creating a staging keystore")?;
    let keymgr = KeyMgrBuilder::default()
        .primary_store(Box::new(store))
        .build()
        .context("building the staging key manager")?;
    insert(&keymgr, key, nick, true)?;
    let file = identity_file(staging.path(), nick).context("the staged identity file")?;
    Ok(Zeroizing::new(
        std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?,
    ))
}

/// Open a new secret file for writing (owner-only on Unix, refusing any
/// existing path).
#[cfg(unix)]
fn open_new(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    // `create_new` (O_CREAT|O_EXCL) refuses any existing path, symlinks included.
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

/// Open a new secret file for writing (refusing any existing path).
#[cfg(not(unix))]
fn open_new(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

/// Write a key file, restricting permissions to the owner where the OS
/// supports it (Unix: mode 0600, set at creation). On Windows there is no
/// POSIX mode: the mode call is a no-op there and access is governed by the
/// ACLs of the directory the caller chose.
///
/// Without `force` the file must not exist yet (`create_new`, which never
/// follows an existing symlink) and an existing path is a typed
/// [`KeysError::ExportExists`]. With `force` the bytes replace `path`
/// atomically through a uniquely named temp file in the same parent
/// directory (a symlink at `path` is replaced, not followed); a failure
/// before the rename cleans the temp file up.
pub fn write_secret_file(path: &Path, bytes: &[u8], force: bool) -> Result<(), KeysError> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    if force {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let temp = tempfile::Builder::new()
            .prefix("onion-key")
            .tempfile_in(parent)
            .with_context(|| format!("creating a temp file next to {}", path.display()))?;
        #[cfg(unix)]
        temp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(anyhow::Error::new)?;
        let (mut file, temp_path) = temp.into_parts();
        file.write_all(bytes).map_err(anyhow::Error::new)?;
        file.sync_all().map_err(anyhow::Error::new)?;
        drop(file);
        std::fs::rename(&temp_path, path)
            .with_context(|| format!("replacing {}", path.display()))?;
        return Ok(());
    }

    let mut file = match open_new(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(KeysError::ExportExists(path.display().to_string()));
        }
        Err(error) => {
            return Err(anyhow::Error::new(error)
                .context(format!("creating {}", path.display()))
                .into())
        }
    };
    file.write_all(bytes).map_err(anyhow::Error::new)?;
    file.sync_all().map_err(anyhow::Error::new)?;
    Ok(())
}

/// `hss/<nickname>` inside the keystore, if the keystore root is readable.
fn service_dir(keystore_dir: &Path, nick: &HsNickname) -> Option<PathBuf> {
    Some(keystore_dir.join("hss").join(nick.to_string()))
}
