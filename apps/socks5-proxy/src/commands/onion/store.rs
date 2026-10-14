//! Arti native keystore access for onion-service identity keys.
//!
//! Keys are read and written exclusively through the tor-keymgr API
//! ([`ArtiNativeKeystore`] + [`KeyMgr`]); the on-disk format is never
//! hand-rolled. The onion address is derived from the identity key by
//! `HsId`'s own `Display` (tor-hscrypto), never locally.
//!
//! Layout: `<config dir>/arti-data/state/keystore/hss/<nickname>/`, where
//! the identity keypair lives in `ks_hs_id.ed25519_expanded_private`
//! (OpenSSH-format file with the custom `ed25519-expanded@spec.torproject.org`
//! algorithm — that file *is* the portable export format).

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use fs_mistrust::Mistrust;
use safelog::DisplayRedacted as _;
use tor_hscrypto::pk::{HsIdKey, HsIdKeypair};
use tor_hsservice::{HsIdKeypairSpecifier, HsIdPublicKeySpecifier, HsNickname};
use tor_keymgr::{ArtiNativeKeystore, KeyMgr, KeyMgrBuilder, KeystoreSelector};
use tor_llcrypto::rng::CautiousRng;

/// File-name prefix of the identity keypair inside `hss/<nickname>/`.
const IDENTITY_FILE_PREFIX: &str = "ks_hs_id.";
/// Extension the Arti native keystore uses for expanded ed25519 keypairs.
const EXPANDED_PRIVATE_EXT: &str = "ed25519_expanded_private";

/// The keystore directory for a config: `<config dir>/arti-data/state/keystore`.
///
/// Same base as the running server: `tor_setup::arti_base_dir` is what the
/// server hands to arti as its state base, and arti pins its keystore under
/// `<state>/keystore`.
pub(crate) fn keystore_dir(config_path: Option<&Path>) -> PathBuf {
    crate::tor_setup::arti_base_dir(config_path)
        .join("state")
        .join("keystore")
}

/// Parse and validate a service nickname.
pub(crate) fn nickname(s: &str) -> Result<HsNickname> {
    HsNickname::new(s.to_owned()).context("invalid service nickname")
}

/// Cross-process mutation lock (sibling `<keystore>.lock`).
///
/// Serialises concurrent `tor-socks5 onion` mutations with each other. Note:
/// a *running* proxy does not hold this lock (arti guards its own state via
/// sqlite), so this does not exclude a live server — it exists so that two
/// CLI invocations cannot interleave, matching how the other CLI commands
/// use `persist_lock`.
pub(crate) fn lock(dir: &Path) -> Result<persist_lock::PathLock> {
    persist_lock::PathLock::acquire_bounded(dir, persist_lock::CLI_LOCK_WAIT)
        .context("onion keystore lock is busy (another onion command may be running)")
}

/// Open (creating if absent) the Arti native keystore at `dir`.
pub(crate) fn open(dir: &Path) -> Result<KeyMgr> {
    let store = ArtiNativeKeystore::from_path_and_mistrust(dir, &Mistrust::new())
        .context("opening the onion keystore")?;
    KeyMgrBuilder::default()
        .primary_store(Box::new(store))
        .build()
        .context("building the key manager")
}

/// Onion address of `nick`, or `None` if the keystore holds no identity.
pub(crate) fn address(keymgr: &KeyMgr, nick: &HsNickname) -> Result<Option<String>> {
    let spec = HsIdPublicKeySpecifier::new(nick.clone());
    Ok(keymgr
        .get::<HsIdKey>(&spec)
        .context("reading the onion identity")?
        .map(|key| key.id().display_unredacted().to_string()))
}

/// Whether an identity keypair for `nick` exists in the keystore.
pub(crate) fn exists(keymgr: &KeyMgr, nick: &HsNickname) -> Result<bool> {
    let spec = HsIdKeypairSpecifier::new(nick.clone());
    Ok(keymgr
        .get::<HsIdKeypair>(&spec)
        .context("reading the onion identity key")?
        .is_some())
}

/// Generate a fresh random identity keypair for `nick`.
///
/// `overwrite` replaces any existing key — and thus the old .onion address;
/// the caller owns warning the user about that.
pub(crate) fn generate(keymgr: &KeyMgr, nick: &HsNickname, overwrite: bool) -> Result<HsIdKeypair> {
    let spec = HsIdKeypairSpecifier::new(nick.clone());
    keymgr
        .generate::<HsIdKeypair>(
            &spec,
            KeystoreSelector::Primary,
            &mut CautiousRng,
            overwrite,
        )
        .context("generating the onion identity key")
}

/// Store `key` as the identity keypair of `nick`.
pub(crate) fn insert(
    keymgr: &KeyMgr,
    key: HsIdKeypair,
    nick: &HsNickname,
    overwrite: bool,
) -> Result<()> {
    let spec = HsIdKeypairSpecifier::new(nick.clone());
    keymgr
        .insert(key, &spec, KeystoreSelector::Primary, overwrite)
        .context("storing the onion identity key")?;
    Ok(())
}

/// Path of the on-disk identity key file for `nick`, if present.
pub(crate) fn identity_file(keystore_dir: &Path, nick: &HsNickname) -> Option<PathBuf> {
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
pub(crate) fn remove_all(keystore_dir: &Path, nick: &HsNickname) -> Result<()> {
    let dir = service_dir(keystore_dir, nick).context("reading the keystore directory")?;
    if !dir.is_dir() {
        bail!("no keys found for nickname {:?}", nick.to_string());
    }
    std::fs::remove_dir_all(&dir)
        .with_context(|| format!("removing keystore entry {}", dir.display()))
}

/// Parse `bytes` as an Arti-keystore identity key file.
///
/// Validation goes through the keystore's own OpenSSH parser: the bytes are
/// staged in a throwaway keystore under the target nickname's path and read
/// back as an [`HsIdKeypair`]. Anything that does not parse as a valid
/// expanded ed25519 keypair is rejected.
pub(crate) fn parse_identity_file(bytes: &[u8], nick: &HsNickname) -> Result<HsIdKeypair> {
    let staging = tempfile::tempdir().context("creating a staging keystore")?;
    // Throwaway directory we just created: its parent (e.g. a shared /tmp) must
    // not fail the permission check.
    let store = ArtiNativeKeystore::from_path_and_mistrust(
        staging.path(),
        &Mistrust::new_dangerously_trust_everyone(),
    )
    .context("creating a staging keystore")?;
    let rel = format!("hss/{}/ks_hs_id.{EXPANDED_PRIVATE_EXT}", nick);
    let path = staging.path().join(&rel);
    std::fs::create_dir_all(path.parent().expect("keystaging parent"))?;
    std::fs::write(&path, bytes).with_context(|| format!("staging {}", path.display()))?;
    let keymgr = KeyMgrBuilder::default()
        .primary_store(Box::new(store))
        .build()
        .context("building the staging key manager")?;
    let spec = HsIdKeypairSpecifier::new(nick.clone());
    keymgr
        .get::<HsIdKeypair>(&spec)
        .context("parsing the identity key file")?
        .ok_or_else(|| anyhow::anyhow!("file does not contain an onion identity key"))
}

/// `hss/<nickname>` inside the keystore, if the keystore root is readable.
fn service_dir(keystore_dir: &Path, nick: &HsNickname) -> Option<PathBuf> {
    Some(keystore_dir.join("hss").join(nick.to_string()))
}
