//! Thin shell over `tor-socks5-onion::keys`: the Arti native keystore access
//! moved to the crate; what stays here is the keystore directory of a config.

use std::path::{Path, PathBuf};

#[cfg(feature = "onion-service")]
pub(crate) use ::tor_socks5_onion::keys::nickname;

#[cfg(all(feature = "onion-service", test))]
pub(crate) use ::tor_socks5_onion::keys::{generate, identity_file, open};

/// The keystore directory for a config: `<config dir>/arti-data/state/keystore`.
///
/// Same base as the running server: `tor_setup::arti_base_dir` is what the
/// server hands to arti as its state base, and arti pins its keystore under
/// `<state>/keystore`. The library takes the directory as an explicit
/// argument; deriving it from the config stays with the application.
pub(crate) fn keystore_dir(config_path: Option<&Path>) -> PathBuf {
    tor_socks5_runtime::tor_setup::arti_base_dir(config_path)
        .join("state")
        .join("keystore")
}
