//! Thin shell over `tor-socks5-onion::keys`: the Arti native keystore access
//! moved to the crate. Keystore paths are derived via `tor_socks5::config`
//! (`tor_socks5::config::arti_keystore_dir`).

#[cfg(feature = "onion-service")]
pub(crate) use tor_socks5::onion::keys::nickname;

#[cfg(all(feature = "onion-service", test))]
pub(crate) use tor_socks5::onion::keys::{generate, identity_file, open};
