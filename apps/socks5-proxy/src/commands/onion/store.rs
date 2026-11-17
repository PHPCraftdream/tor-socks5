//! Thin shell over `tor-socks5-onion::keys`: the Arti native keystore access
//! moved to the crate. Keystore paths are derived via `proxy_config`
//! (`proxy_config::arti_keystore_dir`).

#[cfg(feature = "onion-service")]
pub(crate) use ::tor_socks5_onion::keys::nickname;

#[cfg(all(feature = "onion-service", test))]
pub(crate) use ::tor_socks5_onion::keys::{generate, identity_file, open};
