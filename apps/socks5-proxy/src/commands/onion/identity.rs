//! Thin shell over `tor-socks5-onion::keys`: identity settlement moved to
//! the crate; the launch keeps calling it through this module name.

#[cfg(feature = "onion-service")]
pub(crate) use ::tor_socks5_onion::keys::prepare_all;

/// Test helper re-export (`fresh_identity` exists only in test builds: the
/// crate exposes it behind `test-seams`, enabled by this crate's
/// dev-dependency on `tor-socks5-onion`).
#[cfg(all(feature = "onion-service", test))]
pub(crate) use ::tor_socks5_onion::keys::fresh_identity;
