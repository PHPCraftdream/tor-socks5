//! Thin shell over `tor-socks5-onion`: the address math lives in the crate.

#[cfg(feature = "onion-service")]
pub(crate) use ::tor_socks5_onion::address::{generate, Keypair};
