//! Onion-service helpers: the keystore directory of a config, the CLI
//! commands and the vanity CLI shell (behind
//! the `onion-service` feature). The keystore/identity logic and the address
//! math live in the `tor-socks5-onion` crate.

#[cfg(feature = "onion-service")]
pub(crate) mod commands;
#[cfg(feature = "onion-service")]
pub(crate) mod service;
#[cfg(feature = "onion-service")]
pub(crate) mod store;
#[cfg(feature = "onion-service")]
pub(crate) mod vanity;
