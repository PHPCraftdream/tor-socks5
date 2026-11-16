//! Onion-service CLI commands and vanity helpers (behind the
//! `onion-service` feature). The keystore/identity logic and address math
//! live in the `tor-socks5-onion` crate.

#[cfg(feature = "onion-service")]
pub(crate) mod commands;
#[cfg(feature = "onion-service")]
pub(crate) mod store;
#[cfg(feature = "onion-service")]
pub(crate) mod vanity;
