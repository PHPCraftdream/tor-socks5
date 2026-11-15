//! Onion-service helpers: the address re-exports (always built) plus the key
//! store, CLI commands and the vanity CLI shell (behind the `onion-service`
//! feature). The address math and the search core live in the
//! `tor-socks5-onion` crate.

pub(crate) mod address;
#[cfg(feature = "onion-service")]
pub(crate) mod commands;
#[cfg(feature = "onion-service")]
pub(crate) mod identity;
#[cfg(feature = "onion-service")]
pub(crate) mod service;
#[cfg(feature = "onion-service")]
pub(crate) mod store;
#[cfg(feature = "onion-service")]
pub(crate) mod vanity;
