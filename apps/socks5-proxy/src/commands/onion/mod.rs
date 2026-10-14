//! Onion-service helpers: address and vanity core (always built) plus the
//! key store and CLI commands (behind the `onion-service` feature).

pub(crate) mod address;
#[cfg(feature = "onion-service")]
pub(crate) mod commands;
#[cfg(feature = "onion-service")]
pub(crate) mod store;
pub(crate) mod vanity;
