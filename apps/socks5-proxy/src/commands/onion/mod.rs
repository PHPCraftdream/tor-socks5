//! Onion-service helpers: the keystore directory of a config, the CLI
//! commands and the vanity CLI shell (behind
//! the `onion-service` feature). The keystore/identity logic and the address
//! math live in the `tor-socks5-onion` crate.

#[cfg(feature = "onion-service")]
pub(crate) mod commands;
// The hosting shell moved into the server crate (SDK-10); the CLI onion
// commands do not call it. The file stays (fail-closed on deletions) until
// the API step decides its fate.
#[cfg(feature = "onion-service")]
#[allow(dead_code)]
pub(crate) mod service;
#[cfg(feature = "onion-service")]
pub(crate) mod store;
#[cfg(feature = "onion-service")]
pub(crate) mod vanity;
