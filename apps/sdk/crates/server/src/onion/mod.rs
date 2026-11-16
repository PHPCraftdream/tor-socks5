//! Onion-service hosting shell, moved from the binary with the server tree
//! (SDK-10): `spawn_services` filters the enabled services and hands them,
//! the keystore directory and the config path to the host
//! (`tor_socks5_onion::host`). The launch choreography, the launch logs, the
//! keystore lock and the status snapshot all live in the library crate.
//! Gated on the `onion-service` feature, like the binary's shell was.

#[cfg(feature = "onion-service")]
pub(crate) mod service;
