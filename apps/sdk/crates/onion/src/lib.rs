//! v3 onion service addresses and the vanity prefix search, without Tor.
//!
//! [`address`] derives and parses `.onion` addresses (rend-spec-v3 checksum
//! layout) and generates service keypairs; [`vanity`] searches for a keypair
//! whose address starts with a chosen base32 prefix, on plain threads with an
//! external cancel flag and a shared progress counter. Nothing here prints,
//! touches the network or links Tor: stderr progress, Ctrl-C handling and the
//! key store stay with the application (`apps/socks5-proxy`).
//!
//! Behind the `keys` feature, [`keys`] adds onion *identity* management: the
//! Arti native keystore (tor-keymgr/tor-hscrypto only — no Tor client, no
//! patch-kit), the onion services file, and the command cores `new`, `list`,
//! `show`, `export`, `import` and `remove` are built on. The keystore
//! directory is always an explicit argument; printing, prompting and
//! confirmation stay with the application.
//!
//! Behind the Tor-dependent `host` feature, [`host`] adds the server-side
//! onion-service hosting that used to live in the binary: identity
//! settlement, the gradual launch (at most 4 at a time), stream forwarding
//! with per-service and process-wide caps, lifecycle logging and a `watch`
//! status snapshot. The keystore directory and the services-file location
//! are explicit arguments of [`host::OnionHostConfig`]; the host never
//! prints and never installs process state — shutdown is a cancellation
//! token, and dropping the handle only cancels that token.

#![warn(missing_docs)]

pub mod address;
pub mod vanity;

#[cfg(feature = "keys")]
pub mod keys;

#[cfg(feature = "host")]
pub mod host;
