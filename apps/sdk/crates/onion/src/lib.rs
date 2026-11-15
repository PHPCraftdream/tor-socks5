//! v3 onion service addresses and the vanity prefix search, without Tor.
//!
//! [`address`] derives and parses `.onion` addresses (rend-spec-v3 checksum
//! layout) and generates service keypairs; [`vanity`] searches for a keypair
//! whose address starts with a chosen base32 prefix, on plain threads with an
//! external cancel flag and a shared progress counter. Nothing here prints,
//! touches the network or links Tor: stderr progress, Ctrl-C handling and the
//! key store stay with the application (`apps/socks5-proxy`).

#![warn(missing_docs)]

pub mod address;
pub mod vanity;
