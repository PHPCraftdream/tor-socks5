//! Onion identity keystore and identity management.
//!
//! The onion services file (`<stem>.onion.ktav`) is the source of truth: a
//! service's `key` is its identity and `address` the address that key gives.
//! The Arti native keystore is a copy: a launch (see [`identity`]) puts the
//! key from the file into the keystore, which is what arti reads, and the
//! command cores here (see [`ops`]) drop the copy whenever the file gains
//! the key. Key files are never hand-rolled — everything goes through the
//! tor-keymgr API — and the portable export format is simply the keystore's
//! own key-file bytes (base64 in the file, raw on export).
//!
//! The keystore directory is always an explicit argument: this module never
//! derives it from a config path. Printing, prompting, confirmations and
//! port-string parsing stay with the application.
//!
//! Error type: [`KeysError`], whose typed variants keep the messages the
//! onion commands have always printed; everything else wraps the original
//! `anyhow` chain.

pub mod identity;
pub mod ops;
pub(crate) mod specifier;
pub(crate) mod store;

#[cfg(test)]
pub(crate) use identity::ensure;
pub use identity::{prepare_all, PreparationFailure, PreparedService};
pub use ops::{
    create_service, create_service_with_group, export_identity, identity_exists, import_identity,
    import_identity_with_group, list_services, remove_service, show_service, GroupSpec,
    NewIdentity, Recorded,
};
pub use store::{address, address_of, decode_key, encode_key, lock, nickname, KeysError};

#[cfg(any(test, feature = "test-seams"))]
pub use specifier::{HsIdKeypairSpecifier, HsIdPublicKeySpecifier};
#[cfg(any(test, feature = "test-seams"))]
pub use store::{
    generate, identity_file, identity_file_bytes, insert, lock_with, open, parse_identity_file,
    remove_all, write_secret_file,
};

#[cfg(any(test, feature = "test-seams"))]
pub use identity::fresh_identity;

#[cfg(test)]
mod ops_tests;
