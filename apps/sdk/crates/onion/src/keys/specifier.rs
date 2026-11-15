//! Key-specifier types for onion identity keys.
//!
//! These types repeat the `HsIdKeypairSpecifier` / `HsIdPublicKeySpecifier`
//! declarations of `tor-hsservice` 0.48 (`src/keys.rs`) with the same
//! `prefix`/`role`, derived through tor-keymgr's public
//! `derive_deftly_template_KeySpecifier`, so keys written through this module
//! land at exactly the paths arti (which uses tor-hsservice's own
//! specifiers) reads. When arti is upgraded, these declarations must be
//! checked against the new tor-hsservice. `tor-hsservice` itself is
//! deliberately NOT a dependency: it would pull the whole Tor client, while
//! this module needs only tor-keymgr/tor-hscrypto.
//!
//! The public specifier MUST carry the `keypair_specifier` attribute (and the
//! matching `From<&HsIdPublicKeySpecifier>` impl, which the generated code
//! requires): tor-keymgr does not read the public part of `HsIdKey` from a
//! separate file but derives it from the stored pair via that link
//! (`KeyMgr::get_from_store`). Without the attribute, reading the address
//! after the pair has been written returns `None`.
//!
//! `ctor_path` is not set: the C-tor keystore is not used.

use tor_keymgr::derive_deftly::Deftly;
use tor_keymgr::derive_deftly_template_KeySpecifier;
use tor_keymgr::KeySpecifier;
use tor_persist::hsnickname::HsNickname;

/// The long-term identity keypair specifier of a service: `hss/<nickname>/ks_hs_id`.
///
/// Mirrors `tor_hsservice::HsIdKeypairSpecifier` (same prefix `hss`, same
/// role `KS_hs_id`), see the [module documentation](self).
#[derive(Deftly, Debug, Clone, PartialEq, Eq)]
#[derive_deftly(KeySpecifier)]
#[deftly(prefix = "hss")]
#[deftly(role = "KS_hs_id")]
#[deftly(summary = "Long-term identity keypair")]
pub struct HsIdKeypairSpecifier {
    /// The nickname of the hidden service.
    nickname: HsNickname,
}

impl HsIdKeypairSpecifier {
    /// A specifier for `nickname`'s identity keypair.
    pub fn new(nickname: HsNickname) -> Self {
        Self { nickname }
    }

    /// The nickname this specifier names.
    pub fn nickname(&self) -> &HsNickname {
        &self.nickname
    }
}

/// The public identity key specifier of a service: `hss/<nickname>/kp_hs_id`.
///
/// Mirrors `tor_hsservice::HsIdPublicKeySpecifier` (same prefix `hss`, same
/// role `KP_hs_id`), see the [module documentation](self).
///
/// The `keypair_specifier` attribute is REQUIRED: tor-keymgr derives the
/// public part of `HsIdKey` from the stored pair through it
/// (`KeyMgr::get_from_store`); without it reading the address after writing
/// the pair returns `None`.
#[derive(Deftly, Debug, Clone, PartialEq, Eq)]
#[derive_deftly(KeySpecifier)]
#[deftly(prefix = "hss")]
#[deftly(role = "KP_hs_id")]
#[deftly(keypair_specifier = HsIdKeypairSpecifier)]
#[deftly(summary = "Public part of the identity key")]
pub struct HsIdPublicKeySpecifier {
    /// The nickname of the hidden service.
    nickname: HsNickname,
}

impl HsIdPublicKeySpecifier {
    /// A specifier for `nickname`'s public identity key.
    pub fn new(nickname: HsNickname) -> Self {
        Self { nickname }
    }

    /// The nickname this specifier names.
    pub fn nickname(&self) -> &HsNickname {
        &self.nickname
    }
}

impl From<&HsIdPublicKeySpecifier> for HsIdKeypairSpecifier {
    fn from(spec: &HsIdPublicKeySpecifier) -> HsIdKeypairSpecifier {
        HsIdKeypairSpecifier::new(spec.nickname().clone())
    }
}
