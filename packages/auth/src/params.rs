//! Fixed Argon2id parameters. Centralised so the CLI helpers, the
//! verifier and the on-disk hashes never drift apart. Values mirror the
//! ones used by `resocks5`: memory-bounded at 5 MiB, two passes, single
//! thread — fits comfortably on commodity boxes while still costing
//! enough to make offline brute force expensive.

use argon2::{Algorithm, Argon2, Params, Version};

/// Memory cost in KiB.
pub const ARGON_M_KIB: u32 = 5120;
/// Time cost (iterations).
pub const ARGON_T: u32 = 2;
/// Parallelism (number of lanes).
pub const ARGON_P: u32 = 1;

/// Build a fresh `Argon2` instance with the canonical project parameters.
/// Each call returns a new value because `Argon2` is not `Sync` once the
/// secret slice is bound; the construction cost is negligible.
pub fn argon2_instance() -> Argon2<'static> {
    let params = Params::new(ARGON_M_KIB, ARGON_T, ARGON_P, None)
        .expect("hard-coded Argon2 params must be valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}
