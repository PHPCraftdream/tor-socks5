//! User record persisted on disk.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct User {
    /// Unique username. Used as the SOCKS5 USER field at login.
    pub name: String,
    /// Argon2id PHC string (`$argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>`).
    pub hash: String,
    /// Soft-disable. Disabled accounts silently fail authentication
    /// (no info-leak about whether the account exists).
    #[serde(default = "default_true")]
    pub is_enabled: bool,
    /// Whether this account may open connections to `.onion` hidden
    /// services. Defaults to `false`: an account cannot reach onion
    /// addresses unless explicitly granted. Older registry files that
    /// predate this field load as `false`.
    #[serde(default)]
    pub allowed_onion: bool,
}

fn default_true() -> bool {
    true
}
