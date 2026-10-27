//! User record persisted on disk.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
/// One account record in the on-disk users registry — one entry of the
/// `users` array in the `tor-socks5.users.ktav` file. Parsing is strict:
/// an unknown key inside a record is an error, so a schema mismatch is
/// never silently ignored.
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
    /// Дополнительный ACL клиентов для этой учётки. None = ограничения нет.
    /// Явная пустая строка — ошибка загрузки, а не None/inherit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_clients: Option<client_acl::AllowedClients>,
    /// Per-account SOCKS chain selection: omitted inherits global configuration.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "client_acl::socks5_endpoint_field")]
    pub pre_socks5: Option<client_acl::EndpointOverride>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "client_acl::socks5_endpoint_field")]
    pub post_socks5: Option<client_acl::EndpointOverride>,
}

fn default_true() -> bool {
    true
}
