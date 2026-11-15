//! The on-disk users registry and its administration.
//!
//! [`UsersConfig`] / [`User`] are the file format; [`Registry`] is the
//! transactional way to edit it (what the `users` CLI commands do).

mod ops;
mod user;
mod users_config;

#[cfg(test)]
mod ops_tests;

pub use ops::{parse_pool_override, Hop, NewUser, Registry, RegistryError};
pub use user::User;
pub use users_config::UsersConfig;
