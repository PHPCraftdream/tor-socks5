//! Account administration on the on-disk users registry.
//!
//! Library form of the `users` CLI commands. Every mutation is one
//! cross-process transaction: take the registry's [`PathLock`] (bounded
//! wait), load **under it**, change, save atomically, release. Argon2id
//! hashing always happens before the lock is taken, never under it.
//!
//! Nothing here prompts or prints: the caller supplies passwords and
//! decides what to show. Use [`Registry::ensure_absent`] /
//! [`Registry::ensure_present`] to fail fast before asking a human for
//! input; the authoritative check re-runs inside the transaction.

use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use client_acl::{PoolOverride, ProxyPool, Socks5Endpoint};
use persist_lock::{PathLock, CLI_LOCK_WAIT};

use super::user::User;
use super::users_config::UsersConfig;
use crate::compute_hash::{compute_hash, verify_hash};
use crate::state::INIT_SENTINEL;

/// Why a registry operation failed.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// The account already exists.
    #[error("user \"{0}\" already exists — use `set-password` to change the password")]
    AlreadyExists(String),
    /// The account does not exist.
    #[error("user \"{0}\" does not exist")]
    NotFound(String),
    /// An empty password was given.
    #[error("password must not be empty")]
    EmptyPassword,
    /// The hop was neither `pre` nor `post`.
    #[error("hop must be `pre` or `post`")]
    InvalidHop,
    /// A proxy endpoint failed to parse.
    #[error("invalid proxy endpoint")]
    InvalidEndpoint,
    /// The endpoints do not form a valid pool.
    #[error("{0}")]
    InvalidPool(String),
    /// The previous password still verifies after a password change.
    #[error("internal error: old password still verifies after change")]
    StalePassword,
    /// The registry lock was busy, or reading, hashing or writing failed.
    #[error(transparent)]
    Storage(#[from] anyhow::Error),
}

/// Which proxy hop of an account a pool applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hop {
    /// The pool the traffic passes through before Tor.
    Pre,
    /// The pool the traffic passes through after Tor.
    Post,
}

impl FromStr for Hop {
    type Err = RegistryError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "pre" => Ok(Self::Pre),
            "post" => Ok(Self::Post),
            _ => Err(RegistryError::InvalidHop),
        }
    }
}

/// The attributes of a new account, apart from its credential.
#[derive(Debug, Clone, Default)]
pub struct NewUser {
    /// Username (the SOCKS5 USER field at login).
    pub name: String,
    /// Whether the account may open `.onion` connections.
    pub allow_onion: bool,
    /// Pre pool: `None` inherits the global pool.
    pub pre_proxies: Option<PoolOverride>,
    /// Post pool: `None` inherits the global pool.
    pub post_proxies: Option<PoolOverride>,
}

impl NewUser {
    fn into_user(self, hash: String) -> User {
        User {
            name: self.name,
            hash,
            is_enabled: true,
            allowed_onion: self.allow_onion,
            // New accounts start without a per-user client ACL.
            allowed_clients: None,
            pre_proxies: self.pre_proxies,
            post_proxies: self.post_proxies,
        }
    }
}

/// Parse the text form of a pool setting: nothing or `inherit` keeps the
/// global pool, `none` disables the hop, anything else is a list of
/// SOCKS5 endpoints forming the account's own pool.
pub fn parse_pool_override(values: &[String]) -> Result<Option<PoolOverride>, RegistryError> {
    match values {
        [] => Ok(None),
        [only] if only == "inherit" => Ok(None),
        [only] if only == "none" => Ok(Some(PoolOverride::Disabled)),
        values => {
            let members = values
                .iter()
                .map(|value| {
                    value
                        .parse::<Socks5Endpoint>()
                        .map_err(|_| RegistryError::InvalidEndpoint)
                })
                .collect::<Result<Vec<_>, _>>()?;
            ProxyPool::new(members)
                .map(|pool| Some(PoolOverride::Pool(pool)))
                .map_err(RegistryError::InvalidPool)
        }
    }
}

/// A users registry file, edited through locked transactions.
#[derive(Debug, Clone)]
pub struct Registry {
    path: PathBuf,
    lock_wait: Duration,
}

impl Registry {
    /// The registry stored at `path` (see [`UsersConfig::resolve_path`]),
    /// waiting up to [`CLI_LOCK_WAIT`] for its lock.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock_wait: CLI_LOCK_WAIT,
        }
    }

    /// Bound the wait for the registry lock to `wait`.
    #[must_use]
    pub fn with_lock_wait(mut self, wait: Duration) -> Self {
        self.lock_wait = wait;
        self
    }

    /// The registry file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read the registry. Read-only: takes no lock, since a read never
    /// publishes and so can neither lose nor clobber a writer's change.
    pub fn load(&self) -> Result<UsersConfig, RegistryError> {
        Ok(UsersConfig::load(&self.path)?)
    }

    /// Fail with [`RegistryError::AlreadyExists`] when `name` is taken.
    pub fn ensure_absent(&self, name: &str) -> Result<(), RegistryError> {
        match self.load()?.find(name) {
            Some(_) => Err(RegistryError::AlreadyExists(name.to_string())),
            None => Ok(()),
        }
    }

    /// Fail with [`RegistryError::NotFound`] when `name` is unknown.
    pub fn ensure_present(&self, name: &str) -> Result<(), RegistryError> {
        match self.load()?.find(name) {
            Some(_) => Ok(()),
            None => Err(RegistryError::NotFound(name.to_string())),
        }
    }

    /// Take the transaction lock and load the registry **under it**. The
    /// caller keeps the lock until its `save` has published.
    fn lock_and_load(&self) -> Result<(PathLock, UsersConfig), RegistryError> {
        let lock = PathLock::acquire_bounded(&self.path, self.lock_wait)?;
        let users = UsersConfig::load(&self.path)?;
        Ok((lock, users))
    }

    /// One transaction: lock, load, apply `change` to the registry, save.
    fn transact<T>(
        &self,
        change: impl FnOnce(&mut UsersConfig) -> Result<T, RegistryError>,
    ) -> Result<T, RegistryError> {
        let (lock, mut users) = self.lock_and_load()?;
        let out = change(&mut users)?;
        users.save(&self.path)?;
        drop(lock);
        Ok(out)
    }

    /// One transaction on the named account.
    fn with_user<T>(
        &self,
        name: &str,
        change: impl FnOnce(&mut User) -> T,
    ) -> Result<T, RegistryError> {
        self.transact(|users| {
            let user = users
                .find_mut(name)
                .ok_or_else(|| RegistryError::NotFound(name.to_string()))?;
            Ok(change(user))
        })
    }

    fn insert(&self, user: User) -> Result<(), RegistryError> {
        self.transact(|users| {
            if users.find(&user.name).is_some() {
                return Err(RegistryError::AlreadyExists(user.name.clone()));
            }
            users.users.push(user);
            Ok(())
        })
    }

    /// Create an account with the given password. The password is hashed
    /// (Argon2id) before the lock is taken.
    pub fn add(&self, new: NewUser, password: &str) -> Result<(), RegistryError> {
        if password.is_empty() {
            return Err(RegistryError::EmptyPassword);
        }
        let hash = compute_hash(password)?;
        self.insert(new.into_user(hash))
    }

    /// Create an account in trust-on-first-use mode: no password is set,
    /// the first non-empty one presented at login is adopted and persisted
    /// as the real hash.
    pub fn add_init(&self, new: NewUser) -> Result<(), RegistryError> {
        self.insert(new.into_user(INIT_SENTINEL.to_string()))
    }

    /// Remove an account.
    pub fn remove(&self, name: &str) -> Result<(), RegistryError> {
        self.transact(|users| {
            let before = users.users.len();
            users.users.retain(|user| user.name != name);
            if users.users.len() == before {
                return Err(RegistryError::NotFound(name.to_string()));
            }
            Ok(())
        })
    }

    /// Change an account's password. Hashing happens before the lock; the
    /// sanity check that the old password no longer verifies runs after
    /// the publish and outside the lock, and is skipped when the previous
    /// hash was the trust-on-first-use sentinel.
    pub fn set_password(&self, name: &str, password: &str) -> Result<(), RegistryError> {
        if password.is_empty() {
            return Err(RegistryError::EmptyPassword);
        }
        let new_hash = compute_hash(password)?;
        let old_hash = self.with_user(name, |user| std::mem::replace(&mut user.hash, new_hash))?;
        if old_hash != INIT_SENTINEL && verify_hash(&old_hash, password)? {
            return Err(RegistryError::StalePassword);
        }
        Ok(())
    }

    /// Set the pool of one hop; `None` inherits the global pool.
    pub fn set_proxies(
        &self,
        name: &str,
        hop: Hop,
        setting: Option<PoolOverride>,
    ) -> Result<(), RegistryError> {
        self.with_user(name, |user| match hop {
            Hop::Pre => user.pre_proxies = setting,
            Hop::Post => user.post_proxies = setting,
        })
    }

    /// Enable or disable an account without removing it.
    pub fn set_enabled(&self, name: &str, enabled: bool) -> Result<(), RegistryError> {
        self.with_user(name, |user| user.is_enabled = enabled)
    }

    /// Allow or deny an account's `.onion` connections.
    pub fn set_onion(&self, name: &str, allowed: bool) -> Result<(), RegistryError> {
        self.with_user(name, |user| user.allowed_onion = allowed)
    }
}
