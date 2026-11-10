use std::path::Path;
#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{bail, Result};
use auth::{compute_hash, verify_hash, User, UsersConfig, INIT_SENTINEL};
use clap::Subcommand;
use persist_lock::{PathLock, CLI_LOCK_WAIT};
use proxy_config::{PoolOverride, ProxyPool, Socks5Endpoint};

/// Test-only override (milliseconds) for the CLI lock wait; `0` uses the
/// production [`CLI_LOCK_WAIT`]. Lets tests exercise the busy path
/// without waiting a minute.
#[cfg(test)]
static LOCK_WAIT_OVERRIDE_MS: AtomicU64 = AtomicU64::new(0);

fn cli_lock_wait() -> Duration {
    #[cfg(test)]
    {
        let override_ms = LOCK_WAIT_OVERRIDE_MS.load(Ordering::Relaxed);
        if override_ms > 0 {
            return Duration::from_millis(override_ms);
        }
    }
    CLI_LOCK_WAIT
}

#[derive(Debug, Subcommand)]
pub enum UsersAction {
    /// Create a new user (prompts for password).
    Add {
        /// Username to add.
        name: String,
        /// Create the account in trust-on-first-use mode: no password
        /// is set now; the first non-empty password presented at login
        /// is adopted and persisted as the real hash.
        #[arg(long)]
        init: bool,
        /// Permit this account to open connections to `.onion` hidden
        /// services. Off by default; use `allow-onion <name>` later to
        /// grant an existing account.
        #[arg(long)]
        allow_onion: bool,
        /// Pre proxy pool for this account: one or more endpoints, or `none`
        /// to disable the hop; omitted inherits the global pool.
        #[arg(long, num_args = 1.., value_name = "ENDPOINT")]
        pre_proxies: Vec<String>,
        /// Post proxy pool for this account: one or more endpoints, or `none`
        /// to disable the hop; omitted inherits the global pool.
        #[arg(long, num_args = 1.., value_name = "ENDPOINT")]
        post_proxies: Vec<String>,
    },
    /// Remove an existing user.
    Remove {
        /// Username to remove.
        name: String,
    },
    /// Permit an existing user to open `.onion` connections.
    AllowOnion {
        /// Username to grant onion access.
        name: String,
    },
    /// Revoke an existing user's permission to open `.onion` connections.
    DisallowOnion {
        /// Username to revoke onion access from.
        name: String,
    },
    /// Change the password for an existing user (prompts twice).
    SetPassword {
        /// Username whose password to change.
        name: String,
    },
    /// Set or inherit the proxy pool of a hop (`pre` or `post`): endpoints
    /// replace the pool, `none` disables the hop, `inherit` uses the global pool.
    SetProxies {
        name: String,
        hop: String,
        #[arg(num_args = 1.., value_name = "ENDPOINT")]
        values: Vec<String>,
    },
    /// List all users.
    List,
    /// Enable a disabled user.
    Enable {
        /// Username to enable.
        name: String,
    },
    /// Disable a user without removing it.
    Disable {
        /// Username to disable.
        name: String,
    },
}

pub trait PasswordPrompt {
    fn read_password(&mut self) -> Result<String>;
    fn read_password_confirm(&mut self) -> Result<String>;
}

pub struct RpasswordPrompt;

impl PasswordPrompt for RpasswordPrompt {
    fn read_password(&mut self) -> Result<String> {
        Ok(rpassword::prompt_password("Password: ")?)
    }

    fn read_password_confirm(&mut self) -> Result<String> {
        Ok(rpassword::prompt_password("Confirm: ")?)
    }
}

pub fn run(
    action: UsersAction,
    config_path: Option<&Path>,
    prompt: &mut dyn PasswordPrompt,
) -> Result<()> {
    let config_path = crate::config::Config::resolve_path(config_path);
    let users_path = UsersConfig::resolve_path(Some(&config_path));
    match action {
        UsersAction::Add {
            name,
            init,
            allow_onion,
            pre_proxies,
            post_proxies,
        } => {
            if init {
                cmd_add_init(&users_path, &name, allow_onion, &pre_proxies, &post_proxies)
            } else {
                cmd_add(
                    &users_path,
                    &name,
                    prompt,
                    allow_onion,
                    &pre_proxies,
                    &post_proxies,
                )
            }
        }
        UsersAction::Remove { name } => cmd_remove(&users_path, &name),
        UsersAction::SetPassword { name } => cmd_set_password(&users_path, &name, prompt),
        UsersAction::SetProxies { name, hop, values } => {
            cmd_set_proxies(&users_path, &name, &hop, &values)
        }
        UsersAction::List => cmd_list(&users_path),
        UsersAction::Enable { name } => cmd_enable(&users_path, &name),
        UsersAction::Disable { name } => cmd_disable(&users_path, &name),
        UsersAction::AllowOnion { name } => cmd_set_onion(&users_path, &name, true),
        UsersAction::DisallowOnion { name } => cmd_set_onion(&users_path, &name, false),
    }
}

/// Take the registry's cross-process transaction lock (bounded wait) and
/// load the registry **under it**. Callers must hold the returned lock
/// until their mutation's `save` has published: the lock is what turns
/// the whole read-modify-write into one serialised transaction across
/// processes (TS17-07). The busy error is returned as-is — it already
/// names the lock file and the wait.
fn lock_and_load(users_path: &Path) -> Result<(PathLock, UsersConfig)> {
    let lock = PathLock::acquire_bounded(users_path, cli_lock_wait())?;
    let users = UsersConfig::load(users_path)?;
    Ok((lock, users))
}

fn read_and_confirm(prompt: &mut dyn PasswordPrompt) -> Result<String> {
    let pw = prompt.read_password()?;
    if pw.is_empty() {
        bail!("password must not be empty");
    }
    let confirm = prompt.read_password_confirm()?;
    if pw != confirm {
        bail!("passwords do not match");
    }
    Ok(pw)
}

fn cmd_add(
    users_path: &Path,
    name: &str,
    prompt: &mut dyn PasswordPrompt,
    allow_onion: bool,
    pre_proxies: &[String],
    post_proxies: &[String],
) -> Result<()> {
    // Fail fast before the interactive prompt; the authoritative check
    // re-runs under the transaction lock below.
    let pre_proxies = parse_user_pool(pre_proxies)?;
    let post_proxies = parse_user_pool(post_proxies)?;
    if UsersConfig::load(users_path)?.find(name).is_some() {
        bail!("user \"{name}\" already exists — use `set-password` to change the password");
    }
    // Prompting and Argon2id hashing happen BEFORE the lock: never hold
    // the registry lock on a human or on expensive hashing.
    let pw = read_and_confirm(prompt)?;
    let hash = compute_hash(&pw)?;
    let (lock, mut users) = lock_and_load(users_path)?;
    if users.find(name).is_some() {
        bail!("user \"{name}\" already exists — use `set-password` to change the password");
    }
    users.users.push(User {
        name: name.to_string(),
        hash,
        is_enabled: true,
        allowed_onion: allow_onion,
        // Новые пользователи создаются без per-user ACL.
        allowed_clients: None,
        pre_proxies,
        post_proxies,
    });
    users.save(users_path)?;
    drop(lock);
    println!(
        "user \"{name}\" added (onion: {}) ({})",
        if allow_onion { "allowed" } else { "denied" },
        users_path.display()
    );
    Ok(())
}

/// Create a user in trust-on-first-use mode: the stored hash is the
/// `init` sentinel, so the first non-empty password presented at login
/// is adopted and persisted as the real hash. No password is read here.
fn cmd_add_init(
    users_path: &Path,
    name: &str,
    allow_onion: bool,
    pre_proxies: &[String],
    post_proxies: &[String],
) -> Result<()> {
    let pre_proxies = parse_user_pool(pre_proxies)?;
    let post_proxies = parse_user_pool(post_proxies)?;
    let (lock, mut users) = lock_and_load(users_path)?;
    if users.find(name).is_some() {
        bail!("user \"{name}\" already exists — use `set-password` to change the password");
    }
    users.users.push(User {
        name: name.to_string(),
        hash: INIT_SENTINEL.to_string(),
        is_enabled: true,
        allowed_onion: allow_onion,
        // Новые пользователи создаются без per-user ACL.
        allowed_clients: None,
        pre_proxies,
        post_proxies,
    });
    users.save(users_path)?;
    drop(lock);
    println!(
        "user \"{name}\" added in init mode (onion: {}) — the first password presented at login \
         will be set as its password ({})",
        if allow_onion { "allowed" } else { "denied" },
        users_path.display()
    );
    Ok(())
}

fn cmd_set_proxies(path: &Path, name: &str, hop: &str, values: &[String]) -> Result<()> {
    if !matches!(hop, "pre" | "post") {
        bail!("hop must be `pre` or `post`");
    }
    let setting = parse_user_pool(values)?;
    let (lock, mut users) = lock_and_load(path)?;
    let user = users
        .find_mut(name)
        .ok_or_else(|| anyhow::anyhow!("user does not exist"))?;
    match hop {
        "pre" => user.pre_proxies = setting,
        "post" => user.post_proxies = setting,
        _ => bail!("hop must be `pre` or `post`"),
    }
    users.save(path)?;
    drop(lock);
    println!("user proxy pool updated");
    Ok(())
}

/// `inherit` (or nothing) keeps the global pool, `none` disables the hop,
/// anything else is the account's own pool.
fn parse_user_pool(values: &[String]) -> Result<Option<PoolOverride>> {
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
                        .map_err(|_| anyhow::anyhow!("invalid proxy endpoint"))
                })
                .collect::<Result<Vec<_>>>()?;
            ProxyPool::new(members)
                .map(|pool| Some(PoolOverride::Pool(pool)))
                .map_err(|error| anyhow::anyhow!(error))
        }
    }
}

fn cmd_remove(users_path: &Path, name: &str) -> Result<()> {
    let (lock, mut users) = lock_and_load(users_path)?;
    let before = users.users.len();
    users.users.retain(|u| u.name != name);
    if users.users.len() == before {
        bail!("user \"{name}\" does not exist");
    }
    users.save(users_path)?;
    drop(lock);
    println!("user \"{name}\" removed ({})", users_path.display());
    Ok(())
}

fn cmd_set_password(users_path: &Path, name: &str, prompt: &mut dyn PasswordPrompt) -> Result<()> {
    // Fail fast before the interactive prompt; the authoritative check
    // re-runs under the transaction lock below.
    if UsersConfig::load(users_path)?.find(name).is_none() {
        anyhow::bail!("user \"{name}\" does not exist");
    }
    // Prompting and Argon2id hashing happen BEFORE the lock: never hold
    // the registry lock on a human or on expensive hashing.
    let pw = read_and_confirm(prompt)?;
    let new_hash = compute_hash(&pw)?;
    let (lock, mut users) = lock_and_load(users_path)?;
    let user = users
        .find_mut(name)
        .ok_or_else(|| anyhow::anyhow!("user \"{name}\" does not exist"))?;
    let old_hash = user.hash.clone();
    user.hash = new_hash;
    users.save(users_path)?;
    drop(lock);
    // An `init`-sentinel account has no real old hash to verify against;
    // only run the sanity check when the previous hash was a real one.
    // Runs after the publish and outside the lock: it is expensive and
    // cannot change the outcome of the transaction.
    let still_works = old_hash != INIT_SENTINEL && verify_hash(&old_hash, &pw)?;
    if still_works {
        bail!("internal error: old password still verifies after change");
    }
    println!("password changed for \"{name}\" ({})", users_path.display());
    Ok(())
}

fn cmd_list(users_path: &Path) -> Result<()> {
    // Read-only: no transaction lock — a list never publishes, so it can
    // neither lose nor clobber a concurrent writer's mutation.
    let users = UsersConfig::load(users_path)?;
    if users.users.is_empty() {
        println!("no users yet");
        return Ok(());
    }
    println!("{}", render_list(&users));
    Ok(())
}

pub fn render_list(users: &UsersConfig) -> String {
    let mut rows: Vec<String> = Vec::new();
    rows.push(format!(
        "{:<20} {:<10} {:<8} {}",
        "NAME", "ENABLED", "ONION", "HASH-PREVIEW"
    ));
    for u in &users.users {
        let enabled = if u.is_enabled { "yes" } else { "no" };
        let onion = if u.allowed_onion { "yes" } else { "no" };
        let preview = if u.hash.chars().count() > 24 {
            let head: String = u.hash.chars().take(24).collect();
            format!("{head}…")
        } else {
            u.hash.clone()
        };
        rows.push(format!(
            "{:<20} {:<10} {:<8} {}",
            u.name, enabled, onion, preview
        ));
    }
    rows.join("\n")
}

fn cmd_enable(users_path: &Path, name: &str) -> Result<()> {
    let (lock, mut users) = lock_and_load(users_path)?;
    let user = users
        .find_mut(name)
        .ok_or_else(|| anyhow::anyhow!("user \"{name}\" does not exist"))?;
    user.is_enabled = true;
    users.save(users_path)?;
    drop(lock);
    println!("user \"{name}\" enabled ({})", users_path.display());
    Ok(())
}

fn cmd_disable(users_path: &Path, name: &str) -> Result<()> {
    let (lock, mut users) = lock_and_load(users_path)?;
    let user = users
        .find_mut(name)
        .ok_or_else(|| anyhow::anyhow!("user \"{name}\" does not exist"))?;
    user.is_enabled = false;
    users.save(users_path)?;
    drop(lock);
    println!("user \"{name}\" disabled ({})", users_path.display());
    Ok(())
}

fn cmd_set_onion(users_path: &Path, name: &str, allowed: bool) -> Result<()> {
    let (lock, mut users) = lock_and_load(users_path)?;
    let user = users
        .find_mut(name)
        .ok_or_else(|| anyhow::anyhow!("user \"{name}\" does not exist"))?;
    user.allowed_onion = allowed;
    users.save(users_path)?;
    drop(lock);
    let verb = if allowed { "allowed" } else { "denied" };
    println!(
        "user \"{name}\" onion access {verb} ({})",
        users_path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests;
