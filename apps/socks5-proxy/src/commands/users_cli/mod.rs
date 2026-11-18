use std::path::Path;
#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{bail, Result};
use clap::Subcommand;
use tor_socks5::auth::{parse_pool_override, Hop, NewUser, Registry, UsersConfig};
use tor_socks5::persist::CLI_LOCK_WAIT;

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
    let users_path = UsersConfig::resolve_path(&config_path);
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

/// The registry at `users_path`, waiting for its lock as long as the CLI does.
fn registry(users_path: &Path) -> Registry {
    Registry::new(users_path).with_lock_wait(cli_lock_wait())
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

fn new_user(
    name: &str,
    allow_onion: bool,
    pre_proxies: &[String],
    post_proxies: &[String],
) -> Result<NewUser> {
    Ok(NewUser {
        name: name.to_string(),
        allow_onion,
        pre_proxies: parse_pool_override(pre_proxies)?,
        post_proxies: parse_pool_override(post_proxies)?,
    })
}

fn onion_label(allow_onion: bool) -> &'static str {
    if allow_onion {
        "allowed"
    } else {
        "denied"
    }
}

fn cmd_add(
    users_path: &Path,
    name: &str,
    prompt: &mut dyn PasswordPrompt,
    allow_onion: bool,
    pre_proxies: &[String],
    post_proxies: &[String],
) -> Result<()> {
    let new = new_user(name, allow_onion, pre_proxies, post_proxies)?;
    let registry = registry(users_path);
    // Fail fast before the interactive prompt; the authoritative check
    // re-runs under the transaction lock inside `add`.
    registry.ensure_absent(name)?;
    let pw = read_and_confirm(prompt)?;
    registry.add(new, &pw)?;
    println!(
        "user \"{name}\" added (onion: {}) ({})",
        onion_label(allow_onion),
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
    let new = new_user(name, allow_onion, pre_proxies, post_proxies)?;
    registry(users_path).add_init(new)?;
    println!(
        "user \"{name}\" added in init mode (onion: {}) — the first password presented at login \
         will be set as its password ({})",
        onion_label(allow_onion),
        users_path.display()
    );
    Ok(())
}

fn cmd_set_proxies(path: &Path, name: &str, hop: &str, values: &[String]) -> Result<()> {
    let hop: Hop = hop.parse()?;
    let setting = parse_pool_override(values)?;
    registry(path).set_proxies(name, hop, setting)?;
    println!("user proxy pool updated");
    Ok(())
}

fn cmd_remove(users_path: &Path, name: &str) -> Result<()> {
    registry(users_path).remove(name)?;
    println!("user \"{name}\" removed ({})", users_path.display());
    Ok(())
}

fn cmd_set_password(users_path: &Path, name: &str, prompt: &mut dyn PasswordPrompt) -> Result<()> {
    let registry = registry(users_path);
    // Fail fast before the interactive prompt; the authoritative check
    // re-runs under the transaction lock inside `set_password`.
    registry.ensure_present(name)?;
    let pw = read_and_confirm(prompt)?;
    registry.set_password(name, &pw)?;
    println!("password changed for \"{name}\" ({})", users_path.display());
    Ok(())
}

fn cmd_list(users_path: &Path) -> Result<()> {
    // Read-only: no transaction lock — a list never publishes, so it can
    // neither lose nor clobber a concurrent writer's mutation.
    let users = registry(users_path).load()?;
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
    registry(users_path).set_enabled(name, true)?;
    println!("user \"{name}\" enabled ({})", users_path.display());
    Ok(())
}

fn cmd_disable(users_path: &Path, name: &str) -> Result<()> {
    registry(users_path).set_enabled(name, false)?;
    println!("user \"{name}\" disabled ({})", users_path.display());
    Ok(())
}

fn cmd_set_onion(users_path: &Path, name: &str, allowed: bool) -> Result<()> {
    registry(users_path).set_onion(name, allowed)?;
    println!(
        "user \"{name}\" onion access {} ({})",
        onion_label(allowed),
        users_path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests;
