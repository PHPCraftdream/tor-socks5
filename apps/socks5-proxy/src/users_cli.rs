use std::path::Path;

use anyhow::{bail, Result};
use auth::{compute_hash, verify_hash, User, UsersConfig, INIT_SENTINEL};
use clap::Subcommand;

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
    let users_path = UsersConfig::resolve_path(config_path);
    match action {
        UsersAction::Add {
            name,
            init,
            allow_onion,
        } => {
            if init {
                cmd_add_init(&users_path, &name, allow_onion)
            } else {
                cmd_add(&users_path, &name, prompt, allow_onion)
            }
        }
        UsersAction::Remove { name } => cmd_remove(&users_path, &name),
        UsersAction::SetPassword { name } => cmd_set_password(&users_path, &name, prompt),
        UsersAction::List => cmd_list(&users_path),
        UsersAction::Enable { name } => cmd_enable(&users_path, &name),
        UsersAction::Disable { name } => cmd_disable(&users_path, &name),
        UsersAction::AllowOnion { name } => cmd_set_onion(&users_path, &name, true),
        UsersAction::DisallowOnion { name } => cmd_set_onion(&users_path, &name, false),
    }
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
) -> Result<()> {
    let mut users = UsersConfig::load(users_path)?;
    if users.find(name).is_some() {
        bail!("user \"{name}\" already exists — use `set-password` to change the password");
    }
    let pw = read_and_confirm(prompt)?;
    let hash = compute_hash(&pw)?;
    users.users.push(User {
        name: name.to_string(),
        hash,
        is_enabled: true,
        allowed_onion: allow_onion,
    });
    users.save(users_path)?;
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
fn cmd_add_init(users_path: &Path, name: &str, allow_onion: bool) -> Result<()> {
    let mut users = UsersConfig::load(users_path)?;
    if users.find(name).is_some() {
        bail!("user \"{name}\" already exists — use `set-password` to change the password");
    }
    users.users.push(User {
        name: name.to_string(),
        hash: INIT_SENTINEL.to_string(),
        is_enabled: true,
        allowed_onion: allow_onion,
    });
    users.save(users_path)?;
    println!(
        "user \"{name}\" added in init mode (onion: {}) — the first password presented at login \
         will be set as its password ({})",
        if allow_onion { "allowed" } else { "denied" },
        users_path.display()
    );
    Ok(())
}

fn cmd_remove(users_path: &Path, name: &str) -> Result<()> {
    let mut users = UsersConfig::load(users_path)?;
    let before = users.users.len();
    users.users.retain(|u| u.name != name);
    if users.users.len() == before {
        bail!("user \"{name}\" does not exist");
    }
    users.save(users_path)?;
    println!("user \"{name}\" removed ({})", users_path.display());
    Ok(())
}

fn cmd_set_password(users_path: &Path, name: &str, prompt: &mut dyn PasswordPrompt) -> Result<()> {
    let mut users = UsersConfig::load(users_path)?;
    let user = users
        .find_mut(name)
        .ok_or_else(|| anyhow::anyhow!("user \"{name}\" does not exist"))?;
    let old_hash = user.hash.clone();
    let pw = read_and_confirm(prompt)?;
    let new_hash = compute_hash(&pw)?;
    user.hash = new_hash;
    users.save(users_path)?;
    // An `init`-sentinel account has no real old hash to verify against;
    // only run the sanity check when the previous hash was a real one.
    let still_works = old_hash != INIT_SENTINEL && verify_hash(&old_hash, &pw)?;
    if still_works {
        bail!("internal error: old password still verifies after change");
    }
    println!("password changed for \"{name}\" ({})", users_path.display());
    Ok(())
}

fn cmd_list(users_path: &Path) -> Result<()> {
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
    let mut users = UsersConfig::load(users_path)?;
    let user = users
        .find_mut(name)
        .ok_or_else(|| anyhow::anyhow!("user \"{name}\" does not exist"))?;
    user.is_enabled = true;
    users.save(users_path)?;
    println!("user \"{name}\" enabled ({})", users_path.display());
    Ok(())
}

fn cmd_disable(users_path: &Path, name: &str) -> Result<()> {
    let mut users = UsersConfig::load(users_path)?;
    let user = users
        .find_mut(name)
        .ok_or_else(|| anyhow::anyhow!("user \"{name}\" does not exist"))?;
    user.is_enabled = false;
    users.save(users_path)?;
    println!("user \"{name}\" disabled ({})", users_path.display());
    Ok(())
}

fn cmd_set_onion(users_path: &Path, name: &str, allowed: bool) -> Result<()> {
    let mut users = UsersConfig::load(users_path)?;
    let user = users
        .find_mut(name)
        .ok_or_else(|| anyhow::anyhow!("user \"{name}\" does not exist"))?;
    user.allowed_onion = allowed;
    users.save(users_path)?;
    let verb = if allowed { "allowed" } else { "denied" };
    println!(
        "user \"{name}\" onion access {verb} ({})",
        users_path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedPrompt {
        password: String,
        confirm: String,
    }

    impl PasswordPrompt for FixedPrompt {
        fn read_password(&mut self) -> Result<String> {
            Ok(self.password.clone())
        }
        fn read_password_confirm(&mut self) -> Result<String> {
            Ok(self.confirm.clone())
        }
    }

    fn fixed_prompt(pw: &str) -> FixedPrompt {
        FixedPrompt {
            password: pw.to_string(),
            confirm: pw.to_string(),
        }
    }

    fn mismatch_prompt(pw: &str, confirm: &str) -> FixedPrompt {
        FixedPrompt {
            password: pw.to_string(),
            confirm: confirm.to_string(),
        }
    }

    fn tmp_users_path(dir: &std::path::Path) -> std::path::PathBuf {
        dir.join("test.users.ktav")
    }

    #[test]
    fn add_happy_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = tmp_users_path(dir.path());
        let mut prompt = fixed_prompt("secret123");

        cmd_add(&path, "alice", &mut prompt, false).unwrap();

        let loaded = UsersConfig::load(&path).unwrap();
        assert_eq!(loaded.users.len(), 1);
        assert_eq!(loaded.users[0].name, "alice");
        assert!(loaded.users[0].is_enabled);
        assert!(!loaded.users[0].hash.is_empty());
        assert!(verify_hash(&loaded.users[0].hash, "secret123").unwrap());
    }

    #[test]
    fn add_defaults_to_onion_denied() {
        let dir = tempfile::tempdir().unwrap();
        let path = tmp_users_path(dir.path());
        let mut prompt = fixed_prompt("secret123");
        cmd_add(&path, "alice", &mut prompt, false).unwrap();
        let loaded = UsersConfig::load(&path).unwrap();
        assert!(
            !loaded.find("alice").unwrap().allowed_onion,
            "onion must be denied unless --allow-onion is passed"
        );
    }

    #[test]
    fn add_with_allow_onion_grants_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = tmp_users_path(dir.path());
        let mut prompt = fixed_prompt("secret123");
        cmd_add(&path, "alice", &mut prompt, true).unwrap();
        assert!(
            UsersConfig::load(&path)
                .unwrap()
                .find("alice")
                .unwrap()
                .allowed_onion
        );
    }

    #[test]
    fn add_init_with_allow_onion_grants_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = tmp_users_path(dir.path());
        cmd_add_init(&path, "alice", true).unwrap();
        let u = UsersConfig::load(&path).unwrap();
        let u = u.find("alice").unwrap();
        assert_eq!(u.hash, INIT_SENTINEL);
        assert!(
            u.allowed_onion,
            "init account can be granted onion up front"
        );
    }

    #[test]
    fn set_onion_toggles_flag() {
        let dir = tempfile::tempdir().unwrap();
        let path = tmp_users_path(dir.path());
        let mut prompt = fixed_prompt("pw");
        cmd_add(&path, "alice", &mut prompt, false).unwrap();

        cmd_set_onion(&path, "alice", true).unwrap();
        assert!(
            UsersConfig::load(&path)
                .unwrap()
                .find("alice")
                .unwrap()
                .allowed_onion
        );

        cmd_set_onion(&path, "alice", false).unwrap();
        assert!(
            !UsersConfig::load(&path)
                .unwrap()
                .find("alice")
                .unwrap()
                .allowed_onion
        );
    }

    #[test]
    fn set_onion_errors_on_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = tmp_users_path(dir.path());
        let err = cmd_set_onion(&path, "ghost", true).unwrap_err();
        assert!(format!("{err}").contains("does not exist"));
    }

    #[test]
    fn add_init_stores_sentinel_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = tmp_users_path(dir.path());

        cmd_add_init(&path, "alice", false).unwrap();

        let loaded = UsersConfig::load(&path).unwrap();
        assert_eq!(loaded.users.len(), 1);
        assert_eq!(loaded.users[0].name, "alice");
        assert!(loaded.users[0].is_enabled);
        assert_eq!(loaded.users[0].hash, INIT_SENTINEL);
    }

    #[test]
    fn add_init_rejects_duplicate() {
        let dir = tempfile::tempdir().unwrap();
        let path = tmp_users_path(dir.path());
        cmd_add_init(&path, "alice", false).unwrap();
        let err = cmd_add_init(&path, "alice", false).unwrap_err();
        assert!(format!("{err}").contains("already exists"));
    }

    #[test]
    fn set_password_on_init_account_succeeds() {
        // Provisioning a real password over an `init` sentinel must not
        // trip the "old password still verifies" sanity check.
        let dir = tempfile::tempdir().unwrap();
        let path = tmp_users_path(dir.path());
        cmd_add_init(&path, "alice", false).unwrap();

        let mut prompt = fixed_prompt("real-pass");
        cmd_set_password(&path, "alice", &mut prompt).unwrap();

        let loaded = UsersConfig::load(&path).unwrap();
        let hash = &loaded.find("alice").unwrap().hash;
        assert_ne!(hash, INIT_SENTINEL);
        assert!(verify_hash(hash, "real-pass").unwrap());
    }

    #[test]
    fn add_rejects_duplicate() {
        let dir = tempfile::tempdir().unwrap();
        let path = tmp_users_path(dir.path());
        let mut prompt = fixed_prompt("secret");

        cmd_add(&path, "alice", &mut prompt, false).unwrap();
        let err = cmd_add(&path, "alice", &mut prompt, false).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("set-password"),
            "error should mention set-password: {msg}"
        );
    }

    #[test]
    fn add_rejects_mismatched_confirm() {
        let dir = tempfile::tempdir().unwrap();
        let path = tmp_users_path(dir.path());
        let mut prompt = mismatch_prompt("secret123", "different");

        let err = cmd_add(&path, "alice", &mut prompt, false).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("do not match"),
            "error should mention mismatch: {msg}"
        );
    }

    #[test]
    fn add_rejects_empty_password() {
        let dir = tempfile::tempdir().unwrap();
        let path = tmp_users_path(dir.path());
        let mut prompt = fixed_prompt("");

        let err = cmd_add(&path, "alice", &mut prompt, false).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("empty"), "error should mention empty: {msg}");
    }

    #[test]
    fn remove_deletes_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = tmp_users_path(dir.path());
        let mut prompt = fixed_prompt("pw");

        cmd_add(&path, "alice", &mut prompt, false).unwrap();
        cmd_remove(&path, "alice").unwrap();

        let loaded = UsersConfig::load(&path).unwrap();
        assert!(loaded.users.is_empty());
    }

    #[test]
    fn remove_errors_on_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = tmp_users_path(dir.path());
        let err = cmd_remove(&path, "nobody").unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("does not exist"),
            "error should mention missing: {msg}"
        );
    }

    #[test]
    fn enable_disable_toggles_flag() {
        let dir = tempfile::tempdir().unwrap();
        let path = tmp_users_path(dir.path());
        let mut prompt = fixed_prompt("pw");

        cmd_add(&path, "alice", &mut prompt, false).unwrap();
        cmd_disable(&path, "alice").unwrap();
        let loaded = UsersConfig::load(&path).unwrap();
        assert!(!loaded.find("alice").unwrap().is_enabled);

        cmd_enable(&path, "alice").unwrap();
        let loaded = UsersConfig::load(&path).unwrap();
        assert!(loaded.find("alice").unwrap().is_enabled);
    }

    #[test]
    fn set_password_changes_hash_and_old_no_longer_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let path = tmp_users_path(dir.path());
        let mut prompt = fixed_prompt("old-pass");

        cmd_add(&path, "alice", &mut prompt, false).unwrap();
        let old_hash = UsersConfig::load(&path)
            .unwrap()
            .find("alice")
            .unwrap()
            .hash
            .clone();

        let mut prompt2 = fixed_prompt("new-pass");
        cmd_set_password(&path, "alice", &mut prompt2).unwrap();

        let loaded = UsersConfig::load(&path).unwrap();
        let new_hash = &loaded.find("alice").unwrap().hash;
        assert_ne!(old_hash, *new_hash, "hash must have changed");
        assert!(
            !verify_hash(&old_hash, "new-pass").unwrap(),
            "old hash must not verify new password"
        );
        assert!(
            verify_hash(new_hash, "new-pass").unwrap(),
            "new hash must verify new password"
        );
    }

    #[test]
    fn list_returns_rows_in_insertion_order() {
        let users = UsersConfig {
            users: vec![
                User {
                    name: "charlie".into(),
                    hash: "$argon2id$v=19$m=5120,t=2,p=1$AAAAAAAAAAAAAAAAAAAA$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".into(),
                    is_enabled: true,
                    allowed_onion: false,
                },
                User {
                    name: "alice".into(),
                    hash: "$argon2id$v=19$m=5120,t=2,p=1$CCCCCCCCCCCCCCCCCCCC$DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD".into(),
                    is_enabled: false,
                    allowed_onion: true,
                },
            ],
        };

        let table = render_list(&users);
        let lines: Vec<&str> = table.lines().collect();
        assert_eq!(lines.len(), 3, "header + 2 users");
        assert!(lines[0].contains("NAME"));
        assert!(lines[0].contains("ENABLED"));
        assert!(lines[0].contains("ONION"));
        assert!(lines[0].contains("HASH-PREVIEW"));
        assert!(lines[1].contains("charlie"));
        assert!(lines[1].contains("yes"));
        assert!(lines[2].contains("alice"));
        assert!(lines[2].contains("no"));
    }

    #[test]
    fn enable_errors_on_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = tmp_users_path(dir.path());
        let err = cmd_enable(&path, "ghost").unwrap_err();
        assert!(format!("{err}").contains("does not exist"));
    }

    #[test]
    fn disable_errors_on_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = tmp_users_path(dir.path());
        let err = cmd_disable(&path, "ghost").unwrap_err();
        assert!(format!("{err}").contains("does not exist"));
    }

    #[test]
    fn set_password_errors_on_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = tmp_users_path(dir.path());
        let mut prompt = fixed_prompt("pw");
        let err = cmd_set_password(&path, "ghost", &mut prompt).unwrap_err();
        assert!(format!("{err}").contains("does not exist"));
    }

    // -- render_list edge cases ---

    #[test]
    fn render_list_long_username() {
        let users = UsersConfig {
            users: vec![User {
                name: "a_very_long_username_that_exceeds_twenty_chars".into(),
                hash: "$argon2id$v=19$m=5120,t=2,p=1$salt$hash_value_here".into(),
                is_enabled: true,
                allowed_onion: false,
            }],
        };
        let table = render_list(&users);
        assert!(table.contains("a_very_long_username_that_exceeds_twenty_chars"));
    }

    #[test]
    fn render_list_short_hash_no_truncation() {
        let users = UsersConfig {
            users: vec![User {
                name: "bob".into(),
                hash: "short".into(),
                is_enabled: true,
                allowed_onion: false,
            }],
        };
        let table = render_list(&users);
        assert!(table.contains("short"));
        assert!(!table.contains('…'));
    }

    #[test]
    fn render_list_disabled_user_shows_no() {
        let users = UsersConfig {
            users: vec![User {
                name: "eve".into(),
                hash: "$argon2id$v=19$m=5120,t=2,p=1$AAAA$BBBB_enough_length_for_preview".into(),
                is_enabled: false,
                allowed_onion: false,
            }],
        };
        let table = render_list(&users);
        let user_line = table.lines().nth(1).expect("should have user line");
        assert!(user_line.contains("no"));
    }

    #[test]
    fn render_list_empty_config() {
        let users = UsersConfig { users: vec![] };
        let table = render_list(&users);
        assert!(table.contains("NAME"));
        assert_eq!(table.lines().count(), 1, "only header, no user rows");
    }

    #[test]
    fn add_mismatch_error_does_not_leak_password() {
        let dir = tempfile::tempdir().unwrap();
        let path = tmp_users_path(dir.path());
        let mut prompt = mismatch_prompt("s3cret", "0ther");

        let err = cmd_add(&path, "alice", &mut prompt, false).unwrap_err();
        let msg = format!("{err}");
        assert!(!msg.contains("s3cret"), "error must not contain password");
        assert!(!msg.contains("0ther"), "error must not contain confirm");
    }
}
