//! `tor-socks5 onion new|list|show|export|import|remove` implementations.
//!
//! Pure keystore management: nothing here starts Tor or opens the network.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::Subcommand;

use crate::onion::store;

#[derive(Debug, Subcommand)]
pub(crate) enum OnionAction {
    /// Create a new onion service identity (random key) and print its address.
    New {
        /// Service nickname (used as the keystore directory name).
        nick: String,
        /// Replace an existing identity. WARNING: the old .onion address
        /// will be lost permanently.
        #[arg(long)]
        force: bool,
    },
    /// List all onion services in the keystore (nickname and address).
    List,
    /// Show a service's onion address and keystore path (never the secret key).
    Show {
        /// Service nickname.
        nick: String,
    },
    /// Export a service's identity key to a portable file (Arti keystore
    /// format, so `onion import` on another machine accepts the same file).
    Export {
        /// Service nickname.
        nick: String,
        /// Output file path.
        #[arg(long)]
        out: PathBuf,
        /// Overwrite an existing output file.
        #[arg(long)]
        force: bool,
    },
    /// Import an identity key from an exported file.
    Import {
        /// Service nickname to register the key under.
        nick: String,
        /// File previously produced by `onion export`.
        file: PathBuf,
        /// Replace an existing identity for this nickname. WARNING: the old
        /// .onion address will be lost permanently.
        #[arg(long)]
        force: bool,
    },
    /// Delete a service's keys from the keystore (irreversible without a
    /// prior `onion export`: the .onion address is lost).
    Remove {
        /// Service nickname.
        nick: String,
        /// Confirm the deletion (refused without this flag).
        #[arg(long)]
        yes: bool,
    },
}

pub(crate) fn run(action: OnionAction, config_path: Option<&Path>) -> Result<()> {
    match action {
        OnionAction::New { nick, force } => cmd_new(config_path, &nick, force),
        OnionAction::List => cmd_list(config_path),
        OnionAction::Show { nick } => cmd_show(config_path, &nick),
        OnionAction::Export { nick, out, force } => cmd_export(config_path, &nick, &out, force),
        OnionAction::Import { nick, file, force } => cmd_import(config_path, &nick, &file, force),
        OnionAction::Remove { nick, yes } => cmd_remove(config_path, &nick, yes),
    }
}

fn cmd_new(config_path: Option<&Path>, nick: &str, force: bool) -> Result<()> {
    let nick = store::nickname(nick)?;
    let dir = store::keystore_dir(config_path);
    let _lock = store::lock(&dir)?;
    let keymgr = store::open(&dir)?;
    if store::exists(&keymgr, &nick)? {
        if !force {
            bail!(
                "nickname {:?} already exists; pass --force to replace it \
                 (the old .onion address will be lost)",
                nick.to_string()
            );
        }
        eprintln!(
            "warning: replacing the identity of {:?}: the old .onion address \
             will be lost permanently",
            nick.to_string()
        );
    }
    store::generate(&keymgr, &nick, force)?;
    let address = store::address(&keymgr, &nick)?.context("address after generation")?;
    let file = store::identity_file(&dir, &nick).context("identity file after generation")?;
    println!("nickname: {}", nick);
    println!("address:  {address}");
    println!("keystore: {}", file.display());
    Ok(())
}

fn cmd_list(config_path: Option<&Path>) -> Result<()> {
    let dir = store::keystore_dir(config_path);
    let mut rows: Vec<(String, String)> = Vec::new();
    if dir.is_dir() {
        let keymgr = store::open(&dir)?;
        let hss_root = dir.join("hss");
        let mut entries: Vec<_> = std::fs::read_dir(&hss_root)
            .with_context(|| format!("reading {}", hss_root.display()))?
            .flatten()
            .filter(|entry| entry.path().is_dir())
            .collect();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let Some(name) = entry.file_name().into_string().ok() else {
                continue;
            };
            let Ok(nick) = store::nickname(&name) else {
                continue;
            };
            if let Ok(Some(address)) = store::address(&keymgr, &nick) {
                rows.push((name, address));
            }
        }
    }
    if rows.is_empty() {
        println!("no onion services");
        return Ok(());
    }
    println!("{:<24} ADDRESS", "NICKNAME");
    for (name, address) in rows {
        println!("{:<24} {}", name, address);
    }
    Ok(())
}

fn cmd_show(config_path: Option<&Path>, nick: &str) -> Result<()> {
    let nick = store::nickname(nick)?;
    let dir = store::keystore_dir(config_path);
    if !dir.is_dir() {
        bail!("no onion keystore at {}", dir.display());
    }
    let keymgr = store::open(&dir)?;
    let Some(address) = store::address(&keymgr, &nick)? else {
        bail!("no onion service named {:?}", nick.to_string());
    };
    println!("nickname: {}", nick);
    println!("address:  {address}");
    if let Some(file) = store::identity_file(&dir, &nick) {
        println!("keystore: {}", file.display());
    }
    Ok(())
}

fn cmd_export(config_path: Option<&Path>, nick: &str, out: &Path, force: bool) -> Result<()> {
    let nick = store::nickname(nick)?;
    let dir = store::keystore_dir(config_path);
    if !dir.is_dir() {
        bail!("no onion keystore at {}", dir.display());
    }
    let keymgr = store::open(&dir)?;
    if !store::exists(&keymgr, &nick)? {
        bail!("no onion service named {:?}", nick.to_string());
    }
    let src =
        store::identity_file(&dir, &nick).context("identity key file not found in keystore")?;
    if out.exists() && !force {
        bail!(
            "{} already exists; pass --force to overwrite it",
            out.display()
        );
    }
    // The key file's own bytes ARE the portable format: the Arti native
    // keystore stores the identity as an OpenSSH-format file with the custom
    // ed25519-expanded algorithm, which `onion import` (and arti itself)
    // parse back through the same keystore code.
    let bytes = std::fs::read(&src).with_context(|| format!("reading {}", src.display()))?;
    write_secret_file(out, &bytes)?;
    println!("exported {} to {}", nick, out.display());
    Ok(())
}

fn cmd_import(config_path: Option<&Path>, nick: &str, file: &Path, force: bool) -> Result<()> {
    let nick = store::nickname(nick)?;
    let dir = store::keystore_dir(config_path);
    let _lock = store::lock(&dir)?;
    let bytes = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    let key = store::parse_identity_file(&bytes, &nick)?;
    let keymgr = store::open(&dir)?;
    if store::exists(&keymgr, &nick)? {
        if !force {
            bail!(
                "nickname {:?} already exists; pass --force to replace it \
                 (the old .onion address will be lost)",
                nick.to_string()
            );
        }
        eprintln!(
            "warning: replacing the identity of {:?}: the old .onion address \
             will be lost permanently",
            nick.to_string()
        );
    }
    store::insert(&keymgr, key, &nick, force)?;
    let address = store::address(&keymgr, &nick)?.context("address after import")?;
    println!("imported {} from {}", nick, file.display());
    println!("address:  {address}");
    Ok(())
}

fn cmd_remove(config_path: Option<&Path>, nick: &str, yes: bool) -> Result<()> {
    let nick = store::nickname(nick)?;
    if !yes {
        bail!(
            "refusing to remove {:?} without --yes: this deletes the service's \
             identity key and is irreversible — the .onion address is lost \
             unless it was exported first",
            nick.to_string()
        );
    }
    let dir = store::keystore_dir(config_path);
    let _lock = store::lock(&dir)?;
    store::remove_all(&dir, &nick)?;
    println!("removed {} (all keystore keys deleted)", nick);
    Ok(())
}

/// Write a key file, restricting permissions to the owner where the OS
/// supports it (Unix: mode 0600). On Windows there is no chmod: the file
/// inherits the default ACL of its directory (private per-user temp/profile
/// directories), like every other file arti writes there.
fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut file =
        std::fs::File::create(path).with_context(|| format!("creating {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A fresh temp dir + a config path inside it (the file itself never has
    /// to exist: only its parent directory is used to form `arti-data`).
    fn temp_setup() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("temp dir");
        let config = dir.path().join("tor-socks5.ktav");
        (dir, config)
    }

    fn address_of(config: &Path, nick: &str) -> String {
        let nick = store::nickname(nick).expect("nickname");
        let dir = store::keystore_dir(Some(config));
        let keymgr = store::open(&dir).expect("open keystore");
        store::address(&keymgr, &nick)
            .expect("address")
            .expect("identity present")
    }

    fn run_new(config: &Path, nick: &str, force: bool) -> Result<()> {
        run(
            OnionAction::New {
                nick: nick.to_owned(),
                force,
            },
            Some(config),
        )
    }

    #[test]
    fn onion_new_list_show_export_remove_import_roundtrip() {
        let (_tmp, config) = temp_setup();

        // new
        run_new(&config, "svc", false).expect("new");
        let address_before = address_of(&config, "svc");

        // list + show see the same address
        cmd_list(Some(&config)).expect("list");
        cmd_show(Some(&config), "svc").expect("show");
        assert_eq!(address_of(&config, "svc"), address_before);

        // export
        let export = _tmp.path().join("svc.id");
        cmd_export(Some(&config), "svc", &export, false).expect("export");
        let bytes = std::fs::read(&export).expect("export bytes");
        assert!(!bytes.is_empty());

        // remove (guarded), then import restores the same address
        assert!(cmd_remove(Some(&config), "svc", false).is_err());
        let dir = store::keystore_dir(Some(&config));
        let keymgr = store::open(&dir).expect("reopen");
        let nick = store::nickname("svc").expect("nick");
        assert!(store::exists(&keymgr, &nick).expect("exists check"));
        drop(keymgr);
        cmd_remove(Some(&config), "svc", true).expect("remove");
        cmd_import(Some(&config), "svc", &export, false).expect("import");
        assert_eq!(address_of(&config, "svc"), address_before);
        cmd_show(Some(&config), "svc").expect("show after import");
    }

    #[test]
    fn onion_new_refuses_existing_nickname_without_force() {
        let (_tmp, config) = temp_setup();
        run_new(&config, "dup", false).expect("first new");
        let address = address_of(&config, "dup");
        assert!(run_new(&config, "dup", false).is_err(), "must refuse");
        // Address unchanged after the refusal.
        assert_eq!(address_of(&config, "dup"), address);
        // And --force replaces it.
        run_new(&config, "dup", true).expect("forced new");
        assert_ne!(address_of(&config, "dup"), address);
    }

    #[test]
    fn onion_import_refuses_existing_nickname_without_force() {
        let (_tmp, config) = temp_setup();
        run_new(&config, "imp", false).expect("new");
        let export = _tmp.path().join("imp.id");
        cmd_export(Some(&config), "imp", &export, false).expect("export");
        assert!(cmd_import(Some(&config), "imp", &export, false).is_err());
        cmd_import(Some(&config), "imp", &export, true).expect("forced import");
    }

    #[test]
    fn onion_remove_requires_yes() {
        let (_tmp, config) = temp_setup();
        run_new(&config, "gone", false).expect("new");
        let err = cmd_remove(Some(&config), "gone", false).expect_err("must refuse");
        assert!(err.to_string().contains("--yes"), "{err}");
    }

    #[test]
    fn onion_invalid_nickname_is_rejected() {
        let (_tmp, config) = temp_setup();
        for bad in ["UPPER", "with space", "", "sla/sh"] {
            assert!(
                run_new(&config, bad, false).is_err(),
                "nickname {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn onion_import_of_garbage_fails() {
        let (_tmp, config) = temp_setup();
        let garbage = _tmp.path().join("garbage.id");
        std::fs::write(&garbage, b"definitely not an ssh key").expect("write garbage");
        assert!(cmd_import(Some(&config), "svc", &garbage, false).is_err());
        // Nothing was created for the failed import.
        assert!(!store::keystore_dir(Some(&config))
            .join("hss")
            .join("svc")
            .exists());
    }

    #[test]
    fn onion_list_on_missing_keystore_is_empty_not_error() {
        let (_tmp, config) = temp_setup();
        cmd_list(Some(&config)).expect("list without keystore must succeed");
    }

    #[test]
    fn onion_export_refuses_to_overwrite_without_force() {
        let (_tmp, config) = temp_setup();
        run_new(&config, "exp", false).expect("new");
        let out = _tmp.path().join("existing.id");
        std::fs::write(&out, b"old").expect("seed output file");
        assert!(cmd_export(Some(&config), "exp", &out, false).is_err());
        assert_eq!(std::fs::read(&out).unwrap(), b"old");
        cmd_export(Some(&config), "exp", &out, true).expect("forced export");
        assert_ne!(std::fs::read(&out).unwrap(), b"old");
    }

    #[test]
    fn onion_show_errors_on_unknown_or_missing_keystore() {
        let (_tmp, config) = temp_setup();
        assert!(cmd_show(Some(&config), "nosuch").is_err());
        run_new(&config, "known", false).expect("new");
        assert!(cmd_show(Some(&config), "nosuch").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn onion_export_file_has_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let (_tmp, config) = temp_setup();
        run_new(&config, "perm", false).expect("new");
        let out = _tmp.path().join("perm.id");
        cmd_export(Some(&config), "perm", &out, false).expect("export");
        let mode = std::fs::metadata(&out).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
