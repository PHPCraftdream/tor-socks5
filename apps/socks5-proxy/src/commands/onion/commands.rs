//! `tor-socks5 onion new|list|show|export|import|remove` implementations.
//!
//! The services live in the onion services file next to the main config
//! (`<stem>.onion.ktav`): this is where `new` and `import` record a service
//! with its key and address and where `list`, `show`, `export` and `remove`
//! read and change it. Nothing here starts Tor or opens the network. The
//! Arti keystore is only a copy that a launch refreshes from the file; the
//! commands that change a service still take its lock, so they refuse while
//! the server runs (the server writes the same file).

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::Subcommand;
use proxy_config::{Config, IdentityKey, OnionServiceEntry, OnionServicePort};
use tor_hscrypto::pk::HsIdKeypair;
use tor_hsservice::HsNickname;
use tor_llcrypto::pk::ed25519::ExpandedKeypair;

use super::{address, vanity};
use crate::onion::store;

/// Circuit length a new entry starts with (the config default).
const DEFAULT_CIRCUIT_HOPS: u8 = 4;

#[derive(Debug, Subcommand)]
pub(crate) enum OnionAction {
    /// Create a new onion service in the onion services file: a random key,
    /// its address and the given ports.
    ///
    /// With `--vanity PREFIX`, mine a key whose address starts with PREFIX
    /// (base32: a-z, 2-7; up to 8 chars) instead of using a random one.
    New {
        /// Service nickname.
        nick: String,
        /// Port mapping `ONION_PORT=HOST:PORT`, repeatable. With one or more
        /// the service is enabled; without, it is created disabled and the
        /// ports are added to the file by hand.
        #[arg(long = "port", value_name = "ONION_PORT=HOST:PORT")]
        ports: Vec<String>,
        /// Replace an existing identity. WARNING: the old .onion address
        /// will be lost permanently.
        #[arg(long)]
        force: bool,
        /// Search for an address starting with this prefix (a-z2-7, <= 8 chars).
        #[arg(long)]
        vanity: Option<String>,
        /// Vanity search worker threads; 0 or omitted = all but one core.
        #[arg(long)]
        threads: Option<usize>,
        /// Vanity search time budget, e.g. 30m or 2h (bare number = seconds).
        #[arg(long)]
        timeout: Option<String>,
    },
    /// List the onion services of the file: nickname, address, ports.
    List,
    /// Show a service's address, ports and where its key is (never the secret key).
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
    /// Import an identity key from an exported file into the onion services file.
    Import {
        /// Service nickname to register the key under.
        nick: String,
        /// File previously produced by `onion export`.
        file: PathBuf,
        /// Port mapping `ONION_PORT=HOST:PORT`, repeatable; replaces the
        /// ports of an existing service.
        #[arg(long = "port", value_name = "ONION_PORT=HOST:PORT")]
        ports: Vec<String>,
        /// Replace an existing identity for this nickname. WARNING: the old
        /// .onion address will be lost permanently.
        #[arg(long)]
        force: bool,
    },
    /// Delete a service with its key from the onion services file
    /// (irreversible without a prior `onion export`: the .onion address is lost).
    Remove {
        /// Service nickname.
        nick: String,
        /// Confirm the deletion (refused without this flag).
        #[arg(long)]
        yes: bool,
    },
}

/// Where a command works: the onion services file of the resolved main
/// config, and the keystore copy beside it.
struct Target {
    config: PathBuf,
    keystore: PathBuf,
}

impl Target {
    fn new(config_path: Option<&Path>) -> Self {
        let config = Config::resolve_path(config_path);
        let keystore = store::keystore_dir(Some(&config));
        Self { config, keystore }
    }

    fn file(&self) -> PathBuf {
        Config::onion_path(&self.config)
    }

    fn services(&self) -> Result<Vec<OnionServiceEntry>> {
        Config::read_onion_services(&self.config)
    }

    /// The entry of `nick`, or the "no such service" error.
    fn entry(&self, nick: &HsNickname) -> Result<OnionServiceEntry> {
        self.services()?
            .into_iter()
            .find(|entry| entry.nickname == nick.to_string())
            .with_context(|| format!("no onion service named {:?}", nick.to_string()))
    }
}

pub(crate) fn run(action: OnionAction, config_path: Option<&Path>) -> Result<()> {
    let at = Target::new(config_path);
    match action {
        OnionAction::New {
            nick,
            ports,
            force,
            vanity,
            threads,
            timeout,
        } => cmd_new(&at, &nick, &ports, force, vanity, threads, timeout),
        OnionAction::List => cmd_list(&at),
        OnionAction::Show { nick } => cmd_show(&at, &nick),
        OnionAction::Export { nick, out, force } => cmd_export(&at, &nick, &out, force),
        OnionAction::Import {
            nick,
            file,
            ports,
            force,
        } => cmd_import(&at, &nick, &file, &ports, force),
        OnionAction::Remove { nick, yes } => cmd_remove(&at, &nick, yes),
    }
}

fn parse_ports(raw: &[String]) -> Result<Option<Vec<OnionServicePort>>> {
    if raw.is_empty() {
        return Ok(None);
    }
    let mut ports: Vec<OnionServicePort> = Vec::with_capacity(raw.len());
    for text in raw {
        let port: OnionServicePort = text.parse().map_err(anyhow::Error::msg)?;
        if ports.iter().any(|seen| seen.onion_port == port.onion_port) {
            bail!("onion port {} is given twice", port.onion_port);
        }
        ports.push(port);
    }
    Ok(Some(ports))
}

/// Refuse to replace an identity that exists (in the file, or left in the
/// keystore by an older version) unless `force`; warn when forced.
fn check_replace(at: &Target, nick: &HsNickname, force: bool) -> Result<()> {
    let in_file = at
        .services()?
        .iter()
        .any(|entry| entry.nickname == nick.to_string() && entry.key.is_some());
    let in_keystore = at.keystore.is_dir() && {
        let keymgr = store::open(&at.keystore)?;
        store::exists(&keymgr, nick)?
    };
    if !(in_file || in_keystore) {
        return Ok(());
    }
    if !force {
        bail!(
            "nickname {:?} already has an identity; pass --force to replace it \
             (the old .onion address will be lost)",
            nick.to_string()
        );
    }
    eprintln!(
        "warning: replacing the identity of {:?}: the old .onion address \
         will be lost permanently",
        nick.to_string()
    );
    Ok(())
}

/// The keystore keypair of a generated or searched key, checked against the
/// address the generator computed.
fn hs_keypair(generated: &address::Keypair) -> Result<HsIdKeypair> {
    let expanded = ExpandedKeypair::from_secret_key_bytes(generated.to_expanded_bytes())
        .context("invalid expanded secret key")?;
    let key = HsIdKeypair::from(expanded);
    if store::address_of(&key) != generated.address() {
        bail!("address mismatch; key not saved");
    }
    Ok(key)
}

/// Record `key_bytes` (a keystore key file) as the identity of `nick`.
///
/// `ports`, when given, replace the service's ports and enable it; without
/// them an existing service keeps its ports and a new one is created
/// disabled. Returns the service's address.
fn record_identity(
    at: &Target,
    nick: &HsNickname,
    key_bytes: &[u8],
    address: String,
    ports: Option<Vec<OnionServicePort>>,
) -> Result<String> {
    let key = IdentityKey::new(store::encode_key(key_bytes)).map_err(anyhow::Error::msg)?;
    let name = nick.to_string();
    Config::update_onion_services(&at.config, |services| {
        let service = services.iter_mut().find(|entry| entry.nickname == name);
        match service {
            Some(entry) => {
                entry.address = Some(address.clone());
                entry.key = Some(key);
                if let Some(ports) = ports {
                    entry.ports = ports;
                    entry.enabled = true;
                }
            }
            None => services.push(OnionServiceEntry {
                nickname: name,
                enabled: ports.is_some(),
                address: Some(address.clone()),
                key: Some(key),
                circuit_hops: DEFAULT_CIRCUIT_HOPS,
                ports: ports.unwrap_or_default(),
            }),
        }
        Ok(())
    })?;
    forget_keystore_copy(at, nick)?;
    Ok(address)
}

/// Drop the keystore's copy of `nick`: the file is the source, and the next
/// launch writes the key it holds back into the keystore.
fn forget_keystore_copy(at: &Target, nick: &HsNickname) -> Result<()> {
    if store::identity_file(&at.keystore, nick).is_some() {
        store::remove_all(&at.keystore, nick)?;
    }
    Ok(())
}

fn print_recorded(at: &Target, nick: &HsNickname, address: &str, enabled_ports: bool) {
    println!("nickname: {nick}");
    println!("address:  {address}");
    println!("file:     {}", at.file().display());
    if !enabled_ports {
        println!(
            "no ports yet: the service is disabled; add `ports: [ 80=127.0.0.1:8080 ]` \
             and `enabled: true` to its entry (or run `onion new --force --port ...`)"
        );
    }
}

fn cmd_new(
    at: &Target,
    nick: &str,
    ports: &[String],
    force: bool,
    vanity: Option<String>,
    threads: Option<usize>,
    timeout: Option<String>,
) -> Result<()> {
    if vanity.is_none() && (threads.is_some() || timeout.is_some()) {
        bail!("--threads/--timeout require --vanity");
    }
    let nick = store::nickname(nick)?;
    let ports = parse_ports(ports)?;
    let _lock = store::lock(&at.keystore)?;
    check_replace(at, &nick, force)?;

    let generated = match vanity.as_deref() {
        Some(prefix) => vanity::search_for_cli(prefix, threads, timeout.as_deref())?,
        None => address::generate(),
    };
    let key = hs_keypair(&generated)?;
    let address = store::address_of(&key);
    let bytes = store::identity_file_bytes(key, &nick)?;
    let has_ports = ports.is_some();
    let address = record_identity(at, &nick, &bytes, address, ports)?;
    print_recorded(at, &nick, &address, has_ports);
    Ok(())
}

fn cmd_list(at: &Target) -> Result<()> {
    let services = at.services()?;
    if services.is_empty() {
        println!("no onion services");
        return Ok(());
    }
    println!(
        "{:<24} {:<63} {:<8} PORTS",
        "NICKNAME", "ADDRESS", "ENABLED"
    );
    for service in services {
        let ports = service
            .ports
            .iter()
            .map(|port| format!("{}={}", port.onion_port, port.target))
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "{:<24} {:<63} {:<8} {}",
            service.nickname,
            service.address.as_deref().unwrap_or("-"),
            if service.enabled { "yes" } else { "no" },
            if ports.is_empty() { "-" } else { &ports },
        );
    }
    Ok(())
}

fn cmd_show(at: &Target, nick: &str) -> Result<()> {
    let nick = store::nickname(nick)?;
    let service = at.entry(&nick)?;
    println!("nickname: {nick}");
    println!(
        "address:  {}",
        service
            .address
            .as_deref()
            .unwrap_or("none yet (created at the first start)")
    );
    println!("enabled:  {}", if service.enabled { "yes" } else { "no" });
    for port in &service.ports {
        println!("port:     {}={}", port.onion_port, port.target);
    }
    match service.key {
        Some(_) => println!("key:      stored in {}", at.file().display()),
        None => println!("key:      none yet (created at the first start)"),
    }
    Ok(())
}

fn cmd_export(at: &Target, nick: &str, out: &Path, force: bool) -> Result<()> {
    let nick = store::nickname(nick)?;
    let service = at.entry(&nick)?;
    let Some(key) = service.key else {
        bail!(
            "service {:?} has no key yet: it is created at the first start \
             (or by `onion new --force`)",
            nick.to_string()
        );
    };
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
    let bytes = store::decode_key(key.as_str())?;
    write_secret_file(out, &bytes)?;
    println!("exported {} to {}", nick, out.display());
    Ok(())
}

fn cmd_import(at: &Target, nick: &str, file: &Path, ports: &[String], force: bool) -> Result<()> {
    let nick = store::nickname(nick)?;
    let ports = parse_ports(ports)?;
    let bytes = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    let key = store::parse_identity_file(&bytes, &nick)?;
    let _lock = store::lock(&at.keystore)?;
    check_replace(at, &nick, force)?;
    let address = store::address_of(&key);
    let enabled_ports =
        ports.is_some() || at.entry(&nick).is_ok_and(|entry| !entry.ports.is_empty());
    let address = record_identity(at, &nick, &bytes, address, ports)?;
    println!("imported {} from {}", nick, file.display());
    print_recorded(at, &nick, &address, enabled_ports);
    Ok(())
}

fn cmd_remove(at: &Target, nick: &str, yes: bool) -> Result<()> {
    let nick = store::nickname(nick)?;
    if !yes {
        bail!(
            "refusing to remove {:?} without --yes: this deletes the service's \
             identity key and is irreversible — the .onion address is lost \
             unless it was exported first",
            nick.to_string()
        );
    }
    let _lock = store::lock(&at.keystore)?;
    let name = nick.to_string();
    Config::update_onion_services(&at.config, |services| {
        let before = services.len();
        services.retain(|entry| entry.nickname != name);
        if services.len() == before {
            bail!("no onion service named {name:?}");
        }
        Ok(())
    })?;
    forget_keystore_copy(at, &nick)?;
    println!("removed {nick} (the service and its key are deleted)");
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

    /// A fresh temp dir + a main config path inside it (the config file
    /// itself never has to exist: only its directory and stem are used).
    fn temp_setup() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("temp dir");
        let config = dir.path().join("tor-socks5.ktav");
        (dir, config)
    }

    fn run_new(config: &Path, nick: &str, force: bool) -> Result<()> {
        run_new_full(config, nick, &[], force, None, None, None)
    }

    fn run_new_full(
        config: &Path,
        nick: &str,
        ports: &[&str],
        force: bool,
        vanity: Option<&str>,
        threads: Option<usize>,
        timeout: Option<&str>,
    ) -> Result<()> {
        run(
            OnionAction::New {
                nick: nick.to_owned(),
                ports: ports.iter().map(|port| (*port).to_owned()).collect(),
                force,
                vanity: vanity.map(str::to_owned),
                threads,
                timeout: timeout.map(str::to_owned),
            },
            Some(config),
        )
    }

    fn service(config: &Path, nick: &str) -> OnionServiceEntry {
        Config::read_onion_services(config)
            .expect("read the file")
            .into_iter()
            .find(|entry| entry.nickname == nick)
            .unwrap_or_else(|| panic!("no service {nick} in the file"))
    }

    fn address_of(config: &Path, nick: &str) -> String {
        service(config, nick)
            .address
            .expect("the service has an address")
    }

    fn at(config: &Path) -> Target {
        Target::new(Some(config))
    }

    #[test]
    fn onion_new_list_show_export_remove_import_roundtrip() {
        let (_tmp, config) = temp_setup();

        run_new(&config, "svc", false).expect("new");
        let address_before = address_of(&config, "svc");
        assert!(
            service(&config, "svc").key.is_some(),
            "the key is in the file"
        );

        cmd_list(&at(&config)).expect("list");
        cmd_show(&at(&config), "svc").expect("show");
        assert_eq!(address_of(&config, "svc"), address_before);

        let export = _tmp.path().join("svc.id");
        cmd_export(&at(&config), "svc", &export, false).expect("export");
        let bytes = std::fs::read(&export).expect("export bytes");
        assert!(!bytes.is_empty());

        // remove (guarded), then import restores the same address
        assert!(cmd_remove(&at(&config), "svc", false).is_err());
        cmd_remove(&at(&config), "svc", true).expect("remove");
        assert!(Config::read_onion_services(&config).unwrap().is_empty());
        cmd_import(&at(&config), "svc", &export, &[], false).expect("import");
        assert_eq!(address_of(&config, "svc"), address_before);
        cmd_show(&at(&config), "svc").expect("show after import");
    }

    #[test]
    fn a_new_service_with_ports_is_enabled_and_without_ports_disabled() {
        let (_tmp, config) = temp_setup();
        run_new_full(
            &config,
            "web",
            &["80=127.0.0.1:8080", "443=127.0.0.1:8443"],
            false,
            None,
            None,
            None,
        )
        .expect("new with ports");
        let web = service(&config, "web");
        assert!(web.enabled);
        assert_eq!(web.ports.len(), 2);
        assert_eq!(web.ports[1].onion_port, 443);

        run_new(&config, "later", false).expect("new without ports");
        let later = service(&config, "later");
        assert!(!later.enabled, "nothing to forward yet");
        assert!(later.ports.is_empty());
    }

    #[test]
    fn onion_new_refuses_existing_nickname_without_force() {
        let (_tmp, config) = temp_setup();
        run_new(&config, "dup", false).expect("first new");
        let address = address_of(&config, "dup");
        assert!(run_new(&config, "dup", false).is_err(), "must refuse");
        assert_eq!(address_of(&config, "dup"), address, "address unchanged");
        run_new(&config, "dup", true).expect("forced new");
        assert_ne!(address_of(&config, "dup"), address);
    }

    #[test]
    fn a_forced_new_keeps_the_ports_of_the_service() {
        let (_tmp, config) = temp_setup();
        run_new_full(
            &config,
            "keep",
            &["80=127.0.0.1:8080"],
            false,
            None,
            None,
            None,
        )
        .expect("new");
        run_new(&config, "keep", true).expect("forced new without ports");
        let kept = service(&config, "keep");
        assert!(kept.enabled);
        assert_eq!(kept.ports.len(), 1);
    }

    #[test]
    fn a_key_left_in_the_keystore_counts_as_an_existing_identity() {
        let (_tmp, config) = temp_setup();
        let nick = store::nickname("old").expect("nickname");
        let dir = store::keystore_dir(Some(&config));
        let keymgr = store::open(&dir).expect("keystore");
        store::generate(&keymgr, &nick, false).expect("generate");
        drop(keymgr);
        assert!(run_new(&config, "old", false).is_err(), "must refuse");
        run_new(&config, "old", true).expect("forced new");
        assert!(
            store::identity_file(&dir, &nick).is_none(),
            "the stale keystore copy is dropped: the file is the source"
        );
    }

    #[test]
    fn onion_import_refuses_existing_nickname_without_force() {
        let (_tmp, config) = temp_setup();
        run_new(&config, "imp", false).expect("new");
        let export = _tmp.path().join("imp.id");
        cmd_export(&at(&config), "imp", &export, false).expect("export");
        assert!(cmd_import(&at(&config), "imp", &export, &[], false).is_err());
        cmd_import(&at(&config), "imp", &export, &[], true).expect("forced import");
    }

    #[test]
    fn import_with_ports_replaces_the_ports_and_enables_the_service() {
        let (_tmp, config) = temp_setup();
        run_new(&config, "src", false).expect("new");
        let export = _tmp.path().join("src.id");
        cmd_export(&at(&config), "src", &export, false).expect("export");

        // Moving the identity to another machine: another config, a new name.
        let (_other_tmp, other) = temp_setup();
        cmd_import(
            &at(&other),
            "copy",
            &export,
            &["8080=127.0.0.1:80".to_owned()],
            false,
        )
        .expect("import as a new service");
        let copy = service(&other, "copy");
        assert!(copy.enabled);
        assert_eq!(copy.ports[0].onion_port, 8080);
        assert_eq!(copy.address, service(&config, "src").address);
    }

    #[test]
    fn one_identity_cannot_serve_under_two_nicknames() {
        let (_tmp, config) = temp_setup();
        run_new(&config, "src", false).expect("new");
        let export = _tmp.path().join("src.id");
        cmd_export(&at(&config), "src", &export, false).expect("export");
        let error = cmd_import(&at(&config), "twin", &export, &[], false).expect_err("refused");
        assert!(
            format!("{error:#}").contains("duplicate address"),
            "{error:#}"
        );
        assert!(
            Config::read_onion_services(&config)
                .unwrap()
                .iter()
                .all(|entry| entry.nickname != "twin"),
            "nothing was recorded"
        );
    }

    #[test]
    fn onion_remove_requires_yes() {
        let (_tmp, config) = temp_setup();
        run_new(&config, "gone", false).expect("new");
        let err = cmd_remove(&at(&config), "gone", false).expect_err("must refuse");
        assert!(err.to_string().contains("--yes"), "{err}");
        assert!(cmd_remove(&at(&config), "nosuch", true).is_err());
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
    fn invalid_or_repeated_ports_are_rejected_before_anything_is_created() {
        let (_tmp, config) = temp_setup();
        for ports in [&["80"][..], &["80=127.0.0.1:1", "80=127.0.0.1:2"][..]] {
            assert!(run_new_full(&config, "p", ports, false, None, None, None).is_err());
        }
        assert!(!Config::onion_path(&config).exists());
    }

    #[test]
    fn onion_import_of_garbage_fails() {
        let (_tmp, config) = temp_setup();
        let garbage = _tmp.path().join("garbage.id");
        std::fs::write(&garbage, b"definitely not an ssh key").expect("write garbage");
        assert!(cmd_import(&at(&config), "svc", &garbage, &[], false).is_err());
        // Nothing was created for the failed import.
        assert!(!Config::onion_path(&config).exists());
    }

    #[test]
    fn onion_list_without_a_file_is_empty_not_error() {
        let (_tmp, config) = temp_setup();
        cmd_list(&at(&config)).expect("list without a file must succeed");
    }

    #[test]
    fn onion_export_refuses_to_overwrite_without_force() {
        let (_tmp, config) = temp_setup();
        run_new(&config, "exp", false).expect("new");
        let out = _tmp.path().join("existing.id");
        std::fs::write(&out, b"old").expect("seed output file");
        assert!(cmd_export(&at(&config), "exp", &out, false).is_err());
        assert_eq!(std::fs::read(&out).unwrap(), b"old");
        cmd_export(&at(&config), "exp", &out, true).expect("forced export");
        assert_ne!(std::fs::read(&out).unwrap(), b"old");
    }

    #[test]
    fn export_of_a_service_without_a_key_explains_itself() {
        let (_tmp, config) = temp_setup();
        Config::write_onion_services(
            &config,
            &[OnionServiceEntry {
                nickname: "fresh".to_owned(),
                enabled: false,
                address: None,
                key: None,
                circuit_hops: DEFAULT_CIRCUIT_HOPS,
                ports: Vec::new(),
            }],
        )
        .expect("write");
        let err = cmd_export(&at(&config), "fresh", &_tmp.path().join("x.id"), false)
            .expect_err("no key yet");
        assert!(err.to_string().contains("no key yet"), "{err}");
    }

    #[test]
    fn onion_show_errors_on_unknown_service() {
        let (_tmp, config) = temp_setup();
        assert!(cmd_show(&at(&config), "nosuch").is_err());
        run_new(&config, "known", false).expect("new");
        assert!(cmd_show(&at(&config), "nosuch").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn onion_export_file_has_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let (_tmp, config) = temp_setup();
        run_new(&config, "perm", false).expect("new");
        let out = _tmp.path().join("perm.id");
        cmd_export(&at(&config), "perm", &out, false).expect("export");
        let mode = std::fs::metadata(&out).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn onion_new_vanity_flags_require_vanity() {
        let (_tmp, config) = temp_setup();
        let err = run_new_full(&config, "svc", &[], false, None, Some(2), None)
            .expect_err("threads without vanity");
        assert!(err.to_string().contains("--vanity"), "{err}");
        let err = run_new_full(&config, "svc", &[], false, None, None, Some("30s"))
            .expect_err("timeout without vanity");
        assert!(err.to_string().contains("--vanity"), "{err}");
        assert!(!Config::onion_path(&config).exists());
    }

    #[test]
    fn onion_new_vanity_keypair_roundtrip_to_hs_id() {
        for _ in 0..4 {
            let generated = address::generate();
            let key = hs_keypair(&generated).expect("keypair");
            assert_eq!(store::address_of(&key), generated.address());
        }
    }

    #[test]
    fn onion_new_vanity_finds_prefix_end_to_end() {
        let (_tmp, config) = temp_setup();
        run_new_full(&config, "van", &[], false, Some("a"), Some(2), Some("30s"))
            .expect("vanity new");
        let address = address_of(&config, "van");
        assert!(address.starts_with('a'), "{address}");
        cmd_show(&at(&config), "van").expect("show");
    }

    #[test]
    fn onion_new_vanity_times_out_saves_nothing() {
        let (_tmp, config) = temp_setup();
        let err = run_new_full(
            &config,
            "slow",
            &[],
            false,
            Some("abcdefgh"),
            Some(2),
            Some("1s"),
        )
        .expect_err("8-char prefix must time out");
        assert!(err.to_string().contains("timed out"), "{err}");
        assert!(!Config::onion_path(&config).exists());
    }

    #[test]
    fn onion_new_vanity_requires_timeout_for_long_estimate() {
        let (_tmp, config) = temp_setup();
        let err = run_new_full(&config, "slow", &[], false, Some("abcdefgh"), Some(2), None)
            .expect_err("long estimate without --timeout");
        assert!(err.to_string().contains("--timeout"), "{err}");
        assert!(!Config::onion_path(&config).exists());
    }
}
