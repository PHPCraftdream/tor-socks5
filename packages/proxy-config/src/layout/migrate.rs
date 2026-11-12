//! `tor-socks5 config migrate`: convert a config written in the old layout to
//! the current one. The `bridges` section moves into the bridges file, the
//! `onion_services` section into the onion services file and
//! `dns_server.overrides[].pattern` becomes `patterns: [..]`. The old file is
//! kept as a backup; nothing is written unless the converted result passes
//! the typed schema.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ktav::value::Scalar;
use ktav::{ObjectMap, Value};
use persist_lock::{PathLock, CLI_LOCK_WAIT};

use crate::onion_services::OnionFile;
use crate::{BridgesConfig, Config, OnionServiceEntry};

/// What a successful [`migrate_config`] changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationReport {
    /// Copy of the config as it was before the migration.
    pub backup: PathBuf,
    /// The bridges file that now holds the bridge pool, if the old config
    /// had a `bridges` section.
    pub bridges_file: Option<PathBuf>,
    /// Bridge lines moved into the bridges file.
    pub bridge_lines: usize,
    /// Bridge sources moved into the bridges file.
    pub bridge_sources: usize,
    /// `pattern` keys rewritten as one-element `patterns` lists.
    pub masks_converted: usize,
    /// The onion services file that now holds the services, if the old
    /// config had an `onion_services` section.
    pub onion_file: Option<PathBuf>,
    /// Onion services moved into the onion services file.
    pub onion_services: usize,
}

/// Result of [`migrate_config`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationOutcome {
    /// The config is already in the current layout; nothing was touched.
    AlreadyCurrent,
    /// The config was converted.
    Migrated(MigrationReport),
}

/// Convert the config at `path` to the current layout. Idempotent: a config
/// that is already current is left untouched. Run it while the service is
/// stopped.
pub fn migrate_config(path: &Path) -> Result<MigrationOutcome> {
    let _lock = PathLock::acquire_bounded(path, CLI_LOCK_WAIT)
        .context("config write lock while migrating the config")?;
    let src =
        fs::read_to_string(path).with_context(|| format!("reading config {}", path.display()))?;
    let mut root =
        ktav::parse(&src).with_context(|| format!("parsing config {}", path.display()))?;
    let Value::Object(map) = &mut root else {
        bail!("config {} is not a Ktav object", path.display());
    };
    let inline_bridges = map.shift_remove("bridges");
    let inline_onion = map.shift_remove("onion_services");
    let masks_converted = convert_patterns(map)?;
    if inline_bridges.is_none() && inline_onion.is_none() && masks_converted == 0 {
        return Ok(MigrationOutcome::AlreadyCurrent);
    }

    // Validate the converted result before anything is written.
    let bridges: Option<BridgesConfig> = inline_bridges
        .map(ktav::de::from_value)
        .transpose()
        .context("the old `bridges` section does not match the schema")?;
    let onion: Option<Vec<OnionServiceEntry>> = inline_onion
        .map(inline_onion_services)
        .transpose()
        .context("the old `onion_services` section does not match the schema")?;
    let mut config: Config =
        ktav::de::from_value(root).context("the converted config does not match the schema")?;
    let bridges_path = Config::bridges_path(path);
    let onion_path = Config::onion_path(path);
    if let Some(services) = &onion {
        config.onion_services = services.clone();
        let wanted = crate::onion_file::onion_text(services)?;
        match fs::read_to_string(&onion_path) {
            // A previous run wrote this file and stopped before the main
            // config: the same content is a safe resume.
            Ok(existing) if existing == wanted => {}
            // Any other file would be replaced, losing the services it holds.
            Ok(_) => bail!(
                "{} already exists and differs from the `onion_services` section of {}; remove one of them and run the migration again",
                onion_path.display(),
                path.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("reading onion services file {}", onion_path.display())
                })
            }
        }
    }

    let backup = backup_path(path);
    fs::copy(path, &backup)
        .with_context(|| format!("backing up {} to {}", path.display(), backup.display()))?;
    if bridges.is_some() {
        config.write_bridges(path)?;
    }
    if let Some(services) = &onion {
        Config::write_onion_services(path, services)?;
    }
    config.write_main(path)?;
    Ok(MigrationOutcome::Migrated(MigrationReport {
        backup,
        bridges_file: bridges.is_some().then_some(bridges_path),
        bridge_lines: bridges.as_ref().map_or(0, |b| b.lines.len()),
        bridge_sources: bridges.as_ref().map_or(0, |b| b.sources.len()),
        masks_converted,
        onion_file: onion.is_some().then_some(onion_path),
        onion_services: onion.as_ref().map_or(0, Vec::len),
    }))
}

/// The old `onion_services` list as entries, validated by the same rules a
/// load of the onion services file applies.
fn inline_onion_services(section: Value) -> Result<Vec<OnionServiceEntry>> {
    let mut document = ObjectMap::default();
    document.insert(Scalar::from("services"), section);
    let file: OnionFile = ktav::de::from_value(Value::Object(document))?;
    Ok(file.services)
}

/// Rewrite every `dns_server.overrides[].pattern` as `patterns: [..]`.
fn convert_patterns(root: &mut ObjectMap) -> Result<usize> {
    let Some(Value::Object(dns_server)) = root.get_mut("dns_server") else {
        return Ok(0);
    };
    let Some(Value::Array(overrides)) = dns_server.get_mut("overrides") else {
        return Ok(0);
    };
    let mut converted = 0;
    for (index, entry) in overrides.iter_mut().enumerate() {
        let Value::Object(entry) = entry else {
            continue;
        };
        let Some(mask) = entry.shift_remove("pattern") else {
            continue;
        };
        if entry.contains_key("patterns") {
            bail!(
                "dns_server.overrides[{index}] has both `pattern` and `patterns`; keep only `patterns`"
            );
        }
        entry.insert(Scalar::from("patterns"), Value::Array(vec![mask]));
        converted += 1;
    }
    Ok(converted)
}

/// `<name>.bak-N` next to `path`, with the first free N (never overwrites).
fn backup_path(path: &Path) -> PathBuf {
    let name = path.file_name().unwrap_or_default();
    (1..)
        .map(|n| {
            let mut candidate = name.to_os_string();
            candidate.push(format!(".bak-{n}"));
            path.with_file_name(candidate)
        })
        .find(|candidate| !candidate.exists())
        .expect("an unbounded range yields a free backup name")
}

#[cfg(test)]
#[path = "migrate_tests.rs"]
mod tests;
