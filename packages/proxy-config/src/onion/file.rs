//! The onion services live in their own file next to the main config:
//! `<stem>.onion.ktav`, the same sibling convention as `<stem>.bridges.ktav`
//! and `<stem>.users.ktav`. It is the only source of the services: nickname,
//! key, address, ports. The file holds secret keys, so it is written with
//! owner-only permissions where the OS has them, and the program rewrites it
//! when a service gets its key (comments are not kept).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use anyhow::{Context, Result};
use persist_lock::{PathLock, CLI_LOCK_WAIT};

use crate::onion_services::OnionFile;
use crate::{Config, OnionServiceEntry, SAVE_SEQ};

/// Ktav comments are `##` lines (a single `#` is content).
const HEADER: &str = "## Onion services of tor-socks5: the only source of the services.\n\
## `key` is the secret identity of a service: keep this file private.\n\
## The program rewrites this file; comments are not kept.\n";

impl Config {
    /// Path of the onion services file that belongs to the main config at
    /// `config_path`: same directory, same stem, `.onion.ktav` suffix.
    pub fn onion_path(config_path: &Path) -> PathBuf {
        let dir = config_path.parent().unwrap_or_else(|| Path::new("."));
        let stem = config_path
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
            .unwrap_or_else(|| "tor-socks5".to_owned());
        dir.join(format!("{stem}.onion.ktav"))
    }

    /// The services stored for the main config at `config_path`; none when
    /// the file does not exist.
    pub fn read_onion_services(config_path: &Path) -> Result<Vec<OnionServiceEntry>> {
        load(config_path)
    }

    /// Replace the services of the main config at `config_path` with
    /// `services`, after the same validation a load applies.
    pub fn write_onion_services(config_path: &Path, services: &[OnionServiceEntry]) -> Result<()> {
        let path = Config::onion_path(config_path);
        write_private_atomic(&path, &onion_text(services)?)
    }

    /// Read the services, let `change` edit them, validate the result and
    /// write it back, all under the file's lock, so two writers never lose
    /// each other's edit. Nothing is written when `change` fails.
    pub fn update_onion_services<R>(
        config_path: &Path,
        change: impl FnOnce(&mut Vec<OnionServiceEntry>) -> Result<R>,
    ) -> Result<R> {
        let path = Config::onion_path(config_path);
        let _lock =
            PathLock::acquire_bounded(&path, CLI_LOCK_WAIT).context("onion services file lock")?;
        let mut services = load(config_path)?;
        let outcome = change(&mut services)?;
        write_private_atomic(&path, &onion_text(&services)?)?;
        Ok(outcome)
    }
}

/// Read the onion services file of the main config at `config_path`. A
/// missing file is not an error: it means no services.
pub(crate) fn load(config_path: &Path) -> Result<Vec<OnionServiceEntry>> {
    let path = Config::onion_path(config_path);
    persist_lock::cleanup_temp_files(&path);
    match fs::read_to_string(&path) {
        Ok(src) => {
            parse(&src).with_context(|| format!("parsing onion services file {}", path.display()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => {
            Err(error).with_context(|| format!("reading onion services file {}", path.display()))
        }
    }
}

/// Parse and validate the text of an onion services file.
pub(crate) fn parse(src: &str) -> Result<Vec<OnionServiceEntry>> {
    Ok(ktav::from_str::<OnionFile>(src)?.services)
}

/// The file text for `services`, checked by parsing it back: what is written
/// is exactly what a load accepts.
pub(crate) fn onion_text(services: &[OnionServiceEntry]) -> Result<String> {
    let document = OnionFile {
        services: services.to_vec(),
    };
    let body = ktav::to_string(&document).context("serialise the onion services to Ktav")?;
    let text = format!("{HEADER}{body}");
    parse(&text).context("the onion services are not valid")?;
    Ok(text)
}

/// Atomic write through [`persist_lock::TempFileGuard`] that keeps the key
/// private: the temp file is restricted to its owner (Unix mode 0600) before
/// any byte of the secret is written. On Windows there is no chmod; the file
/// inherits the ACL of its directory, like every other file of the config.
fn write_private_atomic(path: &Path, body: &str) -> Result<()> {
    let seq = SAVE_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut guard = persist_lock::TempFileGuard::create(path, seq)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(guard.temp_path(), fs::Permissions::from_mode(0o600))
            .context("restricting the onion services file to its owner")?;
    }
    guard.write_all(body.as_bytes())?;
    guard.finish()?;
    Ok(())
}

#[cfg(test)]
#[path = "file_tests.rs"]
mod tests;
