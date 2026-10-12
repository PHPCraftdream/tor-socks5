//! The bridge pool configuration (`lines`, `sources`, thresholds) lives in
//! its own file next to the main config: `<stem>.bridges.ktav`, the same
//! sibling convention as `<stem>.users.ktav`. The program rewrites this file
//! as the pool changes, so the hand-edited main config is left alone.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use anyhow::{Context, Result};

use crate::{BridgesConfig, Config, SAVE_SEQ};

/// Ktav comments are `##` lines (a single `#` is content).
const HEADER: &str = "## Bridge pool of tor-socks5: lines, sources and health thresholds.\n\
## The program rewrites this file as the pool changes; comments are not kept.\n";

impl Config {
    /// Path of the bridges file that belongs to the main config at
    /// `config_path`: same directory, same stem, `.bridges.ktav` suffix.
    pub fn bridges_path(config_path: &Path) -> PathBuf {
        let dir = config_path.parent().unwrap_or_else(|| Path::new("."));
        let stem = config_path
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
            .unwrap_or_else(|| "tor-socks5".to_owned());
        dir.join(format!("{stem}.bridges.ktav"))
    }

    /// Write only the bridges file of the main config at `config_path`.
    /// Everything that changes the bridge pool at run time goes through
    /// this, so the main config is never rewritten behind the operator's
    /// back. Atomic like [`Config::write`].
    pub fn write_bridges(&self, config_path: &Path) -> Result<()> {
        write_atomic(&Self::bridges_path(config_path), &self.bridges_text()?)
    }

    /// The exact text [`Config::write_bridges`] puts in the bridges file.
    pub(crate) fn bridges_text(&self) -> Result<String> {
        let body = ktav::to_string(&self.bridges).context("serialise bridges config to Ktav")?;
        Ok(format!("{HEADER}{body}"))
    }
}

/// Read the bridges file of the main config at `config_path`. A missing file
/// is not an error: it means "built-in defaults" (no lines, default sources).
pub(crate) fn load(config_path: &Path) -> Result<BridgesConfig> {
    let path = Config::bridges_path(config_path);
    match fs::read_to_string(&path) {
        Ok(src) => {
            ktav::from_str(&src).with_context(|| format!("parsing bridges file {}", path.display()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(BridgesConfig::default()),
        Err(error) => {
            Err(error).with_context(|| format!("reading bridges file {}", path.display()))
        }
    }
}

/// Atomic text write through [`persist_lock::TempFileGuard`]: a sibling temp
/// held under an advisory lock for the whole create→rename span, then an
/// atomic rename, so readers see the old or the new full file, never a torn
/// one.
pub(crate) fn write_atomic(path: &Path, body: &str) -> Result<()> {
    let seq = SAVE_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut guard = persist_lock::TempFileGuard::create(path, seq)?;
    guard.write_all(body.as_bytes())?;
    guard.finish()?;
    Ok(())
}

#[cfg(test)]
#[path = "bridges_file_tests.rs"]
mod tests;
