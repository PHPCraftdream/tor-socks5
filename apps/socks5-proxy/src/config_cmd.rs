//! `tor-socks5 config ...`: maintenance of the config files themselves.

use std::path::Path;

use anyhow::{ensure, Result};
use clap::Subcommand;

use crate::config::{migrate_config, Config, MigrationOutcome};

#[derive(Subcommand)]
pub(crate) enum ConfigAction {
    /// Convert a config written in the old layout to the current one: the
    /// `bridges` section moves into `<name>.bridges.ktav` and
    /// `dns_server.overrides[].pattern` becomes `patterns: [..]`. Stop the
    /// service first; the old file is kept as `<name>.ktav.bak-N`. A config
    /// that is already current is left untouched.
    Migrate,
}

pub(crate) fn run(action: ConfigAction, config_override: Option<&Path>) -> Result<()> {
    match action {
        ConfigAction::Migrate => migrate(config_override),
    }
}

fn migrate(config_override: Option<&Path>) -> Result<()> {
    let path = Config::resolve_path(config_override);
    ensure!(
        path.exists(),
        "config {} not found; nothing to migrate (pass --config <path>)",
        path.display()
    );
    match migrate_config(&path)? {
        MigrationOutcome::AlreadyCurrent => {
            println!(
                "{}: already in the current layout, nothing to do",
                path.display()
            );
        }
        MigrationOutcome::Migrated(report) => {
            println!("migrated {}", path.display());
            println!("  old config kept as {}", report.backup.display());
            if let Some(file) = &report.bridges_file {
                println!(
                    "  bridge pool moved to {} ({} lines, {} sources)",
                    file.display(),
                    report.bridge_lines,
                    report.bridge_sources
                );
            }
            if report.masks_converted > 0 {
                println!(
                    "  dns_server.overrides: {} `pattern` key(s) rewritten as `patterns`",
                    report.masks_converted
                );
            }
        }
    }
    Ok(())
}
