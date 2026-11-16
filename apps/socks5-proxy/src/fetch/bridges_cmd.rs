//! `tor-socks5 bridges fetch` command: bootstrap Tor (with the configured
//! bridges, or built-in seeds as a fallback), fetch fresh bridges from the
//! configured HTTPS sources, probe them, and merge the live newcomers into
//! the config.

use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Result};
use tokio_util::sync::CancellationToken;

use crate::cli::BridgesAction;
use crate::config::{Config, Loaded};
use crate::process::{init_tracing, install_crypto_provider};
use tor_socks5_runtime::bridge_manager::{fetch_bridges, FetchBridgesParams};
use tor_socks5_server::route::reject_unsupported_pool;

#[cfg(test)]
use tor_socks5_runtime::tor_setup::build_tor_settings;

#[cfg(test)]
tokio::task_local! {
    static FETCH_BOUNDARY: std::cell::Cell<bool>;
}

/// cancel-safe: NO — bootstraps Tor, performs network I/O, writes config.
pub(crate) async fn cmd_bridges(
    action: BridgesAction,
    config_override: Option<&Path>,
) -> Result<()> {
    let BridgesAction::Fetch {
        dry_run,
        no_probe,
        timeout_secs,
        count,
    } = action;

    let loaded = Config::load_with_override(config_override)?;
    let config_path = match &loaded {
        Loaded::FromFile { path, .. } => path.clone(),
        Loaded::Defaults(_) => {
            bail!("no config file found; run the server once to create defaults")
        }
    };
    let cfg = loaded.into_config();
    reject_unsupported_pool(&cfg.pre_proxies, "bridges fetch global pre_proxies")?;

    #[cfg(test)]
    if FETCH_BOUNDARY.try_with(|hit| hit.set(true)).is_ok() {
        bail!("test stopped before fetch startup");
    }
    let _log_guard = init_tracing(&cfg);
    install_crypto_provider();

    // The core of the command lives in the runtime (`fetch_bridges`,
    // SDK-8): bootstrap Tor, refresh the candidate pool, optionally probe
    // and promote. The "no bridge sources configured" check, the trailing
    // 200 ms post-drop sleep and the bootstrapping info log moved with it.
    let outcome = fetch_bridges(
        &cfg,
        Some(&config_path),
        FetchBridgesParams {
            timeout: Duration::from_secs(timeout_secs),
            count,
            probe: !(dry_run || no_probe),
            cancel: CancellationToken::new(),
        },
    )
    .await?;

    match outcome.promoted {
        None => println!(
            "candidate pool refreshed: +{} new, {} total ({}, no probing)",
            outcome.added,
            outcome.pool_len,
            if dry_run { "--dry-run" } else { "--no-probe" }
        ),
        Some(0) => println!(
            "pool refreshed (+{}); no reachable new bridges promoted",
            outcome.added
        ),
        Some(promoted) => println!(
            "pool refreshed (+{}); promoted {promoted} reachable bridges into {}",
            outcome.added,
            config_path.display()
        ),
    }
    Ok(())
}

#[cfg(test)]
#[path = "bridges_cmd_tests.rs"]
mod tests;
