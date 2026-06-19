//! `tor-socks5 bridges fetch` command: bootstrap Tor (with the configured
//! bridges, or built-in seeds as a fallback), fetch fresh bridges from the
//! configured HTTPS sources, probe them, and merge the live newcomers into
//! the config.

use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use arti_wrapper::TorTunnel;
use tracing::info;

use crate::cli::BridgesAction;
use crate::config::{Config, Loaded};
use crate::startup::{init_tracing, install_crypto_provider};
use crate::tor_setup::build_tor_settings;

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

    let _log_guard = init_tracing(&cfg);
    install_crypto_provider();

    if cfg.bridges.sources.is_empty() {
        bail!("no bridge sources configured in bridges.sources — nothing to fetch");
    }

    // Bootstrap Tor using the configured bridges (or built-in seeds as a
    // fallback) so we have a circuit to fetch over.
    let settings = build_tor_settings(&cfg, Some(&config_path)).await?;
    info!(
        count = settings.bridges.len(),
        "bootstrapping Tor to fetch fresh bridges"
    );
    let tor = TorTunnel::bootstrap_with(settings)
        .await
        .context("failed to bootstrap Tor for bridge fetching")?;

    // Step 1: refresh the candidate pool from the sources over Tor.
    let timeout = Duration::from_secs(timeout_secs);
    let added =
        crate::fetch_merge::refresh_candidate_pool(&tor, &cfg, Some(&config_path), timeout).await?;

    if dry_run || no_probe {
        // Fill the pool but do not probe/promote.
        let pool = crate::candidate_pool::CandidatePool::load(
            crate::candidate_pool::CandidatePool::resolve_path(Some(&config_path)),
        )
        .context("loading candidate pool")?;
        println!(
            "candidate pool refreshed: +{added} new, {} total ({}, no probing)",
            pool.len(),
            if dry_run { "--dry-run" } else { "--no-probe" }
        );
    } else {
        // Step 2: drain — lazily probe the pool and promote up to `count`
        // reachable bridges into the working config.
        let promoted = crate::fetch_merge::drain_pool(Some(&config_path), count).await?;
        if promoted == 0 {
            println!("pool refreshed (+{added}); no reachable new bridges promoted");
        } else {
            println!(
                "pool refreshed (+{added}); promoted {promoted} reachable bridges into {}",
                config_path.display()
            );
        }
    }

    drop(tor);
    tokio::time::sleep(Duration::from_millis(200)).await;
    Ok(())
}
