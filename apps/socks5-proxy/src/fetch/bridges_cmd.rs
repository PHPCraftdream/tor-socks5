//! `tor-socks5 bridges fetch` command: bootstrap Tor (with the configured
//! bridges, or built-in seeds as a fallback), fetch fresh bridges from the
//! configured HTTPS sources, probe them, and merge the live newcomers into
//! the config.

use std::future::Future;
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Result};
use tokio_util::sync::CancellationToken;

use crate::cli::BridgesAction;
use crate::config::{Config, Loaded};
use crate::process::{init_tracing, install_crypto_provider, wait_for_signal};
use tor_socks5::runtime::{fetch_bridges, FetchBridgesParams};

#[cfg(test)]
use tor_socks5::runtime::build_tor_settings;

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

    // H10: trip only when the SDK's synchronous pre-flight (see
    // `fetch_bridges`) would pass, so tests still exercise the typed
    // `NoConfigFile`/`PreProxies`/no-sources errors before the mock stop.
    #[cfg(test)]
    if cfg.pre_proxies.is_none()
        && !cfg.bridges.sources.is_empty()
        && FETCH_BOUNDARY.try_with(|hit| hit.set(true)).is_ok()
    {
        bail!("test stopped before fetch startup");
    }
    let _log_guard = init_tracing(&cfg);
    install_crypto_provider();

    // The core of the command lives in the runtime (`fetch_bridges`,
    // SDK-8): bootstrap Tor, refresh the candidate pool, optionally probe
    // and promote. The "no config file found" (typed `NoConfigFile`),
    // `pre_proxies` and "no bridge sources configured" checks live there
    // too, along with the trailing 200 ms post-drop sleep and the
    // bootstrapping info log; the SDK errors propagate via `?`.
    // The first stop signal (Ctrl+C, and Ctrl+Break / SIGTERM where
    // applicable) cancels the fetch gracefully: the SDK drops the tunnel and
    // runs its cleanup tail instead of the process dying mid-write.
    let cancel = CancellationToken::new();
    let stopper = tokio::spawn(cancel_on_signal(cancel.clone(), wait_for_signal()));
    let outcome = fetch_bridges(
        &cfg,
        &config_path,
        FetchBridgesParams {
            timeout: Duration::from_secs(timeout_secs),
            count,
            probe: !(dry_run || no_probe),
            // The binary is its own PT dispatcher (busybox style), so the
            // default environment resolution is correct here; a global
            // `pre_proxies` pool is rejected by the SDK with a typed error.
            pt_binary: tor_socks5::runtime::PtBinary::Environment,
            cancel,
        },
    )
    .await;
    stopper.abort();
    let outcome = outcome?;

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

/// Cancels `cancel` once `stop` resolves with the name of the signal seen.
async fn cancel_on_signal(cancel: CancellationToken, stop: impl Future<Output = &'static str>) {
    let signal = stop.await;
    tracing::info!(signal, "stop requested; cancelling the bridge fetch");
    cancel.cancel();
}

#[cfg(test)]
#[path = "bridges_cmd_tests.rs"]
mod tests;
