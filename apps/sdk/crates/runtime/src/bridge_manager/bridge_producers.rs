//! Runtime-level producer launch (SDK-H14 chunk 1): wires the bridge
//! refresh signaling and starts the bridge producers plus the watchdog
//! pair on a live [`TorHandle`]. Shared by the embedded server and by
//! external embedding hosts.

use crate::arti_observability::ObservationSink;
use crate::bridge_manager::{self, BridgeManagerConfig};
use crate::config::Config;
use crate::tor_watchdog::{spawn_bridge_failover_watchdog, spawn_tor_watchdog, TorHandle};
use arti_wrapper::Settings;
use tokio_util::sync::CancellationToken;

/// Wire the refresh signaling and launch the bridge producers and the
/// watchdogs, appending every spawned task to `producers` so the caller
/// can join or abort each one directly at shutdown.
#[allow(clippy::too_many_arguments)]
pub fn launch_producers(
    handle: TorHandle,
    config_path: Option<std::path::PathBuf>,
    cfg: &Config,
    obs_sink: ObservationSink,
    settings: Settings,
    pt_binary: crate::pt::PtBinary,
    producer_token: CancellationToken,
    producers: &mut Vec<tokio::task::JoinHandle<()>>,
) {
    // In-flight connection attempts observe bridge refreshes through the
    // observation sink; the refresh loop starts pre-armed when the
    // preferred transport is configured but missing from the bridge list.
    obs_sink.set_recovery_notifier(handle.bridge_refresh().recovery());
    handle.bridge_refresh().set_needed(
        cfg.bridges.auto_fetch
            && crate::bridge_maintenance::preferred_missing(cfg, &settings.bridges),
    );

    // Bridge producer tasks live in the same cancellation-safe owner as
    // the server's other producers. Transfer the actual tasks so the
    // caller can join or abort each one directly at shutdown.
    let manager = bridge_manager::start_with_parent_token(
        handle.clone(),
        config_path.clone(),
        cfg,
        obs_sink,
        BridgeManagerConfig {
            settings: settings.clone(),
            pt_binary,
        },
        producer_token.clone(),
    );
    manager.transfer_tasks(producers);

    if settings.pre_endpoint.is_some() {
        if let Some(run) = spawn_tor_watchdog(handle, config_path, cfg.watchdog, producer_token) {
            producers.push(run.join);
        }
    } else {
        // Stale-channel watchdog: rebuilds the `TorClient` when circuits
        // keep failing against TCP-reachable bridges (the half-open
        // channel scenario). Joined at shutdown; disabled by config when unwanted.
        if let Some(run) = spawn_tor_watchdog(
            handle.clone(),
            config_path.clone(),
            cfg.watchdog,
            producer_token.clone(),
        ) {
            producers.push(run.join);
        }

        // Soft-failover watchdog: nudges arti's guard manager away from
        // a specific bridge whose own circuit-layer health has degraded
        // past a threshold, when a meaningfully healthier configured
        // alternative exists. Shares the `[watchdog]` config section and
        // check cadence with the stale-channel watchdog above; disabled
        // by the same `enabled`/`check_interval_secs` switches.
        producers.extend(spawn_bridge_failover_watchdog(
            handle,
            config_path,
            cfg.watchdog,
            producer_token,
        ));
    }
}

#[cfg(test)]
#[path = "bridge_producers_tests.rs"]
mod tests;
