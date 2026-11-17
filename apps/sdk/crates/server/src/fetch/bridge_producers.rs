use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn launch(
    handle: TorHandle,
    config_path: std::path::PathBuf,
    cfg: &Config,
    obs_sink: tor_socks5_runtime::arti_observability::ObservationSink,
    settings: arti_wrapper::Settings,
    pt_binary: tor_socks5_runtime::pt::PtBinary,
    producer_token: CancellationToken,
    producers: &mut Vec<tokio::task::JoinHandle<()>>,
) {
    // Bridge producer tasks live in the same cancellation-safe owner as the
    // server's other producers. Transfer the actual tasks so the server can
    // join or abort each one directly at shutdown.
    let manager = tor_socks5_runtime::bridge_manager::start_with_parent_token(
        handle.clone(),
        config_path.clone(),
        cfg,
        obs_sink,
        tor_socks5_runtime::bridge_manager::BridgeManagerConfig {
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
