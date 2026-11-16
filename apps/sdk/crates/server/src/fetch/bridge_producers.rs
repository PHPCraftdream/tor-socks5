use super::*;

pub(super) fn launch(
    handle: TorHandle,
    config_path: Option<std::path::PathBuf>,
    cfg: &Config,
    obs_sink: tor_socks5_runtime::arti_observability::ObservationSink,
    settings: arti_wrapper::Settings,
    producer_token: CancellationToken,
    producers: &mut Vec<tokio::task::JoinHandle<()>>,
) {
    // Bridge producer tasks must live in the same cancellation-safe owner as
    // the server's other producers. A trampoline awaiting manager.shutdown()
    // would own the child handles; aborting that trampoline at the shutdown
    // deadline would drop and detach those children. Transfer the actual tasks
    // instead. This is the SDK-11 bridge until SDK-14 unifies task ownership.
    let manager = tor_socks5_runtime::bridge_manager::start_for_server(
        handle.clone(),
        config_path.clone(),
        cfg,
        obs_sink,
        settings.clone(),
        producer_token.clone(),
    );
    producers.extend(manager.into_tasks());

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
