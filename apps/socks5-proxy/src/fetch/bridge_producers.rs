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
    // The bridge producers (maintenance, warmer, circuit verifier) belong to
    // one bridge manager (SDK-8): the manager owns their tasks and cancels
    // them through its own token, so nothing is spawned here directly. The
    // pre-endpoint warning now comes from the manager itself. The trampoline
    // below links the manager to the server tree: it awaits the manager's
    // `shutdown()` (cancel + join every producer, so in-flight store writes
    // land) and is itself installed into the same `producers` vec the other
    // producers go through — the owner registry joins it at exactly the
    // point where the direct joins used to happen, so the shutdown ordering
    // is unchanged.
    let manager = tor_socks5_runtime::bridge_manager::start(
        handle.clone(),
        config_path.clone(),
        cfg,
        obs_sink,
        settings.clone(),
    );
    producers.push(tokio::spawn({
        let token = producer_token.clone();
        async move {
            token.cancelled().await;
            manager.shutdown().await;
        }
    }));

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
