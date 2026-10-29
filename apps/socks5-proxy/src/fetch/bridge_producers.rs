use super::*;

pub(super) fn launch(
    handle: TorHandle,
    config_path: Option<std::path::PathBuf>,
    cfg: &Config,
    obs_sink: crate::arti_observability::ObservationSink,
    settings: arti_wrapper::Settings,
    producer_token: CancellationToken,
    producers: &mut Vec<tokio::task::JoinHandle<()>>,
) {
    if settings.pre_endpoint.is_some() {
        warn!("global pre_socks5: bridge refresh, PT, probes, verifier, warmer and watchdogs are unsupported or disabled until restart");
    } else {
        // Periodic upkeep: re-probe, prune dead bridges, top up when short,
        // drain circuit-layer observations from arti's tracing into the
        // health store so descriptor-mismatch / unsuitable bridges are
        // pruned alongside the TCP-dead ones. Reads the tunnel through
        // the handle so pool refreshes follow a watchdog rebuild.
        producers.push(crate::bridge_maintenance::spawn(
            handle.clone(),
            config_path.clone(),
            cfg.bridges.recheck_interval_mins,
            obs_sink.clone(),
            settings,
            producer_token.clone(),
        ));

        // Stale-channel watchdog: rebuilds the `TorClient` when circuits
        // keep failing against TCP-reachable bridges (the half-open
        // channel scenario). Joined at shutdown; disabled by config when unwanted.
        producers.extend(spawn_tor_watchdog(
            handle.clone(),
            config_path.clone(),
            cfg.watchdog,
            producer_token.clone(),
        ));

        // Soft-failover watchdog: nudges arti's guard manager away from
        // a specific bridge whose own circuit-layer health has degraded
        // past a threshold, when a meaningfully healthier configured
        // alternative exists. Shares the `[watchdog]` config section and
        // check cadence with the stale-channel watchdog above; disabled
        // by the same `enabled`/`check_interval_secs` switches.
        producers.extend(spawn_bridge_failover_watchdog(
            handle.clone(),
            config_path.clone(),
            cfg.watchdog,
            producer_token.clone(),
        ));

        // Bridge-channel warm-pool: keeps channels to the healthiest
        // candidate bridges open in the background, so a future
        // switch-over (not built here) does not pay for a cold
        // obfs4/webtunnel handshake. Opt-in; disabled by default.
        producers.extend(crate::bridge_warmer::spawn_bridge_warmer(
            handle.clone(),
            config_path.clone(),
            cfg.warm_pool,
            producer_token.clone(),
        ));

        // Periodic circuit-level bridge verification: every 30 min, checks
        // a small batch of channel-proven bridges for real end-to-end
        // reachability (throwaway clients, live probe) and records the
        // successes into the bridge store. This is the CLI counterpart of
        // android-ffi's background circuit-verify tick; it is self-paced
        // by store state (a tick with no due bridges is nearly free) and
        // uses the active pool but verifies through separate clients.
        producers.push(crate::bridge_verifier::spawn_bridge_circuit_verifier(
            config_path.clone(),
            handle.clone(),
            producer_token.clone(),
        ));
    }
}

#[cfg(test)]
#[path = "bridge_producers_tests.rs"]
mod tests;
