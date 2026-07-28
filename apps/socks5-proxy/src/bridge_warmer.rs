//! Background bridge-channel warming pool.
//!
//! Periodically opens (or reuses) Tor channels to the top-N healthiest
//! candidate bridges, ahead of any circuit actually needing them.
//!
//! ## Why this helps
//!
//! `tor-chanmgr` keys its channel cache by relay identity (see
//! `vendor/tor-chanmgr/src/mgr/state.rs`). If this task opens a channel to
//! bridge X via [`arti_wrapper::TorTunnel::warm_bridge`], and arti's own
//! guard manager later wants to build a circuit through the same bridge X,
//! it transparently reuses the already-open channel instead of paying for a
//! fresh obfs4/webtunnel handshake on the hot path. That reuse is entirely
//! automatic inside `ChanMgr` — this module only needs to *ask* for a
//! channel, not wire up anything extra.
//!
//! ## What this is not
//!
//! This task only warms channels. It does not change which bridge carries
//! traffic, and it does not fail over between bridges on degradation — that
//! is a separate, not-yet-built feature. A failed warm attempt is logged
//! and skipped; it never interrupts warming the remaining candidates, and
//! it never affects the live egress path.
//!
//! ## Candidate ranking
//!
//! Candidates are drawn from the currently configured bridges (the same set
//! [`crate::tor_setup::build_tor_settings`] probes at startup), ranked by
//! the health signals already tracked in [`crate::bridge_store::BridgeStore`]:
//! TCP-unreachable bridges (`tcp_fails > 0` per the last probe round) are
//! excluded outright, then the rest are sorted by ascending `circuit_fails`
//! (fewest circuit-layer failures first) and, as a tie-breaker, descending
//! `ok_count` (more cumulative successful probes first). This mirrors the
//! stability-first ordering `tor_setup.rs` already applies when handing
//! bridges to arti at bootstrap.

use std::path::PathBuf;
use std::time::Duration;

use bridge_line::BridgeLine;
use tracing::{info, warn};

use crate::bridge_store::BridgeStore;
use crate::config::{Config, WarmPoolConfig};
use crate::tor_watchdog::TorHandle;

/// Per-candidate health snapshot used to rank bridges for warming. Pulled
/// out of [`BridgeStore`] into a plain struct so the ranking logic
/// ([`select_top_n`]) is unit-testable without any on-disk state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Health {
    /// Consecutive TCP-probe failures per the last probe round. Non-zero
    /// excludes the bridge from the warming pool outright.
    pub tcp_fails: u32,
    /// Consecutive circuit-layer failures observed from arti's tracing.
    /// Lower is better.
    pub circuit_fails: u32,
    /// Cumulative successful-probe count. Higher is better (tie-breaker).
    pub ok_count: u32,
}

/// Select up to `n` candidates to warm, given each bridge's current health.
///
/// Pure function: filters out any bridge whose `tcp_fails > 0` (per the
/// last probe round — the same TCP-health condition
/// [`BridgeStore::alive_count`] uses), then sorts the remainder by ascending
/// `circuit_fails`, breaking ties by descending `ok_count`. The input order
/// otherwise has no bearing on the result — this is a full sort, not a
/// stable "keep first N alive" filter.
pub(crate) fn select_top_n(candidates: &[(BridgeLine, Health)], n: usize) -> Vec<BridgeLine> {
    let mut healthy: Vec<&(BridgeLine, Health)> = candidates
        .iter()
        .filter(|(_, h)| h.tcp_fails == 0)
        .collect();
    healthy.sort_by(|(_, a), (_, b)| {
        a.circuit_fails
            .cmp(&b.circuit_fails)
            .then_with(|| b.ok_count.cmp(&a.ok_count))
    });
    healthy
        .into_iter()
        .take(n)
        .map(|(bridge, _)| bridge.clone())
        .collect()
}

/// Read the configured bridges and pair each with its current health from
/// the on-disk store. Best-effort: a bridge with no store entry yet is
/// treated as maximally healthy (all-zero counters) rather than excluded —
/// mirrors `BridgeStore`'s own `map_or(0, ..)` convention for unknown
/// bridges.
fn candidates_with_health(
    cfg: &Config,
    config_path: Option<&std::path::Path>,
) -> Vec<(BridgeLine, Health)> {
    let parsed = match cfg.bridges.parsed() {
        Ok(p) => p.bridges,
        Err(e) => {
            warn!(error = %e, "warm-pool: config has invalid bridges");
            return Vec::new();
        }
    };
    if parsed.is_empty() {
        return Vec::new();
    }

    let store_path = BridgeStore::resolve_path(config_path);
    let store = match BridgeStore::load(store_path) {
        Ok(s) => Some(s),
        Err(e) => {
            warn!(error = %e, "warm-pool: could not load bridge health store");
            None
        }
    };

    parsed
        .into_iter()
        .map(|bridge| {
            let health = match &store {
                Some(store) => Health {
                    tcp_fails: store.tcp_fails(&bridge),
                    circuit_fails: store.circuit_fails(&bridge),
                    ok_count: store.ok_count(&bridge),
                },
                None => Health {
                    tcp_fails: 0,
                    circuit_fails: 0,
                    ok_count: 0,
                },
            };
            (bridge, health)
        })
        .collect()
}

/// Spawn the background bridge-warming task as a detached tokio task.
///
/// Every `refresh_interval_secs` the task re-reads the configured bridges
/// and their health from the on-disk store, picks the top `pool_size`
/// candidates (see [`select_top_n`]), and calls
/// [`arti_wrapper::TorTunnel::warm_bridge`] for each in turn. A failed warm
/// attempt is logged at `warn!` and does not stop the remaining candidates
/// from being warmed this tick. `cfg.enabled == false` (the default)
/// disables the task entirely.
pub fn spawn_bridge_warmer(handle: TorHandle, config_path: Option<PathBuf>, cfg: WarmPoolConfig) {
    if !cfg.enabled {
        info!("bridge warm-pool disabled");
        return;
    }
    if cfg.pool_size == 0 || cfg.refresh_interval_secs == 0 {
        info!("bridge warm-pool disabled (pool_size or refresh_interval_secs is 0)");
        return;
    }

    let interval = Duration::from_secs(cfg.refresh_interval_secs);
    let pool_size = cfg.pool_size;

    info!(
        pool_size,
        refresh_interval_secs = cfg.refresh_interval_secs,
        "bridge warm-pool armed"
    );

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await; // consume the immediate first tick

        loop {
            ticker.tick().await;

            let Some(tor) = handle.tunnel().await else {
                // Slot drained (shutdown in progress) — nothing to warm.
                continue;
            };

            let cfg = match Config::load_with_override(config_path.as_deref()) {
                Ok(loaded) => loaded.into_config(),
                Err(e) => {
                    warn!(error = %e, "warm-pool: could not reload config");
                    continue;
                }
            };

            let candidates = candidates_with_health(&cfg, config_path.as_deref());
            if candidates.is_empty() {
                continue;
            }
            let selected = select_top_n(&candidates, pool_size);
            if selected.is_empty() {
                continue;
            }

            info!(
                count = selected.len(),
                "warm-pool: warming channels to top candidate bridges"
            );
            for bridge in &selected {
                match tor.warm_bridge(bridge).await {
                    Ok(()) => {
                        info!(bridge = %bridge, "warm-pool: channel warmed");
                    }
                    Err(e) => {
                        warn!(bridge = %bridge, error = %e, "warm-pool: failed to warm channel");
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bridge(line: &str) -> BridgeLine {
        line.parse().expect("test bridge line parses")
    }

    const OBFS4_A: &str =
        "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=ZZZ iat-mode=0";
    const OBFS4_B: &str =
        "obfs4 5.6.7.8:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=WWW iat-mode=0";
    const OBFS4_C: &str =
        "obfs4 9.9.9.9:443 1111111111111111111111111111111111111111 cert=YYY iat-mode=0";

    fn h(tcp_fails: u32, circuit_fails: u32, ok_count: u32) -> Health {
        Health {
            tcp_fails,
            circuit_fails,
            ok_count,
        }
    }

    #[test]
    fn empty_pool_selects_nothing() {
        assert_eq!(select_top_n(&[], 3), Vec::<BridgeLine>::new());
    }

    #[test]
    fn n_zero_selects_nothing_even_with_candidates() {
        let candidates = vec![(bridge(OBFS4_A), h(0, 0, 5))];
        assert_eq!(select_top_n(&candidates, 0), Vec::<BridgeLine>::new());
    }

    #[test]
    fn all_equally_healthy_keeps_up_to_n_in_some_order() {
        let candidates = vec![
            (bridge(OBFS4_A), h(0, 0, 0)),
            (bridge(OBFS4_B), h(0, 0, 0)),
            (bridge(OBFS4_C), h(0, 0, 0)),
        ];
        let selected = select_top_n(&candidates, 2);
        assert_eq!(selected.len(), 2, "capped at n even when all are tied");
    }

    #[test]
    fn explicit_leader_by_ok_count_comes_first() {
        let candidates = vec![
            (bridge(OBFS4_A), h(0, 0, 1)),
            (bridge(OBFS4_B), h(0, 0, 100)),
            (bridge(OBFS4_C), h(0, 0, 5)),
        ];
        let selected = select_top_n(&candidates, 3);
        assert_eq!(
            selected,
            vec![bridge(OBFS4_B), bridge(OBFS4_C), bridge(OBFS4_A)],
            "higher ok_count ranks first when circuit_fails ties"
        );
    }

    #[test]
    fn circuit_fails_dominates_ok_count() {
        // B has more circuit failures than A despite a much higher ok_count
        // — circuit_fails is the primary sort key, ok_count only breaks ties.
        let candidates = vec![
            (bridge(OBFS4_A), h(0, 0, 1)),
            (bridge(OBFS4_B), h(0, 3, 1000)),
        ];
        let selected = select_top_n(&candidates, 2);
        assert_eq!(
            selected,
            vec![bridge(OBFS4_A), bridge(OBFS4_B)],
            "fewer circuit_fails must outrank a much higher ok_count"
        );
    }

    #[test]
    fn tcp_unhealthy_bridge_is_excluded_entirely() {
        let candidates = vec![
            (bridge(OBFS4_A), h(1, 0, 100)),
            (bridge(OBFS4_B), h(0, 0, 1)),
        ];
        let selected = select_top_n(&candidates, 2);
        assert_eq!(
            selected,
            vec![bridge(OBFS4_B)],
            "a bridge with tcp_fails > 0 must never be selected, regardless of other stats"
        );
    }

    #[test]
    fn circuit_fails_above_threshold_is_deprioritized_not_excluded() {
        // circuit_fails alone does not exclude a candidate (only tcp_fails
        // does) — it just sorts it later. With n large enough, both appear.
        let candidates = vec![
            (bridge(OBFS4_A), h(0, 10, 1)),
            (bridge(OBFS4_B), h(0, 0, 1)),
        ];
        let selected = select_top_n(&candidates, 2);
        assert_eq!(
            selected.len(),
            2,
            "both are TCP-healthy, so both are eligible"
        );
        assert_eq!(
            selected[0],
            bridge(OBFS4_B),
            "lower circuit_fails ranks first"
        );
    }

    #[test]
    fn n_larger_than_pool_returns_whole_pool() {
        let candidates = vec![(bridge(OBFS4_A), h(0, 0, 0)), (bridge(OBFS4_B), h(0, 0, 0))];
        let selected = select_top_n(&candidates, 10);
        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn all_tcp_unhealthy_selects_nothing() {
        let candidates = vec![
            (bridge(OBFS4_A), h(1, 0, 100)),
            (bridge(OBFS4_B), h(2, 0, 100)),
        ];
        assert_eq!(select_top_n(&candidates, 5), Vec::<BridgeLine>::new());
    }
}
