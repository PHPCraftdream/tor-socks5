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
//! the health signals already tracked in [`bridge_store::BridgeStore`]:
//! TCP-unreachable bridges (`tcp_fails > 0` per the last probe round) are
//! excluded outright, then the rest are sorted by ascending `circuit_fails`
//! (fewest circuit-layer failures first), then by descending `verified_count`
//! (a bridge with a confirmed live circuit must not lose to a never-verified
//! one merely because both sit at `circuit_fails == 0`), and finally by
//! descending `ok_count` (more cumulative successful probes first). This
//! mirrors the
//! stability-first ordering `tor_setup.rs` already applies when handing
//! bridges to arti at bootstrap.

use std::cmp::Ordering;
use std::path::{Path, PathBuf};
use std::time::Duration;

use bridge_line::BridgeLine;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::config::{Config, WarmPoolConfig};
use crate::tor_watchdog::TorHandle;
use bridge_store::BridgeStore;

/// Per-candidate health snapshot used to rank bridges for warming. Pulled
/// out of [`BridgeStore`] into a plain struct so the ranking logic
/// ([`select_top_n`]) is unit-testable without any on-disk state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Health {
    /// Consecutive TCP-probe failures per the last probe round. Non-zero
    /// excludes the bridge from the warming pool outright.
    pub tcp_fails: u32,
    /// Consecutive circuit-layer failures observed from arti's tracing.
    /// Lower is better.
    pub circuit_fails: u32,
    /// Count of full end-to-end circuit verifications recorded by the store.
    /// Higher is better.
    pub verified_count: u32,
    /// Cumulative successful-probe count. Higher is better (tie-breaker).
    pub ok_count: u32,
    /// When the bridge's circuit-failure counter was last touched, per the
    /// on-disk store — `None` when the bridge is unknown to the store. Lets
    /// the soft-failover watchdog tell evidence produced by the current
    /// process run from counts inherited from a previous run (see
    /// `BridgeStore::last_circuit_observation`).
    pub cobs: Option<OffsetDateTime>,
}

/// Select up to `n` candidates to warm, given each bridge's current health.
///
/// Pure function: filters out any bridge whose `tcp_fails > 0` (per the
/// last probe round — the same TCP-health condition
/// [`BridgeStore::alive_count`] uses), then sorts the remainder by ascending
/// `circuit_fails` (the primary key: an arti-observed circuit failure is a
/// live negative signal and must keep dominating), then by descending
/// `verified_count` — a circuit-verified bridge must not lose to a
/// never-verified one merely because both sit at `circuit_fails == 0` — and
/// finally by descending `ok_count`. Candidates equal under that rank keep
/// their input order — the tie-break the previous stable sort provided, now
/// made explicit. The selection is a bounded heap over the rank rather than
/// a full sort; `n == 0` returns nothing.
pub(crate) fn select_top_n(candidates: &[(BridgeLine, Health)], n: usize) -> Vec<BridgeLine> {
    let ranked: Vec<RankedCandidate<'_>> = candidates
        .iter()
        .enumerate()
        .filter(|(_, (_, health))| health.tcp_fails == 0)
        .map(|(position, (bridge, health))| RankedCandidate {
            position,
            bridge,
            health,
        })
        .collect();
    take_best(ranked, n)
        .into_iter()
        .map(|candidate| candidate.bridge.clone())
        .collect()
}

/// The warming rank, best first: ascending `circuit_fails` (the primary key:
/// an arti-observed circuit failure is a live negative signal and must keep
/// dominating), then descending `verified_count`, then descending
/// `ok_count`. Unchanged by the top-k rework: only the selection mechanism
/// moved from a full stable sort to a bounded heap.
fn warming_rank(a: &Health, b: &Health) -> Ordering {
    a.circuit_fails
        .cmp(&b.circuit_fails)
        .then_with(|| b.verified_count.cmp(&a.verified_count))
        .then_with(|| b.ok_count.cmp(&a.ok_count))
}

/// One TCP-healthy candidate in [`select_top_n`]'s bounded heap. `Ord` is
/// the warming rank of `warming_rank` with the candidate's original input
/// position as the final tie-breaker — the total order the previous stable
/// sort implemented (candidates equal under the rank kept input order), made
/// explicit so the heap selection reproduces it exactly.
struct RankedCandidate<'a> {
    position: usize,
    bridge: &'a BridgeLine,
    health: &'a Health,
}

impl PartialEq for RankedCandidate<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}
impl Eq for RankedCandidate<'_> {}
impl Ord for RankedCandidate<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        warming_rank(self.health, other.health).then(self.position.cmp(&other.position))
    }
}
impl PartialOrd for RankedCandidate<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// The `limit` best items under the item type's own total `Ord`, ascending —
/// exactly what a stable sort followed by `take(limit)` produced before,
/// given the item's `Ord` breaks ties by the item's original position (as
/// `RankedCandidate` does). Bounded heap instead of a full sort: O(N log
/// limit) comparisons and O(limit) memory rather than O(N log N) / O(N);
/// `limit == 0` and `limit >= N` short-circuit. (Local to this module:
/// `Health` is app-side, so the helper is a deliberate small duplicate of
/// the one in bridge-store's stats module rather than new public API there.)
fn take_best<I: Ord>(items: Vec<I>, limit: usize) -> Vec<I> {
    if limit == 0 {
        return Vec::new();
    }
    if items.len() <= limit {
        let mut items = items;
        items.sort();
        return items;
    }
    let mut kept: std::collections::BinaryHeap<I> =
        std::collections::BinaryHeap::with_capacity(limit);
    for item in items {
        // The heap root is the worst item kept; a strictly better candidate
        // replaces it, so the heap always holds the `limit` best seen so far.
        if kept.len() < limit {
            kept.push(item);
        } else if item < *kept.peek().expect("heap at capacity is non-empty") {
            kept.pop();
            kept.push(item);
        }
    }
    let mut best = kept.into_vec();
    best.sort();
    best
}

/// Read the configured bridges and pair each with its current health from
/// the on-disk store. Best-effort: a bridge with no store entry yet is
/// treated as maximally healthy (all-zero counters) rather than excluded —
/// mirrors `BridgeStore`'s own `map_or(0, ..)` convention for unknown
/// bridges.
///
/// `pub(crate)` so the soft-failover watchdog (`tor_watchdog.rs`) can reuse
/// the exact same candidate-gathering logic this module's own warming loop
/// uses, rather than re-reading `BridgeStore` a second, subtly different
/// way.
pub(crate) fn candidates_with_health(
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
                Some(store) => match store.health_snapshot(&bridge) {
                    Some(snapshot) => Health {
                        tcp_fails: snapshot.tcp_fails,
                        circuit_fails: snapshot.circuit_fails,
                        verified_count: snapshot.verified_count,
                        ok_count: snapshot.ok_count,
                        cobs: snapshot.last_circuit_observation,
                    },
                    None => Health::default(),
                },
                None => Health::default(),
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
///
/// Shutdown: the `token` is selected against before every tick, so no new warm
/// batch starts after cancellation; a `warm_bridge` handshake already in flight
/// runs to completion and its successes are persisted before the caller joins
/// the handle and closes the bridge-store writer.
pub fn spawn_bridge_warmer(
    handle: TorHandle,
    config_path: Option<PathBuf>,
    cfg: WarmPoolConfig,
    token: CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    if !cfg.enabled {
        info!("bridge warm-pool disabled");
        return None;
    }
    if cfg.pool_size == 0 || cfg.refresh_interval_secs == 0 {
        info!("bridge warm-pool disabled (pool_size or refresh_interval_secs is 0)");
        return None;
    }

    let interval = Duration::from_secs(cfg.refresh_interval_secs);
    let pool_size = cfg.pool_size;

    info!(
        pool_size,
        refresh_interval_secs = cfg.refresh_interval_secs,
        "bridge warm-pool armed"
    );

    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await; // consume the immediate first tick

        loop {
            tokio::select! {
                biased;
                _ = token.cancelled() => break,
                _ = ticker.tick() => {},
            }

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

            let active = handle.active_bridges();
            let candidates: Vec<_> = candidates_with_health(&cfg, config_path.as_deref())
                .into_iter()
                .filter(|(bridge, _)| active.contains(bridge))
                .collect();
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
            let mut warmed: Vec<BridgeLine> = Vec::new();
            for bridge in &selected {
                match tor.warm_bridge(bridge).await {
                    Ok(()) => {
                        info!(bridge = %bridge, "warm-pool: channel warmed");
                        warmed.push(bridge.clone());
                    }
                    Err(e) => {
                        warn!(bridge = %bridge, error = %e, "warm-pool: failed to warm channel");
                    }
                }
            }

            // Persist channel-warm successes to the on-disk store (best-effort).
            // Failures are deliberately not recorded: the store has no
            // channel-failure counters by design — `chseen`/`chok` only track
            // successes, because a failed channel warm is not proof a bridge is
            // dead (same convention as android's `persist_warm_results`, which
            // records successes and retirements only).
            if !warmed.is_empty() {
                persist_warm_successes(config_path.as_deref(), warmed).await;
            }
        }
    }))
}

/// Record channel-warm successes through the single writer (best-effort:
/// a load failure is only logged; publish failures are the writer's
/// retry problem).
async fn persist_warm_successes(config_path: Option<&Path>, warmed: Vec<BridgeLine>) {
    let result = crate::bridge_store_writer::apply(config_path, move |store| {
        let now = OffsetDateTime::now_utc();
        for bridge in &warmed {
            store.note_channel_success_at(bridge, now);
        }
    })
    .await;
    if let Err(error) = result {
        warn!(error = %error, "warm-pool: could not record channel-warm successes");
    }
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
        h_verified(tcp_fails, circuit_fails, ok_count, 0)
    }

    fn h_verified(
        tcp_fails: u32,
        circuit_fails: u32,
        ok_count: u32,
        verified_count: u32,
    ) -> Health {
        Health {
            tcp_fails,
            circuit_fails,
            verified_count,
            ok_count,
            cobs: None,
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
    fn verified_bridge_outranks_unverified_at_equal_circuit_fails() {
        // Equal circuit_fails=0: the verified bridge wins even though the
        // unverified one has a much higher ok_count.
        let candidates = vec![
            (bridge(OBFS4_A), h_verified(0, 0, 1, 7)),
            (bridge(OBFS4_B), h(0, 0, 1000)),
        ];
        let selected = select_top_n(&candidates, 2);
        assert_eq!(
            selected,
            vec![bridge(OBFS4_A), bridge(OBFS4_B)],
            "circuit-verified bridge must outrank a never-verified one"
        );
    }

    #[test]
    fn circuit_fails_still_dominates_verification() {
        // A with no verifications still beats B with many, because B has
        // circuit failures and A has none.
        let candidates = vec![
            (bridge(OBFS4_A), h(0, 0, 1)),
            (bridge(OBFS4_B), h_verified(0, 3, 1, 100)),
        ];
        let selected = select_top_n(&candidates, 2);
        assert_eq!(
            selected,
            vec![bridge(OBFS4_A), bridge(OBFS4_B)],
            "circuit_fails must dominate verified_count"
        );
    }

    #[test]
    fn higher_verified_count_ranks_first_among_verified() {
        let candidates = vec![
            (bridge(OBFS4_A), h_verified(0, 0, 0, 2)),
            (bridge(OBFS4_B), h_verified(0, 0, 0, 50)),
            (bridge(OBFS4_C), h_verified(0, 0, 0, 10)),
        ];
        let selected = select_top_n(&candidates, 3);
        assert_eq!(
            selected,
            vec![bridge(OBFS4_B), bridge(OBFS4_C), bridge(OBFS4_A)],
            "higher verified_count ranks first"
        );
    }

    #[test]
    fn tcp_fails_excludes_even_highly_verified_bridge() {
        let candidates = vec![
            (bridge(OBFS4_A), h_verified(1, 0, 100, 500)),
            (bridge(OBFS4_B), h(0, 0, 1)),
        ];
        let selected = select_top_n(&candidates, 2);
        assert_eq!(
            selected,
            vec![bridge(OBFS4_B)],
            "tcp_fails > 0 excludes regardless of verified_count"
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

    /// TS2-06 regression: candidates tied under the warming rank keep their
    /// input order up to n — the tie order the previous stable sort
    /// produced — at n = 0, 1, k < N and k >= N alike.
    #[test]
    fn equal_rank_keeps_input_order_at_every_n() {
        let candidates = vec![
            (bridge(OBFS4_A), h(0, 0, 0)),
            (bridge(OBFS4_B), h(0, 0, 0)),
            (bridge(OBFS4_C), h(0, 0, 0)),
        ];
        assert_eq!(select_top_n(&candidates, 0), Vec::<BridgeLine>::new());
        assert_eq!(select_top_n(&candidates, 1), vec![bridge(OBFS4_A)]);
        assert_eq!(
            select_top_n(&candidates, 2),
            vec![bridge(OBFS4_A), bridge(OBFS4_B)]
        );
        assert_eq!(
            select_top_n(&candidates, 3),
            vec![bridge(OBFS4_A), bridge(OBFS4_B), bridge(OBFS4_C)],
            "k == N"
        );
        assert_eq!(
            select_top_n(&candidates, 10),
            vec![bridge(OBFS4_A), bridge(OBFS4_B), bridge(OBFS4_C)],
            "k >= N"
        );
    }

    /// TS2-06 regression: with mixed ranks and a tie, the selected prefix at
    /// every n is the one the old full stable sort produced (ties keep input
    /// order; here B and C tie fully, so B stays before C).
    #[test]
    fn full_ranked_order_survives_the_heap_selection() {
        let candidates = vec![
            (bridge(OBFS4_A), h(0, 2, 5)),             // circuit failures -> last
            (bridge(OBFS4_B), h_verified(0, 0, 1, 7)), // verified -> first
            (bridge(OBFS4_C), h_verified(0, 0, 1, 7)), // tied with B -> second
        ];
        assert_eq!(
            select_top_n(&candidates, 1),
            vec![bridge(OBFS4_B)],
            "k=1 takes the head of the ranking"
        );
        assert_eq!(
            select_top_n(&candidates, 2),
            vec![bridge(OBFS4_B), bridge(OBFS4_C)]
        );
        assert_eq!(
            select_top_n(&candidates, 3),
            vec![bridge(OBFS4_B), bridge(OBFS4_C), bridge(OBFS4_A)]
        );
    }

    /// TS2-05 regression: `candidates_with_health` must report exactly what
    /// the store's individual getters report — the single-lookup snapshot it
    /// now reads replaced five separate keyed lookups per bridge — and an
    /// unseeded bridge must stay all-zero with `cobs: None`.
    #[test]
    fn candidates_with_health_matches_individual_getters() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("tor-socks5.ktav");
        let mut cfg = Config::default();
        cfg.bridges.lines = vec![OBFS4_A.to_string(), OBFS4_B.to_string()];
        cfg.write(&config_path).expect("write config");

        let seeded = bridge(OBFS4_A);
        let t0 = OffsetDateTime::from_unix_timestamp(1_000_000).unwrap();
        let mut store = BridgeStore::load(BridgeStore::resolve_path(Some(config_path.as_path())))
            .expect("load fresh store");
        store.note_probe_round(
            std::slice::from_ref(&seeded),
            &[(seeded.clone(), Duration::from_millis(7))],
            t0,
            Duration::from_secs(3600),
            10,
            10,
        );
        store.note_probe_round(
            std::slice::from_ref(&seeded),
            &[(seeded.clone(), Duration::from_millis(11))],
            t0 + Duration::from_secs(60),
            Duration::from_secs(3600),
            10,
            10,
        );
        store.note_channel_success_at(&seeded, t0 + Duration::from_secs(60));
        store.note_circuit_verified_at(&seeded, t0 + Duration::from_secs(60));
        store.note_circuit_failure_at(
            &seeded,
            t0 + Duration::from_secs(120),
            Duration::from_secs(60),
        );
        store.save().expect("seed save");

        let candidates = candidates_with_health(&cfg, Some(config_path.as_path()));
        assert_eq!(candidates.len(), 2, "both configured bridges are listed");

        let reloaded = BridgeStore::load(BridgeStore::resolve_path(Some(config_path.as_path())))
            .expect("reload store");
        for (b, health) in &candidates {
            assert_eq!(health.tcp_fails, reloaded.tcp_fails(b), "tcp_fails for {b}");
            assert_eq!(
                health.circuit_fails,
                reloaded.circuit_fails(b),
                "circuit_fails for {b}"
            );
            assert_eq!(
                health.verified_count,
                reloaded.verified_count(b),
                "verified_count for {b}"
            );
            assert_eq!(health.ok_count, reloaded.ok_count(b), "ok_count for {b}");
            assert_eq!(
                health.cobs,
                reloaded.last_circuit_observation(b),
                "cobs for {b}"
            );
        }

        // The seeded entry really carries non-trivial values (so the
        // per-field comparisons above are not vacuous zero == zero checks).
        let first = &candidates[0].1;
        assert_eq!(first.ok_count, 2);
        assert_eq!(first.verified_count, 1);
        assert_eq!(first.circuit_fails, 1);
        assert_eq!(first.tcp_fails, 0);
        assert!(first.cobs.is_some());
        // OBFS4_B is configured but never seeded: maximally healthy defaults.
        assert_eq!(
            candidates[1].1,
            Health {
                tcp_fails: 0,
                circuit_fails: 0,
                verified_count: 0,
                ok_count: 0,
                cobs: None,
            }
        );
    }

    /// Routing proof: 16 concurrent recorders must all land (16 = count),
    /// which only the single-writer path can guarantee — racing inline
    /// load→mutate→save cycles would lose updates.
    #[tokio::test]
    async fn warm_successes_are_recorded_through_the_single_writer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("tor-socks5.ktav");
        let warmed_bridge = bridge(OBFS4_A);

        // Seed the store BEFORE initializing the global writer.
        let mut store = BridgeStore::load(BridgeStore::resolve_path(Some(config_path.as_path())))
            .expect("fresh store loads");
        store.note_source_at(&warmed_bridge, "test", OffsetDateTime::now_utc());
        store.save().expect("seed save");

        let _writer = crate::bridge_store_writer::init_global(Some(config_path.as_path()));

        let mut tasks = Vec::new();
        for _ in 0..16 {
            let config_path = config_path.clone();
            let warmed = warmed_bridge.clone();
            tasks.push(tokio::spawn(async move {
                persist_warm_successes(Some(config_path.as_path()), vec![warmed]).await;
            }));
        }
        for task in tasks {
            task.await.expect("task joins");
        }

        // apply() acks as soon as a mutation is absorbed in memory, before
        // the writer's (now offloaded, coalesced) disk publish runs — so the
        // 16th ack landing does not mean the 16th write has hit disk yet.
        // Poll for it, yielding every iteration so the writer's actor task
        // (on this single-threaded test runtime) actually gets to run.
        let mut count = 0;
        for _ in 0..5000 {
            count = BridgeStore::load(BridgeStore::resolve_path(Some(config_path.as_path())))
                .expect("reload store")
                .channel_ok_count(&warmed_bridge);
            if count == 16 {
                break;
            }
            tokio::task::yield_now().await;
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(count, 16, "no lost update through the single writer");
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read tempdir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "tmp"))
            .collect();
        assert!(leftovers.is_empty(), "no leftover temp files");
    }
}
