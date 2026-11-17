//! Health snapshot and ranking of the configured bridges.
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
//!
//! A leaf module: the warming pool (`bridge_warmer`) and the soft-failover
//! watchdog (`tor_watchdog`) both rank through it, so neither depends on the
//! other.

use std::cmp::Ordering;

use bridge_line::BridgeLine;
use time::OffsetDateTime;
use tracing::warn;

use crate::config::Config;
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
            warn!(error = %e, "config has invalid bridges");
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
            warn!(error = %e, "could not load bridge health store");
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

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
}
