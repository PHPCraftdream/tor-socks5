use super::{resolve_and_probe, Outcome, Report};
use crate::ResolverPolicy;
use bridge_line::BridgeLine;
use futures::stream::{self, StreamExt};
use std::time::Duration;

/// Cap on simultaneous in-flight TCP probes — absorbs a large fetched
/// bridge list without exhausting the per-process file-descriptor budget.
pub(crate) const MAX_INFLIGHT_PROBES: usize = 64;

/// Probe every bridge in `bridges` concurrently. Each probe is bounded by
/// `per_bridge_timeout`. At most [`MAX_INFLIGHT_PROBES`] probes are in
/// flight at any time. The returned vector is **not** guaranteed to
/// preserve input order.
pub async fn probe_all(bridges: Vec<BridgeLine>, per_bridge_timeout: Duration) -> Vec<Report> {
    probe_all_with_policy(bridges, per_bridge_timeout, ResolverPolicy::default()).await
}

pub async fn probe_all_with_policy(
    bridges: Vec<BridgeLine>,
    per_bridge_timeout: Duration,
    resolver_policy: ResolverPolicy,
) -> Vec<Report> {
    stream::iter(bridges)
        .map(|bridge| async move {
            let outcome = resolve_and_probe(&bridge, per_bridge_timeout, resolver_policy).await;
            Report { bridge, outcome }
        })
        .buffer_unordered(MAX_INFLIGHT_PROBES)
        .collect()
        .await
}

/// Convenience helper: probe, log a summary, and return only reachable
/// bridges as `(bridge, latency)` pairs sorted by ascending latency
/// (fastest first). When no bridge responds, returns an empty vector —
/// callers decide what to do.
pub async fn probe_and_sort(
    bridges: Vec<BridgeLine>,
    per_bridge_timeout: Duration,
) -> Vec<(BridgeLine, Duration)> {
    probe_and_sort_with_policy(bridges, per_bridge_timeout, ResolverPolicy::default()).await
}

pub async fn probe_and_sort_with_policy(
    bridges: Vec<BridgeLine>,
    per_bridge_timeout: Duration,
    resolver_policy: ResolverPolicy,
) -> Vec<(BridgeLine, Duration)> {
    probe_round_with_policy(bridges, per_bridge_timeout, resolver_policy)
        .await
        .alive
}

/// What one probe round established, split by whether it established anything.
///
/// Callers that persist results need both halves: recording only the live
/// bridges and treating every other input as dead is what turned a struggling
/// resolver into a pile of false failures.
#[derive(Debug, Clone, Default)]
pub struct ProbeRound {
    /// Reachable bridges, fastest first.
    pub alive: Vec<(BridgeLine, Duration)>,
    /// Bridges the round could not test at all. Not evidence of anything —
    /// leave their health record untouched.
    pub unmeasured: Vec<BridgeLine>,
}

/// Probe `bridges`, log a summary, and report both the live ones and the ones
/// that were never actually tested.
pub async fn probe_round_with_policy(
    bridges: Vec<BridgeLine>,
    per_bridge_timeout: Duration,
    resolver_policy: ResolverPolicy,
) -> ProbeRound {
    let reports = probe_all_with_policy(bridges, per_bridge_timeout, resolver_policy).await;
    summarise(&reports);

    let mut round = ProbeRound::default();
    for report in reports {
        match report.outcome {
            Outcome::Reachable { latency } => round.alive.push((report.bridge, latency)),
            Outcome::Unmeasured { .. } => round.unmeasured.push(report.bridge),
            Outcome::Unreachable { .. } => {}
        }
    }

    round.alive.sort_by_key(|(_, latency)| *latency);
    round
}

/// Probe a single bridge: `Some(latency)` if its (transport-resolved) TCP
/// target answers within `per_bridge_timeout`, `None` otherwise. The lazy
/// pool-drainer uses this to walk candidates one at a time while deciding,
/// per bridge, whether to promote (alive) or discard (dead).
pub async fn probe_one(bridge: &BridgeLine, per_bridge_timeout: Duration) -> Option<Duration> {
    probe_one_with_policy(bridge, per_bridge_timeout, ResolverPolicy::default()).await
}

pub async fn probe_one_with_policy(
    bridge: &BridgeLine,
    per_bridge_timeout: Duration,
    resolver_policy: ResolverPolicy,
) -> Option<Duration> {
    match resolve_and_probe(bridge, per_bridge_timeout, resolver_policy).await {
        Outcome::Reachable { latency } => Some(latency),
        Outcome::Unreachable { .. } | Outcome::Unmeasured { .. } => None,
    }
}

/// Probe `bridges` **sequentially** — one at a time, no concurrent burst —
/// and return the live ones, stopping as soon as `target` live bridges are
/// found or `max_attempts` probes have been made (whichever comes first).
/// Live results are returned in the order they were found.
///
/// This is the *lazy* counterpart to [`probe_and_sort`]: when topping up
/// from a large fetched list (thousands of candidates), hammering the whole
/// list at once would be a network flood. Instead we walk the candidates
/// one by one and bail out the moment we have enough — typically after only
/// a handful of probes, since live bridges are common near the top of a
/// fresh list. `max_attempts` bounds the worst case when few are alive.
pub async fn probe_until(
    bridges: Vec<BridgeLine>,
    per_bridge_timeout: Duration,
    target: usize,
    max_attempts: usize,
) -> Vec<(BridgeLine, Duration)> {
    probe_until_with_policy(
        bridges,
        per_bridge_timeout,
        target,
        max_attempts,
        ResolverPolicy::default(),
    )
    .await
}

pub async fn probe_until_with_policy(
    bridges: Vec<BridgeLine>,
    per_bridge_timeout: Duration,
    target: usize,
    max_attempts: usize,
    resolver_policy: ResolverPolicy,
) -> Vec<(BridgeLine, Duration)> {
    let mut live: Vec<(BridgeLine, Duration)> = Vec::new();
    if target == 0 {
        return live;
    }
    let mut attempts = 0usize;
    let mut dead = 0usize;
    for bridge in bridges {
        if live.len() >= target || attempts >= max_attempts {
            break;
        }
        attempts += 1;
        match resolve_and_probe(&bridge, per_bridge_timeout, resolver_policy).await {
            Outcome::Reachable { latency } => {
                tracing::debug!(
                    addr = %bridge.addr,
                    transport = ?bridge.transport,
                    latency_ms = latency.as_millis() as u64,
                    "bridge reachable (lazy probe)"
                );
                live.push((bridge, latency));
            }
            Outcome::Unreachable { reason } => {
                dead += 1;
                tracing::trace!(addr = %bridge.addr, reason = %reason, "bridge unreachable (lazy probe)");
            }
            Outcome::Unmeasured { reason } => {
                tracing::trace!(addr = %bridge.addr, reason = %reason, "bridge not measured (lazy probe)");
            }
        }
    }
    tracing::info!(
        found = live.len(),
        target,
        attempts,
        dead,
        "lazy bridge probe done"
    );
    live
}

pub(crate) fn summarise(reports: &[Report]) {
    let total = reports.len();
    let alive = reports.iter().filter(|r| r.is_reachable()).count();
    let unmeasured = reports.iter().filter(|r| r.is_unmeasured()).count();
    tracing::info!(
        total,
        alive,
        dead = total - alive - unmeasured,
        unmeasured,
        "bridge reachability probe done"
    );
    for r in reports {
        match &r.outcome {
            Outcome::Reachable { latency } => tracing::info!(
                addr = %r.bridge.addr,
                transport = ?r.bridge.transport,
                latency_ms = latency.as_millis() as u64,
                "bridge reachable"
            ),
            Outcome::Unreachable { reason } => tracing::warn!(
                addr = %r.bridge.addr,
                transport = ?r.bridge.transport,
                reason = %reason,
                "bridge unreachable"
            ),
            Outcome::Unmeasured { reason } => tracing::warn!(
                addr = %r.bridge.addr,
                transport = ?r.bridge.transport,
                reason = %reason,
                "bridge not measured; leaving its health record alone"
            ),
        }
    }
}
