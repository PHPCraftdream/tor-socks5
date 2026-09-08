use super::*;

/// Budget for the post-termination usability check: how long [`heal`] waits
/// for the live client to actually carry traffic again after
/// `terminate_all_channels`, before giving up on this tick and letting the
/// cooldown/backoff machinery gate the next attempt.
pub(super) const VERIFY_TIMEOUT: Duration = Duration::from_secs(90);

/// Minimum number of `TorTunnel::connect` attempts observed within a single
/// tick before "attempts are still coming" (trigger condition 2) is treated
/// as a real signal rather than noise. The incident analyzed in
/// docs/upstream/guard-exhaustion-watchdog-spiral.md fired a rebuild on just
/// 8 attempts over 218 s — already a weak sample to decide "this looks like
/// a stale-channel problem" from. `1` (the previous implicit threshold, since
/// the old check was only `== 0`) lets a single stray retry arm the rebuild
/// decision; this raises the bar slightly without meaningfully delaying a
/// real, live-traffic-driven trigger — a genuinely stale channel under
/// actual use produces many attempts per tick, not one or two.
pub(super) const MIN_ATTEMPTS_TO_TRIGGER: u64 = 3;

/// Once this many heal attempts (terminate-then-reconnect) fail in a row
/// (terminate error, or the client still doesn't reconnect within
/// [`VERIFY_TIMEOUT`]), the watchdog backs off to
/// [`EXTENDED_REBUILD_COOLDOWN`] instead of the configured
/// `rebuild_cooldown_secs`: a persistently blocked network does not merit
/// retrying every few minutes. Field/constant names still say "rebuild" —
/// that's the configured `[watchdog]` key (`rebuild_cooldown_secs`) this
/// mirrors, kept stable across the rebuild-slot → in-place-heal switch so
/// existing config files do not need to change.
pub(super) const CONSECUTIVE_FAILURES_BEFORE_BACKOFF: u32 = 3;

/// Fixed cooldown applied once [`CONSECUTIVE_FAILURES_BEFORE_BACKOFF`] is
/// reached. Deliberately not derived from config: 30 min is "leave it
/// alone for a while", independent of how aggressive the normal cooldown is.
pub(super) const EXTENDED_REBUILD_COOLDOWN: Duration = Duration::from_secs(30 * 60);

/// How many consecutive ticks must pass with all three trigger conditions
/// (stale success, fresh attempts, alive bridges) satisfied but the
/// signature gate ([`should_decline_rebuild`]) declining, before the gate
/// is overridden and the heal proceeds despite the declined signature.
/// Two ticks at the default `check_interval_secs = 45` is ~90+ seconds of
/// *proven* total outage: attempts kept coming, bridges were alive, and no
/// circuit succeeded — the exact production signature (7 consecutive
/// declined ticks at `established=0`, docs/plans/2026-08-28-stability-plan.md
/// §1) the gate was never meant to block forever. The July incident's
/// 8-attempts-in-218s trigger cannot reach this: it fails
/// [`MIN_ATTEMPTS_TO_TRIGGER`] on a single tick, let alone two in a row.
pub(super) const GATED_TICKS_BEFORE_OVERRIDE: u32 = 2;

/// Cooldown that will gate the *next* heal attempt after `consecutive_failures`
/// failed attempts. Pure helper so the loop's failure branches log the
/// cooldown that will actually apply, without duplicating the threshold.
pub(super) fn next_cooldown(consecutive_failures: u32, normal: Duration) -> Duration {
    if consecutive_failures >= CONSECUTIVE_FAILURES_BEFORE_BACKOFF {
        EXTENDED_REBUILD_COOLDOWN
    } else {
        normal
    }
}

/// Signature gate on top of the three existing trigger conditions (stale
/// success, fresh attempts, alive bridges) — see
/// docs/upstream/guard-exhaustion-watchdog-spiral.md §3.A/§4.2 for the full
/// analysis this implements.
///
/// A rebuild only replaces *channels*; it cannot fix a class of failure that
/// has nothing to do with stale channels. Two of the three classified
/// `TorTunnel::connect` failure kinds are exactly that:
/// - `RemoteNetworkTimeout`: the circuit reached the exit and the exit went
///   silent. The Tor stack (guards, circuits, channels) is healthy — this is
///   the far side's problem, and a rebuild changes nothing about it.
/// - `TorAccessFailed`: guards are down or unsuitable (e.g. bridge
///   descriptors missing). A rebuild lands in a *cold* slot whose guard
///   state starts from scratch — it reproduces this exact condition rather
///   than curing it (this is the mechanism behind the 12-minute outage
///   analyzed in the spiral doc: rebuild swapped a live, merely degraded
///   client for one that was guaranteed-broken for minutes).
///
/// Only `TorNetworkTimeout` (genuine circuit-build timeouts) is the
/// "zombie channel after a network change" signature the watchdog exists to
/// fix — fresh channels from a rebuild can plausibly resolve it.
///
/// Decision rule: decline (return `true`) when `net_timeout` is not the
/// strict maximum of the three deltas *and* at least one of the other two
/// is non-zero. This lets a `net_timeout`-dominated window (or a tie broken
/// in its favor) through unconditionally, while a window dominated by
/// `remote_timeout`/`access_failed` — including the incident's 8-for-8
/// `RemoteNetworkTimeout` case — is declined. When all three deltas are
/// zero (the failures came from some other, unclassified path, or there
/// were no `TorTunnel::connect` failures at all this tick) the function
/// returns `false`: no data means "behave as before", not "assume the
/// worst".
pub(super) fn should_decline_rebuild(
    new_remote_timeout: u64,
    new_access_failed: u64,
    new_net_timeout: u64,
) -> bool {
    if new_remote_timeout == 0 && new_access_failed == 0 && new_net_timeout == 0 {
        return false;
    }
    let net_is_strict_max =
        new_net_timeout > new_remote_timeout && new_net_timeout > new_access_failed;
    !net_is_strict_max && (new_remote_timeout > 0 || new_access_failed > 0)
}

/// Whether enough consecutive gate-declined ticks have accumulated to
/// override the signature gate (see [`GATED_TICKS_BEFORE_OVERRIDE`] and
/// `step_gated_ticks`). The counter counts ticks in a row where the gate
/// DECLINED while trigger conditions 1-3 held; it is reset only by a
/// successful `TorTunnel::connect` (`reset_gated_ticks_on_success`) or by
/// an actually-performed heal of any outcome. Pure: no side effects.
pub(super) fn should_override_decline(gated_ticks: u32) -> bool {
    gated_ticks >= GATED_TICKS_BEFORE_OVERRIDE
}

/// Advance the gate-escalation counter for one tick: a declined gate
/// increments the consecutive-declined-ticks counter; a tick where the
/// gate passes neither increments nor resets it (the counter simply stays
/// put and keeps counting from where it was on the next declined tick).
pub(super) fn step_gated_ticks(gated_ticks: u32, gate_declined: bool) -> u32 {
    if gate_declined {
        gated_ticks.saturating_add(1)
    } else {
        gated_ticks
    }
}

/// Reset the gate-escalation counter when a successful `TorTunnel::connect`
/// happened since the previous tick (`last_success` moved) — the outage was
/// demonstrably interrupted, so the escalation restarts from zero. A tick
/// without a new success leaves the counter untouched.
pub(super) fn reset_gated_ticks_on_success(gated_ticks: u32, success_since_prev_tick: bool) -> u32 {
    if success_since_prev_tick {
        0
    } else {
        gated_ticks
    }
}

/// Decide whether the current bridge's circuit-layer health has degraded
/// enough — relative to the healthiest configured alternative — that arti's
/// guard manager should be nudged away from it.
///
/// This is the predicate behind the soft-failover watchdog (see
/// [`spawn_bridge_failover_watchdog`]): unlike [`should_decline_rebuild`],
/// which gates a channel *reset* against the same guards, this gates a
/// signal that actively pushes arti toward a *different* bridge — a much
/// more consequential action, so the bar is deliberately two-part:
///
/// 1. `current_circuit_fails >= threshold` — the current bridge must have
///    crossed an absolute degradation threshold on its own. A single stray
///    failure (or even two) must not arm this; `threshold` is the same
///    "how many consecutive circuit-layer failures constitute real
///    degradation" judgment `bridges.max_circuit_fails` already makes for
///    outright pruning, just set lower (see `WatchdogConfig::
///    failover_min_circuit_fails`'s doc comment for why a lower bar is
///    appropriate here).
/// 2. `current_circuit_fails - best_alternative_circuit_fails >= min_margin`
///    — the *best available alternative* must be meaningfully healthier,
///    not just "not worse". Without this, two bridges with near-identical,
///    both-mediocre health would ping-pong a signal back and forth every
///    tick as their counters see-saw by one.
///
/// Both conditions must hold; either one failing declines to signal.
/// Saturating subtraction: if the alternative is not actually healthier
/// (`best_alternative_circuit_fails >= current_circuit_fails`), the
/// subtraction saturates to `0`, which is `< min_margin` for any
/// `min_margin > 0` — so "alternative is not better than current" always
/// declines, without a separate comparison needed.
pub(super) fn should_signal_failover(
    current_circuit_fails: u32,
    best_alternative_circuit_fails: u32,
    threshold: u32,
    min_margin: u32,
) -> bool {
    if current_circuit_fails < threshold {
        return false;
    }
    let margin = current_circuit_fails.saturating_sub(best_alternative_circuit_fails);
    margin >= min_margin
}

/// Maximum number of guard-failure signals this process will send for any
/// single bridge over its entire lifetime. Production showed the
/// failover task signalling the same ~10 bridges every ~5 minutes for a
/// whole run (7-12 signals each) with no rehabilitation path — a bridge
/// pushed out of rotation cannot reset its `circuit_fails` (reset only
/// happens on a successful circuit), so after cooldown expiry it gets
/// signalled again forever. The budget turns that metronome into a rare
/// correction: either the bridge recovers via Phase 2 verification /
/// pruning, or arti handles it, or we stop punishing it (see
/// docs/plans/2026-08-28-stability-plan.md §1b, principle "every actuator
/// gets a budget and backoff").
pub(super) const MAX_SIGNALS_PER_BRIDGE: u32 = 3;

/// Per-bridge failover-signal bookkeeping, keyed by the bridge's canonical
/// string form (the same key `last_signalled` used before this became a
/// struct).
#[derive(Default)]
pub(super) struct SignalRecord {
    /// When this bridge was last successfully signalled, for the
    /// per-bridge cooldown. `None` = never signalled.
    pub(super) last: Option<Instant>,
    /// How many signals were successfully sent for this bridge so far.
    /// Budget: never exceeds [`MAX_SIGNALS_PER_BRIDGE`].
    pub(super) count: u32,
    /// Whether the one-time "giving up on signalling" INFO has already
    /// been logged for this bridge — without the flag the budget
    /// exhaustion would either stay silent forever or re-log every tick.
    pub(super) exhausted_logged: bool,
}

/// Whether a bridge's circuit-layer evidence was produced by the CURRENT
/// process run: the observation must exist and be strictly newer than the
/// moment the failover task started. Evidence inherited from a previous
/// run (the store can be days old — production fired its first signal
/// volley 45 seconds after boot on `cobs` from three days earlier) must
/// not arm a guard-failure signal against a freshly bootstrapped client.
/// `None` (bridge unknown to the store, or a legacy store line without a
/// `cobs=` timestamp, which parses as the Unix epoch) compares as stale.
pub(super) fn evidence_is_fresh(cobs: Option<OffsetDateTime>, task_start: OffsetDateTime) -> bool {
    cobs.is_some_and(|cobs| cobs > task_start)
}

/// Whether the per-bridge signal budget still has room for one more
/// signal.
pub(super) fn signal_budget_available(signals_sent: u32) -> bool {
    signals_sent < MAX_SIGNALS_PER_BRIDGE
}

/// Spawn the soft-failover watchdog as a detached tokio task.
///
/// There is no public arti API to ask "which bridge is currently the
/// primary guard" (an architectural limitation of `arti-client`/
/// `tor-guardmgr` 0.43, not something this task works around) — so instead
/// this treats **every configured bridge's own circuit-layer health**
/// (already tracked in [`BridgeStore`] via the same observation pipeline
/// `bridge_warmer.rs` ranks candidates with) as the proxy signal: a bridge
/// that is actually carrying — and failing — traffic accumulates
/// `circuit_fails` through the existing `GuardObservabilityLayer` pipeline
/// (see `arti_observability.rs`), rate-limited to one bump per
/// `bridges.circuit_observation_window_mins` the same way pruning already
/// is.
///
/// Every `check_interval` the task re-reads the configured bridges and
/// their health, and for each bridge whose `circuit_fails` has crossed
/// [`WatchdogConfig::failover_min_circuit_fails`] checks
/// [`should_signal_failover`] against the healthiest remaining alternative
/// (via [`crate::bridge_warmer::select_top_n`]'s ranking, excluding the
/// degraded bridge itself). When it returns `true`, calls
/// [`arti_wrapper::TorTunnel::signal_bridge_failure`] for the degraded
/// bridge — arti's own prop271 guard-state machine decides what to do next
/// (there is no swap performed here). A per-bridge cooldown
/// (`failover_signal_cooldown_secs`) prevents re-signalling the same bridge
/// every tick while it hovers at/above the threshold.
///
/// Two further constraints bound the signaler (see
/// docs/plans/2026-08-28-stability-plan.md §1b):
/// - **Freshness**: a signal is only armed when the bridge's circuit-layer
///   evidence (`Health::cobs`) is strictly newer than this task's start —
///   observations inherited from a previous run must not push a guard
///   decision against a freshly bootstrapped client (see
///   `evidence_is_fresh`).
/// - **Budget**: at most [`MAX_SIGNALS_PER_BRIDGE`] signals per bridge per
///   process; once exhausted, a one-time INFO is logged and the bridge is
///   never signalled again by this task.
///
/// A `check_interval_secs == 0` (or `enabled == false`) config disables
/// this the same way it disables [`spawn_tor_watchdog`] — the two share one
/// `[watchdog]` config section and one interval, since both read the same
/// health data on the same cadence.
pub fn spawn_bridge_failover_watchdog(
    handle: TorHandle,
    config_path: Option<PathBuf>,
    cfg: WatchdogConfig,
) {
    if !cfg.enabled || cfg.check_interval_secs == 0 {
        info!("bridge soft-failover watchdog disabled");
        return;
    }

    let interval = Duration::from_secs(cfg.check_interval_secs);
    let signal_cooldown = Duration::from_secs(cfg.failover_signal_cooldown_secs);

    info!(
        check_secs = cfg.check_interval_secs,
        min_circuit_fails = cfg.failover_min_circuit_fails,
        min_margin = cfg.failover_min_margin,
        signal_cooldown_secs = cfg.failover_signal_cooldown_secs,
        "bridge soft-failover watchdog armed"
    );

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await; // consume the immediate first tick

        // Per-bridge last-signalled time and signal budget, keyed by the
        // bridge's canonical string form (`BridgeLine` has no `Eq`/`Hash`
        // impl of its own). Rate-limits re-signalling the same degraded
        // bridge every tick — mirrors `rebuild_cooldown_secs`'s role for
        // channel termination — and caps the total signals per bridge for
        // the process's whole lifetime (see [`SignalRecord`]).
        let mut signalled: HashMap<String, SignalRecord> = HashMap::new();

        // Freshness anchor: circuit-layer observations older than this moment
        // are inherited from a previous run and never arm a signal (see
        // `evidence_is_fresh`).
        let task_start = OffsetDateTime::now_utc();

        loop {
            ticker.tick().await;

            let Some(tor) = handle.tunnel().await else {
                // Slot drained (shutdown in progress) — nothing to signal.
                continue;
            };

            let cfg = match Config::load_with_override(config_path.as_deref()) {
                Ok(loaded) => loaded.into_config(),
                Err(e) => {
                    warn!(error = %e, "soft-failover: could not reload config");
                    continue;
                }
            };

            let active = handle.active_bridges();
            let candidates: Vec<_> = candidates_with_health(&cfg, config_path.as_deref())
                .into_iter()
                .filter(|(bridge, _)| active.contains(bridge))
                .collect();
            if candidates.len() < 2 {
                // Need at least one degraded bridge and one alternative.
                continue;
            }

            for (idx, (bridge, health)) in candidates.iter().enumerate() {
                if health.circuit_fails < cfg.watchdog.failover_min_circuit_fails {
                    continue;
                }

                if !evidence_is_fresh(health.cobs, task_start) {
                    debug!(
                        bridge = %bridge,
                        "soft-failover: circuit-failure evidence predates this process — \
                         ignoring stale evidence"
                    );
                    continue;
                }

                let alternatives: Vec<(BridgeLine, Health)> = candidates
                    .iter()
                    .enumerate()
                    .filter(|(other_idx, _)| *other_idx != idx)
                    .map(|(_, c)| c.clone())
                    .collect();
                let Some(best) = healthiest(&alternatives) else {
                    continue;
                };

                if !should_signal_failover(
                    health.circuit_fails,
                    best.circuit_fails,
                    cfg.watchdog.failover_min_circuit_fails,
                    cfg.watchdog.failover_min_margin,
                ) {
                    continue;
                }

                let record = signalled.entry(bridge.to_string()).or_default();
                if let Some(last) = record.last {
                    if last.elapsed() < signal_cooldown {
                        continue;
                    }
                }
                if !signal_budget_available(record.count) {
                    if !record.exhausted_logged {
                        info!(
                            bridge = %bridge,
                            signals_sent = record.count,
                            "soft-failover: giving up on signalling this bridge — \
                             per-bridge signal budget exhausted"
                        );
                        record.exhausted_logged = true;
                    }
                    continue;
                }

                warn!(
                    bridge = %bridge,
                    circuit_fails = health.circuit_fails,
                    best_alternative_circuit_fails = best.circuit_fails,
                    "bridge health degraded relative to a healthier alternative — \
                     signalling guard failure to arti"
                );
                match tor.signal_bridge_failure(bridge, arti_wrapper::ExternalActivity::DirCache) {
                    Ok(()) => {
                        record.last = Some(Instant::now());
                        record.count += 1;
                    }
                    Err(e) => {
                        warn!(bridge = %bridge, error = %e, "soft-failover: failed to signal guard failure");
                    }
                }
            }
        }
    });
}

/// The healthiest single candidate among `candidates`, per the same
/// ranking [`crate::bridge_warmer::select_top_n`] uses (TCP-unreachable
/// bridges excluded, then ascending `circuit_fails`, ties broken by
/// descending `ok_count`). Returns the winning [`Health`] only — the
/// soft-failover check only needs the alternative's health, not its
/// identity.
pub(super) fn healthiest(candidates: &[(BridgeLine, Health)]) -> Option<Health> {
    crate::bridge_warmer::select_top_n(candidates, 1)
        .into_iter()
        .next()
        .and_then(|winner| {
            candidates
                .iter()
                .find(|(b, _)| b.to_string() == winner.to_string())
                .map(|(_, h)| *h)
        })
}

/// Spawn the stale-channel watchdog as a detached tokio task.
///
/// Every `check_interval` the task evaluates four trigger conditions (stale
/// success, fresh attempts, alive bridges, and a failure-signature gate —
/// see [`should_decline_rebuild`]) and, if all hold and the cooldown has
/// elapsed, calls [`heal`] to terminate the live client's channels in place
/// and verify it reconnects. A `check_interval_secs == 0` (or
/// `enabled == false`) config disables it.
///
/// Mirrors the shape of `spawn_bridge_maintenance` so the two background
/// loops share a house style (detached, gentle, interval-based, logs-only
/// on failure).
pub fn spawn_tor_watchdog(handle: TorHandle, config_path: Option<PathBuf>, cfg: WatchdogConfig) {
    if !cfg.enabled || cfg.check_interval_secs == 0 {
        info!("tor stale-channel watchdog disabled");
        return;
    }

    let interval = Duration::from_secs(cfg.check_interval_secs);
    let stale = Duration::from_secs(cfg.stale_after_secs);
    let cooldown = Duration::from_secs(cfg.rebuild_cooldown_secs);
    let started_secs = unix_secs();

    info!(
        check_secs = cfg.check_interval_secs,
        stale_secs = cfg.stale_after_secs,
        cooldown_secs = cfg.rebuild_cooldown_secs,
        "tor stale-channel watchdog armed"
    );

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await; // consume the immediate first tick

        let mut prev_attempts = handle.health().attempt_count();
        let mut prev_last_success = handle.health().last_success_secs();
        // Consecutive ticks during which conditions 1-3 held but the signature
        // gate declined the heal (see `step_gated_ticks` /
        // `should_override_decline`). Reset by any success or any performed heal.
        let mut gated_ticks: u32 = 0;
        // Baselines for the signature gate (see `should_decline_rebuild`):
        // same delta-between-ticks convention as `prev_attempts` above, one
        // per classified failure kind.
        let mut prev_remote_timeout = handle.health().remote_timeout_count();
        let mut prev_access_failed = handle.health().access_failed_count();
        let mut prev_net_timeout = handle.health().net_timeout_count();
        let mut last_rebuild: Option<Instant> = None;
        // Consecutive failed heal attempts (post-termination reconnect
        // verification timed out or never succeeded). Once it crosses
        // [`CONSECUTIVE_FAILURES_BEFORE_BACKOFF`] the cooldown stretches to
        // [`EXTENDED_REBUILD_COOLDOWN`] so a fully-blocked network is not
        // hammered. Reset to 0 on the first successful heal.
        let mut consecutive_failures: u32 = 0;

        loop {
            ticker.tick().await;

            let health = handle.health();
            let now_secs = unix_secs();
            let last_success = health.last_success_secs();
            // Any successful connect since the previous tick restarts the gate
            // escalation — even if this tick exits early below, the outage was
            // demonstrably interrupted.
            gated_ticks =
                reset_gated_ticks_on_success(gated_ticks, last_success != prev_last_success);
            prev_last_success = last_success;
            let attempts = health.attempt_count();
            let new_attempts = attempts.saturating_sub(prev_attempts);
            prev_attempts = attempts;

            let remote_timeout = health.remote_timeout_count();
            let new_remote_timeout = remote_timeout.saturating_sub(prev_remote_timeout);
            prev_remote_timeout = remote_timeout;

            let access_failed = health.access_failed_count();
            let new_access_failed = access_failed.saturating_sub(prev_access_failed);
            prev_access_failed = access_failed;

            let net_timeout = health.net_timeout_count();
            let new_net_timeout = net_timeout.saturating_sub(prev_net_timeout);
            prev_net_timeout = net_timeout;

            // Anchor the stale window on the last success, or — before the
            // first one — on the watchdog start. This both gives the freshly
            // bootstrapped client a warm-up grace period and covers the
            // "bootstrap ok, network changed, first connect fails" case,
            // where `last_success` is still 0.
            let anchor = if last_success != 0 {
                last_success
            } else {
                started_secs
            };
            let since_anchor = now_secs.saturating_sub(anchor);

            // Condition 1: no successful circuit within the stale window.
            if Duration::from_secs(since_anchor) < stale {
                continue;
            }
            // Condition 2: attempts were made in this tick — silence here
            // means "no traffic", not "circuits failing". Requires at least
            // MIN_ATTEMPTS_TO_TRIGGER rather than just "> 0" — see that
            // constant's doc comment for why 3 and not 0/1.
            if new_attempts < MIN_ATTEMPTS_TO_TRIGGER {
                continue;
            }
            // Condition 3: at least one bridge is proven reachable per the last
            // probe round (answered a probe, no failure since, not retired), so
            // this is a circuit/channel problem, not the bridge-maintenance
            // loop's "bridges are genuinely down" case.
            let alive = live_bridge_count(config_path.as_deref());
            if alive == 0 {
                continue;
            }
            // Condition 4 (signature gate): the first three conditions only
            // tell us "circuits are failing while attempts and bridges are
            // both fine" — they cannot tell a stale channel from a healthy
            // stack whose exits or guards are simply having a bad time.
            // Terminating channels only forces a reconnect; if the failures
            // this window are dominated by `RemoteNetworkTimeout` (exit went
            // silent, Tor stack is fine) or `TorAccessFailed` (guards down/
            // unsuitable), a reconnect over the same guards changes nothing.
            // See `should_decline_rebuild`'s doc comment for the exact rule
            // and docs/upstream/guard-exhaustion-watchdog-spiral.md §3.A/§4.2
            // for the incident this closes (8 attempts in 218 s, all
            // RemoteNetworkTimeout/ExitTimeout to one Telegram DC).
            //
            // Declining here is a deliberate non-attempt, not a failed one:
            // `last_rebuild`/`consecutive_failures` are left untouched so
            // the cooldown timer does not arm and a legitimate heal is not
            // deferred if the signature flips to net-timeout-dominated on a
            // later tick.
            //
            // After [`GATED_TICKS_BEFORE_OVERRIDE`] consecutive declined
            // ticks the gate is overridden: the heal proceeds anyway (with
            // cooldown/backoff/canary still applying), per the stability plan
            // §1a — a sustained total outage is worth healing even when the
            // failure signature is ambiguous.
            let gate_declined =
                should_decline_rebuild(new_remote_timeout, new_access_failed, new_net_timeout);
            gated_ticks = step_gated_ticks(gated_ticks, gate_declined);
            if gate_declined {
                if should_override_decline(gated_ticks) {
                    warn!(
                        gated_ticks,
                        new_remote_timeout,
                        new_access_failed,
                        new_net_timeout,
                        "signature override: total outage persists — healing despite a \
                         RemoteNetworkTimeout/TorAccessFailed-dominated window"
                    );
                } else {
                    warn!(
                        new_remote_timeout,
                        new_access_failed,
                        new_net_timeout,
                        "declining channel termination: failures in this window are \
                         RemoteNetworkTimeout/TorAccessFailed, not TorNetworkTimeout \
                         — reconnecting over the same guards would reproduce the same \
                         state, not fix it"
                    );
                    continue;
                }
            }
            // Cooldown: never act more often than configured, even when it
            // cannot help (a real network block). After a run of consecutive
            // failures we stretch it further (see [`EXTENDED_REBUILD_COOLDOWN`])
            // so a fully-blocked network is not hammered every
            // `rebuild_cooldown_secs`.
            let effective_cooldown = if consecutive_failures >= CONSECUTIVE_FAILURES_BEFORE_BACKOFF
            {
                EXTENDED_REBUILD_COOLDOWN
            } else {
                cooldown
            };
            if let Some(last) = last_rebuild {
                if last.elapsed() < effective_cooldown {
                    continue;
                }
            }

            warn!(
                stale_secs = since_anchor,
                attempts = new_attempts,
                alive_bridges = alive,
                threshold_secs = stale.as_secs(),
                consecutive_failures,
                effective_cooldown_secs = effective_cooldown.as_secs(),
                "no successful Tor circuit in the stale window despite attempts \
                 and alive bridges — terminating all live channels in place, \
                 possibly stale channels from a network change"
            );

            let canary_target = handle.health().last_success_target();
            let Some(tor) = handle.tunnel().await else {
                // Slot already drained (shutdown in progress) — nothing to
                // heal. Leave the cooldown/failure counters untouched, same
                // as the signature-gate decline above: this is not a failed
                // attempt, just nothing to do.
                continue;
            };
            match heal(&tor, canary_target).await {
                HealResult::Healed => {
                    last_rebuild = Some(Instant::now());
                    if consecutive_failures > 0 {
                        info!(
                            prior_consecutive_failures = consecutive_failures,
                            "tor stale-channel watchdog: heal succeeded — backoff counter reset"
                        );
                    }
                    consecutive_failures = 0;
                    info!(
                        "tor stale-channel watchdog: channels terminated and client \
                         reconnected successfully"
                    );
                }
                HealResult::StillUnhealthy => {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    last_rebuild = Some(Instant::now());
                    warn!(
                        verify_timeout_secs = VERIFY_TIMEOUT.as_secs(),
                        consecutive_failures,
                        threshold = CONSECUTIVE_FAILURES_BEFORE_BACKOFF,
                        next_cooldown_secs =
                            next_cooldown(consecutive_failures, cooldown).as_secs(),
                        "tor stale-channel watchdog: channels terminated but the client \
                         did not reconnect within the verify budget — will retry after \
                         cooldown"
                    );
                }
                HealResult::TerminateFailed(e) => {
                    // Count the failure and set the cooldown either way so a
                    // persistently unreachable channel manager does not
                    // trigger a retry storm. `next_cooldown` reports what
                    // will gate the *next* attempt after this bump.
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    last_rebuild = Some(Instant::now());
                    warn!(
                        error = format!("{e:#}"),
                        consecutive_failures,
                        threshold = CONSECUTIVE_FAILURES_BEFORE_BACKOFF,
                        next_cooldown_secs =
                            next_cooldown(consecutive_failures, cooldown).as_secs(),
                        "tor stale-channel watchdog: could not terminate channels — \
                         will retry after cooldown"
                    );
                }
            }
            // A heal was performed — the gate escalation restarts regardless of
            // outcome; how soon the *next* heal may run is the cooldown/backoff
            // machinery's job, not this counter's.
            gated_ticks = 0;
        }
    });
}

/// Outcome of one [`heal`] attempt.
pub(super) enum HealResult {
    /// Channels were terminated and the client reconnected successfully
    /// (verified via [`verify_usable`]) within [`VERIFY_TIMEOUT`].
    Healed,
    /// Channels were terminated, but the client did not carry traffic again
    /// within [`VERIFY_TIMEOUT`] — arti did not (yet) reconnect, or the
    /// underlying network problem is not actually channel-related. The old
    /// client is still live (there was never a second one to fall back to);
    /// the caller backs off via the cooldown/consecutive-failures machinery.
    StillUnhealthy,
    /// `TorTunnel::terminate_all_channels` itself failed — e.g. the client
    /// is not in a "running" state (see `arti_wrapper::TorTunnel::
    /// terminate_all_channels`'s doc comment). No channels were touched.
    TerminateFailed(anyhow::Error),
}

/// Terminate every channel the live `tor` client's `ChanMgr` currently
/// tracks, then judge whether the client actually recovers.
///
/// ## Why there is still a canary here
///
/// The rebuild-slot design canary-tested a *second*, freshly bootstrapped
/// client before trusting it enough to replace the first — the two-client
/// setup was the whole point of the canary (never trust the newcomer
/// blindly). Here there is exactly one client, and terminating its channels
/// cannot itself be undone or second-guessed — there is no alternative to
/// swap to. So the canary's role changes from "gatekeeper before a swap" to
/// "signal for the backoff/cooldown machinery": did terminating the
/// channels actually let the client reconnect, or is whatever was wrong
/// with the network still wrong? Reusing [`verify_usable`] unchanged (retry
/// the most recent successful `(host, port)` under [`VERIFY_TIMEOUT`]) for
/// this keeps that judgment identical to the old design's, so a genuinely
/// blocked network still triggers [`CONSECUTIVE_FAILURES_BEFORE_BACKOFF`]-
/// driven backoff exactly as before, just without a client to construct and
/// dispose of on every tick.
pub(super) async fn heal(tor: &TorTunnel, canary_target: Option<(String, u16)>) -> HealResult {
    if let Err(e) = tor.terminate_all_channels() {
        return HealResult::TerminateFailed(anyhow::Error::new(e));
    }
    if verify_usable(tor, canary_target).await {
        HealResult::Healed
    } else {
        HealResult::StillUnhealthy
    }
}

/// Try to actually establish a connection through the client before
/// declaring a heal attempt successful. `target` is a recently successful
/// (host, port) pair to retry against; if none is available (process just
/// started, nothing has ever succeeded), skip verification entirely — treat
/// the client as usable (nothing better to compare against, and gating
/// everything on this would block first-ever startup too — though note:
/// `heal()` only runs after startup already succeeded once, so in practice
/// `target` should be Some by then).
pub(super) async fn verify_usable(tor: &TorTunnel, target: Option<(String, u16)>) -> bool {
    let Some((host, port)) = target else {
        return true;
    };
    tokio::time::timeout(VERIFY_TIMEOUT, tor.connect(&host, port))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false)
}

/// Number of bridges with proven reachability (`BridgeStore::alive_count`:
/// answered a probe, no failure since, not retired), read straight off the
/// on-disk health store. Best-effort: a
/// missing/unreadable store yields 0 (the watchdog then declines to fire,
/// leaving the bridge-maintenance loop to repopulate it).
pub(super) fn live_bridge_count(config_path: Option<&Path>) -> usize {
    let path = BridgeStore::resolve_path(config_path);
    match BridgeStore::load(path) {
        Ok(store) => store.alive_count(),
        Err(_) => 0,
    }
}

/// Current wall-clock time in Unix seconds. `SystemTime` rather than
/// `Instant` because the value is compared against `last_success`, which is
/// stamped on the SOCKS5 hot path with the same clock.
pub(super) fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
