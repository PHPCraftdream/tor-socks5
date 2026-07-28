//! Stale-channel watchdog: detects Tor channels left half-open by a
//! silent network change and terminates them in place, letting arti
//! reconnect over the same already-bootstrapped `TorClient`.
//!
//! ## The problem this solves
//!
//! `arti-client` / `tor-chanmgr` 0.43 has no hook on network-change events,
//! and `TorClient::reconfigure()` does **not** reset channels — it only
//! re-parameterises padding/KIST on already-open ones. The only automatic
//! channel expiry (`continually_expire_channels`) closes a channel that has
//! been idle for 180–270 s; a channel against which circuits are *actively*
//! (but hopelessly) being attempted is never idle, so it is never expired.
//!
//! The dead-channel signal in arti is an OS-level TCP error (RST/EOF/write
//! failure). On a quiet Wi-Fi handoff the socket stays half-open and the
//! default Windows TCP keepalive is measured in hours, so that signal may
//! never arrive.
//!
//! ## How it heals
//!
//! Every SOCKS5 CONNECT through Tor bumps an attempt counter; a successful
//! one stamps `last_success`. A background task (see [`spawn_tor_watchdog`])
//! periodically checks: if no circuit succeeded within the stale window
//! **while attempts keep coming** and at least one bridge is still
//! TCP-reachable (so this is not the bridge-maintenance loop's problem), it
//! calls [`arti_wrapper::TorTunnel::terminate_all_channels`] on the *live*
//! `TorTunnel` — the same client, in the same state directory, with the
//! same already-warm guard/bridge-descriptor cache — and lets arti's own
//! `ChanMgr::get_or_launch` build fresh channels the next time one is
//! requested. A cooldown prevents a rebuild storm when this does not help
//! (a genuine network block).
//!
//! ## Why this replaced the old rebuild-slot-pool design
//!
//! An earlier version of this watchdog reacted to the same trigger
//! conditions by constructing a brand-new `TorTunnel` in one of a small pool
//! of sibling "rebuild slot" state directories, warming its bridge-
//! descriptor sqlite cache from the primary directory by hand, canary-
//! testing it, and only then swapping it in for the old client. That design
//! existed to work around exactly one problem: there was no public API to
//! force-invalidate a channel, so the only known reset was "build a whole
//! new `TorClient`". Everything else about it was compensating for the
//! side effects of that workaround —
//!
//! - A rebuilt client landed in a *cold* state directory, so guards started
//!   "unsuitable to purpose" until bridge descriptors were re-fetched over
//!   the network, which could take minutes — the sqlite-warm-up step
//!   (`warm_slot_bridge_desc_cache`, since removed) tried to paper over this
//!   by hand-copying `BridgeDescs` rows out of `tor-dirmgr`'s *private*,
//!   version-specific on-disk schema — the code's own doc comments already
//!   flagged this as "an internal implementation detail that could shift on
//!   an arti upgrade".
//! - A single fixed sibling directory assumed the outgoing client's state-
//!   dir lock was always free to reuse; it is not — `TorHandle::swap` only
//!   drops its own reference, and the underlying `Arc<TorClient>` (and
//!   arti's exclusive lock) survives until the last long-lived connection
//!   that had cloned it finishes, which can be hours. This required a pool
//!   of `REBUILD_SLOT_COUNT` candidate directories, each probed with a
//!   non-blocking `fslock-guard` lock check (`slot_is_free`/`pick_free_slot`,
//!   since removed) before use — fragile in its own right (hardcoded
//!   `cache/dir.lock` / `state/state/state.lock` paths) and still capable of
//!   exhausting the whole pool if enough generations were draining at once.
//!
//! [`tor_chanmgr::ChanMgr::terminate_all_channels`] (vendored — see
//! `vendor/tor-chanmgr/src/lib.rs` and `vendor/README.md`) removes the
//! premise these workarounds existed for: it force-closes every channel the
//! *live* client's channel manager tracks without building anything new, so
//! there is no cold cache, no second state-dir lock to juggle, and no slot
//! pool to exhaust. `TorClient::chanmgr()` is behind `arti-client`'s
//! `experimental-api` feature cargo flag, which this workspace now enables.
//!
//! ## Judging success without a second client to canary
//!
//! The old design canary-tested the *new* client (via [`verify_usable`])
//! before trusting it enough to swap in, because there were two clients in
//! play and only one of them should survive. Here there is only ever one
//! client — the same one, with its channels reset — so "swap in on success"
//! has no meaning any more. What still needs answering is the same question
//! the old canary answered: did this actually help? We reuse the identical
//! mechanism ([`verify_usable`], unchanged: retry the most recent
//! successful `(host, port)` under a timeout) *after* calling
//! `terminate_all_channels`, and feed its answer into the exact same
//! `consecutive_failures`/cooldown machinery the rebuild path used — a
//! successful reconnect resets the counter, a failure extends the cooldown.
//! This keeps the operational behavior (backoff under a genuinely blocked
//! network, quick recovery otherwise) identical to before, without a
//! parallel client to construct or dispose of.
//!
//! ## Why "attempts are failing" isn't enough on its own
//!
//! Terminating channels only forces a reconnect — it does nothing for a
//! healthy Tor stack whose *exits* went quiet, or whose guards are
//! temporarily unsuitable; retrying those the exact same way changes
//! nothing. This is the mechanism analyzed in
//! docs/upstream/guard-exhaustion-watchdog-spiral.md: a rebuild triggered by
//! exit-side timeouts, not a stale channel, made an outage worse rather than
//! fixing it. `classify_and_record` (fed from `server.rs` on every failed
//! `TorTunnel::connect`) and [`should_decline_rebuild`] add a fourth trigger
//! condition — a signature gate — that declines to act when the window's
//! failures are dominated by `RemoteNetworkTimeout` or `TorAccessFailed`
//! rather than `TorNetworkTimeout`, since only the latter is the "zombie
//! channel" signature a channel reset can actually fix.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arti_wrapper::TorTunnel;
use bridge_line::BridgeLine;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::bridge_store::BridgeStore;
use crate::bridge_warmer::{candidates_with_health, Health};
use crate::config::{Config, WatchdogConfig};

/// Shared, lock-free circuit-level health signal, updated from the SOCKS5
/// hot path on every Tor `connect`. Cheap to clone (two atomics behind an
/// `Arc`); there are no locks on the per-connection path.
#[derive(Clone, Default)]
pub struct TorHealth {
    /// Unix-seconds of the last successful `TorTunnel::connect`. `0` until
    /// the first success — the watchdog substitutes the start time in that
    /// case so the stale window still elapses from boot, not from the epoch.
    last_success: Arc<AtomicU64>,
    /// Monotonic count of `TorTunnel::connect` calls (success or failure).
    /// The watchdog compares this between ticks to detect "attempts are
    /// still being made" — the difference between *no traffic* and
    /// *circuits failing*.
    attempts: Arc<AtomicU64>,
    /// `(host, port)` of the most recent successful `TorTunnel::connect`.
    /// A plain `Mutex` rather than atomics: the value is a `String`, so it
    /// cannot live in a lock-free cell. Read only by the watchdog (at most
    /// once per check interval), so contention with the hot-path writer is
    /// a non-issue.
    last_success_target: Arc<Mutex<Option<(String, u16)>>>,
    /// Monotonic count of `TorTunnel::connect` failures classified as
    /// `tor_error::ErrorKind::RemoteNetworkTimeout` — the circuit reached
    /// the exit but the exit went silent. The Tor stack itself is working;
    /// rebuilding the client would not help this class of failure. Like
    /// `attempts`, the watchdog reads the *delta* between ticks rather than
    /// a value reset in place — see `spawn_tor_watchdog`'s loop.
    remote_timeout_count: Arc<AtomicU64>,
    /// Monotonic count of `TorTunnel::connect` failures classified as
    /// `tor_error::ErrorKind::TorAccessFailed` — guards are down or
    /// unsuitable (e.g. missing bridge descriptors). A rebuild would land
    /// in the same state, so this class does not indicate a stale-channel
    /// condition the watchdog can fix.
    access_failed_count: Arc<AtomicU64>,
    /// Monotonic count of `TorTunnel::connect` failures classified as
    /// `tor_error::ErrorKind::TorNetworkTimeout` — genuine circuit-build
    /// timeouts. Unlike the other two classes, a rebuild (fresh channels)
    /// can plausibly fix this one.
    net_timeout_count: Arc<AtomicU64>,
}

impl TorHealth {
    /// Bump the attempt counter. Called on every `TorTunnel::connect`.
    pub fn record_attempt(&self) {
        self.attempts.fetch_add(1, Ordering::Relaxed);
    }

    /// Stamp "now" as the last successful connect. Called only on success.
    pub fn record_success(&self) {
        self.last_success.store(unix_secs(), Ordering::Relaxed);
    }

    /// Remember the `(host, port)` of the most recent successful
    /// `TorTunnel::connect`, so the watchdog can later re-try the exact
    /// same target as a post-rebuild usability canary (see
    /// [`verify_usable`]). Last-write-wins — we only need *some* recently
    /// good target, not a history of them.
    pub fn record_success_target(&self, host: &str, port: u16) {
        *self
            .last_success_target
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some((host.to_string(), port));
    }

    /// The most recently recorded successful target, if any. `None` before
    /// the first success ever recorded on this handle (e.g. process just
    /// started).
    fn last_success_target(&self) -> Option<(String, u16)> {
        self.last_success_target
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn last_success_secs(&self) -> u64 {
        self.last_success.load(Ordering::Relaxed)
    }

    fn attempt_count(&self) -> u64 {
        self.attempts.load(Ordering::Relaxed)
    }

    /// Bump the `RemoteNetworkTimeout` class counter. See
    /// [`classify_and_record`] for where this is called from the hot path.
    pub fn record_remote_timeout(&self) {
        self.remote_timeout_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Bump the `TorAccessFailed` class counter.
    pub fn record_access_failed(&self) {
        self.access_failed_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Bump the `TorNetworkTimeout` class counter.
    pub fn record_net_timeout(&self) {
        self.net_timeout_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Cumulative `RemoteNetworkTimeout` count. The watchdog loop is
    /// expected to compare this against the previous tick's value (the same
    /// delta pattern as `attempt_count`) rather than treat it as a
    /// per-interval value — there is no reset method by design.
    ///
    /// Read by `spawn_tor_watchdog`'s loop to feed [`should_decline_rebuild`]
    /// — see that function's doc comment for how the delta is used.
    pub fn remote_timeout_count(&self) -> u64 {
        self.remote_timeout_count.load(Ordering::Relaxed)
    }

    /// Cumulative `TorAccessFailed` count. See `remote_timeout_count` for
    /// the delta-reading convention and its use in the watchdog loop.
    pub fn access_failed_count(&self) -> u64 {
        self.access_failed_count.load(Ordering::Relaxed)
    }

    /// Cumulative `TorNetworkTimeout` count. See `remote_timeout_count` for
    /// the delta-reading convention and its use in the watchdog loop.
    pub fn net_timeout_count(&self) -> u64 {
        self.net_timeout_count.load(Ordering::Relaxed)
    }
}

/// Classify a failed `TorTunnel::connect` and bump the matching counter on
/// `health`, if the error falls into one of the three classes the watchdog
/// cares about (see the module-level doc comment on [`TorHealth`]'s
/// `*_count` fields). Any other `TorError` variant, or any other
/// `tor_error::ErrorKind`, is left uncounted — this classification is
/// deliberately narrow, not exhaustive.
///
/// Pulled out as a free function (rather than inlined at the `server.rs`
/// call site) so it can be unit-tested without a live Tor connection: the
/// three `ErrorKind`s below can only be produced by real network activity
/// deep inside arti, so the classification match itself is what gets
/// exercised here, gated on a hand-built `arti_client::Error`/`ErrorKind`.
///
/// | `ErrorKind`            | meaning                                             |
/// |------------------------|------------------------------------------------------|
/// | `RemoteNetworkTimeout` | circuit built, exit went silent — rebuild won't help |
/// | `TorAccessFailed`      | guards down/unsuitable — rebuild reproduces the same |
/// | `TorNetworkTimeout`    | genuine circuit-build timeout — rebuild can help     |
pub fn classify_and_record(err: &arti_wrapper::TorError, health: &TorHealth) {
    let arti_wrapper::TorError::Connect { source, .. } = err else {
        return;
    };
    match tor_error::HasKind::kind(source) {
        tor_error::ErrorKind::RemoteNetworkTimeout => health.record_remote_timeout(),
        tor_error::ErrorKind::TorAccessFailed => health.record_access_failed(),
        tor_error::ErrorKind::TorNetworkTimeout => health.record_net_timeout(),
        _ => {}
    }
}

/// Swappable handle to the live `TorTunnel`, shared between the accept
/// loop (reads the current tunnel for each new connection), the watchdog
/// (replaces it after a rebuild) and the bridge-maintenance loop (reads it
/// for over-Tor candidate-pool refreshes). All clones share one slot, so a
/// terminate-and-reconnect becomes visible to every consumer without
/// re-distribution — even though the watchdog no longer replaces the
/// tunnel value itself, the slot indirection is still what lets the accept
/// loop and the bridge-maintenance loop read "the current tunnel" without
/// each holding a fixed clone.
#[derive(Clone)]
pub struct TorHandle {
    /// `Option` so the slot can be drained at shutdown, dropping the last
    /// in-slot reference and letting arti's reactor close the PT children
    /// and release the state-dir lock.
    slot: Arc<RwLock<Option<TorTunnel>>>,
    health: TorHealth,
}

impl TorHandle {
    /// Wrap the bootstrapped tunnel. The handle is cheap to clone.
    pub fn new(tor: TorTunnel) -> Self {
        Self {
            slot: Arc::new(RwLock::new(Some(tor))),
            health: TorHealth::default(),
        }
    }

    /// Snapshot the current tunnel for a new connection. Returns `None`
    /// only while the server is shutting down (the slot has been drained);
    /// callers should treat that as a transient "unavailable" error. A
    /// `TorTunnel` is an `Arc<TorClient>` internally, so the clone is cheap.
    pub async fn tunnel(&self) -> Option<TorTunnel> {
        self.slot.read().await.clone()
    }

    /// Circuit-level health counters shared with the watchdog.
    pub fn health(&self) -> &TorHealth {
        &self.health
    }

    /// Take the tunnel out of the slot (graceful shutdown). The returned
    /// `TorTunnel`, when dropped, releases the slot's reference; the
    /// reactor/PT teardown follows once the remaining in-flight clones drain.
    pub async fn drain(self) -> Option<TorTunnel> {
        self.slot.write().await.take()
    }
}

/// Budget for the post-termination usability check: how long [`heal`] waits
/// for the live client to actually carry traffic again after
/// `terminate_all_channels`, before giving up on this tick and letting the
/// cooldown/backoff machinery gate the next attempt.
const VERIFY_TIMEOUT: Duration = Duration::from_secs(90);

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
const MIN_ATTEMPTS_TO_TRIGGER: u64 = 3;

/// Once this many heal attempts (terminate-then-reconnect) fail in a row
/// (terminate error, or the client still doesn't reconnect within
/// [`VERIFY_TIMEOUT`]), the watchdog backs off to
/// [`EXTENDED_REBUILD_COOLDOWN`] instead of the configured
/// `rebuild_cooldown_secs`: a persistently blocked network does not merit
/// retrying every few minutes. Field/constant names still say "rebuild" —
/// that's the configured `[watchdog]` key (`rebuild_cooldown_secs`) this
/// mirrors, kept stable across the rebuild-slot → in-place-heal switch so
/// existing config files do not need to change.
const CONSECUTIVE_FAILURES_BEFORE_BACKOFF: u32 = 3;

/// Fixed cooldown applied once [`CONSECUTIVE_FAILURES_BEFORE_BACKOFF`] is
/// reached. Deliberately not derived from config: 30 min is "leave it
/// alone for a while", independent of how aggressive the normal cooldown is.
const EXTENDED_REBUILD_COOLDOWN: Duration = Duration::from_secs(30 * 60);

/// Cooldown that will gate the *next* heal attempt after `consecutive_failures`
/// failed attempts. Pure helper so the loop's failure branches log the
/// cooldown that will actually apply, without duplicating the threshold.
fn next_cooldown(consecutive_failures: u32, normal: Duration) -> Duration {
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
fn should_decline_rebuild(
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
fn should_signal_failover(
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

        // Per-bridge last-signalled time, keyed by the bridge's canonical
        // string form (`BridgeLine` has no `Eq`/`Hash` impl of its own).
        // Rate-limits re-signalling the same degraded bridge every tick —
        // mirrors `rebuild_cooldown_secs`'s role for channel termination.
        let mut last_signalled: HashMap<String, Instant> = HashMap::new();

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

            let candidates = candidates_with_health(&cfg, config_path.as_deref());
            if candidates.len() < 2 {
                // Need at least one degraded bridge and one alternative.
                continue;
            }

            for (idx, (bridge, health)) in candidates.iter().enumerate() {
                if health.circuit_fails < cfg.watchdog.failover_min_circuit_fails {
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

                let key = bridge.to_string();
                if let Some(last) = last_signalled.get(&key) {
                    if last.elapsed() < signal_cooldown {
                        continue;
                    }
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
                        last_signalled.insert(key, Instant::now());
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
fn healthiest(candidates: &[(BridgeLine, Health)]) -> Option<Health> {
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
            // Condition 3: at least one bridge is TCP-reachable per the last
            // probe round, so this is a circuit/channel problem, not the
            // bridge-maintenance loop's "bridges are genuinely down" case.
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
            if should_decline_rebuild(new_remote_timeout, new_access_failed, new_net_timeout) {
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
        }
    });
}

/// Outcome of one [`heal`] attempt.
enum HealResult {
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
async fn heal(tor: &TorTunnel, canary_target: Option<(String, u16)>) -> HealResult {
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
async fn verify_usable(tor: &TorTunnel, target: Option<(String, u16)>) -> bool {
    let Some((host, port)) = target else {
        return true;
    };
    tokio::time::timeout(VERIFY_TIMEOUT, tor.connect(&host, port))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false)
}

/// Number of bridges in a healthy TCP state (`fails == 0`) per the last
/// probe round, read straight off the on-disk health store. Best-effort: a
/// missing/unreadable store yields 0 (the watchdog then declines to fire,
/// leaving the bridge-maintenance loop to repopulate it).
fn live_bridge_count(config_path: Option<&Path>) -> usize {
    let path = BridgeStore::resolve_path(config_path);
    match BridgeStore::load(path) {
        Ok(store) => store.alive_count(),
        Err(_) => 0,
    }
}

/// Current wall-clock time in Unix seconds. `SystemTime` rather than
/// `Instant` because the value is compared against `last_success`, which is
/// stamped on the SOCKS5 hot path with the same clock.
fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Once;

    /// Install rustls's process-wide `CryptoProvider` exactly once for this
    /// test binary, mirroring `install_crypto_provider()` in
    /// `apps/socks5-proxy/src/startup.rs` (which real app startup always
    /// runs before constructing any `TorTunnel`). A genuinely fresh, empty
    /// `state_dir` (see the tempdir-based tests below) reaches further into
    /// arti's directory-manager setup than a dir with pre-existing state
    /// would, and that path expects a crypto provider to already be
    /// installed. `install_default()` errors if called twice in the same
    /// process, so the error is intentionally discarded.
    fn ensure_crypto_provider() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    #[test]
    fn health_starts_unstamped_and_counts_attempts() {
        let h = TorHealth::default();
        assert_eq!(h.last_success_secs(), 0);
        assert_eq!(h.attempt_count(), 0);
        h.record_attempt();
        h.record_attempt();
        assert_eq!(h.attempt_count(), 2);
        // No success recorded yet.
        assert_eq!(h.last_success_secs(), 0);
    }

    #[test]
    fn record_success_stamps_nonzero() {
        let h = TorHealth::default();
        h.record_success();
        let s = h.last_success_secs();
        assert!(s > 0, "record_success must stamp a real unix time");
    }

    #[test]
    fn success_target_roundtrips_and_starts_empty() {
        let h = TorHealth::default();
        assert_eq!(h.last_success_target(), None);
        h.record_success_target("example.com", 443);
        assert_eq!(
            h.last_success_target(),
            Some(("example.com".to_string(), 443))
        );
    }

    #[test]
    fn success_target_last_write_wins() {
        let h = TorHealth::default();
        h.record_success_target("first.example", 80);
        h.record_success_target("second.example", 8080);
        assert_eq!(
            h.last_success_target(),
            Some(("second.example".to_string(), 8080)),
            "a newer record_success_target call must overwrite the previous one"
        );
    }

    #[test]
    fn handle_clone_shares_slot_and_health() {
        // Two clones of a handle share the same health counters: an attempt
        // recorded through one is visible through the other. This is the
        // property the watchdog relies on to observe the hot path.
        let h = TorHealth::default();
        let h2 = h.clone();
        h.record_attempt();
        assert_eq!(h2.attempt_count(), 1);
    }

    #[tokio::test]
    async fn drain_releases_tunnel() {
        // We can't build a real TorTunnel in a unit test, but the slot only
        // stores Option<TorTunnel> and we never read it here — so a stub
        // via the type system isn't possible without a live tunnel. Instead
        // exercise the Option mechanics indirectly by constructing the slot
        // directly.
        let slot: Arc<RwLock<Option<u32>>> = Arc::new(RwLock::new(Some(42)));
        assert_eq!(slot.read().await.clone(), Some(42));
        // "drain"
        let taken = slot.write().await.take();
        assert_eq!(taken, Some(42));
        assert!(slot.read().await.is_none());
    }

    #[test]
    fn unix_secs_is_plausible() {
        let s = unix_secs();
        // After 2024-01-01 and before year ~2100 — sanity, not exactness.
        assert!(s > 1_704_067_200, "unix_secs should be past 2024");
    }

    #[tokio::test]
    async fn verify_usable_skips_network_when_no_target() {
        // `target: None` must short-circuit to `true` without ever touching
        // the network — this is the "nothing to compare against yet" case
        // (process just started, no success recorded on this handle). We
        // can't cheaply fake a *bootstrapped* TorTunnel in a unit test, but
        // `create_unbootstrapped_with` is synchronous and does no I/O, so it
        // is safe to use here purely to get a real `&TorTunnel` reference —
        // if `verify_usable` ever tried to use it (it must not, for
        // `target: None`), the call would hang/fail and the test would
        // never reach the assertion below within the runtime's default
        // behavior, since nothing here awaits a bootstrap.
        //
        // `state_dir` must point at a fresh tempdir, not `Default::default()`'s
        // `None` (which falls back to arti's shared per-user OS-default
        // state/cache location): constructing even an "unbootstrapped"
        // client eagerly opens that directory's storage, which is flaky on
        // CI (`DirMgrSetup(ReadOnlyStorage(NoDatabase))` on a fresh runner
        // with no prior arti state, or a real `SqliteError` when concurrent
        // tests in this same binary race on the same shared path) — this is
        // exactly the fragility `packages/arti-wrapper/src/lib.rs`'s
        // `signal_bridge_failure_*` tests hit and fixed the same way.
        let dir = tempfile::tempdir().unwrap();
        let settings = arti_wrapper::Settings {
            state_dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        ensure_crypto_provider();
        let tor = arti_wrapper::TorTunnel::create_unbootstrapped_with(settings)
            .expect("synchronous, no-I/O construction must succeed");
        assert!(
            verify_usable(&tor, None).await,
            "target: None must be treated as usable without a network round-trip"
        );
    }

    #[tokio::test]
    async fn heal_reports_terminate_failed_on_a_client_that_is_not_running() {
        // A `TorTunnel` built via `create_unbootstrapped_with` is
        // synchronous, does no I/O, and never reaches arti's "running"
        // state — so `TorClient::chanmgr()` (and therefore
        // `TorTunnel::terminate_all_channels`) must fail on it, exactly the
        // same way it would on a fully dormant client. `heal` must surface
        // this as `TerminateFailed` rather than panicking or silently
        // treating it as `StillUnhealthy` — the two mean different things to
        // the watchdog loop's logging (dead channel manager vs. a live one
        // that just isn't reconnecting).
        //
        // Same tempdir `state_dir` rationale as the test above — do not
        // revert to `Default::default()`.
        let dir = tempfile::tempdir().unwrap();
        let settings = arti_wrapper::Settings {
            state_dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        ensure_crypto_provider();
        let tor = arti_wrapper::TorTunnel::create_unbootstrapped_with(settings)
            .expect("synchronous, no-I/O construction must succeed");
        match heal(&tor, None).await {
            HealResult::TerminateFailed(_) => {}
            HealResult::Healed => panic!("an unbootstrapped client cannot have healed"),
            HealResult::StillUnhealthy => panic!(
                "chanmgr() must fail outright on a client that never bootstrapped, not just \
                 fail the canary"
            ),
        }
    }

    #[test]
    fn error_class_counters_roundtrip_independently() {
        // Each of the three class counters starts at 0 and accumulates
        // independently of the others — the same "record N times, read N"
        // shape as `attempt_count`, but exercised three times over so a
        // copy-paste mistake wiring one counter to the wrong field would
        // fail this test.
        let h = TorHealth::default();
        assert_eq!(h.remote_timeout_count(), 0);
        assert_eq!(h.access_failed_count(), 0);
        assert_eq!(h.net_timeout_count(), 0);

        h.record_remote_timeout();
        h.record_remote_timeout();
        h.record_remote_timeout();
        assert_eq!(h.remote_timeout_count(), 3);
        assert_eq!(
            h.access_failed_count(),
            0,
            "recording remote_timeout must not bump access_failed"
        );
        assert_eq!(
            h.net_timeout_count(),
            0,
            "recording remote_timeout must not bump net_timeout"
        );

        h.record_access_failed();
        h.record_access_failed();
        assert_eq!(h.access_failed_count(), 2);
        assert_eq!(
            h.remote_timeout_count(),
            3,
            "recording access_failed must not touch remote_timeout"
        );
        assert_eq!(
            h.net_timeout_count(),
            0,
            "recording access_failed must not bump net_timeout"
        );

        h.record_net_timeout();
        assert_eq!(h.net_timeout_count(), 1);
        assert_eq!(
            h.remote_timeout_count(),
            3,
            "recording net_timeout must not touch remote_timeout"
        );
        assert_eq!(
            h.access_failed_count(),
            2,
            "recording net_timeout must not touch access_failed"
        );
    }

    #[test]
    fn classify_and_record_ignores_non_connect_variants() {
        // `TorError` variants other than `Connect` (e.g. a config error
        // raised before any network activity) carry no `arti_client::Error`
        // to classify — `classify_and_record` must leave all three counters
        // untouched rather than guess.
        let h = TorHealth::default();
        let err = arti_wrapper::TorError::InvalidBridge("not a real bridge line".to_string());
        classify_and_record(&err, &h);
        assert_eq!(h.remote_timeout_count(), 0);
        assert_eq!(h.access_failed_count(), 0);
        assert_eq!(h.net_timeout_count(), 0);
    }

    #[test]
    fn should_decline_rebuild_no_data_does_not_block() {
        // No classified failures this window at all — either nothing failed
        // through TorTunnel::connect, or the failures came through some
        // other, unclassified path. Either way, "no data" must mean "behave
        // as before" (don't rebuild-gate on an absence of signal), not
        // "assume the worst and decline".
        assert!(!should_decline_rebuild(0, 0, 0));
    }

    #[test]
    fn should_decline_rebuild_pure_net_timeout_allows_rebuild() {
        // Only TorNetworkTimeout this window — the exact "zombie channel"
        // signature the watchdog exists to fix. Must proceed to rebuild.
        assert!(!should_decline_rebuild(0, 0, 5));
    }

    #[test]
    fn should_decline_rebuild_pure_remote_timeout_declines() {
        // Only RemoteNetworkTimeout — exit went silent, Tor stack is
        // healthy. A rebuild cannot help; must decline.
        assert!(should_decline_rebuild(5, 0, 0));
    }

    #[test]
    fn should_decline_rebuild_pure_access_failed_declines() {
        // Only TorAccessFailed — guards down/unsuitable. A rebuild starts in
        // a cold slot and reproduces the same condition; must decline.
        assert!(should_decline_rebuild(0, 5, 0));
    }

    #[test]
    fn should_decline_rebuild_net_timeout_dominant_mix_allows_rebuild() {
        // Mixed window where net_timeout strictly dominates the sum of the
        // other two classes — the zombie-channel signature is still the
        // main story here, so the rebuild should proceed.
        assert!(!should_decline_rebuild(2, 1, 10));
    }

    #[test]
    fn should_decline_rebuild_incident_signature_declines() {
        // The actual incident this gate closes: 8 attempts in 218 s, all
        // RemoteNetworkTimeout/ExitTimeout to a single Telegram DC, zero
        // TorAccessFailed and zero TorNetworkTimeout. The old trigger would
        // have rebuilt into a cold, guard-unsuitable slot and made the
        // outage worse; the gate must decline.
        assert!(should_decline_rebuild(8, 0, 0));
    }

    // -- should_signal_failover ----------------------------------------------

    #[test]
    fn should_signal_failover_below_threshold_never_fires() {
        // Current bridge hasn't even crossed the absolute degradation
        // threshold yet — must decline regardless of how healthy the
        // alternative is.
        assert!(!should_signal_failover(2, 0, 3, 2));
    }

    #[test]
    fn should_signal_failover_at_threshold_with_sufficient_margin_fires() {
        // Current bridge is exactly at the threshold, and the alternative
        // is clearly healthier (margin 5 >= min_margin 2) — must fire.
        assert!(should_signal_failover(3, 0, 3, 2));
    }

    #[test]
    fn should_signal_failover_above_threshold_but_insufficient_margin_declines() {
        // Both bridges are degraded (threshold crossed), but the
        // alternative isn't meaningfully better — margin of 1 is below
        // min_margin of 2. Must decline: this is the "don't ping-pong
        // between two mediocre bridges" case.
        assert!(!should_signal_failover(4, 3, 3, 2));
    }

    #[test]
    fn should_signal_failover_alternative_not_better_declines() {
        // The "alternative" is tied with (or worse than) the current
        // bridge — saturating_sub floors the margin at 0, which is below
        // any positive min_margin, so this must decline without a separate
        // "is it actually better" check.
        assert!(!should_signal_failover(5, 5, 3, 1));
        assert!(!should_signal_failover(5, 8, 3, 1));
    }

    #[test]
    fn should_signal_failover_zero_margin_configured_fires_on_any_nonneg_gap() {
        // A degenerate but valid configuration (`min_margin == 0`): once the
        // threshold is crossed, any alternative that is not strictly worse
        // is enough to fire — including a tie (margin == 0 >= min_margin
        // 0).
        assert!(should_signal_failover(3, 3, 3, 0));
    }

    #[test]
    fn should_signal_failover_large_margin_exact_boundary_fires() {
        // Margin exactly equal to min_margin must fire (>=, not >).
        assert!(should_signal_failover(10, 5, 3, 5));
        // One below the boundary must decline.
        assert!(!should_signal_failover(10, 6, 3, 5));
    }

    // -- healthiest -----------------------------------------------------------

    fn bridge(line: &str) -> BridgeLine {
        line.parse().expect("test bridge line parses")
    }

    fn health(tcp_fails: u32, circuit_fails: u32, ok_count: u32) -> Health {
        Health {
            tcp_fails,
            circuit_fails,
            ok_count,
        }
    }

    const OBFS4_A: &str =
        "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=ZZZ iat-mode=0";
    const OBFS4_B: &str =
        "obfs4 5.6.7.8:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=WWW iat-mode=0";

    #[test]
    fn healthiest_picks_lowest_circuit_fails() {
        let candidates = vec![
            (bridge(OBFS4_A), health(0, 5, 1)),
            (bridge(OBFS4_B), health(0, 1, 1)),
        ];
        let best = healthiest(&candidates).expect("non-empty candidates yield a winner");
        assert_eq!(best.circuit_fails, 1);
    }

    #[test]
    fn healthiest_empty_candidates_yields_none() {
        assert_eq!(healthiest(&[]), None);
    }

    #[test]
    fn healthiest_excludes_tcp_unhealthy_bridges() {
        // Only a TCP-unhealthy alternative is available — `select_top_n`
        // excludes it outright, so `healthiest` must report no winner
        // rather than surfacing an unreachable bridge as "the best
        // alternative".
        let candidates = vec![(bridge(OBFS4_A), health(1, 0, 100))];
        assert_eq!(healthiest(&candidates), None);
    }
}
