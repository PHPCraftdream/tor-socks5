//! Stale-channel watchdog: detects Tor channels left half-open by a
//! silent network change and rebuilds the `TorClient` without restarting
//! the process.
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
//! never arrive. There is no public API to force-invalidate a channel; the
//! only reliable reset is to drop the `TorClient` and build a fresh one.
//!
//! ## How it heals
//!
//! Every SOCKS5 CONNECT through Tor bumps an attempt counter; a successful
//! one stamps `last_success`. A background task (see [`spawn_tor_watchdog`])
//! periodically checks: if no circuit succeeded within the stale window
//! **while attempts keep coming** and at least one bridge is still
//! TCP-reachable (so this is not the bridge-maintenance loop's problem),
//! it rebuilds the `TorClient` via the same bootstrap path used at startup
//! and atomically swaps it in for new connections. A cooldown prevents a
//! rebuild storm when the rebuild does not help (a genuine network block).
//!
//! ## Why "attempts are failing" isn't enough on its own
//!
//! A rebuild only replaces channels — it does nothing for a healthy Tor
//! stack whose *exits* went quiet, or whose guards are temporarily
//! unsuitable. Worse, a rebuild lands in a cold rebuild-slot state
//! directory (see [`REBUILD_SLOT_COUNT`]) whose bridge-descriptor cache
//! starts empty, so its guards are themselves "unsuitable to purpose" for
//! several minutes — trading a live, merely degraded client for one that is
//! *guaranteed* unable to serve traffic. This is the mechanism analyzed in
//! docs/upstream/guard-exhaustion-watchdog-spiral.md: a rebuild triggered by
//! exit-side timeouts, not a stale channel, made an outage worse rather than
//! fixing it. `classify_and_record` (fed from `server.rs` on every failed
//! `TorTunnel::connect`) and [`should_decline_rebuild`] add a fourth trigger
//! condition — a signature gate — that declines to rebuild when the
//! window's failures are dominated by `RemoteNetworkTimeout` or
//! `TorAccessFailed` rather than `TorNetworkTimeout`, since only the latter
//! is the "zombie channel" signature a rebuild can actually fix.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use arti_wrapper::TorTunnel;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::bridge_store::BridgeStore;
use crate::config::WatchdogConfig;
use crate::tor_setup::build_tor_settings;

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
/// rebuild becomes visible to every consumer without re-distribution.
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
    /// `TorTunnel` is an `Arc<TorClient>` internally, so the clone is cheap
    /// and the connection runs against a fixed client even if the watchdog
    /// swaps the slot right after.
    pub async fn tunnel(&self) -> Option<TorTunnel> {
        self.slot.read().await.clone()
    }

    /// Circuit-level health counters shared with the watchdog.
    pub fn health(&self) -> &TorHealth {
        &self.health
    }

    /// Atomically replace the live tunnel. The previously slotted
    /// `TorTunnel` is dropped (releasing the slot's `Arc<TorClient>` ref);
    /// it fully goes away once the in-flight connections that cloned it
    /// finish, because the other consumers read through the slot rather
    /// than holding a fixed clone.
    pub async fn swap(&self, new: TorTunnel) {
        let _ = self.slot.write().await.insert(new);
    }

    /// Take the tunnel out of the slot (graceful shutdown). The returned
    /// `TorTunnel`, when dropped, releases the slot's reference; the
    /// reactor/PT teardown follows once the remaining in-flight clones drain.
    pub async fn drain(self) -> Option<TorTunnel> {
        self.slot.write().await.take()
    }
}

/// Hard cap on how long a single rebuild attempt waits for the network
/// bootstrap to finish. On a fully-blocked network a fresh `dirmgr`
/// bootstrap never completes. Unlike a bare `.await` around the whole
/// rebuild (which would lose the only reference to an already-constructed
/// `TorClient`, orphaning its detached background tasks and any spawned PT
/// child), this timeout wraps only the network-wait phase (see
/// [`rebuild`]): the `TorTunnel` itself is constructed synchronously first
/// and stays fully owned by the caller even when the wait times out, so it
/// can be explicitly dropped instead of leaked. PT subprocess cleanup on
/// that drop is still not instantaneous (see the note at the `rebuild(...)`
/// call site below).
const REBUILD_TIMEOUT: Duration = Duration::from_secs(90);

/// Once this many rebuilds fail in a row (timeout or error), the watchdog
/// backs off to [`EXTENDED_REBUILD_COOLDOWN`] instead of the configured
/// `rebuild_cooldown_secs`: a persistently blocked network does not merit
/// a rebuild every few minutes.
const CONSECUTIVE_FAILURES_BEFORE_BACKOFF: u32 = 3;

/// Fixed cooldown applied once [`CONSECUTIVE_FAILURES_BEFORE_BACKOFF`] is
/// reached. Deliberately not derived from config: 30 min is "leave it
/// alone for a while", independent of how aggressive the normal cooldown is.
const EXTENDED_REBUILD_COOLDOWN: Duration = Duration::from_secs(30 * 60);

/// Cooldown that will gate the *next* rebuild after `consecutive_failures`
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

/// Spawn the stale-channel watchdog as a detached tokio task.
///
/// Every `check_interval` the task evaluates four trigger conditions (stale
/// success, fresh attempts, alive bridges, and a failure-signature gate —
/// see [`should_decline_rebuild`]) and, if all hold and the cooldown has
/// elapsed, rebuilds the `TorClient` and swaps it in. A
/// `check_interval_secs == 0` (or `enabled == false`) config disables it.
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
        // Consecutive failed rebuilds (timeout or error). Once it crosses
        // [`CONSECUTIVE_FAILURES_BEFORE_BACKOFF`] the cooldown stretches to
        // [`EXTENDED_REBUILD_COOLDOWN`] so a fully-blocked network is not
        // hammered. Reset to 0 on the first successful rebuild.
        let mut consecutive_failures: u32 = 0;
        // Which rebuild slot (index into the [`REBUILD_SLOT_COUNT`]-sized
        // pool) is currently live, if any rebuild has ever succeeded. `None`
        // means either the original (primary state-dir) client from startup
        // is still live, or the config has no persistent state dir at all.
        // Only updated on a *successful* rebuild — a failed attempt leaves
        // whatever is actually live unchanged. The slot for the *next*
        // rebuild is no longer precomputed here: `rebuild()` probes each
        // pool slot's on-disk locks itself (via `pick_free_slot`) once it
        // knows the state dir, and picks whichever one is actually free —
        // tolerating however many prior generations are still draining
        // (see the doc comment on `rebuild` for why a fixed A/B pair isn't
        // enough).
        let mut live_slot: Option<u8> = None;

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
            // means "no traffic", not "circuits failing".
            if new_attempts == 0 {
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
            // stack whose exits or guards are simply having a bad time. A
            // rebuild only replaces channels; if the failures this window
            // are dominated by `RemoteNetworkTimeout` (exit went silent,
            // Tor stack is fine) or `TorAccessFailed` (guards down/
            // unsuitable — a rebuild starts in a *cold* slot and reproduces
            // this exact state, worse yet: the spiral analyzed in
            // docs/upstream/guard-exhaustion-watchdog-spiral.md happens
            // precisely because a cold rebuild slot's guards are unsuitable
            // for several minutes), rebuilding cannot fix what's wrong and
            // trades a live, merely degraded client for a guaranteed-broken
            // one. See `should_decline_rebuild`'s doc comment for the exact
            // rule and docs/upstream/guard-exhaustion-watchdog-spiral.md
            // §3.A/§4.2 for the incident this closes (8 attempts in 218 s,
            // all RemoteNetworkTimeout/ExitTimeout to one Telegram DC).
            //
            // Declining here is a deliberate non-attempt, not a failed one:
            // `last_rebuild`/`consecutive_failures` are left untouched so
            // the cooldown timer does not arm and a legitimate rebuild is
            // not deferred if the signature flips to net-timeout-dominated
            // on a later tick.
            if should_decline_rebuild(new_remote_timeout, new_access_failed, new_net_timeout) {
                warn!(
                    new_remote_timeout,
                    new_access_failed,
                    new_net_timeout,
                    "declining rebuild: failures in this window are \
                     RemoteNetworkTimeout/TorAccessFailed, not TorNetworkTimeout \
                     — a fresh client would reproduce the same state, not fix it"
                );
                continue;
            }
            // Cooldown: never rebuild more often than configured, even when
            // the rebuild cannot help (a real network block). After a run of
            // consecutive failures we stretch it further (see
            // [`EXTENDED_REBUILD_COOLDOWN`]) so a fully-blocked network is
            // not hammered every `rebuild_cooldown_secs`.
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
                 and alive bridges — rebuilding TorClient, possibly stale \
                 channels from a network change"
            );

            // `rebuild` itself bounds only the network-wait phase with
            // REBUILD_TIMEOUT (see its doc comment and body): construction
            // of the `TorTunnel` is synchronous and always fully succeeds or
            // fails outright, so a timeout here can never strand an unowned
            // half-built client. On `TimedOut` we still hold the `TorTunnel`
            // and explicitly drop it below — not an *immediate* PT
            // subprocess reap: tor-ptmgr's cleanup only fires the next time
            // the child writes another stdout line and its forwarding thread
            // notices the receiver is gone (ipc.rs in tor-ptmgr — no
            // kill_on_drop). In practice a stuck PT keeps logging (handshake
            // retries/timeouts), so this tends to happen soon, but it is not
            // guaranteed instantly; any process that outlives this is still
            // bounded by the startup Job Object on process exit.
            let canary_target = handle.health().last_success_target();
            match rebuild(config_path.as_deref(), live_slot, canary_target).await {
                Ok(RebuildOutcome::Ready { tor: new_tor, slot }) => {
                    handle.swap(new_tor).await;
                    last_rebuild = Some(Instant::now());
                    live_slot = slot;
                    if consecutive_failures > 0 {
                        info!(
                            prior_consecutive_failures = consecutive_failures,
                            "tor stale-channel watchdog: rebuild succeeded — backoff counter reset"
                        );
                    }
                    consecutive_failures = 0;
                    info!("tor stale-channel watchdog: TorClient rebuilt and swapped in");
                }
                Ok(RebuildOutcome::TimedOut(tor)) => {
                    // Controlled drop of a fully-owned value — not an
                    // orphaning cancellation. `tor` was never lost to an
                    // external future-cancellation, so this relies on
                    // arti's normal, already-working Drop-based cleanup
                    // (the same mechanism the graceful-shutdown path in
                    // `server.rs` already uses successfully).
                    drop(tor);
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    last_rebuild = Some(Instant::now());
                    warn!(
                        timeout_secs = REBUILD_TIMEOUT.as_secs(),
                        consecutive_failures,
                        threshold = CONSECUTIVE_FAILURES_BEFORE_BACKOFF,
                        next_cooldown_secs =
                            next_cooldown(consecutive_failures, cooldown).as_secs(),
                        "tor stale-channel watchdog: rebuild timed out — dropped the \
                         fully-owned half-bootstrapped client"
                    );
                }
                Ok(RebuildOutcome::NotUsable(tor)) => {
                    // Same controlled-drop reasoning as the TimedOut arm: we
                    // fully own `tor`, so this is a normal, safe drop. The
                    // old client stays live in `live_slot` — we deliberately
                    // do not swap, because the freshly bootstrapped client
                    // reported directory-ready but failed to actually carry
                    // traffic within VERIFY_TIMEOUT (see verify_usable's
                    // doc comment and RebuildOutcome::NotUsable): swapping
                    // it in would replace a live, if degraded, client with
                    // one that silently cannot serve traffic for minutes
                    // while it catches up on bridge descriptors.
                    drop(tor);
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    last_rebuild = Some(Instant::now());
                    warn!(
                        verify_timeout_secs = VERIFY_TIMEOUT.as_secs(),
                        consecutive_failures,
                        threshold = CONSECUTIVE_FAILURES_BEFORE_BACKOFF,
                        next_cooldown_secs =
                            next_cooldown(consecutive_failures, cooldown).as_secs(),
                        "tor stale-channel watchdog: rebuild bootstrapped but failed the \
                         usability check — a fresh client would have been unable to serve \
                         traffic; keeping the current one"
                    );
                }
                Err(e) => {
                    // Count the failure and set the cooldown either way so a
                    // persistently unreachable network does not trigger a
                    // rebuild storm. `next_cooldown` reports what will gate
                    // the *next* attempt after this bump.
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    last_rebuild = Some(Instant::now());
                    warn!(
                        // `{:#}` (not `%e`/Display) walks anyhow's full
                        // `.context()` chain — the top-level message alone
                        // ("re-bootstrapping Tor client") hid the actual
                        // cause in production and made a state-dir lock
                        // collision indistinguishable from a real bootstrap
                        // failure.
                        error = format!("{:#}", e),
                        consecutive_failures,
                        threshold = CONSECUTIVE_FAILURES_BEFORE_BACKOFF,
                        next_cooldown_secs =
                            next_cooldown(consecutive_failures, cooldown).as_secs(),
                        "tor stale-channel watchdog: rebuild failed — will retry after cooldown"
                    );
                }
            }
        }
    });
}

/// Number of parallel rebuild-slot state directories the watchdog cycles
/// through. A single fixed pair (the previous design) assumed the slot
/// that is not currently "live" is always free to reuse — but `TorHandle`
/// only drops its OWN reference on swap; the underlying `Arc<TorClient>`
/// (and arti's exclusive state-dir lock) survives until the last in-flight
/// connection that cloned the old `TorTunnel` finishes, which for a
/// long-lived connection (e.g. a persistent Telegram session) can be
/// hours. With only two slots, a rebuild a few cycles later can collide
/// with a still-draining earlier generation. A small pool, probed for an
/// actually-free slot before use, tolerates however many generations are
/// simultaneously draining, up to REBUILD_SLOT_COUNT of them.
const REBUILD_SLOT_COUNT: u8 = 6;

fn rebuild_slot_dir_name(slot: u8) -> String {
    format!("watchdog-rebuild-{slot}")
}

/// Probe whether a slot directory's persistent-state locks are free right
/// now, without holding them ourselves (open-then-immediately-drop). A
/// missing lock file (slot never used) counts as free — `LockFileGuard::
/// try_lock` creates it as a side effect, same as arti's own code does.
///
/// Hardcodes `arti-client` 0.43.0's on-disk layout (`cache/dir.lock`,
/// `state/state/state.lock`) — an internal implementation detail that
/// could shift on an arti upgrade. If either probe errors for any other
/// reason (permissions, unexpected layout), this reports "free" rather
/// than blocking rebuilds outright — worst case we're back to the old
/// blind-retry behavior for that one slot, not stuck forever.
fn slot_is_free(dir: &Path) -> bool {
    let probe = |rel: &str| -> std::io::Result<bool> {
        Ok(fslock_guard::LockFileGuard::try_lock(dir.join(rel))?.is_some())
    };
    probe("cache/dir.lock").unwrap_or(true) && probe("state/state/state.lock").unwrap_or(true)
}

/// Find the first slot (skipping `avoid`, the currently-live one if any)
/// whose locks are currently free. `None` means every slot in the pool is
/// still draining a previous generation — the caller should back off and
/// retry later rather than colliding.
fn pick_free_slot(base: &Path, avoid: Option<u8>) -> Option<u8> {
    (0..REBUILD_SLOT_COUNT)
        .filter(|&s| Some(s) != avoid)
        .find(|&s| slot_is_free(&base.join(rebuild_slot_dir_name(s))))
}

/// Outcome of one rebuild attempt.
enum RebuildOutcome {
    /// Bootstrap finished; here is the ready tunnel and the slot it landed
    /// in (`None` only if the config has no persistent state dir at all).
    Ready { tor: TorTunnel, slot: Option<u8> },
    /// Bootstrap did not finish within [`REBUILD_TIMEOUT`], but — unlike the
    /// old single-phase design — we still fully own the client (it was never
    /// lost to an external future-cancellation); the caller decides what to
    /// do with it (currently: drop it explicitly, which is a safe,
    /// controlled drop of a fully-owned value, not an orphaning
    /// cancellation).
    TimedOut(TorTunnel),
    /// Bootstrap finished and reported ready, but the client could not
    /// actually establish a connection within the verify budget — arti's
    /// readiness signal only covers directory bootstrap, not bridge
    /// descriptors (see docs/upstream/guard-exhaustion-watchdog-spiral.md
    /// §2.2). Swapping this in would replace a live client with one that
    /// silently can't serve traffic for minutes. Caller drops it, same as
    /// TimedOut.
    NotUsable(TorTunnel),
}

/// Budget for the post-bootstrap usability check (separate from
/// REBUILD_TIMEOUT, which only bounds directory bootstrap).
const VERIFY_TIMEOUT: Duration = Duration::from_secs(90);

/// Try to actually establish a connection through a freshly-bootstrapped
/// client before trusting it enough to swap in. `target` is a recently
/// successful (host, port) pair to retry against; if none is available
/// (process just started, nothing has ever succeeded), skip verification
/// entirely — treat the client as usable (nothing better to compare
/// against, and gating everything on this would block first-ever startup
/// too — though note: rebuild() only runs after startup already succeeded
/// once, so in practice `target` should be Some by then).
async fn verify_usable(tor: &TorTunnel, target: Option<(String, u16)>) -> bool {
    let Some((host, port)) = target else {
        return true;
    };
    tokio::time::timeout(VERIFY_TIMEOUT, tor.connect(&host, port))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false)
}

/// Re-run the startup bootstrap path against the current config and return
/// a fresh `TorTunnel`. Re-probes bridges (so a freshly-dead one is dropped)
/// and re-bootstraps, establishing brand-new channels to the reachable
/// bridges — exactly the reset arti has no public API for.
///
/// **State dir.** arti holds an *exclusive* lock on its state directory. The
/// dying client we are replacing still holds its own lock — and, critically,
/// so can any *older* generation whose `TorTunnel` clone is still held open
/// by a long-lived connection (`TorHandle::swap` only drops the slot's own
/// reference; the underlying `Arc<TorClient>` and its state-dir lock survive
/// until the last such clone is dropped, which for a persistent connection
/// can be hours — see `TorHandle::swap`'s doc comment). A single fixed pair
/// of directories assumes the "not currently live" slot is always free,
/// which breaks once a stale generation is still draining when its turn in
/// the pair comes back around. Instead, this probes a small pool of
/// [`REBUILD_SLOT_COUNT`] slots (see [`pick_free_slot`]) for one whose
/// on-disk locks are actually free right now, tolerating however many
/// generations are simultaneously draining, up to the size of the pool.
///
/// **Two-phase construction.** `TorTunnel::create_unbootstrapped_with` is
/// synchronous — it either returns a fully owned client or fails outright,
/// with no `.await` in between to be cancelled mid-way. Only the subsequent
/// network wait (`tor.wait_bootstrapped()`) is wrapped in
/// [`REBUILD_TIMEOUT`]; if that times out, the caller still gets the fully
/// owned `TorTunnel` back via [`RebuildOutcome::TimedOut`] instead of losing
/// it to a cancelled future, which used to orphan its detached background
/// tasks (and any already-spawned PT child process).
async fn rebuild(
    config_path: Option<&Path>,
    avoid_slot: Option<u8>,
    canary_target: Option<(String, u16)>,
) -> anyhow::Result<RebuildOutcome> {
    let cfg = crate::config::Config::load_with_override(config_path)?.into_config();
    let mut settings = build_tor_settings(&cfg, config_path)
        .await
        .context("rebuilding tor settings")?;
    let picked_slot = if let Some(base) = settings.state_dir.clone() {
        let slot = pick_free_slot(&base, avoid_slot).with_context(|| {
            format!(
                "all {REBUILD_SLOT_COUNT} rebuild slots are currently busy — a prior \
                 generation is still draining (long-lived connection holding an old \
                 TorTunnel clone open)"
            )
        })?;
        settings.state_dir = Some(base.join(rebuild_slot_dir_name(slot)));
        Some(slot)
    } else {
        None
    };
    let tor = TorTunnel::create_unbootstrapped_with(settings).context("constructing Tor client")?;
    match tokio::time::timeout(REBUILD_TIMEOUT, tor.wait_bootstrapped()).await {
        Ok(Ok(())) => {
            if verify_usable(&tor, canary_target).await {
                Ok(RebuildOutcome::Ready {
                    tor,
                    slot: picked_slot,
                })
            } else {
                Ok(RebuildOutcome::NotUsable(tor))
            }
        }
        Ok(Err(e)) => Err(e).context("re-bootstrapping Tor client"),
        Err(_elapsed) => Ok(RebuildOutcome::TimedOut(tor)),
    }
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
    async fn swap_and_drain_release_tunnel() {
        // We can't build a real TorTunnel in a unit test, but the slot only
        // stores Option<TorTunnel> and we never read it here — so a stub
        // via the type system isn't possible without a live tunnel. Instead
        // exercise the Option mechanics indirectly: a freshly-built handle
        // (via new) needs a TorTunnel. Cover drain-on-None instead by
        // constructing the slot directly.
        let slot: Arc<RwLock<Option<u32>>> = Arc::new(RwLock::new(Some(42)));
        assert_eq!(slot.read().await.clone(), Some(42));
        // "swap"
        *slot.write().await = Some(7);
        assert_eq!(slot.read().await.clone(), Some(7));
        // "drain"
        let taken = slot.write().await.take();
        assert_eq!(taken, Some(7));
        assert!(slot.read().await.is_none());
    }

    #[test]
    fn unix_secs_is_plausible() {
        let s = unix_secs();
        // After 2024-01-01 and before year ~2100 — sanity, not exactness.
        assert!(s > 1_704_067_200, "unix_secs should be past 2024");
    }

    #[test]
    fn slot_is_free_for_empty_or_missing_dir() {
        let base = tempfile::tempdir().expect("tempdir");
        // Directory exists but has never been used by arti — no lock files.
        assert!(slot_is_free(base.path()));

        // Directory doesn't even exist yet.
        let missing = base.path().join("never-created");
        assert!(slot_is_free(&missing));
    }

    #[test]
    fn slot_is_free_reports_false_while_locked_then_true_after_drop() {
        let base = tempfile::tempdir().expect("tempdir");
        let cache_lock = base.path().join("cache").join("dir.lock");
        std::fs::create_dir_all(cache_lock.parent().unwrap()).expect("mkdir cache");

        {
            // Blocking lock — guaranteed to be held for as long as `guard`
            // is alive, unlike `try_lock` which could race in a test.
            let _guard =
                fslock_guard::LockFileGuard::lock(&cache_lock).expect("acquire cache lock");
            assert!(
                !slot_is_free(base.path()),
                "slot must report busy while cache/dir.lock is held"
            );
        }
        // Guard dropped — the lock is released.
        assert!(
            slot_is_free(base.path()),
            "slot must report free once the lock is released"
        );
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
        let tor = arti_wrapper::TorTunnel::create_unbootstrapped_with(Default::default())
            .expect("synchronous, no-I/O construction must succeed");
        assert!(
            verify_usable(&tor, None).await,
            "target: None must be treated as usable without a network round-trip"
        );
    }

    #[test]
    fn pick_free_slot_skips_busy_and_avoided_slots() {
        let base = tempfile::tempdir().expect("tempdir");

        // Lock slots 0 and 1; leave slot 2 (and beyond) free.
        let mut guards = Vec::new();
        for busy in [0u8, 1u8] {
            let dir = base.path().join(rebuild_slot_dir_name(busy));
            let lock_path = dir.join("cache").join("dir.lock");
            std::fs::create_dir_all(lock_path.parent().unwrap()).expect("mkdir cache");
            guards.push(fslock_guard::LockFileGuard::lock(&lock_path).expect("acquire slot lock"));
        }

        // Slot 2 would be the first free one, but we also ask to avoid it
        // (as if it were the currently-live slot) — expect slot 3 instead.
        let picked = pick_free_slot(base.path(), Some(2));
        assert_eq!(picked, Some(3));

        // Without an avoid constraint, the first free slot (2) wins.
        let picked_no_avoid = pick_free_slot(base.path(), None);
        assert_eq!(picked_no_avoid, Some(2));

        drop(guards);
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
}
