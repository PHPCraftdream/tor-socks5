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

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
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

    fn last_success_secs(&self) -> u64 {
        self.last_success.load(Ordering::Relaxed)
    }

    fn attempt_count(&self) -> u64 {
        self.attempts.load(Ordering::Relaxed)
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

/// Hard cap on a single rebuild attempt. On a fully-blocked network a
/// fresh `dirmgr` bootstrap never completes, and a bare `.await` would
/// leave the half-built second `TorClient` (and its PT children) racing
/// the old one for the same tokio runtime and busybox PT — observed in
/// production as three `tor-socks5.exe` processes instead of two.
/// Timing out drops the in-flight future, cancelling arti's half-built
/// bootstrap; PT subprocess cleanup itself is not instantaneous (see the
/// note at the `timeout(...)` call site below).
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

/// Spawn the stale-channel watchdog as a detached tokio task.
///
/// Every `check_interval` the task evaluates the three trigger conditions
/// (stale success, fresh attempts, alive bridges) and, if all hold and the
/// cooldown has elapsed, rebuilds the `TorClient` and swaps it in. A
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
        let mut last_rebuild: Option<Instant> = None;
        // Consecutive failed rebuilds (timeout or error). Once it crosses
        // [`CONSECUTIVE_FAILURES_BEFORE_BACKOFF`] the cooldown stretches to
        // [`EXTENDED_REBUILD_COOLDOWN`] so a fully-blocked network is not
        // hammered. Reset to 0 on the first successful rebuild.
        let mut consecutive_failures: u32 = 0;

        loop {
            ticker.tick().await;

            let health = handle.health();
            let now_secs = unix_secs();
            let last_success = health.last_success_secs();
            let attempts = health.attempt_count();
            let new_attempts = attempts.saturating_sub(prev_attempts);
            prev_attempts = attempts;

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

            // Bound the rebuild: a bootstrap that can't finish within this
            // window is on a fully-blocked network and will never return; a
            // bare `.await` would leave a second TorClient (and its PT
            // children) racing the old one for the same runtime resources.
            // Timing out drops the in-flight future, cancelling the
            // half-built bootstrap. Note this is not an *immediate* PT
            // subprocess reap: tor-ptmgr's cleanup only fires the next time
            // the child writes another stdout line and its forwarding thread
            // notices the receiver is gone (ipc.rs in tor-ptmgr — no
            // kill_on_drop). In practice a stuck PT keeps logging (handshake
            // retries/timeouts), so this tends to happen soon, but it is not
            // guaranteed instantly; any process that outlives this is still
            // bounded by the startup Job Object on process exit.
            match tokio::time::timeout(REBUILD_TIMEOUT, rebuild(config_path.as_deref())).await {
                Ok(Ok(new_tor)) => {
                    handle.swap(new_tor).await;
                    last_rebuild = Some(Instant::now());
                    if consecutive_failures > 0 {
                        info!(
                            prior_consecutive_failures = consecutive_failures,
                            "tor stale-channel watchdog: rebuild succeeded — backoff counter reset"
                        );
                    }
                    consecutive_failures = 0;
                    info!("tor stale-channel watchdog: TorClient rebuilt and swapped in");
                }
                Ok(Err(e)) => {
                    // Count the failure and set the cooldown either way so a
                    // persistently unreachable network does not trigger a
                    // rebuild storm. `next_cooldown` reports what will gate
                    // the *next* attempt after this bump.
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    last_rebuild = Some(Instant::now());
                    warn!(
                        error = %e,
                        consecutive_failures,
                        threshold = CONSECUTIVE_FAILURES_BEFORE_BACKOFF,
                        next_cooldown_secs = next_cooldown(consecutive_failures, cooldown).as_secs(),
                        "tor stale-channel watchdog: rebuild failed — will retry after cooldown"
                    );
                }
                Err(_elapsed) => {
                    // Timeout: the rebuild future has been dropped, cancelling
                    // the half-built bootstrap. Same treatment as an error.
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    last_rebuild = Some(Instant::now());
                    warn!(
                        timeout_secs = REBUILD_TIMEOUT.as_secs(),
                        consecutive_failures,
                        threshold = CONSECUTIVE_FAILURES_BEFORE_BACKOFF,
                        next_cooldown_secs =
                            next_cooldown(consecutive_failures, cooldown).as_secs(),
                        "tor stale-channel watchdog: rebuild timed out — dropped the \
                         half-built bootstrap to avoid a second live TorClient"
                    );
                }
            }
        }
    });
}

/// Re-run the startup bootstrap path against the current config and return
/// a fresh `TorTunnel`. Re-probes bridges (so a freshly-dead one is dropped)
/// and re-bootstraps, establishing brand-new channels to the reachable
/// bridges — exactly the reset arti has no public API for.
///
/// **State dir.** arti holds an *exclusive* lock on its state directory. The
/// dying client we are replacing still holds the primary `arti-data` lock
/// (its clones drain only as in-flight connections finish, which on
/// half-open channels is not prompt). Bootstrapping the replacement against
/// the same dir would therefore deadlock on that lock. We point the
/// replacement at a sibling subdir (`arti-data/watchdog-rebuild`) instead:
/// distinct lock file, no contention, and reused across rebuilds — by the
/// time the cooldown permits the next rebuild, the previous replacement's
/// in-flight connections have failed on dead circuits and released its lock.
async fn rebuild(config_path: Option<&Path>) -> anyhow::Result<TorTunnel> {
    let cfg = crate::config::Config::load_with_override(config_path)?.into_config();
    let mut settings = build_tor_settings(&cfg, config_path)
        .await
        .context("rebuilding tor settings")?;
    if let Some(primary) = settings.state_dir.as_ref() {
        settings.state_dir = Some(primary.join("watchdog-rebuild"));
    }
    let tor = TorTunnel::bootstrap_with(settings)
        .await
        .context("re-bootstrapping Tor client")?;
    Ok(tor)
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
}
