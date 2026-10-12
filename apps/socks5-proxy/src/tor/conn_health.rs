//! Periodic connection-health summary log.
//!
//! The accept loop (`server.rs`) already logs per-connection events (`new
//! connection`, `tor connection established`, and a `warn!` with a
//! [`crate::server::ConnErrorKind`] on failure) — useful for tracing a single
//! session, but too noisy to eyeball a trend from. This module adds a
//! second, much coarser signal: a handful of lock-free counters bumped
//! alongside those existing log lines, and a background task that, once per
//! configured interval, drains them into a single structured `info!` summary
//! and resets them to zero for the next window.
//!
//! ## Why a rolling window, not a lifetime total
//!
//! A lifetime total only ever grows, so a success rate computed from it
//! would flatten out any real degradation under a long-running process's
//! history (a bad hour buried under a month of good ones reads as "still
//! healthy"). Resetting the counters after every summary — via
//! `swap(0, Ordering::Relaxed)` — means each log line describes exactly the
//! window since the previous one, so a trend is visible tick to tick.
//!
//! ## Why atomics, not a `Mutex`
//!
//! Every counter here is an independent monotonic increment from the hot
//! accept-loop path, read (and reset) only by this module's own background
//! task at a slow, fixed cadence. That is exactly the case `AtomicU64`
//! exists for — no read-modify-write invariant spans more than one counter,
//! so there is nothing a `Mutex` would protect that `Ordering::Relaxed`
//! doesn't already give us for free.
//!
//! ## Counter inventory
//!
//! Windowed event counters (reset by every snapshot): `started` (connections
//! accepted), `connect_ok` / `connect_failed` (CONNECT-stage outcomes),
//! `relay_closed` / `relay_errors` (data-transfer-stage outcomes), and
//! `client_errors` / `tor_errors` / `other_errors` (failures by attribution
//! kind; a connect-stage failure is also counted in `connect_failed` via
//! [`ConnHealthCounters::record_failure`]). Plus one gauge: `pending`, the
//! number of accepted-but-not-yet-finished connections, which is *read* but
//! never reset — in-flight connections do not vanish at a window boundary.
//!
//! This counter set implements the stability review's P2 metrics finding:
//! the summary now reflects real data-transfer outcomes (`relay_closed` vs
//! `relay_errors`) instead of only CONNECT success, so a proxy with 100%
//! CONNECT success and a relay layer that resets every connection is
//! immediately visible.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tracing::info;

use crate::config::ConnHealthConfig;
use crate::server::{ConnErrorKind, ConnStage};

/// Snapshot of one summary window, returned by [`ConnHealthCounters::
/// snapshot_and_reset`].
///
/// All fields except `pending` are windowed event counts (reset by the
/// snapshot); `pending` is the live in-flight gauge and is deliberately NOT
/// reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct ConnHealthSnapshot {
    pub started: u64,
    pub connect_ok: u64,
    pub connect_failed: u64,
    pub relay_closed: u64,
    pub relay_errors: u64,
    pub client_errors: u64,
    pub tor_errors: u64,
    pub other_errors: u64,
    /// Gauge of currently in-flight connections — read but never reset by
    /// [`ConnHealthCounters::snapshot_and_reset`].
    pub pending: u64,
}

impl ConnHealthSnapshot {
    /// True iff every *windowed* field is zero.
    ///
    /// `pending` is deliberately EXCLUDED from this check: it is a gauge, not
    /// an event. A window whose only activity is still-open connections has
    /// no events to report — the per-connection logs already show those
    /// connections, and re-logging an identical pending count every tick
    /// would be noise.
    pub fn is_empty(&self) -> bool {
        self.started == 0
            && self.connect_ok == 0
            && self.connect_failed == 0
            && self.relay_closed == 0
            && self.relay_errors == 0
            && self.client_errors == 0
            && self.tor_errors == 0
            && self.other_errors == 0
    }

    /// `connect_ok / (connect_ok + connect_failed)` as an integer percentage
    /// (0-100), or `None` when no CONNECT stage completed in the window.
    ///
    /// The denominator is the *completion cohort* (ok + failed), not
    /// `started`: a connection started in window N may complete in window
    /// N+1, so blending starts and completions would mix cohorts and corrupt
    /// the percentage. `None` (rather than `0` or `100`) when the window saw
    /// no completed connects — an idle window is not "0% healthy"
    /// (misleadingly alarming) nor "100% healthy" (a made-up number with no
    /// underlying completions to back it).
    pub fn connect_success_rate_pct(&self) -> Option<u8> {
        let completed = self.connect_ok.checked_add(self.connect_failed)?;
        if completed == 0 {
            return None;
        }
        let pct = (self.connect_ok as u128 * 100) / completed as u128;
        Some(pct.min(100) as u8)
    }
}

/// RAII guard returned by [`ConnHealthCounters::record_started`]: dropping it
/// decrements the `pending` gauge. The decrement is paired one-to-one with
/// the `fetch_add` in `record_started`, so underflow cannot happen. Move it into the
/// per-connection task so the decrement happens wherever that task ends —
/// error, success, or panic (a panic unwinds through `Drop`, making the
/// gauge robust against task aborts).
pub(crate) struct PendingConnectionGuard {
    counters: ConnHealthCounters,
}
impl Drop for PendingConnectionGuard {
    fn drop(&mut self) {
        self.counters.pending.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Shared, lock-free counters bumped from the SOCKS5 accept loop and drained
/// by the periodic summary task. Cheap to clone (ten atomics behind an
/// `Arc`).
#[derive(Clone, Default)]
pub struct ConnHealthCounters {
    started: Arc<AtomicU64>,
    pending: Arc<AtomicU64>,
    connect_ok: Arc<AtomicU64>,
    connect_failed: Arc<AtomicU64>,
    relay_closed: Arc<AtomicU64>,
    relay_errors: Arc<AtomicU64>,
    client_errors: Arc<AtomicU64>,
    tor_errors: Arc<AtomicU64>,
    other_errors: Arc<AtomicU64>,
}

impl ConnHealthCounters {
    /// Record an accepted connection: bumps the `started` event counter,
    /// bumps the `pending` gauge, and returns an RAII guard whose drop
    /// decrements `pending`. The guard must be moved into the
    /// per-connection task so the gauge tracks in-flight connections
    /// regardless of how the task ends.
    pub fn record_started(&self) -> PendingConnectionGuard {
        self.started.fetch_add(1, Ordering::Relaxed);
        self.pending.fetch_add(1, Ordering::Relaxed);
        PendingConnectionGuard {
            counters: self.clone(),
        }
    }

    /// Bump the CONNECT-stage-success counter. Called alongside the
    /// existing `info!("tor connection established")` log.
    pub fn record_connect_ok(&self) {
        self.connect_ok.fetch_add(1, Ordering::Relaxed);
    }

    /// Bump the CONNECT-stage-failure counter.
    pub fn record_connect_failed(&self) {
        self.connect_failed.fetch_add(1, Ordering::Relaxed);
    }

    /// Bump the relay-stage-completed-without-error counter.
    pub fn record_relay_closed(&self) {
        self.relay_closed.fetch_add(1, Ordering::Relaxed);
    }

    /// Bump the counter matching `kind`. Called alongside the existing
    /// `warn!("connection finished with error")` log, right after
    /// `classify_conn_failure` has already produced `kind` for that log
    /// line — no re-classification needed here.
    pub fn record_error(&self, kind: ConnErrorKind) {
        let counter = match kind {
            ConnErrorKind::Client => &self.client_errors,
            ConnErrorKind::Tor => &self.tor_errors,
            ConnErrorKind::Relay => &self.relay_errors,
            ConnErrorKind::Other => &self.other_errors,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a failed connection: bumps the counter matching `kind`, and —
    /// when the failure happened at the CONNECT stage — additionally bumps
    /// `connect_failed` so the CONNECT success rate is complete for failures
    /// of any error kind (client, Tor, relay, or other).
    pub fn record_failure(&self, stage: ConnStage, kind: ConnErrorKind) {
        self.record_error(kind);
        if stage == ConnStage::Connect {
            self.record_connect_failed();
        }
    }

    /// Read every windowed counter and reset it to `0` in one pass,
    /// returning the values seen since the previous call (or since
    /// construction, for the first call). The `pending` gauge is read but
    /// NOT reset — in-flight connections do not vanish at a window boundary.
    ///
    /// Each windowed counter's read-then-reset is independently atomic
    /// (`swap`), but the ten are not read as a single joint snapshot — a
    /// counter bumped by the accept loop in the narrow gap between two of
    /// these `swap` calls is attributed to whichever window's `swap` runs
    /// after it. That is an acceptable, unavoidable race for a coarse
    /// periodic summary (at most one event misattributed to the neighboring
    /// window out of however many the window covers) and not worth a `Mutex`
    /// to close.
    pub(crate) fn snapshot_and_reset(&self) -> ConnHealthSnapshot {
        ConnHealthSnapshot {
            started: self.started.swap(0, Ordering::Relaxed),
            connect_ok: self.connect_ok.swap(0, Ordering::Relaxed),
            connect_failed: self.connect_failed.swap(0, Ordering::Relaxed),
            relay_closed: self.relay_closed.swap(0, Ordering::Relaxed),
            relay_errors: self.relay_errors.swap(0, Ordering::Relaxed),
            client_errors: self.client_errors.swap(0, Ordering::Relaxed),
            tor_errors: self.tor_errors.swap(0, Ordering::Relaxed),
            other_errors: self.other_errors.swap(0, Ordering::Relaxed),
            pending: self.pending.load(Ordering::Relaxed),
        }
    }
}

/// Spawn the periodic connection-health summary task as a detached tokio
/// task.
///
/// Every `interval_secs` the task drains [`ConnHealthCounters`] (resetting
/// them for the next window — see [`ConnHealthCounters::snapshot_and_reset`])
/// and logs one structured `info!` line with the raw counts and, when
/// computable, a `connect_rate_pct`. A window is skipped ONLY if it contains
/// no events at all ([`ConnHealthSnapshot::is_empty`]) — an interval in which
/// only OLD connections finished (relay completions or errors, no new
/// accepts) is still logged.
///
/// Connect-rate semantics: the rate is over *completions* in the window
/// (`connect_ok + connect_failed` is a self-consistent completion cohort). A
/// connection started in window N and completing in window N+1 is counted as
/// a completion in N+1; the gap `started - connect_ok - connect_failed` makes
/// cross-window skew visible instead of corrupting one blended percentage.
/// `cfg.enabled == false` or `interval_secs == 0` disables the task entirely.
pub fn spawn_conn_health_logger(counters: ConnHealthCounters, cfg: ConnHealthConfig) {
    if !cfg.enabled || cfg.interval_secs == 0 {
        info!("conn-health summary disabled");
        return;
    }

    let interval = Duration::from_secs(cfg.interval_secs);
    info!(
        interval_secs = cfg.interval_secs,
        "conn-health summary armed"
    );

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await; // consume the immediate first tick

        loop {
            ticker.tick().await;

            let snap = counters.snapshot_and_reset();
            if snap.is_empty() {
                // No events at all this window — nothing meaningful to
                // report. (A nonzero `pending` alone does not count as an
                // event; see `is_empty`'s doc.)
                continue;
            }

            let connect_rate_pct = snap.connect_success_rate_pct();
            info!(
                started = snap.started,
                pending = snap.pending,
                connect_ok = snap.connect_ok,
                connect_failed = snap.connect_failed,
                relay_closed = snap.relay_closed,
                relay_errors = snap.relay_errors,
                client_errors = snap.client_errors,
                tor_errors = snap.tor_errors,
                other_errors = snap.other_errors,
                connect_rate_pct = ?connect_rate_pct,
                "conn health"
            );
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_counters_snapshot_to_all_zero() {
        let counters = ConnHealthCounters::default();
        let snap = counters.snapshot_and_reset();
        assert_eq!(snap, ConnHealthSnapshot::default());
        assert_eq!(snap.connect_success_rate_pct(), None);
        assert!(snap.is_empty());
    }

    #[test]
    fn counters_accumulate_independently() {
        let counters = ConnHealthCounters::default();
        for _ in 0..5 {
            let _guard = counters.record_started();
        }
        for _ in 0..3 {
            counters.record_connect_ok();
        }
        counters.record_failure(ConnStage::Connect, ConnErrorKind::Client);
        counters.record_failure(ConnStage::Connect, ConnErrorKind::Client);
        counters.record_failure(ConnStage::Connect, ConnErrorKind::Tor);
        counters.record_error(ConnErrorKind::Other);

        let snap = counters.snapshot_and_reset();
        assert_eq!(snap.started, 5);
        assert_eq!(snap.connect_ok, 3);
        assert_eq!(snap.connect_failed, 3);
        assert_eq!(snap.client_errors, 2);
        assert_eq!(snap.tor_errors, 1);
        assert_eq!(snap.other_errors, 1);
    }

    #[test]
    fn snapshot_resets_counters_to_zero() {
        let counters = ConnHealthCounters::default();
        drop(counters.record_started());
        counters.record_connect_ok();
        counters.record_error(ConnErrorKind::Tor);

        let first = counters.snapshot_and_reset();
        assert_eq!(first.started, 1);
        assert_eq!(first.connect_ok, 1);
        assert_eq!(first.tor_errors, 1);

        // Nothing recorded in between — the next snapshot must read all
        // zeros, proving the previous call actually reset the counters
        // rather than just reading them.
        let second = counters.snapshot_and_reset();
        assert_eq!(second, ConnHealthSnapshot::default());
    }

    #[test]
    fn snapshot_after_reset_only_reflects_new_activity() {
        let counters = ConnHealthCounters::default();
        drop(counters.record_started());
        let _ = counters.snapshot_and_reset();

        drop(counters.record_started());
        drop(counters.record_started());
        counters.record_connect_ok();

        let snap = counters.snapshot_and_reset();
        assert_eq!(snap.started, 2, "must not include the pre-reset attempt");
        assert_eq!(snap.connect_ok, 1);
    }

    #[test]
    fn pending_gauge_is_not_reset_by_snapshot() {
        let counters = ConnHealthCounters::default();
        let _guard = counters.record_started();
        let snap = counters.snapshot_and_reset();
        assert_eq!(snap.started, 1, "event counter is windowed");
        assert_eq!(snap.pending, 1, "gauge survives the window boundary");
        let snap2 = counters.snapshot_and_reset();
        assert_eq!(snap2.started, 0);
        assert_eq!(snap2.pending, 1, "still in flight — gauge not reset");
    }

    #[test]
    fn connection_spanning_two_windows_is_counted_once() {
        let counters = ConnHealthCounters::default();
        let guard = counters.record_started();

        let snap1 = counters.snapshot_and_reset();
        assert_eq!(snap1.started, 1);
        assert_eq!(snap1.connect_ok, 0);
        assert_eq!(snap1.relay_closed, 0);

        // The connection finishes only after the window boundary.
        counters.record_connect_ok();
        counters.record_relay_closed();
        drop(guard);

        let snap2 = counters.snapshot_and_reset();
        assert_eq!(snap2.started, 0, "started belongs to window 1 only");
        assert_eq!(snap2.connect_ok, 1);
        assert_eq!(snap2.relay_closed, 1);
    }

    #[test]
    fn window_without_new_starts_still_reports_relay_completions() {
        let counters = ConnHealthCounters::default();
        let guard = counters.record_started();
        let _ = counters.snapshot_and_reset();

        // An OLD connection finishes in this window; no new accepts.
        counters.record_relay_closed();
        counters.record_error(ConnErrorKind::Relay);
        drop(guard);

        let snap2 = counters.snapshot_and_reset();
        assert_eq!(snap2.started, 0);
        assert_eq!(snap2.relay_closed, 1);
        assert_eq!(snap2.relay_errors, 1);
        assert!(
            !snap2.is_empty(),
            "relay-only window must be logged, not skipped"
        );
    }

    #[test]
    fn is_empty_fresh_snapshot_is_empty() {
        assert!(ConnHealthSnapshot::default().is_empty());
    }

    #[test]
    fn is_empty_pending_only_is_still_empty() {
        // The gauge is deliberately excluded: pending-only windows have no
        // events to report.
        let snap = ConnHealthSnapshot {
            pending: 3,
            ..Default::default()
        };
        assert!(snap.is_empty());
    }

    #[test]
    fn is_empty_relay_errors_only_is_not_empty() {
        let snap = ConnHealthSnapshot {
            relay_errors: 1,
            ..Default::default()
        };
        assert!(!snap.is_empty());
    }

    #[test]
    fn pending_gauge_tracks_in_flight_and_guard_releases() {
        let counters = ConnHealthCounters::default();
        let g1 = counters.record_started();
        let g2 = counters.record_started();
        assert_eq!(counters.snapshot_and_reset().pending, 2);
        drop(g1);
        drop(g2);
        assert_eq!(counters.snapshot_and_reset().pending, 0);
    }

    #[test]
    fn connect_success_rate_pct_none_when_no_completed_connects() {
        let snap = ConnHealthSnapshot::default();
        assert_eq!(snap.connect_success_rate_pct(), None);
    }

    #[test]
    fn connect_success_rate_pct_all_succeeded_is_100() {
        let snap = ConnHealthSnapshot {
            started: 10,
            connect_ok: 10,
            ..Default::default()
        };
        assert_eq!(snap.connect_success_rate_pct(), Some(100));
    }

    #[test]
    fn connect_success_rate_pct_all_failed_is_zero() {
        let snap = ConnHealthSnapshot {
            started: 10,
            connect_failed: 10,
            client_errors: 10,
            ..Default::default()
        };
        assert_eq!(snap.connect_success_rate_pct(), Some(0));
    }

    #[test]
    fn connect_success_rate_pct_partial_rounds_down() {
        // 1/3 = 33.33...% — integer division must floor, not round.
        let snap = ConnHealthSnapshot {
            connect_ok: 1,
            connect_failed: 2,
            ..Default::default()
        };
        assert_eq!(snap.connect_success_rate_pct(), Some(33));
    }

    #[test]
    fn connect_success_rate_pct_ignores_started_without_completions() {
        // 5 started but only 3 completed connects in this window: the rate
        // is over the completion cohort (2/3 = 66), NOT over starts (2/5 =
        // 40). Blending cohorts would corrupt the number when connections
        // straddle a window boundary.
        let snap = ConnHealthSnapshot {
            started: 5,
            connect_ok: 2,
            connect_failed: 1,
            ..Default::default()
        };
        assert_eq!(snap.connect_success_rate_pct(), Some(66));
    }

    #[test]
    fn connect_success_rate_pct_caps_at_100() {
        // Defensive: the percentage is clamped at 100 — it can never exceed
        // it because the denominator is exactly ok+failed.
        let snap = ConnHealthSnapshot {
            connect_ok: 7,
            connect_failed: 3,
            ..Default::default()
        };
        assert_eq!(snap.connect_success_rate_pct(), Some(70));
        let snap = ConnHealthSnapshot {
            connect_ok: u64::MAX,
            connect_failed: 0,
            ..Default::default()
        };
        assert_eq!(snap.connect_success_rate_pct(), Some(100));
    }

    #[test]
    fn record_error_relay_lands_in_relay_errors() {
        let counters = ConnHealthCounters::default();
        counters.record_error(ConnErrorKind::Relay);
        let snap = counters.snapshot_and_reset();
        assert_eq!(snap.relay_errors, 1);
        assert_eq!(snap.client_errors, 0);
        assert_eq!(snap.tor_errors, 0);
        assert_eq!(snap.other_errors, 0);
    }

    #[test]
    fn record_failure_connect_stage_bumps_connect_failed() {
        let counters = ConnHealthCounters::default();
        counters.record_failure(ConnStage::Connect, ConnErrorKind::Tor);
        counters.record_failure(ConnStage::Relay, ConnErrorKind::Relay);
        let snap = counters.snapshot_and_reset();
        assert_eq!(snap.connect_failed, 1, "only the Connect-stage failure");
        assert_eq!(
            snap.relay_errors, 1,
            "Relay-stage failure lands in relay_errors"
        );
    }

    #[test]
    fn disabled_config_does_not_panic_on_spawn() {
        // Smoke test: spawning with enabled=false (or interval=0) must
        // return immediately without spawning a task — nothing to await
        // here since the function is synchronous in that branch.
        let counters = ConnHealthCounters::default();
        spawn_conn_health_logger(
            counters.clone(),
            ConnHealthConfig {
                enabled: false,
                interval_secs: 60,
            },
        );
        spawn_conn_health_logger(
            counters,
            ConnHealthConfig {
                enabled: true,
                interval_secs: 0,
            },
        );
    }
}
