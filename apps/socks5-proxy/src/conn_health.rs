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
//! A lifetime total only ever grows, so a `success_rate_pct` computed from
//! it would flatten out any real degradation under a long-running process's
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

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tracing::info;

use crate::config::ConnHealthConfig;
use crate::server::ConnErrorKind;

/// Snapshot of one summary window, returned by [`ConnHealthCounters::
/// snapshot_and_reset`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct ConnHealthSnapshot {
    pub attempted: u64,
    pub established: u64,
    pub client_errors: u64,
    pub tor_errors: u64,
    pub other_errors: u64,
}

impl ConnHealthSnapshot {
    /// `established / attempted` as an integer percentage (0-100), or `None`
    /// when `attempted == 0`.
    ///
    /// Design choice: `None` (rather than defaulting to `0` or `100`) when
    /// the window saw no attempts at all — an idle proxy is not "0% healthy"
    /// (misleadingly alarming) nor "100% healthy" (a made-up number with no
    /// underlying attempts to back it). The caller ([`spawn_conn_health_logger`])
    /// skips the summary log entirely for an all-zero window, so this
    /// distinction only matters here and in tests.
    pub fn success_rate_pct(&self) -> Option<u8> {
        if self.attempted == 0 {
            return None;
        }
        let pct = (self.established as u128 * 100) / self.attempted as u128;
        Some(pct.min(100) as u8)
    }
}

/// Shared, lock-free counters bumped from the SOCKS5 accept loop and drained
/// by the periodic summary task. Cheap to clone (five atomics behind an
/// `Arc`).
#[derive(Clone, Default)]
pub struct ConnHealthCounters {
    attempted: Arc<AtomicU64>,
    established: Arc<AtomicU64>,
    client_errors: Arc<AtomicU64>,
    tor_errors: Arc<AtomicU64>,
    other_errors: Arc<AtomicU64>,
}

impl ConnHealthCounters {
    /// Bump the new-connection counter. Called alongside the existing
    /// `debug!("new connection")` log in the accept loop.
    pub fn record_attempt(&self) {
        self.attempted.fetch_add(1, Ordering::Relaxed);
    }

    /// Bump the established-through-Tor counter. Called alongside the
    /// existing `info!("tor connection established")` log.
    pub fn record_established(&self) {
        self.established.fetch_add(1, Ordering::Relaxed);
    }

    /// Bump the counter matching `kind`. Called alongside the existing
    /// `warn!("connection finished with error")` log, right after
    /// `classify_conn_error` has already produced `kind` for that log line —
    /// no re-classification needed here.
    pub fn record_error(&self, kind: ConnErrorKind) {
        let counter = match kind {
            ConnErrorKind::Client => &self.client_errors,
            ConnErrorKind::Tor => &self.tor_errors,
            ConnErrorKind::Other => &self.other_errors,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Read every counter and reset it to `0` in one pass, returning the
    /// values seen since the previous call (or since construction, for the
    /// first call). Each counter's read-then-reset is independently atomic
    /// (`swap`), but the five are not read as a single joint snapshot — a
    /// counter bumped by the accept loop in the narrow gap between two of
    /// these `swap` calls is attributed to whichever window's `swap` runs
    /// after it. That is an acceptable, unavoidable race for a coarse
    /// periodic summary (at most one event misattributed to the neighboring
    /// window out of however many the window covers) and not worth a `Mutex`
    /// to close.
    pub(crate) fn snapshot_and_reset(&self) -> ConnHealthSnapshot {
        ConnHealthSnapshot {
            attempted: self.attempted.swap(0, Ordering::Relaxed),
            established: self.established.swap(0, Ordering::Relaxed),
            client_errors: self.client_errors.swap(0, Ordering::Relaxed),
            tor_errors: self.tor_errors.swap(0, Ordering::Relaxed),
            other_errors: self.other_errors.swap(0, Ordering::Relaxed),
        }
    }
}

/// Spawn the periodic connection-health summary task as a detached tokio
/// task.
///
/// Every `interval_secs` the task drains [`ConnHealthCounters`] (resetting
/// them for the next window — see [`ConnHealthCounters::snapshot_and_reset`])
/// and logs one structured `info!` line with the raw counts and a derived
/// `success_rate_pct`. A window with zero attempts (`attempted == 0`, e.g. an
/// idle proxy) is skipped entirely rather than logged with a placeholder
/// rate — there is nothing to report, and logging "0 attempts, rate: ???"
/// every tick on an idle proxy would just be noise. `cfg.enabled == false` or
/// `interval_secs == 0` disables the task entirely.
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
            let Some(success_rate_pct) = snap.success_rate_pct() else {
                // No attempts this window — nothing meaningful to report.
                continue;
            };

            info!(
                attempted = snap.attempted,
                established = snap.established,
                client_errors = snap.client_errors,
                tor_errors = snap.tor_errors,
                other_errors = snap.other_errors,
                success_rate_pct,
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
        assert_eq!(snap.success_rate_pct(), None);
    }

    #[test]
    fn counters_accumulate_independently() {
        let counters = ConnHealthCounters::default();
        for _ in 0..5 {
            counters.record_attempt();
        }
        for _ in 0..3 {
            counters.record_established();
        }
        counters.record_error(ConnErrorKind::Client);
        counters.record_error(ConnErrorKind::Client);
        counters.record_error(ConnErrorKind::Tor);
        counters.record_error(ConnErrorKind::Other);

        let snap = counters.snapshot_and_reset();
        assert_eq!(snap.attempted, 5);
        assert_eq!(snap.established, 3);
        assert_eq!(snap.client_errors, 2);
        assert_eq!(snap.tor_errors, 1);
        assert_eq!(snap.other_errors, 1);
    }

    #[test]
    fn snapshot_resets_counters_to_zero() {
        let counters = ConnHealthCounters::default();
        counters.record_attempt();
        counters.record_established();
        counters.record_error(ConnErrorKind::Tor);

        let first = counters.snapshot_and_reset();
        assert_eq!(first.attempted, 1);
        assert_eq!(first.established, 1);
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
        counters.record_attempt();
        let _ = counters.snapshot_and_reset();

        counters.record_attempt();
        counters.record_attempt();
        counters.record_established();

        let snap = counters.snapshot_and_reset();
        assert_eq!(snap.attempted, 2, "must not include the pre-reset attempt");
        assert_eq!(snap.established, 1);
    }

    #[test]
    fn success_rate_pct_none_when_no_attempts() {
        let snap = ConnHealthSnapshot {
            attempted: 0,
            established: 0,
            client_errors: 0,
            tor_errors: 0,
            other_errors: 0,
        };
        assert_eq!(snap.success_rate_pct(), None);
    }

    #[test]
    fn success_rate_pct_all_succeeded_is_100() {
        let snap = ConnHealthSnapshot {
            attempted: 10,
            established: 10,
            ..Default::default()
        };
        assert_eq!(snap.success_rate_pct(), Some(100));
    }

    #[test]
    fn success_rate_pct_all_failed_is_zero() {
        let snap = ConnHealthSnapshot {
            attempted: 10,
            established: 0,
            client_errors: 10,
            ..Default::default()
        };
        assert_eq!(snap.success_rate_pct(), Some(0));
    }

    #[test]
    fn success_rate_pct_partial_rounds_down() {
        // 1/3 = 33.33...% — integer division must floor, not round.
        let snap = ConnHealthSnapshot {
            attempted: 3,
            established: 1,
            ..Default::default()
        };
        assert_eq!(snap.success_rate_pct(), Some(33));
    }

    #[test]
    fn success_rate_pct_never_exceeds_100() {
        // Defensive: established should never outnumber attempted in
        // practice (each success also bumped attempted), but the helper
        // must not panic or overflow past 100 if it ever does via a
        // misattributed-window race (see `snapshot_and_reset`'s doc
        // comment).
        let snap = ConnHealthSnapshot {
            attempted: 2,
            established: 5,
            ..Default::default()
        };
        assert_eq!(snap.success_rate_pct(), Some(100));
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
