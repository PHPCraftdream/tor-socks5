//! Hosted-service status: one snapshot (`OnionHostStatus`) of every service
//! the host manages, published through a single `tokio::sync::watch` slot
//! (one slot, no unbounded channels, no loss concerns: subscribers always
//! see the latest state).
//!
//! R2/R4 semantics: updates never block and never queue — [`StatusTracker`]
//! uses `send_modify`, so an update works even with zero receivers, and a
//! receiver's `changed()` only ever reports "the snapshot changed".

use std::collections::BTreeMap;
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::Instant;
use tor_hsservice::status::{DescUploadRetryError, Problem};

/// Snapshot of every service the host manages, keyed by nickname.
///
/// A service that could not start at all (identity settlement failed, or it
/// never got as far as a manager) appears with [`ServiceStatus::Failed`];
/// cancellation before startup appears as [`ServiceStatus::Stopped`].
/// [`ServiceState::failure`] records a typed reason where available.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OnionHostStatus {
    /// One entry per enabled service, keyed by its nickname.
    pub services: BTreeMap<String, ServiceState>,
}

/// Lifecycle status of one hosted service.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ServiceStatus {
    /// The host is settling the service's identity (before any launch).
    #[default]
    Preparing,
    /// The service is waiting for one of at most 4 launch slots.
    WaitingForSlot,
    /// Launched; the `.onion` address is available and the service is
    /// bootstrapping its descriptor publication.
    Bootstrapping,
    /// The service reports itself reachable.
    Running,
    /// Reachable, but degraded (per arti's own status stream).
    DegradedReachable,
    /// Unreachable and degraded; arti is attempting recovery.
    DegradedUnreachable,
    /// Unreachable; arti is attempting recovery.
    Recovering,
    /// The service reports itself broken.
    Broken,
    /// The manager stopped the service (shutdown/cancellation).
    Stopped,
    /// The service failed and will not be retried.
    Failed,
}

/// The state of one hosted service: its lifecycle status plus, for
/// [`ServiceStatus::Failed`], the typed reason.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServiceState {
    /// The lifecycle status.
    pub status: ServiceStatus,
    /// Why the service failed, when a single typed reason fits.
    pub failure: Option<ServiceFailure>,
}

/// Typed failure reasons reported for a service that could not be hosted.
/// Human-readable detail stays in the log, never key material.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ServiceFailure {
    /// The configured nickname is not a valid Tor hidden-service nickname.
    #[error("onion service nickname is invalid")]
    InvalidNickname,
    /// The service configuration is invalid (e.g. arti rejected the built
    /// `OnionServiceConfig`).
    #[error("the onion service configuration is invalid")]
    InvalidConfig,
    /// The Tor client refused to launch the service at all.
    #[error("the onion service was rejected by the Tor client")]
    RejectedByTorClient,
    /// The `.onion` address never appeared within the wait budget.
    #[error("the .onion address never became available within {limit:?}")]
    AddressUnavailable {
        /// The total wait budget that elapsed.
        limit: std::time::Duration,
    },
    /// The service's entry disappeared from the current onion services file.
    #[error("the onion service is no longer in the onion services file")]
    EntryMissingFromFile,
    /// The service's identity key changed after the host loaded its snapshot.
    #[error("the onion service identity changed after configuration was loaded")]
    IdentityChanged,
    /// Identity preparation or host worker failed unexpectedly.
    #[error("internal onion service host failure")]
    Internal,
    /// The configured `.onion` address does not match the address Arti launched.
    #[error("launched onion service address does not match the configured address")]
    AddressMismatch,
    /// The onion keystore could not be opened for identity preparation.
    #[error("the onion keystore is unavailable")]
    KeystoreUnavailable,
    /// Another process holds the onion keystore lock, so nothing was hosted.
    #[error("the onion keystore lock is held elsewhere")]
    KeystoreLockHeld,
    /// The configured keystore directory does not match the running client's
    /// keystore, so keys written there would never be read by arti.
    #[error("the configured onion keystore does not match the running client's keystore")]
    KeystoreMismatch,
}

/// Internal clonable updater sharing one `watch::Sender<OnionHostStatus>`.
///
/// `set()` uses `send_replace`-style updates so it works with zero
/// receivers; a set for an unknown nickname is silently ignored (the
/// nickname set is fixed at construction).
pub(crate) struct StatusTracker {
    sender: watch::Sender<OnionHostStatus>,
}

impl Clone for StatusTracker {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl StatusTracker {
    /// A tracker whose snapshot lists every `nicknames` as [`ServiceStatus::Preparing`].
    pub(crate) fn new(nicknames: impl IntoIterator<Item = String>) -> Self {
        let services = nicknames
            .into_iter()
            .map(|nick| (nick, ServiceState::default()))
            .collect();
        let (sender, _receiver) = watch::channel(OnionHostStatus { services });
        Self { sender }
    }

    /// Replace the state of `nickname`. Ignored for nicknames that were not
    /// given at construction (the nickname set is fixed at construction).
    pub(crate) fn set(&self, nickname: &str, state: ServiceState) {
        self.sender.send_modify(|status| {
            if let Some(entry) = status.services.get_mut(nickname) {
                *entry = state;
            }
        });
    }

    /// Mark every service as `Failed` with `failure` when a host-wide error
    /// prevents preparation or hosting.
    pub(crate) fn set_all(&self, failure: ServiceFailure) {
        self.sender.send_modify(|status| {
            for state in status.services.values_mut() {
                *state = ServiceState {
                    status: ServiceStatus::Failed,
                    failure: Some(failure.clone()),
                };
            }
        });
    }

    /// A receiver for the shared snapshot.
    pub(crate) fn subscribe(&self) -> watch::Receiver<OnionHostStatus> {
        self.sender.subscribe()
    }
}

/// Seconds as a log field, rounded to 0.1 s.
pub(crate) fn secs(duration: Duration) -> f64 {
    (duration.as_secs_f64() * 10.0).round() / 10.0
}

/// Seconds since `start`, rounded to 0.1 s.
pub(crate) fn secs_since(start: Instant) -> f64 {
    secs(start.elapsed())
}

/// `error` and every error in its `source()` chain, joined by `": "`: arti's
/// top-level messages (e.g. "Could not connect rendezvous circuit.") hide the
/// cause.
pub(crate) fn error_chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

/// One-line account of arti's current problem with a service (arti's `Problem`
/// has no `Display`). Counts only: the per-HsDir detail is arti's own log.
pub(crate) fn problem_summary(problem: Option<&Problem>) -> String {
    match problem {
        None => "none".to_owned(),
        Some(Problem::Runtime(error)) => format!("fatal: {error}"),
        Some(Problem::DescriptorUpload(failures)) => {
            let (mut timed_out, mut fatal, mut exhausted, mut other) = (0, 0, 0, 0);
            for failure in failures {
                match failure {
                    DescUploadRetryError::Timeout(_) => timed_out += 1,
                    DescUploadRetryError::FatalError(_) => fatal += 1,
                    DescUploadRetryError::MaxRetryCountExceeded(_) => exhausted += 1,
                    _ => other += 1,
                }
            }
            format!(
                "descriptor upload failed for {} HsDirs (timed out {timed_out}, \
                 fatal {fatal}, retries exhausted {exhausted}, other {other})",
                failures.len()
            )
        }
        Some(Problem::Ipt(failures)) => format!("introduction points: {} failed", failures.len()),
        Some(_) => "other".to_owned(),
    }
}

/// Services per lifecycle bucket, for the startup log lines.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct StatusTally {
    /// Preparing or waiting for a launch slot.
    pub(crate) waiting: usize,
    /// Launched, no status from arti yet.
    pub(crate) bootstrapping: usize,
    pub(crate) running: usize,
    pub(crate) degraded: usize,
    /// Unreachable or recovering.
    pub(crate) unreachable: usize,
    pub(crate) broken: usize,
    /// Stopped or failed.
    pub(crate) ended: usize,
}

impl StatusTally {
    /// Services that have not reported a status yet.
    pub(crate) fn pending(&self) -> usize {
        self.waiting + self.bootstrapping
    }
}

impl OnionHostStatus {
    /// Count the services per lifecycle bucket.
    pub(crate) fn tally(&self) -> StatusTally {
        let mut tally = StatusTally::default();
        for state in self.services.values() {
            match state.status {
                ServiceStatus::Preparing | ServiceStatus::WaitingForSlot => tally.waiting += 1,
                ServiceStatus::Bootstrapping => tally.bootstrapping += 1,
                ServiceStatus::Running => tally.running += 1,
                ServiceStatus::DegradedReachable => tally.degraded += 1,
                ServiceStatus::DegradedUnreachable | ServiceStatus::Recovering => {
                    tally.unreachable += 1;
                }
                ServiceStatus::Broken => tally.broken += 1,
                ServiceStatus::Stopped | ServiceStatus::Failed => tally.ended += 1,
            }
        }
        tally
    }
}

/// The progress line repeats at most this often while services still start.
const PROGRESS_EVERY: Duration = Duration::from_secs(15);

/// A line the host logs about its startup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StartupLine {
    /// Some services have not reported a status yet.
    Progress {
        elapsed: Duration,
        tally: StatusTally,
    },
    /// Every service has reported once. `median` and `slowest` are the times
    /// to the first report (the upper median for an even count).
    Done {
        elapsed: Duration,
        tally: StatusTally,
        median: Duration,
        slowest: Duration,
    },
}

/// Turns status snapshots into the startup log lines. Event-driven (no
/// timers): the caller feeds it a snapshot at every change.
pub(crate) struct StartupReport {
    started: Instant,
    last_progress: Instant,
    first_report: BTreeMap<String, Duration>,
    done: bool,
}

impl StartupReport {
    pub(crate) fn new(started: Instant) -> Self {
        Self {
            started,
            last_progress: started,
            first_report: BTreeMap::new(),
            done: false,
        }
    }

    /// Feed one snapshot taken at `now`; returns the line to log, if any.
    pub(crate) fn observe(
        &mut self,
        snapshot: &OnionHostStatus,
        now: Instant,
    ) -> Option<StartupLine> {
        if self.done {
            return None;
        }
        let elapsed = now.saturating_duration_since(self.started);
        for (nickname, state) in &snapshot.services {
            if !matches!(
                state.status,
                ServiceStatus::Preparing
                    | ServiceStatus::WaitingForSlot
                    | ServiceStatus::Bootstrapping
            ) {
                self.first_report.entry(nickname.clone()).or_insert(elapsed);
            }
        }
        let tally = snapshot.tally();
        if !snapshot.services.is_empty() && tally.pending() == 0 {
            self.done = true;
            let mut times: Vec<Duration> = self.first_report.values().copied().collect();
            times.sort();
            return Some(StartupLine::Done {
                elapsed,
                tally,
                median: times.get(times.len() / 2).copied().unwrap_or_default(),
                slowest: times.last().copied().unwrap_or_default(),
            });
        }
        if now.saturating_duration_since(self.last_progress) >= PROGRESS_EVERY {
            self.last_progress = now;
            return Some(StartupLine::Progress { elapsed, tally });
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tracker_publishes_snapshots_through_watch() {
        let tracker = StatusTracker::new(["web", "relay"].map(String::from));
        let mut rx = tracker.subscribe();

        // Everything starts Preparing.
        let snapshot = rx.borrow_and_update().clone();
        assert_eq!(snapshot.services.len(), 2);
        assert!(snapshot
            .services
            .values()
            .all(|state| state.status == ServiceStatus::Preparing));

        // A Failed update replaces only its own entry and is visible even
        // with the receiver subscribed later.
        tracker.set(
            "web",
            ServiceState {
                status: ServiceStatus::Failed,
                failure: Some(ServiceFailure::InvalidNickname),
            },
        );
        let snapshot = rx.borrow_and_update().clone();
        assert_eq!(
            snapshot.services["web"],
            ServiceState {
                status: ServiceStatus::Failed,
                failure: Some(ServiceFailure::InvalidNickname),
            }
        );
        assert_eq!(snapshot.services["relay"].status, ServiceStatus::Preparing);

        // Zero receivers: set still works.
        drop(rx);
        tracker.set_all(ServiceFailure::KeystoreLockHeld);
        let rx = tracker.subscribe();
        let snapshot = rx.borrow().clone();
        assert!(snapshot.services.values().all(|state| *state
            == ServiceState {
                status: ServiceStatus::Failed,
                failure: Some(ServiceFailure::KeystoreLockHeld),
            }));
    }

    #[test]
    fn unknown_nicknames_are_ignored() {
        let tracker = StatusTracker::new(["web"].map(String::from));
        tracker.set(
            "ghost",
            ServiceState {
                status: ServiceStatus::Running,
                failure: None,
            },
        );
        let snapshot = tracker.subscribe().borrow().clone();
        assert_eq!(snapshot.services.len(), 1);
        assert_eq!(snapshot.services["web"].status, ServiceStatus::Preparing);
    }

    fn snapshot(states: &[(&str, ServiceStatus)]) -> OnionHostStatus {
        OnionHostStatus {
            services: states
                .iter()
                .map(|(nickname, status)| {
                    (
                        (*nickname).to_owned(),
                        ServiceState {
                            status: *status,
                            failure: None,
                        },
                    )
                })
                .collect(),
        }
    }

    #[derive(Debug, thiserror::Error)]
    #[error("outer")]
    struct Outer(#[source] Middle);

    #[derive(Debug, thiserror::Error)]
    #[error("middle")]
    struct Middle(#[source] std::io::Error);

    #[test]
    fn the_error_chain_lists_every_cause() {
        let error = Outer(Middle(std::io::Error::other("root cause")));
        assert_eq!(error_chain(&error), "outer: middle: root cause");
        let plain = std::io::Error::other("alone");
        assert_eq!(error_chain(&plain), "alone");
    }

    #[test]
    fn seconds_are_rounded_to_a_tenth() {
        assert_eq!(secs(Duration::from_millis(1_260)), 1.3);
        assert_eq!(secs(Duration::from_millis(302_949)), 302.9);
        assert_eq!(secs(Duration::ZERO), 0.0);
    }

    #[test]
    fn the_problem_summary_counts_failures() {
        assert_eq!(problem_summary(None), "none");
        assert_eq!(
            problem_summary(Some(&Problem::Ipt(Vec::new()))),
            "introduction points: 0 failed"
        );
        assert_eq!(
            problem_summary(Some(&Problem::DescriptorUpload(Vec::new()))),
            "descriptor upload failed for 0 HsDirs (timed out 0, fatal 0, retries exhausted 0, other 0)"
        );
    }

    #[test]
    fn the_tally_buckets_every_status() {
        let tally = snapshot(&[
            ("a", ServiceStatus::Preparing),
            ("b", ServiceStatus::WaitingForSlot),
            ("c", ServiceStatus::Bootstrapping),
            ("d", ServiceStatus::Running),
            ("e", ServiceStatus::DegradedReachable),
            ("f", ServiceStatus::DegradedUnreachable),
            ("g", ServiceStatus::Recovering),
            ("h", ServiceStatus::Broken),
            ("i", ServiceStatus::Stopped),
            ("j", ServiceStatus::Failed),
        ])
        .tally();
        assert_eq!(
            tally,
            StatusTally {
                waiting: 2,
                bootstrapping: 1,
                running: 1,
                degraded: 1,
                unreachable: 2,
                broken: 1,
                ended: 2,
            }
        );
        assert_eq!(tally.pending(), 3);
    }

    #[test]
    fn the_progress_line_repeats_no_faster_than_the_period() {
        let start = Instant::now();
        let mut report = StartupReport::new(start);
        let waiting = snapshot(&[
            ("a", ServiceStatus::WaitingForSlot),
            ("b", ServiceStatus::Bootstrapping),
        ]);
        assert_eq!(
            report.observe(&waiting, start + Duration::from_secs(1)),
            None
        );
        let line = report.observe(&waiting, start + Duration::from_secs(15));
        assert_eq!(
            line,
            Some(StartupLine::Progress {
                elapsed: Duration::from_secs(15),
                tally: waiting.tally(),
            })
        );
        assert_eq!(
            report.observe(&waiting, start + Duration::from_secs(16)),
            None
        );
        assert!(report
            .observe(&waiting, start + Duration::from_secs(30))
            .is_some());
    }

    #[test]
    fn the_done_line_comes_once_with_the_first_report_times() {
        let start = Instant::now();
        let mut report = StartupReport::new(start);
        let first = snapshot(&[
            ("a", ServiceStatus::Running),
            ("b", ServiceStatus::Bootstrapping),
        ]);
        assert_eq!(
            report.observe(&first, start + Duration::from_secs(10)),
            None
        );

        // `a` flips later; only its FIRST report time (10 s) counts.
        let last = snapshot(&[
            ("a", ServiceStatus::DegradedUnreachable),
            ("b", ServiceStatus::DegradedReachable),
        ]);
        let line = report.observe(&last, start + Duration::from_secs(300));
        assert_eq!(
            line,
            Some(StartupLine::Done {
                elapsed: Duration::from_secs(300),
                tally: last.tally(),
                median: Duration::from_secs(300),
                slowest: Duration::from_secs(300),
            })
        );
        assert_eq!(
            report.observe(&last, start + Duration::from_secs(400)),
            None
        );
    }

    #[test]
    fn an_empty_snapshot_is_never_done() {
        let start = Instant::now();
        let mut report = StartupReport::new(start);
        let empty = OnionHostStatus::default();
        let line = report.observe(&empty, start + Duration::from_secs(60));
        assert!(!matches!(line, Some(StartupLine::Done { .. })));
    }
}
