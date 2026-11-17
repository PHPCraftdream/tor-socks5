//! Hosted-service status: one snapshot (`OnionHostStatus`) of every service
//! the host manages, published through a single `tokio::sync::watch` slot
//! (one slot, no unbounded channels, no loss concerns: subscribers always
//! see the latest state).
//!
//! R2/R4 semantics: updates never block and never queue — [`StatusTracker`]
//! uses `send_modify`, so an update works even with zero receivers, and a
//! receiver's `changed()` only ever reports "the snapshot changed".

use std::collections::BTreeMap;

use tokio::sync::watch;

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
}
