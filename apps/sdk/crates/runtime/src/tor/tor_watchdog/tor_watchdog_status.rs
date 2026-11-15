//! Public status of the stale-channel watchdog.
//!
//! The snapshot travels on a bounded `tokio::sync::watch` channel: latest
//! snapshot wins and history is dropped (R4), so a slow reader always sees
//! the most recent state without accumulating memory. The channel is owned
//! by the spawned task and handed out via [`WatchdogRun`] (R1: no global
//! state). Paired with `TorHealth`: the counters on `TorHandle` answer "is
//! Tor succeeding", [`WatchdogStatus`] answers "what did the watchdog do
//! about it".

/// Outcome of the watchdog's most recent heal (terminate all channels and
/// verify reconnection), for embedding hosts that cannot read tracing logs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HealOutcome {
    /// Channels were terminated and the client reconnected within the
    /// verify budget.
    Healed,
    /// Channels were terminated but the client did not reconnect within
    /// the verify budget; the watchdog applies cooldown/backoff.
    StillUnhealthy,
    /// Terminating channels failed before any channel was touched; the
    /// field carries the formatted error chain.
    TerminateFailed(String),
}

/// Snapshot of the stale-channel watchdog's own state, published after
/// every check tick and heal on the `watch` channel inside [`WatchdogRun`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WatchdogStatus {
    /// Checks this watchdog has started since spawn (one per configured
    /// `check_interval_secs`; `0` until the first interval elapsed).
    pub checks_started: u64,
    /// Consecutive failed heal attempts; drives the extended cooldown and
    /// resets on a successful heal.
    pub consecutive_failures: u32,
    /// The most recent performed heal, `None` before the first one.
    pub last_heal: Option<HealOutcome>,
}

/// What a spawned stale-channel watchdog hands back to its owner: the task
/// to join at shutdown (cancel the token first) and the status channel to
/// read while it runs.
pub struct WatchdogRun {
    /// Join handle of the watchdog task; it ends shortly after the token is cancelled.
    pub join: tokio::task::JoinHandle<()>,
    /// Latest status snapshot (`tokio::sync::watch`: history is dropped).
    pub status: tokio::sync::watch::Receiver<WatchdogStatus>,
}

impl From<&super::runtime::HealResult> for HealOutcome {
    fn from(result: &super::runtime::HealResult) -> Self {
        match result {
            super::runtime::HealResult::Healed => HealOutcome::Healed,
            super::runtime::HealResult::StillUnhealthy => HealOutcome::StillUnhealthy,
            super::runtime::HealResult::TerminateFailed(e) => {
                HealOutcome::TerminateFailed(format!("{e:#}"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heal_outcome_from_healed() {
        assert_eq!(
            HealOutcome::from(&super::super::runtime::HealResult::Healed),
            HealOutcome::Healed
        );
    }

    #[test]
    fn heal_outcome_from_still_unhealthy() {
        assert_eq!(
            HealOutcome::from(&super::super::runtime::HealResult::StillUnhealthy),
            HealOutcome::StillUnhealthy
        );
    }

    #[test]
    fn heal_outcome_from_terminate_failed_carries_error_chain() {
        let err = anyhow::anyhow!("outer").context("inner");
        let outcome = HealOutcome::from(&super::super::runtime::HealResult::TerminateFailed(err));
        assert_eq!(
            outcome,
            HealOutcome::TerminateFailed("inner: outer".to_owned())
        );
    }

    #[test]
    fn default_snapshot_is_quiescent() {
        let status = WatchdogStatus::default();
        assert_eq!(status.checks_started, 0);
        assert_eq!(status.consecutive_failures, 0);
        assert_eq!(status.last_heal, None);
    }
}
