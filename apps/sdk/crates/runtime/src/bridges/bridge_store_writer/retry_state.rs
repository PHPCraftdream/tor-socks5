//! Backoff bookkeeping for the retained, unpublished snapshot. Does not
//! touch the disk itself; the actor calls [`RetryState::record_success`] /
//! [`RetryState::record_failure`] from both the async publish-completion
//! path and the synchronous final flush, so the logging and arithmetic stay
//! in one place.

use tracing::{info, warn};

use super::{INITIAL_BACKOFF, MAX_BACKOFF};

pub(super) struct RetryState {
    pub(super) dirty: bool,
    pub(super) failed_attempts: u32,
    pub(super) retry_at: Option<tokio::time::Instant>,
    pub(super) backoff: std::time::Duration,
}

impl RetryState {
    pub(super) fn new(initial_backoff: std::time::Duration) -> Self {
        Self {
            dirty: false,
            failed_attempts: 0,
            retry_at: None,
            backoff: initial_backoff,
        }
    }

    /// Bookkeeping after a publish succeeded: end any retry streak (logging
    /// recovery at info) and mark the state clean. The caller drops the
    /// snapshot so the next op re-reads the file — unless mutations were
    /// absorbed while the save ran, in which case the caller keeps it dirty.
    pub(super) fn record_success(&mut self) {
        if self.failed_attempts > 0 {
            info!(
                attempts = self.failed_attempts + 1,
                "bridge health store published after retries"
            );
        }
        self.dirty = false;
        self.failed_attempts = 0;
        self.retry_at = None;
        self.backoff = INITIAL_BACKOFF;
    }

    /// Bookkeeping after a publish failed: retain the dirty snapshot and arm
    /// the next exponential-backoff retry. The update stays in memory.
    pub(super) fn record_failure(&mut self, error: &anyhow::Error) {
        self.failed_attempts += 1;
        warn!(
            error = %error,
            attempt = self.failed_attempts,
            retry_in = ?self.backoff,
            "bridge health store publish failed; update retained in memory and will retry"
        );
        self.dirty = true;
        self.retry_at = Some(tokio::time::Instant::now() + self.backoff);
        self.backoff = (self.backoff * 2).min(MAX_BACKOFF);
    }
}
