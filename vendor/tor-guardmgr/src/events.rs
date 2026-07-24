//! Code to remotely notify other crates about changes in the status of the
//! `GuardMgr`.

use std::{pin::Pin, task::Poll};

use crate::skew::SkewEstimate;
use educe::Educe;
use futures::{Stream, StreamExt};
use tor_basic_utils::skip_fmt;

/// A stream of [`SkewEstimate`] events.
///
/// Note that this stream can be lossy: if multiple events trigger before you
/// read from it, you will only get the most recent estimate.
//
// SEMVER NOTE: this type is re-exported from tor-circmgr.
#[derive(Clone, Educe)]
#[educe(Debug)]
pub struct ClockSkewEvents {
    /// The `postage::watch::Receiver` that we're wrapping.
    ///
    /// We wrap this type so that we don't expose its entire API, and so that we
    /// can migrate to some other implementation in the future if we want.
    #[educe(Debug(method = "skip_fmt"))]
    pub(crate) inner: postage::watch::Receiver<Option<SkewEstimate>>,
}

impl Stream for ClockSkewEvents {
    type Item = Option<SkewEstimate>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.inner.poll_next_unpin(cx)
    }
}
impl ClockSkewEvents {
    /// Return our best estimate of our current clock skew, based on reports from the
    /// guards and fallbacks we have contacted.
    pub fn get(&self) -> Option<SkewEstimate> {
        self.inner.borrow().clone()
    }
}

// tor-socks5 local patch: aggregated "guards usable" signal ────────────────
// This mirrors `ClockSkewEvents` above, but carries a `bool` describing whether
// the active guard sample currently has at least one usable guard with complete
// directory information — i.e. a guard through which we can actually build data
// circuits. It is published by `GuardMgr` whenever the guard sample is refreshed
// (see `GuardMgr::update_guard_usability` / `GuardMgr::usable_guard_events`) and
// consumed by arti-client to gate `BootstrapStatus::ready_for_traffic()`, fixing
// the guard-exhaustion spiral where the client reported "ready" once the
// directory was bootstrapped even though no guard had usable descriptors.

/// A stream of "guards usable" events.
///
/// Note that this stream can be lossy: if multiple events trigger before you
/// read from it, you will only get the most recent value.
#[derive(Clone, Educe)]
#[educe(Debug)]
pub struct GuardUsableEvents {
    /// The `postage::watch::Receiver` that we're wrapping.
    ///
    /// We wrap this type so that we don't expose its entire API, and so that we
    /// can migrate to some other implementation in the future if we want.
    #[educe(Debug(method = "skip_fmt"))]
    pub(crate) inner: postage::watch::Receiver<bool>,
}

impl Stream for GuardUsableEvents {
    type Item = bool;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.inner.poll_next_unpin(cx)
    }
}
impl GuardUsableEvents {
    /// Return whether the active guard sample is currently usable for traffic
    /// (true iff at least one usable guard has complete directory information).
    pub fn get(&self) -> bool {
        *self.inner.borrow()
    }
}
