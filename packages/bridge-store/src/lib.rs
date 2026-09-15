//! Persistent health store for bridges, kept next to the active config.
//!
//! Tracks every bridge we have probed, with its reachability history:
//! last successful probe, last failure-counter bump, and a `fails`
//! counter. The store drives bridge lifecycle:
//!
//! * a successful probe resets `fails` to 0 and stamps `ok`;
//! * a failed probe bumps `fails` — but at most once per `fail_window`
//!   (so a burst of retries counts once), stamping `attempt`;
//! * once `fails` reaches `max_fails`, the bridge is pruned (returned to
//!   the caller so it can also be dropped from the config).
//!
//! Failures are observed at the **probe** layer (TCP / obfs4 / webtunnel
//! reachability), which is what this process controls directly — arti
//! owns the live bridge connections and does not surface per-bridge
//! runtime failures to us.
//!
//! File format (line-based, plain text), one metadata comment per bridge:
//!
//! ```text
//! # fails=0 attempt=2026-05-14T15:00:12Z ok=2026-05-14T15:00:12Z latency=234ms
//! obfs4 1.2.3.4:80 ABCDEF... cert=... iat-mode=0
//! ```
//!
//! Dedup key: [`bridge_probe::BridgeIdentity`] includes transport, address,
//! fingerprint, carrier identity, and the obfs4 certificate.
//!
//! Shared by the CLI daemon (`apps/socks5-proxy`) and the Android JNI
//! engine (`packages/android-ffi`) — both processes probe bridges and want
//! to remember which ones tend to work across restarts.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use bridge_line::BridgeLine;
use time::OffsetDateTime;

mod observe;
mod persistence;
mod stats;

type Key = bridge_probe::BridgeIdentity;

#[derive(Debug, Clone)]
struct Entry {
    bridge: BridgeLine,
    /// Last time a probe succeeded, if ever.
    last_ok: Option<OffsetDateTime>,
    /// Last time the failure counter was touched (bumped or reset). Used
    /// to rate-limit `fails` increments to once per `fail_window`.
    last_attempt: OffsetDateTime,
    /// Latency of the last successful probe.
    last_latency: Duration,
    /// Consecutive TCP-probe failure count (reset to 0 on any TCP success).
    fails: u32,
    /// Cumulative count of successful probes over the bridge's lifetime.
    /// Never reset — a long-lived, frequently-reachable bridge accrues a
    /// high count, so this is our persistent **stability** signal (used to
    /// order bridges for arti: more-proven first, then by latency).
    ok_count: u32,
    /// Number of successful PT/channel warm-ups. Unlike `ok_count`, this is
    /// recorded only after the transport channel itself accepted a connection.
    channel_ok_count: u32,
    /// Most recent successful PT/channel warm-up.
    last_channel_ok: Option<OffsetDateTime>,
    /// Number of times a full circuit through this bridge actually reached
    /// the open internet (`arti_wrapper::TorTunnel::verify_bridge_reachable`),
    /// not merely opened a channel. This is the standard the QR-scan
    /// verification flow already holds every scanned bridge to; the
    /// background watchdog applies the same check to a slow trickle of the
    /// already channel-proven pool (see `engine.rs`'s circuit-verify tick),
    /// since running it against the whole pool on every reprobe would be
    /// prohibitively expensive (see `docs/design/real-connectivity-bridge-
    /// verification.md`).
    verified_count: u32,
    /// Most recent successful end-to-end circuit verification.
    last_verified: Option<OffsetDateTime>,
    last_verification_attempt: Option<OffsetDateTime>,
    /// Consecutive **circuit-layer** failure count, observed from arti's
    /// own tracing events (per-guard usability reports). Distinct from
    /// `fails` (TCP-probe layer): a bridge whose TCP/TLS works but whose
    /// descriptor or fingerprint is stale answers reachability probes yet
    /// can't carry multi-hop circuits. Resets to 0 on a circuit success.
    circuit_fails: u32,
    /// Last time the circuit-failure counter was touched (bumped or reset).
    /// Used to rate-limit `circuit_fails` to once per
    /// `circuit_observation_window` (arti retries quickly; we mustn't
    /// count each retry as a fresh failure).
    last_circuit_observation: OffsetDateTime,
    /// Labels of the sources that offered this bridge. A line published by
    /// several collectors credits all of them, or a good source looks barren
    /// merely because another published the same line first.
    sources: std::collections::BTreeSet<String>,
}

/// `circuit_fails` value marking a bridge as permanently unusable, rather than
/// merely failing often. Written by
/// [`BridgeStore::note_permanent_failure_at`].
const RETIRED_CIRCUIT_FAILS: u32 = u32::MAX;

/// One transport's slice of the health store, for a status display.
///
/// The three counts answer progressively stronger questions, and the gaps
/// between them are the interesting part: `known` is what has been seen,
/// `alive` what answered a reachability probe, `channel_proven` what actually
/// completed a Tor channel. A transport with many alive and no channel-proven
/// bridges looks healthy and is not — the case that cost this project a day.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransportStats {
    /// `obfs4`, `webtunnel`, or `plain` for bridges with no transport.
    pub transport: String,
    pub known: usize,
    pub alive: usize,
    pub channel_proven: usize,
    pub retired: usize,
    pub last_probe_ok: Option<OffsetDateTime>,
    pub last_channel_ok: Option<OffsetDateTime>,
}

/// What one bridge-list source has yielded, for scoring and for display.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceStats {
    pub label: String,
    /// Bridges this source has offered, whether or not they ever worked.
    pub offered: usize,
    /// Of those, how many answered a reachability probe.
    pub alive: usize,
    /// Of those, how many actually carried a Tor channel.
    pub channel_proven: usize,
    /// Of those, how many were retired as permanently unusable.
    pub retired: usize,
}

impl SourceStats {
    /// Whether this source has supplied enough bridges to be judged, and none
    /// of them ever worked.
    ///
    /// The sample floor matters: a source that has offered two bridges and had
    /// no luck yet is unremarkable, while one that has offered hundreds without
    /// a single reachable bridge has stopped being a source of bridges. Judged
    /// on reachability rather than on completed channels, because
    /// channel-proven counts stay at zero for any bridge the client has simply
    /// never selected.
    pub fn is_barren(&self, min_sample: usize) -> bool {
        self.offered >= min_sample && self.alive == 0
    }
}

/// One-lookup snapshot of a bridge's health counters, read through
/// [`BridgeStore::health_snapshot`]. Each field is identical to the
/// corresponding individual getter; only the number of key rebuilds and map
/// lookups differs (one here, one per getter otherwise).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthSnapshot {
    /// Consecutive TCP-probe failures per the last probe round
    /// ([`BridgeStore::tcp_fails`]).
    pub tcp_fails: u32,
    /// Consecutive circuit-layer failure count ([`BridgeStore::circuit_fails`]).
    pub circuit_fails: u32,
    /// Successful end-to-end circuit verifications
    /// ([`BridgeStore::verified_count`]).
    pub verified_count: u32,
    /// Cumulative successful-probe count ([`BridgeStore::ok_count`]).
    pub ok_count: u32,
    /// When the circuit-failure counter was last touched
    /// ([`BridgeStore::last_circuit_observation`]).
    pub last_circuit_observation: Option<OffsetDateTime>,
}

impl Entry {
    fn is_retired(&self) -> bool {
        self.circuit_fails == RETIRED_CIRCUIT_FAILS
    }

    /// Proven alive: at least one successful probe ever (`ok_count > 0`),
    /// no failure since (`fails == 0`), and not retired. The same filter
    /// [`BridgeStore::healthiest_bridges`] applies: absence of failure alone
    /// proves nothing — a source-attributed entry starts with `fails == 0`
    /// and `ok_count == 0`, and a retired bridge keeps a spotless TCP record.
    fn is_proven_alive(&self) -> bool {
        self.fails == 0 && self.ok_count > 0 && !self.is_retired()
    }

    fn key(&self) -> Key {
        key_of(&self.bridge)
    }
}

fn key_of(b: &BridgeLine) -> Key {
    bridge_probe::bridge_identity(b)
}

#[derive(Debug, Clone)]
pub struct BridgeStore {
    path: PathBuf,
    entries: BTreeMap<Key, Entry>,
}

impl BridgeStore {
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests;
