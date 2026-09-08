use super::runtime::unix_secs;
use super::*;

/// Shared connection health, including monotonic evidence of recent success.
#[derive(Clone, Default)]
pub struct TorHealth {
    /// Unix-seconds of the last successful `TorTunnel::connect`. `0` until
    /// the first success — the watchdog substitutes the start time in that
    /// case so the stale window still elapses from boot, not from the epoch.
    last_success: Arc<AtomicU64>,
    last_success_instant: Arc<Mutex<Option<tokio::time::Instant>>>,
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
        if let Ok(mut last) = self.last_success_instant.lock() {
            *last = Some(tokio::time::Instant::now());
        }
    }

    pub fn successful_within(&self, window: Duration) -> bool {
        self.last_success_instant
            .lock()
            .ok()
            .and_then(|last| *last)
            .is_some_and(|last| last.elapsed() < window)
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
    pub(super) fn last_success_target(&self) -> Option<(String, u16)> {
        self.last_success_target
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub(super) fn last_success_secs(&self) -> u64 {
        self.last_success.load(Ordering::Relaxed)
    }

    pub(super) fn attempt_count(&self) -> u64 {
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
/// terminate-and-reconnect becomes visible to every consumer without
/// re-distribution — even though the watchdog no longer replaces the
/// tunnel value itself, the slot indirection is still what lets the accept
/// loop and the bridge-maintenance loop read "the current tunnel" without
/// each holding a fixed clone.
#[derive(Clone)]
pub struct TorHandle {
    /// `Option` so the slot can be drained at shutdown, dropping the last
    /// in-slot reference and letting arti's reactor close the PT children
    /// and release the state-dir lock.
    slot: Arc<RwLock<Option<TorTunnel>>>,
    health: TorHealth,
    active_bridges: Arc<Mutex<ActiveBridges>>,
    refresh: Arc<BridgeRefresh>,
}

#[derive(Default)]
struct ActiveBridges {
    bridges: Vec<BridgeLine>,
    activated: Option<tokio::time::Instant>,
}

impl ActiveBridges {
    fn update(&mut self, bridges: Vec<BridgeLine>) {
        if self.bridges != bridges {
            self.bridges = bridges;
            self.activated = Some(tokio::time::Instant::now());
        }
    }

    fn settling(&self, last_success: Option<tokio::time::Instant>) -> bool {
        self.activated.is_some_and(|activated| {
            !self.bridges.is_empty()
                && activated.elapsed() < Duration::from_secs(45)
                && last_success.is_none_or(|success| success < activated)
        })
    }
}

#[derive(Debug, Default)]
pub(crate) struct BridgeRefresh {
    needed: AtomicBool,
    notify: Notify,
    recovery: Arc<Notify>,
}

impl BridgeRefresh {
    pub fn set_needed(&self, needed: bool) {
        self.needed.store(needed, Ordering::Relaxed);
    }

    pub fn request(&self) {
        if self.needed.load(Ordering::Relaxed) {
            self.notify.notify_one();
        }
    }

    pub async fn notified(&self) {
        self.notify.notified().await;
    }

    pub fn recovery(&self) -> &Arc<Notify> {
        &self.recovery
    }

    /// Request recovery while keeping the same connection attempt alive.
    /// cancel-safe: NO — dropping this wrapper also drops the owned attempt.
    pub async fn track_connection<F: std::future::Future>(&self, connection: F) -> F::Output {
        tokio::pin!(connection);
        let period = Duration::from_secs(15);
        let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                result = connection.as_mut() => return result,
                _ = ticker.tick() => self.recovery.notify_one(),
            }
        }
    }

    pub fn request_after_failure(&self, error: &arti_wrapper::TorError) {
        let arti_wrapper::TorError::Connect { source, .. } = error else {
            return;
        };
        if matches!(
            tor_error::HasKind::kind(source),
            tor_error::ErrorKind::TorAccessFailed
                | tor_error::ErrorKind::TorNetworkTimeout
                | tor_error::ErrorKind::TorProtocolViolation
        ) {
            self.recovery.notify_one();
        }
    }
}

impl TorHandle {
    /// Wrap the bootstrapped tunnel. The handle is cheap to clone.
    pub fn new(tor: TorTunnel) -> Self {
        Self {
            slot: Arc::new(RwLock::new(Some(tor))),
            health: TorHealth::default(),
            active_bridges: Arc::new(Mutex::new(ActiveBridges::default())),
            refresh: Arc::new(BridgeRefresh::default()),
        }
    }

    /// Snapshot the current tunnel for a new connection. Returns `None`
    /// only while the server is shutting down (the slot has been drained);
    /// callers should treat that as a transient "unavailable" error. A
    /// `TorTunnel` is an `Arc<TorClient>` internally, so the clone is cheap.
    pub async fn tunnel(&self) -> Option<TorTunnel> {
        self.slot.read().await.clone()
    }

    /// Circuit-level health counters shared with the watchdog.
    pub fn health(&self) -> &TorHealth {
        &self.health
    }

    pub fn active_bridges(&self) -> Vec<BridgeLine> {
        self.active_bridges
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .bridges
            .clone()
    }

    pub fn set_active_bridges(&self, bridges: Vec<BridgeLine>) {
        self.active_bridges
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .update(bridges);
    }

    /// Give an authenticated channel time to fetch its descriptor and build a circuit.
    pub fn route_is_settling(&self) -> bool {
        let last_success = *self
            .health
            .last_success_instant
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        self.active_bridges
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .settling(last_success)
    }

    pub fn bridge_refresh(&self) -> &BridgeRefresh {
        &self.refresh
    }

    /// Take the tunnel out of the slot (graceful shutdown). The returned
    /// `TorTunnel`, when dropped, releases the slot's reference; the
    /// reactor/PT teardown follows once the remaining in-flight clones drain.
    pub async fn drain(self) -> Option<TorTunnel> {
        self.slot.write().await.take()
    }
}

#[cfg(test)]
mod activation_tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn repeated_selection_does_not_extend_bootstrap_grace() {
        let bridge: BridgeLine =
            "obfs4 192.0.2.1:443 1111111111111111111111111111111111111111 cert=AAA"
                .parse()
                .unwrap();
        let mut active = ActiveBridges::default();
        assert!(!active.settling(None));
        let old_success = tokio::time::Instant::now();
        tokio::time::advance(Duration::from_secs(1)).await;
        active.update(vec![bridge.clone()]);
        assert!(active.settling(Some(old_success)));
        tokio::time::advance(Duration::from_secs(15)).await;
        active.update(vec![bridge.clone()]);
        assert!(active.settling(None));
        tokio::time::advance(Duration::from_secs(30)).await;
        assert!(!active.settling(None));
        active.update(Vec::new());
        assert!(!active.settling(None));
        active.update(vec![bridge]);
        assert!(active.settling(None));
        assert!(!active.settling(Some(tokio::time::Instant::now())));
    }
}
