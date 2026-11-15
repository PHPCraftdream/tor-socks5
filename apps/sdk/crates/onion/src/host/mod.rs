//! Hosted onion services: settle every configured service's identity, launch
//! them gradually, forward their virtual ports to local `host:port` targets,
//! log lifecycle/status, publish a status snapshot, and hold the onion
//! keystore lock for as long as any service is published (so
//! `tor-socks5 onion new/import/remove` cannot race a live service).
//!
//! Contract: config in, handle out; one live host per keystore lock (the
//! lock makes concurrent hosting of the same keystore fail loudly,
//! non-fatally); dropping [`OnionHostHandle`] only cancels the token (it
//! never blocks, no async in `Drop`); sequential restart works because the
//! keystore lock is reacquired by a new [`OnionHost::start`]. The keystore
//! directory and the onion services file location are explicit arguments —
//! this module never derives them from anything.
//!
//! Task structure:
//!
//! ```text
//! producer task (one, spawned by OnionHost::start, cancelled via the token)
//!   └─ holds the keystore PathLock guard for its whole life
//!      ├─ settles every service's identity first, in one batch
//!      │  (one rewrite of the onion services file for the whole launch)
//!      └─ one manager task per service that may start
//!         ├─ holds one of at most MAX_STARTING launch slots (`start_gate`)
//!         │  from just before the launch until a terminal status, the 90 s
//!         │  slot cap, or shutdown
//!         ├─ launch + retry/backoff loop (30 s doubling to 5 min, ±20% spread)
//!         ├─ waits for the .onion address, then spawns:
//!         │   ├─ request-serving task (rendezvous → stream requests → TCP; ≤512 process-wide)
//!         │   └─ status-event logging task (fires the slot release signal)
//!         └─ keeps the Arc<RunningOnionService> alive until shutdown
//! ```
//!
//! The watchdog heals the Tor client *in place* (it never rebuilds the
//! `TorClient`), so services launched once survive heals; we still read the
//! tunnel through `TorHandle::tunnel()` per launch attempt, like every other
//! subsystem.
//!
//! Status is published through a single `tokio::sync::watch` slot (see
//! [`status`]); subscribe before or after `start()` — the snapshot is always
//! the latest state, so a late subscriber only misses intermediate
//! transitions, never the current one.
//!
//! Example (the token is the cancellation path; dropping the handle cancels
//! it too):
//!
//! ```text
//! use tor_socks5_onion::host::{OnionHost, OnionHostConfig};
//!
//! let config = OnionHostConfig::new(handle, keystore_dir, token)
//!     .with_entries(enabled_services)
//!     .with_config_path(Some(config_path));
//! let host_handle = OnionHost::new(config).start();
//! let status = host_handle.subscribe();
//! // ... later, in the shutdown choreography:
//! host_handle.shutdown().await;
//! ```

pub mod forward;
pub mod serve;
pub(crate) mod start_gate;
pub mod status;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use proxy_config::OnionServiceEntry;
use safelog::DisplayRedacted as _;
use tokio_util::sync::CancellationToken;
use tor_socks5_runtime::tor_watchdog::TorHandle;
use tor_socks5_runtime::workers::run_fallible_blocking;
use tracing::{debug, error, info, warn};

use crate::keys;
use status::StatusTracker;

pub use status::{OnionHostStatus, ServiceFailure, ServiceState, ServiceStatus};

/// Delay before the first relaunch attempt after a failed launch; doubles
/// up to [`RETRY_DELAY_MAX`] and stays there for the process' lifetime.
const RETRY_DELAY_INITIAL: Duration = Duration::from_secs(30);
/// Upper bound on the launch retry backoff.
const RETRY_DELAY_MAX: Duration = Duration::from_secs(300);

/// Spread a retry delay by ±20%, so many failed services do not retry in
/// lockstep. Uniform in [0.8×, 1.2×); bytes from the OS RNG (`getrandom`,
/// already a direct dependency). On RNG failure the delay is unchanged.
fn backoff_spread(delay: Duration) -> Duration {
    let mut bytes = [0u8; 8];
    if getrandom::getrandom(&mut bytes).is_err() {
        return delay;
    }
    Duration::from_millis(spread_millis(
        // Retry delays are seconds-scale; no truncation at u64.
        delay.as_millis() as u64,
        u64::from_le_bytes(bytes),
    ))
}

/// The pure ±20% scaling: `unit` (any u64) picks uniformly in 40 steps of
/// (80 + step) / 100, i.e. [0.8, 1.2). u128 inner math, no overflow.
fn spread_millis(millis: u64, unit: u64) -> u64 {
    let step = u128::from(unit % 40); // one of 40 evenly-likely steps
    let scaled = u128::from(millis) * (80 + step);
    u64::try_from(scaled / 100).unwrap_or(u64::MAX)
}

/// Poll interval while waiting for the service's `.onion` address to become
/// available (arti finds or generates the identity key asynchronously).
const ADDRESS_POLL_INTERVAL: Duration = Duration::from_secs(1);
/// Total budget for the address wait. Descriptor publication takes much
/// longer than this; the address itself (keystore lookup/generation) should
/// appear within seconds.
const ADDRESS_WAIT_LIMIT: Duration = Duration::from_secs(120);

/// Above this many enabled services the setup is beyond what is known to
/// work through a small bridge pool: a warning is logged, nothing is refused.
const SERVICES_SOFT_LIMIT: usize = 10;

fn beyond_soft_limit(enabled: usize) -> bool {
    enabled > SERVICES_SOFT_LIMIT
}

/// Everything the host needs to run the configured onion services.
///
/// The keystore directory ([`OnionHostConfig::keystore_dir`]) and the onion
/// services file location ([`OnionHostConfig::config_path`]) are explicit:
/// the caller decides where they live (the CLI derives both from its config
/// path; an embedding host may choose anything).
pub struct OnionHostConfig {
    /// The live Tor client handle; read per launch attempt.
    pub handle: TorHandle,
    /// The configured services; only the enabled ones are hosted.
    pub entries: Vec<OnionServiceEntry>,
    /// Where the onion services file lives, as today; `None` means built-in
    /// defaults (no file to complete).
    pub config_path: Option<PathBuf>,
    /// The Arti native keystore directory (explicit; never derived here).
    pub keystore_dir: PathBuf,
    /// The cancellation token: cancels the producer, the managers and every
    /// task they spawned.
    pub token: CancellationToken,
}

impl OnionHostConfig {
    /// A config with no entries and no services-file path; add them with
    /// [`OnionHostConfig::with_entries`] / [`OnionHostConfig::with_config_path`].
    pub fn new(handle: TorHandle, keystore_dir: PathBuf, token: CancellationToken) -> Self {
        Self {
            handle,
            entries: Vec::new(),
            config_path: None,
            keystore_dir,
            token,
        }
    }

    /// Set the configured services (chainable).
    pub fn with_entries(mut self, entries: Vec<OnionServiceEntry>) -> Self {
        self.entries = entries;
        self
    }

    /// Set the onion services file location (chainable).
    pub fn with_config_path(mut self, config_path: Option<PathBuf>) -> Self {
        self.config_path = config_path;
        self
    }
}

/// A hosting run: `OnionHost::new(config).start()` spawns the producer task
/// and returns its handle immediately.
pub struct OnionHost {
    config: OnionHostConfig,
}

impl OnionHost {
    /// Build a host for `config`. Nothing runs until [`OnionHost::start`].
    pub fn new(config: OnionHostConfig) -> Self {
        Self { config }
    }

    /// Spawn the producer task (the whole [`OnionHost::new`]-documented
    /// launch choreography) and return its handle. With no enabled entries
    /// the producer exits immediately and the status stays empty — a handle
    /// is still returned, so callers need no special case.
    pub fn start(self) -> OnionHostHandle {
        let config = self.config;
        let token = config.token;
        let enabled: Vec<OnionServiceEntry> = config
            .entries
            .iter()
            .filter(|entry| entry.enabled)
            .cloned()
            .collect();
        let (tracker, join) = if enabled.is_empty() {
            // Nothing enabled: an empty status and a producer that exits
            // without touching the blocking pool.
            let tracker = StatusTracker::new(std::iter::empty());
            let join = tokio::spawn(async {});
            (tracker, join)
        } else {
            info!(
                count = enabled.len(),
                at_once = start_gate::MAX_STARTING,
                "starting configured onion services; at most 4 launch at a time"
            );
            if beyond_soft_limit(enabled.len()) {
                warn!(
                    count = enabled.len(),
                    soft_limit = SERVICES_SOFT_LIMIT,
                    "more onion services are enabled than are known to work through a small \
                     bridge pool; see docs/guide/ops/onion-service.md (Many services)"
                );
            }
            let tracker = StatusTracker::new(enabled.iter().map(|entry| entry.nickname.clone()));
            let run_config = OnionHostConfig {
                handle: config.handle,
                entries: enabled,
                config_path: config.config_path,
                keystore_dir: config.keystore_dir,
                token: token.clone(),
            };
            let tracker_clone = tracker.clone();
            let join = tokio::spawn(run_services(run_config, tracker_clone));
            (tracker, join)
        };
        let status_rx = tracker.subscribe();
        OnionHostHandle {
            token: Some(token),
            status_rx,
            producer: Some(join),
        }
    }
}

/// The handle of a running [`OnionHost`]: status snapshot, subscription and
/// shutdown. Dropping it cancels the token (never blocks, no async in
/// `Drop`); use [`OnionHostHandle::shutdown`] to also wait for the producer,
/// or [`OnionHostHandle::detach`] to hand the producer to the caller's own
/// shutdown choreography (what the server does) — the token remains the
/// cancellation path either way.
pub struct OnionHostHandle {
    // `Option` so `shutdown`/`detach` can take the token/producer out of
    // `&mut self` without fighting the `Drop` impl: taking from the options
    // defuses the drop-side cancellation (detaching must not cancel).
    token: Option<CancellationToken>,
    status_rx: tokio::sync::watch::Receiver<OnionHostStatus>,
    producer: Option<tokio::task::JoinHandle<()>>,
}

impl OnionHostHandle {
    /// Subscribe to the status snapshot (a `watch` receiver: always holds
    /// the latest state).
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<OnionHostStatus> {
        self.status_rx.clone()
    }

    /// The current status snapshot.
    pub fn status(&self) -> OnionHostStatus {
        self.status_rx.borrow().clone()
    }

    /// Cancel the token and await the producer task (which joins its
    /// managers before releasing the keystore lock).
    pub async fn shutdown(mut self) {
        if let Some(token) = self.token.take() {
            token.cancel();
        }
        if let Err(error) = self
            .producer
            .take()
            .expect("producer joined only here")
            .await
        {
            warn!(%error, "onion service producer task ended with a join error");
        }
    }

    /// Hand the producer join handle to the caller's shutdown choreography.
    /// The token remains the cancellation path; the producer is not awaited
    /// here, and dropping the detached handle does NOT cancel the token —
    /// the caller owns the cancellation from here on.
    pub fn detach(mut self) -> tokio::task::JoinHandle<()> {
        let _ = self.token.take();
        self.producer.take().expect("producer detached only here")
    }

    /// The host's cancellation token.
    pub fn token(&self) -> &CancellationToken {
        self.token
            .as_ref()
            .expect("the token is only taken by shutdown/detach")
    }
}

impl Drop for OnionHostHandle {
    fn drop(&mut self) {
        if let Some(token) = self.token.as_ref() {
            token.cancel();
        }
    }
}

/// Producer task body: acquire the keystore lock (held for the services'
/// lifetime), then run one manager task per service until shutdown.
async fn run_services(config: OnionHostConfig, tracker: StatusTracker) {
    let OnionHostConfig {
        handle,
        entries,
        config_path,
        keystore_dir,
        token,
    } = config;

    // The lock acquisition blocks (file lock + poll loop), so it runs on the
    // blocking pool; the guard then moves into this task and lives until the
    // task ends — i.e. until shutdown cancels the managers and they are
    // joined below. Failing to get it is NOT fatal: the proxy keeps running
    // without onion services.
    let dir = keystore_dir.clone();
    let lock = run_fallible_blocking(move || keys::lock(&dir).map_err(anyhow::Error::new)).await;
    let _lock = match lock {
        Ok(Ok(guard)) => Some(guard),
        Ok(Err(error)) => {
            tracker.set_all(ServiceFailure::KeystoreLockHeld);
            error!(
                %error,
                "onion services not started: the onion keystore lock is held \
                 elsewhere (a tor-socks5 onion command or another server instance?)"
            );
            return;
        }
        Err(error) => {
            mark_all_failed(&tracker, &entries);
            error!(%error, "onion services not started: lock task panicked");
            return;
        }
    };

    // All identities are settled before any manager spawns, in ONE rewrite
    // of the onion services file (see `keys::prepare_all`); the file and
    // keystore work blocks, so it runs on the blocking pool. A join error is
    // NOT fatal: the proxy keeps running without onion services.
    let prepared = match tokio::task::spawn_blocking(move || {
        keys::prepare_all(config_path.as_deref(), &keystore_dir, &entries)
    })
    .await
    {
        Ok(prepared) => prepared,
        Err(error) => {
            error!(
                %error,
                "onion services not started: the identity batch task panicked"
            );
            return;
        }
    };

    // Gradual start: managers spawn in services-file order and the gate
    // hands freed slots out FIFO, so services launch in file order.
    let gate = start_gate::StartGate::new();
    // One process-wide cap on forwarded streams, across ALL services
    // together; each service adds its own per-service cap (see `serve`).
    let global_streams = Arc::new(tokio::sync::Semaphore::new(
        serve::MAX_TOTAL_CONCURRENT_STREAMS,
    ));
    // One manager per service that may start; a failing service must not
    // affect the others (the ones that may not start are already logged).
    let mut managers = Vec::with_capacity(prepared.len());
    for service in prepared {
        if service.address.is_none() {
            // The service never starts: its identity could not be settled or
            // recorded (the concrete cause is logged by `prepare_all`, never
            // any key material) — no single typed reason fits, so the status
            // is `Failed` with `failure: None`.
            mark_failed(&tracker, &service.entry);
            continue;
        }
        managers.push(tokio::spawn(service_manager(
            handle.clone(),
            service.entry,
            gate.clone(),
            global_streams.clone(),
            token.clone(),
            tracker.clone(),
        )));
    }
    // Join the managers so the keystore lock guard is only dropped after
    // every service stopped. Managers exit promptly on cancellation.
    for manager in managers {
        if let Err(error) = manager.await {
            warn!(%error, "onion service manager task ended with a join error");
        }
    }
}

/// Mark one service `Failed` without a typed failure (see
/// [`ServiceFailure`]: no single reason fits the settlement paths).
fn mark_failed(tracker: &StatusTracker, entry: &OnionServiceEntry) {
    tracker.set(
        &entry.nickname,
        ServiceState {
            status: ServiceStatus::Failed,
            failure: None,
        },
    );
}

/// Mark every service `Failed` without a typed failure.
fn mark_all_failed(tracker: &StatusTracker, entries: &[OnionServiceEntry]) {
    for entry in entries {
        mark_failed(tracker, entry);
    }
}

/// Launch (and if necessary relaunch) one service, then keep it alive until
/// shutdown. Holding the `Arc<RunningOnionService>` here is what keeps the
/// service published. Each launch attempt waits for a `start_gate` slot and
/// holds it until the service reports a terminal status, the 90 s slot cap,
/// or shutdown; retries sleep an exponentially growing, ±20%-spread backoff.
async fn service_manager(
    handle: TorHandle,
    entry: OnionServiceEntry,
    gate: start_gate::StartGate,
    global_streams: Arc<tokio::sync::Semaphore>,
    token: CancellationToken,
    tracker: StatusTracker,
) {
    let nick = entry.nickname.clone();
    let nick_hs = match keys::nickname(&nick) {
        Ok(nick) => nick,
        Err(error) => {
            tracker.set(
                &nick,
                ServiceState {
                    status: ServiceStatus::Failed,
                    failure: Some(ServiceFailure::InvalidNickname),
                },
            );
            error!(nickname = %nick, %error, "invalid onion service nickname; service not started");
            return;
        }
    };
    let config = match build_config(nick_hs) {
        Ok(config) => config,
        Err(error) => {
            tracker.set(
                &nick,
                ServiceState {
                    status: ServiceStatus::Failed,
                    failure: Some(ServiceFailure::InvalidConfig),
                },
            );
            error!(nickname = %nick, %error, "invalid onion service configuration; service not started");
            return;
        }
    };
    let ports = serve::port_map(&entry.ports);
    let semaphore = Arc::new(tokio::sync::Semaphore::new(serve::MAX_CONCURRENT_STREAMS));

    let mut delay = RETRY_DELAY_INITIAL;
    loop {
        tracker.set(
            &nick,
            ServiceState {
                status: ServiceStatus::WaitingForSlot,
                failure: None,
            },
        );
        // Snapshot the current tunnel; `None` only while shutting down. The
        // watchdog heals the client in place, so a launch that succeeded
        // never needs repeating after a heal.
        let tunnel = tokio::select! {
            biased;
            () = token.cancelled() => {
                mark_stopped(&tracker, &nick);
                return;
            }
            tunnel = handle.tunnel() => tunnel,
        };
        let Some(tunnel) = tunnel else {
            debug!(nickname = %nick, "onion service launch aborted: Tor is shutting down");
            mark_stopped(&tracker, &nick);
            return;
        };

        // Gradual start: hold one of at most MAX_STARTING launch slots from
        // just before the launch until the service reports a terminal
        // status, the 90 s slot cap elapses, or shutdown. Released before
        // the retry backoff sleeps.
        {
            let Some(slot) = gate.acquire(&token).await else {
                debug!(nickname = %nick, "onion service launch aborted: shutting down while waiting for a launch slot");
                mark_stopped(&tracker, &nick);
                return;
            };
            match tunnel.raw().launch_onion_service(config.clone()) {
                Ok(Some((service, rend_requests))) => {
                    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
                    // The slot is released by its own task (terminal status,
                    // the 90 s cap, or shutdown) while this manager continues
                    // with the address wait and the serving tasks.
                    let slot_release =
                        tokio::spawn(slot.hold_until_started(started_rx, token.clone()));
                    match wait_for_address(&service, &token, &nick).await {
                        AddressWait::Available(address) => {
                            tracker.set(
                                &nick,
                                ServiceState {
                                    status: ServiceStatus::Bootstrapping,
                                    failure: None,
                                },
                            );
                            info!(
                                nickname = %nick,
                                address = %address.display_unredacted(),
                                "onion service address available: onion service starting"
                            );
                            // Serving loop and status logger run as independent tasks;
                            // both exit on cancellation. The manager keeps this first
                            // clone alive; dropping the last clone would unpublish the
                            // service.
                            let serving = tokio::spawn(serve::serve_service(
                                service.clone(),
                                rend_requests,
                                ports,
                                semaphore,
                                global_streams.clone(),
                                token.clone(),
                            ));
                            let status = tokio::spawn(serve::log_status_events(
                                service.status_events(),
                                nick.clone(),
                                address.display_unredacted().to_string(),
                                started_tx,
                                tracker.clone(),
                                token.clone(),
                            ));
                            token.cancelled().await;
                            let _ = serving.await;
                            let _ = status.await;
                            let _ = slot_release.await; // completes on its own; joined for tidiness
                            info!(nickname = %nick, "onion service stopped");
                            mark_stopped(&tracker, &nick);
                            return;
                        }
                        // Shutdown (cancellation) while waiting: the manager
                        // returns without the "onion service stopped" log
                        // line; the status is still `Stopped`, because
                        // shutdown is the cause.
                        AddressWait::Cancelled => {
                            mark_stopped(&tracker, &nick);
                            return; // started_tx drops; the slot task unwinds on cancellation
                        }
                        AddressWait::TimedOut => {
                            tracker.set(
                                &nick,
                                ServiceState {
                                    status: ServiceStatus::Failed,
                                    failure: Some(ServiceFailure::AddressUnavailable {
                                        limit: ADDRESS_WAIT_LIMIT,
                                    }),
                                },
                            );
                            return; // started_tx drops; the slot task unwinds at its cap
                        }
                    }
                }
                // `enabled` defaults to true in our built config; `None` means
                // arti refused to start the service at all.
                Ok(None) => {
                    tracker.set(
                        &nick,
                        ServiceState {
                            status: ServiceStatus::Failed,
                            failure: Some(ServiceFailure::RejectedByTorClient),
                        },
                    );
                    error!(nickname = %nick, "onion service was rejected by the Tor client (disabled configuration); not retried");
                    return;
                }
                Err(error) => {
                    error!(
                        nickname = %nick,
                        %error,
                        retry_in = ?delay,
                        "failed to launch onion service; retrying"
                    );
                }
            }
        }

        tokio::select! {
            biased;
            () = token.cancelled() => {
                mark_stopped(&tracker, &nick);
                return;
            }
            () = tokio::time::sleep(backoff_spread(delay)) => {}
        }
        delay = (delay * 2).min(RETRY_DELAY_MAX);
    }
}

/// Mark one service `Stopped` (the manager returned: shutdown/cancellation).
fn mark_stopped(tracker: &StatusTracker, nick: &str) {
    tracker.set(
        nick,
        ServiceState {
            status: ServiceStatus::Stopped,
            failure: None,
        },
    );
}

/// Build arti's config for a (pre-validated) nickname.
fn build_config(nick: tor_hsservice::HsNickname) -> Result<tor_hsservice::OnionServiceConfig> {
    tor_hsservice::config::OnionServiceConfigBuilder::default()
        .nickname(nick)
        .build()
        .context("building the onion service configuration")
}

/// The outcome of waiting for the `.onion` address.
enum AddressWait {
    /// The address is available.
    Available(tor_hscrypto::pk::HsId),
    /// The token fired while waiting.
    Cancelled,
    /// [`ADDRESS_WAIT_LIMIT`] elapsed without an address.
    TimedOut,
}

/// Poll for the service's `.onion` address, bounded by
/// [`ADDRESS_WAIT_LIMIT`].
async fn wait_for_address(
    service: &Arc<tor_hsservice::RunningOnionService>,
    token: &CancellationToken,
    nick: &str,
) -> AddressWait {
    let deadline = tokio::time::Instant::now() + ADDRESS_WAIT_LIMIT;
    loop {
        if let Some(address) = service.onion_address() {
            return AddressWait::Available(address);
        }
        if tokio::time::Instant::now() >= deadline {
            error!(
                nickname = %nick,
                waited = ?ADDRESS_WAIT_LIMIT,
                "onion service address never became available"
            );
            return AddressWait::TimedOut;
        }
        tokio::select! {
            biased;
            () = token.cancelled() => return AddressWait::Cancelled,
            () = tokio::time::sleep(ADDRESS_POLL_INTERVAL) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Retry-spread scaling (pure, no runtime).
    #[test]
    fn the_spread_stays_within_twenty_percent() {
        assert_eq!(spread_millis(30_000, 0), 24_000);
        // u64::MAX % 40 == 15 → step 15 → factor 0.95.
        assert_eq!(spread_millis(30_000, u64::MAX), 28_500);
        assert_eq!(spread_millis(300_000, 0), 240_000);

        // Monotone non-decreasing across the 40-step period.
        let mut previous = spread_millis(30_000, 0);
        for unit in 1..40u64 {
            let current = spread_millis(30_000, unit);
            assert!(current >= previous, "spread regressed at unit {unit}");
            previous = current;
        }

        // Real samples: the unit comes from the OS RNG, so only bounds and
        // variety are asserted — no wall-clock anywhere.
        let mut distinct = std::collections::HashSet::new();
        for _ in 0..50 {
            let delay = backoff_spread(Duration::from_secs(30));
            assert!(
                delay >= Duration::from_secs(24),
                "below the -20% floor: {delay:?}"
            );
            assert!(
                delay < Duration::from_secs(36),
                "above the +20% ceiling: {delay:?}"
            );
            distinct.insert(delay);
        }
        assert!(distinct.len() >= 2, "the spread produces variety");
    }

    #[test]
    fn the_soft_limit_warning_starts_above_ten_services() {
        assert!(!beyond_soft_limit(1));
        assert!(!beyond_soft_limit(10));
        assert!(beyond_soft_limit(11));
        assert!(beyond_soft_limit(100));
    }

    #[test]
    fn build_config_accepts_valid_nickname() {
        let nick = keys::nickname("svc-one").expect("nickname");
        let config = build_config(nick).expect("config");
        assert_eq!(config.nickname().to_string(), "svc-one");
        // `enabled` defaults to true, so arti will actually start it.
        assert!(config.enabled());
    }

    #[test]
    fn invalid_nickname_is_rejected_before_launch() {
        let entry = OnionServiceEntry {
            nickname: "not a nickname".to_owned(),
            enabled: true,
            address: None,
            key: None,
            circuit_hops: 4,
            ports: Vec::new(),
        };
        // The manager returns without launching when the nickname is invalid;
        // validate that path directly via the keys helper it uses.
        assert!(keys::nickname(&entry.nickname).is_err());
    }

    fn service(nickname: &str) -> OnionServiceEntry {
        OnionServiceEntry {
            nickname: nickname.to_owned(),
            enabled: true,
            address: None,
            key: None,
            circuit_hops: 4,
            ports: vec![proxy_config::OnionServicePort {
                onion_port: 80,
                target: "127.0.0.1:8080".to_owned(),
            }],
        }
    }

    fn temp_config() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().expect("temp dir");
        let config = dir.path().join("tor-socks5.ktav");
        let keystore = dir.path().join("keystore");
        (dir, config, keystore)
    }

    fn keystore_address(keystore: &std::path::Path, nickname: &str) -> Option<String> {
        let keymgr = keys::store::open(keystore).expect("keystore");
        keys::store::address(&keymgr, &keys::nickname(nickname).expect("nickname"))
            .expect("address")
    }

    #[test]
    fn a_launchable_identity_is_prepared_and_the_file_completed() {
        let (_tmp, config, keystore) = temp_config();
        let entry = service("web");
        proxy_config::Config::write_onion_services(&config, std::slice::from_ref(&entry))
            .expect("write");

        let prepared = keys::prepare_all(Some(&config), &keystore, &[entry]);
        let address = prepared[0].address.clone().expect("the service may start");

        let stored = proxy_config::Config::read_onion_services(&config).expect("read");
        assert_eq!(stored[0].address.as_deref(), Some(address.as_str()));
        assert!(stored[0].key.is_some(), "the new key is recorded");
        assert_eq!(keystore_address(&keystore, "web"), Some(address));
    }

    #[test]
    fn an_address_the_key_does_not_give_keeps_the_service_from_starting() {
        let (_tmp, config, keystore) = temp_config();
        let (key, _address) = keys::fresh_identity("web");
        let (_other_key, other_address) = keys::fresh_identity("web");
        let mut entry = service("web");
        entry.key = Some(proxy_config::IdentityKey::new(key).expect("key text"));
        entry.address = Some(other_address);
        proxy_config::Config::write_onion_services(&config, std::slice::from_ref(&entry))
            .expect("write");

        let prepared = keys::prepare_all(Some(&config), &keystore, &[entry]);
        assert_eq!(prepared[0].address, None);
        assert_eq!(
            keystore_address(&keystore, "web"),
            None,
            "nothing was published"
        );
    }

    #[test]
    fn a_key_that_is_not_an_identity_keeps_the_service_from_starting() {
        let (_tmp, config, keystore) = temp_config();
        let mut entry = service("web");
        entry.key = Some(
            proxy_config::IdentityKey::new(keys::store::encode_key(b"not a key"))
                .expect("key text"),
        );
        proxy_config::Config::write_onion_services(&config, std::slice::from_ref(&entry))
            .expect("write");

        let prepared = keys::prepare_all(Some(&config), &keystore, &[entry]);
        assert_eq!(prepared[0].address, None);
    }

    // --- New host-API regression tests (deterministic, no wall-clock). ---

    /// Install rustls's process-wide `CryptoProvider` exactly once for this
    /// test binary (copied verbatim from
    /// `tor_watchdog_tests.rs`): a fresh `state_dir` reaches further into
    /// arti's directory-manager setup, and that path expects a crypto
    /// provider to already be installed. `install_default()` errors if
    /// called twice in the same process, so the error is discarded.
    fn ensure_crypto_provider() {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    fn test_handle(state_dir: &std::path::Path) -> TorHandle {
        ensure_crypto_provider();
        // A fresh tempdir `state_dir` (owned by the caller so it outlives the
        // tunnel): `None` would fall back to arti's shared per-user OS
        // location, which is flaky on CI.
        let settings = arti_wrapper::Settings {
            state_dir: Some(state_dir.to_path_buf()),
            ..Default::default()
        };
        let tor = arti_wrapper::TorTunnel::create_unbootstrapped_with(settings)
            .expect("unbootstrapped tunnel");
        TorHandle::new(tor)
    }

    fn disabled_entry() -> OnionServiceEntry {
        let mut entry = service("off");
        entry.enabled = false;
        entry
    }

    /// With no enabled entries the producer exits immediately (it never
    /// touches the blocking pool) and the status stays empty. This runs on
    /// the default `#[tokio::test]` flavor (current-thread): `tokio::spawn`
    /// works there, and the safe path is that zero enabled entries keep the
    /// producer off the blocking pool entirely.
    #[tokio::test]
    async fn a_host_without_enabled_services_starts_and_shuts_down() {
        let dir = tempfile::tempdir().expect("temp dir");
        let keystore = std::env::temp_dir().join("tor-socks5-onion-host-empty-test");
        let config =
            OnionHostConfig::new(test_handle(dir.path()), keystore, CancellationToken::new())
                .with_entries(vec![disabled_entry()]);
        let host_handle = OnionHost::new(config).start();
        assert!(
            host_handle.status().services.is_empty(),
            "no enabled services, empty status"
        );
        host_handle.shutdown().await;
    }

    /// Dropping the handle cancels the token (the Drop contract: never
    /// blocks, no async).
    #[tokio::test]
    async fn dropping_the_handle_cancels_the_token() {
        let dir = tempfile::tempdir().expect("temp dir");
        let keystore = std::env::temp_dir().join("tor-socks5-onion-host-drop-test");
        let config =
            OnionHostConfig::new(test_handle(dir.path()), keystore, CancellationToken::new());
        let host_handle = OnionHost::new(config).start();
        let token = host_handle.token().clone();
        assert!(!token.is_cancelled());
        std::mem::drop(host_handle);
        assert!(token.is_cancelled(), "Drop cancelled the token");
    }
}
