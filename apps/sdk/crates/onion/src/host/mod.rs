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
//!      └─ managers JoinSet (one manager per service that may start)
//!         └─ per-manager children JoinSet (supervised serving + status
//!            logger; a failure relaunches the service) and a slot-holder
//!            JoinSet
//!            └─ handshake JoinSet (rend.accept only) → accepted-circuit
//!               channel → circuit JoinSet → forwarding JoinSets
//! ```
//!
//! Each JoinSet owns its children: aborting a parent drops its set and aborts
//! descendants rather than detaching them. Graceful cancellation awaits the
//! children before the parent returns. Managers hold one of at most MAX_STARTING
//! launch slots from just before launch until terminal status, the 90 s slot
//! cap, or shutdown; retry/backoff is 30 s doubling to 5 min, ±20% spread.
//! Serving is supervised: rendezvous handshakes run behind a 32-slot accept
//! gate (held only for `rend.accept()`), each accepted circuit gets its own
//! long-lived task, stream permits are per-service first then global
//! (≤512 process-wide, fairly divided per service), arti enforces a 256
//! per-circuit stream cap, and the manager relaunches a service whose
//! serving tasks fail or report `Broken`. Forwarding carries a 5-minute
//! idle timeout, and the local target is connected before the client stream
//! is accepted (connect-before-accept).
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

pub(crate) mod forward;
pub(crate) mod serve;
pub(crate) mod start_gate;
pub mod status;

#[cfg(test)]
#[path = "ownership_tests.rs"]
mod ownership_tests;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use proxy_config::OnionServiceEntry;
use tokio_util::sync::CancellationToken;
use tor_socks5_runtime::tor_watchdog::TorHandle;
use tracing::{error, info, warn};

use crate::keys;
use keys::PreparationFailure;
use status::StatusTracker;

// Used directly in non-test builds or via the cfg(test) HostTestHooks fields.
#[allow(dead_code)]
type PrepareAllHook =
    dyn Fn(Option<&Path>, &Path, &[OnionServiceEntry]) -> Vec<keys::PreparedService> + Send + Sync;
#[allow(dead_code)]
type LockProbeHook = dyn Fn(&Path) -> LockProbe + Send + Sync;
#[allow(dead_code)]
type ServiceLaunchedHook = dyn Fn(&Arc<tor_hsservice::RunningOnionService>) + Send + Sync;
#[allow(dead_code)]
type ServeStartedHook = dyn Fn() + Send + Sync;

#[cfg(test)]
#[derive(Default)]
struct HostTestHooks {
    lock_probe: Option<Arc<LockProbeHook>>,
    prepare_all: Option<Arc<PrepareAllHook>>,
    lock_wait: Option<Duration>,
    service_launched: Option<Arc<ServiceLaunchedHook>>,
    serve_started: Option<Arc<ServeStartedHook>>,
}

enum LockProbe {
    Acquired(persist_lock::PathLock),
    Busy,
    Unavailable,
}

pub use status::{OnionHostStatus, ServiceFailure, ServiceState, ServiceStatus};

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

/// Above this many enabled services the setup is beyond what is known to
/// work through a small bridge pool: a warning is logged, nothing is refused.
const SERVICES_SOFT_LIMIT: usize = 10;

fn beyond_soft_limit(enabled: usize) -> bool {
    enabled > SERVICES_SOFT_LIMIT
}

/// Everything the host needs to run the configured onion services.
///
/// The keystore directory ([`OnionHostConfig::keystore_dir`]) is explicit:
/// the caller supplies it, and the host verifies it against the running
/// client's state dir when known (a foreign dir would mean keys written
/// there are never read by arti). The onion services file location
/// ([`OnionHostConfig::config_path`]) is also explicit: the caller decides
/// where they live (the CLI derives both from its config path; an
/// embedding host may choose anything).
pub struct OnionHostConfig {
    /// The live Tor client handle; read per launch attempt.
    pub handle: TorHandle,
    /// The configured services; only the enabled ones are hosted.
    pub entries: Vec<OnionServiceEntry>,
    /// Where the onion services file lives, as today; `None` means built-in
    /// defaults (no file to complete).
    pub config_path: Option<PathBuf>,
    /// The Arti native keystore directory. Explicit; never derived here.
    /// The caller supplies it; the host verifies it against the running
    /// client's state dir when known (see [`validate_keystore_dir`]).
    pub keystore_dir: PathBuf,
    /// The cancellation token: cancels the producer, the managers and every
    /// task they spawned.
    pub token: CancellationToken,
    #[cfg(test)]
    test_hooks: Option<HostTestHooks>,
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
            #[cfg(test)]
            test_hooks: None,
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
                #[cfg(test)]
                test_hooks: config.test_hooks,
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
/// cancel-safe: yes — lock probes do not wait on the OS lock; cancellation
/// drops a pending probe and is observed during async retry sleeps.
async fn run_services(config: OnionHostConfig, tracker: StatusTracker) {
    let OnionHostConfig {
        handle,
        entries,
        config_path,
        keystore_dir,
        token,
        #[cfg(test)]
        test_hooks,
    } = config;

    if token.is_cancelled() {
        mark_entries_stopped(&tracker, &entries);
        return;
    }

    // Before touching the keystore: a dir the running client would never
    // read fails every service up front.
    if let Err(error) = validate_keystore_dir(handle.state_dir(), &keystore_dir) {
        tracker.set_all(ServiceFailure::KeystoreMismatch);
        error!(%error, "onion services not started: keystore directory mismatch");
        return;
    }

    #[cfg(test)]
    let lock_probe = test_hooks
        .as_ref()
        .and_then(|hooks| hooks.lock_probe.clone())
        .unwrap_or_else(|| Arc::new(probe_keystore_lock));
    #[cfg(not(test))]
    let lock_probe: Arc<LockProbeHook> = Arc::new(probe_keystore_lock);
    #[cfg(test)]
    let lock_wait = test_hooks
        .as_ref()
        .and_then(|hooks| hooks.lock_wait)
        .unwrap_or(persist_lock::CLI_LOCK_WAIT);
    #[cfg(not(test))]
    let lock_wait = persist_lock::CLI_LOCK_WAIT;
    let lock = acquire_keystore_lock(&keystore_dir, &token, lock_probe, lock_wait).await;
    let _lock = match lock {
        LockResult::Acquired(guard) => guard,
        LockResult::Cancelled => {
            mark_entries_stopped(&tracker, &entries);
            return;
        }
        LockResult::Busy => {
            tracker.set_all(ServiceFailure::KeystoreLockHeld);
            error!(
                "onion services not started: the onion keystore lock is held \
                 elsewhere (a tor-socks5 onion command or another server instance?)"
            );
            return;
        }
        LockResult::Unavailable => {
            tracker.set_all(ServiceFailure::KeystoreUnavailable);
            error!("onion services not started: the onion keystore lock is unavailable");
            return;
        }
        LockResult::Internal(error) => {
            tracker.set_all(ServiceFailure::Internal);
            error!(%error, "onion services not started: lock task panicked");
            return;
        }
    };

    // Preparation mutates the keystore and may update the services file, so
    // once started it must finish; cancellation is checked before and after.
    if token.is_cancelled() {
        mark_entries_stopped(&tracker, &entries);
        return;
    }
    let preparation_token = token.clone();
    let preparation_entries = entries.clone();
    #[cfg(test)]
    let preparation_hook: Option<Arc<PrepareAllHook>> = test_hooks
        .as_ref()
        .and_then(|hooks| hooks.prepare_all.clone());
    #[cfg(not(test))]
    let preparation_hook: Option<Arc<PrepareAllHook>> = None;
    let prepared = tokio::task::spawn_blocking(move || {
        if preparation_token.is_cancelled() {
            return None;
        }
        if let Some(prepare) = preparation_hook {
            return Some(prepare(
                config_path.as_deref(),
                &keystore_dir,
                &preparation_entries,
            ));
        }
        Some(keys::prepare_all(
            config_path.as_deref(),
            &keystore_dir,
            &preparation_entries,
        ))
    })
    .await;
    let prepared = match prepared {
        Ok(Some(prepared)) => prepared,
        Ok(None) => {
            mark_entries_stopped(&tracker, &entries);
            return;
        }
        Err(error) => {
            error!(%error, "onion services not started: the identity batch task panicked");
            tracker.set_all(ServiceFailure::Internal);
            return;
        }
    };
    if token.is_cancelled() {
        mark_prepared_stopped(&tracker, &prepared);
        return;
    }

    // Gradual start: managers spawn in services-file order and the gate
    // hands freed slots out FIFO, so services launch in file order.
    let gate = start_gate::StartGate::new();
    // The global stream budget, divided fairly among the enabled services
    // (each manager gets its share; see `serve::per_service_stream_cap`).
    let stream_cap = serve::per_service_stream_cap(entries.len());
    let global_streams = Arc::new(tokio::sync::Semaphore::new(
        serve::MAX_TOTAL_CONCURRENT_STREAMS,
    ));
    let mut managers = tokio::task::JoinSet::new();
    for service in prepared {
        if token.is_cancelled() {
            mark_service_stopped(&tracker, &service.entry.nickname);
            continue;
        }
        let Some(expected_address) = service.address else {
            let (status, failure) = if service.entry.enabled {
                (ServiceStatus::Failed, service.failure.map(service_failure))
            } else {
                (ServiceStatus::Stopped, None)
            };
            tracker.set(&service.entry.nickname, ServiceState { status, failure });
            continue;
        };
        #[cfg(test)]
        let service_launched = test_hooks
            .as_ref()
            .and_then(|hooks| hooks.service_launched.clone());
        #[cfg(test)]
        let serve_started = test_hooks
            .as_ref()
            .and_then(|hooks| hooks.serve_started.clone());
        managers.spawn(serve::service_manager(
            handle.clone(),
            service.entry,
            expected_address,
            gate.clone(),
            stream_cap,
            global_streams.clone(),
            token.clone(),
            tracker.clone(),
            #[cfg(test)]
            service_launched,
            #[cfg(test)]
            serve_started,
        ));
    }
    join_logged(
        &mut managers,
        "onion service manager task ended with a join error",
    )
    .await;
}

/// Outcome of an asynchronous, nonblocking keystore-lock probe.
enum LockResult {
    Acquired(persist_lock::PathLock),
    Busy,
    Unavailable,
    Cancelled,
    Internal(anyhow::Error),
}

/// Repeated zero-duration probes keep cancellation responsive without leaving
/// a blocking worker parked behind a held cross-process lock.
/// cancel-safe: yes — cancellation is checked before each probe and during the
/// asynchronous retry delay; the current zero-wait probe is joined to completion.
async fn acquire_keystore_lock(
    dir: &Path,
    token: &CancellationToken,
    probe: Arc<dyn Fn(&Path) -> LockProbe + Send + Sync>,
    wait: Duration,
) -> LockResult {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        if token.is_cancelled() {
            return LockResult::Cancelled;
        }
        let dir = dir.to_path_buf();
        let probe = Arc::clone(&probe);
        let result = tokio::task::spawn_blocking(move || probe(&dir)).await;
        let result = match result {
            Ok(result) => result,
            Err(error) => return LockResult::Internal(anyhow::Error::new(error)),
        };
        match result {
            LockProbe::Acquired(guard) => return LockResult::Acquired(guard),
            LockProbe::Unavailable => return LockResult::Unavailable,
            LockProbe::Busy if tokio::time::Instant::now() >= deadline => {
                return LockResult::Busy;
            }
            LockProbe::Busy => {}
        }
        tokio::select! {
            biased;
            () = token.cancelled() => return LockResult::Cancelled,
            () = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }
}

/// Canonicalize a path, falling back to the raw path when canonicalization
/// fails (e.g. the dir does not exist), so comparison behaves the same for
/// non-existing dirs.
fn canonicalized(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Check `keystore_dir` against the running client's state dir. `None`
/// (state dir unknown) passes — nothing can be checked. Pure; no I/O the
/// caller cannot predict beyond canonicalization of the two paths.
fn validate_keystore_dir(state_dir: Option<&Path>, keystore_dir: &Path) -> Result<(), String> {
    let Some(state) = state_dir else {
        return Ok(());
    };
    let expected = canonicalized(&state.join("keystore"));
    let configured = canonicalized(keystore_dir);
    if configured == expected {
        return Ok(());
    }
    Err(format!(
        "keystore_dir {} does not match the running client's keystore {}; \
         keys written there would never be read by arti",
        configured.display(),
        expected.display()
    ))
}

fn probe_keystore_lock(dir: &Path) -> LockProbe {
    match persist_lock::PathLock::acquire_bounded(dir, Duration::ZERO) {
        Ok(guard) => LockProbe::Acquired(guard),
        Err(error)
            if error
                .chain()
                .any(|cause| cause.to_string().contains(" is busy:")) =>
        {
            LockProbe::Busy
        }
        Err(_) => LockProbe::Unavailable,
    }
}

fn mark_service_stopped(tracker: &StatusTracker, nickname: &str) {
    tracker.set(
        nickname,
        ServiceState {
            status: ServiceStatus::Stopped,
            failure: None,
        },
    );
}

fn mark_entries_stopped(tracker: &StatusTracker, entries: &[OnionServiceEntry]) {
    for entry in entries {
        mark_service_stopped(tracker, &entry.nickname);
    }
}

fn mark_prepared_stopped(tracker: &StatusTracker, prepared: &[keys::PreparedService]) {
    for service in prepared {
        mark_service_stopped(tracker, &service.entry.nickname);
    }
}

/// Join every child task and log unexpected join failures. Cancelled joins
/// are expected during shutdown.
///
/// This ownership boundary is essential: aborting a parent that owns a
/// `JoinSet` aborts its remaining children on drop. An aborted parent must
/// never detach children, or descendant work would outlive the host.
pub(crate) async fn join_logged(set: &mut tokio::task::JoinSet<()>, message: &'static str) {
    while let Some(result) = set.join_next().await {
        if let Err(error) = result {
            if !error.is_cancelled() {
                warn!(%error, message);
            }
        }
    }
}

fn service_failure(failure: PreparationFailure) -> ServiceFailure {
    match failure {
        PreparationFailure::InvalidNickname => ServiceFailure::InvalidNickname,
        PreparationFailure::EntryMissingFromFile => ServiceFailure::EntryMissingFromFile,
        PreparationFailure::IdentityChanged => ServiceFailure::IdentityChanged,
        PreparationFailure::AddressMismatch => ServiceFailure::AddressMismatch,
        PreparationFailure::KeystoreUnavailable => ServiceFailure::KeystoreUnavailable,
        PreparationFailure::Internal => ServiceFailure::Internal,
    }
}

#[cfg(test)]
mod tests;
