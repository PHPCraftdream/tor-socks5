//! The bridge manager (SDK-8): one handle owning the runtime's background
//! bridge producers, plus `bridges fetch` as a library function.
//!
//! # Process contract (D5, docs/plans/sdk-coverage-plan.md §4 rev. 8 / §9)
//!
//! One live [`BridgeManagerHandle`] per process. The producers' shared state is
//! process-wide, not per-manager:
//!
//! - `bridge_store_writer::{WRITER, init_global, close_global}` — the
//!   bridge-health writer slot. RT-0 is executed: the slot is resettable,
//!   and `init_global` after a *completed* `close_global` starts a fresh
//!   live writer, so a sequential stop → start restart works (covered by
//!   `bridge_store_writer_tests/external_cli_tests.rs`). Caveat: while a
//!   close is still in flight, `init_global` hands back the writer being
//!   closed — await `close_global` before restarting.
//! - `workers::BLOCKING_WORKERS` — the process-wide blocking-worker
//!   registry; it survives restarts by design.
//! - `bridge_verifier::VERIFY_LOCK` and `candidate_pool::SAVE_SEQ` —
//!   process-wide mutex and save counter; correct for sequential restarts.
//!
//! The watchdog producers (`spawn_tor_watchdog`,
//! `spawn_bridge_failover_watchdog`) belong to the server tree, not to this
//! manager; a host composes them alongside.
//!
//! Shutdown order for a correct restart:
//! [`BridgeManagerHandle::shutdown_with_timeout`] first (it awaits every
//! producer so in-flight store writes land), then
//! `bridge_store_writer::close_global`.
//!
//! # Fetching bridges
//!
//! [`fetch_bridges`] is the core of the CLI's `bridges fetch` command:
//! bootstrap Tor from the configured bridges (built-in seeds as fallback),
//! refresh the candidate pool from the configured HTTPS sources, optionally
//! probe-and-promote, and merge into the config. The CLI wrapper keeps
//! config loading, tracing/crypto installation and printing; the typed
//! [`FetchBridgesError`] covers the pre-flight rejections (`NoConfigFile`,
//! `PreProxies`, `NoBridgeSources`) and `Cancelled`. `config_path` is
//! required (D-H1): the type enforces it, and a path to a nonexistent
//! config is the typed `NoConfigFile` error.
//!
//! # Cancel-safety
//!
//! Not cancel-safe, like the code it moved from: `TorTunnel::bootstrap_with`
//! has no cancellation point inside arti, and
//! `fetch_merge::refresh_candidate_pool` / `fetch_merge::drain_pool`
//! perform network I/O and file writes that are aborted mid-way by
//! cancellation (the cross-process pool-lock registry remains registered
//! afterwards, per `fetch_merge`'s own docs). Cancellation is observed at
//! every stage: pre-flight (immediate `Cancelled`, before any I/O), the
//! settings build, the bootstrap, the pool refresh and the drain (each
//! raced against `params.cancel.cancelled()`).
//!
//! Once the tunnel exists, ANY error or cancellation drops the tunnel and
//! then runs the trailing 200 ms post-drop sleep — the cleanup tail is
//! deliberately NOT cancellable, so arti's reactor releases the PT children
//! and the state-dir lock before the next bootstrap. A cancellation during
//! (or before) the *final* pause after a successful fetch skips the rest of
//! the pause but never loses the already-recorded outcome: the call still
//! returns `Ok`.
//!
//! R1/R2/R3/R4/R5: no new statics, config in / handle out, tasks owned by
//! the handle, status via `tokio::sync::watch`, `tracing` only.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use arti_wrapper::TorTunnel;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::arti_observability::ObservationSink;
use crate::config::Config;
use crate::tor_watchdog::TorHandle;

/// Runtime producer configuration. The PT policy is captured once at manager
/// start and reused for every later settings rebuild and admission check.
#[derive(Clone, Debug)]
pub struct BridgeManagerConfig {
    /// Initial Tor settings (including pre-endpoint mode).
    pub settings: arti_wrapper::Settings,
    /// PT executable policy retained for this manager's lifetime.
    pub pt_binary: crate::pt::PtBinary,
}

impl From<arti_wrapper::Settings> for BridgeManagerConfig {
    fn from(settings: arti_wrapper::Settings) -> Self {
        Self {
            settings,
            pt_binary: crate::pt::PtBinary::Environment,
        }
    }
}

/// Snapshot of what the manager is currently running (R4: current state via
/// `watch`). Minimal by design: the producers expose no deeper introspection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeManagerStatus {
    /// Names of the producers started by [`start`]:
    /// `"maintenance"`, plus `"warmer"` when the warm pool is enabled and
    /// `"verifier"`, in start order. Does not change after start.
    pub producers: Vec<String>,
    /// Whether [`BridgeManagerHandle::shutdown`] or dropping the handle has
    /// cancelled the producer token.
    pub cancelled: bool,
}

/// Per-producer shutdown result reported by
/// [`BridgeManagerHandle::shutdown_with_timeout`].
#[derive(Debug)]
pub struct ProducerShutdownOutcome {
    /// Producer name (e.g. `"maintenance"`).
    pub producer: String,
    /// `Ok(())` when the producer finished; `Err` carries the panic message
    /// or `"shutdown budget exceeded"` when the task did not finish in time.
    pub outcome: Result<(), String>,
}

/// Handle owning the producers started by [`start`] (R3).
/// Dropping the handle cancels the token and aborts owned tasks unless their
/// join handles have been transferred to another owner.
pub struct BridgeManagerHandle {
    token: CancellationToken,
    status_tx: watch::Sender<BridgeManagerStatus>,
    status_rx: watch::Receiver<BridgeManagerStatus>,
    handles: Vec<(String, JoinHandle<()>)>,
    tasks_transferred: bool,
}

impl Drop for BridgeManagerHandle {
    fn drop(&mut self) {
        if !self.tasks_transferred {
            self.token.cancel();
            self.status_tx.send_modify(|s| s.cancelled = true);
            for (_, handle) in &self.handles {
                handle.abort();
            }
        }
    }
}

impl BridgeManagerHandle {
    /// A clone of the cancellation token driving every producer.
    pub fn token(&self) -> CancellationToken {
        self.token.clone()
    }

    /// The current snapshot.
    pub fn status(&self) -> BridgeManagerStatus {
        self.status_rx.borrow().clone()
    }

    /// Subscribe to status changes.
    pub fn subscribe(&self) -> watch::Receiver<BridgeManagerStatus> {
        self.status_rx.clone()
    }

    /// Cancel the token and await every producer JoinHandle within `budget`,
    /// so in-flight work (probe batches, store writes) lands before the caller
    /// closes the bridge-store writer.
    ///
    /// Budget semantics: the total time spent joining never exceeds `budget`
    /// (plus scheduling slack). The remaining budget is shared across
    /// producers in order; a hung producer consumes the rest, and any task
    /// that does not finish in time is aborted and reported as
    /// `Err("shutdown budget exceeded")`. A producer task that panicked is
    /// reported as `Err(panic message)` and logged at `warn!`, so panics are
    /// never silently lost.
    ///
    /// Cancel-safe: no. Cancelling this future drops the handle, aborting any
    /// remaining producer tasks without awaiting their completion.
    pub async fn shutdown_with_timeout(mut self, budget: Duration) -> Vec<ProducerShutdownOutcome> {
        self.status_tx.send_modify(|s| s.cancelled = true);
        self.token.cancel();

        let deadline = Instant::now() + budget;
        let mut outcomes = Vec::with_capacity(self.handles.len());
        for (producer, handle) in self.handles.iter_mut() {
            let producer = &**producer;
            let result = if Instant::now() < deadline {
                match tokio::time::timeout_at(deadline, &mut *handle).await {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(join_error)) => {
                        let message = panic_message(join_error);
                        warn!(producer = %producer, message = %message, "producer task panicked during shutdown");
                        Err(message)
                    }
                    Err(_) => {
                        warn!(producer = %producer, "producer did not shut down within the budget; aborted");
                        Err("shutdown budget exceeded".to_string())
                    }
                }
            } else {
                handle.abort();
                warn!(producer = %producer, "producer did not shut down within the budget; aborted");
                Err("shutdown budget exceeded".to_string())
            };
            outcomes.push(ProducerShutdownOutcome {
                producer: producer.to_string(),
                outcome: result,
            });
        }
        outcomes
    }

    /// Transfer producer tasks to `destination` and disable cancellation on
    /// this handle's drop. The caller inherits responsibility for joining or
    /// aborting every transferred task and must arrange their cancellation.
    pub fn transfer_tasks(mut self, destination: &mut Vec<JoinHandle<()>>) {
        self.tasks_transferred = true;
        destination.extend(
            std::mem::take(&mut self.handles)
                .into_iter()
                .map(|(_, handle)| handle),
        );
    }
}

/// Extract a human-readable message from a `JoinError` panic payload.
fn panic_message(join_error: tokio::task::JoinError) -> String {
    if join_error.is_panic() {
        let payload = join_error.into_panic();
        if let Some(message) = payload.downcast_ref::<&str>() {
            (*message).to_string()
        } else if let Ok(message) = payload.downcast::<String>() {
            *message
        } else {
            "unknown panic payload".to_string()
        }
    } else {
        join_error.to_string()
    }
}

/// Start the runtime-owned bridge producers (the non-watchdog part of the
/// binary's `fetch::bridge_producers::launch`). In the pre-endpoint branch
/// only maintenance runs — warmer and verifier are disabled, and the same
/// warning is logged as the binary logs. The tasks belong to the returned
/// handle; nothing is detached (R3). The PT executable policy from `config`
/// is retained for later maintenance rebuilds and verifier admission checks.
pub fn start(
    handle: TorHandle,
    config_path: PathBuf,
    cfg: &Config,
    observations: ObservationSink,
    config: impl Into<BridgeManagerConfig>,
) -> BridgeManagerHandle {
    start_with_token(
        handle,
        config_path,
        cfg,
        observations,
        config.into(),
        CancellationToken::new(),
    )
}

/// Start bridge producers under a child of `parent_token`. Cancelling the
/// parent token cancels the producer token as well; the returned handle owns
/// the producer tasks until they are transferred or shut down.
pub fn start_with_parent_token(
    handle: TorHandle,
    config_path: PathBuf,
    cfg: &Config,
    observations: ObservationSink,
    config: impl Into<BridgeManagerConfig>,
    parent_token: CancellationToken,
) -> BridgeManagerHandle {
    start_with_token(
        handle,
        config_path,
        cfg,
        observations,
        config.into(),
        parent_token.child_token(),
    )
}

fn start_with_token(
    handle: TorHandle,
    config_path: PathBuf,
    cfg: &Config,
    observations: ObservationSink,
    config: BridgeManagerConfig,
    token: CancellationToken,
) -> BridgeManagerHandle {
    let BridgeManagerConfig {
        settings,
        pt_binary,
    } = config;
    let (status_tx, status_rx) = watch::channel(BridgeManagerStatus {
        producers: Vec::new(),
        cancelled: false,
    });
    let mut producers = Vec::new();

    if settings.pre_endpoint.is_some() {
        tracing::warn!(
            "global pre_proxies: warmer, verifier, discovery and soft failover remain disabled"
        );
        producers.push((
            "maintenance",
            crate::bridge_maintenance::spawn(
                handle,
                config_path,
                cfg.bridges.recheck_interval_mins,
                observations,
                settings,
                pt_binary.clone(),
                token.clone(),
            ),
        ));
    } else {
        producers.push((
            "maintenance",
            crate::bridge_maintenance::spawn(
                handle.clone(),
                config_path.clone(),
                cfg.bridges.recheck_interval_mins,
                observations,
                settings,
                pt_binary.clone(),
                token.clone(),
            ),
        ));
        if let Some(warmer) = crate::bridge_warmer::spawn_bridge_warmer(
            handle.clone(),
            config_path.clone(),
            cfg.warm_pool,
            token.clone(),
        ) {
            producers.push(("warmer", warmer));
        }
        producers.push((
            "verifier",
            crate::bridge_verifier::spawn_bridge_circuit_verifier(
                config_path,
                handle,
                pt_binary,
                token.clone(),
            ),
        ));
    }

    status_tx.send_modify(|s| {
        s.producers = producers.iter().map(|(name, _)| name.to_string()).collect();
    });

    BridgeManagerHandle {
        token,
        status_tx,
        status_rx,
        handles: producers
            .into_iter()
            .map(|(name, handle)| (name.to_string(), handle))
            .collect(),
        tasks_transferred: false,
    }
}

/// Parameters for [`fetch_bridges`].
pub struct FetchBridgesParams {
    /// Per-source fetch timeout, passed to
    /// `fetch_merge::refresh_candidate_pool`.
    pub timeout: Duration,
    /// How many reachable bridges to promote into the working config when
    /// `probe` is `true`.
    pub count: usize,
    /// `false` fills the pool without probing/promoting (the CLI's
    /// `--dry-run`/`--no-probe` modes).
    pub probe: bool,
    /// PT executable policy used for the bootstrap settings and the
    /// admission/drain checks.
    pub pt_binary: crate::pt::PtBinary,
    /// Cancellation for the fetch. See the module docs for cancel-safety.
    pub cancel: CancellationToken,
}

/// Typed error for [`fetch_bridges`]: the synchronous pre-flight rejections
/// and cancellation get their own variants; everything else is wrapped.
#[derive(Debug)]
pub enum FetchBridgesError {
    /// The config file at the required path does not exist; the SDK never
    /// creates a default file.
    NoConfigFile,
    /// A global `pre_proxies` pool is configured; remove it (the fetch
    /// cannot honour it — it runs over the host network).
    PreProxies,
    /// No bridge sources configured — nothing to fetch.
    NoBridgeSources,
    /// The fetch was cancelled (see the module docs for cancel-safety).
    Cancelled,
    /// Any other failure, with its root cause.
    Other(anyhow::Error),
}

impl std::fmt::Display for FetchBridgesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoConfigFile => {
                write!(f, "no config file found; run the server once to create defaults")
            }
            Self::PreProxies => write!(
                f,
                "bridges fetch global pre_proxies proxy pool is not supported; remove it"
            ),
            Self::NoBridgeSources => write!(
                f,
                "no bridge sources configured in the `sources` list of the bridges file — nothing to fetch"
            ),
            Self::Cancelled => write!(f, "bridge fetch cancelled"),
            Self::Other(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for FetchBridgesError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Other(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

impl From<anyhow::Error> for FetchBridgesError {
    fn from(error: anyhow::Error) -> Self {
        Self::Other(error)
    }
}

/// Outcome of [`fetch_bridges`].
#[derive(Debug)]
pub struct FetchBridgesOutcome {
    /// New candidates added to the pool.
    pub added: usize,
    /// Reachable bridges promoted into the working config; `None` when
    /// probing was skipped (`probe == false`).
    pub promoted: Option<usize>,
    /// Candidate-pool size after the run.
    pub pool_len: usize,
}

/// The `bridges fetch` core (moved from the CLI's `cmd_bridges`, same calls
/// in the same order). The trailing 200 ms sleep after dropping the tunnel
/// is kept: it lets arti's reactor release the PT children and the state-dir
/// lock before the process exits or a follow-up bootstrap begins.
///
/// Synchronous pre-flight checks run first, before any file or network I/O
/// beyond the existence check of the config file itself: a nonexistent
/// config → [`FetchBridgesError::NoConfigFile`] (the SDK never creates a
/// default config file), then `pre_proxies` → `PreProxies`, then empty
/// `sources` → `NoBridgeSources`.
///
/// Cancel-safety: see the module docs.
pub async fn fetch_bridges(
    cfg: &Config,
    config_path: &std::path::Path,
    params: FetchBridgesParams,
) -> Result<FetchBridgesOutcome, FetchBridgesError> {
    // Pre-flight: synchronous, cheapest/most specific rejection first. A
    // missing config file is rejected before any load that could create a
    // default config file (the only I/O here is the existence check).
    if !config_path.is_file() {
        return Err(FetchBridgesError::NoConfigFile);
    }
    if cfg.pre_proxies.is_some() {
        return Err(FetchBridgesError::PreProxies);
    }
    if cfg.bridges.sources.is_empty() {
        return Err(FetchBridgesError::NoBridgeSources);
    }
    if params.cancel.is_cancelled() {
        return Err(FetchBridgesError::Cancelled);
    }

    let result: Result<FetchBridgesOutcome, FetchBridgesError> = async {
        // Settings build and bootstrap are each cancellation points: the
        // token wins over the in-flight future. Neither has created the
        // tunnel yet, so no cleanup tail runs for them.
        let settings = tokio::select! {
            biased;
            _ = params.cancel.cancelled() => {
                return Err(FetchBridgesError::Cancelled);
            }
            settings = crate::tor_setup::build_tor_settings_with_pt(
                cfg,
                config_path,
                params.pt_binary.clone(),
            ) => {
                settings.map_err(FetchBridgesError::Other)?
            }
        };
        info!(
            count = settings.bridges.len(),
            "bootstrapping Tor to fetch fresh bridges"
        );
        let tor = tokio::select! {
            biased;
            _ = params.cancel.cancelled() => {
                return Err(FetchBridgesError::Cancelled);
            }
            tor = TorTunnel::bootstrap_with(settings) => {
                tor.context("failed to bootstrap Tor for bridge fetching")
                    .map_err(FetchBridgesError::Other)?
            }
        };

        // From here on the tunnel exists: any error or cancellation drops
        // it, then runs the 200 ms cleanup tail before returning.
        let work = async {
            let added = tokio::select! {
                biased;
                _ = params.cancel.cancelled() => {
                    return Err(FetchBridgesError::Cancelled);
                }
                added = crate::fetch_merge::refresh_candidate_pool(
                    &tor,
                    cfg,
                    config_path,
                    params.timeout,
                ) => {
                    added.map_err(FetchBridgesError::Other)?
                }
            };

            if !params.probe {
                let pool = crate::candidate_pool::CandidatePool::load(
                    crate::candidate_pool::CandidatePool::resolve_path(config_path),
                )
                .context("loading candidate pool")?;
                return Ok(FetchBridgesOutcome {
                    added,
                    promoted: None,
                    pool_len: pool.len(),
                });
            }

            let promoted = tokio::select! {
                biased;
                _ = params.cancel.cancelled() => {
                    return Err(FetchBridgesError::Cancelled);
                }
                promoted = crate::fetch_merge::drain_pool(
                    config_path,
                    params.count,
                    Some(&tor),
                    params.pt_binary,
                ) => {
                    promoted.map_err(FetchBridgesError::Other)?
                }
            };
            // A failed pool read here must not fail the command; the length
            // is informational only.
            let pool_len = match crate::candidate_pool::CandidatePool::load(
                crate::candidate_pool::CandidatePool::resolve_path(config_path),
            ) {
                Ok(pool) => pool.len(),
                Err(error) => {
                    tracing::warn!(%error, "candidate pool not readable after the drain; pool_len reported as 0");
                    0
                }
            };
            Ok(FetchBridgesOutcome {
                added,
                promoted: Some(promoted),
                pool_len,
            })
        };

        match work.await {
            Ok(outcome) => {
                drop(tor);
                Ok(outcome)
            }
            Err(error) => {
                drop(tor);
                // The cleanup tail is deliberately NOT cancellable: it lets
                // arti's reactor release the PT children and state-dir lock.
                tokio::time::sleep(Duration::from_millis(200)).await;
                Err(error)
            }
        }
    }
    .await;

    // Final pause: a cancellation during (or before) it must never lose the
    // already-recorded outcome — skip the rest of the pause, return `Ok`.
    match result {
        Ok(outcome) => {
            tokio::select! {
                biased;
                _ = params.cancel.cancelled() => {},
                _ = tokio::time::sleep(Duration::from_millis(200)) => {},
            }
            Ok(outcome)
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
