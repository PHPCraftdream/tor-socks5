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
//! Shutdown order for a correct restart: [`BridgeManagerHandle::shutdown`]
//! first (it awaits every producer so in-flight store writes land), then
//! `bridge_store_writer::close_global`.
//!
//! # Fetching bridges
//!
//! [`fetch_bridges`] is the core of the CLI's `bridges fetch` command:
//! bootstrap Tor from the configured bridges (built-in seeds as fallback),
//! refresh the candidate pool from the configured HTTPS sources, optionally
//! probe-and-promote, and merge into the config. The CLI wrapper keeps
//! config loading, `reject_unsupported_pool`, tracing/crypto installation
//! and printing.
//!
//! # Cancel-safety
//!
//! Not cancel-safe, like the code it moved from: `TorTunnel::bootstrap_with`
//! has no cancellation point, and `fetch_merge::refresh_candidate_pool` /
//! `fetch_merge::drain_pool` perform network I/O and file writes that are
//! aborted mid-way by cancellation (the cross-process pool-lock registry
//! remains registered afterwards, per `fetch_merge`'s own docs). On
//! cancellation [`fetch_bridges`] returns an error and skips the trailing
//! 200 ms post-drop sleep.
//!
//! R1/R2/R3/R4/R5: no new statics, config in / handle out, tasks owned by
//! the handle, status via `tokio::sync::watch`, `tracing` only.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use arti_wrapper::TorTunnel;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::arti_observability::ObservationSink;
use crate::config::Config;
use crate::tor_watchdog::TorHandle;

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

/// Handle owning the producers started by [`start`] (R3).
/// `Drop` cancels the token without blocking; unless tasks are explicitly
/// transferred to the server, their JoinHandles are simply dropped.
pub struct BridgeManagerHandle {
    token: CancellationToken,
    status_tx: watch::Sender<BridgeManagerStatus>,
    status_rx: watch::Receiver<BridgeManagerStatus>,
    handles: Vec<JoinHandle<()>>,
    tasks_transferred: bool,
}

impl Drop for BridgeManagerHandle {
    fn drop(&mut self) {
        if !self.tasks_transferred {
            self.token.cancel();
            self.status_tx.send_modify(|s| s.cancelled = true);
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

    /// Cancel the token and await every producer JoinHandle, so in-flight
    /// work (probe batches, store writes) lands before the caller closes the
    /// bridge-store writer.
    pub async fn shutdown(mut self) {
        self.status_tx.send_modify(|s| s.cancelled = true);
        self.token.cancel();
        for handle in self.handles.drain(..) {
            let _ = handle.await;
        }
    }

    /// Transfer the producer tasks to the server's cancellation-safe owner.
    ///
    /// Transitional SDK-11 bridge: call only on a handle returned by
    /// [`start_for_server`], whose producer token is a child of the server
    /// token. The server retains these handles directly because cancelling a
    /// task awaiting `shutdown()` would detach the manager's children. Remove
    /// this hidden cross-crate API when SDK-14 unifies task ownership.
    #[doc(hidden)]
    pub fn into_tasks(mut self) -> Vec<JoinHandle<()>> {
        self.tasks_transferred = true;
        self.handles.drain(..).collect()
    }
}

/// Start the runtime-owned bridge producers (the non-watchdog part of the
/// binary's `fetch::bridge_producers::launch`). In the pre-endpoint branch
/// only maintenance runs — warmer and verifier are disabled, and the same
/// warning is logged as the binary logs. The tasks belong to the returned
/// handle; nothing is detached (R3).
pub fn start(
    handle: TorHandle,
    config_path: Option<PathBuf>,
    cfg: &Config,
    observations: ObservationSink,
    settings: arti_wrapper::Settings,
) -> BridgeManagerHandle {
    start_with_token(
        handle,
        config_path,
        cfg,
        observations,
        settings,
        CancellationToken::new(),
    )
}

/// Start bridge producers under a child of the server's producer token.
///
/// Transitional SDK-11 server bridge: cancelling or aborting the server's
/// producer owner synchronously cancels the bridge tasks too, even if the
/// owner's shutdown join is timed out. Remove with the SDK-14 ownership
/// unification.
#[doc(hidden)]
pub fn start_for_server(
    handle: TorHandle,
    config_path: Option<PathBuf>,
    cfg: &Config,
    observations: ObservationSink,
    settings: arti_wrapper::Settings,
    server_token: CancellationToken,
) -> BridgeManagerHandle {
    start_with_token(
        handle,
        config_path,
        cfg,
        observations,
        settings,
        server_token.child_token(),
    )
}

fn start_with_token(
    handle: TorHandle,
    config_path: Option<PathBuf>,
    cfg: &Config,
    observations: ObservationSink,
    settings: arti_wrapper::Settings,
    token: CancellationToken,
) -> BridgeManagerHandle {
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
        handles: producers.into_iter().map(|(_, handle)| handle).collect(),
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
    /// Cancellation for the fetch. See the module docs for cancel-safety.
    pub cancel: CancellationToken,
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
/// The "no config file found" and `reject_unsupported_pool` checks stay at
/// the CLI; the "no bridge sources configured" check lives here.
///
/// Cancel-safety: see the module docs.
pub async fn fetch_bridges(
    cfg: &Config,
    config_path: Option<&std::path::Path>,
    params: FetchBridgesParams,
) -> Result<FetchBridgesOutcome> {
    if cfg.bridges.sources.is_empty() {
        bail!("no bridge sources configured in the `sources` list of the bridges file — nothing to fetch");
    }

    let settings = crate::tor_setup::build_tor_settings(cfg, config_path).await?;
    info!(
        count = settings.bridges.len(),
        "bootstrapping Tor to fetch fresh bridges"
    );
    let tor = TorTunnel::bootstrap_with(settings)
        .await
        .context("failed to bootstrap Tor for bridge fetching")?;

    let added = tokio::select! {
        biased;
        _ = params.cancel.cancelled() => {
            bail!("bridge fetch cancelled");
        }
        added = crate::fetch_merge::refresh_candidate_pool(
            &tor,
            cfg,
            config_path,
            params.timeout,
        ) => added?,
    };

    let outcome = if !params.probe {
        let pool = crate::candidate_pool::CandidatePool::load(
            crate::candidate_pool::CandidatePool::resolve_path(config_path),
        )
        .context("loading candidate pool")?;
        FetchBridgesOutcome {
            added,
            promoted: None,
            pool_len: pool.len(),
        }
    } else {
        let promoted =
            crate::fetch_merge::drain_pool(config_path, params.count, Some(&tor)).await?;
        // The probing fetch never read the pool afterwards, so a failure to
        // load it here must not fail the command; the length is informational.
        let pool_len = match crate::candidate_pool::CandidatePool::load(
            crate::candidate_pool::CandidatePool::resolve_path(config_path),
        ) {
            Ok(pool) => pool.len(),
            Err(error) => {
                tracing::warn!(%error, "candidate pool not readable after the drain; pool_len reported as 0");
                0
            }
        };
        FetchBridgesOutcome {
            added,
            promoted: Some(promoted),
            pool_len,
        }
    };

    drop(tor);
    tokio::select! {
        biased;
        _ = params.cancel.cancelled() => {
            bail!("bridge fetch cancelled");
        }
        _ = tokio::time::sleep(Duration::from_millis(200)) => {},
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_sources_bails_before_any_tor_or_io() {
        // The default config carries the built-in sources, so clear them.
        let mut cfg = Config::default();
        cfg.bridges.sources.clear();
        let error = fetch_bridges(
            &cfg,
            None,
            FetchBridgesParams {
                timeout: Duration::from_secs(1),
                count: 1,
                probe: true,
                cancel: CancellationToken::new(),
            },
        )
        .await
        .expect_err("no sources configured");
        assert_eq!(
            error.to_string(),
            "no bridge sources configured in the `sources` list of the bridges file — nothing to fetch"
        );
    }

    #[tokio::test]
    async fn shutdown_sets_cancelled_and_reports_producers() {
        let token = CancellationToken::new();
        let (status_tx, status_rx) = watch::channel(BridgeManagerStatus {
            producers: vec!["maintenance".into()],
            cancelled: false,
        });
        let handle = BridgeManagerHandle {
            token: token.clone(),
            status_tx,
            status_rx,
            handles: Vec::new(),
            tasks_transferred: false,
        };
        assert_eq!(handle.status().producers, vec!["maintenance".to_string()]);
        assert!(!handle.status().cancelled);
        assert!(!token.is_cancelled());

        handle.shutdown().await;
        assert!(token.is_cancelled());
    }

    #[tokio::test]
    async fn drop_cancels_token_without_blocking() {
        let (status_tx, status_rx) = watch::channel(BridgeManagerStatus {
            producers: Vec::new(),
            cancelled: false,
        });
        let token = CancellationToken::new();
        let handle = BridgeManagerHandle {
            token: token.clone(),
            status_tx,
            status_rx,
            handles: Vec::new(),
            tasks_transferred: false,
        };
        drop(handle);
        assert!(token.is_cancelled());
    }
}
