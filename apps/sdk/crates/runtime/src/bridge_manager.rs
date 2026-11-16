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

/// Handle owning the producers started by [`start`] (R3).
/// Dropping the handle cancels the token and aborts owned tasks unless their
/// join handles have been transferred to another owner.
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
            for handle in &self.handles {
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

    /// Cancel the token and await every producer JoinHandle, so in-flight
    /// work (probe batches, store writes) lands before the caller closes the
    /// bridge-store writer.
    ///
    /// Cancel-safe: no. Cancelling this future drops the handle, aborting any
    /// remaining producer tasks without awaiting their completion.
    pub async fn shutdown(mut self) {
        self.status_tx.send_modify(|s| s.cancelled = true);
        self.token.cancel();
        for handle in &mut self.handles {
            let _ = handle.await;
        }
        self.handles.clear();
    }

    /// Transfer producer tasks to `destination` and disable cancellation on
    /// this handle's drop. The caller inherits responsibility for joining or
    /// aborting every transferred task and must arrange their cancellation.
    pub fn transfer_tasks(mut self, destination: &mut Vec<JoinHandle<()>>) {
        self.tasks_transferred = true;
        destination.extend(std::mem::take(&mut self.handles));
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
    config_path: Option<PathBuf>,
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
    config_path: Option<PathBuf>,
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
    config_path: Option<PathBuf>,
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
            crate::bridge_maintenance::spawn_with_pt(
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
            crate::bridge_maintenance::spawn_with_pt(
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
            crate::bridge_verifier::spawn_bridge_circuit_verifier_with_pt(
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

    struct DropSignal(Option<tokio::sync::oneshot::Sender<()>>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            if let Some(signal) = self.0.take() {
                let _ = signal.send(());
            }
        }
    }

    async fn guarded_task(
        wait_for: Option<CancellationToken>,
    ) -> (JoinHandle<()>, tokio::sync::oneshot::Receiver<()>) {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(async move {
            let _guard = DropSignal(Some(dropped_tx));
            let _ = started_tx.send(());
            match wait_for {
                Some(token) => token.cancelled().await,
                None => std::future::pending::<()>().await,
            }
        });
        started_rx.await.expect("task reached its pending point");
        (handle, dropped_rx)
    }

    fn test_manager(token: CancellationToken, handles: Vec<JoinHandle<()>>) -> BridgeManagerHandle {
        let (status_tx, status_rx) = watch::channel(BridgeManagerStatus {
            producers: Vec::new(),
            cancelled: false,
        });
        BridgeManagerHandle {
            token,
            status_tx,
            status_rx,
            handles,
            tasks_transferred: false,
        }
    }

    #[tokio::test]
    async fn sdk14_dropping_manager_aborts_pending_tasks() {
        let (task, dropped) = guarded_task(None).await;
        drop(test_manager(CancellationToken::new(), vec![task]));
        tokio::time::timeout(Duration::from_secs(10), dropped)
            .await
            .expect("manager drop aborts its pending task within 10s")
            .expect("aborted task dropped its guard");
    }

    #[tokio::test]
    async fn sdk14_cancelling_polled_shutdown_aborts_pending_tasks() {
        use std::future::Future;

        let (task, dropped) = guarded_task(None).await;
        let token = CancellationToken::new();
        let mut shutdown = Box::pin(test_manager(token.clone(), vec![task]).shutdown());
        std::future::poll_fn(|cx| match shutdown.as_mut().poll(cx) {
            std::task::Poll::Pending => std::task::Poll::Ready(()),
            std::task::Poll::Ready(()) => panic!("shutdown unexpectedly completed"),
        })
        .await;
        assert!(token.is_cancelled());
        drop(shutdown);
        tokio::time::timeout(Duration::from_secs(10), dropped)
            .await
            .expect("cancelled shutdown aborts its pending task within 10s")
            .expect("cancelled shutdown aborted its task");
    }

    // Synthetic handles and tokens cover transfer and token-tree behavior;
    // this does not exercise start_with_parent_token's production wiring.
    #[tokio::test]
    async fn sdk14_synthetic_child_cancellation_does_not_cancel_parent() {
        let parent = CancellationToken::new();
        let child = parent.child_token();
        test_manager(child.clone(), Vec::new()).shutdown().await;
        assert!(child.is_cancelled());
        assert!(!parent.is_cancelled());
    }

    #[tokio::test]
    async fn sdk14_transferred_synthetic_task_lives_until_parent_cancellation() {
        let parent = CancellationToken::new();
        let child = parent.child_token();
        let (task, mut dropped) = guarded_task(Some(child.clone())).await;
        let manager = test_manager(child.clone(), vec![task]);
        let mut destination = Vec::new();
        manager.transfer_tasks(&mut destination);

        assert_eq!(destination.len(), 1);
        assert!(!destination[0].is_finished());
        assert!(matches!(
            dropped.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));

        parent.cancel();
        assert!(child.is_cancelled());
        for task in destination {
            task.await.expect("cooperatively cancelled task completed");
        }
        dropped
            .await
            .expect("task completed after parent cancellation");
    }

    #[tokio::test(start_paused = true)]
    async fn sdk14_manager_explicit_pt_reaches_maintenance_and_verifier() {
        use std::sync::Once;

        static CRYPTO_PROVIDER: Once = Once::new();
        CRYPTO_PROVIDER.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });

        let dir = tempfile::tempdir().expect("temporary config directory");
        let config_path = dir.path().join("proxy.ktav");
        let bridge: bridge_line::BridgeLine =
            "obfs4 8.8.8.8:443 1414141414141414141414141414141414141414 cert=AAA"
                .parse()
                .expect("valid public obfs4 bridge");
        let mut cfg = Config::default();
        cfg.bridges.lines = vec![bridge.to_string()];
        cfg.bridges.sources.clear();
        cfg.bridges.use_seeds = false;
        cfg.bridges.auto_fetch = false;
        cfg.bridges.recheck_interval_mins = 0;
        cfg.warm_pool.enabled = false;
        cfg.write(&config_path).expect("write isolated config");
        cfg.write_bridges(&config_path)
            .expect("write isolated bridge lines");

        let expected_pt = dir.path().join("explicit-host-pt");
        assert_ne!(
            expected_pt,
            std::env::current_exe().expect("current executable")
        );
        let state_dir = dir.path().join("client-state");
        let initial_settings = arti_wrapper::Settings {
            state_dir: Some(state_dir.clone()),
            bridges: vec![bridge.clone()],
            pt_binary: Some(expected_pt.clone()),
            ..Default::default()
        };
        let tunnel = TorTunnel::create_unbootstrapped_with(arti_wrapper::Settings {
            state_dir: Some(state_dir),
            ..Default::default()
        })
        .expect("create transport-free unbootstrapped tunnel");
        let handle = crate::tor_watchdog::TorHandle::new_with_settings(tunnel, &initial_settings);

        let store_path = bridge_store::BridgeStore::resolve_path(Some(&config_path));
        let mut store = bridge_store::BridgeStore::load(store_path).expect("load bridge store");
        let now = time::OffsetDateTime::now_utc();
        let alive = [(bridge.clone(), Duration::from_millis(1))];
        store.note_probe_round(
            std::slice::from_ref(&bridge),
            &alive,
            now,
            Duration::ZERO,
            u32::MAX,
            u32::MAX,
        );
        store.note_channel_success_at(&bridge, now);
        store
            .save()
            .expect("seed channel-proven verifier candidate");

        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let manager = crate::pt::SDK14_PT_OBSERVER
            .scope(("manager", tx), async {
                start(
                    handle,
                    Some(config_path),
                    &cfg,
                    ObservationSink::default(),
                    BridgeManagerConfig {
                        settings: initial_settings,
                        pt_binary: crate::pt::PtBinary::Explicit(expected_pt.clone()),
                    },
                )
            })
            .await;

        let mut observed = Vec::new();
        tokio::time::timeout(Duration::from_secs(3600), async {
            while !observed.iter().any(|(role, _)| *role == "maintenance")
                || !observed.iter().any(|(role, _)| *role == "verifier")
            {
                observed.push(rx.recv().await.expect("producer PT resolution report"));
            }
        })
        .await
        .expect("maintenance and >30-minute verifier tick report within one hour");

        manager.shutdown().await;
        for (role, path) in observed {
            assert!(matches!(role, "maintenance" | "verifier"));
            assert_eq!(path, expected_pt, "{role} must retain manager PT policy");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn sdk14_manager_explicit_pt_reaches_maintenance_after_transport_free_start() {
        use std::sync::Once;

        static CRYPTO_PROVIDER: Once = Once::new();
        CRYPTO_PROVIDER.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });

        let dir = tempfile::tempdir().expect("temporary config directory");
        let config_path = dir.path().join("proxy.ktav");
        let bridge: bridge_line::BridgeLine =
            "obfs4 8.8.8.8:443 1414141414141414141414141414141414141414 cert=AAA"
                .parse()
                .expect("valid public obfs4 bridge");
        let mut cfg = Config::default();
        cfg.bridges.lines = vec![bridge.to_string()];
        cfg.bridges.sources.clear();
        cfg.bridges.use_seeds = false;
        cfg.bridges.auto_fetch = false;
        cfg.bridges.recheck_interval_mins = 0;
        cfg.warm_pool.enabled = false;
        cfg.write(&config_path).expect("write isolated config");
        cfg.write_bridges(&config_path)
            .expect("write isolated bridge lines");

        let expected_pt = dir.path().join("explicit-host-pt");
        let state_dir = dir.path().join("client-state");
        let initial_settings = arti_wrapper::Settings {
            state_dir: Some(state_dir.clone()),
            bridges: Vec::new(),
            pt_binary: None,
            ..Default::default()
        };
        let tunnel = TorTunnel::create_unbootstrapped_with(arti_wrapper::Settings {
            state_dir: Some(state_dir),
            ..Default::default()
        })
        .expect("create transport-free unbootstrapped tunnel");
        let handle = crate::tor_watchdog::TorHandle::new_with_settings(tunnel, &initial_settings);

        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let manager = crate::pt::SDK14_PT_OBSERVER
            .scope(("manager", tx), async {
                start(
                    handle,
                    Some(config_path),
                    &cfg,
                    ObservationSink::default(),
                    BridgeManagerConfig {
                        settings: initial_settings,
                        pt_binary: crate::pt::PtBinary::Explicit(expected_pt.clone()),
                    },
                )
            })
            .await;

        let mut observed = Vec::new();
        tokio::time::timeout(Duration::from_secs(3600), async {
            while !observed.iter().any(|(role, _)| *role == "maintenance") {
                observed.push(rx.recv().await.expect("maintenance PT resolution report"));
            }
        })
        .await
        .expect("maintenance PT resolution report within one hour");

        manager.shutdown().await;
        assert_eq!(observed, vec![("maintenance", expected_pt)]);
    }
}
