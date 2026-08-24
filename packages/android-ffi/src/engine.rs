//! Engine thread, accept loop, and status management.
//!
//! This module contains the core runtime for the Tor SOCKS5 proxy:
//!
//! - [`EngineStatus`]: Internal status enum that maps to the status text protocol.
//! - [`EngineHandle`]: Holds the stop signal, done notification, and thread handle.
//! - [`engine_main`]: Entry point for the dedicated engine thread.
//! - [`accept_loop`]: SOCKS5 accept loop with semaphore-bounded concurrency.

use std::net::SocketAddr;
use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::callback::JavaCallback;
use anyhow::{Context, Result};
use arti_wrapper::{BootstrapEvent, BootstrapEventCallback, TorTunnel};
use auth::AuthState;
use bridge_line::BridgeLine;
use bridge_store::BridgeStore;
use proxy_config::BridgesConfig;
use socks5_proto::{self, Reply};
use time::OffsetDateTime;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing::{debug, error, info, warn};

/// Maximum concurrent SOCKS5 connections.
///
/// Each connection may perform network I/O and hold a Tor circuit, so we bound
/// concurrency to avoid resource exhaustion under connection floods.
const MAX_CONCURRENT_CONNECTIONS: usize = 256;

/// Engine status, used internally and formatted for the JNI status protocol.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum EngineStatus {
    /// Engine is not running and no error state.
    Off,
    /// Engine is starting, with bootstrap progress percentage (0-100).
    Starting(u8),
    /// Engine is fully operational, listening on the given address.
    On(SocketAddr),
    /// Engine is shutting down.
    Stopping,
    /// Engine encountered an error.
    Error(String),
}

impl std::fmt::Display for EngineStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EngineStatus::Off => write!(f, "Off"),
            EngineStatus::Starting(pct) => write!(f, "Starting:{}", pct),
            EngineStatus::On(addr) => write!(f, "On:{}", addr),
            EngineStatus::Stopping => write!(f, "Stopping"),
            EngineStatus::Error(msg) => write!(f, "Error:{}", msg),
        }
    }
}

/// Handle to a running engine thread.
///
/// Holds:
/// - A `watch::Sender` to signal shutdown.
/// - A `mpsc::Receiver` to wait for thread termination.
/// - A `JoinHandle` to join the thread (if needed).
pub(crate) struct EngineHandle {
    pub stop_tx: tokio::sync::watch::Sender<bool>,
    pub done_rx: std::sync::mpsc::Receiver<()>,
    pub thread: std::thread::JoinHandle<()>,
}

/// Everything the engine thread needs to persist and rank bridge
/// reachability across restarts via the shared `bridge-store` crate.
/// Bundled into one struct so threading it through `engine_main`/
/// `engine_async` doesn't push either function over clippy's
/// `too_many_arguments` threshold.
#[derive(Clone)]
pub(crate) struct BridgeHealthContext {
    /// Path to the ktav config file (`tor-socks5.ktav`), used to derive the
    /// sibling `<stem>.alive-bridges.log` health-store path — see
    /// `BridgeStore::resolve_path`.
    pub config_path: Option<PathBuf>,
    /// `max_fails` / `fail_window_mins` / `max_circuit_fails` from the
    /// loaded config, needed by `BridgeStore::note_probe_round`.
    pub bridges_cfg: BridgesConfig,
}

/// Entry point for the dedicated engine thread.
///
/// This function:
/// 1. Attaches to the JVM for the lifetime of the thread.
/// 2. Creates a Tokio runtime with 4 worker threads.
/// 3. Probes bridges for reachability.
/// 4. Bootstraps the Tor client with event callbacks.
/// 5. Binds the SOCKS5 listener.
/// 6. Runs the accept loop until stopped.
/// 7. Cleans up resources (drop tunnel, sleep 500ms).
/// 8. Sends done notification and sets final status.
///
/// All errors are caught and translated to an `Error` status; panics are
/// caught with `catch_unwind` and also translated to an error.
pub(crate) fn engine_main(
    settings: arti_wrapper::Settings,
    listen_addr: SocketAddr,
    auth_state: Option<Arc<AuthState>>,
    stop_rx: tokio::sync::watch::Receiver<bool>,
    done_tx: std::sync::mpsc::Sender<()>,
    java_callback: Arc<JavaCallback>,
    bridge_health: BridgeHealthContext,
) {
    // Attach to the JVM for the entire lifetime of this thread. The guard
    // detaches on drop — `_attach` (and the `vm` it borrows) are the FIRST
    // locals declared here so that they are the LAST ones dropped: every
    // value holding the callback's `GlobalRef` (moved into the closure
    // below and dropped inside it) is therefore released while the thread
    // is still attached, never hitting jni's detached-thread GlobalRef-drop
    // path. The `JavaVM` handle is Arc-cloned out first because `AttachGuard`
    // borrows the `JavaVM` it was created from, and `java_callback` itself
    // must stay movable into the closure below.
    let vm = java_callback.vm_arc();
    let _attach = match vm.attach_current_thread() {
        Ok(guard) => guard,
        Err(e) => {
            error!(error = %e, "failed to attach engine thread to JVM");
            set_final_status(EngineStatus::Error(format!("failed to attach to JVM: {e}")));
            let _ = done_tx.send(());
            return;
        }
    };

    // Tracks whether a `BootstrapEvent::Failed` was already relayed to Java
    // from inside `engine_async` (`bootstrap_with_notify` emits it itself
    // on a bootstrap-specific failure — see its doc comment). The catch-all
    // below only emits `Failed` when this is still false, so a bootstrap
    // failure doesn't fire `onFailed` twice with slightly different text.
    let failed_already_emitted = Arc::new(AtomicBool::new(false));
    // Cloned out before `java_callback` moves into the async block below —
    // needed here, after `catch_unwind` returns, for the catch-all `emit`
    // calls. Both clones drop before `_attach` regardless (it is the first
    // local declared above), so this doesn't disturb the attach/detach
    // ordering invariant described in the comment on `_attach`.
    let java_callback_outer = Arc::clone(&java_callback);
    let failed_flag_outer = Arc::clone(&failed_already_emitted);

    // Wrap everything in catch_unwind to prevent panic unwinding.
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        // Build Tokio runtime. 8 workers, not 4: bootstrap's dirmgr/chanmgr
        // reactors need enough throughput to avoid ChanTimeout under a guard-
        // descriptor fetch burst (see docs/checkpoints/obfs4-connect-
        // investigation.md) -- the CLI daemon runs 16 for the same reason.
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(8)
            .enable_all()
            .thread_name("torsocks5-rt")
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                let msg = format!("failed to create Tokio runtime: {e}");
                error!("{}", msg);
                return Err(anyhow::anyhow!(msg));
            }
        };

        rt.block_on(async move {
            engine_async(
                settings,
                listen_addr,
                auth_state,
                stop_rx,
                java_callback,
                failed_already_emitted,
                bridge_health,
            )
            .await
        })
    }));

    // Set final status based on result. Any error that reaches here without
    // having already gone through the bootstrap-event `Failed` path (e.g.
    // the bridge-probe-empty error, a listener bind failure, or a panic)
    // still needs to reach the Java `BootstrapCallback` -- without this,
    // `onFailed` is simply never called for those paths and the Kotlin side
    // has no way to learn the engine died.
    let final_status = match result {
        Ok(Ok(())) => EngineStatus::Off,
        Ok(Err(e)) => {
            let msg = format!("{:#}", e);
            error!("engine error: {}", msg);
            if !failed_flag_outer.load(Ordering::SeqCst) {
                java_callback_outer.emit(BootstrapEvent::Failed(msg.clone()));
            }
            EngineStatus::Error(msg)
        }
        Err(panic_info) => {
            let panic_msg = panic_info
                .downcast_ref::<String>()
                .map(|s| s.as_str())
                .or_else(|| panic_info.downcast_ref::<&str>().copied())
                .unwrap_or("unknown panic");
            error!("engine panic: {}", panic_msg);
            let msg = format!("engine panicked: {}", panic_msg);
            java_callback_outer.emit(BootstrapEvent::Failed(msg.clone()));
            EngineStatus::Error(msg)
        }
    };

    set_final_status(final_status);

    // Notify the JNI side that we're done
    let _ = done_tx.send(());
}

/// Async engine body, runs inside a Tokio runtime.
async fn engine_async(
    mut settings: arti_wrapper::Settings,
    listen_addr: SocketAddr,
    auth_state: Option<Arc<AuthState>>,
    mut stop_rx: tokio::sync::watch::Receiver<bool>,
    java_callback: Arc<JavaCallback>,
    failed_already_emitted: Arc<AtomicBool>,
    bridge_health: BridgeHealthContext,
) -> Result<()> {
    // Create a shared callback that updates status AND emits to Java
    let callback: BootstrapEventCallback = Arc::new({
        let cb = Arc::clone(&java_callback);
        let failed_flag = Arc::clone(&failed_already_emitted);
        move |event| {
            // Update status based on event
            match &event {
                BootstrapEvent::Progress(fraction, _status_text) => {
                    let pct = (fraction.clamp(0.0, 1.0) * 100.0).round() as u8;
                    set_final_status(EngineStatus::Starting(pct));
                }
                BootstrapEvent::Ready => {
                    // Not forwarded to Java here: this closure runs on a task spawned by
                    // `TorTunnel::forward_bootstrap_events`, independent of `engine_async`'s
                    // own `wait_bootstrapped().await` below -- there is no ordering guarantee
                    // between the two, so emitting Ready here can call Java's onReady() before
                    // `set_final_status(EngineStatus::On(..))` runs. A caller that reacts to
                    // onReady() by immediately calling nativeGetStatus() can then observe a
                    // stale "Starting:N" even though Tor is already up. `engine_async` sets the
                    // status and emits this event itself, in that order, right after the SOCKS
                    // listener is actually bound.
                    return;
                }
                BootstrapEvent::Blocked(_) => {
                    // Blocked is non-fatal, don't change status
                }
                BootstrapEvent::Failed(_) => {
                    // bootstrap_with_notify already relayed this; tell
                    // engine_main's catch-all not to emit a second onFailed
                    // for the same error.
                    failed_flag.store(true, Ordering::SeqCst);
                }
            }
            // Emit to Java
            cb.emit(event);
        }
    });

    // Full, pristine set of configured bridges -- captured before the probe below narrows
    // `settings.bridges` down to just the ones alive at bootstrap time (see the reassignment
    // a few lines down). `stall_watchdog`'s periodic re-probe (docs/circuit-speed-plan.md's
    // Tier 1) needs the *original* list: a bridge dead at bootstrap can come back later, and
    // that is exactly the information the persisted ranking should pick up for the next
    // connect.
    let all_configured_bridges = settings.bridges.clone();

    // Probe bridges for reachability (5s timeout per bridge), but only when bridges were
    // actually configured -- a direct connection (no bridges/PT at all) has nothing to probe,
    // and skipping this block entirely (rather than probing an empty list) matters: probing
    // zero bridges trivially returns zero alive ones, and the "alive.is_empty()" check below
    // would then reject a direct connection outright, even though "no bridges configured" was
    // the user's intent, not a reachability failure.
    if !settings.bridges.is_empty() {
        // Cancellable: without this select!, a stop signal received while probing (which can
        // itself take up to 5s per bridge) is not observed until the accept-loop select!
        // further down, which is never reached if bridges never come up -- nativeStop would
        // then block for its full 10s timeout instead of returning immediately.
        info!(
            count = settings.bridges.len(),
            "probing bridges for reachability"
        );
        let mut alive = tokio::select! {
            biased;
            _ = stop_rx.changed() => {
                info!("received stop signal while probing bridges");
                return Ok(());
            }
            alive = bridge_probe::probe_and_sort(settings.bridges.clone(), Duration::from_secs(5)) => alive,
        };

        persist_and_rank_probe(&settings.bridges, &mut alive, &bridge_health);

        if alive.is_empty() {
            return Err(anyhow::anyhow!(
                "no reachable bridge responded to a TCP probe within 5s (configured bridges)"
            ));
        }

        info!(
            alive = alive.len(),
            total = settings.bridges.len(),
            "bridge probe complete"
        );

        // Rebuild settings with only reachable bridges (fastest first)
        settings.bridges = alive.into_iter().map(|(bridge, _)| bridge).collect();
    }

    // Bootstrap Tor with event notifications. Cancellable for the same
    // reason as the bridge probe above -- bootstrap can run for tens of
    // seconds, and a stop signal received mid-bootstrap must tear the
    // half-built `TorTunnel` down immediately rather than being ignored
    // until bootstrap finishes or times out on its own.
    //
    // Manual two-step (create_unbootstrapped + wait_bootstrapped) instead of the one-shot
    // bootstrap_with_notify: we need the TorTunnel handle DURING the wait so
    // bootstrap_stall_watchdog can call terminate_all_channels() on it. Bootstrap has no
    // built-in stall detection of its own -- if every candidate bridge's PT/TLS handshake
    // fails (bridges dying deeper than the plain TCP probe already ran can catch), arti can
    // sit retrying the same small pool indefinitely at a fixed percentage with nothing to
    // force a fresh attempt.
    info!("bootstrapping Tor client...");
    let tunnel = TorTunnel::create_unbootstrapped_with(settings).context("creating Tor client")?;
    tunnel.forward_bootstrap_events(callback.clone());
    let stall_handle = tokio::spawn(bootstrap_stall_watchdog(tunnel.clone(), callback.clone()));
    let bootstrap_result = tokio::select! {
        biased;
        _ = stop_rx.changed() => {
            stall_handle.abort();
            info!("received stop signal while bootstrapping");
            return Ok(());
        }
        result = tunnel.wait_bootstrapped() => result,
    };
    stall_handle.abort();
    if let Err(error) = bootstrap_result {
        callback(BootstrapEvent::Failed(format!("{:#}", error)));
        return Err(error).context("failed to bootstrap Tor");
    }
    info!("Tor is ready");

    // Bind SOCKS5 listener
    let listener = TcpListener::bind(&listen_addr)
        .await
        .with_context(|| format!("failed to bind SOCKS5 listener to {}", listen_addr))?;

    let actual_addr = listener
        .local_addr()
        .context("failed to get listener address")?;

    info!(listen_addr = %actual_addr, "SOCKS5 proxy is listening");

    // Set status to On, then tell Java -- in that order, so nativeGetStatus() never lags
    // behind onReady() (see the suppressed BootstrapEvent::Ready arm above for why the
    // event isn't forwarded from there instead).
    set_final_status(EngineStatus::On(actual_addr));
    java_callback.emit(BootstrapEvent::Ready);
    set_current_tunnel(Some(tunnel.clone()));

    // Stall watchdog: a real network interruption (Wi-Fi handoff, carrier
    // switch, a guard going stale) can leave arti's guard/circuit managers
    // stuck retrying a dead set with nothing to notice and force a reset --
    // arti has no automatic "rebuild everything" trigger of its own. Runs
    // for the lifetime of this connection; cancelled by the same stop
    // signal as the accept loop below.
    tokio::spawn(stall_watchdog(
        tunnel.clone(),
        stop_rx.clone(),
        all_configured_bridges,
        bridge_health.clone(),
    ));

    // Create semaphore for concurrency limiting
    let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

    // Run accept loop until stopped. An accept-loop failure is recorded but
    // still falls through to the teardown below — skipping the tunnel drop
    // and the 500ms grace would leave arti's exclusive state-dir lock held
    // and break the next start.
    let accept_result = tokio::select! {
        biased;
        _ = stop_rx.changed() => {
            info!("received stop signal");
            Ok(())
        }
        res = accept_loop(&listener, &tunnel, permits, auth_state) => {
            if let Err(e) = res {
                error!(error = %e, "accept loop exited with error");
                Err(e.context("accept loop failed"))
            } else {
                Ok(())
            }
        }
    };

    // Teardown: drop tunnel, then sleep 500ms to release state-dir lock.
    // Clearing the shared handle *before* dropping the local one matters: a
    // clone left behind in CURRENT_TUNNEL would keep the tunnel alive and
    // could let a concurrent nativeRefreshBridges call reach it mid-teardown.
    set_current_tunnel(None);
    info!("shutting down Tor client");
    drop(tunnel);
    tokio::time::sleep(Duration::from_millis(500)).await;

    info!("engine shutdown complete");
    accept_result
}

/// How often [`stall_watchdog`] probes connectivity once the tunnel is live.
const WATCHDOG_PROBE_INTERVAL: Duration = Duration::from_secs(45);
/// Per-probe timeout -- generous enough that a slow-but-alive circuit isn't
/// mistaken for a dead one.
const WATCHDOG_PROBE_TIMEOUT: Duration = Duration::from_secs(20);
/// Consecutive probe failures before forcing a channel rebuild.
const WATCHDOG_FAILURES_BEFORE_RESET: u32 = 3;
/// Minimum time between two rebuild attempts, so a genuinely blocked network
/// doesn't get hammered with resets that can't help it.
const WATCHDOG_RESET_COOLDOWN: Duration = Duration::from_secs(5 * 60);

/// Per-bridge timeout for the periodic re-probe, matching the bootstrap-time
/// probe in `engine_async`.
const BRIDGE_REPROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// Timeout for the whole auto-fetch-from-sources call, matching
/// `nativeRefreshBridges`'s manual equivalent (`lib.rs`).
const AUTO_FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// How often [`bootstrap_stall_watchdog`] checks bootstrap progress.
const BOOTSTRAP_STALL_CHECK_INTERVAL: Duration = Duration::from_secs(10);
/// How long the bootstrap percentage can stay unchanged before this forces a channel reset.
const BOOTSTRAP_STALL_TIMEOUT: Duration = Duration::from_secs(45);

/// Runs alongside `wait_bootstrapped()` (spawned right before it, aborted right after it
/// resolves either way). Bootstrap has no built-in stall detection: if every currently-tried
/// bridge fails at the PT/TLS layer (deeper than the plain TCP reachability probe already run
/// before bootstrap started), arti can sit retrying the same small pool indefinitely at a
/// fixed percentage. Polls the global `EngineStatus` (the same one `nativeGetStatus` reads)
/// every [`BOOTSTRAP_STALL_CHECK_INTERVAL`]; if the percentage hasn't moved for
/// [`BOOTSTRAP_STALL_TIMEOUT`], calls [`TorTunnel::terminate_all_channels`] to force arti to
/// drop its dead channels and retry fresh ones, and reports it via `BootstrapEvent::Blocked`
/// (already surfaced to the user as a log line on the Kotlin side) so a stall is visible
/// instead of just a frozen percentage.
async fn bootstrap_stall_watchdog(tunnel: TorTunnel, callback: BootstrapEventCallback) {
    let mut last_percent: Option<u8> = None;
    let mut last_change = Instant::now();
    loop {
        tokio::time::sleep(BOOTSTRAP_STALL_CHECK_INTERVAL).await;
        let current_percent = match crate::get_status().lock().unwrap_or_else(|p| p.into_inner()).clone() {
            EngineStatus::Starting(pct) => pct,
            _ => return, // no longer bootstrapping (ready, stopped, or errored)
        };
        if last_percent != Some(current_percent) {
            last_percent = Some(current_percent);
            last_change = Instant::now();
            continue;
        }
        if last_change.elapsed() < BOOTSTRAP_STALL_TIMEOUT {
            continue;
        }
        warn!(
            percent = current_percent,
            stalled_for_secs = last_change.elapsed().as_secs(),
            "bootstrap stalled, forcing a channel reset"
        );
        callback(BootstrapEvent::Blocked(format!(
            "stalled at {current_percent}% for {}s, retrying with fresh channels",
            last_change.elapsed().as_secs()
        )));
        if let Err(e) = tunnel.terminate_all_channels() {
            warn!(error = %e, "bootstrap watchdog: terminate_all_channels failed");
        }
        last_change = Instant::now();
    }
}

/// Background task, spawned once the tunnel reaches `On`, with three independent jobs on
/// their own cadences:
///
/// 1. Every [`WATCHDOG_PROBE_INTERVAL`], probes Tor Project's own connectivity-check endpoint
///    through the tunnel (the same target Tor Browser itself uses for this). After
///    [`WATCHDOG_FAILURES_BEFORE_RESET`] consecutive failures it calls
///    [`TorTunnel::terminate_all_channels`] to force arti to rebuild its channels, giving the
///    guard/circuit managers a clean slate -- mirrors the CLI daemon's `tor_watchdog.rs`,
///    scoped down to a single canary target instead of replaying real traffic history
///    (Android's accept loop doesn't track per-connection success/failure the way the CLI's
///    `TorHealth` does).
/// 2. Every `bridge_health.bridges_cfg.recheck_interval_mins` minutes (`0` disables this and
///    job 3 entirely, deliberately far longer than [`WATCHDOG_PROBE_INTERVAL`] -- bridges have
///    their own flood protection, and re-probing the same set too often risks tripping it, see
///    `arti-wrapper`'s `build_config` doc for the earlier incident that taught this fork to be
///    conservative here), re-probes `bridges` for reachability and persists the outcome via
///    [`persist_and_rank_probe`] -- the same store `engine_async` writes to at bootstrap. This
///    session's already-chosen bridge/circuit is unaffected; the point is keeping the
///    persisted ranking fresh so the *next* connect starts from the genuinely fastest known
///    bridge (docs/circuit-speed-plan.md's Tier 1) instead of whatever was fastest whenever
///    bootstrap last probed.
/// 3. Immediately after job 2, if the reachable count fell below
///    `bridge_health.bridges_cfg.min_alive` and `auto_fetch` is enabled, fetches fresh
///    candidates from `bridges_cfg.sources` over this *already-live* tunnel -- the same fetch
///    `nativeRefreshBridges` does on a manual tap, just triggered automatically instead of only
///    from the menu (docs/android-bridge-freshness-plan.md's Phase 2). Newly found bridges are
///    handed to Kotlin via [`take_auto_fetched_bridges`]/`nativeTakeAutoFetchedBridges`, mirroring
///    [`take_pruned_bridges`]'s pattern -- this task has no access to `Prefs.bridgesList`, only
///    Kotlin does.
///
/// Exits when `stop_rx` fires.
async fn stall_watchdog(
    tunnel: TorTunnel,
    mut stop_rx: tokio::sync::watch::Receiver<bool>,
    bridges: Vec<BridgeLine>,
    bridge_health: BridgeHealthContext,
) {
    let mut consecutive_failures = 0u32;
    let mut last_reset: Option<Instant> = None;
    // Bootstrap already probed once; the first periodic re-probe is due one full interval
    // from now, not immediately.
    let mut last_bridge_reprobe = Instant::now();
    let reprobe_interval = Duration::from_secs(
        bridge_health
            .bridges_cfg
            .recheck_interval_mins
            .saturating_mul(60),
    );

    loop {
        tokio::select! {
            biased;
            _ = stop_rx.changed() => return,
            _ = tokio::time::sleep(WATCHDOG_PROBE_INTERVAL) => {}
        }
        if *stop_rx.borrow() {
            return;
        }

        if !bridges.is_empty()
            && !reprobe_interval.is_zero()
            && last_bridge_reprobe.elapsed() >= reprobe_interval
        {
            let mut alive = tokio::select! {
                biased;
                _ = stop_rx.changed() => return,
                alive = bridge_probe::probe_and_sort(bridges.clone(), BRIDGE_REPROBE_TIMEOUT) => alive,
            };
            persist_and_rank_probe(&bridges, &mut alive, &bridge_health);
            debug!(
                alive = alive.len(),
                total = bridges.len(),
                "watchdog: periodic bridge re-probe complete"
            );

            if alive.len() < bridge_health.bridges_cfg.min_alive
                && bridge_health.bridges_cfg.auto_fetch
                && !bridge_health.bridges_cfg.sources.is_empty()
            {
                let sources: Vec<bridge_fetcher::Source> = bridge_health
                    .bridges_cfg
                    .sources
                    .iter()
                    .map(|s| bridge_fetcher::Source {
                        label: s.label.clone(),
                        url: s.url.clone(),
                        headers: s.headers.clone(),
                        cookies: s.cookies.clone(),
                    })
                    .collect();
                let max_body_bytes = bridge_health.bridges_cfg.max_body_mib.saturating_mul(1024 * 1024);
                info!(
                    alive = alive.len(),
                    min_alive = bridge_health.bridges_cfg.min_alive,
                    "watchdog: alive bridge pool is thin, auto-fetching more"
                );
                let (fetched, outcomes) = tokio::select! {
                    biased;
                    _ = stop_rx.changed() => return,
                    result = bridge_fetcher::fetch_all(&tunnel, &sources, AUTO_FETCH_TIMEOUT, max_body_bytes) => result,
                };
                for outcome in &outcomes {
                    if let Some(err) = &outcome.error {
                        warn!(label = %outcome.label, error = %err, "watchdog: bridge auto-fetch source failed");
                    } else {
                        info!(
                            label = %outcome.label,
                            bridges = outcome.bridges_extracted,
                            "watchdog: bridge auto-fetch source OK"
                        );
                    }
                }
                let (unique, duplicates) = bridge_fetcher::dedup_bridges(fetched);
                info!(unique = unique.len(), duplicates, "watchdog: bridge auto-fetch complete");
                record_auto_fetched_bridges(unique);
            }
            last_bridge_reprobe = Instant::now();
        }

        let probe = tokio::time::timeout(
            WATCHDOG_PROBE_TIMEOUT,
            tunnel.connect("check.torproject.org", 443),
        )
        .await;

        if matches!(probe, Ok(Ok(_))) {
            consecutive_failures = 0;
            continue;
        }

        consecutive_failures += 1;
        debug!(consecutive_failures, "watchdog: connectivity probe failed");
        if consecutive_failures < WATCHDOG_FAILURES_BEFORE_RESET {
            continue;
        }

        let now = Instant::now();
        let cooled_down = last_reset
            .map(|t| now.duration_since(t) >= WATCHDOG_RESET_COOLDOWN)
            .unwrap_or(true);
        if !cooled_down {
            continue;
        }

        warn!(
            consecutive_failures,
            "watchdog: forcing channel rebuild after sustained stall"
        );
        if let Err(e) = tunnel.terminate_all_channels() {
            warn!(error = %e, "watchdog: terminate_all_channels failed");
        }
        last_reset = Some(now);
        consecutive_failures = 0;
    }
}

/// Persist a probe round's reachability outcome to the shared bridge-health store
/// (`<config-stem>.alive-bridges.log`, same file the CLI daemon uses) and re-sort `alive` by
/// historical stability (`ok_count`, ties broken by latency) ahead of a bridge seen reachable
/// for the first time. Shared between the bootstrap-time probe in `engine_async` and
/// `stall_watchdog`'s periodic re-probe -- both need the identical persist-and-rank step, just
/// with different cancellation/error handling around the probe itself. Best-effort throughout:
/// a missing or unwritable store never fails the caller, it just forfeits the ranking boost for
/// this round.
fn persist_and_rank_probe(
    all_bridges: &[BridgeLine],
    alive: &mut Vec<(BridgeLine, Duration)>,
    bridge_health: &BridgeHealthContext,
) {
    let store_path = BridgeStore::resolve_path(bridge_health.config_path.as_deref());
    match BridgeStore::load(store_path.clone()) {
        Ok(mut store) => {
            let now = OffsetDateTime::now_utc();
            let fail_window = Duration::from_secs(
                bridge_health
                    .bridges_cfg
                    .fail_window_mins
                    .saturating_mul(60),
            );
            let pruned = store.note_probe_round(
                all_bridges,
                alive,
                now,
                fail_window,
                bridge_health.bridges_cfg.max_fails,
                bridge_health.bridges_cfg.max_circuit_fails,
            );
            if !pruned.is_empty() {
                info!(
                    count = pruned.len(),
                    "bridges crossed max_fails/max_circuit_fails, pruning"
                );
                record_pruned_bridges(pruned);
            }
            if let Err(e) = store.save() {
                warn!(path = %store_path.display(), error = %e, "could not persist bridge health store");
            }
            alive.sort_by(|(ba, la), (bb, lb)| {
                store
                    .ok_count(bb)
                    .cmp(&store.ok_count(ba))
                    .then_with(|| la.cmp(lb))
            });
        }
        Err(e) => {
            warn!(path = %store_path.display(), error = %e, "could not load bridge health store");
        }
    }
}

/// SOCKS5 accept loop.
///
/// Accepts connections, acquires a semaphore permit, spawns a task per connection.
/// Each task:
/// 1. Performs the SOCKS5 handshake — RFC 1929 USER/PASS when `auth_state` is
///    `Some`, otherwise legacy NO_AUTH (see [`handle_connection`]).
/// 2. Connects through Tor.
/// 3. Sends success reply.
/// 4. Bidirectionally copies data.
///
/// All errors are logged and swallowed; individual connection failures don't
/// crash the loop.
async fn accept_loop(
    listener: &TcpListener,
    tunnel: &TorTunnel,
    permits: Arc<Semaphore>,
    auth_state: Option<Arc<AuthState>>,
) -> Result<()> {
    loop {
        // Accept a new connection
        let (client, peer) = listener.accept().await.context("accept failed")?;

        // Acquire a permit before spawning (bounds task growth)
        let permit = permits
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore not closed");

        // Spawn a task for this connection
        let tunnel = tunnel.clone();
        let auth = auth_state.clone();
        tokio::spawn(async move {
            // Permit is moved into the task and dropped on exit
            let _permit = permit;

            debug!(%peer, "new SOCKS5 connection");

            match handle_connection(client, tunnel, auth).await {
                Ok(()) => {
                    debug!(%peer, "connection closed normally");
                }
                Err(e) => {
                    // Classify and log at appropriate level
                    let error_str = format!("{:#}", e);
                    if error_str.contains("handshake")
                        || error_str.contains("reset")
                        || error_str.contains("broken pipe")
                    {
                        debug!(%peer, error = %error_str, "connection error (client-side)");
                    } else {
                        warn!(%peer, error = %error_str, "connection error");
                    }
                }
            }
        });
    }
}

/// Handle a single SOCKS5 connection.
///
/// `auth` mirrors the CLI's behaviour (see `apps/socks5-proxy/src/server.rs`
/// and `docs/auth.md`): `Some(state)` insists on RFC 1929 USER/PASS and
/// rejects any connection with missing or incorrect credentials before a
/// Tor circuit is ever built; `None` is the legacy anonymous NO_AUTH path,
/// used only when no users are configured for this Android instance (see
/// `nativeStart`'s auth-resolution step in `lib.rs`).
async fn handle_connection(
    mut client: TcpStream,
    tunnel: TorTunnel,
    auth: Option<Arc<AuthState>>,
) -> Result<()> {
    // SOCKS5 handshake: USER/PASS when `auth` is configured, NO_AUTH otherwise.
    let req = socks5_proto::handshake(&mut client, auth)
        .await
        .context("SOCKS5 handshake")?;

    debug!(host = %req.host, port = req.port, "SOCKS5 CONNECT request");

    // Connect through Tor
    let tor_stream = tunnel
        .connect(&req.host, req.port)
        .await
        .context("Tor connect failed")?;

    debug!(host = %req.host, port = req.port, "Tor connection established");

    // Send success reply
    socks5_proto::reply(&mut client, Reply::Success)
        .await
        .context("failed to send SOCKS5 reply")?;

    // Bidirectional copy (DataStream is futures AsyncRead/Write)
    let mut tor_compat = tor_stream.compat();
    tokio::io::copy_bidirectional(&mut client, &mut tor_compat)
        .await
        .context("data relay failed")?;

    Ok(())
}

/// Helper: set the global status from the engine thread.
///
/// Poisoning-tolerant (`into_inner`): a panicked holder must not brick
/// status updates forever — readers/writers share the recovery policy.
fn set_final_status(status: EngineStatus) {
    use crate::get_status;
    *get_status().lock().unwrap_or_else(|p| p.into_inner()) = status;
}

/// The running engine's `TorTunnel`, shared with `nativeRefreshBridges`
/// (`lib.rs`) so it can fetch fresh bridge lists over the already-live
/// circuit -- `bridge_fetcher::fetch_all` requires an established
/// `TorTunnel` and has no direct (non-Tor) fetch path, so this can only
/// ever do anything while the engine is `On`. `None` whenever the engine
/// isn't in that state (not started yet, still bootstrapping, or tearing
/// down -- see the `set_current_tunnel(None)` call just before teardown in
/// `engine_async`).
static CURRENT_TUNNEL: OnceLock<Mutex<Option<TorTunnel>>> = OnceLock::new();

fn set_current_tunnel(tunnel: Option<TorTunnel>) {
    *CURRENT_TUNNEL
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|p| p.into_inner()) = tunnel;
}

/// Cheap `TorTunnel` clone (see [`TorTunnel::clone`]'s use in `accept_loop`)
/// of the currently running engine's tunnel, or `None` if the engine isn't
/// `On` right now.
pub(crate) fn get_current_tunnel() -> Option<TorTunnel> {
    CURRENT_TUNNEL
        .get()?
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone()
}

/// Bridges `persist_and_rank_probe` has pruned (crossed `max_fails`/`max_circuit_fails`)
/// since the last time Kotlin drained them via `nativeTakePrunedBridges`
/// (docs/android-bridge-freshness-plan.md's Phase 1). `Prefs.bridgesList` on the Kotlin side
/// is the actual source of truth for what gets probed/bootstrapped next -- this is just the
/// handoff channel, mirroring `CURRENT_TUNNEL`'s pattern.
static PRUNED_BRIDGES: OnceLock<Mutex<Vec<BridgeLine>>> = OnceLock::new();

fn record_pruned_bridges(mut pruned: Vec<BridgeLine>) {
    if pruned.is_empty() {
        return;
    }
    PRUNED_BRIDGES
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .append(&mut pruned);
}

/// Drain and return every bridge pruned since the last call. Called from the
/// `nativeTakePrunedBridges` JNI entry point (`lib.rs`).
pub(crate) fn take_pruned_bridges() -> Vec<BridgeLine> {
    let Some(lock) = PRUNED_BRIDGES.get() else {
        return Vec::new();
    };
    std::mem::take(&mut *lock.lock().unwrap_or_else(|p| p.into_inner()))
}

/// Bridges `stall_watchdog`'s auto-fetch has found (docs/android-bridge-freshness-plan.md's
/// Phase 2) since the last time Kotlin drained them via `nativeTakeAutoFetchedBridges`. Same
/// handoff pattern as [`PRUNED_BRIDGES`] -- `stall_watchdog` has no access to
/// `Prefs.bridgesList`, only Kotlin does.
static AUTO_FETCHED_BRIDGES: OnceLock<Mutex<Vec<BridgeLine>>> = OnceLock::new();

fn record_auto_fetched_bridges(mut fetched: Vec<BridgeLine>) {
    if fetched.is_empty() {
        return;
    }
    AUTO_FETCHED_BRIDGES
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .append(&mut fetched);
}

/// Drain and return every bridge auto-fetched since the last call. Called from the
/// `nativeTakeAutoFetchedBridges` JNI entry point (`lib.rs`).
pub(crate) fn take_auto_fetched_bridges() -> Vec<BridgeLine> {
    let Some(lock) = AUTO_FETCHED_BRIDGES.get() else {
        return Vec::new();
    };
    std::mem::take(&mut *lock.lock().unwrap_or_else(|p| p.into_inner()))
}

#[cfg(test)]
mod auth_wiring_tests {
    //! Proves the Android accept-loop path (`handle_connection`) actually
    //! enforces RFC 1929 credentials when `auth_state` is configured,
    //! instead of the pre-fix behaviour of always calling
    //! `socks5_proto::handshake(&mut client, None)` (NO_AUTH) regardless
    //! of config. `TorTunnel` needs a live Tor bootstrap and cannot be
    //! constructed in a unit test, so these tests exercise the exact same
    //! call `handle_connection` makes — `socks5_proto::handshake(&mut
    //! client, auth)` — over a real loopback `TcpStream` pair, and assert
    //! that a failed handshake means the socket is closed with **no**
    //! SOCKS5 CONNECT reply ever sent, i.e. `handle_connection`'s `?`
    //! short-circuits before `tunnel.connect` / `socks5_proto::reply` run.

    use std::sync::Arc;

    use auth::{AuthState, User, UsersConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    fn one_user_state(name: &str, password: &str) -> Arc<AuthState> {
        let user = User {
            name: name.into(),
            hash: auth::compute_hash(password).unwrap(),
            is_enabled: true,
            allowed_onion: false,
        };
        Arc::new(AuthState::build(&UsersConfig { users: vec![user] }).unwrap())
    }

    fn rfc1929_frame(user: &str, passwd: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(3 + user.len() + passwd.len());
        out.push(0x01); // RFC1929 sub-negotiation version
        out.push(user.len() as u8);
        out.extend_from_slice(user.as_bytes());
        out.push(passwd.len() as u8);
        out.extend_from_slice(passwd.as_bytes());
        out
    }

    /// Spin up a loopback listener, connect a client, and run the given
    /// client-side script concurrently with
    /// `socks5_proto::handshake(&mut server_stream, auth)` — the exact
    /// call `handle_connection` makes. Returns the handshake `Result`.
    ///
    /// `server_stream` is dropped (closing the socket) as soon as the
    /// handshake settles, *before* we wait on the client task — exactly
    /// like the real accept loop, where `handle_connection`'s early `?`
    /// return drops `client` on the way out. A client script that reads
    /// for EOF after a rejection depends on this ordering; awaiting the
    /// client task before dropping the server half would deadlock both
    /// sides against each other.
    async fn run_handshake_over_loopback(
        auth: Option<Arc<AuthState>>,
        client_script: impl FnOnce(TcpStream) -> tokio::task::JoinHandle<()> + Send + 'static,
    ) -> anyhow::Result<socks5_proto::ConnectRequest> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client_task = tokio::spawn(async move {
            let client = TcpStream::connect(addr).await.unwrap();
            client_script(client).await.unwrap();
        });

        let (mut server_stream, _peer) = listener.accept().await.unwrap();
        let result = socks5_proto::handshake(&mut server_stream, auth).await;
        drop(server_stream);

        let _ = client_task.await;
        result
    }

    #[tokio::test]
    async fn accept_loop_wiring_rejects_missing_credentials() {
        let auth = one_user_state("alice", "hunter2");

        let result = run_handshake_over_loopback(Some(auth), |mut client| {
            tokio::spawn(async move {
                // Offer USER/PASS, then present the WRONG password.
                client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
                let mut method_reply = [0u8; 2];
                client.read_exact(&mut method_reply).await.unwrap();
                assert_eq!(method_reply, [0x05, 0x02], "server must select USER/PASS");

                client
                    .write_all(&rfc1929_frame("alice", "WRONG-PASSWORD"))
                    .await
                    .unwrap();
                let mut auth_reply = [0u8; 2];
                client.read_exact(&mut auth_reply).await.unwrap();
                assert_eq!(auth_reply[1], 0x01, "server must signal auth failure");

                // Server closes the connection after a failed auth — no
                // further bytes (in particular, no CONNECT reply) ever
                // arrive.
                let mut buf = [0u8; 1];
                let n = client.read(&mut buf).await.unwrap_or(0);
                assert_eq!(n, 0, "server must not send anything after rejecting auth");
            })
        })
        .await;

        assert!(
            result.is_err(),
            "handshake must fail for wrong credentials, mirroring handle_connection's `?` \
             short-circuit before any Tor connect is attempted"
        );
    }

    #[tokio::test]
    async fn accept_loop_wiring_rejects_no_auth_when_credentials_required() {
        let auth = one_user_state("alice", "hunter2");

        // Client behaves like the OLD (broken) Android client assumption:
        // it only ever offers NO_AUTH. With auth configured, the server
        // must refuse method negotiation instead of silently accepting.
        let result = run_handshake_over_loopback(Some(auth), |mut client| {
            tokio::spawn(async move {
                client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
                let mut method_reply = [0u8; 2];
                client.read_exact(&mut method_reply).await.unwrap();
                assert_eq!(
                    method_reply,
                    [0x05, 0xFF],
                    "server must reply NO_ACCEPTABLE_METHODS, not silently accept NO_AUTH"
                );
            })
        })
        .await;

        assert!(
            result.is_err(),
            "handshake must fail when only NO_AUTH is offered"
        );
    }

    #[tokio::test]
    async fn accept_loop_wiring_accepts_correct_credentials() {
        let auth = one_user_state("alice", "hunter2");

        let result = run_handshake_over_loopback(Some(auth), |mut client| {
            tokio::spawn(async move {
                client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
                let mut method_reply = [0u8; 2];
                client.read_exact(&mut method_reply).await.unwrap();

                client
                    .write_all(&rfc1929_frame("alice", "hunter2"))
                    .await
                    .unwrap();
                let mut auth_reply = [0u8; 2];
                client.read_exact(&mut auth_reply).await.unwrap();
                assert_eq!(
                    auth_reply[1], 0x00,
                    "server must accept correct credentials"
                );

                // CONNECT to 1.2.3.4:80 so the handshake can complete and
                // return a `ConnectRequest` (handle_connection would now
                // proceed to `tunnel.connect`).
                client
                    .write_all(&[0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80])
                    .await
                    .unwrap();
            })
        })
        .await;

        let req = result.expect("correct credentials must be accepted");
        assert_eq!(req.host, "1.2.3.4");
        assert_eq!(req.port, 80);
        assert_eq!(req.authed_user.as_deref(), Some("alice"));
    }

    #[tokio::test]
    async fn accept_loop_wiring_no_auth_state_falls_back_to_no_auth() {
        // Reproduces the pre-fix default: `auth_state = None` (no users
        // configured) still lets an anonymous NO_AUTH client through —
        // this is the documented, intentional backward-compatible path,
        // not the bug.
        let result = run_handshake_over_loopback(None, |mut client| {
            tokio::spawn(async move {
                client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
                let mut method_reply = [0u8; 2];
                client.read_exact(&mut method_reply).await.unwrap();
                assert_eq!(method_reply, [0x05, 0x00], "server must select NO_AUTH");

                client
                    .write_all(&[0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80])
                    .await
                    .unwrap();
            })
        })
        .await;

        let req = result.expect("NO_AUTH must still work when auth is not configured");
        assert!(req.authed_user.is_none());
    }
}
