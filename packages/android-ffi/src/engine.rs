//! Engine thread, accept loop, and status management.
//!
//! This module contains the core runtime for the Tor SOCKS5 proxy:
//!
//! - [`EngineStatus`]: Internal status enum that maps to the status text protocol.
//! - [`EngineHandle`]: Holds the stop signal, done notification, and thread handle.
//! - [`engine_main`]: Entry point for the dedicated engine thread.
//! - [`accept_loop`]: SOCKS5 accept loop with semaphore-bounded concurrency.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
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

/// Pause before retrying after a failed `accept()`. Any accept error is
/// treated as transient: the loop logs it and retries instead of tearing
/// down the whole engine. The sleep also prevents a busy-spin (and a log
/// flood) if the error is persistent.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(500);

/// Keep channel warm-up bounded even when a bridge refresh has produced thousands of TCP-live
/// candidates. The full candidate set remains persisted and is re-probed on later runs; only the
/// best-ranked slice is worth holding open for immediate rotation.
const MAX_WARM_BRIDGES: usize = 16;

/// Keep the startup probe bounded. The complete configured list remains the background
/// discovery pool (the watchdog re-probes it periodically), while only the best bridges
/// known from the persisted health store participate in the latency-sensitive connect path.
const MAX_ACTIVE_BRIDGES: usize = 30;

/// Target size of the actively-warmed rotation pool.
///
/// Distinct from [`MAX_ACTIVE_BRIDGES`] even though they share a value today: that constant
/// bounds how many bridges get *reachability*-probed, this one is how many should end up
/// *channel*-proven. The two used to be conflated in practice -- the only warm attempt ran
/// once at connect time, over a slice of at most [`MAX_WARM_BRIDGES`] candidates, and never
/// again -- so a pool with plenty of reachable bridges could sit at a handful of proven ones
/// indefinitely (observed on a phone: 26 reachable, 3 proven). [`WARM_TOPUP_INTERVAL`] exists
/// to close that gap.
const TARGET_WARM_POOL_SIZE: usize = 30;

/// How many new candidates one top-up round attempts to warm while below [`TARGET_WARM_POOL_SIZE`].
/// Bounds concurrent channel-opens per round; the target is reached over several rounds.
const WARM_TOPUP_BATCH: usize = 10;

/// How many untried candidates a round still attempts once the pool is at
/// [`TARGET_WARM_POOL_SIZE`]. Small, since the goal has shifted from filling the pool to
/// occasionally finding something faster than its current slowest member.
const WARM_REFRESH_BATCH: usize = 2;

/// Cadence for the top-up/refresh round.
///
/// Deliberately its own interval, not [`WATCHDOG_PROBE_INTERVAL`] (a liveness check on a much
/// tighter cadence) and not `recheck_interval_mins` (a reachability re-probe with its own
/// flood-protection concerns, see `arti-wrapper`'s `build_config` doc). Warming is inherently
/// bounded per round by [`WARM_TOPUP_BATCH`]/[`WARM_REFRESH_BATCH`], so this only controls how
/// quickly the pool fills, not how much load one round can generate.
const WARM_TOPUP_INTERVAL: Duration = Duration::from_secs(2 * 60);

/// Cadence for the background circuit-verify tick -- see `docs/design/real-connectivity-
/// bridge-verification.md`. Deliberately much longer than [`WARM_TOPUP_INTERVAL`]: a full
/// end-to-end check (throwaway client, PT handshake, circuit build, live probe) costs real Tor
/// network resources per bridge, not just a local socket, so it runs against a slow trickle of
/// the already channel-proven pool rather than the whole pool on every round.
const CIRCUIT_VERIFY_INTERVAL: Duration = Duration::from_secs(30 * 60);
/// How many channel-proven bridges one tick checks. Small on purpose -- see
/// [`CIRCUIT_VERIFY_INTERVAL`]'s doc; the whole channel-proven pool is covered gradually over
/// many ticks, oldest/never-verified first (`BridgeStore::needing_circuit_verification`).
const CIRCUIT_VERIFY_BATCH: usize = 2;
/// A bridge verified within this window is not due again yet.
const CIRCUIT_VERIFY_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);
/// Same bootstrap budget as the QR-scan flow (`lib.rs`'s `VERIFY_BRIDGE_BOOTSTRAP_TIMEOUT`) --
/// a cold descriptor fetch for a never-contacted bridge needs real patience regardless of caller.
const CIRCUIT_VERIFY_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(60);
/// Shorter than the QR-scan flow's probe timeout (180s): this tick is a continuous background
/// signal, not a one-shot user-facing action -- a bridge that times out here simply stays "due"
/// and gets tried again next cycle, so there is no need to chase the same worst-case patience a
/// user actively watching a scan result needs.
const CIRCUIT_VERIFY_PROBE_TIMEOUT: Duration = Duration::from_secs(90);

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
    /// Resolver policy for hostname-bearing bridge lines.
    pub resolver_policy: bridge_probe::ResolverPolicy,
}

/// Connection policy shared by the accept loop and each spawned client task.
/// Keeping authentication and destination policy together also prevents the
/// engine entry points from accumulating unrelated boolean arguments.
#[derive(Clone)]
pub(crate) struct ConnectionPolicy {
    pub auth_state: Option<Arc<AuthState>>,
    pub block_onion: bool,
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
    policy: ConnectionPolicy,
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
                policy,
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
    policy: ConnectionPolicy,
    mut stop_rx: tokio::sync::watch::Receiver<bool>,
    java_callback: Arc<JavaCallback>,
    failed_already_emitted: Arc<AtomicBool>,
    bridge_health: BridgeHealthContext,
) -> Result<()> {
    // A start is the one moment we know nothing about the current network:
    // the user may have switched carriers, moved to Wi-Fi, or simply be
    // retrying because the last attempt failed. Cached addresses and provider
    // scores from the previous attempt would be answers to a question about a
    // different network.
    bridge_probe::flush_dns_cache();
    // Deliberately separate from the wipe above: this loads into a store the
    // *live* cache never reads from directly, consulted only once every DoH
    // provider and the in-memory stale fallback have both failed this run.
    // Carrying it across a network change cannot shadow a fresh answer --
    // it can only provide one where a cold start would otherwise have none.
    bridge_probe::load_persisted_dns_cache(&dns_cache_path(bridge_health.config_path.as_deref()));

    // Create a shared callback that updates status AND emits to Java
    // Set once `engine_async` itself has declared the engine On (see the explicit
    // `set_final_status(EngineStatus::On(..))` below `verify_live_circuit`'s success), and
    // checked inside `callback` below to suppress any later `Progress` event.
    //
    // Without this, a real, sustained bug follows: `forward_bootstrap_events`'s subscription
    // is documented to stop delivering once "ready" fires, but that stream and our own
    // On-transition are driven by two different readiness notions -- arti's own
    // `bootstrap_status().ready_for_traffic()` heuristic, vs. this app's `verify_live_circuit`
    // probe -- and the two do not always agree on the same instant. When they don't, the
    // subscription can still be alive, still watching arti's *own* routine periodic
    // directory/cert refresh (harmless, and logged as "Attempted to bootstrap twice;
    // ignoring" -- ordinary Tor client maintenance, not a reconnect), and it keeps forwarding
    // every one of those refreshes as a fresh `Progress` event indefinitely. Each one used to
    // call `set_final_status(EngineStatus::Starting(pct))`, permanently regressing a fully
    // working connection's status back to "Connecting..." -- confirmed on-device via
    // `nativeGetStatus() == "Starting:100"` while circuits were actively carrying live
    // traffic. Once On, no further Progress is real news for the user; the connection does
    // not depend on arti's internal directory-freshness bookkeeping fluctuating.
    let reached_ready = Arc::new(AtomicBool::new(false));

    let callback: BootstrapEventCallback = Arc::new({
        let cb = Arc::clone(&java_callback);
        let failed_flag = Arc::clone(&failed_already_emitted);
        let last_progress = Arc::new(AtomicU8::new(0));
        let reached_ready = Arc::clone(&reached_ready);
        move |event| {
            // Update status based on event
            match &event {
                BootstrapEvent::Progress(fraction, _status_text) => {
                    if reached_ready.load(Ordering::SeqCst) {
                        return;
                    }
                    let pct = (fraction.clamp(0.0, 1.0) * 100.0).round() as u8;
                    // Arti reports progress from several concurrent directory/guard tasks.
                    // Their callbacks can arrive out of order (for example 80% handshake,
                    // then a 15% consensus update). Never make the user-visible status go
                    // backwards or overwrite a later stage with an older one.
                    let previous = last_progress.fetch_max(pct, Ordering::SeqCst);
                    if pct < previous {
                        return;
                    }
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
        let preferred = preferred_transport_bridges(&settings.bridges, &bridge_health);
        let active_probe_bridges = select_active_probe_bridges(&preferred, &bridge_health);
        let probing_all_configured = active_probe_bridges.len() == settings.bridges.len();
        info!(
            count = active_probe_bridges.len(),
            configured = settings.bridges.len(),
            "probing active bridge pool for reachability"
        );
        let mut round = tokio::select! {
            biased;
            _ = stop_rx.changed() => {
                info!("received stop signal while probing bridges");
                return Ok(());
            }
            round = bridge_probe::probe_round_with_policy(active_probe_bridges.clone(), Duration::from_secs(5), bridge_health.resolver_policy) => round,
        };

        persist_and_rank_probe(&active_probe_bridges, &mut round, &bridge_health);
        let mut alive = std::mem::take(&mut round.alive);

        // A stale health store must not make a new installation unusable. If none of the
        // ranked active candidates responds, probe the complete background pool once as a
        // deliberate fallback and persist that round. The common path never waits on all
        // thousands of imported bridges.
        if alive.is_empty() && !probing_all_configured {
            info!(
                active = active_probe_bridges.len(),
                configured = settings.bridges.len(),
                "active bridge pool was unreachable; probing full background pool as fallback"
            );
            round = tokio::select! {
                biased;
                _ = stop_rx.changed() => {
                    info!("received stop signal while probing bridge fallback pool");
                    return Ok(());
                }
                round = bridge_probe::probe_round_with_policy(settings.bridges.clone(), Duration::from_secs(5), bridge_health.resolver_policy) => round,
            };
            persist_and_rank_probe(&settings.bridges, &mut round, &bridge_health);
            alive = std::mem::take(&mut round.alive);
        }

        if alive.is_empty() {
            match cold_start_rescue_fetch(&bridge_health, &mut stop_rx).await {
                ColdStartRescue::Alive(found) => alive = found,
                ColdStartRescue::StopRequested => {
                    info!("received stop signal during cold-start rescue fetch");
                    return Ok(());
                }
            }
        }

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

    // Bootstrap Tor with event notifications. The helper keeps the tunnel
    // alive for the stall watchdog while waiting and tears it down on stop or
    // timeout so the next retry starts with a fresh Arti client.
    // A TCP probe only proves that a socket can be opened; DPI can still kill
    // the subsequent obfs4/PT/TLS handshake. Try the latency-ranked active
    // slice first, but if Arti cannot bootstrap that slice within a bounded
    // attempt, retry with the complete background pool.
    let active_settings = settings.clone();
    let has_full_pool_fallback = all_configured_bridges.len() > active_settings.bridges.len();
    let (tunnel, bootstrap_bridges) = match bootstrap_tunnel_attempt(
        active_settings.clone(),
        &mut stop_rx,
        callback.clone(),
    )
    .await
    {
        Ok(Some(tunnel)) => (tunnel, active_settings.bridges.clone()),
        Ok(None) => return Ok(()),
        Err(active_error) if has_full_pool_fallback => {
            info!(
                active = active_settings.bridges.len(),
                configured = all_configured_bridges.len(),
                error = %active_error,
                "active bridge bootstrap failed; retrying with full background pool"
            );
            callback(BootstrapEvent::Blocked(
                "active bridge slice failed; retrying the full background pool".to_owned(),
            ));
            let mut fallback_settings = active_settings.clone();
            fallback_settings.bridges = all_configured_bridges.clone();
            match bootstrap_tunnel_attempt(fallback_settings, &mut stop_rx, callback.clone()).await
            {
                Ok(Some(tunnel)) => (tunnel, all_configured_bridges.clone()),
                Ok(None) => return Ok(()),
                Err(full_error) => {
                    return Err(full_error).context(format!(
                        "failed to bootstrap Tor with active slice ({active_error:#}) and full bridge pool"
                    ));
                }
            }
        }
        Err(error) => return Err(error).context("failed to bootstrap Tor"),
    };
    settings.bridges = bootstrap_bridges;
    // Deliberately no pool widening when this fails: a preferred transport that
    // cannot carry traffic should be visible as such, not silently papered over
    // by falling back to the other one. Switching transports stays a user
    // decision, made with the failure in front of them.
    info!("Tor bootstrap completed; verifying live circuit");
    if !verify_live_circuit(&tunnel, &mut stop_rx, &callback).await? {
        // A stop signal won the select while the live probe was in flight. The
        // caller owns the tunnel and will drop it as this function returns.
        return Ok(());
    }
    info!("live Tor circuit verified");

    // Bind the listener and advertise readiness as soon as the end-to-end Tor circuit is
    // verified. Channel warm-up is useful for rotation, but it is a background optimization:
    // holding the UI in Connecting while dead candidates consume their 20s timeouts makes a
    // working tunnel look broken and delays clients unnecessarily.
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
    // The verified set is the honest answer until warm-up narrows it: these are
    // the bridges the working circuit was built from.
    crate::set_active_bridges(bridge_health.config_path.as_deref(), &settings.bridges);
    set_final_status(EngineStatus::On(actual_addr));
    reached_ready.store(true, Ordering::SeqCst);
    java_callback.emit(BootstrapEvent::Ready);
    set_current_tunnel(Some(tunnel.clone()));

    // A TorClient created with `create_unbootstrapped` is not in Arti's `running` state yet;
    // `TorTunnel::warm_bridge` consequently must run after bootstrap. Start it only after the
    // real circuit and listener are ready, and persist successful channels for the next start.
    let warm_bridges = settings.bridges.clone();
    let warm_health = bridge_health.clone();
    let warm_tunnel = tunnel.clone();
    let configured_count = all_configured_bridges.len();
    let mut warm_stop_rx = stop_rx.clone();
    info!(
        active = warm_bridges.len().min(MAX_WARM_BRIDGES),
        completed = 0,
        successful = 0,
        failed = 0,
        "parallel bridge warm-up started in background"
    );
    tokio::spawn(async move {
        let pool = tokio::select! {
            biased;
            _ = warm_stop_rx.changed() => {
                info!("received stop signal while warming bridges");
                return;
            }
            pool = warm_bridge_pool(warm_tunnel, warm_bridges) => pool,
        };
        persist_warm_results(&pool, &warm_health);
        if let Some((fastest, latency)) = pool.warmed.first() {
            info!(
                bridge = %fastest.addr,
                latency_ms = latency.as_millis() as u64,
                "selected fastest warmed bridge for rotation"
            );
        }
        for (rank, (bridge, latency)) in pool.warmed.iter().enumerate().skip(1) {
            debug!(
                rank = rank + 1,
                bridge = %bridge.addr,
                latency_ms = latency.as_millis() as u64,
                "kept warmed bridge as rotation fallback"
            );
        }
        if !pool.warmed.is_empty() {
            // Narrow the published set once channels have actually been opened:
            // now we know which bridges carry, not merely which bootstrapped.
            let warmed: Vec<BridgeLine> = pool
                .warmed
                .iter()
                .map(|(bridge, _)| bridge.clone())
                .collect();
            crate::set_active_bridges(warm_health.config_path.as_deref(), &warmed);
        }
        info!(
            warmed = pool.warmed.len(),
            retired = pool.retired.len(),
            configured = configured_count,
            "parallel bridge warm pool ready for rotation"
        );
    });

    // Stall watchdog: a real network interruption (Wi-Fi handoff, carrier
    // switch, a guard going stale) can leave arti's guard/circuit managers
    // stuck retrying a dead set with nothing to notice and force a reset --
    // arti has no automatic "rebuild everything" trigger of its own. Runs
    // for the lifetime of this connection; cancelled by the same stop
    // signal as the accept loop below.
    //
    // Its rotation pool starts empty rather than seeded with an unconfirmed guess: the
    // background warm-up above is already independently warming a first slice, and the
    // watchdog's own top-up round (see WARM_TOPUP_INTERVAL) fills the pool with real,
    // measured warm latencies within its first couple of ticks. A confirmed-empty pool
    // already falls back to the full configured list if a stall forces a rebuild before
    // that happens, so there is nothing to lose by not guessing here.
    tokio::spawn(stall_watchdog(
        tunnel.clone(),
        stop_rx.clone(),
        all_configured_bridges,
        bridge_health.clone(),
        settings.pt_binary.clone(),
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
        res = accept_loop(&listener, &tunnel, permits, policy) => {
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
    crate::set_active_bridges(bridge_health.config_path.as_deref(), &[]);
    info!("shutting down Tor client");
    drop(tunnel);
    tokio::time::sleep(Duration::from_millis(500)).await;

    info!("engine shutdown complete");
    accept_result
}

/// Give one active bridge slice enough time to make a real PT/TLS attempt,
/// then let the caller retry with the complete background pool. Without this
/// bound `wait_bootstrapped()` can keep retrying a dead set forever while the
/// UI remains in Connecting.
// A cold Android start may need several descriptor/consensus retries over a
// high-latency obfs4 channel.  The old 75s ceiling expired after the first
// usable channel had already been established, before the consensus could be
// downloaded.  Keep a finite upper bound, but make it long enough for a cold
// cache miss; the stall watchdog still resets genuinely idle channels.
const BOOTSTRAP_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(300);

/// Bootstrap one bridge set while retaining a handle for the stall watchdog.
///
/// Returns `Ok(None)` when Android requested stop. The returned tunnel is
/// owned by the caller; all spawned watchdog work is aborted before this
/// future resolves. The timeout intentionally cancels only the wait future,
/// then drops the tunnel, so the next attempt gets a fresh Arti client and
/// state-dir lifecycle.
///
/// cancel-safe: NO — cancelling this future drops the in-flight tunnel and
/// aborts its bootstrap attempt; callers use that behaviour for stop/retry.
async fn bootstrap_tunnel_attempt(
    settings: arti_wrapper::Settings,
    stop_rx: &mut tokio::sync::watch::Receiver<bool>,
    callback: BootstrapEventCallback,
) -> Result<Option<TorTunnel>> {
    info!(
        bridges = settings.bridges.len(),
        "bootstrapping Tor client..."
    );
    let tunnel = TorTunnel::create_unbootstrapped_with(settings).context("creating Tor client")?;
    tunnel.forward_bootstrap_events(callback.clone());
    let stall_handle = tokio::spawn(bootstrap_stall_watchdog(tunnel.clone(), callback));

    let result = tokio::select! {
        biased;
        changed = stop_rx.changed() => {
            stall_handle.abort();
            info!(changed = changed.is_ok(), "received stop signal while bootstrapping");
            drop(tunnel);
            return Ok(None);
        }
        result = tokio::time::timeout(
            BOOTSTRAP_ATTEMPT_TIMEOUT,
            tunnel.wait_bootstrapped(),
        ) => result,
    };
    stall_handle.abort();

    match result {
        Ok(Ok(())) => Ok(Some(tunnel)),
        Ok(Err(error)) => {
            drop(tunnel);
            Err(error).context("failed to bootstrap Tor")
        }
        Err(_) => {
            warn!(
                timeout_secs = BOOTSTRAP_ATTEMPT_TIMEOUT.as_secs(),
                "Tor bootstrap attempt timed out; releasing bridge slice"
            );
            if let Err(error) = tunnel.terminate_all_channels() {
                debug!(error = %error, "failed to terminate channels after bootstrap timeout");
            }
            drop(tunnel);
            Err(anyhow::anyhow!(
                "Tor bootstrap attempt timed out after {BOOTSTRAP_ATTEMPT_TIMEOUT:?}"
            ))
        }
    }
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

/// The first readiness signal must include a real end-to-end circuit probe.
/// A plain TCP bridge probe can succeed while DPI kills the obfs4 stream, and
/// cached arti state can otherwise make `wait_bootstrapped` look healthy.
// pub(crate): also the reachability bar `lib.rs`'s nativeVerifyBridges holds
// scanned candidate bridges to -- one canonical "does this actually carry
// Tor traffic" target, not a duplicated literal.
pub(crate) const LIVE_PROBE_TARGET: &str = "check.torproject.org";
pub(crate) const LIVE_PROBE_PORT: u16 = 443;
const LIVE_PROBE_TIMEOUT: Duration = Duration::from_secs(20);
const LIVE_PROBE_ATTEMPTS: u32 = 3;
const LIVE_PROBE_RETRY_DELAY: Duration = Duration::from_secs(2);

/// Bound each parallel PT/channel warm-up so a dead bridge cannot hold the
/// rotation pool open indefinitely.
const WARM_BRIDGE_TIMEOUT: Duration = Duration::from_secs(20);

/// Per-bridge timeout for the periodic re-probe, matching the bootstrap-time
/// probe in `engine_async`.
const BRIDGE_REPROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// Timeout for the whole auto-fetch-from-sources call, matching
/// `nativeRefreshBridges`'s manual equivalent (`lib.rs`).
const AUTO_FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// How often [`bootstrap_stall_watchdog`] checks bootstrap progress.
const BOOTSTRAP_STALL_CHECK_INTERVAL: Duration = Duration::from_secs(10);
/// How long the bootstrap percentage can stay unchanged before this forces a channel reset.
const BOOTSTRAP_STALL_TIMEOUT: Duration = Duration::from_secs(120);

/// Verify that arti can establish a usable circuit before advertising
/// `EngineStatus::On`/`BootstrapEvent::Ready` to Android.
///
/// cancel-safe: NO — cancelling the timeout aborts an in-flight Tor connect;
/// this is intentional because a stop signal must not wait for a dead circuit.
async fn verify_live_circuit(
    tunnel: &TorTunnel,
    stop_rx: &mut tokio::sync::watch::Receiver<bool>,
    callback: &BootstrapEventCallback,
) -> Result<bool> {
    if *stop_rx.borrow() {
        return Ok(false);
    }

    for attempt in 1..=LIVE_PROBE_ATTEMPTS {
        let probe = tokio::select! {
            biased;
            changed = stop_rx.changed() => {
                if changed.is_err() || *stop_rx.borrow() {
                    return Ok(false);
                }
                continue;
            }
            result = tokio::time::timeout(
                LIVE_PROBE_TIMEOUT,
                tunnel.connect(LIVE_PROBE_TARGET, LIVE_PROBE_PORT),
            ) => result,
        };

        match probe {
            Ok(Ok(stream)) => {
                drop(stream);
                return Ok(true);
            }
            Ok(Err(error)) => {
                let reason = error.to_string();
                callback(BootstrapEvent::Blocked(format!(
                    "Tor bootstrapped, but live circuits are not working yet (attempt {attempt}/{LIVE_PROBE_ATTEMPTS}): {reason}"
                )));
            }
            Err(_) => {
                callback(BootstrapEvent::Blocked(format!(
                    "Tor bootstrapped, but live circuits are not working yet (attempt {attempt}/{LIVE_PROBE_ATTEMPTS}): probe timed out after {LIVE_PROBE_TIMEOUT:?}"
                )));
            }
        }

        if attempt < LIVE_PROBE_ATTEMPTS {
            if let Err(error) = tunnel.terminate_all_channels() {
                warn!(error = %error, "live circuit probe failed; channel rotation was unavailable");
            } else {
                info!(
                    attempt,
                    "rotated Tor channels after failed live circuit probe"
                );
            }

            let changed = tokio::time::sleep(LIVE_PROBE_RETRY_DELAY);
            tokio::pin!(changed);
            tokio::select! {
                biased;
                result = stop_rx.changed() => {
                    if result.is_err() || *stop_rx.borrow() {
                        return Ok(false);
                    }
                }
                _ = &mut changed => {}
            }
        }
    }

    Err(anyhow::anyhow!(
        "Tor bootstrap completed, but no live circuit passed the connectivity probe after {LIVE_PROBE_ATTEMPTS} attempts; refusing to report Connected"
    ))
}

/// Open a channel to every candidate concurrently and return successful
/// bridges ordered by measured warm-up latency. The first element is the best
/// immediate rotation candidate; the remainder stay available as fallbacks.
///
/// cancel-safe: NO — dropping this future aborts the in-flight warm-up set;
/// callers use that behaviour when Android requests stop during bootstrap.
async fn warm_bridge_pool(tunnel: TorTunnel, bridges: Vec<BridgeLine>) -> WarmPool {
    let bridges = bridges.into_iter().take(MAX_WARM_BRIDGES);
    let total = bridges.len();
    let mut tasks = tokio::task::JoinSet::new();
    for bridge in bridges {
        let tunnel = tunnel.clone();
        tasks.spawn(async move {
            let started = Instant::now();
            match tokio::time::timeout(WARM_BRIDGE_TIMEOUT, tunnel.warm_bridge(&bridge)).await {
                Ok(Ok(())) => WarmOutcome::Warm(bridge, started.elapsed()),
                Ok(Err(error)) => {
                    let rendered = format!("{error:#}");
                    if is_permanent_bridge_failure(&rendered) {
                        warn!(
                            bridge = %bridge.addr,
                            error = %rendered,
                            "bridge is permanently unusable; retiring it"
                        );
                        WarmOutcome::Retired(bridge)
                    } else {
                        debug!(bridge = %bridge.addr, error = %rendered, "bridge warm-up failed");
                        WarmOutcome::Failed
                    }
                }
                Err(_) => {
                    debug!(
                        bridge = %bridge.addr,
                        timeout = ?WARM_BRIDGE_TIMEOUT,
                        "bridge warm-up timed out"
                    );
                    WarmOutcome::Failed
                }
            }
        });
    }

    let mut warmed = Vec::new();
    let mut retired = Vec::new();
    let mut completed = 0usize;
    let mut failed = 0usize;
    while let Some(result) = tasks.join_next().await {
        completed += 1;
        match result {
            Ok(WarmOutcome::Warm(bridge, elapsed)) => warmed.push((bridge, elapsed)),
            Ok(WarmOutcome::Retired(bridge)) => {
                retired.push(bridge);
                failed += 1;
            }
            Ok(WarmOutcome::Failed) => failed += 1,
            Err(error) => {
                debug!(error = %error, "parallel bridge warm-up task failed");
                failed += 1;
            }
        }
        info!(
            active = total.saturating_sub(completed),
            completed,
            successful = warmed.len(),
            failed,
            "parallel bridge warm-up progress"
        );
    }
    warmed.sort_by_key(|(_, elapsed)| *elapsed);
    info!(
        active = 0,
        completed,
        successful = warmed.len(),
        retired = retired.len(),
        failed,
        "parallel bridge warm-up finished"
    );
    WarmPool { warmed, retired }
}

/// What one bridge's warm-up attempt established.
enum WarmOutcome {
    /// A channel opened; the bridge is proven usable and timed.
    Warm(BridgeLine, Duration),
    /// The bridge answered but can never work as configured — retire it.
    Retired(BridgeLine),
    /// Transient failure or timeout; the bridge keeps its place in the pool.
    Failed,
}

/// Result of warming a set of bridges.
pub(crate) struct WarmPool {
    /// Bridges that opened a channel, fastest first.
    pub warmed: Vec<(BridgeLine, Duration)>,
    /// Bridges whose failure was a verdict rather than bad luck.
    pub retired: Vec<BridgeLine>,
}

/// Whether a warm-up error means the bridge line itself is wrong, rather than
/// the network being uncooperative.
///
/// An identity mismatch is the case that matters in practice: the relay behind
/// the endpoint presents a different key than the fingerprint in the bridge
/// line, so the line is stale and no retry can fix it. Public webtunnel lists
/// carry many of these, and they are invisible to reachability probing --
/// the fronting web server answers perfectly, which is exactly why they
/// otherwise keep ranking well and crowding out working bridges.
///
/// Matching on the rendered message is deliberate: arti surfaces this as an
/// opaque `HandshakeProto` string, with no typed variant to match on.
fn is_permanent_bridge_failure(rendered_error: &str) -> bool {
    rendered_error.contains("does not match target")
}

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
        let current_percent = match crate::get_status()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
        {
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
    pt_binary: Option<PathBuf>,
) {
    let mut consecutive_failures = 0u32;
    let mut last_reset: Option<Instant> = None;
    // Bootstrap already probed once, but a thin pool should be refreshed shortly after the
    // first successful connection. Waiting a full hour here made `auto_fetch` effectively
    // invisible on Android, especially after a fresh install with only a few seed bridges.
    let mut first_bridge_reprobe = true;
    let mut last_bridge_reprobe = Instant::now();
    let mut auto_fetch_round: u32 = 0;
    let reprobe_interval = Duration::from_secs(
        bridge_health
            .bridges_cfg
            .recheck_interval_mins
            .saturating_mul(60),
    );

    // The confirmed-warm rotation pool, fastest first, and the top-up round's own state.
    // Starts empty: see the spawn site's comment for why that beats guessing.
    let mut rotation_bridges: Vec<(BridgeLine, Duration)> = Vec::new();
    // Candidates that failed to warm this session. Nothing demotes a merely-reachable bridge
    // in the health store just because opening a channel to it failed -- reachability and
    // warm success are different questions, see `usable_for_tor`'s webtunnel note for why the
    // gap can be large -- so without this a bridge stuck failing PT/Tor handshake would be
    // re-selected and re-attempted by every single top-up round for the life of the connection.
    let mut warm_session_failed: HashSet<String> = HashSet::new();
    // Due immediately: the first top-up round runs on this loop's first tick rather than
    // waiting a full `WARM_TOPUP_INTERVAL` on top of `WATCHDOG_PROBE_INTERVAL`.
    let mut last_topup = Instant::now()
        .checked_sub(WARM_TOPUP_INTERVAL)
        .unwrap_or_else(Instant::now);
    // Same "due immediately" reasoning as `last_topup`, but the store itself already tracks
    // per-bridge staleness (`BridgeStore::needing_circuit_verification`'s `max_age`) -- this
    // only paces how often a *tick* happens, not which bridges within it are actually checked.
    let mut last_circuit_verify = Instant::now()
        .checked_sub(CIRCUIT_VERIFY_INTERVAL)
        .unwrap_or_else(Instant::now);

    loop {
        tokio::select! {
            biased;
            _ = stop_rx.changed() => return,
            _ = tokio::time::sleep(WATCHDOG_PROBE_INTERVAL) => {}
        }
        if *stop_rx.borrow() {
            return;
        }

        // Cheap, unconditional per-tick housekeeping: keep the on-disk DNS fallback
        // fresh so a future cold start (possibly with DNS fully blocked from the
        // first moment) has something recent to fall back to, not just whatever
        // was known the last time this file happened to get written.
        if let Err(error) = bridge_probe::save_persisted_dns_cache(&dns_cache_path(
            bridge_health.config_path.as_deref(),
        )) {
            warn!(error = %error, "could not persist DNS fallback cache");
        }

        // Runs before the reachability re-probe below on purpose: that re-probe walks the
        // *entire* configured pool (thousands of bridges) and, on this loop's first tick, is
        // forced regardless of `recheck_interval_mins` -- with webtunnel's up-to-27s-per-bridge
        // worst case, a full sweep can take minutes. Running the top-up after it would delay a
        // connection's very first top-up round by however long that sweep takes, defeating the
        // point of "proactively". The health store already has plenty of history from earlier
        // rounds and earlier sessions for `select_active_probe_bridges` to draw on immediately.
        if last_topup.elapsed() >= WARM_TOPUP_INTERVAL {
            last_topup = Instant::now();
            let active = rotation_bridges.len();
            let batch_size = if active < TARGET_WARM_POOL_SIZE {
                WARM_TOPUP_BATCH
            } else {
                WARM_REFRESH_BATCH
            };

            let already_active: HashSet<String> = rotation_bridges
                .iter()
                .map(|(bridge, _)| bridge.to_string())
                .collect();
            // Respect the transport preference the same way the bootstrap-time probe pool
            // does. Without this, ranking-by-reachability over the unfiltered configured pool
            // hands most of every batch to whichever transport is largest and most TCP-reachable
            // -- typically obfs4 -- even on a network where obfs4 is blocked at the flow-shape
            // layer and every one of those attempts is doomed before it starts, starving the
            // transport the user actually asked for of its share of each round's batch.
            let preferred = preferred_transport_bridges(&bridges, &bridge_health);
            let batch: Vec<BridgeLine> = select_active_probe_bridges(&preferred, &bridge_health)
                .into_iter()
                .filter(|bridge| {
                    let text = bridge.to_string();
                    !already_active.contains(&text) && !warm_session_failed.contains(&text)
                })
                .take(batch_size)
                .collect();

            if !batch.is_empty() {
                info!(
                    count = batch.len(),
                    active,
                    target = TARGET_WARM_POOL_SIZE,
                    "warm pool: attempting new candidates"
                );
                let pool = tokio::select! {
                    biased;
                    _ = stop_rx.changed() => return,
                    pool = warm_bridge_pool(tunnel.clone(), batch.clone()) => pool,
                };
                persist_warm_results(&pool, &bridge_health);

                let warmed_keys: HashSet<String> =
                    pool.warmed.iter().map(|(b, _)| b.to_string()).collect();
                for bridge in &batch {
                    let text = bridge.to_string();
                    if !warmed_keys.contains(&text) {
                        warm_session_failed.insert(text);
                    }
                }
                let retired_keys: HashSet<String> =
                    pool.retired.iter().map(|b| b.to_string()).collect();
                rotation_bridges.retain(|(bridge, _)| !retired_keys.contains(&bridge.to_string()));

                let newly_warmed = pool.warmed.len();
                rotation_bridges.extend(pool.warmed);
                // Fastest first; a full pool sheds its slowest members here, which is how a
                // newly-discovered fast bridge displaces an already-active slow one.
                rotation_bridges.sort_by_key(|(_, latency)| *latency);
                if rotation_bridges.len() > TARGET_WARM_POOL_SIZE {
                    let dropped = rotation_bridges.split_off(TARGET_WARM_POOL_SIZE);
                    for (bridge, latency) in &dropped {
                        debug!(
                            bridge = %bridge.addr,
                            latency_ms = latency.as_millis() as u64,
                            "warm pool: dropped in favour of a faster bridge"
                        );
                    }
                }

                crate::set_active_bridges(
                    bridge_health.config_path.as_deref(),
                    &rotation_bridges
                        .iter()
                        .map(|(bridge, _)| bridge.clone())
                        .collect::<Vec<_>>(),
                );
                info!(
                    active = rotation_bridges.len(),
                    target = TARGET_WARM_POOL_SIZE,
                    newly_warmed,
                    "warm pool: rotation updated"
                );
            }
        }

        // Background circuit-verify tick: the standard this whole app now holds bridges to
        // ("reachable" means a live circuit actually reached the open internet, not merely a
        // TCP handshake or an open channel) applied to a slow trickle of the pool, not just the
        // QR-scan flow's user-initiated checks. See `docs/design/real-connectivity-bridge-
        // verification.md` for why this can't simply replace the TCP reprobe above: a full
        // check costs a real Tor circuit per bridge, not a local socket.
        if last_circuit_verify.elapsed() >= CIRCUIT_VERIFY_INTERVAL {
            last_circuit_verify = Instant::now();
            let store_path = BridgeStore::resolve_path(bridge_health.config_path.as_deref());
            let due = match BridgeStore::load(store_path) {
                Ok(store) => store.needing_circuit_verification(
                    OffsetDateTime::now_utc(),
                    CIRCUIT_VERIFY_MAX_AGE,
                    CIRCUIT_VERIFY_BATCH,
                ),
                Err(error) => {
                    warn!(error = %error, "circuit-verify: failed to load bridge store");
                    Vec::new()
                }
            };

            if !due.is_empty() {
                info!(count = due.len(), "circuit-verify: checking due bridges");
                let live_cache_dir = bridge_health
                    .config_path
                    .as_deref()
                    .map(crate::arti_cache_dir)
                    .unwrap_or_else(|| std::path::PathBuf::from("arti-data/cache"));
                let scratch_base = bridge_health
                    .config_path
                    .as_deref()
                    .map(|p| {
                        crate::scratch_dir(p, &format!("circuit-verify-{}", std::process::id()))
                    })
                    .unwrap_or_else(|| {
                        std::path::PathBuf::from(format!(
                            "verify-scratch/circuit-verify-{}",
                            std::process::id()
                        ))
                    });
                let verify_pt_binary = pt_binary.clone();
                let verify_health = bridge_health.clone();
                tokio::spawn(async move {
                    // `verify_bridges_sequential` blocks its calling thread (it builds and
                    // drives its own throwaway tokio runtimes internally, one per bridge) --
                    // `spawn_blocking` moves it off this runtime's async worker threads, the
                    // same reason `nativeVerifyBridges` runs it on a dedicated OS thread rather
                    // than as a plain async task.
                    let results = tokio::task::spawn_blocking(move || {
                        let mut results = Vec::new();
                        crate::verify_bridges_sequential(
                            &live_cache_dir,
                            &scratch_base,
                            due,
                            verify_pt_binary,
                            CIRCUIT_VERIFY_BOOTSTRAP_TIMEOUT,
                            CIRCUIT_VERIFY_PROBE_TIMEOUT,
                            |bridge, result| results.push((bridge.clone(), result.is_ok())),
                        );
                        let _ = std::fs::remove_dir_all(&scratch_base);
                        results
                    })
                    .await
                    .unwrap_or_default();

                    let verified = results.iter().filter(|(_, ok)| *ok).count();
                    info!(
                        checked = results.len(),
                        verified, "circuit-verify: tick complete"
                    );
                    persist_circuit_verify_results(&results, &verify_health);
                });
            }
        }

        let should_reprobe = !reprobe_interval.is_zero()
            && (first_bridge_reprobe || last_bridge_reprobe.elapsed() >= reprobe_interval);
        if !bridges.is_empty() && should_reprobe {
            // Bumped synchronously, before the spawn: this guards against starting a second
            // sweep while one is still running, not against the loop moving on without waiting
            // for this one -- moving on is the fix, not a race to prevent.
            first_bridge_reprobe = false;
            last_bridge_reprobe = Instant::now();
            auto_fetch_round = auto_fetch_round.wrapping_add(1);

            let reprobe_tunnel = tunnel.clone();
            let reprobe_bridges = bridges.clone();
            let reprobe_health = bridge_health.clone();
            let mut reprobe_stop_rx = stop_rx.clone();
            let this_round = auto_fetch_round;
            // Spawned rather than awaited inline: a full sweep of the configured pool (thousands
            // of bridges, some with multi-second timeouts) previously blocked this entire loop --
            // including the warm-pool top-up and the liveness check below -- for as long as the
            // sweep took. Measured on a phone: still running 7+ minutes after the connection came
            // up, during which the top-up round that should fire every WARM_TOPUP_INTERVAL never
            // got a second chance to run. Neither the top-up cadence nor the liveness check has
            // any reason to wait on this; only the health store needs the result, and that's
            // written from inside the spawned task itself.
            tokio::spawn(async move {
                if *reprobe_stop_rx.borrow() {
                    return;
                }
                let mut round = tokio::select! {
                    biased;
                    _ = reprobe_stop_rx.changed() => return,
                    round = bridge_probe::probe_round_with_policy(reprobe_bridges.clone(), BRIDGE_REPROBE_TIMEOUT, reprobe_health.resolver_policy) => round,
                };
                persist_and_rank_probe(&reprobe_bridges, &mut round, &reprobe_health);
                let alive = std::mem::take(&mut round.alive);
                debug!(
                    alive = alive.len(),
                    total = reprobe_bridges.len(),
                    "watchdog: periodic bridge re-probe complete"
                );

                if alive.len() < reprobe_health.bridges_cfg.min_alive
                    && reprobe_health.bridges_cfg.auto_fetch
                    && !reprobe_health.bridges_cfg.sources.is_empty()
                {
                    let barren = barren_sources(&reprobe_health, this_round);
                    let sources: Vec<bridge_fetcher::Source> = reprobe_health
                        .bridges_cfg
                        .sources
                        .iter()
                        .filter(|s| !barren.contains(&s.label))
                        .map(|s| bridge_fetcher::Source {
                            label: s.label.clone(),
                            url: s.url.clone(),
                            headers: s.headers.clone(),
                            cookies: s.cookies.clone(),
                        })
                        .collect();
                    let max_body_bytes = reprobe_health
                        .bridges_cfg
                        .max_body_mib
                        .saturating_mul(1024 * 1024);
                    info!(
                        alive = alive.len(),
                        min_alive = reprobe_health.bridges_cfg.min_alive,
                        "watchdog: alive bridge pool is thin, auto-fetching more"
                    );
                    let (fetched, outcomes) = tokio::select! {
                        biased;
                        _ = reprobe_stop_rx.changed() => return,
                        result = bridge_fetcher::fetch_all(&reprobe_tunnel, &sources, AUTO_FETCH_TIMEOUT, max_body_bytes) => result,
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
                    persist_bridge_sources(&outcomes, &reprobe_health);
                    let (unique, duplicates) = bridge_fetcher::dedup_bridges(fetched);
                    info!(
                        unique = unique.len(),
                        duplicates, "watchdog: bridge auto-fetch complete"
                    );
                    record_auto_fetched_bridges(unique);
                }
            });
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
        // A sustained stall is what a network change looks like from in here,
        // and the DNS cache plus the DoH provider scores both describe the
        // network we were on, not the one we may now be on.
        bridge_probe::flush_dns_cache();
        if let Err(e) = tunnel.terminate_all_channels() {
            warn!(error = %e, "watchdog: terminate_all_channels failed");
        } else {
            let candidates: Vec<BridgeLine> = if rotation_bridges.is_empty() {
                bridges.clone()
            } else {
                rotation_bridges.iter().map(|(b, _)| b.clone()).collect()
            };
            let pool = tokio::select! {
                biased;
                _ = stop_rx.changed() => return,
                pool = warm_bridge_pool(tunnel.clone(), candidates) => pool,
            };
            // Persist even when nothing warmed: a round that only retired stale
            // bridges is still progress worth keeping.
            persist_warm_results(&pool, &bridge_health);
            if !pool.retired.is_empty() {
                let retired: HashSet<String> = pool.retired.iter().map(|b| b.to_string()).collect();
                rotation_bridges.retain(|(b, _)| !retired.contains(&b.to_string()));
            }
            if !pool.warmed.is_empty() {
                rotation_bridges = pool.warmed;
                crate::set_active_bridges(
                    bridge_health.config_path.as_deref(),
                    &rotation_bridges
                        .iter()
                        .map(|(bridge, _)| bridge.clone())
                        .collect::<Vec<_>>(),
                );
                info!(
                    warmed = rotation_bridges.len(),
                    retired = pool.retired.len(),
                    "watchdog: rebuilt parallel bridge rotation pool"
                );
            }
        }
        last_reset = Some(now);
        consecutive_failures = 0;
    }
}

/// Narrow the startup pool to the user's preferred transport, if they set one.
///
/// Blocking is transport-specific: a network that fingerprints obfs4 and kills
/// its streams routinely lets webtunnel through untouched, since webtunnel is
/// ordinary HTTPS to a real web server. Honouring the preference here — before
/// the health ranking — keeps the choice meaningful even when the background
/// pool is dominated by the other transport.
///
/// A preference rather than a filter, but only in one direction: matching
/// nothing falls back to the full list, since asking for a transport the pool
/// does not contain should not amount to asking for nothing. A preference whose
/// bridges all turn out to be dead is deliberately *not* rescued — which
/// transport a network actually permits is what the setting exists to reveal,
/// so that failure is reported rather than papered over.
fn preferred_transport_bridges(
    configured: &[BridgeLine],
    bridge_health: &BridgeHealthContext,
) -> Vec<BridgeLine> {
    let Some(preferred) = bridge_health.bridges_cfg.preferred_transport() else {
        return configured.to_vec();
    };
    let matching: Vec<BridgeLine> = configured
        .iter()
        .filter(|bridge| bridge.transport.as_deref() == Some(preferred))
        .cloned()
        .collect();
    if matching.is_empty() {
        warn!(
            preferred,
            configured = configured.len(),
            "no bridge uses the preferred transport; using the full pool"
        );
        return configured.to_vec();
    }
    info!(
        preferred,
        matching = matching.len(),
        configured = configured.len(),
        "restricted startup pool to the preferred transport"
    );
    matching
}

/// Choose the small, latency-sensitive startup pool from the persisted bridge ranking.
///
/// `configured` is intentionally not reduced here: the watchdog still owns the complete
/// imported list and uses it as the background discovery/re-probe pool. A missing or stale
/// health store falls back to the first bounded slice; the caller performs a full probe only
/// when that slice produces no reachable bridge.
fn select_active_probe_bridges(
    configured: &[BridgeLine],
    bridge_health: &BridgeHealthContext,
) -> Vec<BridgeLine> {
    let store_path = BridgeStore::resolve_path(bridge_health.config_path.as_deref());
    let store = BridgeStore::load(store_path).ok();

    // Drop retired bridges before anything else looks at the list. They are
    // reachable by construction -- a retirement means the endpoint answers but
    // the relay's identity does not match the line -- so every reachability
    // check votes for them, and the short-pool shortcut below would hand them
    // straight back. Keep them if that would leave nothing at all: a pool of
    // known-bad bridges is still a better starting point than an empty one.
    let usable: Vec<BridgeLine> = match &store {
        Some(store) => {
            let live: Vec<BridgeLine> = configured
                .iter()
                .filter(|bridge| !store.is_retired(bridge))
                .cloned()
                .collect();
            if live.is_empty() {
                warn!(
                    configured = configured.len(),
                    "every configured bridge has been retired; using them anyway"
                );
                configured.to_vec()
            } else {
                if live.len() < configured.len() {
                    info!(
                        retired = configured.len() - live.len(),
                        remaining = live.len(),
                        "skipped retired bridges when choosing the active pool"
                    );
                }
                live
            }
        }
        None => configured.to_vec(),
    };

    if usable.len() <= MAX_ACTIVE_BRIDGES {
        return usable;
    }

    if let Some(store) = &store {
        // Ranks within `usable` rather than globally-then-intersect: see
        // `BridgeStore::healthiest_among`'s doc for why that distinction is the whole point --
        // a webtunnel-preferred `usable` ranked against the *global* top bridges would mostly
        // disappear behind a much larger obfs4 history.
        let ranked = store.healthiest_among(&usable, MAX_ACTIVE_BRIDGES);
        if !ranked.is_empty() {
            return ranked;
        }
    }

    usable.into_iter().take(MAX_ACTIVE_BRIDGES).collect()
}

/// Persist a probe round's reachability outcome to the shared bridge-health store
/// (`<config-stem>.alive-bridges.log`, same file the CLI daemon uses) and re-sort `alive` by
/// historical stability (`ok_count`, ties broken by latency) ahead of a bridge seen reachable
/// for the first time. Shared between the bootstrap-time probe in `engine_async`,
/// `stall_watchdog`'s periodic re-probe, and `nativeProbeBridgeTransport`'s on-demand probe --
/// all three need the identical persist-and-rank step, just with different cancellation/error
/// handling and triggers around the probe itself. Best-effort throughout: a missing or
/// unwritable store never fails the caller, it just forfeits the ranking boost for this round.
pub(crate) fn persist_and_rank_probe(
    all_bridges: &[BridgeLine],
    round: &mut bridge_probe::ProbeRound,
    bridge_health: &BridgeHealthContext,
) {
    // A bridge whose hostname would not resolve was never contacted, so this
    // round has nothing to say about it. Recording a failure would be recording
    // our own resolver's trouble against the bridge -- and, through the source
    // tally, against whoever supplied it.
    let measured: Vec<BridgeLine> = if round.unmeasured.is_empty() {
        all_bridges.to_vec()
    } else {
        let skip: HashSet<String> = round.unmeasured.iter().map(|b| b.to_string()).collect();
        all_bridges
            .iter()
            .filter(|b| !skip.contains(&b.to_string()))
            .cloned()
            .collect()
    };
    if !round.unmeasured.is_empty() {
        info!(
            unmeasured = round.unmeasured.len(),
            measured = measured.len(),
            "probe round left some bridges untested; their health is unchanged"
        );
    }

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
                &measured,
                &round.alive,
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
            round.alive.sort_by(|(ba, la), (bb, lb)| {
                store
                    .channel_ok_count(bb)
                    .cmp(&store.channel_ok_count(ba))
                    .then_with(|| store.ok_count(bb).cmp(&store.ok_count(ba)))
                    .then_with(|| la.cmp(lb))
            });
        }
        Err(e) => {
            warn!(path = %store_path.display(), error = %e, "could not load bridge health store");
        }
    }
}

/// Path for the on-disk DNS fallback cache, next to the config file --
/// same sibling-file convention as `active_bridges_path` in `lib.rs`.
fn dns_cache_path(config_path: Option<&std::path::Path>) -> std::path::PathBuf {
    match config_path {
        Some(cfg) => {
            let dir = cfg.parent().unwrap_or_else(|| std::path::Path::new("."));
            let stem = cfg
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "tor-socks5".to_string());
            dir.join(format!("{stem}.dns-cache"))
        }
        None => std::path::PathBuf::from("tor-socks5.dns-cache"),
    }
}

/// Persist the PT-channel rotation signal without confusing it with an
/// end-to-end circuit success or a plain TCP probe.
/// A source must have offered this many bridges before its yield is judged.
/// Below it, a run of bad luck is indistinguishable from a dead collector.
const SOURCE_MIN_SAMPLE: usize = 40;

/// How often a barren source is retried anyway. Collectors do resume, and a
/// source struck off permanently could never prove it.
const BARREN_SOURCE_RETRY_EVERY: u32 = 6;

/// Labels of sources worth skipping this round.
///
/// Barren means "has supplied a meaningful number of bridges and not one of
/// them was ever reachable" — the state a collector reaches when it stops
/// regenerating, which no fetch-level check can see because it keeps answering
/// HTTP 200 with a full list. Skipping is periodic rather than permanent so a
/// revived collector re-earns its place on its own.
fn barren_sources(bridge_health: &BridgeHealthContext, round: u32) -> HashSet<String> {
    if round.is_multiple_of(BARREN_SOURCE_RETRY_EVERY) {
        return HashSet::new();
    }
    let path = BridgeStore::resolve_path(bridge_health.config_path.as_deref());
    let Ok(store) = BridgeStore::load(path) else {
        return HashSet::new();
    };
    let barren: HashSet<String> = store
        .source_summary()
        .into_iter()
        .filter(|s| s.is_barren(SOURCE_MIN_SAMPLE))
        .map(|s| s.label)
        .collect();
    if !barren.is_empty() {
        info!(
            skipped = barren.len(),
            "watchdog: skipping sources that have yielded no reachable bridge"
        );
    }
    barren
}

/// Credit each source with the bridges it supplied, so a collector can later be
/// judged by what it yields rather than by whether its fetch returned 200.
fn persist_bridge_sources(
    outcomes: &[bridge_fetcher::FetchOutcome],
    bridge_health: &BridgeHealthContext,
) {
    if outcomes.iter().all(|o| o.bridges.is_empty()) {
        return;
    }
    let path = BridgeStore::resolve_path(bridge_health.config_path.as_deref());
    let mut store = match BridgeStore::load(path) {
        Ok(store) => store,
        Err(error) => {
            warn!(error = %error, "could not load bridge health store for source attribution");
            return;
        }
    };
    let now = OffsetDateTime::now_utc();
    for outcome in outcomes {
        for bridge in &outcome.bridges {
            store.note_source_at(bridge, &outcome.label, now);
        }
    }
    if let Err(error) = store.save() {
        warn!(error = %error, "could not persist bridge source attribution");
    }
}

/// Outcome of [`cold_start_rescue_fetch`]: either a (possibly still empty)
/// set of newly-alive bridges, or an early exit because the caller asked to
/// stop while the rescue fetch was in flight.
enum ColdStartRescue {
    Alive(Vec<(BridgeLine, Duration)>),
    StopRequested,
}

/// True cold start: every configured bridge (active slice and, where tried,
/// the full background pool) failed its TCP probe, and there is no
/// `TorTunnel` yet to route a normal auto-fetch through — `bridge_fetcher`'s
/// usual path requires one. Without this, a fresh install (or a health store
/// wiped by all-dead bridges) can never recover on its own: `auto_fetch`
/// exists specifically for this, but the watchdog's version of it only runs
/// after a tunnel is already up.
///
/// Fetches the configured collateral-freedom sources directly (no Tor,
/// hostnames resolved through `bridge-probe`'s DoH pool -- see
/// `bridge_fetcher::fetch_all_direct`), persists source attribution the same
/// way the watchdog's own auto-fetch does, records anything found so Kotlin
/// can persist it into the user's saved bridge list, and re-probes the
/// result before handing it back. Returns an empty `Alive` set (not an
/// error) when `auto_fetch` is disabled, no sources are configured, or the
/// rescue fetch itself turns up nothing reachable -- the caller already
/// knows how to fail on an empty set.
async fn cold_start_rescue_fetch(
    bridge_health: &BridgeHealthContext,
    stop_rx: &mut tokio::sync::watch::Receiver<bool>,
) -> ColdStartRescue {
    if !bridge_health.bridges_cfg.auto_fetch || bridge_health.bridges_cfg.sources.is_empty() {
        return ColdStartRescue::Alive(Vec::new());
    }

    info!(
        "no configured bridge is reachable; attempting a direct (non-Tor) fetch of fresh \
         bridges before giving up"
    );

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
    let max_body_bytes = bridge_health
        .bridges_cfg
        .max_body_mib
        .saturating_mul(1024 * 1024);

    let (fetched, outcomes) = tokio::select! {
        biased;
        _ = stop_rx.changed() => return ColdStartRescue::StopRequested,
        result = bridge_fetcher::fetch_all_direct(&sources, bridge_health.resolver_policy, AUTO_FETCH_TIMEOUT, max_body_bytes) => result,
    };
    for outcome in &outcomes {
        if let Some(err) = &outcome.error {
            warn!(label = %outcome.label, error = %err, "cold-start rescue fetch source failed");
        } else {
            info!(
                label = %outcome.label,
                bridges = outcome.bridges_extracted,
                "cold-start rescue fetch source OK"
            );
        }
    }
    persist_bridge_sources(&outcomes, bridge_health);
    let (unique, duplicates) = bridge_fetcher::dedup_bridges(fetched);
    info!(
        unique = unique.len(),
        duplicates, "cold-start rescue fetch complete"
    );
    if unique.is_empty() {
        return ColdStartRescue::Alive(Vec::new());
    }
    record_auto_fetched_bridges(unique.clone());

    let mut round = tokio::select! {
        biased;
        _ = stop_rx.changed() => return ColdStartRescue::StopRequested,
        round = bridge_probe::probe_round_with_policy(unique.clone(), Duration::from_secs(5), bridge_health.resolver_policy) => round,
    };
    persist_and_rank_probe(&unique, &mut round, bridge_health);
    ColdStartRescue::Alive(std::mem::take(&mut round.alive))
}

fn persist_warm_results(pool: &WarmPool, bridge_health: &BridgeHealthContext) {
    if pool.warmed.is_empty() && pool.retired.is_empty() {
        return;
    }
    let path = BridgeStore::resolve_path(bridge_health.config_path.as_deref());
    let mut store = match BridgeStore::load(path) {
        Ok(store) => store,
        Err(error) => {
            warn!(error = %error, "could not load bridge health store for warm pool");
            return;
        }
    };
    let now = OffsetDateTime::now_utc();
    for (bridge, _) in &pool.warmed {
        store.note_channel_success_at(bridge, now);
    }
    // Retiring is the only way a stale bridge line ever leaves the pool: it
    // stays reachable, so probing keeps voting for it, and the ranking keeps
    // promoting it.
    for bridge in &pool.retired {
        store.note_permanent_failure_at(bridge, now);
    }
    if let Err(error) = store.save() {
        warn!(error = %error, "could not persist bridge rotation ranking");
    }
}

/// Persist the background circuit-verify tick's results. Only successes are recorded
/// (`BridgeStore::note_circuit_verified_at`) -- a failed end-to-end check does not demote the
/// bridge or bump any failure counter, it simply stays due for the next tick, since a single
/// timeout is routine (see `verify_bridges_sequential`'s doc) rather than proof the bridge is
/// actually bad.
fn persist_circuit_verify_results(
    results: &[(BridgeLine, bool)],
    bridge_health: &BridgeHealthContext,
) {
    if results.is_empty() {
        return;
    }
    let path = BridgeStore::resolve_path(bridge_health.config_path.as_deref());
    let mut store = match BridgeStore::load(path) {
        Ok(store) => store,
        Err(error) => {
            warn!(error = %error, "circuit-verify: could not load bridge health store");
            return;
        }
    };
    let now = OffsetDateTime::now_utc();
    for (bridge, ok) in results {
        if *ok {
            store.note_circuit_verified_at(bridge, now);
        }
    }
    if let Err(error) = store.save() {
        warn!(error = %error, "circuit-verify: could not persist results");
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
/// crash the loop. Accept errors are also treated as transient and retried
/// after `ACCEPT_ERROR_BACKOFF`.
async fn accept_loop(
    listener: &TcpListener,
    tunnel: &TorTunnel,
    permits: Arc<Semaphore>,
    policy: ConnectionPolicy,
) -> Result<()> {
    loop {
        // Accept a new connection; any accept error is treated as transient —
        // log it, back off, and retry instead of tearing down the engine.
        let (client, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!(?e, "accept failed; retrying in {ACCEPT_ERROR_BACKOFF:?}");
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                continue;
            }
        };

        // Acquire a permit before spawning (bounds task growth)
        let permit = permits
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore not closed");

        // Spawn a task for this connection
        let tunnel = tunnel.clone();
        let auth = policy.auth_state.clone();
        let block_onion = policy.block_onion;
        tokio::spawn(async move {
            // Permit is moved into the task and dropped on exit
            let _permit = permit;

            debug!(%peer, "new SOCKS5 connection");

            match handle_connection(client, tunnel, auth, block_onion).await {
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
    block_onion: bool,
) -> Result<()> {
    // SOCKS5 handshake: USER/PASS when `auth` is configured, NO_AUTH otherwise.
    let req = socks5_proto::handshake(&mut client, auth)
        .await
        .context("SOCKS5 handshake")?;

    if !onion_destination_allowed(&req, block_onion) {
        info!(host = %req.host, port = req.port, "rejecting onion destination by local policy");
        socks5_proto::reply(&mut client, Reply::ConnectionNotAllowed)
            .await
            .context("failed to send onion policy reply")?;
        return Ok(());
    }

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

/// Apply the Android listener's global destination policy after SOCKS5
/// authentication and before any Tor stream is opened.
fn onion_destination_allowed(req: &socks5_proto::ConnectRequest, block_onion: bool) -> bool {
    !block_onion || !req.is_onion()
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
    use std::time::Duration;

    use super::{onion_destination_allowed, ACCEPT_ERROR_BACKOFF};
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

    #[test]
    fn accept_error_backoff_is_sane() {
        assert!(ACCEPT_ERROR_BACKOFF > Duration::ZERO);
        assert!(ACCEPT_ERROR_BACKOFF <= Duration::from_secs(5));
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

    #[test]
    fn onion_policy_blocks_only_when_enabled() {
        let onion = socks5_proto::ConnectRequest {
            host: "example.onion".into(),
            port: 443,
            authed_user: None,
        };
        let clearnet = socks5_proto::ConnectRequest {
            host: "example.com".into(),
            port: 443,
            authed_user: None,
        };
        assert!(!onion_destination_allowed(&onion, true));
        assert!(onion_destination_allowed(&onion, false));
        assert!(onion_destination_allowed(&clearnet, true));
    }
}
