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
///
/// `Debug` is derived because `EngineSlot` (lib.rs) derives it and needs this
/// type to be `Debug` too; all fields implement it.
#[derive(Debug)]
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

/// Final status publication at the end of `engine_main`. Skipped when this
/// thread's generation is no longer current: a newer engine owns the global
/// status. `done_tx.send(())` stays unconditional — the receiver always
/// lives in the ENGINE slot's handle or in an in-flight nativeStop's parker,
/// so it is never orphaned while a consumer could still need it.
fn publish_final_status(generation: u64, status: EngineStatus) {
    if crate::current_engine_generation() != generation {
        info!(
            generation,
            current = crate::current_engine_generation(),
            "stale engine generation: skipping final status publication for a newer engine"
        );
        return;
    }
    set_final_status(status);
}

/// `engine_async`'s teardown side effects (clear CURRENT_TUNNEL + the
/// active-bridges file). Skipped as a unit when the generation is stale, so
/// a late old engine can never wipe a newer engine's state. The early
/// JVM-attach-failure path in `engine_main` and the mid-flight writes
/// (`Starting(pct)` progress, `On(addr)`, startup `set_active_bridges`,
/// `set_current_tunnel(Some(..))`) stay unguarded on purpose: the ENGINE
/// slot only returns to `Idle` after the old thread was joined (see
/// `EngineSlot`'s invariant doc), so no newer engine can exist while this
/// thread is between those points.
fn clear_shared_state(generation: u64, config_path: Option<&std::path::Path>) {
    if crate::current_engine_generation() != generation {
        info!(
            generation,
            current = crate::current_engine_generation(),
            "stale engine generation: skipping teardown of shared state for a newer engine"
        );
        return;
    }
    set_current_tunnel(None);
    crate::set_active_bridges(config_path, &[]);
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
// 8 parameters including `generation` — lifecycle bookkeeping that
// belongs to neither existing struct (same rationale as
// `BridgeHealthContext`'s bundling, which doesn't fit here).
#[allow(clippy::too_many_arguments)]
pub(crate) fn engine_main(
    settings: arti_wrapper::Settings,
    listen_addr: SocketAddr,
    policy: ConnectionPolicy,
    stop_rx: tokio::sync::watch::Receiver<bool>,
    done_tx: std::sync::mpsc::Sender<()>,
    java_callback: Arc<JavaCallback>,
    bridge_health: BridgeHealthContext,
    generation: u64,
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
                generation,
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

    publish_final_status(generation, final_status);

    // Notify the JNI side that we're done
    let _ = done_tx.send(());
}

/// Async engine body, runs inside a Tokio runtime.
// 8 parameters including `generation` — lifecycle bookkeeping that
// belongs to neither existing struct (same rationale as
// `BridgeHealthContext`'s bundling, which doesn't fit here).
#[allow(clippy::too_many_arguments)]
async fn engine_async(
    mut settings: arti_wrapper::Settings,
    listen_addr: SocketAddr,
    policy: ConnectionPolicy,
    mut stop_rx: tokio::sync::watch::Receiver<bool>,
    java_callback: Arc<JavaCallback>,
    failed_already_emitted: Arc<AtomicBool>,
    bridge_health: BridgeHealthContext,
    generation: u64,
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
    clear_shared_state(generation, bridge_health.config_path.as_deref());
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

#[path = "engine_bootstrap.rs"]
mod bootstrap;
#[path = "engine_bridges.rs"]
mod bridges;

use bootstrap::*;
pub(crate) use bootstrap::{LIVE_PROBE_PORT, LIVE_PROBE_TARGET};
use bridges::*;
pub(crate) use bridges::{
    bridge_store_write_lock, get_current_tunnel, persist_and_rank_probe, take_auto_fetched_bridges,
    take_pruned_bridges,
};

#[cfg(test)]
#[path = "engine_tests.rs"]
mod engine_tests;
