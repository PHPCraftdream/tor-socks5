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
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use arti_wrapper::{BootstrapEvent, BootstrapEventCallback, TorTunnel};
use crate::callback::JavaCallback;
use socks5_proto::{self, Reply};
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
    stop_rx: tokio::sync::watch::Receiver<bool>,
    done_tx: std::sync::mpsc::Sender<()>,
    java_callback: Arc<JavaCallback>,
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
            set_final_status(EngineStatus::Error(format!(
                "failed to attach to JVM: {e}"
            )));
            let _ = done_tx.send(());
            return;
        }
    };

    // Wrap everything in catch_unwind to prevent panic unwinding.
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        // Build Tokio runtime (4 workers for mobile budget)
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
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
            engine_async(settings, listen_addr, stop_rx, java_callback).await
        })
    }));

    // Set final status based on result
    let final_status = match result {
        Ok(Ok(())) => EngineStatus::Off,
        Ok(Err(e)) => {
            error!("engine error: {:#}", e);
            EngineStatus::Error(format!("{:#}", e))
        }
        Err(panic_info) => {
            let panic_msg = panic_info
                .downcast_ref::<String>()
                .map(|s| s.as_str())
                .or_else(|| panic_info.downcast_ref::<&str>().copied())
                .unwrap_or("unknown panic");
            error!("engine panic: {}", panic_msg);
            EngineStatus::Error(format!("engine panicked: {}", panic_msg))
        }
    };

    set_final_status(final_status);

    // Notify the JNI side that we're done
    let _ = done_tx.send(());
}

/// Async engine body, runs inside a Tokio runtime.
async fn engine_async(
    settings: arti_wrapper::Settings,
    listen_addr: SocketAddr,
    mut stop_rx: tokio::sync::watch::Receiver<bool>,
    java_callback: Arc<JavaCallback>,
) -> Result<()> {
    // Create a shared callback that updates status AND emits to Java
    let callback: BootstrapEventCallback = Arc::new({
        let cb = Arc::clone(&java_callback);
        move |event| {
            // Update status based on event
            match &event {
                BootstrapEvent::Progress(fraction) => {
                    let pct = (fraction.clamp(0.0, 1.0) * 100.0).round() as u8;
                    set_final_status(EngineStatus::Starting(pct));
                }
                BootstrapEvent::Ready => {
                    // Status will be set to On after listener binds
                }
                BootstrapEvent::Blocked(_) => {
                    // Blocked is non-fatal, don't change status
                }
                BootstrapEvent::Failed(_) => {
                    // Failed is handled separately; bootstrap_with_notify also emits this
                }
            }
            // Emit to Java
            cb.emit(event);
        }
    });

    // Probe bridges for reachability (5s timeout per bridge)
    info!(
        count = settings.bridges.len(),
        "probing bridges for reachability"
    );
    let alive = bridge_probe::probe_and_sort(
        settings.bridges.clone(),
        Duration::from_secs(5),
    )
    .await;

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
    let mut settings = settings;
    settings.bridges = alive.into_iter().map(|(bridge, _)| bridge).collect();

    // Bootstrap Tor with event notifications
    info!("bootstrapping Tor client...");
    let tunnel = TorTunnel::bootstrap_with_notify(settings, Some(callback.clone()))
        .await
        .context("failed to bootstrap Tor")?;
    info!("Tor is ready");

    // Bind SOCKS5 listener
    let listener = TcpListener::bind(&listen_addr)
        .await
        .with_context(|| format!("failed to bind SOCKS5 listener to {}", listen_addr))?;

    let actual_addr = listener
        .local_addr()
        .context("failed to get listener address")?;

    info!(listen_addr = %actual_addr, "SOCKS5 proxy is listening");

    // Set status to On
    set_final_status(EngineStatus::On(actual_addr));

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
        res = accept_loop(&listener, &tunnel, permits) => {
            if let Err(e) = res {
                error!(error = %e, "accept loop exited with error");
                Err(e.context("accept loop failed"))
            } else {
                Ok(())
            }
        }
    };

    // Teardown: drop tunnel, then sleep 500ms to release state-dir lock
    info!("shutting down Tor client");
    drop(tunnel);
    tokio::time::sleep(Duration::from_millis(500)).await;

    info!("engine shutdown complete");
    accept_result
}

/// SOCKS5 accept loop.
///
/// Accepts connections, acquires a semaphore permit, spawns a task per connection.
/// Each task:
/// 1. Performs SOCKS5 handshake (NO_AUTH).
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
        tokio::spawn(async move {
            // Permit is moved into the task and dropped on exit
            let _permit = permit;

            debug!(%peer, "new SOCKS5 connection");

            match handle_connection(client, tunnel).await {
                Ok(()) => {
                    debug!(%peer, "connection closed normally");
                }
                Err(e) => {
                    // Classify and log at appropriate level
                    let error_str = format!("{:#}", e);
                    if error_str.contains("handshake") || error_str.contains("reset") || error_str.contains("broken pipe") {
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
async fn handle_connection(
    mut client: TcpStream,
    tunnel: TorTunnel,
) -> Result<()> {
    // SOCKS5 handshake (NO_AUTH for Android v1)
    let req = socks5_proto::handshake(&mut client, None)
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
