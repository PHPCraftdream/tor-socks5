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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::callback::JavaCallback;
use anyhow::{Context, Result};
use arti_wrapper::{BootstrapEvent, BootstrapEventCallback, TorTunnel};
use auth::AuthState;
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
    auth_state: Option<Arc<AuthState>>,
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
            engine_async(
                settings,
                listen_addr,
                auth_state,
                stop_rx,
                java_callback,
                failed_already_emitted,
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
    settings: arti_wrapper::Settings,
    listen_addr: SocketAddr,
    auth_state: Option<Arc<AuthState>>,
    mut stop_rx: tokio::sync::watch::Receiver<bool>,
    java_callback: Arc<JavaCallback>,
    failed_already_emitted: Arc<AtomicBool>,
) -> Result<()> {
    // Create a shared callback that updates status AND emits to Java
    let callback: BootstrapEventCallback = Arc::new({
        let cb = Arc::clone(&java_callback);
        let failed_flag = Arc::clone(&failed_already_emitted);
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

    // Probe bridges for reachability (5s timeout per bridge). Cancellable:
    // without this select!, a stop signal received while probing (which can
    // itself take up to 5s per bridge) is not observed until the accept-loop
    // select! further down, which is never reached if bridges never come up
    // -- nativeStop would then block for its full 10s timeout instead of
    // returning immediately.
    info!(
        count = settings.bridges.len(),
        "probing bridges for reachability"
    );
    let alive = tokio::select! {
        biased;
        _ = stop_rx.changed() => {
            info!("received stop signal while probing bridges");
            return Ok(());
        }
        alive = bridge_probe::probe_and_sort(settings.bridges.clone(), Duration::from_secs(5)) => alive,
    };

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

    // Bootstrap Tor with event notifications. Cancellable for the same
    // reason as the bridge probe above -- bootstrap can run for tens of
    // seconds, and a stop signal received mid-bootstrap must tear the
    // half-built `TorTunnel` down immediately rather than being ignored
    // until bootstrap finishes or times out on its own.
    info!("bootstrapping Tor client...");
    let tunnel = tokio::select! {
        biased;
        _ = stop_rx.changed() => {
            info!("received stop signal while bootstrapping");
            return Ok(());
        }
        result = TorTunnel::bootstrap_with_notify(settings, Some(callback.clone())) => {
            result.context("failed to bootstrap Tor")?
        }
    };
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
        res = accept_loop(&listener, &tunnel, permits, auth_state) => {
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
