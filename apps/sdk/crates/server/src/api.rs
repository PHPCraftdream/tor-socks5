use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use anyhow::anyhow;
use futures::FutureExt;
use tokio::sync::{oneshot, watch};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::server::ServerArgs;

/// Configuration accepted by the embedded server API.
pub use crate::config::Config;
/// Observation sink accepted by the embedded server API.
pub use tor_socks5_runtime::arti_observability::ObservationSink;
pub use tor_socks5_runtime::pt::PtBinary;

static SERVER_RUNNING: AtomicBool = AtomicBool::new(false);
type ListenAddrs = Arc<StdMutex<Vec<SocketAddr>>>;

/// The returned value is process-wide phase context, not a detailed event log;
/// [`ServerError::stage`] reports the phase of the primary failure. When cleanup
/// also fails, retrieve that secondary failure with [`ServerError::cleanup_error`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerStage {
    /// Process-wide startup recovery.
    Recovery,
    /// Configuration loading or validation.
    Config,
    /// Listener binding.
    Bind,
    /// Remaining startup, including Tor or egress initialization.
    Startup,
    /// Serving requests.
    Runtime,
    /// Startup was cancelled before readiness.
    Cancelled,
    /// A server worker task failed.
    Task,
}

/// Whether startup waits for the optional local DNS listener to bind.
///
/// The SDK defaults to [`Required`](Self::Required). For each configured DNS UDP/TCP
/// pair, binding skips unavailable pairs (`AddrInUse`, `PermissionDenied`, or
/// `AddrNotAvailable`; the latter is queued for background retry), and readiness
/// requires at least one successfully bound pair. Startup returns
/// [`ServerError::Bind`] if no pair binds. `Running` addresses contain only
/// successfully bound UDP/TCP sockets. [`Background`](Self::Background) preserves
/// the proxy CLI's legacy behavior: DNS bind failures are logged by the existing
/// background producer and do not prevent the SOCKS server from starting.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DnsStartupPolicy {
    /// Require at least one configured DNS UDP/TCP pair to bind before server readiness;
    /// unavailable pairs are skipped as described above.
    #[default]
    Required,
    /// Start DNS in the background; DNS bind failures remain non-fatal.
    Background,
}

/// Latest server lifecycle snapshot. This is a watch value, not an event log:
/// intermediate updates may be coalesced. Listener addresses are the actual
/// bound socket addresses, available starting with `Running` and retained through
/// shutdown. When DNS is enabled, its UDP and TCP sockets are included as separate
/// entries (usually the same address); the vector does not identify protocols.
/// A terminal `Stopped` status can follow either success or failure; inspect
/// [`ServerHandle::wait`] or [`ServerHandle::shutdown`] for the result.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerStatus {
    /// Startup is in progress; listener addresses are not yet known.
    Starting,
    /// The listeners are ready to accept connections.
    Running {
        /// Actual local socket addresses of bound SOCKS5 and DNS listeners.
        listen_addrs: Vec<SocketAddr>,
    },
    /// Cancellation has been observed by the worker and cleanup is in progress.
    Stopping {
        /// Actual local socket addresses of bound SOCKS5 and DNS listeners.
        listen_addrs: Vec<SocketAddr>,
    },
    /// The worker's cleanup attempt completed, whether successfully or
    /// with an error; this does not prove every task was joined.
    Stopped {
        /// Last known actual local socket addresses of bound SOCKS5 and DNS listeners;
        /// empty if readiness was not reached.
        listen_addrs: Vec<SocketAddr>,
    },
}

/// Typed failures from admission, startup, runtime, cancellation, or task execution.
/// `Cleanup` retains teardown failures separately from the primary error,
/// accessible through [`ServerError::cleanup_error`].
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// Another server already owns process-local admission.
    #[error("server is already running in this process")]
    AlreadyRunning,
    /// Listener binding failed.
    #[error(transparent)]
    Bind(anyhow::Error),
    /// Configuration loading or validation failed.
    #[error(transparent)]
    Config(anyhow::Error),
    /// Process-wide startup recovery failed.
    #[error(transparent)]
    Recovery(anyhow::Error),
    /// Remaining startup, including Tor or egress initialization, failed.
    #[error(transparent)]
    Startup(anyhow::Error),
    /// Serving requests failed.
    #[error(transparent)]
    Runtime(anyhow::Error),
    /// Startup was cancelled before readiness.
    #[error("server startup cancelled")]
    Cancelled,
    /// A supervised server task failed or panicked.
    #[error(transparent)]
    Task(anyhow::Error),
    /// Cleanup retains the primary error as its source, while the cleanup
    /// failure is available through `cleanup_error`. CLI conversion returns the
    /// primary error chain.
    /// budgets are stage-specific: Settings/global-init/owner recovery uses
    /// explicit deadlines; producer and handler joins have their own budgets
    /// (normal producer grace is 120 seconds). The final blocking-worker join
    /// has a five-second timeout. Closing the bridge-store writer is awaited
    /// without a deadline. Where a bounded stage times out, task handles remain
    /// retained in process slots for recovery by the next start's startup
    /// recovery. `Cleanup` is a secondary-failure wrapper; if secondary cleanup
    /// succeeds, an ordinary shutdown failure may be returned as
    /// `ServerError::Runtime`.
    #[error("server cleanup also failed")]
    Cleanup {
        /// The error that caused the run to fail.
        #[source]
        error: Box<ServerError>,
        /// Cleanup failure is retained separately from the primary error.
        cleanup: anyhow::Error,
    },
}

impl ServerError {
    /// Return the phase associated with this error, if it has one.
    pub fn stage(&self) -> Option<ServerStage> {
        match self {
            Self::AlreadyRunning => None,
            Self::Bind(_) => Some(ServerStage::Bind),
            Self::Config(_) => Some(ServerStage::Config),
            Self::Recovery(_) => Some(ServerStage::Recovery),
            Self::Startup(_) => Some(ServerStage::Startup),
            Self::Runtime(_) => Some(ServerStage::Runtime),
            Self::Cancelled => Some(ServerStage::Cancelled),
            Self::Task(_) => Some(ServerStage::Task),
            Self::Cleanup { error, .. } => error.stage(),
        }
    }

    /// Return a cleanup failure, if cleanup also failed after the primary error.
    pub fn cleanup_error(&self) -> Option<&anyhow::Error> {
        match self {
            Self::Cleanup { cleanup, .. } => Some(cleanup),
            _ => None,
        }
    }

    /// Return the original `anyhow` error chain for CLI compatibility without
    /// adding a formatting context layer.
    pub fn into_anyhow(self) -> anyhow::Error {
        match self {
            Self::Bind(error)
            | Self::Config(error)
            | Self::Recovery(error)
            | Self::Startup(error)
            | Self::Runtime(error)
            | Self::Task(error) => error,
            Self::Cleanup { error, .. } => error.into_anyhow(),
            other => anyhow::Error::new(other),
        }
    }
}

/// Entry point for configuring and starting one process-local server.
///
/// There may be only one live server per process; after its worker has fully
/// stopped, another start is supported. A returned handle or `Ok` means
/// cleanup for any prior failure finished, not that every retained handle was
/// joined; retained handles are recovered by the next start. Owner storage has a process-life
/// quarantine limit of 15 slots; repeated runs that use that
/// storage can exhaust those slots before process exit.
pub struct Server;

impl Server {
    /// Create a builder with the supplied SDK server configuration.
    pub fn builder(config: Config) -> ServerBuilder {
        let (status, status_rx) = watch::channel(ServerStatus::Starting);
        ServerBuilder {
            config,
            config_path: None,
            observation_sink: ObservationSink::new(),
            upstream_addr: None,
            upstream_user: None,
            upstream_pass: None,
            no_upstream: false,
            pt_binary: PtBinary::default(),
            dns_startup_policy: DnsStartupPolicy::default(),
            cancellation_token: CancellationToken::new(),
            test_hooks: None,
            status,
            status_rx,
        }
    }
}

/// Configures and starts an embedded server.
pub struct ServerBuilder {
    config: Config,
    config_path: Option<PathBuf>,
    observation_sink: ObservationSink,
    upstream_addr: Option<String>,
    upstream_user: Option<String>,
    upstream_pass: Option<String>,
    no_upstream: bool,
    pt_binary: PtBinary,
    dns_startup_policy: DnsStartupPolicy,
    cancellation_token: CancellationToken,
    /// Test-only seam (`ServerBuilder::test_hooks`); never set in production.
    test_hooks: Option<std::sync::Arc<crate::server::TestRunHooks>>,
    status: watch::Sender<ServerStatus>,
    status_rx: watch::Receiver<ServerStatus>,
}

impl ServerBuilder {
    /// Set the path of the configuration file the server runs from. Required:
    /// sibling files (users registry, bridge store, DNS cache, keystore) are
    /// resolved from it, and startup fails with [`ServerError::Config`] when
    /// it is missing — nothing is ever written to the current directory.
    ///
    /// The supplied [`Config`] is a startup snapshot: the server reads it once
    /// at startup and never re-reads the file live.
    pub fn config_path(mut self, path: PathBuf) -> Self {
        self.config_path = Some(path);
        self
    }

    /// Set the observation sink used by the server.
    pub fn observation_sink(mut self, sink: ObservationSink) -> Self {
        self.observation_sink = sink;
        self
    }

    /// Configure optional upstream SOCKS5 egress and its credentials.
    ///
    /// This does not connect to or validate the upstream proxy during startup;
    /// it must be available when client connections need egress.
    pub fn upstream(
        mut self,
        address: Option<String>,
        username: Option<String>,
        password: Option<String>,
    ) -> Self {
        self.upstream_addr = address;
        self.upstream_user = username;
        self.upstream_pass = password;
        self
    }

    /// Choose the pluggable-transport executable policy for every Tor client
    /// this server builds (main client settings init, the restricted owner
    /// settings template, and the bridge producer manager). The default
    /// [`PtBinary::Environment`] resolves the documented `TOR_PT_BINARY`
    /// override, else the current process executable, which must itself
    /// dispatch PT mode; embedding hosts without such a dispatch (e.g. a
    /// cdylib) must pass [`PtBinary::Explicit`] pointing at their own
    /// PT-capable binary. `fetch_bridges` is unaffected: it always uses the
    /// `Environment` policy.
    pub fn pt_binary(mut self, pt: PtBinary) -> Self {
        self.pt_binary = pt;
        self
    }

    /// Explicitly disable upstream SOCKS5 egress.
    pub fn no_upstream(mut self, no_upstream: bool) -> Self {
        self.no_upstream = no_upstream;
        self
    }

    /// Choose whether an enabled DNS listener is required for startup readiness.
    /// Defaults to [`DnsStartupPolicy::Required`].
    pub fn dns_startup_policy(mut self, policy: DnsStartupPolicy) -> Self {
        self.dns_startup_policy = policy;
        self
    }

    /// Use a caller-owned token to request graceful shutdown. The server uses a
    /// child token: external cancellation propagates to the server, but server
    /// shutdown and handle drop do not cancel this caller-owned token.
    pub fn cancellation_token(mut self, token: CancellationToken) -> Self {
        self.cancellation_token = token;
        self
    }

    /// Test-only: inject the run hooks (fake Tor settings, injected store
    /// writer, forced accept-loop exit). Invisible outside test builds.
    #[cfg(test)]
    pub(crate) fn test_hooks(mut self, hooks: std::sync::Arc<crate::server::TestRunHooks>) -> Self {
        self.test_hooks = Some(hooks);
        self
    }

    /// Subscribe to lifecycle snapshots. The receiver starts with `Starting`;
    /// updates are latest-value snapshots and intermediate transitions may be
    /// coalesced by Tokio's watch channel.
    pub fn subscribe(&self) -> watch::Receiver<ServerStatus> {
        self.status_rx.clone()
    }

    /// Drives startup and the running server until `shutdown` resolves or the
    /// server terminates naturally. The same startup future is polled through
    /// cancellation so its cleanup result is not lost.
    ///
    /// cancel-safe: NO — dropping this future requests worker cancellation, but
    /// does not await the worker's cleanup attempt. Use the returned result to
    /// observe startup, runtime, and cleanup failures.
    pub async fn run_until(self, shutdown: impl Future<Output = ()>) -> Result<(), ServerError> {
        let cancellation = self.cancellation_token.child_token();
        let start = self.start_inner(Some(cancellation.clone()));
        tokio::pin!(start);
        tokio::pin!(shutdown);

        let mut shutdown_requested = false;
        let started = tokio::select! {
            biased;
            () = &mut shutdown => {
                shutdown_requested = true;
                cancellation.cancel();
                None
            }
            result = &mut start => Some(result),
        };
        let started = match started {
            Some(result) => result,
            None => start.await,
        };

        let handle = match started {
            Ok(handle) => handle,
            // A `Cancelled` result here means the caller's own token (or the
            // shutdown future) requested the stop; `run_until` reports a
            // requested stop as success, preserving real startup failures.
            Err(ServerError::Cancelled) => return Ok(()),
            Err(error) => return Err(error),
        };

        if shutdown_requested {
            return match handle.shutdown().await {
                Err(ServerError::Cancelled) => Ok(()),
                result => result,
            };
        }

        let shutdown_requested = tokio::select! {
            biased;
            () = &mut shutdown => true,
            _ = wait_for_terminal(handle.status.clone()) => false,
        };
        if shutdown_requested {
            match handle.shutdown().await {
                Err(ServerError::Cancelled) => Ok(()),
                result => result,
            }
        } else {
            // Terminal state reached through the caller's cancellation token is
            // a requested stop, not a failure: map it like an awaited shutdown.
            match handle.wait().await {
                Err(ServerError::Cancelled) => Ok(()),
                result => result,
            }
        }
    }

    /// Start and wait until SOCKS listeners are bound. With the default
    /// [`DnsStartupPolicy::Required`], at least one configured DNS UDP/TCP pair
    /// must bind before readiness (unavailable pairs are skipped); [`DnsStartupPolicy::Background`] opts into
    /// non-fatal asynchronous DNS startup.
    ///
    /// cancel-safe: dropping this future requests worker cancellation; the
    /// supervised worker retains admission until its cleanup attempt
    /// completes. Settings/global-init/owner recovery uses explicit deadlines;
    /// producer and handler joins have their own budgets (normal producer grace
    /// is 120 seconds). The final blocking-worker join has a five-second timeout.
    /// Closing the bridge-store writer is awaited without a deadline.
    ///
    /// Dropping this future cancels the server-owned child token; the caller's
    /// token passed to `cancellation_token` remains unaffected. The worker remains
    /// supervised and holds process admission until cleanup finishes. A startup error is
    /// returned only after the worker has finished its cleanup attempt. A
    /// returned handle or `Ok` means cleanup for any prior failure finished,
    /// not that every retained handle was joined; retained handles are
    /// recovered by the next start. The returned handle represents one
    /// process-local server; owner storage can use one of its 15
    /// process-lifetime quarantine slots.
    ///
    /// Cancellation before readiness returns [`ServerError::Cancelled`],
    /// unless startup itself produced a more specific error.
    pub fn start(self) -> Pin<Box<dyn Future<Output = Result<ServerHandle, ServerError>> + Send>> {
        Box::pin(self.start_inner(None))
    }

    async fn start_inner(
        self,
        worker_token: Option<CancellationToken>,
    ) -> Result<ServerHandle, ServerError> {
        let reservation = match AdmissionReservation::acquire() {
            Ok(reservation) => reservation,
            Err(error) => {
                self.status.send_replace(ServerStatus::Stopped {
                    listen_addrs: Vec::new(),
                });
                return Err(error);
            }
        };
        // First thing after admission, before any file I/O: the config path
        // anchors every on-disk location the server uses.
        let Some(config_path) = self.config_path else {
            self.status.send_replace(ServerStatus::Stopped {
                listen_addrs: Vec::new(),
            });
            return Err(ServerError::Config(anyhow!(
                "config path is required: ServerBuilder::config_path must be called before start"
            )));
        };
        let token = worker_token.unwrap_or_else(|| self.cancellation_token.child_token());
        let mut cancel_on_drop = StartCancelGuard(Some(token.clone()));
        let result = Arc::new(StdMutex::new(None));
        let ready_once = Arc::new(AtomicBool::new(false));
        let listen_addrs: ListenAddrs = Arc::new(StdMutex::new(Vec::new()));
        let (ready_tx, ready_rx) = oneshot::channel();
        let tracker = TaskTracker::new();
        let args = ServerArgs {
            config: self.config,
            config_path,
            obs_sink: self.observation_sink,
            upstream_addr: self.upstream_addr,
            upstream_user: self.upstream_user,
            upstream_pass: self.upstream_pass,
            no_upstream: self.no_upstream,
            pt_binary: self.pt_binary,
            dns_startup_policy: self.dns_startup_policy,
            test_hooks: self.test_hooks.clone(),
        };

        let worker_status = self.status.clone();
        let status_rx = self.status_rx;
        let panic_test_hooks = self.test_hooks.clone();
        let worker_result = result.clone();
        let worker_ready = ready_once.clone();
        let worker_addrs = listen_addrs.clone();
        let worker_token = token.clone();
        let writer_started = Arc::new(AtomicBool::new(false));
        let worker_writer_started = writer_started.clone();
        let (stage_tx, stage_rx) = watch::channel(ServerStage::Recovery);
        let worker = async move {
            let mut completion = WorkerCompletion::new(
                reservation,
                worker_status.clone(),
                worker_result,
                worker_addrs.clone(),
            );
            let stage_for_error = stage_rx;
            let stage_tx = stage_tx.clone();
            let stage_callback = move |stage| {
                stage_tx.send_replace(stage);
            };
            let ready_status = worker_status.clone();
            let mut ready_tx = Some(ready_tx);
            let ready_addrs = worker_addrs.clone();
            let ready_callback = move |addresses: Vec<SocketAddr>| {
                *ready_addrs
                    .lock()
                    .unwrap_or_else(|error| error.into_inner()) = addresses.clone();
                worker_ready.store(true, Ordering::Release);
                ready_status.send_replace(ServerStatus::Running {
                    listen_addrs: addresses,
                });
                // A start future that was cancelled no longer needs readiness;
                // the worker still owns the rest of startup and cleanup.
                if let Some(ready_tx) = ready_tx.take() {
                    let _ = ready_tx.send(());
                }
            };
            let stopping_status = worker_status.clone();
            let stopping_addrs = worker_addrs.clone();
            let shutdown_token = worker_token;
            let shutdown_status = stopping_status.clone();
            let shutdown_addrs = stopping_addrs.clone();
            let server = crate::server::run_server_with_callbacks(
                args,
                async move {
                    shutdown_token.cancelled().await;
                    publish_stopping(&shutdown_status, &shutdown_addrs);
                },
                stage_callback,
                ready_callback,
                worker_writer_started.clone(),
            );
            let run = match std::panic::AssertUnwindSafe(server).catch_unwind().await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(failure)) => {
                    let primary = map_stage(*stage_for_error.borrow(), failure.primary);
                    match failure.cleanup {
                        None => Err(primary),
                        Some(cleanup) => Err(ServerError::Cleanup {
                            error: Box::new(primary),
                            cleanup,
                        }),
                    }
                }
                Err(_) => {
                    let primary = ServerError::Task(anyhow!("server worker panicked"));
                    match crate::server::cleanup_failed_run(
                        writer_started.load(Ordering::Acquire),
                        panic_test_hooks.as_deref(),
                    )
                    .await
                    {
                        Ok(()) => Err(primary),
                        Err(cleanup) => Err(ServerError::Cleanup {
                            error: Box::new(primary),
                            cleanup,
                        }),
                    }
                }
            };
            completion.finish(run.err());
        };

        // Keep the handler's deeply nested future layout out of the public API's host crate.
        let worker: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(worker);

        // The returned JoinHandle is intentionally discarded: TaskTracker owns
        // worker lifetime, while catch_unwind + WorkerCompletion store its
        // result and tracker.wait() observes full completion before join returns.
        drop(tracker.spawn(worker));

        enum StartOutcome {
            Ready(bool),
            Cancelled,
            Terminal,
        }
        // Dropping the selected readiness future is safe: its sender is owned
        // by the supervised worker, which continues startup/cleanup.
        let outcome = tokio::select! {
            biased;
            ready = ready_rx => StartOutcome::Ready(ready.is_ok()),
            () = token.cancelled() => StartOutcome::Cancelled,
            _ = wait_for_terminal(status_rx.clone()) => StartOutcome::Terminal,
        };

        let ready_state = matches!(outcome, StartOutcome::Ready(true))
            && ready_once.load(Ordering::Acquire)
            && !token.is_cancelled()
            && matches!(status_rx.borrow().clone(), ServerStatus::Running { .. });
        if ready_state {
            cancel_on_drop.disarm();
            return Ok(ServerHandle {
                cancellation_token: token,
                status: status_rx,
                result,
                tasks: tracker,
                cancel_on_drop: true,
            });
        }

        // Every readiness failure, including a closed ready channel or a
        // cancellation race, joins the worker before returning. This keeps the
        // process admission reservation held through cleanup and preserves the
        // actual Config/Bind/Startup error rather than reporting channel closure.
        tracker.close();
        tracker.wait().await;
        cancel_on_drop.disarm();
        Err(take_result(&result).unwrap_or(ServerError::Cancelled))
    }
}

/// Handle to a running server. Dropping it requests cancellation only; it
/// never blocks, spawns cleanup, or aborts the supervised worker.
#[must_use = "call shutdown().await (or wait().await) to join the server worker"]
pub struct ServerHandle {
    cancellation_token: CancellationToken,
    status: watch::Receiver<ServerStatus>,
    result: Arc<StdMutex<Option<ServerError>>>,
    tasks: TaskTracker,
    cancel_on_drop: bool,
}

impl ServerHandle {
    /// Return a clone of the server-owned shutdown token. Cancelling it stops
    /// this server; cancelling it does not cancel the builder's parent token.
    pub fn token(&self) -> CancellationToken {
        self.cancellation_token.clone()
    }

    /// Return the latest lifecycle snapshot.
    pub fn status(&self) -> ServerStatus {
        self.status.borrow().clone()
    }

    /// Subscribe to lifecycle snapshots. Updates may be coalesced; this is not
    /// an event stream.
    pub fn subscribe(&self) -> watch::Receiver<ServerStatus> {
        self.status.clone()
    }

    /// Observe natural server termination and join the worker without
    /// requesting cancellation.
    ///
    /// cancel-safe: NO — dropping this future drops the handle and requests
    /// server cancellation but does not await cleanup. Settings/global-init/owner
    /// recovery uses explicit deadlines; producer and handler joins have their
    /// own budgets (normal producer grace is 120 seconds). The final blocking-worker
    /// join has a five-second timeout. Closing the bridge-store writer is awaited
    /// without a deadline. `Stopped`
    /// means that attempt completed (successfully or with an error;
    /// `ServerError::Cleanup` preserves a secondary cleanup failure), not that
    /// every task was provably joined.
    /// `Stopped` is returned for both normal and unexpected worker termination;
    /// an unexpected accept-loop exit is reported as `ServerError::Runtime`.
    pub async fn wait(self) -> Result<(), ServerError> {
        self.join(false).await
    }

    /// Request graceful cancellation and join the worker after cleanup.
    ///
    /// cancel-safe: no; dropping this future drops the handle, which keeps the
    /// cancellation request active while the supervised worker finishes.
    /// `Stopped` means the cleanup attempt completed (successfully or with an
    /// error; `ServerError::Cleanup` preserves a secondary cleanup failure),
    /// not that every task was provably joined.
    /// The terminal wait is a watch change loop, so cancellation does not
    /// consume an event or lose the terminal snapshot.
    ///
    /// The worker publishes `Stopping` when it observes cancellation, including
    /// cancellation through an external token or handle drop.
    pub async fn shutdown(self) -> Result<(), ServerError> {
        self.join(true).await
    }

    async fn join(mut self, cancel: bool) -> Result<(), ServerError> {
        if cancel {
            self.cancellation_token.cancel();
        }
        wait_for_terminal(self.status.clone()).await;
        self.tasks.close();
        self.tasks.wait().await;
        self.cancel_on_drop = false;
        take_result(&self.result).map_or(Ok(()), Err)
    }
}

impl Drop for ServerHandle {
    /// Request cancellation without blocking; the worker remains supervised
    /// and performs cleanup asynchronously.
    fn drop(&mut self) {
        if self.cancel_on_drop {
            self.cancellation_token.cancel();
        }
    }
}

struct AdmissionReservation;

impl AdmissionReservation {
    fn acquire() -> Result<Self, ServerError> {
        SERVER_RUNNING
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| Self)
            .map_err(|_| ServerError::AlreadyRunning)
    }
}

impl Drop for AdmissionReservation {
    fn drop(&mut self) {
        SERVER_RUNNING.store(false, Ordering::Release);
    }
}

struct StartCancelGuard(Option<CancellationToken>);

impl StartCancelGuard {
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for StartCancelGuard {
    fn drop(&mut self) {
        if let Some(token) = self.0.take() {
            token.cancel();
        }
    }
}

struct WorkerCompletion {
    reservation: Option<AdmissionReservation>,
    status: watch::Sender<ServerStatus>,
    result: Arc<StdMutex<Option<ServerError>>>,
    listen_addrs: ListenAddrs,
    completed: bool,
}

impl WorkerCompletion {
    fn new(
        reservation: AdmissionReservation,
        status: watch::Sender<ServerStatus>,
        result: Arc<StdMutex<Option<ServerError>>>,
        listen_addrs: ListenAddrs,
    ) -> Self {
        Self {
            reservation: Some(reservation),
            status,
            result,
            listen_addrs,
            completed: false,
        }
    }

    fn finish(&mut self, result: Option<ServerError>) {
        *self
            .result
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = result;
        drop(self.reservation.take());
        self.status.send_replace(ServerStatus::Stopped {
            listen_addrs: listen_addrs_snapshot(&self.listen_addrs),
        });
        self.completed = true;
    }
}

impl Drop for WorkerCompletion {
    fn drop(&mut self) {
        if !self.completed {
            let message = if std::thread::panicking() {
                "server worker task panicked"
            } else {
                "server worker task was dropped before completion"
            };
            *self
                .result
                .lock()
                .unwrap_or_else(|error| error.into_inner()) =
                Some(ServerError::Task(anyhow!(message)));
            drop(self.reservation.take());
            self.status.send_replace(ServerStatus::Stopped {
                listen_addrs: listen_addrs_snapshot(&self.listen_addrs),
            });
        }
    }
}

fn listen_addrs_snapshot(listen_addrs: &ListenAddrs) -> Vec<SocketAddr> {
    listen_addrs
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone()
}

fn publish_stopping(status: &watch::Sender<ServerStatus>, listen_addrs: &ListenAddrs) {
    if !matches!(status.borrow().clone(), ServerStatus::Stopped { .. }) {
        status.send_replace(ServerStatus::Stopping {
            listen_addrs: listen_addrs_snapshot(listen_addrs),
        });
    }
}

fn map_stage(stage: ServerStage, error: anyhow::Error) -> ServerError {
    match stage {
        ServerStage::Recovery => ServerError::Recovery(error),
        ServerStage::Config => ServerError::Config(error),
        ServerStage::Bind => ServerError::Bind(error),
        ServerStage::Startup => ServerError::Startup(error),
        ServerStage::Runtime => ServerError::Runtime(error),
        ServerStage::Cancelled => ServerError::Cancelled,
        ServerStage::Task => ServerError::Task(error),
    }
}

async fn wait_for_terminal(mut status: watch::Receiver<ServerStatus>) {
    loop {
        let current = status.borrow_and_update().clone();
        if matches!(current, ServerStatus::Stopped { .. }) {
            return;
        }
        if status.changed().await.is_err() {
            return;
        }
    }
}

fn take_result(result: &Arc<StdMutex<Option<ServerError>>>) -> Option<ServerError> {
    result
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .take()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;

    /// H11: the builder records the PT policy (default `Environment`) and
    /// threads it into the startup arguments the worker consumes.
    #[test]
    fn pt_binary_builder_defaults_to_environment_and_is_settable() {
        let build = |pt| Server::builder(Config::default()).pt_binary(pt);
        let default = build(PtBinary::Environment);
        assert_eq!(default.pt_binary, PtBinary::Environment);
        let helper = std::path::PathBuf::from("host-pt-helper");
        let explicit = build(PtBinary::Explicit(helper.clone()));
        assert_eq!(explicit.pt_binary, PtBinary::Explicit(helper));
    }

    #[tokio::test]
    async fn start_without_config_path_fails_before_file_io() {
        // H13/D-H1: the check is the first thing after admission, before any
        // file I/O — nothing is written to the current directory (the check
        // runs before the worker, so no file access can precede it).
        let error = match Server::builder(Config::default()).start().await {
            Ok(_) => panic!("start without a config path must fail"),
            Err(error) => error,
        };
        assert!(matches!(error, ServerError::Config(_)), "{error:?}");
        assert_eq!(error.stage(), Some(ServerStage::Config));
        assert!(
            error.to_string().contains("config path is required"),
            "unexpected message: {error}"
        );
    }

    #[test]
    fn server_error_formatting_does_not_duplicate_primary_chain() {
        let error = ServerError::Startup(anyhow!("primary failure").context("startup context"));
        let formatted = format!("{error:#}");
        let cli_error = ServerError::Startup(anyhow!("primary failure").context("startup context"))
            .into_anyhow();
        let formatted_anyhow = format!("{cli_error:#}");
        assert_eq!(formatted.matches("primary failure").count(), 1);
        assert_eq!(formatted_anyhow.matches("primary failure").count(), 1);
        assert_eq!(formatted.matches("startup context").count(), 1);
    }

    #[test]
    fn completion_drop_during_unwind_retains_panic_message() {
        let (status, _receiver) = watch::channel(ServerStatus::Starting);
        let result = Arc::new(StdMutex::new(None));
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe({
            let result = result.clone();
            move || {
                let _completion = WorkerCompletion {
                    reservation: None,
                    status,
                    result,
                    listen_addrs: Arc::new(StdMutex::new(Vec::new())),
                    completed: false,
                };
                panic!("test panic while completion guard is live");
            }
        }));
        assert!(outcome.is_err());
        let error = take_result(&result).unwrap();
        assert!(
            matches!(error, ServerError::Task(ref error) if error.to_string() == "server worker task panicked")
        );
    }

    #[test]
    fn cleanup_error_keeps_primary_as_source_and_exposes_cleanup_separately() {
        let error = ServerError::Cleanup {
            error: Box::new(ServerError::Startup(anyhow!("primary failure"))),
            cleanup: anyhow!("cleanup failure"),
        };

        assert_eq!(error.to_string(), "server cleanup also failed");
        assert_eq!(
            error.cleanup_error().unwrap().to_string(),
            "cleanup failure"
        );
        assert_eq!(error.source().unwrap().to_string(), "primary failure");
        assert_eq!(error.stage(), Some(ServerStage::Startup));
    }

    #[test]
    fn cleanup_error_formatting_keeps_cleanup_out_of_primary_display() {
        let primary = ServerError::Cleanup {
            error: Box::new(ServerError::Startup(anyhow!("primary failure"))),
            cleanup: anyhow!("cleanup failure"),
        };
        let formatted = format!("{primary:#}");
        assert!(!formatted.contains("primary failure"));
        assert!(primary.cleanup_error().is_some());
    }

    #[test]
    fn completion_drop_reports_runtime_shutdown_as_dropped_not_panicked() {
        let (status, mut receiver) = watch::channel(ServerStatus::Starting);
        let result = Arc::new(StdMutex::new(None));
        let completion = WorkerCompletion {
            reservation: None,
            status,
            result: result.clone(),
            listen_addrs: Arc::new(StdMutex::new(Vec::new())),
            completed: false,
        };
        drop(completion);

        assert!(matches!(
            receiver.borrow_and_update().clone(),
            ServerStatus::Stopped { .. }
        ));
        let error = take_result(&result).unwrap();
        assert!(
            matches!(error, ServerError::Task(ref error) if error.to_string() == "server worker task was dropped before completion")
        );
    }
}
