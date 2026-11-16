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
/// `Cleanup` retains teardown failures without replacing the primary error's
/// display text or the original error chain returned to CLI callers.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// Another server already owns process-local admission.
    #[error("server is already running in this process")]
    AlreadyRunning,
    /// Listener binding failed.
    #[error("{0}")]
    Bind(#[source] anyhow::Error),
    /// Configuration loading or validation failed.
    #[error("{0}")]
    Config(#[source] anyhow::Error),
    /// Process-wide startup recovery failed.
    #[error("{0}")]
    Recovery(#[source] anyhow::Error),
    /// Remaining startup, including Tor or egress initialization, failed.
    #[error("{0}")]
    Startup(#[source] anyhow::Error),
    /// Serving requests failed.
    #[error("{0}")]
    Runtime(#[source] anyhow::Error),
    /// Startup was cancelled before readiness.
    #[error("server startup cancelled")]
    Cancelled,
    /// A supervised server task failed or panicked.
    #[error("{0}")]
    Task(#[source] anyhow::Error),
    /// Cleanup failed after `error`; formatting and CLI conversion retain the
    /// primary error while this field exposes the teardown failure. Cleanup
    /// budgets are stage-specific: Settings/global-init/owner recovery uses
    /// explicit deadlines; producer and handler joins have their own budgets
    /// (normal producer grace is 120 seconds). The final blocking-worker join
    /// has a five-second timeout. Closing the bridge-store writer is awaited
    /// without a deadline. Where a bounded stage times out, task handles remain
    /// retained in process slots for recovery by the next start's startup
    /// recovery. `Cleanup` is a secondary-failure wrapper; if secondary cleanup
    /// succeeds, an ordinary shutdown failure may be returned as
    /// `ServerError::Runtime`.
    #[error("{error}")]
    Cleanup {
        /// The error that caused the run to fail.
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
/// stopped, another start is supported (D5). A returned handle or `Ok` means
/// cleanup for any prior failure finished, not that every retained handle was
/// joined; retained handles are recovered by the next start. Owner storage has a process-life
/// quarantine limit of 15 slots (QUARANTINE15); repeated runs that use that
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
            dns_startup_policy: DnsStartupPolicy::default(),
            cancellation_token: CancellationToken::new(),
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
    dns_startup_policy: DnsStartupPolicy,
    cancellation_token: CancellationToken,
    status: watch::Sender<ServerStatus>,
    status_rx: watch::Receiver<ServerStatus>,
}

impl ServerBuilder {
    /// Set the optional path associated with the supplied configuration.
    pub fn config_path(mut self, path: Option<PathBuf>) -> Self {
        self.config_path = path;
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

    /// Use a caller-owned token to request graceful shutdown.
    pub fn cancellation_token(mut self, token: CancellationToken) -> Self {
        self.cancellation_token = token;
        self
    }

    /// Subscribe to lifecycle snapshots. The receiver starts with `Starting`;
    /// updates are latest-value snapshots and intermediate transitions may be
    /// coalesced by Tokio's watch channel.
    pub fn subscribe(&self) -> watch::Receiver<ServerStatus> {
        self.status_rx.clone()
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
    /// Dropping this future cancels the worker; the worker remains supervised
    /// and holds process admission until cleanup finishes. A startup error is
    /// returned only after the worker has finished its cleanup attempt. A
    /// returned handle or `Ok` means cleanup for any prior failure finished,
    /// not that every retained handle was joined; retained handles are
    /// recovered by the next start. The returned handle represents one
    /// process-local server (D5); owner storage can use one of its 15
    /// process-lifetime quarantine slots (QUARANTINE15).
    ///
    /// Cancellation before readiness returns [`ServerError::Cancelled`],
    /// unless startup itself produced a more specific error.
    pub fn start(self) -> Pin<Box<dyn Future<Output = Result<ServerHandle, ServerError>> + Send>> {
        Box::pin(self.start_inner())
    }

    async fn start_inner(self) -> Result<ServerHandle, ServerError> {
        let reservation = AdmissionReservation::acquire()?;
        let token = self.cancellation_token;
        let mut cancel_on_drop = StartCancelGuard(Some(token.clone()));
        let result = Arc::new(StdMutex::new(None));
        let ready_once = Arc::new(AtomicBool::new(false));
        let listen_addrs: ListenAddrs = Arc::new(StdMutex::new(Vec::new()));
        let (ready_tx, ready_rx) = oneshot::channel();
        let tracker = TaskTracker::new();
        let args = ServerArgs {
            config: self.config,
            config_path: self.config_path,
            obs_sink: self.observation_sink,
            upstream_addr: self.upstream_addr,
            upstream_user: self.upstream_user,
            upstream_pass: self.upstream_pass,
            no_upstream: self.no_upstream,
            dns_startup_policy: self.dns_startup_policy,
        };

        let worker_status = self.status.clone();
        let status_rx = self.status_rx;
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
                    match crate::server::cleanup_failed_run(writer_started.load(Ordering::Acquire))
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

        #[cfg(test)]
        let worker = crate::server::scope_run_server_task_locals(worker);

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
    /// Return a clone of the shutdown token.
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
    /// cancel-safe: no; dropping this future drops the handle and requests
    /// cancellation. The worker's cleanup attempt is completed before this
    /// returns; Settings/global-init/owner recovery uses explicit deadlines;
    /// producer and handler joins have their own budgets (normal producer grace
    /// is 120 seconds). The final blocking-worker join has a five-second timeout.
    /// Closing the bridge-store writer is awaited without a deadline. `Stopped`
    /// means that attempt completed (successfully or with an error;
    /// `ServerError::Cleanup` preserves a secondary cleanup failure), not that
    /// every task was provably joined.
    /// The terminal wait is a watch change loop, so cancellation does not
    /// consume an event or lose the terminal snapshot.
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
    _reservation: AdmissionReservation,
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
            _reservation: reservation,
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
        self.status.send_replace(ServerStatus::Stopped {
            listen_addrs: listen_addrs_snapshot(&self.listen_addrs),
        });
        self.completed = true;
    }
}

impl Drop for WorkerCompletion {
    fn drop(&mut self) {
        if !self.completed {
            *self
                .result
                .lock()
                .unwrap_or_else(|error| error.into_inner()) =
                Some(ServerError::Task(anyhow!("server worker task panicked")));
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
