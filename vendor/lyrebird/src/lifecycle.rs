use std::{
    collections::HashMap,
    future::Future,
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};

use anyhow::Result;
use tokio::{
    sync::{Mutex, Semaphore},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

use ptrs::{error, info, warn};

const DRAIN_GRACE: Duration = Duration::from_secs(15);
const FORCE_GRACE: Duration = Duration::from_secs(5);
/// Maximum concurrent connection tasks admitted by the client accept loops.
pub(super) const MAX_CONCURRENT_CONNS: usize = 1024;

/// Signal returned by the platform-specific shutdown watcher.
#[derive(Clone, Copy)]
pub(super) enum Shutdown {
    /// Graceful drain, with a second signal escalating.
    Interrupt,
    /// Immediate connection cancellation.
    Terminate,
}

impl Shutdown {
    fn is_terminate(self) -> bool {
        matches!(self, Self::Terminate)
    }
}

/// Own setup, stdin, listeners, and shutdown signals for one service run.
/// Keeping setup inside this future ensures an early error drops the pending
/// stdin future before returning to the caller.
///
/// Listener-loss policy: fail fast. See [`drive`].
/// cancel-safe: NO — drive to completion to join owned tasks.
pub(super) async fn run_with_setup<I, Setup, S, SF>(
    ctx: RunTasks,
    stdin_wait: I,
    setup: Setup,
    signal: S,
) -> Result<()>
where
    I: Future<Output = std::io::Result<()>>,
    Setup: Future<Output = Result<JoinSet<Result<()>>>>,
    S: FnMut() -> SF,
    SF: Future<Output = Shutdown>,
{
    let listeners = setup.await?;
    drive(ctx, listeners, stdin_wait, signal).await
}

/// Drive the shared service lifecycle with injected stdin and signal futures.
/// Production calls this through [`run_with_setup`]; tests can use deterministic
/// events to exercise the same graceful-drain orchestration.
///
/// Listener-loss policy: fail fast. The first listener task that ends
/// with a fatal accept error or panics ends the whole run — `drive`
/// stops the remaining accept loops, completes the mandatory
/// connection teardown, and then returns the original cause. Declared
/// transports are never restored in-process: client listeners bind
/// ephemeral ports already announced to the parent via `CMETHOD`, and
/// the PT spec provides no re-announcement, so a restarted process
/// re-runs the full PT setup instead.
/// cancel-safe: NO — dropping this future skips orderly task shutdown.
pub(super) async fn drive<I, S, SF>(
    ctx: RunTasks,
    mut listeners: JoinSet<Result<()>>,
    stdin_wait: I,
    mut signal: S,
) -> Result<()>
where
    I: Future<Output = std::io::Result<()>>,
    S: FnMut() -> SF,
    SF: Future<Output = Shutdown>,
{
    tokio::pin!(stdin_wait);
    let exit = loop {
        tokio::select! {
            maybe = listeners.join_next() => match maybe {
                None => break ExitKind::ProxyClosed,
                Some(Ok(Ok(()))) => info!("listener stopped"),
                // Fail fast: keep the original cause for the caller; it
                // must survive the mandatory cleanup below and reach main.
                Some(Ok(Err(e))) => {
                    error!("listener failed fatally: {e:#}");
                    break ExitKind::ListenerFailed(e);
                }
                // Listener tasks are never aborted by this code, so a
                // JoinError here is a task panic (or an unexpected external
                // abort); either way the transport is lost.
                Some(Err(join)) => {
                    error!("listener task aborted: {join}");
                    break ExitKind::ListenerFailed(
                        anyhow::Error::from(join).context("listener task failed"),
                    );
                }
            },
            sig = signal() => {
                if sig.is_terminate() {
                    info!("proxy terminated");
                    break ExitKind::Terminate;
                }
                break ExitKind::Interrupt;
            }
            stdin = &mut stdin_wait => {
                if let Err(e) = stdin {
                    warn!("stdin watcher failed: {e}; treating it as parent shutdown");
                }
                break ExitKind::ParentClosedStdin;
            }
        }
    };

    ctx.stop_accepting();
    let outcome = match exit {
        ExitKind::Interrupt => {
            info!("received interrupt, shutting down");
            join_accept_loops(&mut listeners).await;
            let drained = tokio::select! {
                drained = drain_connections(&ctx, DRAIN_GRACE) => drained,
                _ = signal() => {
                    info!("second interrupt; cancelling remaining connections");
                    false
                }
                stdin = &mut stdin_wait => {
                    if let Err(e) = stdin {
                        warn!("stdin watcher failed during shutdown: {e}");
                    }
                    info!("parent process closed stdin during shutdown; cancelling remaining connections");
                    false
                }
            };
            if !drained {
                cancel_connections(&ctx).await;
            }
            Ok(())
        }
        ExitKind::ProxyClosed => {
            info!("proxy closed");
            join_accept_loops(&mut listeners).await;
            let drained = tokio::select! {
                drained = drain_connections(&ctx, DRAIN_GRACE) => drained,
                _ = signal() => false,
                stdin = &mut stdin_wait => {
                    if let Err(e) = stdin {
                        warn!("stdin watcher failed during shutdown: {e}");
                    }
                    false
                }
            };
            if !drained {
                info!("drain budget elapsed; cancelling remaining connections");
                cancel_connections(&ctx).await;
            }
            Ok(())
        }
        ExitKind::ListenerFailed(cause) => {
            // A declared transport was lost. The teardown is mandatory and
            // identical to the "proxy closed" case — surviving accept loops
            // and every in-flight connection must be stopped and joined
            // before the failure is reported — but the run ends in `Err`
            // carrying the original cause.
            info!("shutting down after listener loss");
            join_accept_loops(&mut listeners).await;
            let drained = tokio::select! {
                drained = drain_connections(&ctx, DRAIN_GRACE) => drained,
                _ = signal() => false,
                stdin = &mut stdin_wait => {
                    if let Err(e) = stdin {
                        warn!("stdin watcher failed during shutdown: {e}");
                    }
                    false
                }
            };
            if !drained {
                info!("drain budget elapsed; cancelling remaining connections");
                cancel_connections(&ctx).await;
            }
            Err(cause)
        }
        ExitKind::Terminate | ExitKind::ParentClosedStdin => {
            join_accept_loops(&mut listeners).await;
            cancel_connections(&ctx).await;
            Ok(())
        }
    };
    join_connection_tasks(&ctx).await;
    debug_assert_eq!(
        ctx.lifecycle.available_permits(),
        MAX_CONCURRENT_CONNS,
        "connection tasks still in flight after shutdown"
    );
    outcome
}

enum ExitKind {
    ProxyClosed,
    Interrupt,
    Terminate,
    ParentClosedStdin,
    /// A declared transport was lost — a fatal accept error or a listener
    /// task panic. The payload is the original cause, returned to the
    /// caller after cleanup.
    ListenerFailed(anyhow::Error),
}

/// Shared ownership and cancellation state for one service run.
#[derive(Clone)]
pub(super) struct RunTasks {
    /// Stops accept loops from admitting more connections.
    pub(super) accept: CancellationToken,
    /// Cancels active connection bodies during forced teardown.
    pub(super) conns: CancellationToken,
    /// Counts active connection tasks through owned permits.
    pub(super) lifecycle: Arc<Semaphore>,
    /// Owns every spawned connection task until it is joined.
    pub(super) connections: Arc<Mutex<JoinSet<()>>>,
    /// Abort handles remain available while the scheduler lock is busy.
    pub(super) aborts: Arc<StdMutex<HashMap<tokio::task::Id, tokio::task::AbortHandle>>>,
}

/// Owns the cancellation state for one run.
///
/// `RunTasks` is deliberately clonable because accept loops and connection
/// bodies need handles, but ownership of their cleanup stays in this guard.
/// This is also the synchronous fallback for a caller that drops `run()`.
pub(super) struct RunOwner {
    tasks: RunTasks,
}

impl RunOwner {
    pub(super) fn new() -> Self {
        Self {
            tasks: RunTasks::new(),
        }
    }

    pub(super) fn tasks(&self) -> RunTasks {
        self.tasks.clone()
    }
}

impl Drop for RunOwner {
    fn drop(&mut self) {
        self.tasks.stop_accepting();
        self.tasks.conns.cancel();
        if let Ok(handles) = self.tasks.aborts.lock() {
            for handle in handles.values() {
                handle.abort();
            }
        }
        // A dropped run cannot await the scheduler. Request immediate abort
        // when the scheduler lock is available; the token remains the
        // fallback if registration is briefly holding the lock.
        if let Ok(mut connections) = self.tasks.connections.try_lock() {
            connections.abort_all();
        }
    }
}

impl RunTasks {
    pub(super) fn new() -> Self {
        Self {
            accept: CancellationToken::new(),
            conns: CancellationToken::new(),
            lifecycle: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNS)),
            connections: Arc::new(Mutex::new(JoinSet::new())),
            aborts: Arc::new(StdMutex::new(HashMap::new())),
        }
    }

    /// Cancel acceptance. An accept already past this check may still finish
    /// its permit path; the listener join is the synchronization point.
    pub(super) fn stop_accepting(&self) {
        self.accept.cancel();
    }

    async fn wait_idle(&self) {
        let _ = self
            .lifecycle
            .acquire_many(u32::try_from(MAX_CONCURRENT_CONNS).expect("permit count fits u32"))
            .await;
    }

    pub(super) async fn spawn_connection<F>(&self, task: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let mut connections = self.connections.lock().await;
        let abort = connections.spawn(task);
        let task_id = abort.id();
        if let Ok(mut handles) = self.aborts.lock() {
            handles.insert(task_id, abort.clone());
            if self.accept.is_cancelled() || self.conns.is_cancelled() {
                abort.abort();
            }
        } else if self.accept.is_cancelled() || self.conns.is_cancelled() {
            abort.abort();
        }
        while let Some(result) = connections.try_join_next_with_id() {
            let task_id = match &result {
                Ok((task_id, _)) => Some(*task_id),
                Err(error) => Some(error.id()),
            };
            if let Some(task_id) = task_id {
                if let Ok(mut handles) = self.aborts.lock() {
                    handles.remove(&task_id);
                }
            }
            if let Err(error) = result {
                warn!("connection task aborted: {error}");
            }
        }
    }
}

/// cancel-safe: yes — dropping the wait leaves active connections running.
pub(super) async fn drain_connections(ctx: &RunTasks, budget: Duration) -> bool {
    tokio::time::timeout(budget, ctx.wait_idle()).await.is_ok()
}

pub(super) async fn cancel_connections(ctx: &RunTasks) {
    ctx.conns.cancel();
    if tokio::time::timeout(FORCE_GRACE, ctx.wait_idle())
        .await
        .is_err()
    {
        ctx.connections.lock().await.abort_all();
    }
    join_connection_tasks(ctx).await;
}

pub(super) async fn join_connection_tasks(ctx: &RunTasks) {
    let mut connections = ctx.connections.lock().await;
    while let Some(result) = connections.join_next_with_id().await {
        let task_id = match &result {
            Ok((task_id, _)) => Some(*task_id),
            Err(error) => Some(error.id()),
        };
        if let Some(task_id) = task_id {
            if let Ok(mut handles) = ctx.aborts.lock() {
                handles.remove(&task_id);
            }
        }
        if let Err(error) = result {
            warn!("connection task aborted: {error}");
        }
    }
}

/// Log a listener result joined during teardown. The primary failure is
/// captured in `drive` before cleanup starts; a result surfacing here can
/// only be a clean stop or a secondary error racing the shutdown, so it
/// is logged, not propagated.
fn log_listener_result(res: std::result::Result<Result<()>, tokio::task::JoinError>) {
    match res {
        Ok(Ok(())) => info!("listener stopped"),
        Ok(Err(e)) => warn!("listener failed: {e:#}"),
        Err(join) => warn!("listener task aborted: {join}"),
    }
}

pub(super) async fn join_accept_loops(listeners: &mut JoinSet<Result<()>>) {
    while let Some(res) = listeners.join_next().await {
        log_listener_result(res);
    }
}

pub(super) async fn shutdown_signal() -> Shutdown {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigint = signal(SignalKind::interrupt()).expect("install SIGINT handler");
        let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            _ = sigterm.recv() => Shutdown::Terminate,
            _ = sigint.recv() => Shutdown::Interrupt,
        }
    }
    #[cfg(not(unix))]
    {
        use tokio::signal::windows::{ctrl_break, ctrl_c};
        let mut c_c = ctrl_c().expect("install Ctrl+C handler");
        let mut c_break = ctrl_break().expect("install Ctrl+Break handler");
        tokio::select! {
            _ = c_break.recv() => Shutdown::Terminate,
            _ = c_c.recv() => Shutdown::Interrupt,
        }
    }
}
