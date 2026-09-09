//! Single writer for the bridge health store (`<config>.alive-bridges.log`).
//!
//! Concurrency contract (fixes the P1 racing-writes finding in
//! docs/stability-review-2026-09-08.md, plus TS2-02/TS2-03 in
//! docs/review-round-2-2026-09-08.md):
//!
//! * Daemon: exactly one actor task owns every publish. Writers send a
//!   mutation through an mpsc channel; the actor applies mutations one at a
//!   time to its authoritative in-memory snapshot, so two background tasks
//!   (maintenance observation drain, channel warmer, circuit verifier,
//!   startup probe rounds, channel fallback) can no longer overwrite each
//!   other's read-modify-write updates. An update is acknowledged as soon as
//!   the owner has applied it to memory — a slow or failing disk publish is
//!   the writer's retry problem, not the caller's.
//! * Disk I/O never runs on the async runtime: both the store load and every
//!   publish (serialize + fsync + rename) run inside
//!   `tokio::task::spawn_blocking`, so a slow disk cannot stall a Tokio
//!   worker or the tasks queued behind it.
//! * The mutate step runs on the blocking pool too. Publish snapshots are
//!   `Arc` clones taken in O(1) on the actor, but when a mutation lands
//!   while a publish is in flight the shared snapshot forces `Arc::make_mut`
//!   into a deep O(S) copy — that copy (and the mutation closure itself)
//!   executes inside `spawn_blocking`, never on an async worker. The actor
//!   waits for the mutation job before its next `select!` iteration, so
//!   mutation order, acks and retry bookkeeping are unchanged. If the
//!   mutation closure panics, the possibly half-mutated snapshot is dropped
//!   (the next op reloads from disk) and the op's ack resolves `Err`.
//! * Publishes are coalesced: at most one publish is in flight at a time,
//!   and mutations that arrive while it runs are absorbed into the same
//!   in-memory snapshot and covered by one follow-up publish. K mutations
//!   therefore cost O(1) full-file writes under load, not K.
//! * When a publish fails, the mutated snapshot is retained in memory and
//!   retried with exponential backoff (1s doubling, 30s cap); each failure
//!   is logged at warn with the attempt number, recovery at info. While a
//!   retry is pending, incoming mutations do NOT trigger an immediate
//!   publish — the backoff timer governs all retry attempts — and absorbed
//!   updates are never dropped because the disk write failed.
//! * When the in-memory snapshot is clean, the actor re-reads the file
//!   before applying the next mutation, so whole-file writes made by other
//!   processes in the meantime (e.g. `tor-socks5 bridges fetch` running as a
//!   separate CLI process) are seen and preserved. This is enforced by
//!   dropping the snapshot as soon as a publish succeeds with no tail
//!   mutations, so a clean state is `store = None` and every op after a
//!   successful publish reloads the file.
//! * Shutdown is explicit: [`StoreWriter::close`] sends a close op, waits
//!   for any in-flight publish (and one coalesced follow-up), performs a
//!   final flush if the snapshot is still dirty — regardless of the backoff
//!   deadline — and resolves with the flush result. Server shutdown calls
//!   [`close_global`] after stopping the producer tasks. Test writers that
//!   drop all handles without closing keep the legacy best-effort final
//!   flush, but the daemon must use the explicit protocol.
//! * CLI subcommands and unit tests run without an initialized writer and
//!   fall back to an inline load→mutate→save (atomic per snapshot thanks to
//!   bridge-store's unique temp names). Policy for a CLI subcommand running
//!   while the daemon is live: both sides publish whole files atomically, so
//!   the file is never torn; concurrent publication resolves as
//!   last-writer-wins per snapshot, and the daemon's next clean-state op
//!   re-reads the file and incorporates the CLI's version. Cross-process
//!   file locking was considered and rejected: it adds a new dependency for
//!   an ops-window race that is self-healing on the daemon's next write,
//!   while sequential CLI usage is fully preserved by the clean-state
//!   re-read rule above.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anyhow::{anyhow, Result};
use bridge_store::BridgeStore;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{info, warn};

type MutateFn = Box<dyn FnOnce(&mut BridgeStore) + Send>;
/// Publishing strategy; production uses `BridgeStore::save`, tests inject failures.
type Publisher = Arc<dyn Fn(&BridgeStore) -> Result<()> + Send + Sync>;

enum Op {
    Mutate {
        apply: MutateFn,
        ack: oneshot::Sender<Result<()>>,
    },
    Close {
        reply: oneshot::Sender<Result<()>>,
    },
}

const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub(crate) struct StoreWriter {
    tx: mpsc::Sender<Op>,
    path: PathBuf,
    /// The actor task's join handle; `close` takes it once (never double-
    /// awaited) and later close callers see `None`, meaning already joined.
    actor: Arc<Mutex<Option<JoinHandle<Result<()>>>>>,
}

/// Backoff bookkeeping for the retained, unpublished snapshot. Does not
/// touch the disk itself; the actor calls [`RetryState::record_success`] /
/// [`RetryState::record_failure`] from both the async publish-completion
/// path and the synchronous final flush, so the logging and arithmetic stay
/// in one place.
struct RetryState {
    dirty: bool,
    failed_attempts: u32,
    retry_at: Option<tokio::time::Instant>,
    backoff: Duration,
}

impl RetryState {
    fn new(initial_backoff: Duration) -> Self {
        Self {
            dirty: false,
            failed_attempts: 0,
            retry_at: None,
            backoff: initial_backoff,
        }
    }

    /// Bookkeeping after a publish succeeded: end any retry streak (logging
    /// recovery at info) and mark the state clean. The caller drops the
    /// snapshot so the next op re-reads the file — unless mutations were
    /// absorbed while the save ran, in which case the caller keeps it dirty.
    fn record_success(&mut self) {
        if self.failed_attempts > 0 {
            info!(
                attempts = self.failed_attempts + 1,
                "bridge health store published after retries"
            );
        }
        self.dirty = false;
        self.failed_attempts = 0;
        self.retry_at = None;
        self.backoff = INITIAL_BACKOFF;
    }

    /// Bookkeeping after a publish failed: retain the dirty snapshot and arm
    /// the next exponential-backoff retry. The update stays in memory.
    fn record_failure(&mut self, error: &anyhow::Error) {
        self.failed_attempts += 1;
        warn!(
            error = %error,
            attempt = self.failed_attempts,
            retry_in = ?self.backoff,
            "bridge health store publish failed; update retained in memory and will retry"
        );
        self.dirty = true;
        self.retry_at = Some(tokio::time::Instant::now() + self.backoff);
        self.backoff = (self.backoff * 2).min(MAX_BACKOFF);
    }
}

impl StoreWriter {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Apply one mutation through the owner. Resolves `Ok` once the
    /// mutation has been absorbed into the owner's in-memory snapshot —
    /// a failed disk publish is the writer's retry problem, not the
    /// caller's. Resolves `Err` when the on-disk snapshot could not be
    /// loaded, in which case the closure was NOT run (a caller draining a
    /// queue keeps its items), or when the closure panicked mid-apply; on
    /// a panic the snapshot's state is unknown, so it is dropped (the next
    /// op reloads from disk) and the caller must assume the mutation did
    /// not land.
    pub(crate) async fn apply(
        &self,
        apply: impl FnOnce(&mut BridgeStore) + Send + 'static,
    ) -> Result<()> {
        let (ack_tx, ack_rx) = oneshot::channel();
        self.tx
            .send(Op::Mutate {
                apply: Box::new(apply),
                ack: ack_tx,
            })
            .await
            .map_err(|_| anyhow!("bridge store writer is not running"))?;
        ack_rx
            .await
            .map_err(|_| anyhow!("bridge store writer dropped the update"))?
    }

    /// Ask the actor to stop: wait for any in-flight publish, flush the
    /// snapshot if it is still dirty (even before the backoff deadline),
    /// then join the actor task. The first caller takes the join handle;
    /// later callers find it `None` (already joined) and get `Ok`. Resolves
    /// `Err` only if the final flush failed or the actor died unexpectedly.
    pub(crate) async fn close(&self) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let mut result = if self.tx.send(Op::Close { reply: reply_tx }).await.is_ok() {
            match reply_rx.await {
                Ok(reply) => reply,
                Err(_) => Err(anyhow!(
                    "bridge store writer actor terminated before replying"
                )),
            }
        } else {
            // The actor is already gone (never started, or dropped without a
            // close op); fall through to the join step.
            Ok(())
        };
        let handle = self.actor.lock().expect("actor join slot lock").take();
        if let Some(handle) = handle {
            match handle.await {
                Ok(joined) => {
                    if result.is_ok() {
                        result = joined;
                    }
                }
                Err(join_error) => {
                    result = Err(anyhow!("bridge store writer actor panicked: {join_error}"));
                }
            }
        }
        result
    }

    pub(crate) fn spawn(path: PathBuf, publish: Publisher, initial_backoff: Duration) -> Self {
        let (tx, mut rx) = mpsc::channel::<Op>(64);
        let actor_path = path.clone();
        let handle = tokio::spawn(async move {
            let path = actor_path;
            let mut retry = RetryState::new(initial_backoff);
            let mut store: Option<Arc<BridgeStore>> = None;
            let mut publishing = false;
            let mut mutations_since_publish: u32 = 0;
            let mut closing = false;
            let mut close_replies: Vec<oneshot::Sender<Result<()>>> = Vec::new();
            // Completion channel for in-flight publishes; the actor holds the
            // receiver, each spawn_blocking job gets a clone of the sender.
            let (done_tx, mut done_rx) = mpsc::channel::<Result<()>>(1);

            loop {
                if closing {
                    // Wait for any in-flight publish, letting a coalesced
                    // tail fire its follow-up, then flush what is left.
                    while publishing {
                        match done_rx.recv().await {
                            Some(res) => {
                                // The in-flight publish just reported in;
                                // try_start_publish only sets this back to
                                // true if it actually starts a follow-up.
                                publishing = false;
                                absorb_publish_result(
                                    res,
                                    &mut retry,
                                    &mut store,
                                    &mut mutations_since_publish,
                                );
                                try_start_publish(
                                    &mut publishing,
                                    &mut retry,
                                    &store,
                                    &mut mutations_since_publish,
                                    &publish,
                                    &done_tx,
                                );
                            }
                            None => publishing = false,
                        }
                    }
                    let outcome = if retry.dirty {
                        match store.clone() {
                            Some(snapshot) => {
                                let publish = publish.clone();
                                let flush = tokio::task::spawn_blocking(move || publish(&snapshot))
                                    .await
                                    .map_err(|join_error| {
                                        anyhow!(
                                            "bridge health store publish task failed: {join_error}"
                                        )
                                    })
                                    .and_then(|published| published);
                                match flush {
                                    Ok(()) => {
                                        info!("bridge health store published on shutdown");
                                        retry.record_success();
                                        Ok(())
                                    }
                                    Err(error) => {
                                        warn!(
                                            error = %error,
                                            "bridge health store has unpublished updates at shutdown"
                                        );
                                        retry.record_failure(&error);
                                        Err(error)
                                    }
                                }
                            }
                            None => Ok(()),
                        }
                    } else {
                        Ok(())
                    };
                    for reply in close_replies.drain(..) {
                        // anyhow::Error is not Clone, and `outcome` is still
                        // needed below for the actor's own return value, so
                        // every extra close() caller gets a reformatted copy
                        // built from a borrow, not the original.
                        let reply_result: Result<()> = match &outcome {
                            Ok(()) => Ok(()),
                            Err(error) => Err(anyhow!("{error:#}")),
                        };
                        let _ = reply.send(reply_result);
                    }
                    break outcome;
                }

                // Only arm the retry branch while there is unpublished work.
                let retry_at = if retry.dirty { retry.retry_at } else { None };
                tokio::select! {
                    op = rx.recv(), if !closing => match op {
                        None => {
                            // All senders dropped without an explicit Close
                            // (test-only path): run the same drain/flush flow.
                            closing = true;
                        }
                        Some(Op::Mutate { apply, ack }) => {
                            // Clean snapshot: re-read the file so whole-file
                            // writes by other processes are seen and preserved.
                            // The load runs on the blocking pool; ops arriving
                            // meanwhile just buffer in the channel.
                            if store.is_none() {
                                let load_path = path.clone();
                                match tokio::task::spawn_blocking(move || {
                                    BridgeStore::load(load_path)
                                })
                                .await
                                {
                                    Ok(Ok(loaded)) => store = Some(Arc::new(loaded)),
                                    Ok(Err(error)) => {
                                        // Never apply to, or publish from, a
                                        // snapshot we failed to load.
                                        warn!(error = %error, path = %path.display(), "bridge health store unreadable; keeping the caller's data queued");
                                        let _ = ack.send(Err(error));
                                        continue;
                                    }
                                    Err(join_error) => {
                                        warn!(error = %join_error, path = %path.display(), "bridge health store load task failed; keeping the caller's data queued");
                                        let _ = ack.send(Err(anyhow!(
                                            "bridge health store load task failed: {join_error}"
                                        )));
                                        continue;
                                    }
                                }
                            }
                            // Move the "maybe deep-clone, then mutate" step
                            // off the async worker: with a publish snapshot
                            // in flight the Arc is shared, so make_mut
                            // deep-copies the whole store (O(S)) — that copy
                            // must not stall this worker thread. Take
                            // temporary ownership: the actor is the sole
                            // owner of `store` outside this window and waits
                            // for the job before the next select! iteration,
                            // so ops stay strictly sequential.
                            let mut owned = store.take().expect("store loaded above");
                            match tokio::task::spawn_blocking(move || {
                                apply(Arc::make_mut(&mut owned));
                                owned
                            })
                            .await
                            {
                                Ok(owned) => {
                                    store = Some(owned);
                                    // Acknowledge the absorption before
                                    // publishing: the disk write is this
                                    // actor's problem now.
                                    let _ = ack.send(Ok(()));
                                    retry.dirty = true;
                                    mutations_since_publish += 1;
                                    // Publish now, unless a publish is already
                                    // in flight (the tail rides along) or a
                                    // backoff retry is pending (the timer
                                    // governs retries).
                                    try_start_publish(
                                        &mut publishing,
                                        &mut retry,
                                        &store,
                                        &mut mutations_since_publish,
                                        &publish,
                                        &done_tx,
                                    );
                                }
                                Err(join_error) => {
                                    // The closure may have panicked
                                    // mid-apply, leaving the snapshot's state
                                    // unknown: treat it like an unreadable
                                    // store (the load-failure branches above)
                                    // — drop it so the NEXT op reloads fresh
                                    // from disk, and report the failure
                                    // instead of silently confirming an
                                    // absorption that may not have happened
                                    // (retry.dirty / try_start_publish are
                                    // skipped, as on those branches).
                                    warn!(
                                        error = %join_error,
                                        path = %path.display(),
                                        "bridge health store mutation task panicked; store will reload on next op"
                                    );
                                    let _ = ack.send(Err(anyhow!(
                                        "bridge health store mutation task panicked: {join_error}"
                                    )));
                                    continue;
                                }
                            }
                        }
                        Some(Op::Close { reply }) => {
                            close_replies.push(reply);
                            closing = true;
                        }
                    },
                    Some(res) = done_rx.recv(), if publishing => {
                        // The in-flight publish just reported in;
                        // try_start_publish only sets this back to true if
                        // it actually starts a follow-up.
                        publishing = false;
                        absorb_publish_result(
                            res,
                            &mut retry,
                            &mut store,
                            &mut mutations_since_publish,
                        );
                        // A tail absorbed during the save gets its own
                        // coalesced publish immediately (backoff was reset).
                        try_start_publish(
                            &mut publishing,
                            &mut retry,
                            &store,
                            &mut mutations_since_publish,
                            &publish,
                            &done_tx,
                        );
                    }
                    _ = tokio::time::sleep_until(retry_at.unwrap_or_else(tokio::time::Instant::now)), if retry.dirty && retry_at.is_some() && !publishing && !closing => {
                        // The gate inside try_start_publish re-checks the
                        // deadline; this handler just offers the attempt.
                        try_start_publish(
                            &mut publishing,
                            &mut retry,
                            &store,
                            &mut mutations_since_publish,
                            &publish,
                            &done_tx,
                        );
                    }
                }
            }
        });
        Self {
            tx,
            path,
            actor: Arc::new(Mutex::new(Some(handle))),
        }
    }
}

/// Publish-completion bookkeeping shared by the normal loop, the close drain
/// and (indirectly, via [`RetryState`]) the final flush: on success reset the
/// retry state, dropping the snapshot only when no tail mutations were
/// absorbed during the save (clean state ⇒ the next op re-reads the file);
/// on failure retain the snapshot and arm the backoff.
fn absorb_publish_result(
    res: Result<()>,
    retry: &mut RetryState,
    store: &mut Option<Arc<BridgeStore>>,
    mutations_since_publish: &mut u32,
) {
    match res {
        Ok(()) => {
            let routine = *mutations_since_publish == 0;
            retry.record_success();
            if routine {
                debug_assert!(!retry.dirty);
                // Success with no tail: drop the snapshot so the next
                // mutation reloads the file and preserves whole-file writes
                // made by other processes in the meantime.
                *store = None;
            } else {
                // Mutations absorbed while the save ran stay dirty; the
                // caller starts the coalesced follow-up publish.
                retry.dirty = true;
            }
        }
        Err(error) => retry.record_failure(&error),
    }
    *mutations_since_publish = 0;
}

/// Start one publish on the blocking pool, unless one is already in flight,
/// there is nothing dirty to publish, or a backoff retry is still pending
/// (the timer governs retries — incoming mutations must not bypass it).
fn try_start_publish(
    publishing: &mut bool,
    retry: &mut RetryState,
    store: &Option<Arc<BridgeStore>>,
    mutations_since_publish: &mut u32,
    publish: &Publisher,
    done_tx: &mpsc::Sender<Result<()>>,
) {
    if *publishing || !retry.dirty || store.is_none() {
        return;
    }
    if retry
        .retry_at
        .is_some_and(|retry_at| retry_at > tokio::time::Instant::now())
    {
        return;
    }
    // O(1): just an Arc refcount bump, not a deep copy of the store.
    let snapshot = store.clone().expect("snapshot present above");
    let publish = publish.clone();
    let done_tx = done_tx.clone();
    // The JoinHandle is deliberately not retained: the job cannot be
    // cancelled and reliably delivers its result via `done_tx`.
    tokio::task::spawn_blocking(move || {
        let res = publish(&snapshot);
        let _ = done_tx.blocking_send(res);
    });
    *publishing = true;
    *mutations_since_publish = 0;
}

static WRITER: OnceLock<StoreWriter> = OnceLock::new();

/// Start the process-wide store writer. Daemon startup calls this once,
/// before any task that writes the store. A second call logs a warning and
/// returns the existing writer.
pub(crate) fn init_global(config_path: Option<&Path>) -> StoreWriter {
    let resolved = BridgeStore::resolve_path(config_path);
    let writer = WRITER.get_or_init(|| {
        StoreWriter::spawn(resolved.clone(), Arc::new(|s| s.save()), INITIAL_BACKOFF)
    });
    if writer.path() != resolved {
        warn!(
            configured = %resolved.display(),
            active = %writer.path().display(),
            "bridge store writer already started for a different path; keeping the original"
        );
    }
    writer.clone()
}

fn global() -> Option<&'static StoreWriter> {
    WRITER.get()
}

/// Close the process-wide store writer at server shutdown, after the
/// producer tasks have stopped: waits for the in-flight publish, flushes any
/// retained snapshot and joins the actor. `None` when no writer was started
/// (CLI subcommands, tests).
pub(crate) async fn close_global() -> Option<Result<()>> {
    Some(global()?.close().await)
}

/// Apply a mutation through the single writer when this process has one for
/// `config_path`; otherwise (CLI subcommands, unit tests) fall back to an
/// inline atomic read-modify-write (see module docs for the CLI policy).
pub(crate) async fn apply(
    config_path: Option<&Path>,
    apply: impl FnOnce(&mut BridgeStore) + Send + 'static,
) -> Result<()> {
    let resolved = BridgeStore::resolve_path(config_path);
    match global() {
        Some(writer) if writer.path() == resolved => writer.apply(apply).await,
        _ => {
            let mut store = BridgeStore::load(resolved)?;
            apply(&mut store);
            store.save()
        }
    }
}

#[cfg(test)]
#[path = "bridge_store_writer_tests.rs"]
mod tests;
