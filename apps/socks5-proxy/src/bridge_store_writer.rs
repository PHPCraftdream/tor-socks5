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
    /// queue keeps its items).
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
            let mut store: Option<BridgeStore> = None;
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
                                    Ok(Ok(loaded)) => store = Some(loaded),
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
                            apply(store.as_mut().expect("store loaded above"));
                            // Acknowledge the absorption before publishing:
                            // the disk write is this actor's problem now.
                            let _ = ack.send(Ok(()));
                            retry.dirty = true;
                            mutations_since_publish += 1;
                            // Publish now, unless a publish is already in
                            // flight (the tail rides along) or a backoff
                            // retry is pending (the timer governs retries).
                            try_start_publish(
                                &mut publishing,
                                &mut retry,
                                &store,
                                &mut mutations_since_publish,
                                &publish,
                                &done_tx,
                            );
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
    store: &mut Option<BridgeStore>,
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
    store: &Option<BridgeStore>,
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
mod tests {
    use super::*;
    use bridge_line::BridgeLine;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use time::OffsetDateTime;

    fn test_bridge() -> BridgeLine {
        "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0"
            .parse()
            .expect("test bridge line parses")
    }

    fn config_path(dir: &Path) -> PathBuf {
        dir.join("tor-socks5.ktav")
    }

    fn seed_store(config_path: &Path, bridge: &BridgeLine) {
        let mut store = BridgeStore::load(BridgeStore::resolve_path(Some(config_path)))
            .expect("fresh store loads");
        store.note_source_at(bridge, "test", OffsetDateTime::now_utc());
        store.save().expect("seed save");
    }

    fn reload(config_path: &Path) -> BridgeStore {
        BridgeStore::load(BridgeStore::resolve_path(Some(config_path))).expect("reload store")
    }

    fn leftover_tmp_files(dir: &Path) -> Vec<std::fs::DirEntry> {
        std::fs::read_dir(dir)
            .expect("read tempdir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "tmp"))
            .collect()
    }

    /// Poll until the on-disk store reports `expected` channel successes for
    /// `bridge`. Publishes now complete asynchronously (ack precedes the disk
    /// write), so tests wait instead of asserting immediately. Uses a real
    /// (non-async) sleep so paused-clock tests keep their virtual timeline
    /// while the spawn_blocking publisher progresses in real time; yields
    /// each iteration so the actor task (which must be polled to drain
    /// `done_rx` and start a coalesced follow-up publish) actually gets to
    /// run on a single-threaded test runtime, even when the caller has no
    /// other `.await` between triggering the publish and this wait.
    async fn wait_for_file_count(path: &Path, bridge: &BridgeLine, expected: u32, what: &str) {
        for _ in 0..5000 {
            if reload(path).channel_ok_count(bridge) == expected {
                return;
            }
            tokio::task::yield_now().await;
            std::thread::sleep(Duration::from_millis(2));
        }
        panic!("store never reached count {expected}: {what}");
    }

    /// Poll until the injected publisher has been called `expected` times.
    /// See [`wait_for_file_count`] for why this yields every iteration.
    async fn wait_for_calls(calls: &AtomicUsize, expected: usize, what: &str) {
        for _ in 0..5000 {
            if calls.load(Ordering::SeqCst) >= expected {
                return;
            }
            tokio::task::yield_now().await;
            std::thread::sleep(Duration::from_millis(2));
        }
        panic!("publisher never reached {expected} calls: {what}");
    }

    /// Fail-first publisher with a call counter (call 0 errors, rest save).
    fn fail_first_publisher(calls: Arc<AtomicUsize>) -> Publisher {
        Arc::new(move |s: &BridgeStore| {
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(anyhow!("injected publish failure"))
            } else {
                s.save()
            }
        })
    }

    #[tokio::test]
    async fn concurrent_updates_are_applied_additively_and_sequentially() {
        let dir = tempfile::tempdir().expect("tempdir");
        let b = test_bridge();
        let path = config_path(dir.path());
        seed_store(&path, &b);

        let writer = StoreWriter::spawn(
            BridgeStore::resolve_path(Some(&path)),
            Arc::new(|s| s.save()),
            INITIAL_BACKOFF,
        );
        let seen = Arc::new(Mutex::new(Vec::<u32>::new()));
        let mut tasks = Vec::new();
        for i in 0..8u32 {
            let writer = writer.clone();
            let seen = seen.clone();
            let b = b.clone();
            tasks.push(tokio::spawn(async move {
                writer
                    .apply(move |s| {
                        seen.lock().unwrap().push(s.channel_ok_count(&b));
                        s.note_channel_success_at(&b, OffsetDateTime::now_utc());
                    })
                    .await
                    .expect("apply succeeds");
                i
            }));
        }
        for task in tasks {
            task.await.expect("task joins");
        }
        let mut counts = seen.lock().unwrap().clone();
        counts.sort_unstable();
        assert_eq!(counts, vec![0, 1, 2, 3, 4, 5, 6, 7], "no lost update");

        // Acks precede the disk publish now; wait for the coalesced save.
        wait_for_file_count(&path, &b, 8, "coalesced publish persisted all 8 updates").await;
        assert!(
            leftover_tmp_files(dir.path()).is_empty(),
            "no leftover temp files"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn publish_failure_retains_absorbed_updates_until_next_op() {
        let dir = tempfile::tempdir().expect("tempdir");
        let b = test_bridge();
        let path = config_path(dir.path());
        seed_store(&path, &b);

        let calls = Arc::new(AtomicUsize::new(0));
        let writer = StoreWriter::spawn(
            BridgeStore::resolve_path(Some(&path)),
            fail_first_publisher(calls.clone()),
            INITIAL_BACKOFF,
        );
        let b1 = b.clone();
        writer
            .apply(move |s| s.note_channel_success_at(&b1, OffsetDateTime::now_utc()))
            .await
            .expect("absorbed");
        wait_for_calls(&calls, 1, "failed publish attempted").await;
        assert_eq!(
            reload(&path).channel_ok_count(&b),
            0,
            "failed publish left the file untouched"
        );

        // A second mutation while the backoff is pending must NOT publish:
        // the retry timer governs all attempts, absorbed updates just ride
        // along in memory.
        let b2 = b.clone();
        writer
            .apply(move |s| s.note_channel_success_at(&b2, OffsetDateTime::now_utc()))
            .await
            .expect("absorbed");
        // Well under the 1s backoff, but enough paused time for the actor to
        // (not) act on the absorption.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "pending backoff must gate publishes; no attempt until the timer"
        );
        assert_eq!(
            reload(&path).channel_ok_count(&b),
            0,
            "absorbed update waits in memory behind the backoff"
        );

        // Closing flushes both retained updates regardless of the deadline.
        let closed = writer.close().await;
        assert!(closed.is_ok(), "close flushes: {closed:?}");
        assert_eq!(
            reload(&path).channel_ok_count(&b),
            2,
            "final flush wrote both absorbed observations"
        );
        assert!(
            leftover_tmp_files(dir.path()).is_empty(),
            "no leftover temp files"
        );
    }

    #[tokio::test]
    async fn mutations_are_coalesced_while_a_publish_is_in_flight() {
        let dir = tempfile::tempdir().expect("tempdir");
        let b = test_bridge();
        let path = config_path(dir.path());
        seed_store(&path, &b);

        let calls = Arc::new(AtomicUsize::new(0));
        let (gate_tx, gate_rx) = oneshot::channel::<()>();
        // The gate receiver is consumed once (blocking_recv takes self), so
        // wrap it for the `Fn` publisher bound.
        let gate = Mutex::new(Some(gate_rx));
        let counter = calls.clone();
        let publisher: Publisher = Arc::new(move |s: &BridgeStore| {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                // Hold publish #1 in-flight until the test releases it.
                let held = gate.lock().unwrap().take().expect("gate used once");
                let _ = held.blocking_recv();
            }
            s.save()
        });
        let writer = StoreWriter::spawn(
            BridgeStore::resolve_path(Some(&path)),
            publisher,
            INITIAL_BACKOFF,
        );

        for i in 0..10u32 {
            let b = b.clone();
            writer
                .apply(move |s| {
                    s.note_channel_success_at(&b, OffsetDateTime::now_utc());
                    s.note_source_at(&b, &format!("src-{i}"), OffsetDateTime::now_utc());
                })
                .await
                .expect("each apply acks once absorbed, even with a publish blocked");
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "mutations arriving during a publish must be absorbed, not published"
        );

        // Release publish #1; the completion triggers one coalesced
        // follow-up carrying all 10 mutations.
        gate_tx.send(()).expect("release the publish gate");
        wait_for_calls(&calls, 2, "coalesced follow-up publish fired").await;
        wait_for_file_count(&path, &b, 10, "no absorbed update was lost").await;
        assert!(
            calls.load(Ordering::SeqCst) <= 3,
            "10 mutations must coalesce into at most a few publishes, got {}",
            calls.load(Ordering::SeqCst)
        );

        let store = reload(&path);
        let sources = store.sources_of(&b);
        // sources_of is backed by a BTreeSet, so it comes back lexicographically
        // sorted, not in insertion order: "src-0".."src-9" before seed_store's
        // "test".
        let mut expected: Vec<String> = (0..10).map(|i| format!("src-{i}")).collect();
        expected.push("test".to_string());
        assert_eq!(
            sources, expected,
            "every mutation applied, none reordered away"
        );

        let closed = writer.close().await;
        assert!(closed.is_ok(), "close after a clean publish: {closed:?}");
        assert!(
            leftover_tmp_files(dir.path()).is_empty(),
            "no leftover temp files"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn backoff_gates_publish_attempts_under_a_continuous_mutation_stream() {
        let dir = tempfile::tempdir().expect("tempdir");
        let b = test_bridge();
        let path = config_path(dir.path());
        seed_store(&path, &b);

        let calls = Arc::new(AtomicUsize::new(0));
        let writer = StoreWriter::spawn(
            BridgeStore::resolve_path(Some(&path)),
            fail_first_publisher(calls.clone()),
            Duration::from_secs(1),
        );

        // A continuous stream of mutations must not produce a publish per
        // mutation, nor bypass the pending backoff: after the first failure
        // only the retry timer may attempt a publish.
        for _ in 0..10u32 {
            let b = b.clone();
            writer
                .apply(move |s| s.note_channel_success_at(&b, OffsetDateTime::now_utc()))
                .await
                .expect("absorbed");
            // Yield so the actor can process ops/completions; the virtual
            // clock barely moves, staying inside the 1s backoff.
            tokio::time::sleep(Duration::ZERO).await;
        }
        wait_for_calls(&calls, 1, "first (failing) publish attempted").await;
        // Stay under the 1s backoff; paused time only moved milliseconds.
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "backoff must gate the continuous mutation stream"
        );

        // Sleep past the backoff (plain sleep is the robust way to drive
        // paused time; see the comment in
        // publish_failure_is_retried_by_the_backoff_timer). The retry
        // publishes the coalesced snapshot once.
        tokio::time::sleep(Duration::from_secs(2)).await;
        wait_for_calls(&calls, 2, "backoff retry fired").await;
        wait_for_file_count(&path, &b, 10, "retry persisted the coalesced snapshot").await;
        assert!(
            calls.load(Ordering::SeqCst) <= 3,
            "10 mutations must not cost 10 publishes, got {}",
            calls.load(Ordering::SeqCst)
        );

        let closed = writer.close().await;
        assert!(closed.is_ok(), "close after a clean retry: {closed:?}");
        assert!(
            leftover_tmp_files(dir.path()).is_empty(),
            "no leftover temp files"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn close_flushes_absorbed_updates_before_the_retry_deadline() {
        let dir = tempfile::tempdir().expect("tempdir");
        let b = test_bridge();
        let path = config_path(dir.path());
        seed_store(&path, &b);

        let calls = Arc::new(AtomicUsize::new(0));
        let writer = StoreWriter::spawn(
            BridgeStore::resolve_path(Some(&path)),
            fail_first_publisher(calls.clone()),
            Duration::from_secs(1),
        );

        // m1 fails to publish, snapshot retained, backoff armed.
        let b1 = b.clone();
        writer
            .apply(move |s| s.note_channel_success_at(&b1, OffsetDateTime::now_utc()))
            .await
            .expect("absorbed");
        wait_for_calls(&calls, 1, "first (failing) publish attempted").await;
        assert_eq!(reload(&path).channel_ok_count(&b), 0, "file still stale");

        // m2 arrives while the backoff is pending: absorbed, no publish.
        let b2 = b.clone();
        writer
            .apply(move |s| s.note_channel_success_at(&b2, OffsetDateTime::now_utc()))
            .await
            .expect("absorbed");

        // Shutdown BEFORE the retry deadline: close must still flush both
        // mutations (this is the TS2-03 regression — the old design lost
        // them when the runtime dropped the pending timer).
        let closed = writer.close().await;
        assert!(
            closed.is_ok(),
            "close must flush retained updates: {closed:?}"
        );
        assert_eq!(
            reload(&path).channel_ok_count(&b),
            2,
            "final flush ran before the backoff deadline and wrote both mutations"
        );

        // The actor has exited: a further apply is rejected by a closed
        // channel ("writer is not running"). The test completing is also the
        // proof that close() joined the actor task without hanging.
        let rejected = writer.apply(|_| {}).await;
        assert!(rejected.is_err(), "apply after close must fail");
        assert!(
            leftover_tmp_files(dir.path()).is_empty(),
            "no leftover temp files"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn close_reports_a_persistent_publish_failure() {
        let dir = tempfile::tempdir().expect("tempdir");
        let b = test_bridge();
        let path = config_path(dir.path());
        seed_store(&path, &b);

        let writer = StoreWriter::spawn(
            BridgeStore::resolve_path(Some(&path)),
            Arc::new(|_s: &BridgeStore| Err(anyhow!("disk is full"))),
            INITIAL_BACKOFF,
        );
        let b1 = b.clone();
        writer
            .apply(move |s| s.note_channel_success_at(&b1, OffsetDateTime::now_utc()))
            .await
            .expect("absorbed");

        // Persistent failure: close returns the flush error promptly (no
        // hang), the file stays untouched, and save's own temp-file cleanup
        // left nothing behind.
        let closed = writer.close().await;
        assert!(closed.is_err(), "persistent failure must surface via close");
        assert_eq!(
            reload(&path).channel_ok_count(&b),
            0,
            "failed flush left the file untouched"
        );
        assert!(
            leftover_tmp_files(dir.path()).is_empty(),
            "no leftover temp files after the failed save"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn publish_failure_is_retried_by_the_backoff_timer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let b = test_bridge();
        let path = config_path(dir.path());
        seed_store(&path, &b);

        let calls = Arc::new(AtomicUsize::new(0));
        let writer = StoreWriter::spawn(
            BridgeStore::resolve_path(Some(&path)),
            fail_first_publisher(calls.clone()),
            Duration::from_secs(1),
        );
        let b1 = b.clone();
        writer
            .apply(move |s| s.note_channel_success_at(&b1, OffsetDateTime::now_utc()))
            .await
            .expect("absorbed");
        assert_eq!(reload(&path).channel_ok_count(&b), 0, "file still stale");

        // Let the actor arm its timer, then sleep past the 1s backoff.
        // `sleep(...).await` (not manual `advance()` + `sleep(ZERO)`) is the
        // robust way to drive paused time here: it fast-forwards the clock
        // AND cooperatively polls the runtime until quiescent at each due
        // timer, so the actor's own `sleep_until` is guaranteed to fire.
        // The publish itself runs on the blocking pool, so the on-disk
        // assertion below polls in real time (wait_for_file_count).
        tokio::time::sleep(Duration::from_secs(2)).await;
        wait_for_calls(&calls, 2, "backoff retry fired").await;
        wait_for_file_count(
            &path,
            &b,
            1,
            "backoff timer republished the retained snapshot",
        )
        .await;

        let closed = writer.close().await;
        assert!(closed.is_ok(), "close after a successful retry: {closed:?}");
        assert!(
            leftover_tmp_files(dir.path()).is_empty(),
            "no leftover temp files"
        );
    }

    #[tokio::test]
    async fn load_failure_rejects_the_op_without_running_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Loading a directory path errors (not NotFound), exercising the
        // unreadable-store rejection path.
        let writer = StoreWriter::spawn(
            dir.path().to_path_buf(),
            Arc::new(|s: &BridgeStore| s.save()),
            INITIAL_BACKOFF,
        );
        let ran = Arc::new(AtomicBool::new(false));
        let ran_closure = ran.clone();
        let result = writer
            .apply(move |_s| {
                ran_closure.store(true, Ordering::SeqCst);
            })
            .await;
        assert!(result.is_err(), "apply must reject when load fails");
        assert!(!ran.load(Ordering::SeqCst), "closure must not run");
    }

    #[tokio::test]
    async fn apply_falls_back_to_inline_write_without_a_global_writer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let b = test_bridge();
        let config_path = config_path(dir.path());
        seed_store(&config_path, &b);

        let b1 = b.clone();
        apply(Some(config_path.as_ref()), move |s| {
            s.note_channel_success_at(&b1, OffsetDateTime::now_utc())
        })
        .await
        .expect("inline fallback write succeeds");
        assert_eq!(reload(&config_path).channel_ok_count(&b), 1);
        assert!(
            leftover_tmp_files(dir.path()).is_empty(),
            "no leftover temp files"
        );
    }

    #[tokio::test]
    async fn external_cli_write_between_daemon_mutations_survives() {
        let dir = tempfile::tempdir().expect("tempdir");
        let b = test_bridge();
        let cli_bridge: BridgeLine =
            "obfs4 5.6.7.8:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=BBB iat-mode=0"
                .parse()
                .expect("CLI bridge line parses");
        let path = config_path(dir.path());
        seed_store(&path, &b);

        let writer = StoreWriter::spawn(
            BridgeStore::resolve_path(Some(&path)),
            Arc::new(|s| s.save()),
            INITIAL_BACKOFF,
        );

        // Daemon mutation #1 publishes cleanly. Acks now precede the disk
        // write, so wait for the publish to land AND for the actor to retire
        // the completion (dropping its snapshot) before the external write.
        let b1 = b.clone();
        writer
            .apply(move |s| s.note_channel_success_at(&b1, OffsetDateTime::now_utc()))
            .await
            .expect("absorbed");
        wait_for_file_count(&path, &b, 1, "first daemon mutation published").await;
        wait_a_real_moment().await;

        // A separate CLI process (sequential, not concurrent) loads, adds a
        // new bridge and bumps the daemon bridge's counter, then saves.
        let mut external = reload(&path);
        external.note_source_at(&cli_bridge, "cli", OffsetDateTime::now_utc());
        external.note_channel_success_at(&b, OffsetDateTime::now_utc());
        external.save().expect("external save");

        // Daemon mutation #2 must build on the CLI's version, not the
        // daemon's stale pre-CLI snapshot.
        let b2 = b.clone();
        writer
            .apply(move |s| s.note_channel_success_at(&b2, OffsetDateTime::now_utc()))
            .await
            .expect("absorbed");

        wait_for_file_count(&path, &b, 3, "daemon's second mutation published").await;
        let store = reload(&path);
        assert_eq!(
            store.channel_ok_count(&b),
            3,
            "daemon's second mutation must build on the CLI's counter (1 daemon + 1 CLI + 1 daemon)"
        );
        assert_eq!(
            store.sources_of(&cli_bridge),
            vec!["cli"],
            "CLI's new bridge must survive the daemon's next publish"
        );
        assert!(
            leftover_tmp_files(dir.path()).is_empty(),
            "no leftover temp files"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn external_cli_write_after_successful_retry_survives() {
        let dir = tempfile::tempdir().expect("tempdir");
        let b = test_bridge();
        let cli_bridge: BridgeLine =
            "obfs4 5.6.7.8:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=BBB iat-mode=0"
                .parse()
                .expect("CLI bridge line parses");
        let path = config_path(dir.path());
        seed_store(&path, &b);

        let calls = Arc::new(AtomicUsize::new(0));
        let writer = StoreWriter::spawn(
            BridgeStore::resolve_path(Some(&path)),
            fail_first_publisher(calls.clone()),
            Duration::from_secs(1),
        );

        // Daemon mutation #1: publish fails, snapshot retained, retry armed.
        let b1 = b.clone();
        writer
            .apply(move |s| s.note_channel_success_at(&b1, OffsetDateTime::now_utc()))
            .await
            .expect("absorbed");
        assert_eq!(reload(&path).channel_ok_count(&b), 0, "file still stale");

        // Paused clock: sleep fast-forwards AND polls the runtime to
        // quiescence, so the actor's retry fires (see the comment in
        // publish_failure_is_retried_by_the_backoff_timer); the publish runs
        // on the blocking pool, hence the real-time polls below.
        tokio::time::sleep(Duration::from_secs(2)).await;
        wait_for_calls(&calls, 2, "retry fired").await;
        wait_for_file_count(&path, &b, 1, "retry published").await;

        // External CLI write lands after the successful retry.
        let mut external = reload(&path);
        external.note_source_at(&cli_bridge, "cli", OffsetDateTime::now_utc());
        external.note_channel_success_at(&b, OffsetDateTime::now_utc());
        external.save().expect("external save");

        // Daemon mutation #2 must build on the CLI's version.
        let b2 = b.clone();
        writer
            .apply(move |s| s.note_channel_success_at(&b2, OffsetDateTime::now_utc()))
            .await
            .expect("absorbed");

        wait_for_file_count(&path, &b, 3, "post-retry mutation published").await;
        let store = reload(&path);
        assert_eq!(
            store.channel_ok_count(&b),
            3,
            "mutation after a successful retry must build on the CLI's counter (1 retry + 1 CLI + 1 daemon)"
        );
        assert_eq!(
            store.sources_of(&cli_bridge),
            vec!["cli"],
            "CLI's new bridge must survive a post-retry daemon publish"
        );
        assert!(
            leftover_tmp_files(dir.path()).is_empty(),
            "no leftover temp files"
        );
    }

    /// Give the actor a few real scheduling turns to retire a publish
    /// completion (drop its snapshot) after the file write has been observed
    /// on disk. Used in wall-clock tests only.
    async fn wait_a_real_moment() {
        for _ in 0..20 {
            tokio::task::yield_now().await;
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}
