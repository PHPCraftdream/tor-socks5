//! Single writer for the bridge health store (`<config>.alive-bridges.log`).
//!
//! # Public surface (SDK-7)
//!
//! [`StoreWriter`] is the handle: [`StoreWriter::open`] starts it (config
//! path in, handle out), [`StoreWriter::apply`] sends one mutation,
//! [`StoreWriter::close`] stops it and returns the final flush result.
//! [`init_global`] / [`close_global`] are the process-wide slot on top of
//! the same actor; a separate server-run slot (`init_run` / `close_run`,
//! `bridge_maintenance/workers/run_writer.rs`) lets the SDK server open its own
//! writer per run and never touch the app's global writer. [`apply`]
//! prefers the run writer. Each slot holds at most one live writer and a
//! sequential restart works — after a close the slot is empty, so the
//! next init starts a fresh writer, never a closed one. The
//! publish strategy (production: `BridgeStore::save`, standard retry
//! backoff) is not configurable through the public API; the injectable
//! constructor is a test seam (R10).
//!
//! Concurrency contract (fixes the P1 racing-writes finding in
//! docs/reviews/2026-09-07-08/stability-review-2026-09-08.md, plus TS2-02/TS2-03 in
//! docs/reviews/2026-09-07-08/review-round-2-2026-09-08.md):
//!
//! * Angel: exactly one actor task owns every publish. Writers send a
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
//! * The mutate step runs on the blocking pool too. Every mutation job
//!   runs on a private deep copy inside `spawn_blocking`: the actor hands
//!   the job a cheap `Arc` clone but keeps its own handle, so
//!   `Arc::make_mut` inside the job is an unconditional O(S) deep copy —
//!   an accepted per-mutation cost paid on the blocking pool, never on an
//!   async worker. The actor waits for the mutation job before its next
//!   `select!` iteration, so mutation order, acks and retry bookkeeping
//!   are unchanged. If the mutation closure panics, only the job's private
//!   copy is destroyed; the actor's snapshot — including all previously
//!   acknowledged and unpublished mutations — is retained, and the op's
//!   ack resolves `Err`.
//! * Retired snapshots are deallocated off the async worker as well: when
//!   the actor swaps in a new snapshot after a mutation, or a clean publish
//!   retires the retained one, the old `Arc` is handed to the blocking pool
//!   for its drop (fire-and-forget `spawn_blocking`), so freeing a large
//!   store never runs inline in the `select!` loop (TS6-04).
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
//! * Cross-process read-modify-write coordination: every writer of the
//!   store file — this actor and the CLI inline fallback — holds the
//!   per-path advisory lock ([`persist_lock::PathLock`], sibling
//!   `<store>.lock` file) from the load that reads the file through the
//!   publish that writes it. The clean-state re-read alone cannot heal an
//!   overlap: a CLI transaction that loads while an actor publish is in
//!   flight saves a snapshot the actor's rename buries permanently. With
//!   the lock, the CLI waits out the actor's dirty window (including
//!   backoff retries) and then mutates the published state, so both sides'
//!   mutations survive. The actor acquires the lock inside its clean-load
//!   `spawn_blocking` job with a bounded wait (never on an async worker) and
//!   releases it as soon as a publish succeeds with no tail mutations. A
//!   busy acquisition rejects the unapplied mutation so its caller can retry.
//! * A close signal uses a separate channel and is selected ahead of queued
//!   mutations. It interrupts the actor's wait for a clean-load blocking job;
//!   queued mutations are applied before shutdown when a snapshot is loaded,
//!   and rejected when closing would require another load. The blocking job
//!   remains independently registered; a late-acquired lock is dropped with it.
//! * Shutdown is explicit: [`StoreWriter::close`] sends a close signal, waits
//!   for any in-flight publish (and one coalesced follow-up), performs a
//!   final flush if the snapshot is still dirty — regardless of the backoff
//!   deadline — and resolves with the flush result. Server shutdown calls
//!   [`close_global`] after stopping the producer tasks. Test writers that
//!   drop all handles without closing keep the legacy best-effort final
//!   flush, but the angel must use the explicit protocol. After
//!   [`close_global`] the slot is empty, so the next [`init_global`] starts
//!   a fresh writer — an engine restarted in the same process does not
//!   inherit a dead one.
//! * CLI subcommands and unit tests run without an initialized writer and
//!   fall back to an inline load→mutate→save under the same per-path write
//!   lock, with a bounded wait ([`persist_lock::CLI_LOCK_WAIT`]) so a
//!   CLI fails with a clear "busy" error instead of hanging behind an angel
//!   stuck retrying a failing publish. Between angel dirty windows the
//!   lock is free, so sequential CLI usage is unaffected.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use bridge_store::BridgeStore;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use persist_lock::{PathLock, CLI_LOCK_WAIT};

type MutateFn = Box<dyn FnOnce(&mut BridgeStore) + Send>;
/// Publishing strategy; production uses `BridgeStore::save`, tests inject failures.
type Publisher = Arc<dyn Fn(&BridgeStore) -> Result<()> + Send + Sync>;

// Payload переходит в реестр без форматирования; актор получает только безопасную ошибку.
#[path = "bridge_store_writer_parts/publisher_panic.rs"]
mod publisher_panic;
use publisher_panic::PublisherPanic;

enum Op {
    Mutate {
        apply: MutateFn,
        ack: oneshot::Sender<Result<()>>,
    },
}

const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

struct ActorState {
    handle: Option<JoinHandle<Result<()>>>,
    close_requested: bool,
}

/// Handle to the single bridge-health writer actor for one store path.
/// Cloning is cheap — the clones share one actor — so the handle can be
/// handed to every producer task.
///
/// Operations:
///
/// * [`StoreWriter::apply`] — one mutation; resolves `Ok` once it is
///   absorbed into the actor's snapshot (a failed disk publish is the
///   actor's retry problem), `Err` when the snapshot could not be loaded,
///   the bounded store lock is busy, or the mutation job panicked. In the
///   first two cases the closure was not run and the caller may retry it;
///   a panicking mutation's private copy is discarded.
/// * [`StoreWriter::close`] — stop: wait for the in-flight publish,
///   flush a dirty snapshot regardless of the retry backoff, join the
///   actor and return the final flush result (`Err` on a failed final
///   write or a dead actor). Concurrent close callers share the
///   outcome; once the actor has been joined, further calls return
///   `Ok(())`.
///
/// Run at most one writer per store path in a process: [`init_global`]
/// enforces that for the engine's process-wide writer, and two `open`
/// handles on one path behave like two concurrent CLI writers (per-path
/// lock plus the clean-state re-read), not like one writer.
#[derive(Clone)]
pub struct StoreWriter {
    tx: mpsc::Sender<Op>,
    close_tx: mpsc::Sender<oneshot::Sender<Result<()>>>,
    path: PathBuf,
    /// Дескриптор остаётся в ячейке до завершения ожидания, даже при отмене close.
    actor: Arc<tokio::sync::Mutex<ActorState>>,
    /// TS6-04: where `drop_off_worker` records the thread each retirement
    /// drop ran on. Test-only: `retirement_tests.rs` asserts every
    /// retirement lands on a blocking-pool thread, never on the actor's
    /// async worker.
    #[cfg(test)]
    retirements: RetirementLog,
    /// Test seam (see `settled_watch`): epoch bumped when a clean publish
    /// retired the snapshot or a shutdown flush succeeded.
    /// `#[allow(dead_code)]`: never read outside test/seam builds.
    #[cfg(any(test, feature = "test-seams"))]
    #[allow(dead_code)]
    settled: tokio::sync::watch::Receiver<u64>,
    /// Test-only: epoch bumped after each retirement drop recorded its
    /// blocking-pool thread, so tests can await retirements.
    #[cfg(test)]
    retire_settled: tokio::sync::watch::Receiver<u64>,
}

/// Settle signal type: a real watch sender in test/seam builds, `()` elsewhere.
#[cfg(any(test, feature = "test-seams"))]
type SettleSignal = tokio::sync::watch::Sender<u64>;
#[cfg(not(any(test, feature = "test-seams")))]
type SettleSignal = ();

/// `#[path]` submodules (plan H19.2): keep this file under the 1000-line limit.
#[path = "bridge_store_writer_parts/retry_state.rs"]
mod retry_state;
use retry_state::RetryState;
#[path = "bridge_store_writer_parts/retire_off_worker.rs"]
mod retire_off_worker;
use retire_off_worker::{drop_off_worker, RetireSignal, RetirementLog};

impl StoreWriter {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Test seam: receiver of the settle watch. The actor bumps the epoch
    /// when a clean publish has retired the snapshot (`store = None`, next
    /// op re-reads the file) and after a successful shutdown flush, so a
    /// caller awaiting epoch >= N knows N successful clean publishes are
    /// durably on disk and the actor holds no stale snapshot.
    #[cfg(any(test, feature = "test-seams"))]
    #[allow(dead_code)] // only read by tests and test-seams consumers
    pub(crate) fn settled_watch(&self) -> tokio::sync::watch::Receiver<u64> {
        self.settled.clone()
    }

    /// Apply one mutation through the owner. Resolves `Ok` once the
    /// mutation has been absorbed into the owner's in-memory snapshot —
    /// a failed disk publish is the writer's retry problem, not the
    /// caller's. Resolves `Err` when the on-disk snapshot could not be
    /// loaded or the bounded store lock is busy; in either case the
    /// closure was NOT run, so the caller can retry the mutation. A
    /// mutation closure panic also resolves `Err`; its private copy is
    /// discarded and the previously acknowledged snapshot is retained.
    pub async fn apply(&self, apply: impl FnOnce(&mut BridgeStore) + Send + 'static) -> Result<()> {
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
    /// then join the actor task. The close signal bypasses the mutation
    /// queue, including while a clean-load lock acquisition is waiting.
    /// Callers are serialized by one mutex. Once Close is sent, cancellation
    /// of this future leaves the actor handle in the slot; a later call joins
    /// it and observes the retained outcome. The first completed join gets
    /// the result; subsequent calls get `Ok(())`. Returns `Err` if the final
    /// write fails or the actor dies.
    pub async fn close(&self) -> Result<()> {
        let mut state = self.actor.lock().await;
        if state.handle.is_none() {
            return Ok(());
        }
        let mut result = Ok(());
        if !state.close_requested {
            let (reply_tx, reply_rx) = oneshot::channel();
            if self.close_tx.send(reply_tx).await.is_ok() {
                // There is no cancellation point between sending Close and recording it.
                state.close_requested = true;
                result = match reply_rx.await {
                    Ok(reply) => reply,
                    Err(_) => Err(anyhow!(
                        "bridge store writer actor terminated before replying"
                    )),
                };
            }
        }
        if let Some(handle) = state.handle.as_mut() {
            let joined = handle.await;
            state.handle.take();
            match joined {
                Ok(joined) => {
                    if joined.is_err() || result.is_ok() {
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

    /// Start the writer for the store file that belongs to the config at
    /// `config_path` (`<config stem>.alive-bridges.log`, the same
    /// resolution [`init_global`] applies): config in, handle out.
    /// Publishes with the production strategy — `BridgeStore::save`
    /// under the per-path lock, retried with the standard backoff.
    ///
    /// The engine itself uses [`init_global`]/[`close_global`], which
    /// keep the single process-wide writer; `open` is for code that
    /// owns the handle explicitly. See the type-level note on running
    /// more than one writer per store path.
    pub fn open(config_path: &Path) -> Self {
        let resolved = BridgeStore::resolve_path(config_path);
        Self::spawn_writer_inner(
            resolved,
            Arc::new(|store| store.save()),
            INITIAL_BACKOFF,
            CLI_LOCK_WAIT,
            None,
        )
    }

    /// Test seam (R10): a custom publisher and initial backoff, for the
    /// writer's own tests and for tests in other crates that enable the
    /// `test-seams` feature through their dev-dependencies. Production
    /// code starts the writer with [`StoreWriter::open`]; this
    /// constructor does not exist outside test builds.
    #[cfg(any(test, feature = "test-seams"))]
    pub fn spawn(path: PathBuf, publish: Publisher, initial_backoff: Duration) -> Self {
        Self::spawn_writer_inner(path, publish, initial_backoff, CLI_LOCK_WAIT, None)
    }

    fn spawn_writer_inner(
        path: PathBuf,
        publish: Publisher,
        initial_backoff: Duration,
        lock_wait: Duration,
        mut load_started: Option<oneshot::Sender<()>>,
    ) -> Self {
        let (tx, mut rx) = mpsc::channel::<Op>(64);
        let (close_tx, mut close_rx) = mpsc::channel::<oneshot::Sender<Result<()>>>(1);
        let actor_path = path.clone();
        let retirements: RetirementLog = Arc::default();
        #[cfg(test)]
        let actor_retirements = Arc::clone(&retirements);
        #[cfg(any(test, feature = "test-seams"))]
        let registry = crate::workers::test_registry();
        #[cfg(any(test, feature = "test-seams"))]
        let (settled_tx, settled_rx) = tokio::sync::watch::channel(0u64);
        #[cfg(not(any(test, feature = "test-seams")))]
        let settled_tx = ();
        #[cfg(test)]
        let (retire_tx, retire_rx) = tokio::sync::watch::channel(0u64);
        #[cfg(test)]
        let retire_tx = Arc::new(retire_tx);
        #[cfg(not(test))]
        let retire_tx = Arc::new(());
        let actor = async move {
            let path = actor_path;
            #[cfg(test)]
            let retirements = actor_retirements;
            let mut retry = RetryState::new(initial_backoff);
            let mut store: Option<Arc<BridgeStore>> = None;
            // Lock spans clean load → publish; released when clean again
            // (or at task exit, covering the shutdown flush). Unlock is a
            // cheap syscall, safe inline on this async worker.
            let mut lock: Option<PathLock> = None;
            let mut publishing = false;
            let mut mutations_since_publish: u32 = 0;
            let mut closing = false;
            let mut close_replies: Vec<oneshot::Sender<Result<()>>> = Vec::new();
            // Completion channel for in-flight publishes; the actor holds the
            // receiver, each spawn_blocking job gets a clone of the sender.
            let (done_tx, mut done_rx) = mpsc::channel::<crate::workers::Delivery<()>>(1);

            loop {
                if closing {
                    rx.close();
                    if store.is_none() {
                        reject_queued_mutations(&mut rx);
                    } else {
                        while let Ok(op) = rx.try_recv() {
                            match op {
                                Op::Mutate { apply, ack } => {
                                    absorb_mutation(
                                        apply,
                                        ack,
                                        &mut store,
                                        &mut retry,
                                        &mut publishing,
                                        &mut mutations_since_publish,
                                        &publish,
                                        &done_tx,
                                        &retirements,
                                        &retire_tx,
                                        &path,
                                    )
                                    .await;
                                }
                            }
                        }
                    }
                    while publishing {
                        match done_rx.recv().await {
                            Some(res) => {
                                publishing = false;
                                absorb_publish_result(
                                    res,
                                    &mut retry,
                                    &mut store,
                                    &mut lock,
                                    &mut mutations_since_publish,
                                    &retirements,
                                    &retire_tx,
                                    &settled_tx,
                                );
                                try_start_publish(
                                    &mut publishing,
                                    &mut retry,
                                    &store,
                                    &mut mutations_since_publish,
                                    &publish,
                                    &done_tx,
                                )
                                .await;
                            }
                            None => publishing = false,
                        }
                    }
                    if store.is_none() {
                        reject_queued_mutations(&mut rx);
                    }
                    let outcome = if retry.dirty {
                        match store.clone() {
                            Some(snapshot) => {
                                let publish = publish.clone();
                                let flush = crate::workers::run_fallible_blocking(move || {
                                    publish(&snapshot)
                                })
                                .await
                                .map_err(|join_error| {
                                    anyhow!("bridge health store publish task failed: {join_error}")
                                })
                                .and_then(|published| published);
                                match flush {
                                    Ok(()) => {
                                        info!("bridge health store published on shutdown");
                                        retry.record_success();
                                        // Settle: the final flush is durably on disk.
                                        #[cfg(any(test, feature = "test-seams"))]
                                        settled_tx.send_modify(|epoch| *epoch += 1);
                                        #[cfg(not(any(test, feature = "test-seams")))]
                                        let _ = &settled_tx;
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
                        let reply_result: Result<()> = match &outcome {
                            Ok(()) => Ok(()),
                            Err(error) => Err(anyhow!("{error:#}")),
                        };
                        let _ = reply.send(reply_result);
                    }
                    #[cfg(any(test, feature = "test-seams"))]
                    {
                        let seam_path = path.clone();
                        let _ = tokio::task::spawn_blocking(move || {
                            crate::test_seams::park_if_armed(
                                crate::test_seams::Site::WriterCloseReplySent,
                                &seam_path,
                            );
                        })
                        .await;
                    }
                    break outcome;
                }

                let retry_at = if retry.dirty { retry.retry_at } else { None };
                tokio::select! {
                    biased;
                    // Close wins; completion precedes mutations to prevent queue starvation.
                    close = close_rx.recv(), if !closing => {
                        if let Some(reply) = close {
                            close_replies.push(reply);
                        }
                        rx.close();
                        if store.is_none() {
                            reject_queued_mutations(&mut rx);
                        }
                        closing = true;
                    }
                    Some(res) = done_rx.recv(), if publishing => {
                        publishing = false;
                        absorb_publish_result(
                            res,
                            &mut retry,
                            &mut store,
                            &mut lock,
                            &mut mutations_since_publish,
                            &retirements,
                            &retire_tx,
                            &settled_tx,
                        );
                        try_start_publish(
                            &mut publishing,
                            &mut retry,
                            &store,
                            &mut mutations_since_publish,
                            &publish,
                            &done_tx,
                        ).await;
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
                        ).await;
                    }
                    op = rx.recv(), if !closing || store.is_some() => match op {
                        None => {
                            // All senders dropped without an explicit Close
                            // (test-only path): run the same drain/flush flow.
                            closing = true;
                        }
                        Some(Op::Mutate { apply, ack }) => {
                            // Clean snapshot: lock + re-read, so external
                            // whole-file writes are seen and no CLI
                            // transaction can interleave between this load
                            // and its publish. Lock wait and load run on the
                            // blocking pool; ops buffer in the channel.
                            if store.is_none() {
                                let load_path = path.clone();
                                let load_started = load_started.take();
                                let load = crate::workers::run_fallible_blocking(move || {
                                    if let Some(started) = load_started {
                                        let _ = started.send(());
                                    }
                                    let lock = PathLock::acquire_bounded(&load_path, lock_wait)?;
                                    let store = BridgeStore::load(load_path.clone())?;
                                    Ok::<(PathLock, BridgeStore), anyhow::Error>((lock, store))
                                });
                                // Cancelling this receiver does not cancel the registered blocking job.
                                // Its eventual (lock, store) result is dropped if no receiver remains.
                                let loaded = tokio::select! {
                                    biased;
                                    close = close_rx.recv() => {
                                        if let Some(reply) = close {
                                            close_replies.push(reply);
                                        }
                                        rx.close();
                                        let _ = ack.send(Err(anyhow!(
                                            "bridge store writer is closing before applying the mutation"
                                        )));
                                        closing = true;
                                        continue;
                                    }
                                    result = load => result,
                                };
                                match loaded {
                                    Ok(Ok((acquired, loaded))) => {
                                        lock = Some(acquired);
                                        store = Some(Arc::new(loaded));
                                    }
                                    Ok(Err(error)) => {
                                        // Never apply to, or publish from, a
                                        // snapshot we failed to load. A busy
                                        // lock is also unapplied; the caller
                                        // can retry with its mutation intact.
                                        warn!(error = %error, path = %path.display(), "bridge health store unavailable; keeping the caller's data queued");
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
                            absorb_mutation(
                                apply, ack, &mut store, &mut retry, &mut publishing,
                                &mut mutations_since_publish, &publish, &done_tx,
                                &retirements, &retire_tx, &path,
                            ).await;
                        }
                    },
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
                        ).await;
                    }
                }
            }
        };
        #[cfg(any(test, feature = "test-seams"))]
        let handle = tokio::spawn(async move {
            match registry {
                Some(registry) => registry.scope(actor).await,
                None => actor.await,
            }
        });
        #[cfg(not(any(test, feature = "test-seams")))]
        let handle = tokio::spawn(actor);
        Self {
            tx,
            close_tx,
            path,
            actor: Arc::new(tokio::sync::Mutex::new(ActorState {
                handle: Some(handle),
                close_requested: false,
            })),
            #[cfg(test)]
            retirements,
            #[cfg(any(test, feature = "test-seams"))]
            settled: settled_rx,
            #[cfg(test)]
            retire_settled: retire_rx,
        }
    }
}

/// Apply one mutation to the loaded snapshot off the async worker, ack it,
/// and offer a publish. A panicking closure destroys only its private copy
/// (TS5-06): `store` keeps all earlier acknowledged mutations.
#[allow(clippy::too_many_arguments)]
async fn absorb_mutation(
    apply: MutateFn,
    ack: oneshot::Sender<Result<()>>,
    store: &mut Option<Arc<BridgeStore>>,
    retry: &mut RetryState,
    publishing: &mut bool,
    mutations_since_publish: &mut u32,
    publish: &Publisher,
    done_tx: &mpsc::Sender<crate::workers::Delivery<()>>,
    retirements: &RetirementLog,
    retire_signal: &RetireSignal,
    path: &Path,
) {
    let cloned = store.clone().expect("loaded snapshot is present");
    match crate::workers::run_tracked_blocking(move || {
        let mut owned = cloned;
        apply(Arc::make_mut(&mut owned));
        owned
    })
    .await
    {
        Ok(owned) => {
            // TS6-04: retire the old Arc on the blocking pool, not inline.
            drop_off_worker(
                store.replace(owned),
                Arc::clone(retirements),
                retire_signal.clone(),
            );
            // Ack the absorption before publishing: the disk write is the actor's problem now.
            let _ = ack.send(Ok(()));
            retry.dirty = true;
            *mutations_since_publish += 1;
            try_start_publish(
                publishing,
                retry,
                store,
                mutations_since_publish,
                publish,
                done_tx,
            )
            .await;
        }
        Err(join_error) => {
            warn!(
                error = %join_error,
                path = %path.display(),
                "bridge health store mutation task panicked",
            );
            let _ = ack.send(Err(anyhow!(
                "bridge health store mutation task panicked: {join_error}"
            )));
        }
    }
}

fn reject_queued_mutations(rx: &mut mpsc::Receiver<Op>) {
    while let Ok(op) = rx.try_recv() {
        match op {
            Op::Mutate { ack, .. } => {
                let _ = ack.send(Err(anyhow!(
                    "bridge store writer is closing before applying the mutation"
                )));
            }
        }
    }
}

/// Publish-completion bookkeeping shared by the normal loop, the close drain
/// and (indirectly, via [`RetryState`]) the final flush: on success reset the
/// retry state, dropping the snapshot only when no tail mutations were
/// absorbed during the save (clean state ⇒ the next op re-reads the file);
/// on failure retain the snapshot and arm the backoff.
#[allow(clippy::too_many_arguments)]
fn absorb_publish_result(
    res: crate::workers::Delivery<()>,
    retry: &mut RetryState,
    store: &mut Option<Arc<BridgeStore>>,
    lock: &mut Option<PathLock>,
    mutations_since_publish: &mut u32,
    retirements: &RetirementLog,
    retire_signal: &RetireSignal,
    settled: &SettleSignal,
) {
    match res.absorb() {
        Ok(()) => {
            let routine = *mutations_since_publish == 0;
            retry.record_success();
            if routine {
                debug_assert!(!retry.dirty);
                // Clean again: retire the snapshot (next op re-reads the
                // file) and release the lock with it — a waiting CLI may now
                // build on what was just published. Arc drop off-worker;
                // unlock is a cheap syscall, stays inline.
                drop_off_worker(store.take(), Arc::clone(retirements), retire_signal.clone());
                drop(lock.take());
                // Settle seam: everything published so far is on disk and
                // the actor's snapshot is retired (next op re-reads the
                // file), so tests may reload and assert deterministically.
                #[cfg(any(test, feature = "test-seams"))]
                settled.send_modify(|epoch| *epoch += 1);
                #[cfg(not(any(test, feature = "test-seams")))]
                let _ = settled;
            } else {
                // Mutations absorbed while the save ran stay dirty; the
                // caller starts the coalesced follow-up publish (and the
                // lock stays held — the follow-up is part of the same
                // read-modify-write window).
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
async fn try_start_publish(
    publishing: &mut bool,
    retry: &mut RetryState,
    store: &Option<Arc<BridgeStore>>,
    mutations_since_publish: &mut u32,
    publish: &Publisher,
    done_tx: &mpsc::Sender<crate::workers::Delivery<()>>,
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
    // Сохраняем задачу независимо от ожидания актора; панику публикации
    // считаем ошибкой, чтобы изменённый снимок можно было отправить повторно.
    match crate::workers::spawn_blocking_with_failure(move |failure| {
        let delivery =
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| publish(&snapshot))) {
                Ok(result) => crate::workers::Delivery::new(result, failure),
                Err(payload) => crate::workers::Delivery::panic(
                    Err(anyhow::Error::new(PublisherPanic::new(payload))),
                    failure,
                ),
            };
        // При закрытом приёмнике ошибка остаётся в реестре.
        let _ = done_tx.blocking_send(delivery);
    })
    .await
    {
        Ok(_receiver) => {
            *publishing = true;
            *mutations_since_publish = 0;
        }
        Err(error) => retry.record_failure(&error),
    }
}

/// Process-wide writer slot. Unlike a `OnceLock`, [`close_global`] empties
/// the slot, so a restarted engine in the same process gets a fresh writer
/// instead of a closed one.
///
/// The mutex guards only slot bookkeeping and is never held across an
/// `.await`. Race contract:
/// * `init_global` spawns only in `Idle`, under the lock — two racing inits
///   cannot create two writers.
/// * `close_global` claims `Active -> Closing` under the lock, then closes
///   on a dedicated task; while `Closing`, `init_global` hands back the
///   writer being closed instead of spawning a second live writer, and a
///   second `close_global` gets `None`.
/// * The closing task empties the slot (`Closing -> Idle`) as soon as the
///   close completes, so the slot never keeps referencing a closed writer.
#[path = "bridge_maintenance/workers/run_writer.rs"]
mod run_writer;
#[cfg(any(test, feature = "test-seams"))]
pub use run_writer::run_is_idle;
use run_writer::Slot;
/// Run-scoped slot used by the SDK server (one writer per server run).
pub use run_writer::{close_run, init_run};
static WRITER: Mutex<Slot> = Mutex::new(Slot::Idle);

/// Serializes the tests that drive the process-global writer slot.
#[cfg(test)]
pub(crate) static GLOBAL_WRITER_TEST_LOCK: tokio::sync::Mutex<()> =
    tokio::sync::Mutex::const_new(());

/// Start the process-wide store writer. Angel startup calls this once,
/// before any task that writes the store. A second call returns the
/// existing writer; while a close started by [`close_global`] is still
/// finishing, that writer is the one being closed — spawning a second live
/// writer would break the single-writer contract. After a close completes
/// the next call starts a fresh writer, so an engine restarted in the same
/// process does not inherit a dead one.
///
/// Contract (RT-0): one live writer per process; the close empties the slot.
pub fn init_global(config_path: &Path) -> StoreWriter {
    let resolved = BridgeStore::resolve_path(config_path);
    let mut slot = WRITER.lock().unwrap_or_else(|error| error.into_inner());
    let writer = match &*slot {
        Slot::Active(writer) | Slot::Closing(writer) => Some(writer.clone()),
        Slot::Idle => None,
    };
    match writer {
        Some(writer) => {
            if writer.path() != resolved {
                warn!(
                    configured = %resolved.display(),
                    active = %writer.path().display(),
                    "bridge store writer already started for a different path; keeping the original"
                );
            }
            writer
        }
        None => {
            let writer = StoreWriter::open(config_path);
            *slot = Slot::Active(writer.clone());
            writer
        }
    }
}

/// Свободен ли процессный слот писателя: нет ни живого, ни закрываемого.
#[cfg(any(test, feature = "test-seams"))]
pub fn global_is_idle() -> bool {
    matches!(
        &*WRITER.lock().unwrap_or_else(|error| error.into_inner()),
        Slot::Idle
    )
}

/// The process writer, if one exists (live, or still finishing a close).
fn global() -> Option<StoreWriter> {
    match &*WRITER.lock().unwrap_or_else(|error| error.into_inner()) {
        Slot::Active(writer) | Slot::Closing(writer) => Some(writer.clone()),
        Slot::Idle => None,
    }
}

/// Close the process-wide store writer at server shutdown, after the
/// producer tasks have stopped: waits for the in-flight publish, flushes any
/// retained snapshot and joins the actor. Returns `None` when no writer is
/// running — none was started (CLI subcommands, tests), one already
/// stopped, or another caller owns the in-progress close. The close always
/// finishes and empties the slot, even if the caller is cancelled.
pub async fn close_global() -> Option<Result<()>> {
    let writer = {
        let mut slot = WRITER.lock().unwrap_or_else(|error| error.into_inner());
        let Slot::Active(writer) = &*slot else {
            // Idle: nothing was started (or it already stopped); Closing:
            // another caller owns the in-progress close.
            return None;
        };
        let writer = writer.clone();
        *slot = Slot::Closing(writer.clone());
        writer
    };
    // Close on a dedicated task: the claim above is synchronous, so a
    // cancelled caller can never strand the slot in `Closing` — the spawned
    // close always runs to completion and empties the slot. On cancellation
    // the handle is dropped and the task detaches: fire-and-forget on
    // purpose, the close itself must still finish.
    let joined = tokio::spawn(async move {
        let result = writer.close().await;
        let mut slot = WRITER.lock().unwrap_or_else(|error| error.into_inner());
        if matches!(&*slot, Slot::Closing(_)) {
            *slot = Slot::Idle;
        }
        result
    })
    .await;
    match joined {
        Ok(result) => Some(result),
        Err(join_error) => {
            // The close task died before emptying the slot; release it so a
            // later init can start a fresh writer.
            let mut slot = WRITER.lock().unwrap_or_else(|error| error.into_inner());
            if matches!(&*slot, Slot::Closing(_)) {
                *slot = Slot::Idle;
            }
            Some(Err(anyhow!(
                "bridge store writer close task panicked: {join_error}"
            )))
        }
    }
}

/// Apply a mutation through the single writer for `config_path` (the
/// server-run writer takes precedence over the app's global writer);
/// otherwise fall back to a locked whole-file RMW on the blocking pool.
pub(crate) async fn apply(
    config_path: &Path,
    apply: impl FnOnce(&mut BridgeStore) + Send + 'static,
) -> Result<()> {
    let resolved = BridgeStore::resolve_path(config_path);
    match (run_writer::run_current(), global()) {
        (Some(w), _) | (None, Some(w)) if w.path() == resolved => w.apply(apply).await,
        _ => crate::workers::run_fallible_blocking(move || {
            #[cfg(any(test, feature = "test-seams"))]
            crate::test_seams::park_if_armed(crate::test_seams::Site::PreAcquire, &resolved);
            let lock = PathLock::acquire_bounded(&resolved, CLI_LOCK_WAIT)
                .context("bridge health store write lock")?;
            let mut store = BridgeStore::load(resolved.clone())?;
            #[cfg(any(test, feature = "test-seams"))]
            crate::test_seams::park_if_armed(crate::test_seams::Site::PostLoad, &resolved);
            apply(&mut store);
            let saved = store.save();
            drop(lock);
            saved
        })
        .await
        .map_err(|join_error| anyhow!("bridge health store write task failed: {join_error}"))?,
    }
}

#[cfg(test)]
#[path = "bridge_store_writer_tests/mod.rs"]
mod tests;
