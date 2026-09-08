//! Single writer for the bridge health store (`<config>.alive-bridges.log`).
//!
//! Concurrency contract (fixes the P1 racing-writes finding in
//! docs/stability-review-2026-09-08.md §1):
//!
//! * Daemon: exactly one actor task owns every publish. Writers send a
//!   mutation through an mpsc channel; the actor applies mutations one at a
//!   time to its authoritative in-memory snapshot, so two background tasks
//!   (maintenance observation drain, channel warmer, circuit verifier,
//!   startup probe rounds, channel fallback) can no longer overwrite each
//!   other's read-modify-write updates. An update is acknowledged only after
//!   the owner has applied it to memory.
//! * When the in-memory snapshot is clean, the actor re-reads the file
//!   before applying the next mutation, so whole-file writes made by other
//!   processes in the meantime (e.g. `tor-socks5 bridges fetch` running as a
//!   separate CLI process) are seen and preserved.
//! * When a publish fails, the mutated snapshot is retained in memory and
//!   retried with exponential backoff (1s doubling, 30s cap); each failure
//!   is logged at warn with the attempt number, recovery at info. Absorbed
//!   updates are never dropped because the disk write failed.
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
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{anyhow, Result};
use bridge_store::BridgeStore;
use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn};

type MutateFn = Box<dyn FnOnce(&mut BridgeStore) + Send>;
/// Publishing strategy; production uses `BridgeStore::save`, tests inject failures.
type Publisher = Arc<dyn Fn(&BridgeStore) -> Result<()> + Send + Sync>;

struct Op {
    apply: MutateFn,
    ack: oneshot::Sender<Result<()>>,
}

const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub(crate) struct StoreWriter {
    tx: mpsc::Sender<Op>,
    path: PathBuf,
}

/// What the actor loop does after a mutation has been absorbed (or on a
/// retry tick): publish the snapshot once, and on failure retain it while
/// arming the exponential-backoff retry timer.
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

    /// Publish once; on success reset the retry bookkeeping, on failure arm
    /// the next retry. Returns the error on failure for logging by the caller.
    fn publish_once(&mut self, snapshot: &BridgeStore, publish: &Publisher) -> Result<()> {
        match publish(snapshot) {
            Ok(()) => {
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
                Ok(())
            }
            Err(error) => {
                self.failed_attempts += 1;
                warn!(
                    error = %error,
                    attempt = self.failed_attempts,
                    retry_in = ?self.backoff,
                    "bridge health store publish failed; update retained in memory and will retry"
                );
                self.retry_at = Some(tokio::time::Instant::now() + self.backoff);
                self.backoff = (self.backoff * 2).min(MAX_BACKOFF);
                Err(error)
            }
        }
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
            .send(Op {
                apply: Box::new(apply),
                ack: ack_tx,
            })
            .await
            .map_err(|_| anyhow!("bridge store writer is not running"))?;
        ack_rx
            .await
            .map_err(|_| anyhow!("bridge store writer dropped the update"))?
    }

    pub(crate) fn spawn(path: PathBuf, publish: Publisher, initial_backoff: Duration) -> Self {
        let (tx, mut rx) = mpsc::channel::<Op>(64);
        let actor_path = path.clone();
        tokio::spawn(async move {
            let path = actor_path;
            let mut retry = RetryState::new(initial_backoff);
            let mut store: Option<BridgeStore> = None;
            loop {
                // Only arm the retry branch while there is unpublished work.
                let retry_at = if retry.dirty { retry.retry_at } else { None };
                tokio::select! {
                    op = rx.recv() => match op {
                        None => {
                            if retry.dirty {
                                if let Some(snapshot) = &store {
                                    if publish_once_logged(snapshot, &publish, &mut retry).is_ok() {
                                        info!("bridge health store published on shutdown");
                                    } else {
                                        warn!("bridge health store has unpublished updates at shutdown");
                                    }
                                }
                            }
                            break;
                        }
                        Some(Op { apply, ack }) => {
                            // Clean snapshot: re-read the file so whole-file
                            // writes by other processes are seen and preserved.
                            if store.is_none() {
                                match BridgeStore::load(path.clone()) {
                                    Ok(loaded) => store = Some(loaded),
                                    Err(error) => {
                                        // Never apply to, or publish from, a snapshot we failed to load.
                                        warn!(error = %error, path = %path.display(), "bridge health store unreadable; keeping the caller's data queued");
                                        let _ = ack.send(Err(error));
                                        continue;
                                    }
                                }
                            }
                            apply(store.as_mut().expect("store loaded above"));
                            retry.dirty = true;
                            // Publish immediately; on failure the snapshot is retained and retried.
                            let snapshot = store.as_ref().expect("store loaded above");
                            let _ = publish_once_logged(snapshot, &publish, &mut retry);
                            let _ = ack.send(Ok(()));
                        }
                    },
                    _ = tokio::time::sleep_until(retry_at.unwrap_or_else(tokio::time::Instant::now)), if retry.dirty && retry_at.is_some() => {
                        if let Some(snapshot) = &store {
                            let _ = publish_once_logged(snapshot, &publish, &mut retry);
                        }
                    }
                }
            }
        });
        Self { tx, path }
    }
}

/// Thin wrapper so call sites don't discard the `Result` silently; the
/// failure logging itself lives in [`RetryState::publish_once`].
fn publish_once_logged(
    snapshot: &BridgeStore,
    publish: &Publisher,
    retry: &mut RetryState,
) -> Result<()> {
    retry.publish_once(snapshot, publish)
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
    use std::sync::Mutex;
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

        let store = reload(&path);
        assert_eq!(store.channel_ok_count(&b), 8);
        assert!(
            leftover_tmp_files(dir.path()).is_empty(),
            "no leftover temp files"
        );
    }

    #[tokio::test]
    async fn publish_failure_retains_absorbed_updates_until_next_op() {
        let dir = tempfile::tempdir().expect("tempdir");
        let b = test_bridge();
        let path = config_path(dir.path());
        seed_store(&path, &b);

        let calls = AtomicUsize::new(0);
        let publisher: Publisher = Arc::new(move |s: &BridgeStore| {
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(anyhow!("injected publish failure"))
            } else {
                s.save()
            }
        });
        let writer = StoreWriter::spawn(
            BridgeStore::resolve_path(Some(&path)),
            publisher,
            INITIAL_BACKOFF,
        );
        let b1 = b.clone();
        writer
            .apply(move |s| s.note_channel_success_at(&b1, OffsetDateTime::now_utc()))
            .await
            .expect("absorbed");
        assert_eq!(
            reload(&path).channel_ok_count(&b),
            0,
            "failed publish left the file untouched"
        );

        let b2 = b.clone();
        writer
            .apply(move |s| s.note_channel_success_at(&b2, OffsetDateTime::now_utc()))
            .await
            .expect("absorbed");
        assert_eq!(
            reload(&path).channel_ok_count(&b),
            2,
            "absorbed observation survived the failed publish"
        );
        assert!(
            leftover_tmp_files(dir.path()).is_empty(),
            "no leftover temp files"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn publish_failure_is_retried_by_the_backoff_timer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let b = test_bridge();
        let path = config_path(dir.path());
        seed_store(&path, &b);

        let calls = AtomicUsize::new(0);
        let publisher: Publisher = Arc::new(move |s: &BridgeStore| {
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(anyhow!("injected publish failure"))
            } else {
                s.save()
            }
        });
        let writer = StoreWriter::spawn(
            BridgeStore::resolve_path(Some(&path)),
            publisher,
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
        // timer, so the actor's own `sleep_until` is guaranteed to fire and
        // run to completion before this call returns.
        tokio::time::sleep(Duration::from_secs(2)).await;

        assert_eq!(
            reload(&path).channel_ok_count(&b),
            1,
            "backoff timer republished the retained snapshot"
        );
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
}
