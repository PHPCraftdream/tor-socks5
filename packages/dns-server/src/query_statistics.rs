//! Payload-free DNS question statistics with bounded nonblocking ingress.
//!
//! Admission is drop-newest only when the queue is full. Slow SQL maintenance,
//! snapshot publication, or a sustained producer burst can fill this bounded
//! queue even with healthy disks; drops indicate queue pressure, not just IO errors.
//! 4096 queued messages, at most 256 events in a SQL
//! batch, and at most two leased disk generations. `Accepted` means queued,
//! NOT durable. Inspect `status()` for loss and accepted-but-unsaved counts.
//! SQL, file publication and persistent ownership run on one dedicated thread.
//! No locks cross await; the error mutex contains only a bounded diagnostic.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use anyhow::{anyhow, Result};
use hickory_proto::op::Query;
use hickory_proto::rr::Name;
use tokio::sync::{mpsc, oneshot};

#[path = "query_statistics_store.rs"]
mod store;
#[cfg(test)]
#[path = "query_statistics_tests.rs"]
mod tests;

const INGRESS_CAPACITY: usize = 4096;
const BATCH_CAPACITY: usize = 256;
const WINDOW_SECONDS: i64 = 2_592_000;
const PAGE_SIZE: usize = 128;

#[derive(Clone, Debug)]
pub(crate) struct StatisticsPaths {
    pub(crate) database: PathBuf,
    pub(crate) snapshot: PathBuf,
}

impl StatisticsPaths {
    pub(crate) fn from_cache_path(cache: &Path) -> Self {
        // Preserve non-UTF8 path components. Only the known ASCII extension is
        // replaced; unrelated extensions remain part of the stem.
        let stem = if cache.extension() == Some(std::ffi::OsStr::new("dns-cache")) {
            cache.with_extension("")
        } else {
            cache.to_path_buf()
        };
        let sibling = |suffix: &str| {
            let mut path = stem.as_os_str().to_os_string();
            path.push(suffix);
            PathBuf::from(path)
        };
        Self {
            database: sibling(".dns-query-statistics.sqlite3"),
            snapshot: sibling(".dns-popular"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecordOutcome {
    Accepted,
    DroppedFull,
    Closed,
}

#[derive(Clone, Debug)]
pub(crate) struct StatisticsStatus {
    pub(crate) accepted: u64,
    /// Cumulative events inserted at their original receipt second (including later pruned rows).
    pub(crate) saved: u64,
    /// Valid accepted receipts already outside the logical window when processed.
    pub(crate) expired: u64,
    pub(crate) dropped_full: u64,
    pub(crate) unsaved: u64,
    pub(crate) pending: u64,
    pub(crate) last_error: Option<String>,
}

#[derive(Default)]
struct Health {
    accepted: AtomicU64,
    saved: AtomicU64,
    expired: AtomicU64,
    dropped: AtomicU64,
    unsaved: AtomicU64,
    stopping: AtomicBool,
    admission: AtomicU64,
    error: Mutex<Option<String>>,
}

const ADMISSION_STOP: u64 = 1 << 63;

/// The high bit closes admission atomically with entrant registration. The
/// remaining bits count producers until both try_send and telemetry finish.
/// CAS contention retries, never drops a question. Only the dedicated store
/// thread waits for admitted producers; receive loops do not wait.
struct Admission<'a>(&'a AtomicU64);

impl<'a> Admission<'a> {
    fn enter(state: &'a AtomicU64) -> Option<Self> {
        let mut value = state.load(Ordering::Acquire);
        loop {
            if value & ADMISSION_STOP != 0 {
                return None;
            }
            // Exhaustion is impossible for live producers on addressable
            // hardware, but must not wrap into the stop bit.
            let next = value.checked_add(1).filter(|n| n & ADMISSION_STOP == 0)?;
            match state.compare_exchange_weak(value, next, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Some(Self(state)),
                Err(current) => value = current,
            }
        }
    }
}

impl Drop for Admission<'_> {
    fn drop(&mut self) {
        // Every guard owns exactly one registration; stop only sets the high
        // bit, so this cannot underflow or clear the stop bit.
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn add(counter: &AtomicU64, amount: u64) {
    // Standalone telemetry, not a publication flag. Saturation is explicit
    // rather than wraparound; durable telemetry is limited to SQLite i64.
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
        Some(n.saturating_add(amount).min(i64::MAX as u64))
    });
}

impl Health {
    fn error(&self, error: &anyhow::Error) {
        let diagnostic: String = error.to_string().chars().take(1024).collect();
        match self.error.lock() {
            Ok(mut slot) => *slot = Some(diagnostic),
            Err(_) => tracing::warn!("DNS statistics diagnostic mutex poisoned"),
        }
        // Bounded aggregate diagnostics only: no question names, payloads, or
        // error text. Concurrent totals are approximate until shutdown drains.
        let status = self.status();
        tracing::warn!(
            accepted = status.accepted,
            saved = status.saved,
            expired = status.expired,
            pending = status.pending,
            unsaved = status.unsaved,
            dropped_full = status.dropped_full,
            "DNS statistics persistence/publication failed; inspect status"
        );
    }

    fn status(&self) -> StatisticsStatus {
        let accepted = self.accepted.load(Ordering::Relaxed);
        let saved = self.saved.load(Ordering::Relaxed);
        let expired = self.expired.load(Ordering::Relaxed);
        let unsaved = self.unsaved.load(Ordering::Relaxed);
        StatisticsStatus {
            accepted,
            saved,
            expired,
            dropped_full: self.dropped.load(Ordering::Relaxed),
            unsaved,
            pending: accepted
                .saturating_sub(saved)
                .saturating_sub(expired)
                .saturating_sub(unsaved),
            last_error: match self.error.lock() {
                Ok(slot) => slot.clone(),
                Err(_) => Some("statistics diagnostic mutex poisoned".into()),
            },
        }
    }
}

#[derive(Clone)]
pub(crate) struct QueryStatistics {
    tx: mpsc::Sender<Command>,
    health: Arc<Health>,
}

impl QueryStatistics {
    /// Nonawaiting, no IO. Stores only normalized question and UTC second.
    pub(crate) fn record(&self, question: &Query) -> RecordOutcome {
        self.record_at(question, time::OffsetDateTime::now_utc().unix_timestamp())
    }

    fn record_at(&self, question: &Query, second: i64) -> RecordOutcome {
        if self.health.stopping.load(Ordering::Acquire) {
            return RecordOutcome::Closed;
        }
        let event = Event {
            domain: normalized_name(question.name()),
            rr_type: u16::from(question.query_type()),
            class: u16::from(question.query_class()),
            second,
        };
        let Some(_admission) = Admission::enter(&self.health.admission) else {
            return RecordOutcome::Closed;
        };
        match self.tx.try_send(Command::Record(event)) {
            Ok(()) => {
                add(&self.health.accepted, 1);
                RecordOutcome::Accepted
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                add(&self.health.dropped, 1);
                RecordOutcome::DroppedFull
            }
            Err(mpsc::error::TrySendError::Closed(_)) => RecordOutcome::Closed,
        }
    }

    /// Approximate concurrent telemetry; final shutdown makes it stable.
    /// `unsaved` counts irrevocably discarded accepted events, not pending work.
    pub(crate) fn status(&self) -> StatisticsStatus {
        self.health.status()
    }
}

fn normalized_name(name: &Name) -> String {
    let mut name = name.to_lowercase();
    name.set_fqdn(true);
    name.to_ascii()
}

struct Event {
    domain: String,
    rr_type: u16,
    class: u16,
    second: i64,
}

enum Command {
    Record(Event),
    Refresh(oneshot::Sender<Result<PopularSnapshot>>),
    Page {
        lease: Arc<GenerationLease>,
        after: Option<PopularCursor>,
        reply: oneshot::Sender<Result<Vec<PopularTarget>>>,
    },
    Wake,
}

struct GenerationLease {
    generation: i64,
    tx: mpsc::Sender<Command>,
}

/// Immutable disk generation, not a vector of all popular questions. Clones
/// share one lease. Paging after worker shutdown returns an error. Drop old
/// snapshots before refreshing when two generations are already leased.
#[derive(Clone)]
pub(crate) struct PopularSnapshot {
    pub(crate) generation: i64,
    lease: Arc<GenerationLease>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PopularCursor {
    domain: String,
    rr_type: u16,
    class: u16,
}

#[derive(Clone, Debug)]
pub(crate) struct PopularTarget {
    pub(crate) question: Query,
    /// Window count for this type/class tuple (not the domain total).
    pub(crate) count: u64,
}

impl PopularTarget {
    pub(crate) fn cursor(&self) -> PopularCursor {
        PopularCursor {
            domain: normalized_name(self.question.name()),
            rr_type: u16::from(self.question.query_type()),
            class: u16::from(self.question.query_class()),
        }
    }
}

impl PopularSnapshot {
    /// Ordered by (normalized name BINARY, numeric type, numeric class), max128.
    /// cancel-safe: yes — cancelling admission sends nothing; after admission
    /// a discarded read-only reply is no longer wanted and changes no ledger.
    pub(crate) async fn page(&self, after: Option<PopularCursor>) -> Result<Vec<PopularTarget>> {
        let (reply, receive) = oneshot::channel();
        self.lease
            .tx
            .send(Command::Page {
                lease: self.lease.clone(),
                after,
                reply,
            })
            .await
            .map_err(|_| anyhow!("statistics worker closed"))?;
        receive
            .await
            .map_err(|_| anyhow!("statistics worker lost page reply"))?
    }
}

#[must_use = "call shutdown().await to flush accepted statistics and join the thread"]
pub(crate) struct StatisticsWorker {
    tx: mpsc::Sender<Command>,
    health: Arc<Health>,
    done: Option<oneshot::Receiver<Result<()>>>,
    thread: Option<JoinHandle<()>>,
}

impl StatisticsWorker {
    /// cancel-safe: NO — once started, open owns a live thread. Cancellation
    /// drops the worker guard, signalling close-and-drain (without awaiting it).
    pub(crate) async fn open(paths: StatisticsPaths) -> Result<(QueryStatistics, Self)> {
        let (tx, rx) = mpsc::channel(INGRESS_CAPACITY);
        let health = Arc::new(Health::default());
        let (ready, receive) = oneshot::channel();
        let (done, finished) = oneshot::channel();
        let thread_health = health.clone();
        let thread_tx = tx.downgrade();
        let thread = std::thread::Builder::new()
            .name("dns-statistics".into())
            .spawn(move || {
                store::run(paths, rx, thread_tx, thread_health, ready, done);
            })?;
        let mut worker = Self {
            tx: tx.clone(),
            health: health.clone(),
            done: Some(finished),
            thread: Some(thread),
        };
        match receive
            .await
            .map_err(|_| anyhow!("statistics startup thread failed"))?
        {
            Ok(()) => Ok((QueryStatistics { tx, health }, worker)),
            Err(error) => {
                let _shutdown = worker.finish().await;
                Err(error)
            }
        }
    }

    /// FIFO barrier: every previously admitted event is processed before
    /// generation creation. No retry loop; a latched SQL failure returns Err.
    /// cancel-safe: NO — after admission refresh can commit a generation and
    /// publish the file even if its receiver is cancelled; retry is a new refresh.
    pub(crate) async fn refresh(&mut self) -> Result<PopularSnapshot> {
        let (reply, receive) = oneshot::channel();
        self.tx
            .send(Command::Refresh(reply))
            .await
            .map_err(|_| anyhow!("statistics worker closed"))?;
        receive
            .await
            .map_err(|_| anyhow!("statistics worker lost refresh reply"))?
    }

    /// Close ingress, drain accepted work even with retained sender clones,
    /// perform a final refresh, and join off the async worker thread.
    /// cancel-safe: NO — consuming shutdown cancellation still signals drain,
    /// but caller loses the final flush/join result. Await without a timeout.
    pub(crate) async fn shutdown(mut self) -> Result<()> {
        self.finish().await
    }

    async fn finish(&mut self) -> Result<()> {
        self.signal_stop();
        let result = match self.done.take() {
            Some(done) => match done.await {
                Ok(result) => result,
                Err(_) => Err(anyhow!("statistics thread failed")),
            },
            None => Ok(()),
        };
        if let Some(thread) = self.thread.take() {
            tokio::task::spawn_blocking(move || {
                thread
                    .join()
                    .map_err(|_| anyhow!("statistics thread panicked"))
            })
            .await??;
        }
        result
    }

    fn signal_stop(&self) {
        self.health
            .admission
            .fetch_or(ADMISSION_STOP, Ordering::AcqRel);
        self.health.stopping.store(true, Ordering::Release);
        // If full, queued work wakes the thread; if empty, Wake does. If closed
        // it already stopped. This closes idle/full races without blocking Drop.
        let _ = self.tx.try_send(Command::Wake);
    }
}

impl Drop for StatisticsWorker {
    fn drop(&mut self) {
        self.signal_stop();
        // Synchronous fallback only. Intentional detach: dedicated thread
        // observes stop, closes its receiver and drains its finite backlog.
        // Explicit shutdown is required to observe durability and join errors.
    }
}
