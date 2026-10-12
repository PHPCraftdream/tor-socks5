//! Domain summaries expose count, last_seen=MAX(second), and refreshed_at.
//! At reopen a future highwater is refused without pruning history: legitimate
//! rollback and malicious metadata cannot be distinguished. Correct the clock
//! before reopening; highwater is never reset. During live rollback the trusted
//! highwater is the conservative logical UTC window end: (highwater-2592000,
//! highwater]. Wall-clock uncertainty cannot extend this window backwards.
//! Eligible trusted live receipts advance highwater and keep their original seconds.
//! Refresh uses max(previous highwater, wall UTC); restored rows never advance it.
//! Dedicated-thread transactional store. rusqlite 0.39.0 APIs were inspected
//! locally: Connection::transaction takes &mut self; commit consumes; default
//! transaction Drop rolls back (including a failed commit). All values bind.
//! SQLite signed integer overflow fails rather than converting counts to REAL.
//! A SQL write failure latches for this worker lifetime: later accepted events
//! are discarded/countable, with no per-event retry storm. Reopen to recover.
//! Snapshot IO errors do not poison a healthy SQL ledger; explicit refresh may
//! try publication again. No automatic IO retry loop is used.

use std::collections::BTreeMap;
use std::sync::Weak;
use std::time::Duration;

use hickory_proto::rr::{DNSClass, RecordType};
use persist_lock::{PathLock, TempFileGuard};
use rusqlite::{params, Connection};

use super::*;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (
 id INTEGER PRIMARY KEY CHECK(id=1),
 schema_version INTEGER NOT NULL,
 highwater INTEGER NOT NULL,
 generation INTEGER NOT NULL,
 refreshed_at INTEGER NOT NULL,
 accepted INTEGER NOT NULL,
 saved INTEGER NOT NULL,
 dropped_full INTEGER NOT NULL,
 unsaved INTEGER NOT NULL,
 invalid_restored INTEGER NOT NULL,
 last_error TEXT
);
INSERT OR IGNORE INTO meta(id,schema_version,highwater,generation,refreshed_at,
 accepted,saved,dropped_full,unsaved,invalid_restored,last_error)
 VALUES(1,1,0,0,0,0,0,0,0,0,NULL);
CREATE TABLE IF NOT EXISTS query_seconds (
 domain TEXT NOT NULL COLLATE BINARY,
 rr_type INTEGER NOT NULL,
 class INTEGER NOT NULL,
 second INTEGER NOT NULL,
 count INTEGER NOT NULL CHECK(typeof(count)='integer' AND count>0),
 PRIMARY KEY(domain,rr_type,class,second)
);
CREATE INDEX IF NOT EXISTS query_seconds_expiry ON query_seconds(second);
CREATE TABLE IF NOT EXISTS domain_summary (
 domain TEXT PRIMARY KEY COLLATE BINARY,
 count INTEGER NOT NULL CHECK(typeof(count)='integer' AND count>0),
 refreshed_at INTEGER NOT NULL,
 last_seen INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS popular_targets (
 generation INTEGER NOT NULL,
 domain TEXT NOT NULL COLLATE BINARY,
 rr_type INTEGER NOT NULL,
 class INTEGER NOT NULL,
 count INTEGER NOT NULL CHECK(typeof(count)='integer' AND count>0),
 PRIMARY KEY(generation,domain,rr_type,class)
);
";

#[derive(Default)]
struct BatchClasses {
    saved: u64,
    expired: u64,
    invalid: u64,
}

pub(super) struct Store {
    pub(super) connection: Connection,
    paths: StatisticsPaths,
    _ownership: PathLock,
    highwater: i64,
    generation: i64,
    leases: Vec<(i64, Weak<GenerationLease>)>,
    fault: Option<String>,
}

fn utc_second() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

impl Store {
    pub(super) fn open(paths: StatisticsPaths, now: i64) -> Result<Self> {
        // Operator-owned local path; not a containment boundary against a
        // hostile local user able to mutate the parent directory.
        std::fs::create_dir_all(persist_lock::parent_dir(&paths.database))?;
        let ownership = PathLock::acquire_bounded(&paths.database, Duration::from_secs(2))?;
        let mut connection = Connection::open(&paths.database)?;
        connection.busy_timeout(Duration::from_secs(2))?;
        // WAL remains locally inspectable; bounded page cache, file-backed
        // aggregate sorts (never materialize whole history/popularity in Rust).
        connection.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            PRAGMA cache_size=-2048; PRAGMA temp_store=FILE;
            PRAGMA journal_size_limit=4194304;",
        )?;
        connection.execute_batch(SCHEMA)?;
        let (version, highwater, generation, refreshed_at): (i64, i64, i64, i64) = connection
            .query_row(
                "SELECT schema_version,highwater,generation,refreshed_at FROM meta WHERE id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )?;
        if !matches!(version, 1 | 2)
            || highwater < 0
            || generation < 0
            || refreshed_at < 0
            || refreshed_at > highwater
            || time::OffsetDateTime::from_unix_timestamp(highwater).is_err()
        {
            return Err(anyhow!(
                "invalid statistics schema/highwater/generation; refusing restore"
            ));
        }
        if highwater > now {
            let diagnostic = "persisted statistics highwater is in the future; restore refused until UTC catches up";
            connection.execute("UPDATE meta SET last_error=?1 WHERE id=1", [diagnostic])?;
            return Err(anyhow!(diagnostic));
        }
        // v1 saved was cumulative processed batches, including excluded receipts.
        // Historical insertion/expiry cannot be reconstructed after pruning; retain
        // those legacy totals rather than inventing a retrospective classification.
        if version == 1 {
            let migration = connection.transaction()?;
            migration.execute_batch(
                "ALTER TABLE meta ADD COLUMN expired INTEGER NOT NULL DEFAULT 0;
                 UPDATE meta SET schema_version=2 WHERE id=1;",
            )?;
            migration.commit()?;
        }
        // Validate signed metadata before any restore pruning. Reading i64
        // requires no rusqlite fallible_uint feature; all unsigned conversion
        // and restart conservation are checked explicitly.
        let _ = restored_health(&connection)?;
        let invalid_restored: i64 =
            connection.query_row("SELECT invalid_restored FROM meta WHERE id=1", [], |row| {
                row.get(0)
            })?;
        if invalid_restored < 0 {
            return Err(anyhow!("negative restored invalid-row count"));
        }
        // Derived summaries from the initial schema can be upgraded without
        // altering original second-ledger timestamps or counts.
        let has_last_seen: i64 = connection.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('domain_summary') WHERE name='last_seen'",
            [],
            |row| row.get(0),
        )?;
        if has_last_seen == 0 {
            connection.execute_batch(
                "ALTER TABLE domain_summary ADD COLUMN last_seen INTEGER NOT NULL DEFAULT 0;
                DELETE FROM domain_summary;",
            )?;
        }
        let mut store = Self {
            connection,
            paths,
            _ownership: ownership,
            highwater: highwater.max(now),
            generation,
            leases: Vec::with_capacity(2),
            fault: None,
        };
        // No live lease can cross process restart. Generation IDs themselves
        // remain monotonic; future rows cannot advance the persisted clock.
        store
            .connection
            .execute("DELETE FROM popular_targets", [])?;
        store.validate_restore(now)?;
        store.advance(now)?;
        Ok(store)
    }

    fn validate_restore(&mut self, now: i64) -> Result<()> {
        // Keyset over rowid, only 128 restored keys resident. Bad storage types,
        // overlong names and huge values are rejected in SQL BEFORE allocation.
        let tx = self.connection.transaction()?;
        let cutoff = self.highwater.saturating_sub(WINDOW_SECONDS);
        let mut invalid = i64::try_from(tx.execute(
            "DELETE FROM query_seconds WHERE typeof(domain)!='text'
             OR length(CAST(domain AS BLOB))>1024
             OR typeof(second)!='integer' OR second<=?1 OR second>?2
             OR typeof(rr_type)!='integer' OR rr_type NOT BETWEEN 0 AND 65535
             OR typeof(class)!='integer' OR class NOT BETWEEN 0 AND 65535
             OR typeof(count)!='integer' OR count<=0",
            params![cutoff, self.highwater.min(now)],
        )?)?;
        let mut after: Option<i64> = None;
        loop {
            let mut statement = tx.prepare(
                "SELECT rowid,domain FROM query_seconds WHERE ?1 IS NULL OR rowid>?1 ORDER BY rowid LIMIT 128")?;
            let rows = statement
                .query_map([after], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            drop(statement);
            if rows.is_empty() {
                break;
            }
            for (id, domain) in rows {
                after = Some(id);
                // Noncanonical restored spelling is rejected, never merged in
                // a way that could inflate qualification or shift its timestamp.
                let valid = Name::from_ascii(&domain)
                    .ok()
                    .is_some_and(|name| normalized_name(&name) == domain);
                if !valid {
                    tx.execute("DELETE FROM query_seconds WHERE rowid=?1", [id])?;
                    invalid = invalid
                        .checked_add(1)
                        .ok_or_else(|| anyhow!("invalid count overflow"))?;
                }
            }
        }
        tx.execute("UPDATE meta SET invalid_restored=invalid_restored+?1,
            last_error=CASE WHEN ?1>0 THEN 'discarded invalid/expired restored rows' ELSE last_error END
            WHERE id=1", [invalid])?;
        tx.commit()?;
        Ok(())
    }

    fn advance(&mut self, now: i64) -> Result<()> {
        let highwater = self.highwater.max(now);
        let tx = self.connection.transaction()?;
        tx.execute(
            "DELETE FROM query_seconds WHERE second<=?1 OR second>?2",
            params![highwater.saturating_sub(WINDOW_SECONDS), highwater],
        )?;
        tx.execute("UPDATE meta SET highwater=?1 WHERE id=1", [highwater])?;
        tx.commit()?;
        self.highwater = highwater;
        Ok(())
    }

    pub(super) fn batch(&mut self, events: &[Event], now: i64, health: &Health) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        let amount = u64::try_from(events.len())?;
        if let Some(fault) = &self.fault {
            add(&health.unsaved, amount);
            return Err(anyhow!(fault.clone()));
        }
        let result = self.save_batch(events, now, health);
        match result {
            Ok(classes) => {
                add(&health.saved, classes.saved);
                add(&health.expired, classes.expired);
                add(&health.unsaved, classes.invalid);
                if classes.invalid != 0 {
                    health.error(&anyhow!("discarded invalid live statistics receipts"));
                }
                Ok(())
            }
            Err(error) => {
                add(&health.unsaved, amount);
                self.fault = Some(error.to_string().chars().take(1024).collect());
                Err(error)
            }
        }
    }

    fn save_batch(&mut self, events: &[Event], now: i64, health: &Health) -> Result<BatchClasses> {
        if events.len() > BATCH_CAPACITY {
            return Err(anyhow!("statistics batch exceeds capacity"));
        }
        // Only validated live receipts carry clock authority. Restored rows take
        // the separate fail-safe validation path in open, never this path.
        let valid = |event: &Event| {
            event.second >= 0
                && time::OffsetDateTime::from_unix_timestamp(event.second).is_ok()
                && event.domain.len() <= 1024
                && Name::from_ascii(&event.domain)
                    .ok()
                    .is_some_and(|name| normalized_name(&name) == event.domain)
        };
        let highwater = events
            .iter()
            .filter(|event| valid(event))
            .fold(self.highwater.max(now), |end, event| end.max(event.second));
        let cutoff = highwater.saturating_sub(WINDOW_SECONDS);
        let mut classes = BatchClasses::default();
        // Bounded by events.len() <=256, independent of domain cardinality.
        let mut counts = BTreeMap::new();
        for event in events {
            if !valid(event) {
                classes.invalid += 1;
            } else if event.second <= cutoff {
                classes.expired += 1;
            } else {
                classes.saved += 1;
                let count = counts
                    .entry((&event.domain, event.rr_type, event.class, event.second))
                    .or_insert(0_i64);
                *count += 1; // At most BATCH_CAPACITY, not lifetime arithmetic.
            }
        }
        let tx = self.connection.transaction()?;
        tx.execute(
            "DELETE FROM query_seconds WHERE second<=?1 OR second>?2",
            params![cutoff, highwater],
        )?;
        for ((domain, rr_type, class, second), count) in counts {
            tx.execute(
                "INSERT INTO query_seconds(domain,rr_type,class,second,count)
                VALUES(?1,?2,?3,?4,?5) ON CONFLICT(domain,rr_type,class,second)
                DO UPDATE SET count=count+excluded.count",
                params![domain, rr_type, class, second, count],
            )?;
        }
        // The consumer may commit before a producer increments accepted after
        // try_send. SQL floors accepted at completed saved+expired+unsaved, including
        // this batch; it does not modify the eventual actual producer total.
        let status = health.status();
        let (saved, expired): (i64, i64) =
            tx.query_row("SELECT saved,expired FROM meta WHERE id=1", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?;
        let saved = u64::try_from(saved)?
            .checked_add(classes.saved)
            .ok_or_else(|| anyhow!("saved counter overflow"))?;
        let expired = u64::try_from(expired)?
            .checked_add(classes.expired)
            .ok_or_else(|| anyhow!("expired counter overflow"))?;
        let unsaved = status
            .unsaved
            .checked_add(classes.invalid)
            .ok_or_else(|| anyhow!("unsaved counter overflow"))?;
        let (accepted, _) = restore_totals(status.accepted, saved, expired, unsaved)?;
        tx.execute(
            "UPDATE meta SET highwater=?1,saved=?2,expired=?3,
            accepted=?4,dropped_full=?5,unsaved=?6,
            last_error=CASE WHEN ?7>0 THEN 'discarded invalid live statistics receipts' ELSE last_error END
            WHERE id=1",
            params![highwater, i64::try_from(saved)?, i64::try_from(expired)?,
                i64::try_from(accepted)?, i64::try_from(status.dropped_full)?,
                i64::try_from(unsaved)?, i64::try_from(classes.invalid)?],
        )?;
        tx.commit()?;
        self.highwater = highwater;
        Ok(classes)
    }

    fn prune_generations(&mut self) -> Result<()> {
        // Weak::upgrade pins while inspecting, not a strong_count TOCTOU.
        let mut retained = Vec::with_capacity(2);
        for (generation, lease) in &self.leases {
            if let Some(live) = lease.upgrade() {
                retained.push((*generation, Arc::downgrade(&live)));
            } else {
                self.connection.execute(
                    "DELETE FROM popular_targets WHERE generation=?1",
                    [generation],
                )?;
            }
        }
        self.leases = retained;
        Ok(())
    }

    pub(super) fn refresh(
        &mut self,
        now: i64,
        tx: &mpsc::WeakSender<Command>,
        health: &Health,
        final_refresh: bool,
    ) -> Result<Option<PopularSnapshot>> {
        if let Some(fault) = &self.fault {
            return Err(anyhow!(fault.clone()));
        }
        self.prune_generations()?;
        if !final_refresh && self.leases.len() >= 2 {
            return Err(anyhow!(
                "two statistics generations still leased; release old snapshot before refresh"
            ));
        }
        self.advance(now)?;
        let generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| anyhow!("generation exhausted"))?;
        let transaction = self.connection.transaction()?;
        transaction.execute("DELETE FROM domain_summary", [])?;
        transaction.execute(
            "INSERT INTO domain_summary(domain,count,refreshed_at,last_seen)
            SELECT domain,SUM(count),?1,MAX(second) FROM query_seconds GROUP BY domain",
            [self.highwater],
        )?;
        if !final_refresh {
            transaction.execute(
                "INSERT INTO popular_targets
                SELECT ?1,q.domain,q.rr_type,q.class,SUM(q.count)
                FROM query_seconds q JOIN domain_summary d ON d.domain=q.domain
                WHERE d.count>100 GROUP BY q.domain,q.rr_type,q.class",
                [generation],
            )?;
        }
        let status = health.status();
        let accepted = completed_floor(&transaction, &status)?;
        transaction.execute(
            "UPDATE meta SET generation=?1,refreshed_at=?2,accepted=?3,
            dropped_full=?4,unsaved=?5,last_error=?6 WHERE id=1",
            params![
                generation,
                self.highwater,
                i64::try_from(accepted)?,
                i64::try_from(status.dropped_full)?,
                i64::try_from(status.unsaved)?,
                status.last_error
            ],
        )?;
        transaction.commit()?;
        self.generation = generation;
        // Publish AFTER the SQL commit; DB/file cannot be one transaction.
        // On publication error DB remains authoritative, old file is preserved
        // until rename (a directory-fsync failure may mean rename succeeded).
        if let Err(error) = self.publish() {
            // No lease was returned. Remove this unobservable generation so
            // repeated file errors cannot accumulate popular sets on disk.
            self.connection.execute(
                "DELETE FROM popular_targets WHERE generation=?1",
                [generation],
            )?;
            return Err(error);
        }
        if final_refresh {
            return Ok(None);
        }
        let tx = tx
            .upgrade()
            .ok_or_else(|| anyhow!("statistics owner closed"))?;
        let lease = Arc::new(GenerationLease { generation, tx });
        self.leases.push((generation, Arc::downgrade(&lease)));
        Ok(Some(PopularSnapshot { generation, lease }))
    }

    pub(super) fn publish(&self) -> Result<()> {
        let mut temp =
            TempFileGuard::create(&self.paths.snapshot, u64::try_from(self.generation)?)?;
        temp.write_all(b"domain\tcount\trefreshed_at\n")?;
        let mut statement = self.connection.prepare(
            "SELECT domain,count,refreshed_at FROM domain_summary WHERE count>100 ORDER BY domain COLLATE BINARY")?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let domain: String = row.get(0)?;
            let count: i64 = row.get(1)?;
            let second: i64 = row.get(2)?;
            let stamp = time::OffsetDateTime::from_unix_timestamp(second)?
                .format(&time::format_description::well_known::Rfc3339)?;
            temp.write_all(format!("{domain}\t{count}\t{stamp}\n").as_bytes())?;
        }
        temp.finish()?;
        Ok(())
    }

    fn page(&self, generation: i64, after: Option<PopularCursor>) -> Result<Vec<PopularTarget>> {
        let cursor = after.unwrap_or(PopularCursor {
            domain: String::new(),
            rr_type: 0,
            class: 0,
        });
        let mut statement = self.connection.prepare(
            "SELECT domain,rr_type,class,count
            FROM popular_targets WHERE generation=?1 AND (domain,rr_type,class)>(?2,?3,?4)
            ORDER BY domain COLLATE BINARY,rr_type,class LIMIT 128",
        )?;
        let mut rows = statement.query(params![
            generation,
            cursor.domain,
            cursor.rr_type,
            cursor.class
        ])?;
        let mut targets = Vec::with_capacity(PAGE_SIZE);
        while let Some(row) = rows.next()? {
            let domain: String = row.get(0)?;
            let rr_type: u16 = row.get(1)?;
            let class: u16 = row.get(2)?;
            let count: i64 = row.get(3)?;
            let mut question = Query::query(Name::from_ascii(domain)?, RecordType::from(rr_type));
            question.set_query_class(DNSClass::from(class));
            targets.push(PopularTarget {
                question,
                count: u64::try_from(count)?,
            });
        }
        Ok(targets)
    }

    pub(super) fn persist_health(&self, health: &Health) -> Result<()> {
        let status = health.status();
        let accepted = completed_floor(&self.connection, &status)?;
        self.connection.execute(
            "UPDATE meta SET accepted=?1,dropped_full=?2,unsaved=?3,last_error=?4 WHERE id=1",
            params![
                i64::try_from(accepted)?,
                i64::try_from(status.dropped_full)?,
                i64::try_from(status.unsaved)?,
                status.last_error
            ],
        )?;
        Ok(())
    }
}

fn completed_floor(connection: &Connection, status: &StatisticsStatus) -> Result<u64> {
    let (saved, expired): (i64, i64) =
        connection.query_row("SELECT saved,expired FROM meta WHERE id=1", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;
    let (accepted, _) = restore_totals(
        status.accepted,
        u64::try_from(saved)?,
        u64::try_from(expired)?,
        status.unsaved,
    )?;
    Ok(accepted)
}

/// Pending accepted work cannot survive process restart. Existing unsaved is
/// already part of accepted-saved-expired, not an additional loss to add again. The
/// accepted floor also covers a commit observed before producer accounting.
/// Reject sums outside SQLite's signed counter range rather than wrapping.
pub(super) fn restore_totals(
    accepted: u64,
    saved: u64,
    expired: u64,
    unsaved: u64,
) -> Result<(u64, u64)> {
    let completed = saved
        .checked_add(expired)
        .and_then(|n| n.checked_add(unsaved))
        .filter(|n| *n <= i64::MAX as u64)
        .ok_or_else(|| anyhow!("statistics restored telemetry exceeds signed counter range"))?;
    let accepted = accepted.max(completed);
    Ok((accepted, accepted - saved - expired))
}

fn restored_health(connection: &Connection) -> Result<(u64, u64, u64, u64, u64, Option<String>)> {
    let (accepted, saved, dropped, unsaved, error, expired) = connection.query_row(
        "SELECT accepted,saved,dropped_full,unsaved,substr(last_error,1,1024),expired FROM meta WHERE id=1",
        [],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, i64>(5)?,
            ))
        },
    )?;
    let accepted = u64::try_from(accepted)?;
    let saved = u64::try_from(saved)?;
    let dropped = u64::try_from(dropped)?;
    let unsaved = u64::try_from(unsaved)?;
    let expired = u64::try_from(expired)?;
    let (accepted, unsaved) = restore_totals(accepted, saved, expired, unsaved)?;
    Ok((accepted, saved, dropped, unsaved, expired, error))
}

pub(super) fn run(
    paths: StatisticsPaths,
    rx: mpsc::Receiver<Command>,
    tx: mpsc::WeakSender<Command>,
    health: Arc<Health>,
    ready: oneshot::Sender<Result<()>>,
    done: oneshot::Sender<Result<()>>,
) {
    run_with_clock(paths, rx, tx, health, ready, done, utc_second);
}

// Instance-local clock injection exercises the real collector and accounting.
pub(super) fn run_with_clock(
    paths: StatisticsPaths,
    mut rx: mpsc::Receiver<Command>,
    tx: mpsc::WeakSender<Command>,
    health: Arc<Health>,
    ready: oneshot::Sender<Result<()>>,
    done: oneshot::Sender<Result<()>>,
    mut clock: impl FnMut() -> i64,
) {
    let mut store = match Store::open(paths, clock()) {
        Ok(store) => store,
        Err(error) => {
            health.error(&error);
            // Cancelled startup no longer wants the reply; thread exits.
            let _ = ready.send(Err(error));
            let _ = done.send(Err(anyhow!("statistics store could not open")));
            return;
        }
    };
    // Session counters start at persisted totals; highwater is independently
    // persisted in each ledger transaction and cannot regress on rollback.
    let restored = restored_health(&store.connection);
    match restored {
        Ok((accepted, saved, dropped, unsaved, expired, error)) => {
            health.accepted.store(accepted, Ordering::Relaxed);
            health.saved.store(saved, Ordering::Relaxed);
            health.expired.store(expired, Ordering::Relaxed);
            health.dropped.store(dropped, Ordering::Relaxed);
            // A process crash can leave admitted-but-not-durable totals.
            health.unsaved.store(unsaved, Ordering::Relaxed);
            if let Ok(mut slot) = health.error.lock() {
                *slot = error;
            }
        }
        Err(error) => {
            let error = anyhow!(error);
            health.error(&error);
            let _ = ready.send(Err(error));
            let _ = done.send(Err(anyhow!("statistics metadata invalid")));
            return;
        }
    }
    // Receiver cancellation means startup abandoned, so close/drain immediately.
    if ready.send(Ok(())).is_err() {
        health.stopping.store(true, Ordering::Release);
    }
    let mut batch = Vec::with_capacity(BATCH_CAPACITY);
    let mut next = None;
    loop {
        if health.stopping.load(Ordering::Acquire) {
            // Stop registration atomically, then wait only on this dedicated
            // thread for try_send and its producer counters to complete. An
            // entrant either registered before stop (and is drained), or sees
            // the high bit and never sends. Acquire observes every guard's
            // release, so final accepted/drop telemetry cannot lag shutdown.
            health.admission.fetch_or(ADMISSION_STOP, Ordering::AcqRel);
            while health.admission.load(Ordering::Acquire) != ADMISSION_STOP {
                std::thread::park_timeout(Duration::from_millis(1));
            }
            rx.close();
        }
        let command = next.take().or_else(|| rx.blocking_recv());
        let Some(command) = command else {
            break;
        };
        match command {
            Command::Record(event) => {
                batch.push(event);
                while batch.len() < BATCH_CAPACITY {
                    match rx.try_recv() {
                        Ok(Command::Record(event)) => batch.push(event),
                        Ok(command) => {
                            next = Some(command);
                            break;
                        }
                        Err(
                            mpsc::error::TryRecvError::Empty
                            | mpsc::error::TryRecvError::Disconnected,
                        ) => break,
                    }
                }
                let already_faulted = store.fault.is_some();
                if let Err(error) = store.batch(&batch, clock(), &health) {
                    if !already_faulted {
                        health.error(&error);
                    }
                }
                batch.clear();
            }
            Command::Refresh(reply) => {
                let result = store
                    .refresh(clock(), &tx, &health, false)
                    .and_then(|snapshot| snapshot.ok_or_else(|| anyhow!("missing generation")));
                if let Err(error) = &result {
                    health.error(error);
                    // Best effort once at a barrier, never retry per event.
                    if let Err(error) = store.persist_health(&health) {
                        health.error(&error);
                    }
                }
                // Cancelled refresh no longer wants the result. Its snapshot
                // lease drops; next refresh prunes the unreferenced generation.
                let _ = reply.send(result);
            }
            Command::Page {
                lease,
                after,
                reply,
            } => {
                let result = store.page(lease.generation, after);
                if let Err(error) = &result {
                    health.error(error);
                }
                // Cancelled read no longer wants the page.
                let _ = reply.send(result);
            }
            Command::Wake => {}
        }
    }
    let result = store.refresh(clock(), &tx, &health, true).map(|_| ());
    if let Err(error) = &result {
        health.error(error);
    }
    let health_result = store.persist_health(&health);
    let result = match (result, health_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => {
            health.error(&error);
            Err(error)
        }
        (Err(error), Err(health_error)) => {
            health.error(&health_error);
            Err(error)
        }
    };
    // Result observer may have cancelled shutdown; thread still releases SQL
    // and ownership by ordinary Drop. Explicit shutdown joins this thread.
    let _ = done.send(result);
}
