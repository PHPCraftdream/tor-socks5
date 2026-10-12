//! Permanent counterfactual regressions, mounted below the defining module.
//! Oracles derive from the statistics contract, not blessed implementation output.
//! Tests deliberately use real SQLite/files; clocks and queue pressure are
//! injected deterministically, without sleeps, builds or external DNS traffic.

use std::fs;
use std::sync::atomic::AtomicUsize;

use hickory_proto::rr::{DNSClass, RecordType};
use rusqlite::{params, Connection};

use super::*;

const NOW: i64 = 1_800_000_000;

struct Fixture {
    directory: PathBuf,
    paths: StatisticsPaths,
}

impl Fixture {
    fn new() -> Self {
        static SEQUENCE: AtomicUsize = AtomicUsize::new(0);
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "dns-statistics-contract-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        let paths = StatisticsPaths::from_cache_path(&directory.join("proxy.dns-cache"));
        Self { directory, paths }
    }

    fn store(&self) -> store::Store {
        store::Store::open(self.paths.clone(), NOW).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Tests close SQL/thread resources before removing the unique fixture.
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn question(domain: &str, kind: RecordType, class: DNSClass) -> Query {
    let mut question = Query::query(Name::from_ascii(domain).unwrap(), kind);
    question.set_query_class(class);
    question
}

fn event(question: &Query, second: i64) -> Event {
    Event {
        domain: normalized_name(question.name()),
        second,
        rr_type: u16::from(question.query_type()),
        class: u16::from(question.query_class()),
    }
}

fn save(
    store: &mut store::Store,
    health: &Health,
    question: &Query,
    count: usize,
    second: i64,
    now: i64,
) {
    let mut remaining = count;
    while remaining != 0 {
        let length = remaining.min(BATCH_CAPACITY);
        let events: Vec<_> = (0..length).map(|_| event(question, second)).collect();
        add(&health.accepted, u64::try_from(events.len()).unwrap());
        store.batch(&events, now, health).unwrap();
        remaining -= length;
    }
}

fn refresh(store: &mut store::Store, now: i64, health: &Health) -> PopularSnapshot {
    let (tx, _rx) = mpsc::channel(1);
    store
        .refresh(now, &tx.downgrade(), health, false)
        .unwrap()
        .unwrap()
}

fn tuple_rows(store: &store::Store, generation: i64) -> Vec<(String, u16, u16, i64)> {
    store
        .connection
        .prepare(
            "SELECT domain,rr_type,class,count FROM popular_targets
        WHERE generation=?1 ORDER BY domain,rr_type,class",
        )
        .unwrap()
        .query_map([generation], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
}

/// Would fail with >=100, tuple-only qualification, class partitioning, or
/// aggregation that accidentally combines two different normalized domains.
#[test]
fn strict_100_101_aggregates_all_types_and_classes_per_domain() {
    let fixture = Fixture::new();
    let mut store = fixture.store();
    let health = Health::default();
    let a = question("ExAmPlE.test", RecordType::A, DNSClass::IN);
    let aaaa = question("example.test.", RecordType::AAAA, DNSClass::CH);
    let other = question("other.test", RecordType::A, DNSClass::IN);
    save(&mut store, &health, &a, 60, NOW, NOW);
    save(&mut store, &health, &aaaa, 40, NOW, NOW);
    save(&mut store, &health, &other, 100, NOW, NOW);
    let at_100 = refresh(&mut store, NOW, &health);
    assert!(tuple_rows(&store, at_100.generation).is_empty());
    drop(at_100);
    save(&mut store, &health, &aaaa, 1, NOW, NOW);
    let at_101 = refresh(&mut store, NOW, &health);
    assert_eq!(
        tuple_rows(&store, at_101.generation),
        vec![
            ("example.test.".into(), 1, 1, 60),
            ("example.test.".into(), 28, 3, 41)
        ]
    );
    let last_seen: i64 = store
        .connection
        .query_row(
            "SELECT last_seen FROM domain_summary WHERE domain='example.test.'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(last_seen, NOW);
    let text = fs::read_to_string(&fixture.paths.snapshot).unwrap();
    assert_eq!(
        text,
        "domain\tcount\trefreshed_at\nexample.test.\t101\t2027-01-15T08:00:00Z\n"
    );
}

/// Would fail with day buckets or a closed lower bound. Tests both entering
/// and leaving, retaining an older generation to detect mutable snapshot rows.
#[test]
fn exact_second_expiry_normalization_enter_leave_and_immutable_generation() {
    let fixture = Fixture::new();
    let mut store = fixture.store();
    let health = Health::default();
    let a = question("Boundary.Test", RecordType::A, DNSClass::IN);
    save(&mut store, &health, &a, 100, NOW - WINDOW_SECONDS + 1, NOW);
    save(&mut store, &health, &a, 1, NOW - WINDOW_SECONDS, NOW);
    let below = refresh(&mut store, NOW, &health);
    assert!(tuple_rows(&store, below.generation).is_empty());
    drop(below);
    save(&mut store, &health, &a, 1, NOW, NOW);
    let popular = refresh(&mut store, NOW, &health);
    assert_eq!(tuple_rows(&store, popular.generation)[0].3, 101);
    let expired = refresh(&mut store, NOW + 1, &health);
    assert!(tuple_rows(&store, expired.generation).is_empty());
    assert_eq!(tuple_rows(&store, popular.generation)[0].3, 101);
    let seconds: i64 = store
        .connection
        .query_row("SELECT COUNT(*) FROM query_seconds", [], |row| row.get(0))
        .unwrap();
    assert_eq!(seconds, 1);
    // saved is insertion history, not the current post-pruning ledger size.
    assert_eq!(health.status().accepted, 102);
    assert_eq!(health.status().saved, 101);
    assert_eq!(health.status().expired, 1);
    assert_eq!(health.status().pending, 0);
    // Two externally leased generations block a third, rather than evicting
    // a still-readable generation or retaining a silently growing disk history.
    let (tx, _rx) = mpsc::channel(1);
    assert!(store
        .refresh(NOW + 1, &tx.downgrade(), &health, false)
        .is_err());
    drop(popular);
    drop(expired);
    let final_snapshot = refresh(&mut store, NOW + 1, &health);
    let generations: i64 = store
        .connection
        .query_row(
            "SELECT COUNT(DISTINCT generation) FROM popular_targets",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(generations, 0);
    drop(final_snapshot);
}

/// Would fail if restart restamped original seconds, if future history
/// advanced highwater, or if clock rollback used wall now as the expiry base.
#[test]
fn restart_validates_corrupt_old_future_rows_and_keeps_highwater() {
    let fixture = Fixture::new();
    let mut store = fixture.store();
    let health = Health::default();
    let a = question("restart.test", RecordType::A, DNSClass::IN);
    save(&mut store, &health, &a, 101, NOW - WINDOW_SECONDS + 1, NOW);
    drop(store);
    let database = Connection::open(&fixture.paths.database).unwrap();
    database
        .execute_batch("PRAGMA ignore_check_constraints=ON")
        .unwrap();
    for (domain, second, count) in [
        ("old.test.", NOW - WINDOW_SECONDS, 200),
        ("future.test.", NOW + 1, 200),
        ("BAD.test.", NOW, 200),
        ("invalid..test.", NOW, 200),
        ("zero.test.", NOW, 0),
    ] {
        database
            .execute(
                "INSERT INTO query_seconds VALUES(?1,1,1,?2,?3)",
                params![domain, second, count],
            )
            .unwrap();
    }
    drop(database);
    assert!(store::Store::open(fixture.paths.clone(), NOW - 100).is_err());
    // Fail-loud reopen is deliberately different from trusted live rollback:
    // no restore validation/pruning occurs until wall UTC reaches highwater.
    let database = Connection::open(&fixture.paths.database).unwrap();
    let untouched: i64 = database
        .query_row("SELECT COUNT(*) FROM query_seconds", [], |r| r.get(0))
        .unwrap();
    assert_eq!(untouched, 6);
    drop(database);
    let mut restored = store::Store::open(fixture.paths.clone(), NOW).unwrap();
    let popular = refresh(&mut restored, NOW, &health);
    assert_eq!(
        tuple_rows(&restored, popular.generation),
        vec![("restart.test.".into(), 1, 1, 101)]
    );
    let highwater: i64 = restored
        .connection
        .query_row("SELECT highwater FROM meta", [], |row| row.get(0))
        .unwrap();
    assert_eq!(highwater, NOW);
    drop(popular);
    let empty = refresh(&mut restored, NOW + 1, &health);
    assert!(tuple_rows(&restored, empty.generation).is_empty());
    drop(empty);
    drop(restored);
    assert!(store::Store::open(fixture.paths.clone(), NOW - 200).is_err());
    let mut restored_again = store::Store::open(fixture.paths.clone(), NOW + 1).unwrap();
    let empty = refresh(&mut restored_again, NOW + 1, &health);
    assert!(tuple_rows(&restored_again, empty.generation).is_empty());
}

/// Refuse nonsensical or representable future metadata without resetting
/// highwater or pruning valid ledger rows. UTC must catch up before reopen.
#[test]
fn invalid_highwater_is_not_silently_reset() {
    let fixture = Fixture::new();
    drop(fixture.store());
    let database = Connection::open(&fixture.paths.database).unwrap();
    database
        .execute("UPDATE meta SET highwater=?1", [i64::MAX])
        .unwrap();
    drop(database);
    assert!(store::Store::open(fixture.paths.clone(), NOW).is_err());
}

/// Guard cleanup must not publish incomplete data over the previous snapshot.
/// Also forces a real TempFileGuard creation error, not a happy-path fake.
#[test]
fn atomic_snapshot_abandonment_and_publish_failure_preserve_old_file() {
    let fixture = Fixture::new();
    let mut store = fixture.store();
    let health = Health::default();
    let a = question("atomic.test", RecordType::A, DNSClass::IN);
    save(&mut store, &health, &a, 101, NOW, NOW);
    let snapshot = refresh(&mut store, NOW, &health);
    let old = fs::read(&fixture.paths.snapshot).unwrap();
    {
        let mut abandoned =
            persist_lock::TempFileGuard::create(&fixture.paths.snapshot, 999).unwrap();
        abandoned.write_all(b"partial and incorrect").unwrap();
    }
    assert_eq!(fs::read(&fixture.paths.snapshot).unwrap(), old);
    // A file at the parent location forces create failure and leaves the real
    // published snapshot unchanged. Restore paths by moving the store itself.
    let blocker = fixture.directory.join("not-a-directory");
    fs::write(&blocker, b"blocker").unwrap();
    let bad_paths = StatisticsPaths {
        database: blocker.join("store.sqlite3"),
        snapshot: blocker.join("popular"),
    };
    assert!(store::Store::open(bad_paths, NOW).is_err());
    // Force publishing failure on the actual store by owning its temp-name
    // companion: fixed generation's guard create cannot acquire ownership.
    let held = persist_lock::TempFileGuard::create(
        &fixture.paths.snapshot,
        u64::try_from(snapshot.generation).unwrap(),
    )
    .unwrap();
    assert!(store.publish().is_err());
    assert_eq!(fs::read(&fixture.paths.snapshot).unwrap(), old);
    drop(held);
    // A transient publication failure does not latch SQL failure. The next
    // explicit refresh succeeds without reopening or a tight retry cycle.
    drop(snapshot);
    save(&mut store, &health, &a, 1, NOW, NOW);
    let recovered = refresh(&mut store, NOW, &health);
    assert_eq!(tuple_rows(&store, recovered.generation)[0].3, 102);
    assert!(fs::read_to_string(&fixture.paths.snapshot)
        .unwrap()
        .contains("atomic.test.\t102\t"));
}

/// No consumer exists: precisely capacity accepted and the next event is
/// dropped-newest. A SQL trigger supplies a real persistent write failure.
#[test]
fn bounded_overflow_and_accepted_unsaved_error_are_inspectable() {
    let health = Arc::new(Health::default());
    let (tx, mut rx) = mpsc::channel(2);
    let statistics = QueryStatistics {
        tx,
        health: health.clone(),
    };
    let a = question("loss.test", RecordType::A, DNSClass::IN);
    assert_eq!(statistics.record_at(&a, NOW), RecordOutcome::Accepted);
    assert_eq!(statistics.record_at(&a, NOW), RecordOutcome::Accepted);
    assert_eq!(statistics.record_at(&a, NOW), RecordOutcome::DroppedFull);
    assert_eq!(statistics.status().dropped_full, 1);
    let mut events = Vec::new();
    for _ in 0..2 {
        match rx.try_recv().unwrap() {
            Command::Record(event) => events.push(event),
            _ => panic!("fixture queued only Record commands"),
        }
    }
    let fixture = Fixture::new();
    let mut store = fixture.store();
    store
        .connection
        .execute_batch(
            "CREATE TRIGGER fail_statistics BEFORE INSERT ON query_seconds
        BEGIN SELECT RAISE(ABORT,'forced persistent failure'); END",
        )
        .unwrap();
    let error = store.batch(&events, NOW, &health).unwrap_err();
    health.error(&error);
    assert_eq!(statistics.status().unsaved, 2);
    assert!(statistics.status().last_error.is_some());
    store
        .connection
        .execute_batch("DROP TRIGGER fail_statistics")
        .unwrap();
    // Removing failure alone must NOT trigger hot per-event retries.
    add(&health.accepted, 1);
    assert!(store.batch(&[event(&a, NOW)], NOW, &health).is_err());
    assert_eq!(statistics.status().unsaved, 3);
    assert_eq!(statistics.status().pending, 0);
    let rows: i64 = store
        .connection
        .query_row("SELECT COUNT(*) FROM query_seconds", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 0);
    rx.close();
    assert_eq!(statistics.record_at(&a, NOW), RecordOutcome::Closed);
}

/// End-to-end use of the API, not a declaration-only test. Pages remain
/// immutable across refresh, cross 128 without top-N truncation, and shutdown
/// drains accepted ingress despite a retained producer and snapshot clone.
#[tokio::test]
async fn pages_are_keyset_immutable_and_shutdown_drains_retained_clones() {
    let fixture = Fixture::new();
    let (statistics, mut worker) = StatisticsWorker::open(fixture.paths.clone()).await.unwrap();
    let a = question("paged.test", RecordType::A, DNSClass::IN);
    for _ in 0..101 {
        assert_eq!(statistics.record(&a), RecordOutcome::Accepted);
    }
    for code in 2_u16..=260 {
        let question = question("paged.test", RecordType::from(code), DNSClass::IN);
        assert_eq!(statistics.record(&question), RecordOutcome::Accepted);
    }
    let old = worker.refresh().await.unwrap();
    assert_eq!(statistics.record(&a), RecordOutcome::Accepted);
    let current = worker.refresh().await.unwrap();
    let first = old.page(None).await.unwrap();
    assert_eq!(first.len(), 128);
    assert_eq!(first[0].count, 101);
    let second = old
        .page(Some(first.last().unwrap().cursor()))
        .await
        .unwrap();
    assert_eq!(second.len(), 128);
    let third = old
        .page(Some(second.last().unwrap().cursor()))
        .await
        .unwrap();
    assert_eq!(third.len(), 4);
    assert!(old
        .page(Some(third.last().unwrap().cursor()))
        .await
        .unwrap()
        .is_empty());
    assert_eq!(current.page(None).await.unwrap()[0].count, 102);
    assert!(worker.refresh().await.is_err());
    drop(old);
    let retained = statistics.clone();
    for _ in 0..101 {
        assert_eq!(retained.record(&a), RecordOutcome::Accepted);
    }
    worker.shutdown().await.unwrap();
    assert_eq!(retained.record(&a), RecordOutcome::Closed);
    assert_eq!(retained.status().pending, 0);
    assert_eq!(retained.status().unsaved, 0);
    assert!(current.page(None).await.is_err());
    drop(current);
    let (restarted, mut worker) = StatisticsWorker::open(fixture.paths.clone()).await.unwrap();
    let snapshot = worker.refresh().await.unwrap();
    assert_eq!(snapshot.page(None).await.unwrap()[0].count, 203);
    assert_eq!(restarted.status().pending, 0);
    worker.shutdown().await.unwrap();
}

/// Barrier-started real producers share one live store. Total admission is
/// below queue capacity even if SQL does not drain at all; contention is not
/// overload and must never cause loss. Final producer and disk totals agree.
#[tokio::test]
async fn concurrent_producers_have_no_contention_loss_and_exact_final_ledger() {
    let fixture = Fixture::new();
    let (statistics, worker) = StatisticsWorker::open(fixture.paths.clone()).await.unwrap();
    let producers = statistics.clone();
    tokio::task::spawn_blocking(move || {
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let mut threads = Vec::with_capacity(8);
        for index in 0..8 {
            let statistics = producers.clone();
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                let kind = if index % 2 == 0 {
                    RecordType::A
                } else {
                    RecordType::AAAA
                };
                let query = question("concurrent.test", kind, DNSClass::IN);
                barrier.wait();
                for _ in 0..128 {
                    assert_eq!(statistics.record(&query), RecordOutcome::Accepted);
                }
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }
    })
    .await
    .unwrap();
    worker.shutdown().await.unwrap();
    let status = statistics.status();
    assert_eq!(status.accepted, 1024);
    assert_eq!(status.saved, 1024);
    assert_eq!(status.dropped_full, 0);
    assert_eq!(status.unsaved, 0);
    assert_eq!(status.pending, 0);
    let paths = fixture.paths.clone();
    tokio::task::spawn_blocking(move || {
        let database = Connection::open(&paths.database).unwrap();
        let counts: Vec<(u16, i64)> = database
            .prepare(
                "SELECT rr_type,SUM(count) FROM query_seconds GROUP BY rr_type ORDER BY rr_type",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(counts, vec![(1, 512), (28, 512)]);
        let totals: (i64, i64, i64, i64) = database
            .query_row(
                "SELECT accepted,saved,unsaved,dropped_full FROM meta",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(totals, (1024, 1024, 0, 0));
    })
    .await
    .unwrap();
}

/// Forces the precise close-vs-accounting race: a producer has registered
/// before stop but has not yet sent. It can complete after stop; the dedicated
/// worker must wait, then close/drain, and persist the stable accepted total.
#[tokio::test]
async fn shutdown_waits_for_registered_producer_accounting() {
    let fixture = Fixture::new();
    let (statistics, worker) = StatisticsWorker::open(fixture.paths.clone()).await.unwrap();
    let admission = Admission::enter(&statistics.health.admission).unwrap();
    worker.signal_stop();
    assert_eq!(
        statistics.record(&question("closed.test", RecordType::A, DNSClass::IN)),
        RecordOutcome::Closed
    );
    let query = question("registered.test", RecordType::A, DNSClass::IN);
    statistics
        .tx
        .try_send(Command::Record(event(
            &query,
            time::OffsetDateTime::now_utc().unix_timestamp(),
        )))
        .unwrap_or_else(|_| panic!("registered producer must still send"));
    add(&statistics.health.accepted, 1);
    drop(admission);
    worker.shutdown().await.unwrap();
    assert_eq!(statistics.status().accepted, 1);
    assert_eq!(statistics.status().saved, 1);
    assert_eq!(statistics.status().pending, 0);
}

/// Hand-derived restart conservation: existing loss is a subset of the gap,
/// not added twice; only formerly pending accepted records become extra loss.
#[test]
fn restart_telemetry_does_not_double_count_existing_unsaved() {
    for (accepted, saved, unsaved, expected) in [
        (100, 80, 20, (100, 20)),
        (100, 80, 10, (100, 20)),
        (100, 80, 0, (100, 20)),
        (80, 80, 0, (80, 0)),
        (70, 80, 20, (100, 20)),
        (0, 0, 0, (0, 0)),
    ] {
        assert_eq!(
            store::restore_totals(accepted, saved, 0, unsaved).unwrap(),
            expected
        );
        // Applying restart reconciliation twice must not create new loss.
        assert_eq!(
            store::restore_totals(expected.0, saved, 0, expected.1).unwrap(),
            expected
        );
    }
    assert!(store::restore_totals(0, i64::MAX as u64, 0, 1).is_err());
}

/// Future meta cannot silently erase valid history; correcting UTC, not
/// resetting the durable clock, makes the same ledger usable again.
#[test]
fn future_highwater_fails_loud_without_pruning_valid_history() {
    let fixture = Fixture::new();
    let mut store = fixture.store();
    let health = Health::default();
    let query = question("preserved.test", RecordType::A, DNSClass::IN);
    save(&mut store, &health, &query, 101, NOW, NOW);
    drop(store);
    let database = Connection::open(&fixture.paths.database).unwrap();
    database
        .execute("UPDATE meta SET highwater=?1", [NOW + WINDOW_SECONDS * 2])
        .unwrap();
    drop(database);
    assert!(store::Store::open(fixture.paths.clone(), NOW).is_err());
    let database = Connection::open(&fixture.paths.database).unwrap();
    let count: i64 = database
        .query_row("SELECT SUM(count) FROM query_seconds", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 101);
    let error: String = database
        .query_row("SELECT last_error FROM meta", [], |r| r.get(0))
        .unwrap();
    assert!(error.contains("future"));
}

/// A trusted live highwater remains the logical window end during rollback.
/// Original old-clock seconds can enter the ledger, but expired seconds cannot
/// be rejuvenated by shifting the cutoff backwards or restamping to highwater.
#[test]
fn live_rollback_keeps_original_seconds_without_rejuvenation() {
    let fixture = Fixture::new();
    let mut store = fixture.store();
    let health = Health::default();
    let query = question("rollback.test", RecordType::A, DNSClass::IN);
    save(&mut store, &health, &query, 101, NOW, NOW);
    save(&mut store, &health, &query, 1, NOW - 10, NOW - 10);
    save(
        &mut store,
        &health,
        &query,
        1,
        NOW - WINDOW_SECONDS,
        NOW - 10,
    );
    // This second would be inside a wall-now-based rolled-back window, but is
    // exactly expired against the persisted highwater and must stay excluded.
    let snapshot = refresh(&mut store, NOW - 10, &health);
    assert_eq!(tuple_rows(&store, snapshot.generation)[0].3, 102);
    let ledger: (i64, i64, i64) = store
        .connection
        .query_row(
            "SELECT MIN(second),MAX(second),SUM(count) FROM query_seconds",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(ledger, (NOW - 10, NOW, 102));
    let timestamps: (i64, i64, i64) = store
        .connection
        .query_row(
            "SELECT m.highwater,d.refreshed_at,d.last_seen FROM meta m,domain_summary d",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(timestamps, (NOW, NOW, NOW));
    drop(snapshot);
    save(&mut store, &health, &query, 1, NOW, NOW);
    let snapshot = refresh(&mut store, NOW, &health);
    assert_eq!(tuple_rows(&store, snapshot.generation)[0].3, 103);
    assert_eq!(health.status().accepted, 104);
    assert_eq!(health.status().saved, 103);
    assert_eq!(health.status().expired, 1);
    assert_eq!(health.status().unsaved, 0);
    assert_eq!(health.status().pending, 0);
}

/// Explicitly restored rowid MIN must be visited, even if its column types
/// pass SQL validation. Subsequent rowids include a valid canonical control.
#[test]
fn restore_validates_minimum_rowid_without_skipping_or_repeating() {
    let fixture = Fixture::new();
    drop(fixture.store());
    let database = Connection::open(&fixture.paths.database).unwrap();
    database
        .execute(
            "INSERT INTO query_seconds(rowid,domain,rr_type,class,second,count)
        VALUES(?1,'UPPER.test.',1,1,?2,101)",
            params![i64::MIN, NOW],
        )
        .unwrap();
    database
        .execute(
            "INSERT INTO query_seconds(rowid,domain,rr_type,class,second,count)
        VALUES(?1,'valid.test.',1,1,?2,101)",
            params![i64::MIN + 1, NOW],
        )
        .unwrap();
    drop(database);
    let mut restored = fixture.store();
    let health = Health::default();
    let snapshot = refresh(&mut restored, NOW, &health);
    assert_eq!(
        tuple_rows(&restored, snapshot.generation),
        vec![("valid.test.".into(), 1, 1, 101)]
    );
    let invalid: i64 = restored
        .connection
        .query_row("SELECT invalid_restored FROM meta", [], |r| r.get(0))
        .unwrap();
    assert_eq!(invalid, 1);
}

/// Deterministic witness for try_send completing before the producer's
/// accepted increment: SQL commits and a refresh both run in that interval.
/// Disk accepted must cover completed work without changing producer counters.
#[test]
fn persisted_accepted_covers_commit_before_producer_accounting() {
    let fixture = Fixture::new();
    let mut store = fixture.store();
    let health = Health::default();
    let query = question("accounting.test", RecordType::A, DNSClass::IN);
    store.batch(&[event(&query, NOW)], NOW, &health).unwrap();
    assert_eq!(health.status().accepted, 0);
    let read = |store: &store::Store| -> (i64, i64, i64) {
        store
            .connection
            .query_row("SELECT accepted,saved,unsaved FROM meta", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap()
    };
    assert_eq!(read(&store), (1, 1, 0));
    let snapshot = refresh(&mut store, NOW, &health);
    assert_eq!(read(&store), (1, 1, 0));
    store.persist_health(&health).unwrap();
    assert_eq!(read(&store), (1, 1, 0));
    // Model another accepted event already classified unsaved, still before
    // its producer increments accepted. This checks the completed-loss floor.
    add(&health.unsaved, 1);
    store.persist_health(&health).unwrap();
    assert_eq!(read(&store), (2, 1, 1));
    add(&health.accepted, 2);
    store.persist_health(&health).unwrap();
    assert_eq!(read(&store), (2, 1, 1));
    assert_eq!(health.status().accepted, 2);
    assert_eq!(health.status().pending, 0);
    drop(snapshot);
}

/// Signed metadata is read without optional unsigned rusqlite conversions.
/// Negative fields and completed-count overflow must be rejected before any
/// history is pruned; ordinary conserved signed totals remain reopenable.
#[test]
fn restore_rejects_negative_metadata_and_completed_overflow() {
    let fixture = Fixture::new();
    drop(fixture.store());
    let database = Connection::open(&fixture.paths.database).unwrap();
    for sql in [
        "UPDATE meta SET expired=-1",
        "UPDATE meta SET expired=0,accepted=-1,saved=0,unsaved=0,dropped_full=0,invalid_restored=0",
        "UPDATE meta SET accepted=0,saved=-1,unsaved=0,dropped_full=0,invalid_restored=0",
        "UPDATE meta SET accepted=0,saved=0,unsaved=-1,dropped_full=0,invalid_restored=0",
        "UPDATE meta SET accepted=0,saved=0,unsaved=0,dropped_full=-1,invalid_restored=0",
        "UPDATE meta SET accepted=0,saved=0,unsaved=0,dropped_full=0,invalid_restored=-1",
        "UPDATE meta SET accepted=0,saved=9223372036854775807,unsaved=1,dropped_full=0,invalid_restored=0",
    ] {
        database.execute(sql,[]).unwrap();
        assert!(store::Store::open(fixture.paths.clone(),NOW).is_err());
    }
    database
        .execute(
            "UPDATE meta SET accepted=100,saved=80,unsaved=20,dropped_full=0,invalid_restored=0",
            [],
        )
        .unwrap();
    drop(database);
    drop(fixture.store());
}

#[path = "query_statistics_receipt_tests.rs"]
mod receipt_tests;

#[test]
fn mixed_receipts_expiry_invalid_and_transaction_failure_have_truthful_classes() {
    let fixture = Fixture::new();
    let mut store = store::Store::open(fixture.paths.clone(), NOW - 20).unwrap();
    let health = Health::default();
    let query = question("mixed.test", RecordType::A, DNSClass::IN);
    let mut bad_key = event(&query, NOW + WINDOW_SECONDS * 2);
    bad_key.domain = "invalid..test.".into();
    let events = vec![
        event(&query, NOW - 10),
        event(&query, NOW),
        event(&query, NOW - WINDOW_SECONDS),
        event(&query, NOW - WINDOW_SECONDS + 1),
        event(&query, -1),
        event(&query, i64::MAX),
        bad_key,
    ];
    add(&health.accepted, 7);
    store.batch(&events, NOW - 10, &health).unwrap();
    let status = health.status();
    assert_eq!(
        (
            status.accepted,
            status.saved,
            status.expired,
            status.unsaved,
            status.pending
        ),
        (7, 3, 1, 3, 0)
    );
    assert!(status.last_error.unwrap().contains("invalid live"));
    let totals: (i64, i64, i64, i64, i64) = store
        .connection
        .query_row(
            "SELECT highwater,accepted,saved,expired,unsaved FROM meta",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .unwrap();
    assert_eq!(totals, (NOW, 7, 3, 1, 3));
    let ledger: (i64, i64, i64) = store
        .connection
        .query_row(
            "SELECT MIN(second),MAX(second),SUM(count) FROM query_seconds",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(ledger, (NOW - WINDOW_SECONDS + 1, NOW, 3));
    store
        .connection
        .execute_batch(
            "CREATE TRIGGER fail_batch BEFORE INSERT ON query_seconds
        BEGIN SELECT RAISE(ABORT,'forced failure'); END;",
        )
        .unwrap();
    add(&health.accepted, 3);
    assert!(store
        .batch(
            &[
                event(&query, NOW + 1),
                event(&query, NOW - WINDOW_SECONDS),
                event(&query, -1)
            ],
            NOW + 1,
            &health
        )
        .is_err());
    let status = health.status();
    assert_eq!(
        (status.saved, status.expired, status.unsaved, status.pending),
        (3, 1, 6, 0)
    );
    // Pruning, insertions, classifications and highwater all rolled back.
    assert_eq!(
        store
            .connection
            .query_row("SELECT highwater FROM meta", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        NOW
    );
    assert_eq!(
        store
            .connection
            .query_row("SELECT SUM(count) FROM query_seconds", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        3
    );
    store.persist_health(&health).unwrap();
    drop(store);
    let restored = store::Store::open(fixture.paths.clone(), NOW).unwrap();
    assert_eq!(store::restore_totals(10, 3, 1, 6).unwrap(), (10, 6));
    assert_eq!(
        restored
            .connection
            .query_row("SELECT expired FROM meta", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn v1_metadata_migrates_once_without_reclassifying_legacy_saved() {
    let fixture = Fixture::new();
    let database = Connection::open(&fixture.paths.database).unwrap();
    database
        .execute_batch(
            "CREATE TABLE meta(id INTEGER PRIMARY KEY,schema_version INTEGER NOT NULL,
        highwater INTEGER NOT NULL,generation INTEGER NOT NULL,refreshed_at INTEGER NOT NULL,
        accepted INTEGER NOT NULL,saved INTEGER NOT NULL,dropped_full INTEGER NOT NULL,
        unsaved INTEGER NOT NULL,invalid_restored INTEGER NOT NULL,last_error TEXT);
        INSERT INTO meta VALUES(1,1,1800000000,0,0,100,80,0,10,0,NULL);",
        )
        .unwrap();
    drop(database);
    for _ in 0..2 {
        let store = fixture.store();
        let totals: (i64, i64, i64) = store
            .connection
            .query_row("SELECT schema_version,saved,expired FROM meta", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
        assert_eq!(totals, (2, 80, 0));
    }
    assert_eq!(store::restore_totals(100, 80, 5, 10).unwrap(), (100, 15));
    assert!(store::restore_totals(0, i64::MAX as u64, 1, 0).is_err());
}

#[test]
fn sibling_paths_replace_only_dns_cache_suffix() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture.paths.database.file_name().unwrap(),
        "proxy.dns-query-statistics.sqlite3"
    );
    assert_eq!(
        fixture.paths.snapshot.file_name().unwrap(),
        "proxy.dns-popular"
    );
    let paths = StatisticsPaths::from_cache_path(&fixture.directory.join("proxy.other"));
    assert_eq!(
        paths.snapshot.file_name().unwrap(),
        "proxy.other.dns-popular"
    );
}
