//! Receipt trust-boundary regressions using real collector admission and SQLite.
use super::*;

/// Red if receipt<=collector-now is restored: ledger/popularity lose all 101.
#[test]
fn trusted_receipts_survive_collector_rollback_even_in_first_batch() {
    for initial in [NOW, NOW - 20] {
        let fixture = Fixture::new();
        let mut store = store::Store::open(fixture.paths.clone(), initial).unwrap();
        let health = Health::default();
        let query = question("receipt.test", RecordType::A, DNSClass::IN);
        save(&mut store, &health, &query, 101, NOW, NOW - 10);
        let ledger: (i64, i64, i64) = store
            .connection
            .query_row(
                "SELECT MIN(second),MAX(second),SUM(count) FROM query_seconds",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            ledger,
            (NOW, NOW, 101),
            "trusted 101 receipts must actually reach ledger"
        );
        let snapshot = refresh(&mut store, NOW - 10, &health);
        assert_eq!(
            tuple_rows(&store, snapshot.generation),
            vec![("receipt.test.".into(), 1, 1, 101)]
        );
        let status = health.status();
        assert_eq!(
            (
                status.accepted,
                status.saved,
                status.expired,
                status.unsaved,
                status.pending
            ),
            (101, 101, 0, 0, 0)
        );
        assert_eq!(
            status.accepted,
            status.saved + status.expired + status.unsaved + status.pending
        );
    }
}

/// Admission begins only after restore/ready, just like the production API.
/// The first batch clock blocks only the dedicated collector thread. Bounded
/// synchronous release and async acknowledgement make this instance-local gate
/// deterministic without blocking a runtime worker or changing core accounting.
#[tokio::test]
async fn collector_persists_101_pre_rollback_receipts_and_qualifies_them() {
    for initial in [NOW, NOW - 20] {
        let fixture = Fixture::new();
        let health = Arc::new(Health::default());
        let (tx, rx) = mpsc::channel(INGRESS_CAPACITY);
        let statistics = QueryStatistics {
            tx: tx.clone(),
            health: health.clone(),
        };
        let query = question("collector-receipt.test", RecordType::A, DNSClass::IN);
        let (ready, started) = oneshot::channel();
        let (done, finished) = oneshot::channel();
        let (at_batch, batch_clock_entered) = oneshot::channel();
        let (release, released) = std::sync::mpsc::sync_channel(1);
        let paths = fixture.paths.clone();
        let thread_health = health.clone();
        let weak = tx.downgrade();
        let thread = std::thread::spawn(move || {
            let mut first = true;
            let mut at_batch = Some(at_batch);
            store::run_with_clock(paths, rx, weak, thread_health, ready, done, move || {
                if first {
                    first = false;
                    initial
                } else {
                    if let Some(at_batch) = at_batch.take() {
                        // The test awaits this signal; no coalescing/global gate.
                        at_batch.send(()).unwrap();
                        released.recv().unwrap();
                    }
                    NOW - 10
                }
            });
        });
        let worker = StatisticsWorker {
            tx,
            health,
            done: Some(finished),
            thread: Some(thread),
        };
        started.await.unwrap().unwrap();
        assert_eq!(statistics.status().accepted, 0);
        // First real admission wakes blocking_recv and reaches the clock gate.
        assert_eq!(statistics.record_at(&query, NOW), RecordOutcome::Accepted);
        batch_clock_entered.await.unwrap();
        for _ in 1..101 {
            assert_eq!(statistics.record_at(&query, NOW), RecordOutcome::Accepted);
        }
        let queued = statistics.status();
        assert_eq!(
            (queued.accepted, queued.saved, queued.pending),
            (101, 0, 101)
        );
        let (reply, snapshot) = oneshot::channel();
        statistics
            .tx
            .try_send(Command::Refresh(reply))
            .unwrap_or_else(|_| panic!("bounded fixture fits"));
        // Backpressure policy: one release into an empty capacity-one channel;
        // try_send cannot block this async test thread.
        release.try_send(()).unwrap();
        let snapshot = snapshot.await.unwrap().unwrap();
        assert_eq!(snapshot.page(None).await.unwrap()[0].count, 101);
        worker.shutdown().await.unwrap();
        let status = statistics.status();
        assert_eq!(
            (
                status.accepted,
                status.saved,
                status.expired,
                status.unsaved,
                status.pending
            ),
            (101, 101, 0, 0, 0)
        );
        assert_eq!(
            status.accepted,
            status.saved + status.expired + status.unsaved + status.pending
        );
        let database = Connection::open(&fixture.paths.database).unwrap();
        let ledger: (i64, i64, i64) = database
            .query_row(
                "SELECT MIN(second),MAX(second),SUM(count) FROM query_seconds",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            ledger,
            (NOW, NOW, 101),
            "receipt<=collector-now regression loses all 101"
        );
        let totals: (i64, i64, i64, i64) = database
            .query_row("SELECT accepted,saved,expired,unsaved FROM meta", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })
            .unwrap();
        assert_eq!(totals, (101, 101, 0, 0));
        assert_eq!(totals.0, totals.1 + totals.2 + totals.3);
        assert_eq!(u64::try_from(totals.0).unwrap(), status.accepted);
        assert_eq!(u64::try_from(ledger.2).unwrap(), status.saved);
    }
}
