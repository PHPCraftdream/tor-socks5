use super::super::*;
use super::{
    config_path, leftover_tmp_files, reload, seed_store, test_bridge, wait_for_calls,
    wait_for_file_count,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use time::OffsetDateTime;
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

/// Copy-on-write / panic-isolation regression: the actor keeps its own Arc
/// handle to the snapshot while every mutation job runs on the blocking
/// pool, so `Arc::make_mut` inside the job is an unconditional deep copy
/// (TS5-06) — the publisher never observes a shared, mid-mutation state.
///
/// Proof is by pointer identity between the actor's mutation target and the
/// allocation the publisher observes:
/// 1. The publisher must see the SAME allocation the actor mutated and
///    stored back (`store = Some(owned)`) — every publish observes exactly
///    the actor's last stored snapshot.
/// 2. A mutation while a publish is in flight must land on a fresh
///    allocation (with the actor's own handle alive, `make_mut` always
///    deep-copies; both allocations are simultaneously live, so the
///    addresses cannot coincide).
/// 3. The coalesced follow-up must publish that same new allocation — no
///    second copy.
/// 4. A quiet mutation must again publish the allocation it mutated
///    (still a private deep copy, per TS5-06, but the address assertions
///    are unchanged). (We do not assert its address differs from the
///    previous one: after a clean publish the actor drops its Arc, so the
///    allocator may legally reuse the address.)
#[tokio::test]
async fn publish_snapshots_are_copy_on_write() {
    let dir = tempfile::tempdir().expect("tempdir");
    let b = test_bridge();
    let path = config_path(dir.path());
    seed_store(&path, &b);

    let calls = Arc::new(AtomicUsize::new(0));
    let snapshots: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));
    let addrs: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    let (gate_tx, gate_rx) = oneshot::channel::<()>();
    // The gate receiver is consumed once (blocking_recv takes self), so
    // wrap it for the `Fn` publisher bound.
    let gate = Mutex::new(Some(gate_rx));
    let counter = calls.clone();
    let snapshot_addrs = snapshots.clone();
    let publisher: Publisher = Arc::new(move |s: &BridgeStore| {
        // Record the snapshot allocation BEFORE bumping the counter, so an
        // entry always exists by the time the counter shows the call.
        snapshot_addrs
            .lock()
            .unwrap()
            .push(s as *const BridgeStore as usize);
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

    // Mutation A: the job deep-copies (the actor keeps its own Arc, so
    // make_mut is unconditional), stores the copy back, and the publisher
    // must observe that same stored allocation.
    let b_a = b.clone();
    let addrs_a = addrs.clone();
    writer
        .apply(move |s| {
            addrs_a.store(s as *mut BridgeStore as usize, Ordering::SeqCst);
            s.note_channel_success_at(&b_a, OffsetDateTime::now_utc());
        })
        .await
        .expect("mutation A absorbed");
    let addr_a = addrs.load(Ordering::SeqCst);
    wait_for_calls(&calls, 1, "publish #1 started and is blocked on the gate").await;
    assert_eq!(
        snapshots.lock().unwrap()[0],
        addr_a,
        "publisher saw the same stored allocation the actor mutated: every publish observes the actor's last stored snapshot"
    );

    // Mutation B: publish #1 is in flight, the job deep-copies (make_mut
    // is unconditional under TS5-06) and B lands on a fresh allocation.
    let b_b = b.clone();
    let addrs_b = addrs.clone();
    writer
        .apply(move |s| {
            addrs_b.store(s as *mut BridgeStore as usize, Ordering::SeqCst);
            s.note_channel_success_at(&b_b, OffsetDateTime::now_utc());
        })
        .await
        .expect("mutation B absorbed");
    let addr_b = addrs.load(Ordering::SeqCst);
    assert_ne!(
        addr_b, addr_a,
        "make_mut cloned the shared Arc: the mutation got a fresh allocation"
    );

    // Release publish #1; the coalesced follow-up must publish B's
    // allocation with no second copy.
    gate_tx.send(()).expect("release the publish gate");
    wait_for_calls(&calls, 2, "coalesced follow-up publish fired").await;
    assert_eq!(
        snapshots.lock().unwrap()[1],
        addr_b,
        "follow-up published B's allocation unchanged"
    );

    // Mutation C: quiet state (publish done, snapshot clean) — the job
    // deep-copies again and the publisher sees C's stored allocation.
    // We deliberately do NOT assert addr_c != addr_b: after the
    // clean publish the actor dropped its Arc, so the allocator may
    // legally reuse that address.
    let b_c = b.clone();
    let addrs_c = addrs.clone();
    writer
        .apply(move |s| {
            addrs_c.store(s as *mut BridgeStore as usize, Ordering::SeqCst);
            s.note_channel_success_at(&b_c, OffsetDateTime::now_utc());
        })
        .await
        .expect("mutation C absorbed");
    let addr_c = addrs.load(Ordering::SeqCst);
    wait_for_calls(&calls, 3, "quiet mutation triggered its own publish").await;
    assert_eq!(
        snapshots.lock().unwrap()[2],
        addr_c,
        "quiet publish again shares the actor's stored allocation"
    );

    wait_for_file_count(&path, &b, 3, "all three publishes persisted").await;
    let closed = writer.close().await;
    assert!(closed.is_ok(), "close after clean publishes: {closed:?}");
    assert!(
        leftover_tmp_files(dir.path()).is_empty(),
        "no leftover temp files"
    );
}

/// A gated mutation on the blocking pool must leave the async worker free
/// to release it, without assumptions about wall-clock scheduling.
#[tokio::test]
async fn mutation_during_in_flight_publish_does_not_block_the_async_worker() {
    let dir = tempfile::tempdir().expect("tempdir");
    let b = test_bridge();
    let path = config_path(dir.path());
    seed_store(&path, &b);

    let calls = Arc::new(AtomicUsize::new(0));
    let (gate_tx, gate_rx) = oneshot::channel::<()>();
    // The gate receiver is consumed once (blocking_recv takes self), so
    // wrap it for the `Fn` publisher bound (same trick as
    // publish_snapshots_are_copy_on_write).
    let gate = Mutex::new(Some(gate_rx));
    let counter = calls.clone();
    let publisher: Publisher = Arc::new(move |s: &BridgeStore| {
        if counter.fetch_add(1, Ordering::SeqCst) == 0 {
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

    // Mutation A triggers publish #1 and leaves it blocked on the gate, so
    // the actor's snapshot Arc is shared once mutation B lands — the only
    // situation in which make_mut deep-copies.
    let b_a = b.clone();
    writer
        .apply(move |s| s.note_channel_success_at(&b_a, OffsetDateTime::now_utc()))
        .await
        .expect("mutation A absorbed");
    wait_for_calls(&calls, 1, "publish #1 started and is blocked on the gate").await;

    // Mutation B waits for an independent async task to release it.
    let writer_b = writer.clone();
    let b_b = b.clone();
    let (started_tx, started_rx) = oneshot::channel::<()>();
    let (release_tx, release_rx) = oneshot::channel::<()>();
    let mutation = tokio::spawn(async move {
        writer_b
            .apply(move |s| {
                started_tx.send(()).expect("announce mutation start");
                release_rx
                    .blocking_recv()
                    .expect("async worker released mutation");
                s.note_channel_success_at(&b_b, OffsetDateTime::now_utc());
            })
            .await
            .expect("mutation B absorbed");
    });

    started_rx.await.expect("mutation started");
    let watchdog = tokio::spawn(async move {
        release_tx.send(()).expect("mutation is still waiting");
    });

    let (mutation_res, watchdog_res) = tokio::join!(mutation, watchdog);
    mutation_res.expect("mutation task joins");
    watchdog_res.expect("watchdog task joins");

    // Semantics unchanged: B was absorbed (ack above) and rides along in
    // the coalesced follow-up once the gated publish completes.
    gate_tx.send(()).expect("release the publish gate");
    wait_for_file_count(&path, &b, 2, "both mutations reached disk").await;
    let closed = writer.close().await;
    assert!(closed.is_ok(), "close after clean publishes: {closed:?}");
    assert!(
        leftover_tmp_files(dir.path()).is_empty(),
        "no leftover temp files"
    );
}
