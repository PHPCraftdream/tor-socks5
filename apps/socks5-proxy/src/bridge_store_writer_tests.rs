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
    let mut store =
        BridgeStore::load(BridgeStore::resolve_path(Some(config_path))).expect("fresh store loads");
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

/// TS4-09 regression: the "maybe deep-clone, then mutate" step must run on
/// the blocking pool, not on the actor's async worker. Proof on the default
/// single-threaded test runtime: while a mutation whose closure sleeps
/// synchronously for 400ms is in flight, an INDEPENDENT async task on the
/// same runtime must get to run. Under the old synchronous placement the
/// actor's closure block stopped the whole runtime — timers included — so
/// the ack necessarily preceded the watchdog; with `spawn_blocking` the
/// watchdog (armed only after the closure demonstrably started) fires long
/// before the ack. The publisher is held in flight on a gate, so the Arc is
/// shared and `Arc::make_mut` really deep-copies — the heavy sleep stands
/// in for that O(S) copy.
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

    // Mutation B: heavy closure (a synchronous 400ms sleep stands in for
    // the O(S) deep copy), announces "started" before sleeping.
    let writer_b = writer.clone();
    let b_b = b.clone();
    let (started_tx, started_rx) = oneshot::channel::<()>();
    let mutation = tokio::spawn(async move {
        writer_b
            .apply(move |s| {
                let _ = started_tx.send(());
                std::thread::sleep(Duration::from_millis(400));
                s.note_channel_success_at(&b_b, OffsetDateTime::now_utc());
            })
            .await
            .expect("mutation B absorbed");
        tokio::time::Instant::now()
    });

    // Arm the watchdog only after the closure demonstrably started, then
    // wait a time far shorter than the closure's sleep on an independent
    // async task.
    let _ = started_rx.await;
    let watchdog = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        tokio::time::Instant::now()
    });

    let (mutation_res, watchdog_res) = tokio::join!(mutation, watchdog);
    let ack_at = mutation_res.expect("mutation task joins");
    let watchdog_at = watchdog_res.expect("watchdog task joins");
    assert!(
        watchdog_at < ack_at,
        "the independent async task must run while the heavy mutation is in \
         flight (watchdog fired at {watchdog_at:?}, ack at {ack_at:?})"
    );
    assert!(
        ack_at - watchdog_at >= Duration::from_millis(100),
        "the ack must come well after the watchdog: the closure must have run \
         to completion off the worker (gap {:?})",
        ack_at - watchdog_at
    );

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

/// TS4-09 panic branch (updated by TS5-06): a mutation closure that
/// panics must not kill the actor. The panicked op's ack resolves `Err`
/// (the caller must assume THAT mutation did not land), nothing is
/// published for it, and the NEXT mutation succeeds. With the TS5-06 fix
/// the actor RETAINS the loaded snapshot rather than dropping it, so the
/// next mutation does not reload from disk — observably equivalent here
/// because nothing external wrote between the load and the panic.
#[tokio::test]
async fn mutation_panic_rejects_the_ack_and_the_next_mutation_succeeds() {
    let dir = tempfile::tempdir().expect("tempdir");
    let b = test_bridge();
    let path = config_path(dir.path());
    seed_store(&path, &b);

    let writer = StoreWriter::spawn(
        BridgeStore::resolve_path(Some(&path)),
        Arc::new(|s| s.save()),
        INITIAL_BACKOFF,
    );

    let result = writer
        .apply(|_s: &mut BridgeStore| panic!("injected mutation panic"))
        .await;
    let error = result.expect_err("a panicking closure must reject its ack");
    assert!(
        error.to_string().contains("panicked"),
        "the ack error must report the panic: {error:#}"
    );
    assert_eq!(
        reload(&path).channel_ok_count(&b),
        0,
        "the panicked mutation must not have published anything"
    );

    // The actor survived the panic; the next mutation is absorbed into
    // the RETAINED snapshot (no reload under TS5-06) and publishes.
    let b1 = b.clone();
    writer
        .apply(move |s| s.note_channel_success_at(&b1, OffsetDateTime::now_utc()))
        .await
        .expect("actor still alive: next mutation is absorbed");
    wait_for_file_count(&path, &b, 1, "post-panic mutation published").await;

    let closed = writer.close().await;
    assert!(closed.is_ok(), "close after recovery: {closed:?}");
    assert!(
        leftover_tmp_files(dir.path()).is_empty(),
        "no leftover temp files"
    );
}

/// TS5-06 regression (the core scenario): a confirmed but UNPUBLISHED
/// mutation (publish failed, snapshot retained for backoff retry) followed
/// by a panicking mutation must not lose the confirmed one. With the old
/// `store.take()` the panic destroyed the actor's whole snapshot
/// (`store = None`), `try_start_publish` then blocked every retry, and the
/// next mutation reloaded the STALE file — mutation A was gone for good.
#[tokio::test(start_paused = true)]
async fn panic_after_a_failed_publish_keeps_the_confirmed_mutation() {
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

    // Mutation A: acked (absorbed), publish #1 fails, snapshot retained.
    let b_a = b.clone();
    writer
        .apply(move |s| s.note_channel_success_at(&b_a, OffsetDateTime::now_utc()))
        .await
        .expect("absorbed");
    wait_for_calls(&calls, 1, "publish #1 attempted and failed").await;
    assert_eq!(
        reload(&path).channel_ok_count(&b),
        0,
        "the failed publish left the file untouched"
    );

    // Mutation B panics: its own ack rejects, and it must not have
    // published anything.
    let result = writer
        .apply(move |_s: &mut BridgeStore| panic!("injected mutation panic"))
        .await;
    let error = result.expect_err("a panicking closure must reject its ack");
    assert!(
        error.to_string().contains("panicked"),
        "the ack error must report the panic: {error:#}"
    );
    assert_eq!(
        reload(&path).channel_ok_count(&b),
        0,
        "the panicked mutation must not have published anything"
    );

    // THE KEY ASSERTION: the disk file still holds count 0, so the only
    // copy of mutation A anywhere is the actor's retained in-memory
    // snapshot. If the actor had dropped it (the old `take()` bug), the
    // retry could never publish (`store.is_none()` blocks
    // `try_start_publish`) and A would be unrecoverable. Prove A survived
    // WITHOUT a reload by letting the backoff retry succeed.
    tokio::time::sleep(Duration::from_secs(2)).await;
    wait_for_calls(&calls, 2, "the backoff retry fired").await;
    wait_for_file_count(
        &path,
        &b,
        1,
        "the backoff retry published the retained snapshot: mutation A survived mutation B's panic without a reload",
    )
    .await;

    // The next successful op must build on the surviving state: its
    // publish carries BOTH the retained A and the new C.
    let b_c = b.clone();
    writer
        .apply(move |s| s.note_source_at(&b_c, "after-panic", OffsetDateTime::now_utc()))
        .await
        .expect("absorbed");
    wait_for_calls(&calls, 3, "mutation C's publish fired").await;
    // The call counter bumps before save() finishes writing, so poll the
    // file (see wait_for_file_count) instead of reloading immediately.
    let mut store = None;
    for _ in 0..5000 {
        let reloaded = reload(&path);
        if reloaded.sources_of(&b).contains(&"after-panic".to_string()) {
            store = Some(reloaded);
            break;
        }
        tokio::task::yield_now().await;
        std::thread::sleep(Duration::from_millis(2));
    }
    let store = store.expect("mutation C's source must reach disk");
    assert_eq!(
        store.channel_ok_count(&b),
        1,
        "mutation A survived B's panic and reached disk via C's publish"
    );
    assert!(
        store.sources_of(&b).contains(&"after-panic".to_string()),
        "mutation C applied on top of the surviving state"
    );

    let closed = writer.close().await;
    assert!(closed.is_ok(), "close after a clean publish: {closed:?}");
    assert!(
        leftover_tmp_files(dir.path()).is_empty(),
        "no leftover temp files"
    );
}

/// TS5-06 regression (anti-busy-loop): with the old `store.take()` bug a
/// panicking mutation left `store = None` while `retry.dirty` stayed true;
/// the expired `retry_at` fired `try_start_publish`, which returned early
/// without touching `RetryState`, so the same deadline was instantly ready
/// again — a zero-delay busy loop. After a panic the retry attempts must
/// keep following the exponential backoff schedule exactly.
#[tokio::test(start_paused = true)]
async fn retries_stay_on_the_backoff_schedule_after_a_panicking_mutation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let b = test_bridge();
    let path = config_path(dir.path());
    seed_store(&path, &b);

    // Fail the first THREE publish calls, succeed from the 4th.
    let calls = Arc::new(AtomicUsize::new(0));
    let publisher: Publisher = {
        let counter = calls.clone();
        Arc::new(move |s: &BridgeStore| {
            if counter.fetch_add(1, Ordering::SeqCst) < 3 {
                Err(anyhow!("injected publish failure"))
            } else {
                s.save()
            }
        })
    };
    let writer = StoreWriter::spawn(
        BridgeStore::resolve_path(Some(&path)),
        publisher,
        INITIAL_BACKOFF,
    );

    // Mutation A: acked, publish call 1 fails at t≈0, backoff 1s→2s.
    let b_a = b.clone();
    writer
        .apply(move |s| s.note_channel_success_at(&b_a, OffsetDateTime::now_utc()))
        .await
        .expect("absorbed");
    wait_for_calls(&calls, 1, "publish #1 attempted and failed").await;

    // Mutation B panics. With the fix, B leaves retry.dirty, retry_at and
    // the retained snapshot exactly as they were before B.
    let result = writer
        .apply(move |_s: &mut BridgeStore| panic!("injected mutation panic"))
        .await;
    let error = result.expect_err("a panicking closure must reject its ack");
    assert!(
        error.to_string().contains("panicked"),
        "the ack error must report the panic: {error:#}"
    );

    // t=5s: the 1s/2s schedule puts retries at t=1s (call 2, fails → next
    // at t=3s) and t=3s (call 3, fails → next at t=7s). Exactly 3 attempts
    // means the attempts follow the exponential schedule — no flood of
    // immediate retries through the expired timer (the old store=None
    // busy-loop would either spin without ever publishing or, worse,
    // hammer the publisher).
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "retries must follow the exponential backoff schedule, not a busy loop"
    );

    // t=9s: the t=7s retry is call 4 and SUCCEEDS.
    tokio::time::sleep(Duration::from_secs(4)).await;
    wait_for_calls(&calls, 4, "the successful retry fired").await;
    wait_for_file_count(
        &path,
        &b,
        1,
        "the successful retry persisted the retained snapshot with mutation A",
    )
    .await;

    // t=11s: a successful publish ends the retry streak; nothing keeps
    // attempting.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        4,
        "a successful publish must end the retry streak"
    );

    let closed = writer.close().await;
    assert!(closed.is_ok(), "close after a clean retry: {closed:?}");
    assert!(
        leftover_tmp_files(dir.path()).is_empty(),
        "no leftover temp files"
    );
}

/// TS5-06 regression: close after a confirmed, unpublished mutation plus a
/// panicking one must flush the RETAINED snapshot (containing A) — the
/// final flush ignores the backoff deadline. With the old bug the panic
/// left `store = None`, so close's flush arm hit `None => Ok(())` and
/// reported a false success while losing A.
#[tokio::test(start_paused = true)]
async fn close_after_a_panicking_mutation_flushes_the_retained_snapshot() {
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

    // Mutation A: acked, publish fails, snapshot retained, backoff armed.
    let b_a = b.clone();
    writer
        .apply(move |s| s.note_channel_success_at(&b_a, OffsetDateTime::now_utc()))
        .await
        .expect("absorbed");
    wait_for_calls(&calls, 1, "publish #1 attempted and failed").await;

    // Mutation B panics; its ack rejects.
    let result = writer
        .apply(move |_s: &mut BridgeStore| panic!("injected mutation panic"))
        .await;
    assert!(
        result.is_err(),
        "the panicking mutation must reject its ack"
    );

    // Close must flush the snapshot that still contains A and report Ok.
    let closed = writer.close().await;
    assert!(
        closed.is_ok(),
        "close must flush the retained snapshot: {closed:?}"
    );
    assert_eq!(
        reload(&path).channel_ok_count(&b),
        1,
        "the final flush wrote the retained mutation A"
    );
    assert!(
        leftover_tmp_files(dir.path()).is_empty(),
        "no leftover temp files"
    );
}

/// TS5-06 regression: if the underlying publish keeps failing, close after
/// a confirmed, unpublished mutation plus a panicking one must return Err
/// — NOT the false `Ok(())` the old `None => Ok(())` close arm produced
/// when `retry.dirty` was true but the panicking mutation had taken the
/// snapshot away.
#[tokio::test(start_paused = true)]
async fn close_after_a_panicking_mutation_reports_a_persistent_failure() {
    let dir = tempfile::tempdir().expect("tempdir");
    let b = test_bridge();
    let path = config_path(dir.path());
    seed_store(&path, &b);

    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let writer = StoreWriter::spawn(
        BridgeStore::resolve_path(Some(&path)),
        Arc::new(move |_s: &BridgeStore| {
            counter.fetch_add(1, Ordering::SeqCst);
            Err(anyhow!("disk is full"))
        }),
        INITIAL_BACKOFF,
    );

    // Mutation A: acked, publish fails, snapshot retained.
    let b_a = b.clone();
    writer
        .apply(move |s| s.note_channel_success_at(&b_a, OffsetDateTime::now_utc()))
        .await
        .expect("absorbed");
    wait_for_calls(&calls, 1, "publish #1 attempted and failed").await;

    // Mutation B panics; its ack rejects.
    let result = writer
        .apply(move |_s: &mut BridgeStore| panic!("injected mutation panic"))
        .await;
    assert!(
        result.is_err(),
        "the panicking mutation must reject its ack"
    );

    // The persistent publish failure must surface via close — never a
    // false Ok.
    let closed = writer.close().await;
    assert!(
        closed.is_err(),
        "a failing final flush must be reported: {closed:?}"
    );
    assert_eq!(
        reload(&path).channel_ok_count(&b),
        0,
        "the failing publisher left the file untouched"
    );
    assert!(
        leftover_tmp_files(dir.path()).is_empty(),
        "no leftover temp files after the failed save"
    );
}
