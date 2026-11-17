use super::super::*;
use super::{config_path, reload, test_bridge};
use persist_lock::PathLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use time::OffsetDateTime;

async fn hold_store_lock(
    path: PathBuf,
) -> (std::sync::mpsc::Sender<()>, std::thread::JoinHandle<()>) {
    tokio::task::spawn_blocking(move || {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            let _lock = PathLock::acquire(&path).expect("holder acquires store lock");
            ready_tx.send(()).expect("test waits for lock holder");
            let _ = release_rx.recv();
        });
        ready_rx.recv().expect("lock holder becomes ready");
        (release_tx, holder)
    })
    .await
    .expect("lock holder setup task succeeds")
}

async fn join_holder(holder: std::thread::JoinHandle<()>) {
    tokio::task::spawn_blocking(move || holder.join().expect("lock holder joins"))
        .await
        .expect("holder join task succeeds");
}

#[tokio::test]
async fn busy_store_lock_rejects_unapplied_mutation_for_retry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bridge = test_bridge();
    let path = BridgeStore::resolve_path(Some(&config_path(dir.path())));
    let (release_lock, holder) = hold_store_lock(path.clone()).await;
    let writer = StoreWriter::spawn_with_lock_wait(
        path.clone(),
        Arc::new(|store| store.save()),
        INITIAL_BACKOFF,
        Duration::from_millis(100),
    );
    let mutation_calls = Arc::new(AtomicUsize::new(0));
    let calls = Arc::clone(&mutation_calls);
    let bridge_for_first_attempt = bridge.clone();
    let error = writer
        .apply(move |store| {
            calls.fetch_add(1, Ordering::SeqCst);
            store.note_source_at(
                &bridge_for_first_attempt,
                "retry-me",
                OffsetDateTime::now_utc(),
            );
        })
        .await
        .expect_err("a held lock must reject this unapplied operation");
    assert!(
        error.to_string().contains("busy"),
        "unexpected error: {error:#}"
    );
    assert_eq!(mutation_calls.load(Ordering::SeqCst), 0);

    release_lock.send(()).expect("release holder");
    join_holder(holder).await;

    let calls_for_retry = Arc::clone(&mutation_calls);
    let bridge_for_retry = bridge.clone();
    writer
        .apply(move |store| {
            calls_for_retry.fetch_add(1, Ordering::SeqCst);
            store.note_source_at(&bridge_for_retry, "retry-me", OffsetDateTime::now_utc());
        })
        .await
        .expect("the same mutation can be retried after the lock is released");
    writer.close().await.expect("writer closes");

    assert_eq!(mutation_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        reload(&config_path(dir.path())).sources_of(&bridge),
        vec!["retry-me"]
    );
}

#[tokio::test]
async fn close_bypasses_saturated_mutations_while_clean_load_waits_for_lock() {
    let registry = Arc::new(crate::workers::TestWorkers::default());
    registry
        .scope(async {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = BridgeStore::resolve_path(Some(&config_path(dir.path())));
            let (release_lock, holder) = hold_store_lock(path.clone()).await;
            let (load_started_tx, load_started_rx) = oneshot::channel();
            let writer = StoreWriter::spawn_with_load_started(
                path.clone(),
                Arc::new(|store| store.save()),
                INITIAL_BACKOFF,
                CLI_LOCK_WAIT,
                load_started_tx,
            );
            let mutation_calls = Arc::new(AtomicUsize::new(0));
            let first_calls = Arc::clone(&mutation_calls);
            let first_writer = writer.clone();
            let first_apply = tokio::spawn(async move {
                first_writer
                    .apply(move |_| {
                        first_calls.fetch_add(1, Ordering::SeqCst);
                    })
                    .await
            });

            load_started_rx.await.expect("clean-load worker started");
            assert!(
                registry.pending_count().await > 0,
                "the clean-load worker must remain registered while the lock is held"
            );
            let mut queued_acks = Vec::new();
            for _ in 0..64 {
                let (ack_tx, ack_rx) = oneshot::channel();
                let calls = Arc::clone(&mutation_calls);
                writer
                    .tx
                    .try_send(Op::Mutate {
                        apply: Box::new(move |_| {
                            calls.fetch_add(1, Ordering::SeqCst);
                        }),
                        ack: ack_tx,
                    })
                    .expect("fill the bounded mutation queue");
                queued_acks.push(ack_rx);
            }
            assert_eq!(writer.tx.capacity(), 0, "mutation queue must be saturated");

            let close_result = tokio::time::timeout(Duration::from_secs(2), writer.close()).await;
            let close_was_timely = close_result.is_ok();
            release_lock.send(()).expect("release holder");
            join_holder(holder).await;
            let final_close = if close_was_timely {
                close_result.expect("close completed within budget")
            } else {
                writer.close().await
            };
            final_close.expect("clean writer closes successfully");
            assert!(
                close_was_timely,
                "close must finish within budget without waiting for the held lock/load"
            );
            assert!(
                first_apply.await.expect("first apply task joins").is_err(),
                "the mutation whose load was interrupted was not applied"
            );
            for ack in queued_acks {
                assert!(
                    ack.await
                        .expect("queued mutation receives a reply")
                        .is_err(),
                    "queued operations must be rejected on close"
                );
            }
            assert_eq!(mutation_calls.load(Ordering::SeqCst), 0);

            registry
                .join()
                .await
                .expect("cancelled load worker is reaped");
            let lock = PathLock::acquire_bounded(&path, Duration::from_secs(1))
                .expect("cancelled load must release any lock it acquired");
            drop(lock);
        })
        .await;
}

#[tokio::test]
async fn close_applies_and_persists_mutations_queued_with_loaded_snapshot() {
    use std::future::{poll_fn, Future};
    use std::task::Poll;

    const MUTATIONS: u32 = 12;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = config_path(dir.path());
    let writer = StoreWriter::open(Some(&path));
    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let first_bridge = test_bridge();
    let first_writer = writer.clone();
    let first_apply = tokio::spawn(async move {
        first_writer
            .apply(move |store| {
                let _ = started_tx.send(());
                release_rx.recv().expect("test releases initial mutation");
                store.note_source_at(&first_bridge, "before-close", OffsetDateTime::now_utc());
            })
            .await
    });
    started_rx
        .await
        .expect("snapshot loaded and mutation is running");

    let mut queued_acks = Vec::new();
    for index in 0..MUTATIONS {
        let (ack_tx, ack_rx) = oneshot::channel();
        let source = format!("queued-{index}");
        let bridge = test_bridge();
        writer
            .tx
            .try_send(Op::Mutate {
                apply: Box::new(move |store| {
                    store.note_source_at(&bridge, &source, OffsetDateTime::now_utc());
                }),
                ack: ack_tx,
            })
            .expect("queue mutation before close");
        queued_acks.push(ack_rx);
    }

    let mut close = Box::pin(writer.close());
    let close_poll = poll_fn(|cx| Poll::Ready(close.as_mut().poll(cx))).await;
    let close_waited_for_mutation = close_poll.is_pending();
    let close_holds_actor = writer.actor.try_lock().is_err();
    release_tx.send(()).expect("release initial mutation");
    first_apply
        .await
        .expect("initial apply task joins")
        .expect("initial mutation applies");
    assert!(close_waited_for_mutation, "close waits for loaded mutation");
    assert!(close_holds_actor, "close signal is sent");
    close.await.expect("close flushes queued mutations");

    for ack in queued_acks {
        ack.await
            .expect("queued mutation receives acknowledgement")
            .expect("queued mutation was applied");
    }
    let persisted = reload(&path).sources_of(&test_bridge());
    let mut expected: Vec<String> = (0..MUTATIONS)
        .map(|index| format!("queued-{index}"))
        .collect();
    expected.push("before-close".to_string());
    expected.sort();
    assert_eq!(persisted, expected, "all queued mutations reached disk");
}
