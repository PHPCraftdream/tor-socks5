use super::super::construction_export::{Evidence, StorageEvidence};
use super::super::construction_wire::Receipt;
use super::*;
use std::time::Duration;
use tokio::sync::oneshot;

fn measured_future<T: 'static>(
    mut future: Pin<Box<dyn Future<Output = T>>>,
    polls: Arc<std::sync::atomic::AtomicUsize>,
) -> Pin<Box<dyn Future<Output = T>>> {
    Box::pin(poll_fn(move |cx| {
        polls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        future.as_mut().poll(cx)
    }))
}

fn fixture() -> (tempfile::TempDir, Delivery, PathBuf, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(directory.path()).unwrap();
    let allocated = base.join("owners-v1/1");
    let executable = base.join("fixture-child");
    let leaf = allocated.join("state/pt_state/fixture-child");
    std::fs::create_dir_all(&leaf).unwrap();
    let delivery = Delivery {
        evidence: Evidence {
            journal_sequence: 2,
            request_id: 0,
            identity: Some(1),
            event: SelectionEvent::StorageAssigned,
            outcome: SelectionOutcome::Reserved,
            explicit_disabled: true,
            effective_none: Some(true),
            storage: Some(StorageEvidence {
                base,
                allocated,
                slot: 1,
            }),
        },
        receipt: Some(Receipt {
            transaction: 3,
            registry: 1,
            operation: Operation::Assigned,
            journal_sequence: 2,
        }),
        producer_ack_sent: true,
        failure: None,
    };
    (directory, delivery, leaf, executable)
}

#[test]
fn receipt_and_exact_leaf_are_required_before_intent() {
    let (_directory, delivery, leaf, executable) = fixture();
    let frame = intent_frame(&delivery, &leaf, &executable).unwrap();
    assert!(frame.starts_with(b"INTENT "));
    assert_eq!(delivery.evidence.request_id, 0);
    for mutation in 0..6 {
        let mut invalid = delivery.clone();
        match mutation {
            0 => invalid.receipt = None,
            1 => invalid.producer_ack_sent = false,
            2 => invalid.evidence.explicit_disabled = false,
            3 => invalid.evidence.effective_none = Some(false),
            4 => invalid.receipt.as_mut().unwrap().journal_sequence += 1,
            _ => invalid.receipt.as_mut().unwrap().registry = 0,
        }
        assert!(intent_frame(&invalid, &leaf, &executable).is_err());
    }
    assert!(intent_frame(&delivery, leaf.parent().unwrap(), &executable).is_err());
    assert!(intent_frame(&delivery, &leaf, Path::new("other-child")).is_err());
}

async fn listener(deadline: Instant) -> TcpListener {
    timeout_at(deadline, TcpListener::bind("127.0.0.1:0"))
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn full_owner_response_precedes_child_readiness_and_no_intent_retry() {
    let deadline = Instant::now() + Duration::from_secs(5);
    let (_directory, delivery, leaf, executable) = fixture();
    let supervisor = listener(deadline).await;
    let supervisor_address = supervisor.local_addr().unwrap();
    let ready = listener(deadline).await;
    let ready_address = ready.local_addr().unwrap();
    let mut owner = Coordinator::new(ready, executable.clone(), supervisor_address);
    owner.observe(&delivery, 0).unwrap();
    let expected = intent_frame(&delivery, &leaf, &executable).unwrap();
    let (partial_tx, partial_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let (done_tx, done_rx) = oneshot::channel();
    let request = format!("READY {}\n", hex(leaf.as_os_str().as_bytes()));
    let child = async {
        let mut stream = TcpStream::connect(ready_address).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        partial_rx.await.unwrap();
        let mut byte = [0];
        assert!(
            futures::poll!(Box::pin(stream.read(&mut byte))).is_pending(),
            "child authorized from partial owner response"
        );
        release_tx.send(()).unwrap();
        let response = line(&mut stream, deadline, 64).await.unwrap();
        assert!(response.starts_with(b"READY ") && response.ends_with(b"\n"));
        done_tx.send(()).unwrap();
    };
    let peer = async {
        let (mut stream, _) = supervisor.accept().await.unwrap();
        let mut actual = vec![0; expected.len()];
        stream.read_exact(&mut actual).await.unwrap();
        assert_eq!(actual, expected);
        stream.write_all(b"O").await.unwrap();
        partial_tx.send(()).unwrap();
        release_rx.await.unwrap();
        stream.write_all(b"K\n").await.unwrap();
        // Keep the authenticated-side socket until the child actually reads readiness.
        done_rx.await.unwrap();
    };
    let driver = async {
        let request = poll_fn(|cx| owner.poll_request(cx, deadline))
            .await
            .unwrap();
        owner.start(request, 0, deadline).unwrap();
        poll_fn(|cx| owner.poll_active(cx)).await.unwrap();
        assert!(owner.phase_complete(0));
        assert!(owner.allocations[0].used);
        assert!(owner.observe(&delivery, 0).is_err());
        owner.settle().await.unwrap();
    };
    timeout_at(deadline, async {
        tokio::join!(child, peer, driver);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn unregistered_and_configured_children_never_send_owner_intent() {
    let deadline = Instant::now() + Duration::from_secs(5);
    let (_directory, mut delivery, leaf, executable) = fixture();
    let supervisor = listener(deadline).await;
    let ready = listener(deadline).await;
    let address = ready.local_addr().unwrap();
    let mut owner = Coordinator::new(ready, executable, supervisor.local_addr().unwrap());
    delivery.evidence.explicit_disabled = false;
    owner.observe(&delivery, 0).unwrap();
    assert!(owner.allocations.is_empty());
    let child = async {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream
            .write_all(format!("READY {}\n", hex(leaf.as_os_str().as_bytes())).as_bytes())
            .await
            .unwrap();
        let mut byte = [0];
        assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
    };
    let driver = async {
        let request = poll_fn(|cx| owner.poll_request(cx, deadline))
            .await
            .unwrap();
        assert!(owner.start(request, 0, deadline).is_err());
        assert!(!owner.has_active());
        assert!(futures::poll!(Box::pin(supervisor.accept())).is_pending());
    };
    timeout_at(deadline, async {
        tokio::join!(child, driver);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancelled_active_intent_remains_owned_until_explicit_settlement() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let deadline = Instant::now() + Duration::from_secs(5);
    let (_directory, delivery, leaf, executable) = fixture();
    let supervisor = listener(deadline).await;
    let ready = listener(deadline).await;
    let address = ready.local_addr().unwrap();
    let mut owner = Coordinator::new(ready, executable.clone(), supervisor.local_addr().unwrap());
    owner.observe(&delivery, 0).unwrap();
    let expected = intent_frame(&delivery, &leaf, &executable).unwrap();
    let (held_tx, held_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let child = async {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream
            .write_all(format!("READY {}\n", hex(leaf.as_os_str().as_bytes())).as_bytes())
            .await
            .unwrap();
        let mut byte = [0];
        assert_eq!(
            stream.read(&mut byte).await.unwrap(),
            0,
            "stopped intent authorized child",
        );
    };
    let peer = async {
        let (mut stream, _) = supervisor.accept().await.unwrap();
        let mut actual = vec![0; expected.len()];
        stream.read_exact(&mut actual).await.unwrap();
        assert_eq!(actual, expected);
        held_tx.send(()).unwrap();
        release_rx.await.unwrap();
        stream.write_all(b"OK\n").await.unwrap();
    };
    let driver = async {
        let request = poll_fn(|cx| owner.poll_request(cx, deadline))
            .await
            .unwrap();
        owner.start(request, 0, deadline).unwrap();
        let polls = Arc::new(AtomicUsize::new(0));
        let transaction = owner.active.take().unwrap();
        owner.active = Some(measured_future(transaction, Arc::clone(&polls)));
        let mut active = Box::pin(poll_fn(|cx| owner.poll_active(cx)));
        tokio::select! {
            result = &mut active => panic!("INTENT completed before hold: {result:?}"),
            result = held_rx => result.unwrap(),
        }
        drop(active);
        assert!(owner.has_active());
        let before_calibration = polls.load(Ordering::SeqCst);
        assert!(before_calibration > 0);
        assert!(futures::poll!(Box::pin(poll_fn(|cx| owner.poll_active(cx)))).is_pending());
        let baseline = polls.load(Ordering::SeqCst);
        assert_eq!(baseline, before_calibration + 1);
        let transaction = owner.active.as_ref().unwrap().as_ref().get_ref()
            as *const dyn Future<Output = Result<()>>;
        let mut first = String::new();
        owner.append_failure_projection(&mut first);
        let mut second = String::new();
        owner.append_failure_projection(&mut second);
        assert_eq!(polls.load(Ordering::SeqCst), baseline);
        assert_eq!(first, second);
        assert!(std::ptr::eq(
            transaction,
            owner.active.as_ref().unwrap().as_ref().get_ref(),
        ));
        assert!(first.contains(
            "incoming_present=false active_present=true failed=false stopped=false allocation_count=1"
        ));
        assert!(
            first.contains("registry=Some(1) request=0 journal=2 identity=Some(1) slot=Some(1)")
        );
        assert!(first.contains("receipt_transaction=Some(3) used_attempted=true"));
        assert!(first.contains("producer_ack_sent_local=true failed=false"));
        assert!(!first.contains("fixture-child"));
        assert!(!owner.stop.is_cancelled());
        assert!(owner.allocations[0].used);
        assert!(futures::poll!(Box::pin(poll_fn(|cx| owner.poll_active(cx)))).is_pending());
        assert_eq!(polls.load(Ordering::SeqCst), baseline + 1);
        owner.stop();
        assert!(owner.has_active());
        release_tx.send(()).unwrap();
        assert!(owner.settle().await.is_err());
        assert!(polls.load(Ordering::SeqCst) > baseline + 1);
        assert!(!owner.has_active());
        assert!(!owner.phase_complete(0));
        assert!(owner.settle().await.is_err());
    };
    timeout_at(deadline, async {
        tokio::join!(child, peer, driver);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn failure_projection_does_not_poll_or_replace_partial_incoming_request() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let deadline = Instant::now() + Duration::from_secs(5);
    let ready = listener(deadline).await;
    let address = ready.local_addr().unwrap();
    let supervisor = listener(deadline).await;
    let mut owner = Coordinator::new(
        ready,
        PathBuf::from("/PRIVATE_EXECUTABLE_SENTINEL"),
        supervisor.local_addr().unwrap(),
    );
    let mut child = timeout_at(deadline, TcpStream::connect(address))
        .await
        .unwrap()
        .unwrap();
    timeout_at(deadline, child.write_all(b"READY "))
        .await
        .unwrap()
        .unwrap();
    assert!(futures::poll!(Box::pin(poll_fn(|cx| owner.poll_request(cx, deadline)))).is_pending());
    let polls = Arc::new(AtomicUsize::new(0));
    let incoming = owner.incoming.take().unwrap();
    owner.incoming = Some(measured_future(incoming, Arc::clone(&polls)));
    assert!(futures::poll!(Box::pin(poll_fn(|cx| owner.poll_request(cx, deadline)))).is_pending());
    assert_eq!(polls.load(Ordering::SeqCst), 1);
    let incoming = owner.incoming.as_ref().unwrap().as_ref().get_ref()
        as *const dyn Future<Output = Result<Request>>;
    let mut first = String::new();
    owner.append_failure_projection(&mut first);
    let mut second = String::new();
    owner.append_failure_projection(&mut second);
    assert_eq!(polls.load(Ordering::SeqCst), 1);
    assert_eq!(first, second);
    assert!(std::ptr::eq(
        incoming,
        owner.incoming.as_ref().unwrap().as_ref().get_ref(),
    ));
    assert!(first.contains(
        "incoming_present=true active_present=false failed=false stopped=false allocation_count=0"
    ));
    assert!(!first.contains("PRIVATE_EXECUTABLE_SENTINEL"));
    assert!(!owner.stop.is_cancelled());
    assert!(futures::poll!(Box::pin(poll_fn(|cx| owner.poll_request(cx, deadline)))).is_pending());
    assert_eq!(polls.load(Ordering::SeqCst), 2);
    timeout_at(
        deadline,
        child.write_all(b"2f5041525449414c5f504154485f53454e54494e454c\n"),
    )
    .await
    .unwrap()
    .unwrap();
    let request = timeout_at(deadline, poll_fn(|cx| owner.poll_request(cx, deadline)))
        .await
        .unwrap()
        .unwrap();
    assert!(polls.load(Ordering::SeqCst) > 2);
    assert_eq!(request.leaf, PathBuf::from("/PARTIAL_PATH_SENTINEL"));
    assert!(owner.incoming.is_none());
    assert!(owner.active.is_none());
    assert!(owner.allocations.is_empty());
    assert!(futures::poll!(Box::pin(supervisor.accept())).is_pending());
    drop(request);
}
