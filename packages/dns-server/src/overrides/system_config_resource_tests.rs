use super::*;
use hickory_proto::op::{Message, OpCode};
use hickory_proto::rr::RecordType;
use std::future::{poll_fn, Future};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::Poll;
use tokio::sync::{oneshot, Semaphore};

// Releases parked blocking workers on unwind, and explicitly before assertions.
struct ReleaseWorker(Option<std::sync::mpsc::SyncSender<()>>);
impl Drop for ReleaseWorker {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            // One message total; receiver disappearance means work already ended.
            let _ = sender.send(());
        }
    }
}

// Poll exactly once: observes admission without sleeps or scheduler assumptions.
// The child registers its own waker; this wrapper immediately returns its Poll.
async fn poll_once<F: Future>(mut future: Pin<&mut F>) -> Poll<F::Output> {
    poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx))).await
}

// Tokio 1.52.3 advance does not acknowledge timer processing. Drive the
// actual result and a later fixture-only guard together: explicit advancement
// also works while spawn_blocking inhibits paused-clock auto-advance.
// cancel-safe: yes — only borrows the caller-owned future; caller drops it on
// guard expiry, and ReleaseWorker still releases the parked worker on unwind.
async fn observe_system_deadline<F: Future>(
    mut future: Pin<&mut F>,
) -> (bool, Result<F::Output, tokio::time::error::Elapsed>) {
    tokio::time::pause();
    let margin = Duration::from_secs(1);
    tokio::time::advance(SYSTEM_RESOLVER_TIMEOUT - margin).await;
    let before = poll_once(future.as_mut()).await;
    let result = match before {
        Poll::Ready(result) => (false, Ok(result)),
        Poll::Pending => {
            tokio::time::advance(margin).await;
            let (result, ()) = tokio::join!(
                tokio::time::timeout(margin, future),
                tokio::time::advance(margin),
            );
            (true, result)
        }
    };
    tokio::time::resume();
    result
}

fn question() -> Query {
    Query::query("example.test.".parse().unwrap(), RecordType::A)
}

// cancel-safe: yes — borrows the fixture socket; cancelled receive/send has
// no framing state to resume and the fixture is discarded with the test.
async fn answer_once(socket: &UdpSocket) -> Result<Message, DnsServerError> {
    let mut buf = [0; 512];
    let (n, peer) = socket
        .recv_from(&mut buf)
        .await
        .map_err(|e| DnsServerError::PlainDns(e.to_string()))?;
    let request = Message::from_vec(&buf[..n]).map_err(|e| DnsServerError::Wire(e.to_string()))?;
    let mut answer = Message::response(request.metadata.id, OpCode::Query);
    answer.add_query(request.queries[0].clone());
    let bytes = answer
        .to_vec()
        .map_err(|e| DnsServerError::Wire(e.to_string()))?;
    socket
        .send_to(&bytes, peer)
        .await
        .map_err(|e| DnsServerError::PlainDns(e.to_string()))?;
    Message::from_vec(&bytes).map_err(|e| DnsServerError::Wire(e.to_string()))
}

#[tokio::test]
async fn concurrent_system_lookups_wait_and_read_fresh_configuration_in_order() {
    let gate = Arc::new(Semaphore::new(1));
    let calls = Arc::new(AtomicUsize::new(0));
    let first_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let second_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let first_server = first_socket.local_addr().unwrap();
    let second_server = second_socket.local_addr().unwrap();
    let q = question();
    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let release = ReleaseWorker(Some(release_tx));
    let first_calls = Arc::clone(&calls);
    let mut first = Box::pin(system_with_config(
        &q,
        &[],
        schedule_config_read(Arc::clone(&gate), move || {
            let order = first_calls.fetch_add(1, Ordering::SeqCst);
            // Best effort: caller may have stopped caring about this handshake.
            let _ = started_tx.send(order);
            let _ = release_rx.recv();
            Ok(vec![first_server])
        }),
    ));
    let start = tokio::select! {
        started = started_rx => started.ok(),
        _ = &mut first => None,
    };
    let second_calls = Arc::clone(&calls);
    let (order_tx, order_rx) = oneshot::channel();
    let mut second = Box::pin(system_with_config(
        &q,
        &[],
        schedule_config_read(Arc::clone(&gate), move || {
            let order = second_calls.fetch_add(1, Ordering::SeqCst);
            let _ = order_tx.send(order); // Observer may have cancelled.
            Ok(vec![second_server])
        }),
    ));
    let pending = poll_once(second.as_mut()).await;
    let calls_before_release = calls.load(Ordering::SeqCst);
    // Release BEFORE asserting even under busy-fail / premature-admission mutants.
    drop(release);
    assert_eq!(start, Some(0));
    assert!(
        pending.is_pending(),
        "second lookup did not wait: {pending:?}"
    );
    assert_eq!(calls_before_release, 1);
    let (first, second, first_reply, second_reply) = tokio::join!(
        first,
        second,
        tokio::time::timeout(SYSTEM_RESOLVER_TIMEOUT, answer_once(&first_socket)),
        tokio::time::timeout(SYSTEM_RESOLVER_TIMEOUT, answer_once(&second_socket)),
    );
    assert_eq!(first.unwrap().message, first_reply.unwrap().unwrap());
    assert_eq!(second.unwrap().message, second_reply.unwrap().unwrap());
    assert_eq!(order_rx.await.ok(), Some(1));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(gate.available_permits(), 1);
}

async fn cancelled_read_retains_admission(timeout_caller: bool) {
    let gate = Arc::new(Semaphore::new(1));
    let calls = Arc::new(AtomicUsize::new(0));
    let q = question();
    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let release = ReleaseWorker(Some(release_tx));
    let worker_calls = Arc::clone(&calls);
    let mut read = Box::pin(system_with_config(
        &q,
        &[],
        schedule_config_read(Arc::clone(&gate), move || {
            worker_calls.fetch_add(1, Ordering::SeqCst);
            let _ = started_tx.send(()); // Cancelled observer no longer cares.
            let _ = release_rx.recv();
            Ok(vec![])
        }),
    ));
    let started = tokio::select! {
        started = started_rx => started.is_ok(),
        _ = &mut read => false,
    };
    let mut timeout_result = None;
    if timeout_caller && started {
        timeout_result = Some(observe_system_deadline(read.as_mut()).await);
    }
    drop(read);
    let held_after_cancel = gate.available_permits();
    let second_calls = Arc::clone(&calls);
    let expected: SocketAddr = "192.0.2.53:53".parse().unwrap();
    let mut second = Box::pin(schedule_config_read(Arc::clone(&gate), move || {
        second_calls.fetch_add(1, Ordering::SeqCst);
        Ok(vec![expected])
    }));
    let pending = poll_once(second.as_mut()).await;
    let observed_calls = calls.load(Ordering::SeqCst);
    drop(release);
    assert!(started, "parked read returned before worker handshake");
    if timeout_caller {
        assert!(
            matches!(timeout_result, Some((true, Ok(Err(DnsServerError::Timeout(d))))) if d == SYSTEM_RESOLVER_TIMEOUT),
            "public system budget did not expire"
        );
    }
    assert_eq!(held_after_cancel, 0, "caller released worker's permit");
    assert!(
        pending.is_pending(),
        "second read did not wait: {pending:?}"
    );
    assert_eq!(observed_calls, 1, "scheduled before actual completion");
    assert_eq!(second.await.unwrap(), vec![expected]);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(gate.available_permits(), 1);
}

#[tokio::test]
async fn cancelled_config_read_retains_worker_permit_until_actual_completion() {
    cancelled_read_retains_admission(false).await;
}

#[tokio::test]
async fn timed_out_config_read_retains_worker_permit_until_actual_completion() {
    cancelled_read_retains_admission(true).await;
}

async fn cancelled_waiter_never_schedules(timeout_caller: bool) {
    let gate = Arc::new(Semaphore::new(1));
    let calls = Arc::new(AtomicUsize::new(0));
    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let release = ReleaseWorker(Some(release_tx));
    let mut active = Box::pin(schedule_config_read(Arc::clone(&gate), move || {
        let _ = started_tx.send(()); // Best effort if setup was cancelled.
        let _ = release_rx.recv();
        Ok(vec![])
    }));
    let started = tokio::select! {
        started = started_rx => started.is_ok(),
        _ = &mut active => false,
    };
    let q = question();
    let waiter_calls = Arc::clone(&calls);
    let mut waiter = Box::pin(system_with_config(
        &q,
        &[],
        schedule_config_read(Arc::clone(&gate), move || {
            waiter_calls.fetch_add(1, Ordering::SeqCst);
            Ok(vec![])
        }),
    ));
    let pending = poll_once(waiter.as_mut()).await;
    let mut timeout_result = None;
    if timeout_caller && pending.is_pending() {
        timeout_result = Some(observe_system_deadline(waiter.as_mut()).await);
    }
    drop(waiter);
    let held_after_cancel = gate.available_permits();
    let calls_before_release = calls.load(Ordering::SeqCst);
    drop(release);
    assert!(started, "active read did not start");
    assert!(pending.is_pending(), "waiter did not wait: {pending:?}");
    if timeout_caller {
        assert!(
            matches!(timeout_result, Some((true, Ok(Err(DnsServerError::Timeout(d))))) if d == SYSTEM_RESOLVER_TIMEOUT),
            "admission was outside public system budget"
        );
    }
    assert_eq!(
        held_after_cancel, 0,
        "waiter released active worker's permit"
    );
    assert_eq!(
        calls_before_release, 0,
        "waiter scheduled while worker parked"
    );
    active.await.unwrap();
    // A fresh read is a FIFO completion barrier: detached waiter work queued
    // on this same gate would run before it, making the count nonzero.
    let fresh = schedule_config_read(Arc::clone(&gate), || Ok(vec![])).await;
    assert!(fresh.is_ok(), "{fresh:?}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "cancelled waiter ran later"
    );
    assert_eq!(gate.available_permits(), 1);
}

#[tokio::test]
async fn cancelled_config_waiter_never_schedules_after_gate_release() {
    cancelled_waiter_never_schedules(false).await;
}

#[tokio::test]
async fn timed_out_config_waiter_never_schedules_after_gate_release() {
    cancelled_waiter_never_schedules(true).await;
}
