use super::*;
use futures::poll;
use std::cell::Cell;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncReadExt, AsyncWrite};
use tokio::time::advance;

struct Lease(Rc<Cell<usize>>);
impl Lease {
    fn new(count: &Rc<Cell<usize>>) -> Self {
        count.set(count.get() + 1);
        Self(count.clone())
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.0.set(self.0.get() - 1);
    }
}

#[tokio::test(start_paused = true)]
async fn total_thirty_seconds_includes_tunnel_then_provider_and_releases_permit() {
    let live = Rc::new(Cell::new(0));
    let acquired = Rc::new(Cell::new(false));
    let attempts = Rc::new(Cell::new(0));
    let backend = Arc::new(Semaphore::new(64));
    let permit = backend.clone().try_acquire_owned().unwrap();
    let start = Instant::now();
    let tunnel_lease = Lease::new(&live);
    let acquisition = {
        let acquired = acquired.clone();
        move || async move {
            tokio::time::sleep(Duration::from_secs(12)).await;
            acquired.set(true);
            Some(tunnel_lease)
        }
    };
    let traversal = {
        let attempts = attempts.clone();
        let live = live.clone();
        move |tunnel| async move {
            let _tunnel = tunnel;
            attempts.set(1);
            {
                let _stream = Lease::new(&live);
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
            attempts.set(2);
            let _stream = Lease::new(&live);
            std::future::pending::<Result<ResolvedAnswer, DnsServerError>>().await
        }
    };
    let mut work = Box::pin(async move {
        let result = finish_miss(
            start + RESOLUTION_TIMEOUT,
            acquire_then_resolve(acquisition, traversal),
        )
        .await;
        drop(permit);
        result
    });
    assert!(poll!(&mut work).is_pending());
    advance(Duration::from_secs(12)).await;
    assert!(poll!(&mut work).is_pending());
    assert!(acquired.get());
    assert_eq!(attempts.get(), 1);
    advance(Duration::from_secs(10)).await;
    assert!(poll!(&mut work).is_pending());
    assert_eq!(attempts.get(), 2);
    assert_eq!(live.get(), 2);
    advance(Duration::from_secs(7)).await;
    assert!(poll!(&mut work).is_pending());
    assert_eq!(backend.available_permits(), 63);
    advance(Duration::from_secs(1)).await;
    assert!(matches!(poll!(&mut work), Poll::Ready(None)));
    assert_eq!(Instant::now() - start, Duration::from_secs(30));
    assert_eq!(live.get(), 0);
    assert_eq!(backend.available_permits(), 64);
}

#[tokio::test(start_paused = true)]
async fn tunnel_acquisition_alone_expires_at_thirty_seconds() {
    let backend = Arc::new(Semaphore::new(64));
    let permit = backend.clone().try_acquire_owned().unwrap();
    let live = Rc::new(Cell::new(0));
    let lease = Lease::new(&live);
    let start = Instant::now();
    let mut work = Box::pin(async move {
        let answer = finish_miss(
            start + RESOLUTION_TIMEOUT,
            acquire_then_resolve(
                move || async move {
                    let _lease = lease;
                    std::future::pending::<Option<()>>().await
                },
                |_| async { panic!("provider must not run without tunnel") },
            ),
        )
        .await;
        drop(permit);
        answer
    });
    assert!(poll!(&mut work).is_pending());
    advance(Duration::from_secs(29)).await;
    assert!(poll!(&mut work).is_pending());
    assert_eq!(backend.available_permits(), 63);
    advance(Duration::from_secs(1)).await;
    assert!(matches!(poll!(&mut work), Poll::Ready(None)));
    assert_eq!(live.get(), 0);
    assert_eq!(backend.available_permits(), 64);
    assert_eq!(Instant::now() - start, RESOLUTION_TIMEOUT);
}

#[tokio::test(start_paused = true)]
async fn frame_prefix_and_body_share_exact_thirty_second_deadline() {
    let (mut peer, mut reader) = tokio::io::duplex(64);
    peer.write_all(&[0]).await.unwrap();
    let start = Instant::now();
    let mut read = Box::pin(wire::read_framed_message(&mut reader, RESOLUTION_TIMEOUT));
    assert!(poll!(&mut read).is_pending());
    advance(Duration::from_secs(20)).await;
    peer.write_all(&[5, b'x']).await.unwrap();
    assert!(poll!(&mut read).is_pending());
    advance(Duration::from_secs(9)).await;
    assert!(poll!(&mut read).is_pending());
    advance(Duration::from_secs(1)).await;
    let Poll::Ready(Err(error)) = poll!(&mut read) else {
        panic!("whole frame must expire at 30s");
    };
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(Instant::now() - start, RESOLUTION_TIMEOUT);
}

struct PartialStalledWriter {
    bytes: Vec<u8>,
    quota: usize,
}
impl AsyncWrite for PartialStalledWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.quota == 0 {
            return Poll::Pending;
        }
        let count = bytes.len().min(self.quota);
        self.bytes.extend_from_slice(&bytes[..count]);
        self.quota -= count;
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test(start_paused = true)]
async fn stalled_partial_frame_write_expires_without_restarting_prefix() {
    let mut writer = PartialStalledWriter {
        bytes: vec![],
        quota: 3,
    };
    let mut write = Box::pin(wire::write_framed_message(
        &mut writer,
        b"abcd",
        RESOLUTION_TIMEOUT,
    ));
    assert!(poll!(&mut write).is_pending());
    advance(Duration::from_secs(29)).await;
    assert!(poll!(&mut write).is_pending());
    advance(Duration::from_secs(1)).await;
    let Poll::Ready(Err(error)) = poll!(&mut write) else {
        panic!("stalled output must expire");
    };
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    drop(write);
    assert_eq!(writer.bytes, vec![0, 4, b'a']);
}

#[tokio::test]
async fn real_tcp_idle_connection_uses_no_backend_and_cancellation_closes_it() {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let backend = Arc::new(Semaphore::new(64));
    let connections = Arc::new(Semaphore::new(1));
    let mut service = Box::pin(listener::tcp_loop(
        tcp,
        ctx(vec![], vec![addr]),
        backend.clone(),
        connections.clone(),
    ));
    let mut peer = TcpStream::connect(addr).await.unwrap();
    {
        let req = request("localhost.", RecordType::A, 31);
        tokio::select! { _ = &mut service => panic!("listener ended"), reply = tcp_exchange(&mut peer, &req) => { assert_eq!(reply.metadata.id, 31); } }
    }
    assert_eq!(connections.available_permits(), 0);
    assert_eq!(backend.available_permits(), 64);
    drop(service);
    assert_eq!(connections.available_permits(), 1);
    let mut byte = [0];
    assert_eq!(peer.read(&mut byte).await.unwrap(), 0);
}

/// Counterfactual: retaining tcp_loop's production permit after the handler
/// returns fails the available-permit assertion and prevents the next real
/// client from being answered. Removing/extending the 30s read timeout fails
/// the bounded completion wait; early release fails the occupied check at 29s.
#[tokio::test]
async fn real_tcp_partial_frame_timeout_releases_connection_without_backend() {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let backend = Arc::new(Semaphore::new(64));
    let connections = Arc::new(Semaphore::new(1));
    let (gate_tx, gate_rx) = tokio::sync::oneshot::channel();
    let mut first_gate = Some(gate_rx);
    let (completed_tx, mut completed_rx) = tokio::sync::mpsc::channel(1);
    let mut service = Box::pin(listener::tcp_loop_gated(
        tcp,
        ctx(vec![], vec![addr]),
        backend.clone(),
        connections.clone(),
        move || {
            // Only the first connection's second frame waits. A fresh client
            // gets an immediately-ready gate, not a reused/spent receiver.
            let mut gate_rx = first_gate.take();
            let mut frames = 0;
            move || {
                frames += 1;
                let gate = if frames == 2 { gate_rx.take() } else { None };
                async move {
                    if let Some(gate) = gate {
                        gate.await.unwrap();
                    }
                }
            }
        },
        move || completed_tx.try_send(()).unwrap(),
    ));
    let mut peer = TcpStream::connect(addr).await.unwrap();
    let req = request("localhost.", RecordType::A, 32);
    tokio::select! {
        _ = &mut service => panic!("listener ended"),
        reply = tcp_exchange(&mut peer, &req) => {
            assert_eq!(reply.metadata.id, 32);
            assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
            assert_eq!(reply.answers[0].data, RData::A(A("127.0.0.1".parse().unwrap())));
        }
    }
    peer.write_all(&[0]).await.unwrap();
    tokio::time::pause();
    gate_tx.send(()).unwrap();
    // Drive the gate and register the actual production frame timer after pause.
    assert!(poll!(&mut service).is_pending());
    let start = Instant::now();
    advance(Duration::from_secs(29)).await;
    assert!(poll!(&mut service).is_pending());
    assert_eq!(connections.available_permits(), 0);
    assert_eq!(backend.available_permits(), 64);
    assert!(matches!(
        completed_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    advance(Duration::from_secs(1)).await;
    assert_eq!(Instant::now() - start, Duration::from_secs(30));
    // Await work.next's observation of actual connection completion, not a
    // test-owned guard drop or cancellation of the infinite listener loop.
    tokio::select! {
        _ = &mut service => panic!("listener ended"),
        completed = timeout(Duration::from_millis(100), completed_rx.recv()) => {
            assert_eq!(
                completed.expect("partial-frame handler did not complete after its deadline"),
                Some(())
            );
        }
    }
    assert_eq!(connections.available_permits(), 1);
    assert_eq!(backend.available_permits(), 64);
    // Handler completion and permit reclamation are established above. Resume
    // before observing real socket EOF: paused time can auto-advance a guard
    // before the OS delivers readiness, despite the server stream being closed.
    tokio::time::resume();
    // Closing with the partial byte still unread yields RST instead of FIN;
    // whether the server read it before the virtual deadline depends on when
    // the OS readiness reached the driver (Windows reports the RST as
    // ConnectionAborted, other platforms as ConnectionReset). All prove the
    // server closed.
    let mut byte = [0];
    match timeout(CASE_BUDGET, peer.read(&mut byte))
        .await
        .expect("timed-out connection did not close")
    {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
            ) => {}
        other => panic!("timed-out connection was not closed: {other:?}"),
    }

    // The same production listener must admit and answer another connection
    // using the reclaimed capacity, also with real I/O and the clock resumed.
    tokio::select! {
        _ = &mut service => panic!("listener ended"),
        result = timeout(CASE_BUDGET, async {
            let mut next_peer = TcpStream::connect(addr).await.unwrap();
            let req = request("localhost.", RecordType::A, 33);
            let reply = tcp_exchange(&mut next_peer, &req).await;
            assert_eq!(reply.metadata.id, 33);
            assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
            assert_eq!(reply.queries, req.queries);
            assert_eq!(reply.answers.len(), 1);
            assert_eq!(reply.answers[0].data, RData::A(A("127.0.0.1".parse().unwrap())));
            assert_eq!(connections.available_permits(), 0);
            assert_eq!(backend.available_permits(), 64);
        }) => result.expect("next real TCP client was not accepted and answered"),
    }
}

#[tokio::test]
async fn real_tcp_nonreading_peer_stalls_framed_output_and_releases_socket() {
    // The outer bound includes setup, fill and drain. Removing the frame
    // timeout fails this bound; retaining the stream prevents EOF during drain.
    timeout(Duration::from_secs(15), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut peer = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut stream, _) = listener.accept().await.unwrap();
        let budget = Duration::from_millis(500);
        wire::write_framed_message(&mut stream, b"warmup", budget)
            .await
            .unwrap();
        assert_eq!(
            wire::read_framed_message(&mut peer, budget)
                .await
                .unwrap()
                .unwrap(),
            b"warmup"
        );
        let payload = vec![0x5a; 65535];
        let mut completed = 0;
        // Stop at the first backpressured timeout, with at most 64MiB emitted.
        let error = loop {
            assert!(
                completed < 1024,
                "nonreading peer did not backpressure within 64MiB"
            );
            match wire::write_framed_message(&mut stream, &payload, budget).await {
                Ok(()) => completed += 1,
                Err(error) => break error,
            }
        };
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        drop(stream);
        let mut bytes = vec![0; 65535];
        let mut drained = 0usize;
        loop {
            match peer.read(&mut bytes).await {
                Ok(0) => break,
                Ok(count) => {
                    drained += count;
                    assert!(drained <= 1024 * (65535 + 2), "drain exceeded fill cap");
                }
                Err(error) => panic!("expected owned-stream EOF, got {error}"),
            }
        }
    })
    .await
    .expect("real TCP setup/fill/EOF drain exceeded outer execution bound");
}

#[tokio::test(start_paused = true)]
async fn periodic_save_keeps_listeners_live_bounds_one_and_shutdown_drains() {
    let shutdown = CancellationToken::new();
    let (probe_tx, mut probe_rx) = tokio::sync::mpsc::channel(1);
    let (ack_tx, mut ack_rx) = tokio::sync::mpsc::channel(1);
    let listener_live = Rc::new(Cell::new(0));
    let lease = Lease::new(&listener_live);
    let listeners = async move {
        let _lease = lease;
        loop {
            if probe_rx.recv().await.is_none() {
                return Ok(());
            }
            ack_tx.send(()).await.unwrap();
        }
    };
    let calls = Rc::new(Cell::new(0));
    let active = Rc::new(Cell::new(0));
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let receiver = Rc::new(std::cell::RefCell::new(Some(release_rx)));
    let save = {
        let calls = calls.clone();
        let active = active.clone();
        move || {
            calls.set(calls.get() + 1);
            let gate = receiver.borrow_mut().take();
            let lease = Lease::new(&active);
            async move {
                let _lease = lease;
                if let Some(gate) = gate {
                    gate.await.unwrap();
                }
                Ok(())
            }
        }
    };
    let mut service = Box::pin(serve_with_saves(listeners, save, shutdown.clone()));
    assert!(poll!(&mut service).is_pending());
    advance(CACHE_SAVE_INTERVAL).await;
    assert!(poll!(&mut service).is_pending());
    assert_eq!(calls.get(), 1);
    probe_tx.send(()).await.unwrap();
    assert!(poll!(&mut service).is_pending());
    assert_eq!(ack_rx.try_recv(), Ok(()));
    advance(CACHE_SAVE_INTERVAL * 2).await;
    assert!(poll!(&mut service).is_pending());
    assert_eq!(calls.get(), 1, "no overlapping or queued periodic saves");
    shutdown.cancel();
    assert!(poll!(&mut service).is_pending());
    assert_eq!(
        listener_live.get(),
        0,
        "socket scope closes before disk drain"
    );
    assert_eq!(active.get(), 1);
    release_tx.send(()).unwrap();
    assert!(matches!(poll!(&mut service), Poll::Ready(Ok(()))));
    assert_eq!(calls.get(), 2, "one serialized final save after drain");
    assert_eq!(active.get(), 0);
}
