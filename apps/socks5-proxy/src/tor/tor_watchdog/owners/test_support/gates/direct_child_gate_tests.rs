use super::*;
use std::{
    cell::Cell,
    future::Future,
    net::{Ipv4Addr, SocketAddrV4},
    time::Duration,
};
use tokio::{net::TcpListener, sync::oneshot};

fn end() -> Instant {
    Instant::now()
        .checked_add(Duration::from_secs(5))
        .expect("test deadline fits")
}

async fn within<T>(deadline: Instant, future: impl Future<Output = T>) -> T {
    timeout_at(deadline, future)
        .await
        .expect("bounded test watchdog expired")
}

async fn listener(deadline: Instant) -> (TcpListener, SocketAddr) {
    let listener = within(
        deadline,
        TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
    )
    .await
    .unwrap();
    let address = listener.local_addr().unwrap();
    (listener, address)
}

async fn line(stream: &mut TcpStream, deadline: Instant) -> Vec<u8> {
    within(deadline, async {
        let mut result = Vec::new();
        loop {
            assert!(result.len() < 100, "unexpected child frame length");
            let mut byte = [0];
            stream.read_exact(&mut byte).await.unwrap();
            result.push(byte[0]);
            if byte[0] == b'\n' {
                return result;
            }
        }
    })
    .await
}

async fn bind_peer(listener: &TcpListener, deadline: Instant) -> TcpStream {
    let (mut stream, _) = within(deadline, listener.accept()).await.unwrap();
    let pid = std::process::id();
    assert!(pid > 1, "CI must run this test as a real non-init process");
    assert_eq!(
        line(&mut stream, deadline).await,
        format!("BIND {pid}\n").into_bytes(),
    );
    stream
}

fn group_frame(raw: &[u8]) -> Vec<u8> {
    let mut result = b"GROUP ".to_vec();
    for byte in raw {
        result.extend_from_slice(format!("{byte:02x}").as_bytes());
    }
    result.push(b'\n');
    result
}

#[test]
fn decoder_preserves_every_nonzero_byte_and_path_boundaries() {
    let raw: Vec<u8> = (1u8..=255).collect();
    let decoded = decode_group(&group_frame(&raw)).unwrap();
    assert_eq!(decoded.as_os_str().as_bytes(), raw);

    let maximum = vec![b'x'; MAX_PATH];
    assert_eq!(
        decode_group(&group_frame(&maximum))
            .unwrap()
            .as_os_str()
            .as_bytes(),
        maximum,
    );
    assert!(decode_group(&group_frame(&vec![b'x'; MAX_PATH + 1])).is_err());

    assert_eq!(
        decode_group(b"GROUP 2f78ff\n")
            .unwrap()
            .as_os_str()
            .as_bytes(),
        b"/x\xff",
    );
}

#[test]
fn decoder_rejects_noncanonical_or_incomplete_frames() {
    for frame in [
        b"".as_slice(),
        b"GROUP \n",
        b"GROUP 2\n",
        b"GROUP gg\n",
        b"GROUP FF\n",
        b"GROUP 00\n",
        b"GROUP 2f00\n",
        b"GROUP 2f78\r\n",
        b"GROUP 2f78",
        b"GROUP 2f78\nextra",
        b"GROUP 2f78 \n",
        b"group 2f78\n",
        b"OK\n",
        b"DENY peer\n",
    ] {
        assert!(decode_group(frame).is_err(), "accepted {frame:?}");
    }
    assert!(decode_group(&vec![b'x'; MAX_PAYLOAD + 1]).is_err());
}

#[tokio::test]
async fn migrates_once_before_moved_and_waits_for_complete_final_ok() {
    let deadline = end();
    let (listener, address) = listener(deadline).await;
    let calls = Cell::new(0usize);
    let (partial_tx, partial_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();

    let client = async {
        let gate = direct_child_gate_with_migration(address, deadline, |path| {
            calls.set(calls.get() + 1);
            assert_eq!(path.as_os_str().as_bytes(), b"/fake/\xff/direct-0");
            Ok(())
        });
        tokio::pin!(gate);
        let partial = partial_rx;
        tokio::pin!(partial);

        tokio::select! {
            biased;
            result = &mut gate => {
                panic!("gate completed before final newline: {result:?}");
            }
            result = &mut partial => result.unwrap(),
        }

        assert!(
            futures::poll!(gate.as_mut()).is_pending(),
            "partial final OK authorized completion",
        );
        release_tx.send(()).unwrap();
        gate.await
    };

    let peer = async {
        let mut stream = bind_peer(&listener, deadline).await;
        for byte in b"GROUP 2f66616b652fff2f6469726563742d30\n" {
            stream.write_all(&[*byte]).await.unwrap();
        }
        assert_eq!(line(&mut stream, deadline).await, b"MOVED\n");
        assert_eq!(calls.get(), 1);

        stream.write_all(b"O").await.unwrap();
        stream.write_all(b"K").await.unwrap();
        partial_tx.send(()).unwrap();
        release_rx.await.unwrap();
        stream.write_all(b"\n").await.unwrap();
    };

    let (result, ()) = within(deadline, async { futures::join!(client, peer) }).await;
    result.unwrap();
    assert_eq!(calls.get(), 1);
}

async fn initial_rejected(reply: Vec<u8>) {
    let deadline = end();
    let (listener, address) = listener(deadline).await;
    let calls = Cell::new(0usize);

    let client = direct_child_gate_with_migration(address, deadline, |_| {
        calls.set(calls.get() + 1);
        Ok(())
    });
    let peer = async {
        let mut stream = bind_peer(&listener, deadline).await;
        // A rejected overlong frame may close the socket during this write.
        if stream.write_all(&reply).await.is_ok() {
            match stream.shutdown().await {
                Ok(()) => {}
                Err(error) => assert!(
                    matches!(
                        error.kind(),
                        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
                    ),
                    "unexpected shutdown error: {error}",
                ),
            }
        }
    };

    let (result, ()) = within(deadline, async { futures::join!(client, peer) }).await;
    assert!(result.is_err(), "accepted initial reply {reply:?}");
    assert_eq!(calls.get(), 0);
}

#[tokio::test]
async fn initial_denial_ok_eof_and_malformed_groups_fail_before_migration() {
    for reply in [
        b"DENY peer\n".to_vec(),
        b"OK\n".to_vec(),
        Vec::new(),
        b"GRO".to_vec(),
        b"GROUP 2f".to_vec(),
        b"GROUP \n".to_vec(),
        b"GROUP 2\n".to_vec(),
        b"GROUP FF\n".to_vec(),
        b"GROUP zz\n".to_vec(),
        b"GROUP 00\n".to_vec(),
        b"GROUP 2f78\r\n".to_vec(),
        group_frame(&vec![b'x'; MAX_PATH + 1]),
        vec![b'x'; MAX_PAYLOAD + 1],
    ] {
        initial_rejected(reply).await;
    }
}

async fn final_rejected(reply: Vec<u8>) {
    let deadline = end();
    let (listener, address) = listener(deadline).await;
    let calls = Cell::new(0usize);

    let client = direct_child_gate_with_migration(address, deadline, |path| {
        assert_eq!(path.as_os_str().as_bytes(), b"/x");
        calls.set(calls.get() + 1);
        Ok(())
    });
    let peer = async {
        let mut stream = bind_peer(&listener, deadline).await;
        stream.write_all(b"GROUP 2f78\n").await.unwrap();
        assert_eq!(line(&mut stream, deadline).await, b"MOVED\n");
        assert_eq!(calls.get(), 1);
        // Rejection can race the remainder of an overlong peer write.
        if stream.write_all(&reply).await.is_ok() {
            match stream.shutdown().await {
                Ok(()) => {}
                Err(error) => assert!(
                    matches!(
                        error.kind(),
                        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
                    ),
                    "unexpected shutdown error: {error}",
                ),
            }
        }
    };

    let (result, ()) = within(deadline, async { futures::join!(client, peer) }).await;
    assert!(result.is_err(), "accepted final reply {reply:?}");
    assert_eq!(calls.get(), 1);
}

#[tokio::test]
async fn final_denial_eof_partial_malformed_and_overlong_replies_fail() {
    for reply in [
        b"DENY peer\n".to_vec(),
        Vec::new(),
        b"O".to_vec(),
        b"OK".to_vec(),
        b"OK\r\n".to_vec(),
        b"OK extra\n".to_vec(),
        b"GROUP 2f78\n".to_vec(),
        vec![b'x'; MAX_PAYLOAD + 1],
    ] {
        final_rejected(reply).await;
    }
}

#[tokio::test]
async fn migration_failure_closes_without_moved() {
    let deadline = end();
    let (listener, address) = listener(deadline).await;
    let calls = Cell::new(0usize);

    let client = direct_child_gate_with_migration(address, deadline, |path| {
        assert_eq!(path.as_os_str().as_bytes(), b"/x");
        calls.set(calls.get() + 1);
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "injected migration failure",
        ))
    });
    let peer = async {
        let mut stream = bind_peer(&listener, deadline).await;
        stream.write_all(b"GROUP 2f78\n").await.unwrap();
        let mut byte = [0];
        assert_eq!(
            stream.read(&mut byte).await.unwrap(),
            0,
            "child sent bytes after migration failure",
        );
    };

    let (result, ()) = within(deadline, async { futures::join!(client, peer) }).await;
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied,);
    assert_eq!(calls.get(), 1);
}

#[tokio::test]
async fn expired_original_deadline_prevents_connect_and_migration() {
    let watchdog = end();
    let (listener, address) = listener(watchdog).await;
    let calls = Cell::new(0usize);
    let result = within(
        watchdog,
        direct_child_gate_with_migration(address, Instant::now(), |_| {
            calls.set(calls.get() + 1);
            Ok(())
        }),
    )
    .await;

    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(calls.get(), 0);
    assert!(
        futures::poll!(Box::pin(listener.accept())).is_pending(),
        "expired gate attempted a connection",
    );
}

#[tokio::test]
async fn withheld_final_ok_expires_original_deadline_and_closes() {
    let watchdog = end();
    let (listener, address) = listener(watchdog).await;
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(1))
        .expect("protocol deadline fits");
    let calls = Cell::new(0usize);

    let client = direct_child_gate_with_migration(address, deadline, |_| {
        calls.set(calls.get() + 1);
        Ok(())
    });
    let peer = async {
        let mut stream = bind_peer(&listener, watchdog).await;
        stream.write_all(b"GROUP 2f78\n").await.unwrap();
        assert_eq!(line(&mut stream, watchdog).await, b"MOVED\n");
        assert_eq!(calls.get(), 1);
        // Deliberately withhold authorization; EOF must follow deadline expiry.
        let mut byte = [0];
        assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
    };

    let (result, ()) = within(watchdog, async { futures::join!(client, peer) }).await;
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(calls.get(), 1);
}

#[test]
fn synchronous_operation_cannot_succeed_after_its_deadline() {
    let calls = Cell::new(0usize);
    let deadline = Instant::now() + Duration::from_millis(250);
    let result = synchronous(deadline, || {
        calls.set(calls.get() + 1);
        // Model a non-preemptible filesystem call without a busy wait.
        std::thread::sleep(Duration::from_millis(500));
        Ok(())
    });
    assert_eq!(calls.get(), 1);
    assert!(Instant::now() >= deadline);
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
}

#[test]
fn expired_synchronous_budget_never_invokes_operation() {
    let calls = Cell::new(0usize);
    let result = synchronous(Instant::now(), || {
        calls.set(calls.get() + 1);
        Ok(())
    });
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(calls.get(), 0);
}
