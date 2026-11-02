use super::super::construction_export::{Progress, StorageEvidence};
use super::*;
use std::net::SocketAddr;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::TcpListener;

fn reservation() -> Evidence {
    Evidence {
        journal_sequence: 1,
        request_id: 0,
        identity: Some(41),
        event: SelectionEvent::Reserved,
        outcome: SelectionOutcome::Reserved,
        explicit_disabled: true,
        effective_none: Some(true),
        storage: None,
    }
}

fn unhex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

#[test]
fn exact_header_preserves_request_zero_and_local_identity() {
    let evidence = reservation();
    let frame = Context::new(7, 0).unwrap().event(&evidence).unwrap();
    let expected = unhex(concat!(
        "025200",
        "0000000000000007",
        "0000000000000001",
        "0000000000000000",
        "0000000000000029",
        "0000000000000000",
        "0101",
        "00000000"
    ));
    assert_eq!(HEADER_SIZE, 49);
    assert_eq!(frame.bytes(), expected);
    match frame.source() {
        Source::Event(retained) => assert_eq!(retained, &evidence),
        _ => panic!("source evidence was not retained"),
    }
}

#[test]
fn exact_failure_status_preserves_drops_and_unacknowledged_progress() {
    let evidence = reservation();
    let snapshot = ExportSnapshot {
        installed: true,
        closed: true,
        failure: Some("construction export acknowledgement cancelled"),
        creation_attempts: 0,
        progress: vec![Progress {
            evidence,
            queued: true,
            acknowledged: false,
            failure: Some("construction export acknowledgement cancelled"),
        }],
    };
    let frame = Context::new(1, 0).unwrap().end(&snapshot, 1, 3).unwrap();
    let mut expected = unhex(concat!(
        "025800",
        "0000000000000001",
        "0000000000000000",
        "0000000000000000",
        "0000000000000000",
        "0000000000000000",
        "0002",
        "00000000"
    ));
    expected.extend(unhex(concat!(
        "010101",
        "0000000000000001",
        "0000000000000003",
        "0000000000000000",
        "01",
        "0000000000000001",
        "010001"
    )));
    assert_eq!(STATUS_SIZE, 28);
    assert_eq!(frame.bytes(), expected);
    match frame.source() {
        Source::Terminal {
            snapshot: retained,
            journal_count,
            dropped,
        } => {
            assert_eq!(retained, &snapshot);
            assert_eq!((*journal_count, *dropped), (1, 3));
        }
        _ => panic!("terminal source was not retained"),
    }
}

#[test]
fn path_bytes_are_lossless_and_unknown_failure_is_not_success() {
    let base = PathBuf::from(std::ffi::OsString::from_vec(b"/tmp/base-\xff".to_vec()));
    let allocated = base.join("owners-v1/1");
    let mut evidence = reservation();
    evidence.journal_sequence = 2;
    evidence.event = SelectionEvent::StorageAssigned;
    evidence.storage = Some(StorageEvidence {
        base: base.clone(),
        allocated: allocated.clone(),
        slot: 1,
    });
    let frame = Context::new(1, 0).unwrap().event(&evidence).unwrap();
    let base_bytes = base.as_os_str().as_encoded_bytes();
    let allocated_bytes = allocated.as_os_str().as_encoded_bytes();
    assert_eq!(
        &frame.bytes()[HEADER_SIZE..HEADER_SIZE + base_bytes.len()],
        base_bytes
    );
    assert_eq!(
        &frame.bytes()[HEADER_SIZE + base_bytes.len()..],
        allocated_bytes
    );
    let snapshot = ExportSnapshot {
        failure: Some("unknown source failure"),
        ..ExportSnapshot::default()
    };
    assert!(matches!(
        Context::new(1, 0).unwrap().end(&snapshot, 0, 0),
        Err(Error::Invalid("unknown producer failure"))
    ));
    assert!(Context::new(0, 0).is_err());
    assert!(Context::new(1, 2).is_err());
}

async fn bind(deadline: Instant) -> TcpListener {
    timeout_at(deadline, TcpListener::bind("127.0.0.1:0"))
        .await
        .expect("test bind exceeded its deadline")
        .expect("test bind failed")
}

async fn connect(address: SocketAddr, deadline: Instant) -> TcpStream {
    timeout_at(deadline, TcpStream::connect(address))
        .await
        .expect("test connect exceeded its deadline")
        .expect("test connect failed")
}

async fn accept(listener: &TcpListener, deadline: Instant) -> TcpStream {
    timeout_at(deadline, listener.accept())
        .await
        .expect("test accept exceeded its deadline")
        .expect("test accept failed")
        .0
}

async fn read_line(stream: &mut TcpStream, deadline: Instant) -> Vec<u8> {
    let mut line = Vec::new();
    loop {
        let mut byte = [0];
        timeout_at(deadline, stream.read_exact(&mut byte))
            .await
            .expect("test read exceeded its deadline")
            .expect("test read failed");
        line.push(byte[0]);
        assert!(line.len() <= MAX_LINE);
        if byte[0] == b'\n' {
            return line;
        }
    }
}

async fn write(stream: &mut TcpStream, bytes: &[u8], deadline: Instant) {
    timeout_at(deadline, stream.write_all(bytes))
        .await
        .expect("test write exceeded its deadline")
        .expect("test write failed");
}

async fn send(client: &mut Client, frame: &Frame, deadline: Instant) -> Result<Receipt, Error> {
    timeout_at(deadline, client.send(frame))
        .await
        .expect("client send exceeded the outer test deadline")
}

async fn successful_script(stream: &mut TcpStream, body: &[u8], number: usize, deadline: Instant) {
    assert_eq!(
        read_line(stream, deadline).await,
        format!("CE START {number} {}\n", body.len()).as_bytes()
    );
    write(stream, format!("CE READY {number}\n").as_bytes(), deadline).await;
    let mut received = Vec::new();
    for (index, chunk) in body.chunks(MAX_CHUNK).enumerate() {
        let offset = index * MAX_CHUNK;
        let line = read_line(stream, deadline).await;
        let prefix = format!("CE DATA {number} {offset} ");
        assert!(line.starts_with(prefix.as_bytes()));
        assert_eq!(line.last(), Some(&b'\n'));
        let encoded = std::str::from_utf8(&line[prefix.len()..line.len() - 1]).unwrap();
        assert_eq!(encoded.len(), chunk.len() * 2);
        assert!(encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
        let decoded = unhex(encoded);
        assert_eq!(decoded, chunk);
        received.extend(decoded);
        write(
            stream,
            format!("CE NEXT {number} {}\n", received.len()).as_bytes(),
            deadline,
        )
        .await;
    }
    assert_eq!(received, body);
    assert_eq!(
        read_line(stream, deadline).await,
        format!("CE COMMIT {number}\n").as_bytes()
    );
    write(stream, format!("CE ACCEPT {number}\n").as_bytes(), deadline).await;
    assert_eq!(
        read_line(stream, deadline).await,
        format!("CE CONFIRM {number}\n").as_bytes()
    );
    write(
        stream,
        format!("CE CONFIRMED {number}\n").as_bytes(),
        deadline,
    )
    .await;
}

#[tokio::test]
async fn retained_stream_requires_all_exact_replies_for_each_receipt() {
    let deadline = Instant::now() + Duration::from_secs(5);
    let listener = bind(deadline).await;
    let address = listener.local_addr().unwrap();
    let context = Context::new(1, 0).unwrap();
    let opening = context.open().unwrap();
    let event = context.event(&reservation()).unwrap();
    let bodies = [opening.bytes().to_vec(), event.bytes().to_vec()];
    let server = async {
        let mut stream = accept(&listener, deadline).await;
        successful_script(&mut stream, &bodies[0], 1, deadline).await;
        successful_script(&mut stream, &bodies[1], 2, deadline).await;
    };
    let client = async {
        let stream = connect(address, deadline).await;
        let mut client = Client::new(stream, deadline);
        let first = send(&mut client, &opening, deadline).await.unwrap();
        assert_eq!(first.transaction, 1);
        assert_eq!(client.state(), State::Ready);
        let second = send(&mut client, &event, deadline).await.unwrap();
        assert_eq!(second.transaction, 2);
        assert_eq!(second.journal_sequence, 1);
        assert_eq!(second.operation, Operation::Reserved);
        assert!(client.last_error().is_none());
        drop(client.into_stream());
    };
    tokio::join!(server, client);
}

#[tokio::test]
async fn wrong_sequence_offset_and_partial_eof_poison_the_client() {
    for mode in 0..3 {
        let deadline = Instant::now() + Duration::from_secs(5);
        let listener = bind(deadline).await;
        let address = listener.local_addr().unwrap();
        let opening = Context::new(1, 0).unwrap().open().unwrap();
        let server = async {
            let mut stream = accept(&listener, deadline).await;
            assert_eq!(read_line(&mut stream, deadline).await, b"CE START 1 49\n");
            match mode {
                0 => write(&mut stream, b"CE READY 2\n", deadline).await,
                1 => {
                    write(&mut stream, b"CE READY 1\n", deadline).await;
                    assert!(read_line(&mut stream, deadline)
                        .await
                        .starts_with(b"CE DATA 1 0 "));
                    write(&mut stream, b"CE NEXT 1 47\n", deadline).await;
                }
                _ => write(&mut stream, b"CE READY ", deadline).await,
            }
        };
        let client = async {
            let stream = connect(address, deadline).await;
            let mut client = Client::new(stream, deadline);
            let expected = if mode == 2 {
                Error::Eof
            } else {
                Error::WrongReply
            };
            assert_eq!(
                send(&mut client, &opening, deadline).await,
                Err(expected.clone())
            );
            assert_eq!(client.state(), State::Failed);
            assert_eq!(client.last_error(), Some(&expected));
            assert_eq!(
                send(&mut client, &opening, deadline).await,
                Err(Error::Unusable)
            );
            drop(client.into_stream());
        };
        tokio::join!(server, client);
    }
}

#[tokio::test]
async fn cancellation_after_start_cannot_retry_or_acknowledge() {
    let deadline = Instant::now() + Duration::from_secs(5);
    let listener = bind(deadline).await;
    let address = listener.local_addr().unwrap();
    let opening = Context::new(1, 0).unwrap().open().unwrap();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let server = async {
        let mut stream = accept(&listener, deadline).await;
        assert_eq!(read_line(&mut stream, deadline).await, b"CE START 1 49\n");
        started_tx.send(()).unwrap();
        let mut byte = [0];
        assert_eq!(
            timeout_at(deadline, stream.read(&mut byte))
                .await
                .expect("cancelled client did not release its stream before the deadline")
                .expect("terminal read failed"),
            0
        );
    };
    let client = async {
        let stream = connect(address, deadline).await;
        let mut client = Client::new(stream, deadline);
        let mut pending_send = Box::pin(client.send(&opening));
        tokio::select! {
            result = timeout_at(deadline, &mut pending_send) => {
                panic!("send completed before cancellation control: {result:?}");
            }
            result = timeout_at(deadline, started_rx) => {
                result
                    .expect("START receipt exceeded the deadline")
                    .expect("START receipt sender was lost");
            }
        }
        drop(pending_send);
        assert_eq!(client.state(), State::InFlight);
        assert_eq!(
            send(&mut client, &opening, deadline).await,
            Err(Error::Unusable)
        );
        drop(client.into_stream());
    };
    tokio::join!(server, client);
}

#[tokio::test]
async fn held_reply_expires_without_a_receipt() {
    let start = Instant::now();
    let outer_deadline = start + Duration::from_secs(1);
    let client_deadline = start + Duration::from_millis(500);
    let listener = bind(outer_deadline).await;
    let address = listener.local_addr().unwrap();
    let opening = Context::new(1, 0).unwrap().open().unwrap();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (completed_tx, completed_rx) = tokio::sync::oneshot::channel();

    let server = async {
        let mut stream = accept(&listener, outer_deadline).await;
        assert_eq!(
            read_line(&mut stream, client_deadline).await,
            b"CE START 1 49\n"
        );
        assert!(Instant::now() < client_deadline);
        started_tx.send(()).unwrap();
        timeout_at(outer_deadline, completed_rx)
            .await
            .expect("client did not complete before the outer deadline")
            .expect("client completion proof was lost");
        drop(stream);
    };
    let client = async {
        let stream = connect(address, client_deadline).await;
        let mut client = Client::new(stream, client_deadline);
        let mut pending_send = Box::pin(client.send(&opening));
        tokio::select! {
            biased;
            result = &mut pending_send => {
                panic!("send completed before actual START delivery: {result:?}");
            }
            result = timeout_at(client_deadline, started_rx) => {
                result
                    .expect("START was not delivered before the client deadline")
                    .expect("START receipt sender was lost");
            }
        }
        let result = timeout_at(outer_deadline, &mut pending_send)
            .await
            .expect("client failed to enforce its earlier deadline");
        drop(pending_send);
        assert_eq!(result, Err(Error::Deadline));
        assert_eq!(client.state(), State::Failed);
        assert_eq!(client.last_error(), Some(&Error::Deadline));
        assert!(Instant::now() >= client_deadline);
        assert!(Instant::now() < outer_deadline);
        completed_tx.send(()).unwrap();
        drop(client.into_stream());
    };
    tokio::join!(server, client);
}

#[tokio::test]
async fn end_and_finish_complete_only_after_exact_receipts() {
    let deadline = Instant::now() + Duration::from_secs(5);
    let listener = bind(deadline).await;
    let address = listener.local_addr().unwrap();
    let context = Context::new(1, 0).unwrap();
    let snapshot = ExportSnapshot {
        installed: true,
        closed: true,
        ..ExportSnapshot::default()
    };
    let frames = [
        context.open().unwrap(),
        context.end(&snapshot, 0, 0).unwrap(),
        Frame::finish().unwrap(),
    ];
    let server = async {
        let mut stream = accept(&listener, deadline).await;
        for (index, frame) in frames.iter().enumerate() {
            successful_script(&mut stream, frame.bytes(), index + 1, deadline).await;
        }
    };
    let client = async {
        let stream = connect(address, deadline).await;
        let mut client = Client::new(stream, deadline);
        for (index, frame) in frames.iter().enumerate() {
            let receipt = send(&mut client, frame, deadline).await.unwrap();
            assert_eq!(receipt.transaction, index + 1);
            assert_eq!(receipt.operation, frame.operation);
            assert_eq!(
                client.state(),
                if index == 2 {
                    State::Finished
                } else {
                    State::Ready
                }
            );
        }
        assert!(client.last_error().is_none());
        assert_eq!(
            send(&mut client, &frames[0], deadline).await,
            Err(Error::Unusable)
        );
        assert_eq!(client.state(), State::Finished);
        assert!(client.last_error().is_none());
        drop(client.into_stream());
    };
    tokio::join!(server, client);
}

#[tokio::test]
async fn complete_denial_and_overlong_reply_never_return_receipts() {
    for overlong in [false, true] {
        let deadline = Instant::now() + Duration::from_secs(5);
        let listener = bind(deadline).await;
        let address = listener.local_addr().unwrap();
        let opening = Context::new(1, 0).unwrap().open().unwrap();
        let server = async {
            let mut stream = accept(&listener, deadline).await;
            assert_eq!(read_line(&mut stream, deadline).await, b"CE START 1 49\n");
            if overlong {
                write(&mut stream, &[b'x'; MAX_LINE + 1], deadline).await;
            } else {
                write(&mut stream, b"DENY evidence-rejected\n", deadline).await;
            }
        };
        let client = async {
            let stream = connect(address, deadline).await;
            let mut client = Client::new(stream, deadline);
            let expected = if overlong {
                Error::ReplyBound
            } else {
                Error::Denied("evidence-rejected".into())
            };
            assert_eq!(
                send(&mut client, &opening, deadline).await,
                Err(expected.clone())
            );
            assert_eq!(client.state(), State::Failed);
            assert_eq!(client.last_error(), Some(&expected));
            assert_eq!(
                send(&mut client, &opening, deadline).await,
                Err(Error::Unusable)
            );
            assert_eq!(client.state(), State::Failed);
            assert_eq!(client.last_error(), Some(&expected));
            drop(client.into_stream());
        };
        tokio::join!(server, client);
    }
}
