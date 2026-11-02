use super::super::{SelectionObservation, SelectionOutcome};
use super::*;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn listener(deadline: Instant) -> TcpListener {
    timeout_at(deadline, TcpListener::bind("127.0.0.1:0"))
        .await
        .expect("listener deadline")
        .expect("listener failed")
}

async fn connect(address: SocketAddr, deadline: Instant) -> TcpStream {
    timeout_at(deadline, TcpStream::connect(address))
        .await
        .expect("connect deadline")
        .expect("connect failed")
}

async fn accept(listener: &TcpListener, deadline: Instant) -> TcpStream {
    timeout_at(deadline, listener.accept())
        .await
        .expect("accept deadline")
        .expect("accept failed")
        .0
}

async fn line(stream: &mut TcpStream, deadline: Instant) -> Vec<u8> {
    let mut result = Vec::new();
    loop {
        let mut byte = [0];
        timeout_at(deadline, stream.read_exact(&mut byte))
            .await
            .expect("read deadline")
            .expect("read failed");
        result.push(byte[0]);
        assert!(result.len() <= 128);
        if byte[0] == b'\n' {
            return result;
        }
    }
}

async fn write(stream: &mut TcpStream, text: &[u8], deadline: Instant) {
    timeout_at(deadline, stream.write_all(text))
        .await
        .expect("write deadline")
        .expect("write failed");
}

async fn eof(stream: &mut TcpStream, deadline: Instant) {
    let mut byte = [0];
    assert_eq!(
        timeout_at(deadline, stream.read(&mut byte))
            .await
            .expect("stream release deadline")
            .expect("stream release read failed"),
        0
    );
}

async fn open(consumer: &mut Consumer, client: &mut Client, deadline: Instant) {
    timeout_at(deadline, consumer.open(client))
        .await
        .expect("consumer OPEN deadline")
        .expect("consumer OPEN failed");
}

async fn finish(
    consumer: &mut Consumer,
    client: &mut Client,
    deadline: Instant,
) -> Result<(), Error> {
    timeout_at(deadline, consumer.finish(client))
        .await
        .expect("consumer END deadline")
}

fn unhex(bytes: &[u8]) -> Vec<u8> {
    assert_eq!(bytes.len() % 2, 0);
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

async fn transaction(
    stream: &mut TcpStream,
    number: usize,
    deadline: Instant,
    final_reply: Option<&[u8]>,
) -> Vec<u8> {
    let start = line(stream, deadline).await;
    let text = std::str::from_utf8(&start).unwrap();
    let fields = text.trim_end_matches('\n').split(' ').collect::<Vec<_>>();
    assert_eq!(fields.len(), 4);
    assert_eq!(fields[0..2], ["CE", "START"]);
    assert_eq!(fields[2], number.to_string());
    let size = fields[3].parse::<usize>().unwrap();
    assert!((49..=4877).contains(&size));
    write(stream, format!("CE READY {number}\n").as_bytes(), deadline).await;
    let mut body = Vec::new();
    while body.len() < size {
        let request = line(stream, deadline).await;
        let text = std::str::from_utf8(&request).unwrap();
        let fields = text.trim_end_matches('\n').split(' ').collect::<Vec<_>>();
        assert_eq!(fields.len(), 5);
        assert_eq!(fields[0..2], ["CE", "DATA"]);
        assert_eq!(fields[2], number.to_string());
        assert_eq!(fields[3], body.len().to_string());
        let chunk = unhex(fields[4].as_bytes());
        assert!(!chunk.is_empty() && chunk.len() <= 48);
        body.extend(chunk);
        assert!(body.len() <= size);
        write(
            stream,
            format!("CE NEXT {number} {}\n", body.len()).as_bytes(),
            deadline,
        )
        .await;
    }
    assert_eq!(
        line(stream, deadline).await,
        format!("CE COMMIT {number}\n").as_bytes()
    );
    write(stream, format!("CE ACCEPT {number}\n").as_bytes(), deadline).await;
    assert_eq!(
        line(stream, deadline).await,
        format!("CE CONFIRM {number}\n").as_bytes()
    );
    if let Some(reply) = final_reply {
        write(stream, reply, deadline).await;
    }
    body
}

async fn confirmed(stream: &mut TcpStream, number: usize, deadline: Instant) -> Vec<u8> {
    transaction(
        stream,
        number,
        deadline,
        Some(format!("CE CONFIRMED {number}\n").as_bytes()),
    )
    .await
}

fn observation() -> SelectionObservation {
    SelectionObservation {
        request_id: 0,
        route: "none".into(),
        identity: Some(41),
        storage_slot: None,
        outcome: SelectionOutcome::Reserved,
        event: SelectionEvent::Reserved,
    }
}

fn integer(body: &[u8], start: usize) -> u64 {
    u64::from_be_bytes(body[start..start + 8].try_into().unwrap())
}

fn assert_event(body: &[u8], registry: u64) {
    assert_eq!(body.len(), 49);
    assert_eq!(&body[..3], &[2, b'R', 0]);
    assert_eq!(integer(body, 3), registry);
    assert_eq!(integer(body, 11), 1);
    assert_eq!(integer(body, 19), 0);
    assert_eq!(integer(body, 27), 41);
    assert_eq!(integer(body, 35), 0);
    assert_eq!(&body[43..], &[1, 1, 0, 0, 0, 0]);
}

fn assert_terminal(body: &[u8], registry: u64, cancelled: bool) {
    assert_eq!(body.len(), 88);
    assert_eq!(&body[..3], &[2, b'X', 0]);
    assert_eq!(integer(body, 3), registry);
    assert_eq!(&body[11..43], &[0; 32]);
    assert_eq!(&body[43..49], &[0, 2, 0, 0, 0, 0]);
    assert_eq!(
        &body[49..52],
        if cancelled { &[1, 1, 1] } else { &[1, 1, 0] }
    );
    assert_eq!(integer(body, 52), 1);
    assert_eq!(integer(body, 60), 0);
    assert_eq!(integer(body, 68), 0);
    assert_eq!(body[76], 1);
    assert_eq!(integer(body, 77), 1);
    assert_eq!(
        &body[85..88],
        if cancelled { &[1, 0, 1] } else { &[1, 1, 0] }
    );
}

fn assert_unacknowledged(probe: &SelectionProbe) {
    assert_eq!(probe.snapshot(), (vec![observation()], 0));
    let snapshot = probe.construction_export_snapshot();
    assert!(snapshot.installed);
    assert!(!snapshot.closed);
    assert_eq!(snapshot.creation_attempts, 0);
    assert_eq!(snapshot.progress.len(), 1);
    assert_eq!(snapshot.progress[0].evidence.request_id, 0);
    assert_eq!(snapshot.progress[0].evidence.journal_sequence, 1);
    assert!(snapshot.progress[0].queued);
    assert!(!snapshot.progress[0].acknowledged);
}

async fn assert_rejected(
    producer: &mut std::pin::Pin<Box<impl std::future::Future<Output = anyhow::Result<()>>>>,
    probe: &SelectionProbe,
    deadline: Instant,
) {
    let error = timeout_at(deadline, producer.as_mut())
        .await
        .expect("producer rejection deadline")
        .expect_err("producer was falsely accepted");
    assert_eq!(
        error.to_string(),
        "construction export acknowledgement rejected"
    );
    assert_eq!(
        probe.construction_export_snapshot().failure,
        Some("construction export acknowledgement rejected")
    );
    assert_eq!(
        probe.construction_export_snapshot().progress[0].failure,
        Some("construction export acknowledgement rejected")
    );
    assert!(!probe.construction_export_snapshot().progress[0].acknowledged);
}

#[tokio::test]
async fn actual_producer_waits_until_complete_matching_confirmation() {
    let deadline = Instant::now() + Duration::from_secs(5);
    let listener = listener(deadline).await;
    let address = listener.local_addr().unwrap();
    let probe = Arc::new(SelectionProbe::new());
    let mut consumer = Consumer::install(Arc::clone(&probe), 1, 0, deadline).unwrap();
    let (held_tx, held_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();

    let server = async {
        let mut stream = accept(&listener, deadline).await;
        confirmed(&mut stream, 1, deadline).await;
        let event = transaction(&mut stream, 2, deadline, None).await;
        assert_event(&event, 1);
        held_tx.send(()).unwrap();
        timeout_at(deadline, release_rx).await.unwrap().unwrap();
        write(&mut stream, b"CE CONFIRMED 2\n", deadline).await;
        assert_terminal(&confirmed(&mut stream, 3, deadline).await, 1, false);
    };
    let client = async {
        let mut client = Client::new(connect(address, deadline).await, deadline);
        open(&mut consumer, &mut client, deadline).await;
        let mut producer =
            Box::pin(probe.publish_construction(observation(), true, Some(true), None, None));
        let mut delivery = Box::pin(consumer.next(&mut client));
        tokio::select! {
            result = &mut producer => panic!("producer completed before wire confirmation: {result:?}"),
            result = &mut delivery => panic!("delivery completed before final wire reply: {result:?}"),
            result = timeout_at(deadline, held_rx) => result.unwrap().unwrap(),
        }
        assert_unacknowledged(&probe);
        assert!(probe.construction_export_snapshot().failure.is_none());
        release_tx.send(()).unwrap();
        let (producer_result, delivery_result) = timeout_at(deadline, async {
            tokio::join!(&mut producer, &mut delivery)
        })
        .await
        .unwrap();
        producer_result.unwrap();
        let receipt = delivery_result.unwrap();
        assert_eq!(receipt.registry, 1);
        assert_eq!(receipt.operation, Operation::Reserved);
        assert_eq!(receipt.journal_sequence, 1);
        drop(producer);
        drop(delivery);
        assert!(probe.construction_export_snapshot().progress[0].acknowledged);
        assert_eq!(finish(&mut consumer, &mut client, deadline).await, Ok(()));
        assert!(consumer.terminal().unwrap().successful);
        assert!(consumer.deliveries()[0].producer_ack_sent);
        assert_eq!(
            consumer.deliveries()[0].evidence,
            probe.construction_export_snapshot().progress[0].evidence
        );
        drop(client.into_stream());
    };
    tokio::join!(server, client);
}

async fn failed_final_reply(partial: bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let listener = listener(deadline).await;
    let address = listener.local_addr().unwrap();
    let probe = Arc::new(SelectionProbe::new());
    let mut consumer = Consumer::install(Arc::clone(&probe), 1, 0, deadline).unwrap();
    let server = async {
        let mut stream = accept(&listener, deadline).await;
        confirmed(&mut stream, 1, deadline).await;
        let reply = if partial {
            &b"CE CONFIRMED "[..]
        } else {
            &b"CE CONFIRMED 9\n"[..]
        };
        assert_event(&transaction(&mut stream, 2, deadline, Some(reply)).await, 1);
    };
    let client = async {
        let mut client = Client::new(connect(address, deadline).await, deadline);
        open(&mut consumer, &mut client, deadline).await;
        let mut producer =
            Box::pin(probe.publish_construction(observation(), true, Some(true), None, None));
        let result = {
            let mut delivery = Box::pin(consumer.next(&mut client));
            tokio::select! {
                result = &mut producer => panic!("unexpected producer completion: {result:?}"),
                result = timeout_at(deadline, &mut delivery) => result.unwrap(),
            }
        };
        let wire_error = if partial {
            WireError::Eof
        } else {
            WireError::WrongReply
        };
        let expected = Error::Wire(wire_error.clone());
        assert_eq!(result, Err(expected.clone()));
        assert_eq!(client.state(), State::Failed);
        assert_eq!(client.last_error(), Some(&wire_error));
        assert_unacknowledged(&probe);
        assert!(consumer.pending.is_some());
        assert!(consumer.deliveries()[0].receipt.is_none());
        assert!(!consumer.deliveries()[0].producer_ack_sent);
        consumer.reject_pending();
        assert_rejected(&mut producer, &probe, deadline).await;
        drop(producer);
        assert_eq!(
            finish(&mut consumer, &mut client, deadline).await,
            Err(Error::ProducerIncomplete)
        );
        assert_eq!(consumer.failure(), Some(&expected));
        let terminal = consumer.terminal().unwrap();
        assert_eq!(terminal.journal_count, 1);
        assert_eq!(terminal.dropped, 0);
        assert!(terminal.snapshot.closed);
        assert!(!terminal.local_finish_ok);
        assert!(!terminal.successful);
        assert!(terminal.wire_receipt.is_none());
        assert_eq!(
            terminal.snapshot.failure,
            Some("construction export acknowledgement rejected")
        );
        drop(client.into_stream());
    };
    tokio::join!(server, client);
}

#[tokio::test]
async fn wrong_final_reply_rejects_original_producer_and_retains_client() {
    failed_final_reply(false).await;
}

#[tokio::test]
async fn partial_final_eof_retains_pending_envelope_until_explicit_rejection() {
    failed_final_reply(true).await;
}

#[tokio::test]
async fn lost_final_reply_requires_client_deadline_and_retains_actual_failure() {
    let start = Instant::now();
    let deadline = start + Duration::from_secs(5);
    let client_deadline = start + Duration::from_millis(2500);
    let listener = listener(deadline).await;
    let address = listener.local_addr().unwrap();
    let probe = Arc::new(SelectionProbe::new());
    let mut consumer = Consumer::install(Arc::clone(&probe), 1, 0, deadline).unwrap();
    let (held_tx, held_rx) = tokio::sync::oneshot::channel();
    let (completed_tx, completed_rx) = tokio::sync::oneshot::channel();

    let server = async {
        let mut stream = accept(&listener, client_deadline).await;
        confirmed(&mut stream, 1, client_deadline).await;
        assert_event(&transaction(&mut stream, 2, client_deadline, None).await, 1);
        assert!(Instant::now() < client_deadline);
        held_tx.send(()).unwrap();
        timeout_at(deadline, completed_rx)
            .await
            .expect("consumer did not complete before outer deadline")
            .expect("consumer completion proof lost");
        drop(stream);
    };
    let client = async {
        let mut client = Client::new(connect(address, client_deadline).await, client_deadline);
        open(&mut consumer, &mut client, client_deadline).await;
        let mut producer =
            Box::pin(probe.publish_construction(observation(), true, Some(true), None, None));
        let mut delivery = Box::pin(consumer.next(&mut client));
        tokio::select! {
            biased;
            result = &mut producer => panic!("producer completed without confirmation: {result:?}"),
            result = &mut delivery => panic!("delivery completed before held reply: {result:?}"),
            result = timeout_at(client_deadline, held_rx) => result.unwrap().unwrap(),
        }
        assert_unacknowledged(&probe);
        let result = timeout_at(deadline, &mut delivery)
            .await
            .expect("wire client failed to enforce its earlier deadline");
        assert_eq!(result, Err(Error::Wire(WireError::Deadline)));
        drop(delivery);
        assert_eq!(client.state(), State::Failed);
        assert_eq!(client.last_error(), Some(&WireError::Deadline));
        assert!(Instant::now() >= client_deadline);
        assert!(Instant::now() < deadline);
        assert!(consumer.pending.is_some());
        assert_unacknowledged(&probe);
        consumer.reject_pending();
        assert_rejected(&mut producer, &probe, deadline).await;
        drop(producer);
        assert_eq!(
            finish(&mut consumer, &mut client, deadline).await,
            Err(Error::ProducerIncomplete)
        );
        assert_eq!(consumer.failure(), Some(&Error::Wire(WireError::Deadline)));
        let terminal = consumer.terminal().unwrap();
        assert!(!terminal.local_finish_ok);
        assert!(terminal.snapshot.closed);
        assert!(!terminal.successful);
        assert!(terminal.wire_receipt.is_none());
        completed_tx.send(()).unwrap();
        drop(client.into_stream());
    };
    tokio::join!(server, client);
}

#[tokio::test]
async fn cancelled_producer_failure_is_forwarded_without_terminal_success() {
    let deadline = Instant::now() + Duration::from_secs(5);
    let listener = listener(deadline).await;
    let address = listener.local_addr().unwrap();
    let probe = Arc::new(SelectionProbe::new());
    let mut consumer = Consumer::install(Arc::clone(&probe), 1, 0, deadline).unwrap();
    let (held_tx, held_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let server = async {
        let mut stream = accept(&listener, deadline).await;
        confirmed(&mut stream, 1, deadline).await;
        assert_event(&transaction(&mut stream, 2, deadline, None).await, 1);
        held_tx.send(()).unwrap();
        timeout_at(deadline, release_rx).await.unwrap().unwrap();
        write(&mut stream, b"CE CONFIRMED 2\n", deadline).await;
        assert_terminal(&confirmed(&mut stream, 3, deadline).await, 1, true);
    };
    let client = async {
        let mut client = Client::new(connect(address, deadline).await, deadline);
        open(&mut consumer, &mut client, deadline).await;
        let mut producer =
            Box::pin(probe.publish_construction(observation(), true, Some(true), None, None));
        let mut delivery = Box::pin(consumer.next(&mut client));
        tokio::select! {
            result = &mut producer => panic!("producer unexpectedly completed: {result:?}"),
            result = &mut delivery => panic!("delivery unexpectedly completed: {result:?}"),
            result = timeout_at(deadline, held_rx) => result.unwrap().unwrap(),
        }
        drop(producer);
        assert_eq!(
            probe.construction_export_snapshot().failure,
            Some("construction export acknowledgement cancelled")
        );
        release_tx.send(()).unwrap();
        assert_eq!(
            timeout_at(deadline, &mut delivery).await.unwrap(),
            Err(Error::ProducerGone)
        );
        drop(delivery);
        assert_eq!(client.state(), State::Ready);
        assert_eq!(
            finish(&mut consumer, &mut client, deadline).await,
            Err(Error::ProducerIncomplete)
        );
        assert_eq!(consumer.failure(), Some(&Error::ProducerGone));
        let terminal = consumer.terminal().unwrap();
        assert!(!terminal.local_finish_ok);
        assert!(!terminal.successful);
        assert!(terminal.wire_receipt.is_some());
        assert_eq!(
            terminal.snapshot.failure,
            Some("construction export acknowledgement cancelled")
        );
        assert!(!terminal.snapshot.progress[0].acknowledged);
        drop(client.into_stream());
    };
    tokio::join!(server, client);
}

#[tokio::test]
async fn cancelling_consumer_retains_envelope_for_explicit_rejection() {
    let deadline = Instant::now() + Duration::from_secs(5);
    let listener = listener(deadline).await;
    let address = listener.local_addr().unwrap();
    let probe = Arc::new(SelectionProbe::new());
    let mut consumer = Consumer::install(Arc::clone(&probe), 1, 0, deadline).unwrap();
    let (held_tx, held_rx) = tokio::sync::oneshot::channel();
    let server = async {
        let mut stream = accept(&listener, deadline).await;
        confirmed(&mut stream, 1, deadline).await;
        assert_event(&transaction(&mut stream, 2, deadline, None).await, 1);
        held_tx.send(()).unwrap();
        eof(&mut stream, deadline).await;
    };
    let client = async {
        let mut client = Client::new(connect(address, deadline).await, deadline);
        open(&mut consumer, &mut client, deadline).await;
        let mut producer =
            Box::pin(probe.publish_construction(observation(), true, Some(true), None, None));
        let mut delivery = Box::pin(consumer.next(&mut client));
        tokio::select! {
            result = &mut producer => panic!("producer unexpectedly completed: {result:?}"),
            result = &mut delivery => panic!("delivery unexpectedly completed: {result:?}"),
            result = timeout_at(deadline, held_rx) => result.unwrap().unwrap(),
        }
        drop(delivery);
        assert_eq!(client.state(), State::InFlight);
        assert!(client.last_error().is_none());
        assert_unacknowledged(&probe);
        assert_eq!(consumer.pending.as_ref().unwrap().evidence.request_id, 0);
        assert!(consumer.deliveries()[0].receipt.is_none());
        assert!(!consumer.deliveries()[0].producer_ack_sent);
        consumer.reject_pending();
        assert_rejected(&mut producer, &probe, deadline).await;
        drop(producer);
        assert!(consumer.pending.is_none());
        assert_eq!(consumer.failure(), Some(&Error::ProducerIncomplete));
        assert_eq!(
            finish(&mut consumer, &mut client, deadline).await,
            Err(Error::ProducerIncomplete)
        );
        let terminal = consumer.terminal().unwrap();
        assert!(terminal.snapshot.closed);
        assert!(!terminal.local_finish_ok);
        assert!(!terminal.successful);
        assert!(terminal.wire_receipt.is_none());
        assert_eq!(client.state(), State::InFlight);
        drop(client.into_stream());
    };
    tokio::join!(server, client);
}

#[tokio::test]
async fn independent_probes_share_client_through_end_and_global_finish() {
    let deadline = Instant::now() + Duration::from_secs(5);
    let listener = listener(deadline).await;
    let address = listener.local_addr().unwrap();
    let first = Arc::new(SelectionProbe::new());
    let second = Arc::new(SelectionProbe::new());
    let mut first_consumer = Consumer::install(Arc::clone(&first), 1, 0, deadline).unwrap();
    let mut second_consumer = Consumer::install(Arc::clone(&second), 2, 0, deadline).unwrap();

    let server = async {
        let mut stream = accept(&listener, deadline).await;
        for registry in 1..=2 {
            let base = usize::try_from((registry - 1) * 3).unwrap();
            let opening = confirmed(&mut stream, base + 1, deadline).await;
            assert_eq!(opening[1], b'O');
            assert_eq!(integer(&opening, 3), registry);
            assert_event(&confirmed(&mut stream, base + 2, deadline).await, registry);
            assert_terminal(
                &confirmed(&mut stream, base + 3, deadline).await,
                registry,
                false,
            );
        }
        let finishing = confirmed(&mut stream, 7, deadline).await;
        assert_eq!(finishing.len(), 49);
        assert_eq!(&finishing[..3], &[2, b'Z', 0]);
        assert_eq!(integer(&finishing, 3), 0);
        eof(&mut stream, deadline).await;
    };
    let client = async {
        let mut client = Client::new(connect(address, deadline).await, deadline);
        for (probe, consumer) in [
            (&first, &mut first_consumer),
            (&second, &mut second_consumer),
        ] {
            open(consumer, &mut client, deadline).await;
            let producer = probe.publish_construction(observation(), true, Some(true), None, None);
            let delivery = consumer.next(&mut client);
            let (produced, delivered) =
                timeout_at(deadline, async { tokio::join!(producer, delivery) })
                    .await
                    .unwrap();
            produced.unwrap();
            let receipt = delivered.unwrap();
            assert_eq!(receipt.journal_sequence, 1);
            assert_eq!(consumer.deliveries()[0].evidence.request_id, 0);
            assert_eq!(consumer.deliveries()[0].evidence.identity, Some(41));
            assert_eq!(finish(consumer, &mut client, deadline).await, Ok(()));
            assert!(consumer.terminal().unwrap().successful);
            assert!(consumer.terminal().unwrap().wire_receipt.is_some());
            assert_eq!(probe.snapshot(), (vec![observation()], 0));
        }
        let receipt = timeout_at(deadline, finish_stream(&mut client, deadline))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(receipt.transaction, 7);
        assert_eq!(receipt.operation, Operation::Finish);
        assert_eq!(receipt.registry, 0);
        assert_eq!(client.state(), State::Finished);
        drop(client.into_stream());
    };
    tokio::join!(server, client);
}

#[tokio::test]
async fn incomplete_context_prevents_global_finish_without_wire_transaction() {
    let deadline = Instant::now() + Duration::from_secs(5);
    let listener = listener(deadline).await;
    let address = listener.local_addr().unwrap();
    let probe = Arc::new(SelectionProbe::new());
    let mut consumer = Consumer::install(Arc::clone(&probe), 1, 0, deadline).unwrap();
    let server = async {
        let mut stream = accept(&listener, deadline).await;
        confirmed(&mut stream, 1, deadline).await;
        assert_event(&confirmed(&mut stream, 2, deadline).await, 1);
        eof(&mut stream, deadline).await;
    };
    let client = async {
        let mut client = Client::new(connect(address, deadline).await, deadline);
        open(&mut consumer, &mut client, deadline).await;
        let (produced, delivered) = timeout_at(deadline, async {
            tokio::join!(
                probe.publish_construction(observation(), true, Some(true), None, None),
                consumer.next(&mut client),
            )
        })
        .await
        .unwrap();
        produced.unwrap();
        delivered.unwrap();
        assert!(probe.construction_export_snapshot().progress[0].acknowledged);
        assert!(consumer.terminal().is_none());
        let expected = WireError::Invalid("unfinished contexts");
        assert_eq!(
            timeout_at(deadline, finish_stream(&mut client, deadline))
                .await
                .unwrap(),
            Err(Error::Wire(expected.clone()))
        );
        assert_eq!(client.state(), State::Failed);
        assert_eq!(client.last_error(), Some(&expected));
        assert_eq!(
            timeout_at(deadline, finish_stream(&mut client, deadline))
                .await
                .unwrap(),
            Err(Error::Wire(WireError::Unusable))
        );
        assert_eq!(
            finish(&mut consumer, &mut client, deadline).await,
            Err(Error::ProducerIncomplete)
        );
        let terminal = consumer.terminal().unwrap();
        assert!(terminal.local_finish_ok);
        assert!(terminal.snapshot.closed);
        assert!(terminal.wire_receipt.is_none());
        assert!(!terminal.successful);
        drop(client.into_stream());
    };
    tokio::join!(server, client);
}

#[tokio::test]
async fn idle_first_registry_does_not_block_ready_second_registry() {
    let deadline = Instant::now() + Duration::from_secs(5);
    let listener = listener(deadline).await;
    let address = listener.local_addr().unwrap();
    let first_probe = Arc::new(SelectionProbe::new());
    let second_probe = Arc::new(SelectionProbe::new());
    let mut first = Consumer::install(Arc::clone(&first_probe), 1, 0, deadline).unwrap();
    let mut second = Consumer::install(Arc::clone(&second_probe), 2, 0, deadline).unwrap();
    let server = async {
        let mut stream = accept(&listener, deadline).await;
        assert_eq!(integer(&confirmed(&mut stream, 1, deadline).await, 3), 1);
        assert_eq!(integer(&confirmed(&mut stream, 2, deadline).await, 3), 2);
        assert_event(&confirmed(&mut stream, 3, deadline).await, 2);
        let empty_terminal = confirmed(&mut stream, 4, deadline).await;
        assert_eq!(empty_terminal.len(), 77);
        assert_eq!(empty_terminal[1], b'X');
        assert_eq!(integer(&empty_terminal, 3), 1);
        assert_eq!(&empty_terminal[49..52], &[1, 1, 0]);
        assert_eq!(integer(&empty_terminal, 52), 0);
        assert_eq!(empty_terminal[76], 0);
        assert_terminal(&confirmed(&mut stream, 5, deadline).await, 2, false);
        let finishing = confirmed(&mut stream, 6, deadline).await;
        assert_eq!(finishing[1], b'Z');
        eof(&mut stream, deadline).await;
    };
    let client = async {
        let mut client = Client::new(connect(address, deadline).await, deadline);
        open(&mut first, &mut client, deadline).await;
        open(&mut second, &mut client, deadline).await;
        let producer =
            second_probe.publish_construction(observation(), true, Some(true), None, None);
        let delivery = async {
            let ready = timeout_at(
                deadline,
                std::future::poll_fn(|cx| {
                    if let std::task::Poll::Ready(result) = first.poll_receive(cx) {
                        return std::task::Poll::Ready(result.map(|()| 1usize));
                    }
                    second
                        .poll_receive(cx)
                        .map(|result| result.map(|()| 2usize))
                }),
            )
            .await
            .expect("idle registry blocked ready delivery")
            .unwrap();
            assert_eq!(ready, 2);
            assert!(!first.has_pending());
            assert!(first.deliveries().is_empty());
            assert!(second.has_pending());
            assert_eq!(client.state(), State::Ready);
            assert_unacknowledged(&second_probe);
            second.deliver(&mut client).await
        };
        let (produced, delivered) =
            timeout_at(deadline, async { tokio::join!(producer, delivery) })
                .await
                .unwrap();
        produced.unwrap();
        assert_eq!(delivered.unwrap().registry, 2);
        assert!(!second.has_pending());
        assert!(second_probe.construction_export_snapshot().progress[0].acknowledged);
        assert_eq!(first_probe.snapshot(), (Vec::new(), 0));
        assert_eq!(finish(&mut first, &mut client, deadline).await, Ok(()));
        assert_eq!(finish(&mut second, &mut client, deadline).await, Ok(()));
        assert!(first.terminal().unwrap().successful);
        assert!(second.terminal().unwrap().successful);
        assert_eq!(
            timeout_at(deadline, finish_stream(&mut client, deadline))
                .await
                .unwrap()
                .unwrap()
                .transaction,
            6
        );
        assert_eq!(client.state(), State::Finished);
        drop(client.into_stream());
    };
    tokio::join!(server, client);
}

#[tokio::test]
async fn finish_drains_cancelled_buffered_producer_as_producer_gone() {
    let deadline = Instant::now() + Duration::from_secs(5);
    let listener = listener(deadline).await;
    let address = listener.local_addr().unwrap();
    let probe = Arc::new(SelectionProbe::new());
    let mut consumer = Consumer::install(Arc::clone(&probe), 1, 0, deadline).unwrap();
    let server = async {
        let mut stream = accept(&listener, deadline).await;
        confirmed(&mut stream, 1, deadline).await;
        assert_terminal(&confirmed(&mut stream, 2, deadline).await, 1, true);
        eof(&mut stream, deadline).await;
    };
    let client = async {
        let mut client = Client::new(connect(address, deadline).await, deadline);
        open(&mut consumer, &mut client, deadline).await;
        let mut producer =
            Box::pin(probe.publish_construction(observation(), true, Some(true), None, None));
        assert!(futures::poll!(producer.as_mut()).is_pending());
        assert_unacknowledged(&probe);
        assert_eq!(consumer.receiver.len(), 1);
        assert!(consumer.pending.is_none());
        drop(producer);
        assert_eq!(
            probe.construction_export_snapshot().failure,
            Some("construction export acknowledgement cancelled")
        );
        assert_eq!(
            finish(&mut consumer, &mut client, deadline).await,
            Err(Error::ProducerIncomplete)
        );
        assert_eq!(consumer.failure(), Some(&Error::ProducerGone));
        assert!(consumer.deliveries().is_empty());
        assert!(consumer.receiver.is_empty());
        let terminal = consumer.terminal().unwrap();
        assert_eq!(terminal.journal_count, 1);
        assert_eq!(terminal.dropped, 0);
        assert!(!terminal.local_finish_ok);
        assert!(!terminal.successful);
        assert!(terminal.wire_receipt.is_some());
        assert_eq!(
            terminal.snapshot.failure,
            Some("construction export acknowledgement cancelled")
        );
        assert!(terminal.snapshot.closed);
        assert!(terminal.snapshot.progress[0].queued);
        assert!(!terminal.snapshot.progress[0].acknowledged);
        assert_eq!(client.state(), State::Ready);
        drop(client.into_stream());
    };
    tokio::join!(server, client);
}

#[tokio::test]
async fn failure_projection_preserves_first_receipt_and_pending_second_export() {
    let deadline = Instant::now() + Duration::from_secs(5);
    let listener = listener(deadline).await;
    let address = listener.local_addr().unwrap();
    let probe = Arc::new(SelectionProbe::new());
    let mut consumer = Consumer::install(Arc::clone(&probe), 7, 0, deadline).unwrap();

    let server = async {
        let mut stream = accept(&listener, deadline).await;
        assert_eq!(integer(&confirmed(&mut stream, 1, deadline).await, 3), 7);
        assert_eq!(confirmed(&mut stream, 2, deadline).await[1], b'R');
        eof(&mut stream, deadline).await;
    };
    let client = async {
        let mut client = Client::new(connect(address, deadline).await, deadline);
        open(&mut consumer, &mut client, deadline).await;
        let mut reserved = observation();
        reserved.route = "SECRET_ROUTE_SENTINEL".into();
        let (produced, delivered) = timeout_at(deadline, async {
            tokio::join!(
                probe.publish_construction(reserved, true, Some(true), None, None),
                consumer.next(&mut client),
            )
        })
        .await
        .unwrap();
        produced.unwrap();
        let receipt = delivered.unwrap();
        assert_eq!(receipt.transaction, 2);
        assert_eq!(receipt.registry, 7);
        assert_eq!(receipt.operation, Operation::Reserved);
        assert_eq!(receipt.journal_sequence, 1);

        let storage = super::super::construction_export::StorageEvidence {
            base: std::path::PathBuf::from("/PRIVATE_PATH_SENTINEL"),
            allocated: std::path::PathBuf::from("/PRIVATE_PATH_SENTINEL/owners-v1/3"),
            slot: 3,
        };
        let mut producer = Box::pin(probe.export_storage(
            (0, "SECRET_ROUTE_SENTINEL".into(), true),
            41,
            storage,
            true,
            deadline,
        ));
        assert!(futures::poll!(producer.as_mut()).is_pending());
        std::future::poll_fn(|cx| consumer.poll_receive(cx))
            .await
            .unwrap();
        assert_eq!(consumer.deliveries.len(), 2);
        assert!(consumer.pending.is_some());
        consumer.failure = Some(Error::Wire(WireError::Denied(
            "DENIED_SECRET_SENTINEL".into(),
        )));
        let before = probe.construction_export_snapshot();
        assert_eq!(before.progress.len(), 2);
        assert!(before.progress[0].acknowledged);
        assert!(before.progress[0].failure.is_none());
        assert!(!before.progress[1].acknowledged);
        assert!(before.progress[1].failure.is_none());
        let pending = consumer.pending.as_ref().unwrap() as *const Envelope;
        let mut first = String::new();
        consumer.append_failure_projection(&mut first, 0);
        let mut second = String::new();
        consumer.append_failure_projection(&mut second, 0);
        assert_eq!(first, second);
        assert_eq!(
            pending,
            consumer.pending.as_ref().unwrap() as *const Envelope,
        );
        assert!(!consumer
            .pending
            .as_ref()
            .unwrap()
            .acknowledgement
            .is_closed());
        assert_eq!(probe.construction_export_snapshot(), before);
        assert!(futures::poll!(producer.as_mut()).is_pending());
        assert!(first.contains("registry=7"));
        assert!(first.contains("pending_envelope=true delivery_count=2 failed=true"));
        assert!(first.contains("receipt_transaction=Some(2)"));
        assert!(first.contains("receipt_operation=reserved producer_ack_sent_local=true"));
        assert!(first.contains("request=0 journal=2 identity=Some(41) slot=Some(3)"));
        assert!(first.contains("receipt_operation=absent producer_ack_sent_local=false"));
        for forbidden in [
            "SECRET_ROUTE_SENTINEL",
            "PRIVATE_PATH_SENTINEL",
            "DENIED_SECRET_SENTINEL",
        ] {
            assert!(!first.contains(forbidden));
        }

        consumer.reject_pending();
        let error = timeout_at(deadline, producer.as_mut())
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "construction export acknowledgement rejected",
        );
        let after = probe.construction_export_snapshot();
        assert_eq!(
            after.failure,
            Some("construction export acknowledgement rejected"),
        );
        assert_eq!(after.progress.len(), 2);
        assert_eq!(after.progress[0], before.progress[0]);
        assert!(after.progress[0].acknowledged);
        assert!(after.progress[0].failure.is_none());
        assert_eq!(after.progress[1].evidence, before.progress[1].evidence);
        assert!(after.progress[1].queued);
        assert!(!after.progress[1].acknowledged);
        assert_eq!(
            after.progress[1].failure,
            Some("construction export acknowledgement rejected"),
        );
        assert!(consumer.pending.is_none());
        assert_eq!(consumer.deliveries[0].receipt.as_ref(), Some(&receipt));
        assert!(consumer.deliveries[0].producer_ack_sent);
        assert!(consumer.deliveries[0].failure.is_none());
        assert!(consumer.deliveries[1].receipt.is_none());
        assert!(!consumer.deliveries[1].producer_ack_sent);
        assert_eq!(
            consumer.deliveries[1].failure,
            Some(Error::ProducerIncomplete),
        );
        assert_eq!(
            consumer.failure,
            Some(Error::Wire(WireError::Denied(
                "DENIED_SECRET_SENTINEL".into(),
            ))),
        );
        drop(producer);
        drop(client.into_stream());
    };
    timeout_at(deadline, async {
        tokio::join!(server, client);
    })
    .await
    .unwrap();
}
