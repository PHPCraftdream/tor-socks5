use super::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn line(stream: &mut TcpStream, deadline: Instant) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let byte = timeout_at(deadline, stream.read_u8())
            .await
            .unwrap()
            .unwrap();
        bytes.push(byte);
        assert!(bytes.len() <= 128);
        if byte == b'\n' {
            return bytes;
        }
    }
}

async fn reply(stream: &mut TcpStream, text: &str, deadline: Instant) {
    timeout_at(deadline, stream.write_all(text.as_bytes()))
        .await
        .unwrap()
        .unwrap();
}

async fn transaction(stream: &mut TcpStream, number: usize, deadline: Instant) -> Vec<u8> {
    let start = line(stream, deadline).await;
    let fields = std::str::from_utf8(&start)
        .unwrap()
        .trim_end()
        .split(' ')
        .collect::<Vec<_>>();
    assert_eq!(&fields[..2], &["CE", "START"]);
    assert_eq!(fields[2], number.to_string());
    let size = fields[3].parse::<usize>().unwrap();
    assert!((49..=4877).contains(&size));
    reply(stream, &format!("CE READY {number}\n"), deadline).await;
    let mut body = Vec::new();
    while body.len() < size {
        let chunk = line(stream, deadline).await;
        let fields = std::str::from_utf8(&chunk)
            .unwrap()
            .trim_end()
            .split(' ')
            .collect::<Vec<_>>();
        assert_eq!(&fields[..2], &["CE", "DATA"]);
        assert_eq!(fields[2], number.to_string());
        assert_eq!(fields[3], body.len().to_string());
        let hex = fields[4].as_bytes();
        assert!(!hex.is_empty() && hex.len() <= 96 && hex.len() % 2 == 0);
        for pair in hex.as_chunks::<2>().0 {
            body.push(u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap());
        }
        assert!(body.len() <= size);
        reply(
            stream,
            &format!("CE NEXT {number} {}\n", body.len()),
            deadline,
        )
        .await;
    }
    assert_eq!(
        line(stream, deadline).await,
        format!("CE COMMIT {number}\n").as_bytes()
    );
    reply(stream, &format!("CE ACCEPT {number}\n"), deadline).await;
    assert_eq!(
        line(stream, deadline).await,
        format!("CE CONFIRM {number}\n").as_bytes()
    );
    body
}

async fn confirmed(stream: &mut TcpStream, number: usize, deadline: Instant) -> Vec<u8> {
    let body = transaction(stream, number, deadline).await;
    reply(stream, &format!("CE CONFIRMED {number}\n"), deadline).await;
    body
}

async fn listener(deadline: Instant) -> TcpListener {
    timeout_at(deadline, TcpListener::bind("127.0.0.1:0"))
        .await
        .unwrap()
        .unwrap()
}

async fn connect(address: SocketAddr, deadline: Instant) -> TcpStream {
    timeout_at(deadline, TcpStream::connect(address))
        .await
        .unwrap()
        .unwrap()
}

async fn accept(listener: &TcpListener, deadline: Instant) -> TcpStream {
    timeout_at(deadline, listener.accept())
        .await
        .unwrap()
        .unwrap()
        .0
}

async fn eof(stream: &mut TcpStream, deadline: Instant) {
    let mut byte = [0];
    assert_eq!(
        timeout_at(deadline, stream.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

async fn direct_lease(directory: &std::path::Path) -> auth::AdmissionLease {
    let path = directory.join("users.ktav");
    let users = auth::UsersConfig {
        users: vec![auth::User {
            name: "direct".into(),
            hash: auth::compute_hash("pw").unwrap(),
            is_enabled: true,
            allowed_onion: false,
            allowed_clients: None,
            pre_socks5: Some(proxy_config::EndpointOverride::Disabled),
            post_socks5: None,
        }],
    };
    users.save(&path).unwrap();
    let auth = auth::AuthState::build_persistent(&users, path).unwrap();
    let proof = auth.verify_proof("direct", "pw").unwrap();
    auth.admit(&proof).await.unwrap()
}

#[tokio::test]
async fn actual_assignment_receipt_drives_owner_intent_before_child_readiness() {
    use std::os::unix::ffi::OsStrExt;
    let _serial = super::super::TEST_LIFECYCLE.lock().await;
    let deadline = Instant::now() + Duration::from_secs(5);
    let listener = listener(deadline).await;
    let address = listener.local_addr().unwrap();
    let ready = self::listener(deadline).await;
    let ready_address = ready.local_addr().unwrap();
    let executable = std::env::current_exe().unwrap();
    let expected = Arc::new(Mutex::new(None::<Vec<u8>>));
    let server = async {
        let mut stream = accept(&listener, deadline).await;
        assert_eq!(confirmed(&mut stream, 1, deadline).await[1], b'O');
        assert_eq!(confirmed(&mut stream, 2, deadline).await[1], b'R');
        assert_eq!(confirmed(&mut stream, 3, deadline).await[1], b'S');
        let mut intent = accept(&listener, deadline).await;
        let frame = expected.lock().unwrap().as_ref().unwrap().clone();
        let mut actual = vec![0; frame.len()];
        timeout_at(deadline, intent.read_exact(&mut actual))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(actual, frame);
        reply(&mut intent, "OK\n", deadline).await;
        assert_eq!(confirmed(&mut stream, 4, deadline).await[1], b'X');
        assert_eq!(confirmed(&mut stream, 5, deadline).await[1], b'Z');
        eof(&mut stream, deadline).await;
    };
    let client = async {
        let mut session = Session::new(connect(address, deadline).await, deadline);
        session.coordinator = Some(super::super::owner_intent::Coordinator::new(
            ready,
            executable.clone(),
            address,
        ));
        let directory = tempfile::tempdir().unwrap();
        let expected = Arc::clone(&expected);
        session
            .run_phase(0, deadline, async move {
                let mut registry = super::super::tests::registry(directory.path());
                registry.bootstrap_hook = Some(Arc::new(|| Box::pin(async {})));
                let lease = direct_lease(directory.path()).await;
                drop(registry.select_admitted(&lease).await.unwrap());
                let snapshot = registry.selection_probe.construction_export_snapshot();
                let storage = snapshot
                    .progress
                    .iter()
                    .find_map(|item| item.evidence.storage.clone())
                    .unwrap();
                assert_eq!(snapshot.progress[1].evidence.request_id, 0);
                assert!(snapshot.progress[1].acknowledged);
                let leaf = storage
                    .allocated
                    .join("state/pt_state")
                    .join(executable.file_name().unwrap());
                // Synthetic child notification; the allocation/receipt above is from the real registry.
                std::fs::create_dir_all(&leaf).unwrap();
                let encode = |bytes: &[u8]| {
                    bytes
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>()
                };
                let allocated = storage.allocated.as_os_str().as_bytes();
                let leaf_bytes = leaf.as_os_str().as_bytes();
                *expected.lock().unwrap() = Some(
                    format!(
                        "INTENT {} {}\n{} {}\n",
                        allocated.len(),
                        leaf_bytes.len(),
                        encode(allocated),
                        encode(leaf_bytes)
                    )
                    .into_bytes(),
                );
                let mut child = connect(ready_address, deadline).await;
                reply(
                    &mut child,
                    &format!("READY {}\n", encode(leaf_bytes)),
                    deadline,
                )
                .await;
                let response = line(&mut child, deadline).await;
                assert!(response.starts_with(b"READY "));
                drop(lease);
                registry.close_with_deadline(deadline).await.unwrap();
            })
            .await
            .unwrap();
        assert!(session.coordinator.as_ref().unwrap().phase_complete(0));
        session.finish().await.unwrap();
        drop(session);
    };
    timeout_at(deadline, async {
        tokio::join!(server, client);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn actual_registry_attaches_before_publication_and_waits_before_creation() {
    let _serial = super::super::TEST_LIFECYCLE.lock().await;
    let deadline = Instant::now() + Duration::from_secs(5);
    let listener = listener(deadline).await;
    let address = listener.local_addr().unwrap();
    let probe_slot = Arc::new(Mutex::new(None::<Arc<SelectionProbe>>));
    let server = async {
        let mut stream = accept(&listener, deadline).await;
        assert_eq!(confirmed(&mut stream, 1, deadline).await[1], b'O');
        let reserved = confirmed(&mut stream, 2, deadline).await;
        assert_eq!(reserved[1], b'R');
        let assigned = transaction(&mut stream, 3, deadline).await;
        assert_eq!(assigned[1], b'S');
        assert_eq!(&assigned[19..27], &reserved[19..27]);
        assert_eq!(&assigned[27..35], &reserved[27..35]);
        let probe = probe_slot.lock().unwrap().as_ref().unwrap().clone();
        let snapshot = probe.construction_export_snapshot();
        assert_eq!(snapshot.creation_attempts, 0);
        assert_eq!(snapshot.progress.len(), 2);
        assert!(snapshot.progress[0].acknowledged);
        assert!(!snapshot.progress[1].acknowledged);
        reply(&mut stream, "CE CONFIRMED 3\n", deadline).await;
        let terminal = confirmed(&mut stream, 4, deadline).await;
        assert_eq!(terminal[1], b'X');
        assert_eq!(&terminal[49..52], &[1, 1, 0]);
        assert_eq!(confirmed(&mut stream, 5, deadline).await[1], b'Z');
        eof(&mut stream, deadline).await;
    };
    let client = async {
        let mut session = Session::new(connect(address, deadline).await, deadline);
        let directory = tempfile::tempdir().unwrap();
        let work_slot = Arc::clone(&probe_slot);
        let work = async move {
            let mut registry = super::super::tests::registry(directory.path());
            assert!(
                registry
                    .selection_probe
                    .construction_export_snapshot()
                    .installed
            );
            assert!(registry.selection_probe.snapshot().0.is_empty());
            *work_slot.lock().unwrap() = Some(Arc::clone(&registry.selection_probe));
            registry.bootstrap_hook = Some(Arc::new(|| Box::pin(async {})));
            let lease = direct_lease(directory.path()).await;
            let owner = registry.select_admitted(&lease).await.unwrap();
            assert_eq!(
                registry
                    .selection_probe
                    .construction_export_snapshot()
                    .creation_attempts,
                1
            );
            drop((owner, lease));
            registry.close_with_deadline(deadline).await.unwrap();
        };
        session.run_phase(0, deadline, work).await.unwrap();
        assert!(ACTIVE.try_with(|_| ()).is_err());
        assert_eq!(session.records.len(), 1);
        assert!(session.records[0].closed && session.records[0].finished);
        assert!(
            session.records[0]
                .registration
                .consumer
                .terminal()
                .unwrap()
                .successful
        );
        session.finish().await.unwrap();
        drop(session);
        let directory = tempfile::tempdir().unwrap();
        let registry = super::super::tests::registry(directory.path());
        assert!(
            !registry
                .selection_probe
                .construction_export_snapshot()
                .installed
        );
        registry.close_with_deadline(deadline).await.unwrap();
    };
    timeout_at(deadline, async {
        tokio::join!(server, client);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn real_idle_registry_does_not_block_another_constructor() {
    let _serial = super::super::TEST_LIFECYCLE.lock().await;
    let deadline = Instant::now() + Duration::from_secs(5);
    let listener = listener(deadline).await;
    let address = listener.local_addr().unwrap();
    let server = async {
        let mut stream = accept(&listener, deadline).await;
        let first = confirmed(&mut stream, 1, deadline).await;
        let second = confirmed(&mut stream, 2, deadline).await;
        assert_eq!(&first[3..11], &1u64.to_be_bytes());
        assert_eq!(&second[3..11], &2u64.to_be_bytes());
        for (number, operation) in [(3, b'R'), (4, b'S')] {
            let event = confirmed(&mut stream, number, deadline).await;
            assert_eq!(event[1], operation);
            assert_eq!(&event[3..11], &2u64.to_be_bytes());
        }
        for (number, registry) in [(5, 1u64), (6, 2u64)] {
            let terminal = confirmed(&mut stream, number, deadline).await;
            assert_eq!(terminal[1], b'X');
            assert_eq!(&terminal[3..11], &registry.to_be_bytes());
        }
        assert_eq!(confirmed(&mut stream, 7, deadline).await[1], b'Z');
        eof(&mut stream, deadline).await;
    };
    let client = async {
        let mut session = Session::new(connect(address, deadline).await, deadline);
        let first_directory = tempfile::tempdir().unwrap();
        let second_directory = tempfile::tempdir().unwrap();
        session
            .run_phase(0, deadline, async move {
                let first = super::super::tests::registry(first_directory.path());
                let mut second = super::super::tests::registry(second_directory.path());
                second.bootstrap_hook = Some(Arc::new(|| Box::pin(async {})));
                let lease = direct_lease(second_directory.path()).await;
                drop(second.select_admitted(&lease).await.unwrap());
                assert!(first.selection_probe.snapshot().0.is_empty());
                assert_eq!(second.selection_probe.snapshot().0.len(), 2);
                drop(lease);
                first.close_with_deadline(deadline).await.unwrap();
                second.close_with_deadline(deadline).await.unwrap();
            })
            .await
            .unwrap();
        assert_eq!(session.records.len(), 2);
        session.finish().await.unwrap();
        drop(session);
    };
    timeout_at(deadline, async {
        tokio::join!(server, client);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn wrong_external_receipt_cancels_and_retains_actual_registry() {
    let _serial = super::super::TEST_LIFECYCLE.lock().await;
    let deadline = Instant::now() + Duration::from_secs(5);
    let listener = listener(deadline).await;
    let address = listener.local_addr().unwrap();
    let server = async {
        let mut stream = accept(&listener, deadline).await;
        confirmed(&mut stream, 1, deadline).await;
        assert_eq!(transaction(&mut stream, 2, deadline).await[1], b'R');
        reply(&mut stream, "CE CONFIRMED 99\n", deadline).await;
        eof(&mut stream, deadline).await;
    };
    let client = async {
        let mut session = Session::new(connect(address, deadline).await, deadline);
        let directory = tempfile::tempdir().unwrap();
        let result = session
            .run_phase(0, deadline, async move {
                let registry = super::super::tests::registry(directory.path());
                let lease = direct_lease(directory.path()).await;
                assert!(registry.select_admitted(&lease).await.is_err());
                assert_eq!(
                    registry
                        .selection_probe
                        .construction_export_snapshot()
                        .failure,
                    Some("construction export acknowledgement cancelled")
                );
                registry.close_with_deadline(deadline).await.unwrap();
            })
            .await;
        assert!(result.is_err());
        assert!(ACTIVE.try_with(|_| ()).is_err());
        assert_eq!(session.records.len(), 1);
        assert!(session.records[0].closed);
        {
            let retained = &session.records[0].registration.retained;
            let entries = retained.entries.lock().unwrap();
            assert_eq!(entries.len(), 1);
            assert_eq!(
                retained.probe.snapshot().0[0].identity,
                Some(Arc::as_ptr(&entries[0]) as usize)
            );
        }
        let terminal = session.records[0].registration.consumer.terminal().unwrap();
        assert!(!terminal.successful && terminal.wire_receipt.is_none());
        assert!(!terminal.snapshot.progress[0].acknowledged);
        assert!(session.finish().await.is_err());
        drop(session);
    };
    timeout_at(deadline, async {
        tokio::join!(server, client);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn phase_deadline_hands_off_live_constructor_and_scenario_ownership() {
    let _serial = super::super::TEST_LIFECYCLE.lock().await;
    let start = Instant::now();
    let deadline = start + Duration::from_secs(5);
    let phase_deadline = start + Duration::from_millis(2500);
    let listener = listener(deadline).await;
    let address = listener.local_addr().unwrap();
    let server = async {
        let mut stream = accept(&listener, deadline).await;
        assert_eq!(confirmed(&mut stream, 1, deadline).await[1], b'O');
        assert_eq!(confirmed(&mut stream, 2, deadline).await[1], b'R');
        assert_eq!(confirmed(&mut stream, 3, deadline).await[1], b'S');
        let mut received = 0usize;
        loop {
            let mut bytes = [0; 128];
            let count = timeout_at(deadline, stream.read(&mut bytes))
                .await
                .unwrap()
                .unwrap();
            if count == 0 {
                break;
            }
            received += count;
            assert!(received <= 8192);
        }
    };
    let client = async {
        let mut session = Session::new(connect(address, deadline).await, deadline);
        let directory = tempfile::tempdir().unwrap();
        let (resume_tx, resume_rx) = tokio::sync::oneshot::channel::<()>();
        let work = async move {
            let mut registry = super::super::tests::registry(directory.path());
            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            let (_release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
            let gate = Mutex::new(Some((started_tx, release_rx)));
            registry.bootstrap_hook = Some(Arc::new(move || {
                let (started, release) = gate.lock().unwrap().take().unwrap();
                Box::pin(async move {
                    started.send(()).unwrap();
                    let _ = release.await;
                })
            }));
            let lease = direct_lease(directory.path()).await;
            let mut selection = Box::pin(registry.select_admitted(&lease));
            tokio::select! {
                result = &mut selection => panic!("constructor completed before its hold: {}", result.is_ok()),
                result = timeout_at(phase_deadline, started_rx) => result.unwrap().unwrap(),
            }
            resume_rx.await.unwrap();
            drop(selection);
            drop(lease);
            registry.close_with_deadline(deadline).await.unwrap();
        };
        let result = timeout_at(deadline, session.run_phase(0, phase_deadline, work))
            .await
            .expect("phase failed to hand back retained ownership");
        assert!(result.is_err());
        assert!(Instant::now() >= phase_deadline && Instant::now() < deadline);
        assert!(session.work.is_some());
        assert!(!session.registries_closed());
        assert_eq!(session.records.len(), 1);
        assert_eq!(
            session.records[0]
                .registration
                .retained
                .entries
                .lock()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            session.records[0]
                .registration
                .retained
                .probe
                .construction_export_snapshot()
                .creation_attempts,
            1
        );
        resume_tx.send(()).unwrap();
        assert!(timeout_at(deadline, session.finish())
            .await
            .unwrap()
            .is_err());
        assert!(session.work.is_none());
        assert!(session.registries_closed());
        assert!(timeout_at(deadline, session.settle())
            .await
            .unwrap()
            .is_ok());
        drop(session);
    };
    timeout_at(deadline, async {
        tokio::join!(server, client);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancelled_phase_keeps_work_after_finish_deadline_until_settlement() {
    let _serial = super::super::TEST_LIFECYCLE.lock().await;
    let start = Instant::now();
    let deadline = start + Duration::from_secs(5);
    let session_deadline = start + Duration::from_millis(2500);
    let listener = listener(deadline).await;
    let address = listener.local_addr().unwrap();
    let (held_tx, held_rx) = tokio::sync::oneshot::channel();
    let server = async {
        let mut stream = accept(&listener, deadline).await;
        assert_eq!(transaction(&mut stream, 1, deadline).await[1], b'O');
        held_tx.send(()).unwrap();
        eof(&mut stream, deadline).await;
    };
    let client = async {
        let mut session = Session::new(connect(address, deadline).await, session_deadline);
        let directory = tempfile::tempdir().unwrap();
        let (resume_tx, resume_rx) = tokio::sync::oneshot::channel::<()>();
        let mut phase = Box::pin(session.run_phase(0, session_deadline, async move {
            let registry = super::super::tests::registry(directory.path());
            assert!(
                registry
                    .selection_probe
                    .construction_export_snapshot()
                    .installed
            );
            resume_rx.await.unwrap();
            registry.close_with_deadline(deadline).await.unwrap();
        }));
        tokio::select! {
            result = &mut phase => panic!("phase completed before cancellation: {result:?}"),
            result = timeout_at(deadline, held_rx) => result.unwrap().unwrap(),
        }
        drop(phase);
        assert!(ACTIVE.try_with(|_| ()).is_err());
        assert!(session.hook.is_some());
        assert_eq!(session.client.state(), WireState::InFlight);
        assert_eq!(session.records.len(), 1);
        assert!(!session.records[0].closed);
        assert!(session.work.is_some());
        assert!(timeout_at(deadline, session.finish())
            .await
            .expect("finish did not return its retained deadline handoff")
            .is_err());
        assert!(Instant::now() >= session_deadline && Instant::now() < deadline);
        assert!(session.hook.is_none());
        assert!(session.registrations.is_none());
        assert!(session.work.is_some());
        assert!(!session.records[0].closed);
        assert!(!session.records[0].finished);
        assert!(session.records[0]
            .registration
            .consumer
            .terminal()
            .is_none());
        resume_tx
            .send(())
            .expect("finish dropped the retained scenario");
        timeout_at(deadline, session.settle())
            .await
            .expect("settlement did not finish after explicit scenario release")
            .unwrap();
        assert!(session.work.is_none());
        assert!(session.failure.is_some());
        assert!(session.finish().await.is_err());
        assert!(session.records[0].closed);
        assert!(
            !session.records[0]
                .registration
                .consumer
                .terminal()
                .unwrap()
                .successful
        );
        drop(session);
    };
    timeout_at(deadline, async {
        tokio::join!(server, client);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn first_fail_projects_before_rejection_without_polling_retained_work() {
    use super::super::{SelectionEvent, SelectionObservation, SelectionOutcome};
    use std::sync::atomic::{AtomicUsize, Ordering};

    let _serial = super::super::TEST_LIFECYCLE.lock().await;
    let deadline = Instant::now() + Duration::from_secs(5);
    let listener = listener(deadline).await;
    let address = listener.local_addr().unwrap();

    let server = async {
        let mut stream = accept(&listener, deadline).await;
        assert_eq!(confirmed(&mut stream, 1, deadline).await[1], b'O');
        eof(&mut stream, deadline).await;
    };
    let client = async {
        let mut session = Session::new(connect(address, deadline).await, deadline);
        session.start(0, deadline).unwrap();
        let scope = Arc::clone(&session.hook.as_ref().unwrap().0);
        let directory = tempfile::tempdir().unwrap();
        let registry = ACTIVE
            .scope(scope, async {
                super::super::tests::registry(directory.path())
            })
            .await;
        let registration = session.registrations.as_mut().unwrap().try_recv().unwrap();
        let index = session.insert(registration);
        session.records[index]
            .registration
            .consumer
            .open(&mut session.client)
            .await
            .unwrap();
        session.records[index].enabled = true;

        let probe = Arc::clone(&registry.selection_probe);
        let observation = SelectionObservation {
            request_id: 9,
            route: "DRIVER_SECRET_SENTINEL".into(),
            identity: Some(91),
            storage_slot: None,
            outcome: SelectionOutcome::Reserved,
            event: SelectionEvent::Reserved,
        };
        let mut producer =
            Box::pin(probe.publish_construction(observation, true, Some(true), None, None));
        assert!(futures::poll!(producer.as_mut()).is_pending());
        poll_fn(|cx| {
            session.records[index]
                .registration
                .consumer
                .poll_receive(cx)
        })
        .await
        .unwrap();
        let (resume_tx, resume_rx) = tokio::sync::oneshot::channel::<()>();
        session.work = Some(Box::pin(async move {
            resume_rx.await.unwrap();
            Ok(())
        }));
        let polls = Arc::new(AtomicUsize::new(0));
        let measured_polls = Arc::clone(&polls);
        let mut work = session.work.take().unwrap();
        session.work = Some(Box::pin(poll_fn(move |cx| {
            measured_polls.fetch_add(1, Ordering::SeqCst);
            work.as_mut().poll(cx)
        })));
        assert!(futures::poll!(session.work.as_mut().unwrap().as_mut()).is_pending());
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        let work_pointer = session.work.as_ref().unwrap().as_ref().get_ref()
            as *const dyn Future<Output = std::thread::Result<()>>;
        let export_before = probe.construction_export_snapshot();
        assert!(!registry.cancel.is_cancelled());
        assert!(session.records[index].registration.consumer.has_pending());

        session.fail("construction delivery failed");
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert!(std::ptr::eq(
            work_pointer,
            session.work.as_ref().unwrap().as_ref().get_ref(),
        ));
        let first = session.failure_projection.as_ref().unwrap().clone();
        assert!(first.contains(
            "PT construction before-driver-fail category=construction-delivery-failed wire_state=ready"
        ));
        assert!(first.contains(
            "work_present=true hook_present=true registration_receiver_present=true record_count=1"
        ));
        assert!(first.contains(
            "record index=0 enabled=true closed=false finished=false registry_cancelled=false"
        ));
        assert!(first.contains(
            "registry=1 opened=true stopped=false pending_envelope=true delivery_count=1 failed=false"
        ));
        assert!(first.contains("request=9 journal=1 identity=Some(91)"));
        assert!(first.contains("producer_ack_sent_local=false failed=false"));
        assert!(!first.contains("DRIVER_SECRET_SENTINEL"));
        assert!(registry.cancel.is_cancelled());
        assert!(!session.records[index].enabled);
        assert!(!session.records[index].registration.consumer.has_pending());
        assert!(!resume_tx.is_closed());
        assert_eq!(probe.construction_export_snapshot(), export_before);

        session.fail("owner scenario panicked");
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert_eq!(session.failure, Some("construction delivery failed"));
        assert_eq!(session.failure_projection.as_ref(), Some(&first));
        assert!(!resume_tx.is_closed());
        assert!(futures::poll!(session.work.as_mut().unwrap().as_mut()).is_pending());
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        let error = timeout_at(deadline, producer.as_mut())
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "construction export acknowledgement rejected",
        );
        assert!(!probe.construction_export_snapshot().progress[0].acknowledged);
        drop(producer);
        resume_tx.send(()).unwrap();
        session.work.as_mut().unwrap().as_mut().await.unwrap();
        assert_eq!(polls.load(Ordering::SeqCst), 3);
        session.work.take();
        session.end_scope();
        session.registrations.take();
        registry.close_with_deadline(deadline).await.unwrap();
        drop(session);
    };
    timeout_at(deadline, async {
        tokio::join!(server, client);
    })
    .await
    .unwrap();
}
