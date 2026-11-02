use super::*;
use crate::tor_watchdog::TorHandle;
use arti_wrapper::Socks5PreEndpoint;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

fn reserved(request_id: usize, identity: usize) -> SelectionObservation {
    SelectionObservation {
        request_id,
        route: "none".into(),
        identity: Some(identity),
        storage_slot: None,
        outcome: SelectionOutcome::Reserved,
        event: SelectionEvent::Reserved,
    }
}

fn acknowledge(envelope: Envelope, accepted: bool) {
    envelope
        .acknowledgement
        .send(Acknowledgement {
            journal_sequence: envelope.evidence.journal_sequence,
            accepted,
        })
        .unwrap();
}

fn assert_pending(probe: &SelectionProbe, observation: &SelectionObservation) {
    assert_eq!(probe.snapshot(), (vec![observation.clone()], 0));
    let snapshot = probe.construction_export_snapshot();
    assert!(snapshot.installed);
    assert!(!snapshot.closed);
    assert!(snapshot.failure.is_none());
    assert_eq!(snapshot.creation_attempts, 0);
    assert_eq!(snapshot.progress.len(), 1);
    assert!(snapshot.progress[0].queued);
    assert!(!snapshot.progress[0].acknowledged);
    assert!(snapshot.progress[0].failure.is_none());
}

#[tokio::test]
async fn absent_export_preserves_journal_delivery_and_drop_accounting() {
    let probe = SelectionProbe::new();
    let mut events = probe.subscribe();
    for request in 0..=OBSERVATION_CAP {
        probe
            .publish_construction(reserved(request, request + 1), true, Some(true), None, None)
            .await
            .unwrap();
    }
    assert_eq!(probe.snapshot().0.len(), OBSERVATION_CAP);
    assert_eq!(probe.snapshot().1, 1);
    assert_eq!(*events.borrow_and_update(), OBSERVATION_CAP);
    assert_eq!(
        probe.construction_export_snapshot(),
        ExportSnapshot::default()
    );
    assert!(probe
        .install_construction_export(Instant::now() + Duration::from_secs(5))
        .is_err());
}

#[tokio::test]
async fn held_acknowledgement_expires_after_actual_delivery() {
    let probe = SelectionProbe::new();
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut receiver = probe.install_construction_export(deadline).unwrap();
    let observation = reserved(0, 17);
    let mut producer =
        Box::pin(probe.publish_construction(observation.clone(), true, Some(true), None, None));
    let envelope = tokio::select! {
        biased;
        result = &mut producer => panic!("producer completed before receipt: {result:?}"),
        envelope = receiver.recv() => envelope.unwrap(),
    };
    assert_pending(&probe, &observation);
    assert!(!envelope.acknowledgement.is_closed());
    assert!(producer.await.is_err());
    assert!(envelope.acknowledgement.is_closed());
    assert_eq!(probe.snapshot(), (vec![observation], 0));
    let snapshot = probe.construction_export_snapshot();
    assert_eq!(
        snapshot.failure,
        Some("construction export acknowledgement deadline")
    );
    assert!(!snapshot.progress[0].acknowledged);
    assert_eq!(
        snapshot.progress[0].failure,
        Some("construction export acknowledgement deadline")
    );
    assert!(probe.finish_construction_export().is_err());
    assert!(probe.construction_export_snapshot().closed);
    assert!(envelope
        .acknowledgement
        .send(Acknowledgement {
            journal_sequence: 1,
            accepted: true,
        })
        .is_err());
}

#[tokio::test]
async fn dropping_the_awaiting_producer_retains_failed_progress() {
    let probe = SelectionProbe::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut receiver = probe.install_construction_export(deadline).unwrap();
    let observation = reserved(0, 19);
    let mut producer =
        Box::pin(probe.publish_construction(observation.clone(), true, Some(true), None, None));
    let envelope = tokio::select! {
        biased;
        result = &mut producer => panic!("producer completed before receipt: {result:?}"),
        envelope = receiver.recv() => envelope.unwrap(),
    };
    assert_pending(&probe, &observation);
    assert!(!envelope.acknowledgement.is_closed());
    drop(producer);
    assert!(envelope.acknowledgement.is_closed());
    assert_eq!(probe.snapshot(), (vec![observation], 0));
    let snapshot = probe.construction_export_snapshot();
    assert_eq!(
        snapshot.failure,
        Some("construction export acknowledgement cancelled")
    );
    assert_eq!(
        snapshot.progress[0].failure,
        Some("construction export acknowledgement cancelled")
    );
    assert!(snapshot.progress[0].queued);
    assert!(!snapshot.progress[0].acknowledged);
    assert!(envelope
        .acknowledgement
        .send(Acknowledgement {
            journal_sequence: 1,
            accepted: true,
        })
        .is_err());
    assert!(probe.finish_construction_export().is_err());
    let snapshot = probe.construction_export_snapshot();
    assert!(snapshot.closed);
    assert!(!snapshot.progress[0].acknowledged);
}

#[tokio::test]
async fn mismatched_acknowledgement_is_retained() {
    let probe = SelectionProbe::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut receiver = probe.install_construction_export(deadline).unwrap();
    let observation = reserved(0, 23);
    let producer = probe.publish_construction(observation.clone(), true, Some(true), None, None);
    let consumer = async {
        let envelope = receiver.recv().await.unwrap();
        envelope
            .acknowledgement
            .send(Acknowledgement {
                journal_sequence: 2,
                accepted: true,
            })
            .unwrap();
    };
    let (result, ()) = tokio::join!(producer, consumer);
    assert!(result.is_err());
    assert_eq!(probe.snapshot(), (vec![observation], 0));
    assert_eq!(
        probe.construction_export_snapshot().progress[0].failure,
        Some("construction export acknowledgement mismatch")
    );
    assert!(probe.finish_construction_export().is_err());
}

#[tokio::test]
async fn lost_acknowledgement_is_not_completion() {
    let probe = SelectionProbe::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut receiver = probe.install_construction_export(deadline).unwrap();
    let observation = reserved(0, 29);
    let producer = probe.publish_construction(observation.clone(), true, Some(true), None, None);
    let consumer = async {
        drop(receiver.recv().await.unwrap());
    };
    let (result, ()) = tokio::join!(producer, consumer);
    assert!(result.is_err());
    assert_eq!(probe.snapshot(), (vec![observation], 0));
    assert_eq!(
        probe.construction_export_snapshot().progress[0].failure,
        Some("construction export acknowledgement lost")
    );
    assert!(probe.finish_construction_export().is_err());
}

#[tokio::test]
async fn unexported_journal_records_cannot_manufacture_completion() {
    let probe = SelectionProbe::new();
    let _receiver = probe
        .install_construction_export(Instant::now() + Duration::from_secs(5))
        .unwrap();
    for request in 0..OBSERVATION_CAP {
        probe.publish(reserved(request, request + 1));
    }
    assert!(probe
        .publish_construction(
            reserved(OBSERVATION_CAP, OBSERVATION_CAP + 1),
            true,
            Some(true),
            None,
            None,
        )
        .await
        .is_err());
    assert_eq!(probe.snapshot().0.len(), OBSERVATION_CAP);
    assert_eq!(probe.snapshot().1, 1);
    assert!(probe.finish_construction_export().is_err());
}

fn registry(base: &Path) -> OwnerRegistry {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let settings = Settings {
        pre_endpoint: Some(Socks5PreEndpoint::new(
            "127.0.0.1:1080".parse().unwrap(),
            Some(("alice".into(), "not-exported".into())),
        )),
        bridges: vec!["192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01"
            .parse()
            .unwrap()],
        state_dir: Some(base.join("global")),
        ..Default::default()
    };
    let tunnel = TorTunnel::create_unbootstrapped_with(settings.clone()).unwrap();
    OwnerRegistry::new(TorHandle::new(tunnel), settings).unwrap()
}

fn direct_auth(directory: &Path) -> Arc<auth::AuthState> {
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
    Arc::new(auth::AuthState::build_persistent(&users, path).unwrap())
}

async fn construction_case(accept_storage: bool) {
    let _serial = super::super::TEST_LIFECYCLE.lock().await;
    let directory = tempfile::tempdir().unwrap();
    let mut registry = registry(directory.path());
    let bootstrap = Arc::new(AtomicBool::new(false));
    registry.bootstrap_hook = Some(Arc::new({
        let bootstrap = Arc::clone(&bootstrap);
        move || {
            bootstrap.store(true, Ordering::SeqCst);
            Box::pin(async {})
        }
    }));
    let auth = direct_auth(directory.path());
    let proof = auth.verify_proof("direct", "pw").unwrap();
    let lease = auth.admit(&proof).await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let probe = Arc::clone(&registry.selection_probe);
    let mut receiver = probe.install_construction_export(deadline).unwrap();
    let consumer = async {
        let reservation = receiver.recv().await.unwrap();
        let reserved = reservation.evidence.clone();
        assert_eq!(reserved.event, SelectionEvent::Reserved);
        assert_eq!(reserved.journal_sequence, 1);
        assert_eq!(reserved.request_id, 0);
        assert!(reserved.identity.is_some());
        assert!(reserved.explicit_disabled);
        assert_eq!(reserved.effective_none, Some(true));
        assert!(reserved.storage.is_none());
        assert_eq!(probe.construction_export_snapshot().creation_attempts, 0);
        acknowledge(reservation, true);

        let assignment = receiver.recv().await.unwrap();
        let assigned = assignment.evidence.clone();
        assert_eq!(assigned.event, SelectionEvent::StorageAssigned);
        assert_eq!(assigned.journal_sequence, 2);
        assert_eq!(assigned.request_id, reserved.request_id);
        assert_eq!(assigned.identity, reserved.identity);
        assert!(assigned.explicit_disabled);
        assert_eq!(assigned.effective_none, Some(true));
        let storage = assigned.storage.as_ref().unwrap();
        assert_eq!(storage.base, directory.path().join("global"));
        assert_eq!(
            storage.allocated,
            storage
                .base
                .join("owners-v1")
                .join(storage.slot.to_string())
        );
        assert!(storage.allocated.is_dir());
        assert_eq!(probe.construction_export_snapshot().creation_attempts, 0);
        assert!(!bootstrap.load(Ordering::SeqCst));
        acknowledge(assignment, accept_storage);
        (reserved, assigned)
    };
    let (selection, (reserved, assigned)) = tokio::time::timeout_at(deadline, async {
        tokio::join!(registry.select_admitted(&lease), consumer)
    })
    .await
    .unwrap();
    let (journal, dropped) = probe.snapshot();
    assert_eq!(dropped, 0);
    assert_eq!(journal.len(), 2);
    assert_eq!(journal[0].request_id, reserved.request_id);
    assert_eq!(journal[0].identity, reserved.identity);
    assert_eq!(journal[0].event, reserved.event);
    assert_eq!(journal[1].request_id, assigned.request_id);
    assert_eq!(journal[1].identity, assigned.identity);
    assert_eq!(journal[1].event, assigned.event);
    assert_eq!(
        journal[1].storage_slot,
        Some(assigned.storage.as_ref().unwrap().slot)
    );
    assert_eq!(selection.is_ok(), accept_storage);
    assert_eq!(bootstrap.load(Ordering::SeqCst), accept_storage);
    let snapshot = probe.construction_export_snapshot();
    assert_eq!(snapshot.creation_attempts, usize::from(accept_storage));
    assert!(snapshot.progress[0].acknowledged);
    assert_eq!(snapshot.progress[1].acknowledged, accept_storage);
    drop(selection);
    drop(lease);
    if accept_storage {
        probe.finish_construction_export().unwrap();
    } else {
        assert_eq!(
            snapshot.progress[1].failure,
            Some("construction export acknowledgement rejected")
        );
        assert!(probe.finish_construction_export().is_err());
    }
    registry.close_with_deadline(deadline).await.unwrap();
}

#[tokio::test]
async fn actual_storage_acknowledgement_precedes_tunnel_creation() {
    construction_case(true).await;
}

#[tokio::test]
async fn rejected_storage_acknowledgement_prevents_tunnel_creation() {
    construction_case(false).await;
}

#[tokio::test]
async fn reuse_preserves_the_original_construction_request() {
    let _serial = super::super::TEST_LIFECYCLE.lock().await;
    let directory = tempfile::tempdir().unwrap();
    let mut registry = registry(directory.path());
    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel::<()>();
    let gate = Mutex::new(Some((started_tx, release_rx)));
    registry.bootstrap_hook = Some(Arc::new(move || {
        let (started, release) = gate.lock().unwrap().take().unwrap();
        Box::pin(async move {
            started.send(()).unwrap();
            release.await.unwrap();
        })
    }));
    let auth = direct_auth(directory.path());
    let proof = auth.verify_proof("direct", "pw").unwrap();
    let lease = auth.admit(&proof).await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let probe = Arc::clone(&registry.selection_probe);
    let mut receiver = probe.install_construction_export(deadline).unwrap();
    let body = async {
        let mut first = Box::pin(registry.select_admitted(&lease));
        let reservation = tokio::select! {
            result = &mut first => panic!("first selection completed: {}", result.is_ok()),
            envelope = receiver.recv() => envelope.unwrap(),
        };
        let original = reservation.evidence.clone();
        assert_eq!(original.event, SelectionEvent::Reserved);
        assert_eq!(original.request_id, 0);
        acknowledge(reservation, true);
        let assignment = tokio::select! {
            result = &mut first => panic!("first selection completed: {}", result.is_ok()),
            envelope = receiver.recv() => envelope.unwrap(),
        };
        let constructed = assignment.evidence.clone();
        assert_eq!(constructed.event, SelectionEvent::StorageAssigned);
        assert_eq!(constructed.request_id, original.request_id);
        assert_eq!(constructed.identity, original.identity);
        assert_eq!(probe.construction_export_snapshot().creation_attempts, 0);
        acknowledge(assignment, true);
        tokio::select! {
            result = &mut first => panic!("first selection completed: {}", result.is_ok()),
            result = started_rx => result.unwrap(),
        }
        assert_eq!(probe.construction_export_snapshot().creation_attempts, 1);
        drop(first);
        assert!(probe.construction_export_snapshot().failure.is_none());

        let mut second = Box::pin(registry.select_admitted(&lease));
        let reservation = tokio::select! {
            result = &mut second => panic!("reuse completed before reserve receipt: {}", result.is_ok()),
            envelope = receiver.recv() => envelope.unwrap(),
        };
        let reused = reservation.evidence.clone();
        assert_eq!(reused.event, SelectionEvent::Reserved);
        assert_eq!(reused.journal_sequence, 3);
        assert_eq!(reused.request_id, 1);
        assert_ne!(reused.request_id, constructed.request_id);
        assert_eq!(reused.identity, constructed.identity);
        assert!(reused.explicit_disabled);
        assert_eq!(reused.effective_none, Some(true));
        assert!(reused.storage.is_none());
        acknowledge(reservation, true);
        release_tx.send(()).unwrap();
        drop(second.await.unwrap());

        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        let (journal, dropped) = probe.snapshot();
        assert_eq!(dropped, 0);
        assert_eq!(journal.len(), 3);
        assert_eq!(
            journal
                .iter()
                .filter(|event| event.event == SelectionEvent::StorageAssigned)
                .count(),
            1
        );
        assert_eq!(journal[0].request_id, original.request_id);
        assert_eq!(journal[1].request_id, original.request_id);
        assert_eq!(journal[2].request_id, reused.request_id);
        assert_eq!(journal[1].identity, journal[2].identity);
        assert_eq!(
            journal[1].storage_slot,
            Some(constructed.storage.as_ref().unwrap().slot)
        );
        let snapshot = probe.construction_export_snapshot();
        assert_eq!(snapshot.creation_attempts, 1);
        assert_eq!(snapshot.progress.len(), 3);
        assert!(snapshot
            .progress
            .iter()
            .all(|progress| progress.queued && progress.acknowledged));
        assert!(snapshot.failure.is_none());
        probe.finish_construction_export().unwrap();
    };
    tokio::time::timeout_at(deadline, body).await.unwrap();
    drop(lease);
    registry.close_with_deadline(deadline).await.unwrap();
}
