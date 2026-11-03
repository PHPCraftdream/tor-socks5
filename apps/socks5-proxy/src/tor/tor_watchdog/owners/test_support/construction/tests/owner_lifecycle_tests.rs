use super::super::super::owner_lifecycle as life;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio_util::sync::CancellationToken;

fn returned(snapshot: &life::Snapshot, stage: life::Stage) -> &life::Record {
    snapshot
        .records
        .iter()
        .find(|record| record.stage == stage && record.kind == life::Kind::Returned)
        .expect("actual boundary returned record")
}

async fn entry(registry: &OwnerRegistry) -> Arc<super::super::super::Entry> {
    registry.state.lock().await.entries[0].clone()
}

fn pending_hook(started: oneshot::Sender<()>) -> super::super::super::BootstrapHook {
    let started = Mutex::new(Some(started));
    Arc::new(move || {
        let started = started.lock().unwrap().take().unwrap();
        Box::pin(async move {
            started.send(()).unwrap();
            std::future::pending::<()>().await;
        })
    })
}

async fn reach_bootstrap<'a>(
    registry: &'a OwnerRegistry,
    lease: &'a auth::AdmissionLease,
    receiver: &mut mpsc::Receiver<Envelope>,
    started: oneshot::Receiver<()>,
) -> Pin<Box<dyn Future<Output = Result<super::super::super::Owner>> + Send + 'a>> {
    let mut selection = Box::pin(registry.select_admitted(lease));
    for event in [SelectionEvent::Reserved, SelectionEvent::StorageAssigned] {
        let envelope = tokio::select! {
            result = &mut selection => panic!(
                "selection returned before bootstrap: {}",
                result.is_ok()
            ),
            envelope = receiver.recv() => envelope.unwrap(),
        };
        assert_eq!(envelope.evidence.event, event);
        acknowledge(envelope, true);
    }
    tokio::select! {
        result = &mut selection => panic!(
            "selection returned before bootstrap gate: {}",
            result.is_ok()
        ),
        result = started => result.unwrap(),
    }
    selection
}

#[tokio::test]
async fn construction_storage_failure_is_observed_at_the_actual_boundary() {
    let _serial = super::super::super::TEST_LIFECYCLE.lock().await;
    let directory = tempfile::tempdir().unwrap();
    let registry = registry(directory.path());
    let base = registry
        .settings
        .as_ref()
        .unwrap()
        .state_dir
        .as_ref()
        .unwrap();
    std::fs::write(base.join("owners-v1"), b"private-storage-sentinel").unwrap();
    let auth = direct_auth(directory.path());
    let proof = auth.verify_proof("direct", "pw").unwrap();
    let lease = auth.admit(&proof).await.unwrap();

    let result = registry.select_admitted(&lease).await;
    assert!(result.is_err());

    let entry = entry(&registry).await;
    let snapshot = entry.lifecycle.snapshot();
    assert_eq!(
        returned(&snapshot, life::Stage::Storage).outcome,
        life::Outcome::Error
    );
    assert_eq!(
        returned(&snapshot, life::Stage::Worker).outcome,
        life::Outcome::Error
    );
    assert_eq!(
        returned(&snapshot, life::Stage::Select).outcome,
        life::Outcome::Error
    );
    assert!(!snapshot.records.iter().any(|record| {
        matches!(
            record.stage,
            life::Stage::Export | life::Stage::Create | life::Stage::Bootstrap
        )
    }));
    assert_eq!(snapshot.first_failure.unwrap().stage, life::Stage::Storage);
    assert!(entry.state.lock().await.constructing.is_none());
    registry
        .close_with_deadline(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
}

#[tokio::test]
async fn construction_create_failure_is_not_bootstrap_or_readiness() {
    let _serial = super::super::super::TEST_LIFECYCLE.lock().await;
    let directory = tempfile::tempdir().unwrap();
    let mut registry = registry(directory.path());
    registry.settings.as_mut().unwrap().circuit_hops = 0;
    let auth = direct_auth(directory.path());
    let proof = auth.verify_proof("direct", "pw").unwrap();
    let lease = auth.admit(&proof).await.unwrap();

    assert!(registry.select_admitted(&lease).await.is_err());

    let entry = entry(&registry).await;
    let snapshot = entry.lifecycle.snapshot();
    assert_eq!(
        returned(&snapshot, life::Stage::Storage).outcome,
        life::Outcome::Ok
    );
    assert_eq!(
        returned(&snapshot, life::Stage::Export).outcome,
        life::Outcome::Ok
    );
    assert_eq!(
        returned(&snapshot, life::Stage::Create).outcome,
        life::Outcome::Error
    );
    assert_eq!(
        returned(&snapshot, life::Stage::Worker).outcome,
        life::Outcome::Error
    );
    assert_eq!(
        returned(&snapshot, life::Stage::Select).outcome,
        life::Outcome::Error
    );
    assert!(!snapshot
        .records
        .iter()
        .any(|record| record.stage == life::Stage::Bootstrap));
    assert_eq!(snapshot.first_failure.unwrap().stage, life::Stage::Create);
    registry
        .close_with_deadline(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
}

#[tokio::test]
async fn construction_close_consumes_the_real_retained_constructor() {
    let _serial = super::super::super::TEST_LIFECYCLE.lock().await;
    let directory = tempfile::tempdir().unwrap();
    let mut registry = registry(directory.path());
    let (started_tx, started_rx) = oneshot::channel();
    registry.bootstrap_hook = Some(pending_hook(started_tx));
    let auth = direct_auth(directory.path());
    let proof = auth.verify_proof("direct", "pw").unwrap();
    let lease = auth.admit(&proof).await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut receiver = registry
        .selection_probe
        .install_construction_export(deadline)
        .unwrap();
    let selection = reach_bootstrap(&registry, &lease, &mut receiver, started_rx).await;
    let entry = entry(&registry).await;
    drop(selection);

    let before = entry.lifecycle.snapshot();
    assert!(!before.records.iter().any(
        |record| record.kind == life::Kind::Returned && record.stage == life::Stage::Bootstrap
    ));

    registry.close_with_deadline(deadline).await.unwrap();

    let snapshot = entry.lifecycle.snapshot();
    assert_eq!(
        returned(&snapshot, life::Stage::Bootstrap).outcome,
        life::Outcome::Cancelled
    );
    assert_eq!(
        returned(&snapshot, life::Stage::Worker).outcome,
        life::Outcome::Ok
    );
    assert_eq!(
        returned(&snapshot, life::Stage::Close).outcome,
        life::Outcome::Ok
    );
    assert_eq!(returned(&snapshot, life::Stage::Close).waiter, None);
    assert!(!snapshot
        .records
        .iter()
        .any(|record| record.kind == life::Kind::Returned && record.stage == life::Stage::Select));
    assert_eq!(
        snapshot.first_failure.unwrap().stage,
        life::Stage::Bootstrap
    );
    let state = entry.state.lock().await;
    assert!(state.constructing.is_none());
    assert!(state.tunnel.is_none());
    assert!(state.teardown.is_none());
}

#[tokio::test]
async fn construction_terminal_recovery_consumes_the_real_retained_constructor() {
    let _serial = super::super::super::TEST_LIFECYCLE.lock().await;
    let directory = tempfile::tempdir().unwrap();
    let mut registry = registry(directory.path());
    let (started_tx, started_rx) = oneshot::channel();
    registry.bootstrap_hook = Some(pending_hook(started_tx));
    let registry = Arc::new(registry);
    let auth = direct_auth(directory.path());
    let proof = auth.verify_proof("direct", "pw").unwrap();
    let lease = auth.admit(&proof).await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut receiver = registry
        .selection_probe
        .install_construction_export(deadline)
        .unwrap();
    let selection = reach_bootstrap(&registry, &lease, &mut receiver, started_rx).await;
    let entry = entry(&registry).await;
    drop(selection);
    registry.retain_for_shutdown().unwrap();

    OwnerRegistry::recover_retained_terminal().await.unwrap();

    let snapshot = entry.lifecycle.snapshot();
    assert_eq!(
        returned(&snapshot, life::Stage::Bootstrap).outcome,
        life::Outcome::Cancelled
    );
    assert_eq!(
        returned(&snapshot, life::Stage::Worker).outcome,
        life::Outcome::Ok
    );
    assert_eq!(
        returned(&snapshot, life::Stage::Recover).outcome,
        life::Outcome::Ok
    );
    assert_eq!(returned(&snapshot, life::Stage::Recover).waiter, None);
    assert!(!snapshot
        .records
        .iter()
        .any(|record| record.stage == life::Stage::Close));
    assert!(super::super::super::RETAINED.lock().unwrap().is_none());
    assert!(entry.state.lock().await.constructing.is_none());
}

#[tokio::test]
async fn construction_actual_bootstrap_deadline_retains_tunnel_and_returns_failure() {
    let _serial = super::super::super::TEST_LIFECYCLE.lock().await;
    let directory = tempfile::tempdir().unwrap();
    let mut registry = registry(directory.path());
    let (started_tx, started_rx) = oneshot::channel();
    registry.bootstrap_hook = Some(pending_hook(started_tx));
    let auth = direct_auth(directory.path());
    let proof = auth.verify_proof("direct", "pw").unwrap();
    let lease = auth.admit(&proof).await.unwrap();
    let mut receiver = registry
        .selection_probe
        .install_construction_export(Instant::now() + Duration::from_secs(5))
        .unwrap();
    let selection = reach_bootstrap(&registry, &lease, &mut receiver, started_rx).await;
    let entry = entry(&registry).await;

    tokio::time::pause();
    tokio::time::advance(super::super::super::SETUP_DEADLINE + Duration::from_secs(1)).await;
    tokio::time::resume();
    let error = match selection.await {
        Err(error) => error,
        Ok(_) => panic!("the original bootstrap deadline must remain a failure"),
    };
    assert_eq!(error.to_string(), "истёк срок запуска Tor владельца");
    assert!(error
        .downcast_ref::<super::super::super::ConstructorCancelled>()
        .is_none());

    let snapshot = entry.lifecycle.snapshot();
    assert_eq!(
        returned(&snapshot, life::Stage::Bootstrap).outcome,
        life::Outcome::Deadline
    );
    assert_eq!(
        returned(&snapshot, life::Stage::Worker).outcome,
        life::Outcome::Ok
    );
    assert_eq!(
        returned(&snapshot, life::Stage::Select).outcome,
        life::Outcome::Ok
    );
    assert_eq!(
        snapshot.first_failure.unwrap().outcome,
        life::Outcome::Deadline
    );
    {
        let state = entry.state.lock().await;
        assert!(state.failed);
        assert!(state.constructing.is_none());
        assert!(state.tunnel.is_some());
    }
    registry
        .close_with_deadline(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
}

#[tokio::test]
async fn construction_lifecycle_preserves_error_identity_and_zero_poll_cancellation() {
    #[derive(Debug)]
    struct PrivateError(Arc<()>);
    impl std::fmt::Display for PrivateError {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("credential-path-route-error-sentinel")
        }
    }
    impl std::error::Error for PrivateError {}

    let journal = life::Journal::default();
    journal.start(life::Context {
        probe: 1,
        entry: 2,
        initiator: Some(3),
    });
    let token = Arc::new(());
    let error = anyhow::Error::new(PrivateError(Arc::clone(&token)));
    let returned = journal
        .sync(life::Stage::Create, || Err::<(), _>(error))
        .unwrap_err();
    assert!(Arc::ptr_eq(
        &returned.downcast_ref::<PrivateError>().unwrap().0,
        &token
    ));

    let cancel = CancellationToken::new();
    let polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = Arc::clone(&polls);
    let work = std::future::poll_fn(move |_| {
        counted.fetch_add(1, Ordering::SeqCst);
        Poll::<Result<()>>::Pending
    });
    let mut wait = Box::pin(life::bootstrap(
        &journal,
        &cancel,
        Instant::now() + Duration::from_secs(120),
        work,
    ));
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    let waker = futures::task::noop_waker();
    let mut context = Context::from_waker(&waker);
    assert!(wait.as_mut().poll(&mut context).is_pending());
    assert_eq!(polls.load(Ordering::SeqCst), 1);
    drop(wait);
    assert_eq!(polls.load(Ordering::SeqCst), 1);
    let snapshot = journal.snapshot();
    assert_eq!(snapshot.first_failure.unwrap().stage, life::Stage::Create);
    assert!(snapshot.records.iter().any(|record| {
        record.stage == life::Stage::Bootstrap
            && record.kind == life::Kind::Abandoned
            && record.outcome == life::Outcome::Dropped
    }));
    for record in &snapshot.records {
        assert!(!life::render(record).contains("credential-path-route-error-sentinel"));
    }
}

#[test]
fn construction_lifecycle_saturation_reserves_terminal_and_first_failure_records() {
    let journal = life::Journal::default();
    journal.start(life::Context {
        probe: 4,
        entry: 5,
        initiator: Some(6),
    });
    for waiter in 0..100 {
        drop(journal.begin(life::Stage::Select, Some(waiter)));
    }
    let before = journal.snapshot();
    assert_eq!(before.records.len(), 2);
    assert!(before.suppression_reported);
    assert_eq!(before.suppressed, 198);

    journal
        .begin(life::Stage::Select, Some(101))
        .finish(life::Outcome::Error);
    let after = journal.snapshot();
    assert_eq!(
        returned(&after, life::Stage::Select).outcome,
        life::Outcome::Error
    );
    assert_eq!(returned(&after, life::Stage::Select).waiter, Some(101));
    let first = after.first_failure.unwrap();
    journal
        .begin(life::Stage::Select, Some(102))
        .finish(life::Outcome::JoinPanic);
    let final_snapshot = journal.snapshot();
    assert_eq!(final_snapshot.first_failure, Some(first));
    assert_eq!(
        returned(&final_snapshot, life::Stage::Select).outcome,
        life::Outcome::Error
    );
}

#[tokio::test]
async fn construction_actual_private_inputs_are_redacted_and_mapped_errors_are_preserved() {
    let _serial = super::super::super::TEST_LIFECYCLE.lock().await;

    for fail_storage in [true, false] {
        const USER: &str = "owner-private-user-sentinel";
        const PASSWORD: &str = "owner-private-password-sentinel";
        const PROXY_USER: &str = "owner-private-proxy-user-sentinel";
        const PROXY_PASSWORD: &str = "owner-private-proxy-password-sentinel";
        const ROUTE: &str = "127.0.0.2:19055";
        const PRIVATE_DIRECTORY: &str = "owner-private-state-path-sentinel";

        let directory = tempfile::tempdir().unwrap();
        let mut registry = registry(directory.path());
        let private_base = directory.path().join(PRIVATE_DIRECTORY);
        std::fs::create_dir(&private_base).unwrap();
        {
            let settings = registry.settings.as_mut().unwrap();
            settings.state_dir = Some(private_base.clone());
            settings.cache_dir = Some(private_base.join("owner-private-cache-sentinel"));
            if !fail_storage {
                settings.circuit_hops = 0;
            }
        }
        if fail_storage {
            std::fs::write(
                private_base.join("owners-v1"),
                b"owner-private-storage-content-sentinel",
            )
            .unwrap();
        }

        let endpoint = proxy_config::EndpointOverride::Endpoint(
            format!("{ROUTE}|{PROXY_USER}:{PROXY_PASSWORD}")
                .parse()
                .unwrap(),
        );
        let users = auth::UsersConfig {
            users: vec![auth::User {
                name: USER.into(),
                hash: auth::compute_hash(PASSWORD).unwrap(),
                is_enabled: true,
                allowed_onion: false,
                allowed_clients: None,
                pre_socks5: Some(endpoint),
                post_socks5: None,
            }],
        };
        let users_path = directory.path().join("owner-private-users-path-sentinel");
        users.save(&users_path).unwrap();
        let auth = Arc::new(auth::AuthState::build_persistent(&users, users_path).unwrap());
        let proof = auth.verify_proof(USER, PASSWORD).unwrap();
        let lease = auth.admit(&proof).await.unwrap();

        let first_error = match registry.select_admitted(&lease).await {
            Err(error) => error,
            Ok(_) => panic!("the actual owner failure must remain a failure"),
        };
        assert_eq!(
            first_error.to_string(),
            "конструктор Tor завершился ошибкой",
        );

        let entry = entry(&registry).await;
        let expected_pre = Socks5PreEndpoint::new(
            ROUTE.parse().unwrap(),
            Some((PROXY_USER.into(), PROXY_PASSWORD.into())),
        );
        assert!(entry.pre.as_ref() == Some(&expected_pre));

        let probe = Arc::clone(&registry.selection_probe);
        let (selection_records, selection_dropped) = probe.snapshot();
        assert_eq!(selection_dropped, 0);
        assert!(!selection_records.is_empty());
        assert!(selection_records.iter().any(|record| record.route == ROUTE));
        let initiator = selection_records[0].request_id;
        let identity = selection_records[0].identity;
        assert_eq!(identity, Some(Arc::as_ptr(&entry) as usize));

        let before_retry = entry.lifecycle.snapshot();
        let failed_stage = if fail_storage {
            life::Stage::Storage
        } else {
            life::Stage::Create
        };
        assert_eq!(
            returned(&before_retry, failed_stage).outcome,
            life::Outcome::Error,
        );
        assert_eq!(
            returned(&before_retry, life::Stage::Worker).outcome,
            life::Outcome::Error,
        );
        assert_eq!(
            returned(&before_retry, life::Stage::Select).outcome,
            life::Outcome::Error,
        );
        assert_eq!(before_retry.first_failure.unwrap().stage, failed_stage,);
        assert!(!before_retry
            .records
            .iter()
            .any(|record| { record.stage == life::Stage::Bootstrap }));
        if fail_storage {
            assert!(!before_retry.records.iter().any(|record| {
                matches!(record.stage, life::Stage::Export | life::Stage::Create)
            }));
        } else {
            assert_eq!(
                returned(&before_retry, life::Stage::Storage).outcome,
                life::Outcome::Ok,
            );
            assert_eq!(
                returned(&before_retry, life::Stage::Export).outcome,
                life::Outcome::Ok,
            );
        }

        let mut actual_output = String::new();
        for record in &before_retry.records {
            assert_eq!(record.context.initiator, Some(initiator));
            assert_eq!(Some(record.context.entry), identity);
            assert_eq!(record.context.probe, Arc::as_ptr(&probe) as usize,);
            actual_output.push_str(&life::render(record));
            actual_output.push('\n');
        }
        assert!(!actual_output.is_empty());
        assert!(actual_output.contains("owner_lifecycle"));
        assert!(actual_output.contains("outcome=Error"));

        let private_path = private_base.to_string_lossy().into_owned();
        for forbidden in [
            USER,
            PASSWORD,
            PROXY_USER,
            PROXY_PASSWORD,
            ROUTE,
            PRIVATE_DIRECTORY,
            private_path.as_str(),
            "owner-private-cache-sentinel",
            "owner-private-users-path-sentinel",
            "owner-private-storage-content-sentinel",
            "circuit_hops",
            "не удалось создать пространство владельцев",
            "не удалось создать Tor владельца",
            "конструктор Tor завершился ошибкой",
        ] {
            assert!(
                !actual_output.contains(forbidden),
                "actual lifecycle output disclosed a private input or error",
            );
        }

        {
            let state = entry.state.lock().await;
            assert!(state.failed);
            assert!(state.constructing.is_none());
            assert!(state.tunnel.is_none());
        }

        let repeated_error = match registry.select_admitted(&lease).await {
            Err(error) => error,
            Ok(_) => panic!("a failed entry must not restart construction"),
        };
        assert_eq!(
            repeated_error.to_string(),
            "конструктор Tor владельца завершился ошибкой",
        );
        let after_retry = entry.lifecycle.snapshot();
        assert_eq!(after_retry.records, before_retry.records);
        assert_eq!(after_retry.first_failure, before_retry.first_failure);
        assert_eq!(after_retry.suppressed, before_retry.suppressed);
        assert_eq!(
            after_retry.suppression_reported,
            before_retry.suppression_reported,
        );

        drop(lease);
        registry
            .close_with_deadline(Instant::now() + Duration::from_secs(5))
            .await
            .unwrap();
    }
}
