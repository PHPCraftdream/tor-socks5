/// Find the actual boundary record required by a regression.
fn record(trace: &diagnostics::Trace, stage: Stage) -> diagnostics::Record {
    trace
        .snapshot()
        .records
        .into_iter()
        .find(|record| record.stage == stage)
        .expect("actual managed boundary record")
}

/// Require that the common emission path accepted a record's exact rendering.
fn emitted_record(trace: &diagnostics::Trace, stage: Stage) -> diagnostics::Record {
    let actual = record(trace, stage);
    let line = diagnostics::render(&actual);
    assert!(
        trace
            .snapshot()
            .emitted
            .iter()
            .any(|emitted| emitted == &line)
    );
    actual
}

/// Check actual emitted lines without printing private sentinel values on failure.
fn private_output(trace: &diagnostics::Trace, forbidden: &[&str]) {
    let snapshot = trace.snapshot();
    assert!(!snapshot.emitted.is_empty());
    assert!(snapshot.emitted.len() <= 18);
    for line in &snapshot.emitted {
        for value in forbidden {
            assert!(
                !line.contains(value),
                "managed diagnostics disclosed private input"
            );
        }
    }
}

/// Create a transaction for explicitly exercising a completed-result branch.
fn completion_ticket<R: Runtime>(
    reactor: &mut PtReactor<R>,
    generation: Option<u64>,
) -> diagnostics::Ticket {
    reactor.diagnostic_ticket(None, generation, true)
}

/// Setup failure and unpolled abandonment must be observed by actual start ownership.
#[test]
fn diagnostic_setup_failure_and_unpolled_abandonment_use_actual_start() {
    tor_rtcompat::test_with_one_runtime!(|rt| async move {
        let (_tx, rx) = futures::channel::mpsc::unbounded();
        let mut reactor = real_reactor(rt, rx, PathBuf::from("private-state-sentinel"));
        let mut config = slot_config();
        config.path = CfgPath::new("/".to_owned());
        config.arguments = vec!["private-argument-sentinel".into()];
        reactor.start(
            PathBuf::from("private-key-sentinel"),
            config.clone(),
            None,
            73,
        );
        let trace = Arc::clone(&reactor.diagnostic_traces[0]);
        assert_eq!(trace.snapshot().emitted.len(), 1);
        assert_eq!(
            emitted_record(&trace, Stage::Queued).context.generation,
            Some(73)
        );
        assert!(!bounded_step(&mut reactor).await);
        assert!(reactor.slots.is_empty());
        assert!(reactor.tasks.is_empty());
        assert_eq!(
            emitted_record(&trace, Stage::Worker).outcome,
            Outcome::Begin
        );
        assert_eq!(
            emitted_record(&trace, Stage::SetupBegin).outcome,
            Outcome::Begin
        );
        assert_eq!(
            emitted_record(&trace, Stage::SetupEnd).outcome,
            Outcome::Error
        );
        assert_eq!(
            record(&trace, Stage::SetupEnd).facts.owner_present,
            Some(false)
        );
        assert_eq!(
            emitted_record(&trace, Stage::WorkerReturn).outcome,
            Outcome::Error
        );
        assert_eq!(
            emitted_record(&trace, Stage::Receipt).facts.slot_generation,
            Some(73)
        );
        assert_eq!(
            emitted_record(&trace, Stage::Apply).outcome,
            Outcome::Removed
        );
        assert!(
            !trace
                .snapshot()
                .records
                .iter()
                .any(|record| { record.stage == Stage::LaunchBegin })
        );
        private_output(
            &trace,
            &[
                "private-state-sentinel",
                "private-argument-sentinel",
                "private-key-sentinel",
            ],
        );

        reactor.start(PathBuf::from("private-second-key"), config, None, 74);
        let abandoned = Arc::clone(&reactor.diagnostic_traces[1]);
        assert_eq!(abandoned.snapshot().emitted.len(), 1);
        drop(reactor);
        assert_eq!(abandoned.snapshot().emitted.len(), 2);
        assert_eq!(
            emitted_record(&abandoned, Stage::Abandoned).outcome,
            Outcome::Dropped,
        );
        assert!(
            !abandoned
                .snapshot()
                .records
                .iter()
                .any(|record| { record.stage == Stage::Worker })
        );
    });
}

/// An actual launch failure must retain its original variant and cleanup ownership.
#[test]
fn diagnostic_launch_failure_preserves_error_variant_and_retained_cleanup() {
    tor_rtcompat::test_with_one_runtime!(|rt| async move {
        let state_dir = temp_state_dir("diagnostic-private-state");
        let missing = state_dir.join("private-executable-sentinel");
        let (_tx, rx) = futures::channel::mpsc::unbounded();
        let mut reactor = real_reactor(rt, rx, state_dir);
        let mut config = slot_config();
        config.path = CfgPath::new(missing.to_string_lossy().into_owned());
        config.arguments = vec!["private-argv-sentinel".into()];
        reactor.start(missing.clone(), config, None, 81);
        let trace = Arc::clone(&reactor.diagnostic_traces[0]);

        let (key, outcome, ticket) = tokio::time::timeout(STEP_DEADLINE, reactor.tasks.next())
            .await
            .expect("launch failure within existing step deadline")
            .expect("owned launch result");
        match &outcome {
            TaskOutcome::Started(Err(PtError::ChildSpawnFailed { path, .. }), retained) => {
                assert!(path == &missing);
                assert!(retained.is_some());
            }
            _ => panic!("original launch failure variant or retention changed"),
        }
        assert_eq!(emitted_record(&trace, Stage::SetupEnd).outcome, Outcome::Ok);
        assert_eq!(
            emitted_record(&trace, Stage::LaunchBegin).outcome,
            Outcome::Begin
        );
        assert_eq!(
            emitted_record(&trace, Stage::LaunchEnd).outcome,
            Outcome::Error
        );
        assert_eq!(
            emitted_record(&trace, Stage::WorkerReturn)
                .facts
                .owner_present,
            Some(true),
        );
        reactor.complete_task(key, outcome, ticket);
        assert_eq!(
            emitted_record(&trace, Stage::Receipt).outcome,
            Outcome::Error
        );
        assert_eq!(
            emitted_record(&trace, Stage::Apply).outcome,
            Outcome::Retained
        );
        assert!(matches!(reactor.slots[0].phase, Phase::Cleaning));
        assert_eq!(reactor.tasks.len(), 1);
        assert!(!bounded_step(&mut reactor).await);
        assert!(reactor.slots.is_empty());
        let cleanup = Arc::clone(&reactor.diagnostic_traces[1]);
        assert!(cleanup.context().cleanup);
        assert_eq!(cleanup.context().generation, Some(81));
        assert_eq!(cleanup.context().slot, trace.context().slot);
        assert_eq!(emitted_record(&cleanup, Stage::Signal).outcome, Outcome::Ok);
        assert_eq!(
            emitted_record(&cleanup, Stage::WorkerReturn).outcome,
            Outcome::Ok
        );
        assert_eq!(
            emitted_record(&cleanup, Stage::Apply).outcome,
            Outcome::Removed
        );
        let private_path = missing.to_string_lossy().into_owned();
        private_output(
            &trace,
            &[
                "private-executable-sentinel",
                "private-argv-sentinel",
                private_path.as_str(),
            ],
        );
    });
}

/// A real completed launch must not publish after the current generation changes.
#[test]
fn diagnostic_actual_generation_validation_rejects_completed_stale_launch() {
    tor_rtcompat::test_with_one_runtime!(|rt| async move {
        let state_dir = temp_state_dir("diagnostic-stale");
        let (_tx, rx) = futures::channel::mpsc::unbounded();
        let state = Arc::new(RwLock::new(PtSharedState::default()));
        let mut reactor = real_reactor_with_state(rt, rx, state_dir, Arc::clone(&state));
        let name: PtTransportName = "obfs4".parse().expect("test transport");
        let config = ManagedTransportOptions {
            protocols: vec![name.clone()],
            path: CfgPath::new("/bin/sh".into()),
            arguments: vec![
                "-c".into(),
                "echo 'VERSION 1'; echo 'CMETHOD obfs4 socks5 127.0.0.1:12345'; \
                 echo 'CMETHODS DONE'; while read line; do :; done"
                    .into(),
            ],
            run_on_startup: false,
        };
        {
            let mut shared = state.write().expect("test shared state");
            shared.generation = 91;
            shared
                .configured
                .insert(name.clone(), TransportOptions::Managed(config.clone()));
        }
        let (sender, receiver) = oneshot::channel();
        reactor.requests.insert(name, vec![sender]);
        reactor.start(PathBuf::from("/bin/sh"), config, None, 91);
        let trace = Arc::clone(&reactor.diagnostic_traces[0]);
        let (key, outcome, ticket) = tokio::time::timeout(STEP_DEADLINE, reactor.tasks.next())
            .await
            .expect("launch within existing step deadline")
            .expect("owned launch result");
        assert!(matches!(&outcome, TaskOutcome::Started(Ok(_), _)));
        assert!(
            state
                .read()
                .expect("test shared state")
                .managed_cmethods
                .is_empty()
        );
        state.write().expect("test shared state").generation = 92;

        reactor.complete_task(key, outcome, ticket);

        let validation = emitted_record(&trace, Stage::Validation);
        assert_eq!(validation.context.generation, Some(91));
        assert_eq!(validation.facts.slot_generation, Some(91));
        assert_eq!(validation.facts.state_generation, Some(92));
        assert_eq!(validation.outcome, Outcome::Rejected);
        assert!(
            !trace
                .snapshot()
                .records
                .iter()
                .any(|record| { record.stage == Stage::Publication })
        );
        assert!(
            state
                .read()
                .expect("test shared state")
                .managed_cmethods
                .is_empty()
        );
        assert!(matches!(
            receiver.await.expect("original waiter result"),
            Err(PtError::UnconfiguredTransportDueToConcurrentReconfiguration)
        ));
        assert!(matches!(reactor.slots[0].phase, Phase::Cleaning));
        assert!(!bounded_step(&mut reactor).await);
        assert!(reactor.slots.is_empty());
    });
}

/// Successful and failed cleanup without a slot have different actual dispositions.
#[test]
fn diagnostic_no_slot_cleanup_reports_discard_versus_orphan_retention() {
    tor_rtcompat::test_with_one_runtime!(|rt| async move {
        let (_tx, rx) = futures::channel::mpsc::unbounded();
        let mut reactor = real_reactor(rt, rx, PathBuf::from("private-orphan-state"));

        reactor.clean(PathBuf::from("private-success-key"), dummy_pt());
        let success = Arc::clone(&reactor.diagnostic_traces[0]);
        assert!(!bounded_step(&mut reactor).await);
        assert!(reactor.slots.is_empty());
        assert!(reactor.orphans.is_empty());
        assert_eq!(
            emitted_record(&success, Stage::Receipt).facts.owner_present,
            Some(true),
        );
        let applied = emitted_record(&success, Stage::Apply);
        assert_eq!(applied.outcome, Outcome::Removed);
        assert_eq!(applied.facts.owner_present, Some(false));

        let source = Arc::new(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "private-error-sentinel",
        ));
        let error = PtError::ChildReadFailed(Arc::clone(&source));
        let mut pt = dummy_pt();
        pt.binary_path = PathBuf::from("private-config-path-sentinel");
        let ticket = completion_ticket(&mut reactor, None);
        let failure = Arc::clone(&ticket.trace);
        reactor.complete_task(
            PathBuf::from("private-error-key"),
            TaskOutcome::Cleaned(Err(error), pt),
            ticket,
        );
        assert_eq!(reactor.orphans.len(), 1);
        assert_eq!(reactor.orphans[0].attempts, MAX_CLEANUP_ATTEMPTS,);
        assert_eq!(
            emitted_record(&failure, Stage::Receipt).facts.owner_present,
            Some(true),
        );
        let applied = emitted_record(&failure, Stage::Apply);
        assert_eq!(applied.outcome, Outcome::Retained);
        assert_eq!(applied.facts.owner_present, Some(true));
        assert_eq!(Arc::strong_count(&source), 1);
        private_output(
            &failure,
            &[
                "private-error-sentinel",
                "private-config-path-sentinel",
                "private-error-key",
            ],
        );
    });
}

/// Actual cleanup application must expose acceptance and rejection of pending generations.
#[test]
fn diagnostic_pending_cleanup_generation_decision_is_emitted() {
    tor_rtcompat::test_with_one_runtime!(|rt| async move {
        for accepted in [true, false] {
            let (_tx, rx) = futures::channel::mpsc::unbounded();
            let state = Arc::new(RwLock::new(PtSharedState::default()));
            let mut reactor = real_reactor_with_state(
                rt.clone(),
                rx,
                PathBuf::from("private-pending-state"),
                Arc::clone(&state),
            );
            let name: PtTransportName = "private_transport_sentinel"
                .parse()
                .expect("test transport name");
            let mut pending = slot_config();
            pending.path = CfgPath::new("/".into());
            pending.protocols = vec![name.clone()];
            pending.arguments = vec!["private-pending-argument".into()];
            {
                let mut shared = state.write().expect("test shared state");
                shared.generation = if accepted { 12 } else { 13 };
                shared
                    .configured
                    .insert(name.clone(), TransportOptions::Managed(pending.clone()));
            }
            let key = PathBuf::from("private-pending-key");
            let mut slot = running_slot();
            slot.key = key.clone();
            slot.generation = 11;
            slot.pending = Some((pending, None, 12));
            let pt = match std::mem::replace(&mut slot.phase, Phase::Cleaning) {
                Phase::Running(pt) => pt,
                _ => panic!("pending cleanup fixture must begin with one running owner"),
            };
            reactor.slots.push(slot);
            let (sender, receiver) = oneshot::channel();
            reactor.requests.insert(name, vec![sender]);

            reactor.clean(key, pt);
            let cleanup = Arc::clone(&reactor.diagnostic_traces[0]);
            assert!(!bounded_step(&mut reactor).await);

            let decision = emitted_record(&cleanup, Stage::Pending);
            assert_eq!(decision.context.generation, Some(11));
            assert_eq!(decision.facts.slot_generation, Some(11));
            assert_eq!(decision.facts.pending_generation, Some(12));
            assert_eq!(
                decision.facts.state_generation,
                Some(if accepted { 12 } else { 13 }),
            );
            assert_eq!(
                decision.outcome,
                if accepted {
                    Outcome::Ok
                } else {
                    Outcome::Rejected
                },
            );
            assert!(
                state
                    .read()
                    .expect("test shared state")
                    .managed_cmethods
                    .is_empty()
            );
            if accepted {
                assert_eq!(reactor.slots.len(), 1);
                assert_eq!(reactor.slots[0].generation, 12);
                assert!(matches!(reactor.slots[0].phase, Phase::Starting(_)));
                assert_eq!(reactor.tasks.len(), 1);
            } else {
                assert!(reactor.slots.is_empty());
                assert!(reactor.tasks.is_empty());
                assert!(matches!(
                    receiver.await.expect("original rejection result"),
                    Err(PtError::UnconfiguredTransportDueToConcurrentReconfiguration)
                ));
            }
            private_output(
                &cleanup,
                &[
                    "private-pending-state",
                    "private-pending-key",
                    "private-pending-argument",
                    "private_transport_sentinel",
                ],
            );
        }
    });
}

/// The actual running-message path must emit before its existing cleanup transition.
#[test]
fn diagnostic_running_message_failure_uses_actual_reactor_event() {
    tor_rtcompat::test_with_one_runtime!(|rt| async move {
        let (_tx, rx) = futures::channel::mpsc::unbounded();
        let mut reactor = real_reactor(rt, rx, PathBuf::from("private-message-state"));
        let mut slot = running_slot();
        slot.generation = 31;
        slot.key = PathBuf::from("private-message-key");
        reactor.slots.push(slot);

        assert!(!bounded_step(&mut reactor).await);

        let message = Arc::clone(&reactor.diagnostic_traces[0]);
        assert_eq!(message.context().generation, Some(31));
        assert_eq!(
            emitted_record(&message, Stage::Message).outcome,
            Outcome::Error
        );
        assert_eq!(
            emitted_record(&message, Stage::Apply).outcome,
            Outcome::Retained
        );
        assert!(matches!(reactor.slots[0].phase, Phase::Cleaning));
        assert_eq!(reactor.tasks.len(), 1);
        let cleanup = Arc::clone(&reactor.diagnostic_traces[1]);
        assert_eq!(cleanup.context().slot, message.context().slot);
        assert_eq!(cleanup.context().generation, Some(31));
        assert!(!bounded_step(&mut reactor).await);
        assert!(reactor.slots.is_empty());
        assert_eq!(
            emitted_record(&cleanup, Stage::Apply).outcome,
            Outcome::Removed
        );
        private_output(&message, &["private-message-state", "private-message-key"]);
    });
}

/// Common emitted-output policy must retain a first failure and terminal after saturation.
#[test]
fn diagnostic_emitted_bounds_reserve_first_failure_and_terminal() {
    let mut ticket = diagnostics::Ticket::new(diagnostics::Context {
        manager: diagnostics::id(),
        transaction: diagnostics::id(),
        slot: diagnostics::id(),
        generation: Some(101),
        cleanup: false,
    });
    for _ in 0..100 {
        ticket
            .trace
            .event(Stage::Worker, Outcome::Begin, Facts::default());
    }
    let before = ticket.trace.snapshot();
    assert_eq!(before.records.len(), 2);
    assert_eq!(before.suppressed, 99);
    assert_eq!(before.emitted.len(), 3);
    assert_eq!(
        before
            .emitted
            .iter()
            .filter(|line| { line.contains("suppression=at_least_one_duplicate") })
            .count(),
        1,
    );

    ticket
        .trace
        .event(Stage::Worker, Outcome::Error, Facts::default());
    let failed = ticket.trace.snapshot();
    let first = failed.first_failure.expect("reserved first failure");
    assert_eq!(first.outcome, Outcome::Error);
    assert_eq!(failed.emitted.len(), 4);
    assert!(failed.emitted[3].contains("reserved_first_failure=true"));
    assert!(failed.emitted[3].contains("outcome=Error"));

    ticket.finish(
        Outcome::Removed,
        Facts {
            owner_present: Some(false),
            ..Facts::default()
        },
    );
    let after = ticket.trace.snapshot();
    assert_eq!(
        emitted_record(&ticket.trace, Stage::Apply).outcome,
        Outcome::Removed
    );
    assert_eq!(after.first_failure, Some(first));
    assert_eq!(after.emitted.len(), 5);

    for stage in [
        Stage::SetupBegin,
        Stage::SetupEnd,
        Stage::LaunchBegin,
        Stage::LaunchEnd,
        Stage::Signal,
        Stage::WorkerReturn,
        Stage::Receipt,
        Stage::Validation,
        Stage::Publication,
        Stage::Pending,
        Stage::Abandoned,
        Stage::Message,
        Stage::Reserved,
    ] {
        ticket.trace.event(stage, Outcome::Ok, Facts::default());
    }
    for _ in 0..100 {
        ticket
            .trace
            .event(Stage::Worker, Outcome::Cancelled, Facts::default());
    }
    assert_eq!(ticket.trace.snapshot().emitted.len(), 18);
    assert_eq!(ticket.trace.snapshot().first_failure, Some(first));
}
/// Capture formatter output without writing to a process output stream.
#[derive(Clone, Default)]
struct DiagnosticBuffer {
    /// Bytes accepted by the formatting subscriber's writer.
    bytes: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
}

impl std::io::Write for DiagnosticBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let mut captured = self.bytes.lock().expect("diagnostic test buffer lock");
        captured.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for DiagnosticBuffer {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }

    fn make_writer_for(&'a self, metadata: &tracing::Metadata<'_>) -> Self::Writer {
        if metadata.target() == "tor_ptmgr::managed_diagnostics" {
            assert_eq!(
                metadata.callsite(),
                tracing::callsite::Identifier(diagnostics::emission_callsite()),
                "formatted diagnostics must use the callsite whose stale interest is injected",
            );
        }
        self.clone()
    }
}

impl DiagnosticBuffer {
    /// Read captured formatter bytes as UTF-8 without consuming them.
    fn text(&self) -> String {
        String::from_utf8(
            self.bytes
                .lock()
                .expect("diagnostic test buffer lock")
                .clone(),
        )
        .expect("diagnostic formatter output is UTF-8")
    }
}

/// Exercise real formatting and stale-interest states only in an exact test process.
#[test]
#[ignore = "Executed by the exact-process backend regression"]
fn diagnostic_tracing_backend_process_fixture() {
    let buffer = DiagnosticBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .without_time()
        .with_ansi(false)
        .with_writer(buffer.clone())
        .finish();

    tracing::subscriber::with_default(subscriber, || {
        let parent = tracing::info_span!("private_parent", private_field = "parent-only-sentinel");
        assert!(!parent.is_disabled());
        let _entered = parent.enter();

        tracing::info!("parent_capture_control");
        let callsite = diagnostics::emission_callsite();
        tracing::callsite::Callsite::set_interest(callsite, tracing::subscriber::Interest::never());
        assert!(callsite.interest().is_never());
        diagnostic_emitted_bounds_reserve_first_failure_and_terminal();
    });

    let output = buffer.text();
    let lines: Vec<_> = output.lines().collect();
    assert_eq!(lines.len(), 19);

    let controls: Vec<_> = lines
        .iter()
        .filter(|line| line.contains("parent_capture_control"))
        .collect();
    assert_eq!(controls.len(), 1);
    assert!(controls[0].contains("private_parent"));
    assert!(controls[0].contains("private_field"));
    assert!(controls[0].contains("parent-only-sentinel"));

    let managed: Vec<_> = lines
        .iter()
        .filter(|line| line.contains("tor_ptmgr::managed_diagnostics"))
        .collect();
    assert_eq!(managed.len(), 18);
    for line in &managed {
        assert!(line.contains("managed_pt "));
        assert!(
            !line.contains("parent-only-sentinel"),
            "managed diagnostics inherited a private parent-span value"
        );
        assert!(
            !line.contains("private_parent"),
            "managed diagnostics inherited a parent span"
        );
        assert!(
            !line.contains("private_field"),
            "managed diagnostics inherited a parent-span field"
        );
    }
    assert!(lines.iter().all(|line| {
        line.contains("parent_capture_control") || line.contains("tor_ptmgr::managed_diagnostics")
    }));
    assert_eq!(
        managed
            .iter()
            .filter(|line| line.contains("suppression=at_least_one_duplicate"))
            .count(),
        1,
    );
    assert_eq!(
        managed
            .iter()
            .filter(|line| line.contains("reserved_first_failure=true"))
            .count(),
        1,
    );
    assert_eq!(
        managed
            .iter()
            .filter(|line| {
                line.contains("stage=Worker")
                    && line.contains("outcome=Error")
                    && line.contains("reserved_first_failure=true")
            })
            .count(),
        1,
    );
    assert_eq!(
        managed
            .iter()
            .filter(|line| line.contains("stage=Apply"))
            .count(),
        1,
    );
    assert_eq!(
        managed
            .iter()
            .filter(|line| {
                line.contains("stage=Apply")
                    && line.contains("outcome=Removed")
                    && line.contains("owner_present=Some(false)")
            })
            .count(),
        1,
    );

    let off_buffer = DiagnosticBuffer::default();
    let off_subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::level_filters::LevelFilter::OFF)
        .without_time()
        .with_ansi(false)
        .with_writer(off_buffer.clone())
        .finish();

    tracing::subscriber::with_default(off_subscriber, || {
        let callsite = diagnostics::emission_callsite();
        tracing::callsite::Callsite::set_interest(
            callsite,
            tracing::subscriber::Interest::always(),
        );
        assert!(callsite.interest().is_always());
        diagnostic_emitted_bounds_reserve_first_failure_and_terminal();
    });
    assert!(off_buffer.text().is_empty());
}

/// Run every backend assertion once in a process isolated from other callsite rebuilds.
#[test]
fn diagnostic_tracing_backend_is_bounded_filtered_and_parentless() {
    let (_, module) = module_path!()
        .split_once("::")
        .expect("test module includes its crate prefix");
    let fixture = format!("{module}::diagnostic_tracing_backend_process_fixture");
    let output = std::process::Command::new(
        std::env::current_exe().expect("current managed test executable"),
    )
    .arg("--exact")
    .arg(&fixture)
    .arg("--ignored")
    .arg("--nocapture")
    .arg("--color=never")
    .output()
    .expect("isolated diagnostic backend fixture completes");
    assert!(output.status.success(), "diagnostic backend fixture failed");

    let stdout = String::from_utf8(output.stdout).expect("test harness stdout is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("diagnostic stderr is UTF-8");
    assert!(stdout.contains("running 1 test"));
    assert!(stdout.contains(&fixture));
    assert!(stdout.contains("1 passed; 0 failed; 0 ignored"));
    assert!(
        !stdout.contains("managed_pt "),
        "managed diagnostics bypassed the formatting subscriber through stdout"
    );
    assert!(
        stderr.is_empty(),
        "managed diagnostics bypassed the formatting subscriber through stderr"
    );
}

/// Exercise the bounded policy in an isolated test process with tracing disabled.
#[test]
fn diagnostic_tracing_off_process_fixture() {
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::level_filters::LevelFilter::OFF)
        .without_time()
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        diagnostic_emitted_bounds_reserve_first_failure_and_terminal();
    });
}

/// Detect direct process-output writes alongside an otherwise-correct tracing backend.
#[test]
fn diagnostic_tracing_off_rejects_out_of_band_process_output() {
    let (_, module) = module_path!()
        .split_once("::")
        .expect("test module includes its crate prefix");
    let fixture = format!("{module}::diagnostic_tracing_off_process_fixture");
    let output = std::process::Command::new(
        std::env::current_exe().expect("current managed test executable"),
    )
    .arg("--exact")
    .arg(&fixture)
    .arg("--nocapture")
    .arg("--color=never")
    .output()
    .expect("isolated diagnostic filter fixture completes");
    assert!(output.status.success(), "diagnostic filter fixture failed");
    let stdout = String::from_utf8(output.stdout).expect("test harness stdout is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("diagnostic stderr is UTF-8");
    assert!(stdout.contains("running 1 test"));
    assert!(stdout.contains(&fixture));
    assert!(stdout.contains("1 passed; 0 failed; 0 ignored"));
    assert!(
        !stdout.contains("managed_pt "),
        "managed diagnostics bypassed the subscriber through stdout"
    );
    assert!(
        stderr.is_empty(),
        "managed diagnostics bypassed the disabled subscriber through stderr"
    );
}
