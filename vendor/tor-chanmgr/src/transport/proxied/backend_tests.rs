//! Real connector dispatch and bounded-terminal regressions.

use super::*;

/// Dedicated production event target.
const TARGET: &str = "tor_chanmgr::pt_connector_diagnostics";

/// Subscriber behaviour selected entirely within the test.
#[derive(Clone, Copy)]
enum Mode {
    /// Accept connector events and the private parent control.
    Enabled,
    /// Reject events at the metadata filter.
    Off,
    /// Accept metadata but reject connector events at the event filter.
    RejectEvents,
}

/// Actual private span fields recorded by the subscriber.
#[derive(Default)]
struct ParentFields {
    /// Rendered fields supplied by the enabled span.
    text: String,
}

impl tracing::field::Visit for ParentFields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        self.text.push_str(&format!(" {}={value:?}", field.name()));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.text.push_str(&format!(" {}={value}", field.name()));
    }
}

/// Subscriber state independently retained by assertions.
#[derive(Clone, Default)]
struct DispatchState {
    /// Actual fields recorded when the private parent span was created.
    parent: Arc<Mutex<ParentFields>>,
    /// Whether that span is presently entered.
    entered: Arc<AtomicBool>,
    /// Metadata-filter calls for connector events.
    enabled_calls: Arc<AtomicUsize>,
    /// Event-filter calls for connector events.
    event_calls: Arc<AtomicUsize>,
    /// Connector events actually delivered to the subscriber.
    delivered: Arc<AtomicUsize>,
    /// Contextual control events actually delivered.
    controls: Arc<AtomicUsize>,
    /// Rendered control output containing available parent context.
    control_output: Arc<Mutex<Vec<String>>>,
}

/// Scoped subscriber that checks real ancestry, filtering, and callsite identity.
struct BackendCapture {
    /// Selected metadata and event filtering behaviour.
    mode: Mode,
    /// Existing stream lifecycle and delivered-message witnesses.
    tracker: Tracker,
    /// Parent-context and dispatch witnesses.
    state: DispatchState,
}

impl tracing::Subscriber for BackendCapture {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        if metadata.target() == TARGET {
            self.state.enabled_calls.fetch_add(1, Ordering::SeqCst);
            return !matches!(self.mode, Mode::Off);
        }
        matches!(self.mode, Mode::Enabled) && metadata.target() == "connector_backend_control"
    }

    fn new_span(&self, attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        let mut parent = self.state.parent.lock().expect("parent fields");
        attrs.record(&mut *parent);
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, values: &tracing::span::Record<'_>) {
        let mut parent = self.state.parent.lock().expect("parent fields");
        values.record(&mut *parent);
    }

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event_enabled(&self, event: &tracing::Event<'_>) -> bool {
        if event.metadata().target() == TARGET {
            self.state.event_calls.fetch_add(1, Ordering::SeqCst);
            return !matches!(self.mode, Mode::RejectEvents);
        }
        matches!(self.mode, Mode::Enabled)
    }

    fn event(&self, event: &tracing::Event<'_>) {
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        let message = visitor.message.expect("event message");

        if event.metadata().target() == "connector_backend_control" {
            assert!(event.is_contextual());
            assert!(self.state.entered.load(Ordering::SeqCst));
            let parent = self.state.parent.lock().expect("parent fields");
            self.state
                .control_output
                .lock()
                .expect("control output")
                .push(format!("{message}{}", parent.text));
            self.state.controls.fetch_add(1, Ordering::SeqCst);
            return;
        }

        assert_eq!(event.metadata().target(), TARGET);
        assert!(
            event.metadata().callsite()
                == tracing::callsite::Identifier(diagnostics::emission_callsite()),
            "injected callsite differs from the emitting callsite"
        );
        assert!(event.is_root(), "connector event inherited parent ancestry");
        assert!(
            !message.contains("private_parent_sentinel"),
            "connector message disclosed a private parent value"
        );
        assert!(
            !message.contains("private_field"),
            "connector message disclosed a private parent field"
        );
        self.state.delivered.fetch_add(1, Ordering::SeqCst);
        if message.contains("terminal=true") {
            self.tracker.terminal.store(true, Ordering::SeqCst);
        }
        self.tracker
            .messages
            .lock()
            .expect("connector output")
            .push(message);
    }

    fn enter(&self, _span: &tracing::span::Id) {
        self.state.entered.store(true, Ordering::SeqCst);
    }

    fn exit(&self, _span: &tracing::span::Id) {
        self.state.entered.store(false, Ordering::SeqCst);
    }
}

/// Exercise the actual fragmented handshake without substituting its result.
fn real_success(tracker: &Tracker) {
    let response = [5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    let request = target();
    let result = block_on(do_socks_handshake(
        ScriptedStream::new(&response, false, None, tracker.clone()),
        &SocksVersion::V5,
        &SocksAuth::NoAuth,
        &request,
        Some(Attempt::new()),
    ));
    let stream = match result {
        Ok(stream) => stream,
        Err(_) => panic!("filtered scripted handshake must retain success"),
    };
    assert_eq!(tracker.reads.load(Ordering::SeqCst), response.len());
    assert_eq!(tracker.drops.load(Ordering::SeqCst), 0);
    drop(stream);
    assert_eq!(tracker.drops.load(Ordering::SeqCst), 1);
}

/// Exercise the original read error while retaining its payload identity.
fn real_failure(tracker: &Tracker) {
    let token = Arc::new(AtomicUsize::new(0));
    let error = io::Error::new(
        io::ErrorKind::BrokenPipe,
        Marker {
            token: Arc::clone(&token),
        },
    );
    let request = target();
    let result = block_on(do_socks_handshake(
        ScriptedStream::new(&[], false, Some(error), tracker.clone()),
        &SocksVersion::V5,
        &SocksAuth::NoAuth,
        &request,
        Some(Attempt::new()),
    ));
    let error = match result {
        Err(ProxyError::ProxyIo(error)) => error,
        _ => panic!("filtering must preserve the original ProxyIo result"),
    };
    let marker = error
        .get_ref()
        .and_then(|payload| payload.downcast_ref::<Marker>())
        .expect("original read payload");
    assert!(Arc::ptr_eq(&marker.token, &token));
    assert_eq!(token.load(Ordering::SeqCst), 0);
    assert_eq!(tracker.reads.load(Ordering::SeqCst), 1);
    assert_eq!(tracker.drops.load(Ordering::SeqCst), 1);
    drop(error);
    assert_eq!(token.load(Ordering::SeqCst), 1);
}

/// Exercise every reserved stage through the production emission policy.
fn saturated_attempt(tracker: &Tracker) {
    let stages = [
        Stage::Prepare,
        Stage::Dial,
        Stage::Negotiate,
        Stage::Send,
        Stage::Flush,
        Stage::Receive,
        Stage::Decode,
        Stage::Status,
        Stage::Returned,
    ];
    let mut attempt = Attempt::new();
    for _ in 0..32 {
        for stage in stages {
            attempt.begin(stage);
            attempt.ok(stage);
        }
    }
    assert_eq!(tracker.messages.lock().expect("connector output").len(), 18,);

    attempt.finish(Outcome::Rejected);
    attempt.finish(Outcome::IoError);
    attempt.begin(Stage::Dial);
    attempt.ok(Stage::Dial);
    drop(attempt);

    let messages = tracker.messages.lock().expect("connector output");
    assert_eq!(messages.len(), 19);
    for stage in [
        "Prepare",
        "Dial",
        "Negotiate",
        "Send",
        "Flush",
        "Receive",
        "Decode",
        "Status",
        "Returned",
    ] {
        for outcome in ["Begin", "Ok"] {
            let boundary = format!("stage={stage} outcome={outcome} terminal=false");
            assert_eq!(
                messages
                    .iter()
                    .filter(|message| message.contains(&boundary))
                    .count(),
                1,
            );
        }
    }
    assert_eq!(
        messages
            .iter()
            .filter(|message| message.contains("terminal=true"))
            .count(),
        1,
    );
    let terminal = messages.last().expect("reserved terminal");
    assert!(terminal.contains("sequence=18 "));
    assert!(terminal.contains("stage=Returned outcome=Rejected terminal=true"));
    assert!(!terminal.contains("Abandoned"));
}

/// Run one isolated enabled handshake while proving actual parent context is available.
fn enabled_private_parent_case() {
    let tracker = Tracker::default();
    let state = DispatchState::default();
    tracing::subscriber::with_default(
        BackendCapture {
            mode: Mode::Enabled,
            tracker: tracker.clone(),
            state: state.clone(),
        },
        || {
            let parent = tracing::info_span!(
                target: "connector_backend_control",
                "private_parent",
                private_field = "private_parent_sentinel"
            );
            assert!(!parent.is_disabled());
            let _entered = parent.enter();
            tracing::info!(
                target: "connector_backend_control",
                "parent_capture_control"
            );

            let callsite = diagnostics::emission_callsite();
            tracing::callsite::Callsite::set_interest(
                callsite,
                tracing::subscriber::Interest::never(),
            );
            assert!(callsite.interest().is_never());
            real_success(&tracker);
        },
    );

    assert_eq!(state.controls.load(Ordering::SeqCst), 1);
    let controls = state.control_output.lock().expect("control output");
    assert_eq!(controls.len(), 1);
    assert!(controls[0].contains("parent_capture_control"));
    assert!(controls[0].contains("private_field"));
    assert!(controls[0].contains("private_parent_sentinel"));
    drop(controls);

    assert_eq!(state.delivered.load(Ordering::SeqCst), 15);
    assert_eq!(tracker.messages.lock().expect("connector output").len(), 15);
    assert!(tracker.ordered_drop.load(Ordering::SeqCst));
    assert_terminal(&tracker, "outcome=Ok");
}

/// Run real operations under OFF or event-level rejection with a stale interested cache.
fn rejected_case(mode: Mode) {
    for failure in [false, true] {
        let tracker = Tracker::default();
        let state = DispatchState::default();
        tracing::subscriber::with_default(
            BackendCapture {
                mode,
                tracker: tracker.clone(),
                state: state.clone(),
            },
            || {
                let callsite = diagnostics::emission_callsite();
                tracing::callsite::Callsite::set_interest(
                    callsite,
                    tracing::subscriber::Interest::always(),
                );
                assert!(callsite.interest().is_always());
                state.enabled_calls.store(0, Ordering::SeqCst);
                state.event_calls.store(0, Ordering::SeqCst);
                if failure {
                    real_failure(&tracker);
                } else {
                    real_success(&tracker);
                }
            },
        );
        assert!(state.enabled_calls.load(Ordering::SeqCst) > 0);
        if matches!(mode, Mode::RejectEvents) {
            assert!(state.event_calls.load(Ordering::SeqCst) > 0);
        } else {
            assert_eq!(state.event_calls.load(Ordering::SeqCst), 0);
        }
        assert_eq!(state.delivered.load(Ordering::SeqCst), 0);
        assert!(
            tracker
                .messages
                .lock()
                .expect("connector output")
                .is_empty()
        );
    }
}

/// Isolate deliberate global callsite-cache mutations from parallel library tests.
#[test]
#[ignore = "Executed by the exact-process connector backend regression"]
fn connector_backend_process_fixture() {
    enabled_private_parent_case();

    let tracker = Tracker::default();
    let state = DispatchState::default();
    tracing::subscriber::with_default(
        BackendCapture {
            mode: Mode::Enabled,
            tracker: tracker.clone(),
            state: state.clone(),
        },
        || saturated_attempt(&tracker),
    );
    assert_eq!(state.delivered.load(Ordering::SeqCst), 19);

    let tracker = Tracker::default();
    let state = DispatchState::default();
    tracing::subscriber::with_default(
        BackendCapture {
            mode: Mode::Enabled,
            tracker: tracker.clone(),
            state,
        },
        || real_failure(&tracker),
    );
    assert!(tracker.ordered_drop.load(Ordering::SeqCst));
    assert_terminal(&tracker, "outcome=IoError");

    rejected_case(Mode::Off);
    rejected_case(Mode::RejectEvents);
}

/// Require one real fixture execution and reject additive process-output bypass.
#[test]
fn connector_backend_privacy_filters_and_reserved_terminal() {
    let (_, module) = module_path!()
        .split_once("::")
        .expect("test module includes crate prefix");
    let fixture = format!("{module}::connector_backend_process_fixture");
    let output = std::process::Command::new(
        std::env::current_exe().expect("current connector test executable"),
    )
    .arg("--exact")
    .arg(&fixture)
    .arg("--ignored")
    .arg("--nocapture")
    .arg("--color=never")
    .output()
    .expect("isolated connector backend fixture completes");
    assert!(output.status.success(), "connector backend fixture failed");
    let stdout = String::from_utf8(output.stdout).expect("test stdout is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("test stderr is UTF-8");
    assert!(stdout.contains("running 1 test"));
    assert!(stdout.contains(&fixture));
    assert!(stdout.contains("1 passed; 0 failed; 0 ignored"));
    assert!(
        !stdout.contains("pt_connector "),
        "connector diagnostics bypassed the subscriber through stdout"
    );
    assert!(
        stderr.is_empty(),
        "connector diagnostics bypassed the subscriber through stderr"
    );
}
