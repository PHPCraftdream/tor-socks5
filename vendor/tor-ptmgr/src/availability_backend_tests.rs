//! Actual availability consumer delivery through the existing formatting stack.

use super::*;

/// Subscriber behaviour under test.
#[derive(Clone, Copy)]
enum Mode {
    /// Accept the availability event.
    Enabled,
    /// Reject metadata but permit any event that incorrectly reaches delivery.
    Off,
    /// Accept metadata but reject event delivery.
    RejectEvents,
}

/// Actual filter invocations after registration and cache injection.
#[derive(Clone, Default)]
struct Counts {
    /// Availability metadata checks.
    enabled: Arc<AtomicUsize>,
    /// Availability event checks.
    events: Arc<AtomicUsize>,
}

/// Formatting output with an emitting-callsite identity assertion.
#[derive(Clone, Default)]
struct Buffer {
    /// Bytes accepted by the real formatting subscriber.
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl std::io::Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes
            .lock()
            .expect("format buffer")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buffer {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }

    fn make_writer_for(&'a self, metadata: &tracing::Metadata<'_>) -> Self::Writer {
        if metadata.target() == "tor_ptmgr::availability_diagnostics" {
            assert!(
                metadata.callsite()
                    == tracing::callsite::Identifier(availability::emission_callsite()),
                "formatted event differs from injected availability callsite"
            );
        }
        self.clone()
    }
}

impl Buffer {
    /// Read actual accepted formatter output without consuming it.
    fn text(&self) -> String {
        String::from_utf8(self.bytes.lock().expect("format buffer").clone())
            .expect("formatter output is UTF-8")
    }
}

/// Apply independently testable filters before forwarding to the real formatter.
struct Filtered {
    /// Existing formatting subscriber retained through its dispatcher.
    formatter: tracing::Dispatch,
    /// Filtering behaviour selected only within this test.
    mode: Mode,
    /// Independent post-registration filter counters.
    counts: Counts,
}

impl tracing::Subscriber for Filtered {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        if metadata.target() == "tor_ptmgr::availability_diagnostics" {
            self.counts.enabled.fetch_add(1, Ordering::SeqCst);
            if matches!(self.mode, Mode::Off) {
                return false;
            }
        }
        self.formatter.enabled(metadata)
    }

    fn new_span(&self, attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        self.formatter.new_span(attrs)
    }

    fn record(&self, span: &tracing::span::Id, values: &tracing::span::Record<'_>) {
        self.formatter.record(span, values);
    }

    fn record_follows_from(&self, span: &tracing::span::Id, follows: &tracing::span::Id) {
        self.formatter.record_follows_from(span, follows);
    }

    fn event_enabled(&self, event: &tracing::Event<'_>) -> bool {
        if event.metadata().target() == "tor_ptmgr::availability_diagnostics" {
            self.counts.events.fetch_add(1, Ordering::SeqCst);
            return !matches!(self.mode, Mode::RejectEvents);
        }
        true
    }

    fn event(&self, event: &tracing::Event<'_>) {
        self.formatter.event(event);
    }

    fn enter(&self, span: &tracing::span::Id) {
        self.formatter.enter(span);
    }

    fn exit(&self, span: &tracing::span::Id) {
        self.formatter.exit(span);
    }

    fn clone_span(&self, span: &tracing::span::Id) -> tracing::span::Id {
        self.formatter.clone_span(span)
    }

    fn try_close(&self, span: tracing::span::Id) -> bool {
        self.formatter.try_close(span)
    }
}

/// Construct a scoped filter wrapper around the existing formatting subscriber.
fn subscriber(mode: Mode, buffer: Buffer, counts: Counts) -> Filtered {
    let formatter = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .without_time()
        .with_ansi(false)
        .with_writer(buffer)
        .finish();
    Filtered {
        formatter: tracing::Dispatch::new(formatter),
        mode,
        counts,
    }
}

/// Clear registration-time observations before testing per-event filtering.
fn reset(counts: &Counts) {
    counts.enabled.store(0, Ordering::SeqCst);
    counts.events.store(0, Ordering::SeqCst);
}

/// Drive the genuine absent or closed-state consumer and retain its result.
fn immediate<R: Runtime>(manager: &PtMgr<R>, closed: bool) {
    let transport = name();
    let mut future =
        tor_chanmgr::factory::AbstractPtMgr::factory_for_transport(manager, &transport);
    match (closed, poll_once(future.as_mut())) {
        (false, Poll::Ready(Ok(None))) => {}
        (true, Poll::Ready(Err(_))) => {}
        _ => panic!("availability filtering changed the original lookup result"),
    }
    drop(future);
}

/// Exercise stale interest only in an exact isolated libtest process.
#[test]
#[ignore = "Executed by the exact-process availability backend regression"]
fn availability_backend_process_fixture() {
    tor_rtcompat::test_with_one_runtime!(|rt| async move {
        let (available, _receiver) = manager(rt.clone(), false);
        let buffer = Buffer::default();
        let counts = Counts::default();

        tracing::subscriber::with_default(
            subscriber(Mode::Enabled, buffer.clone(), counts.clone()),
            || {
                let parent = tracing::info_span!(
                    "private_availability_parent",
                    private_field = "private_availability_parent_sentinel"
                );
                assert!(!parent.is_disabled());
                let _entered = parent.enter();
                tracing::info!("availability_parent_control");

                let callsite = availability::emission_callsite();
                tracing::callsite::Callsite::set_interest(
                    callsite,
                    tracing::subscriber::Interest::never(),
                );
                assert!(callsite.interest().is_never());
                reset(&counts);
                immediate(&available, false);
            },
        );

        let output = buffer.text();
        let lines: Vec<_> = output.lines().collect();
        assert_eq!(lines.len(), 4);
        let controls: Vec<_> = lines
            .iter()
            .filter(|line| line.contains("availability_parent_control"))
            .collect();
        assert_eq!(controls.len(), 1);
        assert!(controls[0].contains("private_field"));
        assert!(controls[0].contains("private_availability_parent_sentinel"));

        let records: Vec<_> = lines
            .iter()
            .filter(|line| line.contains("pt_availability "))
            .collect();
        assert_eq!(records.len(), 3);
        for record in &records {
            assert!(!record.contains("private_field"));
            assert!(!record.contains("private_availability_parent"));
            assert!(!record.contains("private_availability_transport"));
        }
        assert_eq!(
            records
                .iter()
                .filter(|line| line.contains("terminal=true"))
                .count(),
            1,
        );
        assert!(records[2].contains("stage=Lookup outcome=None terminal=true"));
        assert!(counts.enabled.load(Ordering::SeqCst) > 0);
        assert_eq!(counts.events.load(Ordering::SeqCst), 3);

        for mode in [Mode::Off, Mode::RejectEvents] {
            for closed in [false, true] {
                let (manager, _receiver) = manager(rt.clone(), false);
                manager.state.write().expect("test state").closed = closed;
                let buffer = Buffer::default();
                let counts = Counts::default();

                tracing::subscriber::with_default(
                    subscriber(mode, buffer.clone(), counts.clone()),
                    || {
                        let callsite = availability::emission_callsite();
                        tracing::callsite::Callsite::set_interest(
                            callsite,
                            tracing::subscriber::Interest::always(),
                        );
                        assert!(callsite.interest().is_always());
                        reset(&counts);
                        immediate(&manager, closed);
                    },
                );

                assert!(counts.enabled.load(Ordering::SeqCst) > 0);
                if matches!(mode, Mode::Off) {
                    assert_eq!(counts.events.load(Ordering::SeqCst), 0);
                } else {
                    assert_eq!(counts.events.load(Ordering::SeqCst), 3);
                }
                assert!(buffer.text().is_empty());
            }
        }
    });
}

/// Require actual isolated execution and reject additive process-output bypass.
#[test]
fn availability_backend_privacy_and_independent_filters() {
    let (_, module) = module_path!()
        .split_once("::")
        .expect("test module includes crate prefix");
    let fixture = format!("{module}::availability_backend_process_fixture");
    let output = std::process::Command::new(
        std::env::current_exe().expect("current availability test executable"),
    )
    .arg("--exact")
    .arg(&fixture)
    .arg("--ignored")
    .arg("--nocapture")
    .arg("--color=never")
    .output()
    .expect("isolated availability backend fixture completes");
    assert!(
        output.status.success(),
        "availability backend fixture failed"
    );
    let stdout = String::from_utf8(output.stdout).expect("test stdout is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("test stderr is UTF-8");
    assert!(stdout.contains("running 1 test"));
    assert!(stdout.contains(&fixture));
    assert!(stdout.contains("1 passed; 0 failed; 0 ignored"));
    assert!(
        !stdout.contains("pt_availability "),
        "availability diagnostics bypassed the subscriber through stdout"
    );
    assert!(
        stderr.is_empty(),
        "availability diagnostics bypassed the subscriber through stderr"
    );
}
