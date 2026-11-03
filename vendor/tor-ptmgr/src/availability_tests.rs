//! Actual factory-consumer regressions without starting a reactor or child process.

use super::*;
use futures::{Future, StreamExt};
use std::fmt;
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

/// Real events delivered by the scoped subscriber.
#[derive(Clone, Default)]
struct Capture {
    /// Accepted availability messages.
    messages: Arc<Mutex<Vec<String>>>,
}

/// Extract only the diagnostic message field.
#[derive(Default)]
struct Visitor {
    /// Delivered message, if present.
    message: Option<String>,
}

impl tracing::field::Visit for Visitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{value:?}"));
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_owned());
        }
    }
}

impl tracing::Subscriber for Capture {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target() == "tor_ptmgr::availability_diagnostics"
    }

    fn new_span(&self, _attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        assert_eq!(
            event.metadata().target(),
            "tor_ptmgr::availability_diagnostics",
        );
        assert!(event.is_root());
        let mut visitor = Visitor::default();
        event.record(&mut visitor);
        self.messages
            .lock()
            .expect("availability capture")
            .push(visitor.message.expect("availability message"));
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

/// Original error payload with a separately retained destruction witness.
struct Marker {
    /// Number of destructions of this original payload.
    drops: Arc<AtomicUsize>,
}

impl fmt::Debug for Marker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("private_availability_error")
    }
}

impl fmt::Display for Marker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("private_availability_error")
    }
}

impl std::error::Error for Marker {}

impl Drop for Marker {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

/// Poll one existing future exactly once.
fn poll_once<F: Future + ?Sized>(future: Pin<&mut F>) -> Poll<F::Output> {
    let waker = futures::task::noop_waker();
    let mut context = Context::from_waker(&waker);
    future.poll(&mut context)
}

/// Genuine input used by lookup and by the captured reactor request.
fn name() -> PtTransportName {
    "private_availability_transport"
        .parse()
        .expect("test transport name")
}

/// Construct a retained manager with no spawned reactor.
fn manager<R: Runtime>(
    runtime: R,
    configured: bool,
) -> (
    PtMgr<R>,
    futures::channel::mpsc::UnboundedReceiver<PtReactorMessage>,
) {
    let (tx, rx) = futures::channel::mpsc::unbounded();
    let mut state = PtSharedState::default();
    if configured {
        state.configured.insert(
            name(),
            TransportOptions::Managed(crate::config::ManagedTransportOptions {
                protocols: vec![name()],
                path: tor_config_path::CfgPath::new("private_availability_path".into()),
                arguments: vec!["private_availability_argument".into()],
                run_on_startup: false,
            }),
        );
    }
    (
        PtMgr {
            runtime,
            state: Arc::new(RwLock::new(state)),
            tx,
        },
        rx,
    )
}

/// Receive the actual lookup request without polling its consumer again.
fn sender(
    receiver: &mut futures::channel::mpsc::UnboundedReceiver<PtReactorMessage>,
) -> oneshot::Sender<err::Result<PtClientMethod>> {
    match poll_once(Box::pin(receiver.next()).as_mut()) {
        Poll::Ready(Some(PtReactorMessage::Spawn { pt, result })) => {
            assert!(pt == name());
            result
        }
        _ => panic!("actual availability lookup must queue one Spawn request"),
    }
}

/// Require exact delivered count, one terminal, and scalar-only output.
fn receipt(capture: &Capture, count: usize, outcome: &str) {
    let messages = capture.messages.lock().expect("availability capture");
    assert_eq!(messages.len(), count);
    assert!(count <= 4);
    let terminals: Vec<_> = messages
        .iter()
        .filter(|message| message.contains("terminal=true"))
        .collect();
    assert_eq!(terminals.len(), 1);
    assert!(terminals[0].contains(outcome));
    for private in [
        "private_availability_transport",
        "private_availability_path",
        "private_availability_argument",
        "private_availability_error",
        "192.0.2.23",
    ] {
        assert!(
            messages.iter().all(|message| !message.contains(private)),
            "availability diagnostic disclosed private input"
        );
    }
}

/// Count polls of the actual lookup future without requiring it to be Unpin.
struct Counted<F> {
    /// Original lookup, pinned once for this test witness.
    inner: Pin<Box<F>>,
    /// Polls reaching that lookup rather than only its outer consumer.
    polls: Arc<AtomicUsize>,
}

impl<F: Future> Future for Counted<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.polls.fetch_add(1, Ordering::SeqCst);
        this.inner.as_mut().poll(cx)
    }
}

/// Retain and count one genuine manager lookup.
fn counted<F: Future>(inner: F, polls: Arc<AtomicUsize>) -> Counted<F> {
    Counted {
        inner: Box::pin(inner),
        polls,
    }
}

/// An unpolled factory future neither requests a method nor creates observations.
#[test]
fn availability_unpolled_factory_has_no_request_or_record() {
    tor_rtcompat::test_with_one_runtime!(|rt| async move {
        let (manager, mut receiver) = manager(rt, true);
        let capture = Capture::default();
        let transport = name();
        tracing::subscriber::with_default(capture.clone(), || {
            let future =
                tor_chanmgr::factory::AbstractPtMgr::factory_for_transport(&manager, &transport);
            drop(future);
            assert!(
                capture
                    .messages
                    .lock()
                    .expect("availability capture")
                    .is_empty()
            );
            assert!(matches!(
                poll_once(Box::pin(receiver.next()).as_mut()),
                Poll::Pending
            ));
        });
    });
}

/// Compare real lookup polling directly and through its observed factory consumer.
#[test]
fn availability_pending_consumer_drop_is_not_a_returned_method() {
    tor_rtcompat::test_with_one_runtime!(|rt| async move {
        for observed in [false, true] {
            let (manager, mut receiver) = manager(rt.clone(), true);
            let capture = Capture::default();
            let transport = name();
            let polls = Arc::new(AtomicUsize::new(0));

            tracing::subscriber::with_default(capture.clone(), || {
                let lookup = counted(
                    manager.get_cmethod_for_transport(&transport),
                    Arc::clone(&polls),
                );

                if observed {
                    let mut future = Box::pin(manager.factory_from_lookup(lookup));
                    assert!(matches!(poll_once(future.as_mut()), Poll::Pending));
                    assert_eq!(polls.load(Ordering::SeqCst), 1);
                    let result = sender(&mut receiver);
                    assert_eq!(
                        capture.messages.lock().expect("availability capture").len(),
                        2,
                    );

                    drop(future);

                    assert_eq!(polls.load(Ordering::SeqCst), 1);
                    receipt(&capture, 3, "outcome=Abandoned");
                    assert!(result.send(Err(PtError::Timeout)).is_err());
                    assert_eq!(polls.load(Ordering::SeqCst), 1);
                    receipt(&capture, 3, "outcome=Abandoned");
                } else {
                    let mut future = Box::pin(lookup);
                    assert!(matches!(poll_once(future.as_mut()), Poll::Pending));
                    assert_eq!(polls.load(Ordering::SeqCst), 1);
                    let result = sender(&mut receiver);

                    drop(future);

                    assert_eq!(polls.load(Ordering::SeqCst), 1);
                    assert!(result.send(Err(PtError::Timeout)).is_err());
                    assert!(
                        capture
                            .messages
                            .lock()
                            .expect("availability capture")
                            .is_empty()
                    );
                }

                assert!(matches!(
                    poll_once(Box::pin(receiver.next()).as_mut()),
                    Poll::Pending
                ));
                assert_eq!(polls.load(Ordering::SeqCst), 1);
            });
        }
    });
}

/// Actual absent and closed-state results remain distinct and do not contact the reactor.
#[test]
fn availability_none_and_closed_error_are_returned_by_actual_lookup() {
    tor_rtcompat::test_with_one_runtime!(|rt| async move {
        for closed in [false, true] {
            let (manager, mut receiver) = manager(rt.clone(), false);
            manager.state.write().expect("test state").closed = closed;
            let capture = Capture::default();
            let transport = name();
            tracing::subscriber::with_default(capture.clone(), || {
                let mut future = tor_chanmgr::factory::AbstractPtMgr::factory_for_transport(
                    &manager, &transport,
                );
                match (closed, poll_once(future.as_mut())) {
                    (false, Poll::Ready(Ok(None))) => {}
                    (true, Poll::Ready(Err(_))) => {}
                    _ => panic!("actual lookup result changed"),
                }
                drop(future);
                receipt(
                    &capture,
                    3,
                    if closed {
                        "outcome=ChildGone"
                    } else {
                        "outcome=None"
                    },
                );
                assert!(matches!(
                    poll_once(Box::pin(receiver.next()).as_mut()),
                    Poll::Pending
                ));
            });
        }
    });
}

/// Consuming an actual method reply returns a factory without polling its connector.
#[test]
fn availability_method_reply_is_consumed_before_factory_return() {
    tor_rtcompat::test_with_one_runtime!(|rt| async move {
        let (manager, mut receiver) = manager(rt, true);
        let capture = Capture::default();
        let transport = name();
        tracing::subscriber::with_default(capture.clone(), || {
            let mut future =
                tor_chanmgr::factory::AbstractPtMgr::factory_for_transport(&manager, &transport);
            assert!(matches!(poll_once(future.as_mut()), Poll::Pending));
            let result = sender(&mut receiver);
            assert!(
                result
                    .send(Ok(PtClientMethod {
                        kind: SocksVersion::V5,
                        endpoint: "192.0.2.23:19050".parse().expect("test method endpoint"),
                    }))
                    .is_ok()
            );
            assert_eq!(
                capture.messages.lock().expect("availability capture").len(),
                2
            );
            let factory = match poll_once(future.as_mut()) {
                Poll::Ready(Ok(Some(factory))) => factory,
                _ => panic!("consumed method must return its factory"),
            };
            drop(future);
            receipt(&capture, 4, "stage=Factory outcome=Returned");
            let messages = capture.messages.lock().expect("availability capture");
            assert!(messages[2].contains("sequence=2 stage=Lookup outcome=Method terminal=false"));
            assert!(
                messages[3].contains("sequence=3 stage=Factory outcome=Returned terminal=true")
            );
            drop(messages);
            drop(factory);
            receipt(&capture, 4, "stage=Factory outcome=Returned");
        });
    });
}

/// An actual error reply preserves its original allocation and records before destruction.
#[test]
fn availability_error_reply_preserves_payload_and_first_terminal() {
    tor_rtcompat::test_with_one_runtime!(|rt| async move {
        let (manager, mut receiver) = manager(rt, true);
        let capture = Capture::default();
        let transport = name();
        let drops = Arc::new(AtomicUsize::new(0));
        let original = Arc::new(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            Marker {
                drops: Arc::clone(&drops),
            },
        ));
        tracing::subscriber::with_default(capture.clone(), || {
            let mut future =
                tor_chanmgr::factory::AbstractPtMgr::factory_for_transport(&manager, &transport);
            assert!(matches!(poll_once(future.as_mut()), Poll::Pending));
            let result = sender(&mut receiver);
            assert!(
                result
                    .send(Err(PtError::ChildReadFailed(Arc::clone(&original))))
                    .is_ok()
            );
            let error = match poll_once(future.as_mut()) {
                Poll::Ready(Err(error)) => error,
                _ => panic!("consumed error must retain the original failure"),
            };
            drop(future);
            receipt(&capture, 3, "outcome=ReadError");
            assert_eq!(Arc::strong_count(&original), 2);
            assert_eq!(drops.load(Ordering::SeqCst), 0);
            drop(error);
            assert_eq!(Arc::strong_count(&original), 1);
            receipt(&capture, 3, "outcome=ReadError");
            drop(original);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
        });
    });
}

/// Isolated real-subscriber privacy and independent filter regressions.
#[path = "availability_backend_tests.rs"]
mod backend_tests;
