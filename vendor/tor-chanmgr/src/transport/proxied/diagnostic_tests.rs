//! Actual handshake regressions with deterministic stream lifecycle witnesses.

use super::*;
use futures::executor::block_on;
use futures::io::{AsyncRead, AsyncWrite};
use std::collections::VecDeque;
use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

/// Shared observations retained independently of the owned stream.
#[derive(Clone, Default)]
struct Tracker {
    /// Real diagnostic messages delivered to the scoped subscriber.
    messages: Arc<Mutex<Vec<String>>>,
    /// Number of reads actually polled.
    reads: Arc<AtomicUsize>,
    /// Number of owned stream destructions.
    drops: Arc<AtomicUsize>,
    /// Whether the subscriber has already received a terminal record.
    terminal: Arc<AtomicBool>,
    /// Whether stream destruction observed that terminal record.
    ordered_drop: Arc<AtomicBool>,
    /// Bytes actually accepted by the scripted write implementation.
    written: Arc<Mutex<Vec<u8>>>,
}

/// An original I/O payload with independently retained identity and destruction count.
struct Marker {
    /// Stable test-only payload identity and destruction counter.
    token: Arc<AtomicUsize>,
}

impl fmt::Debug for Marker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("private_error_sentinel")
    }
}

impl fmt::Display for Marker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("private_error_sentinel")
    }
}

impl std::error::Error for Marker {}

impl Drop for Marker {
    fn drop(&mut self) {
        self.token.fetch_add(1, Ordering::SeqCst);
    }
}

/// Owned futures I/O stream with fragmented replies and explicit pending/error behaviour.
struct ScriptedStream {
    /// Reply bytes supplied one byte at a time.
    input: VecDeque<u8>,
    /// Remain pending when the next read is attempted.
    pending: bool,
    /// Original error returned by the next read, if present.
    error: Option<io::Error>,
    /// External lifecycle and emission witnesses.
    tracker: Tracker,
}

impl ScriptedStream {
    /// Construct one stream without performing any I/O.
    fn new(input: &[u8], pending: bool, error: Option<io::Error>, tracker: Tracker) -> Self {
        Self {
            input: input.iter().copied().collect(),
            pending,
            error,
            tracker,
        }
    }
}

impl Drop for ScriptedStream {
    fn drop(&mut self) {
        self.tracker.ordered_drop.store(
            self.tracker.terminal.load(Ordering::SeqCst),
            Ordering::SeqCst,
        );
        self.tracker.drops.fetch_add(1, Ordering::SeqCst);
    }
}

impl AsyncRead for ScriptedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.tracker.reads.fetch_add(1, Ordering::SeqCst);
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.pending {
            return Poll::Pending;
        }
        if let Some(error) = self.error.take() {
            return Poll::Ready(Err(error));
        }
        match self.input.pop_front() {
            Some(byte) => {
                buf[0] = byte;
                Poll::Ready(Ok(1))
            }
            None => Poll::Ready(Ok(0)),
        }
    }
}

impl AsyncWrite for ScriptedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(byte) = buf.first() {
            self.tracker
                .written
                .lock()
                .expect("scripted writes")
                .push(*byte);
            Poll::Ready(Ok(1))
        } else {
            Poll::Ready(Ok(0))
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Extract only the fixed diagnostic message field.
#[derive(Default)]
struct MessageVisitor {
    /// Captured message, if the event supplied one.
    message: Option<String>,
}

impl tracing::field::Visit for MessageVisitor {
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

/// Capture only this connector target through the real tracing dispatch path.
struct Capture {
    /// External witnesses shared with the owned scripted stream.
    tracker: Tracker,
}

impl tracing::Subscriber for Capture {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target() == "tor_chanmgr::pt_connector_diagnostics"
    }

    fn new_span(&self, _attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        if event.metadata().target() != "tor_chanmgr::pt_connector_diagnostics" {
            return;
        }
        assert!(event.is_root());
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        let message = visitor.message.expect("connector message");
        if message.contains("terminal=true") {
            self.tracker.terminal.store(true, Ordering::SeqCst);
        }
        self.tracker
            .messages
            .lock()
            .expect("captured messages")
            .push(message);
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

/// Select a fixed request address without network activity.
fn target() -> PtTargetAddr {
    PtTargetAddr::IpPort("192.0.2.7:443".parse().expect("test request address"))
}

/// Require one terminal classification and no later abandonment replacement.
fn assert_terminal(tracker: &Tracker, outcome: &str) {
    let messages = tracker.messages.lock().expect("captured messages");
    let terminals: Vec<_> = messages
        .iter()
        .filter(|message| message.contains("terminal=true"))
        .collect();
    assert_eq!(terminals.len(), 1);
    assert!(terminals[0].contains(outcome));
    assert!(messages.len() <= 19);
    assert!(
        messages
            .iter()
            .all(|message| !message.contains("private_error_sentinel"))
    );
}

/// Fragmented real negotiation returns its original owned stream without destroying it.
#[test]
fn handshake_success_retains_stream_and_records_one_terminal() {
    let tracker = Tracker::default();
    let response = [5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    tracing::subscriber::with_default(
        Capture {
            tracker: tracker.clone(),
        },
        || {
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
                Err(_) => panic!("scripted handshake must succeed"),
            };
            assert_eq!(tracker.drops.load(Ordering::SeqCst), 0);
            assert_eq!(tracker.reads.load(Ordering::SeqCst), response.len());
            assert_terminal(&tracker, "outcome=Ok");

            let written = tracker.written.lock().expect("scripted writes");
            assert_eq!(
                written.as_slice(),
                &[5, 1, 0, 5, 1, 0, 1, 192, 0, 2, 7, 1, 187],
            );
            drop(written);
            drop(stream);
            assert_eq!(tracker.drops.load(Ordering::SeqCst), 1);
            assert!(tracker.ordered_drop.load(Ordering::SeqCst));
            assert_terminal(&tracker, "outcome=Ok");
        },
    );
}

/// Read failure preserves the original payload and records before owned-stream cleanup.
#[test]
fn handshake_io_error_preserves_payload_and_precedes_cleanup() {
    let tracker = Tracker::default();
    let token = Arc::new(AtomicUsize::new(0));
    let original = io::Error::new(
        io::ErrorKind::BrokenPipe,
        Marker {
            token: Arc::clone(&token),
        },
    );
    tracing::subscriber::with_default(
        Capture {
            tracker: tracker.clone(),
        },
        || {
            let request = target();
            let result = block_on(do_socks_handshake(
                ScriptedStream::new(&[], false, Some(original), tracker.clone()),
                &SocksVersion::V5,
                &SocksAuth::NoAuth,
                &request,
                Some(Attempt::new()),
            ));
            let error = match result {
                Err(ProxyError::ProxyIo(error)) => error,
                _ => panic!("original read failure must remain ProxyIo"),
            };
            assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
            let marker = error
                .get_ref()
                .and_then(|payload| payload.downcast_ref::<Marker>())
                .expect("original error payload");
            assert!(Arc::ptr_eq(&marker.token, &token));
            assert_eq!(token.load(Ordering::SeqCst), 0);
            assert_eq!(tracker.drops.load(Ordering::SeqCst), 1);
            assert!(tracker.ordered_drop.load(Ordering::SeqCst));
            assert_eq!(tracker.reads.load(Ordering::SeqCst), 1);
            assert_terminal(&tracker, "outcome=IoError");
            drop(error);
            assert_eq!(token.load(Ordering::SeqCst), 1);
        },
    );
}

/// Cancellation destroys the stream after abandonment without another read poll.
#[test]
fn handshake_pending_read_drop_does_not_poll_again() {
    let tracker = Tracker::default();
    tracing::subscriber::with_default(
        Capture {
            tracker: tracker.clone(),
        },
        || {
            let request = target();
            let version = SocksVersion::V5;
            let auth = SocksAuth::NoAuth;
            let mut future = Box::pin(do_socks_handshake(
                ScriptedStream::new(&[], true, None, tracker.clone()),
                &version,
                &auth,
                &request,
                Some(Attempt::new()),
            ));
            let waker = futures::task::noop_waker();
            let mut context = Context::from_waker(&waker);
            assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
            assert_eq!(tracker.reads.load(Ordering::SeqCst), 1);
            assert_eq!(tracker.drops.load(Ordering::SeqCst), 0);
            assert!(!tracker.terminal.load(Ordering::SeqCst));

            drop(future);

            assert_eq!(tracker.reads.load(Ordering::SeqCst), 1);
            assert_eq!(tracker.drops.load(Ordering::SeqCst), 1);
            assert!(tracker.ordered_drop.load(Ordering::SeqCst));
            assert_terminal(&tracker, "outcome=Abandoned");
            let messages = tracker.messages.lock().expect("captured messages");
            assert!(
                messages
                    .last()
                    .expect("abandonment record")
                    .contains("stage=Receive")
            );
        },
    );
}

/// Provider and selected-plugin regressions using the existing stream witnesses.
#[cfg(feature = "pt-client")]
#[path = "provider_tests.rs"]
mod provider_tests;
