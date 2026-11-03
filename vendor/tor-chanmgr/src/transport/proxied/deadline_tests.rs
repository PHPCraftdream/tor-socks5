//! Deterministic composition of the real timeout facility and connector futures.

use super::*;
use std::time::Duration;
use tor_rtcompat::{SleepProvider, SleepProviderExt, TimeoutError};

/// Manually advanced sleep state, independent of wall-clock time.
#[derive(Clone)]
struct Clock {
    /// Current synthetic elapsed time in seconds.
    seconds: Arc<AtomicUsize>,
    /// Every sleep construction and its original absolute endpoint.
    sleeps: Arc<Mutex<Vec<(usize, Duration, usize)>>>,
    /// Number of actual polls of the constructed sleep future.
    polls: Arc<AtomicUsize>,
    /// Number of sleep-future destructions.
    drops: Arc<AtomicUsize>,
}

impl Clock {
    /// Start at a nonzero origin so accidental deadline rebasing is observable.
    fn new() -> Self {
        Self {
            seconds: Arc::new(AtomicUsize::new(7)),
            sleeps: Arc::new(Mutex::new(Vec::new())),
            polls: Arc::new(AtomicUsize::new(0)),
            drops: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Advance only the synthetic clock; tests manually poll the wrapper.
    fn advance_to(&self, seconds: usize) {
        let previous = self.seconds.load(Ordering::SeqCst);
        assert!(seconds >= previous);
        self.seconds.store(seconds, Ordering::SeqCst);
    }

    /// Require one unchanged 45-second sleep constructed at the original origin.
    fn assert_original_sleep(&self) {
        assert_eq!(
            self.sleeps.lock().expect("constructed sleeps").as_slice(),
            &[(7, Duration::from_secs(45), 52)],
        );
    }
}

/// One sleep returned to the production timeout future.
struct Sleep {
    /// Shared manually controlled clock and counters.
    clock: Clock,
    /// Endpoint captured once when the sleep was constructed.
    deadline: usize,
}

impl Future for Sleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        self.clock.polls.fetch_add(1, Ordering::SeqCst);
        if self.clock.seconds.load(Ordering::SeqCst) >= self.deadline {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        self.clock.drops.fetch_add(1, Ordering::SeqCst);
    }
}

impl SleepProvider for Clock {
    type SleepFuture = Sleep;

    fn sleep(&self, duration: Duration) -> Self::SleepFuture {
        let origin = self.seconds.load(Ordering::SeqCst);
        let seconds = usize::try_from(duration.as_secs()).expect("test duration fits usize");
        assert_eq!(duration.subsec_nanos(), 0);
        let deadline = origin
            .checked_add(seconds)
            .expect("test deadline fits usize");
        self.sleeps
            .lock()
            .expect("constructed sleeps")
            .push((origin, duration, deadline));
        Sleep {
            clock: self.clone(),
            deadline,
        }
    }
}

/// Poll exactly once using the same pinned wrapper throughout a test.
fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    let waker = futures::task::noop_waker();
    let mut context = Context::from_waker(&waker);
    future.poll(&mut context)
}

/// Require expiration from the actual timeout wrapper, not a connector error.
fn assert_expired<T>(result: Poll<Result<T, TimeoutError>>) {
    match result {
        Poll::Ready(Err(error)) => assert_eq!(error, TimeoutError),
        _ => panic!("pending operation must expire at the original deadline"),
    }
}

/// Pending dial expires without retry, but abandonment occurs only on wrapper drop.
#[test]
fn timeout_pending_dial_keeps_origin_and_defers_abandonment_until_drop() {
    let tracker = Tracker::default();
    let provider = Provider::new(Plan::Pending, tracker.clone());
    let clock = Clock::new();

    tracing::subscriber::with_default(
        Capture {
            tracker: tracker.clone(),
        },
        || {
            let address = proxy();
            let protocol = Protocol::Socks(SocksVersion::V5, SocksAuth::NoAuth);
            let request = target();
            let operation = connect_via_proxy_observed(
                &provider,
                &address,
                &protocol,
                &request,
                Some(Attempt::new()),
            );
            let mut timeout = Box::pin(clock.timeout(Duration::from_secs(45), operation));

            clock.assert_original_sleep();
            assert_eq!(provider.polls(), 0);
            assert_eq!(clock.polls.load(Ordering::SeqCst), 0);
            assert!(matches!(poll_once(timeout.as_mut()), Poll::Pending));
            assert_eq!(provider.polls(), 1);
            assert_eq!(clock.polls.load(Ordering::SeqCst), 1);

            clock.advance_to(51);
            assert!(matches!(poll_once(timeout.as_mut()), Poll::Pending));
            assert_eq!(provider.polls(), 2);
            assert_eq!(clock.polls.load(Ordering::SeqCst), 2);
            clock.assert_original_sleep();

            clock.advance_to(52);
            assert_expired(poll_once(timeout.as_mut()));
            assert_eq!(provider.polls(), 3);
            assert_eq!(clock.polls.load(Ordering::SeqCst), 3);
            assert_eq!(provider.created(), 0);
            assert_eq!(tracker.drops.load(Ordering::SeqCst), 0);
            assert_eq!(clock.drops.load(Ordering::SeqCst), 0);
            assert!(!tracker.terminal.load(Ordering::SeqCst));
            clock.assert_original_sleep();

            drop(timeout);

            provider.assert_forwarded(address);
            assert_eq!(provider.polls(), 3);
            assert_eq!(provider.created(), 0);
            assert_eq!(tracker.drops.load(Ordering::SeqCst), 0);
            assert_eq!(clock.polls.load(Ordering::SeqCst), 3);
            assert_eq!(clock.drops.load(Ordering::SeqCst), 1);
            assert_stage_terminal(&tracker, "stage=Dial", "outcome=Abandoned");
        },
    );
}

/// Pending read retains its stream after expiration and records before cleanup on drop.
#[test]
fn timeout_pending_read_preserves_poll_count_and_terminal_cleanup_order() {
    let tracker = Tracker::default();
    let clock = Clock::new();

    tracing::subscriber::with_default(
        Capture {
            tracker: tracker.clone(),
        },
        || {
            let request = target();
            let version = SocksVersion::V5;
            let auth = SocksAuth::NoAuth;
            let operation = do_socks_handshake(
                ScriptedStream::new(&[], true, None, tracker.clone()),
                &version,
                &auth,
                &request,
                Some(Attempt::new()),
            );
            let mut timeout = Box::pin(clock.timeout(Duration::from_secs(45), operation));

            clock.assert_original_sleep();
            assert!(matches!(poll_once(timeout.as_mut()), Poll::Pending));
            assert_eq!(tracker.reads.load(Ordering::SeqCst), 1);

            clock.advance_to(51);
            assert!(matches!(poll_once(timeout.as_mut()), Poll::Pending));
            assert_eq!(tracker.reads.load(Ordering::SeqCst), 2);
            clock.assert_original_sleep();

            clock.advance_to(52);
            assert_expired(poll_once(timeout.as_mut()));
            assert_eq!(tracker.reads.load(Ordering::SeqCst), 3);
            assert_eq!(clock.polls.load(Ordering::SeqCst), 3);
            assert_eq!(tracker.drops.load(Ordering::SeqCst), 0);
            assert!(!tracker.terminal.load(Ordering::SeqCst));
            assert_eq!(clock.drops.load(Ordering::SeqCst), 0);
            clock.assert_original_sleep();

            drop(timeout);

            assert_eq!(tracker.reads.load(Ordering::SeqCst), 3);
            assert_eq!(clock.polls.load(Ordering::SeqCst), 3);
            assert_eq!(clock.drops.load(Ordering::SeqCst), 1);
            assert_eq!(tracker.drops.load(Ordering::SeqCst), 1);
            assert!(tracker.ordered_drop.load(Ordering::SeqCst));
            assert_stage_terminal(&tracker, "stage=Receive", "outcome=Abandoned");
        },
    );
}

/// Ready original dial errors win both before expiration and at simultaneous readiness.
#[test]
fn timeout_preserves_ready_dial_error_and_operation_first_priority() {
    for now in [51, 52] {
        let tracker = Tracker::default();
        let token = Arc::new(AtomicUsize::new(0));
        let provider = Provider::new(Plan::Refused(Some(refusal(&token))), tracker.clone());
        let clock = Clock::new();

        tracing::subscriber::with_default(
            Capture {
                tracker: tracker.clone(),
            },
            || {
                let address = proxy();
                let protocol = Protocol::Socks(SocksVersion::V5, SocksAuth::NoAuth);
                let request = target();
                let operation = connect_via_proxy_observed(
                    &provider,
                    &address,
                    &protocol,
                    &request,
                    Some(Attempt::new()),
                );
                let mut timeout = Box::pin(clock.timeout(Duration::from_secs(45), operation));

                clock.assert_original_sleep();
                clock.advance_to(now);
                let error = match poll_once(timeout.as_mut()) {
                    Poll::Ready(Ok(Err(ProxyError::ProxyConnect(error)))) => error,
                    _ => panic!("ready dial error must win over the timeout"),
                };
                provider.assert_forwarded(address);
                assert_eq!(provider.polls(), 1);
                assert_eq!(provider.created(), 0);
                assert_eq!(clock.polls.load(Ordering::SeqCst), 0);
                assert_refusal(&error, &token);
                assert_stage_terminal(&tracker, "stage=Dial", "outcome=DialError");

                drop(timeout);

                assert_eq!(provider.polls(), 1);
                assert_eq!(clock.polls.load(Ordering::SeqCst), 0);
                assert_eq!(clock.drops.load(Ordering::SeqCst), 1);
                assert_stage_terminal(&tracker, "stage=Dial", "outcome=DialError");
                assert_refusal(&error, &token);
                drop(error);
                assert_eq!(token.load(Ordering::SeqCst), 1);
            },
        );
    }
}

/// Ready handshake errors retain payload and cleanup order even at the deadline.
#[test]
fn timeout_preserves_ready_read_error_without_abandonment_replacement() {
    for now in [51, 52] {
        let tracker = Tracker::default();
        let token = Arc::new(AtomicUsize::new(0));
        let original = io::Error::new(
            io::ErrorKind::BrokenPipe,
            Marker {
                token: Arc::clone(&token),
            },
        );
        let clock = Clock::new();

        tracing::subscriber::with_default(
            Capture {
                tracker: tracker.clone(),
            },
            || {
                let request = target();
                let version = SocksVersion::V5;
                let auth = SocksAuth::NoAuth;
                let operation = do_socks_handshake(
                    ScriptedStream::new(&[], false, Some(original), tracker.clone()),
                    &version,
                    &auth,
                    &request,
                    Some(Attempt::new()),
                );
                let mut timeout = Box::pin(clock.timeout(Duration::from_secs(45), operation));

                clock.assert_original_sleep();
                clock.advance_to(now);
                let error = match poll_once(timeout.as_mut()) {
                    Poll::Ready(Ok(Err(ProxyError::ProxyIo(error)))) => error,
                    _ => panic!("ready read error must win over the timeout"),
                };
                assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
                let marker = error
                    .get_ref()
                    .and_then(|payload| payload.downcast_ref::<Marker>())
                    .expect("original read payload");
                assert!(Arc::ptr_eq(&marker.token, &token));
                assert_eq!(token.load(Ordering::SeqCst), 0);
                assert_eq!(tracker.reads.load(Ordering::SeqCst), 1);
                assert_eq!(tracker.drops.load(Ordering::SeqCst), 1);
                assert!(tracker.ordered_drop.load(Ordering::SeqCst));
                assert_eq!(clock.polls.load(Ordering::SeqCst), 0);
                assert_stage_terminal(&tracker, "stage=Receive", "outcome=IoError");

                drop(timeout);

                assert_eq!(tracker.reads.load(Ordering::SeqCst), 1);
                assert_eq!(tracker.drops.load(Ordering::SeqCst), 1);
                assert_eq!(clock.drops.load(Ordering::SeqCst), 1);
                assert_stage_terminal(&tracker, "stage=Receive", "outcome=IoError");
                assert_eq!(token.load(Ordering::SeqCst), 0);
                drop(error);
                assert_eq!(token.load(Ordering::SeqCst), 1);
            },
        );
    }
}
