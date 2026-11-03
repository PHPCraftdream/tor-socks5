//! Actual provider and selected-plugin entry regressions.

use super::*;
use tor_rtcompat::{NetStreamListener, StreamOps};

impl StreamOps for ScriptedStream {}

/// Options whose actual forwarded value is retained by the provider.
#[derive(Clone, Default)]
struct ConnectOptions {
    /// Default options must reach the provider unchanged.
    changed: bool,
}

/// Controlled result of the existing provider connect operation.
enum Plan {
    /// Create one stream only when the dial completes.
    Success(Vec<u8>),
    /// Move the original error into the existing dial-error conversion.
    Refused(Option<io::Error>),
    /// Remain pending without creating a stream.
    Pending,
}

/// Provider state retained outside the connector future.
struct ProviderState {
    /// Selected deterministic dial behaviour.
    plan: Mutex<Plan>,
    /// Number of polls of the provider's dial operation.
    polls: AtomicUsize,
    /// Number of streams actually created by successful dial completion.
    created: AtomicUsize,
    /// Actual destination and option values received by connect.
    forwarded: Mutex<Vec<(SocketAddr, bool)>>,
    /// Shared stream and diagnostic witnesses.
    tracker: Tracker,
}

/// Minimal provider implementing the pinned futures-I/O contracts.
#[derive(Clone)]
struct Provider {
    /// State shared with assertions after connector cancellation.
    state: Arc<ProviderState>,
}

impl Provider {
    /// Configure a provider without constructing a stream or error replacement.
    fn new(plan: Plan, tracker: Tracker) -> Self {
        Self {
            state: Arc::new(ProviderState {
                plan: Mutex::new(plan),
                polls: AtomicUsize::new(0),
                created: AtomicUsize::new(0),
                forwarded: Mutex::new(Vec::new()),
                tracker,
            }),
        }
    }

    /// Require one original dial with its unchanged address and default options.
    fn assert_forwarded(&self, proxy: SocketAddr) {
        let forwarded = self.state.forwarded.lock().expect("forwarded dial");
        assert_eq!(forwarded.as_slice(), &[(proxy, false)]);
    }

    /// Read the number of actual provider polls.
    fn polls(&self) -> usize {
        self.state.polls.load(Ordering::SeqCst)
    }

    /// Read the number of streams actually created.
    fn created(&self) -> usize {
        self.state.created.load(Ordering::SeqCst)
    }
}

/// Listener contract required by the provider; no test opens a listener.
struct Listener;

impl NetStreamListener for Listener {
    type Stream = ScriptedStream;
    type Incoming = futures::stream::Empty<io::Result<(ScriptedStream, SocketAddr)>>;

    fn incoming(self) -> Self::Incoming {
        futures::stream::empty()
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(proxy())
    }
}

#[async_trait::async_trait]
impl NetStreamProvider for Provider {
    type Stream = ScriptedStream;
    type Listener = Listener;
    type ConnectOptions = ConnectOptions;
    type ListenOptions = ();

    async fn connect(
        &self,
        addr: &SocketAddr,
        options: &Self::ConnectOptions,
    ) -> io::Result<Self::Stream> {
        self.state
            .forwarded
            .lock()
            .expect("forwarded dial")
            .push((*addr, options.changed));

        futures::future::poll_fn(|_cx| {
            self.state.polls.fetch_add(1, Ordering::SeqCst);
            let mut plan = self.state.plan.lock().expect("dial plan");
            match &mut *plan {
                Plan::Success(response) => {
                    self.state.created.fetch_add(1, Ordering::SeqCst);
                    Poll::Ready(Ok(ScriptedStream::new(
                        response,
                        false,
                        None,
                        self.state.tracker.clone(),
                    )))
                }
                Plan::Refused(error) => {
                    Poll::Ready(Err(error.take().expect("dial refusal returned only once")))
                }
                Plan::Pending => Poll::Pending,
            }
        })
        .await
    }

    async fn listen(
        &self,
        _addr: &SocketAddr,
        _options: &Self::ListenOptions,
    ) -> io::Result<Self::Listener> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "connector test provider does not listen",
        ))
    }
}

/// Fixed proxy address whose forwarding is checked without network activity.
fn proxy() -> SocketAddr {
    "192.0.2.19:19050".parse().expect("test proxy address")
}

/// Fragmented no-auth selection and successful final SOCKS reply.
fn no_auth_reply() -> Vec<u8> {
    vec![5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0]
}

/// Username/password selection, successful authentication, and final SOCKS reply.
fn authenticated_reply() -> Vec<u8> {
    vec![5, 2, 1, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0]
}

/// Require one terminal at the named boundary.
fn assert_stage_terminal(tracker: &Tracker, stage: &str, outcome: &str) {
    assert_terminal(tracker, outcome);
    let messages = tracker.messages.lock().expect("captured messages");
    let terminal = messages
        .iter()
        .find(|message| message.contains("terminal=true"))
        .expect("terminal record");
    assert!(terminal.contains(stage));
}

/// Require that an unstarted connector did not create observations or resources.
fn assert_unstarted(provider: &Provider, tracker: &Tracker) {
    assert_eq!(provider.polls(), 0);
    assert_eq!(provider.created(), 0);
    assert!(
        provider
            .state
            .forwarded
            .lock()
            .expect("forwarded dial")
            .is_empty()
    );
    assert!(
        tracker
            .messages
            .lock()
            .expect("captured messages")
            .is_empty()
    );
    assert_eq!(tracker.drops.load(Ordering::SeqCst), 0);
}

/// Preserve the original error payload through the existing ProxyConnect wrapper.
fn assert_refusal(error: &Arc<io::Error>, token: &Arc<AtomicUsize>) {
    assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
    let marker = error
        .get_ref()
        .and_then(|payload| payload.downcast_ref::<Marker>())
        .expect("original refusal payload");
    assert!(Arc::ptr_eq(&marker.token, token));
    assert_eq!(token.load(Ordering::SeqCst), 0);
}

/// Construct the original refusal with a separately retained payload identity.
fn refusal(token: &Arc<AtomicUsize>) -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionRefused,
        Marker {
            token: Arc::clone(token),
        },
    )
}

/// Supply identities using the same builder API as existing channel tests.
fn channel_target(method: ChannelMethod) -> OwnedChanTarget {
    OwnedChanTarget::builder()
        .addrs(vec!["192.0.2.7:443".parse().expect("test relay address")])
        .method(method)
        .ed_identity(tor_llcrypto::pk::ed25519::Ed25519Identity::from(
            crate::testing::msgs::ED_ID,
        ))
        .rsa_identity(tor_llcrypto::pk::rsa::RsaIdentity::from(
            crate::testing::msgs::RSA_ID,
        ))
        .build()
        .expect("test channel target")
}

/// Genuine PT settings and hostname passed through the production preparation path.
fn private_target() -> OwnedChanTarget {
    let mut target = tor_linkspec::PtTarget::new(
        "private_transport".parse().expect("test transport name"),
        PtTargetAddr::HostPort("private_target_sentinel.invalid".to_owned(), 443),
    );
    target
        .push_setting("private_setting_key", "private_setting_value")
        .expect("test PT setting");
    channel_target(ChannelMethod::Pluggable(target))
}

/// Check a genuine byte subsequence without printing private input on failure.
fn contains_bytes(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|window| window == needle)
}

/// Require that the real wire input did not become a diagnostic field.
fn assert_private_output(tracker: &Tracker) {
    let messages = tracker.messages.lock().expect("captured messages");
    assert!(!messages.is_empty());
    for private in [
        "private_transport",
        "private_target_sentinel.invalid",
        "private_setting_key",
        "private_setting_value",
        "private_error_sentinel",
    ] {
        assert!(
            messages.iter().all(|message| !message.contains(private)),
            "connector diagnostic disclosed private input"
        );
    }
}

/// The actual observed helper forwards the original dial and returns its stream.
#[test]
fn provider_success_forwards_address_options_and_retains_stream() {
    let tracker = Tracker::default();
    let provider = Provider::new(Plan::Success(no_auth_reply()), tracker.clone());
    tracing::subscriber::with_default(
        Capture {
            tracker: tracker.clone(),
        },
        || {
            let protocol = Protocol::Socks(SocksVersion::V5, SocksAuth::NoAuth);
            let request = target();
            let result = block_on(connect_via_proxy_observed(
                &provider,
                &proxy(),
                &protocol,
                &request,
                Some(Attempt::new()),
            ));
            let stream = match result {
                Ok(stream) => stream,
                Err(_) => panic!("scripted provider connection must succeed"),
            };
            provider.assert_forwarded(proxy());
            assert_eq!(provider.polls(), 1);
            assert_eq!(provider.created(), 1);
            assert_eq!(tracker.drops.load(Ordering::SeqCst), 0);
            assert_stage_terminal(&tracker, "stage=Returned", "outcome=Ok");
            drop(stream);
            assert_eq!(tracker.drops.load(Ordering::SeqCst), 1);
            assert!(tracker.ordered_drop.load(Ordering::SeqCst));
        },
    );
}

/// Dial refusal retains the original payload until the returned error is released.
#[test]
fn provider_refusal_preserves_original_error_and_records_dial_terminal() {
    let tracker = Tracker::default();
    let token = Arc::new(AtomicUsize::new(0));
    let provider = Provider::new(Plan::Refused(Some(refusal(&token))), tracker.clone());
    tracing::subscriber::with_default(
        Capture {
            tracker: tracker.clone(),
        },
        || {
            let protocol = Protocol::Socks(SocksVersion::V5, SocksAuth::NoAuth);
            let request = target();
            let result = block_on(connect_via_proxy_observed(
                &provider,
                &proxy(),
                &protocol,
                &request,
                Some(Attempt::new()),
            ));
            let error = match result {
                Err(ProxyError::ProxyConnect(error)) => error,
                _ => panic!("original dial failure must remain ProxyConnect"),
            };
            provider.assert_forwarded(proxy());
            assert_eq!(provider.polls(), 1);
            assert_eq!(provider.created(), 0);
            assert_eq!(tracker.drops.load(Ordering::SeqCst), 0);
            assert_refusal(&error, &token);
            assert_stage_terminal(&tracker, "stage=Dial", "outcome=DialError");
            drop(error);
            assert_eq!(token.load(Ordering::SeqCst), 1);
        },
    );
}

/// Pending helper cancellation does not poll again or construct a stream.
#[test]
fn provider_pending_drop_records_one_dial_abandonment_without_repoll() {
    let tracker = Tracker::default();
    let provider = Provider::new(Plan::Pending, tracker.clone());
    tracing::subscriber::with_default(
        Capture {
            tracker: tracker.clone(),
        },
        || {
            let address = proxy();
            let protocol = Protocol::Socks(SocksVersion::V5, SocksAuth::NoAuth);
            let request = target();
            let mut future = Box::pin(connect_via_proxy_observed(
                &provider,
                &address,
                &protocol,
                &request,
                Some(Attempt::new()),
            ));
            let waker = futures::task::noop_waker();
            let mut context = Context::from_waker(&waker);
            assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
            assert_eq!(provider.polls(), 1);
            assert_eq!(provider.created(), 0);
            assert!(!tracker.terminal.load(Ordering::SeqCst));

            drop(future);

            provider.assert_forwarded(address);
            assert_eq!(provider.polls(), 1);
            assert_eq!(provider.created(), 0);
            assert_eq!(tracker.drops.load(Ordering::SeqCst), 0);
            assert_stage_terminal(&tracker, "stage=Dial", "outcome=Abandoned");
        },
    );
}

/// The original shared wrapper does not create selected-PT observations.
#[test]
fn ordinary_proxy_wrapper_produces_no_pt_attempt_records() {
    let tracker = Tracker::default();
    let provider = Provider::new(Plan::Success(no_auth_reply()), tracker.clone());
    tracing::subscriber::with_default(
        Capture {
            tracker: tracker.clone(),
        },
        || {
            let protocol = Protocol::Socks(SocksVersion::V5, SocksAuth::NoAuth);
            let request = target();
            let result = block_on(connect_via_proxy(&provider, &proxy(), &protocol, &request));
            let stream = match result {
                Ok(stream) => stream,
                Err(_) => panic!("ordinary scripted proxy must succeed"),
            };
            provider.assert_forwarded(proxy());
            assert_eq!(provider.polls(), 1);
            assert_eq!(provider.created(), 1);
            assert!(
                tracker
                    .messages
                    .lock()
                    .expect("captured messages")
                    .is_empty()
            );
            drop(stream);
            assert_eq!(tracker.drops.load(Ordering::SeqCst), 1);
        },
    );
}

/// An unpolled selected-plugin future creates neither an attempt nor a dial.
#[test]
fn plugin_unpolled_drop_has_no_attempt_or_provider_activity() {
    let tracker = Tracker::default();
    let provider = Provider::new(Plan::Pending, tracker.clone());
    let plugin = ExternalProxyPlugin::new(provider.clone(), proxy(), SocksVersion::V5);
    let request = private_target();
    tracing::subscriber::with_default(
        Capture {
            tracker: tracker.clone(),
        },
        || {
            let future = TransportImplHelper::connect(&plugin, &request);
            drop(future);
            assert_unstarted(&provider, &tracker);
        },
    );
}

/// Invalid direct targets are rejected by the actual plugin before provider polling.
#[test]
fn plugin_direct_target_rejection_precedes_dial() {
    let tracker = Tracker::default();
    let provider = Provider::new(Plan::Pending, tracker.clone());
    let plugin = ExternalProxyPlugin::new(provider.clone(), proxy(), SocksVersion::V5);
    let request = channel_target(ChannelMethod::Direct(vec![
        "192.0.2.7:443".parse().expect("test direct address"),
    ]));
    tracing::subscriber::with_default(
        Capture {
            tracker: tracker.clone(),
        },
        || {
            let result = block_on(TransportImplHelper::connect(&plugin, &request));
            assert!(matches!(result, Err(crate::Error::UnusableTarget(_))));
            assert_eq!(provider.polls(), 0);
            assert_eq!(provider.created(), 0);
            assert!(
                provider
                    .state
                    .forwarded
                    .lock()
                    .expect("forwarded dial")
                    .is_empty()
            );
            assert_stage_terminal(&tracker, "stage=Prepare", "outcome=Invalid");
        },
    );
}

/// Real PT preparation sends genuine settings and target without logging them.
#[test]
fn plugin_preparation_traverses_settings_and_returns_negotiated_stream() {
    let tracker = Tracker::default();
    let provider = Provider::new(Plan::Success(authenticated_reply()), tracker.clone());
    let plugin = ExternalProxyPlugin::new(provider.clone(), proxy(), SocksVersion::V5);
    let request = private_target();
    tracing::subscriber::with_default(
        Capture {
            tracker: tracker.clone(),
        },
        || {
            let result = block_on(TransportImplHelper::connect(&plugin, &request));
            let (_, stream) = match result {
                Ok(value) => value,
                Err(_) => panic!("selected scripted PT connector must succeed"),
            };
            provider.assert_forwarded(proxy());
            assert_eq!(provider.polls(), 1);
            assert_eq!(provider.created(), 1);
            assert_eq!(tracker.drops.load(Ordering::SeqCst), 0);
            assert_stage_terminal(&tracker, "stage=Returned", "outcome=Ok");

            let written = tracker.written.lock().expect("scripted writes");
            assert!(written.starts_with(&[5, 2, 2, 0]));
            assert!(
                contains_bytes(&written, b"private_setting_key=private_setting_value"),
                "genuine PT setting did not traverse request preparation"
            );
            assert!(
                contains_bytes(&written, b"private_target_sentinel.invalid"),
                "genuine PT target did not traverse SOCKS encoding"
            );
            drop(written);
            assert_private_output(&tracker);
            drop(stream);
            assert_eq!(tracker.drops.load(Ordering::SeqCst), 1);
            assert!(tracker.ordered_drop.load(Ordering::SeqCst));
        },
    );
}

/// Actual plugin dial failure retains its original mapped ProxyConnect payload.
#[test]
fn plugin_refusal_preserves_existing_connect_error_mapping() {
    let tracker = Tracker::default();
    let token = Arc::new(AtomicUsize::new(0));
    let provider = Provider::new(Plan::Refused(Some(refusal(&token))), tracker.clone());
    let plugin = ExternalProxyPlugin::new(provider.clone(), proxy(), SocksVersion::V5);
    let request = private_target();
    tracing::subscriber::with_default(
        Capture {
            tracker: tracker.clone(),
        },
        || {
            let result = block_on(TransportImplHelper::connect(&plugin, &request));
            let addresses = match result {
                Err(crate::Error::Connect { addresses }) => addresses,
                _ => panic!("plugin dial error must retain Connect mapping"),
            };
            assert_eq!(addresses.len(), 1);
            match &addresses[0].1 {
                crate::err::ConnectError::Proxy(ProxyError::ProxyConnect(error)) => {
                    assert_refusal(error, &token);
                }
                _ => panic!("mapped dial error must retain ProxyConnect"),
            }
            provider.assert_forwarded(proxy());
            assert_eq!(provider.polls(), 1);
            assert_eq!(provider.created(), 0);
            assert_stage_terminal(&tracker, "stage=Dial", "outcome=DialError");
            assert_private_output(&tracker);
            drop(addresses);
            assert_eq!(token.load(Ordering::SeqCst), 1);
        },
    );
}

/// Actual plugin cancellation retains the pending dial's poll and resource counts.
#[test]
fn plugin_pending_dial_drop_records_one_abandonment_without_repoll() {
    let tracker = Tracker::default();
    let provider = Provider::new(Plan::Pending, tracker.clone());
    let plugin = ExternalProxyPlugin::new(provider.clone(), proxy(), SocksVersion::V5);
    let request = private_target();
    tracing::subscriber::with_default(
        Capture {
            tracker: tracker.clone(),
        },
        || {
            let mut future = TransportImplHelper::connect(&plugin, &request);
            let waker = futures::task::noop_waker();
            let mut context = Context::from_waker(&waker);
            assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
            assert_eq!(provider.polls(), 1);
            assert_eq!(provider.created(), 0);
            assert!(!tracker.terminal.load(Ordering::SeqCst));

            drop(future);

            provider.assert_forwarded(proxy());
            assert_eq!(provider.polls(), 1);
            assert_eq!(provider.created(), 0);
            assert_eq!(tracker.drops.load(Ordering::SeqCst), 0);
            assert_stage_terminal(&tracker, "stage=Dial", "outcome=Abandoned");
            assert_private_output(&tracker);
        },
    );
}
