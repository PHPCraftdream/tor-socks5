//! Thin wrapper over `arti-client`: bootstraps a Tor client and opens streams
//! through the Tor network. The returned `DataStream` implements
//! `futures::AsyncRead/Write` — wrap it with `tokio_util::compat` when a tokio
//! interface is needed.
//!
//! Supports configuring bridges (with pluggable transports) via [`Settings`].

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;

use arti_client::config::pt::TransportConfigBuilder;
use arti_client::config::{BridgeConfigBuilder, CfgPath, Reconfigure, TorClientConfigBuilder};
use arti_client::{DataStream, TorClient, TorClientConfig};
use bridge_line::BridgeLine;
use tor_rtcompat::PreferredRuntime;

#[derive(Debug, thiserror::Error)]
pub enum TorError {
    #[error("failed to bootstrap Tor client: {0}")]
    Bootstrap(#[source] arti_client::Error),

    #[error("failed to reconfigure bridge order: {0}")]
    Reconfigure(#[source] arti_client::Error),

    #[error("failed to connect through Tor to {host}:{port}: {source}")]
    Connect {
        host: String,
        port: u16,
        #[source]
        source: arti_client::Error,
    },

    #[error("invalid bridge configuration: {0}")]
    InvalidBridge(String),

    #[error("invalid pluggable-transport configuration: {0}")]
    InvalidPt(String),

    #[error("failed to build Tor client config: {0}")]
    BuildConfig(String),

    #[error("could not access Tor client's channel manager: {0}")]
    ChanMgrUnavailable(#[source] arti_client::Error),

    #[error("failed to warm a channel to bridge {bridge}: {source}")]
    Warm {
        bridge: String,
        #[source]
        source: Box<tor_chanmgr::Error>,
    },

    #[error("failed to signal guard failure for bridge {bridge}: {source}")]
    SignalFailure {
        bridge: String,
        #[source]
        source: arti_client::Error,
    },
}

/// Re-exported so callers (e.g. `apps/socks5-proxy/src/tor_watchdog.rs`) do
/// not need a direct dependency on `tor-guardmgr` just to call
/// [`TorTunnel::signal_bridge_failure`]. Mirrors `arti_client`'s own
/// re-export of the same type from its crate root.
pub use tor_guardmgr::ExternalActivity;

pub type Result<T, E = TorError> = std::result::Result<T, E>;

/// A bootstrap-progress event, flattened from arti's `BootstrapStatus`
/// for embedders (CLI logging, the future JNI FFI crate). Treat
/// `Progress` values as idempotent state updates, not a counter: arti's
/// underlying watch stream coalesces and may repeat values.
#[derive(Debug, Clone, PartialEq)]
pub enum BootstrapEvent {
    /// Rough progress estimate (`0.0..=1.0`, arti's `as_frac()`) plus arti's own
    /// human-readable phase description (`BootstrapStatus`'s `Display` impl, e.g.
    /// "15%: connecting successfully; directory is fetching a consensus") -- the exact text
    /// already visible in this crate's own tracing logs, now also handed to embedders instead
    /// of being dropped at this boundary.
    Progress(f32, String),
    /// The client is ready to carry traffic (`ready_for_traffic()`).
    Ready,
    /// arti currently reports it cannot make forward progress
    /// (a human-readable blockage reason). Not necessarily fatal —
    /// bootstrap status is non-monotonic.
    Blocked(String),
    /// The bootstrap attempt failed (the `wait_bootstrapped` error,
    /// with its cause chain rendered into the string).
    Failed(String),
}

/// Callback invoked for every [`BootstrapEvent`]. Shared via `Arc` (not
/// `Box`) so the same callback can be held by both the event-forwarding
/// task and the code awaiting bootstrap completion.
pub type BootstrapEventCallback = Arc<dyn Fn(BootstrapEvent) + Send + Sync>;

/// Bootstrap-time settings for [`TorTunnel`].
#[derive(Debug, Default, Clone)]
pub struct Settings {
    /// Bridges to use. When non-empty, the client will go through these
    /// instead of public guards.
    pub bridges: Vec<BridgeLine>,
    /// Path to a pluggable-transport binary (e.g. `lyrebird`/`obfs4proxy`).
    /// Required if any bridge specifies a transport other than `none`.
    pub pt_binary: Option<PathBuf>,
    /// Base directory for arti's on-disk **state** and **cache**. When set,
    /// arti's `state_dir`/`cache_dir` are pinned under here (`state/` and
    /// `cache/` subdirs) instead of arti's per-user OS-default location.
    ///
    /// Pinning this matters: the OS-default arti dirs are **shared across
    /// every arti instance on the machine** and persist across runs, so a
    /// stale guard sample / cached consensus from a previous (or unrelated)
    /// run can shadow the bridges we configure here. An app-local dir makes
    /// state predictable and wipeable. `None` keeps arti's default.
    pub state_dir: Option<PathBuf>,
    /// Tier 2 (docs/circuit-speed-plan.md): restrict middle/exit relay selection to the
    /// upper `min_bandwidth_percentile`-th percentile of consensus bandwidth. `0` (default)
    /// disables the floor -- stock, bandwidth-weighted-but-unrestricted selection. Trades
    /// anonymity (a smaller candidate pool) for fewer slow hops.
    pub min_bandwidth_percentile: u8,
    /// Override the `iat-mode` parameter on every obfs4 bridge line before
    /// handing it to arti. `iat-mode` is a *client-side* obfs4 knob: `0`
    /// sends cells as they come (fastest, but leaves obfs4's packet-size and
    /// timing distribution intact for a statistical/ML classifier to
    /// fingerprint), `1` splits and delays writes, `2` is the paranoid
    /// variant. Nearly every published bridge line ships `iat-mode=0`, so
    /// enabling the randomiser has to happen here rather than by picking
    /// different bridges. `None` (default) keeps whatever each line
    /// published. Costs latency and throughput -- only worth it where DPI
    /// actively kills obfs4 streams.
    pub obfs4_iat_mode: Option<u8>,
}

impl Settings {
    pub fn is_default(&self) -> bool {
        self.bridges.is_empty()
            && self.pt_binary.is_none()
            && self.min_bandwidth_percentile == 0
            && self.obfs4_iat_mode.is_none()
    }
}

/// Apply [`Settings::obfs4_iat_mode`] to one bridge line.
///
/// Only obfs4 carries `iat-mode`; other transports (webtunnel, plain) are
/// returned untouched, as is every line when no override is configured.
fn with_iat_mode_override(line: &BridgeLine, iat_mode: Option<u8>) -> BridgeLine {
    let Some(mode) = iat_mode else {
        return line.clone();
    };
    if line.transport.as_deref() != Some("obfs4") {
        return line.clone();
    }
    let mut overridden = line.clone();
    overridden
        .params
        .insert("iat-mode".to_owned(), mode.to_string());
    overridden
}

/// Tor tunnel client. Cheap to clone (uses `Arc` internally).
#[derive(Clone)]
pub struct TorTunnel {
    inner: Arc<TorClient<PreferredRuntime>>,
}

/// Map one `BootstrapStatus` to callback event(s). Returns `true` when
/// the status is ready for traffic (the subscriber's terminal success —
/// the forwarding task exits after emitting `Ready`).
fn emit_bootstrap_event(
    status: &arti_client::status::BootstrapStatus,
    on_event: &BootstrapEventCallback,
) -> bool {
    if status.ready_for_traffic() {
        on_event(BootstrapEvent::Ready);
        true
    } else {
        on_event(BootstrapEvent::Progress(
            status.as_frac(),
            status.to_string(),
        ));
        if let Some(blockage) = status.blocked() {
            on_event(BootstrapEvent::Blocked(blockage.to_string()));
        }
        false
    }
}

/// Render an error plus its whole `source()` chain into one line
/// ("msg: cause: cause") — thiserror's `Display` stops at the top layer,
/// and the FFI consumer only gets the string.
fn error_chain_string(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(err) = source {
        text.push_str(": ");
        text.push_str(&err.to_string());
        source = err.source();
    }
    text
}

impl TorTunnel {
    /// Bootstrap a Tor client with default configuration.
    pub async fn bootstrap() -> Result<Self> {
        Self::bootstrap_with(Settings::default()).await
    }

    /// Bootstrap a Tor client applying the given [`Settings`].
    pub async fn bootstrap_with(settings: Settings) -> Result<Self> {
        let config = build_config(&settings)?;
        Self::bootstrap_raw(config).await
    }

    /// Bootstrap using a pre-built `arti-client` config (escape hatch).
    pub async fn bootstrap_raw(config: TorClientConfig) -> Result<Self> {
        tracing::info!("bootstrapping Tor client...");
        let client = tor_builder(config)
            .create_bootstrapped()
            .await
            .map_err(TorError::Bootstrap)?;
        tracing::info!("Tor is ready");
        Ok(Self { inner: client })
    }

    /// Forward this client's bootstrap events to `on_event` from a background
    /// Tokio task: the current status is emitted synchronously first (a
    /// subscriber always sees at least one `Progress` immediately), then one
    /// `Progress` (+ `Blocked` when arti reports a blockage) per observed
    /// status change, and a final `Ready` once the client can carry traffic —
    /// after which the task exits. This is a *bootstrap* channel, not an
    /// ongoing health monitor: post-ready status changes (e.g. losing the
    /// network later) are not delivered; use the watchdog for that.
    ///
    /// Never fails bootstrap and never blocks. The spawned task deliberately
    /// holds only the event stream and the callback — NOT a client clone —
    /// so it cannot keep the `TorClient` (and its runtime tasks) alive
    /// forever after the tunnel is dropped.
    pub fn forward_bootstrap_events(&self, on_event: BootstrapEventCallback) {
        use futures::StreamExt as _;
        let mut events = self.inner.bootstrap_events();
        if emit_bootstrap_event(&self.inner.bootstrap_status(), &on_event) {
            return;
        }
        tokio::spawn(async move {
            while let Some(status) = events.next().await {
                if emit_bootstrap_event(&status, &on_event) {
                    return;
                }
            }
        });
    }

    /// [`bootstrap_with`](Self::bootstrap_with) plus an optional
    /// bootstrap-event subscription — the entry point the future JNI FFI
    /// crate will use. Uses the timeout-safe two-step path
    /// ([`create_unbootstrapped`](Self::create_unbootstrapped) →
    /// [`wait_bootstrapped`](Self::wait_bootstrapped)) rather than the
    /// one-shot `create_bootstrapped`, so see the former's docs for why the
    /// `TorTunnel` stays owned by the caller on a failed/cancelled wait.
    /// `None` behaves like `bootstrap_with` minus the event forwarding.
    /// On bootstrap failure the callback receives
    /// [`BootstrapEvent::Failed`] (error + cause chain) and the error is
    /// still returned.
    pub async fn bootstrap_with_notify(
        settings: Settings,
        on_event: Option<BootstrapEventCallback>,
    ) -> Result<Self> {
        let config = build_config(&settings)?;
        let tunnel = Self::create_unbootstrapped(config)?;
        if let Some(on_event) = &on_event {
            tunnel.forward_bootstrap_events(on_event.clone());
        }
        match tunnel.wait_bootstrapped().await {
            Ok(()) => Ok(tunnel),
            Err(error) => {
                if let Some(on_event) = &on_event {
                    on_event(BootstrapEvent::Failed(error_chain_string(&error)));
                }
                Err(error)
            }
        }
    }

    /// Open a stream through Tor to the given address.
    /// `host` may be a domain (including `.onion`) or an IP address.
    pub async fn connect(&self, host: &str, port: u16) -> Result<DataStream> {
        self.inner
            .connect((host, port))
            .await
            .map_err(|source| TorError::Connect {
                host: host.to_string(),
                port,
                source,
            })
    }

    /// Access the inner `TorClient` for features not exposed by the wrapper.
    pub fn raw(&self) -> &TorClient<PreferredRuntime> {
        &self.inner
    }

    /// Unconditionally close every channel this client's `ChanMgr` currently
    /// tracks, in place, without constructing a new `TorClient`.
    ///
    /// Requires the vendored `tor-chanmgr` patch (see
    /// `vendor/tor-chanmgr/src/lib.rs`'s `ChanMgr::terminate_all_channels`)
    /// and `arti-client`'s `experimental-api` feature, which is what gates
    /// `TorClient::chanmgr()`. Any circuit builder holding a reference to a
    /// terminated channel observes it fail exactly as it would after a real
    /// network-level disconnection; `ChanMgr::get_or_launch` transparently
    /// builds a fresh channel (over the same already-warm guard/bridge-
    /// descriptor state) the next time one is requested. See
    /// `tor_watchdog.rs`'s module doc comment for why this replaced building
    /// a whole second `TorClient` in a cold rebuild-slot directory.
    ///
    /// `TorClient::chanmgr()` itself returns a `Result` — it fails only when
    /// the client is not in a "running" state (e.g. fully dormant); that
    /// failure is surfaced here rather than swallowed so the watchdog can
    /// tell "termination requested, arti will reconnect" from "could not
    /// even reach the channel manager".
    pub fn terminate_all_channels(&self) -> Result<()> {
        let chanmgr = self.inner.chanmgr().map_err(TorError::ChanMgrUnavailable)?;
        chanmgr.terminate_all_channels();
        Ok(())
    }

    /// Open (or reuse) a channel to `bridge`, without building a circuit or
    /// carrying any traffic over it yet.
    ///
    /// This is the primitive behind the background bridge-warming pool
    /// (`bridge_warmer.rs` in `apps/socks5-proxy`): calling
    /// `ChanMgr::get_or_launch` for a bridge populates `tor-chanmgr`'s own
    /// identity-keyed channel cache (see `vendor/tor-chanmgr/src/mgr/
    /// state.rs`), so when arti's guard manager later wants to build a
    /// circuit through the same bridge it transparently reuses the
    /// already-open (and already-warm) channel instead of paying for a
    /// fresh obfs4/webtunnel handshake on the hot path. The routing to a
    /// bridge's pluggable transport (if any) happens automatically inside
    /// `ChanMgr` (`vendor/tor-chanmgr/src/factory.rs`'s `CompoundFactory`)
    /// — callers do not need to special-case PT bridges.
    ///
    /// `usage: ChannelUsage::UserTraffic` is deliberate — it matches what a
    /// real circuit build for user traffic would request, so the resulting
    /// channel is not treated as disposable by any usage-based bookkeeping
    /// `ChanMgr` may apply.
    ///
    /// Requires `TorClient::chanmgr()` (the `experimental-api` feature,
    /// already enabled workspace-wide), same as
    /// [`terminate_all_channels`](Self::terminate_all_channels).
    pub async fn warm_bridge(&self, bridge: &BridgeLine) -> Result<()> {
        let chanmgr = self.inner.chanmgr().map_err(TorError::ChanMgrUnavailable)?;
        let serialized = bridge.to_string();
        let builder: BridgeConfigBuilder =
            serialized
                .parse()
                .map_err(|e: arti_client::config::BridgeParseError| {
                    TorError::InvalidBridge(format!("{serialized:?}: {e}"))
                })?;
        let target = builder
            .build()
            .map_err(|e| TorError::InvalidBridge(format!("{serialized:?}: {e}")))?;
        chanmgr
            .get_or_launch(&target, tor_chanmgr::ChannelUsage::UserTraffic)
            .await
            .map_err(|source| TorError::Warm {
                bridge: serialized,
                source: Box::new(source),
            })?;
        Ok(())
    }

    /// Tell arti's guard manager that `bridge` has been observed (by this
    /// application, outside of arti's own circuit-build accounting) to be
    /// degrading, so it can factor that into its own primary/confirmed/
    /// sample guard-state machine (prop271) the next time it picks a guard.
    ///
    /// This is the soft-failover primitive behind the stale-channel
    /// watchdog's bridge-degradation check (`tor_watchdog.rs` in
    /// `apps/socks5-proxy`): unlike [`terminate_all_channels`]
    /// (Self::terminate_all_channels), which forces a reconnect over the
    /// same guards, this actively nudges arti away from a specific
    /// degrading bridge toward a healthier one, without this crate having
    /// to pick or configure the replacement itself — arti already owns that
    /// decision.
    ///
    /// Symmetric with [`warm_bridge`](Self::warm_bridge): the same
    /// `BridgeLine` → `BridgeConfigBuilder` → `BridgeConfig` conversion is
    /// reused here to obtain a `HasRelayIds` identity, since `BridgeLine`
    /// itself does not implement that trait.
    ///
    /// Requires `TorClient::note_external_guard_failure` (the
    /// `experimental-api` feature, already enabled workspace-wide) — see
    /// `vendor/arti-client/src/client.rs`. That call only fails when the
    /// client is not in a "running" state (e.g. fully dormant or not yet
    /// bootstrapped); that failure is surfaced here rather than swallowed,
    /// mirroring [`terminate_all_channels`](Self::terminate_all_channels)'s
    /// and [`warm_bridge`](Self::warm_bridge)'s error handling.
    pub fn signal_bridge_failure(
        &self,
        bridge: &BridgeLine,
        activity: tor_guardmgr::ExternalActivity,
    ) -> Result<()> {
        let serialized = bridge.to_string();
        let builder: BridgeConfigBuilder =
            serialized
                .parse()
                .map_err(|e: arti_client::config::BridgeParseError| {
                    TorError::InvalidBridge(format!("{serialized:?}: {e}"))
                })?;
        let target = builder
            .build()
            .map_err(|e| TorError::InvalidBridge(format!("{serialized:?}: {e}")))?;
        self.inner
            .note_external_guard_failure(&target, activity)
            .map_err(|source| TorError::SignalFailure {
                bridge: serialized,
                source,
            })
    }

    /// Construct a `TorClient` without waiting for network bootstrap.
    ///
    /// Synchronous — no `.await` inside, so nothing external can cancel it
    /// mid-construction; it either returns a fully owned client or an error,
    /// atomically. Pair with [`wait_bootstrapped`](Self::wait_bootstrapped)
    /// to actually reach a usable directory; unlike
    /// [`bootstrap_raw`](Self::bootstrap_raw), the two steps are separate
    /// `await` points, so a timeout wrapped around only the second one can
    /// never strand an unowned, half-built client with detached background
    /// tasks (chanmgr/circmgr/dirmgr/ptmgr) — the caller always keeps the
    /// `TorTunnel` value and can explicitly `drop` it.
    pub fn create_unbootstrapped(config: TorClientConfig) -> Result<Self> {
        // `tor_builder` mirrors `TorClient::create_bootstrapped`'s own runtime
        // lookup, including its panic-on-no-runtime `.expect(...)` semantics
        // — this app always runs inside a tokio runtime, so that's consistent,
        // not a new risk — and additionally installs the fatal-shutdown
        // observability hook (see `fatal_protocol_error_hook`).
        let client = tor_builder(config)
            .create_unbootstrapped()
            .map_err(TorError::Bootstrap)?;
        Ok(Self { inner: client })
    }

    /// Settings-based convenience mirror of `bootstrap_with`, but synchronous
    /// and without waiting for the network — parallels
    /// [`create_unbootstrapped`](Self::create_unbootstrapped) the way
    /// `bootstrap_with` parallels `bootstrap_raw`.
    pub fn create_unbootstrapped_with(settings: Settings) -> Result<Self> {
        let config = build_config(&settings)?;
        Self::create_unbootstrapped(config)
    }

    /// Wait for the client to reach a usable directory.
    ///
    /// Safe to wrap in an external timeout: cancelling this future only
    /// abandons the *wait* — the `TorTunnel` itself (owned separately by the
    /// caller, outside this future) is untouched and can be retried or
    /// dropped explicitly afterward.
    pub async fn wait_bootstrapped(&self) -> Result<()> {
        self.inner.bootstrap().await.map_err(TorError::Bootstrap)
    }

    /// Apply a new bridge order before bootstrap starts. The channel manager may already have
    /// warmed channels for this same client; reconfiguring the guard set makes the measured
    /// fastest candidates the first choices instead of leaving the initial bootstrap to the
    /// original config-file order.
    pub fn reconfigure_bridges(&self, settings: &Settings) -> Result<()> {
        let config = build_config(settings)?;
        self.inner
            .reconfigure(&config, Reconfigure::AllOrNothing)
            .map_err(TorError::Reconfigure)
    }
}

// tor-socks5 local patch: build every `TorClient` through this helper so the
// intentional protocol-mismatch shutdown (Tor proposal 266) is observable.
fn tor_builder(config: TorClientConfig) -> arti_client::TorClientBuilder<PreferredRuntime> {
    let runtime = PreferredRuntime::current().expect(
        "TorClient could not get an asynchronous runtime; are you running in the right context?",
    );
    TorClient::with_runtime(runtime)
        .config(config)
        // Surface the otherwise-silent intentional shutdown as a structured
        // log line before arti calls `std::process::exit(1)`. The shutdown
        // itself is deliberately NOT disabled — it is a security measure.
        .fatal_protocol_error_handler(fatal_protocol_error_hook)
}

// tor-socks5 local patch: structured marker emitted immediately before arti's
// fatal protocol-mismatch shutdown. This process has no external supervisor to
// notice the exit, so without this the event is silent until a human wonders
// why the proxy stopped responding. `target = "arti_wrapper"` is already in
// the app's tracing directive set (see `config.rs`), so this is captured by
// the normal logging pipeline.
fn fatal_protocol_error_hook(error: &arti_client::Error) {
    use arti_client::HasKind as _;
    tracing::error!(
        target: "arti_wrapper",
        error_kind = %error.kind(),
        error = %error,
        "arti is performing an intentional fatal shutdown: this build is missing a Tor \
         subprotocol the live network consensus marks as required for clients (proposal 266). \
         The process will exit shortly. Upgrade arti and restart the proxy to recover.",
    );
}

fn build_config(settings: &Settings) -> Result<TorClientConfig> {
    let mut builder: TorClientConfigBuilder = TorClientConfig::builder();

    // Patience for slow bridges. arti's default download schedules are tuned
    // for fast public relays; over a slow/marginal obfs4 or webtunnel bridge
    // the consensus / certificates / microdescriptors arrive slowly and the
    // last few objects keep getting dropped, so the bootstrap never reaches a
    // usable directory (bridges stay `dir_info_missing` → "unsuitable to
    // purpose" → no Data guard).
    //
    // GENTLE, not aggressive. An earlier revision widened per-object
    // parallelism (consensus x10, microdesc x12) to "race many bridges at
    // once". That backfired: it opens a burst of simultaneous obfs4 channels
    // to the small bridge pool, and the bridges' flood/abuse protection
    // forcibly resets the connections (os error 10054) — exactly the network
    // flood we must avoid. C-tor is stable on these same bridges precisely
    // because it is conservative: few concurrent connections, patient retries.
    // We mirror that — keep a generous *attempts* budget (retries spread over
    // time are fine) but low concurrency so we never hammer a bridge.
    {
        let sched = builder.download_schedule();
        sched.retry_bootstrap().attempts(64);
        sched.retry_consensus().attempts(32).parallelism(2);
        sched.retry_certs().attempts(32).parallelism(2);
        sched.retry_microdescs().attempts(64).parallelism(3);
    }

    // Pin arti's state + cache under an app-local directory when asked, so
    // they are predictable, wipeable, and never shared with another arti
    // instance. A shared OS-default state dir can carry a stale guard
    // sample / cached consensus from a previous run that shadows the
    // bridges configured below (observed with webtunnel-only configs).
    if let Some(base) = &settings.state_dir {
        let join = |sub: &str| CfgPath::new(base.join(sub).to_string_lossy().into_owned());
        builder
            .storage()
            .cache_dir(join("cache"))
            .state_dir(join("state"));
    }

    // Tier 2 (docs/circuit-speed-plan.md): the default floor is zero, so this is a no-op
    // unless explicitly opted into.
    builder
        .path_rules()
        .min_bandwidth_percentile(settings.min_bandwidth_percentile);

    if !settings.bridges.is_empty() {
        for line in &settings.bridges {
            let serialized = with_iat_mode_override(line, settings.obfs4_iat_mode).to_string();
            let bridge: BridgeConfigBuilder =
                serialized
                    .parse()
                    .map_err(|e: arti_client::config::BridgeParseError| {
                        TorError::InvalidBridge(format!("{serialized:?}: {e}"))
                    })?;
            builder.bridges().bridges().push(bridge);
        }

        // Collect distinct transport names that need PT support.
        let transports: BTreeSet<&str> = settings
            .bridges
            .iter()
            .filter_map(|b| b.transport.as_deref())
            .collect();

        if !transports.is_empty() {
            let pt_binary = settings.pt_binary.as_ref().ok_or_else(|| {
                TorError::InvalidPt(format!(
                    "bridges use pluggable transport(s) {transports:?} but pt_binary is not set"
                ))
            })?;
            if !pt_binary.exists() {
                return Err(TorError::InvalidPt(format!(
                    "pt_binary {pt_binary:?} does not exist (build it with `cargo build --bin lyrebird`)"
                )));
            }

            let mut transport = TransportConfigBuilder::default();
            let mut protocols = Vec::with_capacity(transports.len());
            for name in &transports {
                let parsed = name
                    .parse()
                    .map_err(|e| TorError::InvalidPt(format!("transport {name:?}: {e}")))?;
                protocols.push(parsed);
            }
            transport
                .protocols(protocols)
                .path(CfgPath::new(pt_binary.to_string_lossy().into_owned()))
                .run_on_startup(true);
            builder.bridges().transports().push(transport);

            // NOTE (webtunnel): this wiring is sufficient for webtunnel
            // bridges too — they bootstrap end-to-end (verified live to
            // `{"IsTor":true}`). An earlier investigation found webtunnel
            // appearing to be "dropped" at runtime; the real cause was a
            // stale/shared arti state dir (a persisted netdir guard sample
            // + cached consensus from prior runs) keeping arti in direct
            // mode. Pinning `Settings::state_dir` to an app-local directory
            // (see above) fixed it. See docs/webtunnel.md.
        }
    }

    builder
        .build()
        .map_err(|e| TorError::BuildConfig(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Once;

    /// Install rustls's process-wide `CryptoProvider` exactly once for this
    /// test binary, mirroring `install_crypto_provider()` in
    /// `apps/socks5-proxy/src/startup.rs` (which real app startup always
    /// runs before constructing any `TorTunnel`). Only needed by tests that
    /// build a real `TorClientConfig` with a *fresh* (empty) state/cache dir:
    /// with no cached consensus to read, `TorClientConfig::builder().build()`
    /// reaches further into arti's directory-manager setup than a dir with
    /// pre-existing state would, and that path expects a crypto provider to
    /// already be installed. `install_default()` errors if called twice in
    /// the same process (e.g. across multiple `#[tokio::test]`s here), so
    /// the error is intentionally discarded.
    fn ensure_crypto_provider() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    #[test]
    fn settings_default_is_default() {
        let s = Settings::default();
        assert!(s.is_default());
        assert!(s.bridges.is_empty());
        assert!(s.pt_binary.is_none());
    }

    #[test]
    fn settings_with_bridges_is_not_default() {
        let bridge: BridgeLine = "192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01"
            .parse()
            .unwrap();
        let s = Settings {
            bridges: vec![bridge],
            pt_binary: None,
            state_dir: None,
            ..Default::default()
        };
        assert!(!s.is_default());
    }

    #[test]
    fn build_config_empty_settings_succeeds() {
        let cfg = build_config(&Settings::default());
        assert!(cfg.is_ok());
    }

    #[test]
    fn build_config_plain_bridge_without_pt_binary_succeeds() {
        let bridge: BridgeLine = "192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01"
            .parse()
            .unwrap();
        let s = Settings {
            bridges: vec![bridge],
            pt_binary: None,
            state_dir: None,
            ..Default::default()
        };
        let cfg = build_config(&s);
        assert!(
            cfg.is_ok(),
            "plain bridge (no transport) should not require pt_binary"
        );
    }

    #[test]
    fn build_config_transport_bridge_without_pt_binary_errors() {
        let bridge: BridgeLine =
            "obfs4 192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0"
                .parse()
                .unwrap();
        let s = Settings {
            bridges: vec![bridge],
            pt_binary: None,
            state_dir: None,
            ..Default::default()
        };
        let err = build_config(&s).unwrap_err();
        assert!(
            matches!(err, TorError::InvalidPt(_)),
            "expected InvalidPt, got: {err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("pt_binary"),
            "error must mention pt_binary: {msg}"
        );
    }

    #[test]
    fn build_config_transport_bridge_with_nonexistent_pt_binary_errors() {
        let bridge: BridgeLine =
            "obfs4 192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0"
                .parse()
                .unwrap();
        let s = Settings {
            bridges: vec![bridge],
            pt_binary: Some(PathBuf::from("/nonexistent/path/lyrebird")),
            state_dir: None,
            ..Default::default()
        };
        let err = build_config(&s).unwrap_err();
        assert!(matches!(err, TorError::InvalidPt(_)));
        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn build_config_transport_bridge_with_valid_pt_binary_succeeds() {
        let bridge: BridgeLine =
            "obfs4 192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0"
                .parse()
                .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let fake_binary = dir.path().join("fake-lyrebird");
        std::fs::write(&fake_binary, b"#!/bin/sh\n").unwrap();
        let s = Settings {
            bridges: vec![bridge],
            pt_binary: Some(fake_binary),
            state_dir: None,
            ..Default::default()
        };
        let cfg = build_config(&s);
        assert!(cfg.is_ok(), "valid pt_binary should produce a valid config");
    }

    #[test]
    fn build_config_multiple_transports_collected() {
        let obfs4: BridgeLine =
            "obfs4 192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0"
                .parse()
                .unwrap();
        let webtunnel: BridgeLine =
            "webtunnel 192.0.2.2:1 0123456789ABCDEF0123456789ABCDEF01234567 url=https://example.com/x ver=0.0.3"
                .parse()
                .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let fake_binary = dir.path().join("fake-lyrebird");
        std::fs::write(&fake_binary, b"#!/bin/sh\n").unwrap();
        let s = Settings {
            bridges: vec![obfs4, webtunnel],
            pt_binary: Some(fake_binary),
            state_dir: None,
            ..Default::default()
        };
        let cfg = build_config(&s);
        assert!(
            cfg.is_ok(),
            "mixed transports should work with a valid pt_binary"
        );
    }

    #[tokio::test]
    async fn signal_bridge_failure_requires_running_client() {
        // `create_unbootstrapped_with` is synchronous and does no I/O, so the
        // resulting client never reaches arti's "running" state — the same
        // property `tor_watchdog.rs`'s
        // `heal_reports_terminate_failed_on_a_client_that_is_not_running`
        // test relies on for `terminate_all_channels`. This exercises the
        // BridgeLine → BridgeConfigBuilder → BridgeConfig conversion path
        // (shared with `warm_bridge`) end to end without any network access,
        // and confirms the "not running" failure surfaces as
        // `TorError::SignalFailure` rather than panicking or being silently
        // swallowed.
        //
        // `#[tokio::test]`, not `#[test]`: `create_unbootstrapped_with` looks
        // up the current tokio runtime via `PreferredRuntime::current()` (see
        // `tor_builder`), which panics outside of an async context.
        //
        // `state_dir` must point at a fresh tempdir rather than
        // `Settings::default()`'s `None`: with `None`, arti falls back to
        // its per-user OS-default state/cache location, and constructing
        // even an "unbootstrapped" client eagerly opens that directory's
        // storage — which fails with `DirMgrSetup(ReadOnlyStorage(NoDatabase))`
        // on a fresh CI runner with no pre-existing arti state (the same
        // real-shared-OS-path fragility `tor_setup.rs` already avoids for
        // the live proxy, and that `verify_usable_skips_network_when_no_target`
        // hit for the same reason in an earlier session).
        ensure_crypto_provider();
        let dir = tempfile::tempdir().unwrap();
        let settings = Settings {
            state_dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        let tor = TorTunnel::create_unbootstrapped_with(settings)
            .expect("synchronous, no-I/O construction must succeed");
        let bridge: BridgeLine =
            "obfs4 192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0"
                .parse()
                .unwrap();
        let err = tor
            .signal_bridge_failure(&bridge, tor_guardmgr::ExternalActivity::DirCache)
            .unwrap_err();
        assert!(
            matches!(err, TorError::SignalFailure { .. }),
            "expected SignalFailure, got: {err}"
        );
    }

    #[tokio::test]
    async fn signal_bridge_failure_conversion_succeeds_for_plain_bridge_without_transport() {
        // Same "not running" contract as the obfs4 case above, but with a
        // plain bridge line (no transport) — confirms the BridgeLine →
        // BridgeConfigBuilder → BridgeConfig conversion path used by
        // `signal_bridge_failure` handles both bridge shapes, same as
        // `warm_bridge`'s conversion. Same tempdir `state_dir` rationale as
        // the obfs4 case above — do not revert to `Settings::default()`.
        ensure_crypto_provider();
        let dir = tempfile::tempdir().unwrap();
        let settings = Settings {
            state_dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        let tor = TorTunnel::create_unbootstrapped_with(settings)
            .expect("synchronous, no-I/O construction must succeed");
        let bridge: BridgeLine = "192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01"
            .parse()
            .unwrap();
        let err = tor
            .signal_bridge_failure(&bridge, tor_guardmgr::ExternalActivity::DirCache)
            .unwrap_err();
        assert!(matches!(err, TorError::SignalFailure { .. }));
    }

    #[test]
    fn emit_bootstrap_event_maps_default_status_to_progress() {
        // `BootstrapStatus::default()` is documented by the vendored crate's
        // own tests to never be ready for traffic, so `emit_bootstrap_event`
        // must emit a `Progress` event and return `false`.
        use std::sync::Mutex;
        let events = Arc::new(Mutex::new(Vec::new()));
        let callback: BootstrapEventCallback = Arc::new({
            let events = events.clone();
            move |event| events.lock().unwrap().push(event)
        });
        let status = arti_client::status::BootstrapStatus::default();
        let ready = emit_bootstrap_event(&status, &callback);
        assert!(!ready, "default status is not ready for traffic");
        let collected = events.lock().unwrap();
        assert_eq!(collected.len(), 1, "should emit exactly one event");
        assert!(
            matches!(collected[0], BootstrapEvent::Progress(f, _) if f == 0.0),
            "default status should emit Progress(0.0), got: {:?}",
            collected[0]
        );
    }

    #[tokio::test]
    async fn forward_bootstrap_events_emits_initial_progress() {
        // `forward_bootstrap_events` synchronously emits the current status
        // before spawning the background task, so the callback receives a
        // `Progress` event immediately without any network activity.
        // The event arrives because the client's default bootstrap status
        // (not yet bootstrapped, no network) is emitted on the first call.
        ensure_crypto_provider();
        let dir = tempfile::tempdir().unwrap();
        let settings = Settings {
            state_dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        let tor = TorTunnel::create_unbootstrapped_with(settings)
            .expect("synchronous, no-I/O construction must succeed");
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let tx = Arc::new(tx);
        let callback: BootstrapEventCallback = Arc::new({
            let tx = tx.clone();
            move |event| {
                let _ = tx.try_send(event);
            }
        });
        tor.forward_bootstrap_events(callback);
        let event = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .expect("timeout waiting for initial event")
            .expect("channel should not close");
        assert!(
            matches!(event, BootstrapEvent::Progress(_, _)),
            "first event should be Progress, got: {:?}",
            event
        );
    }

    #[test]
    fn iat_mode_override_rewrites_obfs4_and_leaves_others_alone() {
        let obfs4: BridgeLine =
            "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0"
                .parse()
                .expect("obfs4 line parses");
        let rewritten = with_iat_mode_override(&obfs4, Some(1));
        assert_eq!(
            rewritten.params.get("iat-mode").map(String::as_str),
            Some("1")
        );
        assert!(rewritten.to_string().contains("iat-mode=1"));

        // No override configured: line is untouched.
        assert_eq!(with_iat_mode_override(&obfs4, None), obfs4);

        // webtunnel has no iat-mode concept; it must not gain one.
        let webtunnel: BridgeLine =
            "webtunnel 192.0.2.3:1 2852538D49D7D73C1A6694FC492104983A9C4FA2 url=https://example.com/x"
                .parse()
                .expect("webtunnel line parses");
        assert_eq!(with_iat_mode_override(&webtunnel, Some(1)), webtunnel);
    }

    #[test]
    fn iat_mode_override_adds_the_param_when_the_line_omits_it() {
        let obfs4: BridgeLine =
            "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA"
                .parse()
                .expect("obfs4 line parses");
        let rewritten = with_iat_mode_override(&obfs4, Some(2));
        assert_eq!(
            rewritten.params.get("iat-mode").map(String::as_str),
            Some("2")
        );
    }
}
