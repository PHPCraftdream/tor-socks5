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
use arti_client::config::{BridgeConfigBuilder, CfgPath, TorClientConfigBuilder};
use arti_client::{DataStream, TorClient, TorClientConfig};
use bridge_line::BridgeLine;
use tor_rtcompat::PreferredRuntime;

#[derive(Debug, thiserror::Error)]
pub enum TorError {
    #[error("failed to bootstrap Tor client: {0}")]
    Bootstrap(#[source] arti_client::Error),

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
}

pub type Result<T, E = TorError> = std::result::Result<T, E>;

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
}

impl Settings {
    pub fn is_default(&self) -> bool {
        self.bridges.is_empty() && self.pt_binary.is_none()
    }
}

/// Tor tunnel client. Cheap to clone (uses `Arc` internally).
#[derive(Clone)]
pub struct TorTunnel {
    inner: Arc<TorClient<PreferredRuntime>>,
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
        let client = TorClient::create_bootstrapped(config)
            .await
            .map_err(TorError::Bootstrap)?;
        tracing::info!("Tor is ready");
        Ok(Self { inner: client })
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
        // Mirrors `TorClient::create_bootstrapped`'s own runtime lookup,
        // including its panic-on-no-runtime `.expect(...)` semantics — this
        // app always runs inside a tokio runtime, so that's consistent, not
        // a new risk.
        let runtime = PreferredRuntime::current().expect(
            "TorClient could not get an asynchronous runtime; are you running in the right context?",
        );
        let client = TorClient::with_runtime(runtime)
            .config(config)
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

    if !settings.bridges.is_empty() {
        for line in &settings.bridges {
            let serialized = line.to_string();
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
        };
        let cfg = build_config(&s);
        assert!(
            cfg.is_ok(),
            "mixed transports should work with a valid pt_binary"
        );
    }
}
