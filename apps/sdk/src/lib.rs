//! One dependency for the tor-socks5 libraries.
//!
//! A facade: every module is the workspace crate of the same name re-exported
//! whole, so nothing here is copied or wrapped and the crates keep their own
//! versions, tests and docs. Features pick which crates are linked; the
//! default set is Tor-free.
//!
//! | Module | Crate | Feature |
//! |---|---|---|
//! | [`persist`] | `persist-lock` | always on |
//! | [`proto`] | `tor-socks5-proto` | `socks5` |
//! | [`acl`] | `tor-socks5-client-acl` | `acl` |
//! | [`route`] | `tor-socks5-route-pool` | `route` |
//! | [`auth`] | `tor-socks5-auth` | `auth` |
//! | [`config`] | `tor-socks5-config` | `config` |
//! | [`probe`], [`store`], [`verify`] | `bridge-probe`, `bridge-store`, `bridge-verify-core` | `bridges` |
//! | [`tor`] | `arti-wrapper` | `tor` |
//! | [`fetch`] | `bridge-fetcher` | `fetch` |
//! | [`dns`] | `tor-socks5-dns` | `dns` |
//! | [`onion`] | `tor-socks5-onion` | `onion`, `onion-keys`, `onion-host` |
//! | [`runtime`] | `tor-socks5-runtime` — the curated SDK-7/8/9 surfaces, not the whole crate | `runtime` |
//!
//! The `tor` feature (and `fetch`, `dns`, `runtime`, `onion-service`,
//! `full`, which imply it) links Arti. Without the vendored forks of the patch-kit a
//! consumer gets stock Arti and silently loses their fixes; see the SDK guide
//! (`apps/sdk/README.md`) for the `[patch.crates-io]` block.

#![warn(missing_docs)]

/// Cross-process file locks and atomic saves (`persist-lock`).
pub use ::persist_lock as persist;

/// SOCKS5 and HTTP CONNECT server framing (`tor-socks5-proto`).
#[cfg(feature = "socks5")]
pub use ::socks5_proto as proto;

/// Client address rules and proxy pools (`tor-socks5-client-acl`).
#[cfg(feature = "acl")]
pub use ::client_acl as acl;

/// Rotation of proxy pools: sticky choice, failover, quarantine (`tor-socks5-route-pool`).
#[cfg(feature = "route")]
pub use ::route_pool as route;

/// SOCKS5 accounts and the Argon2id authenticator (`tor-socks5-auth`).
#[cfg(feature = "auth")]
pub use ::auth;

/// The Ktav settings schema (`tor-socks5-config`).
#[cfg(feature = "config")]
pub use ::proxy_config as config;

/// Bridge reachability probing and DNS for bridge hosts (`bridge-probe`).
#[cfg(feature = "bridges")]
pub use ::bridge_probe as probe;

/// Bridge health kept between restarts (`bridge-store`).
#[cfg(feature = "bridges")]
pub use ::bridge_store as store;

/// Pluggable-transport process reaping and cache snapshots (`bridge-verify-core`).
#[cfg(feature = "bridges")]
pub use ::bridge_verify_core as verify;

/// The Tor tunnel: bootstrap, bridges, streams, proxy routes (`arti-wrapper`).
#[cfg(feature = "tor")]
pub use ::arti_wrapper as tor;

/// Fetching bridge lists over Tor or directly (`bridge-fetcher`).
#[cfg(feature = "fetch")]
pub use ::bridge_fetcher as fetch;

/// A local DNS resolver that asks over Tor (`tor-socks5-dns`).
#[cfg(feature = "dns")]
pub use ::dns_server as dns;

/// v3 onion addresses and the vanity prefix search, without Tor
/// (`tor-socks5-onion`).
///
/// Behind the `onion-keys` feature the crate also carries the service
/// identity keys and keystore of the Arti native keystore: `onion::keys`
/// (`create_service`, `import_identity`, `export_identity`, …), with no Tor
/// client linked.
///
/// Behind the Tor-dependent `onion-host` feature it also carries the hosted
/// onion-service manager: `onion::host` (`OnionHost`, `OnionHostHandle`,
/// `OnionHostStatus`), with the keystore directory and services-file path as
/// explicit arguments and a cancellation token for shutdown.
#[cfg(any(feature = "onion", feature = "onion-keys", feature = "onion-host"))]
pub use ::tor_socks5_onion as onion;

/// The embedded Tor runtime (`tor-socks5-runtime`, `apps/sdk/crates/runtime`),
/// curated by module — this is not the whole crate. Three surfaces are open
/// so far (SDK-7, SDK-8, SDK-9); the proxy server (SDK-10/11) is not
/// exposed yet.
///
/// Nothing here installs process state on its own (R1): the bridge-health
/// writer slot ([`init_global`]/[`close_global`]: one live writer per
/// process, sequential restart works) is driven by the application, and
/// [`observation_layer`] is a tracing layer for the application's own log
/// subscriber; the runtime never sets a subscriber.
///
/// **Bridge health and observation (SDK-7):**
///
/// ```no_run
/// use tor_socks5::runtime::{init_global, observation_layer, ObservationSink};
/// use tracing_subscriber::layer::SubscriberExt;
/// use tracing_subscriber::util::SubscriberInitExt;
///
/// let _writer = init_global(Some(std::path::Path::new("tor-socks5.ktav")));
/// let sink = ObservationSink::new();
/// let fmt_layer = tracing_subscriber::fmt::layer();
/// tracing_subscriber::registry()
///     .with(fmt_layer)
///     .with(observation_layer(&sink))
///     .init();
/// ```
///
/// **Tor client (SDK-9):**
///
/// - [`runtime::tor_setup`] — Tor client settings built from the ktav
///   config (`build_tor_settings`, `build_tor_settings_with_pt`), the arti
///   state dir (`arti_base_dir`) and the owner-routing relatives.
/// - [`runtime::pt`] — the pluggable-transport entry point for an embedding
///   host (`PtBinary`): environment-resolved (the CLI binary's busybox
///   dispatch, `TOR_PT_BINARY` override) or an explicit dispatcher path.
/// - [`runtime::tor_watchdog`] — the live-client handle (`TorHandle`,
///   `TorHealth`), the watchdog spawn/status surface (`WatchdogRun`,
///   `WatchdogStatus`) and failure classification.
/// - [`runtime::conn_health`] — connection-health counters and windowed
///   snapshots.
///
/// **Bridge manager (SDK-8):**
///
/// - [`runtime::start`] — spawn the runtime-owned bridge producers
///   (maintenance, plus the warmer and circuit verifier when enabled) and
///   get a [`runtime::BridgeManagerHandle`] (`token`, `status`,
///   `subscribe`, `shutdown().await`). One live manager per process (D5);
///   await `shutdown()` before `close_global` so in-flight store writes
///   land.
/// - [`runtime::fetch_bridges`] — the `bridges fetch` core
///   ([`runtime::FetchBridgesParams`], [`runtime::FetchBridgesOutcome`]):
///   bootstrap Tor, refresh the candidate pool, optionally probe and
///   promote into the config. Not cancel-safe; see the crate docs.
///
/// This feature links Arti: without the patch-kit (`[patch.crates-io]` in
/// your final binary/workspace root, see the SDK guide in README.md and
/// `vendor/README.md`) stock Arti is resolved and the fixes are lost.
#[cfg(feature = "runtime")]
pub mod runtime {
    /// Connection-health counters and snapshots (`tor-socks5-runtime::conn_health`).
    pub use ::tor_socks5_runtime::conn_health;
    /// Pluggable-transport binary resolution (`tor-socks5-runtime::pt`).
    pub use ::tor_socks5_runtime::pt;
    /// Tor client settings built from the config file (`tor-socks5-runtime::tor_setup`).
    pub use ::tor_socks5_runtime::tor_setup;
    /// The live-client handle and the watchdog surface (`tor-socks5-runtime::tor_watchdog`).
    pub use ::tor_socks5_runtime::tor_watchdog;

    /// The bridge-health writer: the [`StoreWriter`] handle (`apply`,
    /// `close`) and the process-wide `init_global`/`close_global` slot
    /// (one live writer per process, sequential restart works).
    pub use ::tor_socks5_runtime::bridge_store_writer::{close_global, init_global, StoreWriter};

    /// Guard-event observation: [`observation_layer`] for the
    /// application's subscriber, the shared [`ObservationSink`], and the
    /// observation and layer types.
    pub use ::tor_socks5_runtime::arti_observability::{
        observation_layer, GuardObservabilityLayer, GuardObservation, ObservationSink,
    };

    /// The bridge manager (SDK-8): [`start`] owns the background bridge
    /// producers (one live manager per process, D5), [`BridgeManagerHandle`]
    /// reports status and joins them at shutdown; [`fetch_bridges`] is the
    /// `bridges fetch` core.
    pub use ::tor_socks5_runtime::bridge_manager::{
        fetch_bridges, start, BridgeManagerHandle, BridgeManagerStatus, FetchBridgesOutcome,
        FetchBridgesParams,
    };
}
