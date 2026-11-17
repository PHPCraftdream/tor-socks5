//! One dependency for the tor-socks5 libraries.
//!
//! A facade over selected workspace APIs. Most leaf-library modules are
//! re-exported whole; the runtime and embedded-server modules are curated
//! surfaces. Features pick which crates are linked; the default set is Tor-free.
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
//! | [`pt`] | `tor-socks5-runtime` — managed-transport PT dispatch | `pt` |
//! | [`server`] | `tor-socks5-server` — the curated embedded server API | `server` |
//!
//! The `tor` feature (and `fetch`, `dns`, `runtime`, `server`, `onion-service`,
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

/// Install the process-wide rustls crypto provider. rustls 0.23 requires an
/// explicit provider; call this once, before any Tor client bootstraps —
/// a fresh state dir fails its TLS setup without it. The SDK never installs
/// process state on its own (R1): the host does.
#[cfg(feature = "runtime")]
pub use ::tor_socks5_runtime::host::install_crypto_provider;

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
/// curated as a flat surface — this is not the whole crate. It exposes the
/// selected Tor setup, PT, watchdog, and connection-health APIs, alongside
/// the bridge-health writer, observation, and manager APIs (SDK-7/8/9). The
/// embedded server is available through [`server`] (SDK-11).
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
/// - [`runtime::arti_base_dir`] and [`runtime::arti_keystore_dir`],
///   [`runtime::build_tor_settings`], and [`runtime::build_tor_settings_with_pt`]
///   construct the Arti paths and client settings from the config and PT
///   policy. The keystore path is exposed for host-managed onion-service keys.
/// - [`runtime::PtBinary`] is the pluggable-transport entry point for an
///   embedding host: environment-resolved (the CLI binary's busybox
///   dispatch, `TOR_PT_BINARY` override) or an explicit dispatcher path.
/// - [`runtime::TorHandle`], [`runtime::TorHealth`],
///   [`runtime::BridgeRefresh`], [`runtime::WatchdogRun`],
///   [`runtime::WatchdogStatus`], and [`runtime::HealOutcome`] provide the
///   live-client handle, refresh signaling, watchdog status, and failure
///   classification. The watchdog spawn functions and
///   [`runtime::classify_and_record`] are exported at the same flat level.
/// - [`runtime::ConnHealthCounters`], [`runtime::ConnHealthSnapshot`],
///   [`runtime::PendingConnectionGuard`], [`runtime::ConnStage`],
///   [`runtime::ConnErrorKind`], [`runtime::spawn_conn_health_logger`], and
///   [`runtime::run_conn_health_logger`] expose connection-health counters and
///   windowed snapshots.
///
/// These functions take [`runtime::WatchdogConfig`] and
/// [`runtime::ConnHealthConfig`] where applicable. [`runtime::TorError`] is
/// the error type accepted by [`runtime::classify_and_record`].
///
/// **Bridge manager (SDK-8):**
///
/// - [`runtime::start`] owns the standalone bridge producers;
///   [`runtime::start_with_parent_token`] composes them under a caller's
///   cancellation tree. [`runtime::BridgeManagerHandle`] exposes typed status
///   subscription and async shutdown; await shutdown before closing the writer.
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
    /// Tor error accepted by [`classify_and_record`].
    pub use ::arti_wrapper::TorError;
    /// Configuration types used by the runtime spawn functions.
    pub use ::proxy_config::{ConnHealthConfig, WatchdogConfig};
    /// Connection-health counters and their periodic logger.
    pub use ::tor_socks5_runtime::conn_health::{
        run_conn_health_logger, spawn_conn_health_logger, ConnErrorKind, ConnHealthCounters,
        ConnHealthSnapshot, ConnStage, PendingConnectionGuard,
    };
    /// Pluggable-transport executable policy.
    pub use ::tor_socks5_runtime::pt::PtBinary;
    /// Tor state-directory, keystore, and settings constructors.
    pub use ::tor_socks5_runtime::tor_setup::{
        arti_base_dir, arti_keystore_dir, build_tor_settings, build_tor_settings_with_pt,
    };
    /// Live Tor handle, watchdog, and failure-classification API.
    pub use ::tor_socks5_runtime::tor_watchdog::{
        classify_and_record, spawn_bridge_failover_watchdog, spawn_tor_watchdog, BridgeRefresh,
        HealOutcome, TorHandle, TorHealth, WatchdogRun, WatchdogStatus,
    };

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
        fetch_bridges, start, start_with_parent_token, BridgeManagerConfig, BridgeManagerHandle,
        BridgeManagerStatus, FetchBridgesError, FetchBridgesOutcome, FetchBridgesParams,
    };

    pub use ::tokio_util::sync::CancellationToken;
    /// Shared producer launch for embedding hosts: wires the bridge-refresh
    /// signaling (recovery notifier, `set_needed(auto_fetch &&
    /// preferred_missing)`) and spawns the bridge manager plus the
    /// stale-channel/soft-failover watchdogs into a caller-owned task vector.
    pub use ::tor_socks5_runtime::bridge_producers::launch_producers;

    pub use ::tor_socks5_runtime::host::bind_child_processes_to_self;
    /// Host-process initialisation for an embedding application:
    /// [`bind_child_processes_to_self`] (on Windows, put spawned children —
    /// the lyrebird PT — in a `KILL_ON_JOB_CLOSE` Job Object so they die
    /// with the host process; a documented no-op elsewhere) and [`log_layer`]
    /// (build the tracing fmt layer from a [`LogConfig`](crate::config::LogConfig)
    /// together with its non-blocking writer's guard, without installing a
    /// global subscriber).
    pub use ::tor_socks5_runtime::host::logging::log_layer;
}

/// Pluggable-transport dispatch for an embedding host: when arti spawns
/// this process as a managed transport, run the in-process lyrebird PT
/// loop. See [`pt::run_if_managed_transport`].
#[cfg(feature = "pt")]
pub mod pt {
    pub use ::tor_socks5_runtime::pt::run_if_managed_transport;
}

/// Embedded SOCKS5/HTTP CONNECT server API (`tor-socks5-server`), curated to
/// the builder, running handle, lifecycle stage/status and error types. Requires `server`;
/// the same feature also enables the `runtime` and `onion-service` features.
#[cfg(feature = "server")]
pub mod server {
    pub use ::tor_socks5_server::{
        DnsStartupPolicy, PtBinary, Server, ServerBuilder, ServerError, ServerHandle, ServerStage,
        ServerStatus,
    };
}
