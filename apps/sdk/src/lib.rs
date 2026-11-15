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
//! | [`runtime`] | `tor-socks5-runtime` (SDK-7 surface) | `runtime` |
//! | [`onion`] | `tor-socks5-onion` | `onion`, `onion-keys` |
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
#[cfg(any(feature = "onion", feature = "onion-keys"))]
pub use ::tor_socks5_onion as onion;

/// The embedded Tor runtime (`tor-socks5-runtime`), opened step by step
/// as the SDK plan's API tasks land. This is the SDK-7 surface: the
/// bridge-health writer and the guard-event observation layer. The Tor
/// client setup, the bridge manager and the server are not exposed yet
/// (SDK-8/9/10).
///
/// Nothing here installs process state on its own (R1):
/// [`init_global`]/[`close_global`] are the documented process-wide
/// writer slot the application drives — one live writer per process,
/// sequential restart works — and [`observation_layer`] is a tracing
/// layer for the application's own log subscriber; the runtime never
/// sets a subscriber.
///
/// ```no_run
/// use tor_socks5::runtime::{init_global, observation_layer, ObservationSink};
/// use tracing_subscriber::layer::SubscriberExt;
///
/// let _writer = init_global(Some(std::path::Path::new("tor-socks5.ktav")));
/// let sink = ObservationSink::new();
/// let fmt_layer = tracing_subscriber::fmt::layer();
/// tracing_subscriber::registry()
///     .with(fmt_layer)
///     .with(observation_layer(&sink))
///     .init();
/// ```
#[cfg(feature = "runtime")]
pub mod runtime {
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
}
