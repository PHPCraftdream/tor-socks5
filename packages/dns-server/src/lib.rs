//! Local DNS server: plain wire-format UDP/TCP answers, resolved through
//! public DoH providers with every DoH request tunnelled through the live
//! Tor connection ([`arti_wrapper::TorTunnel::connect`]), plus a TTL-aware
//! on-disk answer cache.
//!
//! Optional (default OFF) companion to the tor-socks5 proxy: clients point
//! their resolver at the local listener, and hostname lookups leave the
//! machine only inside the Tor tunnel — never as plaintext DNS to the
//! local network.
//!
//! Module map:
//!
//! * [`cache`] — on-disk, TTL-aware store of resolved answers;
//! * [`doh_client`] — DNS-over-HTTPS exchanges sent through [`arti_wrapper::TorTunnel`];
//! * [`overrides`] — runtime DNS overrides: operator-listed host masks
//!   resolved directly (plain DNS to a given server, or the OS resolver),
//!   deliberately leaving the Tor tunnel;
//! * [`providers`] — the pool of [`DohProvider`] endpoints;
//! * [`server`] — the UDP/TCP listener tying it all together.
#![warn(missing_docs)]

#[path = "cache/cache.rs"]
pub mod cache;
#[path = "doh/doh_client.rs"]
pub mod doh_client;
#[path = "overrides/overrides.rs"]
pub mod overrides;
#[path = "doh/providers.rs"]
pub mod providers;
#[path = "server/server.rs"]
pub mod server;

#[path = "doh/error.rs"]
mod error;
#[path = "popular_prefetch/popular_prefetch.rs"]
mod popular_prefetch;
#[path = "statistics/query_statistics.rs"]
mod query_statistics;
#[path = "doh/types.rs"]
mod types;

pub use error::DnsServerError;
pub use overrides::{DnsOverride, OverrideResolver};
pub use types::{DohProvider, ResolvedAnswer};
