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
//! * [`providers`] — the pool of [`DohProvider`] endpoints;
//! * [`server`] — the UDP/TCP listener tying it all together.

pub mod cache;
pub mod doh_client;
pub mod providers;
pub mod server;

mod error;
mod types;

pub use error::DnsServerError;
pub use types::{DohProvider, ResolvedAnswer};
