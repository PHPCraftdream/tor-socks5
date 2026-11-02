//! DNS-over-HTTPS (DoH) resolver for webtunnel.
//!
//! Webtunnel is the only ptrs-gesher transport whose `bridge-line` carries
//! a domain rather than an IP address (see `url=https://host/path`). System
//! DNS lookups at the moment of TCP dial expose that hostname to the local
//! resolver — and, by extension, to a censor able to inspect or hijack DNS
//! traffic. This module routes the hostname resolution through DoH instead,
//! using a curated pool of public DoH endpoints with **bootstrap IP
//! addresses** so the resolver itself never depends on system DNS.
//!
//! See the `endpoints` submodule (crate-private) for the curated pool and
//! [`DohMode`] for the operating modes (`Off` / `Strict` / `Fallback`).

// The DoH machinery (curated pool + resolver) is wired into the webtunnel
// connect path in a follow-up commit. Suppress dead-code warnings on the
// whole module until then; remove this attribute once the resolver is
// actually consumed from `handshake::connect`.
#![allow(dead_code, unused_imports)]

pub(crate) mod endpoints;
mod resolver;

// Public re-export so `WebTunnelConfig::doh_mode` and
// `WebTunnelConfig::with_doh_mode` can name the type without leaking
// the rest of the resolver module.
pub use resolver::DohMode;
pub(crate) use resolver::DohResolver;
