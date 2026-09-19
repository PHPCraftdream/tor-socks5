//! Shared value types used across the cache, DoH client, provider pool,
//! and listener.

use std::net::IpAddr;
use std::time::Duration;

use time::OffsetDateTime;

/// One resolved answer, ready to be cached and served to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAnswer {
    /// Addresses the name resolved to.
    pub addrs: Vec<IpAddr>,
    /// Time-to-live reported by the provider; together with `resolved_at`
    /// this bounds how long the answer may be served from cache.
    pub ttl: Duration,
    /// When the answer was received (UTC).
    pub resolved_at: OffsetDateTime,
}

/// One DoH provider: TCP address to reach through Tor, hostname for
/// SNI/HTTP Host, DoH endpoint path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DohProvider {
    /// IP address to open the TCP connection to (through Tor — the name is
    /// never resolved locally).
    pub ip: IpAddr,
    /// Hostname used for TLS SNI and the HTTP Host header.
    pub hostname: String,
    /// Path of the DoH endpoint (e.g. `/dns-query`).
    pub path: String,
}
