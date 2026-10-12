//! Unified error type for the DNS server crate.

use std::time::Duration;

use thiserror::Error;

/// Everything that can go wrong while resolving a query over Tor-DoH or
/// serving it from cache.
#[derive(Debug, Error)]
pub enum DnsServerError {
    /// Opening the connection to a DoH provider through the Tor tunnel failed.
    #[error("tor connect to DoH provider failed: {0}")]
    TorConnect(String),
    /// The TLS handshake with a DoH provider failed.
    #[error("tls handshake with DoH provider failed: {0}")]
    Tls(String),
    /// The DoH HTTP exchange failed (bad status, malformed body, ...).
    #[error("doh exchange failed: {0}")]
    DohExchange(String),
    /// A DNS message could not be encoded or decoded.
    #[error("dns wire-format error: {0}")]
    Wire(String),
    /// Reading or writing the on-disk cache failed.
    #[error("cache {op}: {source}")]
    CacheIo {
        /// What the cache was doing (e.g. `"load"`, `"save"`).
        op: &'static str,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// A plain (direct, non-Tor, non-DoH) UDP/TCP DNS exchange with an
    /// override server failed.
    #[error("plain dns exchange failed: {0}")]
    PlainDns(String),
    /// The operating-system resolver lookup (hickory-resolver system
    /// configuration) failed.
    #[error("system resolver failed: {0}")]
    SystemResolver(String),
    /// Every configured DoH provider failed (or the pool is empty).
    #[error("all DoH providers failed")]
    AllProvidersFailed,
    /// The query did not complete within its deadline.
    #[error("timeout after {0:?}")]
    Timeout(Duration),
}
