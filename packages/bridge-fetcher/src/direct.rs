//! Direct (non-Tor) TCP connection for the cold-start fetch path.
//!
//! `fetch_all`/`fetch_one` always route through an already-bootstrapped
//! `TorTunnel`. That is unusable at a true cold start where zero configured
//! bridges are reachable at all -- there is no tunnel yet to route through,
//! so the collateral-freedom bridge sources (GitHub/GitLab raw URLs) can
//! never be reached even though `auto_fetch` is enabled. This module gives
//! that one narrow case a way to resolve and connect without Tor, using
//! `bridge-probe`'s existing DoH pool instead of the OS resolver (the same
//! reasoning as `ResolverPolicy` itself: a censored network's own resolver is
//! not to be trusted).

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use bridge_probe::ResolverPolicy;
use tokio::net::TcpStream;

use crate::error::FetchError;

/// Best-effort seed IPs for the default collateral-freedom bridge sources.
///
/// Tried before DoH resolution as a zero-network-round-trip first attempt.
/// NOT authoritative: a stale or wrong entry simply fails to connect and
/// falls through to DoH, same as any other unreachable address -- nothing
/// here is trusted without the TLS handshake (real cert, real SNI) that
/// follows in `http.rs`. Verified reachable via DoH lookup on 2026-08-27;
/// Fastly's GitHub Pages range (185.199.108-111.0/24) has been stable for
/// years and is shared by millions of unrelated `*.github.io` sites.
const KNOWN_HOST_PINS: &[(&str, &[&str])] = &[
    (
        "raw.githubusercontent.com",
        &[
            "185.199.108.133",
            "185.199.109.133",
            "185.199.110.133",
            "185.199.111.133",
        ],
    ),
    ("gitlab.torproject.org", &["204.8.99.149"]),
];

/// Per-address connect attempt budget. Several candidates may need trying
/// (pins, then DoH answers); keep each one short so a dead address does not
/// dominate the caller's overall fetch timeout.
const CONNECT_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);

fn pinned_addrs(host: &str, port: u16) -> Vec<SocketAddr> {
    KNOWN_HOST_PINS
        .iter()
        .find(|(h, _)| *h == host)
        .map(|(_, ips)| {
            ips.iter()
                .filter_map(|ip| ip.parse::<IpAddr>().ok())
                .map(|ip| SocketAddr::new(ip, port))
                .collect()
        })
        .unwrap_or_default()
}

/// Resolve `host` (pins first, then the DoH pool) and connect to the first
/// address that accepts a TCP connection.
pub(crate) async fn connect_direct(
    host: &str,
    port: u16,
    resolver_policy: ResolverPolicy,
) -> Result<TcpStream, FetchError> {
    let mut candidates = pinned_addrs(host, port);

    // Pins are a shortcut, not a substitute: always also resolve via DoH so a
    // stale/incomplete pin table degrades to the same reliability as having
    // no pins at all, rather than to a hard failure.
    match bridge_probe::resolve_addrs(host, port, resolver_policy).await {
        Ok(resolved) => candidates.extend(resolved),
        Err(e) if candidates.is_empty() => {
            return Err(FetchError::Resolve(format!("{host}: {e}")));
        }
        Err(_) => {
            // Pins exist; a DoH failure alone is not fatal, try them anyway.
        }
    }

    if candidates.is_empty() {
        return Err(FetchError::Resolve(format!(
            "{host}: no pinned or DoH-resolved address available"
        )));
    }

    let mut last_err = None;
    for addr in candidates {
        match tokio::time::timeout(CONNECT_ATTEMPT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => last_err = Some(format!("{addr}: {e}")),
            Err(_) => last_err = Some(format!("{addr}: connect timed out")),
        }
    }
    Err(FetchError::Resolve(format!(
        "{host}: every candidate address failed to connect ({})",
        last_err.unwrap_or_default()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_pins_cover_the_default_source_hosts() {
        assert_eq!(
            pinned_addrs("raw.githubusercontent.com", 443).len(),
            4,
            "expected all four Fastly addresses"
        );
        assert_eq!(pinned_addrs("gitlab.torproject.org", 443).len(), 1);
    }

    #[test]
    fn unknown_host_has_no_pins() {
        assert!(pinned_addrs("example.com", 443).is_empty());
    }

    #[tokio::test]
    async fn connect_direct_fails_cleanly_for_an_unroutable_host_with_no_dns() {
        // A host with no pins and no real DNS record must produce a Resolve
        // error, not a panic or a hang past the connect-attempt timeout.
        let policy = ResolverPolicy {
            doh_enabled: false,
            system_fallback: false,
        };
        let err = connect_direct("nonexistent.invalid", 443, policy)
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::Resolve(_)));
    }
}
