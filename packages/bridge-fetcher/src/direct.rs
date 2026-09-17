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

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use bridge_probe::ResolverPolicy;
use tokio::net::TcpStream;

use crate::error::FetchError;

/// Best-effort seed IPs for the default collateral-freedom bridge sources.
///
/// Tried (dialled) BEFORE any DNS wait as a zero-network-round-trip first
/// attempt, in time as well as in list order: the resolver is only consulted
/// once every pin failed to connect (or there are no pins).
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

/// Connect to the first address that accepts a TCP connection.
///
/// IP-literal shortcut: needs no name resolution at all; no resolver is
/// passed, so a failed literal dial does not fall into DNS either.
pub(crate) async fn connect_direct(
    host: &str,
    port: u16,
    resolver_policy: ResolverPolicy,
) -> Result<TcpStream, FetchError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return connect_dialing_pins(
            host,
            vec![SocketAddr::new(ip, port)],
            // No resolver at all: a failed literal dial must not fall into DNS.
            None::<fn() -> std::future::Pending<Result<Vec<SocketAddr>, String>>>,
        )
        .await;
    }
    connect_dialing_pins(
        host,
        pinned_addrs(host, port),
        Some(move || bridge_probe::resolve_addrs(host, port, resolver_policy)),
    )
    .await
}

/// Dial `pins` first; only once every pin failed to connect (or there are no
/// pins) is the resolver invoked. On pin success the resolver is never
/// awaited, so a known host connects with zero DNS round trips.
///
/// Phase order and budget story: each pin is dialled under its own
/// [`CONNECT_ATTEMPT_TIMEOUT`] bound, then the dynamic (DoH-resolved)
/// addresses are dialled in order. Every `.await` in this function is
/// cancellable and the whole function runs under the caller's outer fetch
/// timeout in `fetch_one_direct` (http.rs), so the caller's budget bounds the
/// total exactly as before -- the code cannot outlive it even if the resolver
/// never completes. Note that on a successful pin dial the DoH resolution is
/// skipped entirely, so this path no longer warms bridge-probe's shared
/// DNS cache either -- which is acceptable because that cache is private to
/// bridge-probe (every reader treats a miss as a normal lookup, and a cold
/// process starts with an empty cache anyway), and for a pinned host a later
/// fetch short-circuits at the pin dial without needing DNS at all.
async fn connect_dialing_pins<F, Fut>(
    host: &str,
    pins: Vec<SocketAddr>,
    resolve: Option<F>,
) -> Result<TcpStream, FetchError>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<Vec<SocketAddr>, String>>,
{
    // Phase 1: pins dial first, in order.
    let mut last_err = None;
    for addr in pins.iter().copied() {
        match dial_one(addr).await {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = Some(e),
        }
    }

    // Phase 2: resolution only runs when no pin accepted a connection.
    // A pin that DOES accept TCP is still untrusted: the fetch proceeds only
    // through the unchanged rustls handshake in http.rs (real cert + SNI for
    // the hostname), so skipping DNS on a connected pin changes latency,
    // never the trust boundary. And because every pin dial failure falls
    // through to the DoH-resolved addresses here, a stale/incomplete pin
    // table degrades to the same reliability as having no pins at all.
    let dynamic = match resolve {
        Some(resolve) => match resolve().await {
            Ok(resolved) => resolved,
            Err(e) if pins.is_empty() => {
                return Err(FetchError::Resolve(format!("{host}: {e}")));
            }
            // Pins existed; a DoH failure alone is not fatal, they were tried.
            Err(_) => Vec::new(),
        },
        None => Vec::new(),
    };

    if pins.is_empty() && dynamic.is_empty() {
        return Err(FetchError::Resolve(format!(
            "{host}: no pinned or DoH-resolved address available"
        )));
    }

    for addr in dynamic {
        match dial_one(addr).await {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = Some(e),
        }
    }
    Err(FetchError::Resolve(format!(
        "{host}: every candidate address failed to connect ({})",
        last_err.unwrap_or_default()
    )))
}

/// One bounded connect attempt. On success returns the stream; on failure an
/// error string naming the address and the reason (refused/unreachable, or
/// the [`CONNECT_ATTEMPT_TIMEOUT`] expiring).
async fn dial_one(addr: SocketAddr) -> Result<TcpStream, String> {
    match tokio::time::timeout(CONNECT_ATTEMPT_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(e)) => Err(format!("{addr}: {e}")),
        Err(_) => Err(format!("{addr}: connect timed out")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    const NO_RESOLVERS: ResolverPolicy = ResolverPolicy {
        doh_enabled: false,
        system_fallback: false,
    };

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
        let policy = NO_RESOLVERS;
        let err = connect_direct("nonexistent.invalid", 443, policy)
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::Resolve(_)));
    }

    #[tokio::test]
    async fn connect_direct_connects_to_ipv4_literal_with_no_dns() {
        // An IP literal needs no name resolution: it must connect even with
        // every resolver disabled.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let stream = connect_direct("127.0.0.1", port, NO_RESOLVERS)
            .await
            .unwrap();
        assert_eq!(stream.peer_addr().unwrap().port(), port);

        // The accept proves a real TCP connect happened, not just "no error".
        let (_sock, peer) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .expect("connection arrives within timeout")
            .expect("accept succeeds");
        assert_eq!(peer.port(), stream.local_addr().unwrap().port());
    }

    #[tokio::test]
    async fn connect_direct_connects_to_ipv6_literal_with_no_dns() {
        let listener = TcpListener::bind("[::1]:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let stream = connect_direct("::1", port, NO_RESOLVERS).await.unwrap();
        assert_eq!(stream.peer_addr().unwrap().port(), port);

        let (_sock, peer) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .expect("connection arrives within timeout")
            .expect("accept succeeds");
        assert_eq!(peer.port(), stream.local_addr().unwrap().port());
    }

    #[tokio::test]
    async fn pin_dial_wins_while_resolver_is_pending() {
        // A pin that accepts TCP must be dialled without ever awaiting the
        // resolver: the pending future below never completes, so completing
        // at all proves the path did not wait for DNS. The 5s wrapper is only
        // a counterfactual tripwire; on correct code this finishes in ms.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let res = tokio::time::timeout(
            Duration::from_secs(5),
            connect_dialing_pins(
                "raw.githubusercontent.com",
                vec![addr],
                Some(std::future::pending::<Result<Vec<SocketAddr>, String>>),
            ),
        )
        .await;
        let stream = res
            .expect("pin dial must not wait for a pending resolver (timed out)")
            .expect("pin dial succeeds");
        assert_eq!(stream.peer_addr().unwrap().port(), addr.port());

        let (_sock, peer) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .expect("connection arrives within timeout")
            .expect("accept succeeds");
        assert_eq!(peer.port(), stream.local_addr().unwrap().port());
    }

    #[tokio::test]
    async fn failed_pins_fall_through_to_dynamic_addresses() {
        // A dead pin (port closed) must degrade to the DoH-resolved
        // addresses, same reliability as having no pins at all.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live_addr = listener.local_addr().unwrap();

        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead); // port now closed -> instant connection-refused on loopback

        let resolver = move || {
            let live = live_addr;
            async move { Ok(vec![live]) }
        };
        let stream = connect_dialing_pins("gitlab.torproject.org", vec![dead_addr], Some(resolver))
            .await
            .expect("dynamic address dial succeeds after pin failure");
        assert_eq!(stream.peer_addr().unwrap().port(), live_addr.port());

        let (_sock, peer) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .expect("connection arrives within timeout")
            .expect("accept succeeds");
        assert_eq!(peer.port(), stream.local_addr().unwrap().port());
    }

    #[tokio::test]
    async fn connect_stays_bounded_by_caller_budget_when_pins_fail_and_resolver_pending() {
        // With every pin dead and a resolver that never completes, the whole
        // call must still be bounded by the caller's outer timeout -- the new
        // phase order cannot outlive the fetch budget.
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);

        let start = std::time::Instant::now();
        let res = tokio::time::timeout(
            Duration::from_secs(2),
            connect_dialing_pins(
                "gitlab.torproject.org",
                vec![dead_addr],
                Some(std::future::pending::<Result<Vec<SocketAddr>, String>>),
            ),
        )
        .await;
        let elapsed = start.elapsed();
        assert!(res.is_err(), "outer caller budget must end the fetch");
        assert!(
            elapsed < Duration::from_secs(4),
            "expected the caller budget (2s) to bound the call, took {elapsed:?}"
        );
    }
}
