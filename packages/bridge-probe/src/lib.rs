//! Parallel reachability probe for a list of bridges.
//!
//! Arti's guard manager picks one bridge at a time, retries it with long
//! back-offs, and only then moves on — fine for stability, bad for cold
//! start when half the configured bridges are dead. We probe TCP
//! reachability of every bridge in parallel, then hand arti the list of
//! responders sorted by latency, so the fastest live bridge becomes the
//! first one arti tries.
//!
//! For most transports the TCP target is `bridge.addr`, but webtunnel
//! is special: the bridge-line `<addr>:<port>` is cosmetic and the real
//! target lives in the `url=` parameter (with an optional `addr=` override).
//! `resolve_probe_target` computes the correct `(host, port)` pair per
//! transport before the TCP handshake.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bridge_line::BridgeLine;
use futures::stream::{self, StreamExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Outcome of probing a single bridge.
#[derive(Debug, Clone)]
pub enum Outcome {
    Reachable { latency: Duration },
    Unreachable { reason: String },
}

#[derive(Debug, Clone)]
pub struct Report {
    pub bridge: BridgeLine,
    pub outcome: Outcome,
}

impl Report {
    pub fn is_reachable(&self) -> bool {
        matches!(self.outcome, Outcome::Reachable { .. })
    }

    pub fn latency(&self) -> Option<Duration> {
        match &self.outcome {
            Outcome::Reachable { latency } => Some(*latency),
            Outcome::Unreachable { .. } => None,
        }
    }
}

/// Determine the `(host, port)` pair that should be probed for a given
/// bridge, based on its transport type.
///
/// - No transport or `obfs4` → `bridge.addr`.
/// - `webtunnel` → `addr=` param if present, otherwise the host:port from
///   the `url=` param (defaulting port to 443 for `https://`, 80 for
///   `http://`).
/// - Any other unrecognised transport → fall back to `bridge.addr`.
fn resolve_probe_target(bridge: &BridgeLine) -> Result<(String, u16), String> {
    match bridge.transport.as_deref() {
        None | Some("obfs4") => Ok((bridge.addr.ip().to_string(), bridge.addr.port())),
        Some("webtunnel") => webtunnel_probe_target(&bridge.params),
        _ => Ok((bridge.addr.ip().to_string(), bridge.addr.port())),
    }
}

/// Extract the probe target from webtunnel bridge-line params.
///
/// Priority: `addr=` param wins over URL host:port. The URL's port
/// defaults to 443 for `https://` and 80 for `http://`.
///
/// Keep in sync with `vendor/ptrs/crates/webtunnel/src/lib.rs`
/// (`WebTunnelConfig::connect_host_port`).
fn webtunnel_probe_target(params: &BTreeMap<String, String>) -> Result<(String, u16), String> {
    if let Some(addr) = params.get("addr") {
        let socket: SocketAddr = addr
            .parse()
            .map_err(|e| format!("invalid addr={addr:?}: {e}"))?;
        return Ok((socket.ip().to_string(), socket.port()));
    }

    let url_str = params
        .get("url")
        .ok_or_else(|| "webtunnel bridge missing both url= and addr=".to_string())?;

    let parsed = url::Url::parse(url_str).map_err(|e| format!("invalid url={url_str:?}: {e}"))?;

    let host = parsed
        .host_str()
        .ok_or_else(|| format!("url={url_str:?} has no host"))?;

    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| format!("url={url_str:?} has no port and an unrecognised scheme"))?;

    Ok((host.to_string(), port))
}

/// Resolve the probe target for `bridge`, then perform a TCP handshake.
/// DNS resolution (when needed) shares the same `per_bridge_timeout` budget
/// as the TCP probe itself.
async fn resolve_and_probe(bridge: &BridgeLine, per_bridge_timeout: Duration) -> Outcome {
    let (host, port) = match resolve_probe_target(bridge) {
        Ok(v) => v,
        Err(reason) => return Outcome::Unreachable { reason },
    };

    let addr = if let Ok(a) = host.parse::<SocketAddr>() {
        a
    } else {
        match timeout(per_bridge_timeout, resolve_addr(&host, port)).await {
            Ok(Ok(a)) => a,
            Ok(Err(reason)) => return Outcome::Unreachable { reason },
            Err(_) => {
                return Outcome::Unreachable {
                    reason: format!("DNS resolution timed out after {per_bridge_timeout:?}"),
                }
            }
        }
    };

    tcp_probe(addr, per_bridge_timeout).await
}

/// Resolve a `(host, port)` pair to a `SocketAddr` via DNS.
/// Takes the first address returned by the resolver.
async fn resolve_addr(host: &str, port: u16) -> Result<SocketAddr, String> {
    let host_port = format!("{host}:{port}");
    let mut addrs = tokio::net::lookup_host(&host_port)
        .await
        .map_err(|e| format!("DNS lookup failed for {host_port}: {e}"))?;
    addrs
        .next()
        .ok_or_else(|| format!("DNS lookup returned no addresses for {host_port}"))
}

/// Perform a single TCP reachability probe against `addr` within the
/// per-bridge timeout budget.
async fn tcp_probe(addr: SocketAddr, per_bridge_timeout: Duration) -> Outcome {
    let started = Instant::now();
    match timeout(per_bridge_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(_)) => Outcome::Reachable {
            latency: started.elapsed(),
        },
        Ok(Err(e)) => Outcome::Unreachable {
            reason: e.to_string(),
        },
        Err(_) => Outcome::Unreachable {
            reason: format!("timed out after {per_bridge_timeout:?}"),
        },
    }
}

/// Cap on simultaneous in-flight TCP probes — absorbs a large fetched
/// bridge list without exhausting the per-process file-descriptor budget.
const MAX_INFLIGHT_PROBES: usize = 64;

/// Probe every bridge in `bridges` concurrently. Each probe is bounded by
/// `per_bridge_timeout`. At most [`MAX_INFLIGHT_PROBES`] probes are in
/// flight at any time. The returned vector is **not** guaranteed to
/// preserve input order.
pub async fn probe_all(bridges: Vec<BridgeLine>, per_bridge_timeout: Duration) -> Vec<Report> {
    stream::iter(bridges)
        .map(|bridge| async move {
            let outcome = resolve_and_probe(&bridge, per_bridge_timeout).await;
            Report { bridge, outcome }
        })
        .buffer_unordered(MAX_INFLIGHT_PROBES)
        .collect()
        .await
}

/// Convenience helper: probe, log a summary, and return only reachable
/// bridges as `(bridge, latency)` pairs sorted by ascending latency
/// (fastest first). When no bridge responds, returns an empty vector —
/// callers decide what to do.
pub async fn probe_and_sort(
    bridges: Vec<BridgeLine>,
    per_bridge_timeout: Duration,
) -> Vec<(BridgeLine, Duration)> {
    let reports = probe_all(bridges, per_bridge_timeout).await;
    summarise(&reports);

    let mut alive: Vec<(BridgeLine, Duration)> = reports
        .into_iter()
        .filter_map(|r| match r.outcome {
            Outcome::Reachable { latency } => Some((r.bridge, latency)),
            Outcome::Unreachable { .. } => None,
        })
        .collect();

    alive.sort_by_key(|(_, latency)| *latency);
    alive
}

/// Probe a single bridge: `Some(latency)` if its (transport-resolved) TCP
/// target answers within `per_bridge_timeout`, `None` otherwise. The lazy
/// pool-drainer uses this to walk candidates one at a time while deciding,
/// per bridge, whether to promote (alive) or discard (dead).
pub async fn probe_one(bridge: &BridgeLine, per_bridge_timeout: Duration) -> Option<Duration> {
    match resolve_and_probe(bridge, per_bridge_timeout).await {
        Outcome::Reachable { latency } => Some(latency),
        Outcome::Unreachable { .. } => None,
    }
}

/// Probe `bridges` **sequentially** — one at a time, no concurrent burst —
/// and return the live ones, stopping as soon as `target` live bridges are
/// found or `max_attempts` probes have been made (whichever comes first).
/// Live results are returned in the order they were found.
///
/// This is the *lazy* counterpart to [`probe_and_sort`]: when topping up
/// from a large fetched list (thousands of candidates), hammering the whole
/// list at once would be a network flood. Instead we walk the candidates
/// one by one and bail out the moment we have enough — typically after only
/// a handful of probes, since live bridges are common near the top of a
/// fresh list. `max_attempts` bounds the worst case when few are alive.
pub async fn probe_until(
    bridges: Vec<BridgeLine>,
    per_bridge_timeout: Duration,
    target: usize,
    max_attempts: usize,
) -> Vec<(BridgeLine, Duration)> {
    let mut live: Vec<(BridgeLine, Duration)> = Vec::new();
    if target == 0 {
        return live;
    }
    let mut attempts = 0usize;
    let mut dead = 0usize;
    for bridge in bridges {
        if live.len() >= target || attempts >= max_attempts {
            break;
        }
        attempts += 1;
        match resolve_and_probe(&bridge, per_bridge_timeout).await {
            Outcome::Reachable { latency } => {
                tracing::debug!(
                    addr = %bridge.addr,
                    transport = ?bridge.transport,
                    latency_ms = latency.as_millis() as u64,
                    "bridge reachable (lazy probe)"
                );
                live.push((bridge, latency));
            }
            Outcome::Unreachable { reason } => {
                dead += 1;
                tracing::trace!(addr = %bridge.addr, reason = %reason, "bridge unreachable (lazy probe)");
            }
        }
    }
    tracing::info!(
        found = live.len(),
        target,
        attempts,
        dead,
        "lazy bridge probe done"
    );
    live
}

fn summarise(reports: &[Report]) {
    let total = reports.len();
    let alive = reports.iter().filter(|r| r.is_reachable()).count();
    tracing::info!(
        total,
        alive,
        dead = total - alive,
        "bridge reachability probe done"
    );
    for r in reports {
        match &r.outcome {
            Outcome::Reachable { latency } => tracing::info!(
                addr = %r.bridge.addr,
                transport = ?r.bridge.transport,
                latency_ms = latency.as_millis() as u64,
                "bridge reachable"
            ),
            Outcome::Unreachable { reason } => tracing::warn!(
                addr = %r.bridge.addr,
                transport = ?r.bridge.transport,
                reason = %reason,
                "bridge unreachable"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bridge_line::BridgeLine;
    use std::str::FromStr;
    use tokio::net::TcpListener;

    fn bridge_for(addr: std::net::SocketAddr) -> BridgeLine {
        BridgeLine::from_str(&format!(
            "obfs4 {addr} ABCDEF0123456789ABCDEF0123456789ABCDEF01"
        ))
        .expect("synthetic bridge line parses")
    }

    #[tokio::test]
    async fn reports_alive_bridge_as_reachable() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let reports = probe_all(vec![bridge_for(addr)], Duration::from_secs(2)).await;
        assert_eq!(reports.len(), 1);
        assert!(reports[0].is_reachable());
        assert!(reports[0].latency().unwrap() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn reports_closed_port_as_unreachable() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let reports = probe_all(vec![bridge_for(addr)], Duration::from_secs(2)).await;
        assert_eq!(reports.len(), 1);
        assert!(!reports[0].is_reachable());
    }

    #[tokio::test]
    async fn probe_and_sort_orders_by_latency_and_drops_dead() {
        let live = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live_addr = live.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = live.accept().await;
        });

        let dead_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead_listener.local_addr().unwrap();
        drop(dead_listener);

        let alive = probe_and_sort(
            vec![bridge_for(dead_addr), bridge_for(live_addr)],
            Duration::from_secs(2),
        )
        .await;

        assert_eq!(alive.len(), 1);
        assert_eq!(alive[0].0.addr, live_addr);
    }

    #[tokio::test]
    async fn probe_until_stops_at_target() {
        // Two live listeners; target=1 must stop after finding the first
        // live one (it should not probe both).
        let l1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a1 = l1.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = l1.accept().await;
        });
        let l2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a2 = l2.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = l2.accept().await;
        });

        let live = probe_until(
            vec![bridge_for(a1), bridge_for(a2)],
            Duration::from_secs(2),
            1,
            100,
        )
        .await;
        assert_eq!(live.len(), 1, "must stop after reaching target=1");
        assert_eq!(live[0].0.addr, a1, "probes in order, first live wins");
    }

    #[tokio::test]
    async fn probe_until_respects_max_attempts() {
        // One dead addr repeated; max_attempts=2 caps the work and yields
        // zero live without walking the whole (longer) list.
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);
        let candidates = vec![
            bridge_for(dead_addr),
            bridge_for(dead_addr),
            bridge_for(dead_addr),
            bridge_for(dead_addr),
        ];
        let live = probe_until(candidates, Duration::from_secs(1), 3, 2).await;
        assert!(live.is_empty(), "no live bridges among dead candidates");
    }

    #[tokio::test]
    async fn probe_until_target_zero_is_noop() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let live = probe_until(vec![bridge_for(addr)], Duration::from_secs(2), 0, 100).await;
        assert!(live.is_empty(), "target=0 probes nothing");
    }

    #[tokio::test]
    async fn probe_times_out_within_budget() {
        let stub_addr: std::net::SocketAddr = "192.0.2.1:9".parse().unwrap();
        let started = std::time::Instant::now();
        let reports = probe_all(vec![bridge_for(stub_addr)], Duration::from_millis(500)).await;
        let elapsed = started.elapsed();

        assert!(!reports[0].is_reachable());
        assert!(elapsed < Duration::from_secs(3));
        match &reports[0].outcome {
            Outcome::Unreachable { reason } => {
                assert!(
                    reason.contains("timed out")
                        || reason.contains("unreachable")
                        || reason.contains("network"),
                    "unexpected reason: {reason}",
                );
            }
            _ => panic!("expected Unreachable"),
        }
    }

    // -- Probe-target resolution tests (no network, no DNS) ------------------

    #[test]
    fn obfs4_bridge_probes_bridge_addr() {
        let bridge: BridgeLine = "obfs4 10.0.0.1:9001 ABCDEF0123456789ABCDEF0123456789ABCDEF01"
            .parse()
            .unwrap();
        let (host, port) = resolve_probe_target(&bridge).unwrap();
        assert_eq!(host, "10.0.0.1");
        assert_eq!(port, 9001);
    }

    #[test]
    fn plain_bridge_probes_bridge_addr() {
        let bridge: BridgeLine = "10.0.0.1:9001 ABCDEF0123456789ABCDEF0123456789ABCDEF01"
            .parse()
            .unwrap();
        let (host, port) = resolve_probe_target(&bridge).unwrap();
        assert_eq!(host, "10.0.0.1");
        assert_eq!(port, 9001);
    }

    #[test]
    fn webtunnel_bridge_probes_url_host_port() {
        let bridge: BridgeLine =
            "webtunnel 192.0.2.3:1 2852538D49D7D73C1A6694FC492104983A9C4FA2 url=https://example.com/secretRoute"
                .parse()
                .unwrap();
        let (host, port) = resolve_probe_target(&bridge).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn webtunnel_http_url_defaults_to_port_80() {
        let bridge: BridgeLine =
            "webtunnel 192.0.2.3:1 2852538D49D7D73C1A6694FC492104983A9C4FA2 url=http://example.com/x"
                .parse()
                .unwrap();
        let (host, port) = resolve_probe_target(&bridge).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
    }

    #[test]
    fn webtunnel_explicit_port_in_url_wins() {
        let bridge: BridgeLine =
            "webtunnel 192.0.2.3:1 2852538D49D7D73C1A6694FC492104983A9C4FA2 url=https://example.com:8443/x"
                .parse()
                .unwrap();
        let (host, port) = resolve_probe_target(&bridge).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8443);
    }

    #[test]
    fn webtunnel_addr_param_overrides_url() {
        let bridge: BridgeLine =
            "webtunnel 192.0.2.3:1 2852538D49D7D73C1A6694FC492104983A9C4FA2 url=https://example.com/secret addr=10.0.0.1:9001"
                .parse()
                .unwrap();
        let (host, port) = resolve_probe_target(&bridge).unwrap();
        assert_eq!(host, "10.0.0.1");
        assert_eq!(port, 9001);
    }

    #[test]
    fn webtunnel_missing_url_and_addr_is_error() {
        let bridge: BridgeLine =
            "webtunnel 192.0.2.3:1 2852538D49D7D73C1A6694FC492104983A9C4FA2 ver=0.0.3"
                .parse()
                .unwrap();
        let err = resolve_probe_target(&bridge).unwrap_err();
        assert!(
            err.contains("missing") || err.contains("url"),
            "expected error about missing url/addr, got: {err}"
        );
    }

    #[test]
    fn webtunnel_invalid_url_is_error() {
        let bridge: BridgeLine =
            "webtunnel 192.0.2.3:1 2852538D49D7D73C1A6694FC492104983A9C4FA2 url=:::not_a_url"
                .parse()
                .unwrap();
        let err = resolve_probe_target(&bridge).unwrap_err();
        assert!(
            err.contains("invalid url"),
            "expected error about invalid url, got: {err}"
        );
    }

    #[test]
    fn unrecognised_transport_falls_back_to_bridge_addr() {
        let bridge: BridgeLine = "snowflake 10.0.0.1:9001 ABCDEF0123456789ABCDEF0123456789ABCDEF01"
            .parse()
            .unwrap();
        let (host, port) = resolve_probe_target(&bridge).unwrap();
        assert_eq!(host, "10.0.0.1");
        assert_eq!(port, 9001);
    }

    #[test]
    fn webtunnel_invalid_addr_param_is_error() {
        let bridge: BridgeLine =
            "webtunnel 192.0.2.3:1 2852538D49D7D73C1A6694FC492104983A9C4FA2 url=https://example.com/x addr=not-an-addr"
                .parse()
                .unwrap();
        let err = resolve_probe_target(&bridge).unwrap_err();
        assert!(
            err.contains("invalid addr"),
            "expected addr error, got: {err}"
        );
    }

    #[test]
    fn webtunnel_url_with_unknown_scheme_no_port_is_error() {
        let bridge: BridgeLine =
            "webtunnel 192.0.2.3:1 2852538D49D7D73C1A6694FC492104983A9C4FA2 url=xyzzy://example.com/x"
                .parse()
                .unwrap();
        let err = resolve_probe_target(&bridge).unwrap_err();
        assert!(
            err.contains("no port") || err.contains("scheme"),
            "expected port/scheme error, got: {err}"
        );
    }

    #[test]
    fn obfs4_ipv6_bridge_addr_resolved() {
        let bridge: BridgeLine = "obfs4 [::1]:9050 ABCDEF0123456789ABCDEF0123456789ABCDEF01"
            .parse()
            .unwrap();
        let (host, port) = resolve_probe_target(&bridge).unwrap();
        assert_eq!(host, "::1");
        assert_eq!(port, 9050);
    }

    #[test]
    fn report_accessors() {
        let report = Report {
            bridge: bridge_for("127.0.0.1:1".parse().unwrap()),
            outcome: Outcome::Reachable {
                latency: Duration::from_millis(42),
            },
        };
        assert!(report.is_reachable());
        assert_eq!(report.latency(), Some(Duration::from_millis(42)));

        let unreachable = Report {
            bridge: bridge_for("127.0.0.1:1".parse().unwrap()),
            outcome: Outcome::Unreachable {
                reason: "test".into(),
            },
        };
        assert!(!unreachable.is_reachable());
        assert!(unreachable.latency().is_none());
    }
}
