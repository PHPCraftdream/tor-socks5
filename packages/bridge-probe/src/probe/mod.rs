// The single-file probe module split (TS5-09): items moved into sibling files
// keep their old crate-wide effective visibility by turning `pub(super)`
// (which meant "visible in crate::" from the old crate::probe) into
// `pub(crate)` there; mod.rs re-exports them so existing callers of
// `crate::probe::<name>` compile unchanged.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::dns::forget_dns_answer;
use crate::ResolverPolicy;
use bridge_line::BridgeLine;
use tokio::time::timeout;
mod batch;
mod dns_resolution;
mod webtunnel_upgrade;

pub use batch::{
    probe_all, probe_all_with_policy, probe_and_sort, probe_and_sort_with_policy, probe_one,
    probe_one_with_policy, probe_round_with_policy, probe_until, probe_until_with_policy,
    ProbeRound,
};
pub use dns_resolution::resolve_addrs;
#[allow(unused_imports)]
pub(crate) use dns_resolution::{
    coalesced_doh_lookup, order_candidates, order_candidates_with_limit, race_doh_wave,
    race_first_answer, tcp_probe, DohAttemptOutcome, MAX_PROBE_ADDRS,
};

// TS6-05: test-only seam for the coalescing tests (counting wave searches
// without network access); does not exist in non-test builds.
#[cfg(test)]
pub(crate) use dns_resolution::{
    clear_fake_doh_wave_search, inflight_doh_registry_len, install_fake_doh_wave_search,
    FakeDohWaveSearch,
};
// `#[allow(unused_imports)]`: these re-exports keep the moved items
// crate-visible exactly as their pre-split `pub(super)` did, even where only
// the defining sibling uses them.
#[allow(unused_imports)]
pub(crate) use batch::{summarise, MAX_INFLIGHT_PROBES};
#[allow(unused_imports)]
pub(crate) use webtunnel_upgrade::{
    webtunnel_upgrade_probe, MIN_WEBTUNNEL_TIMEOUT, WEBTUNNEL_HEAD_LIMIT,
};

/// Return whether a bridge address is a real network endpoint rather than a
/// documentation/test placeholder.  The public webtunnel collector currently
/// publishes `2001:db8::/32` addresses; that prefix is reserved by RFC 3849
/// and can never identify a reachable Tor relay.  Keeping this check here
/// gives every consumer (config loading, source fetches, and probes) one
/// canonical policy. Loopback and IPv4 documentation ranges remain accepted
/// because the probe crate deliberately supports local test listeners and
/// callers may use them in offline integration tests.
///
/// Exception: webtunnel bridges legitimately carry a `2001:db8::/32` ORPort
/// placeholder — the real endpoint lives in the `url=`/`addr=` param (see
/// [`resolve_probe_target`]), so the RFC 3849 check must not apply to them.
pub fn usable_for_tor(bridge: &BridgeLine) -> bool {
    if bridge.transport.as_deref() == Some("webtunnel") {
        return bridge.params.contains_key("url") || bridge.params.contains_key("addr");
    }
    match bridge.addr.ip() {
        std::net::IpAddr::V4(_) => true,
        std::net::IpAddr::V6(ip) => !ip.octets().starts_with(&[0x20, 0x01, 0x0d, 0xb8]),
    }
}

/// Outcome of probing a single bridge.
#[derive(Debug, Clone)]
pub enum Outcome {
    Reachable {
        latency: Duration,
    },
    Unreachable {
        reason: String,
    },
    /// The round never got far enough to learn anything about this bridge —
    /// its hostname would not resolve.
    ///
    /// Distinct from [`Outcome::Unreachable`] because it is a statement about
    /// our own resolver, not about the bridge. Counting it as a failure was
    /// filling the health store with verdicts we had not earned: on a phone
    /// where DoH was struggling, two thirds of all webtunnel "failures" were
    /// this, and each one pushed a possibly-live bridge towards being pruned
    /// and its source towards being written off as barren.
    Unmeasured {
        reason: String,
    },
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

    /// True when the probe produced no evidence either way, so no caller
    /// should record a result for this bridge.
    pub fn is_unmeasured(&self) -> bool {
        matches!(self.outcome, Outcome::Unmeasured { .. })
    }

    pub fn latency(&self) -> Option<Duration> {
        match &self.outcome {
            Outcome::Reachable { latency } => Some(*latency),
            Outcome::Unreachable { .. } | Outcome::Unmeasured { .. } => None,
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
///
/// Everything the webtunnel upgrade probe needs from the bridge params,
/// derived from a single parse of `url=`.
///
/// This mirrors the transport's `PreparedTarget` in ptrs-gesher's webtunnel
/// crate (`crates/webtunnel/src/target.rs`) field for field: TS4-03 exists
/// because the probe and the transport disagreed about which host went in
/// the SNI, which name went in the Host header, and whether the connection
/// was TLS at all. Keeping the same names and the same construction order
/// makes a side-by-side review of the two trivial, so a future divergence
/// is a review failure rather than a silent one.
#[derive(Debug)]
pub(super) struct PreparedTarget {
    /// Dial host (`addr=` override wins, else URL host, brackets stripped).
    pub(super) dial_host: String,
    /// Dial port (`addr=` override wins, else explicit or scheme-default port).
    pub(super) dial_port: u16,
    /// TLS SNI / Host-header name (`servername=` override wins, else URL host).
    pub(super) sni: String,
    /// Preformatted HTTP Host header value: bracketed if `sni` is an IPv6
    /// literal, plus ":port" ONLY if the URL carried an explicit port
    /// (`url::Url::port()`, not the scheme default — parity with the
    /// transport).
    pub(super) host_header: String,
    /// HTTP request-target: URL path (or "/") plus "?query" when the query
    /// is present and non-empty.
    pub(super) request_target: String,
    /// True for `https://`, false for `http://`.
    pub(super) use_tls: bool,
}

impl PreparedTarget {
    /// Build the plan, following the transport's checks in the same order
    /// and with the same errors: url parse, scheme check, SNI selection +
    /// `ServerName` validation, then dial host/port extraction.
    pub(super) fn new(params: &BTreeMap<String, String>) -> Result<Self, String> {
        let url_str = params
            .get("url")
            .ok_or_else(|| "webtunnel bridge missing both url= and addr=".to_string())?;
        let parsed = parse_webtunnel_url(url_str)?;
        if !parsed.scheme().eq_ignore_ascii_case("http")
            && !parsed.scheme().eq_ignore_ascii_case("https")
        {
            return Err(format!(
                "unsupported url scheme {} in url={url_str:?} (expected http or https)",
                parsed.scheme()
            ));
        }

        // SNI follows the `servername=` override or the URL's own host, which
        // is not always the probe target: an addr= override redirects the
        // connection while the certificate, and the bridge's identity, still
        // belong to the URL host. The ServerName check rejects e.g. CRLF
        // injection before it can reach the wire, as the transport does.
        let sni = match params.get("servername") {
            Some(s) => s.trim_start_matches('[').trim_end_matches(']').to_string(),
            None => parsed
                .host_str()
                .map(|host| {
                    host.trim_start_matches('[')
                        .trim_end_matches(']')
                        .to_string()
                })
                .ok_or_else(|| format!("url={url_str:?} has no host"))?,
        };
        rustls::pki_types::ServerName::try_from(sni.as_str())
            .map_err(|e| format!("invalid servername {sni:?}: {e}"))?;

        // Dial target: addr= wins over the URL, and unlike a SocketAddr parse
        // it may be a bare `host:port` — collectors publish hostname addr=
        // values, and rejecting them here used to unprobe those bridges.
        let (dial_host, dial_port) = match params.get("addr") {
            Some(addr) => {
                if let Ok(socket) = addr.parse::<SocketAddr>() {
                    (socket.ip().to_string(), socket.port())
                } else {
                    let (host, port) = addr.rsplit_once(':').ok_or_else(|| {
                        format!("invalid addr={addr:?}: missing ':' (expected host:port)")
                    })?;
                    if host.is_empty() || host.contains([':', '[', ']']) {
                        return Err(format!("invalid addr={addr:?}: bad host {host:?}"));
                    }
                    let port: u16 = port
                        .parse()
                        .map_err(|e| format!("invalid addr={addr:?}: bad port {port:?}: {e}"))?;
                    (host.to_string(), port)
                }
            }
            None => {
                let host = parsed
                    .host_str()
                    .map(|host| {
                        host.trim_start_matches('[')
                            .trim_end_matches(']')
                            .to_string()
                    })
                    .ok_or_else(|| format!("url={url_str:?} has no host"))?;
                let port = parsed.port_or_known_default().ok_or_else(|| {
                    format!("url={url_str:?} has no port and an unrecognised scheme")
                })?;
                (host, port)
            }
        };

        // Path and query exactly as configured: the secret path is what
        // identifies the bridge, and a wrong one is answered by the site
        // rather than the bridge.
        let path = parsed.path();
        let path = if path.is_empty() { "/" } else { path };
        let request_target = match parsed.query() {
            Some(q) if !q.is_empty() => format!("{path}?{q}"),
            _ => path.to_string(),
        };

        // An explicit URL port goes on the wire (parity with the transport);
        // a scheme-default port does not.
        let mut host_header = if sni.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{sni}]")
        } else {
            sni.clone()
        };
        if let Some(explicit_port) = parsed.port() {
            host_header = format!("{host_header}:{explicit_port}");
        }

        Ok(Self {
            dial_host,
            dial_port,
            sni,
            host_header,
            request_target,
            use_tls: parsed.scheme().eq_ignore_ascii_case("https"),
        })
    }
}

/// Canonical WebTunnel carrier identity for dedup/pool keys: every field of
/// [`PreparedTarget`] that shapes the actual connection — dial address, TLS
/// SNI, HTTP Host authority, TLS-vs-plain, and path+query. Two bridge lines
/// collapse into one dedup/pool candidate only when the probe would dial them
/// identically, so first-wins dedup can no longer discard a distinct,
/// possibly working, configuration.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WebtunnelEndpointIdentity {
    /// Dial host (`addr=` override wins, else URL host, brackets stripped).
    pub dial_host: String,
    /// Dial port (`addr=` override wins, else explicit or scheme-default port).
    pub dial_port: u16,
    /// TLS SNI / Host-header name (`servername=` override wins, else URL host).
    pub sni: String,
    /// Preformatted HTTP Host header value (see [`PreparedTarget::host_header`]).
    pub host_header: String,
    /// HTTP request-target: URL path (or "/") plus "?query" when present.
    pub request_target: String,
    /// True for `https://`, false for `http://`.
    pub use_tls: bool,
}

/// Canonical WebTunnel carrier identity for dedup/pool keys, computed via
/// [`PreparedTarget`] so dedup and probing can never disagree about what
/// counts as "the same connection". See [`WebtunnelEndpointIdentity`].
/// `None` for non-webtunnel bridges or when the params don't parse — the
/// caller should then fall back to the plain (transport, addr, fingerprint)
/// key, not drop the bridge.
pub fn webtunnel_endpoint_identity(bridge: &BridgeLine) -> Option<WebtunnelEndpointIdentity> {
    if bridge.transport.as_deref() != Some("webtunnel") {
        return None;
    }
    PreparedTarget::new(&bridge.params)
        .ok()
        .map(|t| WebtunnelEndpointIdentity {
            dial_host: t.dial_host,
            dial_port: t.dial_port,
            sni: t.sni,
            host_header: t.host_header,
            request_target: t.request_target,
            use_tls: t.use_tls,
        })
}

pub(super) fn resolve_probe_target(bridge: &BridgeLine) -> Result<(String, u16), String> {
    match bridge.transport.as_deref() {
        None | Some("obfs4") => Ok((bridge.addr.ip().to_string(), bridge.addr.port())),
        Some("webtunnel") => webtunnel_probe_target(&bridge.params),
        _ => Ok((bridge.addr.ip().to_string(), bridge.addr.port())),
    }
}

/// Extract the probe target from webtunnel bridge-line params.
///
/// Thin delegate over [`PreparedTarget`]: the plan and the (host, port)
/// pair are the same computation, so they cannot drift apart again.
/// Priority: `addr=` param wins over URL host:port. The URL's port
/// defaults to 443 for `https://` and 80 for `http://`.
///
/// Keep in sync with ptrs-gesher `crates/webtunnel/src/target.rs`.
pub(super) fn webtunnel_probe_target(
    params: &BTreeMap<String, String>,
) -> Result<(String, u16), String> {
    PreparedTarget::new(params).map(|t| (t.dial_host, t.dial_port))
}

/// Parse a webtunnel `url=` value, tolerating a missing scheme.
///
/// Collectors publish the occasional bare host (`url=tor.cenesp.es`), which
/// `Url::parse` rejects as a relative URL. webtunnel is HTTPS by construction,
/// so assuming that scheme recovers the bridge instead of discarding it
/// unprobed.
pub(super) fn parse_webtunnel_url(url_str: &str) -> Result<url::Url, String> {
    match url::Url::parse(url_str) {
        Ok(url) => Ok(url),
        Err(url::ParseError::RelativeUrlWithoutBase) => {
            url::Url::parse(&format!("https://{url_str}"))
                .map_err(|e| format!("invalid url={url_str:?} (even as https): {e}"))
        }
        Err(e) => Err(format!("invalid url={url_str:?}: {e}")),
    }
}

/// Floor for the DNS half of [`resolve_and_probe`].
///
/// `per_bridge_timeout` is sized for a bare TCP handshake (a few seconds), but
/// a DoH lookup has to open its own TCP+TLS session to the resolver before it
/// can even ask the question. Sharing the TCP budget made every hostname-based
/// bridge — i.e. every webtunnel bridge — time out on a mobile link. The TCP
/// probe still gets the caller's budget in full.
pub(super) const MIN_DNS_RESOLVE_TIMEOUT: Duration = Duration::from_secs(15);

/// Resolve the probe target for `bridge`, then perform a TCP handshake.
/// DNS resolution (when needed) gets its own budget — at least
/// [`MIN_DNS_RESOLVE_TIMEOUT`] — on top of the TCP probe's.
///
/// For webtunnel the whole probe runs from a single [`PreparedTarget`]
/// built here, so DNS, SNI, Host header and scheme cannot disagree with
/// each other or with the real transport.
pub(super) async fn resolve_and_probe(
    bridge: &BridgeLine,
    per_bridge_timeout: Duration,
    resolver_policy: ResolverPolicy,
) -> Outcome {
    if !usable_for_tor(bridge) {
        return Outcome::Unreachable {
            reason: "documentation or local-only bridge address".to_owned(),
        };
    }

    let plan = if bridge.transport.as_deref() == Some("webtunnel") {
        // The TCP target for webtunnel is the fronting web server, which answers
        // whether or not a bridge lives behind it, so a bare connect proves
        // nothing. Ask the endpoint to upgrade instead -- only a real bridge can.
        match PreparedTarget::new(&bridge.params) {
            Ok(plan) => Some(plan),
            Err(reason) => return Outcome::Unreachable { reason },
        }
    } else {
        None
    };
    let (host, port) = match &plan {
        Some(plan) => (plan.dial_host.clone(), plan.dial_port),
        None => match resolve_probe_target(bridge) {
            Ok(v) => v,
            Err(reason) => return Outcome::Unreachable { reason },
        },
    };

    let resolved_by_dns = host.parse::<IpAddr>().is_err();
    let addrs = if let Ok(ip) = host.parse::<IpAddr>() {
        vec![SocketAddr::new(ip, port)]
    } else {
        let dns_timeout = per_bridge_timeout.max(MIN_DNS_RESOLVE_TIMEOUT);
        match timeout(dns_timeout, resolve_addrs(&host, port, resolver_policy)).await {
            Ok(Ok(a)) => a,
            Ok(Err(reason)) => return Outcome::Unmeasured { reason },
            Err(_) => {
                return Outcome::Unmeasured {
                    reason: format!("DNS resolution timed out after {dns_timeout:?}"),
                }
            }
        }
    };

    let outcome = if let Some(plan) = &plan {
        webtunnel_upgrade_probe(&addrs, plan, per_bridge_timeout.max(MIN_WEBTUNNEL_TIMEOUT)).await
    } else {
        tcp_probe(&addrs, per_bridge_timeout).await
    };

    // Every address we were given failed. The name may simply have moved, and
    // holding the answer for the rest of its TTL would keep the bridge dead in
    // the store for no better reason than a stale cache line.
    if resolved_by_dns && matches!(outcome, Outcome::Unreachable { .. }) {
        forget_dns_answer(host.trim_end_matches('.'));
    }

    outcome
}
