use rustls::pki_types::ServerName;

use super::dns::{
    cached_doh_answer, disk_fallback_answer, doh_order, doh_pool, doh_slots, forget_dns_answer,
    note_doh_result, remember_doh_answer, remember_doh_failure, stale_fallback_answer, CacheHit,
    DOH_FANOUT, DOH_MAX_WAVES, DOH_PROVIDER_TIMEOUT,
};
use super::*;

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

/// Floor for the webtunnel probe: it has to complete a TLS handshake and an
/// HTTP round trip, not just a TCP one, so the plain TCP budget is too tight.
pub(super) const MIN_WEBTUNNEL_TIMEOUT: Duration = Duration::from_secs(12);

/// Largest response head we will read while looking for the status line.
pub(super) const WEBTUNNEL_HEAD_LIMIT: usize = 8 * 1024;

pub(super) fn webtunnel_tls_config() -> std::sync::Arc<rustls::ClientConfig> {
    static CFG: OnceLock<std::sync::Arc<rustls::ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        std::sync::Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    })
    .clone()
}

/// Decide whether `addr` really serves the webtunnel bridge named by `url`.
///
/// A webtunnel bridge is reached by TLS to an ordinary-looking web server and
/// an HTTP/1.1 GET carrying WebSocket upgrade headers; only the bridge answers
/// `101 Switching Protocols`. Everything else on that host -- the site itself,
/// a CDN error page, a reverse proxy whose backend has died -- answers with a
/// normal status code.
///
/// This distinction is not cosmetic. Measured against a public collector's
/// list, 33 hosts passed a plain TCP probe and only 2 completed the upgrade;
/// the rest were live websites with no bridge behind them. Worse, those dead
/// entries sit behind CDNs and so post excellent latencies, which promoted them
/// to the top of the health ranking and pushed working bridges out of the
/// active pool entirely.
///
/// cancel-safe: NO — cancelling mid-handshake leaves partial TLS state, which
/// is fine because the connection is dropped either way.
pub(super) async fn webtunnel_upgrade_probe(
    addrs: &[SocketAddr],
    plan: &PreparedTarget,
    budget: Duration,
) -> Outcome {
    let started = Instant::now();
    // One budget for the whole candidate list, not one per candidate: a host
    // with several addresses must not cost several times the wall clock of a
    // host with one.
    let attempt = async {
        let mut last = "hostname resolved to no usable address".to_owned();
        for addr in addrs {
            match webtunnel_upgrade_inner(*addr, plan).await {
                Ok(()) => return Ok(()),
                Err(reason) => last = format!("{addr}: {reason}"),
            }
        }
        Err(last)
    };
    match timeout(budget, attempt).await {
        Ok(Ok(())) => Outcome::Reachable {
            latency: started.elapsed(),
        },
        Ok(Err(reason)) => Outcome::Unreachable { reason },
        Err(_) => Outcome::Unreachable {
            reason: format!("webtunnel upgrade timed out after {budget:?}"),
        },
    }
}

pub(super) async fn webtunnel_upgrade_inner(
    addr: SocketAddr,
    plan: &PreparedTarget,
) -> Result<(), String> {
    // A fixed key is fine: nothing here verifies the server's accept hash, and
    // the probe carries no data. Host header and request-target come straight
    // from the shared plan, so the wire format matches the transport's.
    let request = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         User-Agent: Mozilla/5.0\r\n\
         \r\n",
        plan.request_target, plan.host_header
    );

    let tcp = TcpStream::connect(addr)
        .await
        .map_err(|e| format!("tcp connect: {e}"))?;
    if plan.use_tls {
        let server_name = ServerName::try_from(plan.sni.clone())
            .map_err(|e| format!("invalid SNI {:?}: {e}", plan.sni))?;
        let connector = tokio_rustls::TlsConnector::from(webtunnel_tls_config());
        let tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| format!("tls: {e}"))?;
        send_upgrade_request(tls, &request).await
    } else {
        // Plain http:// : the transport speaks cleartext too, so the probe
        // must not demand a certificate the bridge never offers.
        send_upgrade_request(tcp, &request).await
    }
}

/// Write the upgrade request and look for `101 Switching Protocols`.
///
/// Generic over the stream so the TLS and plain-http paths share this
/// verbatim without boxing or an enum wrapper.
async fn send_upgrade_request<S>(mut stream: S, request: &str) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("write request: {e}"))?;
    stream.flush().await.map_err(|e| format!("flush: {e}"))?;

    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| format!("read response: {e}"))?;
        if n == 0 {
            return Err("connection closed before a status line arrived".to_owned());
        }
        buf.extend_from_slice(&chunk[..n]);

        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut response = httparse::Response::new(&mut headers);
        match response.parse(&buf) {
            Ok(httparse::Status::Complete(_)) => {
                return match response.code {
                    Some(101) => Ok(()),
                    Some(code) => Err(format!("not a webtunnel endpoint (HTTP {code})")),
                    None => Err("response had no status code".to_owned()),
                };
            }
            Ok(httparse::Status::Partial) => {
                if buf.len() >= WEBTUNNEL_HEAD_LIMIT {
                    return Err("response head exceeded the probe limit".to_owned());
                }
            }
            Err(e) => return Err(format!("malformed HTTP response: {e}")),
        }
    }
}

/// Most addresses tried for one hostname.
///
/// A resolver may hand back a long RR set; connecting to every entry would let
/// one hostname consume the budget of several bridges. Two covers the case
/// this exists for — one address per family — with a little room to spare.
pub(super) const MAX_PROBE_ADDRS: usize = 3;

/// Order resolved addresses so an unroutable family costs a failed `connect`
/// rather than the whole bridge.
///
/// The phone that exposed this has no IPv6 route at all, only the app's own
/// `tun0`, so every AAAA answer came back `Network is unreachable` and the
/// bridge was filed as dead — 29% of one round's webtunnel failures. IPv4 goes
/// first because it is the family that is nearly always routable, but both are
/// tried: an unroutable address fails instantly, so the ordering costs a
/// dual-stack host nothing and rescues a single-stack one.
///
/// The limit is shared between the families that are actually present: when
/// both an A and an AAAA answer arrive and the limit allows it (>= 2), each
/// family keeps at least one attempt, and any leftover capacity goes to IPv4.
/// A blanket `take(limit)` would otherwise let a long A-only RR set evict the
/// IPv6 candidate of a dual-stack host entirely.
pub(super) fn order_candidates(ips: &[IpAddr], port: u16) -> Vec<SocketAddr> {
    order_candidates_with_limit(ips, port, MAX_PROBE_ADDRS)
}

pub(super) fn order_candidates_with_limit(
    ips: &[IpAddr],
    port: u16,
    limit: usize,
) -> Vec<SocketAddr> {
    let mut seen = std::collections::HashSet::new();
    let mut sorted: Vec<IpAddr> = ips.iter().copied().filter(|ip| seen.insert(*ip)).collect();
    // Stable, so the resolver's own ordering survives within each family.
    sorted.sort_by_key(|ip| u8::from(ip.is_ipv6()));
    let v4_count = sorted.iter().filter(|ip| ip.is_ipv4()).count();
    let v6_count = sorted.len() - v4_count;
    if limit < 2 || v4_count == 0 || v6_count == 0 {
        return sorted
            .into_iter()
            .take(limit)
            .map(|ip| SocketAddr::new(ip, port))
            .collect();
    }
    // Both families present: reserve one slot for IPv6, give the remainder
    // to IPv4 (capped by what exists), and hand any slack back to IPv6.
    let v4_take = (limit - 1).min(v4_count);
    let v6_take = (limit - v4_take).min(v6_count);
    sorted[..v4_take]
        .iter()
        .chain(sorted[v4_count..v4_count + v6_take].iter())
        .map(|ip| SocketAddr::new(*ip, port))
        .collect()
}

/// What one DoH provider attempt reports back: its wave index, how long the
/// lookup took, and — if it produced one — the non-empty answer with the
/// records' own TTL. `None` means "no usable answer" (failure or NODATA).
pub(super) type DohAttemptOutcome = (usize, Duration, Option<(Vec<IpAddr>, Duration)>);

/// Everything one DoH provider does for a wave: grab a semaphore permit,
/// run the bounded lookup, record the provider's statistics, and map a
/// successful lookup into `(ips, ttl)` — or `None` when nothing usable came
/// back (an empty answer is not a win; the wave keeps waiting).
///
/// Recording happens inside this future (not in the race's spawn wrapper),
/// so a caller that stopped waiting on the wave after a winner still
/// receives this provider's verdict.
async fn doh_provider_attempt(
    index: usize,
    resolver: hickory_resolver::TokioResolver,
    query: String,
    slots: std::sync::Arc<tokio::sync::Semaphore>,
) -> DohAttemptOutcome {
    let _permit = slots.acquire_owned().await.ok();
    let started = Instant::now();
    // Per-provider bound. Without it a blocked provider holds its
    // semaphore permit for the caller's whole budget, starving the
    // providers that would have answered.
    let response = timeout(
        DOH_PROVIDER_TIMEOUT,
        resolver.lookup_ip(format!("{query}.")),
    )
    .await
    .ok()
    .and_then(Result::ok);
    let latency = started.elapsed();
    // An empty answer still proves the provider is usable here — the name
    // simply does not exist — so it must not be scored as a failure.
    // Recorded inside the attempt itself, so a caller that stopped waiting
    // on this wave after a winner still receives this provider's verdict.
    note_doh_result(index, response.is_some());
    let answer = response.and_then(|lookup| {
        let ips: Vec<IpAddr> = lookup.iter().collect();
        if ips.is_empty() {
            return None; // NODATA: not a win, keep waiting.
        }
        // The record's own TTL, so a short-lived CDN answer is not
        // held as long as a stable one. Clamped by the caller.
        let ttl = lookup
            .valid_until()
            .saturating_duration_since(Instant::now());
        Some((ips, ttl))
    });
    (index, latency, answer)
}

/// Race a set of provider attempts and return at the FIRST non-empty answer
/// (TS4-04), instead of draining the whole wave. Every attempt is spawned as
/// its own task reporting through a channel; the winner returns immediately
/// while the losers finish detached in the background, still recording their
/// statistics (that side effect lives inside each attempt future).
///
/// Dropping the receiver's clones (and finally `rx`) detaches the remaining
/// tasks: dropping a `JoinHandle` does not abort a tokio task. Each task is
/// self-bounded — permit wait, then [`DOH_PROVIDER_TIMEOUT`] on the lookup —
/// so detached tasks always terminate.
///
/// Cancel-safety: this is called under the caller's outer
/// `timeout(dns_timeout, ...)`; if THAT fires, the already-spawned wave tasks
/// continue in the background and still record their stats, which is intended.
pub(super) async fn race_first_answer<A>(
    query: &str,
    attempts: impl IntoIterator<Item = A>,
) -> Option<(Vec<IpAddr>, Duration)>
where
    A: std::future::Future<Output = DohAttemptOutcome> + Send + 'static,
{
    let attempts: Vec<A> = attempts.into_iter().collect();
    // Capacity >= task count, so a task's single send never blocks while
    // its recording is still pending.
    let (tx, mut rx) = tokio::sync::mpsc::channel(attempts.len().max(1));
    for attempt in attempts {
        let tx = tx.clone();
        // The send is best-effort: the receiver may already be gone once a
        // winner returned, so its error is ignored. Side effects such as
        // `note_doh_result` must live INSIDE the attempt future, not here.
        tokio::spawn(async move {
            let outcome = attempt.await;
            let _ = tx.send(outcome).await;
        });
    }
    drop(tx); // `rx.recv()` ends once every task finished without a winner.

    while let Some((_index, latency, result)) = rx.recv().await {
        let Some((ips, ttl)) = result else {
            continue; // Failed or empty answer: not a win, keep waiting.
        };
        tracing::debug!(
            provider_latency_ms = latency.as_millis() as u64,
            host = %query,
            "DoH provider won the resolution race"
        );
        return Some((ips, ttl));
    }
    None
}

/// Race one wave of DoH providers for `query`, returning the first non-empty
/// answer together with how long the records claim to be good for — and
/// returning it immediately rather than waiting for the whole wave (TS4-04).
/// The losing providers finish in the background and still record their
/// behaviour so [`doh_order`] can learn.
pub(super) async fn race_doh_wave(wave: &[usize], query: &str) -> Option<(Vec<IpAddr>, Duration)> {
    let pool = doh_pool();
    let attempts = wave.iter().filter_map(|&index| {
        let resolver = pool.get(index).cloned()?;
        Some(doh_provider_attempt(
            index,
            resolver,
            query.to_owned(),
            std::sync::Arc::clone(doh_slots()),
        ))
    });
    race_first_answer(query, attempts).await
}

/// Resolve a `(host, port)` pair to the addresses worth trying, best first.
///
/// Public so other crates that need to resolve a hostname without going
/// through the OS resolver (e.g. `bridge-fetcher`'s direct, non-Tor fetch
/// path for a cold start with zero live bridges) can reuse this crate's DoH
/// pool instead of duplicating it.
pub async fn resolve_addrs(
    host: &str,
    port: u16,
    resolver_policy: ResolverPolicy,
) -> Result<Vec<SocketAddr>, String> {
    let query = host.trim_end_matches('.');
    if resolver_policy.doh_enabled {
        match cached_doh_answer(query) {
            Some(CacheHit::Addrs(ips)) => return Ok(order_candidates(&ips, port)),
            // Remembered failure: skip the providers, but still let the system
            // resolver below have its turn if policy allows one.
            Some(CacheHit::Unresolvable) => {}
            None => {
                let order = doh_order();
                let mut resolved = None;
                for wave in order.chunks(DOH_FANOUT).take(DOH_MAX_WAVES) {
                    if let Some(answer) = race_doh_wave(wave, query).await {
                        resolved = Some(answer);
                        break;
                    }
                }
                match resolved {
                    Some((ips, ttl)) => {
                        remember_doh_answer(query, &ips, ttl);
                        return Ok(order_candidates(&ips, port));
                    }
                    None => {
                        if let Some(stale) = stale_fallback_answer(query) {
                            tracing::warn!(
                                host = %query,
                                addrs = stale.len(),
                                "all DoH providers failed; falling back to a stale cached answer"
                            );
                            return Ok(order_candidates(&stale, port));
                        }
                        if let Some(persisted) = disk_fallback_answer(query) {
                            tracing::warn!(
                                host = %query,
                                addrs = persisted.len(),
                                "all DoH providers failed and no in-memory answer remains; \
                                 falling back to a previous run's persisted answer"
                            );
                            return Ok(order_candidates(&persisted, port));
                        }
                        remember_doh_failure(query);
                        tracing::warn!(host = %query, "all DoH providers failed");
                    }
                }
            }
        }
    }

    if resolver_policy.system_fallback {
        let host_port = format!("{host}:{port}");
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&host_port)
            .await
            .map_err(|e| format!("system DNS lookup failed for {host_port}: {e}"))?
            .collect();
        if addrs.is_empty() {
            return Err(format!(
                "system DNS lookup returned no addresses for {host_port}"
            ));
        }
        let ips: Vec<IpAddr> = addrs.iter().map(|a| a.ip()).collect();
        return Ok(order_candidates(&ips, port));
    }

    Err(format!(
        "no DNS resolver available for {host}:{port} (DoH disabled/failed and system fallback disabled)"
    ))
}

/// Perform a TCP reachability probe against the resolved candidates, within
/// the per-bridge timeout budget per candidate.
pub(super) async fn tcp_probe(addrs: &[SocketAddr], per_bridge_timeout: Duration) -> Outcome {
    let started = Instant::now();
    let mut last = "hostname resolved to no usable address".to_owned();
    for addr in addrs {
        match timeout(per_bridge_timeout, TcpStream::connect(*addr)).await {
            Ok(Ok(_)) => {
                return Outcome::Reachable {
                    latency: started.elapsed(),
                }
            }
            Ok(Err(e)) => last = format!("{addr}: {e}"),
            Err(_) => last = format!("{addr}: timed out after {per_bridge_timeout:?}"),
        }
    }
    Outcome::Unreachable { reason: last }
}

/// Cap on simultaneous in-flight TCP probes — absorbs a large fetched
/// bridge list without exhausting the per-process file-descriptor budget.
pub(super) const MAX_INFLIGHT_PROBES: usize = 64;

/// Probe every bridge in `bridges` concurrently. Each probe is bounded by
/// `per_bridge_timeout`. At most [`MAX_INFLIGHT_PROBES`] probes are in
/// flight at any time. The returned vector is **not** guaranteed to
/// preserve input order.
pub async fn probe_all(bridges: Vec<BridgeLine>, per_bridge_timeout: Duration) -> Vec<Report> {
    probe_all_with_policy(bridges, per_bridge_timeout, ResolverPolicy::default()).await
}

pub async fn probe_all_with_policy(
    bridges: Vec<BridgeLine>,
    per_bridge_timeout: Duration,
    resolver_policy: ResolverPolicy,
) -> Vec<Report> {
    stream::iter(bridges)
        .map(|bridge| async move {
            let outcome = resolve_and_probe(&bridge, per_bridge_timeout, resolver_policy).await;
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
    probe_and_sort_with_policy(bridges, per_bridge_timeout, ResolverPolicy::default()).await
}

pub async fn probe_and_sort_with_policy(
    bridges: Vec<BridgeLine>,
    per_bridge_timeout: Duration,
    resolver_policy: ResolverPolicy,
) -> Vec<(BridgeLine, Duration)> {
    probe_round_with_policy(bridges, per_bridge_timeout, resolver_policy)
        .await
        .alive
}

/// What one probe round established, split by whether it established anything.
///
/// Callers that persist results need both halves: recording only the live
/// bridges and treating every other input as dead is what turned a struggling
/// resolver into a pile of false failures.
#[derive(Debug, Clone, Default)]
pub struct ProbeRound {
    /// Reachable bridges, fastest first.
    pub alive: Vec<(BridgeLine, Duration)>,
    /// Bridges the round could not test at all. Not evidence of anything —
    /// leave their health record untouched.
    pub unmeasured: Vec<BridgeLine>,
}

/// Probe `bridges`, log a summary, and report both the live ones and the ones
/// that were never actually tested.
pub async fn probe_round_with_policy(
    bridges: Vec<BridgeLine>,
    per_bridge_timeout: Duration,
    resolver_policy: ResolverPolicy,
) -> ProbeRound {
    let reports = probe_all_with_policy(bridges, per_bridge_timeout, resolver_policy).await;
    summarise(&reports);

    let mut round = ProbeRound::default();
    for report in reports {
        match report.outcome {
            Outcome::Reachable { latency } => round.alive.push((report.bridge, latency)),
            Outcome::Unmeasured { .. } => round.unmeasured.push(report.bridge),
            Outcome::Unreachable { .. } => {}
        }
    }

    round.alive.sort_by_key(|(_, latency)| *latency);
    round
}

/// Probe a single bridge: `Some(latency)` if its (transport-resolved) TCP
/// target answers within `per_bridge_timeout`, `None` otherwise. The lazy
/// pool-drainer uses this to walk candidates one at a time while deciding,
/// per bridge, whether to promote (alive) or discard (dead).
pub async fn probe_one(bridge: &BridgeLine, per_bridge_timeout: Duration) -> Option<Duration> {
    probe_one_with_policy(bridge, per_bridge_timeout, ResolverPolicy::default()).await
}

pub async fn probe_one_with_policy(
    bridge: &BridgeLine,
    per_bridge_timeout: Duration,
    resolver_policy: ResolverPolicy,
) -> Option<Duration> {
    match resolve_and_probe(bridge, per_bridge_timeout, resolver_policy).await {
        Outcome::Reachable { latency } => Some(latency),
        Outcome::Unreachable { .. } | Outcome::Unmeasured { .. } => None,
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
    probe_until_with_policy(
        bridges,
        per_bridge_timeout,
        target,
        max_attempts,
        ResolverPolicy::default(),
    )
    .await
}

pub async fn probe_until_with_policy(
    bridges: Vec<BridgeLine>,
    per_bridge_timeout: Duration,
    target: usize,
    max_attempts: usize,
    resolver_policy: ResolverPolicy,
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
        match resolve_and_probe(&bridge, per_bridge_timeout, resolver_policy).await {
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
            Outcome::Unmeasured { reason } => {
                tracing::trace!(addr = %bridge.addr, reason = %reason, "bridge not measured (lazy probe)");
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

pub(super) fn summarise(reports: &[Report]) {
    let total = reports.len();
    let alive = reports.iter().filter(|r| r.is_reachable()).count();
    let unmeasured = reports.iter().filter(|r| r.is_unmeasured()).count();
    tracing::info!(
        total,
        alive,
        dead = total - alive - unmeasured,
        unmeasured,
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
            Outcome::Unmeasured { reason } => tracing::warn!(
                addr = %r.bridge.addr,
                transport = ?r.bridge.transport,
                reason = %reason,
                "bridge not measured; leaving its health record alone"
            ),
        }
    }
}
