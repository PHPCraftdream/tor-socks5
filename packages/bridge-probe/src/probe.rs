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
pub(super) fn resolve_probe_target(bridge: &BridgeLine) -> Result<(String, u16), String> {
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
pub(super) fn webtunnel_probe_target(
    params: &BTreeMap<String, String>,
) -> Result<(String, u16), String> {
    if let Some(addr) = params.get("addr") {
        let socket: SocketAddr = addr
            .parse()
            .map_err(|e| format!("invalid addr={addr:?}: {e}"))?;
        return Ok((socket.ip().to_string(), socket.port()));
    }

    let url_str = params
        .get("url")
        .ok_or_else(|| "webtunnel bridge missing both url= and addr=".to_string())?;

    let parsed = parse_webtunnel_url(url_str)?;

    let host = parsed
        .host_str()
        .ok_or_else(|| format!("url={url_str:?} has no host"))?;

    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| format!("url={url_str:?} has no port and an unrecognised scheme"))?;

    Ok((host.to_string(), port))
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
    let (host, port) = match resolve_probe_target(bridge) {
        Ok(v) => v,
        Err(reason) => return Outcome::Unreachable { reason },
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

    let outcome = if bridge.transport.as_deref() == Some("webtunnel") {
        // The TCP target for webtunnel is the fronting web server, which answers
        // whether or not a bridge lives behind it, so a bare connect proves
        // nothing. Ask the endpoint to upgrade instead -- only a real bridge can.
        let Some(url) = bridge.params.get("url") else {
            return Outcome::Unreachable {
                reason: "webtunnel bridge has no url= to upgrade against".to_owned(),
            };
        };
        webtunnel_upgrade_probe(
            &addrs,
            &host,
            url,
            per_bridge_timeout.max(MIN_WEBTUNNEL_TIMEOUT),
        )
        .await
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
    host: &str,
    url: &str,
    budget: Duration,
) -> Outcome {
    let started = Instant::now();
    // One budget for the whole candidate list, not one per candidate: a host
    // with several addresses must not cost several times the wall clock of a
    // host with one.
    let attempt = async {
        let mut last = "hostname resolved to no usable address".to_owned();
        for addr in addrs {
            match webtunnel_upgrade_inner(*addr, host, url).await {
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
    host: &str,
    url: &str,
) -> Result<(), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let parsed = parse_webtunnel_url(url)?;
    // Path and query exactly as configured: the secret path is what identifies
    // the bridge, and a wrong one is answered by the site rather than the bridge.
    let mut path = parsed.path().to_owned();
    if path.is_empty() {
        path.push('/');
    }
    if let Some(query) = parsed.query() {
        path.push('?');
        path.push_str(query);
    }
    // SNI follows the URL's own host, which is not always the probe target: an
    // addr= override redirects the connection while the certificate, and the
    // bridge's identity, still belong to the URL host.
    let sni_host = parsed.host_str().unwrap_or(host).to_owned();

    let tcp = TcpStream::connect(addr)
        .await
        .map_err(|e| format!("tcp connect: {e}"))?;
    let server_name = rustls::pki_types::ServerName::try_from(sni_host.clone())
        .map_err(|e| format!("invalid SNI {sni_host:?}: {e}"))?;
    let connector = tokio_rustls::TlsConnector::from(webtunnel_tls_config());
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| format!("tls: {e}"))?;

    // A fixed key is fine: nothing here verifies the server's accept hash, and
    // the probe carries no data.
    let request = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {sni_host}\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         User-Agent: Mozilla/5.0\r\n\
         \r\n"
    );
    tls.write_all(request.as_bytes())
        .await
        .map_err(|e| format!("write request: {e}"))?;
    tls.flush().await.map_err(|e| format!("flush: {e}"))?;

    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = tls
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
pub(super) fn order_candidates(ips: &[IpAddr], port: u16) -> Vec<SocketAddr> {
    let mut seen = std::collections::HashSet::new();
    let mut sorted: Vec<IpAddr> = ips.iter().copied().filter(|ip| seen.insert(*ip)).collect();
    // Stable, so the resolver's own ordering survives within each family.
    sorted.sort_by_key(|ip| u8::from(ip.is_ipv6()));
    sorted
        .into_iter()
        .take(MAX_PROBE_ADDRS)
        .map(|ip| SocketAddr::new(ip, port))
        .collect()
}

/// Race one wave of DoH providers for `query`, returning the first non-empty
/// answer together with how long the records claim to be good for. Records
/// each provider's behaviour so [`doh_order`] can learn.
pub(super) async fn race_doh_wave(wave: &[usize], query: &str) -> Option<(Vec<IpAddr>, Duration)> {
    let pool = doh_pool();
    let mut attempts = futures::stream::FuturesUnordered::new();
    for &index in wave {
        let Some(resolver) = pool.get(index).cloned() else {
            continue;
        };
        let query = query.to_owned();
        let slots = std::sync::Arc::clone(doh_slots());
        attempts.push(async move {
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
            (index, started.elapsed(), response)
        });
    }

    let mut answer = None;
    while let Some((index, latency, response)) = attempts.next().await {
        // An empty answer still proves the provider is usable here — the name
        // simply does not exist — so it must not be scored as a failure.
        note_doh_result(index, response.is_some());
        if answer.is_some() {
            continue;
        }
        if let Some(lookup) = response {
            let ips: Vec<IpAddr> = lookup.iter().collect();
            if !ips.is_empty() {
                tracing::debug!(
                    provider_latency_ms = latency.as_millis() as u64,
                    host = %query,
                    "DoH provider won the resolution race"
                );
                // The record's own TTL, so a short-lived CDN answer is not
                // held as long as a stable one. Clamped by the caller.
                let ttl = lookup
                    .valid_until()
                    .saturating_duration_since(Instant::now());
                answer = Some((ips, ttl));
            }
        }
    }
    answer
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
