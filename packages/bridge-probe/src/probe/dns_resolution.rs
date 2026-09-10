use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use super::{Outcome, ResolverPolicy};
use crate::dns::{
    cached_doh_answer, disk_fallback_answer, doh_order, doh_pool, doh_slots, note_doh_result,
    remember_doh_answer, remember_doh_failure, stale_fallback_answer, CacheHit, DOH_FANOUT,
    DOH_MAX_WAVES, DOH_PROVIDER_TIMEOUT,
};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

/// Most addresses tried for one hostname.
///
/// A resolver may hand back a long RR set; connecting to every entry would let
/// one hostname consume the budget of several bridges. Two covers the case
/// this exists for — one address per family — with a little room to spare.
pub(crate) const MAX_PROBE_ADDRS: usize = 3;

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
pub(crate) fn order_candidates(ips: &[IpAddr], port: u16) -> Vec<SocketAddr> {
    order_candidates_with_limit(ips, port, MAX_PROBE_ADDRS)
}

pub(crate) fn order_candidates_with_limit(
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
pub(crate) type DohAttemptOutcome = (usize, Duration, Option<(Vec<IpAddr>, Duration)>);

/// Everything one DoH provider does for a wave: grab a semaphore permit (or
/// give up when the race's admission token fires first -- TS5-02), run the
/// bounded lookup, record the provider's statistics, and map a
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
    admission: CancellationToken,
) -> DohAttemptOutcome {
    // TS5-02: the permit wait is the one place a queued attempt can outlive its
    // owner -- the race's tasks are detached, so an outer timeout does not stop
    // them. Race the wait against the admission token: an attempt whose owner
    // stopped waiting (outer DNS timeout, or a winner already delivered) gives
    // up its place in the queue instead of starting a lookup for nobody.
    let _permit = tokio::select! {
        biased;
        _ = admission.cancelled() => {
            // Cancelled before it ever started: nothing was learned about this
            // provider, so it must not be scored as a failure -- the same
            // principle as the empty-answer comment below. Do not call
            // `note_doh_result` for a lookup that never ran.
            return (index, Duration::ZERO, None);
        }
        p = slots.acquire_owned() => p.ok(),
    };
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
/// Each attempt is built by a factory that receives this race's OWN admission
/// token (TS5-02). The spawned tasks are detached -- dropping this future does
/// not abort them -- but the token is cancelled on EVERY exit path, and an
/// attempt still queued on a semaphore permit then gives up instead of
/// starting a lookup nobody will consume. Attempts that already started
/// (permit held) keep their detached, self-bounded behaviour unchanged.
///
/// The token fires on both exit kinds: a normal return (a winner, or the whole
/// wave finishing without one) drops `_cancel_on_exit` at function end, and
/// this future being dropped mid-race by the caller's `timeout` drops the very
/// same guard, because dropping a future runs its locals' `Drop` impls.
///
/// Dropping the receiver's clones (and finally `rx`) detaches the remaining
/// tasks: dropping a `JoinHandle` does not abort a tokio task. Each task is
/// self-bounded -- admission token, then [`DOH_PROVIDER_TIMEOUT`] on the
/// lookup -- so detached tasks always terminate.
///
/// Cancel-safety: this is called under the caller's outer
/// `timeout(dns_timeout, ...)`; if THAT fires, started tasks continue in the
/// background and still record their stats (intended), while queued ones are
/// cancelled by the token instead of starting work for an owner that left.
pub(crate) async fn race_first_answer<A, F, I>(
    query: &str,
    attempts: I,
) -> Option<(Vec<IpAddr>, Duration)>
where
    A: std::future::Future<Output = DohAttemptOutcome> + Send + 'static,
    F: FnOnce(CancellationToken) -> A,
    I: IntoIterator<Item = F>,
{
    let admission = CancellationToken::new();
    // `let _cancel_on_exit`, NOT `let _`: a named binding lives to the end of
    // the scope, so the guard is dropped -- and the token cancelled -- on every
    // path out of this function, including the future being dropped mid-`await`.
    let _cancel_on_exit = admission.clone().drop_guard();

    let attempts: Vec<F> = attempts.into_iter().collect();
    // Capacity >= task count, so a task's single send never blocks while
    // its recording is still pending.
    let (tx, mut rx) = tokio::sync::mpsc::channel(attempts.len().max(1));
    for build_attempt in attempts {
        let tx = tx.clone();
        let attempt = build_attempt(admission.clone());
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
pub(crate) async fn race_doh_wave(wave: &[usize], query: &str) -> Option<(Vec<IpAddr>, Duration)> {
    let pool = doh_pool();
    // Factories, not futures: the admission token (TS5-02) exists only for the
    // duration of one `race_first_answer` call and only the race may create and
    // cancel it, so attempts cannot be built before the race runs.
    let attempts = wave.iter().filter_map(|&index| {
        let resolver = pool.get(index).cloned()?;
        Some(move |admission: CancellationToken| {
            doh_provider_attempt(
                index,
                resolver,
                query.to_owned(),
                std::sync::Arc::clone(doh_slots()),
                admission,
            )
        })
    });
    race_first_answer(query, attempts).await
}

/// Coalesced result of a wave-search across the configured DoH providers
/// for one hostname: the resolved IPs with their TTL, or the failure
/// reason if every provider (and every wave, up to [`DOH_MAX_WAVES`]) failed.
pub(crate) type DohWaveResult = Result<(Vec<IpAddr>, Duration), String>;

/// Registry of in-flight DoH wave lookups, keyed by hostname (TS6-05): two
/// concurrent `resolve_addrs` calls for the SAME still-uncached host share
/// ONE set of provider waves instead of each launching its own. Entries hold
/// only a `Weak` cell: once every caller's `Arc` clone is dropped (the
/// lookup finished and all callers consumed it), `upgrade()` returns `None`,
/// so a later call for the same host either hits the long-term
/// `cached_doh_answer` cache (already updated by `remember_doh_answer`
/// inside the coalesced lookup below) or starts a fresh coalesced lookup.
/// TS7-05: a dead `Weak` does NOT disappear on its own -- `upgrade()`
/// failing leaves the key and the `Weak` allocation in the map forever
/// until something removes them explicitly. The map is therefore swept
/// LAZILY at insertion time: every fresh insert first drops all dead
/// entries, under the same lock (see `coalesced_doh_lookup`). That bounds
/// the registry to the DISTINCT hostnames actively being resolved
/// concurrently (itself bounded elsewhere, MAX_INFLIGHT_PROBES) plus the
/// entries that died since the last insertion, instead of growing with
/// every hostname ever resolved across the whole process lifetime.
static INFLIGHT_DOH: std::sync::OnceLock<
    std::sync::Mutex<
        std::collections::HashMap<String, std::sync::Weak<tokio::sync::OnceCell<DohWaveResult>>>,
    >,
> = std::sync::OnceLock::new();

/// Run (or join) the coalesced wave-search for `query`. Multiple concurrent
/// callers for the same still-uncached hostname share ONE set of provider
/// waves (TS6-05): only the "owner" (first to reach `get_or_init`) actually
/// runs the wave loop and calls `remember_doh_answer`; every other waiter
/// just receives a clone of the same result. Each caller applies its OWN
/// port to the returned IPs afterward — this function never sees a port.
///
/// `tokio::sync::OnceCell::get_or_init` is cancel-safe by contract: when the
/// owner's init future is dropped (an outer timeout, a cancelled probe), a
/// waiter takes over the initialization instead of being left waiting, so
/// one cancelled caller cannot forfeit a lookup the others still need.
/// Failure is deliberately NOT remembered here: `resolve_addrs` only calls
/// `remember_doh_failure` after its stale and persisted fallbacks also
/// missed, because a negative entry would overwrite the very
/// expired-but-fallback-eligible answer those fallbacks serve.
pub(crate) async fn coalesced_doh_lookup(query: &str) -> DohWaveResult {
    let registry =
        INFLIGHT_DOH.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let cell: std::sync::Arc<tokio::sync::OnceCell<DohWaveResult>> = {
        let mut map = registry.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(existing) = map.get(query).and_then(std::sync::Weak::upgrade) {
            existing
        } else {
            // TS7-05: a dead Weak (and its key) is not removed automatically
            // just because upgrade() would fail -- only an explicit removal
            // does. Sweep dead entries HERE, right before inserting a new
            // one, under the SAME lock as the insert (race-free: a live
            // entry always has strong_count > 0 at this exact moment, so
            // retain can never remove something a concurrent caller is
            // still using or just started). This bounds the registry to
            // "currently active lookups + entries that died between the
            // last two distinct-hostname insertions" instead of growing
            // across the whole process lifetime.
            map.retain(|_, w| w.strong_count() > 0);
            let fresh = std::sync::Arc::new(tokio::sync::OnceCell::new());
            map.insert(query.to_owned(), std::sync::Arc::downgrade(&fresh));
            fresh
        }
    };
    cell.get_or_init(|| async {
        match doh_wave_search(query).await {
            Some((ips, ttl)) => {
                remember_doh_answer(query, &ips, ttl);
                Ok((ips, ttl))
            }
            None => Err("all DoH providers failed".to_owned()),
        }
    })
    .await
    .clone()
}

/// The wave search one coalesced lookup runs per hostname: chunks of
/// [`DOH_FANOUT`] providers, at most [`DOH_MAX_WAVES`] of them, stopping at
/// the first wave with a non-empty answer. Factored out of `resolve_addrs`
/// verbatim so the TS6-05 coalescing tests can count wave sets through the
/// test seam below without touching the network.
async fn doh_wave_search(query: &str) -> Option<(Vec<IpAddr>, Duration)> {
    #[cfg(test)]
    {
        let fake = FAKE_DOH_WAVE_SEARCH
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        if let Some(fake) = fake {
            return fake(query).await;
        }
    }
    let order = doh_order();
    let mut resolved = None;
    for wave in order.chunks(DOH_FANOUT).take(DOH_MAX_WAVES) {
        if let Some(answer) = race_doh_wave(wave, query).await {
            resolved = Some(answer);
            break;
        }
    }
    resolved
}

/// TS6-05 test seam: a stand-in for [`doh_wave_search`], so the coalescing
/// tests can count how many wave sets the production lookup launches with
/// zero network access. Never set outside test builds.
#[cfg(test)]
pub(crate) type FakeDohWaveSearch = std::sync::Arc<
    dyn Fn(
            &str,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Option<(Vec<IpAddr>, Duration)>> + Send>,
        > + Send
        + Sync,
>;

#[cfg(test)]
static FAKE_DOH_WAVE_SEARCH: std::sync::Mutex<Option<FakeDohWaveSearch>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
pub(crate) fn install_fake_doh_wave_search(fake: FakeDohWaveSearch) {
    *FAKE_DOH_WAVE_SEARCH
        .lock()
        .unwrap_or_else(|p| p.into_inner()) = Some(fake);
}

#[cfg(test)]
pub(crate) fn clear_fake_doh_wave_search() {
    *FAKE_DOH_WAVE_SEARCH
        .lock()
        .unwrap_or_else(|p| p.into_inner()) = None;
}

/// TS7-05 test seam: current number of entries in the [`INFLIGHT_DOH`]
/// registry -- live cells and dead `Weak`s alike -- so tests can observe
/// the lazy sweep actually bounding the map. Never exists in non-test
/// builds.
#[cfg(test)]
pub(crate) fn inflight_doh_registry_len() -> usize {
    INFLIGHT_DOH
        .get()
        .map(|registry| registry.lock().unwrap_or_else(|p| p.into_inner()).len())
        .unwrap_or(0)
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
                // TS6-05: several bridge lines of one fronting host are probed
                // in parallel, and before coalescing each caller raced the
                // providers on its own while the answer was still uncached.
                // Join (or start) the ONE shared wave search instead. The
                // winning answer is cached inside the coalesced lookup; on
                // failure the fallback chain below runs exactly as before,
                // and the failure is still remembered only after BOTH
                // fallbacks missed -- remembering earlier would overwrite the
                // expired-but-fallback-eligible entry `stale_fallback_answer`
                // exists to serve.
                match coalesced_doh_lookup(query).await {
                    Ok((ips, _ttl)) => return Ok(order_candidates(&ips, port)),
                    Err(_) => {
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
        // Tuple form, not a "{host}:{port}" string: correct for IPv4/IPv6
        // literals and hostnames alike, without splicing and re-parsing.
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
            .await
            .map_err(|e| format!("system DNS lookup failed for {host}:{port}: {e}"))?
            .collect();
        if addrs.is_empty() {
            return Err(format!(
                "system DNS lookup returned no addresses for {host}:{port}"
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
pub(crate) async fn tcp_probe(addrs: &[SocketAddr], per_bridge_timeout: Duration) -> Outcome {
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
