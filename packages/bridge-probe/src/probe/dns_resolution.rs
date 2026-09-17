use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::dns_invalidation::CacheIdentity;
use super::{Outcome, ResolverPolicy};
use crate::dns::{
    cached_doh_answer_observed, disk_fallback_answer, doh_order, doh_pool, doh_slots,
    note_doh_result, remember_doh_answer_if_generation_observed,
    remember_doh_failure_if_generation, stale_fallback_answer_observed, DNS_NETWORK_GENERATION,
    DOH_FANOUT, DOH_MAX_WAVES, DOH_PROVIDER_TIMEOUT,
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
#[cfg(test)]
pub(crate) type DohWaveResult = Result<(Vec<IpAddr>, Duration), String>;
type ObservedDohWaveResult = Result<(Vec<IpAddr>, Duration, Option<CacheIdentity>), String>;

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
/// until something removes them explicitly. Removal is therefore POINTWISE
/// (TS8-04): a caller whose lookup has finished deletes its own key right
/// after the result is published (`remove_finished_inflight_entry`), with a
/// cell-identity check so a newer cell under the same key is never touched.
/// A sweep of entries that died elsewhere still exists, but it runs only
/// every [`INFLIGHT_SWEEP_INTERVAL`]-th fresh insertion (an amortized
/// counter) instead of on EVERY insert -- sweeping on every insert made H
/// concurrent cold hostnames cost O(H^2) lock-held work -- and it visits at
/// most [`INFLIGHT_SWEEP_BUDGET`] queued keys per run (TS10-02). The FIFO
/// cursor rotates live keys to its back, so a stable live prefix cannot starve
/// dead entries behind it; stale cursor keys are discarded. Cleanup visits a
/// bounded number of keys regardless of map size or capacity. The registry holds the DISTINCT
/// hostnames actively being resolved concurrently plus entries that died
/// since the last sweep -- NOT a permanently fixed size: MAX_INFLIGHT_PROBES
/// bounds ONE `probe_all` batch, not all concurrent resolve calls registry-
/// wide, so no global size bound is claimed here; the bounded sweep is what
/// keeps per-insert cost constant instead.
/// TS7-06: keys are `(hostname, network generation)`, so a lookup started
/// before a `flush_dns_cache` can never be joined by (or publish into) the
/// post-flush world.
type InflightKey = (Arc<str>, u64);
type InflightCell = tokio::sync::OnceCell<ObservedDohWaveResult>;

fn inflight_key(host: &str, generation: u64) -> InflightKey {
    (Arc::<str>::from(host), generation)
}

struct InflightDohRegistry {
    entries: std::collections::HashMap<InflightKey, std::sync::Weak<InflightCell>>,
    /// Each key has at most one queued cursor entry. A key removed from
    /// `entries` remains queued until its turn, so reinsertion cannot starve
    /// behind a duplicate marker or require an O(n) queue search.
    sweep_queue: std::collections::VecDeque<InflightKey>,
    queued_keys: std::collections::HashSet<InflightKey>,
}

impl InflightDohRegistry {
    fn new() -> Self {
        Self {
            entries: std::collections::HashMap::new(),
            sweep_queue: std::collections::VecDeque::new(),
            queued_keys: std::collections::HashSet::new(),
        }
    }

    fn queue_key(&mut self, key: InflightKey) {
        if self.queued_keys.insert(key.clone()) {
            self.sweep_queue.push_back(key);
        }
    }

    fn clear_if_empty(&mut self) {
        if self.entries.is_empty() {
            self.sweep_queue.clear();
            self.queued_keys.clear();
            self.entries.shrink_to_fit();
            self.sweep_queue.shrink_to_fit();
            self.queued_keys.shrink_to_fit();
        }
    }
}
static INFLIGHT_DOH: std::sync::OnceLock<std::sync::Mutex<InflightDohRegistry>> =
    std::sync::OnceLock::new();

/// Fresh insertions between amortized sweeps of dead entries elsewhere in
/// the registry (TS8-04), so dead entries cannot accumulate past this many
/// further insertions without a cleanup attempt. Exact timing is irrelevant
/// (the counter is process-global and racy by design), so plain
/// `AtomicUsize` suffices.
const INFLIGHT_SWEEP_INTERVAL: usize = 64;
static INFLIGHT_SWEEP_COUNTER: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Upper bound on cursor keys visited by one sweep. FIFO rotation gives later
/// sweeps access to entries beyond this bound without scanning hash buckets.
const INFLIGHT_SWEEP_BUDGET: usize = 128;

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
///
/// TS7-06: the registry key is `(hostname, network generation)` and the
/// owner skips `remember_doh_answer` when the generation changed under the
/// lookup (a `flush_dns_cache` while the wave search was in flight) -- the
/// answer belongs to the old network and must not be cached for the new one.
#[cfg(test)]
pub(crate) async fn coalesced_doh_lookup(query: &str) -> DohWaveResult {
    coalesced_doh_lookup_observed(query)
        .await
        .map(|(ips, ttl, _)| (ips, ttl))
}

async fn coalesced_doh_lookup_observed(query: &str) -> ObservedDohWaveResult {
    // TS7-06: capture the network generation BEFORE touching the registry.
    // A lookup is identified by the generation it started in; see the
    // registry docs above.
    let gen = DNS_NETWORK_GENERATION.load(std::sync::atomic::Ordering::SeqCst);
    let registry = INFLIGHT_DOH.get_or_init(|| std::sync::Mutex::new(InflightDohRegistry::new()));
    let cell: std::sync::Arc<tokio::sync::OnceCell<ObservedDohWaveResult>> = {
        let mut map = registry.lock().unwrap_or_else(|p| p.into_inner());
        let key = inflight_key(query, gen);
        if let Some(existing) = map.entries.get(&key).and_then(std::sync::Weak::upgrade) {
            existing
        } else {
            // TS10-02: BOUNDED sweep, not `retain` or a bounded HashMap
            // iterator. The FIFO cursor visits at most the fixed budget and
            // rotates live keys, so later dead keys are eventually reached.
            if INFLIGHT_SWEEP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                % INFLIGHT_SWEEP_INTERVAL
                == INFLIGHT_SWEEP_INTERVAL - 1
            {
                sweep_inflight_dead_entries(&mut map);
            }
            let fresh = std::sync::Arc::new(tokio::sync::OnceCell::new());
            map.entries
                .insert(key.clone(), std::sync::Arc::downgrade(&fresh));
            map.queue_key(key);
            fresh
        }
    };
    let result = cell
        .get_or_init(|| async {
            match doh_wave_search(query).await {
                Some((ips, ttl)) => {
                    // TS7-06: publish only into the generation this lookup
                    // started in; TS8-01: the generation re-check now runs
                    // INSIDE `remember_doh_answer_if_generation`, under the same
                    // `doh_cache()` mutex `flush_dns_cache` holds for its
                    // bump+clear, so a flush can no longer land between the
                    // check and the insert (the old "residual race").
                    let identity =
                        remember_doh_answer_if_generation_observed(query, &ips, ttl, gen);
                    Ok((ips, ttl, identity))
                }
                None => Err("all DoH providers failed".to_owned()),
            }
        })
        .await
        .clone();
    remove_finished_inflight_entry(registry, query, gen, &cell);
    result
}

/// TS8-04: after a caller's lookup has finished, delete its registry entry
/// by key, but only if the stored `Weak` is still THIS call's cell
/// (`Weak::as_ptr` identity): if a newer cell was inserted under the same
/// key meanwhile, that newer lookup stays joined by later callers.
/// Deleting only after `get_or_init` returned means the value is already
/// published (success into `remember_doh_answer`'s cache, failure into the
/// cell itself) AND the init can no longer be cancelled -- a cancelled owner
/// must not delete a cell a waiter took over, or late joiners would start a
/// duplicate search. Entries whose owners were cancelled stay as dead
/// `Weak`s and are removed by the amortized sweep instead.
fn remove_finished_inflight_entry(
    registry: &std::sync::Mutex<InflightDohRegistry>,
    query: &str,
    gen: u64,
    cell: &std::sync::Arc<tokio::sync::OnceCell<ObservedDohWaveResult>>,
) {
    let mut map = registry.lock().unwrap_or_else(|p| p.into_inner());
    let key = inflight_key(query, gen);
    if map
        .entries
        .get(&key)
        .is_some_and(|w| w.as_ptr() == std::sync::Arc::as_ptr(cell))
    {
        map.entries.remove(&key);
        // The cursor marker is discarded lazily in the bounded sweep. If the
        // registry drained completely, reclaim all three containers together.
        map.clear_if_empty();
    }
}

/// TS10-02: visit at most [`INFLIGHT_SWEEP_BUDGET`] cursor keys. Live entries
/// are rotated to the back, dead entries are removed, and stale markers from
/// pointwise removals or key replacement are discarded. The cursor is FIFO,
/// so a finite live prefix cannot starve dead entries behind it, while the
/// number of hash map operations is independent of map size and capacity.
fn sweep_inflight_dead_entries(registry: &mut InflightDohRegistry) -> usize {
    let mut visited = 0;
    let visit_limit = INFLIGHT_SWEEP_BUDGET.min(registry.sweep_queue.len());
    for _ in 0..visit_limit {
        let Some(key) = registry.sweep_queue.pop_front() else {
            break;
        };
        visited += 1;
        registry.queued_keys.remove(&key);

        let Some(weak) = registry.entries.get(&key) else {
            continue;
        };
        if weak.strong_count() == 0 {
            registry.entries.remove(&key);
            continue;
        }
        registry.queue_key(key);
    }
    visited
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
        .map(|registry| {
            registry
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .entries
                .len()
        })
        .unwrap_or(0)
}

/// TS10-02 test seam: current value of the sweep counter, so the bounded-
/// sweep test can insert deterministically UNTIL the next sweep boundary
/// (the sweep fires on the insertion that makes the counter a multiple of
/// [`INFLIGHT_SWEEP_INTERVAL`]) instead of guessing at counts. Never exists
/// in non-test builds.
#[cfg(test)]
pub(crate) fn inflight_sweep_counter_value() -> usize {
    INFLIGHT_SWEEP_COUNTER.load(std::sync::atomic::Ordering::Relaxed)
}

/// TS10-02 test seam: whether ANY registry entry for `host` (in any network
/// generation) is currently present, dead or live. Lets the bounded-sweep
/// test assert per-key removal without asserting an exact GLOBAL length --
/// unrelated concurrent lookups (e.g. probe tests resolving IP literals
/// through the default policy) legitimately appear in the shared registry
/// and must not break the assertions. Never exists in non-test builds.
#[cfg(test)]
pub(crate) fn inflight_doh_contains_host(host: &str) -> bool {
    INFLIGHT_DOH
        .get()
        .map(|registry| {
            registry
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .entries
                .keys()
                .any(|(h, _)| h.as_ref() == host)
        })
        .unwrap_or(false)
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
    resolve_addrs_observed(host, port, resolver_policy)
        .await
        .map(|resolved| resolved.addrs)
}

pub(crate) struct ResolvedAddrs {
    pub(crate) addrs: Vec<SocketAddr>,
    pub(crate) cache_identity: Option<CacheIdentity>,
}

pub(crate) async fn resolve_addrs_observed(
    host: &str,
    port: u16,
    resolver_policy: ResolverPolicy,
) -> Result<ResolvedAddrs, String> {
    let query = host.trim_end_matches('.');
    let generation = DNS_NETWORK_GENERATION.load(std::sync::atomic::Ordering::SeqCst);
    if resolver_policy.doh_enabled {
        match cached_doh_answer_observed(query) {
            Some((ips, cache_identity)) if !ips.is_empty() => {
                return Ok(ResolvedAddrs {
                    addrs: order_candidates(&ips, port),
                    cache_identity: Some(cache_identity),
                });
            }
            // Remembered failure: skip the providers, but still let the system
            // resolver below have its turn if policy allows one.
            Some((_empty, _identity)) => {}
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
                // TS7-06: a failure observed entirely inside one network
                // generation must not poison the cache of the next one --
                // after a flush, the name may resolve fine in the new
                // network. Same residual race as the answer-publish gate.
                match coalesced_doh_lookup_observed(query).await {
                    Ok((ips, _ttl, cache_identity)) => {
                        return Ok(ResolvedAddrs {
                            addrs: order_candidates(&ips, port),
                            cache_identity,
                        });
                    }
                    Err(_) => {
                        if let Some((stale, cache_identity)) = stale_fallback_answer_observed(query)
                        {
                            tracing::warn!(
                                host = %query,
                                addrs = stale.len(),
                                "all DoH providers failed; falling back to a stale cached answer"
                            );
                            return Ok(ResolvedAddrs {
                                addrs: order_candidates(&stale, port),
                                cache_identity: Some(cache_identity),
                            });
                        }
                        if let Some(persisted) = disk_fallback_answer(query) {
                            tracing::warn!(
                                host = %query,
                                addrs = persisted.len(),
                                "all DoH providers failed and no in-memory answer remains; \
                                 falling back to a previous run's persisted answer"
                            );
                            return Ok(ResolvedAddrs {
                                addrs: order_candidates(&persisted, port),
                                cache_identity: None,
                            });
                        }
                        // TS7-06/TS8-01: only remember the failure if the
                        // network generation did not change under the
                        // lookup; the re-check runs under the cache mutex,
                        // so a flush landing after the check can no longer
                        // be overtaken by the insert.
                        remember_doh_failure_if_generation(query, generation);
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
        return Ok(ResolvedAddrs {
            addrs: order_candidates(&ips, port),
            cache_identity: None,
        });
    }

    Err(format!(
        "no DNS resolver available for {host}:{port} (DoH disabled/failed and system fallback disabled)"
    ))
}

/// Perform a TCP reachability probe against the resolved candidates, within
/// the per-bridge timeout budget per candidate.
#[cfg(test)]
pub(crate) async fn tcp_probe(addrs: &[SocketAddr], per_bridge_timeout: Duration) -> Outcome {
    tcp_probe_observed(addrs, per_bridge_timeout).await.0
}

pub(crate) async fn tcp_probe_observed(
    addrs: &[SocketAddr],
    per_bridge_timeout: Duration,
) -> (Outcome, Vec<SocketAddr>) {
    let started = Instant::now();
    let mut last = "hostname resolved to no usable address".to_owned();
    let mut tried = Vec::with_capacity(addrs.len());
    for addr in addrs {
        tried.push(*addr);
        match timeout(per_bridge_timeout, TcpStream::connect(*addr)).await {
            Ok(Ok(_)) => {
                return (
                    Outcome::Reachable {
                        latency: started.elapsed(),
                    },
                    Vec::new(),
                );
            }
            Ok(Err(e)) => {
                last = format!("{addr}: {e}");
            }
            Err(_) => {
                last = format!("{addr}: timed out after {per_bridge_timeout:?}");
            }
        }
    }
    (Outcome::Unreachable { reason: last }, tried)
}

#[cfg(test)]
mod registry_tests {
    use super::*;

    fn add_entry(
        registry: &mut InflightDohRegistry,
        key: InflightKey,
        live: bool,
    ) -> Option<std::sync::Arc<InflightCell>> {
        let cell = std::sync::Arc::new(InflightCell::new());
        registry
            .entries
            .insert(key.clone(), std::sync::Arc::downgrade(&cell));
        registry.queue_key(key);
        live.then_some(cell)
    }

    #[test]
    fn live_sweep_reuses_shared_hostname_allocation() {
        let mut registry = InflightDohRegistry::new();
        let key = (Arc::<str>::from("live-identity.test.invalid"), 0);
        let _cell = add_entry(&mut registry, key.clone(), true).expect("live cell is retained");
        assert_eq!(
            sweep_inflight_dead_entries(&mut registry),
            1,
            "a sweep visits each queued key at most once"
        );
        assert!(Arc::ptr_eq(
            &key.0,
            &registry.sweep_queue.front().unwrap().0
        ));
        assert!(Arc::ptr_eq(
            &key.0,
            &registry.queued_keys.get(&key).unwrap().0
        ));
        assert!(Arc::ptr_eq(
            &key.0,
            &registry.entries.get_key_value(&key).unwrap().0 .0
        ));
        assert_eq!(registry.sweep_queue.len(), registry.queued_keys.len());
    }

    #[test]
    fn fifo_sweep_visits_bound_and_reaches_dead_entries_behind_live_prefix() {
        let mut registry = InflightDohRegistry::new();
        let mut live_cells = Vec::new();
        for i in 0..=INFLIGHT_SWEEP_BUDGET {
            live_cells.push(
                add_entry(
                    &mut registry,
                    (Arc::<str>::from(format!("live-{i}")), 0),
                    true,
                )
                .expect("live cell is retained"),
            );
        }
        for i in 0..3 {
            let _ = add_entry(
                &mut registry,
                (Arc::<str>::from(format!("dead-{i}")), 0),
                false,
            );
        }

        assert_eq!(
            sweep_inflight_dead_entries(&mut registry),
            INFLIGHT_SWEEP_BUDGET
        );
        assert_eq!(registry.entries.len(), INFLIGHT_SWEEP_BUDGET + 4);
        assert!(registry
            .entries
            .keys()
            .any(|(host, _)| host.as_ref() == "dead-0"));
        assert_eq!(registry.sweep_queue.len(), registry.queued_keys.len());

        assert_eq!(
            sweep_inflight_dead_entries(&mut registry),
            INFLIGHT_SWEEP_BUDGET
        );
        assert!(!registry
            .entries
            .keys()
            .any(|(host, _)| host.starts_with("dead-")));
        assert_eq!(registry.entries.len(), INFLIGHT_SWEEP_BUDGET + 1);

        let replacement_key = (Arc::<str>::from("live-0"), 0);
        registry.entries.remove(&replacement_key);
        let replacement = add_entry(&mut registry, replacement_key.clone(), true)
            .expect("replacement cell is retained");
        assert_eq!(registry.sweep_queue.len(), registry.queued_keys.len());
        assert!(registry.entries[&replacement_key].strong_count() > 0);
        drop(replacement);
        drop(live_cells);
    }
}
