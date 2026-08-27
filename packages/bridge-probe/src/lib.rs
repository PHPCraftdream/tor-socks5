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

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicI64, Ordering as AtomicOrdering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use bridge_line::BridgeLine;
use futures::stream::{self, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

/// Controls how hostname-based bridge targets are resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolverPolicy {
    /// Use the built-in pool of encrypted DNS-over-HTTPS providers.
    pub doh_enabled: bool,
    /// Permit the operating-system resolver if DoH is disabled or unavailable.
    pub system_fallback: bool,
}

impl Default for ResolverPolicy {
    fn default() -> Self {
        Self {
            doh_enabled: true,
            system_fallback: false,
        }
    }
}

/// Public DoH services are queried in parallel. The first successful answer
/// wins, which naturally prefers the currently reachable/fastest provider;
/// this also avoids pinning Android users to a single blocked DNS service.
const DOH_PROVIDERS: &[(&str, &str, &str)] = &[
    // Cloudflare (two anycast addresses, unfiltered).
    ("1.1.1.1", "cloudflare-dns.com", "/dns-query"),
    ("1.0.0.1", "cloudflare-dns.com", "/dns-query"),
    // Google Public DNS -- one of the most heavily anycast-routed, hardest-to-block
    // IP pairs in existence; blocking it costs the censor collateral damage far
    // beyond DNS circumvention. Notably absent before: adding it is one line.
    ("8.8.8.8", "dns.google", "/dns-query"),
    ("8.8.4.4", "dns.google", "/dns-query"),
    // Quad9 secure and no-threat-blocking variants.
    ("9.9.9.9", "dns.quad9.net", "/dns-query"),
    ("149.112.112.112", "dns.quad9.net", "/dns-query"),
    ("9.9.9.10", "dns10.quad9.net", "/dns-query"),
    ("149.112.112.10", "dns10.quad9.net", "/dns-query"),
    // AdGuard default and explicitly unfiltered endpoints.
    ("94.140.14.14", "dns.adguard-dns.com", "/dns-query"),
    ("94.140.15.15", "dns.adguard-dns.com", "/dns-query"),
    ("94.140.14.140", "unfiltered.adguard-dns.com", "/dns-query"),
    ("94.140.14.141", "unfiltered.adguard-dns.com", "/dns-query"),
    // Independent privacy-focused anycast/single-site operators.
    ("194.242.2.2", "dns.mullvad.net", "/dns-query"),
    ("185.222.222.222", "dns.sb", "/dns-query"),
    ("45.11.45.11", "dns.sb", "/dns-query"),
    ("76.76.2.0", "p0.freedns.controld.com", "/dns-query"),
    ("86.54.11.100", "unfiltered.joindns4.eu", "/dns-query"),
    ("88.198.92.222", "doh.libredns.gr", "/dns-query"),
    ("176.9.93.198", "dnsforge.de", "/dns-query"),
    ("5.2.75.75", "doh.nl.ahadns.net", "/dns-query"),
];

fn doh_pool() -> &'static Vec<hickory_resolver::TokioResolver> {
    static POOL: OnceLock<Vec<hickory_resolver::TokioResolver>> = OnceLock::new();
    POOL.get_or_init(|| {
        use hickory_resolver::config::{NameServerConfig, ResolverConfig};
        use hickory_resolver::net::runtime::TokioRuntimeProvider;
        use std::sync::Arc;

        DOH_PROVIDERS
            .iter()
            .filter_map(|(ip, server_name, path)| {
                let ip = ip.parse::<IpAddr>().ok()?;
                let nameserver =
                    NameServerConfig::https(ip, Arc::from(*server_name), Some(Arc::from(*path)));
                hickory_resolver::TokioResolver::builder_with_config(
                    ResolverConfig::from_parts(None, vec![], vec![nameserver]),
                    TokioRuntimeProvider::default(),
                )
                .build()
                .ok()
            })
            .collect()
    })
}

/// Cap on concurrent DoH lookups. Each one opens its own TLS session to a
/// provider, so this bounds sockets rather than answers.
fn doh_slots() -> &'static std::sync::Arc<Semaphore> {
    static SLOTS: OnceLock<std::sync::Arc<Semaphore>> = OnceLock::new();
    SLOTS.get_or_init(|| std::sync::Arc::new(Semaphore::new(64)))
}

/// How many providers are raced for one hostname before widening.
///
/// Racing the whole list per hostname is affordable for a handful of bridges
/// and ruinous for hundreds: 425 webtunnel hosts against 18 providers is 7650
/// lookups queued behind [`doh_slots`], each able to hold its permit for
/// [`DOH_PROVIDER_TIMEOUT`], while one bridge waits only
/// [`MIN_DNS_RESOLVE_TIMEOUT`] for its answer. Later bridges then failed DNS
/// having never been asked, and were recorded as dead bridges.
const DOH_FANOUT: usize = 4;

/// Waves of [`DOH_FANOUT`] providers tried for one hostname before giving up.
///
/// Two waves keep the worst case at `2 * DOH_PROVIDER_TIMEOUT`, inside the DNS
/// budget. Giving up on eight providers would be premature if the order were
/// arbitrary, but [`doh_order`] puts the ones answering on this network first,
/// so a wave is a considered choice rather than the head of a fixed list.
const DOH_MAX_WAVES: usize = 2;

/// Per-provider bound on one DoH lookup, so a blocked or black-holed provider
/// releases its [`doh_slots`] permit promptly instead of pinning it for the
/// caller's entire DNS budget.
const DOH_PROVIDER_TIMEOUT: Duration = Duration::from_secs(4);

/// One remembered resolution and the moment it stops being trustworthy.
///
/// An empty address list is a remembered *failure*: worth keeping, because a
/// bridge list points several lines at the same fronting host and a name that
/// nobody could resolve a moment ago is not worth eight more provider queries
/// in the same round.
#[derive(Clone)]
struct CachedAnswer {
    addrs: Vec<IpAddr>,
    expires_at: Instant,
}

/// Floor on how long an answer is kept.
///
/// Fronting hosts sit behind CDNs that publish 20-30 second TTLs. Honouring
/// those literally would re-resolve hundreds of names every round and rebuild
/// the very lookup storm the narrow fan-out exists to prevent; a minute is
/// still short next to the re-probe interval.
const DNS_MIN_TTL: Duration = Duration::from_secs(60);

/// Ceiling on how long an answer is kept, whatever the record claims. A
/// webtunnel bridge that moves to a new address has to become reachable again
/// without waiting for the process to restart.
const DNS_MAX_TTL: Duration = Duration::from_secs(30 * 60);

/// How long a failed resolution is remembered. Long enough to cover the
/// duplicate hostnames inside one round, short enough that a passing DoH
/// outage cannot keep a host unresolvable into the next one.
const DNS_NEGATIVE_TTL: Duration = Duration::from_secs(120);

/// Bound on remembered hosts. The pool churns as sources refresh, and entries
/// for bridges that have left it should not accumulate for the life of a VPN
/// session.
const DNS_CACHE_CAP: usize = 2048;

/// How long an expired (but not overwritten) positive answer stays eligible
/// as a last-resort fallback once every DoH provider is unreachable.
///
/// Far longer than [`DNS_MAX_TTL`] on purpose: a fully unreachable resolver
/// pool is evidence about the *network*, not about whether the bridge moved.
/// A self-hosted webtunnel bridge is far more likely to still be listening at
/// the same address after a few hours of DoH being down than to have both
/// moved AND had DoH recover in that same window. Never served in place of a
/// fresh lookup -- see [`stale_fallback_answer`].
const DNS_STALE_FALLBACK_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

/// Cache of DoH resolutions, positive and negative.
///
/// A bridge list routinely points many bridge lines at a handful of fronting
/// hosts, and every probe round re-resolves the same names. Each miss costs a
/// full TLS session to a DoH provider, so caching removes the bulk of the
/// resolution work from any round after the first.
fn doh_cache() -> &'static std::sync::Mutex<HashMap<String, CachedAnswer>> {
    static CACHE: OnceLock<std::sync::Mutex<HashMap<String, CachedAnswer>>> = OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

/// What the cache knows about a hostname right now.
enum CacheHit {
    /// Addresses still inside their TTL.
    Addrs(Vec<IpAddr>),
    /// Resolution failed recently; skip the providers and move on.
    Unresolvable,
}

fn cached_doh_answer(host: &str) -> Option<CacheHit> {
    let cache = doh_cache().lock().unwrap_or_else(|p| p.into_inner());
    let entry = cache.get(host)?;
    // Expired entries are no longer served here -- but are deliberately not
    // deleted either; they stay put for `stale_fallback_answer` until the
    // fallback window itself elapses (see `store_cached`'s retain criterion).
    if entry.expires_at <= Instant::now() {
        return None;
    }
    if entry.addrs.is_empty() {
        Some(CacheHit::Unresolvable)
    } else {
        Some(CacheHit::Addrs(entry.addrs.clone()))
    }
}

/// Last-resort answer for `host` when every DoH provider in this round's
/// wave(s) has failed: an expired-but-not-yet-stale-expired positive answer,
/// if one exists.
///
/// Never a substitute for a fresh lookup -- callers must attempt DoH first
/// (see `resolve_addrs`) and only reach for this once every provider failed.
/// Deliberately does not touch the cache: leaving the entry as-is lets it
/// keep serving as a fallback on a later attempt too, rather than being
/// clobbered by a negative marker the moment DoH has one bad round.
fn stale_fallback_answer(host: &str) -> Option<Vec<IpAddr>> {
    let cache = doh_cache().lock().unwrap_or_else(|p| p.into_inner());
    let entry = cache.get(host)?;
    if entry.addrs.is_empty() {
        return None; // a remembered failure has nothing to fall back to
    }
    let now = Instant::now();
    if entry.expires_at > now {
        return None; // still fresh -- cached_doh_answer already serves this
    }
    if now.duration_since(entry.expires_at) > DNS_STALE_FALLBACK_WINDOW {
        return None; // too old to trust
    }
    Some(entry.addrs.clone())
}

fn remember_doh_answer(host: &str, ips: &[IpAddr], valid_for: Duration) {
    let ttl = valid_for.clamp(DNS_MIN_TTL, DNS_MAX_TTL);
    store_cached(
        host,
        CachedAnswer {
            addrs: ips.to_vec(),
            expires_at: Instant::now() + ttl,
        },
    );
}

fn remember_doh_failure(host: &str) {
    store_cached(
        host,
        CachedAnswer {
            addrs: Vec::new(),
            expires_at: Instant::now() + DNS_NEGATIVE_TTL,
        },
    );
}

/// Drop what we remember about `host`.
///
/// Called when every address we handed out failed to connect. A cached answer
/// that no longer works is worse than no answer: without eviction the probe
/// would keep dialling the stale address for the rest of the TTL and keep
/// filing the bridge as dead. Re-resolving a host that is genuinely blocked
/// costs one lookup per round, which is what it cost before there was a cache.
fn forget_dns_answer(host: &str) {
    doh_cache()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(host);
}

fn store_cached(host: &str, answer: CachedAnswer) {
    let mut cache = doh_cache().lock().unwrap_or_else(|p| p.into_inner());
    if cache.len() >= DNS_CACHE_CAP {
        let now = Instant::now();
        // Sweep by the fallback window, not the TTL itself -- an expired-but-
        // still-fallback-eligible entry must survive cap pressure, or
        // `stale_fallback_answer` loses exactly the answers it exists for.
        cache.retain(|_, entry| entry.expires_at + DNS_STALE_FALLBACK_WINDOW > now);
        if cache.len() >= DNS_CACHE_CAP {
            // Still full: shed the ones closest to falling out of the
            // fallback window, which have the least left to give.
            let mut by_expiry: Vec<(String, Instant)> = cache
                .iter()
                .map(|(host, entry)| (host.clone(), entry.expires_at))
                .collect();
            by_expiry.sort_by_key(|(_, expires_at)| *expires_at);
            for (host, _) in by_expiry.into_iter().take(DNS_CACHE_CAP / 4) {
                cache.remove(&host);
            }
        }
    }
    cache.insert(host.to_owned(), answer);
}

/// Forget every cached answer and every provider score.
///
/// Both describe the network the device is attached to, not the bridges:
/// which resolver is reachable and which address a name maps to can both
/// change the moment the phone moves between mobile data and Wi-Fi. Carrying
/// the old answers across that boundary produces precisely the failure this
/// module exists to avoid — a live bridge dialled at an address that is no
/// longer right, and recorded as dead for it.
pub fn flush_dns_cache() {
    doh_cache()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clear();
    for slot in doh_scores() {
        slot.store(0, AtomicOrdering::Relaxed);
    }
    tracing::debug!("DNS cache and DoH provider scores cleared");
}

/// Wall-clock-anchored answer for the on-disk last-known-good store.
/// `Instant` cannot survive a process restart (no fixed epoch); this uses
/// Unix time instead. Only ever consulted as an absolute last resort (see
/// [`disk_fallback_answer`]) -- below both a fresh DoH lookup and the
/// in-memory [`stale_fallback_answer`], never a substitute for either.
struct PersistedAnswer {
    addrs: Vec<IpAddr>,
    resolved_at_unix: u64,
}

fn disk_fallback_store() -> &'static std::sync::Mutex<HashMap<String, PersistedAnswer>> {
    static STORE: OnceLock<std::sync::Mutex<HashMap<String, PersistedAnswer>>> = OnceLock::new();
    STORE.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One line per host: `host\tip1,ip2,...\tresolved_at_unix`. Plain text,
/// matching this codebase's other file-based persistence (e.g. the
/// active-bridges file) rather than pulling in a serialization dependency
/// for a handful of fields.
fn format_persisted_line(host: &str, entry: &PersistedAnswer) -> String {
    let addrs = entry
        .addrs
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    format!("{host}\t{addrs}\t{}", entry.resolved_at_unix)
}

fn parse_persisted_line(line: &str) -> Option<(String, PersistedAnswer)> {
    let mut parts = line.splitn(3, '\t');
    let host = parts.next()?.to_owned();
    let addrs: Vec<IpAddr> = parts
        .next()?
        .split(',')
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse().ok())
        .collect();
    let resolved_at_unix: u64 = parts.next()?.trim().parse().ok()?;
    if addrs.is_empty() {
        return None;
    }
    Some((host, PersistedAnswer { addrs, resolved_at_unix }))
}

/// Insert `entry` for `host` unless the store already holds a strictly newer
/// one. Shared by every writer of `disk_fallback_store` (the on-disk loader
/// and imported [`DnsHint`]s via [`seed_disk_fallback`]) so the two can race
/// in any order without either clobbering a more recent answer the other
/// already knows about.
fn merge_disk_fallback_entry(host: String, entry: PersistedAnswer) {
    let mut store = disk_fallback_store().lock().unwrap_or_else(|p| p.into_inner());
    let keep_existing = store
        .get(&host)
        .is_some_and(|existing| existing.resolved_at_unix >= entry.resolved_at_unix);
    if !keep_existing {
        store.insert(host, entry);
    }
}

/// Load the on-disk last-known-good DNS answers from a previous run into
/// memory, for [`disk_fallback_answer`] to serve once every DoH provider and
/// the in-memory stale fallback have both failed.
///
/// Call once at engine start. Deliberately independent of
/// [`flush_dns_cache`]'s wipe of the *live* cache: this store only ever acts
/// as an absolute last resort (see the age check in
/// [`disk_fallback_answer`]), so carrying it across a network change cannot
/// shadow a fresh answer -- it can only provide one where a cold start would
/// otherwise have none at all. Silently does nothing if the file is missing
/// or unreadable: a first run, or one with nothing worth persisting yet.
pub fn load_persisted_dns_cache(path: &std::path::Path) {
    let Ok(data) = std::fs::read_to_string(path) else {
        return;
    };
    let mut loaded = 0usize;
    for line in data.lines() {
        if let Some((host, entry)) = parse_persisted_line(line) {
            merge_disk_fallback_entry(host, entry);
            loaded += 1;
        }
    }
    tracing::debug!(loaded, path = %path.display(), "loaded persisted DNS fallback cache");
}

/// Persist every positive DNS answer currently in memory (fresh or still
/// within the stale-fallback window) to `path`, so a future cold start has
/// something to fall back to even before that run has resolved anything
/// itself. Call periodically (e.g. from the watchdog loop), not per-lookup.
pub fn save_persisted_dns_cache(path: &std::path::Path) -> std::io::Result<()> {
    let now = now_unix();
    let lines: Vec<String> = {
        let cache = doh_cache().lock().unwrap_or_else(|p| p.into_inner());
        cache
            .iter()
            .filter(|(_, entry)| !entry.addrs.is_empty())
            .map(|(host, entry)| {
                format_persisted_line(
                    host,
                    &PersistedAnswer {
                        addrs: entry.addrs.clone(),
                        resolved_at_unix: now,
                    },
                )
            })
            .collect()
    };
    std::fs::write(path, lines.join("\n"))
}

/// Last-resort answer for `host` sourced from a previous run, once every DoH
/// provider AND the in-memory [`stale_fallback_answer`] have failed. Same
/// [`DNS_STALE_FALLBACK_WINDOW`] bound, measured from when the entry was
/// persisted rather than from an in-memory TTL expiry.
fn disk_fallback_answer(host: &str) -> Option<Vec<IpAddr>> {
    let store = disk_fallback_store().lock().unwrap_or_else(|p| p.into_inner());
    let entry = store.get(host)?;
    let age = now_unix().saturating_sub(entry.resolved_at_unix);
    if age > DNS_STALE_FALLBACK_WINDOW.as_secs() {
        return None;
    }
    Some(entry.addrs.clone())
}

/// A portable DNS resolution, shareable across devices and processes.
///
/// Shareability is the whole point of this type existing separately from the
/// internal [`CachedAnswer`]/[`PersistedAnswer`] representations: an answer
/// only belongs here if the (host, addrs) pairing is a fact about the
/// Internet, not a fact about the network the resolving device happened to
/// be on. A CDN-fronted hostname's resolved IP is viewpoint-dependent and
/// must never become a `DnsHint` -- see [`best_known_answer`], the only
/// constructor, for where that line is actually drawn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsHint {
    pub host: String,
    pub addrs: Vec<IpAddr>,
    pub resolved_at_unix: u64,
}

/// Prefix marking a DNS-hint directive line among otherwise plain bridge
/// lines (see `proxy-config::BridgesConfig::parsed`, which must recognise
/// and divert these before attempting to parse a line as a `BridgeLine`).
/// Chosen to look like an ordinary comment to anything that does not know
/// about it, and to be unambiguous with any real bridge-line syntax.
pub const DNS_HINT_PREFIX: &str = "# xorbot:dns ";

/// Render one hint as `"{DNS_HINT_PREFIX}{host} {ip1,ip2,...} {resolved_at_unix}"`.
pub fn format_dns_hint_line(hint: &DnsHint) -> String {
    let addrs = hint
        .addrs
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    format!("{DNS_HINT_PREFIX}{} {addrs} {}", hint.host, hint.resolved_at_unix)
}

/// Parse one directive line produced by [`format_dns_hint_line`]. `None` for
/// anything that is not a well-formed hint line, including a plain bridge
/// line or an unrelated comment -- callers should treat that the same as
/// "not a hint", never as an error.
pub fn parse_dns_hint_line(line: &str) -> Option<DnsHint> {
    let rest = line.strip_prefix(DNS_HINT_PREFIX)?;
    let mut parts = rest.split_whitespace();
    let host = parts.next()?.to_owned();
    let addrs: Vec<IpAddr> = parts
        .next()?
        .split(',')
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse().ok())
        .collect();
    let resolved_at_unix: u64 = parts.next()?.parse().ok()?;
    if addrs.is_empty() {
        return None;
    }
    Some(DnsHint {
        host,
        addrs,
        resolved_at_unix,
    })
}

/// The hostname `bridge` needs resolved, if any.
///
/// `None` when the bridge's own target is already a literal IP (obfs4 and
/// plain bridges: the address in the bridge line itself; a webtunnel bridge
/// pinned via `addr=`) -- there is nothing to hint at for those. `Some` only
/// for a webtunnel bridge whose target comes from a `url=` hostname, the one
/// case that actually costs a DNS lookup.
pub fn dns_hostname_of(bridge: &BridgeLine) -> Option<String> {
    let (host, _port) = resolve_probe_target(bridge).ok()?;
    if host.parse::<IpAddr>().is_ok() {
        return None;
    }
    Some(host)
}

/// The best answer currently known for `host`, wall-clock-stamped, from
/// whichever tier has one: the live cache (fresh, or stale-but-inside the
/// fallback window) first, then the on-disk store from a previous run.
/// Read-only -- never attempts a network resolution. This is the query side
/// of exporting [`DnsHint`]s (see `dns_hostname_of` for picking which
/// bridges are worth asking about); resolving a hostname to serve live
/// traffic goes through [`resolve_addrs`] instead.
pub fn best_known_answer(host: &str) -> Option<DnsHint> {
    {
        let cache = doh_cache().lock().unwrap_or_else(|p| p.into_inner());
        if let Some(entry) = cache.get(host) {
            if !entry.addrs.is_empty() {
                let now = Instant::now();
                let fresh_or_recent = entry.expires_at > now
                    || now.duration_since(entry.expires_at) <= DNS_STALE_FALLBACK_WINDOW;
                if fresh_or_recent {
                    return Some(DnsHint {
                        host: host.to_owned(),
                        addrs: entry.addrs.clone(),
                        resolved_at_unix: now_unix(),
                    });
                }
            }
        }
    }
    let store = disk_fallback_store().lock().unwrap_or_else(|p| p.into_inner());
    let entry = store.get(host)?;
    let age = now_unix().saturating_sub(entry.resolved_at_unix);
    if age > DNS_STALE_FALLBACK_WINDOW.as_secs() {
        return None;
    }
    Some(DnsHint {
        host: host.to_owned(),
        addrs: entry.addrs.clone(),
        resolved_at_unix: entry.resolved_at_unix,
    })
}

/// Merge imported [`DnsHint`]s into the on-disk fallback store, so an
/// imported bridge (typically from a QR code, see
/// `proxy-config::BridgesConfig::parsed`'s scope check on the caller side)
/// can skip DNS entirely on a device whose network cannot resolve it.
///
/// Last-write-wins by `resolved_at_unix` via the same merge as
/// [`load_persisted_dns_cache`] -- call order between the two never matters.
pub fn seed_disk_fallback(hints: &[DnsHint]) {
    for hint in hints {
        merge_disk_fallback_entry(
            hint.host.clone(),
            PersistedAnswer {
                addrs: hint.addrs.clone(),
                resolved_at_unix: hint.resolved_at_unix,
            },
        );
    }
}

/// Running tally per provider: `+1` when it answers, `-1` when it does not.
///
/// Which providers are usable is a property of the network, not of the
/// hostname being looked up, so it is worth learning once and reusing. Without
/// this, every hostname pays the same timeouts against the same blocked
/// providers; with it, a censored provider sinks below the working ones after
/// the first few lookups of a round and the narrow fan-out above stays cheap.
fn doh_scores() -> &'static Vec<AtomicI64> {
    static SCORES: OnceLock<Vec<AtomicI64>> = OnceLock::new();
    SCORES.get_or_init(|| doh_pool().iter().map(|_| AtomicI64::new(0)).collect())
}

/// Bound on the tally so a provider that worked all day cannot need an equally
/// long run of failures before the order reacts to it going dark.
const DOH_SCORE_LIMIT: i64 = 8;

fn note_doh_result(index: usize, answered: bool) {
    let Some(slot) = doh_scores().get(index) else {
        return;
    };
    let delta = if answered { 1 } else { -1 };
    let _ = slot.fetch_update(
        AtomicOrdering::Relaxed,
        AtomicOrdering::Relaxed,
        |current| Some((current + delta).clamp(-DOH_SCORE_LIMIT, DOH_SCORE_LIMIT)),
    );
}

/// Provider indices, best-scoring first. Ties keep the declaration order, so
/// an untried pool resolves against the list as written.
fn doh_order() -> Vec<usize> {
    let scores = doh_scores();
    let mut order: Vec<usize> = (0..scores.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(scores[i].load(AtomicOrdering::Relaxed)));
    order
}

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
fn parse_webtunnel_url(url_str: &str) -> Result<url::Url, String> {
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
const MIN_DNS_RESOLVE_TIMEOUT: Duration = Duration::from_secs(15);

/// Resolve the probe target for `bridge`, then perform a TCP handshake.
/// DNS resolution (when needed) gets its own budget — at least
/// [`MIN_DNS_RESOLVE_TIMEOUT`] — on top of the TCP probe's.
async fn resolve_and_probe(
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
const MIN_WEBTUNNEL_TIMEOUT: Duration = Duration::from_secs(12);

/// Largest response head we will read while looking for the status line.
const WEBTUNNEL_HEAD_LIMIT: usize = 8 * 1024;

fn webtunnel_tls_config() -> std::sync::Arc<rustls::ClientConfig> {
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
async fn webtunnel_upgrade_probe(
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

async fn webtunnel_upgrade_inner(addr: SocketAddr, host: &str, url: &str) -> Result<(), String> {
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
const MAX_PROBE_ADDRS: usize = 3;

/// Order resolved addresses so an unroutable family costs a failed `connect`
/// rather than the whole bridge.
///
/// The phone that exposed this has no IPv6 route at all, only the app's own
/// `tun0`, so every AAAA answer came back `Network is unreachable` and the
/// bridge was filed as dead — 29% of one round's webtunnel failures. IPv4 goes
/// first because it is the family that is nearly always routable, but both are
/// tried: an unroutable address fails instantly, so the ordering costs a
/// dual-stack host nothing and rescues a single-stack one.
fn order_candidates(ips: &[IpAddr], port: u16) -> Vec<SocketAddr> {
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
async fn race_doh_wave(wave: &[usize], query: &str) -> Option<(Vec<IpAddr>, Duration)> {
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
async fn tcp_probe(addrs: &[SocketAddr], per_bridge_timeout: Duration) -> Outcome {
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
const MAX_INFLIGHT_PROBES: usize = 64;

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

fn summarise(reports: &[Report]) {
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

    /// The cache tests share one process-wide map, so each uses its own
    /// hostname and cleans up after itself rather than flushing the lot.
    #[test]
    fn cached_answer_is_returned_until_it_expires() {
        let host = "cache-hit.test.invalid";
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        remember_doh_answer(host, &[ip], Duration::from_secs(300));

        match cached_doh_answer(host) {
            Some(CacheHit::Addrs(addrs)) => assert_eq!(addrs, vec![ip]),
            _ => panic!("a fresh answer must be served from the cache"),
        }

        forget_dns_answer(host);
        assert!(cached_doh_answer(host).is_none());
    }

    #[test]
    fn expired_answer_is_not_served_by_the_normal_path() {
        let host = "cache-stale.test.invalid";
        // Straight into the map with an expiry already in the past — the
        // public helper clamps TTLs upwards, so it cannot express this.
        store_cached(
            host,
            CachedAnswer {
                addrs: vec!["203.0.113.8".parse().unwrap()],
                expires_at: Instant::now() - Duration::from_secs(1),
            },
        );
        assert!(cached_doh_answer(host).is_none());
        // Deliberately NOT dropped: an expired-but-recent positive answer
        // must survive for `stale_fallback_answer` to serve as a last
        // resort when every DoH provider is unreachable.
        assert!(
            doh_cache().lock().unwrap().contains_key(host),
            "an expired positive answer must stay available for the stale fallback"
        );
        forget_dns_answer(host);
    }

    #[test]
    fn stale_fallback_serves_a_recently_expired_positive_answer() {
        let host = "cache-stale-fallback.test.invalid";
        let ip: IpAddr = "203.0.113.20".parse().unwrap();
        store_cached(
            host,
            CachedAnswer {
                addrs: vec![ip],
                expires_at: Instant::now() - Duration::from_secs(60),
            },
        );
        assert_eq!(stale_fallback_answer(host), Some(vec![ip]));
        forget_dns_answer(host);
    }

    #[test]
    fn stale_fallback_refuses_an_answer_past_the_fallback_window() {
        let host = "cache-too-stale.test.invalid";
        store_cached(
            host,
            CachedAnswer {
                addrs: vec!["203.0.113.21".parse().unwrap()],
                expires_at: Instant::now() - DNS_STALE_FALLBACK_WINDOW - Duration::from_secs(1),
            },
        );
        assert!(stale_fallback_answer(host).is_none());
        forget_dns_answer(host);
    }

    #[test]
    fn stale_fallback_refuses_a_fresh_answer() {
        // A still-valid entry must be served by `cached_doh_answer`, not by
        // the stale path -- `resolve_addrs` only calls the latter after a
        // live DoH round has already failed.
        let host = "cache-fresh-not-stale.test.invalid";
        remember_doh_answer(host, &["203.0.113.22".parse().unwrap()], Duration::from_secs(300));
        assert!(stale_fallback_answer(host).is_none());
        forget_dns_answer(host);
    }

    #[test]
    fn stale_fallback_refuses_a_remembered_failure() {
        let host = "cache-negative-not-stale.test.invalid";
        remember_doh_failure(host);
        // Force it into the past so it would otherwise look "expired".
        {
            let mut cache = doh_cache().lock().unwrap();
            cache.get_mut(host).unwrap().expires_at = Instant::now() - Duration::from_secs(1);
        }
        assert!(stale_fallback_answer(host).is_none());
        forget_dns_answer(host);
    }

    #[test]
    fn persisted_line_round_trips() {
        let entry = PersistedAnswer {
            addrs: vec!["203.0.113.30".parse().unwrap(), "203.0.113.31".parse().unwrap()],
            resolved_at_unix: 1_700_000_000,
        };
        let line = format_persisted_line("example.test.invalid", &entry);
        let (host, parsed) = parse_persisted_line(&line).expect("line must parse back");
        assert_eq!(host, "example.test.invalid");
        assert_eq!(parsed.addrs, entry.addrs);
        assert_eq!(parsed.resolved_at_unix, entry.resolved_at_unix);
    }

    #[test]
    fn parse_persisted_line_rejects_garbage() {
        assert!(parse_persisted_line("").is_none());
        assert!(parse_persisted_line("only-a-host").is_none());
        assert!(parse_persisted_line("host\t\tnotanumber").is_none());
        assert!(parse_persisted_line("host\tnotanip\t123").is_none());
    }

    #[test]
    fn save_and_load_persisted_cache_round_trips_through_disk_fallback() {
        let host = "cache-disk-roundtrip.test.invalid";
        let ip: IpAddr = "203.0.113.40".parse().unwrap();
        remember_doh_answer(host, &[ip], Duration::from_secs(300));

        let dir = std::env::temp_dir().join(format!("bridge-probe-dns-cache-test-{}", now_unix()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("dns-cache.txt");
        save_persisted_dns_cache(&path).expect("save must succeed");
        forget_dns_answer(host); // wipe the in-memory entry entirely

        load_persisted_dns_cache(&path);
        assert_eq!(disk_fallback_answer(host), Some(vec![ip]));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn disk_fallback_refuses_an_answer_past_the_fallback_window() {
        let host = "cache-disk-too-stale.test.invalid";
        {
            let mut store = disk_fallback_store().lock().unwrap();
            store.insert(
                host.to_owned(),
                PersistedAnswer {
                    addrs: vec!["203.0.113.41".parse().unwrap()],
                    resolved_at_unix: now_unix() - DNS_STALE_FALLBACK_WINDOW.as_secs() - 1,
                },
            );
        }
        assert!(disk_fallback_answer(host).is_none());
    }

    #[test]
    fn load_persisted_dns_cache_is_a_no_op_for_a_missing_file() {
        // Must not panic -- a first run, or one predating this feature.
        load_persisted_dns_cache(std::path::Path::new("/nonexistent/does-not-exist.txt"));
    }

    #[test]
    fn dns_hint_line_round_trips() {
        let hint = DnsHint {
            host: "bridge.example.test".to_owned(),
            addrs: vec!["198.51.100.5".parse().unwrap(), "198.51.100.6".parse().unwrap()],
            resolved_at_unix: 1_700_000_500,
        };
        let line = format_dns_hint_line(&hint);
        assert!(line.starts_with(DNS_HINT_PREFIX));
        assert_eq!(parse_dns_hint_line(&line), Some(hint));
    }

    #[test]
    fn parse_dns_hint_line_rejects_non_hint_lines() {
        assert!(parse_dns_hint_line("obfs4 1.2.3.4:443 ABCDEF cert=x").is_none());
        assert!(parse_dns_hint_line("# just a comment").is_none());
        assert!(parse_dns_hint_line("").is_none());
        assert!(parse_dns_hint_line("# xorbot:dns onlyhost").is_none());
        assert!(parse_dns_hint_line("# xorbot:dns host notanip 123").is_none());
    }

    #[test]
    fn dns_hostname_of_is_none_for_ip_only_bridges() {
        let obfs4: BridgeLine =
            "obfs4 192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0"
                .parse()
                .unwrap();
        assert_eq!(dns_hostname_of(&obfs4), None);

        let webtunnel_addr: BridgeLine =
            "webtunnel 192.0.2.2:1 0123456789ABCDEF0123456789ABCDEF01234567 addr=192.0.2.9:443 url=https://example.com/x"
                .parse()
                .unwrap();
        assert_eq!(dns_hostname_of(&webtunnel_addr), None);
    }

    #[test]
    fn dns_hostname_of_finds_the_webtunnel_url_host() {
        let webtunnel: BridgeLine =
            "webtunnel 192.0.2.3:1 0123456789ABCDEF0123456789ABCDEF01234567 url=https://fronting.example.test/x"
                .parse()
                .unwrap();
        assert_eq!(
            dns_hostname_of(&webtunnel),
            Some("fronting.example.test".to_owned())
        );
    }

    #[test]
    fn best_known_answer_prefers_live_cache_over_disk() {
        let host = "best-answer-live.test.invalid";
        let live_ip: IpAddr = "203.0.113.50".parse().unwrap();
        remember_doh_answer(host, &[live_ip], Duration::from_secs(300));
        {
            let mut store = disk_fallback_store().lock().unwrap();
            store.insert(
                host.to_owned(),
                PersistedAnswer {
                    addrs: vec!["203.0.113.51".parse().unwrap()],
                    resolved_at_unix: now_unix(),
                },
            );
        }
        let hint = best_known_answer(host).expect("must find an answer");
        assert_eq!(hint.addrs, vec![live_ip]);
        forget_dns_answer(host);
    }

    #[test]
    fn best_known_answer_falls_back_to_disk_when_live_cache_is_empty() {
        let host = "best-answer-disk.test.invalid";
        let ip: IpAddr = "203.0.113.52".parse().unwrap();
        {
            let mut store = disk_fallback_store().lock().unwrap();
            store.insert(
                host.to_owned(),
                PersistedAnswer {
                    addrs: vec![ip],
                    resolved_at_unix: now_unix(),
                },
            );
        }
        let hint = best_known_answer(host).expect("must find an answer");
        assert_eq!(hint.addrs, vec![ip]);
    }

    #[test]
    fn best_known_answer_is_none_when_nothing_is_known() {
        assert!(best_known_answer("never-seen.test.invalid").is_none());
    }

    #[test]
    fn seed_disk_fallback_respects_last_write_wins() {
        let host = "seed-lww.test.invalid";
        let older: IpAddr = "203.0.113.60".parse().unwrap();
        let newer: IpAddr = "203.0.113.61".parse().unwrap();
        seed_disk_fallback(&[DnsHint {
            host: host.to_owned(),
            addrs: vec![newer],
            resolved_at_unix: 2_000_000_000,
        }]);
        // An older hint must not overwrite the newer one already seeded.
        seed_disk_fallback(&[DnsHint {
            host: host.to_owned(),
            addrs: vec![older],
            resolved_at_unix: 1_000_000_000,
        }]);
        assert_eq!(
            disk_fallback_store().lock().unwrap().get(host).unwrap().addrs,
            vec![newer]
        );
    }

    #[test]
    fn a_failed_resolution_is_remembered_briefly() {
        let host = "cache-negative.test.invalid";
        remember_doh_failure(host);
        assert!(matches!(
            cached_doh_answer(host),
            Some(CacheHit::Unresolvable)
        ));
        forget_dns_answer(host);
    }

    #[test]
    fn ttl_is_clamped_into_the_useful_range() {
        let host = "cache-ttl.test.invalid";
        let ip: IpAddr = "203.0.113.9".parse().unwrap();

        // A CDN's 20-second TTL must not send us back to the providers on the
        // next round.
        remember_doh_answer(host, &[ip], Duration::from_secs(20));
        let floor = doh_cache().lock().unwrap()[host].expires_at;
        assert!(floor >= Instant::now() + DNS_MIN_TTL - Duration::from_secs(1));

        // A record claiming a day must not outlive the bridge moving.
        remember_doh_answer(host, &[ip], Duration::from_secs(86_400));
        let ceiling = doh_cache().lock().unwrap()[host].expires_at;
        assert!(ceiling <= Instant::now() + DNS_MAX_TTL);

        forget_dns_answer(host);
    }

    #[test]
    fn scheme_less_webtunnel_url_is_read_as_https() {
        let url = parse_webtunnel_url("tor.cenesp.es").expect("a bare host is accepted");
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("tor.cenesp.es"));
    }

    #[test]
    fn candidates_put_ipv4_ahead_of_ipv6() {
        let ips: Vec<IpAddr> = vec![
            "2001:4860:4860::8888".parse().unwrap(),
            "93.184.216.34".parse().unwrap(),
        ];
        let ordered = order_candidates(&ips, 443);
        assert_eq!(ordered.len(), 2);
        assert!(ordered[0].is_ipv4(), "IPv4 must be tried first");
        assert!(ordered[1].is_ipv6(), "IPv6 is still tried, just second");
    }

    #[test]
    fn candidates_drop_duplicates_and_cap_the_list() {
        let ips: Vec<IpAddr> = vec![
            "10.0.0.1".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            "10.0.0.3".parse().unwrap(),
            "10.0.0.4".parse().unwrap(),
        ];
        let ordered = order_candidates(&ips, 443);
        assert_eq!(ordered.len(), MAX_PROBE_ADDRS);
        assert_eq!(ordered[0].ip(), "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(ordered[1].ip(), "10.0.0.2".parse::<IpAddr>().unwrap());
    }

    /// A bridge we could not resolve must not be reported as dead — that
    /// verdict belongs to the resolver, not the bridge.
    #[tokio::test]
    async fn unresolvable_hostname_is_unmeasured_rather_than_unreachable() {
        let bridge = BridgeLine::from_str(
            "webtunnel [2001:db8::1]:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 \
             url=https://nothing.invalid/secret",
        )
        .expect("webtunnel bridge line parses");

        let no_resolver = ResolverPolicy {
            doh_enabled: false,
            system_fallback: false,
        };
        let reports =
            probe_all_with_policy(vec![bridge], Duration::from_millis(200), no_resolver).await;

        assert_eq!(reports.len(), 1);
        assert!(reports[0].is_unmeasured());
        assert!(!reports[0].is_reachable());
        assert!(reports[0].latency().is_none());
    }

    /// The round's two halves must stay separate all the way to the caller.
    #[tokio::test]
    async fn probe_round_keeps_unmeasured_out_of_alive() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let unresolvable = BridgeLine::from_str(
            "webtunnel [2001:db8::1]:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 \
             url=https://nothing.invalid/secret",
        )
        .unwrap();

        let round = probe_round_with_policy(
            vec![bridge_for(addr), unresolvable],
            Duration::from_millis(500),
            ResolverPolicy {
                doh_enabled: false,
                system_fallback: false,
            },
        )
        .await;

        assert_eq!(round.alive.len(), 1);
        assert_eq!(round.unmeasured.len(), 1);
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
    fn default_resolver_policy_uses_doh_without_system_fallback() {
        assert!(ResolverPolicy::default().doh_enabled);
        assert!(!ResolverPolicy::default().system_fallback);
        assert!(
            DOH_PROVIDERS.len() >= 10,
            "keep a broad provider/address pool"
        );
    }

    #[tokio::test]
    async fn disabled_resolvers_fail_hostname_explicitly() {
        let result = resolve_addrs(
            "bridge.example.invalid",
            443,
            ResolverPolicy {
                doh_enabled: false,
                system_fallback: false,
            },
        )
        .await;
        let error = result.expect_err("both resolver paths are disabled");
        assert!(error.contains("no DNS resolver available"));
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
    fn rejects_documentation_ipv6_bridge_addresses() {
        // A plain bridge with a 2001:db8::/32 ORPort is a real placeholder.
        let bridge: BridgeLine =
            "obfs4 [2001:db8::1]:443 2852538D49D7D73C1A6694FC492104983A9C4FA2 cert=AAA iat-mode=0"
                .parse()
                .expect("bridge line parses");
        assert!(!usable_for_tor(&bridge));
    }

    #[test]
    fn keeps_webtunnel_with_documentation_orport_placeholder() {
        // webtunnel legitimately uses a 2001:db8::/32 ORPort placeholder; the
        // real endpoint is in url=, so the bridge must be kept.
        let bridge: BridgeLine =
            "webtunnel [2001:db8::1]:443 2852538D49D7D73C1A6694FC492104983A9C4FA2 url=https://example.com/x"
                .parse()
                .expect("bridge line parses");
        assert!(usable_for_tor(&bridge));
    }

    #[test]
    fn rejects_webtunnel_missing_url_and_addr() {
        let bridge: BridgeLine =
            "webtunnel [2001:db8::1]:443 2852538D49D7D73C1A6694FC492104983A9C4FA2 ver=0.0.3"
                .parse()
                .expect("bridge line parses");
        assert!(!usable_for_tor(&bridge));
    }

    #[test]
    fn keeps_public_ipv4_bridge_addresses_usable() {
        let bridge: BridgeLine =
            "obfs4 5.45.101.108:36781 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0"
                .parse()
                .expect("bridge line parses");
        assert!(usable_for_tor(&bridge));
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
