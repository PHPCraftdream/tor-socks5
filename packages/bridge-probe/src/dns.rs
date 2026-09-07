use super::probe::resolve_probe_target;
use super::*;

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
pub(super) const DOH_PROVIDERS: &[(&str, &str, &str)] = &[
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

pub(super) fn doh_pool() -> &'static Vec<hickory_resolver::TokioResolver> {
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
pub(super) fn doh_slots() -> &'static std::sync::Arc<Semaphore> {
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
pub(super) const DOH_FANOUT: usize = 4;

/// Waves of [`DOH_FANOUT`] providers tried for one hostname before giving up.
///
/// Two waves keep the worst case at `2 * DOH_PROVIDER_TIMEOUT`, inside the DNS
/// budget. Giving up on eight providers would be premature if the order were
/// arbitrary, but [`doh_order`] puts the ones answering on this network first,
/// so a wave is a considered choice rather than the head of a fixed list.
pub(super) const DOH_MAX_WAVES: usize = 2;

/// Per-provider bound on one DoH lookup, so a blocked or black-holed provider
/// releases its [`doh_slots`] permit promptly instead of pinning it for the
/// caller's entire DNS budget.
pub(super) const DOH_PROVIDER_TIMEOUT: Duration = Duration::from_secs(4);

/// One remembered resolution and the moment it stops being trustworthy.
///
/// An empty address list is a remembered *failure*: worth keeping, because a
/// bridge list points several lines at the same fronting host and a name that
/// nobody could resolve a moment ago is not worth eight more provider queries
/// in the same round.
#[derive(Clone)]
pub(super) struct CachedAnswer {
    pub(super) addrs: Vec<IpAddr>,
    pub(super) expires_at: Instant,
}

/// Floor on how long an answer is kept.
///
/// Fronting hosts sit behind CDNs that publish 20-30 second TTLs. Honouring
/// those literally would re-resolve hundreds of names every round and rebuild
/// the very lookup storm the narrow fan-out exists to prevent; a minute is
/// still short next to the re-probe interval.
pub(super) const DNS_MIN_TTL: Duration = Duration::from_secs(60);

/// Ceiling on how long an answer is kept, whatever the record claims. A
/// webtunnel bridge that moves to a new address has to become reachable again
/// without waiting for the process to restart.
pub(super) const DNS_MAX_TTL: Duration = Duration::from_secs(30 * 60);

/// How long a failed resolution is remembered. Long enough to cover the
/// duplicate hostnames inside one round, short enough that a passing DoH
/// outage cannot keep a host unresolvable into the next one.
pub(super) const DNS_NEGATIVE_TTL: Duration = Duration::from_secs(120);

/// Bound on remembered hosts. The pool churns as sources refresh, and entries
/// for bridges that have left it should not accumulate for the life of a VPN
/// session.
pub(super) const DNS_CACHE_CAP: usize = 2048;

/// How long an expired (but not overwritten) positive answer stays eligible
/// as a last-resort fallback once every DoH provider is unreachable.
///
/// Far longer than [`DNS_MAX_TTL`] on purpose: a fully unreachable resolver
/// pool is evidence about the *network*, not about whether the bridge moved.
/// A self-hosted webtunnel bridge is far more likely to still be listening at
/// the same address after a few hours of DoH being down than to have both
/// moved AND had DoH recover in that same window. Never served in place of a
/// fresh lookup -- see [`stale_fallback_answer`].
pub(super) const DNS_STALE_FALLBACK_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

/// Cache of DoH resolutions, positive and negative.
///
/// A bridge list routinely points many bridge lines at a handful of fronting
/// hosts, and every probe round re-resolves the same names. Each miss costs a
/// full TLS session to a DoH provider, so caching removes the bulk of the
/// resolution work from any round after the first.
pub(super) fn doh_cache() -> &'static std::sync::Mutex<HashMap<String, CachedAnswer>> {
    static CACHE: OnceLock<std::sync::Mutex<HashMap<String, CachedAnswer>>> = OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

/// What the cache knows about a hostname right now.
pub(super) enum CacheHit {
    /// Addresses still inside their TTL.
    Addrs(Vec<IpAddr>),
    /// Resolution failed recently; skip the providers and move on.
    Unresolvable,
}

pub(super) fn cached_doh_answer(host: &str) -> Option<CacheHit> {
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
pub(super) fn stale_fallback_answer(host: &str) -> Option<Vec<IpAddr>> {
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

pub(super) fn remember_doh_answer(host: &str, ips: &[IpAddr], valid_for: Duration) {
    let ttl = valid_for.clamp(DNS_MIN_TTL, DNS_MAX_TTL);
    store_cached(
        host,
        CachedAnswer {
            addrs: ips.to_vec(),
            expires_at: Instant::now() + ttl,
        },
    );
}

pub(super) fn remember_doh_failure(host: &str) {
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
pub(super) fn forget_dns_answer(host: &str) {
    doh_cache()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(host);
}

pub(super) fn store_cached(host: &str, answer: CachedAnswer) {
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
pub(super) struct PersistedAnswer {
    pub(super) addrs: Vec<IpAddr>,
    pub(super) resolved_at_unix: u64,
}

pub(super) fn disk_fallback_store() -> &'static std::sync::Mutex<HashMap<String, PersistedAnswer>> {
    static STORE: OnceLock<std::sync::Mutex<HashMap<String, PersistedAnswer>>> = OnceLock::new();
    STORE.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

pub(super) fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One line per host: `host\tip1,ip2,...\tresolved_at_unix`. Plain text,
/// matching this codebase's other file-based persistence (e.g. the
/// active-bridges file) rather than pulling in a serialization dependency
/// for a handful of fields.
pub(super) fn format_persisted_line(host: &str, entry: &PersistedAnswer) -> String {
    let addrs = entry
        .addrs
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    format!("{host}\t{addrs}\t{}", entry.resolved_at_unix)
}

pub(super) fn parse_persisted_line(line: &str) -> Option<(String, PersistedAnswer)> {
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
    Some((
        host,
        PersistedAnswer {
            addrs,
            resolved_at_unix,
        },
    ))
}

/// Insert `entry` for `host` unless the store already holds a strictly newer
/// one. Shared by every writer of `disk_fallback_store` (the on-disk loader
/// and imported [`DnsHint`]s via [`seed_disk_fallback`]) so the two can race
/// in any order without either clobbering a more recent answer the other
/// already knows about.
pub(super) fn merge_disk_fallback_entry(host: String, entry: PersistedAnswer) {
    let mut store = disk_fallback_store()
        .lock()
        .unwrap_or_else(|p| p.into_inner());
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
pub(super) fn disk_fallback_answer(host: &str) -> Option<Vec<IpAddr>> {
    let store = disk_fallback_store()
        .lock()
        .unwrap_or_else(|p| p.into_inner());
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
    format!(
        "{DNS_HINT_PREFIX}{} {addrs} {}",
        hint.host, hint.resolved_at_unix
    )
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
    let store = disk_fallback_store()
        .lock()
        .unwrap_or_else(|p| p.into_inner());
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
pub(super) fn doh_scores() -> &'static Vec<AtomicI64> {
    static SCORES: OnceLock<Vec<AtomicI64>> = OnceLock::new();
    SCORES.get_or_init(|| doh_pool().iter().map(|_| AtomicI64::new(0)).collect())
}

/// Bound on the tally so a provider that worked all day cannot need an equally
/// long run of failures before the order reacts to it going dark.
pub(super) const DOH_SCORE_LIMIT: i64 = 8;

pub(super) fn note_doh_result(index: usize, answered: bool) {
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
pub(super) fn doh_order() -> Vec<usize> {
    let scores = doh_scores();
    let mut order: Vec<usize> = (0..scores.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(scores[i].load(AtomicOrdering::Relaxed)));
    order
}
