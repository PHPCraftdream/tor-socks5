use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use crate::dns::{self, CachedAnswer, DNS_NETWORK_GENERATION};

/// Identifies one observed cache value. The generation rejects answers from a
/// previous network, while the version rejects a replacement in the same
/// generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CacheIdentity {
    pub(crate) generation: u64,
    pub(crate) version: u64,
}

static NEXT_CACHE_VERSION: AtomicU64 = AtomicU64::new(1);

pub(crate) fn next_cache_version() -> u64 {
    NEXT_CACHE_VERSION.fetch_add(1, Ordering::Relaxed)
}

pub(crate) fn cache_identity(entry: &CachedAnswer) -> CacheIdentity {
    CacheIdentity {
        generation: entry.generation,
        version: entry.version,
    }
}

#[cfg(test)]
pub(crate) fn cached_doh_answer(host: &str) -> Option<dns::CacheHit> {
    cached_doh_answer_observed(host).map(|(addrs, _)| {
        if addrs.is_empty() {
            dns::CacheHit::Unresolvable
        } else {
            dns::CacheHit::Addrs(addrs)
        }
    })
}

pub(crate) fn cached_doh_answer_observed(host: &str) -> Option<(Vec<IpAddr>, CacheIdentity)> {
    let cache = dns::doh_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let entry = cache.get(host)?;
    if entry.expires_at <= Instant::now() {
        return None;
    }
    Some((entry.addrs.clone(), cache_identity(entry)))
}

#[cfg(test)]
pub(crate) fn stale_fallback_answer(host: &str) -> Option<Vec<IpAddr>> {
    stale_fallback_answer_observed(host).map(|(addrs, _)| addrs)
}

pub(crate) fn stale_fallback_answer_observed(host: &str) -> Option<(Vec<IpAddr>, CacheIdentity)> {
    let cache = dns::doh_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let entry = cache.get(host)?;
    if entry.addrs.is_empty() {
        return None;
    }
    let now = Instant::now();
    if entry.expires_at > now
        || now.duration_since(entry.expires_at) > dns::DNS_STALE_FALLBACK_WINDOW
    {
        return None;
    }
    Some((entry.addrs.clone(), cache_identity(entry)))
}

/// Drop the remembered answer for `host`. The cache entry and its identity are
/// removed under one lock, so a concurrent replacement cannot lose its marker.
#[cfg(test)]
pub(crate) fn forget_dns_answer(host: &str) {
    dns::doh_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(host);
}

/// Invalidate only the cache entry that supplied every address actually tried
/// by a failed probe. A resolver may return more addresses than the probe
/// budget permits, so untried cached addresses must not block invalidation.
/// A newer answer or a different network generation is left intact.
pub(crate) fn invalidate_if_current(
    host: &str,
    observed: CacheIdentity,
    tried_addrs: &[IpAddr],
) -> bool {
    if DNS_NETWORK_GENERATION.load(Ordering::SeqCst) != observed.generation {
        return false;
    }
    let mut cache = dns::doh_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(entry) = cache.get(host) else {
        return false;
    };
    if cache_identity(entry) != observed
        || entry.addrs.is_empty()
        || tried_addrs.is_empty()
        || !tried_addrs.iter().all(|ip| entry.addrs.contains(ip))
    {
        return false;
    }
    cache.remove(host);
    true
}
