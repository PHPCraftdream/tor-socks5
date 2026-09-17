//! Portable DNS hints: the shareable `# xorbot:dns` directive lines that
//! travel inside bridge-store files.
//!
//! Split out of `dns.rs` (which owns the live DoH cache and the on-disk
//! fallback store) because this is a distinct concern -- a wire format plus
//! the one rule deciding which answers may legitimately enter it -- and
//! because `dns.rs` reached the repository's per-file line limit.

use std::net::IpAddr;
use std::time::Instant;

use bridge_line::BridgeLine;

use crate::dns::{
    disk_fallback_store, doh_cache, live_entry_is_usable, merge_disk_fallback_entry, now_unix,
    stamp_beyond_future_tolerance, PersistedAnswer, DNS_STALE_FALLBACK_WINDOW,
};
use crate::probe::resolve_probe_target;

/// A portable DNS resolution, shareable across devices and processes.
///
/// Shareability is the whole point of this type existing separately from the
/// internal `CachedAnswer`/`PersistedAnswer` representations: an answer
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
/// "not a hint", never as an error. A `resolved_at_unix` further ahead than
/// a timestamp beyond the configured future tolerance is likewise rejected.
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
    if addrs.is_empty() || stamp_beyond_future_tolerance(resolved_at_unix) {
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
/// traffic goes through the crate's `resolve_addrs` API instead.
pub fn best_known_answer(host: &str) -> Option<DnsHint> {
    {
        let cache = doh_cache().lock().unwrap_or_else(|p| p.into_inner());
        if let Some(entry) = cache.get(host) {
            if !entry.addrs.is_empty() && live_entry_is_usable(entry, Instant::now()) {
                return Some(DnsHint {
                    host: host.to_owned(),
                    addrs: entry.addrs.clone(),
                    resolved_at_unix: entry.resolved_at_unix,
                });
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
/// `load_persisted_dns_cache` -- call order between the two never matters.
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
