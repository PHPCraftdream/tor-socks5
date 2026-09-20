//! The built-in pool of public DNS-over-HTTPS (DoH) providers and the
//! pool-selection logic used to combine it with user-supplied entries.
//!
//! # Design
//!
//! [`builtin_doh_providers`] exposes a static, compile-time-known list of
//! public DoH endpoints (IPv4 address, TLS hostname, endpoint path).
//! [`provider_pool`] merges that list with operator-supplied custom entries
//! into the slice handed to
//! [`doh_client::resolve_with_pool`](crate::doh_client::resolve_with_pool).
//!
//! Selection policy is deliberately boring: the pool is tried in **fixed
//! order**, and per-provider fallback (move on to the next entry on error or
//! timeout) lives entirely inside
//! [`doh_client::resolve_with_pool`](crate::doh_client::resolve_with_pool).
//! There is no scoring, latency measurement, or racing here. This is a
//! low-QPS local resolver: one query at a time can afford to walk the list,
//! whereas bridge-probe races providers in parallel because it resolves
//! hundreds of hostnames per run. A fixed order also makes behavior
//! reproducible and testable, and means an operator who prepends their own
//! entry knows exactly when it is used.
//!
//! # Verification status
//!
//! Every entry below was network-verified at authoring time: an RFC 8484
//! POST sent over TLS to the pinned IP with SNI = hostname returned HTTP 200
//! plus a NOERROR answer for `example.com/A`, over an HTTP/1.1-compatible
//! exchange. That is the same wire shape our DoH client speaks.
//!
//! Honest caveat: a few of the *base-20* entries (transferred as-is from the
//! production-verified bridge-probe list) have since become HTTP/2-only
//! frontends — Quad9 and Mullvad answered HTTP 505 / closed the connection
//! to an HTTP/1.1 client when re-verified, and `unfiltered.joindns4.eu` and
//! `doh.nl.ahadns.net` were unreachable from the validating network. Such
//! entries simply never win under the fixed-order fallback and cost one
//! timed-out attempt each; they are kept because the pool is shared heritage
//! with bridge-probe and the through-Tor vantage point differs from the
//! validating network (an entry dead from here may work from a Tor exit).

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::OnceLock;

use crate::types::DohProvider;

/// Built-in DoH providers as `(ip, hostname, path)` string triples, grouped
/// by operator. The base-20 entries are transferred as-is from the
/// production-verified bridge-probe list; the remaining 16 were
/// network-verified at authoring time (RFC 8484 POST to the pinned IP,
/// HTTP 200 + NOERROR answer, HTTP/1.1-compatible).
///
/// The order of this table is the resolution order used by
/// [`doh_client::resolve_with_pool`](crate::doh_client::resolve_with_pool)
/// (fixed order, fall through to the next entry on failure).
const BUILTIN_DOH_PROVIDER_TUPLES: &[(&str, &str, &str)] = &[
    // Base 20, transferred as-is from the prod-verified bridge-probe list.
    // Cloudflare (two anycast addresses).
    ("1.1.1.1", "cloudflare-dns.com", "/dns-query"),
    ("1.0.0.1", "cloudflare-dns.com", "/dns-query"),
    // Google Public DNS.
    ("8.8.8.8", "dns.google", "/dns-query"),
    ("8.8.4.4", "dns.google", "/dns-query"),
    // Quad9: malware-blocking and unfiltered variants.
    ("9.9.9.9", "dns.quad9.net", "/dns-query"),
    ("149.112.112.112", "dns.quad9.net", "/dns-query"),
    ("9.9.9.10", "dns10.quad9.net", "/dns-query"),
    ("149.112.112.10", "dns10.quad9.net", "/dns-query"),
    // AdGuard: default (blocking) and unfiltered variants.
    ("94.140.14.14", "dns.adguard-dns.com", "/dns-query"),
    ("94.140.15.15", "dns.adguard-dns.com", "/dns-query"),
    ("94.140.14.140", "unfiltered.adguard-dns.com", "/dns-query"),
    ("94.140.14.141", "unfiltered.adguard-dns.com", "/dns-query"),
    // Independent privacy-focused operators.
    ("194.242.2.2", "dns.mullvad.net", "/dns-query"), // Mullvad VPN, no-log
    ("185.222.222.222", "dns.sb", "/dns-query"),      // DNS.SB (xTom)
    ("45.11.45.11", "dns.sb", "/dns-query"),
    ("76.76.2.0", "p0.freedns.controld.com", "/dns-query"), // ControlD
    ("86.54.11.100", "unfiltered.joindns4.eu", "/dns-query"), // DNS4EU
    ("88.198.92.222", "doh.libredns.gr", "/dns-query"),     // LibreDNS
    ("176.9.93.198", "dnsforge.de", "/dns-query"),          // DNSForge
    ("5.2.75.75", "doh.nl.ahadns.net", "/dns-query"),       // AhaDNS NL
    // Additional entries, each network-verified at authoring time.
    ("76.76.2.11", "freedns.controld.com", "/dns-query"), // ControlD uncensored (anycast; explicitly anti-censorship tier)
    ("45.90.30.0", "anycast.dns.nextdns.io", "/dns-query"), // NextDNS (large anycast)
    ("185.71.138.138", "wikimedia-dns.org", "/dns-query"), // Wikimedia Foundation, no-log
    ("95.215.19.53", "dns.njal.la", "/dns-query"),        // Njalla, privacy
    ("103.2.57.5", "public.dns.iij.jp", "/dns-query"),    // IIJ Public DNS (Japan, anycast)
    ("185.194.94.71", "dns.circl.lu", "/dns-query"),      // CIRCL (Luxembourg CERT.lu)
    ("178.105.16.6", "doh.lacontrevoie.fr", "/dns-query"), // La Contre-Voie (French non-profit)
    ("5.1.66.255", "doh.ffmuc.net", "/dns-query"),        // Freifunk München
    ("185.150.99.255", "doh.ffmuc.net", "/dns-query"),
    ("116.202.176.26", "doh.libredns.gr", "/dns-query"), // LibreDNS current IP (second IP for the base entry's hostname)
    ("185.250.250.61", "dnsbunker.org", "/dns-query"),   // DNSBunker, no-log
    ("185.111.188.46", "dns1.dnscrypt.ca", "/dns-query"), // dnscrypt.ca (Canada)
    ("78.46.244.143", "doh-de.blahdns.com", "/dns-query"), // BlahDNS DE, no-log
    ("217.197.91.153", "dns.artikel10.org", "/dns-query"), // Artikel10 (anti-censorship, Iran-focused)
    ("174.138.29.175", "doh.tiar.app", "/dns-query"),      // TIAR anti-censorship (Indonesia)
    ("104.21.65.60", "doh.tiarap.org", "/dns-query"),      // TIAR mirror (CDN-fronted)
];

/// The built-in DoH provider pool, parsed once and cached for the process
/// lifetime.
///
/// Parsed lazily from [`BUILTIN_DOH_PROVIDER_TUPLES`] into
/// [`DohProvider`](crate::types::DohProvider) values via a `OnceLock`
/// (project idiom). The `expect` below cannot fire: the table is static,
/// compile-time-known data whose IP literals all parse as `IpAddr`, and the
/// `all_builtin_tuples_parse` test pins every entry.
pub fn builtin_doh_providers() -> &'static [DohProvider] {
    static POOL: OnceLock<Vec<DohProvider>> = OnceLock::new();
    POOL.get_or_init(|| {
        BUILTIN_DOH_PROVIDER_TUPLES
            .iter()
            .map(|(ip, hostname, path)| DohProvider {
                // Static, compile-time-known literal; covered by the
                // `all_builtin_tuples_parse` test.
                ip: ip
                    .parse::<IpAddr>()
                    .expect("builtin DoH provider tuple is valid"),
                hostname: (*hostname).to_owned(),
                path: (*path).to_owned(),
            })
            .collect()
    })
    .as_slice()
}

/// Build the provider pool: built-in entries first (unless
/// `disable_builtin`), then `custom` in the given order.
///
/// The returned vector feeds
/// [`doh_client::resolve_with_pool`](crate::doh_client::resolve_with_pool),
/// which tries it in fixed order and falls through to the next provider on
/// failure — so position here is priority, and earlier entries win.
///
/// Duplicates are removed by `(ip, hostname)` pair, keeping the FIRST
/// occurrence: a custom entry duplicating a built-in one, or a duplicate
/// inside `custom`, is dropped. Note the key is the *pair*, not the hostname
/// alone: two entries sharing a hostname with different IPs are intentional
/// redundancy (extra vantage points for the same operator) and both stay.
pub fn provider_pool(custom: &[DohProvider], disable_builtin: bool) -> Vec<DohProvider> {
    let mut seen: HashSet<(IpAddr, &str)> = HashSet::new();
    let builtin = builtin_doh_providers();
    let mut pool = Vec::with_capacity(builtin.len() + custom.len());
    let candidates = if disable_builtin { &[][..] } else { builtin };
    for provider in candidates.iter().chain(custom.iter()) {
        let key = (provider.ip, provider.hostname.as_str());
        if seen.insert(key) {
            pool.push(provider.clone());
        }
    }
    pool
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test helper: build a [`DohProvider`] from shorthand parts.
    fn provider(ip: &str, hostname: &str) -> DohProvider {
        DohProvider {
            ip: ip.parse().expect("test ip parses"),
            hostname: hostname.to_owned(),
            path: "/dns-query".to_owned(),
        }
    }

    #[test]
    fn all_builtin_tuples_parse() {
        let pool = builtin_doh_providers();
        assert!(!pool.is_empty());
        assert_eq!(pool.len(), BUILTIN_DOH_PROVIDER_TUPLES.len());
    }

    #[test]
    fn builtin_pairs_are_unique() {
        let mut seen = HashSet::new();
        for provider in builtin_doh_providers() {
            let key = (provider.ip, provider.hostname.as_str());
            assert!(seen.insert(key), "duplicate (ip, hostname): {key:?}");
        }
    }

    #[test]
    fn builtin_wire_format_invariants() {
        for provider in builtin_doh_providers() {
            assert!(!provider.hostname.is_empty());
            assert!(provider.path.starts_with('/'));
        }
    }

    #[test]
    fn empty_custom_pool_equals_builtin() {
        let pool = provider_pool(&[], false);
        assert_eq!(pool.as_slice(), builtin_doh_providers());
        assert_eq!(pool.len(), BUILTIN_DOH_PROVIDER_TUPLES.len());
        // Spot-check order: first and last built-in entries.
        assert_eq!(pool[0].ip.to_string(), "1.1.1.1");
        assert_eq!(pool[pool.len() - 1].ip.to_string(), "104.21.65.60");
    }

    #[test]
    fn disable_builtin_with_empty_custom_is_empty() {
        assert!(provider_pool(&[], true).is_empty());
    }

    #[test]
    fn custom_entries_appended_in_order() {
        let custom = vec![provider("192.0.2.1", "resolver.example.net")];
        let pool = provider_pool(&custom, false);
        assert_eq!(pool.len(), builtin_doh_providers().len() + 1);
        assert_eq!(pool[pool.len() - 1], custom[0]);
        // Built-in entries still lead the pool, in order.
        assert_eq!(pool[..pool.len() - 1], *builtin_doh_providers());
    }

    #[test]
    fn custom_duplicating_builtin_is_dropped() {
        let custom = vec![provider("1.1.1.1", "cloudflare-dns.com")];
        let pool = provider_pool(&custom, false);
        assert_eq!(pool.len(), builtin_doh_providers().len());
        // The built-in (first) occurrence is kept.
        assert_eq!(pool[0].ip.to_string(), "1.1.1.1");
    }

    #[test]
    fn duplicate_inside_custom_keeps_first() {
        let custom = vec![
            provider("192.0.2.1", "resolver.example.net"),
            provider("192.0.2.1", "resolver.example.net"),
        ];
        let pool = provider_pool(&custom, true);
        assert_eq!(pool.len(), 1);
        assert_eq!(pool[0], custom[0]);
    }

    #[test]
    fn same_hostname_different_ip_keeps_both() {
        let custom = vec![
            provider("192.0.2.1", "resolver.example.net"),
            provider("192.0.2.2", "resolver.example.net"),
        ];
        let pool = provider_pool(&custom, true);
        assert_eq!(pool, custom);
    }
}
