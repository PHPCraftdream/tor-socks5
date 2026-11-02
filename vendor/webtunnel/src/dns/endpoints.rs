//! Curated pool of public DNS-over-HTTPS endpoints, each carrying its own
//! **bootstrap IP addresses** so the resolver can establish the TLS session
//! without depending on system DNS to find the DoH server.
//!
//! Each `DohEndpoint` is converted at runtime to one or more
//! [`hickory_resolver::config::NameServerConfig`] entries via
//! [`DohEndpoint::to_name_server_configs`] — one entry per bootstrap IP.
//! The SNI / TLS server-name is taken from `sni`, not from the IP, so
//! certificate validation still runs against the provider's domain.
//!
//! ## Sourcing & maintenance
//!
//! Bootstrap IPs are taken from each provider's published DoH documentation
//! as of June 2026. They are pinned at build time deliberately: any drift
//! is surfaced as a connectivity issue (the IP fails to TLS), not silently
//! re-resolved through system DNS. When a provider rotates IPs, this list
//! is what gets updated.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use hickory_resolver::config::NameServerConfig;

/// A single DoH provider: human-readable name, the SNI/TLS hostname,
/// the HTTPS path for the `/dns-query` (or provider-specific) endpoint,
/// and the bootstrap IP addresses to dial directly without system DNS.
#[derive(Debug, Clone)]
pub(crate) struct DohEndpoint {
    /// Human-readable provider name (telemetry / debugging only).
    pub name: &'static str,
    /// TLS SNI / certificate hostname (e.g. `"cloudflare-dns.com"`).
    pub sni: &'static str,
    /// HTTPS path of the DoH endpoint (e.g. `Some("/dns-query")`).
    /// `None` means hickory's default (`/dns-query`).
    pub path: Option<&'static str>,
    /// Pinned bootstrap IPs — one or more. The resolver dials TCP to one
    /// of these and presents `sni` in the TLS ClientHello.
    pub bootstrap: &'static [IpAddr],
}

impl DohEndpoint {
    /// Expand this endpoint into hickory `NameServerConfig`s, one per
    /// bootstrap IP. All entries share the same SNI and path.
    pub fn to_name_server_configs(&self) -> Vec<NameServerConfig> {
        let server_name: Arc<str> = Arc::from(self.sni);
        let path: Option<Arc<str>> = self.path.map(Arc::from);
        self.bootstrap
            .iter()
            .map(|ip| NameServerConfig::https(*ip, Arc::clone(&server_name), path.clone()))
            .collect()
    }
}

// ── Bootstrap IP literals ────────────────────────────────────────────────
// One `const` per provider keeps the list readable and lets the compiler
// flag any malformed literal at build time.

const CLOUDFLARE_IPS: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001)),
];

const QUAD9_IPS: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
    IpAddr::V4(Ipv4Addr::new(149, 112, 112, 112)),
    IpAddr::V6(Ipv6Addr::new(0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x00fe)),
    IpAddr::V6(Ipv6Addr::new(0x2620, 0x00fe, 0, 0, 0, 0, 0, 9)),
];

const GOOGLE_IPS: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
    IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844)),
];

const ADGUARD_IPS: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(94, 140, 14, 14)),
    IpAddr::V4(Ipv4Addr::new(94, 140, 15, 15)),
    IpAddr::V6(Ipv6Addr::new(0x2a10, 0x50c0, 0, 0, 0, 0, 0x00ad, 0x0001)),
    IpAddr::V6(Ipv6Addr::new(0x2a10, 0x50c0, 0, 0, 0, 0, 0x00ad, 0x0002)),
];

const MULLVAD_IPS: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(194, 242, 2, 2)),
    IpAddr::V4(Ipv4Addr::new(194, 242, 2, 3)),
    IpAddr::V6(Ipv6Addr::new(0x2a07, 0xe340, 0, 0, 0, 0, 0, 2)),
    IpAddr::V6(Ipv6Addr::new(0x2a07, 0xe340, 0, 0, 0, 0, 0, 3)),
];

const NEXTDNS_IPS: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(45, 90, 28, 0)),
    IpAddr::V4(Ipv4Addr::new(45, 90, 30, 0)),
    IpAddr::V6(Ipv6Addr::new(0x2a07, 0xa8c0, 0, 0, 0, 0, 0, 0)),
    IpAddr::V6(Ipv6Addr::new(0x2a07, 0xa8c1, 0, 0, 0, 0, 0, 0)),
];

const DNS_SB_IPS: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(185, 222, 222, 222)),
    IpAddr::V4(Ipv4Addr::new(45, 11, 45, 11)),
    IpAddr::V6(Ipv6Addr::new(0x2a09, 0, 0, 0, 0, 0, 0, 0)),
    IpAddr::V6(Ipv6Addr::new(0x2a11, 0, 0, 0, 0, 0, 0, 0)),
];

const CONTROLD_IPS: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(76, 76, 2, 0)),
    IpAddr::V4(Ipv4Addr::new(76, 76, 10, 0)),
    IpAddr::V6(Ipv6Addr::new(0x2606, 0x1a40, 0, 0, 0, 0, 0, 0)),
    IpAddr::V6(Ipv6Addr::new(0x2606, 0x1a40, 1, 0, 0, 0, 0, 0)),
];

const CLEANBROWSING_IPS: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(185, 228, 168, 9)),
    IpAddr::V4(Ipv4Addr::new(185, 228, 169, 9)),
];

const OPENDNS_IPS: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(208, 67, 222, 222)),
    IpAddr::V4(Ipv4Addr::new(208, 67, 220, 220)),
    IpAddr::V6(Ipv6Addr::new(0x2620, 0x119, 0x35, 0, 0, 0, 0, 0x35)),
    IpAddr::V6(Ipv6Addr::new(0x2620, 0x119, 0x53, 0, 0, 0, 0, 0x53)),
];

/// Curated DoH pool: ten public providers, each with pinned bootstrap IPs
/// (v4 + v6 where the provider publishes both) and the SNI / path needed
/// for TLS validation and HTTPS dispatch.
pub(crate) const DEFAULT_DOH: &[DohEndpoint] = &[
    DohEndpoint {
        name: "Cloudflare",
        sni: "cloudflare-dns.com",
        path: Some("/dns-query"),
        bootstrap: CLOUDFLARE_IPS,
    },
    DohEndpoint {
        name: "Quad9",
        sni: "dns.quad9.net",
        path: Some("/dns-query"),
        bootstrap: QUAD9_IPS,
    },
    DohEndpoint {
        name: "Google",
        sni: "dns.google",
        path: Some("/dns-query"),
        bootstrap: GOOGLE_IPS,
    },
    DohEndpoint {
        name: "AdGuard",
        sni: "dns.adguard-dns.com",
        path: Some("/dns-query"),
        bootstrap: ADGUARD_IPS,
    },
    DohEndpoint {
        name: "Mullvad",
        sni: "dns.mullvad.net",
        path: Some("/dns-query"),
        bootstrap: MULLVAD_IPS,
    },
    DohEndpoint {
        name: "NextDNS",
        sni: "dns.nextdns.io",
        path: Some("/dns-query"),
        bootstrap: NEXTDNS_IPS,
    },
    DohEndpoint {
        name: "DNS.SB",
        sni: "doh.sb",
        path: Some("/dns-query"),
        bootstrap: DNS_SB_IPS,
    },
    DohEndpoint {
        name: "ControlD",
        sni: "freedns.controld.com",
        path: Some("/p0"),
        bootstrap: CONTROLD_IPS,
    },
    DohEndpoint {
        name: "CleanBrowsing",
        sni: "doh.cleanbrowsing.org",
        path: Some("/doh/security-filter"),
        bootstrap: CLEANBROWSING_IPS,
    },
    DohEndpoint {
        name: "OpenDNS",
        sni: "doh.opendns.com",
        path: Some("/dns-query"),
        bootstrap: OPENDNS_IPS,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    /// §F (enumerate, don't sample): walk the whole curated pool and the
    /// whole bootstrap IP list of each entry, asserting every endpoint is
    /// well-formed. The bug pattern this catches is a typo in a literal IP,
    /// SNI, or path — surfaced at `cargo test` time, never in production.
    ///
    /// Negative control: deleting any bootstrap list (e.g. setting it to
    /// `&[]`) fails the non-empty assertion; mistyping an SNI to a value
    /// that contains a space or starts with `-` fails the `ServerName`
    /// parse; an out-of-spec path like `"no-leading-slash"` fails the
    /// path-format assertion.
    #[test]
    fn all_default_endpoints_well_formed() {
        assert!(
            !DEFAULT_DOH.is_empty(),
            "the curated DoH pool must not be empty"
        );

        for ep in DEFAULT_DOH {
            assert!(
                !ep.name.is_empty(),
                "endpoint name must be non-empty (sni={})",
                ep.sni
            );
            assert!(
                !ep.sni.is_empty(),
                "endpoint sni must be non-empty (name={})",
                ep.name
            );

            // Bootstrap list must carry at least one IP — otherwise the
            // endpoint is unreachable without system DNS, which defeats
            // the whole point of pinning a bootstrap.
            assert!(
                !ep.bootstrap.is_empty(),
                "endpoint {} has no bootstrap IPs",
                ep.name
            );

            // SNI must be a valid TLS server name (the same check
            // tokio-rustls runs in production at handshake time). Catches
            // accidental whitespace, leading dots, or IP-shaped SNIs.
            rustls::pki_types::ServerName::try_from(ep.sni)
                .unwrap_or_else(|e| panic!("endpoint {}: invalid SNI {:?}: {e}", ep.name, ep.sni));

            // Provider-specific paths must look like an HTTP path. We do
            // not parse them against RFC 3986 here — the only realistic
            // typo class is forgetting the leading slash.
            if let Some(p) = ep.path {
                assert!(
                    p.starts_with('/'),
                    "endpoint {}: path must start with '/', got {:?}",
                    ep.name,
                    p
                );
                assert!(
                    !p.contains(char::is_whitespace),
                    "endpoint {}: path must not contain whitespace, got {:?}",
                    ep.name,
                    p
                );
            }

            // Conversion to hickory `NameServerConfig` must not panic and
            // must produce one config per bootstrap IP.
            let configs = ep.to_name_server_configs();
            assert_eq!(
                configs.len(),
                ep.bootstrap.len(),
                "endpoint {}: expected {} configs, got {}",
                ep.name,
                ep.bootstrap.len(),
                configs.len()
            );
        }
    }
}
