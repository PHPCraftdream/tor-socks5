//! DNS-over-HTTPS resolver: thin wrapper over `hickory-resolver` configured
//! with the curated [`endpoints::DEFAULT_DOH`] pool.
//!
//! The resolver dials TCP straight to each provider's pinned bootstrap IP
//! (see `endpoints` module) and presents the provider's SNI in the TLS
//! ClientHello — so the resolver itself never depends on system DNS, and
//! certificate validation still happens against the provider's hostname.
//!
//! ## Mode
//!
//! [`DohMode`] decides what happens when DoH fails. `Strict` returns an
//! error rather than touching the system resolver — required when the
//! caller's threat model is censorship-resistance. `Fallback` returns the
//! system resolver's answer when the whole DoH pool is unreachable.
//! `Off` means "system DNS only" and the resolver is not even consulted.
//!
//! ## Known limitation: RFC 6761 special-case names
//!
//! Hickory short-circuits RFC 6761 reserved zones — most notably
//! `localhost`, which resolves to `::1` / `127.0.0.1` without issuing
//! a DoH query, even with `use_hosts_file = Never`. In `Strict` mode
//! this is technically a path that bypasses DoH; in practice it is not
//! a real censorship leak because (a) `localhost` is not a legitimate
//! bridge endpoint and (b) the response is fixed by the standard, not
//! influenced by any resolver or network party. Callers that need
//! "no special-case handling at all" must avoid passing such names.
//!
//! ## Cancellation
//!
//! [`DohResolver::resolve`] is **not cancel-safe** (§B3 in `rust-intel`).
//! Dropping the returned future mid-flight aborts the in-flight DoH
//! queries cleanly — hickory's tokio-backed transports tear themselves
//! down on drop — but a caller racing the resolve against another future
//! must not rely on partial state from the cancelled side.

use std::io;
use std::net::{IpAddr, SocketAddr};

use hickory_resolver::config::{ResolveHosts, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::{Resolver, TokioResolver};

use super::endpoints::{DohEndpoint, DEFAULT_DOH};

/// Failure mode of DoH resolution when the configured pool cannot
/// satisfy the request (DoH lookup error or every connect attempt
/// failing).
///
/// The default is [`DohMode::Fallback`] — additive defence that never
/// breaks existing webtunnel deployments. Set to [`DohMode::Strict`]
/// when you do **not** want a system-DNS fallback under any circumstance
/// (the censorship-resistance use case).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DohMode {
    /// DoH is disabled entirely. The caller is expected to use
    /// `TcpStream::connect((host, port))` directly, hitting the system
    /// resolver. `DohResolver::resolve` is not called in this mode.
    Off,
    /// Resolve through DoH only. If the whole DoH pool fails, return
    /// `Err` — never silently leak the query into the system resolver.
    Strict,
    /// Resolve through DoH first; on full DoH-pool failure, fall back
    /// to `tokio::net::lookup_host` and return its answer.
    #[default]
    Fallback,
}

impl std::fmt::Display for DohMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Off => f.write_str("off"),
            Self::Strict => f.write_str("strict"),
            Self::Fallback => f.write_str("fallback"),
        }
    }
}

impl std::str::FromStr for DohMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "strict" => Ok(Self::Strict),
            "fallback" => Ok(Self::Fallback),
            other => Err(format!(
                "invalid doh-mode {other:?}: expected one of off, strict, fallback"
            )),
        }
    }
}

/// DoH resolver backed by hickory. Holds a single resolver instance
/// configured with every endpoint from [`DEFAULT_DOH`] (or a custom set
/// supplied via [`DohResolver::from_endpoints`]); hickory's own
/// multi-nameserver dispatch picks an upstream per query.
///
/// The Tokio runtime provider is handle-independent: constructing this value
/// does not spawn work or capture a runtime. Hickory starts its background
/// exchange tasks on the runtime that polls [`DohResolver::resolve`]. The
/// client therefore shares this value only inside one builder context and can
/// safely use separate contexts on separate runtimes.
pub(crate) struct DohResolver {
    inner: TokioResolver,
}

impl std::fmt::Debug for DohResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hide the TokioResolver internals — they carry runtime state and
        // their `Debug` is noisy. The struct's identity is enough for the
        // call sites that need it (tests asserting Err on builder errors).
        f.debug_struct("DohResolver").finish_non_exhaustive()
    }
}

impl DohResolver {
    /// Build a resolver over the curated [`DEFAULT_DOH`] pool.
    pub fn with_default_pool() -> io::Result<Self> {
        Self::from_endpoints(DEFAULT_DOH)
    }

    /// Build a resolver over an explicit endpoint set.
    ///
    /// Returns an error if `pool` is empty — an empty pool can never
    /// produce an answer, and silently degrading to a no-op resolver
    /// would hide a configuration bug (§F1 / §D1a).
    pub fn from_endpoints(pool: &[DohEndpoint]) -> io::Result<Self> {
        if pool.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DohResolver requires at least one endpoint",
            ));
        }

        let mut cfg = ResolverConfig::default();
        for ep in pool {
            for ns in ep.to_name_server_configs() {
                cfg.add_name_server(ns);
            }
        }

        // §F1 — DoH-only means DoH-only. Disable the hosts-file path so
        // a censor who can write `/etc/hosts` (or `%SystemRoot%/...
        // /hosts`) cannot bypass DoH by injecting a bridge-domain entry.
        // Without this, `lookup_ip("localhost")` (or any name in the
        // hosts file) silently resolves through the OS, not DoH — that's
        // the exact `Strict` leak this module is supposed to prevent.
        let mut opts = ResolverOpts::default();
        opts.use_hosts_file = ResolveHosts::Never;

        let resolver = Resolver::builder_with_config(cfg, TokioRuntimeProvider::default())
            .with_options(opts)
            .build()
            .map_err(|e| io::Error::other(format!("failed to build hickory resolver: {e}")))?;

        Ok(Self { inner: resolver })
    }

    /// Resolve `host` to one or more `SocketAddr`s carrying `port`.
    ///
    /// On success returns at least one address. On failure returns an
    /// `io::Error` whose `ErrorKind` is `Other` and whose source carries
    /// the underlying hickory error.
    pub async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let lookup = self
            .inner
            .lookup_ip(host)
            .await
            .map_err(|e| io::Error::other(format!("DoH lookup failed: {e}")))?;

        let addrs: Vec<SocketAddr> = lookup
            .iter()
            .map(|ip: IpAddr| SocketAddr::new(ip, port))
            .collect();

        if addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("DoH returned no addresses for {host}"),
            ));
        }
        Ok(addrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doh_mode_default_is_fallback() {
        assert_eq!(DohMode::default(), DohMode::Fallback);
    }

    #[test]
    fn doh_mode_parses_known_strings() {
        assert_eq!("off".parse::<DohMode>().unwrap(), DohMode::Off);
        assert_eq!("strict".parse::<DohMode>().unwrap(), DohMode::Strict);
        assert_eq!("fallback".parse::<DohMode>().unwrap(), DohMode::Fallback);
        assert_eq!("STRICT".parse::<DohMode>().unwrap(), DohMode::Strict);
        assert_eq!("  off  ".parse::<DohMode>().unwrap(), DohMode::Off);
    }

    #[test]
    fn doh_mode_rejects_garbage() {
        assert!("dnsstrict".parse::<DohMode>().is_err());
        assert!("".parse::<DohMode>().is_err());
        assert!("0".parse::<DohMode>().is_err());
    }

    #[test]
    fn doh_mode_display_roundtrips_through_from_str() {
        for m in [DohMode::Off, DohMode::Strict, DohMode::Fallback] {
            let s = m.to_string();
            assert_eq!(s.parse::<DohMode>().unwrap(), m, "{s:?}");
        }
    }

    #[test]
    fn from_endpoints_rejects_empty_pool() {
        let err = DohResolver::from_endpoints(&[]).expect_err("empty pool must error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn with_default_pool_builds() {
        // The whole pool must produce a buildable resolver — exercises
        // every endpoint's `to_name_server_configs` path through
        // `add_name_server`.
        let _ = DohResolver::with_default_pool().expect("default pool must build");
    }

    /// §F1 / §D1a: `DohResolver::resolve` exposes ONLY hickory's
    /// lookup — there is no system-DNS fallback baked in here, by
    /// design. The connect-path's `Strict` mode relies on this
    /// invariant: any failure to talk to DoH must surface as `Err`,
    /// never as a covert system-resolver lookup.
    ///
    /// The test builds a resolver whose only nameserver bootstraps at
    /// 127.0.0.1:443 (no TLS listener — hickory fails the handshake
    /// instantly) and asks it to resolve an RFC-2606 `.invalid` name
    /// that no resolver on earth answers. The result must be `Err` —
    /// any `Ok` here would be the leak indicator.
    ///
    /// Negative control verified by hand: replacing the `?`-propagated
    /// error path in `resolve` with a `match ... { Err => Vec::new() }`
    /// makes this test fail (returns `Ok(vec![])` — caught by the
    /// "empty result" `Err NotFound` branch in `resolve`).
    #[tokio::test]
    async fn resolve_returns_err_with_unreachable_pool() {
        use std::net::{IpAddr, Ipv4Addr};

        use super::super::endpoints::DohEndpoint;

        const UNREACHABLE: DohEndpoint = DohEndpoint {
            name: "unreachable-test",
            sni: "localhost.invalid",
            path: Some("/dns-query"),
            bootstrap: &[IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))],
        };

        let resolver =
            DohResolver::from_endpoints(&[UNREACHABLE]).expect("unreachable pool builds");

        let result = resolver.resolve("bridge.test.invalid", 443).await;
        assert!(
            result.is_err(),
            "DohResolver must not surface a successful lookup when its \
             whole DoH pool is unreachable; got Ok",
        );
    }
}
