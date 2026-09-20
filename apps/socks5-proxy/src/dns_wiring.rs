//! Glue between the proxy configuration (`proxy-config`) and the
//! `dns-server` crate: the DNS-cache path resolution (the sibling-file
//! convention shared with the users registry and the bridge store) and the
//! conversion of operator-configured DoH providers into the runnable
//! `dns_server::DohProvider` type. Nothing else — the listener spawn
//! itself lives in `server.rs`.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use tracing::warn;

use dns_server::DohProvider;

use crate::config::DohProviderConfig;

/// Resolve the DNS-cache file path from the main config path. Mirrors
/// `UsersConfig::resolve_path` (auth) and `BridgeStore::resolve_path`
/// (bridge-store): same directory, same file stem, fixed `.dns-cache`
/// suffix. Falls back to `./tor-socks5.dns-cache` when the config came
/// from built-in defaults (no path on disk), so the cache still lands
/// somewhere writable instead of silently never persisting.
pub(crate) fn dns_cache_path(config_path: Option<&Path>) -> PathBuf {
    match config_path {
        Some(cfg) => {
            let dir = cfg.parent().unwrap_or_else(|| Path::new("."));
            let stem = cfg
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "tor-socks5".to_string());
            dir.join(format!("{stem}.dns-cache"))
        }
        None => PathBuf::from("tor-socks5.dns-cache"),
    }
}

/// Convert operator-configured DoH providers into the dns-server crate's
/// runnable type. Entries whose `ip` does not parse as an IPv4/IPv6
/// literal are logged and skipped rather than fatal: one typo in an
/// optional config entry must not stop the whole proxy from starting, and
/// the remaining pool (built-ins plus the valid customs) still serves.
pub(crate) fn convert_custom_doh_providers(configs: &[DohProviderConfig]) -> Vec<DohProvider> {
    configs
        .iter()
        .filter_map(|entry| match entry.ip.parse::<IpAddr>() {
            Ok(ip) => Some(DohProvider {
                ip,
                hostname: entry.hostname.clone(),
                path: entry.path.clone(),
            }),
            Err(error) => {
                warn!(
                    ip = %entry.ip,
                    hostname = %entry.hostname,
                    %error,
                    "skipping dns_server.custom_doh_providers entry with an unparseable IP"
                );
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_cache_path_uses_config_dir_and_stem() {
        let cfg = Path::new("/etc/tor-socks5.ktav");
        // Built the same way as the function so the expectation is
        // Windows-safe (join, not string concat with a hardcoded slash).
        let expected = Path::new("/etc").join(format!(
            "{}.dns-cache",
            cfg.file_stem().unwrap().to_string_lossy()
        ));
        assert_eq!(dns_cache_path(Some(cfg)), expected);
    }

    #[test]
    fn dns_cache_path_defaults_without_config() {
        assert_eq!(dns_cache_path(None), PathBuf::from("tor-socks5.dns-cache"));
    }

    #[test]
    fn convert_custom_doh_providers_keeps_valid_skips_invalid_ip() {
        let configs = vec![
            DohProviderConfig {
                ip: "9.9.9.9".to_owned(),
                hostname: "dns.quad9.net".to_owned(),
                path: "/dns-query".to_owned(),
            },
            DohProviderConfig {
                ip: "not-an-ip".to_owned(),
                hostname: "broken.example".to_owned(),
                path: "/dns-query".to_owned(),
            },
            DohProviderConfig {
                ip: "2620:fe::fe".to_owned(),
                hostname: "dns.quad9.net".to_owned(),
                path: "/dns-query".to_owned(),
            },
        ];
        let pool = convert_custom_doh_providers(&configs);
        assert_eq!(pool.len(), 2);
        // Order preserved, hostname/path carried through.
        assert_eq!(pool[0].ip.to_string(), "9.9.9.9");
        assert_eq!(pool[0].hostname, "dns.quad9.net");
        assert_eq!(pool[0].path, "/dns-query");
        assert_eq!(pool[1].ip.to_string(), "2620:fe::fe");
        assert_eq!(pool[1].hostname, "dns.quad9.net");
        assert_eq!(pool[1].path, "/dns-query");
    }
}
