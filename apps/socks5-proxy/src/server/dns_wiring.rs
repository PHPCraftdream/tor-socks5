//! Glue between the proxy configuration (`proxy-config`) and the
//! `dns-server` crate: the DNS-cache path resolution (the sibling-file
//! convention shared with the users registry and the bridge store) and the
//! conversion of operator-configured DoH providers and per-host override
//! entries into the runnable `dns_server::DohProvider` and
//! `dns_server::overrides::DnsOverride` types. Nothing else — the listener
//! spawn itself lives in `server.rs`.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use tracing::warn;

use dns_server::overrides::{DnsOverride, OverrideResolver};
use dns_server::DohProvider;

use crate::config::{
    AllowedClients, Config, DnsOverrideConfig, DnsOverrideKind, DohProviderConfig,
};

/// Независимая DNS-политика (dns_server-инстанс), serde-валидация до старта.
pub(crate) fn dns_client_access(cfg: &Config) -> AllowedClients {
    cfg.dns_server.client_access.allowed_clients.clone()
}

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

/// Convert operator-configured per-host overrides into the dns-server
/// crate's engine type. Same skip-not-fatal convention as
/// `convert_custom_doh_providers` above: an unparseable `server` is logged
/// and dropped — one typo in an optional entry must not take down the
/// whole exception list. A non-empty `server` on a `system` override is
/// warn-but-keep: dropping the entry would silently lose the operator's
/// exception entirely, so it degrades to plain system resolution.
pub(crate) fn convert_dns_overrides(
    configs: &[DnsOverrideConfig],
) -> Vec<dns_server::overrides::DnsOverride> {
    configs.iter().flat_map(convert_dns_override).collect()
}

/// One config entry becomes one runtime override per usable mask, in list
/// order, all sharing the entry's resolver (first-match order is unchanged).
fn convert_dns_override(entry: &DnsOverrideConfig) -> Vec<DnsOverride> {
    let patterns: Vec<&str> = entry
        .patterns
        .iter()
        .map(String::as_str)
        .filter(|pattern| {
            // An empty mask would match only the empty host under the
            // `dns_server::overrides::matches` semantics (matches("", host)
            // is true just when host is empty, e.g. a root-zone query), so
            // it could never do useful work: an operator typo, and
            // skipping keeps the override list meaningful — same convention
            // as the unparseable-server case below.
            if pattern.is_empty() {
                warn!(
                    server = %entry.server,
                    "skipping an empty mask in a dns_server.overrides entry"
                );
            }
            !pattern.is_empty()
        })
        .collect();
    if patterns.is_empty() {
        warn!(
            server = %entry.server,
            "skipping dns_server.overrides entry without a usable mask"
        );
        return Vec::new();
    }
    let resolver = match entry.resolver {
        DnsOverrideKind::System => {
            if !entry.server.is_empty() {
                warn!(
                    patterns = ?patterns,
                    server = %entry.server,
                    "system resolver override ignores non-empty server, treating as system"
                );
            }
            OverrideResolver::System
        }
        DnsOverrideKind::Dns => match entry.server.parse::<SocketAddr>() {
            Ok(server) => OverrideResolver::Dns { server },
            Err(error) => {
                warn!(
                    patterns = ?patterns,
                    server = %entry.server,
                    %error,
                    "skipping dns_server.overrides entry with an unparseable server"
                );
                return Vec::new();
            }
        },
    };
    patterns
        .into_iter()
        .map(|pattern| DnsOverride {
            pattern: pattern.to_owned(),
            resolver: resolver.clone(),
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

    #[test]
    fn converts_a_valid_system_override() {
        let configs = vec![DnsOverrideConfig {
            patterns: vec!["*.lan".to_owned()],
            resolver: DnsOverrideKind::System,
            server: String::new(),
        }];
        let overrides = convert_dns_overrides(&configs);
        assert_eq!(overrides.len(), 1);
        assert_eq!(overrides[0].resolver, OverrideResolver::System);
    }

    #[test]
    fn converts_a_valid_dns_override() {
        let configs = vec![DnsOverrideConfig {
            patterns: vec!["ns.home.arpa".to_owned()],
            resolver: DnsOverrideKind::Dns,
            server: "192.0.2.53:53".to_owned(),
        }];
        let overrides = convert_dns_overrides(&configs);
        assert_eq!(overrides.len(), 1);
        assert_eq!(
            overrides[0].resolver,
            OverrideResolver::Dns {
                server: "192.0.2.53:53".parse().unwrap()
            }
        );
    }

    #[test]
    fn skips_dns_override_with_unparseable_server() {
        let configs = vec![
            DnsOverrideConfig {
                patterns: vec!["a.lan".to_owned()],
                resolver: DnsOverrideKind::Dns,
                server: "192.0.2.53:53".to_owned(),
            },
            DnsOverrideConfig {
                patterns: vec!["broken.lan".to_owned()],
                resolver: DnsOverrideKind::Dns,
                server: "not-addr".to_owned(),
            },
            DnsOverrideConfig {
                patterns: vec!["b.lan".to_owned()],
                resolver: DnsOverrideKind::Dns,
                server: "192.0.2.54:53".to_owned(),
            },
        ];
        let overrides = convert_dns_overrides(&configs);
        assert_eq!(overrides.len(), 2);
        // Order preserved: the valid entries around the typo stay in place.
        assert_eq!(overrides[0].pattern, "a.lan");
        assert_eq!(overrides[1].pattern, "b.lan");
    }

    #[test]
    fn keeps_system_override_with_nonempty_server() {
        // Warn-but-keep: a non-empty `server` on a system override is an
        // operator typo, but dropping the entry would lose the whole
        // exception, so it degrades to plain system resolution.
        let configs = vec![DnsOverrideConfig {
            patterns: vec!["*.lan".to_owned()],
            resolver: DnsOverrideKind::System,
            server: "192.0.2.9:53".to_owned(),
        }];
        let overrides = convert_dns_overrides(&configs);
        assert_eq!(overrides.len(), 1);
        assert_eq!(overrides[0].resolver, OverrideResolver::System);
    }

    #[test]
    fn skips_empty_pattern_override() {
        let configs = vec![DnsOverrideConfig {
            patterns: vec![String::new()],
            resolver: DnsOverrideKind::System,
            server: String::new(),
        }];
        assert!(convert_dns_overrides(&configs).is_empty());
    }

    #[test]
    fn expands_every_mask_of_an_entry_in_order_with_the_shared_resolver() {
        let configs = vec![
            DnsOverrideConfig {
                patterns: vec!["*.ru".to_owned(), "*.рф".to_owned(), "exact.lan".to_owned()],
                resolver: DnsOverrideKind::Dns,
                server: "192.0.2.53:53".to_owned(),
            },
            DnsOverrideConfig {
                patterns: vec!["*.lan".to_owned()],
                resolver: DnsOverrideKind::System,
                server: String::new(),
            },
        ];
        let overrides = convert_dns_overrides(&configs);
        let masks: Vec<&str> = overrides.iter().map(|o| o.pattern.as_str()).collect();
        assert_eq!(masks, ["*.ru", "*.рф", "exact.lan", "*.lan"]);
        let shared = OverrideResolver::Dns {
            server: "192.0.2.53:53".parse().unwrap(),
        };
        assert!(overrides[..3].iter().all(|o| o.resolver == shared));
        assert_eq!(overrides[3].resolver, OverrideResolver::System);
    }

    #[test]
    fn drops_only_the_empty_masks_of_an_entry() {
        let configs = vec![DnsOverrideConfig {
            patterns: vec![String::new(), "*.ru".to_owned(), String::new()],
            resolver: DnsOverrideKind::System,
            server: String::new(),
        }];
        let overrides = convert_dns_overrides(&configs);
        assert_eq!(overrides.len(), 1);
        assert_eq!(overrides[0].pattern, "*.ru");
    }

    #[test]
    fn skips_entry_with_an_empty_mask_list() {
        let configs = vec![DnsOverrideConfig {
            patterns: Vec::new(),
            resolver: DnsOverrideKind::System,
            server: String::new(),
        }];
        assert!(convert_dns_overrides(&configs).is_empty());
    }

    #[test]
    fn unparseable_server_drops_every_mask_of_the_entry() {
        let configs = vec![
            DnsOverrideConfig {
                patterns: vec!["a.lan".to_owned(), "b.lan".to_owned()],
                resolver: DnsOverrideKind::Dns,
                server: "not-addr".to_owned(),
            },
            DnsOverrideConfig {
                patterns: vec!["ok.lan".to_owned()],
                resolver: DnsOverrideKind::System,
                server: String::new(),
            },
        ];
        let overrides = convert_dns_overrides(&configs);
        assert_eq!(overrides.len(), 1);
        assert_eq!(overrides[0].pattern, "ok.lan");
    }
}
