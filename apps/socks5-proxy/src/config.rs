//! Startup configuration loaded from a Ktav file.
//!
//! Resolution order:
//! 1. Path from the `TOR_SOCKS5_CONFIG` env var, if set.
//! 2. `tor-socks5.ktav` in the current working directory.
//! 3. Built-in defaults (if no file is found).

use std::collections::HashSet;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::{env, fs};

use anyhow::{Context, Result};
use bridge_line::BridgeLine;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

const ENV_VAR: &str = "TOR_SOCKS5_CONFIG";
const DEFAULT_FILE: &str = "tor-socks5.ktav";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Local address the SOCKS5 listener binds to.
    pub listen: String,
    /// Logging configuration.
    pub log: LogConfig,
    /// Bridges configuration.
    pub bridges: BridgesConfig,
    /// Optional upstream SOCKS5 proxy used as the egress instead of Tor.
    pub upstream: UpstreamConfig,
}

/// An upstream SOCKS5 proxy the daemon can forward through instead of
/// dialing out via Tor. When `enabled`, the Tor bootstrap is skipped
/// entirely and every accepted CONNECT is chained
/// `client -> us -> upstream -> target`.
///
/// `username`/`password` are optional RFC 1929 credentials presented to
/// the upstream; leave them empty for an unauthenticated upstream.
#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamConfig {
    /// Master switch. CLI flags can still override this at runtime.
    pub enabled: bool,
    /// Upstream proxy address, `host:port` (e.g. `127.0.0.1:9050`).
    pub address: String,
    /// RFC 1929 username; empty means "no authentication".
    pub username: String,
    /// RFC 1929 password; only meaningful when `username` is set.
    pub password: String,
}

impl std::fmt::Debug for UpstreamConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamConfig")
            .field("enabled", &self.enabled)
            .field("address", &self.address)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Where log lines are written.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogOutput {
    /// Standard error (default).
    #[default]
    Stderr,
    /// Standard output.
    Stdout,
    /// The file named by [`LogConfig::file`]. Falls back to stderr when
    /// the path is empty or cannot be opened.
    File,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogConfig {
    /// Default log level for everything not matched by `targets`.
    pub default: String,
    /// Per-target overrides, e.g. `socks5_proxy => debug`. The map preserves
    /// insertion order, so the resulting filter directive is stable.
    pub targets: IndexMap<String, String>,
    /// Sink for log lines: `stderr` (default), `stdout`, or `file`.
    pub output: LogOutput,
    /// Path used when `output: file`. Empty falls back to stderr.
    pub file: String,
    /// Colorize output with ANSI escapes. Ignored (forced off) for file
    /// output. Default `true`.
    pub ansi: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BridgesConfig {
    /// Bridge lines in standard `torrc` format (e.g.
    /// `obfs4 IP:PORT FINGERPRINT cert=... iat-mode=0`). Stored verbatim
    /// for ergonomics; use [`BridgesConfig::parsed`] to obtain typed,
    /// deduplicated `BridgeLine`s ready for the rest of the pipeline.
    pub lines: Vec<String>,
    /// HTTPS endpoints fetched by `tor-socks5 bridges fetch`.
    pub sources: Vec<BridgeSource>,
    /// Fall back to the binary's built-in seed bridges when none of the
    /// configured `lines` are reachable at startup. Default `true`.
    pub use_seeds: bool,
    /// After bootstrap, if fewer than `min_alive` bridges are usable,
    /// fetch fresh bridges from `sources` in the background and merge the
    /// live ones into the config for the next start. Default `true`.
    pub auto_fetch: bool,
    /// Threshold for `auto_fetch`: enrich the config when the number of
    /// reachable bridges at startup is below this. Default `2`.
    pub min_alive: usize,
    /// Maximum size, in MiB, of a single bridge-list response downloaded
    /// from a `sources` URL. A response larger than this is rejected (the
    /// whole source is skipped). Bounds in-memory buffering per fetch —
    /// does NOT affect proxied user traffic. Default `64`.
    pub max_body_mib: usize,
    /// A bridge that fails reachability probes this many times is removed
    /// from the config and the health store. Default `24`.
    pub max_fails: u32,
    /// The failure counter for a bridge is bumped at most once per this
    /// many minutes (so a burst of retries counts once). Default `60`.
    pub fail_window_mins: u64,
    /// How often (minutes) the background task re-probes our bridges and,
    /// if we are short on healthy ones, fetches more. `0` disables the
    /// periodic task. Default `60`. Kept generous to avoid network flood.
    pub recheck_interval_mins: u64,
}

/// An HTTPS endpoint to fetch a bridge list from. The minimal form is just
/// `{ url: https://... }`; `label`, `headers`, and `cookies` are optional.
/// `headers`/`cookies` let a source be hit in a custom way (an API token, a
/// session cookie, etc.).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BridgeSource {
    /// Human-readable label for logs. Optional.
    #[serde(default)]
    pub label: String,
    /// HTTPS endpoint. Required.
    pub url: String,
    /// Extra request headers, each a full `Name: Value` line. Optional.
    #[serde(default)]
    pub headers: Vec<String>,
    /// Cookies, each a `name=value` pair (folded into one `Cookie:` header). Optional.
    #[serde(default)]
    pub cookies: Vec<String>,
}

impl Default for BridgesConfig {
    fn default() -> Self {
        Self {
            lines: Vec::new(),
            sources: vec![
                BridgeSource {
                    label: "scriptzteam-obfs4".into(),
                    url: "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/main/bridges-obfs4".into(),
                    headers: Vec::new(),
                    cookies: Vec::new(),
                },
                BridgeSource {
                    label: "scriptzteam-webtunnel".into(),
                    url: "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/main/bridges-webtunnel".into(),
                    headers: Vec::new(),
                    cookies: Vec::new(),
                },
                BridgeSource {
                    label: "tor-browser-obfs4".into(),
                    url: "https://gitlab.torproject.org/tpo/applications/tor-browser/-/raw/main/projects/common/bridges_list.obfs4.txt".into(),
                    headers: Vec::new(),
                    cookies: Vec::new(),
                },
            ],
            use_seeds: true,
            auto_fetch: true,
            min_alive: 2,
            max_body_mib: 64,
            max_fails: 24,
            fail_window_mins: 60,
            recheck_interval_mins: 60,
        }
    }
}

/// Outcome of parsing the raw bridge-line strings from the config.
#[derive(Debug, Default)]
pub struct ParsedBridges {
    pub bridges: Vec<BridgeLine>,
    pub duplicates: usize,
}

impl BridgesConfig {
    /// Parse the raw config strings into `BridgeLine`s, dropping any
    /// duplicates by `(transport, addr, fingerprint)`. The first
    /// occurrence wins; subsequent ones contribute to `duplicates`.
    pub fn parsed(&self) -> Result<ParsedBridges> {
        let mut bridges = Vec::with_capacity(self.lines.len());
        let mut seen: HashSet<(Option<String>, SocketAddr, Option<String>)> = HashSet::new();
        let mut duplicates = 0usize;
        for (idx, line) in self.lines.iter().enumerate() {
            let parsed: BridgeLine = line
                .parse()
                .with_context(|| format!("invalid bridge at index {idx}: {line:?}"))?;
            let key = (
                parsed.transport.clone(),
                parsed.addr,
                parsed.fingerprint.clone(),
            );
            if seen.insert(key) {
                bridges.push(parsed);
            } else {
                duplicates += 1;
            }
        }
        Ok(ParsedBridges {
            bridges,
            duplicates,
        })
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:1080".to_string(),
            log: LogConfig::default(),
            bridges: BridgesConfig::default(),
            upstream: UpstreamConfig::default(),
        }
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        let mut targets = IndexMap::new();
        targets.insert("socks5_proxy".to_string(), "debug".to_string());
        targets.insert("arti_wrapper".to_string(), "debug".to_string());
        targets.insert("bridge_line".to_string(), "debug".to_string());
        targets.insert("tor_".to_string(), "warn".to_string());
        targets.insert("arti_".to_string(), "warn".to_string());
        Self {
            default: "info".to_string(),
            targets,
            output: LogOutput::Stderr,
            file: String::new(),
            ansi: true,
        }
    }
}

impl LogConfig {
    /// Build a `tracing-subscriber` env-filter directive from the structured
    /// settings.
    pub fn to_filter(&self) -> String {
        let mut out = self.default.clone();
        for (target, level) in &self.targets {
            out.push(',');
            out.push_str(target);
            out.push('=');
            out.push_str(level);
        }
        out
    }
}

/// Outcome of [`Config::load`]: where the values came from.
pub enum Loaded {
    FromFile {
        path: PathBuf,
        config: Config,
    },
    /// Reserved for an explicit "skip file IO" code path; not used by
    /// `Config::load` after the default-file-autocreate behaviour was
    /// added, but kept so external callers can still bypass disk.
    #[allow(dead_code)]
    Defaults(Config),
}

impl Loaded {
    pub fn into_config(self) -> Config {
        match self {
            Loaded::FromFile { config, .. } => config,
            Loaded::Defaults(config) => config,
        }
    }
}

impl Config {
    /// Load configuration following the resolution order described in the
    /// module docs. Side-effect: when the default file (`tor-socks5.ktav`
    /// in CWD) is missing, write out a fresh default and continue with
    /// that path — so the user gets a template they can edit instead of
    /// silently running on built-in defaults.
    #[allow(dead_code)]
    pub fn load() -> Result<Loaded> {
        Self::load_with_override(None)
    }

    /// Like [`load`](Self::load), but a CLI `--config` path takes
    /// precedence over both the env var and the default-file fallback.
    pub fn load_with_override(cli_override: Option<&Path>) -> Result<Loaded> {
        if let Some(path) = cli_override {
            let config = Self::from_file(path)
                .with_context(|| format!("loading config from {}", path.display()))?;
            return Ok(Loaded::FromFile {
                path: path.to_path_buf(),
                config,
            });
        }
        if let Some(path) = env::var_os(ENV_VAR) {
            let path = PathBuf::from(path);
            let config = Self::from_file(&path)
                .with_context(|| format!("loading config from {}", path.display()))?;
            return Ok(Loaded::FromFile { path, config });
        }

        let default_path = PathBuf::from(DEFAULT_FILE);
        if !default_path.exists() {
            let fresh = Config::default();
            fresh.write(&default_path).with_context(|| {
                format!("creating default config at {}", default_path.display())
            })?;
        }

        let config = Self::from_file(&default_path)
            .with_context(|| format!("loading config from {}", default_path.display()))?;
        Ok(Loaded::FromFile {
            path: default_path,
            config,
        })
    }

    fn from_file(path: &Path) -> Result<Self> {
        let src = fs::read_to_string(path).context("read config file")?;
        let cfg: Config = ktav::from_str(&src).context("parse Ktav config")?;
        Ok(cfg)
    }

    /// Serialise to a Ktav file. Atomic via sibling temp + rename.
    pub fn write(&self, path: &Path) -> Result<()> {
        let body = ktav::to_string(self).context("serialise default config to Ktav")?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).ok();
            }
        }
        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        let file_name = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| DEFAULT_FILE.to_string());
        let tmp = dir.join(format!(".{file_name}.{}.tmp", std::process::id()));
        {
            let mut f =
                fs::File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
            f.write_all(body.as_bytes())
                .with_context(|| format!("write {}", tmp.display()))?;
            f.sync_all()
                .with_context(|| format!("fsync {}", tmp.display()))?;
        }
        fs::rename(&tmp, path)
            .with_context(|| format!("rename {} → {}", tmp.display(), path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_listen_address_is_loopback_1080() {
        let cfg = Config::default();
        assert_eq!(cfg.listen, "127.0.0.1:1080");
    }

    #[test]
    fn log_to_filter_renders_default_then_targets_in_order() {
        let log = LogConfig::default();
        let filter = log.to_filter();
        // Default level first, then comma-separated target=level pairs in
        // their insertion order.
        assert!(filter.starts_with("info"));
        assert!(filter.contains(",socks5_proxy=debug"));
        assert!(filter.contains(",arti_wrapper=debug"));
        assert!(filter.contains(",tor_=warn"));
        // The first comma comes immediately after `info` — no whitespace.
        assert_eq!(filter.find(','), Some("info".len()));
    }

    #[test]
    fn log_to_filter_handles_no_targets() {
        let mut log = LogConfig::default();
        log.targets.clear();
        assert_eq!(log.to_filter(), log.default);
    }

    #[test]
    fn parses_minimal_ktav() {
        let src = r#"
listen: 127.0.0.1:9050
"#;
        let cfg: Config = ktav::from_str(src).expect("ktav parses");
        assert_eq!(cfg.listen, "127.0.0.1:9050");
        // Other fields should fall back to defaults.
        assert_eq!(cfg.log.default, LogConfig::default().default);
        assert!(cfg.bridges.lines.is_empty());
    }

    #[test]
    fn parses_dotted_log_targets() {
        let src = r#"
listen: 127.0.0.1:1080

log.default: trace
log.targets.my_crate: debug
log.targets.other: warn
"#;
        let cfg: Config = ktav::from_str(src).expect("ktav parses");
        assert_eq!(cfg.log.default, "trace");
        assert_eq!(
            cfg.log.targets.get("my_crate").map(String::as_str),
            Some("debug")
        );
        assert_eq!(
            cfg.log.targets.get("other").map(String::as_str),
            Some("warn")
        );
    }

    #[test]
    fn bridges_parsed_dedupes_by_transport_addr_fingerprint() {
        let cfg = BridgesConfig {
            lines: vec![
                "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0"
                    .into(),
                // Same key, different params — counts as a duplicate.
                "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=BBB iat-mode=1"
                    .into(),
                // Different addr — distinct.
                "obfs4 5.6.7.8:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=CCC iat-mode=0"
                    .into(),
            ],
            sources: Vec::new(),
            ..Default::default()
        };
        let parsed = cfg.parsed().expect("parses");
        assert_eq!(parsed.bridges.len(), 2);
        assert_eq!(parsed.duplicates, 1);
    }

    #[test]
    fn bridges_parsed_reports_invalid_line_with_index() {
        let cfg = BridgesConfig {
            lines: vec![
                "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01".into(),
                "not-a-bridge".into(),
            ],
            sources: Vec::new(),
            ..Default::default()
        };
        let err = cfg.parsed().expect_err("must reject");
        let msg = format!("{err:?}");
        assert!(msg.contains("index 1"), "error mentions which row: {msg}");
    }

    #[test]
    fn parses_config_with_double_hash_comments() {
        // ktav >= 0.5: comments are `##`; a single `#` is content. A
        // config that uses `##` headers and a block array (with the odd
        // blank line between items) must load cleanly. Synthetic data —
        // no real bridges.
        let src = "\
## Startup configuration for the tor-socks5 proxy.
## ktav comments use a double hash.
listen: 127.0.0.1:1080

bridges.lines: [
\tobfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=aa+bb/cc+dd/ee iat-mode=0

\tobfs4 5.6.7.8:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=ff/gg+hh/ii iat-mode=0
]
";
        let cfg: Config = ktav::from_str(src).expect("double-hash comments + block array parse");
        assert_eq!(cfg.listen, "127.0.0.1:1080");
        assert_eq!(cfg.bridges.lines.len(), 2);
    }

    #[test]
    fn single_hash_line_is_content_not_comment() {
        // Regression guard for the 0.3 -> 0.6 migration gotcha: a single
        // `#` line is NO LONGER a comment (it is content), so a config
        // header written the old way fails to parse. This documents why
        // our shipped examples must use `##`.
        let src = "# old-style comment\nlisten: 127.0.0.1:1080\n";
        assert!(
            ktav::from_str::<Config>(src).is_err(),
            "a single-# header is content under ktav 0.6 and must not parse as a comment"
        );
    }

    #[test]
    fn parses_bridges_array() {
        let src = r#"
listen: 127.0.0.1:1080

bridges.lines: [
    obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=ZZZ iat-mode=0
    obfs4 5.6.7.8:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=YYY iat-mode=0
]
"#;
        let cfg: Config = ktav::from_str(src).expect("ktav parses");
        assert_eq!(cfg.bridges.lines.len(), 2);
        assert!(cfg.bridges.lines[0].starts_with("obfs4 1.2.3.4:80"));
    }

    #[test]
    fn parses_source_with_headers_and_cookies() {
        // Mirrors the README example: a source with custom headers + cookies.
        let src = "listen: 127.0.0.1:1080\nbridges.sources: [\n\t{\n\t\tlabel: private\n\t\turl: https://api.example.org/bridges\n\t\theaders: [\n\t\t\tAuthorization: Bearer SECRET\n\t\t]\n\t\tcookies: [\n\t\t\tsession=abc123\n\t\t]\n\t}\n]\n";
        let cfg: Config = ktav::from_str(src).expect("source with headers/cookies parses");
        assert_eq!(cfg.bridges.sources.len(), 1);
        let s = &cfg.bridges.sources[0];
        assert_eq!(s.url, "https://api.example.org/bridges");
        assert_eq!(s.headers, vec!["Authorization: Bearer SECRET".to_string()]);
        assert_eq!(s.cookies, vec!["session=abc123".to_string()]);
    }

    #[test]
    fn minimal_source_is_just_a_url() {
        // A source can be the bare `{ url: ... }` form; label/headers/cookies
        // default to empty.
        let src = "listen: 127.0.0.1:1080\nbridges.sources: [\n\t{\n\t\turl: https://x.example/a\n\t}\n]\n";
        let cfg: Config = ktav::from_str(src).expect("minimal {url} source parses");
        assert_eq!(cfg.bridges.sources.len(), 1);
        assert_eq!(cfg.bridges.sources[0].url, "https://x.example/a");
        assert!(cfg.bridges.sources[0].label.is_empty());
        assert!(cfg.bridges.sources[0].headers.is_empty());
        assert!(cfg.bridges.sources[0].cookies.is_empty());
    }

    // -- Config extension tests ---

    #[test]
    fn default_bridge_sources_are_populated() {
        let cfg = BridgesConfig::default();
        assert!(cfg.sources.len() >= 3, "expect at least 3 default sources");
        assert!(cfg.sources.iter().any(|s| s.label.contains("obfs4")));
        assert!(cfg.sources.iter().any(|s| s.label.contains("webtunnel")));
    }

    #[test]
    fn bridge_source_serde_roundtrip() {
        let src = BridgeSource {
            label: "test-src".into(),
            url: "https://example.com/bridges".into(),
            headers: vec!["Authorization: Bearer x".into()],
            cookies: vec!["sid=abc".into()],
        };
        let serialized = ktav::to_string(&src).expect("serialize");
        let deserialized: BridgeSource = ktav::from_str(&serialized).expect("deserialize");
        assert_eq!(src, deserialized);
    }

    #[test]
    fn upstream_defaults_to_disabled() {
        let cfg = Config::default();
        assert!(!cfg.upstream.enabled);
        assert!(cfg.upstream.address.is_empty());
        assert!(cfg.upstream.username.is_empty());
    }

    #[test]
    fn parses_upstream_section() {
        let src = r#"
listen: 127.0.0.1:1080

upstream.enabled: true
upstream.address: 127.0.0.1:9050
upstream.username: alice
upstream.password: s3cret
"#;
        let cfg: Config = ktav::from_str(src).expect("ktav parses");
        assert!(cfg.upstream.enabled);
        assert_eq!(cfg.upstream.address, "127.0.0.1:9050");
        assert_eq!(cfg.upstream.username, "alice");
        assert_eq!(cfg.upstream.password, "s3cret");
    }

    #[test]
    fn upstream_roundtrip_preserves_fields() {
        let mut cfg = Config::default();
        cfg.upstream.enabled = true;
        cfg.upstream.address = "10.0.0.1:1080".into();
        let serialized = ktav::to_string(&cfg).expect("serialize");
        let deserialized: Config = ktav::from_str(&serialized).expect("deserialize");
        assert!(deserialized.upstream.enabled);
        assert_eq!(deserialized.upstream.address, "10.0.0.1:1080");
    }

    #[test]
    fn config_serialized_roundtrip_preserves_sources() {
        let cfg = Config::default();
        let serialized = ktav::to_string(&cfg).expect("serialize");
        let deserialized: Config = ktav::from_str(&serialized).expect("deserialize");
        assert_eq!(
            deserialized.bridges.sources.len(),
            cfg.bridges.sources.len()
        );
        assert_eq!(
            deserialized.bridges.sources[0].label,
            cfg.bridges.sources[0].label
        );
    }
}
