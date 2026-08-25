//! Startup configuration loaded from a Ktav file.
//!
//! Resolution order:
//! 1. Path from the `TOR_SOCKS5_CONFIG` env var, if set.
//! 2. `tor-socks5.ktav` in the current working directory.
//! 3. Built-in defaults (if no file is found).
//!
//! This schema is shared with the Android JNI FFI crate via this crate.

use std::collections::HashSet;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::{env, fs};

use anyhow::{Context, Result};
use bridge_line::BridgeLine;
use bridge_probe::usable_for_tor;
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
    /// Stale-channel watchdog configuration.
    pub watchdog: WatchdogConfig,
    /// Background bridge-channel warming pool configuration.
    pub warm_pool: WarmPoolConfig,
    /// Periodic connection-health summary logging configuration.
    pub conn_health: ConnHealthConfig,
    /// Optional upstream SOCKS5 proxy used as the egress instead of Tor.
    pub upstream: UpstreamConfig,
    /// Local SOCKS5 (RFC 1929) authentication for the listener. Used by
    /// both the CLI and the Android JNI FFI crate — see [`AuthConfig`].
    pub auth: AuthConfig,
    /// Destination policy enforced by the local SOCKS5 listener.
    pub security: SecurityConfig,
    /// Name-resolution policy used by bridge reachability probes.
    pub dns: DnsConfig,
}

/// Name-resolution policy for bridge probes. DoH is deliberately the default:
/// it avoids relying on a carrier-provided DNS server which may be blocked or
/// tampered with. System DNS is an explicit opt-in fallback.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct DnsConfig {
    /// Resolve bridge hostnames through the built-in multi-provider DoH pool.
    pub doh_enabled: bool,
    /// If DoH cannot resolve a name, also try the operating-system resolver.
    pub system_fallback: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            doh_enabled: true,
            system_fallback: false,
        }
    }
}

impl DnsConfig {
    pub fn resolver_policy(self) -> bridge_probe::ResolverPolicy {
        bridge_probe::ResolverPolicy {
            doh_enabled: self.doh_enabled,
            system_fallback: self.system_fallback,
        }
    }
}

/// Security policy for destinations accepted by the local SOCKS5 listener.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct SecurityConfig {
    /// Reject `.onion` destinations before a Tor stream is opened. Enabled by default;
    /// set to `false` only when onion access is explicitly desired.
    pub block_onion: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self { block_onion: true }
    }
}

/// Controls whether — and from where — the SOCKS5 listener loads its
/// RFC 1929 USERNAME/PASSWORD user registry.
///
/// This is primarily an **Android affordance**: the CLI already derives
/// its users-file path purely from `--config`/`$TOR_SOCKS5_CONFIG`
/// (`auth::UsersConfig::resolve_path`, `{config_stem}.users.ktav` next
/// to the main config) and never needed a config field for it — a users
/// file simply existing is enough to switch the listener from anonymous
/// NO_AUTH to USER/PASS. Android's Kotlin side, however, benefits from
/// an explicit, discoverable knob in the same Ktav file it already
/// writes for `nativeStart`, rather than relying on an implicit
/// sibling-file convention it would have to reverse-engineer.
///
/// Both fields are optional and additive: an absent `auth` section
/// preserves today's behaviour exactly (registry auto-discovered next
/// to the config, empty registry means anonymous access).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    /// Master switch. Default `true`: when a non-empty users registry is
    /// found, the listener requires USER/PASS. Set to `false` to force
    /// anonymous NO_AUTH even if a users file is present (e.g. to
    /// temporarily disable auth without deleting the registry).
    pub enabled: bool,
    /// Optional explicit path to the `.users.ktav` registry, relative to
    /// the process's current directory or absolute. Empty (the default)
    /// falls back to the standard convention:
    /// `auth::UsersConfig::resolve_path(config_path)` — same directory
    /// and stem as the main config, `.users.ktav` suffix.
    pub users_file: String,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            users_file: String::new(),
        }
    }
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

/// Stale-channel watchdog: detects Tor channels left half-open by a
/// silent network change (no carrier/IEEE event reaches arti, so
/// `tor-chanmgr` never expires the channel and `TorClient::connect`
/// keeps failing against a dead guard) and rebuilds the `TorClient`
/// without restarting the process. See `tor_watchdog.rs`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WatchdogConfig {
    /// Master switch. Default `true`.
    pub enabled: bool,
    /// Seconds between watchdog checks. Default `45` (every check reads
    /// a few atomics and the bridge store — cheap enough to run this
    /// often).
    pub check_interval_secs: u64,
    /// Seconds without a successful Tor `connect` (while attempts are
    /// still being made) before the watchdog rebuilds the `TorClient`.
    /// Default `180` (3 min): long enough to ride out a slow circuit
    /// build, short enough that a user does not sit on dead channels
    /// for many minutes.
    pub stale_after_secs: u64,
    /// Minimum seconds between two `TorClient` rebuilds. Default `300`
    /// (5 min): if a rebuild did not help (a real network block, not a
    /// stale channel), this prevents a rebuild storm.
    pub rebuild_cooldown_secs: u64,
    /// **Soft-failover degradation threshold.** A configured bridge whose
    /// `circuit_fails` (per `bridge_store.rs`'s already-existing circuit-
    /// layer observation, itself rate-limited by
    /// `bridges.circuit_observation_window_mins`) reaches this many
    /// consecutive failures is considered "degraded enough to consider
    /// switching away from". Default `3` — deliberately lower than
    /// `bridges.max_circuit_fails`'s default of `5` (which prunes the
    /// bridge outright): failing over is a much cheaper, fully reversible
    /// action than pruning, so it can fire on a smaller sample. See
    /// `tor_watchdog.rs`'s `should_signal_failover`.
    pub failover_min_circuit_fails: u32,
    /// **Soft-failover health margin.** A healthier alternative must have
    /// at least this many *fewer* `circuit_fails` than the degraded bridge
    /// before the watchdog signals arti's guard manager away from it —
    /// prevents flapping between two bridges whose health is roughly tied.
    /// Default `2`.
    pub failover_min_margin: u32,
    /// Minimum seconds between two soft-failover signals for the **same**
    /// bridge — rate-limits `TorTunnel::signal_bridge_failure` the same
    /// way `rebuild_cooldown_secs` rate-limits channel termination, so a
    /// bridge hovering right at the threshold does not get signalled every
    /// watchdog tick. Default `600` (10 min).
    pub failover_signal_cooldown_secs: u64,
}

impl Default for WatchdogConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            check_interval_secs: 45,
            stale_after_secs: 180,
            rebuild_cooldown_secs: 300,
            failover_min_circuit_fails: 3,
            failover_min_margin: 2,
            failover_signal_cooldown_secs: 600,
        }
    }
}

/// Background bridge-channel warming pool: periodically opens (or reuses)
/// channels to the top-N healthiest candidate bridges, ahead of any circuit
/// actually needing them. See `bridge_warmer.rs`.
///
/// This is prep work only — it does not switch egress between bridges (that
/// is a separate, not-yet-built feature). Warming a channel just seeds
/// `tor-chanmgr`'s own identity-keyed channel cache (see
/// `vendor/tor-chanmgr/src/mgr/state.rs`) so that if arti's guard manager
/// later builds a circuit through the same bridge, it reuses the
/// already-open channel instead of paying for a fresh handshake on the hot
/// path.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WarmPoolConfig {
    /// Master switch. Default `false` — opt-in: this feature changes
    /// nothing about which bridge carries traffic, but it does open extra
    /// background channels, so it stays off until explicitly enabled.
    pub enabled: bool,
    /// How many of the healthiest candidate bridges to keep warm. Default
    /// `3`.
    pub pool_size: usize,
    /// Seconds between warming passes. Default `60`.
    pub refresh_interval_secs: u64,
}

impl Default for WarmPoolConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            pool_size: 3,
            refresh_interval_secs: 60,
        }
    }
}

/// Periodic connection-health summary: once per `interval_secs`, drains a
/// rolling window of accept-loop counters (new connections, successful Tor
/// establishments, and errors by ConnErrorKind) into one
/// structured `info!("conn health")` line and resets them for the next
/// window. See `conn_health.rs`.
///
/// Unlike [`WarmPoolConfig`], this is pure observation — it reads counters
/// already bumped on the hot path and never touches the network or the Tor
/// client, so it is safe to enable by default.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConnHealthConfig {
    /// Master switch. Default `true` — pure observation, safe by default.
    pub enabled: bool,
    /// Seconds between summary logs. Default `60`.
    pub interval_secs: u64,
}

impl Default for ConnHealthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 60,
        }
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
    /// Colorize output with ANSI escapes when writing to a real terminal.
    /// Set to `false` to force plain text even on a terminal. Has no effect
    /// when the actual output is not a terminal (redirected to a file/pipe):
    /// colors are then always disabled regardless of this setting, so raw
    /// `\x1b[...m` bytes never pollute redirected log files. Ignored (forced
    /// off) for `file` output. Default `true`. The same stderr-based
    /// decision is propagated to the pluggable-transport child process via
    /// the `NO_COLOR` env var, so its independent logging layer (which
    /// always writes to the inherited stderr) stays plain under the same
    /// conditions.
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
    /// reachable bridges at startup is below this. Default `8`.
    ///
    /// A generous default is the cheap baseline of "active health
    /// observation": arti's guard manager itself drops guards it can't
    /// use, so keeping a healthy buffer of TCP-reachable bridges in the
    /// config lets arti settle on a working subset on its own, even when
    /// some of those bridges are bootstrap-only or have stale fingerprints.
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
    /// **Circuit-layer pruning threshold.** A bridge that passes TCP
    /// reachability probes but accumulates this many consecutive
    /// circuit-layer failures (per arti's per-guard usability events) is
    /// removed from the config and the health store. Default `5` —
    /// roughly the number of independent failure observations needed to
    /// trust that a bridge is structurally unusable (descriptor stale,
    /// fingerprint mismatch) rather than victim of a transient outage.
    pub max_circuit_fails: u32,
    /// The circuit-failure counter for a bridge is bumped at most once
    /// per this many minutes — arti retries quickly, and without rate
    /// limiting every retry would be counted as a fresh failure. Default
    /// `30`, half of `fail_window_mins` because circuit signals arrive
    /// more frequently than TCP probes.
    pub circuit_observation_window_mins: u64,
    /// Override `iat-mode` on every obfs4 bridge line (`0` off, `1` on,
    /// `2` paranoid). obfs4's inter-arrival-time randomiser reshapes the
    /// packet-size/timing distribution that a statistical or ML-based DPI
    /// classifier fingerprints; virtually every published bridge line ships
    /// `iat-mode=0`, so it can only be turned on here. `0` (default) keeps
    /// each line's published value. Costs latency and throughput.
    #[serde(default)]
    pub iat_mode: u8,
    /// Preferred pluggable transport: `any` (default), `obfs4`, or
    /// `webtunnel`.
    ///
    /// Censorship is transport-specific — a network that fingerprints and
    /// kills obfs4 streams often passes webtunnel untouched, because the
    /// latter is indistinguishable from ordinary HTTPS. This is a
    /// *preference*, not a restriction: bridges of the named transport are
    /// tried first, and the complete pool stays available as fallback, so a
    /// choice that turns out to have no working bridges cannot strand the
    /// client.
    #[serde(default = "default_bridge_transport")]
    pub transport: String,
}

/// Default for [`BridgesConfig::transport`]: no preference.
fn default_bridge_transport() -> String {
    "any".to_owned()
}

impl BridgesConfig {
    /// [`iat_mode`](Self::iat_mode) as an override, or `None` to keep each
    /// bridge line's published value. Values above `2` are not defined by
    /// obfs4 and are ignored rather than passed through to the transport.
    pub fn iat_mode_override(&self) -> Option<u8> {
        match self.iat_mode {
            1 | 2 => Some(self.iat_mode),
            _ => None,
        }
    }

    /// [`transport`](Self::transport) as a transport name, or `None` for no
    /// preference. Unrecognised values are treated as "no preference" rather
    /// than silently matching nothing.
    pub fn preferred_transport(&self) -> Option<&str> {
        match self.transport.trim().to_ascii_lowercase().as_str() {
            "obfs4" => Some("obfs4"),
            "webtunnel" => Some("webtunnel"),
            _ => None,
        }
    }
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

/// Bridge-list collectors shipped as defaults, as `(label, url)`.
///
/// Public, regenerated automatically, and reachable over plain HTTPS — they are
/// fetched through the running tunnel, so one blocked locally is still usable.
/// The `_tested` variants are listed alongside the full ones: they are much
/// smaller and pre-filtered upstream, which gives a fresh client a usable pool
/// before it has probed anything itself.
pub fn default_bridge_sources() -> &'static [(&'static str, &'static str)] {
    &[
        // scriptzteam v2 — successor to the original collector, regenerated daily.
        (
            "scriptzteam-v2-webtunnel",
            "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector-v2/main/bridges/webtunnel.txt",
        ),
        (
            "scriptzteam-v2-webtunnel-tested",
            "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector-v2/main/bridges/webtunnel_tested.txt",
        ),
        (
            "scriptzteam-v2-obfs4",
            "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector-v2/main/bridges/obfs4.txt",
        ),
        // Delta-Kronecker — independent collector, same layout, regenerated daily.
        (
            "delta-webtunnel",
            "https://raw.githubusercontent.com/Delta-Kronecker/Tor-Bridges-Collector/main/bridge/webtunnel.txt",
        ),
        (
            "delta-webtunnel-tested",
            "https://raw.githubusercontent.com/Delta-Kronecker/Tor-Bridges-Collector/main/bridge/webtunnel_tested.txt",
        ),
        (
            "delta-obfs4",
            "https://raw.githubusercontent.com/Delta-Kronecker/Tor-Bridges-Collector/main/bridge/obfs4.txt",
        ),
        // OnionHop — third independent collector.
        (
            "onionhop-webtunnel",
            "https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/webtunnel.txt",
        ),
        (
            "onionhop-webtunnel-tested",
            "https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/webtunnel_tested.txt",
        ),
        (
            "onionhop-obfs4",
            "https://raw.githubusercontent.com/center2055/OnionHop-Bridges-Collector/main/bridge/obfs4.txt",
        ),
        // The Tor Project's own built-in lists, as shipped with Tor Browser.
        (
            "tor-browser-obfs4",
            "https://gitlab.torproject.org/tpo/applications/tor-browser/-/raw/main/projects/common/bridges_list.obfs4.txt",
        ),
        (
            "tor-browser-webtunnel",
            "https://gitlab.torproject.org/tpo/applications/tor-browser/-/raw/main/projects/common/bridges_list.webtunnel.txt",
        ),
    ]
}

impl Default for BridgesConfig {
    fn default() -> Self {
        Self {
            lines: Vec::new(),
            // Several independent collectors rather than one, and freshness over
            // size: webtunnel bridges run on volunteers' own web servers and
            // rotate constantly, so a list that has not been regenerated in
            // weeks is mostly dead entries. The original scriptzteam repo had
            // gone 27 days without an update while its v2 successor and two
            // other collectors were regenerating daily; keeping only the former
            // is what left the pool without a single live webtunnel bridge.
            sources: default_bridge_sources()
                .iter()
                .map(|(label, url)| BridgeSource {
                    label: (*label).into(),
                    url: (*url).into(),
                    headers: Vec::new(),
                    cookies: Vec::new(),
                })
                .collect(),
            use_seeds: true,
            auto_fetch: true,
            min_alive: 8,
            max_body_mib: 64,
            max_fails: 24,
            fail_window_mins: 60,
            recheck_interval_mins: 60,
            max_circuit_fails: 5,
            circuit_observation_window_mins: 30,
            iat_mode: 0,
            transport: default_bridge_transport(),
        }
    }
}

/// Outcome of parsing the raw bridge-line strings from the config.
#[derive(Debug, Default)]
pub struct ParsedBridges {
    pub bridges: Vec<BridgeLine>,
    pub duplicates: usize,
    /// Bridge lines that parsed successfully but use documentation/local-only
    /// addresses and were therefore ignored.
    pub rejected: usize,
}

impl BridgesConfig {
    /// Parse the raw config strings into `BridgeLine`s, dropping any
    /// duplicates by `(transport, addr, fingerprint)`. The first
    /// occurrence wins; subsequent ones contribute to `duplicates`.
    pub fn parsed(&self) -> Result<ParsedBridges> {
        let mut bridges = Vec::with_capacity(self.lines.len());
        let mut seen: HashSet<(Option<String>, SocketAddr, Option<String>)> = HashSet::new();
        let mut duplicates = 0usize;
        let mut rejected = 0usize;
        for (idx, line) in self.lines.iter().enumerate() {
            let parsed: BridgeLine = line
                .parse()
                .with_context(|| format!("invalid bridge at index {idx}: {line:?}"))?;
            if !usable_for_tor(&parsed) {
                rejected += 1;
                continue;
            }
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
            rejected,
        })
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:1080".to_string(),
            log: LogConfig::default(),
            bridges: BridgesConfig::default(),
            watchdog: WatchdogConfig::default(),
            warm_pool: WarmPoolConfig::default(),
            conn_health: ConnHealthConfig::default(),
            upstream: UpstreamConfig::default(),
            auth: AuthConfig::default(),
            security: SecurityConfig::default(),
            dns: DnsConfig::default(),
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
    fn bridge_transport_defaults_to_no_preference() {
        let cfg = BridgesConfig::default();
        assert_eq!(cfg.transport, "any");
        assert_eq!(cfg.preferred_transport(), None);
    }

    #[test]
    fn bridge_transport_accepts_known_names_case_insensitively() {
        for (raw, expected) in [
            ("obfs4", Some("obfs4")),
            ("WebTunnel", Some("webtunnel")),
            (" webtunnel ", Some("webtunnel")),
            // Unknown values mean "no preference" rather than matching nothing,
            // so a typo cannot silently empty the bridge pool.
            ("snowflake", None),
            ("", None),
        ] {
            let cfg = BridgesConfig {
                transport: raw.to_owned(),
                ..Default::default()
            };
            assert_eq!(cfg.preferred_transport(), expected, "input {raw:?}");
        }
    }

    #[test]
    fn iat_mode_override_only_accepts_defined_obfs4_modes() {
        for (raw, expected) in [(0, None), (1, Some(1)), (2, Some(2)), (7, None)] {
            let cfg = BridgesConfig {
                iat_mode: raw,
                ..Default::default()
            };
            assert_eq!(cfg.iat_mode_override(), expected, "iat_mode {raw}");
        }
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
    fn default_circuit_pruning_knobs_are_sensible() {
        let cfg = BridgesConfig::default();
        assert_eq!(cfg.max_circuit_fails, 5);
        assert_eq!(cfg.circuit_observation_window_mins, 30);
        // Sanity: the circuit window is finer-grained than the TCP one,
        // matching the relative arrival rates of the two signal classes.
        assert!(cfg.circuit_observation_window_mins < cfg.fail_window_mins);
    }

    #[test]
    fn circuit_pruning_knobs_are_overridable_in_ktav() {
        let src = "\
listen: 127.0.0.1:1080
bridges.max_circuit_fails: 12
bridges.circuit_observation_window_mins: 10
";
        let cfg: Config = ktav::from_str(src).expect("ktav parses circuit knobs");
        assert_eq!(cfg.bridges.max_circuit_fails, 12);
        assert_eq!(cfg.bridges.circuit_observation_window_mins, 10);
    }

    #[test]
    fn circuit_pruning_knobs_fall_back_to_defaults_when_absent() {
        // A minimal config touches none of the new knobs — defaults stick.
        let src = "listen: 127.0.0.1:1080\n";
        let cfg: Config = ktav::from_str(src).expect("ktav parses without circuit knobs");
        assert_eq!(cfg.bridges.max_circuit_fails, 5);
        assert_eq!(cfg.bridges.circuit_observation_window_mins, 30);
    }

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

    // -- warm_pool config --------------------------------------------------

    #[test]
    fn warm_pool_defaults_to_disabled_with_sensible_knobs() {
        let cfg = Config::default();
        assert!(!cfg.warm_pool.enabled);
        assert_eq!(cfg.warm_pool.pool_size, 3);
        assert_eq!(cfg.warm_pool.refresh_interval_secs, 60);
    }

    #[test]
    fn parses_warm_pool_section() {
        let src = r#"
listen: 127.0.0.1:1080

warm_pool.enabled: true
warm_pool.pool_size: 5
warm_pool.refresh_interval_secs: 30
"#;
        let cfg: Config = ktav::from_str(src).expect("ktav parses");
        assert!(cfg.warm_pool.enabled);
        assert_eq!(cfg.warm_pool.pool_size, 5);
        assert_eq!(cfg.warm_pool.refresh_interval_secs, 30);
    }

    #[test]
    fn warm_pool_falls_back_to_defaults_when_absent() {
        let src = "listen: 127.0.0.1:1080\n";
        let cfg: Config = ktav::from_str(src).expect("ktav parses without warm_pool");
        assert!(!cfg.warm_pool.enabled);
        assert_eq!(cfg.warm_pool.pool_size, 3);
        assert_eq!(cfg.warm_pool.refresh_interval_secs, 60);
    }

    #[test]
    fn warm_pool_roundtrip_preserves_fields() {
        let mut cfg = Config::default();
        cfg.warm_pool.enabled = true;
        cfg.warm_pool.pool_size = 7;
        cfg.warm_pool.refresh_interval_secs = 120;
        let serialized = ktav::to_string(&cfg).expect("serialize");
        let deserialized: Config = ktav::from_str(&serialized).expect("deserialize");
        assert!(deserialized.warm_pool.enabled);
        assert_eq!(deserialized.warm_pool.pool_size, 7);
        assert_eq!(deserialized.warm_pool.refresh_interval_secs, 120);
    }

    // -- conn_health config -------------------------------------------------

    #[test]
    fn conn_health_defaults_to_enabled_with_sensible_interval() {
        let cfg = Config::default();
        assert!(cfg.conn_health.enabled);
        assert_eq!(cfg.conn_health.interval_secs, 60);
    }

    #[test]
    fn parses_conn_health_section() {
        let src = r#"
listen: 127.0.0.1:1080

conn_health.enabled: false
conn_health.interval_secs: 120
"#;
        let cfg: Config = ktav::from_str(src).expect("ktav parses");
        assert!(!cfg.conn_health.enabled);
        assert_eq!(cfg.conn_health.interval_secs, 120);
    }

    #[test]
    fn conn_health_falls_back_to_defaults_when_absent() {
        let src = "listen: 127.0.0.1:1080\n";
        let cfg: Config = ktav::from_str(src).expect("ktav parses without conn_health");
        assert!(cfg.conn_health.enabled);
        assert_eq!(cfg.conn_health.interval_secs, 60);
    }

    #[test]
    fn conn_health_roundtrip_preserves_fields() {
        let mut cfg = Config::default();
        cfg.conn_health.enabled = false;
        cfg.conn_health.interval_secs = 90;
        let serialized = ktav::to_string(&cfg).expect("serialize");
        let deserialized: Config = ktav::from_str(&serialized).expect("deserialize");
        assert!(!deserialized.conn_health.enabled);
        assert_eq!(deserialized.conn_health.interval_secs, 90);
    }

    // -- auth config ---------------------------------------------------

    #[test]
    fn auth_defaults_to_enabled_with_no_explicit_users_file() {
        let cfg = Config::default();
        assert!(cfg.auth.enabled);
        assert!(cfg.auth.users_file.is_empty());
    }

    #[test]
    fn auth_falls_back_to_defaults_when_absent() {
        // A config predating this field must still parse (`deny_unknown_fields`
        // only rejects *unknown* keys — an absent optional section is fine).
        let src = "listen: 127.0.0.1:1080\n";
        let cfg: Config = ktav::from_str(src).expect("ktav parses without auth section");
        assert!(cfg.auth.enabled);
        assert!(cfg.auth.users_file.is_empty());
    }

    #[test]
    fn parses_auth_section() {
        let src = r#"
listen: 127.0.0.1:1080

auth.enabled: true
auth.users_file: /data/data/org.torproject.android/files/tor-socks5.users.ktav
"#;
        let cfg: Config = ktav::from_str(src).expect("ktav parses");
        assert!(cfg.auth.enabled);
        assert_eq!(
            cfg.auth.users_file,
            "/data/data/org.torproject.android/files/tor-socks5.users.ktav"
        );
    }

    #[test]
    fn auth_can_be_explicitly_disabled() {
        let src = "listen: 127.0.0.1:1080\nauth.enabled: false\n";
        let cfg: Config = ktav::from_str(src).expect("ktav parses");
        assert!(!cfg.auth.enabled);
    }

    #[test]
    fn auth_roundtrip_preserves_fields() {
        let mut cfg = Config::default();
        cfg.auth.enabled = false;
        cfg.auth.users_file = "/tmp/custom.users.ktav".into();
        let serialized = ktav::to_string(&cfg).expect("serialize");
        let deserialized: Config = ktav::from_str(&serialized).expect("deserialize");
        assert!(!deserialized.auth.enabled);
        assert_eq!(deserialized.auth.users_file, "/tmp/custom.users.ktav");
    }

    #[test]
    fn security_and_dns_defaults_are_safe() {
        let cfg = Config::default();
        assert!(cfg.security.block_onion);
        assert!(cfg.dns.doh_enabled);
        assert!(!cfg.dns.system_fallback);
    }

    #[test]
    fn parses_security_section() {
        let src = "listen: 127.0.0.1:1080\nsecurity.block_onion: true\n";
        let cfg: Config = ktav::from_str(src).expect("ktav parses security section");
        assert!(cfg.security.block_onion);
    }

    #[test]
    fn security_and_dns_sections_fall_back_when_absent() {
        let src = "listen: 127.0.0.1:1080\n";
        let cfg: Config = ktav::from_str(src).expect("old config remains valid");
        assert!(cfg.security.block_onion);
        assert!(cfg.dns.doh_enabled);
        assert!(!cfg.dns.system_fallback);
    }

    #[test]
    fn parses_dns_policy_and_roundtrips() {
        let src = "listen: 127.0.0.1:1080\ndns.doh_enabled: false\ndns.system_fallback: true\n";
        let cfg: Config = ktav::from_str(src).expect("ktav parses DNS policy");
        assert!(!cfg.dns.doh_enabled);
        assert!(cfg.dns.system_fallback);
        let serialized = ktav::to_string(&cfg).expect("serialize DNS policy");
        let restored: Config = ktav::from_str(&serialized).expect("deserialize DNS policy");
        assert_eq!(restored.dns, cfg.dns);
    }
}
