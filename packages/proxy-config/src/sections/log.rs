//! `log.*`: default level, per-target overrides, output sink, and ANSI
//! coloring. [`LogConfig::to_filter`] renders it as a
//! `tracing-subscriber` env-filter directive.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

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

/// Logging configuration (`log.*` keys in the Ktav file): default level,
/// per-target overrides in insertion order, output sink, and ANSI coloring.
/// [`LogConfig::to_filter`] renders it as a `tracing-subscriber` env-filter
/// directive.
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

/// Product crates whose names start with `tor_`. A broad `tor_=warn` target
/// (the default, meant to quiet arti's own `tor_*` crates) would otherwise
/// silence them: their log lines used to carry the `socks5_proxy` target
/// before the code moved into library crates.
const PRODUCT_TARGETS: [&str; 2] = ["tor_socks5_runtime", "tor_socks5_onion"];

impl LogConfig {
    /// Build a `tracing-subscriber` env-filter directive from the structured
    /// settings.
    ///
    /// A product crate (see [`PRODUCT_TARGETS`]) that a broader configured
    /// target would catch, and that has no target of its own, inherits the
    /// level of `socks5_proxy` (or the default level), so a config written
    /// before the code moved keeps logging as it did.
    pub fn to_filter(&self) -> String {
        let mut out = self.default.clone();
        for (target, level) in &self.targets {
            out.push(',');
            out.push_str(target);
            out.push('=');
            out.push_str(level);
        }
        let inherited = self.targets.get("socks5_proxy").unwrap_or(&self.default);
        for krate in PRODUCT_TARGETS {
            let swallowed = self
                .targets
                .keys()
                .any(|target| krate.starts_with(target.as_str()));
            if swallowed && !self.targets.contains_key(krate) {
                out.push(',');
                out.push_str(krate);
                out.push('=');
                out.push_str(inherited);
            }
        }
        out
    }
}
