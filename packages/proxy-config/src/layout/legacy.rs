//! Detection of the old config layout. An old config is never read quietly:
//! loading it fails with a message that names every difference and the
//! command that converts the file (`tor-socks5 config migrate`).

use std::path::Path;

use anyhow::{bail, Result};
use ktav::Value;

use crate::Config;

/// One difference between the old layout and the current one.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Problem {
    /// The `bridges` section is still inside the main config.
    InlineBridges,
    /// `dns_server.overrides[index]` still uses the single-mask key `pattern`.
    OverridePattern { index: usize },
}

/// Every old-layout difference in `src`. A document that does not parse yields
/// none: the typed parse reports the syntax error with its own location.
pub(crate) fn problems(src: &str) -> Vec<Problem> {
    let Ok(Value::Object(root)) = ktav::parse(src) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    if root.contains_key("bridges") {
        found.push(Problem::InlineBridges);
    }
    if let Some(Value::Object(dns_server)) = root.get("dns_server") {
        if let Some(Value::Array(overrides)) = dns_server.get("overrides") {
            for (index, entry) in overrides.iter().enumerate() {
                if matches!(entry, Value::Object(entry) if entry.contains_key("pattern")) {
                    found.push(Problem::OverridePattern { index });
                }
            }
        }
    }
    found
}

/// Fail with the full explanation when `src` (the main config at `path`) is
/// in the old layout.
pub(crate) fn check(src: &str, path: &Path) -> Result<()> {
    let found = problems(src);
    if found.is_empty() {
        return Ok(());
    }
    let mut message = format!(
        "config {} uses the old layout and cannot be loaded:\n",
        path.display()
    );
    for problem in &found {
        match problem {
            Problem::InlineBridges => message.push_str(&format!(
                "  - the `bridges` section moved to its own file {}\n",
                Config::bridges_path(path).display()
            )),
            Problem::OverridePattern { index } => message.push_str(&format!(
                "  - dns_server.overrides[{index}]: `pattern` was replaced by `patterns`, a list of masks\n"
            )),
        }
    }
    message.push_str(&format!(
        "convert it with: tor-socks5 config migrate --config {}\n\
         (stop the running service first; the old file is kept as a backup)",
        path.display()
    ));
    bail!(message)
}

#[cfg(test)]
#[path = "legacy_tests.rs"]
mod tests;
