//! Optional seed bridges loaded from a file next to the config.
//!
//! These let a fresh install bootstrap Tor without the operator first
//! sourcing a working bridge by hand (the bootstrap chicken-and-egg).
//! They are used only as a fallback when no configured bridge in
//! `bridges.lines` is reachable at startup (and `bridges.use_seeds` is
//! on). Once Tor is up, `auto_fetch` replenishes the config, so reliance
//! on seeds is transient.
//!
//! Seeds are deliberately **not** baked into the source: real bridge
//! lines decay and don't belong in version control. Instead, place one
//! bridge line per line in a `*.seeds` file next to the main config:
//!
//! ```text
//! tor-socks5.ktav         (main config)
//! tor-socks5.seeds        (optional seed bridges — one per line)
//! ```
//!
//! Blank lines and `#` comments are ignored. A missing file simply means
//! "no seeds".

use std::path::Path;

use bridge_line::BridgeLine;

/// Suffix of the seed-bridges file, derived from the config stem.
const SEED_SUFFIX: &str = ".seeds";

/// Default seed filename when the config came from built-in defaults
/// (no path on disk).
const DEFAULT_SEED_FILE: &str = "tor-socks5.seeds";

/// Resolve the seed file path next to the main config (same directory,
/// same stem, `.seeds` suffix), mirroring `UsersConfig::resolve_path`.
fn resolve_seed_path(config_path: Option<&Path>) -> std::path::PathBuf {
    match config_path {
        Some(cfg) => {
            let dir = cfg.parent().unwrap_or_else(|| Path::new("."));
            let stem = cfg
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "tor-socks5".to_string());
            dir.join(format!("{stem}{SEED_SUFFIX}"))
        }
        None => std::path::PathBuf::from(DEFAULT_SEED_FILE),
    }
}

/// Load seed bridges from the `*.seeds` file next to the config. Returns
/// an empty vec when the file is absent or contains no parseable lines
/// (so a missing/typo'd seed can never take down startup).
pub(crate) fn seed_bridges(config_path: Option<&Path>) -> Vec<BridgeLine> {
    let path = resolve_seed_path(config_path);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.parse::<BridgeLine>().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_seed_file_yields_no_seeds() {
        let dir = std::env::temp_dir().join(format!("tor-socks5-seed-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("tor-socks5.ktav");
        assert!(seed_bridges(Some(&cfg)).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn loads_seeds_skipping_comments_and_blanks() {
        let dir =
            std::env::temp_dir().join(format!("tor-socks5-seed-test-load-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("tor-socks5.ktav");
        std::fs::write(
            dir.join("tor-socks5.seeds"),
            "# a comment\n\
             obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0\n\
             \n\
             not-a-bridge\n\
             obfs4 5.6.7.8:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=BBB iat-mode=0\n",
        )
        .unwrap();
        let seeds = seed_bridges(Some(&cfg));
        assert_eq!(
            seeds.len(),
            2,
            "two valid bridge lines, comment/blank/garbage skipped"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
