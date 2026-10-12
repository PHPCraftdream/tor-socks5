use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::Config;

const LINE: &str = "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=ZZZ iat-mode=0";

fn tmp_dir(tag: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "tor-socks5-bridges-file-{}-{}-{tag}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn load(path: &Path) -> Config {
    Config::load_with_override(Some(path))
        .unwrap()
        .into_config()
}

#[test]
fn bridges_path_uses_config_dir_and_stem() {
    let path = Config::bridges_path(Path::new("some/dir/node.ktav"));
    assert_eq!(path, Path::new("some/dir").join("node.bridges.ktav"));
    assert_eq!(
        Config::bridges_path(Path::new("tor-socks5.ktav")),
        Path::new("").join("tor-socks5.bridges.ktav")
    );
}

#[test]
fn missing_bridges_file_means_defaults() {
    let dir = tmp_dir("missing");
    let path = dir.join("tor-socks5.ktav");
    fs::write(&path, "listen: 127.0.0.1:1080\n").unwrap();
    let config = load(&path);
    assert!(config.bridges.lines.is_empty());
    assert_eq!(
        config.bridges.sources.len(),
        crate::BridgesConfig::default().sources.len()
    );
    assert!(!Config::bridges_path(&path).exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn write_splits_the_pool_from_the_main_file() {
    let dir = tmp_dir("split");
    let path = dir.join("tor-socks5.ktav");
    let mut config = Config::default();
    config.bridges.lines = vec![LINE.to_owned()];
    config.bridges.min_alive = 17;
    config.write(&path).unwrap();

    let main = fs::read_to_string(&path).unwrap();
    assert!(!main.contains("bridges"), "{main}");
    assert!(!main.contains(LINE), "{main}");
    let pool = fs::read_to_string(Config::bridges_path(&path)).unwrap();
    assert!(pool.contains(LINE), "{pool}");

    let loaded = load(&path);
    assert_eq!(loaded.bridges.lines, vec![LINE.to_owned()]);
    assert_eq!(loaded.bridges.min_alive, 17);
    assert_eq!(loaded.bridges.sources, config.bridges.sources);
    assert_eq!(loaded.listen, config.listen);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn write_bridges_leaves_the_main_file_untouched() {
    let dir = tmp_dir("only-pool");
    let path = dir.join("tor-socks5.ktav");
    let mut config = Config::default();
    config.write(&path).unwrap();
    let before = fs::read_to_string(&path).unwrap();

    config.bridges.lines.push(LINE.to_owned());
    config.write_bridges(&path).unwrap();

    assert_eq!(fs::read_to_string(&path).unwrap(), before);
    assert_eq!(load(&path).bridges.lines, vec![LINE.to_owned()]);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn the_comment_header_is_a_real_ktav_comment() {
    let dir = tmp_dir("header");
    let path = dir.join("tor-socks5.ktav");
    Config::default().write(&path).unwrap();
    let pool = fs::read_to_string(Config::bridges_path(&path)).unwrap();
    assert!(pool.starts_with("## "), "{pool}");
    assert!(load(&path).bridges.use_seeds);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn an_unknown_key_in_the_bridges_file_is_rejected_with_its_path() {
    let dir = tmp_dir("unknown");
    let path = dir.join("tor-socks5.ktav");
    Config::default().write(&path).unwrap();
    fs::write(Config::bridges_path(&path), "bogus: 1\n").unwrap();
    let error = format!(
        "{:#}",
        Config::load_with_override(Some(&path)).err().unwrap()
    );
    assert!(error.contains("tor-socks5.bridges.ktav"), "{error}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_bridges_wrapper_inside_the_bridges_file_is_rejected() {
    let dir = tmp_dir("wrapper");
    let path = dir.join("tor-socks5.ktav");
    Config::default().write(&path).unwrap();
    fs::write(
        Config::bridges_path(&path),
        format!("bridges.lines: [\n\t{LINE}\n]\n"),
    )
    .unwrap();
    assert!(Config::load_with_override(Some(&path)).is_err());
    let _ = fs::remove_dir_all(&dir);
}
