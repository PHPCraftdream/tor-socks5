use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::{migrate_config, MigrationOutcome};
use crate::Config;

const LINE_A: &str =
    "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=ZZZ iat-mode=0";
const LINE_B: &str =
    "obfs4 5.6.7.8:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=YYY iat-mode=0";

fn tmp_dir(tag: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "tor-socks5-migrate-{}-{}-{tag}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// A config as the previous version wrote it: bridges inline (dotted keys,
/// reopened prefix) and single-mask overrides.
fn old_config() -> String {
    format!(
        "listen: 127.0.0.1:1080\n\
         bridges.lines: [\n\t{LINE_A}\n\t{LINE_B}\n]\n\
         bridges.min_alive: 12\n\
         bridges.sources: [\n\t{{\n\t\tlabel: mine\n\t\turl: https://x.example/a\n\t}}\n]\n\
         dns_server.enabled: true\n\
         dns_server.overrides: [\n\
         \t{{\n\t\tpattern: *.ru\n\t\tresolver: system\n\t\tserver: \n\t}}\n\
         \t{{\n\t\tpattern: ns.lan\n\t\tresolver: dns\n\t\tserver: 192.0.2.53:53\n\t}}\n\
         ]\n"
    )
}

fn migrated(outcome: MigrationOutcome) -> super::MigrationReport {
    match outcome {
        MigrationOutcome::Migrated(report) => report,
        MigrationOutcome::AlreadyCurrent => panic!("expected a migration"),
    }
}

fn file_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| !name.ends_with(".lock"))
        .collect();
    names.sort();
    names
}

#[test]
fn moves_the_pool_out_and_rewrites_the_masks() {
    let dir = tmp_dir("full");
    let path = dir.join("tor-socks5.ktav");
    fs::write(&path, old_config()).unwrap();
    assert!(Config::load_with_override(Some(&path)).is_err());

    let report = migrated(migrate_config(&path).unwrap());
    assert_eq!(report.bridge_lines, 2);
    assert_eq!(report.bridge_sources, 1);
    assert_eq!(report.masks_converted, 2);
    assert_eq!(report.bridges_file, Some(Config::bridges_path(&path)));
    assert_eq!(fs::read_to_string(&report.backup).unwrap(), old_config());

    let config = Config::load_with_override(Some(&path))
        .unwrap()
        .into_config();
    assert_eq!(
        config.bridges.lines,
        vec![LINE_A.to_owned(), LINE_B.to_owned()]
    );
    assert_eq!(config.bridges.min_alive, 12);
    assert_eq!(config.bridges.sources.len(), 1);
    assert_eq!(config.bridges.sources[0].url, "https://x.example/a");
    assert_eq!(config.listen, vec!["127.0.0.1:1080"]);
    assert!(config.dns_server.enabled);
    assert_eq!(config.dns_server.overrides[0].patterns, ["*.ru"]);
    assert_eq!(config.dns_server.overrides[1].patterns, ["ns.lan"]);
    assert_eq!(config.dns_server.overrides[1].server, "192.0.2.53:53");

    let main = fs::read_to_string(&path).unwrap();
    assert!(
        !main.contains("bridges") && !main.contains(LINE_A),
        "{main}"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_second_run_changes_nothing() {
    let dir = tmp_dir("again");
    let path = dir.join("tor-socks5.ktav");
    fs::write(&path, old_config()).unwrap();
    migrated(migrate_config(&path).unwrap());
    let names = file_names(&dir);
    let main = fs::read_to_string(&path).unwrap();
    let pool = fs::read_to_string(Config::bridges_path(&path)).unwrap();

    assert_eq!(
        migrate_config(&path).unwrap(),
        MigrationOutcome::AlreadyCurrent
    );

    assert_eq!(file_names(&dir), names, "no new backup, no new file");
    assert_eq!(fs::read_to_string(&path).unwrap(), main);
    assert_eq!(
        fs::read_to_string(Config::bridges_path(&path)).unwrap(),
        pool
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_config_in_the_current_layout_is_left_alone() {
    let dir = tmp_dir("current");
    let path = dir.join("tor-socks5.ktav");
    Config::default().write(&path).unwrap();
    let names = file_names(&dir);
    assert_eq!(
        migrate_config(&path).unwrap(),
        MigrationOutcome::AlreadyCurrent
    );
    assert_eq!(file_names(&dir), names);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn masks_only_config_creates_no_bridges_file() {
    let dir = tmp_dir("masks");
    let path = dir.join("tor-socks5.ktav");
    fs::write(
        &path,
        "dns_server.overrides: [\n\t{\n\t\tpattern: *.ru\n\t\tresolver: system\n\t\tserver: \n\t}\n]\n",
    )
    .unwrap();
    let report = migrated(migrate_config(&path).unwrap());
    assert_eq!(report.bridges_file, None);
    assert_eq!(report.masks_converted, 1);
    assert!(!Config::bridges_path(&path).exists());
    let config = Config::load_with_override(Some(&path))
        .unwrap()
        .into_config();
    assert_eq!(config.dns_server.overrides[0].patterns, ["*.ru"]);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn bridges_only_config_keeps_the_rest_intact() {
    let dir = tmp_dir("pool");
    let path = dir.join("tor-socks5.ktav");
    fs::write(
        &path,
        format!("listen: 127.0.0.1:2080\nbridges.lines: [\n\t{LINE_A}\n]\n"),
    )
    .unwrap();
    let report = migrated(migrate_config(&path).unwrap());
    assert_eq!(report.masks_converted, 0);
    let config = Config::load_with_override(Some(&path))
        .unwrap()
        .into_config();
    assert_eq!(config.listen, vec!["127.0.0.1:2080"]);
    assert_eq!(config.bridges.lines, vec![LINE_A.to_owned()]);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn an_existing_different_bridges_file_stops_the_migration_untouched() {
    let dir = tmp_dir("conflict");
    let path = dir.join("tor-socks5.ktav");
    fs::write(&path, old_config()).unwrap();
    fs::write(Config::bridges_path(&path), "min_alive: 99\n").unwrap();
    let names = file_names(&dir);

    let error = migrate_config(&path).unwrap_err().to_string();
    assert!(error.contains("already exists and differs"), "{error}");
    assert_eq!(file_names(&dir), names, "no backup was made");
    assert_eq!(fs::read_to_string(&path).unwrap(), old_config());
    assert_eq!(
        fs::read_to_string(Config::bridges_path(&path)).unwrap(),
        "min_alive: 99\n"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_run_that_stopped_after_the_bridges_file_can_be_repeated() {
    let dir = tmp_dir("resume");
    let path = dir.join("tor-socks5.ktav");
    fs::write(&path, old_config()).unwrap();
    // First attempt; then put the old main config back, as if the process had
    // died between the two writes.
    migrated(migrate_config(&path).unwrap());
    fs::write(&path, old_config()).unwrap();

    let report = migrated(migrate_config(&path).unwrap());
    assert_eq!(report.bridge_lines, 2);
    assert!(Config::load_with_override(Some(&path)).is_ok());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn an_invalid_section_writes_nothing() {
    let dir = tmp_dir("invalid");
    let path = dir.join("tor-socks5.ktav");
    let text = "listen: 127.0.0.1:1080\nbridges.bogus_key: 1\n";
    fs::write(&path, text).unwrap();
    let names = file_names(&dir);

    let error = format!("{:#}", migrate_config(&path).unwrap_err());
    assert!(error.contains("does not match the schema"), "{error}");
    assert_eq!(file_names(&dir), names);
    assert_eq!(fs::read_to_string(&path).unwrap(), text);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn both_mask_keys_in_one_entry_are_refused() {
    let dir = tmp_dir("both");
    let path = dir.join("tor-socks5.ktav");
    let text = "dns_server.overrides: [\n\t{\n\t\tpattern: *.ru\n\t\tpatterns: [\n\t\t\t*.su\n\t\t]\n\t\tresolver: system\n\t\tserver: \n\t}\n]\n";
    fs::write(&path, text).unwrap();
    let error = migrate_config(&path).unwrap_err().to_string();
    assert!(error.contains("both `pattern` and `patterns`"), "{error}");
    assert_eq!(fs::read_to_string(&path).unwrap(), text);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn backups_never_overwrite_each_other() {
    let dir = tmp_dir("backups");
    let path = dir.join("tor-socks5.ktav");
    fs::write(&path, old_config()).unwrap();
    fs::write(dir.join("tor-socks5.ktav.bak-1"), "earlier backup").unwrap();

    let report = migrated(migrate_config(&path).unwrap());
    assert_eq!(report.backup, dir.join("tor-socks5.ktav.bak-2"));
    assert_eq!(
        fs::read_to_string(dir.join("tor-socks5.ktav.bak-1")).unwrap(),
        "earlier backup"
    );
    let _ = fs::remove_dir_all(&dir);
}
