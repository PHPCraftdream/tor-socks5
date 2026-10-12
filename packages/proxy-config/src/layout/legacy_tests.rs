use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use super::{check, problems, Problem};
use crate::Config;

const LINE: &str = "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=ZZZ iat-mode=0";

fn tmp_dir(tag: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "tor-socks5-legacy-{}-{}-{tag}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn inline_bridges_are_reported_in_dotted_and_block_form() {
    let dotted = format!("listen: 127.0.0.1:1080\nbridges.lines: [\n\t{LINE}\n]\n");
    assert_eq!(problems(&dotted), vec![Problem::InlineBridges]);
    let block = format!("listen: 127.0.0.1:1080\nbridges: {{\n\tlines: [\n\t\t{LINE}\n\t]\n}}\n");
    assert_eq!(problems(&block), vec![Problem::InlineBridges]);
    assert_eq!(
        problems("bridges.min_alive: 3\n"),
        vec![Problem::InlineBridges]
    );
}

#[test]
fn the_old_pattern_key_is_reported_with_its_index() {
    let src = "dns_server.overrides: [\n\
               \t{\n\t\tpatterns: *.su\n\t\tresolver: system\n\t\tserver: \n\t}\n\
               \t{\n\t\tpattern: *.ru\n\t\tresolver: system\n\t\tserver: \n\t}\n\
               ]\n";
    assert_eq!(problems(src), vec![Problem::OverridePattern { index: 1 }]);
}

#[test]
fn the_current_layout_has_no_problems() {
    let src = "listen: 127.0.0.1:1080\ndns_server.overrides: [\n\
               \t{\n\t\tpatterns: [\n\t\t\t*.ru\n\t\t]\n\t\tresolver: system\n\t\tserver: \n\t}\n]\n";
    assert!(problems(src).is_empty());
    assert!(problems("").is_empty());
}

#[test]
fn a_broken_document_is_left_to_the_typed_parse() {
    assert!(problems("this is {{ not ktav\n").is_empty());
}

#[test]
fn the_message_names_every_difference_and_the_fix() {
    let src = format!(
        "bridges.lines: [\n\t{LINE}\n]\ndns_server.overrides: [\n\
         \t{{\n\t\tpattern: *.ru\n\t\tresolver: system\n\t\tserver: \n\t}}\n]\n"
    );
    let error = check(&src, std::path::Path::new("etc/node.ktav"))
        .unwrap_err()
        .to_string();
    for needle in [
        "etc/node.ktav",
        "old layout",
        "node.bridges.ktav",
        "dns_server.overrides[0]",
        "`patterns`",
        "tor-socks5 config migrate --config etc/node.ktav",
        "stop the running service",
    ] {
        assert!(
            error.replace('\\', "/").contains(needle),
            "missing {needle:?} in:\n{error}"
        );
    }
}

#[test]
fn loading_an_old_config_fails_before_anything_else() {
    let dir = tmp_dir("load");
    let path = dir.join("tor-socks5.ktav");
    fs::write(&path, format!("bridges.lines: [\n\t{LINE}\n]\n")).unwrap();
    let error = format!(
        "{:#}",
        Config::load_with_override(Some(&path)).err().unwrap()
    );
    assert!(error.contains("old layout"), "{error}");
    assert!(error.contains("config migrate"), "{error}");
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        format!("bridges.lines: [\n\t{LINE}\n]\n"),
        "loading must not rewrite the old file"
    );
    let _ = fs::remove_dir_all(&dir);
}
