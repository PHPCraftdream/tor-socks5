//! Tests for the bridge-source URL migration in [`super`]: legacy URLs
//! moved to their current lists and retired sources dropped from the config.

use super::*;
use crate::config::BridgeSource;

#[test]
fn source_migration_only_changes_the_known_legacy_webtunnel_list() {
    let old = "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/main/bridges-webtunnel";
    let current = current_source_url(old);
    assert!(current.ends_with("Tor-Bridges-Collector-v2/main/bridges/webtunnel_tested.txt"));
    assert_eq!(current_source_url(current), current);
    let custom = "https://private.example/bridges-webtunnel";
    assert_eq!(current_source_url(custom), custom);
}

#[test]
fn source_migration_moves_the_abandoned_obfs4_list_to_v2() {
    let old =
        "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/main/bridges-obfs4";
    let current = current_source_url(old);
    assert_eq!(
        current,
        "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector-v2/main/bridges/obfs4.txt"
    );
    assert_eq!(current_source_url(current), current);
    // Other sources, including the v2 webtunnel list, are left alone.
    for untouched in [
        "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector-v2/main/bridges/webtunnel.txt",
        "https://private.example/bridges-obfs4",
    ] {
        assert_eq!(current_source_url(untouched), untouched);
    }
}

const RETIRED_TOR_BROWSER_OBFS4: &str = "https://gitlab.torproject.org/tpo/applications/tor-browser/-/raw/main/projects/common/bridges_list.obfs4.txt";
const RETIRED_TOR_BROWSER_WEBTUNNEL: &str = "https://gitlab.torproject.org/tpo/applications/tor-browser/-/raw/main/projects/common/bridges_list.webtunnel.txt";

#[test]
fn retired_sources_are_recognized_exactly() {
    assert!(retired_source(RETIRED_TOR_BROWSER_OBFS4));
    assert!(retired_source(RETIRED_TOR_BROWSER_WEBTUNNEL));
    for live in [
        "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector-v2/main/bridges/webtunnel_tested.txt",
        "https://gitlab.torproject.org/tpo/applications/tor-browser/-/raw/main/projects/common/bridges_list.snowflake.txt",
        "https://private.example/bridges_list.obfs4.txt",
    ] {
        assert!(!retired_source(live), "{live}");
    }
}

/// Counterfactual: without the removal a config keeps a source that can never
/// answer, and warns about it on every refresh.
#[test]
fn migration_drops_retired_sources_and_moves_legacy_ones() {
    let source = |label: &str, url: &str| BridgeSource {
        label: label.into(),
        url: url.into(),
        headers: Vec::new(),
        cookies: Vec::new(),
        allow_credentials_cross_origin: false,
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("proxy.ktav");
    let mut cfg = Config::default();
    cfg.bridges.sources = vec![
        source(
            "old-obfs4",
            "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/main/bridges-obfs4",
        ),
        source("dead-obfs4", RETIRED_TOR_BROWSER_OBFS4),
        source("dead-webtunnel", RETIRED_TOR_BROWSER_WEBTUNNEL),
        source("mine", "https://private.example/list.txt"),
    ];
    cfg.write(&path).unwrap();

    migrate_legacy_source(&path).unwrap();

    let after = Config::load_with_override(Some(&path))
        .unwrap()
        .into_config();
    let sources: Vec<(&str, &str)> = after
        .bridges
        .sources
        .iter()
        .map(|s| (s.label.as_str(), s.url.as_str()))
        .collect();
    assert_eq!(
        sources,
        vec![
            (
                "old-obfs4",
                "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector-v2/main/bridges/obfs4.txt"
            ),
            ("mine", "https://private.example/list.txt"),
        ]
    );
}
