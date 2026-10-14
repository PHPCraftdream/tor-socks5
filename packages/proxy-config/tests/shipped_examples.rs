//! The shipped example configs and the README's canonical reference stay
//! loadable by the current schema, so documentation cannot drift from it.

use std::path::PathBuf;

use proxy_config::{BridgesConfig, Config};

/// A file of the repository checkout (line endings normalised, since a Windows
/// checkout may convert them), or `None` when the crate is built outside it
/// (for example from a published package).
fn repo_file(name: &str) -> Option<String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(name);
    std::fs::read_to_string(path)
        .ok()
        .map(|text| text.replace("\r\n", "\n"))
}

fn ktav_blocks(markdown: &str) -> Vec<String> {
    markdown
        .split("```ktav\n")
        .skip(1)
        .filter_map(|rest| rest.split("\n```").next())
        .map(str::to_owned)
        .collect()
}

#[test]
fn bridges_starter_parses_and_leads_with_webtunnel() {
    let text = include_str!("../examples/tor-socks5.bridges.example.ktav");
    let config: BridgesConfig = ktav::from_str(text).expect("bridges starter parses");
    assert!(!config.sources.is_empty());
    assert!(config.sources[0].label.contains("webtunnel"));
}

#[test]
fn main_example_parses_as_the_current_layout() {
    let Some(text) = repo_file("tor-socks5.example.ktav") else {
        return;
    };
    assert!(text.lines().any(|line| line == "tor.circuit_hops: 3"));
    let config: Config = ktav::from_str(&text).expect("main example parses");
    assert_eq!(config.listen, ["127.0.0.1:1080"]);
}

#[test]
fn readme_reference_blocks_parse() {
    let Some(readme) = repo_file("README.md") else {
        return;
    };
    let blocks = ktav_blocks(&readme);
    let main = blocks
        .iter()
        .find(|block| block.contains("watchdog.enabled"))
        .expect("README has the main config reference");
    let config: Config = ktav::from_str(main).expect("README main reference parses");
    assert_eq!(
        config.dns_server.overrides[0].patterns,
        ["*.lan", "*.home.arpa"]
    );
    assert!(main.lines().any(|line| line == "tor.circuit_hops: 3"));
    assert!(
        !main.lines().any(|line| line.starts_with("bridges.")),
        "the bridge pool is not part of the main config"
    );

    let pool = blocks
        .iter()
        .find(|block| block.starts_with("## Bridge lines"))
        .expect("README has the bridges file reference");
    let bridges: BridgesConfig = ktav::from_str(pool).expect("README bridges reference parses");
    assert_eq!(bridges.min_alive, BridgesConfig::default().min_alive);
    assert_eq!(bridges.transport, BridgesConfig::default().transport);
}
