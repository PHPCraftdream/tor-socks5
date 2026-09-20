use super::*;

const CERT_OLD: &str = "EREREREREREREREREREREREREREiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIg";
const CERT_NEW: &str = "EREREREREREREREREREREREREREzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMw";

#[test]
fn default_listen_address_is_loopback_1080() {
    let cfg = Config::default();
    assert_eq!(cfg.listen, vec!["127.0.0.1:1080"]);
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
    assert_eq!(cfg.listen, vec!["127.0.0.1:9050"]);
    // Other fields should fall back to defaults.
    assert_eq!(cfg.log.default, LogConfig::default().default);
    assert!(cfg.bridges.lines.is_empty());
}

#[test]
fn parses_legacy_scalar_listen_as_single_address() {
    // Compat contract: the old scalar `listen:` form keeps parsing and
    // becomes a one-element vector.
    let src = "listen: 127.0.0.1:9050\n";
    let cfg: Config = ktav::from_str(src).expect("ktav parses");
    assert_eq!(cfg.listen, vec!["127.0.0.1:9050".to_string()]);
}

#[test]
fn parses_listen_list_form() {
    let src = r#"
listen: [
    127.0.0.1:9050
    127.0.0.1:1080
]
"#;
    let cfg: Config = ktav::from_str(src).expect("ktav parses");
    assert_eq!(
        cfg.listen,
        vec!["127.0.0.1:9050".to_string(), "127.0.0.1:1080".to_string()]
    );
}

#[test]
fn listen_round_trips_through_write() {
    let dir = unique_test_dir("listen-roundtrip");
    let path = dir.join("tor-socks5.ktav");
    let cfg = Config {
        listen: vec!["127.0.0.1:9050".to_string(), "[::1]:1080".to_string()],
        ..Default::default()
    };
    cfg.write(&path).expect("write");
    let loaded = Config::load_with_override(Some(&path))
        .expect("load")
        .into_config();
    assert_eq!(
        loaded.listen,
        vec!["127.0.0.1:9050".to_string(), "[::1]:1080".to_string()]
    );
    let _ = std::fs::remove_dir_all(&dir);
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
fn bridges_parsed_keeps_rotated_certs_and_first_order() {
    let cfg = BridgesConfig {
        lines: vec![
            format!("obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert={CERT_OLD} iat-mode=0"),
            // A rotated obfs4 certificate is a distinct endpoint.
            format!("obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert={CERT_NEW} iat-mode=0"),
            // An exact repeat is still a duplicate.
            format!("obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert={CERT_OLD} iat-mode=0"),
            format!("obfs4 5.6.7.8:443 0123456789ABCDEF0123456789ABCDEF01234567 cert={CERT_OLD} iat-mode=0"),
        ],
        sources: Vec::new(),
        ..Default::default()
    };
    let parsed = cfg.parsed().expect("parses");
    assert_eq!(parsed.bridges.len(), 3);
    assert_eq!(parsed.duplicates, 1);
    assert_eq!(
        parsed.bridges[0].params.get("cert").map(String::as_str),
        Some(CERT_OLD)
    );
    assert_eq!(
        parsed.bridges[1].params.get("cert").map(String::as_str),
        Some(CERT_NEW)
    );
    assert_eq!(parsed.bridges[2].addr.to_string(), "5.6.7.8:443");
}

#[test]
fn bridges_parsed_keeps_webtunnel_carrier_variants() {
    let cfg = BridgesConfig {
        lines: vec![
            "webtunnel 192.0.2.3:443 1111111111111111111111111111111111111111 url=https://edge.example/old addr=198.51.100.10:443 servername=old.example ver=0.0.3".into(),
            "webtunnel 192.0.2.3:443 1111111111111111111111111111111111111111 url=https://edge.example/new addr=198.51.100.10:443 servername=old.example ver=0.0.3".into(),
            "webtunnel 192.0.2.3:443 1111111111111111111111111111111111111111 url=https://edge.example/new addr=198.51.100.11:443 servername=new.example ver=0.0.3".into(),
            // Only the exact first line is a duplicate.
            "webtunnel 192.0.2.3:443 1111111111111111111111111111111111111111 url=https://edge.example/old addr=198.51.100.10:443 servername=old.example ver=0.0.3".into(),
        ],
        sources: Vec::new(),
        ..Default::default()
    };
    let parsed = cfg.parsed().expect("parses");
    assert_eq!(parsed.bridges.len(), 3);
    assert_eq!(parsed.duplicates, 1);
    assert!(parsed.bridges[0].to_string().contains("/old"));
    assert!(parsed.bridges[1].to_string().contains("/new"));
    assert!(parsed.bridges[2].to_string().contains("198.51.100.11:443"));
}

#[test]
fn bridge_identity_survives_save_load_and_parsed() {
    let mut cfg = Config::default();
    cfg.bridges.lines = vec![
        format!("obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert={CERT_OLD} iat-mode=0"),
        format!("obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert={CERT_NEW} iat-mode=0"),
        "webtunnel 192.0.2.3:443 1111111111111111111111111111111111111111 url=https://edge.example/old servername=old.example ver=0.0.3".into(),
        "webtunnel 192.0.2.3:443 1111111111111111111111111111111111111111 url=https://edge.example/new servername=old.example ver=0.0.3".into(),
    ];
    let path = std::env::temp_dir().join(format!(
        "tor-socks5-proxy-config-{}-identity.ktav",
        std::process::id()
    ));
    cfg.write(&path).expect("save config");
    let loaded = Config::load_with_override(Some(&path))
        .expect("load config")
        .into_config();
    let _ = std::fs::remove_file(&path);

    let parsed = loaded.bridges.parsed().expect("parse loaded config");
    assert_eq!(parsed.bridges.len(), 4);
    assert_eq!(parsed.duplicates, 0);
    assert_eq!(
        parsed.bridges[0].params.get("cert").map(String::as_str),
        Some(CERT_OLD)
    );
    assert_eq!(
        parsed.bridges[1].params.get("cert").map(String::as_str),
        Some(CERT_NEW)
    );
    assert!(parsed.bridges[2].to_string().contains("/old"));
    assert!(parsed.bridges[3].to_string().contains("/new"));
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
fn bridges_parsed_diverts_dns_hint_lines_instead_of_rejecting_them() {
    let cfg = BridgesConfig {
        lines: vec![
            "webtunnel 192.0.2.3:1 0123456789ABCDEF0123456789ABCDEF01234567 \
             url=https://fronting.example.test/x"
                .into(),
            "# xorbot:dns fronting.example.test 203.0.113.9 1700000000".into(),
        ],
        sources: Vec::new(),
        ..Default::default()
    };
    let parsed = cfg
        .parsed()
        .expect("hint lines must not be treated as invalid bridges");
    assert_eq!(parsed.bridges.len(), 1);
    assert_eq!(parsed.dns_hints.len(), 1);
    assert_eq!(parsed.dns_hints[0].host, "fronting.example.test");
}

#[test]
fn bridges_parsed_drops_a_hint_for_a_host_no_bridge_actually_uses() {
    // The scope check: a hint whose host is not one of the bridges in
    // this same batch must be dropped, not trusted -- otherwise an
    // untrusted imported blob could poison the cache for an unrelated
    // hostname (e.g. this app's own collateral-freedom source domains).
    let cfg = BridgesConfig {
        lines: vec![
            "webtunnel 192.0.2.3:1 0123456789ABCDEF0123456789ABCDEF01234567 \
             url=https://fronting.example.test/x"
                .into(),
            "# xorbot:dns raw.githubusercontent.com 203.0.113.9 1700000000".into(),
        ],
        sources: Vec::new(),
        ..Default::default()
    };
    let parsed = cfg.parsed().expect("parses");
    assert!(
        parsed.dns_hints.is_empty(),
        "a hint for an unrelated host must be dropped, got: {:?}",
        parsed.dns_hints
    );
}

#[test]
fn bridges_parsed_ignores_a_hint_with_no_bridges_at_all() {
    let cfg = BridgesConfig {
        lines: vec!["# xorbot:dns fronting.example.test 203.0.113.9 1700000000".into()],
        sources: Vec::new(),
        ..Default::default()
    };
    let parsed = cfg.parsed().expect("parses");
    assert!(parsed.bridges.is_empty());
    assert!(parsed.dns_hints.is_empty());
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
    assert_eq!(cfg.listen, vec!["127.0.0.1:1080"]);
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
    let src =
        "listen: 127.0.0.1:1080\nbridges.sources: [\n\t{\n\t\turl: https://x.example/a\n\t}\n]\n";
    let cfg: Config = ktav::from_str(src).expect("minimal {url} source parses");
    assert_eq!(cfg.bridges.sources.len(), 1);
    assert_eq!(cfg.bridges.sources[0].url, "https://x.example/a");
    assert!(cfg.bridges.sources[0].label.is_empty());
    assert!(cfg.bridges.sources[0].headers.is_empty());
    assert!(cfg.bridges.sources[0].cookies.is_empty());
}

#[test]
fn source_credentials_cross_origin_defaults_to_false() {
    // Without the key, credentials stay pinned to the source's own origin.
    let src =
        "listen: 127.0.0.1:1080\nbridges.sources: [\n\t{\n\t\turl: https://x.example/a\n\t}\n]\n";
    let cfg: Config = ktav::from_str(src).expect("minimal source parses");
    assert_eq!(cfg.bridges.sources.len(), 1);
    assert!(!cfg.bridges.sources[0].allow_credentials_cross_origin);
}

#[test]
fn source_credentials_cross_origin_opt_in_parses() {
    let src = "listen: 127.0.0.1:1080\nbridges.sources: [\n\t{\n\t\turl: https://x.example/a\n\t\tallow_credentials_cross_origin: true\n\t}\n]\n";
    let cfg: Config = ktav::from_str(src).expect("opt-in source parses");
    assert_eq!(cfg.bridges.sources.len(), 1);
    assert!(cfg.bridges.sources[0].allow_credentials_cross_origin);
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
        allow_credentials_cross_origin: false,
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

fn unique_test_dir(label: &str) -> std::path::PathBuf {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "tor-socks5-proxy-config-{}-{}-{label}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn from_file_spares_temp_owned_by_live_writer() {
    let dir = unique_test_dir("live-writer");
    let path = dir.join("tor-socks5.ktav");
    std::fs::write(&path, "listen: 127.0.0.1:1080\n").unwrap();
    // Models a live writer: same canonical temp name the writer produces,
    // advisory lock held across processes by the OS.
    let guard = persist_lock::TempFileGuard::create(&path, 1).expect("guard");
    Config::from_file(&path).expect("from_file");
    assert!(
        guard.temp_path().exists(),
        "cleanup must not delete a temp whose owner still holds the lock"
    );
    drop(guard);
    Config::from_file(&path).expect("from_file");
    assert!(
        !persist_lock::temp_path_for(&path, 1).unwrap().exists(),
        "dead owner temp must be cleaned"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn from_file_spares_malformed_temp_names() {
    let dir = unique_test_dir("malformed");
    let path = dir.join("tor-socks5.ktav");
    std::fs::write(&path, "listen: 127.0.0.1:1080\n").unwrap();
    let names = [
        ".tor-socks5.ktav.notapid.42.tmp",     // garbage pid
        ".tor-socks5.ktav.99999999999.42.tmp", // pid over u32::MAX
        ".tor-socks5.ktav.1.abc.tmp",          // non-numeric seq
        ".tor-socks5.ktav.1.42.tmp.bak",       // extra segment
        ".tor-socks5.ktav.1.tmp",              // missing seq
    ];
    for name in names {
        std::fs::write(dir.join(name), "x").unwrap();
    }
    Config::from_file(&path).expect("from_file");
    for name in names {
        assert!(
            dir.join(name).exists(),
            "malformed temp {name} must survive cleanup"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn dns_server_defaults_to_disabled_on_loopback_15353() {
    let cfg = DnsServerConfig::default();
    assert!(!cfg.enabled);
    assert_eq!(cfg.listen, vec!["127.0.0.1:15353"]);
    assert!(!cfg.disable_builtin_providers);
    assert!(cfg.custom_doh_providers.is_empty());
}

#[test]
fn parses_dns_server_legacy_scalar_listen_as_single_address() {
    // Compat contract: the legacy scalar `dns_server.listen:` form keeps
    // parsing and becomes a one-element vector (same rule as
    // `Config::listen`).
    let src = "listen: 127.0.0.1:1080\ndns_server.listen: 127.0.0.1:15353\n";
    let cfg: Config = ktav::from_str(src).expect("ktav parses");
    assert_eq!(cfg.dns_server.listen, vec!["127.0.0.1:15353".to_string()]);
}

#[test]
fn parses_dns_server_listen_list_form() {
    let src = r#"
listen: 127.0.0.1:1080

dns_server.listen: [
    127.0.0.1:15353
    127.0.0.1:25353
]
"#;
    let cfg: Config = ktav::from_str(src).expect("ktav parses");
    assert_eq!(
        cfg.dns_server.listen,
        vec!["127.0.0.1:15353".to_string(), "127.0.0.1:25353".to_string()]
    );
}

#[test]
fn dns_server_listen_round_trips_through_write() {
    // A plain `ktav::to_string`/`from_str` round trip is enough here —
    // `Config::write` delegates to the same serializer.
    let cfg = Config {
        dns_server: DnsServerConfig {
            listen: vec!["127.0.0.1:15353".to_string(), "127.0.0.1:25353".to_string()],
            ..Default::default()
        },
        ..Default::default()
    };
    let serialized = ktav::to_string(&cfg).expect("serialize");
    let deserialized: Config = ktav::from_str(&serialized).expect("deserialize");
    assert_eq!(
        deserialized.dns_server.listen,
        vec!["127.0.0.1:15353".to_string(), "127.0.0.1:25353".to_string()]
    );
}

#[test]
fn dns_server_section_falls_back_to_defaults_when_absent() {
    // A config that predates the section must still parse, and the
    // feature must stay OFF (`#[serde(default)]` section wiring).
    let src = "listen: 127.0.0.1:1080\n";
    let cfg: Config = ktav::from_str(src).expect("ktav parses without dns_server");
    assert_eq!(cfg.dns_server, DnsServerConfig::default());
}

#[test]
fn parses_dns_server_section_with_a_custom_provider() {
    let src = "listen: 127.0.0.1:1080\n\
               dns_server.enabled: true\n\
               dns_server.disable_builtin_providers: true\n\
               dns_server.custom_doh_providers: [\n\
               \t{\n\
               \t\tip: 9.9.9.9\n\
               \t\thostname: dns.quad9.net\n\
               \t\tpath: /dns-query\n\
               \t}\n\
               ]\n";
    let cfg: Config = ktav::from_str(src).expect("ktav parses dns_server section");
    assert!(cfg.dns_server.enabled);
    assert!(cfg.dns_server.disable_builtin_providers);
    assert_eq!(cfg.dns_server.custom_doh_providers.len(), 1);
    let p = &cfg.dns_server.custom_doh_providers[0];
    assert_eq!(p.ip, "9.9.9.9");
    assert_eq!(p.hostname, "dns.quad9.net");
    assert_eq!(p.path, "/dns-query");
}

#[test]
fn dns_server_roundtrip_preserves_custom_providers_exactly() {
    let mut cfg = Config::default();
    cfg.dns_server.enabled = true;
    cfg.dns_server.custom_doh_providers = vec![
        DohProviderConfig {
            ip: "1.1.1.1".into(),
            hostname: "cloudflare-dns.com".into(),
            path: "/dns-query".into(),
        },
        DohProviderConfig {
            ip: "2620:fe::fe".into(),
            hostname: "dns.quad9.net".into(),
            path: "/dns-query".into(),
        },
    ];
    let serialized = ktav::to_string(&cfg).expect("serialize");
    let deserialized: Config = ktav::from_str(&serialized).expect("deserialize");
    assert!(deserialized.dns_server.enabled);
    assert_eq!(
        deserialized.dns_server.custom_doh_providers,
        cfg.dns_server.custom_doh_providers
    );
    assert_eq!(
        deserialized.dns_server.custom_doh_providers[1].ip,
        "2620:fe::fe"
    );
}

#[test]
fn dns_server_unknown_field_is_rejected() {
    // deny_unknown_fields: a typo inside the section must fail loudly.
    let src = "listen: 127.0.0.1:1080\ndns_server.port: 5353\n";
    assert!(
        ktav::from_str::<Config>(src).is_err(),
        "unknown key inside dns_server must be rejected"
    );
}

#[test]
fn dns_server_unknown_field_inside_custom_provider_is_rejected() {
    let src = "listen: 127.0.0.1:1080\n\
               dns_server.custom_doh_providers: [\n\
               \t{\n\
               \t\tip: 9.9.9.9\n\
               \t\thostname: dns.quad9.net\n\
               \t\tpath: /dns-query\n\
               \t\tscheme: https\n\
               \t}\n\
               ]\n";
    assert!(
        ktav::from_str::<Config>(src).is_err(),
        "unknown key inside a custom provider must be rejected"
    );
}
