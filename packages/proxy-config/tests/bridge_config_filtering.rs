use proxy_config::BridgesConfig;

#[test]
fn config_parser_rejects_documentation_addresses_before_engine_start() {
    let config = BridgesConfig {
        lines: vec![
            "webtunnel [2001:db8::1]:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 url=https://example.com/path ver=0.0.3".into(),
            "obfs4 5.45.101.108:36781 0123456789ABCDEF0123456789ABCDEF01234567 cert=BBB iat-mode=0".into(),
        ],
        ..Default::default()
    };

    let parsed = config.parsed().expect("valid bridge syntax");

    assert_eq!(parsed.rejected, 1);
    assert_eq!(parsed.duplicates, 0);
    assert_eq!(parsed.bridges.len(), 1);
    assert_eq!(parsed.bridges[0].addr.to_string(), "5.45.101.108:36781");
}
