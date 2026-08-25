use proxy_config::BridgesConfig;

#[test]
fn config_parser_rejects_documentation_addresses_before_engine_start() {
    // webtunnel lines use a 2001:db8::/32 ORPort placeholder by design (their
    // real endpoint is in url=) and must survive; a plain obfs4 line on the
    // same placeholder is a dead documentation address and must be rejected.
    let config = BridgesConfig {
        lines: vec![
            "webtunnel [2001:db8::1]:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 url=https://example.com/path ver=0.0.3".into(),
            "obfs4 [2001:db8::2]:443 ABCDEF0123456789ABCDEF0123456789ABCDEF02 cert=AAA iat-mode=0".into(),
            "obfs4 5.45.101.108:36781 0123456789ABCDEF0123456789ABCDEF01234567 cert=BBB iat-mode=0".into(),
        ],
        ..Default::default()
    };

    let parsed = config.parsed().expect("valid bridge syntax");

    assert_eq!(parsed.rejected, 1);
    assert_eq!(parsed.duplicates, 0);
    assert_eq!(parsed.bridges.len(), 2);
    assert_eq!(parsed.bridges[0].transport.as_deref(), Some("webtunnel"));
    assert_eq!(parsed.bridges[1].addr.to_string(), "5.45.101.108:36781");
}
