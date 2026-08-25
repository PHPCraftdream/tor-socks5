use bridge_fetcher::parse_bridges_from_body;

#[test]
fn public_source_payload_keeps_real_bridge_and_drops_documentation_webtunnel() {
    let payload = "\
# collector output\n\
webtunnel [2001:db8:abcd::1]:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 url=https://example.com/path ver=0.0.3\n\
obfs4 5.45.101.108:36781 0123456789ABCDEF0123456789ABCDEF01234567 cert=BBB iat-mode=0\n";

    let bridges = parse_bridges_from_body(payload);

    assert_eq!(bridges.len(), 1);
    assert_eq!(bridges[0].transport.as_deref(), Some("obfs4"));
    assert_eq!(bridges[0].addr.to_string(), "5.45.101.108:36781");
}
