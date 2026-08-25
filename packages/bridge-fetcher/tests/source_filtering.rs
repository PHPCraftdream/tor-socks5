use bridge_fetcher::parse_bridges_from_body;

#[test]
fn public_source_payload_keeps_webtunnel_and_obfs4_drops_placeholder_obfs4() {
    // webtunnel lines carry a 2001:db8::/32 ORPort placeholder by design (the
    // real endpoint is in url=), so they are kept. A plain obfs4 line with the
    // same placeholder ORPort is a dead documentation address and is dropped.
    let payload = "\
# collector output\n\
webtunnel [2001:db8:abcd::1]:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 url=https://example.com/path ver=0.0.3\n\
obfs4 [2001:db8:abcd::2]:443 ABCDEF0123456789ABCDEF0123456789ABCDEF02 cert=AAA iat-mode=0\n\
obfs4 5.45.101.108:36781 0123456789ABCDEF0123456789ABCDEF01234567 cert=BBB iat-mode=0\n";

    let bridges = parse_bridges_from_body(payload);

    assert_eq!(bridges.len(), 2);
    assert_eq!(bridges[0].transport.as_deref(), Some("webtunnel"));
    assert_eq!(bridges[1].transport.as_deref(), Some("obfs4"));
    assert_eq!(bridges[1].addr.to_string(), "5.45.101.108:36781");
}
