use crate::probe::*;
use bridge_line::BridgeLine;

#[test]
fn webtunnel_identity_from_url() {
    let bridge: BridgeLine = "webtunnel 9.9.9.9:443 1111111111111111111111111111111111111111 \
         url=https://e.com/x ver=0.0.3"
        .parse()
        .unwrap();
    assert_eq!(
        webtunnel_endpoint_identity(&bridge),
        Some(WebtunnelEndpointIdentity {
            dial_host: "e.com".to_string(),
            dial_port: 443,
            sni: "e.com".to_string(),
            host_header: "e.com".to_string(),
            request_target: "/x".to_string(),
            use_tls: true,
        })
    );
}

#[test]
fn webtunnel_identity_distinguishes_paths() {
    let old: BridgeLine = "webtunnel 9.9.9.9:443 1111111111111111111111111111111111111111 \
         url=https://e.com/old ver=0.0.3"
        .parse()
        .unwrap();
    let new: BridgeLine = "webtunnel 9.9.9.9:443 1111111111111111111111111111111111111111 \
         url=https://e.com/new ver=0.0.3"
        .parse()
        .unwrap();
    let old_id = webtunnel_endpoint_identity(&old).unwrap();
    let new_id = webtunnel_endpoint_identity(&new).unwrap();
    assert_ne!(old_id, new_id, "different url paths must differ");
}

#[test]
fn webtunnel_identity_distinguishes_servername() {
    let old: BridgeLine = "webtunnel 9.9.9.9:443 1111111111111111111111111111111111111111 \
         url=https://edge.example/x servername=old.example ver=0.0.3"
        .parse()
        .unwrap();
    let new: BridgeLine = "webtunnel 9.9.9.9:443 1111111111111111111111111111111111111111 \
         url=https://edge.example/x servername=new.example ver=0.0.3"
        .parse()
        .unwrap();
    let old_id = webtunnel_endpoint_identity(&old).unwrap();
    let new_id = webtunnel_endpoint_identity(&new).unwrap();
    assert_ne!(
        old_id.sni, new_id.sni,
        "servername= must reach the identity"
    );
    assert_ne!(old_id, new_id);
}

#[test]
fn webtunnel_identity_distinguishes_tls_from_plain_http() {
    let plain: BridgeLine = "webtunnel 9.9.9.9:443 1111111111111111111111111111111111111111 \
         url=http://edge.example:443/x ver=0.0.3"
        .parse()
        .unwrap();
    let tls: BridgeLine = "webtunnel 9.9.9.9:443 1111111111111111111111111111111111111111 \
         url=https://edge.example/x ver=0.0.3"
        .parse()
        .unwrap();
    let plain_id = webtunnel_endpoint_identity(&plain).unwrap();
    let tls_id = webtunnel_endpoint_identity(&tls).unwrap();
    // Same dial address on purpose: only the scheme (and with it the Host
    // header's explicit :443) separates the two.
    assert_eq!(plain_id.dial_host, tls_id.dial_host);
    assert_eq!(plain_id.dial_port, tls_id.dial_port);
    assert!(!plain_id.use_tls);
    assert!(tls_id.use_tls);
    assert_ne!(plain_id, tls_id);
}

#[test]
fn webtunnel_identity_distinguishes_virtual_hosts_on_one_addr() {
    let a: BridgeLine = "webtunnel 9.9.9.9:443 1111111111111111111111111111111111111111 \
         url=https://a.example/x addr=9.9.9.9:443 ver=0.0.3"
        .parse()
        .unwrap();
    let b: BridgeLine = "webtunnel 9.9.9.9:443 1111111111111111111111111111111111111111 \
         url=https://b.example/x addr=9.9.9.9:443 ver=0.0.3"
        .parse()
        .unwrap();
    let a_id = webtunnel_endpoint_identity(&a).unwrap();
    let b_id = webtunnel_endpoint_identity(&b).unwrap();
    assert_eq!(a_id.dial_host, b_id.dial_host, "addr= override is shared");
    assert_ne!(a_id.sni, b_id.sni, "virtual hosts must differ");
    assert_ne!(a_id, b_id);
}

#[test]
fn webtunnel_identity_collapses_equivalent_configs() {
    let first: BridgeLine = "webtunnel 9.9.9.9:443 1111111111111111111111111111111111111111 \
         url=https://edge.example/x servername=edge.example addr=9.9.9.9:443 ver=0.0.3"
        .parse()
        .unwrap();
    let second: BridgeLine = "webtunnel 9.9.9.9:443 1111111111111111111111111111111111111111 \
         url=https://edge.example/x servername=edge.example addr=9.9.9.9:443 ver=0.0.3"
        .parse()
        .unwrap();
    assert_eq!(
        webtunnel_endpoint_identity(&first),
        webtunnel_endpoint_identity(&second),
        "literally identical url/servername/addr must dedup to one identity"
    );
}

#[test]
fn non_webtunnel_has_no_identity() {
    let bridge: BridgeLine =
        "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0"
            .parse()
            .unwrap();
    assert_eq!(webtunnel_endpoint_identity(&bridge), None);
}

#[test]
fn webtunnel_without_url_has_no_identity() {
    let bridge: BridgeLine =
        "webtunnel 9.9.9.9:443 1111111111111111111111111111111111111111 ver=0.0.3"
            .parse()
            .unwrap();
    assert_eq!(webtunnel_endpoint_identity(&bridge), None);
}
