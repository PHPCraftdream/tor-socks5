use super::bridge_for;
use crate::*;
use crate::{dns::*, probe::*};
use bridge_line::BridgeLine;
use std::str::FromStr;
use tokio::net::TcpListener;

#[test]
fn scheme_less_webtunnel_url_is_read_as_https() {
    let url = parse_webtunnel_url("tor.cenesp.es").expect("a bare host is accepted");
    assert_eq!(url.scheme(), "https");
    assert_eq!(url.host_str(), Some("tor.cenesp.es"));
}

// -- Probe-target resolution tests (no network, no DNS) ------------------

#[test]
fn obfs4_bridge_probes_bridge_addr() {
    let bridge: BridgeLine = "obfs4 10.0.0.1:9001 ABCDEF0123456789ABCDEF0123456789ABCDEF01"
        .parse()
        .unwrap();
    let (host, port) = resolve_probe_target(&bridge).unwrap();
    assert_eq!(host, "10.0.0.1");
    assert_eq!(port, 9001);
}

#[test]
fn default_resolver_policy_uses_doh_without_system_fallback() {
    assert!(ResolverPolicy::default().doh_enabled);
    assert!(!ResolverPolicy::default().system_fallback);
    assert!(
        DOH_PROVIDERS.len() >= 10,
        "keep a broad provider/address pool"
    );
}

#[tokio::test]
async fn disabled_resolvers_fail_hostname_explicitly() {
    let result = resolve_addrs(
        "bridge.example.invalid",
        443,
        ResolverPolicy {
            doh_enabled: false,
            system_fallback: false,
        },
    )
    .await;
    let error = result.expect_err("both resolver paths are disabled");
    assert!(error.contains("no DNS resolver available"));
}

#[test]
fn plain_bridge_probes_bridge_addr() {
    let bridge: BridgeLine = "10.0.0.1:9001 ABCDEF0123456789ABCDEF0123456789ABCDEF01"
        .parse()
        .unwrap();
    let (host, port) = resolve_probe_target(&bridge).unwrap();
    assert_eq!(host, "10.0.0.1");
    assert_eq!(port, 9001);
}

#[test]
fn webtunnel_bridge_probes_url_host_port() {
    let bridge: BridgeLine =
        "webtunnel 192.0.2.3:1 2852538D49D7D73C1A6694FC492104983A9C4FA2 url=https://example.com/secretRoute"
            .parse()
            .unwrap();
    let (host, port) = resolve_probe_target(&bridge).unwrap();
    assert_eq!(host, "example.com");
    assert_eq!(port, 443);
}

#[test]
fn rejects_documentation_ipv6_bridge_addresses() {
    // A plain bridge with a 2001:db8::/32 ORPort is a real placeholder.
    let bridge: BridgeLine =
        "obfs4 [2001:db8::1]:443 2852538D49D7D73C1A6694FC492104983A9C4FA2 cert=AAA iat-mode=0"
            .parse()
            .expect("bridge line parses");
    assert!(!usable_for_tor(&bridge));
}

#[test]
fn keeps_webtunnel_with_documentation_orport_placeholder() {
    // webtunnel legitimately uses a 2001:db8::/32 ORPort placeholder; the
    // real endpoint is in url=, so the bridge must be kept.
    let bridge: BridgeLine =
        "webtunnel [2001:db8::1]:443 2852538D49D7D73C1A6694FC492104983A9C4FA2 url=https://example.com/x"
            .parse()
            .expect("bridge line parses");
    assert!(usable_for_tor(&bridge));
}

#[test]
fn rejects_webtunnel_missing_url_and_addr() {
    let bridge: BridgeLine =
        "webtunnel [2001:db8::1]:443 2852538D49D7D73C1A6694FC492104983A9C4FA2 ver=0.0.3"
            .parse()
            .expect("bridge line parses");
    assert!(!usable_for_tor(&bridge));
}

#[test]
fn keeps_public_ipv4_bridge_addresses_usable() {
    let bridge: BridgeLine =
        "obfs4 5.45.101.108:36781 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0"
            .parse()
            .expect("bridge line parses");
    assert!(usable_for_tor(&bridge));
}

#[test]
fn webtunnel_http_url_defaults_to_port_80() {
    let bridge: BridgeLine =
        "webtunnel 192.0.2.3:1 2852538D49D7D73C1A6694FC492104983A9C4FA2 url=http://example.com/x"
            .parse()
            .unwrap();
    let (host, port) = resolve_probe_target(&bridge).unwrap();
    assert_eq!(host, "example.com");
    assert_eq!(port, 80);
}

#[test]
fn webtunnel_explicit_port_in_url_wins() {
    let bridge: BridgeLine =
        "webtunnel 192.0.2.3:1 2852538D49D7D73C1A6694FC492104983A9C4FA2 url=https://example.com:8443/x"
            .parse()
            .unwrap();
    let (host, port) = resolve_probe_target(&bridge).unwrap();
    assert_eq!(host, "example.com");
    assert_eq!(port, 8443);
}

#[test]
fn webtunnel_addr_param_overrides_url() {
    let bridge: BridgeLine =
        "webtunnel 192.0.2.3:1 2852538D49D7D73C1A6694FC492104983A9C4FA2 url=https://example.com/secret addr=10.0.0.1:9001"
            .parse()
            .unwrap();
    let (host, port) = resolve_probe_target(&bridge).unwrap();
    assert_eq!(host, "10.0.0.1");
    assert_eq!(port, 9001);
}

#[test]
fn webtunnel_missing_url_and_addr_is_error() {
    let bridge: BridgeLine =
        "webtunnel 192.0.2.3:1 2852538D49D7D73C1A6694FC492104983A9C4FA2 ver=0.0.3"
            .parse()
            .unwrap();
    let err = resolve_probe_target(&bridge).unwrap_err();
    assert!(
        err.contains("missing") || err.contains("url"),
        "expected error about missing url/addr, got: {err}"
    );
}

#[test]
fn webtunnel_invalid_url_is_error() {
    let bridge: BridgeLine =
        "webtunnel 192.0.2.3:1 2852538D49D7D73C1A6694FC492104983A9C4FA2 url=:::not_a_url"
            .parse()
            .unwrap();
    let err = resolve_probe_target(&bridge).unwrap_err();
    assert!(
        err.contains("invalid url"),
        "expected error about invalid url, got: {err}"
    );
}

#[test]
fn unrecognised_transport_falls_back_to_bridge_addr() {
    let bridge: BridgeLine = "snowflake 10.0.0.1:9001 ABCDEF0123456789ABCDEF0123456789ABCDEF01"
        .parse()
        .unwrap();
    let (host, port) = resolve_probe_target(&bridge).unwrap();
    assert_eq!(host, "10.0.0.1");
    assert_eq!(port, 9001);
}

#[test]
fn webtunnel_invalid_addr_param_is_error() {
    let bridge: BridgeLine =
        "webtunnel 192.0.2.3:1 2852538D49D7D73C1A6694FC492104983A9C4FA2 url=https://example.com/x addr=not-an-addr"
            .parse()
            .unwrap();
    let err = resolve_probe_target(&bridge).unwrap_err();
    assert!(
        err.contains("invalid addr"),
        "expected addr error, got: {err}"
    );
}

#[test]
fn webtunnel_url_with_unknown_scheme_no_port_is_error() {
    let bridge: BridgeLine =
        "webtunnel 192.0.2.3:1 2852538D49D7D73C1A6694FC492104983A9C4FA2 url=xyzzy://example.com/x"
            .parse()
            .unwrap();
    let err = resolve_probe_target(&bridge).unwrap_err();
    assert!(
        err.contains("no port") || err.contains("scheme"),
        "expected port/scheme error, got: {err}"
    );
}

#[test]
fn obfs4_ipv6_bridge_addr_resolved() {
    let bridge: BridgeLine = "obfs4 [::1]:9050 ABCDEF0123456789ABCDEF0123456789ABCDEF01"
        .parse()
        .unwrap();
    let (host, port) = resolve_probe_target(&bridge).unwrap();
    assert_eq!(host, "::1");
    assert_eq!(port, 9050);
}

#[test]
fn report_accessors() {
    let report = Report {
        bridge: bridge_for("127.0.0.1:1".parse().unwrap()),
        outcome: Outcome::Reachable {
            latency: Duration::from_millis(42),
        },
    };
    assert!(report.is_reachable());
    assert_eq!(report.latency(), Some(Duration::from_millis(42)));

    let unreachable = Report {
        bridge: bridge_for("127.0.0.1:1".parse().unwrap()),
        outcome: Outcome::Unreachable {
            reason: "test".into(),
        },
    };
    assert!(!unreachable.is_reachable());
    assert!(unreachable.latency().is_none());
}

// -- PreparedTarget plan tests (no I/O) -----------------------------------

fn plan_for(bridge_line: &str) -> PreparedTarget {
    let bridge: BridgeLine = bridge_line.parse().expect("bridge line parses");
    PreparedTarget::new(&bridge.params).expect("plan builds")
}

#[test]
fn plan_servername_override_replaces_url_host() {
    let t = plan_for(
        "webtunnel 192.0.2.3:1 2852538D49D7D73C1A6694FC492104983A9C4FA2 \
         url=https://example.com/x servername=front.test",
    );
    assert_eq!(t.sni, "front.test");
    assert_eq!(t.host_header, "front.test");
    assert_eq!(t.dial_host, "example.com");
    assert_eq!(t.dial_port, 443);
    assert!(t.use_tls);
}

#[test]
fn plan_explicit_url_port_reaches_the_host_header() {
    let t = plan_for(
        "webtunnel 192.0.2.3:1 2852538D49D7D73C1A6694FC492104983A9C4FA2 \
         url=https://example.com:8443/x servername=front.test",
    );
    assert_eq!(t.host_header, "front.test:8443");
}

#[test]
fn plan_ipv6_url_host_is_bracketed_on_the_wire() {
    let t = plan_for(
        "webtunnel 192.0.2.3:1 2852538D49D7D73C1A6694FC492104983A9C4FA2 \
         url=https://[::1]:8443/x",
    );
    assert_eq!(t.sni, "::1");
    assert_eq!(t.host_header, "[::1]:8443");
    assert_eq!(t.dial_host, "::1");
    assert_eq!(t.dial_port, 8443);
    assert!(t.use_tls);
}

#[test]
fn plan_http_url_disables_tls() {
    let t = plan_for(
        "webtunnel 192.0.2.3:1 2852538D49D7D73C1A6694FC492104983A9C4FA2 \
         url=http://example.com/x",
    );
    assert!(!t.use_tls);
}

#[test]
fn plan_and_resolve_accept_bare_hostname_addr_param() {
    // Collectors publish hostname addr= values; a SocketAddr parse rejects
    // them and used to leave those bridges unprobed entirely.
    let line = "webtunnel 192.0.2.3:1 2852538D49D7D73C1A6694FC492104983A9C4FA2 \
         url=https://example.com/x addr=bridge.host.invalid:443";
    let t = plan_for(line);
    assert_eq!(t.dial_host, "bridge.host.invalid");
    assert_eq!(t.dial_port, 443);

    let bridge: BridgeLine = line.parse().unwrap();
    let (host, port) = resolve_probe_target(&bridge).unwrap();
    assert_eq!(host, "bridge.host.invalid");
    assert_eq!(port, 443);
}

#[test]
fn plan_rejects_crlf_in_servername() {
    let bridge: BridgeLine = "webtunnel 192.0.2.3:1 2852538D49D7D73C1A6694FC492104983A9C4FA2 \
         url=https://example.com/x servername=front.test%0d%0aX-Injected:%201"
        .parse()
        .unwrap();
    // The percent-decoded value carries a CRLF; the ServerName check must
    // reject it before it can reach the wire, as the transport does.
    assert!(PreparedTarget::new(&bridge.params).is_err());
}

#[test]
fn plan_rejects_addr_without_port_and_without_colon() {
    let base =
        "webtunnel 192.0.2.3:1 2852538D49D7D73C1A6694FC492104983A9C4FA2 url=https://example.com/x";
    let bridge: BridgeLine = format!("{base} addr=host.notaport").parse().unwrap();
    let err = PreparedTarget::new(&bridge.params).unwrap_err();
    assert!(err.contains("invalid addr"), "got: {err}");

    let bridge: BridgeLine = format!("{base} addr=nocolon").parse().unwrap();
    let err = PreparedTarget::new(&bridge.params).unwrap_err();
    assert!(err.contains("invalid addr"), "got: {err}");
}

// -- Wire-level webtunnel upgrade tests (local listeners only) ------------

const WEBTUNNEL_KEY: &str = "2852538D49D7D73C1A6694FC492104983A9C4FA2";

/// Read one request off the socket and answer with `101 Switching
/// Protocols`, then hold the socket so the probe's read sees the response
/// before the connection goes away.
async fn serve_one_upgrade(listener: TcpListener) -> Vec<u8> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut sock, _) = listener.accept().await.expect("probe connects");
    let mut buf = vec![0u8; 4096];
    let n = sock.read(&mut buf).await.expect("read request");
    buf.truncate(n);
    sock.write_all(
        b"HTTP/1.1 101 Switching Protocols\r\n\
          Upgrade: websocket\r\n\
          Connection: Upgrade\r\n\
          \r\n",
    )
    .await
    .expect("write 101");
    // Keep the socket open briefly; dropping it inside this task is fine
    // once the probe has parsed the response.
    tokio::time::sleep(Duration::from_millis(50)).await;
    buf
}

fn webtunnel_bridge(url: &str, extra: &str) -> BridgeLine {
    BridgeLine::from_str(&format!(
        "webtunnel [2001:db8::1]:443 {WEBTUNNEL_KEY} url={url}{extra}"
    ))
    .expect("webtunnel bridge line parses")
}

const NO_RESOLVERS: ResolverPolicy = ResolverPolicy {
    doh_enabled: false,
    system_fallback: false,
};

#[tokio::test]
async fn http_url_upgrade_probe_is_plain_without_tls() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(serve_one_upgrade(listener));

    let bridge = webtunnel_bridge(&format!("http://127.0.0.1:{port}/secret"), "");

    let outcome = resolve_and_probe(&bridge, Duration::from_secs(2), NO_RESOLVERS).await;
    assert!(
        matches!(outcome, Outcome::Reachable { .. }),
        "expected Reachable, got {outcome:?}"
    );

    let request = server.await.expect("server task");
    let request = String::from_utf8_lossy(&request).into_owned();
    assert!(
        request.starts_with("GET /secret HTTP/1.1"),
        "unexpected request: {request}"
    );
    assert!(
        request.contains(&format!("Host: 127.0.0.1:{port}")),
        "explicit URL port must reach the Host header: {request}"
    );
}

#[tokio::test]
async fn servername_override_reaches_the_wire_as_host() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(serve_one_upgrade(listener));

    let bridge = webtunnel_bridge(
        &format!("http://127.0.0.1:{port}/secret"),
        " servername=front.example.test",
    );

    let outcome = resolve_and_probe(&bridge, Duration::from_secs(2), NO_RESOLVERS).await;
    assert!(
        matches!(outcome, Outcome::Reachable { .. }),
        "expected Reachable, got {outcome:?}"
    );

    let request = server.await.expect("server task");
    let request = String::from_utf8_lossy(&request).into_owned();
    assert!(
        request.contains("Host: front.example.test"),
        "servername override must become the Host header: {request}"
    );
    assert!(
        !request.contains("Host: 127.0.0.1"),
        "URL host must not leak into the Host header: {request}"
    );
}

/// Extract the SNI hostname from a TLS ClientHello, bounds-checked and
/// panic-free: anything unexpected just yields `None`.
fn client_hello_sni(bytes: &[u8]) -> Option<String> {
    fn be16(b: &[u8]) -> Option<usize> {
        Some((usize::from(*b.first()?) << 8) | usize::from(*b.get(1)?))
    }

    // One TLS record: type 0x16 (handshake), then version + u16 length.
    if bytes.first() != Some(&0x16) {
        return None;
    }
    let record_len = be16(&bytes[3..5])?;
    let end = 5usize.checked_add(record_len)?;
    if bytes.len() < end {
        return None;
    }
    let hs = &bytes[5..end];

    // ClientHello: type 0x01, 3-byte length, version, 32 random bytes.
    if hs.first() != Some(&0x01) || hs.len() < 43 {
        return None;
    }
    let mut pos = 1 + 3 + 2 + 32;
    // session_id, cipher_suites, compression methods: 1/2/1-byte lengths.
    let session_id_len = usize::from(*hs.get(pos)?);
    pos += 1 + session_id_len;
    let ciphers_len = be16(hs.get(pos..pos + 2)?)?;
    pos += 2 + ciphers_len;
    let comp_len = usize::from(*hs.get(pos)?);
    pos += 1 + comp_len;
    if pos > hs.len() {
        return None;
    }
    // Extensions: u16 total length, then type/length/data triples.
    let ext_total = be16(hs.get(pos..pos + 2)?)?;
    pos += 2;
    let ext_end = pos.checked_add(ext_total)?;
    if hs.len() < ext_end {
        return None;
    }
    while pos + 4 <= ext_end {
        let etype = be16(&hs[pos..pos + 2])?;
        let elen = be16(&hs[pos + 2..pos + 4])?;
        let data = hs.get(pos + 4..pos + 4 + elen)?;
        pos += 4 + elen;
        if etype != 0x0000 {
            continue;
        }
        // server_name extension: u16 list length, name_type 0x00, u16 len, name.
        if data.len() < 5 || data[2] != 0x00 {
            return None;
        }
        let list_len = be16(&data[..2])?;
        if data.len() < 2 + list_len {
            return None;
        }
        let name_len = be16(data.get(3..5)?)?;
        let name = data.get(5..5 + name_len)?;
        return String::from_utf8(name.to_vec()).ok();
    }
    None
}

#[tokio::test]
async fn servername_override_sets_tls_sni_on_the_wire() {
    // A PLAIN listener: the probe must attempt TLS (ClientHello on the wire),
    // the ClientHello must carry the servername override as SNI, and the
    // handshake must fail against a non-TLS server with our own "tls:" prefix.
    use tokio::io::AsyncReadExt;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let reader = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("probe connects");
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        // Loop-read until a full TLS record is buffered (cap at 16 KiB).
        while buf.len() < 16 * 1024 {
            let n = tokio::time::timeout(Duration::from_secs(2), sock.read(&mut chunk))
                .await
                .expect("read does not hang")
                .expect("read ClientHello");
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.len() >= 5 {
                let record_len = usize::from(buf[3]) << 8 | usize::from(buf[4]);
                if buf.len() >= 5 + record_len {
                    break;
                }
            }
        }
        buf
    });

    let bridge = webtunnel_bridge(
        &format!("https://127.0.0.1:{port}/secret"),
        " servername=real.example.test",
    );

    let outcome = resolve_and_probe(&bridge, Duration::from_secs(5), NO_RESOLVERS).await;
    match &outcome {
        Outcome::Unreachable { reason } => {
            assert!(
                reason.contains("tls:"),
                "TLS must have been genuinely attempted and failed: {reason}"
            );
        }
        other => panic!("expected Unreachable, got {other:?}"),
    }

    let hello = reader.await.expect("reader task");
    assert_eq!(
        client_hello_sni(&hello).as_deref(),
        Some("real.example.test"),
        "servername override must be the on-the-wire SNI, not the URL host"
    );
}

// TS5-03: every webtunnel candidate gets its own slice of the budget for one
// complete attempt (TCP + TLS + upgrade), so a first address that accepts and
// then hangs cannot starve the remaining candidates.

/// A listener that accepts and then never speaks again: the "hangs after
/// accept" failure mode that used to eat the whole probe budget.
async fn hanging_listener() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        // Bind the accepted socket in a named variable so the connection is
        // HELD open without ever reading or writing: the probe's request is
        // never answered.
        if let Ok((held, _)) = listener.accept().await {
            let _held = held;
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });
    addr
}

fn webtunnel_plan(url: &str) -> PreparedTarget {
    PreparedTarget::new(&webtunnel_bridge(url, "").params).expect("webtunnel plan parses")
}

#[tokio::test]
async fn a_hanging_first_address_leaves_budget_for_the_second() {
    let hanging = hanging_listener().await;
    let good = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let good_addr = good.local_addr().unwrap();
    let server = tokio::spawn(serve_one_upgrade(good));

    let plan = webtunnel_plan("http://frontend.test/secret");
    let budget = Duration::from_secs(6);
    let started = std::time::Instant::now();
    let outcome = webtunnel_upgrade_probe(&[hanging, good_addr], &plan, budget).await;
    let elapsed = started.elapsed();

    // Without the per-address budget this is exactly the bug: the hanging
    // first address eats all 6 seconds, the outer timeout fires, and the
    // outcome is Unreachable with the working second address never tried.
    assert!(
        matches!(outcome, Outcome::Reachable { .. }),
        "the working second address must be reached past the hanging first one, got {outcome:?}"
    );
    assert!(
        elapsed < budget,
        "the first address must not consume more than its own share of the budget; took {elapsed:?}"
    );
    let request = server.await.expect("server task");
    assert!(
        !request.is_empty(),
        "the second address must have received the upgrade request"
    );
}

#[tokio::test]
async fn a_hanging_ipv4_still_tries_the_ipv6_candidate() {
    let hanging = hanging_listener().await;
    assert!(hanging.is_ipv4());
    let good = TcpListener::bind("[::1]:0").await.unwrap();
    let good_addr = good.local_addr().unwrap();
    assert!(good_addr.is_ipv6());
    let server = tokio::spawn(serve_one_upgrade(good));

    let plan = webtunnel_plan("http://frontend.test/secret");
    let budget = Duration::from_secs(6);
    let started = std::time::Instant::now();
    let outcome = webtunnel_upgrade_probe(&[hanging, good_addr], &plan, budget).await;
    let elapsed = started.elapsed();

    assert!(
        matches!(outcome, Outcome::Reachable { .. }),
        "the working IPv6 candidate must be reached past the hanging IPv4 one, got {outcome:?}"
    );
    assert!(
        elapsed < budget,
        "the hanging IPv4 address must not eat the whole budget; took {elapsed:?}"
    );
    assert!(
        !server.await.expect("server task").is_empty(),
        "the IPv6 candidate must have received the upgrade request"
    );
}

#[tokio::test]
async fn a_hanging_ipv6_still_tries_the_ipv4_candidate() {
    let good = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let good_addr = good.local_addr().unwrap();
    assert!(good_addr.is_ipv4());
    let server = tokio::spawn(serve_one_upgrade(good));

    let hanging_listener = TcpListener::bind("[::1]:0").await.unwrap();
    let hanging = hanging_listener.local_addr().unwrap();
    assert!(hanging.is_ipv6());
    tokio::spawn(async move {
        if let Ok((held, _)) = hanging_listener.accept().await {
            let _held = held;
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });

    let plan = webtunnel_plan("http://frontend.test/secret");
    let budget = Duration::from_secs(6);
    let started = std::time::Instant::now();
    let outcome = webtunnel_upgrade_probe(&[hanging, good_addr], &plan, budget).await;
    let elapsed = started.elapsed();

    assert!(
        matches!(outcome, Outcome::Reachable { .. }),
        "the working IPv4 candidate must be reached past the hanging IPv6 one, got {outcome:?}"
    );
    assert!(
        elapsed < budget,
        "the hanging IPv6 address must not eat the whole budget; took {elapsed:?}"
    );
    assert!(
        !server.await.expect("server task").is_empty(),
        "the IPv4 candidate must have received the upgrade request"
    );
}

#[tokio::test]
async fn all_candidates_hanging_is_unreachable_within_the_budget() {
    let hanging1 = hanging_listener().await;
    let hanging2 = hanging_listener().await;

    let plan = webtunnel_plan("http://frontend.test/secret");
    let budget = Duration::from_secs(6);
    let started = std::time::Instant::now();
    let outcome = webtunnel_upgrade_probe(&[hanging1, hanging2], &plan, budget).await;
    let elapsed = started.elapsed();

    match &outcome {
        Outcome::Unreachable { reason } => {
            assert!(
                reason.contains("timed out"),
                "both candidates hang, so the reason must be the per-address timeout: {reason}"
            );
        }
        other => panic!("expected Unreachable, got {other:?}"),
    }
    // Per-address slices sum to the whole budget here (2 x 3s); the outer
    // budget cap must keep the probe from running any longer than that.
    assert!(
        elapsed <= budget + Duration::from_millis(500),
        "the probe must not run meaningfully past the overall budget; took {elapsed:?}"
    );
}
