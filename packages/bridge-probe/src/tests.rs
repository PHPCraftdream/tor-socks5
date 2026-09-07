use super::*;
use super::{dns::*, probe::*};
use bridge_line::BridgeLine;
use std::str::FromStr;
use tokio::net::TcpListener;

fn bridge_for(addr: std::net::SocketAddr) -> BridgeLine {
    BridgeLine::from_str(&format!(
        "obfs4 {addr} ABCDEF0123456789ABCDEF0123456789ABCDEF01"
    ))
    .expect("synthetic bridge line parses")
}

/// The cache tests share one process-wide map, so each uses its own
/// hostname and cleans up after itself rather than flushing the lot.
#[test]
fn cached_answer_is_returned_until_it_expires() {
    let host = "cache-hit.test.invalid";
    let ip: IpAddr = "203.0.113.7".parse().unwrap();
    remember_doh_answer(host, &[ip], Duration::from_secs(300));

    match cached_doh_answer(host) {
        Some(CacheHit::Addrs(addrs)) => assert_eq!(addrs, vec![ip]),
        _ => panic!("a fresh answer must be served from the cache"),
    }

    forget_dns_answer(host);
    assert!(cached_doh_answer(host).is_none());
}

#[test]
fn expired_answer_is_not_served_by_the_normal_path() {
    let host = "cache-stale.test.invalid";
    // Straight into the map with an expiry already in the past — the
    // public helper clamps TTLs upwards, so it cannot express this.
    store_cached(
        host,
        CachedAnswer {
            addrs: vec!["203.0.113.8".parse().unwrap()],
            expires_at: Instant::now() - Duration::from_secs(1),
        },
    );
    assert!(cached_doh_answer(host).is_none());
    // Deliberately NOT dropped: an expired-but-recent positive answer
    // must survive for `stale_fallback_answer` to serve as a last
    // resort when every DoH provider is unreachable.
    assert!(
        doh_cache().lock().unwrap().contains_key(host),
        "an expired positive answer must stay available for the stale fallback"
    );
    forget_dns_answer(host);
}

#[test]
fn stale_fallback_serves_a_recently_expired_positive_answer() {
    let host = "cache-stale-fallback.test.invalid";
    let ip: IpAddr = "203.0.113.20".parse().unwrap();
    store_cached(
        host,
        CachedAnswer {
            addrs: vec![ip],
            expires_at: Instant::now() - Duration::from_secs(60),
        },
    );
    assert_eq!(stale_fallback_answer(host), Some(vec![ip]));
    forget_dns_answer(host);
}

#[test]
fn stale_fallback_refuses_an_answer_past_the_fallback_window() {
    let host = "cache-too-stale.test.invalid";
    store_cached(
        host,
        CachedAnswer {
            addrs: vec!["203.0.113.21".parse().unwrap()],
            expires_at: Instant::now() - DNS_STALE_FALLBACK_WINDOW - Duration::from_secs(1),
        },
    );
    assert!(stale_fallback_answer(host).is_none());
    forget_dns_answer(host);
}

#[test]
fn stale_fallback_refuses_a_fresh_answer() {
    // A still-valid entry must be served by `cached_doh_answer`, not by
    // the stale path -- `resolve_addrs` only calls the latter after a
    // live DoH round has already failed.
    let host = "cache-fresh-not-stale.test.invalid";
    remember_doh_answer(
        host,
        &["203.0.113.22".parse().unwrap()],
        Duration::from_secs(300),
    );
    assert!(stale_fallback_answer(host).is_none());
    forget_dns_answer(host);
}

#[test]
fn stale_fallback_refuses_a_remembered_failure() {
    let host = "cache-negative-not-stale.test.invalid";
    remember_doh_failure(host);
    // Force it into the past so it would otherwise look "expired".
    {
        let mut cache = doh_cache().lock().unwrap();
        cache.get_mut(host).unwrap().expires_at = Instant::now() - Duration::from_secs(1);
    }
    assert!(stale_fallback_answer(host).is_none());
    forget_dns_answer(host);
}

#[test]
fn persisted_line_round_trips() {
    let entry = PersistedAnswer {
        addrs: vec![
            "203.0.113.30".parse().unwrap(),
            "203.0.113.31".parse().unwrap(),
        ],
        resolved_at_unix: 1_700_000_000,
    };
    let line = format_persisted_line("example.test.invalid", &entry);
    let (host, parsed) = parse_persisted_line(&line).expect("line must parse back");
    assert_eq!(host, "example.test.invalid");
    assert_eq!(parsed.addrs, entry.addrs);
    assert_eq!(parsed.resolved_at_unix, entry.resolved_at_unix);
}

#[test]
fn parse_persisted_line_rejects_garbage() {
    assert!(parse_persisted_line("").is_none());
    assert!(parse_persisted_line("only-a-host").is_none());
    assert!(parse_persisted_line("host\t\tnotanumber").is_none());
    assert!(parse_persisted_line("host\tnotanip\t123").is_none());
}

#[test]
fn save_and_load_persisted_cache_round_trips_through_disk_fallback() {
    let host = "cache-disk-roundtrip.test.invalid";
    let ip: IpAddr = "203.0.113.40".parse().unwrap();
    remember_doh_answer(host, &[ip], Duration::from_secs(300));

    let dir = std::env::temp_dir().join(format!("bridge-probe-dns-cache-test-{}", now_unix()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("dns-cache.txt");
    save_persisted_dns_cache(&path).expect("save must succeed");
    forget_dns_answer(host); // wipe the in-memory entry entirely

    load_persisted_dns_cache(&path);
    assert_eq!(disk_fallback_answer(host), Some(vec![ip]));

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn disk_fallback_refuses_an_answer_past_the_fallback_window() {
    let host = "cache-disk-too-stale.test.invalid";
    {
        let mut store = disk_fallback_store().lock().unwrap();
        store.insert(
            host.to_owned(),
            PersistedAnswer {
                addrs: vec!["203.0.113.41".parse().unwrap()],
                resolved_at_unix: now_unix() - DNS_STALE_FALLBACK_WINDOW.as_secs() - 1,
            },
        );
    }
    assert!(disk_fallback_answer(host).is_none());
}

#[test]
fn load_persisted_dns_cache_is_a_no_op_for_a_missing_file() {
    // Must not panic -- a first run, or one predating this feature.
    load_persisted_dns_cache(std::path::Path::new("/nonexistent/does-not-exist.txt"));
}

#[test]
fn dns_hint_line_round_trips() {
    let hint = DnsHint {
        host: "bridge.example.test".to_owned(),
        addrs: vec![
            "198.51.100.5".parse().unwrap(),
            "198.51.100.6".parse().unwrap(),
        ],
        resolved_at_unix: 1_700_000_500,
    };
    let line = format_dns_hint_line(&hint);
    assert!(line.starts_with(DNS_HINT_PREFIX));
    assert_eq!(parse_dns_hint_line(&line), Some(hint));
}

#[test]
fn parse_dns_hint_line_rejects_non_hint_lines() {
    assert!(parse_dns_hint_line("obfs4 1.2.3.4:443 ABCDEF cert=x").is_none());
    assert!(parse_dns_hint_line("# just a comment").is_none());
    assert!(parse_dns_hint_line("").is_none());
    assert!(parse_dns_hint_line("# xorbot:dns onlyhost").is_none());
    assert!(parse_dns_hint_line("# xorbot:dns host notanip 123").is_none());
}

#[test]
fn dns_hostname_of_is_none_for_ip_only_bridges() {
    let obfs4: BridgeLine =
        "obfs4 192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0"
            .parse()
            .unwrap();
    assert_eq!(dns_hostname_of(&obfs4), None);

    let webtunnel_addr: BridgeLine =
        "webtunnel 192.0.2.2:1 0123456789ABCDEF0123456789ABCDEF01234567 addr=192.0.2.9:443 url=https://example.com/x"
            .parse()
            .unwrap();
    assert_eq!(dns_hostname_of(&webtunnel_addr), None);
}

#[test]
fn dns_hostname_of_finds_the_webtunnel_url_host() {
    let webtunnel: BridgeLine =
        "webtunnel 192.0.2.3:1 0123456789ABCDEF0123456789ABCDEF01234567 url=https://fronting.example.test/x"
            .parse()
            .unwrap();
    assert_eq!(
        dns_hostname_of(&webtunnel),
        Some("fronting.example.test".to_owned())
    );
}

#[test]
fn best_known_answer_prefers_live_cache_over_disk() {
    let host = "best-answer-live.test.invalid";
    let live_ip: IpAddr = "203.0.113.50".parse().unwrap();
    remember_doh_answer(host, &[live_ip], Duration::from_secs(300));
    {
        let mut store = disk_fallback_store().lock().unwrap();
        store.insert(
            host.to_owned(),
            PersistedAnswer {
                addrs: vec!["203.0.113.51".parse().unwrap()],
                resolved_at_unix: now_unix(),
            },
        );
    }
    let hint = best_known_answer(host).expect("must find an answer");
    assert_eq!(hint.addrs, vec![live_ip]);
    forget_dns_answer(host);
}

#[test]
fn best_known_answer_falls_back_to_disk_when_live_cache_is_empty() {
    let host = "best-answer-disk.test.invalid";
    let ip: IpAddr = "203.0.113.52".parse().unwrap();
    {
        let mut store = disk_fallback_store().lock().unwrap();
        store.insert(
            host.to_owned(),
            PersistedAnswer {
                addrs: vec![ip],
                resolved_at_unix: now_unix(),
            },
        );
    }
    let hint = best_known_answer(host).expect("must find an answer");
    assert_eq!(hint.addrs, vec![ip]);
}

#[test]
fn best_known_answer_is_none_when_nothing_is_known() {
    assert!(best_known_answer("never-seen.test.invalid").is_none());
}

#[test]
fn seed_disk_fallback_respects_last_write_wins() {
    let host = "seed-lww.test.invalid";
    let older: IpAddr = "203.0.113.60".parse().unwrap();
    let newer: IpAddr = "203.0.113.61".parse().unwrap();
    seed_disk_fallback(&[DnsHint {
        host: host.to_owned(),
        addrs: vec![newer],
        resolved_at_unix: 2_000_000_000,
    }]);
    // An older hint must not overwrite the newer one already seeded.
    seed_disk_fallback(&[DnsHint {
        host: host.to_owned(),
        addrs: vec![older],
        resolved_at_unix: 1_000_000_000,
    }]);
    assert_eq!(
        disk_fallback_store()
            .lock()
            .unwrap()
            .get(host)
            .unwrap()
            .addrs,
        vec![newer]
    );
}

#[test]
fn a_failed_resolution_is_remembered_briefly() {
    let host = "cache-negative.test.invalid";
    remember_doh_failure(host);
    assert!(matches!(
        cached_doh_answer(host),
        Some(CacheHit::Unresolvable)
    ));
    forget_dns_answer(host);
}

#[test]
fn ttl_is_clamped_into_the_useful_range() {
    let host = "cache-ttl.test.invalid";
    let ip: IpAddr = "203.0.113.9".parse().unwrap();

    // A CDN's 20-second TTL must not send us back to the providers on the
    // next round.
    remember_doh_answer(host, &[ip], Duration::from_secs(20));
    let floor = doh_cache().lock().unwrap()[host].expires_at;
    assert!(floor >= Instant::now() + DNS_MIN_TTL - Duration::from_secs(1));

    // A record claiming a day must not outlive the bridge moving.
    remember_doh_answer(host, &[ip], Duration::from_secs(86_400));
    let ceiling = doh_cache().lock().unwrap()[host].expires_at;
    assert!(ceiling <= Instant::now() + DNS_MAX_TTL);

    forget_dns_answer(host);
}

#[test]
fn scheme_less_webtunnel_url_is_read_as_https() {
    let url = parse_webtunnel_url("tor.cenesp.es").expect("a bare host is accepted");
    assert_eq!(url.scheme(), "https");
    assert_eq!(url.host_str(), Some("tor.cenesp.es"));
}

#[test]
fn candidates_put_ipv4_ahead_of_ipv6() {
    let ips: Vec<IpAddr> = vec![
        "2001:4860:4860::8888".parse().unwrap(),
        "93.184.216.34".parse().unwrap(),
    ];
    let ordered = order_candidates(&ips, 443);
    assert_eq!(ordered.len(), 2);
    assert!(ordered[0].is_ipv4(), "IPv4 must be tried first");
    assert!(ordered[1].is_ipv6(), "IPv6 is still tried, just second");
}

#[test]
fn candidates_drop_duplicates_and_cap_the_list() {
    let ips: Vec<IpAddr> = vec![
        "10.0.0.1".parse().unwrap(),
        "10.0.0.1".parse().unwrap(),
        "10.0.0.2".parse().unwrap(),
        "10.0.0.3".parse().unwrap(),
        "10.0.0.4".parse().unwrap(),
    ];
    let ordered = order_candidates(&ips, 443);
    assert_eq!(ordered.len(), MAX_PROBE_ADDRS);
    assert_eq!(ordered[0].ip(), "10.0.0.1".parse::<IpAddr>().unwrap());
    assert_eq!(ordered[1].ip(), "10.0.0.2".parse::<IpAddr>().unwrap());
}

/// A bridge we could not resolve must not be reported as dead — that
/// verdict belongs to the resolver, not the bridge.
#[tokio::test]
async fn unresolvable_hostname_is_unmeasured_rather_than_unreachable() {
    let bridge = BridgeLine::from_str(
        "webtunnel [2001:db8::1]:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 \
         url=https://nothing.invalid/secret",
    )
    .expect("webtunnel bridge line parses");

    let no_resolver = ResolverPolicy {
        doh_enabled: false,
        system_fallback: false,
    };
    let reports =
        probe_all_with_policy(vec![bridge], Duration::from_millis(200), no_resolver).await;

    assert_eq!(reports.len(), 1);
    assert!(reports[0].is_unmeasured());
    assert!(!reports[0].is_reachable());
    assert!(reports[0].latency().is_none());
}

/// The round's two halves must stay separate all the way to the caller.
#[tokio::test]
async fn probe_round_keeps_unmeasured_out_of_alive() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = listener.accept().await;
    });
    let unresolvable = BridgeLine::from_str(
        "webtunnel [2001:db8::1]:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 \
         url=https://nothing.invalid/secret",
    )
    .unwrap();

    let round = probe_round_with_policy(
        vec![bridge_for(addr), unresolvable],
        Duration::from_millis(500),
        ResolverPolicy {
            doh_enabled: false,
            system_fallback: false,
        },
    )
    .await;

    assert_eq!(round.alive.len(), 1);
    assert_eq!(round.unmeasured.len(), 1);
}

#[tokio::test]
async fn reports_alive_bridge_as_reachable() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = listener.accept().await;
    });

    let reports = probe_all(vec![bridge_for(addr)], Duration::from_secs(2)).await;
    assert_eq!(reports.len(), 1);
    assert!(reports[0].is_reachable());
    assert!(reports[0].latency().unwrap() < Duration::from_secs(2));
}

#[tokio::test]
async fn reports_closed_port_as_unreachable() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let reports = probe_all(vec![bridge_for(addr)], Duration::from_secs(2)).await;
    assert_eq!(reports.len(), 1);
    assert!(!reports[0].is_reachable());
}

#[tokio::test]
async fn probe_and_sort_orders_by_latency_and_drops_dead() {
    let live = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let live_addr = live.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = live.accept().await;
    });

    let dead_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead_listener.local_addr().unwrap();
    drop(dead_listener);

    let alive = probe_and_sort(
        vec![bridge_for(dead_addr), bridge_for(live_addr)],
        Duration::from_secs(2),
    )
    .await;

    assert_eq!(alive.len(), 1);
    assert_eq!(alive[0].0.addr, live_addr);
}

#[tokio::test]
async fn probe_until_stops_at_target() {
    // Two live listeners; target=1 must stop after finding the first
    // live one (it should not probe both).
    let l1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a1 = l1.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = l1.accept().await;
    });
    let l2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a2 = l2.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = l2.accept().await;
    });

    let live = probe_until(
        vec![bridge_for(a1), bridge_for(a2)],
        Duration::from_secs(2),
        1,
        100,
    )
    .await;
    assert_eq!(live.len(), 1, "must stop after reaching target=1");
    assert_eq!(live[0].0.addr, a1, "probes in order, first live wins");
}

#[tokio::test]
async fn probe_until_respects_max_attempts() {
    // One dead addr repeated; max_attempts=2 caps the work and yields
    // zero live without walking the whole (longer) list.
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);
    let candidates = vec![
        bridge_for(dead_addr),
        bridge_for(dead_addr),
        bridge_for(dead_addr),
        bridge_for(dead_addr),
    ];
    let live = probe_until(candidates, Duration::from_secs(1), 3, 2).await;
    assert!(live.is_empty(), "no live bridges among dead candidates");
}

#[tokio::test]
async fn probe_until_target_zero_is_noop() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = listener.accept().await;
    });
    let live = probe_until(vec![bridge_for(addr)], Duration::from_secs(2), 0, 100).await;
    assert!(live.is_empty(), "target=0 probes nothing");
}

#[tokio::test]
async fn probe_times_out_within_budget() {
    let stub_addr: std::net::SocketAddr = "192.0.2.1:9".parse().unwrap();
    let started = std::time::Instant::now();
    let reports = probe_all(vec![bridge_for(stub_addr)], Duration::from_millis(500)).await;
    let elapsed = started.elapsed();

    assert!(!reports[0].is_reachable());
    assert!(elapsed < Duration::from_secs(3));
    match &reports[0].outcome {
        Outcome::Unreachable { reason } => {
            assert!(
                reason.contains("timed out")
                    || reason.contains("unreachable")
                    || reason.contains("network"),
                "unexpected reason: {reason}",
            );
        }
        _ => panic!("expected Unreachable"),
    }
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
