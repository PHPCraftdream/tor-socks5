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

// TS4-08: the address limit must not let a long A-only RR set evict the
// IPv6 candidate of a dual-stack host — the limit is shared between the
// families that are present.

#[test]
fn candidates_with_many_ipv4_still_try_ipv6() {
    let ips: Vec<IpAddr> = vec![
        "10.0.0.1".parse().unwrap(),
        "10.0.0.2".parse().unwrap(),
        "10.0.0.3".parse().unwrap(),
        "10.0.0.4".parse().unwrap(),
        "2001:4860:4860::8888".parse().unwrap(),
    ];
    let ordered = order_candidates(&ips, 443);
    assert_eq!(ordered.len(), MAX_PROBE_ADDRS);
    assert_eq!(ordered[0].ip(), "10.0.0.1".parse::<IpAddr>().unwrap());
    assert_eq!(ordered[1].ip(), "10.0.0.2".parse::<IpAddr>().unwrap());
    assert!(
        ordered[2].is_ipv6(),
        "the IPv6 candidate must survive the cap"
    );
}

#[test]
fn ipv6_only_candidates_are_capped_in_order() {
    let ips: Vec<IpAddr> = vec![
        "2001:db8::1".parse().unwrap(),
        "2001:db8::2".parse().unwrap(),
        "2001:db8::3".parse().unwrap(),
        "2001:db8::4".parse().unwrap(),
        "2001:db8::5".parse().unwrap(),
    ];
    let ordered = order_candidates(&ips, 443);
    let expected: Vec<IpAddr> = vec![
        "2001:db8::1".parse().unwrap(),
        "2001:db8::2".parse().unwrap(),
        "2001:db8::3".parse().unwrap(),
    ];
    let got: Vec<IpAddr> = ordered.iter().map(|a| a.ip()).collect();
    assert_eq!(got, expected);
}

#[test]
fn ipv4_shortage_gives_slack_to_ipv6() {
    let ips: Vec<IpAddr> = vec![
        "10.0.0.1".parse().unwrap(),
        "2001:db8::1".parse().unwrap(),
        "2001:db8::2".parse().unwrap(),
        "2001:db8::3".parse().unwrap(),
        "2001:db8::4".parse().unwrap(),
        "2001:db8::5".parse().unwrap(),
    ];
    let ordered = order_candidates(&ips, 443);
    let got: Vec<IpAddr> = ordered.iter().map(|a| a.ip()).collect();
    let expected: Vec<IpAddr> = vec![
        "10.0.0.1".parse().unwrap(),
        "2001:db8::1".parse().unwrap(),
        "2001:db8::2".parse().unwrap(),
    ];
    assert_eq!(got, expected, "IPv6 fills the slack left by IPv4 shortage");
}

#[test]
fn limit_one_keeps_the_previous_result() {
    let mixed: Vec<IpAddr> = vec![
        "10.0.0.1".parse().unwrap(),
        "10.0.0.2".parse().unwrap(),
        "2001:db8::1".parse().unwrap(),
    ];
    let ordered = order_candidates_with_limit(&mixed, 443, 1);
    assert_eq!(
        ordered,
        vec!["10.0.0.1".parse::<IpAddr>().unwrap()]
            .into_iter()
            .map(|ip| SocketAddr::new(ip, 443))
            .collect::<Vec<_>>()
    );
    let v6_only: Vec<IpAddr> = vec![
        "2001:db8::1".parse().unwrap(),
        "2001:db8::2".parse().unwrap(),
    ];
    let ordered = order_candidates_with_limit(&v6_only, 443, 1);
    assert_eq!(
        ordered,
        vec!["2001:db8::1".parse::<IpAddr>().unwrap()]
            .into_iter()
            .map(|ip| SocketAddr::new(ip, 443))
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn tcp_probe_falls_through_to_ipv6_candidate() {
    // With the old blanket take(3) the IPv6 candidate was evicted and this
    // dial would have ended Unreachable.
    //
    // `order_candidates` attaches ONE shared port to every resolved IP (its
    // real caller resolves one hostname to several IPs serving the same
    // target port), so every candidate here -- dead and live alike -- must
    // share that same port for the `ordered[i] == expected` comparisons
    // below to be meaningful. A throwaway bind picks a free port; nothing
    // then listens on it for the three (distinct, 127.0.0.0/8 all routes
    // locally) dead IPv4 addresses, so connecting to them refuses fast.
    let port = {
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        probe.local_addr().unwrap().port()
    };
    let dead_ips =
        ["127.0.0.1", "127.0.0.2", "127.0.0.3"].map(|ip| ip.parse::<std::net::Ipv4Addr>().unwrap());
    let dead: Vec<SocketAddr> = dead_ips
        .iter()
        .map(|ip| SocketAddr::new(IpAddr::V4(*ip), port))
        .collect();
    let live = TcpListener::bind(("::1", port)).await.unwrap();
    let live_addr = live.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            if live.accept().await.is_err() {
                break;
            }
        }
    });

    let mut ips: Vec<IpAddr> = dead.iter().map(|a| a.ip()).collect();
    ips.push(live_addr.ip());
    let ordered = order_candidates(&ips, port);
    assert_eq!(ordered.len(), MAX_PROBE_ADDRS);
    assert_eq!(ordered[0], dead[0]);
    assert_eq!(ordered[1], dead[1]);
    assert_eq!(ordered[2], live_addr);

    let outcome = tcp_probe(&ordered, Duration::from_secs(2)).await;
    assert!(
        matches!(outcome, Outcome::Reachable { .. }),
        "the dial must walk past the instant IPv4 refusals to the live IPv6 candidate, got {outcome:?}"
    );
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

// TS4-04: the DoH wave race must return at the first usable answer instead
// of draining the whole wave, while every completing provider still records
// its statistics from inside its own attempt future.

fn winner_outcome(index: usize, ttl: Duration) -> DohAttemptOutcome {
    (
        index,
        Duration::ZERO,
        Some((vec!["203.0.113.77".parse().unwrap()], ttl)),
    )
}

#[tokio::test]
async fn race_first_answer_returns_before_slow_losers_finish() {
    let losers = [0usize, 1].map(|i| async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        (i, Duration::ZERO, None)
    });
    let winner = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        winner_outcome(2, Duration::from_secs(300))
    };
    type Boxed = std::pin::Pin<Box<dyn std::future::Future<Output = DohAttemptOutcome> + Send>>;
    let attempts: Vec<Boxed> = losers
        .into_iter()
        .map(|f| Box::pin(f) as Boxed)
        .chain(std::iter::once(Box::pin(winner) as Boxed))
        .collect();
    let started = std::time::Instant::now();
    let answer = race_first_answer("", attempts).await;
    let elapsed = started.elapsed();

    assert_eq!(
        answer,
        Some((
            vec!["203.0.113.77".parse().unwrap()],
            Duration::from_secs(300)
        )),
        "the first non-empty answer must win the race"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "must not wait for the 5-second losers; took {elapsed:?}"
    );
}

#[tokio::test]
async fn losing_attempts_still_record_after_the_race_returns() {
    let recorded = std::sync::Arc::new(std::sync::Mutex::new(Vec::<usize>::new()));

    let make = |index: usize,
                delay: Duration,
                wins: bool,
                recorded: std::sync::Arc<std::sync::Mutex<Vec<usize>>>| {
        async move {
            tokio::time::sleep(delay).await;
            // Mimics note_doh_result's placement inside doh_provider_attempt.
            recorded.lock().expect("recorded lock").push(index);
            if wins {
                winner_outcome(index, Duration::from_secs(300))
            } else {
                (index, Duration::ZERO, None)
            }
        }
    };

    let attempts = vec![
        make(
            0,
            Duration::from_millis(100),
            true,
            std::sync::Arc::clone(&recorded),
        ),
        make(
            1,
            Duration::from_millis(400),
            false,
            std::sync::Arc::clone(&recorded),
        ),
        make(
            2,
            Duration::from_millis(400),
            false,
            std::sync::Arc::clone(&recorded),
        ),
    ];

    let answer = race_first_answer("", attempts).await;
    assert!(
        answer.is_some(),
        "the winner's answer must be returned by the race"
    );

    // The losers are detached after the win; give their side effects a hard
    // deadline so a regression fails instead of hanging forever.
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while *recorded.lock().expect("recorded lock") != vec![0, 1, 2] {
        assert!(
            std::time::Instant::now() < deadline,
            "detached losers must still record their statistics after the race returns"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test]
async fn race_is_not_delayed_by_a_loser_queued_on_a_permit() {
    let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(1));

    let holder_slots = std::sync::Arc::clone(&slots);
    let holder = async move {
        let _permit = holder_slots.acquire_owned().await.ok();
        tokio::time::sleep(Duration::from_secs(10)).await;
        (0usize, Duration::ZERO, None)
    };
    let queued_slots = std::sync::Arc::clone(&slots);
    let queued = async move {
        let _permit = queued_slots.acquire_owned().await.ok();
        (1usize, Duration::ZERO, None)
    };
    let winner = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        winner_outcome(2, Duration::from_secs(300))
    };
    let attempts: Vec<
        std::pin::Pin<Box<dyn std::future::Future<Output = DohAttemptOutcome> + Send>>,
    > = vec![Box::pin(holder), Box::pin(queued), Box::pin(winner)];

    let started = std::time::Instant::now();
    let answer = race_first_answer("", attempts).await;
    let elapsed = started.elapsed();

    assert_eq!(
        answer,
        Some((
            vec!["203.0.113.77".parse().unwrap()],
            Duration::from_secs(300)
        )),
        "the permit-free winner must answer"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "a loser queued on the only permit must not delay the race; took {elapsed:?}"
    );
}

#[tokio::test]
async fn race_doh_wave_with_no_valid_pool_indices_is_none() {
    let started = std::time::Instant::now();
    let answer = race_doh_wave(&[usize::MAX], "wave-empty.test.invalid").await;
    let elapsed = started.elapsed();

    assert_eq!(answer, None, "no pool index means no attempt and no answer");
    assert!(
        elapsed < Duration::from_secs(2),
        "filtering everything out must return promptly; took {elapsed:?}"
    );
}

#[test]
fn save_preserves_an_unexpired_disk_fallback_entry() {
    let host = "save-keeps-disk.test.invalid";
    let ip: IpAddr = "203.0.113.70".parse().unwrap();
    let stamp = now_unix() - 3600;
    {
        let mut store = disk_fallback_store().lock().unwrap();
        store.insert(
            host.to_owned(),
            PersistedAnswer {
                addrs: vec![ip],
                resolved_at_unix: stamp,
            },
        );
    }
    let dir = std::env::temp_dir().join(format!("save-keeps-disk-{}-{}", host, now_unix()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("dns-cache.txt");
    save_persisted_dns_cache(&path).expect("save must succeed");
    let file_text = std::fs::read_to_string(&path).unwrap();
    assert!(
        file_text.contains(&stamp.to_string()),
        "saved file must carry the ORIGINAL stamp, got: {file_text}"
    );

    // Simulate the next cold start: wipe this test's own key (not the
    // whole store -- it's process-wide and shared by other tests running
    // concurrently, so a blanket `clear()` here would race their inserts),
    // then reload.
    disk_fallback_store().lock().unwrap().remove(host);
    forget_dns_answer(host);
    load_persisted_dns_cache(&path);

    assert_eq!(disk_fallback_answer(host), Some(vec![ip]));
    let reloaded_stamp = {
        let store = disk_fallback_store().lock().unwrap();
        let entry = store.get(host).expect("host must survive save/wipe/load");
        entry.resolved_at_unix
    };
    assert_eq!(
        reloaded_stamp, stamp,
        "save must not refresh the persisted stamp"
    );

    let _ = std::fs::remove_dir_all(&dir);
    disk_fallback_store().lock().unwrap().remove(host);
}

#[test]
fn save_drops_a_genuinely_expired_disk_fallback_entry() {
    let host = "save-drops-expired.test.invalid";
    let ip: IpAddr = "203.0.113.71".parse().unwrap();
    {
        let mut store = disk_fallback_store().lock().unwrap();
        store.insert(
            host.to_owned(),
            PersistedAnswer {
                addrs: vec![ip],
                resolved_at_unix: now_unix() - DNS_STALE_FALLBACK_WINDOW.as_secs() - 1,
            },
        );
    }
    let dir = std::env::temp_dir().join(format!("save-drops-expired-{}-{}", host, now_unix()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("dns-cache.txt");
    save_persisted_dns_cache(&path).expect("save must succeed");
    let file_text = std::fs::read_to_string(&path).unwrap();
    assert!(
        !file_text.contains(host),
        "expired entry must not be written, got: {file_text}"
    );

    // Wipe only this test's own key: the store is process-wide and shared
    // by other tests running concurrently, so a blanket `clear()` here
    // would race their inserts.
    disk_fallback_store().lock().unwrap().remove(host);
    load_persisted_dns_cache(&path);

    assert_eq!(disk_fallback_answer(host), None);
    assert!(!disk_fallback_store().lock().unwrap().contains_key(host));

    let _ = std::fs::remove_dir_all(&dir);
    disk_fallback_store().lock().unwrap().remove(host);
}

#[test]
fn save_prefers_the_live_answer_for_a_host() {
    let host = "save-live-wins.test.invalid";
    let live_ip: IpAddr = "203.0.113.72".parse().unwrap();
    let disk_ip: IpAddr = "203.0.113.73".parse().unwrap();
    remember_doh_answer(host, &[live_ip], Duration::from_secs(300));
    {
        let mut store = disk_fallback_store().lock().unwrap();
        store.insert(
            host.to_owned(),
            PersistedAnswer {
                addrs: vec![disk_ip],
                resolved_at_unix: now_unix() - 3600,
            },
        );
    }
    let dir = std::env::temp_dir().join(format!("save-live-wins-{}-{}", host, now_unix()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("dns-cache.txt");
    save_persisted_dns_cache(&path).expect("save must succeed");
    let file_text = std::fs::read_to_string(&path).unwrap();
    assert!(
        file_text.contains(&live_ip.to_string()),
        "live answer must be written, got: {file_text}"
    );
    assert!(
        !file_text.contains(&disk_ip.to_string()),
        "persisted answer must be superseded, got: {file_text}"
    );

    forget_dns_answer(host);
    // Wipe only this test's own key: the store is process-wide and shared
    // by other tests running concurrently, so a blanket `clear()` here
    // would race their inserts.
    disk_fallback_store().lock().unwrap().remove(host);
    load_persisted_dns_cache(&path);

    assert_eq!(disk_fallback_answer(host), Some(vec![live_ip]));

    let _ = std::fs::remove_dir_all(&dir);
    disk_fallback_store().lock().unwrap().remove(host);
}

#[test]
fn save_keeps_the_fallback_when_the_live_cache_only_remembers_a_failure() {
    let host = "save-failure-keeps-disk.test.invalid";
    let ip: IpAddr = "203.0.113.74".parse().unwrap();
    remember_doh_failure(host);
    {
        let mut store = disk_fallback_store().lock().unwrap();
        store.insert(
            host.to_owned(),
            PersistedAnswer {
                addrs: vec![ip],
                resolved_at_unix: now_unix() - 3600,
            },
        );
    }
    let dir = std::env::temp_dir().join(format!("save-failure-keeps-disk-{}-{}", host, now_unix()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("dns-cache.txt");
    save_persisted_dns_cache(&path).expect("save must succeed");
    let file_text = std::fs::read_to_string(&path).unwrap();
    assert!(
        file_text.contains(&ip.to_string()),
        "a remembered failure must not displace the persisted fallback, got: {file_text}"
    );

    forget_dns_answer(host);
    // Wipe only this test's own key: the store is process-wide and shared
    // by other tests running concurrently, so a blanket `clear()` here
    // would race their inserts.
    disk_fallback_store().lock().unwrap().remove(host);
    load_persisted_dns_cache(&path);

    assert_eq!(disk_fallback_answer(host), Some(vec![ip]));

    let _ = std::fs::remove_dir_all(&dir);
    disk_fallback_store().lock().unwrap().remove(host);
}

#[test]
fn parse_dns_hint_line_rejects_future_timestamps() {
    let host = "hint-future.test.invalid";
    let ip: IpAddr = "203.0.113.75".parse().unwrap();
    let make_line = |stamp: u64| {
        format_dns_hint_line(&DnsHint {
            host: host.to_owned(),
            addrs: vec![ip],
            resolved_at_unix: stamp,
        })
    };
    assert!(parse_dns_hint_line(&make_line(now_unix() + 10 * 24 * 60 * 60)).is_none());
    assert!(parse_dns_hint_line(&make_line(u64::MAX)).is_none());
    // Ordinary clock skew is not an attack: still accepted.
    assert_eq!(
        parse_dns_hint_line(&make_line(now_unix() + 30))
            .expect("modest skew must be accepted")
            .addrs,
        vec![ip]
    );
    assert_eq!(
        parse_dns_hint_line(&make_line(now_unix()))
            .expect("an honest stamp must be accepted")
            .addrs,
        vec![ip]
    );
}

#[test]
fn parse_persisted_line_rejects_future_timestamps() {
    let host = "persisted-future.test.invalid";
    let ip: IpAddr = "203.0.113.76".parse().unwrap();
    let make_line = |stamp: u64| {
        format_persisted_line(
            host,
            &PersistedAnswer {
                addrs: vec![ip],
                resolved_at_unix: stamp,
            },
        )
    };
    assert!(parse_persisted_line(&make_line(now_unix() + 10 * 24 * 60 * 60)).is_none());
    assert!(parse_persisted_line(&make_line(u64::MAX)).is_none());
    let modest = parse_persisted_line(&make_line(now_unix() + 30)).expect("skew accepted");
    assert_eq!(modest.1.addrs, vec![ip]);
    let honest = parse_persisted_line(&make_line(now_unix())).expect("honest stamp accepted");
    assert_eq!(honest.1.addrs, vec![ip]);
}

#[test]
fn load_rejects_future_stamps_and_expired_stamps_but_keeps_fresh_ones() {
    let fresh_host = "load-fresh.test.invalid";
    let expired_host = "load-expired.test.invalid";
    let future_host = "load-future.test.invalid";
    let ip_a: IpAddr = "203.0.113.77".parse().unwrap();
    let ip_b: IpAddr = "203.0.113.78".parse().unwrap();
    let ip_c: IpAddr = "203.0.113.79".parse().unwrap();
    let now = now_unix();
    let lines = [
        format_persisted_line(
            fresh_host,
            &PersistedAnswer {
                addrs: vec![ip_a],
                resolved_at_unix: now - 60,
            },
        ),
        format_persisted_line(
            expired_host,
            &PersistedAnswer {
                addrs: vec![ip_b],
                resolved_at_unix: now - DNS_STALE_FALLBACK_WINDOW.as_secs() - 1,
            },
        ),
        format_persisted_line(
            future_host,
            &PersistedAnswer {
                addrs: vec![ip_c],
                resolved_at_unix: now + 10 * 24 * 60 * 60,
            },
        ),
    ];
    let dir = std::env::temp_dir().join(format!("load-stamps-{}-{now}", fresh_host));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("dns-cache.txt");
    std::fs::write(&path, lines.join("\n")).unwrap();

    load_persisted_dns_cache(&path);

    assert_eq!(disk_fallback_answer(fresh_host), Some(vec![ip_a]));
    // `expired_host` parsed fine (its stamp is not in the future) and is
    // loaded into the raw store same as ever; age-based filtering has
    // always happened at READ time via `disk_fallback_answer`, not at
    // load time -- this is unrelated to the future-timestamp guard below
    // and unchanged by it.
    assert_eq!(disk_fallback_answer(expired_host), None);
    // `future_host`'s stamp is rejected by `parse_persisted_line` itself
    // (TS4-06), so it never even enters the raw store.
    assert!(!disk_fallback_store()
        .lock()
        .unwrap()
        .contains_key(future_host));

    // A correctly-stamped hint for the formerly-forged host still applies.
    seed_disk_fallback(&[DnsHint {
        host: future_host.to_owned(),
        addrs: vec![ip_c],
        resolved_at_unix: now_unix(),
    }]);
    assert_eq!(disk_fallback_answer(future_host), Some(vec![ip_c]));

    let _ = std::fs::remove_dir_all(&dir);
    {
        let mut store = disk_fallback_store().lock().unwrap();
        store.remove(fresh_host);
        store.remove(expired_host);
        store.remove(future_host);
    }
}
