use super::bridge_for;
use crate::*;
use crate::{dns::*, probe::*};
use bridge_line::BridgeLine;
use std::str::FromStr;
use tokio::net::TcpListener;

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
