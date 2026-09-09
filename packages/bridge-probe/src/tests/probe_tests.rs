use super::bridge_for;
use crate::*;
use crate::{dns::*, probe::*};
use bridge_line::BridgeLine;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

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

type BoxedAttempt = std::pin::Pin<Box<dyn std::future::Future<Output = DohAttemptOutcome> + Send>>;
type BoxedFactory = Box<dyn FnOnce(CancellationToken) -> BoxedAttempt + Send>;

#[tokio::test]
async fn race_first_answer_returns_before_slow_losers_finish() {
    let losers: [BoxedFactory; 2] = [0usize, 1].map(|i| {
        Box::new(move |_admission: CancellationToken| {
            Box::pin(async move {
                tokio::time::sleep(Duration::from_secs(5)).await;
                (i, Duration::ZERO, None)
            }) as BoxedAttempt
        }) as BoxedFactory
    });
    let winner: BoxedFactory = Box::new(|_admission: CancellationToken| {
        Box::pin(async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            winner_outcome(2, Duration::from_secs(300))
        }) as BoxedAttempt
    });
    let attempts = losers.into_iter().chain(std::iter::once(winner));
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
        move |_admission: CancellationToken| async move {
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
    let holder: BoxedFactory = Box::new(move |_admission: CancellationToken| {
        Box::pin(async move {
            let _permit = holder_slots.acquire_owned().await.ok();
            tokio::time::sleep(Duration::from_secs(10)).await;
            (0usize, Duration::ZERO, None)
        }) as BoxedAttempt
    });
    let queued_slots = std::sync::Arc::clone(&slots);
    let queued: BoxedFactory = Box::new(move |_admission: CancellationToken| {
        Box::pin(async move {
            let _permit = queued_slots.acquire_owned().await.ok();
            (1usize, Duration::ZERO, None)
        }) as BoxedAttempt
    });
    let winner: BoxedFactory = Box::new(|_admission: CancellationToken| {
        Box::pin(async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            winner_outcome(2, Duration::from_secs(300))
        }) as BoxedAttempt
    });
    let attempts = [holder, queued, winner];

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

// TS5-02: the race owns an admission token. An attempt still queued on a
// semaphore permit when the owner stops waiting must never start its lookup,
// while an attempt that already holds its permit must still finish and record.
//
// These mocks mirror `doh_provider_attempt`'s admission contract: wait for the
// permit racing the token, and only once the permit is held do real work.

#[tokio::test]
async fn stopping_the_race_never_starts_a_queued_attempt() {
    let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
    // Hold the only permit: the attempt stays queued until we release it.
    let held = slots.clone().acquire_owned().await.unwrap();

    let started = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let attempt_slots = std::sync::Arc::clone(&slots);
    let started_flag = std::sync::Arc::clone(&started);
    let attempts = [move |admission: CancellationToken| {
        let attempt_slots = std::sync::Arc::clone(&attempt_slots);
        let started_flag = std::sync::Arc::clone(&started_flag);
        async move {
            let _permit = tokio::select! {
                biased;
                _ = admission.cancelled() => return (0usize, Duration::ZERO, None),
                p = attempt_slots.acquire_owned() => p.expect("semaphore is not closed"),
            };
            // First step after the permit: prove the lookup really started.
            started_flag.store(true, std::sync::atomic::Ordering::SeqCst);
            (0usize, Duration::ZERO, None)
        }
    }];

    // The owner gives up while the permit is still held: the outer timeout
    // drops the race future, which must cancel the queued attempt.
    let raced =
        tokio::time::timeout(Duration::from_millis(100), race_first_answer("", attempts)).await;
    assert!(
        raced.is_err(),
        "the race must still be queued on the permit when the owner gives up"
    );

    // Only NOW release the permit. A cancelled attempt must not wake up,
    // acquire it, and start a lookup nobody will consume.
    drop(held);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !started.load(std::sync::atomic::Ordering::SeqCst),
        "an attempt queued on a permit must not start its lookup after the race's owner stopped waiting"
    );
}

#[tokio::test]
async fn a_started_attempt_still_finishes_after_the_race_is_cancelled() {
    let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
    let recorded = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    let attempt_slots = std::sync::Arc::clone(&slots);
    let recorded_flag = std::sync::Arc::clone(&recorded);
    let attempts = [move |admission: CancellationToken| {
        let attempt_slots = std::sync::Arc::clone(&attempt_slots);
        let recorded_flag = std::sync::Arc::clone(&recorded_flag);
        async move {
            let _permit = tokio::select! {
                biased;
                _ = admission.cancelled() => return (0usize, Duration::ZERO, None),
                p = attempt_slots.acquire_owned() => p.expect("semaphore is not closed"),
            };
            // Started: the owner cancelling must not stop this attempt from
            // finishing and recording (mirrors doh_provider_attempt, whose
            // bounded lookup and note_doh_result stay untouched).
            tokio::time::sleep(Duration::from_millis(150)).await;
            recorded_flag.store(true, std::sync::atomic::Ordering::SeqCst);
            (0usize, Duration::ZERO, None)
        }
    }];

    let raced = tokio::spawn(race_first_answer("", attempts));
    // Let the attempt acquire the free permit, then cancel the race mid-flight.
    tokio::time::sleep(Duration::from_millis(50)).await;
    raced.abort();

    // The started attempt must still complete its work on its own schedule.
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while !recorded.load(std::sync::atomic::Ordering::SeqCst) {
        assert!(
            std::time::Instant::now() < deadline,
            "a started attempt must finish and record even after the race's owner was cancelled"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
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

// TS6-05: concurrent resolutions of one still-uncached hostname must
// coalesce into ONE DoH wave search. The `race_first_answer` mocks above stop
// at the race boundary; these tests need the seam ABOVE the wave loop, so
// `install_fake_doh_wave_search` stands in for the whole provider wave set
// and counts how many wave sets the production lookup launches -- with zero
// network access. The seam is process-wide and cargo runs tests in parallel
// threads, so every fake-using test holds FAKE_WAVE_LOCK for its whole body.

static FAKE_WAVE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A wave-search stand-in that counts how often it is started, optionally
/// flags that start (for "the owner is now mid-lookup" coordination), waits
/// `delay`, and then answers with `ips` (`win`) or fails (`!win`).
fn counting_wave_fake(
    counter: std::sync::Arc<AtomicUsize>,
    ips: Vec<IpAddr>,
    started: Option<std::sync::Arc<AtomicBool>>,
    delay: Duration,
    win: bool,
) -> FakeDohWaveSearch {
    std::sync::Arc::new(move |_query: &str| {
        let counter = std::sync::Arc::clone(&counter);
        let ips = ips.clone();
        let started = started.clone();
        Box::pin(async move {
            counter.fetch_add(1, Ordering::SeqCst);
            if let Some(flag) = &started {
                flag.store(true, Ordering::SeqCst);
            }
            tokio::time::sleep(delay).await;
            win.then(|| (ips, Duration::from_secs(300)))
        })
            as std::pin::Pin<
                Box<dyn std::future::Future<Output = Option<(Vec<IpAddr>, Duration)>> + Send>,
            >
    })
}

#[tokio::test]
async fn concurrent_resolves_of_one_host_share_one_doh_wave_search() {
    let _serial = FAKE_WAVE_LOCK.lock().await;
    let host = "coalesce-one-wave.test.invalid";
    forget_dns_answer(host);

    let searches = std::sync::Arc::new(AtomicUsize::new(0));
    let answer_ips: Vec<IpAddr> = vec![
        "203.0.113.10".parse().unwrap(),
        "2001:db8::10".parse().unwrap(),
    ];
    install_fake_doh_wave_search(counting_wave_fake(
        std::sync::Arc::clone(&searches),
        answer_ips.clone(),
        None,
        Duration::from_millis(100),
        true,
    ));

    // Both callers join BEFORE any answer exists: the fake's delay keeps the
    // shared lookup in flight while the second caller reaches the registry.
    let (first, second) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            resolve_addrs(host, 443, ResolverPolicy::default()),
            resolve_addrs(host, 8443, ResolverPolicy::default())
        )
    })
    .await
    .expect("both coalesced callers finish");

    assert_eq!(
        searches.load(Ordering::SeqCst),
        1,
        "two concurrent resolves of one host must run ONE wave search, not two"
    );
    assert_eq!(
        first.expect("first caller resolves"),
        order_candidates(&answer_ips, 443)
    );
    assert_eq!(
        second.expect("second caller resolves"),
        order_candidates(&answer_ips, 8443)
    );

    clear_fake_doh_wave_search();
    forget_dns_answer(host);
}

#[tokio::test]
async fn coalesced_waiters_each_apply_their_own_port() {
    let _serial = FAKE_WAVE_LOCK.lock().await;
    let host = "coalesce-ports.test.invalid";
    forget_dns_answer(host);

    let searches = std::sync::Arc::new(AtomicUsize::new(0));
    let answer_ips: Vec<IpAddr> = vec![
        "203.0.113.21".parse().unwrap(),
        "2001:db8::21".parse().unwrap(),
    ];
    install_fake_doh_wave_search(counting_wave_fake(
        std::sync::Arc::clone(&searches),
        answer_ips.clone(),
        None,
        Duration::from_millis(100),
        true,
    ));

    let results = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            resolve_addrs(host, 443, ResolverPolicy::default()),
            resolve_addrs(host, 8443, ResolverPolicy::default()),
            resolve_addrs(host, 9050, ResolverPolicy::default())
        )
    })
    .await
    .expect("all three coalesced callers finish");

    assert_eq!(searches.load(Ordering::SeqCst), 1, "one shared wave search");
    for (result, port) in [(results.0, 443), (results.1, 8443), (results.2, 9050)] {
        assert_eq!(
            result.expect("caller resolves"),
            order_candidates(&answer_ips, port),
            "each caller must get the shared IPs at its OWN port"
        );
    }

    clear_fake_doh_wave_search();
    forget_dns_answer(host);
}

#[tokio::test]
async fn cancelling_the_lookup_owner_does_not_abandon_its_waiter() {
    let _serial = FAKE_WAVE_LOCK.lock().await;
    let host = "coalesce-cancel.test.invalid";
    forget_dns_answer(host);

    let searches = std::sync::Arc::new(AtomicUsize::new(0));
    let owner_started = std::sync::Arc::new(AtomicBool::new(false));
    let answer_ips: Vec<IpAddr> = vec!["203.0.113.22".parse().unwrap()];
    install_fake_doh_wave_search(counting_wave_fake(
        std::sync::Arc::clone(&searches),
        answer_ips.clone(),
        Some(std::sync::Arc::clone(&owner_started)),
        Duration::from_millis(300),
        true,
    ));

    let owner = tokio::spawn(resolve_addrs(host, 443, ResolverPolicy::default()));
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !owner_started.load(Ordering::SeqCst) {
        assert!(
            std::time::Instant::now() < deadline,
            "the owner must reach the fake wave search"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // The waiter parks on the shared cell while the owner is mid-lookup.
    let waiter = tokio::spawn(resolve_addrs(host, 8443, ResolverPolicy::default()));
    tokio::time::sleep(Duration::from_millis(50)).await;
    owner.abort();

    // tokio::sync::OnceCell::get_or_init is cancel-safe: dropping the owner's
    // init future hands the initialization to the parked waiter instead of
    // stranding it, so the surviving caller still gets its resolution.
    let addrs = tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .expect("the surviving waiter must still finish")
        .expect("waiter task joins")
        .expect("waiter gets the resolution");
    assert_eq!(addrs, order_candidates(&answer_ips, 8443));
    assert!(
        searches.load(Ordering::SeqCst) >= 1,
        "the lookup ran under whichever caller owned it"
    );

    clear_fake_doh_wave_search();
    forget_dns_answer(host);
}

#[tokio::test]
async fn a_finished_failed_coalesced_lookup_can_be_retried() {
    let _serial = FAKE_WAVE_LOCK.lock().await;
    let host = "coalesce-retry.test.invalid";
    forget_dns_answer(host);

    let searches = std::sync::Arc::new(AtomicUsize::new(0));
    install_fake_doh_wave_search(counting_wave_fake(
        std::sync::Arc::clone(&searches),
        Vec::new(),
        None,
        Duration::ZERO,
        false,
    ));

    let first = coalesced_doh_lookup(host).await;
    assert!(first.is_err(), "all providers failing must surface as Err");
    assert_eq!(searches.load(Ordering::SeqCst), 1);

    // The first lookup finished and its cell is gone (only a Weak remains in
    // the registry), so the failure must NOT stick: a later caller starts a
    // fresh search instead of replaying the finished one.
    let second = coalesced_doh_lookup(host).await;
    assert!(second.is_err());
    assert_eq!(
        searches.load(Ordering::SeqCst),
        2,
        "a finished failed lookup must not stick in the registry"
    );

    clear_fake_doh_wave_search();
    forget_dns_answer(host);
}

#[test]
fn webtunnel_identity_from_url() {
    let bridge: BridgeLine = "webtunnel 9.9.9.9:443 1111111111111111111111111111111111111111 \
         url=https://e.com/x ver=0.0.3"
        .parse()
        .unwrap();
    assert_eq!(
        webtunnel_endpoint_identity(&bridge),
        Some(("e.com".to_string(), 443, "/x".to_string()))
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
