use crate::*;
// TS9-01: the pre-publish pause seam lives in its own test-only module.
use crate::dns_publish_pause::*;
use crate::{dns::*, probe::*};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

// TS6-05: concurrent resolutions of one still-uncached hostname must
// coalesce into ONE DoH wave search. The `race_first_answer` mocks in
// probe_race_tests stop at the race boundary; these tests need the seam
// ABOVE the wave loop, so `install_fake_doh_wave_search` stands in for the
// whole provider wave set and counts how many wave sets the production
// lookup launches -- with zero network access. The seam is process-wide and
// cargo runs tests in parallel threads, so every fake-using test holds
// FAKE_WAVE_LOCK for its whole body.

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

// TS7-05: a dead `Weak` entry does not leave the registry on its own --
// only an explicit removal does. The lazy sweep at insertion time must
// bound the map: sequential lookups of DISTINCT hosts (each fully finished
// before the next starts, so no concurrency at all) used to leave one
// permanently dead entry behind per lookup, growing the registry linearly
// with every hostname ever resolved. FAKE_WAVE_LOCK makes every
// registry-writing test mutually exclusive, so the observed length is
// deterministic: each distinct-host insertion sweeps the previous lookup's
// dead entry, and nothing sweeps the LAST one -- hence at most 1 entry.
#[tokio::test]
async fn sequential_distinct_host_lookups_do_not_grow_the_inflight_registry() {
    let _serial = FAKE_WAVE_LOCK.lock().await;

    const DISTINCT_HOSTS: usize = 20;
    let searches = std::sync::Arc::new(AtomicUsize::new(0));
    install_fake_doh_wave_search(counting_wave_fake(
        std::sync::Arc::clone(&searches),
        Vec::new(),
        None,
        Duration::ZERO,
        false,
    ));

    for i in 0..DISTINCT_HOSTS {
        let host = format!("registry-sweep-{i}.test.invalid");
        assert!(
            coalesced_doh_lookup(&host).await.is_err(),
            "the fake fails on purpose; only the registry mechanics are under test"
        );
    }

    assert_eq!(
        searches.load(Ordering::SeqCst),
        DISTINCT_HOSTS,
        "every distinct host must have run its own (failing) wave search"
    );
    let len = inflight_doh_registry_len();
    assert!(
        len <= 1,
        "sequential distinct-host lookups must not grow the registry \
         linearly: {len} entries left after {DISTINCT_HOSTS} finished lookups"
    );

    clear_fake_doh_wave_search();
}

// TS7-05: the lazy sweep must never drop a STILL-INFLIGHT lookup of a
// different host. A live entry always has strong_count > 0 (every caller
// holds its Arc across get_or_init), so retain keeps it. If that broke, a
// caller joining a parked lookup after a sweep would silently start a
// SECOND wave search for the same host instead of sharing the first --
// exactly what the live-host search counter observes here.
#[tokio::test]
async fn sweeping_dead_entries_never_drops_a_still_inflight_lookup() {
    let _serial = FAKE_WAVE_LOCK.lock().await;
    let dead_host = "sweep-dead.test.invalid";
    let live_host = "sweep-live.test.invalid";
    forget_dns_answer(live_host);

    let live_searches = std::sync::Arc::new(AtomicUsize::new(0));
    let live_started = std::sync::Arc::new(AtomicBool::new(false));
    let gate = std::sync::Arc::new(tokio::sync::Notify::new());
    let answer_ips: Vec<IpAddr> = vec!["203.0.113.23".parse().unwrap()];
    install_fake_doh_wave_search({
        let live_searches = std::sync::Arc::clone(&live_searches);
        let live_started = std::sync::Arc::clone(&live_started);
        let gate = std::sync::Arc::clone(&gate);
        let ips = answer_ips.clone();
        std::sync::Arc::new(move |query: &str| {
            let live_searches = std::sync::Arc::clone(&live_searches);
            let live_started = std::sync::Arc::clone(&live_started);
            let gate = std::sync::Arc::clone(&gate);
            let ips = ips.clone();
            let query = query.to_owned();
            Box::pin(async move {
                if query == live_host {
                    live_searches.fetch_add(1, Ordering::SeqCst);
                    live_started.store(true, Ordering::SeqCst);
                    gate.notified().await;
                    return Some((ips, Duration::from_secs(300)));
                }
                None
            })
                as std::pin::Pin<
                    Box<dyn std::future::Future<Output = Option<(Vec<IpAddr>, Duration)>> + Send>,
                >
        })
    });

    // A finished (failed) lookup for another host leaves a dead entry behind.
    assert!(coalesced_doh_lookup(dead_host).await.is_err());

    // Start the live lookup and wait until its owner is parked inside the
    // fake: the registry entry is LIVE (strong_count > 0) at this point.
    let owner = tokio::spawn(coalesced_doh_lookup(live_host));
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !live_started.load(Ordering::SeqCst) {
        assert!(
            std::time::Instant::now() < deadline,
            "the owner must reach the fake wave search"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // A third, distinct hostname inserts a fresh entry -- and thereby runs
    // the sweep over the live entry and the dead one.
    assert!(coalesced_doh_lookup("sweep-trigger.test.invalid")
        .await
        .is_err());

    // A second caller must still JOIN the parked live lookup (its registry
    // entry must have survived the sweep), not start a second wave search.
    let joiner = tokio::spawn(coalesced_doh_lookup(live_host));
    tokio::time::sleep(Duration::from_millis(50)).await;
    gate.notify_one();

    let owner_result = tokio::time::timeout(Duration::from_secs(5), owner)
        .await
        .expect("owner finishes")
        .expect("owner task joins")
        .expect("owner lookup succeeds");
    let joiner_result = tokio::time::timeout(Duration::from_secs(5), joiner)
        .await
        .expect("joiner finishes")
        .expect("joiner task joins")
        .expect("joiner lookup succeeds");
    assert_eq!(
        owner_result, joiner_result,
        "both callers must share one lookup result"
    );
    assert_eq!(
        live_searches.load(Ordering::SeqCst),
        1,
        "the sweep must keep the in-flight lookup: the joiner must share its \
         wave search, not start a second one"
    );

    clear_fake_doh_wave_search();
    forget_dns_answer(live_host);
}

// TS7-06: a lookup parked in flight when `flush_dns_cache` runs must be
// invisible to the post-flush world: a caller arriving AFTER the flush must
// start its OWN wave search (the registry key carries the network
// generation), and the pre-flush owner must NOT republish its stale answer
// into the freshly-cleared cache. Without the generation key + publish gate,
// B would join A (one wave search) and A's old-network answer would
// overwrite B's new-network answer.
#[tokio::test]
async fn flush_separates_an_inflight_lookup_of_the_previous_network() {
    let _serial = FAKE_WAVE_LOCK.lock().await;
    // flush_dns_cache clears the SHARED live cache: serialize against the
    // dns_*_tests that snapshot it (see DNS_GLOBAL_STORE_LOCK in mod.rs).
    let _store_serial = super::DNS_GLOBAL_STORE_LOCK.lock().await;
    let host = "flush-inflight.test.invalid";
    forget_dns_answer(host);

    let searches = std::sync::Arc::new(AtomicUsize::new(0));
    let started = std::sync::Arc::new(AtomicBool::new(false));
    let gate = std::sync::Arc::new(tokio::sync::Notify::new());
    let ips_a: Vec<IpAddr> = vec!["203.0.113.30".parse().unwrap()];
    let ips_b: Vec<IpAddr> = vec!["203.0.113.31".parse().unwrap()];
    install_fake_doh_wave_search({
        let searches = std::sync::Arc::clone(&searches);
        let started = std::sync::Arc::clone(&started);
        let gate = std::sync::Arc::clone(&gate);
        let ips_a = ips_a.clone();
        let ips_b = ips_b.clone();
        std::sync::Arc::new(move |query: &str| {
            let searches = std::sync::Arc::clone(&searches);
            let started = std::sync::Arc::clone(&started);
            let gate = std::sync::Arc::clone(&gate);
            let ips_a = ips_a.clone();
            let ips_b = ips_b.clone();
            let query = query.to_owned();
            Box::pin(async move {
                assert_eq!(query, host);
                let call = searches.fetch_add(1, Ordering::SeqCst);
                if call == 0 {
                    started.store(true, Ordering::SeqCst);
                    gate.notified().await;
                    return Some((ips_a, Duration::from_secs(300)));
                }
                Some((ips_b, Duration::from_secs(300)))
            })
                as std::pin::Pin<
                    Box<dyn std::future::Future<Output = Option<(Vec<IpAddr>, Duration)>> + Send>,
                >
        })
    });

    // Lookup A starts and parks inside the fake (pre-flush generation).
    let owner_a = tokio::spawn(resolve_addrs(host, 443, ResolverPolicy::default()));
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !started.load(Ordering::SeqCst) {
        assert!(
            std::time::Instant::now() < deadline,
            "lookup A must reach the fake wave search"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // The network changes while A is parked.
    flush_dns_cache();

    // Lookup B, same host, post-flush generation: must NOT join A.
    let owner_b = tokio::spawn(resolve_addrs(host, 443, ResolverPolicy::default()));
    let b_result = tokio::time::timeout(Duration::from_secs(5), owner_b)
        .await
        .expect("B finishes")
        .expect("B task joins")
        .expect("B lookup succeeds");
    assert_eq!(
        searches.load(Ordering::SeqCst),
        2,
        "post-flush lookup B must start its OWN wave search, not join the \
         pre-flush lookup A"
    );
    assert_eq!(b_result, order_candidates(&ips_b, 443));
    // B's own answer (same generation as itself) may be cached.
    match cached_doh_answer(host) {
        Some(CacheHit::Addrs(got)) => {
            assert_eq!(got, ips_b, "B's own post-flush answer must be cached");
        }
        _ => panic!("B's own post-flush answer must be cached"),
    }

    // Release A: it completes with its pre-flush answer, but must NOT
    // republish it into the new generation's cache.
    gate.notify_one();
    let a_result = tokio::time::timeout(Duration::from_secs(5), owner_a)
        .await
        .expect("A finishes")
        .expect("A task joins")
        .expect("A lookup succeeds");
    assert_eq!(a_result, order_candidates(&ips_a, 443));
    assert_eq!(
        searches.load(Ordering::SeqCst),
        2,
        "A must not trigger any further wave searches"
    );
    match cached_doh_answer(host) {
        Some(CacheHit::Addrs(got)) => {
            assert_eq!(
                got, ips_b,
                "A must NOT republish its pre-flush answer \
                 over B's -- without the generation key + publish gate, B would \
                 have joined A and A's stale answer would overwrite B's"
            );
        }
        _ => panic!(
            "A must NOT republish its pre-flush answer over B's -- \
             without the generation key + publish gate, B would have joined A \
             and A's stale answer would overwrite B's"
        ),
    }

    clear_fake_doh_wave_search();
    forget_dns_answer(host);
}

// TS7-06 failure path: a lookup that fails entirely inside the pre-flush
// generation must not be remembered as a negative entry of the NEW
// generation -- a remembered failure would make `resolve_addrs` skip DoH
// entirely for DNS_NEGATIVE_TTL, even though the name may resolve fine
// after the network change.
#[tokio::test]
async fn flush_prevents_a_pre_flush_failure_from_poisoning_the_new_generation() {
    let _serial = FAKE_WAVE_LOCK.lock().await;
    // flush_dns_cache clears the SHARED live cache: serialize against the
    // dns_*_tests that snapshot it (see DNS_GLOBAL_STORE_LOCK in mod.rs).
    let _store_serial = super::DNS_GLOBAL_STORE_LOCK.lock().await;
    let host = "flush-failure.test.invalid";
    forget_dns_answer(host);

    let searches = std::sync::Arc::new(AtomicUsize::new(0));
    let started = std::sync::Arc::new(AtomicBool::new(false));
    let gate = std::sync::Arc::new(tokio::sync::Notify::new());
    install_fake_doh_wave_search({
        let searches = std::sync::Arc::clone(&searches);
        let started = std::sync::Arc::clone(&started);
        let gate = std::sync::Arc::clone(&gate);
        std::sync::Arc::new(move |query: &str| {
            let searches = std::sync::Arc::clone(&searches);
            let started = std::sync::Arc::clone(&started);
            let gate = std::sync::Arc::clone(&gate);
            let query = query.to_owned();
            Box::pin(async move {
                assert_eq!(query, host);
                searches.fetch_add(1, Ordering::SeqCst);
                started.store(true, Ordering::SeqCst);
                gate.notified().await;
                None
            })
                as std::pin::Pin<
                    Box<dyn std::future::Future<Output = Option<(Vec<IpAddr>, Duration)>> + Send>,
                >
        })
    });

    let owner = tokio::spawn(resolve_addrs(host, 443, ResolverPolicy::default()));
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !started.load(Ordering::SeqCst) {
        assert!(
            std::time::Instant::now() < deadline,
            "the lookup must reach the fake wave search"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // The network changes while the failing lookup is parked.
    flush_dns_cache();
    gate.notify_one();

    let result = tokio::time::timeout(Duration::from_secs(5), owner)
        .await
        .expect("lookup finishes")
        .expect("task joins");
    assert!(
        result.is_err(),
        "with the cache cleared and the fallback chain missing, the lookup must fail"
    );
    assert_eq!(searches.load(Ordering::SeqCst), 1);
    assert!(
        cached_doh_answer(host).is_none(),
        "the pre-flush failure must not be remembered as a negative entry of \
         the new generation"
    );

    clear_fake_doh_wave_search();
    forget_dns_answer(host);
}

// TS9-01: the pre-publish pause now lives INSIDE
// `store_cached_if_generation`, parked around the `doh_cache()` mutex
// acquisition itself (the old seam sat in the callers, BEFORE the gated
// write was even entered, so the generation check was never actually
// straddled). The gate is a std Condvar, so the publishing lookup runs on
// its OWN OS thread (with a private current-thread runtime) instead of a
// `tokio::spawn` on this test's worker. A flush lands while A is parked;
// after that, a FRESH record B is published into the new generation and
// must survive A's release: A's write must be vetoed entirely, not merely
// reordered, and in particular must not overwrite (or evict) B.
#[tokio::test]
async fn flush_landing_after_the_generation_check_still_blocks_the_write() {
    let _serial = FAKE_WAVE_LOCK.lock().await;
    // flush_dns_cache clears the SHARED live cache: serialize against the
    // dns_*_tests that snapshot it (see DNS_GLOBAL_STORE_LOCK in mod.rs).
    let _store_serial = super::DNS_GLOBAL_STORE_LOCK.lock().await;
    let host = "flush-after-check.test.invalid";
    forget_dns_answer(host);
    disarm_pre_publish_pause();

    let ips_a: Vec<IpAddr> = vec!["203.0.113.40".parse().unwrap()];
    install_fake_doh_wave_search({
        let ips_a = ips_a.clone();
        std::sync::Arc::new(move |_query: &str| {
            let ips_a = ips_a.clone();
            Box::pin(async move { Some((ips_a, Duration::from_secs(300))) })
                as std::pin::Pin<
                    Box<dyn std::future::Future<Output = Option<(Vec<IpAddr>, Duration)>> + Send>,
                >
        })
    });

    // Arm the in-function pause: the next generation-gated write parks
    // around its mutex acquisition.
    let gate = arm_pre_publish_pause();

    let (result_tx, result_rx) = std::sync::mpsc::channel();
    let host_owned = host.to_owned();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("publisher runtime builds");
        let result = runtime.block_on(resolve_addrs(&host_owned, 443, ResolverPolicy::default()));
        let _ = result_tx.send(result);
    });

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !pre_publish_pause_parked() {
        assert!(
            std::time::Instant::now() < deadline,
            "A must reach the in-function pre-publish pause"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // The network changes while A holds the publication window open.
    flush_dns_cache();

    // A fresh answer B is published into the NEW generation before A
    // resumes: the assertion below proves A's vetoed write neither
    // overwrites nor removes it.
    let ips_b: Vec<IpAddr> = vec!["203.0.113.99".parse().unwrap()];
    remember_doh_answer(host, &ips_b, Duration::from_secs(300));

    // Release A: its write must be vetoed by the now-changed generation.
    gate.release();
    let a_result = result_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("A finishes")
        .expect("A lookup succeeds");
    assert_eq!(a_result, order_candidates(&ips_a, 443));

    match cached_doh_answer(host) {
        Some(CacheHit::Addrs(served)) => assert_eq!(
            served, ips_b,
            "A's pre-flush answer must stay vetoed (TS8-01): a flush landing              inside the parked window must still block the write, and the              fresh post-flush record B must survive untouched"
        ),
        _ => panic!("the fresh post-flush record B must remain in the cache"),
    }

    disarm_pre_publish_pause();
    clear_fake_doh_wave_search();
    forget_dns_answer(host);
}

// TS9-01 negative-path counterpart: `remember_doh_failure_if_generation`
// funnels through the SAME gated write, so the same in-function park must
// block a stale failure from poisoning the new generation -- and the fresh
// positive record B published after the flush must not be overwritten by
// A's negative entry.
#[tokio::test]
async fn flush_landing_after_the_generation_check_still_blocks_the_failure_write() {
    let _serial = FAKE_WAVE_LOCK.lock().await;
    // flush_dns_cache clears the SHARED live cache: serialize against the
    // dns_*_tests that snapshot it (see DNS_GLOBAL_STORE_LOCK in mod.rs).
    let _store_serial = super::DNS_GLOBAL_STORE_LOCK.lock().await;
    let host = "flush-after-check-fail.test.invalid";
    forget_dns_answer(host);
    disarm_pre_publish_pause();

    install_fake_doh_wave_search(std::sync::Arc::new(move |_query: &str| {
        Box::pin(async move { None })
            as std::pin::Pin<
                Box<dyn std::future::Future<Output = Option<(Vec<IpAddr>, Duration)>> + Send>,
            >
    }));

    let gate = arm_pre_publish_pause();

    let (result_tx, result_rx) = std::sync::mpsc::channel();
    let host_owned = host.to_owned();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("publisher runtime builds");
        let result = runtime.block_on(resolve_addrs(&host_owned, 443, ResolverPolicy::default()));
        let _ = result_tx.send(result);
    });

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !pre_publish_pause_parked() {
        assert!(
            std::time::Instant::now() < deadline,
            "A must reach the in-function pre-publish pause"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    flush_dns_cache();

    let ips_b: Vec<IpAddr> = vec!["203.0.113.98".parse().unwrap()];
    remember_doh_answer(host, &ips_b, Duration::from_secs(300));

    gate.release();
    let a_result = result_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("A finishes");
    assert!(
        a_result.is_err(),
        "with the cache cleared and no fallback, the lookup must fail"
    );

    match cached_doh_answer(host) {
        Some(CacheHit::Addrs(served)) => assert_eq!(
            served, ips_b,
            "A's stale failure must stay vetoed (TS8-01): the negative write              must not replace the fresh post-flush record B"
        ),
        _ => panic!(
            "the fresh post-flush record B must remain servable -- A's              failure write must not have replaced or masked it"
        ),
    }

    disarm_pre_publish_pause();
    clear_fake_doh_wave_search();
    forget_dns_answer(host);
}

// TS8-04: a lookup whose owner finished must remove its OWN registry entry
// pointwise, right after the result is published -- not leave a dead `Weak`
// for the next insertion's registry-wide sweep to trip over. After a burst
// of finished lookups the registry must be back to EMPTY, which also means
// the sweep no longer needs to run on the insertion path at all.
#[tokio::test]
async fn a_finished_lookup_removes_its_own_registry_entry_pointwise() {
    let _serial = FAKE_WAVE_LOCK.lock().await;
    let host = "ts804-point-remove.test.invalid";
    forget_dns_answer(host);

    let searches = std::sync::Arc::new(AtomicUsize::new(0));
    install_fake_doh_wave_search(counting_wave_fake(
        std::sync::Arc::clone(&searches),
        Vec::new(),
        None,
        Duration::ZERO,
        false,
    ));

    assert!(coalesced_doh_lookup(host).await.is_err());

    assert_eq!(
        inflight_doh_registry_len(),
        0,
        "a finished lookup must delete its own entry by key; no dead Weak may \
         linger in the registry"
    );

    clear_fake_doh_wave_search();
    forget_dns_answer(host);
}

// TS8-04: a lookup abandoned by its owner (cancelled probe, outer timeout)
// leaves a dead `Weak` behind. Later callers must NOT join that dead cell --
// a fresh wave search must run -- and once that fresh lookup finishes, its
// pointwise removal must bring the registry back to empty, so cancelled
// entries cannot accumulate without bound.
#[tokio::test]
async fn an_abandoned_lookup_does_not_stick_in_the_registry() {
    let _serial = FAKE_WAVE_LOCK.lock().await;
    let host = "ts804-abandoned.test.invalid";
    forget_dns_answer(host);

    let searches = std::sync::Arc::new(AtomicUsize::new(0));
    let owner_started = std::sync::Arc::new(AtomicBool::new(false));
    let gate = std::sync::Arc::new(tokio::sync::Notify::new());
    let answer_ips: Vec<IpAddr> = vec!["203.0.113.31".parse().unwrap()];
    install_fake_doh_wave_search({
        let searches = std::sync::Arc::clone(&searches);
        let owner_started = std::sync::Arc::clone(&owner_started);
        let gate = std::sync::Arc::clone(&gate);
        let ips = answer_ips.clone();
        std::sync::Arc::new(move |_query: &str| {
            let searches = std::sync::Arc::clone(&searches);
            let owner_started = std::sync::Arc::clone(&owner_started);
            let gate = std::sync::Arc::clone(&gate);
            let ips = ips.clone();
            Box::pin(async move {
                searches.fetch_add(1, Ordering::SeqCst);
                owner_started.store(true, Ordering::SeqCst);
                // First (owner) call parks forever; nobody else reaches the
                // gate, so the fresh second search below runs to completion.
                if searches.load(Ordering::SeqCst) == 1 {
                    gate.notified().await;
                }
                Some((ips, Duration::from_secs(300)))
            })
                as std::pin::Pin<
                    Box<dyn std::future::Future<Output = Option<(Vec<IpAddr>, Duration)>> + Send>,
                >
        })
    });

    let owner = tokio::spawn(coalesced_doh_lookup(host));
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !owner_started.load(Ordering::SeqCst) {
        assert!(
            std::time::Instant::now() < deadline,
            "the owner must reach the fake wave search"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    owner.abort();
    // Dropping the aborted owner's future drops its Arc, so the registry now
    // holds a dead Weak for this key.
    tokio::time::sleep(Duration::from_millis(20)).await;

    let retry = coalesced_doh_lookup(host).await;
    let ips = retry.expect("a fresh lookup after abandonment must run and win");
    assert_eq!(
        searches.load(Ordering::SeqCst),
        2,
        "a caller after an abandoned lookup must start a FRESH wave search, \
         not join the dead cell"
    );
    assert_eq!(ips, (answer_ips.clone(), Duration::from_secs(300)));
    assert_eq!(
        inflight_doh_registry_len(),
        0,
        "the fresh lookup's pointwise removal must leave the registry empty"
    );

    clear_fake_doh_wave_search();
    forget_dns_answer(host);
}

// TS8-04: the pointwise removal must never fire while other callers still
// hold the cell waiting for the result. The entry stays in the registry for
// the whole in-flight window (so late joiners coalesce), and disappears only
// after the value is published to every waiter.
#[tokio::test]
async fn the_registry_entry_survives_while_waiters_hold_the_cell() {
    let _serial = FAKE_WAVE_LOCK.lock().await;
    let host = "ts804-inflight-entry.test.invalid";
    forget_dns_answer(host);

    let searches = std::sync::Arc::new(AtomicUsize::new(0));
    let owner_started = std::sync::Arc::new(AtomicBool::new(false));
    let gate = std::sync::Arc::new(tokio::sync::Notify::new());
    let answer_ips: Vec<IpAddr> = vec!["203.0.113.32".parse().unwrap()];
    install_fake_doh_wave_search({
        let searches = std::sync::Arc::clone(&searches);
        let owner_started = std::sync::Arc::clone(&owner_started);
        let gate = std::sync::Arc::clone(&gate);
        let ips = answer_ips.clone();
        std::sync::Arc::new(move |_query: &str| {
            let searches = std::sync::Arc::clone(&searches);
            let owner_started = std::sync::Arc::clone(&owner_started);
            let gate = std::sync::Arc::clone(&gate);
            let ips = ips.clone();
            Box::pin(async move {
                searches.fetch_add(1, Ordering::SeqCst);
                owner_started.store(true, Ordering::SeqCst);
                gate.notified().await;
                Some((ips, Duration::from_secs(300)))
            })
                as std::pin::Pin<
                    Box<dyn std::future::Future<Output = Option<(Vec<IpAddr>, Duration)>> + Send>,
                >
        })
    });

    let owner = tokio::spawn(coalesced_doh_lookup(host));
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !owner_started.load(Ordering::SeqCst) {
        assert!(
            std::time::Instant::now() < deadline,
            "the owner must reach the fake wave search"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let joiner = tokio::spawn(coalesced_doh_lookup(host));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        inflight_doh_registry_len(),
        1,
        "the entry must stay while callers still hold the in-flight cell"
    );

    gate.notify_one();
    let owner_ips = tokio::time::timeout(Duration::from_secs(5), owner)
        .await
        .expect("owner finishes")
        .expect("owner task joins")
        .expect("owner lookup succeeds");
    let joiner_ips = tokio::time::timeout(Duration::from_secs(5), joiner)
        .await
        .expect("joiner finishes")
        .expect("joiner task joins")
        .expect("joiner lookup succeeds");
    assert_eq!(owner_ips, joiner_ips, "both callers share one cell");
    assert_eq!(
        searches.load(Ordering::SeqCst),
        1,
        "the joiner must coalesce onto the owner's cell, not start a second search"
    );
    assert_eq!(
        inflight_doh_registry_len(),
        0,
        "only after the result is published to every waiter may the entry go"
    );

    clear_fake_doh_wave_search();
    forget_dns_answer(host);
}
