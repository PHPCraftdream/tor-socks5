// TS10-02: the amortized sweep must be BOUNDED in work, not a full-map
// retain. This file proves the boundary deterministically: more dead
// entries than one sweep interval are planted, a still-inflight lookup is
// parked, fresh insertions drive the sweep counter across its next
// boundary, and the assertions check that the sweep removed the dead
// entries (all of them -- their count stays under the visit budget) while
// the live entry survived and coalescing still works. No wall-clock
// timing: coordination happens through the fake wave search, flags and
// the #[cfg(test)] sweep-counter seam, exactly as in probe_coalesce_tests.
use crate::probe::{
    clear_fake_doh_wave_search, coalesced_doh_lookup, inflight_doh_contains_host,
    inflight_sweep_counter_value, install_fake_doh_wave_search,
};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

// Number of dead entries planted. Must exceed INFLIGHT_SWEEP_INTERVAL (64)
// so a sweep that only visited "recent" entries would be observable, and
// must stay below the INFLIGHT_SWEEP_BUDGET (128) visit budget so ONE sweep
// deterministically visits and removes ALL of them even with the live
// entry present. The mirror literals of the private consts below are tied
// to those two facts.
const DEAD_ENTRIES: usize = 80;

fn dead_host(i: usize) -> String {
    format!("ts1002-dead-{i}.test.invalid")
}

#[tokio::test]
async fn bounded_sweep_removes_dead_entries_and_spares_the_inflight_one() {
    // The registry and the fake wave-search seam are process-global: same
    // serialization as every other registry-writing test.
    let _serial = super::probe_coalesce_tests::FAKE_WAVE_LOCK.lock().await;
    let live_host = "ts1002-sweep-live.test.invalid";

    // The fake parks lookups of the `ts1002-dead-*` hosts (their owners are
    // aborted below, leaving dead `Weak`s), parks the live lookup on
    // `gate`, and fails EVERYTHING else immediately. Branching by HOST (not
    // by a global call counter) matters: unrelated tests resolve other
    // hosts through the same seam and must never park on this test's gate.
    let live_searches = std::sync::Arc::new(AtomicUsize::new(0));
    let live_started = std::sync::Arc::new(AtomicBool::new(false));
    let gate = std::sync::Arc::new(tokio::sync::Notify::new());
    let answer_ips: Vec<IpAddr> = vec!["203.0.113.40".parse().unwrap()];
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
                if query.starts_with("ts1002-dead-") {
                    // Doomed owner: park so the test's abort leaves a dead
                    // `Weak` behind (a completing lookup would remove its
                    // own entry pointwise and never die).
                    gate.notified().await;
                    return Some((ips, Duration::from_secs(300)));
                }
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

    // Phase 1: DEAD_ENTRIES abandoned lookups on distinct hosts ->
    // DEAD_ENTRIES dead `Weak`s. Waiting for every key to be PRESENT (the
    // registry lock serializes the inserts) makes the count exact; awaiting
    // each aborted handle then guarantees the future -- and its Arc to the
    // cell -- is really gone.
    let mut doomed = Vec::new();
    for i in 0..DEAD_ENTRIES {
        doomed.push(tokio::spawn({
            let host = dead_host(i);
            async move { coalesced_doh_lookup(&host).await }
        }));
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    for i in 0..DEAD_ENTRIES {
        while !inflight_doh_contains_host(&dead_host(i)) {
            assert!(
                std::time::Instant::now() < deadline,
                "all {DEAD_ENTRIES} doomed owners must insert their registry entries"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
    for handle in doomed {
        handle.abort();
        let cancelled = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("aborted owner joins")
            .is_err();
        assert!(cancelled, "each doomed owner must have been cancelled");
    }

    // Phase 2: a still-inflight lookup of a different host.
    let owner = tokio::spawn(coalesced_doh_lookup(live_host));
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !live_started.load(Ordering::SeqCst) {
        assert!(
            std::time::Instant::now() < deadline,
            "the live owner must reach the fake wave search"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // Phase 3: fresh insertions (fast, failing, distinct hosts) until the
    // sweep counter crosses its next boundary -- the insertion that makes
    // the counter a multiple of INFLIGHT_SWEEP_INTERVAL (64, mirrored here
    // from dns_resolution's private const) runs the sweep. With 80 dead +
    // 1 live entries the map stays under the visit budget, so THAT sweep
    // must visit and remove every dead entry.
    let start = inflight_sweep_counter_value();
    let target = (start / 64 + 1) * 64;
    let mut i = 0usize;
    while inflight_sweep_counter_value() < target {
        assert!(
            i < 4 * 64,
            "the sweep counter must advance within a bounded number of inserts"
        );
        let host = format!("ts1002-trigger-{i}.test.invalid");
        assert!(coalesced_doh_lookup(&host).await.is_err());
        i += 1;
    }

    for i in 0..DEAD_ENTRIES {
        assert!(
            !inflight_doh_contains_host(&dead_host(i)),
            "the bounded sweep must have removed the dead entry for {} \
             (the whole map fits inside the visit budget)",
            dead_host(i)
        );
    }
    assert!(
        inflight_doh_contains_host(live_host),
        "the sweep must have spared the still-inflight lookup's registry entry"
    );

    // Phase 4: the live entry must still coalesce -- a joiner shares the
    // parked lookup instead of starting a second wave search.
    let joiner = tokio::spawn(coalesced_doh_lookup(live_host));
    tokio::time::sleep(Duration::from_millis(50)).await;
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
    assert_eq!(owner_ips, joiner_ips, "both callers share one lookup");
    assert_eq!(
        live_searches.load(Ordering::SeqCst),
        1,
        "the joiner must coalesce onto the owner's cell: no second wave \
         search for the live host may run"
    );
    assert!(
        !inflight_doh_contains_host(live_host),
        "after the result was published to every waiter, the owner's \
         pointwise removal must have deleted the entry"
    );

    clear_fake_doh_wave_search();
}
