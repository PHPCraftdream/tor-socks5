// TS10-02: the amortized sweep must be BOUNDED in work, not a full-map
// retain. This file proves the boundary deterministically: more dead
// entries than one sweep interval are planted, a still-inflight lookup is
// parked, fresh insertions drive the sweep counter across its next
// boundary, and the assertions check that the sweep removed the dead
// entries while a stable live prefix survives and coalescing still works.
// Coordination uses fake-wave channels and the #[cfg(test)] sweep-counter
// seam, with no wall-clock timing oracle.
use crate::probe::{
    clear_fake_doh_wave_search, coalesced_doh_lookup, inflight_doh_contains_host,
    inflight_sweep_counter_value, install_fake_doh_wave_search,
};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

// Keep a live prefix ahead of more than one sweep's budget of abandoned
// entries. The first sweep must stop before the tail, then later FIFO sweeps
// must reach it. These mirror the private interval and budget constants.
const LIVE_PREFIX: usize = 129;
const DEAD_ENTRIES: usize = 140;

/// Ceiling on how long a parked fake lookup may take to finish once it is
/// released — a guard against a wedged test, never a claim about latency.
/// This test spawns hundreds of tasks, so on a slow or loaded CI runner the
/// join can legitimately take seconds; the previous 5s budget expired on the
/// macOS runner and failed the run. Worse, failing here leaves entries in the
/// process-wide in-flight registry, which then fails unrelated tests, so a
/// tight bound here is expensive in a way that is not obvious from the
/// failure it produces.
const TASK_SETTLE_GUARD: Duration = Duration::from_secs(60);

fn dead_host(i: usize) -> String {
    format!("ts1002-dead-{i}.test.invalid")
}

fn live_host(i: usize) -> String {
    format!("ts1002-sweep-live-{i}.test.invalid")
}

fn any_dead_entry_remains() -> bool {
    (0..DEAD_ENTRIES).any(|i| inflight_doh_contains_host(&dead_host(i)))
}

struct AbortOnDrop<T>(Vec<tokio::task::JoinHandle<T>>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        for handle in &self.0 {
            handle.abort();
        }
    }
}

struct FakeSearchCleanup;

impl Drop for FakeSearchCleanup {
    fn drop(&mut self) {
        clear_fake_doh_wave_search();
    }
}

async fn recv_started(
    started_rx: &mut tokio::sync::mpsc::Receiver<(String, tokio::sync::oneshot::Sender<()>)>,
) -> (String, tokio::sync::oneshot::Sender<()>) {
    tokio::time::timeout(TASK_SETTLE_GUARD, started_rx.recv())
        .await
        .expect("fake lookup starts promptly")
        .expect("fake lookup sender remains connected")
}

#[tokio::test]
async fn bounded_sweep_removes_dead_entries_and_spares_the_inflight_one() {
    // The registry and the fake wave-search seam are process-global: same
    // serialization as every other registry-writing test.
    let _serial = super::probe_coalesce_tests::FAKE_WAVE_LOCK.lock().await;
    let _fake_cleanup = FakeSearchCleanup;
    let primary_live_host = live_host(0);

    // The fake parks lookups of the `ts1002-dead-*` hosts (their owners are
    // aborted below, leaving dead `Weak`s), parks live lookups on their
    // one shot release channels, and fails EVERYTHING else immediately.
    // Branching by HOST (not
    // by a global call counter) matters: unrelated tests resolve other
    // hosts through the same seam and must never park on this test's channels.
    let live_searches = std::sync::Arc::new(AtomicUsize::new(0));
    let (started_tx, mut started_rx) = tokio::sync::mpsc::channel::<(
        String,
        tokio::sync::oneshot::Sender<()>,
    )>(DEAD_ENTRIES + LIVE_PREFIX);
    let answer_ips: Vec<IpAddr> = vec!["203.0.113.40".parse().unwrap()];
    install_fake_doh_wave_search({
        let live_searches = std::sync::Arc::clone(&live_searches);
        let started_tx = started_tx.clone();
        let ips = answer_ips.clone();
        std::sync::Arc::new(move |query: &str| {
            let live_searches = std::sync::Arc::clone(&live_searches);
            let started_tx = started_tx.clone();
            let ips = ips.clone();
            let query = query.to_owned();
            Box::pin(async move {
                let (release_tx, release_rx) = tokio::sync::oneshot::channel();
                if query.starts_with("ts1002-dead-") {
                    // Doomed owner: park so the test's abort leaves a dead
                    // `Weak` behind (a completing lookup would remove its
                    // own entry pointwise and never die).
                    started_tx
                        .send((query, release_tx))
                        .await
                        .expect("test receiver is alive");
                    let _ = release_rx.await;
                    return Some((ips, Duration::from_secs(300)));
                }
                if query.starts_with("ts1002-sweep-live-") {
                    live_searches.fetch_add(1, Ordering::SeqCst);
                    started_tx
                        .send((query, release_tx))
                        .await
                        .expect("test receiver is alive");
                    let _ = release_rx.await;
                    return Some((ips, Duration::from_secs(300)));
                }
                None
            })
                as std::pin::Pin<
                    Box<dyn std::future::Future<Output = Option<(Vec<IpAddr>, Duration)>> + Send>,
                >
        })
    });

    // Phase 1: put live entries at the front of the FIFO cursor. The bounded
    // sweep must visit these and rotate them before it can reach later dead
    // entries.
    let mut live_owners = AbortOnDrop(Vec::new());
    let mut live_releases = Vec::new();
    for i in 0..LIVE_PREFIX {
        let host = live_host(i);
        let lookup_host = host.clone();
        live_owners.0.push(tokio::spawn(async move {
            coalesced_doh_lookup(&lookup_host).await
        }));
        let (started, release) = recv_started(&mut started_rx).await;
        assert_eq!(started, host);
        live_releases.push(release);
    }

    // Phase 2: DEAD_ENTRIES abandoned lookups on distinct hosts ->
    // DEAD_ENTRIES dead `Weak`s. The bounded channel tells us exactly when
    // each owner reached the fake search, and awaiting each aborted handle
    // guarantees its Arc to the cell is gone.
    let mut doomed = AbortOnDrop(Vec::new());
    let mut dead_releases = Vec::new();
    for i in 0..DEAD_ENTRIES {
        let host = dead_host(i);
        let lookup_host = host.clone();
        let handle = tokio::spawn(async move { coalesced_doh_lookup(&lookup_host).await });
        let (started, release) = recv_started(&mut started_rx).await;
        assert_eq!(started, host);
        doomed.0.push(handle);
        dead_releases.push(release);
    }
    for handle in doomed.0.drain(..) {
        handle.abort();
        let cancelled = tokio::time::timeout(TASK_SETTLE_GUARD, handle)
            .await
            .expect("aborted owner joins")
            .is_err();
        assert!(cancelled, "each doomed owner must have been cancelled");
    }

    // Phase 3: fresh insertions (fast, failing, distinct hosts) until the
    // sweep counter crosses its next boundary -- the insertion that makes
    // the counter a multiple of INFLIGHT_SWEEP_INTERVAL (64, mirrored here
    // from dns_resolution's private const) runs the sweep. With more than one
    // budget of stable live entries, the first sweep leaves dead entries for
    // later cursor rotations, proving that one operation does not scan past
    // its fixed budget.
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

    assert!(
        any_dead_entry_remains(),
        "the first bounded sweep must leave part of the dead tail"
    );
    for i in 0..LIVE_PREFIX {
        assert!(
            inflight_doh_contains_host(&live_host(i)),
            "the sweep must spare live entry {}",
            live_host(i)
        );
    }

    // Later sweep boundaries rotate the stable live prefix and eventually
    // reclaim every dead entry, without any timing or capacity assumption.
    let mut sweeps = 0;
    while any_dead_entry_remains() {
        let start = inflight_sweep_counter_value();
        let target = (start / 64 + 1) * 64;
        let mut i = 0usize;
        while inflight_sweep_counter_value() < target {
            assert!(i < 4 * 64, "the sweep counter must advance promptly");
            let host = format!("ts1002-trigger-later-{sweeps}-{i}.test.invalid");
            assert!(coalesced_doh_lookup(&host).await.is_err());
            i += 1;
        }
        sweeps += 1;
        assert!(sweeps <= 8, "the FIFO sweep must reach the dead tail");
    }
    for i in 0..DEAD_ENTRIES {
        assert!(!inflight_doh_contains_host(&dead_host(i)));
    }

    // Phase 4: the live entry must still coalesce -- a joiner shares the
    // parked lookup instead of starting a second wave search.
    //
    // The sweeps above must not have evicted this still-live entry; check that
    // before building the joiner, so an eviction is reported as an eviction
    // rather than as the joiner hanging sixty seconds further down.
    assert!(
        inflight_doh_contains_host(&primary_live_host),
        "the bounded sweep must spare the entry whose lookup is still in flight"
    );
    let searches_before_joiner = live_searches.load(Ordering::SeqCst);
    let mut joiner = Box::pin(coalesced_doh_lookup(&primary_live_host));
    assert!(
        matches!(futures::poll!(joiner.as_mut()), std::task::Poll::Pending),
        "the joiner must register on the parked cell before release"
    );
    // Registration is synchronous -- everything before `get_or_init().await`
    // in `coalesced_doh_lookup` runs on that first poll -- so by now the
    // joiner has either upgraded the owner's cell or created its own. Only the
    // latter starts a fresh wave search, and it would park on a release
    // channel this test never sends, hanging the join below. Fail here, with
    // the reason, instead of there.
    assert_eq!(
        live_searches.load(Ordering::SeqCst),
        searches_before_joiner,
        "the joiner must coalesce onto the parked owner's cell, not start a \
         second wave search"
    );
    for release in live_releases {
        release.send(()).expect("live owner is parked");
    }

    let owner = live_owners.0.remove(0);
    let owner_ips = tokio::time::timeout(TASK_SETTLE_GUARD, owner)
        .await
        .expect("owner finishes")
        .expect("owner task joins")
        .expect("owner lookup succeeds");
    let joiner_ips = tokio::time::timeout(TASK_SETTLE_GUARD, joiner)
        .await
        .expect("joiner finishes")
        .expect("joiner lookup succeeds");
    for owner in live_owners.0.drain(..) {
        tokio::time::timeout(TASK_SETTLE_GUARD, owner)
            .await
            .expect("live owner finishes")
            .expect("live owner task joins")
            .expect("live lookup succeeds");
    }
    assert_eq!(owner_ips, joiner_ips, "both callers share one lookup");
    assert_eq!(
        live_searches.load(Ordering::SeqCst),
        LIVE_PREFIX,
        "the joiner must coalesce onto the owner's cell: no extra wave \
         search for the live prefix may run"
    );
    assert!(
        !inflight_doh_contains_host(&primary_live_host),
        "after the result was published to every waiter, pointwise removal \
         must delete the primary live entry"
    );
}
