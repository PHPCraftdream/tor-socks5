//! Tests of the group bridge registry, of bridge selection and reservation, and
//! of the tasks of one generation — all without Tor, without network and without a host.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::Duration;

use arti_wrapper::Settings;
use bridge_line::BridgeLine;
use tokio_util::sync::CancellationToken;

use super::super::{
    apply_claim, bootstrap_group, close_generation, offered_bridges, stop_before_release, Assigned,
    GroupTask,
};
use super::{plan_claim, Claim, GroupBridges};

fn pool(count: usize) -> Vec<BridgeLine> {
    (0..count)
        .map(|n| {
            format!("192.0.2.{} 443 {:040X}", n + 1, n + 1)
                .replacen(' ', ":", 1)
                .parse()
                .expect("a bridge line")
        })
        .collect()
}

fn main_settings() -> Settings {
    Settings {
        bridges: pool(6),
        state_dir: Some(Path::new("base").join("arti-data")),
        ..Settings::default()
    }
}

fn assigned(bridges: Vec<BridgeLine>) -> Assigned {
    Assigned {
        bridges,
        overlaps: false,
        short: false,
    }
}

/// A registry with the groups "a" and "b", both holding `bridges`.
fn two_groups(bridges: Vec<BridgeLine>) -> Arc<GroupBridges> {
    GroupBridges::new(&BTreeMap::from([
        ("a".to_owned(), assigned(bridges.clone())),
        ("b".to_owned(), assigned(bridges)),
    ]))
}

/// A registry seeded with the one group named by the caller.
fn seeded(name: &str, bridges: Vec<BridgeLine>) -> Arc<GroupBridges> {
    GroupBridges::new(&BTreeMap::from([(name.to_owned(), assigned(bridges))]))
}

#[test]
fn a_bridge_the_process_dropped_is_replaced_from_its_working_list() {
    let group = pool(2);
    let free = pool(3)[2].clone();
    let working = vec![group[1].clone(), free.clone()];
    let claim = plan_claim(&group, &working, &BTreeSet::new());
    assert_eq!(claim.dead, vec![group[0].clone()]);
    assert_eq!(claim.taken, vec![free.clone()]);
    assert_eq!(claim.bridges, vec![group[1].clone(), free]);
    assert_eq!(claim.unreplaced(), 0);
}

#[test]
fn a_replacement_never_takes_a_bridge_another_group_holds() {
    let group = pool(2);
    let free = pool(3)[2].clone();
    let held = pool(4)[3].clone();
    let working = vec![group[1].clone(), free.clone(), held.clone()];
    let claim = plan_claim(&group, &working, &BTreeSet::from([held.to_string()]));
    assert_eq!(
        claim.taken,
        vec![free.clone()],
        "only the free bridge is taken"
    );
    assert_eq!(claim.unreplaced(), 0);

    let all_taken: BTreeSet<String> = [free, held].iter().map(ToString::to_string).collect();
    let nothing_free = plan_claim(&group, &working, &all_taken);
    assert!(nothing_free.taken.is_empty());
    assert_eq!(nothing_free.unreplaced(), 1, "the dead bridge stays");
}

#[test]
fn a_group_whose_bridges_the_process_still_works_with_keeps_its_set() {
    let group = pool(2);
    let claim = plan_claim(&group, &pool(4), &BTreeSet::new());
    assert!(claim.dead.is_empty());
    assert!(claim.taken.is_empty());
    assert_eq!(claim.bridges, group, "nothing to change");
}

#[test]
fn the_choice_does_not_depend_on_the_order_of_the_working_list() {
    let group = pool(2);
    let chosen = pool(5)[2].clone();
    let working = vec![
        pool(5)[4].clone(),
        pool(5)[3].clone(),
        group[1].clone(),
        chosen.clone(),
    ];
    let mut reversed = working.clone();
    reversed.reverse();
    let forward = plan_claim(&group, &working, &BTreeSet::new());
    let backward = plan_claim(&group, &reversed, &BTreeSet::new());
    assert_eq!(
        forward.taken,
        vec![chosen],
        "the lowest free bridge is chosen, so the result is not empty"
    );
    assert_eq!(backward.taken, forward.taken);
}

#[test]
fn one_free_bridge_replaces_one_dead_one_and_the_other_dead_one_stays() {
    let group = pool(2);
    let free = pool(4)[3].clone();
    let claim = plan_claim(&group, std::slice::from_ref(&free), &BTreeSet::new());
    assert_eq!(claim.dead.len(), 2);
    assert_eq!(
        claim.taken,
        vec![free.clone()],
        "a partial replacement happens"
    );
    assert_eq!(claim.unreplaced(), 1, "the other dead bridge stays");
    assert_eq!(claim.bridges.len(), group.len(), "the size never changes");
    assert_eq!(claim.bridges, vec![free, group[1].clone()]);
}

#[test]
fn every_dead_bridge_gets_a_free_one_when_the_pool_has_them() {
    let group = pool(2);
    let first = pool(4)[2].clone();
    let second = pool(4)[3].clone();
    let claim = plan_claim(&group, &[second.clone(), first.clone()], &BTreeSet::new());
    assert_eq!(claim.dead.len(), 2);
    assert_eq!(claim.taken, vec![first.clone(), second.clone()]);
    assert_eq!(claim.unreplaced(), 0);
    assert_eq!(claim.bridges, vec![first, second], "bridge-line order");
    assert_eq!(claim.bridges.len(), group.len());
}

#[test]
fn a_claim_never_grows_or_shrinks_the_group() {
    let group = pool(2);
    let working = vec![group[1].clone(), pool(5)[2].clone(), pool(5)[3].clone()];
    let claim = plan_claim(&group, &working, &BTreeSet::new());
    assert_eq!(claim.taken.len(), 1, "one dead bridge, one replacement");
    assert_eq!(claim.bridges.len(), group.len());
}

#[test]
fn a_claim_is_recorded_so_the_next_group_sees_the_bridge() {
    let dead = pool(2);
    let free = pool(3)[2].clone();
    let registry = two_groups(dead.clone());
    // The process dropped the first bridge of both groups; it works with the
    // second one and one free bridge.
    let working = vec![dead[1].clone(), free.clone()];
    let first = registry.claim("a", &dead, &working);
    assert_eq!(first.dead, vec![dead[0].clone()]);
    assert_eq!(first.taken, vec![free.clone()]);
    assert_eq!(registry.bridges_of("a"), Some(vec![dead[1].clone(), free]));

    let second = registry.claim("b", &dead, &working);
    assert!(second.taken.is_empty(), "b may not take what a holds");
    assert_eq!(second.unreplaced(), 1);
    assert_eq!(registry.bridges_of("b"), Some(dead));
}

#[test]
fn a_reservation_keeps_the_old_bridges_until_the_client_switches() {
    let x = pool(3)[0].clone();
    let y = pool(3)[1].clone();
    let free = pool(4)[3].clone();
    let own = pool(5)[4].clone();
    let registry = GroupBridges::new(&BTreeMap::from([
        ("a".to_owned(), assigned(vec![x.clone(), y.clone()])),
        ("b".to_owned(), assigned(vec![own.clone()])),
    ]));
    // The process dropped x, but the client of "a" still runs on it.
    let dropped = vec![y.clone(), free.clone()];
    let claim = registry.reserve_for("a", &[x.clone(), y.clone()], &dropped);
    assert_eq!(claim.taken, vec![free.clone()]);
    assert_eq!(
        registry.bridges_of("a"),
        Some(vec![x.clone(), y.clone(), free.clone()]),
        "the old and the new bridges are both held while the switch is in flight"
    );

    // x is back in the process's working list, but it is still "a"'s bridge.
    let back = vec![x.clone(), y.clone(), free.clone()];
    let neighbour = registry.reserve_for("b", std::slice::from_ref(&own), &back);
    assert!(
        neighbour.taken.is_empty(),
        "a neighbour may not take a bridge the client of the first group runs on"
    );

    // The switch worked: the old bridge is released and the neighbour may take it.
    registry.commit("a", &claim);
    assert_eq!(registry.bridges_of("a"), Some(vec![y, free]));
    let retry = registry.reserve_for("b", &[own], &back);
    assert_eq!(retry.taken, vec![x], "the released bridge is free now");
}

#[test]
fn a_client_that_refuses_the_switch_keeps_its_bridge_and_frees_the_reserved_one() {
    let dead = pool(2);
    let free = pool(3)[2].clone();
    let registry = two_groups(dead.clone());
    let working = vec![dead[1].clone(), free.clone()];

    let applied = apply_claim("a", &registry, &dead, &working, |_| false);
    assert!(applied.is_none(), "the client refused the new set");
    assert_eq!(
        registry.bridges_of("a"),
        Some(dead.clone()),
        "the group keeps the bridge its client runs on"
    );
    assert_eq!(
        registry.reserve_for("b", &dead, &working).taken,
        vec![free],
        "the reserved bridge went back to the pool"
    );
}

#[test]
fn a_client_that_takes_the_switch_drops_its_old_bridge() {
    let dead = pool(2);
    let free = pool(3)[2].clone();
    let registry = two_groups(dead.clone());
    let working = vec![dead[1].clone(), free.clone()];

    let applied = apply_claim("a", &registry, &dead, &working, |bridges| {
        assert_eq!(
            bridges,
            [dead[1].clone(), free.clone()],
            "the client is asked to run on the new set"
        );
        true
    });
    let claim = applied.expect("the client took the switch");
    assert_eq!(registry.bridges_of("a"), Some(claim.bridges.clone()));
    assert!(
        !claim.bridges.contains(&dead[0]),
        "the old bridge is dropped once the client moved"
    );
}

/// Smoke test: the barrier lines the threads up at the call, not inside it,
/// so a split lock could still pass. The guarantee is structural: `claim`
/// reads the neighbours' bridges and writes the reservation under one lock.
#[test]
fn smoke_two_groups_claiming_at_once_never_get_the_same_bridge() {
    let dead = pool(2);
    let free = pool(3)[2].clone();
    // The process dropped the first bridge and offers the free one.
    let working = vec![dead[1].clone(), free];
    let registry = two_groups(dead.clone());
    // Both claims meet between choosing and recording: with one lock the second
    // one waits for the lock and cannot meet, with two locks both meet and both
    // take the free bridge.
    registry.arm_midpoint();
    let barrier = Arc::new(Barrier::new(2));
    let claims: Vec<Claim> = std::thread::scope(|scope| {
        ["a", "b"]
            .into_iter()
            .map(|name| {
                let registry = Arc::clone(&registry);
                let barrier = Arc::clone(&barrier);
                let current = dead.clone();
                let working = working.clone();
                scope.spawn(move || {
                    barrier.wait();
                    registry.claim(name, &current, &working)
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|handle| handle.join().expect("claim thread"))
            .collect()
    });
    let taken: Vec<BridgeLine> = claims.iter().flat_map(|c| c.taken.clone()).collect();
    assert_eq!(taken.len(), 1, "exactly one group may take the free bridge");
    assert_ne!(
        claims[0].bridges, claims[1].bridges,
        "only the winner's set contains the free bridge"
    );
}

#[test]
fn a_released_group_frees_its_bridges_for_the_others() {
    let taken_by_a = pool(3)[2].clone();
    let own = pool(4)[3].clone();
    let registry = GroupBridges::new(&BTreeMap::from([
        ("a".to_owned(), assigned(vec![taken_by_a.clone()])),
        ("b".to_owned(), assigned(vec![own.clone()])),
    ]));
    // The process works with the bridge of "a" only, and it is the one "b"
    // would take if it were free.
    let working = vec![taken_by_a.clone()];
    assert!(
        registry
            .reserve_for("b", std::slice::from_ref(&own), &working)
            .taken
            .is_empty(),
        "the bridge is taken while the first group runs"
    );

    registry.release("a");
    assert_eq!(registry.bridges_of("a"), None);
    assert_eq!(
        registry.reserve_for("b", &[own], &working).taken,
        vec![taken_by_a],
        "the bridge of the stopped group is free now"
    );
}

#[tokio::test(start_paused = true)]
async fn the_client_is_released_only_after_its_tasks_are_finished() {
    struct Mark(Arc<AtomicU32>);
    impl Drop for Mark {
        fn drop(&mut self) {
            self.0.store(1, Ordering::SeqCst);
        }
    }

    let finished = Arc::new(AtomicU32::new(0));
    let mark = Mark(Arc::clone(&finished));
    let task = GroupTask::new(tokio::spawn(async move {
        let _mark = mark;
        std::future::pending::<()>().await;
    }));
    tokio::time::sleep(Duration::from_secs(3)).await;

    let observed = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&observed);
    let flag = Arc::clone(&finished);
    stop_before_release(&CancellationToken::new(), None, task, async move {
        recorder
            .lock()
            .expect("releases")
            .push(flag.load(Ordering::SeqCst));
    })
    .await;

    assert_eq!(
        observed.lock().expect("releases").clone(),
        vec![1],
        "the task is finished before the client is released"
    );
}

#[tokio::test(start_paused = true)]
async fn a_task_that_ignores_the_stop_is_still_finished_before_the_release() {
    let runs = Arc::new(AtomicU32::new(0));
    let counter = Arc::clone(&runs);
    let task = GroupTask::new(tokio::spawn(async move {
        loop {
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }));
    let stopped_at = Arc::new(AtomicU32::new(0));
    let recorder = Arc::clone(&stopped_at);
    let observed = Arc::clone(&runs);
    stop_before_release(&CancellationToken::new(), None, task, async move {
        recorder.store(observed.load(Ordering::SeqCst), Ordering::SeqCst);
    })
    .await;
    let at_release = stopped_at.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(30)).await;
    assert_eq!(
        runs.load(Ordering::SeqCst),
        at_release,
        "the aborted task cannot run after the client was released"
    );
}

#[tokio::test(start_paused = true)]
async fn a_task_that_stops_is_waited_for() {
    let done = Arc::new(AtomicU32::new(0));
    let flag = Arc::clone(&done);
    let task = GroupTask::new(tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(2)).await;
        flag.store(1, Ordering::SeqCst);
    }));
    task.stop(Duration::from_secs(10), "test task").await;
    assert_eq!(done.load(Ordering::SeqCst), 1, "the task ended in time");
}

#[tokio::test(start_paused = true)]
async fn a_task_that_ignores_the_stop_is_aborted_and_awaited() {
    let runs = Arc::new(AtomicU32::new(0));
    let counter = Arc::clone(&runs);
    let task = GroupTask::new(tokio::spawn(async move {
        loop {
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }));
    tokio::time::sleep(Duration::from_secs(3)).await;
    task.stop(Duration::from_millis(1), "test task").await;
    let after = runs.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(30)).await;
    assert_eq!(
        runs.load(Ordering::SeqCst),
        after,
        "an aborted task is over for good"
    );
}

#[tokio::test(start_paused = true)]
async fn dropping_a_task_aborts_it() {
    let runs = Arc::new(AtomicU32::new(0));
    let counter = Arc::clone(&runs);
    let task = GroupTask::new(tokio::spawn(async move {
        loop {
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }));
    tokio::time::sleep(Duration::from_secs(3)).await;
    drop(task);
    tokio::time::sleep(Duration::from_secs(30)).await;
    let after_drop = runs.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(30)).await;
    assert_eq!(
        runs.load(Ordering::SeqCst),
        after_drop,
        "an aborted task does not run again"
    );
}

/// Records its label when dropped, so a test can see when a task finished.
struct PushOnDrop(Arc<Mutex<Vec<&'static str>>>, &'static str);

impl Drop for PushOnDrop {
    fn drop(&mut self) {
        self.0.lock().expect("events").push(self.1);
    }
}

#[tokio::test(start_paused = true)]
async fn the_groups_bridges_are_read_only_after_the_generation_is_released() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let next_bridges = vec![pool(3)[2].clone()];
    let registry = seeded("edge", pool(2));

    let watcher = {
        let events = Arc::clone(&events);
        GroupTask::new(tokio::spawn(async move {
            let _end = PushOnDrop(events, "watcher ended");
            std::future::pending::<()>().await;
        }))
    };
    let host = {
        let events = Arc::clone(&events);
        GroupTask::new(tokio::spawn(async move {
            let _end = PushOnDrop(events, "host ended");
            std::future::pending::<()>().await;
        }))
    };
    let release_events = Arc::clone(&events);
    let release_registry = Arc::clone(&registry);
    let release_bridges = next_bridges.clone();
    let read = close_generation(
        &CancellationToken::new(),
        Some(watcher),
        host,
        async move {
            release_events
                .lock()
                .expect("events")
                .push("client released");
            // A task that outlived the release would overwrite this.
            release_registry.rollback("edge", &release_bridges);
        },
        &registry,
        "edge",
    )
    .await;

    assert_eq!(
        events.lock().expect("events").clone(),
        vec!["watcher ended", "host ended", "client released"],
        "both tasks finish before the client is released"
    );
    assert_eq!(
        read,
        Some(next_bridges),
        "the bridges are read after the release, not before"
    );
}

#[test]
fn a_group_without_maintenance_never_reads_the_process_pool() {
    let offered = offered_bridges(false, || {
        panic!("the pool must not be read when maintenance is off")
    });
    assert_eq!(offered, None, "no claim is made without maintenance");

    let bridge = pool(1);
    assert_eq!(
        offered_bridges(true, || bridge.clone()),
        Some(bridge),
        "with maintenance on the working list is used"
    );
}

#[tokio::test(start_paused = true)]
async fn a_group_without_maintenance_bootstraps_on_the_bridges_it_was_given() {
    let token = CancellationToken::new();
    let dead = pool(1);
    let registry = seeded("edge", dead.clone());
    let mut bridges = dead.clone();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&seen);
    let (_, prepared) = bootstrap_group(
        &registry,
        "edge",
        &main_settings(),
        &mut bridges,
        || None,
        |settings| {
            let recorder = Arc::clone(&recorder);
            async move {
                recorder
                    .lock()
                    .expect("attempts")
                    .push(settings.bridges.clone());
                Ok::<(), anyhow::Error>(())
            }
        },
        &token,
    )
    .await
    .expect("no configuration error")
    .expect("bootstrapped");
    assert_eq!(
        seen.lock().expect("attempts").clone(),
        vec![dead.clone()],
        "with maintenance off the group keeps the bridges it was given"
    );
    assert_eq!(prepared.settings.bridges, dead);
}
