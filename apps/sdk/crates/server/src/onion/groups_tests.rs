use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arti_wrapper::Settings;
use bridge_line::BridgeLine;
use proxy_config::{OnionServiceEntry, OnionServicePort};
use tokio_util::sync::CancellationToken;

use super::{
    assign_bridges, bootstrap_group, bootstrap_until_ready, group_settings, retry_delay,
    split_entries, start_window, Assigned, GroupBridges, GroupPlan, BOOTSTRAP_ATTEMPT_LIMIT,
    BOOTSTRAP_FIRST_DELAY, BOOTSTRAP_MAX_DELAY, GROUP_START_WINDOW, GROUP_START_WINDOW_MAX,
};

fn entry(nickname: &str, group: Option<(&str, Option<u8>)>) -> OnionServiceEntry {
    OnionServiceEntry {
        nickname: nickname.to_owned(),
        enabled: true,
        address: None,
        key: None,
        circuit_hops: 4,
        bridge_group: group.map(|(name, _)| name.to_owned()),
        bridges: group.and_then(|(_, bridges)| bridges),
        ports: vec![OnionServicePort {
            onion_port: 80,
            target: "127.0.0.1:8080".to_owned(),
        }],
    }
}

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

fn plans(groups: &[(&str, u8)]) -> BTreeMap<String, GroupPlan> {
    groups
        .iter()
        .map(|(name, bridges)| {
            (
                (*name).to_owned(),
                GroupPlan {
                    bridges: *bridges,
                    entries: Vec::new(),
                },
            )
        })
        .collect()
}

fn names(entries: &[OnionServiceEntry]) -> Vec<&str> {
    entries.iter().map(|e| e.nickname.as_str()).collect()
}

#[test]
fn services_without_a_group_stay_on_the_shared_client() {
    let split = split_entries(vec![entry("a", None), entry("b", None)]);
    assert_eq!(names(&split.shared), ["a", "b"]);
    assert!(split.groups.is_empty());
}

#[test]
fn services_of_one_group_share_a_plan_in_file_order() {
    let split = split_entries(vec![
        entry("a", Some(("edge", Some(2)))),
        entry("plain", None),
        entry("b", Some(("core", None))),
        entry("c", Some(("edge", Some(2)))),
    ]);
    assert_eq!(names(&split.shared), ["plain"]);
    assert_eq!(split.groups.keys().collect::<Vec<_>>(), ["core", "edge"]);
    assert_eq!(split.groups["edge"].bridges, 2);
    assert_eq!(names(&split.groups["edge"].entries), ["a", "c"]);
    assert_eq!(split.groups["core"].bridges, 1, "an unstated count is one");
}

#[test]
fn groups_get_disjoint_bridges_while_the_pool_lasts() {
    let groups = plans(&[("a", 2), ("b", 3), ("c", 1)]);
    let assigned = assign_bridges(&pool(6), &groups);
    let mut seen = HashSet::new();
    for (name, plan) in &groups {
        let got = &assigned[name];
        assert_eq!(got.bridges.len(), usize::from(plan.bridges), "{name}");
        assert!(!got.overlaps && !got.short, "{name}");
        for line in &got.bridges {
            assert!(seen.insert(line.to_string()), "{name} reuses {line}");
        }
    }
    assert_eq!(seen.len(), 6);
}

#[test]
fn the_same_pool_in_any_order_gives_the_same_bridges() {
    let groups = plans(&[("a", 2), ("b", 2)]);
    let forward = pool(5);
    let mut reversed = forward.clone();
    reversed.reverse();
    assert_eq!(
        assign_bridges(&forward, &groups),
        assign_bridges(&reversed, &groups)
    );
}

#[test]
fn a_used_up_pool_wraps_around_and_says_so() {
    let groups = plans(&[("a", 2), ("b", 2), ("c", 2)]);
    let assigned = assign_bridges(&pool(3), &groups);
    assert!(!assigned["a"].overlaps);
    assert!(
        assigned["b"].overlaps,
        "b needs a fourth bridge and the pool has three"
    );
    assert!(assigned["c"].overlaps);
    for got in assigned.values() {
        assert_eq!(got.bridges.len(), 2);
        assert!(!got.short);
        assert_ne!(
            got.bridges[0], got.bridges[1],
            "no bridge twice in one group"
        );
    }
}

#[test]
fn a_pool_smaller_than_the_group_gives_the_whole_pool_and_says_so() {
    let assigned = assign_bridges(&pool(2), &plans(&[("a", 5)]));
    assert_eq!(assigned["a"].bridges.len(), 2);
    assert!(assigned["a"].short);
}

#[test]
fn an_empty_pool_gives_no_bridges() {
    let assigned = assign_bridges(&[], &plans(&[("a", 1)]));
    assert!(assigned["a"].bridges.is_empty());
    assert!(assigned["a"].short);
}

#[test]
fn a_repeated_bridge_in_the_pool_counts_once() {
    let mut doubled = pool(2);
    doubled.extend(pool(2));
    let assigned = assign_bridges(&doubled, &plans(&[("a", 2), ("b", 2)]));
    assert!(!assigned["a"].overlaps);
    assert!(assigned["b"].overlaps, "only two distinct bridges exist");
}

fn main_settings() -> Settings {
    Settings {
        bridges: pool(6),
        state_dir: Some(Path::new("base").join("arti-data")),
        circuit_hops: 2,
        service_circuit_hops: 3,
        guard_spread: 1,
        extra_pt_protocols: vec!["webtunnel".to_owned()],
        ..Settings::default()
    }
}

#[test]
fn a_group_client_has_its_own_state_the_shared_cache_and_only_its_bridges() {
    let main = main_settings();
    let bridges = pool(2);
    let (settings, keystore) = group_settings(&main, "edge", bridges.clone()).expect("settings");
    let base = Path::new("base").join("arti-data");
    assert_eq!(settings.bridges, bridges);
    assert_eq!(settings.state_dir, Some(base.join("group-edge")));
    assert_eq!(settings.cache_dir, Some(base.join("cache")));
    assert_eq!(
        keystore,
        base.join("group-edge").join("state").join("keystore"),
        "the keystore the host expects for the client's base directory"
    );
    assert_eq!(settings.circuit_hops, 2, "the rest is the process client's");
    assert_eq!(settings.service_circuit_hops, 3);
    assert_eq!(settings.extra_pt_protocols, ["webtunnel"]);
}

#[test]
fn an_explicit_cache_directory_of_the_process_client_is_kept() {
    let mut main = main_settings();
    main.cache_dir = Some(Path::new("elsewhere").join("cache"));
    let (settings, _) = group_settings(&main, "edge", pool(1)).expect("settings");
    assert_eq!(
        settings.cache_dir,
        Some(Path::new("elsewhere").join("cache"))
    );
}

#[test]
fn a_group_spreads_circuits_over_up_to_three_of_its_bridges() {
    let main = main_settings();
    for (count, expected) in [(1, 1), (2, 2), (3, 3), (8, 3)] {
        let (settings, _) = group_settings(&main, "edge", pool(count)).expect("settings");
        assert_eq!(settings.guard_spread, expected, "{count} bridges");
    }
}

#[test]
fn a_group_without_bridges_is_refused_rather_than_reaching_tor_directly() {
    assert!(group_settings(&main_settings(), "edge", Vec::new()).is_err());
}

#[test]
fn a_group_needs_the_state_directory() {
    let mut main = main_settings();
    main.state_dir = None;
    assert!(group_settings(&main, "edge", pool(1)).is_err());
}

#[tokio::test(start_paused = true)]
async fn a_group_bootstraps_on_its_first_attempt() {
    let token = CancellationToken::new();
    let calls = Arc::new(AtomicU32::new(0));
    let seen = Arc::clone(&calls);
    let started = tokio::time::Instant::now();
    let client = bootstrap_until_ready(
        || {
            let seen = Arc::clone(&seen);
            async move {
                seen.fetch_add(1, Ordering::SeqCst);
                Ok::<&str, anyhow::Error>("client")
            }
        },
        &token,
    )
    .await;
    assert_eq!(client, Some("client"));
    assert_eq!(calls.load(Ordering::SeqCst), 1, "one attempt is enough");
    assert_eq!(
        started.elapsed(),
        Duration::ZERO,
        "no pause after a working attempt"
    );
}

#[tokio::test(start_paused = true)]
async fn a_group_retries_failures_until_a_client_bootstraps() {
    let token = CancellationToken::new();
    let calls = Arc::new(AtomicU32::new(0));
    let seen = Arc::clone(&calls);
    let started = tokio::time::Instant::now();
    let client = bootstrap_until_ready(
        || {
            let seen = Arc::clone(&seen);
            async move {
                let call = seen.fetch_add(1, Ordering::SeqCst) + 1;
                match call {
                    1 => Err(anyhow::anyhow!("no directory consensus")),
                    2 => Err(anyhow::anyhow!("every bridge failed")),
                    _ => Ok(call),
                }
            }
        },
        &token,
    )
    .await;
    assert_eq!(client, Some(3), "the third attempt produced the client");
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert_eq!(
        started.elapsed(),
        retry_delay(1) + retry_delay(2),
        "a pause after each of the two failures"
    );
}

#[tokio::test(start_paused = true)]
async fn a_stuck_attempt_is_cut_at_the_limit_and_retried() {
    let token = CancellationToken::new();
    let calls = Arc::new(AtomicU32::new(0));
    let seen = Arc::clone(&calls);
    let started = tokio::time::Instant::now();
    let client = tokio::time::timeout(
        BOOTSTRAP_ATTEMPT_LIMIT * 3,
        bootstrap_until_ready(
            || {
                let seen = Arc::clone(&seen);
                async move {
                    let call = seen.fetch_add(1, Ordering::SeqCst) + 1;
                    if call == 1 {
                        // A dead bridge: the client makes no progress at all.
                        std::future::pending::<()>().await;
                    }
                    Ok::<u32, anyhow::Error>(call)
                }
            },
            &token,
        ),
    )
    .await
    .expect("a stuck attempt is cut at its deadline, not waited on");
    assert_eq!(client, Some(2), "the stuck attempt gave way to a retry");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        started.elapsed(),
        BOOTSTRAP_ATTEMPT_LIMIT + retry_delay(1),
        "the stuck attempt ran to its deadline, then the first pause"
    );
}

#[tokio::test(start_paused = true)]
async fn cancellation_cuts_a_running_attempt() {
    let token = CancellationToken::new();
    let calls = Arc::new(AtomicU32::new(0));
    let seen = Arc::clone(&calls);
    let started = tokio::time::Instant::now();
    let canceller = token.clone();
    tokio::spawn(async move {
        tokio::time::sleep(BOOTSTRAP_FIRST_DELAY).await;
        canceller.cancel();
    });
    let client = bootstrap_until_ready(
        || {
            let seen = Arc::clone(&seen);
            async move {
                seen.fetch_add(1, Ordering::SeqCst);
                std::future::pending::<()>().await;
                Ok::<(), anyhow::Error>(())
            }
        },
        &token,
    )
    .await;
    assert_eq!(client, None);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "only the attempt that was cut by cancellation ran"
    );
    assert_eq!(
        started.elapsed(),
        BOOTSTRAP_FIRST_DELAY,
        "the attempt was cut on cancellation, not left until its deadline"
    );
}

#[tokio::test(start_paused = true)]
async fn cancellation_cuts_the_pause_between_attempts() {
    let token = CancellationToken::new();
    let calls = Arc::new(AtomicU32::new(0));
    let seen = Arc::clone(&calls);
    let started = tokio::time::Instant::now();
    let canceller = token.clone();
    tokio::spawn(async move {
        // Half of the first pause: the second attempt must never start.
        tokio::time::sleep(BOOTSTRAP_FIRST_DELAY / 2).await;
        canceller.cancel();
    });
    let client = bootstrap_until_ready(
        || {
            let seen = Arc::clone(&seen);
            async move {
                seen.fetch_add(1, Ordering::SeqCst);
                Err::<(), anyhow::Error>(anyhow::anyhow!("no bridge answers"))
            }
        },
        &token,
    )
    .await;
    assert_eq!(client, None);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the second attempt never started"
    );
    assert_eq!(
        started.elapsed(),
        BOOTSTRAP_FIRST_DELAY / 2,
        "the pause ended on cancellation, not after the full delay"
    );
}

#[tokio::test(start_paused = true)]
async fn the_pause_grows_and_stops_at_the_ceiling() {
    let token = CancellationToken::new();
    let times = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&times);
    let client = bootstrap_until_ready(
        || {
            let seen = Arc::clone(&seen);
            async move {
                let call = {
                    let mut times = seen.lock().expect("attempt times");
                    times.push(tokio::time::Instant::now());
                    times.len()
                };
                match call {
                    12 => Ok(call),
                    _ => Err(anyhow::anyhow!("no bridge answers yet")),
                }
            }
        },
        &token,
    )
    .await;
    assert_eq!(client, Some(12));
    let times = times.lock().expect("attempt times");
    assert_eq!(times.len(), 12);
    let gaps: Vec<Duration> = times.windows(2).map(|pair| pair[1] - pair[0]).collect();
    let expected = vec![
        Duration::from_secs(5),
        Duration::from_secs(10),
        Duration::from_secs(20),
        Duration::from_secs(40),
        Duration::from_secs(80),
        Duration::from_secs(160),
        Duration::from_secs(300),
        Duration::from_secs(300),
        Duration::from_secs(300),
        Duration::from_secs(300),
        Duration::from_secs(300),
    ];
    assert_eq!(
        gaps, expected,
        "5 s doubling per failure, held at the 300 s ceiling, and no gap above it"
    );
    assert!(gaps.iter().all(|gap| *gap <= BOOTSTRAP_MAX_DELAY));
}

/// A registry entry for the group named by the caller.
fn assigned(bridges: Vec<BridgeLine>) -> Assigned {
    Assigned {
        bridges,
        overlaps: false,
        short: false,
    }
}

/// A registry seeded with the one group named by the caller.
fn seeded(name: &str, bridges: Vec<BridgeLine>) -> Arc<GroupBridges> {
    GroupBridges::new(&BTreeMap::from([(name.to_owned(), assigned(bridges))]))
}

#[tokio::test(start_paused = true)]
async fn the_first_attempt_uses_the_bridge_claimed_before_it() {
    let token = CancellationToken::new();
    let dead = pool(1);
    let free = pool(2)[1].clone();
    let registry = seeded("edge", dead.clone());
    let mut bridges = dead.clone();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&seen);
    let (client, prepared) = bootstrap_group(
        &registry,
        "edge",
        &main_settings(),
        &mut bridges,
        || Some(vec![free.clone()]),
        |settings| {
            let recorder = Arc::clone(&recorder);
            async move {
                recorder
                    .lock()
                    .expect("attempts")
                    .push(settings.bridges.clone());
                Ok::<u32, anyhow::Error>(7)
            }
        },
        &token,
    )
    .await
    .expect("no configuration error")
    .expect("bootstrapped");
    assert_eq!(client, 7);
    assert_eq!(
        seen.lock().expect("attempts").clone(),
        vec![vec![free.clone()]],
        "the very first attempt already runs on the claimed bridge"
    );
    assert_eq!(prepared.settings.bridges, vec![free.clone()]);
    assert_eq!(bridges, [free], "the group keeps what it claimed");
}

#[tokio::test(start_paused = true)]
async fn a_retry_claims_the_bridge_the_process_offers_in_the_meantime() {
    let token = CancellationToken::new();
    let dead = pool(1);
    let free = pool(2)[1].clone();
    let registry = seeded("edge", dead.clone());
    let mut bridges = dead.clone();
    let calls = Arc::new(AtomicU32::new(0));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let working_calls = Arc::clone(&calls);
    let recorder = Arc::clone(&seen);
    let offered = free.clone();
    let (_, prepared) = bootstrap_group(
        &registry,
        "edge",
        &main_settings(),
        &mut bridges,
        move || {
            if working_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                Some(Vec::new())
            } else {
                Some(vec![offered.clone()])
            }
        },
        |settings| {
            let recorder = Arc::clone(&recorder);
            async move {
                let first = recorder.lock().expect("attempts").is_empty();
                recorder
                    .lock()
                    .expect("attempts")
                    .push(settings.bridges.clone());
                if first {
                    return Err(anyhow::anyhow!("the dead bridge does not answer"));
                }
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
        vec![dead.clone(), vec![free.clone()]],
        "the failed attempt kept the dead bridge, the retry claimed the free one"
    );
    assert_eq!(prepared.settings.bridges, [free]);
}

#[tokio::test(start_paused = true)]
async fn a_group_that_can_never_have_a_client_stops_instead_of_retrying() {
    let token = CancellationToken::new();
    let mut main = main_settings();
    main.state_dir = None;
    let dead = pool(1);
    let registry = seeded("edge", dead.clone());
    let mut bridges = dead.clone();
    let attempts = Arc::new(AtomicU32::new(0));
    let counter = Arc::clone(&attempts);
    let result = tokio::time::timeout(
        Duration::from_secs(600),
        bootstrap_group(
            &registry,
            "edge",
            &main,
            &mut bridges,
            || None,
            |_| {
                let counter = Arc::clone(&counter);
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Ok::<(), anyhow::Error>(())
                }
            },
            &token,
        ),
    )
    .await
    .expect("a configuration error must stop the loop instead of retrying forever");
    assert!(
        result.is_err(),
        "a group without a state directory cannot have a client"
    );
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        0,
        "no bootstrap attempt is made for a configuration error"
    );
}

#[test]
fn the_start_window_doubles_per_restart_and_stops_at_its_ceiling() {
    assert_eq!(start_window(0), GROUP_START_WINDOW);
    assert_eq!(start_window(1), GROUP_START_WINDOW * 2);
    assert_eq!(
        start_window(2),
        (GROUP_START_WINDOW * 4).min(GROUP_START_WINDOW_MAX)
    );
    assert_eq!(start_window(9), GROUP_START_WINDOW_MAX);
    assert_eq!(start_window(u32::MAX), GROUP_START_WINDOW_MAX);
}
