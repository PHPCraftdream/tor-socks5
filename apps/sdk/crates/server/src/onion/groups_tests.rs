use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use arti_wrapper::Settings;
use bridge_line::BridgeLine;
use proxy_config::{OnionServiceEntry, OnionServicePort};

use super::{assign_bridges, group_settings, split_entries, GroupPlan};

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
        "b needs the 4th bridge of a pool of 3"
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
