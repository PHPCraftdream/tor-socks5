// @@ begin test lint list maintained by maint/add_warning @@
#![allow(clippy::bool_assert_comparison)]
#![allow(clippy::clone_on_copy)]
#![allow(clippy::dbg_macro)]
#![allow(clippy::mixed_attributes_style)]
#![allow(clippy::print_stderr)]
#![allow(clippy::print_stdout)]
#![allow(clippy::single_char_pattern)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::unchecked_time_subtraction)]
#![allow(clippy::useless_vec)]
#![allow(clippy::needless_pass_by_value)]
//! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
use super::*;
use crate::ids::FirstHopId;
use tor_linkspec::{HasRelayIds, RelayId};
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use web_time_compat::SystemTimeExt;

#[test]
fn crate_id() {
    let id = CrateId::this_crate().unwrap();
    assert_eq!(&id.crate_name, "tor-guardmgr");
    assert_eq!(Some(id.version.as_ref()), option_env!("CARGO_PKG_VERSION"));
}

fn basic_id() -> GuardId {
    GuardId::new([13; 32].into(), [37; 20].into())
}
fn basic_guard() -> Guard {
    let id = basic_id();
    let ports = vec!["127.0.0.7:7777".parse().unwrap()];
    let added = SystemTime::get();
    Guard::new(id, ports, None, added)
}

// tor-socks5 local patch: verify the directory-info accessor that backs the
// aggregated guard-usable signal (GuardSet::any_guard_usable_for_traffic).
#[test]
fn has_complete_dir_info_accessor() {
    let mut g = basic_guard();
    assert!(g.usable());
    // A freshly-created guard has no missing directory information.
    assert!(g.has_complete_dir_info());
    // Simulate the guard-exhaustion case: the guard is listed, but we lack
    // its microdescriptor.
    g.dir_info_missing = true;
    assert!(!g.has_complete_dir_info());
    g.dir_info_missing = false;
    assert!(g.has_complete_dir_info());
}

#[test]
fn simple_accessors() {
    fn ed(id: [u8; 32]) -> RelayId {
        RelayId::Ed25519(id.into())
    }
    let id = basic_id();
    let g = basic_guard();

    assert_eq!(g.guard_id(), &id);
    assert!(g.same_relay_ids(&FirstHopId::in_sample(GuardSetSelector::Default, id)));
    assert_eq!(
        g.addrs().collect_vec(),
        &["127.0.0.7:7777".parse().unwrap()]
    );
    assert_eq!(g.reachable(), Reachable::Untried);
    assert_eq!(g.reachable(), Reachable::default());

    use crate::GuardUsageBuilder;
    let mut usage1 = GuardUsageBuilder::new();

    usage1
        .restrictions()
        .push(GuardRestriction::AvoidId(ed([22; 32])));
    let usage1 = usage1.build().unwrap();
    let mut usage2 = GuardUsageBuilder::new();
    usage2
        .restrictions()
        .push(GuardRestriction::AvoidId(ed([13; 32])));
    let usage2 = usage2.build().unwrap();
    let usage3 = GuardUsage::default();
    let mut usage4 = GuardUsageBuilder::new();
    usage4
        .restrictions()
        .push(GuardRestriction::AvoidId(ed([22; 32])));
    usage4
        .restrictions()
        .push(GuardRestriction::AvoidId(ed([13; 32])));
    let usage4 = usage4.build().unwrap();
    let mut usage5 = GuardUsageBuilder::new();
    usage5.restrictions().push(GuardRestriction::AvoidAllIds(
        vec![ed([22; 32]), ed([13; 32])].into_iter().collect(),
    ));
    let usage5 = usage5.build().unwrap();
    let mut usage6 = GuardUsageBuilder::new();
    usage6.restrictions().push(GuardRestriction::AvoidAllIds(
        vec![ed([99; 32]), ed([100; 32])].into_iter().collect(),
    ));
    let usage6 = usage6.build().unwrap();

    assert!(g.conforms_to_usage(&usage1));
    assert!(!g.conforms_to_usage(&usage2));
    assert!(g.conforms_to_usage(&usage3));
    assert!(!g.conforms_to_usage(&usage4));
    assert!(!g.conforms_to_usage(&usage5));
    assert!(g.conforms_to_usage(&usage6));
}

#[allow(clippy::redundant_clone)]
#[test]
fn trickier_usages() {
    let g = basic_guard();
    use crate::{GuardUsageBuilder, GuardUsageKind};
    let data_usage = GuardUsageBuilder::new()
        .kind(GuardUsageKind::Data)
        .build()
        .unwrap();
    let dir_usage = GuardUsageBuilder::new()
        .kind(GuardUsageKind::OneHopDirectory)
        .build()
        .unwrap();
    assert!(g.conforms_to_usage(&data_usage));
    assert!(g.conforms_to_usage(&dir_usage));

    let mut g2 = g.clone();
    g2.dir_info_missing = true;
    assert!(!g2.conforms_to_usage(&data_usage));
    assert!(g2.conforms_to_usage(&dir_usage));

    let mut g3 = g.clone();
    g3.is_dir_cache = false;
    assert!(g3.conforms_to_usage(&data_usage));
    assert!(!g3.conforms_to_usage(&dir_usage));
}

#[test]
fn record_attempt() {
    let t1 = Instant::get() - Duration::from_secs(10);
    let t2 = Instant::get() - Duration::from_secs(5);
    let t3 = Instant::get();

    let mut g = basic_guard();

    assert!(g.last_tried_to_connect_at.is_none());
    g.record_attempt(t1);
    assert_eq!(g.last_tried_to_connect_at, Some(t1));
    g.record_attempt(t3);
    assert_eq!(g.last_tried_to_connect_at, Some(t3));
    g.record_attempt(t2);
    assert_eq!(g.last_tried_to_connect_at, Some(t3));
}

#[test]
fn record_failure() {
    let t1 = Instant::get() - Duration::from_secs(10);
    let t2 = Instant::get();

    let mut g = basic_guard();
    g.record_failure(t1, true);
    assert!(g.retry_schedule.is_some());
    assert_eq!(g.reachable(), Reachable::Unreachable);
    let retry1 = g.retry_at.unwrap();
    assert_eq!(retry1, t1 + Duration::from_secs(30));

    g.record_failure(t2, true);
    let retry2 = g.retry_at.unwrap();
    assert!(retry2 >= t2 + Duration::from_secs(30));
    assert!(retry2 <= t2 + Duration::from_secs(200));
}

#[test]
fn record_success() {
    let t1 = Instant::get() - Duration::from_secs(10);
    // has to be in the future, since the guard's "added_at" time is based on now.
    let now = SystemTime::get();
    let t2 = now + Duration::from_secs(300 * 86400);
    let t3 = Instant::get() + Duration::from_secs(310 * 86400);
    let t4 = now + Duration::from_secs(320 * 86400);

    let mut g = basic_guard();
    g.record_failure(t1, true);
    assert_eq!(g.reachable(), Reachable::Unreachable);

    let conf = g.record_success(t2, &GuardParams::default());
    assert_eq!(g.reachable(), Reachable::Reachable);
    assert_eq!(conf, NewlyConfirmed::Yes);
    assert!(g.retry_at.is_none());
    assert!(g.confirmed_at.unwrap() <= t2);
    assert!(g.confirmed_at.unwrap() >= t2 - Duration::from_secs(12 * 86400));
    let confirmed_at_orig = g.confirmed_at;

    g.record_failure(t3, true);
    assert_eq!(g.reachable(), Reachable::Unreachable);

    let conf = g.record_success(t4, &GuardParams::default());
    assert_eq!(conf, NewlyConfirmed::No);
    assert_eq!(g.reachable(), Reachable::Reachable);
    assert!(g.retry_at.is_none());
    assert_eq!(g.confirmed_at, confirmed_at_orig);
}

#[test]
fn retry() {
    let t1 = Instant::get();
    let mut g = basic_guard();

    g.record_failure(t1, true);
    assert!(g.retry_at.is_some());
    assert_eq!(g.reachable(), Reachable::Unreachable);

    // Not yet retriable.
    g.consider_retry(t1);
    assert!(g.retry_at.is_some());
    assert_eq!(g.reachable(), Reachable::Unreachable);

    // Not retriable right before the retry time.
    g.consider_retry(g.retry_at.unwrap() - Duration::from_secs(1));
    assert!(g.retry_at.is_some());
    assert_eq!(g.reachable(), Reachable::Unreachable);

    // Retriable right after the retry time.
    g.consider_retry(g.retry_at.unwrap() + Duration::from_secs(1));
    assert!(g.retry_at.is_none());
    assert_eq!(g.reachable(), Reachable::Retriable);
}

#[test]
fn expiration() {
    const DAY: Duration = Duration::from_secs(24 * 60 * 60);
    let params = GuardParams::default();
    let now = SystemTime::get();

    let g = basic_guard();
    assert!(!g.is_expired(&params, now));
    assert!(!g.is_expired(&params, now + 10 * DAY));
    assert!(!g.is_expired(&params, now + 25 * DAY));
    assert!(!g.is_expired(&params, now + 70 * DAY));
    assert!(g.is_expired(&params, now + 200 * DAY)); // lifetime_unconfirmed.

    let mut g = basic_guard();
    let _ = g.record_success(now, &params);
    assert!(!g.is_expired(&params, now));
    assert!(!g.is_expired(&params, now + 10 * DAY));
    assert!(!g.is_expired(&params, now + 25 * DAY));
    assert!(g.is_expired(&params, now + 70 * DAY)); // lifetime_confirmed.

    let mut g = basic_guard();
    g.mark_unlisted(now);
    assert!(!g.is_expired(&params, now));
    assert!(!g.is_expired(&params, now + 10 * DAY));
    assert!(g.is_expired(&params, now + 25 * DAY)); // lifetime_unlisted
}

#[test]
fn netdir_integration() {
    use tor_netdir::testnet;
    let netdir = testnet::construct_netdir().unwrap_if_sufficient().unwrap();
    let params = GuardParams::default();
    let now = SystemTime::get();

    // Construct a guard from a relay from the netdir.
    let relay22 = netdir.by_id(&Ed25519Identity::from([22; 32])).unwrap();
    let guard22 = Guard::from_chan_target(&relay22, now, &params);
    assert!(guard22.same_relay_ids(&relay22));
    assert!(Some(guard22.added_at) <= Some(now));

    // Can we still get the relay back?
    let id = FirstHopId::in_sample(GuardSetSelector::Default, guard22.id);
    let r = id.get_relay(&netdir).unwrap();
    assert!(r.same_relay_ids(&relay22));

    // Now try a guard that isn't in the netdir.
    let guard255 = Guard::new(
        GuardId::new([255; 32].into(), [255; 20].into()),
        vec![],
        None,
        now,
    );
    let id = FirstHopId::in_sample(GuardSetSelector::Default, guard255.id);
    assert!(id.get_relay(&netdir).is_none());
}

#[test]
fn update_from_netdir() {
    use tor_netdir::testnet;
    let netdir = testnet::construct_netdir().unwrap_if_sufficient().unwrap();
    // Same as above but omit [22]
    let netdir2 = testnet::construct_custom_netdir(|idx, node, _| {
        if idx == 22 {
            node.omit_rs = true;
        }
    })
    .unwrap()
    .unwrap_if_sufficient()
    .unwrap();
    // Same as above but omit [22] as well as MD for [23].
    let netdir3 = testnet::construct_custom_netdir(|idx, node, _| {
        if idx == 22 {
            node.omit_rs = true;
        } else if idx == 23 {
            node.omit_md = true;
        }
    })
    .unwrap()
    .unwrap_if_sufficient()
    .unwrap();

    //let params = GuardParams::default();
    let now = SystemTime::get();

    // Try a guard that isn't in the netdir at all.
    let mut guard255 = Guard::new(
        GuardId::new([255; 32].into(), [255; 20].into()),
        vec!["8.8.8.8:53".parse().unwrap()],
        None,
        now,
    );
    assert_eq!(guard255.unlisted_since, None);
    assert_eq!(guard255.listed_in(&netdir), Some(false));
    guard255.update_from_universe(&netdir);
    assert_eq!(
        guard255.unlisted_since,
        Some(netdir.lifetime().valid_after())
    );
    assert!(!guard255.orports.is_empty());

    // Try a guard that is in netdir, but not netdir2.
    let mut guard22 = Guard::new(
        GuardId::new([22; 32].into(), [22; 20].into()),
        vec![],
        None,
        now,
    );
    let id22: FirstHopId = FirstHopId::in_sample(GuardSetSelector::Default, guard22.id.clone());
    let relay22 = id22.get_relay(&netdir).unwrap();
    assert_eq!(guard22.listed_in(&netdir), Some(true));
    guard22.update_from_universe(&netdir);
    assert_eq!(guard22.unlisted_since, None); // It's listed.
    assert_eq!(guard22.orports, relay22.addrs().collect_vec()); // Addrs are set.
    assert_eq!(guard22.listed_in(&netdir2), Some(false));
    guard22.update_from_universe(&netdir2);
    assert_eq!(
        guard22.unlisted_since,
        Some(netdir2.lifetime().valid_after())
    );
    assert_eq!(guard22.orports, relay22.addrs().collect_vec()); // Addrs still set.
    assert!(!guard22.dir_info_missing);

    // Now see what happens for a guard that's in the consensus, but missing an MD.
    let mut guard23 = Guard::new(
        GuardId::new([23; 32].into(), [23; 20].into()),
        vec![],
        None,
        now,
    );
    assert_eq!(guard23.listed_in(&netdir2), Some(true));
    assert_eq!(guard23.listed_in(&netdir3), None);
    guard23.update_from_universe(&netdir3);
    assert!(guard23.dir_info_missing);
    assert!(guard23.is_dir_cache);
}

#[test]
fn pending() {
    let mut g = basic_guard();
    let t1 = Instant::get();
    let t2 = t1 + Duration::from_secs(100);
    let t3 = t1 + Duration::from_secs(200);

    assert!(!g.exploratory_attempt_after(t1));
    assert!(!g.exploratory_circ_pending());

    g.note_exploratory_circ(true);
    g.record_attempt(t2);
    assert!(g.exploratory_circ_pending());
    assert!(g.exploratory_attempt_after(t1));
    assert!(!g.exploratory_attempt_after(t3));

    g.note_exploratory_circ(false);
    assert!(!g.exploratory_circ_pending());
    assert!(!g.exploratory_attempt_after(t1));
    assert!(!g.exploratory_attempt_after(t3));
}

#[test]
fn circ_history() {
    let mut h = CircHistory {
        n_successes: 3,
        n_failures: 4,
        n_indeterminate: 3,
    };
    assert!(h.indeterminate_ratio().is_none());

    h.n_successes = 20;
    assert!((h.indeterminate_ratio().unwrap() - 3.0 / 23.0).abs() < 0.0001);
}

#[test]
fn disable_on_failure() {
    let mut g = basic_guard();
    let params = GuardParams::default();

    let now = SystemTime::get();

    let _ignore = g.record_success(now, &params);
    for _ in 0..13 {
        g.record_indeterminate_result();
    }
    // We're still under the observation threshold.
    assert!(g.disabled.is_none());

    // This crosses the threshold.
    g.record_indeterminate_result();
    assert!(g.disabled.is_some());

    #[allow(unreachable_patterns)]
    match g.disabled.unwrap().into_option().unwrap() {
        GuardDisabled::TooManyIndeterminateFailures {
            history: _,
            failure_ratio,
            threshold_ratio,
        } => {
            assert!((failure_ratio - 0.933).abs() < 0.01);
            assert!((threshold_ratio - 0.7).abs() < 0.01);
        }
        other => {
            panic!("Wrong variant: {:?}", other);
        }
    }
}

// tor-socks5 local patch: verify the reset-disabled primitive that an
// application-level watchdog uses to recover a permanently-disabled guard.
#[test]
fn reset_disabled() {
    let mut g = basic_guard();
    let params = GuardParams::default();
    let now = SystemTime::get();

    // A fresh, healthy guard is not disabled; resetting it is a no-op that
    // returns false and must not touch anything.
    assert!(!g.reset_disabled());
    assert!(g.disabled.is_none());

    // Drive the guard into the disabled state (mirror `disable_on_failure`):
    // 1 success + 14 indeterminate => 15 observations, ratio 14/15 ~= 0.93.
    let _ignore = g.record_success(now, &params);
    for _ in 0..14 {
        g.record_indeterminate_result();
    }
    assert!(g.disabled.is_some());
    assert_eq!(g.circ_history.n_successes, 1);
    assert_eq!(g.circ_history.n_indeterminate, 14);

    // Reset: disabled clears, history clears, suspicious-warn flag clears,
    // and the call reports that a guard was re-enabled.
    assert!(g.reset_disabled());
    assert!(g.disabled.is_none());
    assert_eq!(g.circ_history.n_successes, 0);
    assert_eq!(g.circ_history.n_indeterminate, 0);

    // After reset we are back below MIN_OBSERVATIONS, so a single new
    // indeterminate result must NOT re-disable the guard: it gets a genuine
    // fresh start rather than being immediately re-tripped by the old
    // accumulated numerator. (This is exactly why the history is reset and
    // not just `disabled`.)
    g.record_indeterminate_result();
    assert!(g.disabled.is_none());

    // A healthy guard with no disable stays a no-op even after activity.
    assert!(!g.reset_disabled());
}

#[test]
fn mark_retriable() {
    let mut g = basic_guard();
    use super::Reachable::*;

    assert_eq!(g.reachable(), Untried);

    for (pre, post) in &[
        (Untried, Untried),
        (Unreachable, Retriable),
        (Reachable, Reachable),
    ] {
        g.reachable = *pre;
        g.mark_retriable();
        assert_eq!(g.reachable(), *post);
    }
}

#[test]
fn dir_status() {
    // We're going to see how directory failures interact with circuit
    // failures.

    use crate::GuardUsageBuilder;
    let mut g = basic_guard();
    let inst = Instant::get();
    let st = SystemTime::get();
    let sec = Duration::from_secs(1);
    let params = GuardParams::default();
    let dir_usage = GuardUsageBuilder::new()
        .kind(GuardUsageKind::OneHopDirectory)
        .build()
        .unwrap();
    let data_usage = GuardUsage::default();

    // Record a circuit success.
    let _ = g.record_success(st, &params);
    assert_eq!(g.next_retry(&dir_usage), None);
    assert!(g.ready_for_usage(&dir_usage, inst));
    assert_eq!(g.next_retry(&data_usage), None);
    assert!(g.ready_for_usage(&data_usage, inst));

    // Record a dircache failure.  This does not influence data usage.
    g.record_external_failure(ExternalActivity::DirCache, inst);
    assert_eq!(g.next_retry(&data_usage), None);
    assert!(g.ready_for_usage(&data_usage, inst));
    let next_dir_retry = g.next_retry(&dir_usage).unwrap();
    assert!(next_dir_retry >= inst + GUARD_DIR_RETRY_FLOOR);
    assert!(!g.ready_for_usage(&dir_usage, inst));
    assert!(g.ready_for_usage(&dir_usage, next_dir_retry));

    // Record a circuit success again.  This does not make the guard usable
    // as a directory cache.
    let _ = g.record_success(st, &params);
    assert!(g.ready_for_usage(&data_usage, inst));
    assert!(!g.ready_for_usage(&dir_usage, inst));

    // Record a circuit failure.
    g.record_failure(inst + sec * 10, true);
    let next_circ_retry = g.next_retry(&data_usage).unwrap();
    assert!(!g.ready_for_usage(&data_usage, inst + sec * 10));
    assert!(!g.ready_for_usage(&dir_usage, inst + sec * 10));
    assert_eq!(
        g.next_retry(&dir_usage).unwrap(),
        std::cmp::max(next_circ_retry, next_dir_retry)
    );

    // Record a directory success.  This won't supersede the circuit
    // failure.
    g.record_external_success(ExternalActivity::DirCache);
    assert_eq!(g.next_retry(&data_usage).unwrap(), next_circ_retry);
    assert_eq!(g.next_retry(&dir_usage).unwrap(), next_circ_retry);
    assert!(!g.ready_for_usage(&dir_usage, inst + sec * 10));
    assert!(!g.ready_for_usage(&data_usage, inst + sec * 10));
}
