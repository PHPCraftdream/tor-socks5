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
use tor_linkspec::{HasAddrs, HasRelayIds};
use tor_persist::TestingStateMgr;
use tor_rtcompat::test_with_all_runtimes;

#[test]
fn guard_param_defaults() {
    let p1 = GuardParams::default();
    let p2: GuardParams = (&NetParameters::default()).try_into().unwrap();
    assert_eq!(p1, p2);
}

fn init<R: Runtime>(rt: R) -> (GuardMgr<R>, TestingStateMgr, NetDir) {
    use tor_netdir::{MdReceiver, PartialNetDir, testnet};
    let statemgr = TestingStateMgr::new();
    let have_lock = statemgr.try_lock().unwrap();
    assert!(have_lock.held());
    let guardmgr = GuardMgr::new(rt, statemgr.clone(), &TestConfig::default()).unwrap();
    let (con, mds) = testnet::construct_network().unwrap();
    let param_overrides = vec![
        // We make the sample size smaller than usual to compensate for the
        // small testing network.  (Otherwise, we'd sample the whole network,
        // and not be able to observe guards in the tests.)
        "guard-min-filtered-sample-size=5",
        // We choose only two primary guards, to make the tests easier to write.
        "guard-n-primary-guards=2",
        // We define any restriction that allows 75% or fewer of relays as "meaningful",
        // so that we can test the "restrictive" guard sample behavior, and to avoid
        "guard-meaningful-restriction-percent=75",
    ];
    let param_overrides: String =
        itertools::Itertools::intersperse(param_overrides.into_iter(), " ").collect();
    let override_p = param_overrides.parse().unwrap();
    let mut netdir = PartialNetDir::new(con, Some(&override_p));
    for md in mds {
        netdir.add_microdesc(md);
    }
    let netdir = netdir.unwrap_if_sufficient().unwrap();

    (guardmgr, statemgr, netdir)
}

#[test]
#[allow(clippy::clone_on_copy)]
fn simple_case() {
    test_with_all_runtimes!(|rt| async move {
        let (guardmgr, statemgr, netdir) = init(rt.clone());
        let usage = GuardUsage::default();
        guardmgr.install_test_netdir(&netdir);

        let (id, mon, usable) = guardmgr.select_guard(usage).unwrap();
        // Report that the circuit succeeded.
        mon.succeeded();

        // May we use the circuit?
        let usable = usable.await.unwrap();
        assert!(usable);

        // Save the state...
        guardmgr.flush_msg_queue().await;
        guardmgr.store_persistent_state().unwrap();
        drop(guardmgr);

        // Try reloading from the state...
        let guardmgr2 =
            GuardMgr::new(rt.clone(), statemgr.clone(), &TestConfig::default()).unwrap();
        guardmgr2.install_test_netdir(&netdir);

        // Since the guard was confirmed, we should get the same one this time!
        let usage = GuardUsage::default();
        let (id2, _mon, _usable) = guardmgr2.select_guard(usage).unwrap();
        assert!(id2.same_relay_ids(&id));
    });
}

#[test]
fn simple_waiting() {
    // TODO(nickm): This test fails in rare cases; I suspect a
    // race condition somewhere.
    //
    // I've doubled up on the queue flushing in order to try to make the
    // race less likely, but we should investigate.
    test_with_all_runtimes!(|rt| async move {
        let (guardmgr, _statemgr, netdir) = init(rt);
        let u = GuardUsage::default();
        guardmgr.install_test_netdir(&netdir);

        // We'll have the first two guard fail, which should make us
        // try a non-primary guard.
        let (id1, mon, _usable) = guardmgr.select_guard(u.clone()).unwrap();
        mon.failed();
        guardmgr.flush_msg_queue().await; // avoid race
        guardmgr.flush_msg_queue().await; // avoid race
        let (id2, mon, _usable) = guardmgr.select_guard(u.clone()).unwrap();
        mon.failed();
        guardmgr.flush_msg_queue().await; // avoid race
        guardmgr.flush_msg_queue().await; // avoid race

        assert!(!id1.same_relay_ids(&id2));

        // Now we should get two sampled guards. They should be different.
        let (id3, mon3, usable3) = guardmgr.select_guard(u.clone()).unwrap();
        let (id4, mon4, usable4) = guardmgr.select_guard(u.clone()).unwrap();
        assert!(!id3.same_relay_ids(&id4));

        let (u3, u4) = futures::join!(
            async {
                mon3.failed();
                guardmgr.flush_msg_queue().await; // avoid race
                usable3.await.unwrap()
            },
            async {
                mon4.succeeded();
                usable4.await.unwrap()
            }
        );

        assert_eq!((u3, u4), (false, true));
    });
}

#[test]
fn filtering_basics() {
    test_with_all_runtimes!(|rt| async move {
        let (guardmgr, _statemgr, netdir) = init(rt);
        let u = GuardUsage::default();
        let filter = {
            let mut f = GuardFilter::default();
            // All the addresses in the test network are {0,1,2,3,4}.0.0.3:9001.
            // Limit to only 2.0.0.0/8
            f.push_reachable_addresses(vec!["2.0.0.0/8:9001".parse().unwrap()]);
            f
        };
        guardmgr.set_filter(filter);
        guardmgr.install_test_netdir(&netdir);
        let (guard, _mon, _usable) = guardmgr.select_guard(u).unwrap();
        // Make sure that the filter worked.
        let addr = guard.addrs().next().unwrap();
        assert_eq!(addr, "2.0.0.3:9001".parse().unwrap());
    });
}

#[test]
fn external_status() {
    test_with_all_runtimes!(|rt| async move {
        let (guardmgr, _statemgr, netdir) = init(rt);
        let data_usage = GuardUsage::default();
        let dir_usage = GuardUsageBuilder::new()
            .kind(GuardUsageKind::OneHopDirectory)
            .build()
            .unwrap();
        guardmgr.install_test_netdir(&netdir);
        {
            // Override this parameter, so that we can get deterministic results below.
            let mut inner = guardmgr.inner.lock().unwrap();
            inner.params.dir_parallelism = 1;
        }

        let (guard, mon, _usable) = guardmgr.select_guard(data_usage.clone()).unwrap();
        mon.succeeded();

        // Record that this guard gave us a bad directory object.
        guardmgr.note_external_failure(&guard, ExternalActivity::DirCache);

        // We ask for another guard, for data usage.  We should get the same
        // one as last time, since the director failure doesn't mean this
        // guard is useless as a primary guard.
        let (g2, mon, _usable) = guardmgr.select_guard(data_usage).unwrap();
        assert_eq!(g2.ed_identity(), guard.ed_identity());
        mon.succeeded();

        // But if we ask for a guard for directory usage, we should get a
        // different one, since the last guard we gave out failed.
        let (g3, mon, _usable) = guardmgr.select_guard(dir_usage.clone()).unwrap();
        assert_ne!(g3.ed_identity(), guard.ed_identity());
        mon.succeeded();

        // Now record a success for directory usage.
        guardmgr.note_external_success(&guard, ExternalActivity::DirCache);

        // Now that the guard is working as a cache, asking for it should get us the same guard.
        let (g4, _mon, _usable) = guardmgr.select_guard(dir_usage).unwrap();
        assert_eq!(g4.ed_identity(), guard.ed_identity());
    });
}

#[cfg(feature = "bridge-client")]
#[test]
fn bridge_descriptorless_guard_is_retriable_not_internal() {
    // Regression test for the vendor patch: when a bridge guard is picked
    // for Data usage but has no descriptor (circ-target), the error must be
    // AllGuardsDown (→ RetryTime::AfterWaiting) not Internal (→
    // RetryTime::Never). Additionally, select_guard_with_expand must retry
    // unconditionally after update_guardset_internal recomputes the guard's
    // dir_info_missing, not only when the sample grew (ExtendedStatus::Yes).
    test_with_all_runtimes!(|rt| async move {
        let statemgr = TestingStateMgr::new();
        let have_lock = statemgr.try_lock().unwrap();
        assert!(have_lock.held());

        // A single configured bridge with NO descriptor fetched yet.
        // A direct (non-PT) bridge line so pt-client isn't required.
        let bridge: crate::bridge::BridgeConfig =
            "38.229.33.83:80 0BAC39417268B96B9F514E7F63FA6FBA1A788955"
                .parse()
                .unwrap();
        let config = TestConfig {
            bridges: vec![bridge],
            ..TestConfig::default()
        };

        let guardmgr = GuardMgr::new(rt, statemgr, &config).unwrap();

        // The bridge must have been sampled during GuardMgr::new.
        {
            let inner = guardmgr.inner.lock().expect("Poisoned lock");
            assert!(
                inner.guards.bridges.n_sampled_for_test() > 0,
                "bridge was not sampled; test setup needs fixing"
            );
        }

        // Inject the production stale state that triggers the bug: a guard
        // whose cached dir_info_missing is false (so pick_guard selects it)
        // while the live descriptor is absent (so lookup_bridge_circ_target
        // finds no circ-target). Without this injection, the freshly-
        // sampled descriptor-less bridge is already filtered out by
        // pick_guard (dir_info_missing=true from update_from_universe).
        {
            let mut inner = guardmgr.inner.lock().expect("Poisoned lock");
            inner
                .guards
                .bridges
                .set_all_guards_dir_info_missing_for_test(false);
        }

        // GuardUsage::default() is GuardUsageKind::Data.
        let res = guardmgr.select_guard(GuardUsage::default());

        // Pre-fix: PickGuardError::Internal → RetryTime::Never (abort).
        // Post-fix: PickGuardError::AllGuardsDown → RetryTime::AfterWaiting.
        assert!(
            matches!(res, Err(PickGuardError::AllGuardsDown { .. })),
            "expected AllGuardsDown (retriable), got {:?}",
            res
        );
    });
}

#[cfg(feature = "bridge-client")]
#[test]
fn reenabled_bridge_is_retried_without_resetting_active_failures() {
    tor_rtmock::MockRuntime::test_with_various(|rt| async move {
        let statemgr = TestingStateMgr::new();
        assert!(statemgr.try_lock().unwrap().held());
        let bridges: Vec<bridge::BridgeConfig> = [
            "192.0.2.1:443 1111111111111111111111111111111111111111",
            "192.0.2.2:443 2222222222222222222222222222222222222222",
        ]
        .into_iter()
        .map(|line| line.parse().unwrap())
        .collect();
        let config = TestConfig {
            bridges: bridges.clone(),
            ..Default::default()
        };
        let guardmgr = GuardMgr::new(rt, statemgr, &config).unwrap();
        let usage = GuardUsageBuilder::default()
            .kind(GuardUsageKind::OneHopDirectory)
            .build()
            .unwrap();
        for _ in 0..2 {
            let (_, monitor, _) = guardmgr.select_guard(usage.clone()).unwrap();
            monitor.failed();
            guardmgr.flush_msg_queue().await;
        }
        assert!(guardmgr.select_guard(usage.clone()).is_err());
        guardmgr.reconfigure(&config).unwrap();
        assert!(guardmgr.select_guard(usage.clone()).is_err());

        let narrowed = TestConfig {
            bridges: vec![bridges[0].clone()],
            ..Default::default()
        };
        guardmgr.reconfigure(&narrowed).unwrap();
        assert!(guardmgr.select_guard(usage.clone()).is_err());
        guardmgr.reconfigure(&config).unwrap();
        let (guard, monitor, _) = guardmgr.select_guard(usage.clone()).expect(
            "re-enabling a bridge must allow a fresh attempt without restarting the client",
        );
        assert_eq!(guard.rsa_identity(), bridges[1].rsa_identity());
        monitor.failed();
        guardmgr.flush_msg_queue().await;
        assert!(guardmgr.select_guard(usage).is_err());
    });
}

#[cfg(feature = "bridge-client")]
#[test]
fn disabled_identity_stays_blocked_after_bridge_reconfiguration() {
    tor_rtmock::MockRuntime::test_with_various(|rt| async move {
        let state = TestingStateMgr::new();
        assert!(state.try_lock().unwrap().held());
        let bridge: bridge::BridgeConfig = "192.0.2.7:443 7777777777777777777777777777777777777777"
            .parse()
            .unwrap();
        let config = TestConfig {
            bridges: vec![bridge.clone()],
            ..Default::default()
        };
        let manager = GuardMgr::new(rt, state, &config).unwrap();
        assert!(!manager.guard_is_disabled(&bridge));
        {
            let mut inner = manager.inner.lock().unwrap();
            let hop = inner.lookup_ids(&bridge).into_iter().next().unwrap();
            let FirstHopIdInner::Guard(_, id) = hop.0 else {
                panic!("configured bridge must be a guard");
            };
            for _ in 0..32 {
                inner.guards.bridges.record_indeterminate_result(&id);
                if inner.guards.bridges.guard_is_disabled(&id) {
                    break;
                }
            }
        }
        assert!(manager.guard_is_disabled(&bridge));
        manager.reconfigure(&TestConfig::default()).unwrap();
        manager.reconfigure(&config).unwrap();
        assert!(manager.guard_is_disabled(&bridge));
    });
}

#[cfg(feature = "vanguards")]
#[test]
fn vanguard_mode_ord() {
    assert!(VanguardMode::Disabled < VanguardMode::Lite);
    assert!(VanguardMode::Disabled < VanguardMode::Full);
    assert!(VanguardMode::Lite < VanguardMode::Full);
}
