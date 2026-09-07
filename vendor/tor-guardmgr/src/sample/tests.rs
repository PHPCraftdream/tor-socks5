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
    use tor_linkspec::{HasRelayIds, RelayIdType};
    use tor_netdir::NetDir;
    use tor_netdoc::doc::netstatus::RelayWeight;
    use tor_netdoc::types::relay_flags::RelayFlag;
    use web_time_compat::{InstantExt, SystemTimeExt};

    use super::*;
    use crate::FirstHopId;
    use std::time::Duration;

    fn netdir() -> NetDir {
        use tor_netdir::testnet;
        testnet::construct_netdir().unwrap_if_sufficient().unwrap()
    }

    #[test]
    fn sample_test() {
        // Make a test network that gives every relay equal weight, and which
        // has 20 viable (Guard + V2Dir + DirCache=2) candidates.  Otherwise the
        // calculation of collision probability at the end of this function is
        // too tricky.
        let netdir = tor_netdir::testnet::construct_custom_netdir(|idx, builder, _| {
            // Give every node equal bandwidth.
            builder.rs.weight(RelayWeight::Measured(1000));
            // The default network has 40 relays, and the first 10 are
            // not Guard by default.
            if idx >= 10 {
                builder.rs.add_flags(RelayFlag::Guard);
                if idx >= 20 {
                    builder.rs.protos("DirCache=2".parse().unwrap());
                } else {
                    builder.rs.protos("".parse().unwrap());
                }
            }
        })
        .unwrap()
        .unwrap_if_sufficient()
        .unwrap();
        // Make sure that we got the numbers we expected.
        assert_eq!(40, netdir.relays().count());
        assert_eq!(
            30,
            netdir
                .relays()
                .filter(|r| r.low_level_details().is_suitable_as_guard())
                .count()
        );
        assert_eq!(
            20,
            netdir
                .relays()
                .filter(|r| r.low_level_details().is_suitable_as_guard()
                    && r.low_level_details().is_dir_cache())
                .count()
        );

        let params = GuardParams {
            min_filtered_sample_size: 5,
            max_sample_bw_fraction: 1.0,
            ..GuardParams::default()
        };

        let mut samples: Vec<HashSet<GuardId>> = Vec::new();
        for _ in 0..3 {
            let mut guards = GuardSet::default();
            guards.extend_sample_as_needed(SystemTime::get(), &params, &netdir);
            assert_eq!(guards.guards.len(), params.min_filtered_sample_size);
            assert_eq!(guards.confirmed.len(), 0);
            assert_eq!(guards.primary.len(), 0);
            guards.assert_consistency();

            // make sure all the guards are okay.
            for guard in guards.guards.values() {
                let id = FirstHopId::in_sample(GuardSetSelector::Default, guard.guard_id().clone());
                let relay = id.get_relay(&netdir).unwrap();
                assert!(relay.low_level_details().is_suitable_as_guard());
                assert!(relay.low_level_details().is_dir_cache());
                assert!(guards.guards.by_all_ids(&relay).is_some());
                {
                    assert!(!guard.is_expired(&params, SystemTime::get()));
                }
            }

            // Make sure that the sample doesn't expand any further.
            guards.extend_sample_as_needed(SystemTime::get(), &params, &netdir);
            assert_eq!(guards.guards.len(), params.min_filtered_sample_size);
            guards.assert_consistency();

            samples.push(guards.sample.into_iter().collect());
        }

        // The probability of getting the same sample 3 times in a row is (20 choose 5)^-2,
        // which is pretty low.  (About 1 in 240 million.)
        assert!(samples[0] != samples[1] || samples[1] != samples[2]);
    }

    #[test]
    fn persistence() {
        let netdir = netdir();
        let params = GuardParams {
            min_filtered_sample_size: 5,
            ..GuardParams::default()
        };

        let t1 = SystemTime::get();
        let t2 = t1 + Duration::from_secs(20);

        let mut guards = GuardSet::default();
        guards.extend_sample_as_needed(t1, &params, &netdir);

        // Pick a guard and mark it as confirmed.
        let id1 = guards.sample[0].clone();
        guards.record_success(&id1, &params, None, t2);
        assert_eq!(&guards.confirmed, std::slice::from_ref(&id1));

        // Encode the guards, then decode them.
        let state: GuardSample = (&guards).into();
        let guards2: GuardSet = state.into();

        assert_eq!(&guards2.sample, &guards.sample);
        assert_eq!(&guards2.confirmed, &guards.confirmed);
        assert_eq!(&guards2.confirmed, &[id1]);
        assert_eq!(
            guards
                .guards
                .values()
                .map(Guard::guard_id)
                .collect::<HashSet<_>>(),
            guards2
                .guards
                .values()
                .map(Guard::guard_id)
                .collect::<HashSet<_>>()
        );
        for g in guards.guards.values() {
            let g2 = guards2.guards.by_all_ids(g.guard_id()).unwrap();
            assert_eq!(format!("{:?}", g), format!("{:?}", g2));
        }
    }

    #[test]
    fn select_primary() {
        let netdir = netdir();
        let params = GuardParams {
            min_filtered_sample_size: 5,
            n_primary: 4,
            ..GuardParams::default()
        };
        let t1 = SystemTime::get();
        let t2 = t1 + Duration::from_secs(20);
        let t3 = t2 + Duration::from_secs(30);

        let mut guards = GuardSet::default();
        guards.extend_sample_as_needed(t1, &params, &netdir);

        // Pick a guard and mark it as confirmed.
        let id3 = guards.sample[3].clone();
        guards.record_success(&id3, &params, None, t2);
        assert_eq!(&guards.confirmed, std::slice::from_ref(&id3));
        let id1 = guards.sample[1].clone();
        guards.record_success(&id1, &params, None, t3);
        assert_eq!(&guards.confirmed, &[id3.clone(), id1.clone()]);

        // Select primary guards and make sure we're obeying the rules.
        guards.select_primary_guards(&params);
        assert_eq!(guards.primary.len(), 4);
        assert_eq!(&guards.primary[0], &id3);
        assert_eq!(&guards.primary[1], &id1);
        let p3 = guards.primary[2].clone();
        let p4 = guards.primary[3].clone();
        assert_eq!(
            [id1.clone(), id3.clone(), p3.clone(), p4.clone()]
                .iter()
                .unique()
                .count(),
            4
        );

        // Mark another guard as confirmed and see that the list changes to put
        // that guard right after the previously confirmed guards, but we keep
        // one of the previous unconfirmed primary guards.
        guards.record_success(&p4, &params, None, t3);
        assert_eq!(&guards.confirmed, &[id3.clone(), id1.clone(), p4.clone()]);
        guards.select_primary_guards(&params);
        assert_eq!(guards.primary.len(), 4);
        assert_eq!(&guards.primary[0], &id3);
        assert_eq!(&guards.primary[1], &id1);
        assert_eq!(&guards.primary, &[id3, id1, p4, p3]);
    }

    #[test]
    fn expiration() {
        let netdir = netdir();
        let params = GuardParams::default();
        let t1 = SystemTime::get();

        let mut guards = GuardSet::default();
        guards.extend_sample_as_needed(t1, &params, &netdir);
        // note that there are only 10 Guard+V2Dir nodes in the netdir().
        assert_eq!(guards.sample.len(), 10);

        // Mark one guard as confirmed; it will have a different timeout.
        // Pick a guard and mark it as confirmed.
        let id1 = guards.sample[0].clone();
        guards.record_success(&id1, &params, None, t1);
        assert_eq!(&guards.confirmed, &[id1]);

        let one_day = Duration::from_secs(86400);
        guards.expire_old_guards(&params, t1 + one_day * 30);
        assert_eq!(guards.sample.len(), 10); // nothing has expired.

        // This is long enough to make sure that the confirmed guard has expired.
        guards.expire_old_guards(&params, t1 + one_day * 70);
        assert_eq!(guards.sample.len(), 9);

        guards.expire_old_guards(&params, t1 + one_day * 200);
        assert_eq!(guards.sample.len(), 0);
    }

    // tor-socks5 local patch: verify the aggregated "guards usable" signal that
    // gates arti-client's BootstrapStatus::ready_for_traffic(). This is the core
    // of the guard-exhaustion-spiral fix: when every sampled guard lacks a
    // microdescriptor the aggregate must be false, even though the guards are
    // still listed (usable()).
    #[test]
    fn any_guard_usable_for_traffic_aggregation() {
        let netdir = netdir();
        let params = GuardParams {
            n_primary: 4,
            ..GuardParams::default()
        };
        let mut guards = GuardSet::default();
        guards.extend_sample_as_needed(SystemTime::get(), &params, &netdir);
        guards.select_primary_guards(&params);

        // Normal case: sampled guards carry complete directory information, so
        // the active sample is usable for traffic.
        assert!(guards.any_guard_usable_for_traffic());

        // Guard-exhaustion spiral: every guard lacks a microdescriptor. The
        // guards are still listed (usable()), but none can build data circuits,
        // so the aggregate must be false — the exact condition that must keep
        // BootstrapStatus::ready_for_traffic() reporting "not ready".
        guards.set_all_guards_dir_info_missing_for_test(true);
        assert!(!guards.any_guard_usable_for_traffic());

        // Once guards regain their descriptors, the sample becomes usable again.
        guards.set_all_guards_dir_info_missing_for_test(false);
        assert!(guards.any_guard_usable_for_traffic());
    }

    // tor-socks5 local patch: verify the adaptive widening of the
    // descriptor-request parallelism when the guard sample is exhausted. With
    // a usable guard present, `descriptors_to_request` must honor the
    // conservative top-N cap; with none usable, it must request the whole
    // eligible sample so a reachable bridge is not starved behind dead/slow
    // bridges earlier in preference order.
    #[cfg(feature = "bridge-client")]
    #[test]
    fn descriptors_to_request_adaptive_parallelism() {
        let netdir = netdir();
        let params = GuardParams {
            min_filtered_sample_size: 5,
            // keep `data_parallelism` at its default of 1 so `maximum` is the
            // MINIMUM floor of 2 — small enough to be observably narrower than
            // the 5-guard sample.
            ..GuardParams::default()
        };
        let now = Instant::get();
        let mut guards = GuardSet::default();
        guards.extend_sample_as_needed(SystemTime::get(), &params, &netdir);
        guards.select_primary_guards(&params);

        // `data_parallelism=1` ⇒ maximum = max(1, 2) = 2, well below the
        // 5-guard sample, so the cap is observable.
        let maximum = std::cmp::max(params.data_parallelism, 2);
        assert_eq!(maximum, 2);
        assert!(guards.guards.len() > maximum);

        // Normal case: sampled guards carry complete directory information, so
        // at least one is usable for traffic — the conservative cap applies.
        assert!(guards.any_guard_usable_for_traffic());
        assert_eq!(
            guards.descriptors_to_request(now, &params).len(),
            maximum,
            "conservative cap must bind when a usable guard exists"
        );

        // Guard-exhaustion spiral: every guard lacks a descriptor, so none is
        // usable for traffic. The adaptive path must widen past the cap so the
        // bridges beyond the top-2 also get descriptor requests.
        guards.set_all_guards_dir_info_missing_for_test(true);
        assert!(!guards.any_guard_usable_for_traffic());
        let n_exhausted = guards.descriptors_to_request(now, &params).len();
        assert!(
            n_exhausted > maximum,
            "exhaustion must widen parallelism beyond the {maximum}-guard cap, got {n_exhausted}"
        );

        // Recovery: once a guard regains its descriptor, the conservative cap
        // snaps back.
        guards.set_all_guards_dir_info_missing_for_test(false);
        assert!(guards.any_guard_usable_for_traffic());
        assert_eq!(
            guards.descriptors_to_request(now, &params).len(),
            maximum,
            "conservative cap must return once a guard becomes usable"
        );
    }

    // tor-socks5 local patch: regression test for the narrow-vs-wide
    // oscillation livelock (docs/checkpoints/obfs4-connect-investigation.md).
    // A guard outside the top-`maximum` cutoff is the *only* one that has a
    // descriptor. Once that flips `any_guard_usable_for_traffic()` true, a
    // plain `.take(maximum)` would drop that guard from every subsequent
    // request (it is not in the top-2 by preference order) — and
    // `tor_dirmgr::bridgedesc::set_bridges` treats "not in the requested
    // set" as "forget this bridge's descriptor", flipping the signal back to
    // false and re-widening forever. The fix must keep requesting this guard
    // on the narrow pass because it already has a complete descriptor.
    #[cfg(feature = "bridge-client")]
    #[test]
    fn descriptors_to_request_retains_out_of_band_descriptor() {
        let netdir = netdir();
        let params = GuardParams {
            min_filtered_sample_size: 5,
            ..GuardParams::default()
        };
        let now = Instant::get();
        let mut guards = GuardSet::default();
        guards.extend_sample_as_needed(SystemTime::get(), &params, &netdir);
        guards.select_primary_guards(&params);

        let maximum = std::cmp::max(params.data_parallelism, 2);
        assert_eq!(maximum, 2);
        assert!(guards.guards.len() > maximum);

        // Rank-`maximum` among *eligible* guards (same filter
        // `descriptors_to_request` applies) -- i.e. the first guard just
        // past the conservative cutoff. `usable()`/reachability/filter
        // eligibility does not depend on `dir_info_missing`, so this rank is
        // the same before and after exhausting descriptors below.
        let data_usage = GuardUsage::default();
        let recovered_id = guards
            .preference_order()
            .filter(|(_, g)| {
                g.usable()
                    && g.reachable() != Reachable::Unreachable
                    && g.ready_for_usage(&data_usage, now)
                    && guards.active_filter.permits(*g)
            })
            .nth(maximum)
            .expect("sample has more than `maximum` eligible guards")
            .1
            .guard_id()
            .clone();

        // Exhaust every guard, then hand exactly the rank-`maximum` guard
        // its descriptor back. That is the guard that must survive
        // narrowing.
        guards.set_all_guards_dir_info_missing_for_test(true);
        guards.set_guard_dir_info_missing_for_test(&recovered_id, false);
        assert!(
            guards.any_guard_usable_for_traffic(),
            "the one recovered guard must make the sample usable again"
        );

        // Narrow pass: the recovered guard must still be present even though
        // its preference-order rank is `maximum` (i.e. one past the cutoff).
        let requested = guards.descriptors_to_request(now, &params);
        assert!(
            requested.iter().any(|g| g.guard_id() == &recovered_id),
            "a guard with a complete descriptor must never be dropped from \
             the requested set, or set_bridges() will forget it and re-open \
             the oscillation"
        );
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn sampling_and_usage() {
        let netdir = netdir();
        let params = GuardParams {
            min_filtered_sample_size: 5,
            n_primary: 2,
            ..GuardParams::default()
        };
        let st1 = SystemTime::get();
        let i1 = Instant::get();
        let sec = Duration::from_secs(1);

        let mut guards = GuardSet::default();
        guards.extend_sample_as_needed(st1, &params, &netdir);
        guards.select_primary_guards(&params);

        // First guard: try it, and let it fail.
        let usage = crate::GuardUsageBuilder::default().build().unwrap();
        let id1 = guards.primary[0].clone();
        let id2 = guards.primary[1].clone();
        let (src, id) = guards.pick_guard_id(&usage, &params, i1).unwrap();
        assert_eq!(src, ListKind::Primary);
        assert_eq!(&id, &id1);

        guards.record_attempt(&id, i1);
        guards.record_failure(&id, None, i1 + sec);

        // Second guard: try it, and try it again, and have it fail.
        let (src, id) = guards.pick_guard_id(&usage, &params, i1 + sec).unwrap();
        assert_eq!(src, ListKind::Primary);
        assert_eq!(&id, &id2);
        guards.record_attempt(&id, i1 + sec);

        let (src, id_x) = guards.pick_guard_id(&usage, &params, i1 + sec).unwrap();
        // We get the same guard this (second) time that we pick it too, since
        // it is a primary guard, and is_pending won't block it.
        assert_eq!(id_x, id);
        assert_eq!(src, ListKind::Primary);
        guards.record_attempt(&id_x, i1 + sec * 2);
        guards.record_failure(&id_x, None, i1 + sec * 3);
        guards.record_failure(&id, None, i1 + sec * 4);

        // Third guard: this one won't be primary.
        let (src, id3) = guards.pick_guard_id(&usage, &params, i1 + sec * 4).unwrap();
        assert_eq!(src, ListKind::Sample);
        assert!(!guards.primary.contains(&id3));
        guards.record_attempt(&id3, i1 + sec * 5);

        // Fourth guard: Third guard will be pending, so a different one gets
        // handed out here.
        let (src, id4) = guards.pick_guard_id(&usage, &params, i1 + sec * 5).unwrap();
        assert_eq!(src, ListKind::Sample);
        assert!(id3 != id4);
        assert!(!guards.primary.contains(&id4));
        guards.record_attempt(&id4, i1 + sec * 6);

        // Look at usability status: primary guards should be usable
        // immediately; third guard should be too (since primary
        // guards are down).  Fourth should not have a known status,
        // since third is pending.
        assert_eq!(
            guards.circ_usability_status(&id1, &usage, &params, i1 + sec * 6),
            Some(true)
        );
        assert_eq!(
            guards.circ_usability_status(&id2, &usage, &params, i1 + sec * 6),
            Some(true)
        );
        assert_eq!(
            guards.circ_usability_status(&id3, &usage, &params, i1 + sec * 6),
            Some(true)
        );
        assert_eq!(
            guards.circ_usability_status(&id4, &usage, &params, i1 + sec * 6),
            None
        );

        // Have both guards succeed.
        guards.record_success(&id3, &params, None, st1 + sec * 7);
        guards.record_success(&id4, &params, None, st1 + sec * 8);

        // Check the impact of having both guards succeed.
        assert!(guards.primary_guards_invalidated);
        guards.select_primary_guards(&params);
        assert_eq!(&guards.primary, &[id3.clone(), id4.clone()]);

        // Next time we ask for a guard, we get a primary guard again.
        let (src, id) = guards
            .pick_guard_id(&usage, &params, i1 + sec * 10)
            .unwrap();
        assert_eq!(src, ListKind::Primary);
        assert_eq!(&id, &id3);

        // If we ask for a directory guard, we get one of the primaries.
        let mut found = HashSet::new();
        let usage = crate::GuardUsageBuilder::default()
            .kind(crate::GuardUsageKind::OneHopDirectory)
            .build()
            .unwrap();
        for _ in 0..64 {
            let (src, id) = guards
                .pick_guard_id(&usage, &params, i1 + sec * 10)
                .unwrap();
            assert_eq!(src, ListKind::Primary);
            assert_eq!(
                guards.circ_usability_status(&id, &usage, &params, i1 + sec * 10),
                Some(true)
            );
            guards.record_attempt_abandoned(&id);
            found.insert(id);
        }
        assert!(found.len() == 2);
        assert!(found.contains(&id3));
        assert!(found.contains(&id4));

        // Since the primaries are now up, other guards are not usable.
        assert_eq!(
            guards.circ_usability_status(&id1, &usage, &params, i1 + sec * 12),
            Some(false)
        );
        assert_eq!(
            guards.circ_usability_status(&id2, &usage, &params, i1 + sec * 12),
            Some(false)
        );
    }

    #[test]
    fn everybodys_down() {
        let netdir = netdir();
        let params = GuardParams {
            min_filtered_sample_size: 5,
            n_primary: 2,
            max_sample_bw_fraction: 1.0,
            ..GuardParams::default()
        };
        let mut st = SystemTime::get();
        let mut inst = Instant::get();
        let sec = Duration::from_secs(1);
        let usage = crate::GuardUsageBuilder::default().build().unwrap();

        let mut guards = GuardSet::default();

        guards.extend_sample_as_needed(st, &params, &netdir);
        guards.select_primary_guards(&params);

        assert_eq!(guards.sample.len(), 5);
        for _ in 0..5 {
            let (_, id) = guards.pick_guard_id(&usage, &params, inst).unwrap();
            guards.record_attempt(&id, inst);
            guards.record_failure(&id, None, inst + sec);

            inst += sec * 2;
            st += sec * 2;
        }

        let e = guards.pick_guard_id(&usage, &params, inst);
        assert!(matches!(e, Err(PickGuardError::AllGuardsDown { .. })));

        // Now in theory we should re-grow when we extend.
        guards.extend_sample_as_needed(st, &params, &netdir);
        guards.select_primary_guards(&params);
        assert_eq!(guards.sample.len(), 10);
    }

    #[test]
    fn retry_primary() {
        let netdir = netdir();
        let params = GuardParams {
            min_filtered_sample_size: 5,
            n_primary: 2,
            max_sample_bw_fraction: 1.0,
            ..GuardParams::default()
        };
        let usage = crate::GuardUsageBuilder::default().build().unwrap();

        let mut guards = GuardSet::default();

        guards.extend_sample_as_needed(SystemTime::get(), &params, &netdir);
        guards.select_primary_guards(&params);

        assert_eq!(guards.primary.len(), 2);
        assert!(!guards.all_primary_guards_are_unreachable());

        // Let one primary guard fail.
        let (kind, p_id1) = guards
            .pick_guard_id(&usage, &params, Instant::get())
            .unwrap();
        assert_eq!(kind, ListKind::Primary);
        guards.record_failure(&p_id1, None, Instant::get());
        assert!(!guards.all_primary_guards_are_unreachable());

        // Now let the other one fail.
        let (kind, p_id2) = guards
            .pick_guard_id(&usage, &params, Instant::get())
            .unwrap();
        assert_eq!(kind, ListKind::Primary);
        guards.record_failure(&p_id2, None, Instant::get());
        assert!(guards.all_primary_guards_are_unreachable());

        // Now mark the guards retriable.
        guards.mark_primary_guards_retriable();
        assert!(!guards.all_primary_guards_are_unreachable());
        let (kind, p_id3) = guards
            .pick_guard_id(&usage, &params, Instant::get())
            .unwrap();
        assert_eq!(kind, ListKind::Primary);
        assert_eq!(p_id3, p_id1);
    }

    #[test]
    fn count_missing_mds() {
        let netdir = netdir();
        let params = GuardParams {
            min_filtered_sample_size: 5,
            n_primary: 2,
            max_sample_bw_fraction: 1.0,
            ..GuardParams::default()
        };
        let usage = crate::GuardUsageBuilder::default().build().unwrap();
        let mut guards = GuardSet::default();
        guards.extend_sample_as_needed(SystemTime::get(), &params, &netdir);
        guards.select_primary_guards(&params);
        assert_eq!(guards.primary.len(), 2);

        let (_kind, p_id1) = guards
            .pick_guard_id(&usage, &params, Instant::get())
            .unwrap();
        guards.record_success(&p_id1, &params, None, SystemTime::get());
        assert_eq!(guards.n_primary_without_id_info_in(&netdir), 0);

        use tor_netdir::testnet;
        let netdir2 = testnet::construct_custom_netdir(|_idx, bld, _| {
            let md_so_far = bld.md.testing_md().expect("Couldn't build md?");
            if &p_id1.0.identity(RelayIdType::Ed25519).unwrap() == md_so_far.ed25519_id() {
                bld.omit_md = true;
            }
        })
        .unwrap()
        .unwrap_if_sufficient()
        .unwrap();

        assert_eq!(guards.n_primary_without_id_info_in(&netdir2), 1);
    }

    #[test]
    fn copy_status() {
        let netdir = netdir();
        let params = GuardParams {
            min_filtered_sample_size: 5,
            n_primary: 2,
            max_sample_bw_fraction: 1.0,
            ..GuardParams::default()
        };
        let mut guards1 = GuardSet::default();
        guards1.extend_sample_as_needed(SystemTime::get(), &params, &netdir);
        guards1.select_primary_guards(&params);
        let mut guards2 = guards1.clone();

        // Make a persistent change in guards1, and a different persistent change in guards2.
        let id1 = guards1.primary[0].clone();
        let id2 = guards1.primary[1].clone();
        guards1.record_success(&id1, &params, None, SystemTime::get());
        guards2.record_success(&id2, &params, None, SystemTime::get());
        // Make a non-persistent change in guards2.
        guards2.record_failure(&id2, None, Instant::get());

        // Copy status: make sure non-persistent status changed, and  persistent didn't.
        guards1.copy_ephemeral_status_into_newly_loaded_state(guards2);
        {
            let g1 = guards1.get(&id1).unwrap();
            let g2 = guards1.get(&id2).unwrap();
            assert!(g1.confirmed());
            assert!(!g2.confirmed());
            assert_eq!(g1.reachable(), Reachable::Untried);
            assert_eq!(g2.reachable(), Reachable::Unreachable);
        }

        // Now make a new set of unrelated guards, and make sure that copying
        // from it doesn't change the membership of guards1.
        let mut guards3 = GuardSet::default();
        let g1_set: HashSet<_> = guards1
            .guards
            .values()
            .map(|g| g.guard_id().clone())
            .collect();
        let mut g3_set: HashSet<_> = HashSet::new();
        for _ in 0..4 {
            // There is roughly a 1-in-5000 chance of getting the same set
            // twice, so we loop until that doesn't happen.
            guards3.extend_sample_as_needed(SystemTime::get(), &params, &netdir);
            guards3.select_primary_guards(&params);
            g3_set = guards3
                .guards
                .values()
                .map(|g| g.guard_id().clone())
                .collect();

            // There is roughly a 1-in-5000 chance of getting the same set twice, so
            if g1_set == g3_set {
                guards3 = GuardSet::default();
                continue;
            }
            break;
        }
        assert_ne!(g1_set, g3_set);
        // Do the copy; make sure that the membership is unchanged.
        guards1.copy_ephemeral_status_into_newly_loaded_state(guards3);
        let g1_set_new: HashSet<_> = guards1
            .guards
            .values()
            .map(|g| g.guard_id().clone())
            .collect();
        assert_eq!(g1_set, g1_set_new);
    }
