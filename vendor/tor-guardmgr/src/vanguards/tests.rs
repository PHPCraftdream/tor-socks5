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

    use std::{fmt, time};

    use set::TimeBoundVanguard;
    use tor_config::ExplicitOrAuto;
    use tor_relay_selection::RelayExclusion;

    use super::*;

    use Layer::*;
    use tor_basic_utils::test_rng::testing_rng;
    use tor_linkspec::{HasRelayIds, RelayIds};
    use tor_netdir::{
        testnet::{self, construct_custom_netdir_with_params},
        testprovider::TestNetDirProvider,
    };
    use tor_persist::FsStateMgr;
    use tor_rtmock::MockRuntime;

    use itertools::Itertools;

    /// Enable lite vanguards for onion services.
    const ENABLE_LITE_VANGUARDS: [(&str, i32); 1] = [("vanguards-hs-service", 1)];

    /// Enable full vanguards for hidden services.
    const ENABLE_FULL_VANGUARDS: [(&str, i32); 1] = [("vanguards-hs-service", 2)];

    /// A valid vanguard state file.
    const VANGUARDS_JSON: &str = include_str!("../testdata/vanguards.json");

    /// A invalid vanguard state file.
    const INVALID_VANGUARDS_JSON: &str = include_str!("../testdata/vanguards_invalid.json");

    /// Create the `StateMgr`, populating the vanguards.json state file with the specified JSON string.
    fn state_dir_with_vanguards(vanguards_json: &str) -> (FsStateMgr, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("state")).unwrap();
        std::fs::write(dir.path().join("state/vanguards.json"), vanguards_json).unwrap();

        let statemgr = FsStateMgr::from_path_and_mistrust(
            dir.path(),
            &fs_mistrust::Mistrust::new_dangerously_trust_everyone(),
        )
        .unwrap();

        (statemgr, dir)
    }

    impl fmt::Debug for Vanguard<'_> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.debug_struct("Vanguard").finish()
        }
    }

    impl Inner {
        /// Return the L2 vanguard set.
        pub(super) fn l2_vanguards(&self) -> &Vec<TimeBoundVanguard> {
            self.vanguard_sets.l2_vanguards()
        }

        /// Return the L3 vanguard set.
        pub(super) fn l3_vanguards(&self) -> &Vec<TimeBoundVanguard> {
            self.vanguard_sets.l3_vanguards()
        }
    }

    /// Return a maximally permissive RelaySelector for a vanguard.
    fn permissive_selector() -> RelaySelector<'static> {
        RelaySelector::new(
            tor_relay_selection::RelayUsage::vanguard(),
            RelayExclusion::no_relays_excluded(),
        )
    }

    /// Look up the vanguard in the specified VanguardSet.
    fn find_in_set<R: Runtime>(
        relay_ids: &RelayIds,
        mgr: &VanguardMgr<R>,
        layer: Layer,
    ) -> Option<TimeBoundVanguard> {
        let inner = mgr.inner.read().unwrap();

        let vanguards = match layer {
            Layer2 => inner.l2_vanguards(),
            Layer3 => inner.l3_vanguards(),
        };

        // Look up the TimeBoundVanguard that corresponds to this Vanguard,
        // and figure out its expiry.
        vanguards.iter().find(|v| v.id == *relay_ids).cloned()
    }

    /// Get the total number of vanguard entries (L2 + L3).
    fn vanguard_count<R: Runtime>(mgr: &VanguardMgr<R>) -> usize {
        let inner = mgr.inner.read().unwrap();
        inner.l2_vanguards().len() + inner.l3_vanguards().len()
    }

    /// Return a `Duration` representing how long until this vanguard expires.
    fn duration_until_expiry<R: Runtime>(
        relay_ids: &RelayIds,
        mgr: &VanguardMgr<R>,
        runtime: &R,
        layer: Layer,
    ) -> Duration {
        // Look up the TimeBoundVanguard that corresponds to this Vanguard,
        // and figure out its expiry.
        let vanguard = find_in_set(relay_ids, mgr, layer).unwrap();

        vanguard
            .when
            .duration_since(runtime.wallclock())
            .unwrap_or_default()
    }

    /// Assert the lifetime of the specified `vanguard` is within the bounds of its `layer`.
    fn assert_expiry_in_bounds<R: Runtime>(
        vanguard: &Vanguard<'_>,
        mgr: &VanguardMgr<R>,
        runtime: &R,
        params: &VanguardParams,
        layer: Layer,
    ) {
        let (min, max) = match layer {
            Layer2 => (params.l2_lifetime_min(), params.l2_lifetime_max()),
            Layer3 => (params.l3_lifetime_min(), params.l3_lifetime_max()),
        };

        let vanguard = RelayIds::from_relay_ids(vanguard.relay());
        // This is not exactly the lifetime of the vanguard,
        // but rather the time left until it expires (but it's close enough for our purposes).
        let lifetime = duration_until_expiry(&vanguard, mgr, runtime, layer);

        assert!(
            lifetime >= min && lifetime <= max,
            "lifetime {lifetime:?} not between {min:?} and {max:?}",
        );
    }

    /// Assert that the vanguard manager's pools are empty.
    fn assert_sets_empty<R: Runtime>(vanguardmgr: &VanguardMgr<R>) {
        let inner = vanguardmgr.inner.read().unwrap();
        // The sets are initially empty, and the targets are set to 0
        assert_eq!(inner.vanguard_sets.l2_vanguards_deficit(), 0);
        assert_eq!(inner.vanguard_sets.l3_vanguards_deficit(), 0);
        assert_eq!(vanguard_count(vanguardmgr), 0);
    }

    /// Assert that the vanguard manager's pools have been filled.
    fn assert_sets_filled<R: Runtime>(vanguardmgr: &VanguardMgr<R>, params: &VanguardParams) {
        let inner = vanguardmgr.inner.read().unwrap();
        let l2_pool_size = params.l2_pool_size();
        // The sets are initially empty
        assert_eq!(inner.vanguard_sets.l2_vanguards_deficit(), 0);

        if inner.mode == VanguardMode::Full {
            assert_eq!(inner.vanguard_sets.l3_vanguards_deficit(), 0);
            let l3_pool_size = params.l3_pool_size();
            assert_eq!(vanguard_count(vanguardmgr), l2_pool_size + l3_pool_size);
        }
    }

    /// Assert the target size of the specified vanguard set matches the target from `params`.
    fn assert_set_vanguards_targets_match_params<R: Runtime>(
        mgr: &VanguardMgr<R>,
        params: &VanguardParams,
    ) {
        let inner = mgr.inner.read().unwrap();
        assert_eq!(
            inner.vanguard_sets.l2_vanguards_target(),
            params.l2_pool_size()
        );
        if inner.mode == VanguardMode::Full {
            assert_eq!(
                inner.vanguard_sets.l3_vanguards_target(),
                params.l3_pool_size()
            );
        }
    }

    #[test]
    fn full_vanguards_disabled() {
        MockRuntime::test_with_various(|rt| async move {
            let vanguardmgr = VanguardMgr::new_testing(&rt, VanguardMode::Lite).unwrap();
            let netdir = testnet::construct_netdir().unwrap_if_sufficient().unwrap();
            let mut rng = testing_rng();
            // Wait until the vanguard manager has bootstrapped
            // (otherwise we'll get a BootstrapRequired error)
            let _netdir_provider = vanguardmgr.init_vanguard_sets(&netdir).await.unwrap();

            // Cannot select an L3 vanguard when running in "Lite" mode.
            let err = vanguardmgr
                .select_vanguard(&mut rng, &netdir, Layer3, &permissive_selector())
                .unwrap_err();
            assert!(
                matches!(
                    err,
                    VanguardMgrError::LayerNotSupported {
                        layer: Layer::Layer3,
                        mode: VanguardMode::Lite
                    }
                ),
                "{err}"
            );
        });
    }

    #[test]
    fn background_task_not_spawned() {
        MockRuntime::test_with_various(|rt| async move {
            let vanguardmgr = VanguardMgr::new_testing(&rt, VanguardMode::Lite).unwrap();
            let netdir = testnet::construct_netdir().unwrap_if_sufficient().unwrap();
            let mut rng = testing_rng();

            // The sets are initially empty
            assert_sets_empty(&vanguardmgr);

            // VanguardMgr::launch_background tasks was not called, so select_vanguard will return
            // an error (because the vanguard sets are empty)
            let err = vanguardmgr
                .select_vanguard(&mut rng, &netdir, Layer2, &permissive_selector())
                .unwrap_err();

            assert!(
                matches!(
                    err,
                    VanguardMgrError::BootstrapRequired {
                        action: "select vanguard"
                    }
                ),
                "{err:?}"
            );
        });
    }

    #[test]
    fn select_vanguards() {
        MockRuntime::test_with_various(|rt| async move {
            let vanguardmgr = VanguardMgr::new_testing(&rt, VanguardMode::Full).unwrap();

            let netdir = testnet::construct_netdir().unwrap_if_sufficient().unwrap();
            let params = VanguardParams::try_from(netdir.params()).unwrap();
            let mut rng = testing_rng();

            // The sets are initially empty
            assert_sets_empty(&vanguardmgr);

            // Wait until the vanguard manager has bootstrapped
            let _netdir_provider = vanguardmgr.init_vanguard_sets(&netdir).await.unwrap();

            assert_sets_filled(&vanguardmgr, &params);

            let vanguard1 = vanguardmgr
                .select_vanguard(&mut rng, &netdir, Layer2, &permissive_selector())
                .unwrap();
            assert_expiry_in_bounds(&vanguard1, &vanguardmgr, &rt, &params, Layer2);

            let exclusion = RelayExclusion::exclude_identities(
                vanguard1
                    .relay()
                    .identities()
                    .map(|id| id.to_owned())
                    .collect(),
            );
            let selector =
                RelaySelector::new(tor_relay_selection::RelayUsage::vanguard(), exclusion);

            let vanguard2 = vanguardmgr
                .select_vanguard(&mut rng, &netdir, Layer3, &selector)
                .unwrap();

            assert_expiry_in_bounds(&vanguard2, &vanguardmgr, &rt, &params, Layer3);
            // Ensure we didn't select the same vanguard twice
            assert_ne!(
                vanguard1.relay().identities().collect_vec(),
                vanguard2.relay().identities().collect_vec()
            );
        });
    }

    /// Override the vanguard params from the netdir, returning the new VanguardParams.
    ///
    /// This also waits until the vanguard manager has had a chance to process the changes.
    async fn install_new_params(
        rt: &MockRuntime,
        netdir_provider: &TestNetDirProvider,
        params: impl IntoIterator<Item = (&str, i32)>,
    ) -> VanguardParams {
        let new_netdir = testnet::construct_custom_netdir_with_params(|_, _, _| {}, params, None)
            .unwrap()
            .unwrap_if_sufficient()
            .unwrap();
        let new_params = VanguardParams::try_from(new_netdir.params()).unwrap();

        netdir_provider.set_netdir_and_notify(new_netdir).await;

        // Wait until the vanguard mgr has finished handling the new netdir.
        rt.progress_until_stalled().await;

        new_params
    }

    /// Switch the vanguard "mode" of the VanguardMgr to `mode`,
    /// by setting the vanguards-hs-service parameter.
    //
    // TODO(#1382): use this instead of switch_hs_mode_config.
    #[allow(unused)]
    async fn switch_hs_mode(
        rt: &MockRuntime,
        vanguardmgr: &VanguardMgr<MockRuntime>,
        netdir_provider: &TestNetDirProvider,
        mode: VanguardMode,
    ) {
        use VanguardMode::*;

        let _params = match mode {
            Lite => install_new_params(rt, netdir_provider, ENABLE_LITE_VANGUARDS).await,
            Full => install_new_params(rt, netdir_provider, ENABLE_FULL_VANGUARDS).await,
            Disabled => panic!("cannot disable vanguards in the vanguard tests!"),
        };

        assert_eq!(vanguardmgr.mode(), mode);
    }

    /// Switch the vanguard "mode" of the VanguardMgr to `mode`,
    /// by calling `VanguardMgr::reconfigure`.
    fn switch_hs_mode_config(vanguardmgr: &VanguardMgr<MockRuntime>, mode: VanguardMode) {
        let _ = vanguardmgr
            .reconfigure(&VanguardConfig {
                mode: ExplicitOrAuto::Explicit(mode),
            })
            .unwrap();

        assert_eq!(vanguardmgr.mode(), mode);
    }

    /// Use a new NetDir that excludes one of our L2 vanguards
    async fn install_netdir_excluding_vanguard<'a>(
        runtime: &MockRuntime,
        vanguard: &Vanguard<'_>,
        params: impl IntoIterator<Item = (&'a str, i32)>,
        netdir_provider: &TestNetDirProvider,
    ) -> NetDir {
        let new_netdir = construct_custom_netdir_with_params(
            |_idx, bld, _| {
                let md_so_far = bld.md.testing_md().unwrap();
                if md_so_far.ed25519_id() == vanguard.relay().id() {
                    bld.omit_rs = true;
                }
            },
            params,
            None,
        )
        .unwrap()
        .unwrap_if_sufficient()
        .unwrap();

        netdir_provider
            .set_netdir_and_notify(new_netdir.clone())
            .await;
        // Wait until the vanguard mgr has finished handling the new netdir.
        runtime.progress_until_stalled().await;

        new_netdir
    }

    #[test]
    fn override_vanguard_set_size() {
        MockRuntime::test_with_various(|rt| async move {
            let vanguardmgr = VanguardMgr::new_testing(&rt, VanguardMode::Lite).unwrap();
            let netdir = testnet::construct_netdir().unwrap_if_sufficient().unwrap();
            // Wait until the vanguard manager has bootstrapped
            let netdir_provider = vanguardmgr.init_vanguard_sets(&netdir).await.unwrap();

            let params = VanguardParams::try_from(netdir.params()).unwrap();
            let old_size = params.l2_pool_size();
            assert_set_vanguards_targets_match_params(&vanguardmgr, &params);

            const PARAMS: [[(&str, i32); 2]; 2] = [
                [("guard-hs-l2-number", 1), ("guard-hs-l3-number", 10)],
                [("guard-hs-l2-number", 10), ("guard-hs-l3-number", 10)],
            ];

            for params in PARAMS {
                let new_params = install_new_params(&rt, &netdir_provider, params).await;

                // Ensure the target size was updated.
                assert_set_vanguards_targets_match_params(&vanguardmgr, &new_params);
                {
                    let inner = vanguardmgr.inner.read().unwrap();
                    let l2_vanguards = inner.l2_vanguards();
                    let l3_vanguards = inner.l3_vanguards();
                    let new_l2_size = params[0].1 as usize;
                    if new_l2_size < old_size {
                        // The actual size of the set hasn't changed: it's OK to have more vanguards than
                        // needed in the set (they extraneous ones will eventually expire).
                        assert_eq!(l2_vanguards.len(), old_size);
                    } else {
                        // The new size is greater, so we have more L2 vanguards now.
                        assert_eq!(l2_vanguards.len(), new_l2_size);
                    }
                    // There are no L3 vanguards because full vanguards are not in use.
                    assert_eq!(l3_vanguards.len(), 0);
                }
            }
        });
    }

    #[test]
    fn expire_vanguards() {
        MockRuntime::test_with_various(|rt| async move {
            let vanguardmgr = VanguardMgr::new_testing(&rt, VanguardMode::Lite).unwrap();
            let netdir = testnet::construct_netdir().unwrap_if_sufficient().unwrap();
            let params = VanguardParams::try_from(netdir.params()).unwrap();
            let initial_l2_number = params.l2_pool_size();

            // Wait until the vanguard manager has bootstrapped
            let netdir_provider = vanguardmgr.init_vanguard_sets(&netdir).await.unwrap();
            assert_eq!(vanguard_count(&vanguardmgr), params.l2_pool_size());

            // Find the RelayIds of the vanguard that is due to expire next
            let vanguard_id = {
                let inner = vanguardmgr.inner.read().unwrap();
                let next_expiry = inner.vanguard_sets.next_expiry().unwrap();
                inner
                    .l2_vanguards()
                    .iter()
                    .find(|v| v.when == next_expiry)
                    .cloned()
                    .unwrap()
                    .id
            };

            const FEWER_VANGUARDS_PARAM: [(&str, i32); 1] = [("guard-hs-l2-number", 1)];
            // Set the number of L2 vanguards to a lower value to ensure the vanguard that is about
            // to expire is not replaced. This allows us to test that it has indeed expired
            // (we can't simply check that the relay is no longer is the set,
            // because it's possible for the set to get replenished with the same relay).
            let new_params = install_new_params(&rt, &netdir_provider, FEWER_VANGUARDS_PARAM).await;

            // The vanguard has not expired yet.
            let timebound_vanguard = find_in_set(&vanguard_id, &vanguardmgr, Layer2);
            assert!(timebound_vanguard.is_some());
            assert_eq!(vanguard_count(&vanguardmgr), initial_l2_number);

            let lifetime = duration_until_expiry(&vanguard_id, &vanguardmgr, &rt, Layer2);
            // Wait until this vanguard expires
            rt.advance_by(lifetime).await.unwrap();
            rt.progress_until_stalled().await;

            let timebound_vanguard = find_in_set(&vanguard_id, &vanguardmgr, Layer2);

            // The vanguard expired, but was not replaced.
            assert!(timebound_vanguard.is_none());
            assert_eq!(vanguard_count(&vanguardmgr), initial_l2_number - 1);

            // Wait until more vanguards expire. This will reduce the set size to 1
            // (the new target size we set by overriding the params).
            for _ in 0..initial_l2_number - 1 {
                let vanguard_id = {
                    let inner = vanguardmgr.inner.read().unwrap();
                    let next_expiry = inner.vanguard_sets.next_expiry().unwrap();
                    inner
                        .l2_vanguards()
                        .iter()
                        .find(|v| v.when == next_expiry)
                        .cloned()
                        .unwrap()
                        .id
                };
                let lifetime = duration_until_expiry(&vanguard_id, &vanguardmgr, &rt, Layer2);
                rt.advance_by(lifetime).await.unwrap();

                rt.progress_until_stalled().await;
            }

            assert_eq!(vanguard_count(&vanguardmgr), new_params.l2_pool_size());

            // Update the L2 set size again, to force the vanguard manager to replenish the L2 set.
            const MORE_VANGUARDS_PARAM: [(&str, i32); 1] = [("guard-hs-l2-number", 5)];
            // Set the number of L2 vanguards to a lower value to ensure the vanguard that is about
            // to expire is not replaced. This allows us to test that it has indeed expired
            // (we can't simply check that the relay is no longer is the set,
            // because it's possible for the set to get replenished with the same relay).
            let new_params = install_new_params(&rt, &netdir_provider, MORE_VANGUARDS_PARAM).await;

            // Check that we replaced the expired vanguard with a new one:
            assert_eq!(vanguard_count(&vanguardmgr), new_params.l2_pool_size());

            {
                let inner = vanguardmgr.inner.read().unwrap();
                let l2_count = inner.l2_vanguards().len();
                assert_eq!(l2_count, new_params.l2_pool_size());
            }
        });
    }

    #[test]
    fn full_vanguards_persistence() {
        MockRuntime::test_with_various(|rt| async move {
            let vanguardmgr = VanguardMgr::new_testing(&rt, VanguardMode::Lite).unwrap();

            let netdir =
                construct_custom_netdir_with_params(|_, _, _| {}, ENABLE_LITE_VANGUARDS, None)
                    .unwrap()
                    .unwrap_if_sufficient()
                    .unwrap();
            let netdir_provider = vanguardmgr.init_vanguard_sets(&netdir).await.unwrap();

            // Full vanguards are not enabled, so we don't expect anything to be written
            // to persistent storage.
            assert_eq!(vanguardmgr.mode(), VanguardMode::Lite);
            assert!(vanguardmgr.storage.load().unwrap().is_none());

            let mut rng = testing_rng();
            assert!(
                vanguardmgr
                    .select_vanguard(&mut rng, &netdir, Layer3, &permissive_selector())
                    .is_err()
            );

            // Enable full vanguards again.
            //
            // We expect VanguardMgr to populate the L3 set, and write the VanguardSets to storage.
            switch_hs_mode_config(&vanguardmgr, VanguardMode::Full);
            rt.progress_until_stalled().await;

            let vanguard_sets_orig = vanguardmgr.storage.load().unwrap();
            assert!(
                vanguardmgr
                    .select_vanguard(&mut rng, &netdir, Layer3, &permissive_selector())
                    .is_ok()
            );

            // Switch to lite vanguards.
            switch_hs_mode_config(&vanguardmgr, VanguardMode::Lite);

            // The vanguard sets should not change when switching between lite and full vanguards.
            assert_eq!(vanguard_sets_orig, vanguardmgr.storage.load().unwrap());
            switch_hs_mode_config(&vanguardmgr, VanguardMode::Full);
            assert_eq!(vanguard_sets_orig, vanguardmgr.storage.load().unwrap());

            // TODO HS-VANGUARDS: we may want to disable the ability to switch back to lite
            // vanguards.

            // Switch to lite vanguards and remove a relay from the consensus.
            // The relay should *not* be persisted to storage until we switch back to full
            // vanguards.
            switch_hs_mode_config(&vanguardmgr, VanguardMode::Lite);

            let mut rng = testing_rng();
            let excluded_vanguard = vanguardmgr
                .select_vanguard(&mut rng, &netdir, Layer2, &permissive_selector())
                .unwrap();

            let _ = install_netdir_excluding_vanguard(
                &rt,
                &excluded_vanguard,
                ENABLE_LITE_VANGUARDS,
                &netdir_provider,
            )
            .await;

            // The vanguard sets from storage haven't changed, because we are in "lite" mode.
            assert_eq!(vanguard_sets_orig, vanguardmgr.storage.load().unwrap());
            let _ = install_netdir_excluding_vanguard(
                &rt,
                &excluded_vanguard,
                ENABLE_FULL_VANGUARDS,
                &netdir_provider,
            )
            .await;
        });
    }

    #[test]
    fn load_from_state_file() {
        MockRuntime::test_with_various(|rt| async move {
            // Set the wallclock to a time when some of the stored vanguards are still valid.
            let now = time::UNIX_EPOCH + Duration::from_secs(1610000000);
            rt.jump_wallclock(now);

            let config = VanguardConfig {
                mode: ExplicitOrAuto::Explicit(VanguardMode::Full),
            };

            // The state file contains no vanguards
            let (statemgr, _dir) =
                state_dir_with_vanguards(r#"{ "l2_vanguards": [], "l3_vanguards": [] }"#);
            let vanguardmgr = VanguardMgr::new(&config, rt.clone(), statemgr, false).unwrap();
            {
                let inner = vanguardmgr.inner.read().unwrap();

                // The vanguard sets should be empty too
                assert!(inner.vanguard_sets.l2().is_empty());
                assert!(inner.vanguard_sets.l3().is_empty());
            }

            let (statemgr, _dir) = state_dir_with_vanguards(VANGUARDS_JSON);
            let vanguardmgr =
                Arc::new(VanguardMgr::new(&config, rt.clone(), statemgr, false).unwrap());
            let (initial_l2, initial_l3) = {
                let inner = vanguardmgr.inner.read().unwrap();
                let l2_vanguards = inner.vanguard_sets.l2_vanguards().clone();
                let l3_vanguards = inner.vanguard_sets.l3_vanguards().clone();

                // The sets actually contain 4 and 5 vanguards, respectively,
                // but the expired ones are discarded.
                assert_eq!(l2_vanguards.len(), 3);
                assert_eq!(l3_vanguards.len(), 2);
                // We don't know how many vanguards we're going to need
                // until we fetch the consensus.
                assert_eq!(inner.vanguard_sets.l2_vanguards_target(), 0);
                assert_eq!(inner.vanguard_sets.l3_vanguards_target(), 0);
                assert_eq!(inner.vanguard_sets.l2_vanguards_deficit(), 0);
                assert_eq!(inner.vanguard_sets.l3_vanguards_deficit(), 0);

                (l2_vanguards, l3_vanguards)
            };

            let netdir = testnet::construct_netdir().unwrap_if_sufficient().unwrap();
            let _netdir_provider = vanguardmgr.init_vanguard_sets(&netdir).await.unwrap();
            {
                let inner = vanguardmgr.inner.read().unwrap();
                let l2_vanguards = inner.vanguard_sets.l2_vanguards();
                let l3_vanguards = inner.vanguard_sets.l3_vanguards();

                // The sets were replenished with more vanguards
                assert_eq!(l2_vanguards.len(), 4);
                assert_eq!(l3_vanguards.len(), 8);
                // We now know we need 4 L2 vanguards and 8 L3 ones.
                assert_eq!(inner.vanguard_sets.l2_vanguards_target(), 4);
                assert_eq!(inner.vanguard_sets.l3_vanguards_target(), 8);
                assert_eq!(inner.vanguard_sets.l2_vanguards_deficit(), 0);
                assert_eq!(inner.vanguard_sets.l3_vanguards_deficit(), 0);

                // All of the vanguards read from the state file should still be in the sets.
                assert!(initial_l2.iter().all(|v| l2_vanguards.contains(v)));
                assert!(initial_l3.iter().all(|v| l3_vanguards.contains(v)));
            }
        });
    }

    #[test]
    fn invalid_state_file() {
        MockRuntime::test_with_various(|rt| async move {
            let config = VanguardConfig {
                mode: ExplicitOrAuto::Explicit(VanguardMode::Full),
            };
            let (statemgr, _dir) = state_dir_with_vanguards(INVALID_VANGUARDS_JSON);
            let res = VanguardMgr::new(&config, rt.clone(), statemgr, false);
            assert!(matches!(res, Err(VanguardMgrError::State(_))));
        });
    }
