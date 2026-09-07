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
    use crate::Error;

    use futures::{join, poll};
    use std::error::Error as StdError;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;
    use tor_error::bad_api_usage;
    use tor_linkspec::ChannelMethod;
    use tor_llcrypto::pk::ed25519::Ed25519Identity;
    use tor_memquota::ArcMemoryQuotaTrackerExt as _;

    use crate::ChannelUsage as CU;
    use tor_rtcompat::{Runtime, task::yield_now, test_with_one_runtime};

    // Two distinct addresses we can use in tests.
    const ADDR_A: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 443));
    const ADDR_B: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(2, 2, 2, 2), 443));

    #[derive(Clone)]
    struct FakeChannelFactory<RT> {
        runtime: RT,
        build_attempts: Arc<AtomicUsize>,
    }

    #[derive(Clone, Debug)]
    struct FakeChannel {
        ed_ident: Ed25519Identity,
        mood: char,
        closing: Arc<AtomicBool>,
        detect_reuse: Arc<char>,
        // last_params: Option<ChannelPaddingInstructionsUpdates>,
    }

    impl PartialEq for FakeChannel {
        fn eq(&self, other: &Self) -> bool {
            Arc::ptr_eq(&self.detect_reuse, &other.detect_reuse)
        }
    }

    impl AbstractChannel for FakeChannel {
        fn is_canonical(&self) -> bool {
            unimplemented!()
        }
        fn is_canonical_to_peer(&self) -> bool {
            unimplemented!()
        }
        fn is_usable(&self) -> bool {
            !self.closing.load(Ordering::SeqCst)
        }
        fn duration_unused(&self) -> Option<Duration> {
            None
        }
        fn reparameterize(
            &self,
            _updates: Arc<ChannelPaddingInstructionsUpdates>,
        ) -> tor_proto::Result<()> {
            // *self.last_params.lock().unwrap() = Some((*updates).clone());
            match self.mood {
                // Build succeeds, but installing the channel into the manager fails.
                'r' => Err(tor_proto::Error::ChanProto(
                    "synthetic reparameterize failure".into(),
                )),
                _ => Ok(()),
            }
        }
        fn reparameterize_kist(&self, _kist_params: KistParams) -> tor_proto::Result<()> {
            Ok(())
        }
        fn engage_padding_activities(&self) {}
        fn terminate(&self) {
            self.start_closing();
        }
    }

    impl HasRelayIds for FakeChannel {
        fn identity(
            &self,
            key_type: tor_linkspec::RelayIdType,
        ) -> Option<tor_linkspec::RelayIdRef<'_>> {
            match key_type {
                tor_linkspec::RelayIdType::Ed25519 => Some((&self.ed_ident).into()),
                _ => None,
            }
        }
    }

    impl FakeChannel {
        fn start_closing(&self) {
            self.closing.store(true, Ordering::SeqCst);
        }
    }

    impl<RT: Runtime> FakeChannelFactory<RT> {
        fn new(runtime: RT, build_attempts: Arc<AtomicUsize>) -> Self {
            FakeChannelFactory {
                runtime,
                build_attempts,
            }
        }
    }

    fn new_test_abstract_chanmgr<R: Runtime>(runtime: R) -> AbstractChanMgr<FakeChannelFactory<R>> {
        new_test_abstract_chanmgr_and_build_attempts(runtime).0
    }

    fn new_test_abstract_chanmgr_and_build_attempts<R: Runtime>(
        runtime: R,
    ) -> (AbstractChanMgr<FakeChannelFactory<R>>, Arc<AtomicUsize>) {
        let build_attempts = Arc::new(AtomicUsize::new(0));
        let cf = FakeChannelFactory::new(runtime, Arc::clone(&build_attempts));
        let mgr = AbstractChanMgr::new(
            cf,
            Default::default(),
            Default::default(),
            &Default::default(),
            BootstrapReporter::fake(),
            ToplevelAccount::new_noop(),
        );
        (mgr, build_attempts)
    }

    #[derive(Clone, Debug)]
    struct FakeBuildSpec(u32, char, Ed25519Identity, SocketAddr);

    impl HasRelayIds for FakeBuildSpec {
        fn identity(
            &self,
            key_type: tor_linkspec::RelayIdType,
        ) -> Option<tor_linkspec::RelayIdRef<'_>> {
            match key_type {
                tor_linkspec::RelayIdType::Ed25519 => Some((&self.2).into()),
                _ => None,
            }
        }
    }

    impl HasChanMethod for FakeBuildSpec {
        fn chan_method(&self) -> ChannelMethod {
            ChannelMethod::Direct(vec![self.3.clone()])
        }
    }

    /// Helper to make a fake Ed identity from a u32.
    fn u32_to_ed(n: u32) -> Ed25519Identity {
        let mut bytes = [0; 32];
        bytes[0..4].copy_from_slice(&n.to_be_bytes());
        bytes.into()
    }

    /// Return true if `needle` appears anywhere in `err`'s error chain.
    fn error_contains(err: &Error, needle: &str) -> bool {
        let mut source: Option<&(dyn StdError + 'static)> = Some(err);
        while let Some(err) = source {
            if err.to_string().contains(needle) || format!("{err:?}").contains(needle) {
                return true;
            }
            source = err.source();
        }
        false
    }

    #[async_trait]
    impl<RT: Runtime> AbstractChannelFactory for FakeChannelFactory<RT> {
        type Channel = FakeChannel;
        type BuildSpec = FakeBuildSpec;
        type Stream = ();

        async fn build_channel(
            &self,
            target: &Self::BuildSpec,
            _reporter: BootstrapReporter,
            _memquota: ChannelAccount,
        ) -> Result<Arc<FakeChannel>> {
            self.build_attempts.fetch_add(1, Ordering::SeqCst);
            yield_now().await;
            let FakeBuildSpec(ident, mood, id, _addr) = *target;
            let ed_ident = u32_to_ed(ident);
            assert_eq!(ed_ident, id);
            match mood {
                // "X" means never connect.
                '❌' | '🔥' => return Err(Error::UnusableTarget(bad_api_usage!("emoji"))),
                // "zzz" means wait for 15 seconds then succeed.
                '💤' => {
                    self.runtime.sleep(Duration::new(15, 0)).await;
                }
                _ => {}
            }
            Ok(Arc::new(FakeChannel {
                ed_ident,
                mood,
                closing: Arc::new(AtomicBool::new(false)),
                detect_reuse: Default::default(),
                // last_params: None,
            }))
        }

        #[cfg(feature = "relay")]
        async fn build_channel_using_incoming(
            &self,
            _peer: Sensitive<std::net::SocketAddr>,
            _stream: Self::Stream,
            _memquota: ChannelAccount,
        ) -> Result<Arc<Self::Channel>> {
            unimplemented!()
        }
    }

    #[test]
    fn connect_one_ok() {
        test_with_one_runtime!(|runtime| async {
            let mgr = new_test_abstract_chanmgr(runtime);
            let target = FakeBuildSpec(413, '!', u32_to_ed(413), ADDR_A);
            let chan1 = mgr
                .get_or_launch(target.clone(), CU::UserTraffic)
                .await
                .unwrap()
                .0;
            let chan2 = mgr.get_or_launch(target, CU::UserTraffic).await.unwrap().0;

            assert_eq!(chan1, chan2);
            assert_eq!(mgr.get_nowait(&u32_to_ed(413)), vec![chan1]);
        });
    }

    #[test]
    fn connect_one_fail() {
        test_with_one_runtime!(|runtime| async {
            let mgr = new_test_abstract_chanmgr(runtime);

            // This is set up to always fail.
            let target = FakeBuildSpec(999, '❌', u32_to_ed(999), ADDR_A);
            let res1 = mgr.get_or_launch(target, CU::UserTraffic).await;
            assert!(matches!(res1, Err(Error::UnusableTarget(_))));

            assert!(mgr.get_nowait(&u32_to_ed(999)).is_empty());
        });
    }

    #[test]
    fn connect_different_address() {
        test_with_one_runtime!(|runtime| async {
            let mgr = new_test_abstract_chanmgr(runtime);

            // Two targets that have different addresses.
            let target1 = FakeBuildSpec(413, '!', u32_to_ed(413), ADDR_A);
            let mut target2 = target1.clone();
            target2.3 = ADDR_B;

            let chan1 = mgr.get_or_launch(target1, CU::UserTraffic).await.unwrap().0;
            let chan2 = mgr.get_or_launch(target2, CU::UserTraffic).await.unwrap().0;

            // Even with different addresses, the original channel is returned.
            assert_eq!(chan1, chan2);
            assert_eq!(mgr.get_nowait(&u32_to_ed(413)), vec![chan1]);
        });
    }

    #[test]
    fn test_concurrent() {
        test_with_one_runtime!(|runtime| async {
            let mgr = new_test_abstract_chanmgr(runtime);

            let usage = CU::UserTraffic;

            // TODO(nickm): figure out how to make these actually run
            // concurrently. Right now it seems that they don't actually
            // interact.
            let (ch3a, ch3b, ch44a, ch44b, ch50a, ch50b, ch86a, ch86b) = join!(
                mgr.get_or_launch(FakeBuildSpec(3, 'a', u32_to_ed(3), ADDR_A), usage),
                mgr.get_or_launch(FakeBuildSpec(3, 'b', u32_to_ed(3), ADDR_A), usage),
                mgr.get_or_launch(FakeBuildSpec(44, 'a', u32_to_ed(44), ADDR_A), usage),
                mgr.get_or_launch(FakeBuildSpec(44, 'b', u32_to_ed(44), ADDR_A), usage),
                mgr.get_or_launch(FakeBuildSpec(50, 'a', u32_to_ed(50), ADDR_A), usage),
                mgr.get_or_launch(FakeBuildSpec(50, 'b', u32_to_ed(50), ADDR_B), usage),
                mgr.get_or_launch(FakeBuildSpec(86, '❌', u32_to_ed(86), ADDR_A), usage),
                mgr.get_or_launch(FakeBuildSpec(86, '🔥', u32_to_ed(86), ADDR_A), usage),
            );
            let ch3a = ch3a.unwrap();
            let ch3b = ch3b.unwrap();
            let ch44a = ch44a.unwrap();
            let ch44b = ch44b.unwrap();
            let ch50a = ch50a.unwrap();
            let ch50b = ch50b.unwrap();
            let err_a = ch86a.unwrap_err();
            let err_b = ch86b.unwrap_err();

            assert_eq!(ch3a, ch3b);
            assert_eq!(ch44a, ch44b);
            assert_eq!(ch50a, ch50b);
            assert_ne!(ch44a, ch3a);

            assert!(matches!(err_a, Error::UnusableTarget(_)));
            assert!(matches!(err_b, Error::UnusableTarget(_)));
        });
    }

    #[test]
    fn dropped_launch_reports_request_cancelled_to_waiters() {
        test_with_one_runtime!(|runtime| async {
            let mgr = new_test_abstract_chanmgr(runtime);
            let target = FakeBuildSpec(777, '💤', u32_to_ed(777), ADDR_A);
            let usage = CU::UserTraffic;

            let mut owner1 = Box::pin(mgr.get_or_launch(target.clone(), usage));
            assert!(poll!(&mut owner1).is_pending());

            let mut waiter = Box::pin(mgr.get_or_launch(target.clone(), usage));
            assert!(poll!(&mut waiter).is_pending());

            drop(owner1);

            let mut owner2 = Box::pin(mgr.get_or_launch(target, usage));
            assert!(poll!(&mut owner2).is_pending());

            assert!(poll!(&mut waiter).is_pending());

            drop(owner2);

            let waiter = waiter.await;
            assert!(
                matches!(&waiter, Err(Error::RequestCancelled)),
                "{waiter:?}"
            );
            if let Err(ref err) = waiter {
                assert!(!error_contains(err, "channel build task disappeared"));
            }
        });
    }

    #[test]
    fn failed_upgrade_reports_original_error_without_owner_retry() {
        test_with_one_runtime!(|runtime| async {
            let (mgr, build_attempts) = new_test_abstract_chanmgr_and_build_attempts(runtime);
            let target = FakeBuildSpec(778, 'r', u32_to_ed(778), ADDR_A);
            let usage = CU::UserTraffic;

            let mut owner = Box::pin(mgr.get_or_launch(target.clone(), usage));
            assert!(poll!(&mut owner).is_pending());

            let mut waiter = Box::pin(mgr.get_or_launch(target.clone(), usage));
            assert!(poll!(&mut waiter).is_pending());

            let owner = owner.await;
            assert!(matches!(&owner, Err(Error::Internal(_))), "{owner:?}");
            if let Err(ref err) = owner {
                assert!(error_contains(err, "failure on new channel"));
                assert!(!error_contains(err, "channel build task disappeared"));
            }

            assert_eq!(build_attempts.load(Ordering::SeqCst), 1);
            assert!(mgr.get_nowait(&u32_to_ed(778)).is_empty());

            let waiter = waiter.await;
            assert!(matches!(&waiter, Err(Error::Internal(_))), "{waiter:?}");
            if let Err(ref err) = waiter {
                assert!(error_contains(err, "failure on new channel"));
                assert!(!error_contains(err, "channel build task disappeared"));
            }
        });
    }

    #[test]
    fn unusable_entries() {
        test_with_one_runtime!(|runtime| async {
            let mgr = new_test_abstract_chanmgr(runtime);

            let (ch3, ch4, ch5) = join!(
                mgr.get_or_launch(FakeBuildSpec(3, 'a', u32_to_ed(3), ADDR_A), CU::UserTraffic),
                mgr.get_or_launch(FakeBuildSpec(4, 'a', u32_to_ed(4), ADDR_A), CU::UserTraffic),
                mgr.get_or_launch(FakeBuildSpec(5, 'a', u32_to_ed(5), ADDR_A), CU::UserTraffic),
            );

            let ch3 = ch3.unwrap().0;
            let _ch4 = ch4.unwrap();
            let ch5 = ch5.unwrap().0;

            ch3.start_closing();
            ch5.start_closing();

            let ch3_new = mgr
                .get_or_launch(FakeBuildSpec(3, 'b', u32_to_ed(3), ADDR_A), CU::UserTraffic)
                .await
                .unwrap()
                .0;
            assert_ne!(ch3, ch3_new);
            assert_eq!(ch3_new.mood, 'b');

            mgr.remove_unusable_entries().unwrap();

            assert!(!mgr.get_nowait(&u32_to_ed(3)).is_empty());
            assert!(!mgr.get_nowait(&u32_to_ed(4)).is_empty());
            assert!(mgr.get_nowait(&u32_to_ed(5)).is_empty());
        });
    }

    // tor-socks5 local patch: coverage for `AbstractChanMgr::terminate_all_channels`.
    #[test]
    fn terminate_all_channels() {
        test_with_one_runtime!(|runtime| async {
            let mgr = new_test_abstract_chanmgr(runtime);

            let (ch7, ch8) = join!(
                mgr.get_or_launch(FakeBuildSpec(7, 'a', u32_to_ed(7), ADDR_A), CU::UserTraffic),
                mgr.get_or_launch(FakeBuildSpec(8, 'a', u32_to_ed(8), ADDR_A), CU::UserTraffic),
            );
            let ch7 = ch7.unwrap().0;
            let ch8 = ch8.unwrap().0;

            // Neither channel is "unusable" yet: unlike `expire_channels`, which
            // requires channels to be idle past their `max_unused_duration`,
            // `terminate_all_channels` closes them unconditionally.
            assert!(ch7.is_usable());
            assert!(ch8.is_usable());

            mgr.terminate_all_channels();

            // Both channels were force-closed...
            assert!(ch7.closing.load(Ordering::SeqCst));
            assert!(ch8.closing.load(Ordering::SeqCst));
            // ...and removed from the manager's map.
            assert!(mgr.get_nowait(&u32_to_ed(7)).is_empty());
            assert!(mgr.get_nowait(&u32_to_ed(8)).is_empty());
        });
    }

    #[test]
    fn terminate_all_channels_leaves_pending_alone() {
        test_with_one_runtime!(|runtime| async {
            let mgr = new_test_abstract_chanmgr(runtime);

            // '💤' never completes within this test, so the entry stays
            // `Building` in the map throughout.
            let target = FakeBuildSpec(9, '💤', u32_to_ed(9), ADDR_A);
            let mut pending = Box::pin(mgr.get_or_launch(target, CU::UserTraffic));
            assert!(poll!(&mut pending).is_pending());

            // Should not panic or otherwise disturb the still-building entry.
            mgr.terminate_all_channels();

            assert!(poll!(&mut pending).is_pending());
        });
    }
