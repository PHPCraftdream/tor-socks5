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
    use crate::factory::BootstrapReporter;
    use async_trait::async_trait;
    #[cfg(feature = "relay")]
    use safelog::Sensitive;
    use std::sync::{Arc, Mutex};
    use tor_llcrypto::pk::ed25519::Ed25519Identity;
    use tor_proto::channel::params::ChannelPaddingInstructionsUpdates;
    use tor_proto::memquota::ChannelAccount;

    fn new_test_state() -> MgrState<FakeChannelFactory> {
        MgrState::new(
            FakeChannelFactory::default(),
            ChannelConfig::default(),
            Default::default(),
            &Default::default(),
        )
    }

    #[derive(Clone, Debug, Default)]
    struct FakeChannelFactory {}

    #[allow(clippy::diverging_sub_expression)] // for unimplemented!() + async_trait
    #[async_trait]
    impl AbstractChannelFactory for FakeChannelFactory {
        type Channel = FakeChannel;

        type BuildSpec = tor_linkspec::OwnedChanTarget;

        type Stream = ();

        async fn build_channel(
            &self,
            _target: &Self::BuildSpec,
            _reporter: BootstrapReporter,
            _memquota: ChannelAccount,
        ) -> Result<Arc<FakeChannel>> {
            unimplemented!()
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

    #[derive(Clone, Debug)]
    struct FakeChannel {
        ed_ident: Ed25519Identity,
        usable: bool,
        unused_duration: Option<u64>,
        params_update: Arc<Mutex<Option<Arc<ChannelPaddingInstructionsUpdates>>>>,
    }
    impl AbstractChannel for FakeChannel {
        fn is_canonical(&self) -> bool {
            unimplemented!()
        }
        fn is_canonical_to_peer(&self) -> bool {
            unimplemented!()
        }
        fn is_usable(&self) -> bool {
            self.usable
        }
        fn duration_unused(&self) -> Option<Duration> {
            self.unused_duration.map(Duration::from_secs)
        }
        fn reparameterize(
            &self,
            update: Arc<ChannelPaddingInstructionsUpdates>,
        ) -> tor_proto::Result<()> {
            *self.params_update.lock().unwrap() = Some(update);
            Ok(())
        }
        fn reparameterize_kist(&self, _kist_params: KistParams) -> tor_proto::Result<()> {
            Ok(())
        }
        fn engage_padding_activities(&self) {}
        fn terminate(&self) {
            // Not exercised by this module's tests (see `terminate_all_channels`
            // tests below, which use a dedicated `TerminateFakeChannel` with
            // interior mutability to observe the call).
        }
    }
    impl tor_linkspec::HasRelayIds for FakeChannel {
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
    /// Get a fake ed25519 identity from the first byte of a string.
    fn str_to_ed(s: &str) -> Ed25519Identity {
        let byte = s.as_bytes()[0];
        [byte; 32].into()
    }
    fn ch(ident: &'static str) -> ChannelState<FakeChannel> {
        let channel = FakeChannel {
            ed_ident: str_to_ed(ident),
            usable: true,
            unused_duration: None,
            params_update: Arc::new(Mutex::new(None)),
        };
        ChannelState::Open(OpenEntry {
            channel: Arc::new(channel),
            max_unused_duration: Duration::from_secs(180),
        })
    }
    fn ch_with_details(
        ident: &'static str,
        max_unused_duration: Duration,
        unused_duration: Option<u64>,
    ) -> ChannelState<FakeChannel> {
        let channel = FakeChannel {
            ed_ident: str_to_ed(ident),
            usable: true,
            unused_duration,
            params_update: Arc::new(Mutex::new(None)),
        };
        ChannelState::Open(OpenEntry {
            channel: Arc::new(channel),
            max_unused_duration,
        })
    }
    fn closed(ident: &'static str) -> ChannelState<FakeChannel> {
        let channel = FakeChannel {
            ed_ident: str_to_ed(ident),
            usable: false,
            unused_duration: None,
            params_update: Arc::new(Mutex::new(None)),
        };
        ChannelState::Open(OpenEntry {
            channel: Arc::new(channel),
            max_unused_duration: Duration::from_secs(180),
        })
    }

    #[test]
    fn rmv_unusable() -> Result<()> {
        let map = new_test_state();

        map.with_channels(|map| {
            map.insert(closed("machen"));
            map.insert(closed("wir"));
            map.insert(ch("wir"));
            map.insert(ch("feinen"));
            map.insert(ch("Fug"));
            map.insert(ch("Fug"));
        })?;

        map.remove_unusable().unwrap();

        map.with_channels(|map| {
            assert_eq!(map.by_id(&str_to_ed("m")).len(), 0);
            assert_eq!(map.by_id(&str_to_ed("w")).len(), 1);
            assert_eq!(map.by_id(&str_to_ed("f")).len(), 1);
            assert_eq!(map.by_id(&str_to_ed("F")).len(), 2);
        })?;

        Ok(())
    }

    #[test]
    fn reparameterize_via_netdir() -> Result<()> {
        let map = new_test_state();

        // Set some non-default parameters so that we can tell when an update happens
        let _ = map
            .inner
            .lock()
            .unwrap()
            .channels_params
            .padding
            .start_update()
            .padding_parameters(
                PaddingParametersBuilder::default()
                    .low(1234.into())
                    .build()
                    .unwrap(),
            )
            .finish();

        map.with_channels(|map| {
            map.insert(ch("track"));
        })?;

        let netdir = tor_netdir::testnet::construct_netdir()
            .unwrap_if_sufficient()
            .unwrap();
        let netdir = Arc::new(netdir);

        let with_ch = |f: &dyn Fn(&FakeChannel)| {
            let inner = map.inner.lock().unwrap();
            let mut ch = inner.channels.by_ed25519(&str_to_ed("t"));
            let ch = ch.next().unwrap().unwrap_open();
            f(ch);
        };

        eprintln!("-- process a default netdir, which should send an update --");
        map.reconfigure_general(None, None, netdir.clone()).unwrap();
        with_ch(&|ch| {
            assert_eq!(
                format!("{:?}", ch.params_update.lock().unwrap().take().unwrap()),
                // evade field visibility by (ab)using Debug impl
                "ChannelPaddingInstructionsUpdates { padding_enable: None, \
                    padding_parameters: Some(Parameters { \
                        low: IntegerMilliseconds { value: 1500 }, \
                        high: IntegerMilliseconds { value: 9500 } }), \
                    padding_negotiate: None }"
            );
        });
        eprintln!();

        eprintln!("-- process a default netdir again, which should *not* send an update --");
        map.reconfigure_general(None, None, netdir).unwrap();
        with_ch(&|ch| assert!(ch.params_update.lock().unwrap().is_none()));

        Ok(())
    }

    #[test]
    fn expire_channels() -> Result<()> {
        let map = new_test_state();

        // Channel that has been unused beyond max duration allowed is expired
        map.with_channels(|map| {
            map.insert(ch_with_details(
                "wello",
                Duration::from_secs(180),
                Some(181),
            ));
        })?;

        // Minimum value of max unused duration is 180 seconds
        assert_eq!(180, map.expire_channels().as_secs());
        map.with_channels(|map| {
            assert_eq!(map.by_ed25519(&str_to_ed("w")).len(), 0);
        })?;

        let map = new_test_state();

        // Channel that has been unused for shorter than max unused duration
        map.with_channels(|map| {
            map.insert(ch_with_details(
                "wello",
                Duration::from_secs(180),
                Some(120),
            ));

            map.insert(ch_with_details(
                "yello",
                Duration::from_secs(180),
                Some(170),
            ));

            // Channel that has been unused beyond max duration allowed is expired
            map.insert(ch_with_details(
                "gello",
                Duration::from_secs(180),
                Some(181),
            ));

            // Closed channel should be retained
            map.insert(closed("hello"));
        })?;

        // Return duration until next channel expires
        assert_eq!(10, map.expire_channels().as_secs());
        map.with_channels(|map| {
            assert_eq!(map.by_ed25519(&str_to_ed("w")).len(), 1);
            assert_eq!(map.by_ed25519(&str_to_ed("y")).len(), 1);
            assert_eq!(map.by_ed25519(&str_to_ed("h")).len(), 1);
            assert_eq!(map.by_ed25519(&str_to_ed("g")).len(), 0);
        })?;
        Ok(())
    }

    // tor-socks5 local patch: coverage for `MgrState::terminate_all_channels`.

    /// A `FakeChannel` variant with interior mutability, so tests can observe
    /// whether `AbstractChannel::terminate()` was actually invoked (unlike the
    /// plain `FakeChannel` above, whose `usable: bool` field isn't mutable
    /// through `&self`).
    #[derive(Clone, Debug)]
    struct TerminateFakeChannel {
        ed_ident: Ed25519Identity,
        terminated: Arc<std::sync::atomic::AtomicBool>,
    }
    impl AbstractChannel for TerminateFakeChannel {
        fn is_canonical(&self) -> bool {
            unimplemented!()
        }
        fn is_canonical_to_peer(&self) -> bool {
            unimplemented!()
        }
        fn is_usable(&self) -> bool {
            !self.terminated.load(Ordering::SeqCst)
        }
        fn duration_unused(&self) -> Option<Duration> {
            None
        }
        fn reparameterize(
            &self,
            _updates: Arc<ChannelPaddingInstructionsUpdates>,
        ) -> tor_proto::Result<()> {
            Ok(())
        }
        fn reparameterize_kist(&self, _kist_params: KistParams) -> tor_proto::Result<()> {
            Ok(())
        }
        fn engage_padding_activities(&self) {}
        fn terminate(&self) {
            self.terminated.store(true, Ordering::SeqCst);
        }
    }
    impl tor_linkspec::HasRelayIds for TerminateFakeChannel {
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

    #[derive(Clone, Debug, Default)]
    struct TerminateFakeChannelFactory {}

    #[allow(clippy::diverging_sub_expression)] // for unimplemented!() + async_trait
    #[async_trait]
    impl AbstractChannelFactory for TerminateFakeChannelFactory {
        type Channel = TerminateFakeChannel;
        type BuildSpec = tor_linkspec::OwnedChanTarget;
        type Stream = ();

        async fn build_channel(
            &self,
            _target: &Self::BuildSpec,
            _reporter: BootstrapReporter,
            _memquota: ChannelAccount,
        ) -> Result<Arc<TerminateFakeChannel>> {
            unimplemented!()
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

    fn terminate_ch(
        ident: &'static str,
        terminated: &Arc<std::sync::atomic::AtomicBool>,
    ) -> ChannelState<TerminateFakeChannel> {
        let channel = TerminateFakeChannel {
            ed_ident: str_to_ed(ident),
            terminated: Arc::clone(terminated),
        };
        ChannelState::Open(OpenEntry {
            channel: Arc::new(channel),
            max_unused_duration: Duration::from_secs(180),
        })
    }

    #[test]
    fn terminate_all_channels() -> Result<()> {
        let map = MgrState::<TerminateFakeChannelFactory>::new(
            TerminateFakeChannelFactory::default(),
            ChannelConfig::default(),
            Default::default(),
            &Default::default(),
        );

        let flag_a = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag_b = Arc::new(std::sync::atomic::AtomicBool::new(false));

        // A pending ("Building") entry should survive untouched: there is no
        // live channel there yet to terminate.
        let pending_ids = RelayIds::from_relay_ids(&TerminateFakeChannel {
            ed_ident: str_to_ed("pending"),
            terminated: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        });
        let (pending_entry, _send, _unique_id) = setup_launch(pending_ids);

        map.with_channels(|map| {
            map.insert(terminate_ch("wello", &flag_a));
            map.insert(terminate_ch("yello", &flag_b));
            map.insert(ChannelState::Building(pending_entry));
        })?;

        map.terminate_all_channels();

        assert!(flag_a.load(Ordering::SeqCst), "channel should be terminated");
        assert!(flag_b.load(Ordering::SeqCst), "channel should be terminated");

        map.with_channels(|map| {
            // Open channels were terminated and removed from the map.
            assert_eq!(map.by_ed25519(&str_to_ed("w")).len(), 0);
            assert_eq!(map.by_ed25519(&str_to_ed("y")).len(), 0);
            // The pending ("Building") entry was left untouched.
            assert_eq!(map.by_ed25519(&str_to_ed("p")).len(), 1);
        })?;

        Ok(())
    }
