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
use crate::isolation::test::{IsolationTokenEq, assert_isoleq};
use crate::mocks::{FakeBuilder, FakeCirc, FakeId, FakeOp};
use crate::usage::{ExitPolicy, SupportedTunnelUsage};
use crate::{Error, IsolationToken, StreamIsolation, TargetPort, TargetPorts, TargetTunnelUsage};
use std::sync::LazyLock;
use tor_dircommon::fallback::FallbackList;
use tor_guardmgr::TestConfig;
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_netdir::testnet;
use tor_persist::TestingStateMgr;
use tor_rtcompat::SleepProvider;
use tor_rtmock::MockRuntime;
use web_time_compat::InstantExt;

#[allow(deprecated)] // TODO #1885
use tor_rtmock::MockSleepRuntime;

static FALLBACKS_EMPTY: LazyLock<FallbackList> = LazyLock::new(|| [].into());

fn di() -> DirInfo<'static> {
    (&*FALLBACKS_EMPTY).into()
}

fn target_to_spec(target: &TargetTunnelUsage) -> SupportedTunnelUsage {
    match target {
        TargetTunnelUsage::Exit {
            ports,
            isolation,
            country_code,
            require_stability,
        } => SupportedTunnelUsage::Exit {
            policy: ExitPolicy::from_target_ports(&TargetPorts::from(&ports[..])),
            isolation: Some(isolation.clone()),
            country_code: country_code.clone(),
            all_relays_stable: *require_stability,
        },
        _ => unimplemented!(),
    }
}

impl<U: PartialEq> IsolationTokenEq for OpenEntry<U> {
    fn isol_eq(&self, other: &Self) -> bool {
        self.spec.isol_eq(&other.spec)
            && self.tunnel == other.tunnel
            && self.expiration == other.expiration
    }
}

impl<U: PartialEq> IsolationTokenEq for &mut OpenEntry<U> {
    fn isol_eq(&self, other: &Self) -> bool {
        self.spec.isol_eq(&other.spec)
            && self.tunnel == other.tunnel
            && self.expiration == other.expiration
    }
}

fn make_builder<R: Runtime>(runtime: &R) -> FakeBuilder<R> {
    let state_mgr = TestingStateMgr::new();
    let guard_config = TestConfig::default();
    FakeBuilder::new(runtime, state_mgr, &guard_config)
}

#[test]
fn basic_tests() {
    MockRuntime::test_with_various(|rt| async move {
        #[allow(deprecated)] // TODO #1885
        let rt = MockSleepRuntime::new(rt);

        let builder = make_builder(&rt);

        let mgr = Arc::new(AbstractTunnelMgr::new(
            builder,
            rt.clone(),
            CircuitTiming::default(),
        ));

        let webports = TargetTunnelUsage::new_from_ipv4_ports(&[80, 443]);

        // Check initialization.
        assert_eq!(mgr.n_tunnels(), 0);
        assert!(mgr.peek_builder().script.lock().unwrap().is_empty());

        // Launch a tunnel ; make sure we get it.
        let c1 = rt.wait_for(mgr.get_or_launch(&webports, di())).await;
        let c1 = c1.unwrap().0;
        assert_eq!(mgr.n_tunnels(), 1);

        // Make sure we get the one we already made if we ask for it.
        let port80 = TargetTunnelUsage::new_from_ipv4_ports(&[80]);
        let c2 = mgr.get_or_launch(&port80, di()).await;

        let c2 = c2.unwrap().0;
        assert!(FakeCirc::eq(&c1, &c2));
        assert_eq!(mgr.n_tunnels(), 1);

        // Now try launching two tunnels "at once" to make sure that our
        // pending-tunnel code works.

        let dnsport = TargetTunnelUsage::new_from_ipv4_ports(&[53]);
        let dnsport_restrict = TargetTunnelUsage::Exit {
            ports: vec![TargetPort::ipv4(53)],
            isolation: StreamIsolation::builder().build().unwrap(),
            country_code: None,
            require_stability: false,
        };

        let (c3, c4) = rt
            .wait_for(futures::future::join(
                mgr.get_or_launch(&dnsport, di()),
                mgr.get_or_launch(&dnsport_restrict, di()),
            ))
            .await;

        let c3 = c3.unwrap().0;
        let c4 = c4.unwrap().0;
        assert!(!FakeCirc::eq(&c1, &c3));
        assert!(FakeCirc::eq(&c3, &c4));
        assert_eq!(c3.id(), c4.id());
        assert_eq!(mgr.n_tunnels(), 2);

        // Now we're going to remove c3 from consideration.  It's the
        // same as c4, so removing c4 will give us None.
        let c3_taken = mgr.take_tunnel(&c3.id()).unwrap();
        let now_its_gone = mgr.take_tunnel(&c4.id());
        assert!(FakeCirc::eq(&c3_taken, &c3));
        assert!(now_its_gone.is_none());
        assert_eq!(mgr.n_tunnels(), 1);

        // Having removed them, let's launch another dnsport and make
        // sure we get a different tunnel.
        let c5 = rt.wait_for(mgr.get_or_launch(&dnsport, di())).await;
        let c5 = c5.unwrap().0;
        assert!(!FakeCirc::eq(&c3, &c5));
        assert!(!FakeCirc::eq(&c4, &c5));
        assert_eq!(mgr.n_tunnels(), 2);

        // Now try launch_by_usage.
        let prev = mgr.n_pending_tunnels();
        assert!(mgr.launch_by_usage(&dnsport, di()).is_ok());
        assert_eq!(mgr.n_pending_tunnels(), prev + 1);
        // TODO: Actually make sure that launch_by_usage launched
        // the right thing.
    });
}

#[test]
fn request_timeout() {
    MockRuntime::test_with_various(|rt| async move {
        #[allow(deprecated)] // TODO #1885
        let rt = MockSleepRuntime::new(rt);

        let ports = TargetTunnelUsage::new_from_ipv4_ports(&[80, 443]);

        // This will fail once, and then completely time out.  The
        // result will be a failure.
        let builder = make_builder(&rt);
        builder.set(&ports, vec![FakeOp::Fail, FakeOp::Timeout]);

        let mgr = Arc::new(AbstractTunnelMgr::new(
            builder,
            rt.clone(),
            CircuitTiming::default(),
        ));
        let c1 = mgr
            .peek_runtime()
            .wait_for(mgr.get_or_launch(&ports, di()))
            .await;

        assert!(matches!(c1, Err(Error::RequestFailed(_))));
    });
}

#[test]
fn request_timeout2() {
    MockRuntime::test_with_various(|rt| async move {
        #[allow(deprecated)] // TODO #1885
        let rt = MockSleepRuntime::new(rt);

        // Now try a more complicated case: we'll try to get things so
        // that we wait for a little over our predicted time because
        // of our wait-for-next-action logic.
        let ports = TargetTunnelUsage::new_from_ipv4_ports(&[80, 443]);
        let builder = make_builder(&rt);
        builder.set(
            &ports,
            vec![
                FakeOp::Delay(Duration::from_millis(60_000 - 25)),
                FakeOp::NoPlan,
            ],
        );

        let mgr = Arc::new(AbstractTunnelMgr::new(
            builder,
            rt.clone(),
            CircuitTiming::default(),
        ));
        let c1 = mgr
            .peek_runtime()
            .wait_for(mgr.get_or_launch(&ports, di()))
            .await;

        assert!(matches!(c1, Err(Error::RequestFailed(_))));
    });
}

#[test]
fn request_unplannable() {
    MockRuntime::test_with_various(|rt| async move {
        #[allow(deprecated)] // TODO #1885
        let rt = MockSleepRuntime::new(rt);

        let ports = TargetTunnelUsage::new_from_ipv4_ports(&[80, 443]);

        // This will fail a the planning stages, a lot.
        let builder = make_builder(&rt);
        builder.set(&ports, vec![FakeOp::NoPlan; 2000]);

        let mgr = Arc::new(AbstractTunnelMgr::new(
            builder,
            rt.clone(),
            CircuitTiming::default(),
        ));
        let c1 = rt.wait_for(mgr.get_or_launch(&ports, di())).await;

        assert!(matches!(c1, Err(Error::RequestFailed(_))));
    });
}

#[test]
fn request_fails_too_much() {
    MockRuntime::test_with_various(|rt| async move {
        #[allow(deprecated)] // TODO #1885
        let rt = MockSleepRuntime::new(rt);
        let ports = TargetTunnelUsage::new_from_ipv4_ports(&[80, 443]);

        // This will fail 1000 times, which is above the retry limit.
        let builder = make_builder(&rt);
        builder.set(&ports, vec![FakeOp::Fail; 1000]);

        let mgr = Arc::new(AbstractTunnelMgr::new(
            builder,
            rt.clone(),
            CircuitTiming::default(),
        ));
        let c1 = rt.wait_for(mgr.get_or_launch(&ports, di())).await;

        assert!(matches!(c1, Err(Error::RequestFailed(_))));
    });
}

#[test]
fn request_wrong_spec() {
    MockRuntime::test_with_various(|rt| async move {
        #[allow(deprecated)] // TODO #1885
        let rt = MockSleepRuntime::new(rt);
        let ports = TargetTunnelUsage::new_from_ipv4_ports(&[80, 443]);

        // The first time this is called, it will build a tunnel
        // with the wrong spec.  (A tunnel builder should never
        // actually _do_ that, but it's something we code for.)
        let builder = make_builder(&rt);
        builder.set(
            &ports,
            vec![FakeOp::WrongSpec(target_to_spec(
                &TargetTunnelUsage::new_from_ipv4_ports(&[22]),
            ))],
        );

        let mgr = Arc::new(AbstractTunnelMgr::new(
            builder,
            rt.clone(),
            CircuitTiming::default(),
        ));
        let c1 = rt.wait_for(mgr.get_or_launch(&ports, di())).await;

        assert!(c1.is_ok());
    });
}

#[test]
fn request_retried() {
    MockRuntime::test_with_various(|rt| async move {
        #[allow(deprecated)] // TODO #1885
        let rt = MockSleepRuntime::new(rt);
        let ports = TargetTunnelUsage::new_from_ipv4_ports(&[80, 443]);

        // This will fail twice, and then succeed. The result will be
        // a success.
        let builder = make_builder(&rt);
        builder.set(&ports, vec![FakeOp::Fail, FakeOp::Fail]);

        let mgr = Arc::new(AbstractTunnelMgr::new(
            builder,
            rt.clone(),
            CircuitTiming::default(),
        ));

        // This test doesn't exercise any timeout behaviour.
        rt.block_advance("test doesn't require advancing");

        let (c1, c2) = rt
            .wait_for(futures::future::join(
                mgr.get_or_launch(&ports, di()),
                mgr.get_or_launch(&ports, di()),
            ))
            .await;

        let c1 = c1.unwrap().0;
        let c2 = c2.unwrap().0;

        assert!(FakeCirc::eq(&c1, &c2));
    });
}

#[test]
fn isolated() {
    MockRuntime::test_with_various(|rt| async move {
        #[allow(deprecated)] // TODO #1885
        let rt = MockSleepRuntime::new(rt);
        let builder = make_builder(&rt);
        let mgr = Arc::new(AbstractTunnelMgr::new(
            builder,
            rt.clone(),
            CircuitTiming::default(),
        ));

        // Set our isolation so that iso1 and iso2 can't share a tunnel,
        // but no_iso can share a tunnel with either.
        let iso1 = TargetTunnelUsage::Exit {
            ports: vec![TargetPort::ipv4(443)],
            isolation: StreamIsolation::builder()
                .owner_token(IsolationToken::new())
                .build()
                .unwrap(),
            country_code: None,
            require_stability: false,
        };
        let iso2 = TargetTunnelUsage::Exit {
            ports: vec![TargetPort::ipv4(443)],
            isolation: StreamIsolation::builder()
                .owner_token(IsolationToken::new())
                .build()
                .unwrap(),
            country_code: None,
            require_stability: false,
        };
        let no_iso1 = TargetTunnelUsage::new_from_ipv4_ports(&[443]);
        let no_iso2 = no_iso1.clone();

        // We're going to try launching these tunnels in 24 different
        // orders, to make sure that the outcome is correct each time.
        use itertools::Itertools;
        let timeouts: Vec<_> = [0_u64, 2, 4, 6]
            .iter()
            .map(|d| Duration::from_millis(*d))
            .collect();

        for delays in timeouts.iter().permutations(4) {
            let d1 = delays[0];
            let d2 = delays[1];
            let d3 = delays[2];
            let d4 = delays[2];
            let (c_iso1, c_iso2, c_no_iso1, c_no_iso2) = rt
                .wait_for(futures::future::join4(
                    async {
                        rt.sleep(*d1).await;
                        mgr.get_or_launch(&iso1, di()).await
                    },
                    async {
                        rt.sleep(*d2).await;
                        mgr.get_or_launch(&iso2, di()).await
                    },
                    async {
                        rt.sleep(*d3).await;
                        mgr.get_or_launch(&no_iso1, di()).await
                    },
                    async {
                        rt.sleep(*d4).await;
                        mgr.get_or_launch(&no_iso2, di()).await
                    },
                ))
                .await;

            let c_iso1 = c_iso1.unwrap().0;
            let c_iso2 = c_iso2.unwrap().0;
            let c_no_iso1 = c_no_iso1.unwrap().0;
            let c_no_iso2 = c_no_iso2.unwrap().0;

            assert!(!FakeCirc::eq(&c_iso1, &c_iso2));
            assert!(!FakeCirc::eq(&c_iso1, &c_no_iso1));
            assert!(!FakeCirc::eq(&c_iso1, &c_no_iso2));
            assert!(!FakeCirc::eq(&c_iso2, &c_no_iso1));
            assert!(!FakeCirc::eq(&c_iso2, &c_no_iso2));
            assert!(FakeCirc::eq(&c_no_iso1, &c_no_iso2));
        }
    });
}

#[test]
fn opportunistic() {
    MockRuntime::test_with_various(|rt| async move {
        #[allow(deprecated)] // TODO #1885
        let rt = MockSleepRuntime::new(rt);

        // The first request will time out completely, but we're
        // making a second request after we launch it.  That
        // request should succeed, and notify the first request.

        let ports1 = TargetTunnelUsage::new_from_ipv4_ports(&[80]);
        let ports2 = TargetTunnelUsage::new_from_ipv4_ports(&[80, 443]);

        let builder = make_builder(&rt);
        builder.set(&ports1, vec![FakeOp::Timeout]);

        let mgr = Arc::new(AbstractTunnelMgr::new(
            builder,
            rt.clone(),
            CircuitTiming::default(),
        ));
        // Note that ports2 will be wider than ports1, so the second
        // request will have to launch a new tunnel.

        let (c1, c2) = rt
            .wait_for(futures::future::join(
                mgr.get_or_launch(&ports1, di()),
                async {
                    rt.sleep(Duration::from_millis(100)).await;
                    mgr.get_or_launch(&ports2, di()).await
                },
            ))
            .await;

        if let (Ok((c1, _)), Ok((c2, _))) = (c1, c2) {
            assert!(FakeCirc::eq(&c1, &c2));
        } else {
            panic!();
        };
    });
}

#[test]
fn prebuild() {
    MockRuntime::test_with_various(|rt| async move {
        // This time we're going to use ensure_tunnel() to make
        // sure that a tunnel gets built, and then launch two
        // other tunnels that will use it.
        #[allow(deprecated)] // TODO #1885
        let rt = MockSleepRuntime::new(rt);
        let builder = make_builder(&rt);
        let mgr = Arc::new(AbstractTunnelMgr::new(
            builder,
            rt.clone(),
            CircuitTiming::default(),
        ));

        let ports1 = TargetTunnelUsage::new_from_ipv4_ports(&[80, 443]);
        let ports2 = TargetTunnelUsage::new_from_ipv4_ports(&[80]);
        let ports3 = TargetTunnelUsage::new_from_ipv4_ports(&[443]);

        let ok = mgr.ensure_tunnel(&ports1, di());
        let (c1, c2) = rt
            .wait_for(futures::future::join(
                async {
                    rt.sleep(Duration::from_millis(10)).await;
                    mgr.get_or_launch(&ports2, di()).await
                },
                async {
                    rt.sleep(Duration::from_millis(50)).await;
                    mgr.get_or_launch(&ports3, di()).await
                },
            ))
            .await;

        assert!(ok.is_ok());

        let c1 = c1.unwrap().0;
        let c2 = c2.unwrap().0;

        // If we had launched these separately, they wouldn't share
        // a tunnel.
        assert!(FakeCirc::eq(&c1, &c2));
    });
}

#[test]
fn expiration() {
    MockRuntime::test_with_various(|rt| async move {
        use crate::config::CircuitTimingBuilder;
        // Now let's make some tunnels -- one dirty, one clean, and
        // make sure that one expires and one doesn't.
        #[allow(deprecated)] // TODO #1885
        let rt = MockSleepRuntime::new(rt);
        let builder = make_builder(&rt);

        let circuit_timing = CircuitTimingBuilder::default()
            .max_dirtiness(Duration::from_secs(15))
            .build()
            .unwrap();

        let mgr = Arc::new(AbstractTunnelMgr::new(builder, rt.clone(), circuit_timing));

        let imap = TargetTunnelUsage::new_from_ipv4_ports(&[993]);
        let pop = TargetTunnelUsage::new_from_ipv4_ports(&[995]);

        let ok = mgr.ensure_tunnel(&imap, di());
        let pop1 = rt.wait_for(mgr.get_or_launch(&pop, di())).await;

        assert!(ok.is_ok());
        let pop1 = pop1.unwrap().0;

        rt.advance(Duration::from_secs(30)).await;
        rt.advance(Duration::from_secs(15)).await;
        let imap1 = rt.wait_for(mgr.get_or_launch(&imap, di())).await.unwrap().0;

        // This should expire the pop tunnel, since it came from
        // get_or_launch() [which marks the tunnel as being
        // used].  It should not expire the imap tunnel, since
        // it was not dirty until 15 seconds after the cutoff.
        let now = rt.now();

        mgr.expire_tunnels(now).await;

        let (pop2, imap2) = rt
            .wait_for(futures::future::join(
                mgr.get_or_launch(&pop, di()),
                mgr.get_or_launch(&imap, di()),
            ))
            .await;

        let pop2 = pop2.unwrap().0;
        let imap2 = imap2.unwrap().0;

        assert!(!FakeCirc::eq(&pop2, &pop1));
        assert!(FakeCirc::eq(&imap2, &imap1));
    });
}

/// Returns three exit policies; one that permits nothing, one that permits ports 80
/// and 443 only, and one that permits all ports.
fn get_exit_policies() -> (ExitPolicy, ExitPolicy, ExitPolicy) {
    // FIXME(eta): the below is copypasta; would be nice to have a better way of
    //             constructing ExitPolicy objects for testing maybe
    let network = testnet::construct_netdir().unwrap_if_sufficient().unwrap();

    // Nodes with ID 0x0a through 0x13 and 0x1e through 0x27 are
    // exits.  Odd-numbered ones allow only ports 80 and 443;
    // even-numbered ones allow all ports.
    let id_noexit: Ed25519Identity = [0x05; 32].into();
    let id_webexit: Ed25519Identity = [0x11; 32].into();
    let id_fullexit: Ed25519Identity = [0x20; 32].into();

    let not_exit = network.by_id(&id_noexit).unwrap();
    let web_exit = network.by_id(&id_webexit).unwrap();
    let full_exit = network.by_id(&id_fullexit).unwrap();

    let ep_none = ExitPolicy::from_relay(&not_exit);
    let ep_web = ExitPolicy::from_relay(&web_exit);
    let ep_full = ExitPolicy::from_relay(&full_exit);
    (ep_none, ep_web, ep_full)
}

#[test]
fn test_find_supported() {
    let (ep_none, ep_web, ep_full) = get_exit_policies();
    let fake_circ = FakeCirc { id: FakeId::next() };
    let expiration = ExpirationInfo::Unused {
        created: Instant::get(),
    };

    let mut entry_none = OpenEntry::new(
        SupportedTunnelUsage::Exit {
            policy: ep_none,
            isolation: None,
            country_code: None,
            all_relays_stable: true,
        },
        fake_circ.clone(),
        expiration.clone(),
    );
    let mut entry_none_c = entry_none.clone();
    let mut entry_web = OpenEntry::new(
        SupportedTunnelUsage::Exit {
            policy: ep_web,
            isolation: None,
            country_code: None,
            all_relays_stable: true,
        },
        fake_circ.clone(),
        expiration.clone(),
    );
    let mut entry_web_c = entry_web.clone();
    let mut entry_full = OpenEntry::new(
        SupportedTunnelUsage::Exit {
            policy: ep_full,
            isolation: None,
            country_code: None,
            all_relays_stable: true,
        },
        fake_circ,
        expiration,
    );
    let mut entry_full_c = entry_full.clone();

    let usage_web = TargetTunnelUsage::new_from_ipv4_ports(&[80]);
    let empty: Vec<&mut OpenEntry<FakeCirc>> = vec![];

    assert_isoleq!(
        SupportedTunnelUsage::find_supported(vec![&mut entry_none].into_iter(), &usage_web),
        empty
    );

    // HACK(eta): We have to faff around with clones and such because
    //            `abstract_spec_find_supported` has a silly signature that involves `&mut`
    //            refs, which we can't have more than one of.

    assert_isoleq!(
        SupportedTunnelUsage::find_supported(
            vec![&mut entry_none, &mut entry_web].into_iter(),
            &usage_web,
        ),
        vec![&mut entry_web_c]
    );

    assert_isoleq!(
        SupportedTunnelUsage::find_supported(
            vec![&mut entry_none, &mut entry_web, &mut entry_full].into_iter(),
            &usage_web,
        ),
        vec![&mut entry_web_c, &mut entry_full_c]
    );

    // Test preemptive tunnel usage:

    let usage_preemptive_web = TargetTunnelUsage::Preemptive {
        port: Some(TargetPort::ipv4(80)),
        circs: 2,
        require_stability: false,
    };
    let usage_preemptive_dns = TargetTunnelUsage::Preemptive {
        port: None,
        circs: 2,
        require_stability: false,
    };

    // shouldn't return anything unless there are >=2 tunnels

    assert_isoleq!(
        SupportedTunnelUsage::find_supported(
            vec![&mut entry_none].into_iter(),
            &usage_preemptive_web
        ),
        empty
    );

    assert_isoleq!(
        SupportedTunnelUsage::find_supported(
            vec![&mut entry_none].into_iter(),
            &usage_preemptive_dns
        ),
        empty
    );

    assert_isoleq!(
        SupportedTunnelUsage::find_supported(
            vec![&mut entry_none, &mut entry_web].into_iter(),
            &usage_preemptive_web
        ),
        empty
    );

    assert_isoleq!(
        SupportedTunnelUsage::find_supported(
            vec![&mut entry_none, &mut entry_web].into_iter(),
            &usage_preemptive_dns
        ),
        vec![&mut entry_none_c, &mut entry_web_c]
    );

    assert_isoleq!(
        SupportedTunnelUsage::find_supported(
            vec![&mut entry_none, &mut entry_web, &mut entry_full].into_iter(),
            &usage_preemptive_web
        ),
        vec![&mut entry_web_c, &mut entry_full_c]
    );
}

#[test]
fn test_circlist_preemptive_target_circs() {
    MockRuntime::test_with_various(|rt| async move {
        #[allow(deprecated)] // TODO #1885
        let rt = MockSleepRuntime::new(rt);
        let netdir = testnet::construct_netdir().unwrap_if_sufficient().unwrap();
        let dirinfo = DirInfo::Directory(&netdir);

        let builder = make_builder(&rt);

        for circs in [2, 8].iter() {
            let mut circlist = TunnelList::<FakeBuilder<MockRuntime>, MockRuntime>::new();

            let preemptive_target = TargetTunnelUsage::Preemptive {
                port: Some(TargetPort::ipv4(80)),
                circs: *circs,
                require_stability: false,
            };

            for _ in 0..*circs {
                assert!(circlist.find_open(&preemptive_target).is_none());

                let usage = TargetTunnelUsage::new_from_ipv4_ports(&[80]);
                let (plan, _) = builder.plan_tunnel(&usage, dirinfo).unwrap();
                let (spec, circ) = rt.wait_for(builder.build_tunnel(plan)).await.unwrap();
                let entry = OpenEntry::new(
                    spec,
                    circ,
                    ExpirationInfo::new(rt.now() + Duration::from_secs(60)),
                );
                circlist.add_open(entry);
            }

            assert!(circlist.find_open(&preemptive_target).is_some());
        }
    });
}
