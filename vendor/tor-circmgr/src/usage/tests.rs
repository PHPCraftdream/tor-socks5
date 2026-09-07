#![allow(clippy::unwrap_used)]
use super::*;
use crate::isolation::test::{IsolationTokenEq, assert_isoleq};
use crate::isolation::{IsolationToken, StreamIsolationBuilder};
use crate::path::OwnedPath;
use tor_basic_utils::test_rng::testing_rng;
use tor_guardmgr::TestConfig;
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_netdir::testnet;
use tor_persist::TestingStateMgr;
use web_time_compat::SystemTimeExt;

impl IsolationTokenEq for TargetTunnelUsage {
    fn isol_eq(&self, other: &Self) -> bool {
        use TargetTunnelUsage::*;
        match (self, other) {
            (Dir, Dir) => true,
            (
                Exit {
                    ports: p1,
                    isolation: is1,
                    country_code: cc1,
                    ..
                },
                Exit {
                    ports: p2,
                    isolation: is2,
                    country_code: cc2,
                    ..
                },
            ) => p1 == p2 && cc1 == cc2 && is1.isol_eq(is2),
            (TimeoutTesting, TimeoutTesting) => true,
            (
                Preemptive {
                    port: p1,
                    circs: c1,
                    ..
                },
                Preemptive {
                    port: p2,
                    circs: c2,
                    ..
                },
            ) => p1 == p2 && c1 == c2,
            _ => false,
        }
    }
}

impl IsolationTokenEq for SupportedTunnelUsage {
    fn isol_eq(&self, other: &Self) -> bool {
        use SupportedTunnelUsage::*;
        match (self, other) {
            (Dir, Dir) => true,
            (
                Exit {
                    policy: p1,
                    isolation: is1,
                    country_code: cc1,
                    ..
                },
                Exit {
                    policy: p2,
                    isolation: is2,
                    country_code: cc2,
                    ..
                },
            ) => p1 == p2 && is1.isol_eq(is2) && cc1 == cc2,
            (NoUsage, NoUsage) => true,
            _ => false,
        }
    }
}

#[test]
fn exit_policy() {
    use tor_netdir::testnet::construct_custom_netdir;
    use tor_netdoc::types::relay_flags::RelayFlag;

    let network = construct_custom_netdir(|idx, nb, _| {
        if (0x21..0x27).contains(&idx) {
            nb.rs.add_flags(RelayFlag::BadExit);
        }
    })
    .unwrap()
    .unwrap_if_sufficient()
    .unwrap();

    // Nodes with ID 0x0a through 0x13 and 0x1e through 0x27 are
    // exits.  Odd-numbered ones allow only ports 80 and 443;
    // even-numbered ones allow all ports.  Nodes with ID 0x21
    // through 0x27 are bad exits.
    let id_noexit: Ed25519Identity = [0x05; 32].into();
    let id_webexit: Ed25519Identity = [0x11; 32].into();
    let id_fullexit: Ed25519Identity = [0x20; 32].into();
    let id_badexit: Ed25519Identity = [0x25; 32].into();

    let not_exit = network.by_id(&id_noexit).unwrap();
    let web_exit = network.by_id(&id_webexit).unwrap();
    let full_exit = network.by_id(&id_fullexit).unwrap();
    let bad_exit = network.by_id(&id_badexit).unwrap();

    let ep_none = ExitPolicy::from_relay(&not_exit);
    let ep_web = ExitPolicy::from_relay(&web_exit);
    let ep_full = ExitPolicy::from_relay(&full_exit);
    let ep_bad = ExitPolicy::from_relay(&bad_exit);

    assert!(!ep_none.allows_port(TargetPort::ipv4(80)));
    assert!(!ep_none.allows_port(TargetPort::ipv4(9999)));

    assert!(ep_web.allows_port(TargetPort::ipv4(80)));
    assert!(ep_web.allows_port(TargetPort::ipv4(443)));
    assert!(!ep_web.allows_port(TargetPort::ipv4(9999)));

    assert!(ep_full.allows_port(TargetPort::ipv4(80)));
    assert!(ep_full.allows_port(TargetPort::ipv4(443)));
    assert!(ep_full.allows_port(TargetPort::ipv4(9999)));

    assert!(!ep_bad.allows_port(TargetPort::ipv4(80)));

    // Note that nobody in the testdir::network allows ipv6.
    assert!(!ep_none.allows_port(TargetPort::ipv6(80)));
    assert!(!ep_web.allows_port(TargetPort::ipv6(80)));
    assert!(!ep_full.allows_port(TargetPort::ipv6(80)));
    assert!(!ep_bad.allows_port(TargetPort::ipv6(80)));

    // Check is_supported_by while we're here.
    assert!(TargetPort::ipv4(80).is_supported_by(&web_exit.low_level_details()));
    assert!(!TargetPort::ipv6(80).is_supported_by(&web_exit.low_level_details()));
    assert!(!TargetPort::ipv6(80).is_supported_by(&bad_exit.low_level_details()));
}

#[test]
fn usage_ops() {
    // Make an exit-policy object that allows web on IPv4 and
    // smtp on IPv6.
    let policy = ExitPolicy {
        v4: Arc::new("accept 80,443".parse().unwrap()),
        v6: Arc::new("accept 23".parse().unwrap()),
    };
    let tok1 = IsolationToken::new();
    let tok2 = IsolationToken::new();
    let isolation = StreamIsolationBuilder::new()
        .owner_token(tok1)
        .build()
        .unwrap();
    let isolation2 = StreamIsolationBuilder::new()
        .owner_token(tok2)
        .build()
        .unwrap();

    let supp_dir = SupportedTunnelUsage::Dir;
    let targ_dir = TargetTunnelUsage::Dir;
    let supp_exit = SupportedTunnelUsage::Exit {
        policy: policy.clone(),
        isolation: Some(isolation.clone()),
        country_code: None,
        all_relays_stable: true,
    };
    let supp_exit_iso2 = SupportedTunnelUsage::Exit {
        policy: policy.clone(),
        isolation: Some(isolation2.clone()),
        country_code: None,
        all_relays_stable: true,
    };
    let supp_exit_no_iso = SupportedTunnelUsage::Exit {
        policy,
        isolation: None,
        country_code: None,
        all_relays_stable: true,
    };
    let supp_none = SupportedTunnelUsage::NoUsage;

    let targ_80_v4 = TargetTunnelUsage::Exit {
        ports: vec![TargetPort::ipv4(80)],
        isolation: isolation.clone(),
        country_code: None,
        require_stability: false,
    };
    let targ_80_v4_iso2 = TargetTunnelUsage::Exit {
        ports: vec![TargetPort::ipv4(80)],
        isolation: isolation2,
        country_code: None,
        require_stability: false,
    };
    let targ_80_23_v4 = TargetTunnelUsage::Exit {
        ports: vec![TargetPort::ipv4(80), TargetPort::ipv4(23)],
        isolation: isolation.clone(),
        country_code: None,
        require_stability: false,
    };

    let targ_80_23_mixed = TargetTunnelUsage::Exit {
        ports: vec![TargetPort::ipv4(80), TargetPort::ipv6(23)],
        isolation: isolation.clone(),
        country_code: None,
        require_stability: false,
    };
    let targ_999_v6 = TargetTunnelUsage::Exit {
        ports: vec![TargetPort::ipv6(999)],
        isolation,
        country_code: None,
        require_stability: false,
    };
    let targ_testing = TargetTunnelUsage::TimeoutTesting;

    assert!(supp_dir.supports(&targ_dir));
    assert!(!supp_dir.supports(&targ_80_v4));
    assert!(!supp_exit.supports(&targ_dir));
    assert!(supp_exit.supports(&targ_80_v4));
    assert!(!supp_exit.supports(&targ_80_v4_iso2));
    assert!(supp_exit.supports(&targ_80_23_mixed));
    assert!(!supp_exit.supports(&targ_80_23_v4));
    assert!(!supp_exit.supports(&targ_999_v6));
    assert!(!supp_exit_iso2.supports(&targ_80_v4));
    assert!(supp_exit_iso2.supports(&targ_80_v4_iso2));
    assert!(supp_exit_no_iso.supports(&targ_80_v4));
    assert!(supp_exit_no_iso.supports(&targ_80_v4_iso2));
    assert!(!supp_exit_no_iso.supports(&targ_80_23_v4));
    assert!(!supp_none.supports(&targ_dir));
    assert!(!supp_none.supports(&targ_80_23_v4));
    assert!(!supp_none.supports(&targ_80_v4_iso2));
    assert!(!supp_dir.supports(&targ_testing));
    assert!(supp_exit.supports(&targ_testing));
    assert!(supp_exit_no_iso.supports(&targ_testing));
    assert!(supp_exit_iso2.supports(&targ_testing));
    assert!(supp_none.supports(&targ_testing));
}

#[test]
fn restrict_mut() {
    let policy = ExitPolicy {
        v4: Arc::new("accept 80,443".parse().unwrap()),
        v6: Arc::new("accept 23".parse().unwrap()),
    };

    let tok1 = IsolationToken::new();
    let tok2 = IsolationToken::new();
    let isolation = StreamIsolationBuilder::new()
        .owner_token(tok1)
        .build()
        .unwrap();
    let isolation2 = StreamIsolationBuilder::new()
        .owner_token(tok2)
        .build()
        .unwrap();

    let supp_dir = SupportedTunnelUsage::Dir;
    let targ_dir = TargetTunnelUsage::Dir;
    let supp_exit = SupportedTunnelUsage::Exit {
        policy: policy.clone(),
        isolation: Some(isolation.clone()),
        country_code: None,
        all_relays_stable: true,
    };
    let supp_exit_iso2 = SupportedTunnelUsage::Exit {
        policy: policy.clone(),
        isolation: Some(isolation2.clone()),
        country_code: None,
        all_relays_stable: true,
    };
    let supp_exit_no_iso = SupportedTunnelUsage::Exit {
        policy,
        isolation: None,
        country_code: None,
        all_relays_stable: true,
    };
    let supp_none = SupportedTunnelUsage::NoUsage;
    let targ_exit = TargetTunnelUsage::Exit {
        ports: vec![TargetPort::ipv4(80)],
        isolation,
        country_code: None,
        require_stability: false,
    };
    let targ_exit_iso2 = TargetTunnelUsage::Exit {
        ports: vec![TargetPort::ipv4(80)],
        isolation: isolation2,
        country_code: None,
        require_stability: false,
    };
    let targ_testing = TargetTunnelUsage::TimeoutTesting;

    // not allowed, do nothing
    let mut supp_dir_c = supp_dir.clone();
    assert!(supp_dir_c.restrict_mut(&targ_exit).is_err());
    assert!(supp_dir_c.restrict_mut(&targ_testing).is_err());
    assert_isoleq!(supp_dir, supp_dir_c);

    let mut supp_exit_c = supp_exit.clone();
    assert!(supp_exit_c.restrict_mut(&targ_dir).is_err());
    assert_isoleq!(supp_exit, supp_exit_c);

    let mut supp_exit_c = supp_exit.clone();
    assert!(supp_exit_c.restrict_mut(&targ_exit_iso2).is_err());
    assert_isoleq!(supp_exit, supp_exit_c);

    let mut supp_exit_iso2_c = supp_exit_iso2.clone();
    assert!(supp_exit_iso2_c.restrict_mut(&targ_exit).is_err());
    assert_isoleq!(supp_exit_iso2, supp_exit_iso2_c);

    let mut supp_none_c = supp_none.clone();
    assert!(supp_none_c.restrict_mut(&targ_exit).is_err());
    assert!(supp_none_c.restrict_mut(&targ_dir).is_err());
    assert_isoleq!(supp_none_c, supp_none);

    // allowed but nothing to do
    let mut supp_dir_c = supp_dir.clone();
    supp_dir_c.restrict_mut(&targ_dir).unwrap();
    assert_isoleq!(supp_dir, supp_dir_c);

    let mut supp_exit_c = supp_exit.clone();
    supp_exit_c.restrict_mut(&targ_exit).unwrap();
    assert_isoleq!(supp_exit, supp_exit_c);

    let mut supp_exit_iso2_c = supp_exit_iso2.clone();
    supp_exit_iso2_c.restrict_mut(&targ_exit_iso2).unwrap();
    supp_none_c.restrict_mut(&targ_testing).unwrap();
    assert_isoleq!(supp_exit_iso2, supp_exit_iso2_c);

    let mut supp_none_c = supp_none.clone();
    supp_none_c.restrict_mut(&targ_testing).unwrap();
    assert_isoleq!(supp_none_c, supp_none);

    // allowed, do something
    let mut supp_exit_no_iso_c = supp_exit_no_iso.clone();
    supp_exit_no_iso_c.restrict_mut(&targ_exit).unwrap();
    assert!(supp_exit_no_iso_c.supports(&targ_exit));
    assert!(!supp_exit_no_iso_c.supports(&targ_exit_iso2));

    let mut supp_exit_no_iso_c = supp_exit_no_iso;
    supp_exit_no_iso_c.restrict_mut(&targ_exit_iso2).unwrap();
    assert!(!supp_exit_no_iso_c.supports(&targ_exit));
    assert!(supp_exit_no_iso_c.supports(&targ_exit_iso2));
}

#[test]
fn buildpath() {
    tor_rtcompat::test_with_all_runtimes!(|rt| async move {
        let mut rng = testing_rng();
        let netdir = testnet::construct_netdir().unwrap_if_sufficient().unwrap();
        let di = (&netdir).into();
        let config = crate::PathConfig::default();
        let statemgr = TestingStateMgr::new();
        let guards =
            tor_guardmgr::GuardMgr::new(rt.clone(), statemgr.clone(), &TestConfig::default())
                .unwrap();
        guards.install_test_netdir(&netdir);
        let now = SystemTime::get();

        // Only doing basic tests for now.  We'll test the path
        // building code a lot more closely in the tests for TorPath
        // and friends.

        #[cfg(all(feature = "vanguards", feature = "hs-common"))]
        let vanguards = VanguardMgr::new(&Default::default(), rt.clone(), statemgr, false).unwrap();

        // First, a one-hop directory circuit
        let (p_dir, u_dir, _, _) = TargetTunnelUsage::Dir
            .build_path(
                &mut rng,
                di,
                &guards,
                #[cfg(all(feature = "vanguards", feature = "hs-common"))]
                &vanguards,
                &config,
                now,
            )
            .unwrap();
        assert!(matches!(u_dir, SupportedTunnelUsage::Dir));
        assert_eq!(p_dir.len(), 1);

        // Now an exit circuit, to port 995.
        let tok1 = IsolationToken::new();
        let isolation = StreamIsolationBuilder::new()
            .owner_token(tok1)
            .build()
            .unwrap();

        let exit_usage = TargetTunnelUsage::Exit {
            ports: vec![TargetPort::ipv4(995)],
            isolation: isolation.clone(),
            country_code: None,
            require_stability: false,
        };
        let (p_exit, u_exit, _, _) = exit_usage
            .build_path(
                &mut rng,
                di,
                &guards,
                #[cfg(all(feature = "vanguards", feature = "hs-common"))]
                &vanguards,
                &config,
                now,
            )
            .unwrap();
        assert!(matches!(
            u_exit,
            SupportedTunnelUsage::Exit {
                isolation: ref iso,
                ..
            } if iso.isol_eq(&Some(isolation))
        ));
        assert!(u_exit.supports(&exit_usage));
        assert_eq!(p_exit.len(), 3);

        // Now try testing circuits.
        let (path, usage, _, _) = TargetTunnelUsage::TimeoutTesting
            .build_path(
                &mut rng,
                di,
                &guards,
                #[cfg(all(feature = "vanguards", feature = "hs-common"))]
                &vanguards,
                &config,
                now,
            )
            .unwrap();
        let path = match OwnedPath::try_from(&path).unwrap() {
            OwnedPath::ChannelOnly(_) => panic!("Impossible path type."),
            OwnedPath::Normal(p) => p,
        };
        assert_eq!(path.len(), 3);

        // Make sure that the usage is correct.
        let last_relay = netdir.by_ids(&path[2]).unwrap();
        let policy = ExitPolicy::from_relay(&last_relay);
        // We'll always get exits for these, since we try to build
        // paths with an exit if there are any exits.
        assert!(policy.allows_some_port());
        assert!(last_relay.low_level_details().policies_allow_some_port());
        assert_isoleq!(
            usage,
            SupportedTunnelUsage::Exit {
                policy,
                isolation: None,
                country_code: None,
                all_relays_stable: true
            }
        );
    });
}

#[test]
fn build_testing_noexit() {
    // Here we'll try to build paths for testing circuits on a network
    // with no exits.
    tor_rtcompat::test_with_all_runtimes!(|rt| async move {
        let mut rng = testing_rng();
        let netdir = testnet::construct_custom_netdir(|_idx, bld, _| {
            bld.md.parse_ipv4_policy("reject 1-65535").unwrap();
        })
        .unwrap()
        .unwrap_if_sufficient()
        .unwrap();
        let di = (&netdir).into();
        let config = crate::PathConfig::default();
        let statemgr = TestingStateMgr::new();
        let guards =
            tor_guardmgr::GuardMgr::new(rt.clone(), statemgr.clone(), &TestConfig::default())
                .unwrap();
        guards.install_test_netdir(&netdir);
        let now = SystemTime::get();

        #[cfg(all(feature = "vanguards", feature = "hs-common"))]
        let vanguards = VanguardMgr::new(&Default::default(), rt.clone(), statemgr, false).unwrap();

        let (path, usage, _, _) = TargetTunnelUsage::TimeoutTesting
            .build_path(
                &mut rng,
                di,
                &guards,
                #[cfg(all(feature = "vanguards", feature = "hs-common"))]
                &vanguards,
                &config,
                now,
            )
            .unwrap();
        assert_eq!(path.len(), 3);
        assert_isoleq!(usage, SupportedTunnelUsage::NoUsage);
    });
}

#[test]
fn display_target_ports() {
    let ports = [];
    assert_eq!(TargetPorts::from(&ports[..]).to_string(), "[]");

    let ports = [TargetPort::ipv4(80)];
    assert_eq!(TargetPorts::from(&ports[..]).to_string(), "80v4");
    let ports = [TargetPort::ipv4(80), TargetPort::ipv6(443)];
    assert_eq!(TargetPorts::from(&ports[..]).to_string(), "[80v4,443v6]");
}
