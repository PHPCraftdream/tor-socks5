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
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use super::*;

#[test]
fn defaults() {
    let dflt = TorClientConfig::default();
    let b2 = TorClientConfigBuilder::default();
    let dflt2 = b2.build().unwrap();
    assert_eq!(&dflt, &dflt2);
}

#[test]
fn builder() {
    let sec = std::time::Duration::from_secs(1);

    let mut authorities = dir::AuthorityContacts::builder();
    authorities.v3idents().push([22; 20].into());
    authorities.v3idents().push([44; 20].into());
    authorities.uploads().push(vec![
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80)),
        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 80, 0, 0)),
    ]);

    let mut fallback = dir::FallbackDir::builder();
    fallback
        .rsa_identity([23; 20].into())
        .ed_identity([99; 32].into())
        .orports()
        .push("127.0.0.7:7".parse().unwrap());

    let mut bld = TorClientConfig::builder();
    *bld.tor_network().authorities() = authorities;
    bld.tor_network().set_fallback_caches(vec![fallback]);
    bld.storage()
        .cache_dir(CfgPath::new("/var/tmp/foo".to_owned()))
        .state_dir(CfgPath::new("/var/tmp/bar".to_owned()));
    bld.download_schedule().retry_certs().attempts(10);
    bld.download_schedule().retry_certs().initial_delay(sec);
    bld.download_schedule().retry_certs().parallelism(3);
    bld.download_schedule().retry_microdescs().attempts(30);
    bld.download_schedule()
        .retry_microdescs()
        .initial_delay(10 * sec);
    bld.download_schedule().retry_microdescs().parallelism(9);
    bld.override_net_params()
        .insert("wombats-per-quokka".to_owned(), 7);
    bld.path_rules()
        .ipv4_subnet_family_prefix(20)
        .ipv6_subnet_family_prefix(48);
    bld.circuit_timing()
        .max_dirtiness(90 * sec)
        .request_timeout(10 * sec)
        .request_max_retries(22)
        .request_loyalty(3600 * sec);
    bld.address_filter().allow_local_addrs(true);

    let val = bld.build().unwrap();

    assert_ne!(val, TorClientConfig::default());
}

#[test]
fn bridges_supported() {
    /// checks that when s is processed as TOML for a client config,
    /// the resulting number of bridges is according to `exp`
    fn chk(exp: Result<usize, ()>, s: &str) {
        eprintln!("----------\n{s}\n----------\n");
        let got = (|| {
            let cfg: toml::Value = toml::from_str(s).unwrap();
            let cfg: TorClientConfigBuilder = cfg.try_into()?;
            let cfg = cfg.build()?;
            let n_bridges = cfg.bridges.bridges.len();
            Ok::<_, anyhow::Error>(n_bridges) // anyhow is just something we can use for ?
        })()
        .map_err(|_| ());
        assert_eq!(got, exp);
    }

    let chk_enabled_or_auto = |exp, bridges_toml| {
        for enabled in [r#""#, r#"enabled = true"#, r#"enabled = "auto""#] {
            chk(exp, &format!("[bridges]\n{}\n{}", enabled, bridges_toml));
        }
    };

    let ok_1_if = |b: bool| b.then_some(1).ok_or(());

    chk(
        Err(()),
        r#"
                [bridges]
                enabled = true
            "#,
    );

    chk_enabled_or_auto(
        ok_1_if(cfg!(feature = "bridge-client")),
        r#"
                bridges = ["192.0.2.83:80 $0bac39417268b96b9f514ef763fa6fba1a788956"]
            "#,
    );

    chk_enabled_or_auto(
        ok_1_if(cfg!(feature = "pt-client")),
        r#"
                bridges = ["obfs4 bridge.example.net:80 $0bac39417268b69b9f514e7f63fa6fba1a788958 ed25519:dGhpcyBpcyBbpmNyZWRpYmx5IHNpbGx5ISEhISEhISA iat-mode=1"]
                [[bridges.transports]]
                protocols = ["obfs4"]
                path = "obfs4proxy"
            "#,
    );
}

#[test]
fn check_default() {
    // We don't want to second-guess the directories crate too much
    // here, so we'll just make sure it does _something_ plausible.

    let dflt = default_config_files().unwrap();
    assert!(dflt[0].as_path().unwrap().ends_with("arti.toml"));
    assert!(dflt[1].as_path().unwrap().ends_with("arti.d"));
    assert_eq!(dflt.len(), 2);
}

#[test]
#[cfg(not(all(
    feature = "vanguards",
    any(feature = "onion-service-client", feature = "onion-service-service"),
)))]
fn check_disabled_vanguards_static() {
    // Force us to evaluate the closure to ensure that it builds correctly.
    #[allow(clippy::borrowed_box)]
    let _: &Box<VanguardConfig> = LazyLock::force(&DISABLED_VANGUARDS);
}

#[test]
#[cfg(feature = "pt-client")]
fn check_bridge_pt() {
    let from_toml = |s: &str| -> TorClientConfigBuilder {
        let cfg: toml::Value = toml::from_str(dbg!(s)).unwrap();
        let cfg: TorClientConfigBuilder = cfg.try_into().unwrap();
        cfg
    };

    let chk =
        |cfg: &TorClientConfigBuilder, expected: Result<(), &str>| match (cfg.build(), expected) {
            (Ok(_), Ok(())) => {}
            (Err(e), Err(ex)) => {
                if !e.to_string().contains(ex) {
                    panic!("\"{e}\" did not contain {ex}");
                }
            }
            (Ok(_), Err(ex)) => {
                panic!("Expected {ex} but cfg succeeded");
            }
            (Err(e), Ok(())) => {
                panic!("Expected success but got error {e}")
            }
        };

    let test_cases = [
        ("# No bridges", Ok(())),
        (
            r#"
                    # No bridges but we still enabled bridges
                    [bridges]
                    enabled = true
                    bridges = []
                "#,
            Err("bridges.enabled=true, but no bridges defined"),
        ),
        (
            r#"
                    # One non-PT bridge
                    [bridges]
                    enabled = true
                    bridges = [
                        "192.0.2.83:80 $0bac39417268b96b9f514ef763fa6fba1a788956",
                    ]
                "#,
            Ok(()),
        ),
        (
            r#"
                    # One obfs4 bridge
                    [bridges]
                    enabled = true
                    bridges = [
                        "obfs4 bridge.example.net:80 $0bac39417268b69b9f514e7f63fa6fba1a788958 ed25519:dGhpcyBpcyBbpmNyZWRpYmx5IHNpbGx5ISEhISEhISA iat-mode=1",
                    ]
                    [[bridges.transports]]
                    protocols = ["obfs4"]
                    path = "obfs4proxy"
                "#,
            Ok(()),
        ),
        (
            r#"
                    # One obfs4 bridge with unmanaged transport.
                    [bridges]
                    enabled = true
                    bridges = [
                        "obfs4 bridge.example.net:80 $0bac39417268b69b9f514e7f63fa6fba1a788958 ed25519:dGhpcyBpcyBbpmNyZWRpYmx5IHNpbGx5ISEhISEhISA iat-mode=1",
                    ]
                    [[bridges.transports]]
                    protocols = ["obfs4"]
                    proxy_addr = "127.0.0.1:31337"
                "#,
            Ok(()),
        ),
        (
            r#"
                    # Transport is both managed and unmanaged.
                    [[bridges.transports]]
                    protocols = ["obfs4"]
                    path = "obfsproxy"
                    proxy_addr = "127.0.0.1:9999"
                "#,
            Err("Cannot provide both path and proxy_addr"),
        ),
        (
            r#"
                    # One obfs4 bridge and non-PT bridge
                    [bridges]
                    enabled = false
                    bridges = [
                        "192.0.2.83:80 $0bac39417268b96b9f514ef763fa6fba1a788956",
                        "obfs4 bridge.example.net:80 $0bac39417268b69b9f514e7f63fa6fba1a788958 ed25519:dGhpcyBpcyBbpmNyZWRpYmx5IHNpbGx5ISEhISEhISA iat-mode=1",
                    ]
                    [[bridges.transports]]
                    protocols = ["obfs4"]
                    path = "obfs4proxy"
                "#,
            Ok(()),
        ),
        (
            r#"
                    # One obfs4 and non-PT bridge with no transport
                    [bridges]
                    enabled = true
                    bridges = [
                        "192.0.2.83:80 $0bac39417268b96b9f514ef763fa6fba1a788956",
                        "obfs4 bridge.example.net:80 $0bac39417268b69b9f514e7f63fa6fba1a788958 ed25519:dGhpcyBpcyBbpmNyZWRpYmx5IHNpbGx5ISEhISEhISA iat-mode=1",
                    ]
                "#,
            Ok(()),
        ),
        (
            r#"
                    # One obfs4 bridge with no transport
                    [bridges]
                    enabled = true
                    bridges = [
                        "obfs4 bridge.example.net:80 $0bac39417268b69b9f514e7f63fa6fba1a788958 ed25519:dGhpcyBpcyBbpmNyZWRpYmx5IHNpbGx5ISEhISEhISA iat-mode=1",
                    ]
                "#,
            Err("all bridges unusable due to lack of corresponding pluggable transport"),
        ),
        (
            r#"
                    # One obfs4 bridge with no transport but bridges are disabled
                    [bridges]
                    enabled = false
                    bridges = [
                        "obfs4 bridge.example.net:80 $0bac39417268b69b9f514e7f63fa6fba1a788958 ed25519:dGhpcyBpcyBbpmNyZWRpYmx5IHNpbGx5ISEhISEhISA iat-mode=1",
                    ]
                "#,
            Ok(()),
        ),
        (
            r#"
                        # One non-PT bridge with a redundant transports section
                        [bridges]
                        enabled = false
                        bridges = [
                            "192.0.2.83:80 $0bac39417268b96b9f514ef763fa6fba1a788956",
                        ]
                        [[bridges.transports]]
                        protocols = ["obfs4"]
                        path = "obfs4proxy"
                "#,
            Ok(()),
        ),
    ];

    for (test_case, expected) in test_cases.iter() {
        chk(&from_toml(test_case), *expected);
    }
}
