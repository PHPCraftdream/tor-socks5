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

#[cfg(feature = "pt-client")]
fn mk_pt_target(name: &str, addr: PtTargetAddr, params: &[(&str, &str)]) -> ChannelMethod {
    let mut target = PtTarget::new(name.parse().unwrap(), addr);
    for &(k, v) in params {
        target.push_setting(k, v).unwrap();
    }
    ChannelMethod::Pluggable(target)
}

fn mk_direct(s: &str) -> ChannelMethod {
    ChannelMethod::Direct(vec![s.parse().unwrap()])
}

fn mk_rsa(s: &str) -> RsaIdentity {
    match s.parse().unwrap() {
        RelayId::Rsa(y) => y,
        _ => panic!("not rsa {:?}", s),
    }
}
fn mk_ed(s: &str) -> Ed25519Identity {
    match s.parse().unwrap() {
        RelayId::Ed25519(y) => y,
        _ => panic!("not ed {:?}", s),
    }
}

#[test]
fn bridge_lines() {
    let chk = |sl: &[&str], exp: Inner| {
        for s in sl {
            let got: BridgeConfig = s.parse().expect(s);
            assert_eq!(*got.0, exp, "{:?}", s);

            let display = got.to_string();
            assert_eq!(display, sl[0]);
        }
    };

    let chk_e = |sl: &[&str], exp: &str| {
        for s in sl {
            let got: Result<BridgeConfig, _> = s.parse();
            let got = got.expect_err(s);
            let got_s = got.to_string();
            assert!(
                got_s.contains(exp),
                "{:?} => {:?} ({}) not {}",
                s,
                got,
                got_s,
                exp
            );
        }
    };

    // example from https://tb-manual.torproject.org/bridges/, with cert= truncated
    #[cfg(feature = "pt-client")]
    chk(
        &[
            "obfs4 38.229.33.83:80 $0bac39417268b96b9f514e7f63fa6fba1a788955 cert=VwEFpk9F/UN9JED7XpG1XOjm/O8ZCXK80oPecgWnNDZDv5pdkhq1Op iat-mode=1",
            "obfs4 38.229.33.83:80 0BAC39417268B96B9F514E7F63FA6FBA1A788955 cert=VwEFpk9F/UN9JED7XpG1XOjm/O8ZCXK80oPecgWnNDZDv5pdkhq1Op iat-mode=1",
            "Bridge obfs4 38.229.33.83:80 0BAC39417268B96B9F514E7F63FA6FBA1A788955 cert=VwEFpk9F/UN9JED7XpG1XOjm/O8ZCXK80oPecgWnNDZDv5pdkhq1Op iat-mode=1",
        ],
        Inner {
            addrs: mk_pt_target(
                "obfs4",
                PtTargetAddr::IpPort("38.229.33.83:80".parse().unwrap()),
                &[
                    (
                        "cert",
                        "VwEFpk9F/UN9JED7XpG1XOjm/O8ZCXK80oPecgWnNDZDv5pdkhq1Op",
                    ),
                    ("iat-mode", "1"),
                ],
            ),
            rsa_id: mk_rsa("0BAC39417268B96B9F514E7F63FA6FBA1A788955"),
            ed_id: None,
        },
    );

    #[cfg(feature = "pt-client")]
    chk(
        &[
            "obfs4 some-host:80 $0bac39417268b96b9f514e7f63fa6fba1a788955 ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE iat-mode=1",
            "obfs4 some-host:80 ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE 0BAC39417268B96B9F514E7F63FA6FBA1A788955 iat-mode=1",
        ],
        Inner {
            addrs: mk_pt_target(
                "obfs4",
                PtTargetAddr::HostPort("some-host".into(), 80),
                &[("iat-mode", "1")],
            ),
            rsa_id: mk_rsa("0BAC39417268B96B9F514E7F63FA6FBA1A788955"),
            ed_id: Some(mk_ed("dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE")),
        },
    );

    chk(
        &[
            "38.229.33.83:80 $0bac39417268b96b9f514e7f63fa6fba1a788955",
            "Bridge 38.229.33.83:80 0BAC39417268B96B9F514E7F63FA6FBA1A788955",
        ],
        Inner {
            addrs: mk_direct("38.229.33.83:80"),
            rsa_id: mk_rsa("0BAC39417268B96B9F514E7F63FA6FBA1A788955"),
            ed_id: None,
        },
    );

    chk(
        &[
            "[2001:db8::42]:123 $0bac39417268b96b9f514e7f63fa6fba1a788955",
            "[2001:0db8::42]:123 $0bac39417268b96b9f514e7f63fa6fba1a788955",
        ],
        Inner {
            addrs: mk_direct("[2001:0db8::42]:123"),
            rsa_id: mk_rsa("0BAC39417268B96B9F514E7F63FA6FBA1A788955"),
            ed_id: None,
        },
    );

    chk(
        &[
            "38.229.33.83:80 $0bac39417268b96b9f514e7f63fa6fba1a788955 ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE",
            "38.229.33.83:80 ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE 0BAC39417268B96B9F514E7F63FA6FBA1A788955",
        ],
        Inner {
            addrs: mk_direct("38.229.33.83:80"),
            rsa_id: mk_rsa("0BAC39417268B96B9F514E7F63FA6FBA1A788955"),
            ed_id: Some(mk_ed("dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE")),
        },
    );

    chk_e(
        &[
            "38.229.33.83:80 ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE",
            "Bridge 38.229.33.83:80 ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE",
        ],
        "lacks specification of RSA identity key",
    );

    chk_e(&["", "bridge"], "Bridge line was empty");

    chk_e(
        &["999.329.33.83:80 0BAC39417268B96B9F514E7F63FA6FBA1A788955"],
        // Some Rust versions say "invalid socket address syntax",
        // some "invalid IP address syntax"
        r#"Cannot parse "999.329.33.83:80" as direct bridge IpAddress:ORPort"#,
    );

    chk_e(
        &[
            "38.229.33.83:80 0BAC39417268B96B9F514E7F63FA6FBA1A788955 key=value",
            "Bridge 38.229.33.83:80 0BAC39417268B96B9F514E7F63FA6FBA1A788955 key=value",
        ],
        "Parameters supplied but not valid without a pluggable transport",
    );

    chk_e(
        &[
            "bridge bridge some-host:80 0BAC39417268B96B9F514E7F63FA6FBA1A788955",
            "yikes! some-host:80 0BAC39417268B96B9F514E7F63FA6FBA1A788955",
        ],
        #[cfg(feature = "pt-client")]
        r" is not a valid pluggable transport ID), nor as direct bridge IpAddress:ORPort",
        #[cfg(not(feature = "pt-client"))]
        "is not an IpAddress:ORPort), but support disabled in cargo features",
    );

    #[cfg(feature = "pt-client")]
    chk_e(
        &["obfs4 garbage 0BAC39417268B96B9F514E7F63FA6FBA1A788955"],
        "as pluggable transport Host:ORPort",
    );

    #[cfg(feature = "pt-client")]
    chk_e(
        &["obfs4 some-host:80 0BAC39417268B96B9F514E7F63FA6FBA1A788955 key=value garbage"],
        r#"Expected PT key=value parameter, found "garbage" (which lacks an equals sign"#,
    );

    #[cfg(feature = "pt-client")]
    chk_e(
        &["obfs4 some-host:80 garbage"],
        r#"Cannot parse "garbage" as identity key (Invalid base64 data), or PT key=value"#,
    );

    chk_e(
        &[
            "38.229.33.83:80 0BAC39417268B96B9F514E7F63FA6FBA1A788955 23AC39417268B96B9F514E7F63FA6FBA1A788955",
            "38.229.33.83:80 0BAC39417268B96B9F514E7F63FA6FBA1A788955 dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE xGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE",
        ],
        "More than one identity of the same type specified",
    );
}

#[test]
fn config_api() {
    let chk_bridgeline = |line: &str, jsons: &[&str], f: &dyn Fn(&mut BridgeConfigBuilder)| {
        eprintln!(" ---- chk_bridgeline ----\n{}", line);

        let mut bcb = BridgeConfigBuilder::default();
        f(&mut bcb);
        let built = bcb.build().unwrap();
        assert_eq!(&built, &line.parse::<BridgeConfig>().unwrap());

        let parsed_b: BridgeConfigBuilder = line.parse().unwrap();
        assert_eq!(&built, &parsed_b.build().unwrap());

        let re_serialized = serde_json::to_value(&bcb).unwrap();
        assert_eq!(re_serialized, serde_json::Value::String(line.to_string()));

        for json in jsons {
            let from_dict: BridgeConfigBuilder = serde_json::from_str(json).unwrap();
            assert_eq!(&from_dict, &bcb);
            assert_eq!(&built, &from_dict.build().unwrap());
        }
    };

    chk_bridgeline(
        "38.229.33.83:80 $0bac39417268b96b9f514e7f63fa6fba1a788955 ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE",
        &[r#"{
                "addrs": ["38.229.33.83:80"],
                "ids": ["ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE",
                      "$0bac39417268b96b9f514e7f63fa6fba1a788955"]
            }"#],
        &|bcb| {
            bcb.addrs().push("38.229.33.83:80".parse().unwrap());
            bcb.ids().push(
                "ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE"
                    .parse()
                    .unwrap(),
            );
            bcb.ids()
                .push("$0bac39417268b96b9f514e7f63fa6fba1a788955".parse().unwrap());
        },
    );

    #[cfg(feature = "pt-client")]
    chk_bridgeline(
        "obfs4 some-host:80 $0bac39417268b96b9f514e7f63fa6fba1a788955 iat-mode=1",
        &[r#"{
                "transport": "obfs4",
                "addrs": ["some-host:80"],
                "ids": ["$0bac39417268b96b9f514e7f63fa6fba1a788955"],
                "settings": [["iat-mode", "1"]]
            }"#],
        &|bcb| {
            bcb.transport("obfs4");
            bcb.addrs().push("some-host:80".parse().unwrap());
            bcb.ids()
                .push("$0bac39417268b96b9f514e7f63fa6fba1a788955".parse().unwrap());
            bcb.push_setting("iat-mode", "1");
        },
    );

    let chk_broken = |emsg: &str, jsons: &[&str], f: &dyn Fn(&mut BridgeConfigBuilder)| {
        eprintln!(" ---- chk_bridgeline ----\n{:?}", emsg);

        let mut bcb = BridgeConfigBuilder::default();
        f(&mut bcb);

        for json in jsons {
            let from_dict: BridgeConfigBuilder = serde_json::from_str(json).unwrap();
            assert_eq!(&from_dict, &bcb);
        }

        let err = bcb.build().expect_err("succeeded?!");
        let got_emsg = err.to_string();
        assert!(
            got_emsg.contains(emsg),
            "wrong error message: got_emsg={:?} err={:?} expected={:?}",
            got_emsg,
            err,
            emsg,
        );

        // This is a kludge.  When we serialize `Option<Vec<_>>` as JSON,
        // we get a `Null` entry.  These `Null`s aren't in our test cases and we don't
        // really want them, although it's OK that they're there in the JSON.
        // The TOML serialization omits them completely, though.
        // So, we serialize the builder as TOML, and then convert the TOML to JSON Value.
        // That launders out the `Null`s and gives us the same Value as our original JSON.
        let toml_got = toml::to_string(&bcb).unwrap();
        let json_got: serde_json::Value = toml::from_str(&toml_got).unwrap();
        let json_exp: serde_json::Value = serde_json::from_str(jsons[0]).unwrap();
        assert_eq!(&json_got, &json_exp);
    };

    chk_broken(
        "Specified `settings` for a direct bridge connection",
        &[r#"{
                "settings": [["hi","there"]]
            }"#],
        &|bcb| {
            bcb.settings().push(("hi".into(), "there".into()));
        },
    );

    #[cfg(not(feature = "pt-client"))]
    chk_broken(
        "Not compiled with pluggable transport support",
        &[r#"{
                "transport": "obfs4"
            }"#],
        &|bcb| {
            bcb.transport("obfs4");
        },
    );

    #[cfg(feature = "pt-client")]
    chk_broken(
        "only numeric addresses are supported for a direct bridge connection",
        &[r#"{
                "transport": "bridge",
                "addrs": ["some-host:80"]
            }"#],
        &|bcb| {
            bcb.transport("bridge");
            bcb.addrs().push("some-host:80".parse().unwrap());
        },
    );

    chk_broken(
        "Missing `addrs` for a direct bridge connection",
        &[r#"{
                "transport": "-"
            }"#],
        &|bcb| {
            bcb.transport("-");
        },
    );

    #[cfg(feature = "pt-client")]
    chk_broken(
        "only supports a single nominal address",
        &[r#"{
                "transport": "obfs4",
                "addrs": ["some-host:80", "38.229.33.83:80"]
            }"#],
        &|bcb| {
            bcb.transport("obfs4");
            bcb.addrs().push("some-host:80".parse().unwrap());
            bcb.addrs().push("38.229.33.83:80".parse().unwrap());
        },
    );

    chk_broken(
        "multiple different ids of the same type (ed25519)",
        &[r#"{
                "addrs": ["38.229.33.83:80"],
                "ids": ["ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE",
                        "ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISA"]
            }"#],
        &|bcb| {
            bcb.addrs().push("38.229.33.83:80".parse().unwrap());
            bcb.ids().push(
                "ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE"
                    .parse()
                    .unwrap(),
            );
            bcb.ids().push(
                "ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISA"
                    .parse()
                    .unwrap(),
            );
        },
    );

    chk_broken(
        "need an RSA identity",
        &[r#"{
                "addrs": ["38.229.33.83:80"],
                "ids": ["ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE"]
            }"#],
        &|bcb| {
            bcb.addrs().push("38.229.33.83:80".parse().unwrap());
            bcb.ids().push(
                "ed25519:dGhpcyBpcyBpbmNyZWRpYmx5IHNpbGx5ISEhISEhISE"
                    .parse()
                    .unwrap(),
            );
        },
    );
}
