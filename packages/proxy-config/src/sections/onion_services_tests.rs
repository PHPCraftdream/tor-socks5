use super::OnionFile;
use crate::{IdentityKey, OnionServiceEntry, OnionServicePort};

fn service(nickname: &str, ports: &str) -> String {
    format!("\t{{\n\t\tnickname: {nickname}\n\t\tenabled: true\n\t\tports: [{ports}]\n\t}}\n")
}

fn config_with_services(services: &str) -> String {
    format!("services: [\n{services}]\n")
}

fn parse(src: &str) -> Result<OnionFile, String> {
    ktav::from_str::<OnionFile>(src).map_err(|err| err.to_string())
}

#[test]
fn parses_minimal_onion_service() {
    let src = config_with_services(&service("web", "80=127.0.0.1:8080"));
    let cfg = parse(&src).expect("parses");
    assert_eq!(cfg.services.len(), 1);
    let svc = &cfg.services[0];
    assert_eq!(svc.nickname, "web");
    assert!(svc.enabled);
    assert_eq!(svc.circuit_hops, 4);
    assert_eq!(svc.ports.len(), 1);
    assert_eq!(svc.ports[0].onion_port, 80);
    assert_eq!(svc.ports[0].target, "127.0.0.1:8080");
}

#[test]
fn parses_multiple_port_mappings_in_order() {
    let src = config_with_services(&service("web", "80=127.0.0.1:8080, 443=127.0.0.1:8443"));
    let cfg = parse(&src).expect("parses");
    let ports: Vec<(u16, &str)> = cfg.services[0]
        .ports
        .iter()
        .map(|p| (p.onion_port, p.target.as_str()))
        .collect();
    assert_eq!(ports, [(80, "127.0.0.1:8080"), (443, "127.0.0.1:8443")]);
}

#[test]
fn absent_section_defaults_to_empty() {
    let cfg: OnionFile = ktav::from_str("").expect("parses");
    assert!(cfg.services.is_empty());
}

#[test]
fn enabled_defaults_to_true_when_absent() {
    let src = "services: [\n\
               \t{\n\
               \t\tnickname: web\n\
               \t\tports: [ 80=127.0.0.1:8080 ]\n\
               \t}\n\
               ]\n";
    let cfg = parse(src).expect("parses");
    assert!(cfg.services[0].enabled);
}

#[test]
fn explicit_enabled_false_is_kept() {
    let src = "services: [\n\
               \t{\n\
               \t\tnickname: web\n\
               \t\tenabled: false\n\
               \t\tports: [ 80=127.0.0.1:8080 ]\n\
               \t}\n\
               ]\n";
    let cfg = parse(src).expect("parses");
    assert!(!cfg.services[0].enabled);
}

#[test]
fn duplicate_nicknames_are_rejected() {
    let src = config_with_services(&format!(
        "{}{}",
        service("web", "80=127.0.0.1:8080"),
        service("web", "443=127.0.0.1:8443")
    ));
    let err = parse(&src).expect_err("rejected");
    assert!(err.contains("services: duplicate nickname 'web'"), "{err}");
}

#[test]
fn duplicate_onion_port_within_one_service_is_rejected() {
    let src = config_with_services(&service("web", "80=127.0.0.1:8080, 80=127.0.0.1:8081"));
    let err = parse(&src).expect_err("rejected");
    assert!(
        err.contains("services[0].ports: duplicate onion port 80"),
        "{err}"
    );
}

#[test]
fn same_onion_port_in_different_services_is_allowed() {
    let src = config_with_services(&format!(
        "{}{}",
        service("web", "80=127.0.0.1:8080"),
        service("api", "80=127.0.0.1:9080")
    ));
    let cfg = parse(&src).expect("parses");
    assert_eq!(cfg.services.len(), 2);
}

#[test]
fn empty_ports_are_rejected_for_an_enabled_service() {
    let src = "services: [\n\
               \t{\n\
               \t\tnickname: web\n\
               \t\tports: []\n\
               \t}\n\
               ]\n";
    let err = parse(src).expect_err("rejected");
    assert!(
        err.contains("services[0].ports: at least one port mapping is required"),
        "{err}"
    );
}

#[test]
fn onion_port_bounds_are_enforced() {
    for port in ["0", "65536", "abc", ""] {
        let src = config_with_services(&service("web", &format!("{port}=127.0.0.1:8080")));
        let err = parse(&src).expect_err("rejected");
        assert!(err.contains("services[0].ports:"), "port {port:?}: {err}");
    }
}

#[test]
fn target_port_bounds_are_enforced() {
    for port in ["0", "65536"] {
        let src = config_with_services(&service("web", &format!("80=127.0.0.1:{port}")));
        let err = parse(&src).expect_err("rejected");
        assert!(err.contains("services[0].ports:"), "port {port:?}: {err}");
    }
}

#[test]
fn target_without_colon_is_rejected() {
    let src = config_with_services(&service("web", "80=127.0.0.1"));
    let err = parse(&src).expect_err("rejected");
    assert!(err.contains("services[0].ports:"), "{err}");
}

#[test]
fn target_with_extra_colon_is_rejected() {
    let src = config_with_services(&service("web", "80=127.0.0.1:8080:9"));
    let err = parse(&src).expect_err("rejected");
    assert!(err.contains("services[0].ports:"), "{err}");
}

#[test]
fn bare_ipv6_target_without_brackets_is_rejected() {
    let src = config_with_services(&service("web", "80=::1:8443"));
    let err = parse(&src).expect_err("rejected");
    assert!(err.contains("services[0].ports:"), "{err}");
}

#[test]
fn bracketed_ipv6_target_is_accepted() {
    // Ktav reads an unquoted `[` as the start of an inline compound, so a
    // `[::1]` target cannot appear inside the comma-separated inline list —
    // it needs the block-list form with the `::` literal marker per item.
    let src = "services: [\n\
               \t{\n\
               \t\tnickname: web\n\
               \t\tports: [\n\
               \t\t\t80=127.0.0.1:8080\n\
               \t\t\t:: 443=[::1]:8443\n\
               \t\t]\n\
               \t}\n\
               ]\n";
    let cfg = parse(src).expect("parses");
    let targets: Vec<&str> = cfg.services[0]
        .ports
        .iter()
        .map(|p| p.target.as_str())
        .collect();
    assert_eq!(targets, ["127.0.0.1:8080", "[::1]:8443"]);
}

#[test]
fn target_host_with_invalid_characters_is_rejected() {
    for host in ["bad host", "exa$mple.com"] {
        let src = config_with_services(&service("web", &format!("80={host}:8080")));
        let err = parse(&src).expect_err("rejected");
        assert!(err.contains("services[0].ports:"), "{err}");
    }
}

#[test]
fn hostname_and_underscore_hosts_are_accepted() {
    let src = config_with_services(&service(
        "web",
        "80=my_host.example.com:8080, 443=my-host:443",
    ));
    let cfg = parse(&src).expect("parses");
    assert_eq!(cfg.services[0].ports[0].target, "my_host.example.com:8080");
}

#[test]
fn empty_and_invalid_nicknames_are_rejected() {
    for (nickname, label) in [("", "empty"), ("bad nick!", "space-bang")] {
        let src = config_with_services(&service(nickname, "80=127.0.0.1:8080"));
        let err = parse(&src).expect_err("rejected");
        assert!(
            err.contains("services[0].nickname: invalid nickname"),
            "{label}: {err}"
        );
    }
}

#[test]
fn nickname_length_limit_is_enforced() {
    let ok = "a".repeat(25);
    let too_long = "a".repeat(26);
    let src = config_with_services(&service(&ok, "80=127.0.0.1:8080"));
    assert_eq!(parse(&src).expect("parses").services[0].nickname, ok);
    let src = config_with_services(&service(&too_long, "80=127.0.0.1:8080"));
    let err = parse(&src).expect_err("rejected");
    assert!(
        err.contains("services[0].nickname: invalid nickname"),
        "{err}"
    );
}

#[test]
fn unknown_field_inside_entry_is_rejected() {
    let src = "services: [\n\
               \t{\n\
               \t\tnickname: web\n\
               \t\tports: [ 80=127.0.0.1:8080 ]\n\
               \t\tstealth: true\n\
               \t}\n\
               ]\n";
    assert!(
        parse(src).is_err(),
        "unknown key inside an entry must be rejected"
    );
}

#[test]
fn onion_services_roundtrip_through_write() {
    let cfg = OnionFile {
        services: vec![OnionServiceEntry {
            nickname: "web".into(),
            enabled: false,
            address: None,
            key: None,
            circuit_hops: 4,
            ports: vec![
                OnionServicePort {
                    onion_port: 80,
                    target: "127.0.0.1:8080".into(),
                },
                OnionServicePort {
                    onion_port: 443,
                    target: "[::1]:8443".into(),
                },
            ],
        }],
    };
    let serialized = ktav::to_string(&cfg).expect("serialize");
    let deserialized: OnionFile = ktav::from_str(&serialized).expect("deserialize");
    assert_eq!(deserialized.services, cfg.services);
    assert!(!deserialized.services[0].enabled);
    // Port mappings must keep the compact scalar spelling.
    assert!(serialized.contains("80=127.0.0.1:8080"));
    assert!(serialized.contains("[::1]:8443"));
}

#[test]
fn circuit_hops_is_skipped_in_serialized_output_when_default() {
    let cfg = OnionFile {
        services: vec![OnionServiceEntry {
            nickname: "web".into(),
            enabled: true,
            address: None,
            key: None,
            circuit_hops: 4,
            ports: vec![OnionServicePort {
                onion_port: 80,
                target: "127.0.0.1:8080".into(),
            }],
        }],
    };
    let serialized = ktav::to_string(&cfg).expect("serialize");
    assert!(
        !serialized.contains("circuit_hops: 4"),
        "default hop count must be omitted:\n{serialized}"
    );
    let entry = serialized.split("services:").last().expect("section");
    assert!(!entry.contains("circuit_hops"), "{entry}");
    let deserialized: OnionFile = ktav::from_str(&serialized).expect("deserialize");
    assert_eq!(deserialized.services, cfg.services);
}

#[test]
fn non_default_circuit_hops_is_serialized_and_roundtrips() {
    let cfg = OnionFile {
        services: vec![OnionServiceEntry {
            nickname: "web".into(),
            enabled: true,
            address: None,
            key: None,
            circuit_hops: 2,
            ports: vec![OnionServicePort {
                onion_port: 80,
                target: "127.0.0.1:8080".into(),
            }],
        }],
    };
    let serialized = ktav::to_string(&cfg).expect("serialize");
    assert!(serialized.contains("circuit_hops: 2"), "{serialized}");
    let deserialized: OnionFile = ktav::from_str(&serialized).expect("deserialize");
    assert_eq!(deserialized.services, cfg.services);
    assert_eq!(deserialized.services[0].circuit_hops, 2);
}

#[test]
fn circuit_hops_defaults_to_four_and_accepts_two_three_four() {
    for (value, expected) in [("2", 2), ("3", 3), ("4", 4)] {
        let src = format!(
            "services: [\n\
             \t{{\n\
             \t\tnickname: web\n\
             \t\tcircuit_hops: {value}\n\
             \t\tports: [ 80=127.0.0.1:8080 ]\n\
             \t}}\n\
             ]\n"
        );
        let cfg = parse(&src).expect("valid circuit_hops parses");
        assert_eq!(cfg.services[0].circuit_hops, expected);
    }
}

#[test]
fn invalid_circuit_hops_values_are_rejected_with_key_path() {
    for value in ["1", "5", "0", "255"] {
        let src = format!(
            "services: [\n\
             \t{{\n\
             \t\tnickname: web\n\
             \t\tcircuit_hops: {value}\n\
             \t\tports: [ 80=127.0.0.1:8080 ]\n\
             \t}}\n\
             ]\n"
        );
        let err = parse(&src).expect_err("invalid circuit_hops must fail");
        assert!(
            err.contains("services[0].circuit_hops"),
            "circuit_hops {value:?}: {err}"
        );
        assert!(err.contains("2, 3, or 4"), "circuit_hops {value:?}: {err}");
    }
    // Values that do not fit u8 (or are not integers) fail in the field
    // deserializer before the entry index is known, so the message
    // carries the generic path.
    for value in ["256", "-1", "\"3\"", "abc"] {
        let src = format!(
            "services: [\n\
             \t{{\n\
             \t\tnickname: web\n\
             \t\tcircuit_hops: {value}\n\
             \t\tports: [ 80=127.0.0.1:8080 ]\n\
             \t}}\n\
             ]\n"
        );
        let err = parse(&src).expect_err("invalid circuit_hops must fail");
        assert!(
            err.contains("circuit_hops"),
            "circuit_hops {value:?}: {err}"
        );
        assert!(err.contains("2, 3, or 4"), "circuit_hops {value:?}: {err}");
    }
}

#[test]
fn enabled_services_with_identical_circuit_hops_are_accepted() {
    let src = config_with_services(&format!(
        "{}{}",
        service_with_hops("web", 3, "80=127.0.0.1:8080"),
        service_with_hops("api", 3, "443=127.0.0.1:8443")
    ));
    let cfg = parse(&src).expect("parses");
    assert!(cfg.services.iter().all(|svc| svc.circuit_hops == 3));
}

#[test]
fn enabled_services_with_conflicting_circuit_hops_are_rejected() {
    let src = config_with_services(&format!(
        "{}{}",
        service_with_hops("web", 3, "80=127.0.0.1:8080"),
        service_with_hops("api", 2, "443=127.0.0.1:8443")
    ));
    let err = parse(&src).expect_err("rejected");
    assert!(
        err.contains("all enabled services must use the same circuit_hops"),
        "{err}"
    );
    assert!(err.contains("services[0].circuit_hops: 3"), "{err}");
    assert!(err.contains("services[1].circuit_hops: 2"), "{err}");
}

#[test]
fn disabled_service_may_differ_from_enabled_ones() {
    let src = config_with_services(&format!(
        "{}{}",
        service_with_hops("web", 3, "80=127.0.0.1:8080"),
        "\t{\n\t\tnickname: off\n\t\tenabled: false\n\t\tcircuit_hops: 2\n\t\tports: [ 443=127.0.0.1:8443 ]\n\t}\n"
    ));
    let cfg = parse(&src).expect("parses");
    assert_eq!(cfg.services[1].circuit_hops, 2);
}

fn service_with_hops(nickname: &str, circuit_hops: u8, ports: &str) -> String {
    format!(
        "\t{{\n\t\tnickname: {nickname}\n\t\tenabled: true\n\
         \t\tcircuit_hops: {circuit_hops}\n\t\tports: [{ports}]\n\t}}\n"
    )
}

#[test]
fn disabled_service_may_have_no_ports_yet() {
    let src =
        config_with_services("\t{\n\t\tnickname: web\n\t\tenabled: false\n\t\tports: []\n\t}\n");
    let cfg = parse(&src).expect("parses");
    assert!(cfg.services[0].ports.is_empty());
}

const ADDRESS: &str = "6oglpb2ubuf72tczfd6iwwqvvmlb6s2jlrzxgwtctmzfrnse2qluqaqd.onion";

fn service_with(extra: &str) -> String {
    config_with_services(&format!(
        "\t{{\n\t\tnickname: web\n\t\t{extra}\n\t\tports: [ 80=127.0.0.1:8080 ]\n\t}}\n"
    ))
}

#[test]
fn address_and_key_are_read_when_present() {
    let src = service_with(&format!("address: {ADDRESS}\n\t\tkey: LS0tLS1CRUdJTg=="));
    let cfg = parse(&src).expect("parses");
    assert_eq!(cfg.services[0].address.as_deref(), Some(ADDRESS));
    assert_eq!(
        cfg.services[0].key,
        Some(IdentityKey::new("LS0tLS1CRUdJTg==").unwrap())
    );
}

#[test]
fn address_and_key_are_optional() {
    let cfg = parse(&service("web", "80=127.0.0.1:8080")).expect("parses");
    assert_eq!(cfg.services[0].address, None);
    assert_eq!(cfg.services[0].key, None);
}

#[test]
fn malformed_addresses_are_rejected_with_the_entry_path() {
    for address in [
        "web.onion",
        "6oglpb2ubuf72tczfd6iwwqvvmlb6s2jlrzxgwtctmzfrnse2qluqaqd",
        "6OGLPB2UBUF72TCZFD6IWWQVVMLB6S2JLRZXGWTCTMZFRNSE2QLUQAQD.onion",
        "6oglpb2ubuf72tczfd6iwwqvvmlb6s2jlrzxgwtctmzfrnse2qluqaq1.onion",
    ] {
        let err = parse(&service_with(&format!("address: {address}"))).expect_err("rejected");
        assert!(err.contains("services[0].address"), "{address}: {err}");
    }
}

#[test]
fn a_key_that_is_not_base64_is_rejected_without_echoing_it() {
    let err = parse(&service_with("key: not base64 !!")).expect_err("rejected");
    assert!(err.contains("services[0].key"), "{err}");
    assert!(!err.contains("not base64 !!"), "the secret leaked: {err}");
}

#[test]
fn duplicate_addresses_are_rejected() {
    let both = format!(
        "\t{{\n\t\tnickname: web\n\t\taddress: {ADDRESS}\n\t\tports: [ 80=127.0.0.1:8080 ]\n\t}}\n\
         \t{{\n\t\tnickname: api\n\t\taddress: {ADDRESS}\n\t\tports: [ 80=127.0.0.1:9080 ]\n\t}}\n"
    );
    let err = parse(&config_with_services(&both)).expect_err("rejected");
    assert!(err.contains("duplicate address"), "{err}");
}

#[test]
fn address_and_key_roundtrip_and_key_is_redacted_in_debug() {
    let file = OnionFile {
        services: vec![OnionServiceEntry {
            nickname: "web".into(),
            enabled: true,
            address: Some(ADDRESS.into()),
            key: Some(IdentityKey::new("LS0tLS1CRUdJTg==").unwrap()),
            circuit_hops: 4,
            ports: vec![OnionServicePort {
                onion_port: 80,
                target: "127.0.0.1:8080".into(),
            }],
        }],
    };
    let serialized = ktav::to_string(&file).expect("serialize");
    assert!(serialized.contains("key: LS0tLS1CRUdJTg=="), "{serialized}");
    let back: OnionFile = ktav::from_str(&serialized).expect("deserialize");
    assert_eq!(back, file);
    assert!(!format!("{file:?}").contains("LS0tLS1CRUdJTg=="));
}

#[test]
fn unknown_top_level_key_in_the_file_is_rejected() {
    assert!(parse("service: []\n").is_err());
}
