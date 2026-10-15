use crate::{Config, OnionServiceEntry, OnionServicePort};

fn service(nickname: &str, ports: &str) -> String {
    format!("\t{{\n\t\tnickname: {nickname}\n\t\tenabled: true\n\t\tports: [{ports}]\n\t}}\n")
}

fn config_with_services(services: &str) -> String {
    format!("listen: 127.0.0.1:1080\nonion_services: [\n{services}]\n")
}

fn parse(src: &str) -> Result<Config, String> {
    ktav::from_str::<Config>(src).map_err(|err| err.to_string())
}

#[test]
fn parses_minimal_onion_service() {
    let src = config_with_services(&service("web", "80=127.0.0.1:8080"));
    let cfg = parse(&src).expect("parses");
    assert_eq!(cfg.onion_services.len(), 1);
    let svc = &cfg.onion_services[0];
    assert_eq!(svc.nickname, "web");
    assert!(svc.enabled);
    assert_eq!(svc.ports.len(), 1);
    assert_eq!(svc.ports[0].onion_port, 80);
    assert_eq!(svc.ports[0].target, "127.0.0.1:8080");
}

#[test]
fn parses_multiple_port_mappings_in_order() {
    let src = config_with_services(&service("web", "80=127.0.0.1:8080, 443=127.0.0.1:8443"));
    let cfg = parse(&src).expect("parses");
    let ports: Vec<(u16, &str)> = cfg.onion_services[0]
        .ports
        .iter()
        .map(|p| (p.onion_port, p.target.as_str()))
        .collect();
    assert_eq!(ports, [(80, "127.0.0.1:8080"), (443, "127.0.0.1:8443")]);
}

#[test]
fn absent_section_defaults_to_empty() {
    let cfg: Config = ktav::from_str("listen: 127.0.0.1:1080\n").expect("parses");
    assert!(cfg.onion_services.is_empty());
}

#[test]
fn enabled_defaults_to_true_when_absent() {
    let src = "listen: 127.0.0.1:1080\n\
               onion_services: [\n\
               \t{\n\
               \t\tnickname: web\n\
               \t\tports: [ 80=127.0.0.1:8080 ]\n\
               \t}\n\
               ]\n";
    let cfg = parse(src).expect("parses");
    assert!(cfg.onion_services[0].enabled);
}

#[test]
fn explicit_enabled_false_is_kept() {
    let src = "listen: 127.0.0.1:1080\n\
               onion_services: [\n\
               \t{\n\
               \t\tnickname: web\n\
               \t\tenabled: false\n\
               \t\tports: [ 80=127.0.0.1:8080 ]\n\
               \t}\n\
               ]\n";
    let cfg = parse(src).expect("parses");
    assert!(!cfg.onion_services[0].enabled);
}

#[test]
fn duplicate_nicknames_are_rejected() {
    let src = config_with_services(&format!(
        "{}{}",
        service("web", "80=127.0.0.1:8080"),
        service("web", "443=127.0.0.1:8443")
    ));
    let err = parse(&src).expect_err("rejected");
    assert!(
        err.contains("onion_services: duplicate nickname 'web'"),
        "{err}"
    );
}

#[test]
fn duplicate_onion_port_within_one_service_is_rejected() {
    let src = config_with_services(&service("web", "80=127.0.0.1:8080, 80=127.0.0.1:8081"));
    let err = parse(&src).expect_err("rejected");
    assert!(
        err.contains("onion_services[0].ports: duplicate onion port 80"),
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
    assert_eq!(cfg.onion_services.len(), 2);
}

#[test]
fn empty_ports_are_rejected() {
    let src = "listen: 127.0.0.1:1080\n\
               onion_services: [\n\
               \t{\n\
               \t\tnickname: web\n\
               \t\tports: []\n\
               \t}\n\
               ]\n";
    let err = parse(src).expect_err("rejected");
    assert!(
        err.contains("onion_services[0].ports: at least one port mapping is required"),
        "{err}"
    );
}

#[test]
fn onion_port_bounds_are_enforced() {
    for port in ["0", "65536", "abc", ""] {
        let src = config_with_services(&service("web", &format!("{port}=127.0.0.1:8080")));
        let err = parse(&src).expect_err("rejected");
        assert!(
            err.contains("onion_services[0].ports:"),
            "port {port:?}: {err}"
        );
    }
}

#[test]
fn target_port_bounds_are_enforced() {
    for port in ["0", "65536"] {
        let src = config_with_services(&service("web", &format!("80=127.0.0.1:{port}")));
        let err = parse(&src).expect_err("rejected");
        assert!(
            err.contains("onion_services[0].ports:"),
            "port {port:?}: {err}"
        );
    }
}

#[test]
fn target_without_colon_is_rejected() {
    let src = config_with_services(&service("web", "80=127.0.0.1"));
    let err = parse(&src).expect_err("rejected");
    assert!(err.contains("onion_services[0].ports:"), "{err}");
}

#[test]
fn target_with_extra_colon_is_rejected() {
    let src = config_with_services(&service("web", "80=127.0.0.1:8080:9"));
    let err = parse(&src).expect_err("rejected");
    assert!(err.contains("onion_services[0].ports:"), "{err}");
}

#[test]
fn bare_ipv6_target_without_brackets_is_rejected() {
    let src = config_with_services(&service("web", "80=::1:8443"));
    let err = parse(&src).expect_err("rejected");
    assert!(err.contains("onion_services[0].ports:"), "{err}");
}

#[test]
fn bracketed_ipv6_target_is_accepted() {
    // Ktav reads an unquoted `[` as the start of an inline compound, so a
    // `[::1]` target cannot appear inside the comma-separated inline list —
    // it needs the block-list form with the `::` literal marker per item.
    let src = "listen: 127.0.0.1:1080\n\
               onion_services: [\n\
               \t{\n\
               \t\tnickname: web\n\
               \t\tports: [\n\
               \t\t\t80=127.0.0.1:8080\n\
               \t\t\t:: 443=[::1]:8443\n\
               \t\t]\n\
               \t}\n\
               ]\n";
    let cfg = parse(src).expect("parses");
    let targets: Vec<&str> = cfg.onion_services[0]
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
        assert!(err.contains("onion_services[0].ports:"), "{err}");
    }
}

#[test]
fn hostname_and_underscore_hosts_are_accepted() {
    let src = config_with_services(&service(
        "web",
        "80=my_host.example.com:8080, 443=my-host:443",
    ));
    let cfg = parse(&src).expect("parses");
    assert_eq!(
        cfg.onion_services[0].ports[0].target,
        "my_host.example.com:8080"
    );
}

#[test]
fn empty_and_invalid_nicknames_are_rejected() {
    for (nickname, label) in [("", "empty"), ("bad nick!", "space-bang")] {
        let src = config_with_services(&service(nickname, "80=127.0.0.1:8080"));
        let err = parse(&src).expect_err("rejected");
        assert!(
            err.contains("onion_services[0].nickname: invalid nickname"),
            "{label}: {err}"
        );
    }
}

#[test]
fn nickname_length_limit_is_enforced() {
    let ok = "a".repeat(25);
    let too_long = "a".repeat(26);
    let src = config_with_services(&service(&ok, "80=127.0.0.1:8080"));
    assert_eq!(parse(&src).expect("parses").onion_services[0].nickname, ok);
    let src = config_with_services(&service(&too_long, "80=127.0.0.1:8080"));
    let err = parse(&src).expect_err("rejected");
    assert!(
        err.contains("onion_services[0].nickname: invalid nickname"),
        "{err}"
    );
}

#[test]
fn unknown_field_inside_entry_is_rejected() {
    let src = "listen: 127.0.0.1:1080\n\
               onion_services: [\n\
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
    let cfg = Config {
        onion_services: vec![OnionServiceEntry {
            nickname: "web".into(),
            enabled: false,
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
        ..Default::default()
    };
    let serialized = ktav::to_string(&cfg).expect("serialize");
    let deserialized: Config = ktav::from_str(&serialized).expect("deserialize");
    assert_eq!(deserialized.onion_services, cfg.onion_services);
    assert!(!deserialized.onion_services[0].enabled);
    // Port mappings must keep the compact scalar spelling.
    assert!(serialized.contains("80=127.0.0.1:8080"));
    assert!(serialized.contains("[::1]:8443"));
}

#[test]
fn generated_default_config_contains_empty_section() {
    let serialized = ktav::to_string(&Config::default()).expect("serialize");
    assert!(
        serialized.contains("onion_services: []"),
        "default config must contain an empty onion_services section:\n{serialized}"
    );
}
