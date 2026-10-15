use crate::{Config, DnsOverrideKind};

fn entry(masks: &str) -> String {
    format!("dns_server.overrides: [\n\t{{\n{masks}\t\tresolver: system\n\t\tserver: \n\t}}\n]\n")
}

fn patterns(config: &Config) -> &[String] {
    &config.dns_server.overrides[0].patterns
}

#[test]
fn list_of_masks_keeps_order() {
    let config: Config = ktav::from_str(&entry(
        "\t\tpatterns: [\n\t\t\t*.ru\n\t\t\t*.example.com\n\t\t\texact.lan\n\t\t]\n",
    ))
    .unwrap();
    assert_eq!(patterns(&config), ["*.ru", "*.example.com", "exact.lan"]);
    assert_eq!(
        config.dns_server.overrides[0].resolver,
        DnsOverrideKind::System
    );
}

#[test]
fn a_lone_string_is_a_one_element_list() {
    let config: Config = ktav::from_str(&entry("\t\tpatterns: *.ru\n")).unwrap();
    assert_eq!(patterns(&config), ["*.ru"]);
}

#[test]
fn non_ascii_masks_are_kept_verbatim() {
    let config: Config = ktav::from_str(&entry(
        "\t\tpatterns: [\n\t\t\t*.рф\n\t\t\t*.москва\n\t\t]\n",
    ))
    .unwrap();
    assert_eq!(patterns(&config), ["*.рф", "*.москва"]);
}

#[test]
fn empty_list_parses_and_is_left_for_the_wiring_to_skip() {
    let config: Config = ktav::from_str(&entry("\t\tpatterns: []\n")).unwrap();
    assert!(patterns(&config).is_empty());
}

#[test]
fn the_old_single_mask_key_is_not_accepted_by_the_typed_parse() {
    assert!(ktav::from_str::<Config>(&entry("\t\tpattern: *.ru\n")).is_err());
}

#[test]
fn entry_without_any_mask_key_is_rejected() {
    assert!(ktav::from_str::<Config>(&entry("")).is_err());
}

#[test]
fn serialization_writes_the_list_form_and_round_trips() {
    let mut config = Config::default();
    config.dns_server.overrides = ktav::from_str::<Config>(&entry("\t\tpatterns: *.ru\n"))
        .unwrap()
        .dns_server
        .overrides;
    config.dns_server.overrides[0]
        .patterns
        .push("*.su".to_owned());
    let serialized = ktav::to_string(&config).unwrap();
    assert!(serialized.contains("patterns: ["), "{serialized}");
    assert!(!serialized.contains("pattern:"), "{serialized}");
    let reparsed: Config = ktav::from_str(&serialized).unwrap();
    assert_eq!(reparsed.dns_server.overrides, config.dns_server.overrides);
}
