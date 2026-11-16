use super::*;

#[test]
fn log_to_filter_renders_default_then_targets_in_order() {
    let log = LogConfig::default();
    let filter = log.to_filter();
    // Default level first, then comma-separated target=level pairs in
    // their insertion order.
    assert!(filter.starts_with("info"));
    assert!(filter.contains(",socks5_proxy=debug"));
    assert!(filter.contains(",arti_wrapper=debug"));
    assert!(filter.contains(",tor_=warn"));
    // The first comma comes immediately after `info` — no whitespace.
    assert_eq!(filter.find(','), Some("info".len()));
}

#[test]
fn log_to_filter_keeps_product_crates_out_of_the_broad_tor_target() {
    // The default `tor_=warn` would silence `tor_socks5_runtime`,
    // `tor_socks5_onion` and `tor_socks5_server`; they inherit the level of
    // `socks5_proxy`.
    let filter = LogConfig::default().to_filter();
    assert!(filter.contains(",tor_=warn"));
    assert!(filter.contains(",tor_socks5_runtime=debug"), "{filter}");
    assert!(filter.contains(",tor_socks5_onion=debug"), "{filter}");
    assert!(filter.contains(",tor_socks5_server=debug"), "{filter}");

    // Without a `socks5_proxy` target they inherit the default level.
    let mut log = LogConfig::default();
    log.targets.shift_remove("socks5_proxy");
    log.default = "info".to_string();
    assert!(log.to_filter().contains(",tor_socks5_runtime=info"));
    assert!(log.to_filter().contains(",tor_socks5_server=info"));

    // An explicit target of its own is not overridden.
    let mut log = LogConfig::default();
    log.targets
        .insert("tor_socks5_runtime".to_string(), "trace".to_string());
    let filter = log.to_filter();
    assert!(filter.contains(",tor_socks5_runtime=trace"));
    assert_eq!(filter.matches("tor_socks5_runtime=").count(), 1);

    // An explicit target of its own is not overridden (the server crate).
    let mut log = LogConfig::default();
    log.targets
        .insert("tor_socks5_server".to_string(), "trace".to_string());
    let filter = log.to_filter();
    assert!(filter.contains(",tor_socks5_server=trace"));
    assert_eq!(filter.matches("tor_socks5_server=").count(), 1);

    // Nothing swallows them (no `tor_` target): no extra directive.
    let mut log = LogConfig::default();
    log.targets.shift_remove("tor_");
    assert!(!log.to_filter().contains("tor_socks5_runtime"));
}

#[test]
fn log_to_filter_handles_no_targets() {
    let mut log = LogConfig::default();
    log.targets.clear();
    assert_eq!(log.to_filter(), log.default);
}
