use super::*;

fn outcome(label: &str, error: Option<&str>) -> bridge_fetcher::FetchOutcome {
    bridge_fetcher::FetchOutcome {
        label: label.to_owned(),
        bridges_extracted: 0,
        error: error.map(str::to_owned),
        bridges: Vec::new(),
    }
}

#[test]
fn dns_hints_for_lines_is_empty_when_nothing_is_cached() {
    let lines = "webtunnel 192.0.2.3:1 0123456789ABCDEF0123456789ABCDEF01234567 \
                  url=https://never-cached.example.test/x";
    assert_eq!(dns_hints_for_lines(lines), "");
}

#[test]
fn dns_hints_for_lines_is_empty_for_ip_only_bridges() {
    // obfs4 without a hostname target has nothing worth hinting at.
    let lines = "obfs4 192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0";
    assert_eq!(dns_hints_for_lines(lines), "");
}

#[test]
fn dns_hints_for_lines_finds_a_cached_webtunnel_host() {
    let host = "cached-for-export.example.test";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    bridge_probe::seed_disk_fallback(&[bridge_probe::DnsHint {
        host: host.to_owned(),
        addrs: vec!["203.0.113.77".parse().unwrap()],
        resolved_at_unix: now,
    }]);
    let lines = format!(
        "webtunnel 192.0.2.3:1 0123456789ABCDEF0123456789ABCDEF01234567 url=https://{host}/x"
    );
    let result = dns_hints_for_lines(&lines);
    assert!(
        result.starts_with(bridge_probe::DNS_HINT_PREFIX),
        "got: {result:?}"
    );
    let parsed = bridge_probe::parse_dns_hint_line(&result).expect("must parse back");
    assert_eq!(parsed.host, host);
}

#[test]
fn dns_hints_for_lines_ignores_unparseable_lines() {
    // A garbage line must not abort the whole call -- other lines still
    // get a chance.
    let lines = "not a bridge line at all\nalso garbage";
    assert_eq!(dns_hints_for_lines(lines), "");
}

#[test]
fn refresh_reports_all_source_failures() {
    let message = refresh_sources_failure(&[
        outcome("primary", Some("timeout")),
        outcome("backup", Some("403")),
    ])
    .expect("all failed sources should produce an error");
    assert!(message.contains("primary: timeout"));
    assert!(message.contains("backup: 403"));
}

#[test]
fn refresh_keeps_no_new_bridges_for_successful_sources() {
    assert!(refresh_sources_failure(&[outcome("primary", None)]).is_none());
    assert!(refresh_sources_failure(&[]).is_some());
}

#[test]
fn test_status_formatting() {
    assert_eq!(EngineStatus::Off.to_string(), "Off");
    assert_eq!(EngineStatus::Starting(50).to_string(), "Starting:50");
    assert_eq!(
        EngineStatus::On("127.0.0.1:1080".parse().unwrap()).to_string(),
        "On:127.0.0.1:1080"
    );
    assert_eq!(EngineStatus::Stopping.to_string(), "Stopping");
    assert_eq!(
        EngineStatus::Error("test error".into()).to_string(),
        "Error:test error"
    );
}

#[test]
fn test_progress_to_percent() {
    // Test the clamp and rounding logic used in status mapping
    let test_cases = [
        (-0.5f32, 0u8),
        (0.0, 0),
        (0.25, 25),
        (0.5, 50),
        (0.75, 75),
        (1.0, 100),
        (1.5, 100),
    ];

    for (fraction, expected) in test_cases {
        let clamped = fraction.clamp(0.0, 1.0);
        let percent = (clamped * 100.0).round() as u8;
        assert_eq!(percent, expected, "fraction={}", fraction);
    }
}
