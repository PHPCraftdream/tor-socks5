use super::*;
#[test]
fn matches_exact_hostname_without_star() {
    assert!(matches("example.com", "example.com"));
    assert!(!matches("example.com", "example.org"));
    assert!(!matches("example.com", "sub.example.com"));
}

#[test]
fn matches_case_insensitively_in_both_directions() {
    assert!(matches("example.com", "EXAMPLE.com"));
    assert!(matches("EXAMPLE.COM", "example.com"));
    assert!(matches("Example.Com", "eXaMpLe.CoM"));
    assert!(!matches("EXAMPLE.com", "EXAMPLE.org"));
}

#[test]
fn leading_star_matches_deeper_subdomains() {
    assert!(matches("*.example.com", "foo.example.com"));
    assert!(matches("*.example.com", "a.b.example.com"));
    assert!(matches("*.example.com", "FOO.EXAMPLE.COM"));
}

#[test]
fn leading_star_does_not_match_bare_parent() {
    // The documented edge case: the pattern's literal `.` must appear
    // in the host, so the mask never captures the parent itself.
    assert!(!matches("*.example.com", "example.com"));
}

#[test]
fn mid_pattern_star_matches_empty_run() {
    assert!(matches("foo*.com", "foobar.com"));
    assert!(matches("foo*.com", "foo.com"));
    assert!(!matches("foo*.com", "bar.com"));
}

#[test]
fn bare_star_matches_anything() {
    assert!(matches("*", "example.com"));
    assert!(matches("*", "a.b.c.example.org"));
    assert!(matches("*", "x"));
}

#[test]
fn no_match_when_host_has_extra_trailing_label() {
    assert!(matches("*.example.com", "foo.example.com"));
    assert!(!matches("*.com", "foo.com.org"));
    assert!(!matches("foo.com", "foo.com.org"));
}

fn override_with(pattern: &str, resolver: OverrideResolver) -> DnsOverride {
    DnsOverride {
        pattern: pattern.to_owned(),
        resolver,
    }
}

#[test]
fn find_override_first_match_wins() {
    let overrides = [
        override_with("*.example.com", OverrideResolver::System),
        override_with(
            "foo.example.com",
            OverrideResolver::Dns {
                server: "192.0.2.53:53".parse().expect("test addr parses"),
            },
        ),
    ];
    let found = find_override(&overrides, "foo.example.com").expect("a mask matches");
    assert_eq!(
        found.resolver,
        OverrideResolver::System,
        "the FIRST matching entry must win"
    );
}

#[test]
fn find_override_no_match_returns_none() {
    let overrides = [override_with("*.example.com", OverrideResolver::System)];
    assert!(find_override(&overrides, "example.org").is_none());
    assert!(find_override(&[], "example.com").is_none());
}

#[test]
fn find_override_is_case_insensitive_on_host() {
    let overrides = [override_with("*.Example.com", OverrideResolver::System)];
    let found = find_override(&overrides, "FOO.EXAMPLE.COM").expect("case-insensitive match");
    assert_eq!(found.resolver, OverrideResolver::System);
}
