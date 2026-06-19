//! Extract `BridgeLine`s from a fetched response body.

use bridge_line::BridgeLine;

/// Parse bridge lines from a text body, skipping blank lines, `#`
/// comments, and any line that does not parse as a `BridgeLine`.
pub fn parse_bridges_from_body(body: &str) -> Vec<BridgeLine> {
    body.lines()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty() && !trimmed.starts_with('#')
        })
        .filter_map(|line| line.trim().parse::<BridgeLine>().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bridges_mixed_body() {
        let body = "\
# This is a comment
obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0

garbage line that won't parse
obfs4 5.6.7.8:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=BBB iat-mode=0
";
        let bridges = parse_bridges_from_body(body);
        assert_eq!(bridges.len(), 2);
        assert_eq!(bridges[0].addr.to_string(), "1.2.3.4:80");
        assert_eq!(bridges[1].addr.to_string(), "5.6.7.8:443");
    }

    #[test]
    fn parse_bridges_empty_body() {
        assert!(parse_bridges_from_body("").is_empty());
        assert!(parse_bridges_from_body("# only comments\n").is_empty());
    }

    #[test]
    fn parse_bridges_keeps_valid_skips_invalid() {
        let body = "\
obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0
not-a-bridge
obfs4 5.6.7.8:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=BBB iat-mode=0
also bad
";
        let bridges = parse_bridges_from_body(body);
        assert_eq!(bridges.len(), 2);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn parse_bridges_from_body_never_panics(s in ".*") {
            let _ = parse_bridges_from_body(&s);
        }
    }
}
