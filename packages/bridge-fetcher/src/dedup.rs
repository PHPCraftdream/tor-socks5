//! Deduplicate bridge lines by their identity tuple.

use std::collections::HashSet;

use bridge_line::BridgeLine;
use bridge_probe::webtunnel_endpoint_identity;

/// Dedup bridge lines by (transport, addr, fingerprint) plus, for webtunnel
/// bridges, the canonical endpoint identity `(dial_host, dial_port,
/// path+query)` from `bridge_probe::webtunnel_endpoint_identity` (non-webtunnel
/// bridges get `None` there, so their dedup is unchanged). Keeps the first
/// occurrence. Returns (unique, duplicates_count).
#[must_use]
pub fn dedup_bridges(bridges: Vec<BridgeLine>) -> (Vec<BridgeLine>, usize) {
    let mut seen = HashSet::new();
    let mut unique = Vec::with_capacity(bridges.len());
    let mut dups = 0usize;
    for b in bridges {
        let key = (
            b.transport.clone(),
            b.addr,
            b.fingerprint.clone(),
            webtunnel_endpoint_identity(&b),
        );
        if seen.insert(key) {
            unique.push(b);
        } else {
            dups += 1;
        }
    }
    (unique, dups)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse_bridges_from_body;

    #[test]
    fn dedup_removes_exact_duplicates() {
        let body = "\
obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0
obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=BBB iat-mode=1
obfs4 5.6.7.8:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=CCC iat-mode=0
";
        let bridges = parse_bridges_from_body(body);
        let (unique, dups) = dedup_bridges(bridges);
        assert_eq!(unique.len(), 2);
        assert_eq!(dups, 1);
    }

    #[test]
    fn dedup_empty_input() {
        let (unique, dups) = dedup_bridges(vec![]);
        assert!(unique.is_empty());
        assert_eq!(dups, 0);
    }

    #[test]
    fn dedup_keeps_webtunnel_bridges_with_different_urls() {
        let body = "\
webtunnel 9.9.9.9:443 1111111111111111111111111111111111111111 url=https://e.com/old ver=0.0.3
webtunnel 9.9.9.9:443 1111111111111111111111111111111111111111 url=https://e.com/new ver=0.0.3
";
        let bridges = parse_bridges_from_body(body);
        let (unique, dups) = dedup_bridges(bridges);
        assert_eq!(unique.len(), 2);
        assert_eq!(dups, 0);
    }

    #[test]
    fn dedup_removes_webtunnel_exact_duplicates() {
        let body = "\
webtunnel 9.9.9.9:443 1111111111111111111111111111111111111111 url=https://e.com/x ver=0.0.3
webtunnel 9.9.9.9:443 1111111111111111111111111111111111111111 url=https://e.com/x ver=0.0.3
";
        let bridges = parse_bridges_from_body(body);
        let (unique, dups) = dedup_bridges(bridges);
        assert_eq!(unique.len(), 1);
        assert_eq!(dups, 1);
    }

    #[test]
    fn dedup_single_element() {
        let bridges = parse_bridges_from_body(
            "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0",
        );
        let (unique, dups) = dedup_bridges(bridges);
        assert_eq!(unique.len(), 1);
        assert_eq!(dups, 0);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use crate::parse::parse_bridges_from_body;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn dedup_is_idempotent(body in "([a-z0-9 .:/=\\-\n]{0,500})") {
            let bridges = parse_bridges_from_body(&body);
            let (first, _) = dedup_bridges(bridges.clone());
            let (second, dups2) = dedup_bridges(first.clone());
            prop_assert_eq!(&first, &second, "dedup must be idempotent");
            prop_assert_eq!(dups2, 0, "second dedup should find no duplicates");
        }
    }
}
