use std::net::IpAddr;

/// Maps a target host to the key one pool member is assigned to.
///
/// Hosts group by registrable domain (eTLD+1) from the embedded Public Suffix
/// List, so `a.example.com` and `b.example.com` share a member. Names are
/// lower-cased and converted to ASCII (punycode) first. IP literals, `.onion`
/// names and hosts without a registrable domain (single labels such as
/// `localhost`, or a bare public suffix) keep a key of their own and are never
/// rejected: a pool must be able to route any host the client asks for.
pub fn site_key(host: &str) -> String {
    let host = host.trim();
    let host = host.strip_suffix('.').unwrap_or(host);
    let bare = host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return format!("ip:{ip}");
    }
    let ascii = match idna::domain_to_ascii(host) {
        Ok(ascii) if !ascii.is_empty() => ascii,
        _ => return format!("raw:{}", host.to_ascii_lowercase()),
    };
    if ascii.ends_with(".onion") {
        let mut labels = ascii.rsplit('.');
        let tld = labels.next().unwrap_or_default();
        return match labels.next() {
            Some(service) => format!("{service}.{tld}"),
            None => ascii,
        };
    }
    match psl::domain(ascii.as_bytes()) {
        Some(domain) => String::from_utf8_lossy(domain.as_bytes()).into_owned(),
        None => ascii,
    }
}

#[cfg(test)]
mod tests {
    use super::site_key;

    #[test]
    fn subdomains_share_the_registrable_domain() {
        assert_eq!(site_key("www.example.com"), "example.com");
        assert_eq!(site_key("a.b.example.com"), "example.com");
        assert_eq!(site_key("example.com"), "example.com");
        assert_eq!(site_key("a.b.example.co.uk"), "example.co.uk");
    }

    #[test]
    fn case_trailing_dot_and_idn_are_normalised() {
        assert_eq!(site_key("WWW.Example.COM."), "example.com");
        assert_eq!(site_key("www.b\u{fc}cher.de"), "xn--bcher-kva.de");
        assert_eq!(site_key("b\u{fc}cher.de"), site_key("xn--bcher-kva.de"));
    }

    #[test]
    fn ip_literals_keep_their_own_key() {
        assert_eq!(site_key("192.0.2.1"), "ip:192.0.2.1");
        assert_eq!(site_key("[2001:db8::1]"), "ip:2001:db8::1");
        assert_eq!(site_key("2001:db8::1"), "ip:2001:db8::1");
        assert_ne!(site_key("192.0.2.1"), site_key("192.0.2.2"));
    }

    #[test]
    fn onion_names_group_by_service() {
        assert_eq!(site_key("www.abcdefgh.onion"), "abcdefgh.onion");
        assert_eq!(site_key("abcdefgh.onion"), "abcdefgh.onion");
    }

    #[test]
    fn hosts_without_a_registrable_domain_are_never_rejected() {
        assert_eq!(site_key("localhost"), "localhost");
        assert_eq!(site_key("co.uk"), "co.uk");
        assert!(!site_key("").is_empty());
        assert_eq!(site_key("bad host name"), site_key("bad host name"));
    }
}
