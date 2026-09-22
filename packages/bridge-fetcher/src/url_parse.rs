//! Parse an `https://` URL into a connect target (host, port, path).

use crate::error::FetchError;

/// Connect target for one `https://` request: what to dial, what the
/// `Host` header must say, and what path to request. Built by
/// [`parse_https_url`]. Note the two host spellings with different jobs:
/// `dial_host` is for dialling and TLS SNI only, `host_header` is the only
/// one that may go on the wire in a header.
#[derive(Debug)]
pub struct UrlTarget {
    /// Dial host for the TCP socket and TLS ServerName: an IP literal
    /// WITHOUT brackets (IPv6 included) or a bare hostname. Never send this
    /// on the wire as an HTTP authority.
    pub dial_host: String,
    /// Port to dial: the URL's explicit port if it carried one, otherwise
    /// the `https` default (443).
    pub port: u16,
    /// Preformatted HTTP `Host` header value: the host bracketed if it is an
    /// IPv6 literal, plus ":port" ONLY when the URL carried an explicit port
    /// (`url::Url::port()`); a defaulted port (`port_or_known_default()`)
    /// must NOT appear here.
    pub host_header: String,
    /// Request target for the `GET` request line, sent verbatim: the URL's
    /// path (`/` if the URL had none) with `?query` appended when the URL
    /// carried a query string, e.g. `/bridges?country=de`.
    pub path_and_query: String,
}

/// Bracket the host iff it is an IPv6 literal (URL-authority form).
fn bracketed_if_ipv6(dial_host: &str) -> String {
    match dial_host.parse::<std::net::Ipv6Addr>() {
        Ok(v6) => format!("[{v6}]"),
        Err(_) => dial_host.to_string(),
    }
}

impl UrlTarget {
    /// Host as it must appear in a URL authority: bracketed iff IPv6, with
    /// no port. For rebuilding absolute redirect URLs; the wire `Host`
    /// header value is `host_header`.
    pub(crate) fn bracketed_host(&self) -> String {
        bracketed_if_ipv6(&self.dial_host)
    }
}

/// Parse an `https://` URL into a [`UrlTarget`].
///
/// Fails with [`FetchError::InvalidUrl`] when the string does not parse as
/// a URL at all, the scheme is anything other than `https`, the host is
/// missing, or no port can be determined. IPv6 literals are accepted in
/// bracketed authority form and normalised (lowercased, brackets stripped
/// in `dial_host`, kept in `host_header`); otherwise parsing and
/// normalisation are the `url` crate's.
pub fn parse_https_url(url_str: &str) -> Result<UrlTarget, FetchError> {
    let parsed = url::Url::parse(url_str).map_err(|e| FetchError::InvalidUrl(e.to_string()))?;
    if parsed.scheme() != "https" {
        return Err(FetchError::InvalidUrl(format!(
            "scheme {:?} not supported, only https://",
            parsed.scheme()
        )));
    }
    let dial_host = parsed
        .host_str()
        .ok_or_else(|| FetchError::InvalidUrl("missing host".into()))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| FetchError::InvalidUrl("cannot determine port".into()))?;
    let bracketed = bracketed_if_ipv6(&dial_host);
    let host_header = match parsed.port() {
        Some(p) => format!("{bracketed}:{p}"),
        None => bracketed,
    };
    let mut path = parsed.path().to_string();
    if path.is_empty() {
        path = "/".to_string();
    }
    if let Some(query) = parsed.query() {
        path.push('?');
        path.push_str(query);
    }
    Ok(UrlTarget {
        dial_host,
        port,
        host_header,
        path_and_query: path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_url_extracts_host_port_path() {
        let t = parse_https_url("https://example.com/foo/bar").unwrap();
        assert_eq!(t.dial_host, "example.com");
        assert_eq!(t.host_header, "example.com");
        assert_eq!(t.port, 443);
        assert_eq!(t.path_and_query, "/foo/bar");
    }

    #[test]
    fn parse_url_explicit_port() {
        let t = parse_https_url("https://example.com:8443/x").unwrap();
        assert_eq!(t.port, 8443);
        assert_eq!(t.host_header, "example.com:8443");
    }

    #[test]
    fn host_header_omits_default_port() {
        let t = parse_https_url("https://example.com/foo/bar").unwrap();
        assert_eq!(t.host_header, "example.com");
    }

    #[test]
    fn host_header_keeps_explicit_non_default_port() {
        let t = parse_https_url("https://example.com:8443/x").unwrap();
        assert_eq!(t.host_header, "example.com:8443");
    }

    #[test]
    fn host_header_keeps_explicit_default_port() {
        // The url crate normalizes an explicit default port away: `port()`
        // returns None for `:443`, so no port appears in the header.
        let t = parse_https_url("https://example.com:443/x").unwrap();
        assert_eq!(t.host_header, "example.com");
        assert_eq!(t.port, 443);
    }

    #[test]
    fn ipv6_with_explicit_port() {
        let t = parse_https_url("https://[2001:0DB8::1]:8443/x").unwrap();
        assert_eq!(t.dial_host, "2001:db8::1");
        assert_eq!(t.host_header, "[2001:db8::1]:8443");
        assert_eq!(t.port, 8443);
    }

    #[test]
    fn ipv6_default_port() {
        let t = parse_https_url("https://[::1]/p").unwrap();
        assert_eq!(t.dial_host, "::1");
        assert_eq!(t.host_header, "[::1]");
        assert_eq!(t.port, 443);
    }

    #[test]
    fn parse_url_with_query() {
        let t = parse_https_url("https://example.com/p?a=1&b=2").unwrap();
        assert_eq!(t.path_and_query, "/p?a=1&b=2");
    }

    #[test]
    fn parse_url_rejects_http() {
        let err = parse_https_url("http://example.com/x").unwrap_err();
        assert!(err.to_string().contains("only https://"));
    }

    #[test]
    fn parse_url_garbage_is_error() {
        assert!(parse_https_url("not a url at all").is_err());
    }

    #[test]
    fn parse_url_ftp_rejected() {
        let err = parse_https_url("ftp://example.com/x").unwrap_err();
        assert!(err.to_string().contains("only https://"));
    }

    #[test]
    fn parse_url_default_path_is_slash() {
        let t = parse_https_url("https://example.com").unwrap();
        assert_eq!(t.path_and_query, "/");
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn parse_https_url_never_panics(s in ".*") {
            let _ = parse_https_url(&s);
        }
    }
}
