//! Parse an `https://` URL into a connect target (host, port, path).

use crate::error::FetchError;

#[derive(Debug)]
pub struct UrlTarget {
    pub host: String,
    pub port: u16,
    pub path_and_query: String,
}

pub fn parse_https_url(url_str: &str) -> Result<UrlTarget, FetchError> {
    let parsed = url::Url::parse(url_str).map_err(|e| FetchError::InvalidUrl(e.to_string()))?;
    if parsed.scheme() != "https" {
        return Err(FetchError::InvalidUrl(format!(
            "scheme {:?} not supported, only https://",
            parsed.scheme()
        )));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| FetchError::InvalidUrl("missing host".into()))?
        .to_string();
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| FetchError::InvalidUrl("cannot determine port".into()))?;
    let mut path = parsed.path().to_string();
    if path.is_empty() {
        path = "/".to_string();
    }
    if let Some(query) = parsed.query() {
        path.push('?');
        path.push_str(query);
    }
    Ok(UrlTarget {
        host,
        port,
        path_and_query: path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_url_extracts_host_port_path() {
        let t = parse_https_url("https://example.com/foo/bar").unwrap();
        assert_eq!(t.host, "example.com");
        assert_eq!(t.port, 443);
        assert_eq!(t.path_and_query, "/foo/bar");
    }

    #[test]
    fn parse_url_explicit_port() {
        let t = parse_https_url("https://example.com:8443/x").unwrap();
        assert_eq!(t.port, 8443);
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
