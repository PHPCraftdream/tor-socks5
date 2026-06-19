//! HTTPS-over-Tor GET: request building, header parsing, the TLS client
//! config, and the single-URL fetch (with redirect following and bounded
//! body reads).

use std::sync::Arc;
use std::time::Duration;

use arti_wrapper::TorTunnel;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing::debug;

use crate::error::FetchError;
use crate::url_parse::parse_https_url;

pub(crate) const MAX_REDIRECTS: usize = 3;
const READ_BUF_SIZE: usize = 8192;

/// Strip CR/LF so a config-supplied header or cookie value cannot inject
/// extra header lines (header smuggling) or fold the request.
fn sanitize_header_value(s: &str) -> String {
    s.replace(['\r', '\n'], "").trim().to_string()
}

/// Build the GET request, appending any caller-supplied `headers` (each a
/// full `Name: Value` line) and a single combined `Cookie:` line built from
/// `cookies` (each a `name=value` pair). Both are sanitized of CR/LF.
pub fn build_get_request(
    host: &str,
    path: &str,
    headers: &[String],
    cookies: &[String],
) -> Vec<u8> {
    let mut req = format!(
        "GET {path} HTTP/1.1\r\n\
Host: {host}\r\n\
Connection: close\r\n\
User-Agent: tor-socks5/0.1\r\n\
Accept: */*\r\n"
    );
    for h in headers {
        let line = sanitize_header_value(h);
        if !line.is_empty() {
            req.push_str(&line);
            req.push_str("\r\n");
        }
    }
    let cookie_jar: Vec<String> = cookies
        .iter()
        .map(|c| sanitize_header_value(c))
        .filter(|c| !c.is_empty())
        .collect();
    if !cookie_jar.is_empty() {
        req.push_str("Cookie: ");
        req.push_str(&cookie_jar.join("; "));
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    req.into_bytes()
}

pub struct HttpResponse {
    pub status: u16,
    pub location: Option<String>,
    pub content_length: Option<usize>,
    pub header_len: usize,
}

pub fn parse_response_headers(buf: &[u8]) -> Result<Option<HttpResponse>, FetchError> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut headers);
    match resp.parse(buf) {
        Ok(httparse::Status::Complete(header_len)) => {
            let status = resp
                .code
                .ok_or_else(|| FetchError::Http("no status code".into()))?;
            let mut location = None;
            let mut content_length = None;
            for h in resp.headers.iter() {
                if h.name.eq_ignore_ascii_case("location") {
                    location = Some(String::from_utf8_lossy(h.value).to_string());
                }
                if h.name.eq_ignore_ascii_case("content-length") {
                    if let Ok(s) = std::str::from_utf8(h.value) {
                        content_length = s.trim().parse().ok();
                    }
                }
            }
            Ok(Some(HttpResponse {
                status,
                location,
                content_length,
                header_len,
            }))
        }
        Ok(httparse::Status::Partial) => Ok(None),
        Err(e) => Err(FetchError::Http(e.to_string())),
    }
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    static CFG: std::sync::OnceLock<Arc<rustls::ClientConfig>> = std::sync::OnceLock::new();
    CFG.get_or_init(|| {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        )
    })
    .clone()
}

/// cancel-safe: NO — partial TLS/HTTP state if cancelled mid-handshake.
pub async fn fetch_one(
    tor: &TorTunnel,
    url: &str,
    timeout: Duration,
    max_body_bytes: usize,
    headers: &[String],
    cookies: &[String],
) -> Result<String, FetchError> {
    tokio::time::timeout(
        timeout,
        fetch_one_inner(tor, url, tls_config(), max_body_bytes, headers, cookies),
    )
    .await
    .map_err(|_| FetchError::Timeout(timeout))?
}

async fn fetch_one_inner(
    tor: &TorTunnel,
    url: &str,
    tls_cfg: Arc<rustls::ClientConfig>,
    max_body_bytes: usize,
    headers: &[String],
    cookies: &[String],
) -> Result<String, FetchError> {
    let mut current_url = url.to_string();

    for hop in 0..=MAX_REDIRECTS {
        if hop == MAX_REDIRECTS {
            return Err(FetchError::TooManyRedirects);
        }

        let target = parse_https_url(&current_url)?;
        debug!(
            host = %target.host,
            port = target.port,
            path = %target.path_and_query,
            hop,
            "fetching via Tor"
        );

        let data_stream = tor
            .connect(&target.host, target.port)
            .await
            .map_err(|e| FetchError::TorConnect(e.to_string()))?;

        let compat = data_stream.compat();

        let server_name = rustls::pki_types::ServerName::try_from(target.host.clone())
            .map_err(|e| FetchError::Tls(format!("invalid SNI: {e}")))?;

        let connector = tokio_rustls::TlsConnector::from(tls_cfg.clone());
        let mut tls = connector
            .connect(server_name, compat)
            .await
            .map_err(|e| FetchError::Tls(e.to_string()))?;

        let req = build_get_request(&target.host, &target.path_and_query, headers, cookies);
        tls.write_all(&req).await.map_err(|e| FetchError::Io {
            op: "write request",
            source: e,
        })?;
        tls.flush().await.map_err(|e| FetchError::Io {
            op: "flush request",
            source: e,
        })?;

        let body = read_http_response(&mut tls, max_body_bytes).await?;

        match body {
            ResponseBody::Ok(text) => return Ok(text),
            ResponseBody::Redirect(loc) => {
                let next = if loc.starts_with("https://") {
                    loc
                } else if loc.starts_with('/') {
                    format!("https://{}:{}{}", target.host, target.port, loc)
                } else {
                    return Err(FetchError::Http(format!(
                        "unsupported redirect location: {loc}"
                    )));
                };
                debug!(from = %current_url, to = %next, "following redirect");
                current_url = next;
            }
        }
    }

    Err(FetchError::TooManyRedirects)
}

#[derive(Debug)]
enum ResponseBody {
    Ok(String),
    Redirect(String),
}

async fn read_http_response<S>(
    stream: &mut S,
    max_body_bytes: usize,
) -> Result<ResponseBody, FetchError>
where
    S: AsyncReadExt + Unpin,
{
    let mut header_buf = vec![0u8; READ_BUF_SIZE];
    let mut total = 0usize;

    let resp_info = loop {
        if total >= header_buf.len() {
            header_buf.resize(header_buf.len() * 2, 0);
            if header_buf.len() > max_body_bytes {
                return Err(FetchError::TooLarge {
                    max_bytes: max_body_bytes,
                });
            }
        }
        let n = stream
            .read(&mut header_buf[total..])
            .await
            .map_err(|e| FetchError::Io {
                op: "read headers",
                source: e,
            })?;
        if n == 0 {
            return Err(FetchError::Http(
                "connection closed before headers complete".into(),
            ));
        }
        total += n;

        if let Some(info) = parse_response_headers(&header_buf[..total])? {
            break info;
        }
    };

    if matches!(resp_info.status, 301 | 302 | 307 | 308) {
        let loc = resp_info
            .location
            .ok_or_else(|| FetchError::Http("redirect without Location header".into()))?;
        return Ok(ResponseBody::Redirect(loc));
    }

    if resp_info.status != 200 {
        return Err(FetchError::Non200(format!("HTTP {}", resp_info.status)));
    }

    let body_start = resp_info.header_len;
    let mut body = Vec::from(&header_buf[body_start..total]);

    if let Some(cl) = resp_info.content_length {
        if cl > max_body_bytes {
            return Err(FetchError::TooLarge {
                max_bytes: max_body_bytes,
            });
        }
        if body.len() > cl {
            body.truncate(cl);
        }
        while body.len() < cl {
            let mut chunk = vec![0u8; READ_BUF_SIZE.min(cl - body.len())];
            let n = stream.read(&mut chunk).await.map_err(|e| FetchError::Io {
                op: "read body (content-length)",
                source: e,
            })?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
        }
    } else {
        loop {
            let mut chunk = vec![0u8; READ_BUF_SIZE];
            let n = stream.read(&mut chunk).await.map_err(|e| FetchError::Io {
                op: "read body (eof)",
                source: e,
            })?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
            if body.len() > max_body_bytes {
                return Err(FetchError::TooLarge {
                    max_bytes: max_body_bytes,
                });
            }
        }
    }

    String::from_utf8(body)
        .map(ResponseBody::Ok)
        .map_err(|e| FetchError::Http(format!("response body is not valid UTF-8: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MAX_BODY: usize = 1024 * 1024;

    #[test]
    fn build_request_format() {
        let req = build_get_request("example.com", "/bridges", &[], &[]);
        let s = String::from_utf8(req).unwrap();
        assert!(s.starts_with("GET /bridges HTTP/1.1\r\n"));
        assert!(s.contains("Host: example.com\r\n"));
        assert!(s.contains("Connection: close\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
        // No obs-fold: no line starts with whitespace after CRLF
        assert!(!s.contains("\r\n "));
        assert!(!s.contains("\r\n\t"));
    }

    #[test]
    fn build_request_with_headers_and_cookies() {
        let headers = vec![
            "Authorization: Bearer xyz".to_string(),
            "X-Api: 1".to_string(),
        ];
        let cookies = vec!["sid=abc".to_string(), "lang=en".to_string()];
        let s = String::from_utf8(build_get_request("h.com", "/b", &headers, &cookies)).unwrap();
        assert!(s.contains("Authorization: Bearer xyz\r\n"));
        assert!(s.contains("X-Api: 1\r\n"));
        // Cookies are folded into one Cookie line, "; "-joined.
        assert!(s.contains("Cookie: sid=abc; lang=en\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn header_value_crlf_is_stripped() {
        // A malicious value must not inject extra header lines.
        let headers = vec!["X-Evil: a\r\nInjected: yes".to_string()];
        let s = String::from_utf8(build_get_request("h.com", "/b", &headers, &[])).unwrap();
        // The CR/LF is stripped, so "Injected" never starts its own header
        // line — it is glued onto the previous value instead of smuggled in.
        assert!(
            !s.contains("\r\nInjected:"),
            "CRLF injection must be neutralised"
        );
        assert!(s.contains("X-Evil: aInjected: yes\r\n"));
    }

    #[test]
    fn parse_response_200_with_content_length() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let info = parse_response_headers(raw).unwrap().unwrap();
        assert_eq!(info.status, 200);
        assert_eq!(info.content_length, Some(5));
        assert_eq!(&raw[info.header_len..], b"hello");
    }

    #[test]
    fn parse_response_301_with_location() {
        let raw = b"HTTP/1.1 301 Moved\r\nLocation: https://new.example.com/x\r\n\r\n";
        let info = parse_response_headers(raw).unwrap().unwrap();
        assert_eq!(info.status, 301);
        assert_eq!(info.location.as_deref(), Some("https://new.example.com/x"));
    }

    #[test]
    fn parse_response_partial() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Len";
        assert!(parse_response_headers(raw).unwrap().is_none());
    }

    #[test]
    fn parse_response_404() {
        let raw = b"HTTP/1.1 404 Not Found\r\n\r\n";
        let info = parse_response_headers(raw).unwrap().unwrap();
        assert_eq!(info.status, 404);
    }

    #[test]
    fn parse_response_no_content_length() {
        let raw = b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n";
        let info = parse_response_headers(raw).unwrap().unwrap();
        assert_eq!(info.status, 200);
        assert!(info.content_length.is_none());
    }

    #[tokio::test]
    async fn read_response_200_from_mock() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world";
        let mut cursor = tokio::io::BufReader::new(&response[..]);
        let result = read_http_response(&mut cursor, TEST_MAX_BODY)
            .await
            .unwrap();
        match result {
            ResponseBody::Ok(body) => assert_eq!(body, "hello world"),
            ResponseBody::Redirect(_) => panic!("expected Ok"),
        }
    }

    #[tokio::test]
    async fn read_response_redirect() {
        let response = b"HTTP/1.1 302 Found\r\nLocation: https://other.com/x\r\n\r\n";
        let mut cursor = tokio::io::BufReader::new(&response[..]);
        let result = read_http_response(&mut cursor, TEST_MAX_BODY)
            .await
            .unwrap();
        match result {
            ResponseBody::Redirect(loc) => {
                assert_eq!(loc, "https://other.com/x");
            }
            ResponseBody::Ok(_) => panic!("expected redirect"),
        }
    }

    #[tokio::test]
    async fn read_response_404_is_error() {
        let response = b"HTTP/1.1 404 Not Found\r\n\r\n";
        let mut cursor = tokio::io::BufReader::new(&response[..]);
        let err = read_http_response(&mut cursor, TEST_MAX_BODY)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("HTTP 404"));
    }

    #[tokio::test]
    async fn read_response_connection_closed_before_headers() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Len";
        let mut cursor = tokio::io::BufReader::new(&response[..]);
        let err = read_http_response(&mut cursor, TEST_MAX_BODY)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("closed before headers"));
    }

    #[tokio::test]
    async fn read_response_empty_stream() {
        let response: &[u8] = b"";
        let mut cursor = tokio::io::BufReader::new(response);
        let err = read_http_response(&mut cursor, TEST_MAX_BODY)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("closed before headers"));
    }

    #[tokio::test]
    async fn read_response_200_no_content_length_reads_to_eof() {
        let response = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nall the data";
        let mut cursor = tokio::io::BufReader::new(&response[..]);
        let result = read_http_response(&mut cursor, TEST_MAX_BODY)
            .await
            .unwrap();
        match result {
            ResponseBody::Ok(body) => assert_eq!(body, "all the data"),
            ResponseBody::Redirect(_) => panic!("expected Ok"),
        }
    }

    #[tokio::test]
    async fn read_response_200_content_length_truncates() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello extra ignored";
        let mut cursor = tokio::io::BufReader::new(&response[..]);
        let result = read_http_response(&mut cursor, TEST_MAX_BODY)
            .await
            .unwrap();
        match result {
            ResponseBody::Ok(body) => assert_eq!(body, "hello"),
            ResponseBody::Redirect(_) => panic!("expected Ok"),
        }
    }

    #[tokio::test]
    async fn read_response_redirect_307_preserves_location() {
        let response = b"HTTP/1.1 307 Temporary Redirect\r\nLocation: /new-path\r\n\r\n";
        let mut cursor = tokio::io::BufReader::new(&response[..]);
        let result = read_http_response(&mut cursor, TEST_MAX_BODY)
            .await
            .unwrap();
        match result {
            ResponseBody::Redirect(loc) => assert_eq!(loc, "/new-path"),
            ResponseBody::Ok(_) => panic!("expected redirect"),
        }
    }

    #[tokio::test]
    async fn read_response_redirect_without_location_is_error() {
        let response = b"HTTP/1.1 301 Moved\r\n\r\n";
        let mut cursor = tokio::io::BufReader::new(&response[..]);
        let err = read_http_response(&mut cursor, TEST_MAX_BODY)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Location"));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn parse_response_headers_never_panics(data in proptest::collection::vec(any::<u8>(), 0..2000)) {
            let _ = parse_response_headers(&data);
        }

        #[test]
        fn build_get_request_never_panics(
            host in "[a-z]{1,50}\\.[a-z]{2,5}",
            path in "/[a-z0-9/]{0,100}",
        ) {
            let req = build_get_request(&host, &path, &[], &[]);
            let s = String::from_utf8(req).expect("GET request is UTF-8");
            prop_assert!(s.ends_with("\r\n\r\n"));
            prop_assert!(!s.contains("\r\n "));
            prop_assert!(!s.contains("\r\n\t"));
        }
    }
}
