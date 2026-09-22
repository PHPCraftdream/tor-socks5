//! HTTPS-over-Tor GET: request building, header parsing, the TLS client
//! config, and the single-URL fetch (with redirect following and bounded
//! body reads).

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use arti_wrapper::TorTunnel;
use bridge_probe::ResolverPolicy;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing::debug;

use crate::direct::{connect_direct, connect_direct_with};
use crate::error::FetchError;
use crate::url_parse::parse_https_url;

mod framing;

/// A connected-but-not-yet-TLS-wrapped byte stream, boxed so the redirect
/// loop below does not need to be generic over which connection strategy
/// produced it.
type BoxedIo = Pin<Box<dyn AsyncStream>>;

trait AsyncStream: AsyncRead + AsyncWrite + Send {}
impl<T: AsyncRead + AsyncWrite + Send> AsyncStream for T {}

/// How to establish the raw connection for one hop. A redirect can point at
/// a different host, so this is re-invoked per hop rather than once per
/// fetch.
enum Connector<'a> {
    /// Route through an already-bootstrapped Tor circuit -- the normal path,
    /// used once at least one bridge is up.
    Tor(&'a TorTunnel),
    /// Resolve and connect directly, bypassing Tor entirely. Only used for
    /// the cold-start rescue fetch (see `fetch_one_direct`), when zero
    /// bridges are reachable and there is no tunnel to route through yet.
    Direct(ResolverPolicy),
    /// TEST-ONLY in-memory TLS loopback server (see `redirect_loopback`).
    #[cfg(test)]
    Test(&'a redirect_loopback::TestServer),
}

impl Connector<'_> {
    async fn connect(&self, host: &str, port: u16) -> Result<BoxedIo, FetchError> {
        match self {
            Connector::Tor(tor) => {
                let stream = tor
                    .connect(host, port)
                    .await
                    .map_err(|e| FetchError::TorConnect(e.to_string()))?;
                Ok(Box::pin(stream.compat()))
            }
            Connector::Direct(policy) => {
                let stream = connect_direct(host, port, *policy).await?;
                Ok(Box::pin(stream))
            }
            #[cfg(test)]
            Connector::Test(srv) => srv.connect(host, port).await,
        }
    }
}

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

/// The parsed head of an HTTP/1.1 response: the status plus the handful of
/// fields the fetch loop acts on. Produced by [`parse_response_headers`];
/// the body is not part of this struct — it begins at `header_len` in the
/// buffer that was parsed and is read separately.
pub struct HttpResponse {
    /// Status code as sent (200, 301, 404, …). The fetch loop follows
    /// 301/302/307/308 and rejects every other non-200 status with
    /// [`FetchError::Non200`].
    pub status: u16,
    /// `Location` header value if the response carried one (the last
    /// occurrence wins). Required for the redirect statuses, ignored for
    /// everything else.
    pub location: Option<String>,
    /// Body size in bytes as declared by the `Content-Length` header.
    /// Used only for the early [`FetchError::TooLarge`] check and as the
    /// `expected` side of [`FetchError::IncompleteBody`] — the actual read
    /// stops at exactly this many bytes. An absent or unparseable header
    /// means "unknown": the body is then read until EOF instead. Ignored
    /// when `chunked` is set (RFC 9112: Transfer-Encoding overrides
    /// Content-Length).
    pub content_length: Option<usize>,
    /// Whether `Transfer-Encoding` advertises the `chunked` coding; the
    /// body is then decoded by the chunked-framing reader, which enforces
    /// `max_body_bytes` itself and can fail with
    /// [`FetchError::ChunkedEncoding`].
    pub chunked: bool,
    /// Length in bytes of the head (status line + headers + the blank line
    /// that ends it) within the buffer passed to [`parse_response_headers`]
    /// — the offset at which the body starts. Head bytes are consumed by
    /// the parser and skipped, never counted as body.
    pub header_len: usize,
}

/// Incrementally parse an HTTP/1.1 response head from the front of `buf`.
///
/// Returns `Ok(None)` while the head is still incomplete (read more bytes
/// and call again), `Ok(Some(HttpResponse))` once a complete head has been
/// seen, and [`FetchError::Http`] when `buf` cannot be a response head at
/// all (httparse rejects it). Only the head is inspected: any body bytes
/// already present in `buf` behind it are left untouched — resume reading
/// at the returned `header_len`.
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
            let mut chunked = false;
            for h in resp.headers.iter() {
                if h.name.eq_ignore_ascii_case("location") {
                    location = Some(String::from_utf8_lossy(h.value).to_string());
                }
                if h.name.eq_ignore_ascii_case("content-length") {
                    if let Ok(s) = std::str::from_utf8(h.value) {
                        content_length = s.trim().parse().ok();
                    }
                }
                if h.name.eq_ignore_ascii_case("transfer-encoding") {
                    if let Ok(s) = std::str::from_utf8(h.value) {
                        if s.split(',').any(|c| {
                            c.split(';')
                                .next()
                                .unwrap_or("")
                                .trim()
                                .eq_ignore_ascii_case("chunked")
                        }) {
                            chunked = true;
                        }
                    }
                }
            }
            Ok(Some(HttpResponse {
                status,
                location,
                content_length,
                chunked,
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
///
/// `allow_credentials_cross_origin` controls whether `headers`/`cookies` are
/// sent to redirect targets on a different origin than `url` (different host
/// or port; both URLs go through `parse_https_url`, so the comparison is on
/// normalized origin). Default `false`: a cross-origin redirect is followed
/// with an otherwise-identical request that carries none of them — including
/// subsequent relative redirects, until the chain returns to the original
/// origin (RFC 9110 §15.4).
pub async fn fetch_one(
    tor: &TorTunnel,
    url: &str,
    timeout: Duration,
    max_body_bytes: usize,
    headers: &[String],
    cookies: &[String],
    allow_credentials_cross_origin: bool,
) -> Result<String, FetchError> {
    tokio::time::timeout(
        timeout,
        fetch_one_inner(
            &Connector::Tor(tor),
            url,
            tls_config(),
            max_body_bytes,
            headers,
            cookies,
            allow_credentials_cross_origin,
        ),
    )
    .await
    .map_err(|_| FetchError::Timeout(timeout))?
}

/// Cold-start rescue fetch: same as [`fetch_one`], but bypasses Tor entirely
/// (direct TCP, hostnames resolved via `bridge-probe`'s DoH pool). Only
/// meant for the narrow case where zero bridges are reachable yet and there
/// is no tunnel to route [`fetch_one`] through.
///
/// `allow_credentials_cross_origin` has the same meaning as in [`fetch_one`].
///
/// cancel-safe: NO — same reason as `fetch_one`.
pub async fn fetch_one_direct(
    resolver_policy: ResolverPolicy,
    url: &str,
    timeout: Duration,
    max_body_bytes: usize,
    headers: &[String],
    cookies: &[String],
    allow_credentials_cross_origin: bool,
) -> Result<String, FetchError> {
    tokio::time::timeout(
        timeout,
        fetch_one_inner(
            &Connector::Direct(resolver_policy),
            url,
            tls_config(),
            max_body_bytes,
            headers,
            cookies,
            allow_credentials_cross_origin,
        ),
    )
    .await
    .map_err(|_| FetchError::Timeout(timeout))?
}

async fn fetch_one_inner(
    connector: &Connector<'_>,
    url: &str,
    tls_cfg: Arc<rustls::ClientConfig>,
    max_body_bytes: usize,
    headers: &[String],
    cookies: &[String],
    allow_credentials_cross_origin: bool,
) -> Result<String, FetchError> {
    let mut current_url = url.to_string();
    // Fixed credential boundary: the origin of the URL the caller asked for,
    // not the previous hop. Both sides go through `parse_https_url` (the `url`
    // crate), so host is lowercased and brackets stripped, and an omitted
    // port folds to 443 — a plain tuple comparison is a normalized origin
    // comparison.
    let original_origin: (String, u16) = parse_https_url(url).map(|t| (t.dial_host, t.port))?;

    for hop in 0..=MAX_REDIRECTS {
        if hop == MAX_REDIRECTS {
            return Err(FetchError::TooManyRedirects);
        }

        let target = parse_https_url(&current_url)?;
        // RFC 9110 §15.4: source credentials (API tokens, session cookies)
        // must not leak to a different origin just because that origin sent a
        // redirect. Withhold ALL caller-supplied headers/cookies together on
        // cross-origin hops (opt-out via `allow_credentials_cross_origin`).
        let same_origin = allow_credentials_cross_origin
            || (target.dial_host == original_origin.0 && target.port == original_origin.1);
        let (hop_headers, hop_cookies): (&[String], &[String]) = if same_origin {
            (headers, cookies)
        } else {
            (&[], &[])
        };
        if !same_origin {
            debug!(
                host = %target.dial_host,
                port = target.port,
                hop,
                "cross-origin redirect: withholding source credentials"
            );
        }
        debug!(
            host = %target.dial_host,
            port = target.port,
            path = %target.path_and_query,
            hop,
            "fetching"
        );

        let mut tls: tokio_rustls::client::TlsStream<BoxedIo> = match connector {
            Connector::Direct(policy) => {
                let host = target.dial_host.clone();
                let cfg = tls_cfg.clone();
                connect_direct_with(&target.dial_host, target.port, *policy, move |raw| {
                    let host = host.clone();
                    let cfg = cfg.clone();
                    async move {
                        let server_name = rustls::pki_types::ServerName::try_from(host)
                            .map_err(|e| FetchError::Tls(format!("invalid SNI: {e}")))?;
                        let raw: BoxedIo = Box::pin(raw);
                        tokio_rustls::TlsConnector::from(cfg)
                            .connect(server_name, raw)
                            .await
                            .map_err(|e| FetchError::Tls(e.to_string()))
                    }
                })
                .await?
            }
            _ => {
                let raw = connector.connect(&target.dial_host, target.port).await?;
                let server_name = rustls::pki_types::ServerName::try_from(target.dial_host.clone())
                    .map_err(|e| FetchError::Tls(format!("invalid SNI: {e}")))?;
                tokio_rustls::TlsConnector::from(tls_cfg.clone())
                    .connect(server_name, raw)
                    .await
                    .map_err(|e| FetchError::Tls(e.to_string()))?
            }
        };

        let req = build_get_request(
            &target.host_header,
            &target.path_and_query,
            hop_headers,
            hop_cookies,
        );
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
                    format!("https://{}:{}{}", target.bracketed_host(), target.port, loc)
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
    let body = if resp_info.chunked {
        // Chunked wins over Content-Length (RFC 9112: TE overrides CL);
        // Content-Length is ignored in that case.
        framing::decode_chunked_body(stream, &header_buf[body_start..total], max_body_bytes).await?
    } else {
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
                    return Err(FetchError::IncompleteBody {
                        expected: cl,
                        got: body.len(),
                    });
                }
                body.extend_from_slice(&chunk[..n]);
            }
        } else {
            // Bytes already buffered with the headers count against the cap
            // BEFORE any further read: a body delivered whole in the first
            // read and closed with EOF otherwise slips past the limit (the
            // loop below re-checks only after a successful non-EOF read).
            if body.len() > max_body_bytes {
                return Err(FetchError::TooLarge {
                    max_bytes: max_body_bytes,
                });
            }
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
        body
    };

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

    /// A 200 without Content-Length/chunked whose whole body arrived in the
    /// FIRST read (with the headers) and closed with EOF must be rejected
    /// over the cap: the pre-fix reader checked the limit only after a later
    /// non-EOF read, so this response was accepted at `max_body_bytes = 0`.
    #[tokio::test]
    async fn eof_body_fully_buffered_with_headers_over_limit_is_too_large() {
        let response =
            b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nobfs4 192.0.2.1:443 0123 cert=aaaa";
        let mut cursor = tokio::io::BufReader::new(&response[..]);
        let err = read_http_response(&mut cursor, 0).await.unwrap_err();
        assert!(
            matches!(err, FetchError::TooLarge { max_bytes: 0 }),
            "expected TooLarge, got: {err}"
        );
    }

    /// Boundary that must remain accepted: the fully-buffered EOF body is
    /// exactly at the cap.
    #[tokio::test]
    async fn eof_body_fully_buffered_exactly_at_the_limit_is_accepted() {
        let body = b"obfs4 192.0.2.1:443 0123 cert=aaaa";
        let mut response = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec();
        response.extend_from_slice(body);
        let mut cursor = tokio::io::BufReader::new(&response[..]);
        let result = read_http_response(&mut cursor, body.len()).await.unwrap();
        match result {
            ResponseBody::Ok(text) => assert_eq!(text, String::from_utf8_lossy(body)),
            ResponseBody::Redirect(_) => panic!("expected Ok"),
        }
    }

    /// Boundary that must remain accepted: no body at all under a zero cap.
    #[tokio::test]
    async fn eof_response_without_a_body_is_accepted_at_max_zero() {
        let response = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
        let mut cursor = tokio::io::BufReader::new(&response[..]);
        let result = read_http_response(&mut cursor, 0).await.unwrap();
        match result {
            ResponseBody::Ok(text) => assert_eq!(text, ""),
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

    #[tokio::test]
    async fn read_response_content_length_short_body_is_error() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello";
        let mut cursor = tokio::io::BufReader::new(&response[..]);
        let err = read_http_response(&mut cursor, TEST_MAX_BODY)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("incomplete response body"), "{msg}");
        assert!(msg.contains("expected 11"), "{msg}");
        assert!(msg.contains("got 5"), "{msg}");
    }

    #[tokio::test]
    async fn read_response_content_length_one_byte_short_mid_line() {
        let line =
            b"obfs4 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=aaaa iat-mode=0\n";
        let body = &line[..line.len() - 1];
        let mut response = b"HTTP/1.1 200 OK\r\nContent-Length: ".to_vec();
        response.extend_from_slice((body.len() + 1).to_string().as_bytes());
        response.extend_from_slice(b"\r\n\r\n");
        response.extend_from_slice(body);
        let mut cursor = tokio::io::BufReader::new(&response[..]);
        let err = read_http_response(&mut cursor, TEST_MAX_BODY)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("incomplete response body"));
    }

    #[tokio::test]
    async fn read_response_content_length_one_byte_short_after_full_line() {
        let body: &[u8] =
            b"obfs4 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=aaaa iat-mode=0\n\
            obfs4 192.0.2.2:443 7A3CDE9876ABCDEF0123456789ABCDEF01234567 cert=bbbb iat-mode=0\n";
        let mut response = b"HTTP/1.1 200 OK\r\nContent-Length: ".to_vec();
        response.extend_from_slice((body.len() + 1).to_string().as_bytes());
        response.extend_from_slice(b"\r\n\r\n");
        response.extend_from_slice(body);
        let mut cursor = tokio::io::BufReader::new(&response[..]);
        let err = read_http_response(&mut cursor, TEST_MAX_BODY)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("incomplete response body"));
    }

    #[test]
    fn parse_response_chunked_flag() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        let info = parse_response_headers(raw).unwrap().unwrap();
        assert!(info.chunked);
        assert!(info.content_length.is_none());
    }

    #[test]
    fn parse_response_chunked_case_insensitive() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: CHUNKED\r\n\r\n";
        let info = parse_response_headers(raw).unwrap().unwrap();
        assert!(info.chunked);
    }

    #[test]
    fn parse_response_chunked_in_coding_list() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n";
        let info = parse_response_headers(raw).unwrap().unwrap();
        assert!(info.chunked);
    }

    #[test]
    fn parse_response_transfer_encoding_non_chunked() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n";
        let info = parse_response_headers(raw).unwrap().unwrap();
        assert!(!info.chunked);
    }

    #[tokio::test]
    async fn read_response_chunked_decodes() {
        let mut response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        response.extend_from_slice(b"2\r\nhe\r\n3\r\nllo\r\n0\r\n\r\n");
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
    async fn read_response_chunked_truncated_is_error() {
        let mut response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        response.extend_from_slice(b"5\r\nhel");
        let mut cursor = tokio::io::BufReader::new(&response[..]);
        let err = read_http_response(&mut cursor, TEST_MAX_BODY)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("chunked") || msg.contains("closed"), "{msg}");
    }

    #[tokio::test]
    async fn read_response_chunked_takes_priority_over_content_length() {
        let mut response =
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        response.extend_from_slice(b"5\r\nhello\r\n0\r\n\r\n");
        let mut cursor = tokio::io::BufReader::new(&response[..]);
        let result = read_http_response(&mut cursor, TEST_MAX_BODY)
            .await
            .unwrap();
        match result {
            ResponseBody::Ok(body) => assert_eq!(body, "hello"),
            ResponseBody::Redirect(_) => panic!("expected Ok"),
        }
    }

    /// Yields at most `drip` bytes per `read()` to force arbitrary read
    /// boundaries.
    struct DripReader<'a> {
        data: &'a [u8],
        pos: usize,
        drip: usize,
    }

    impl tokio::io::AsyncRead for DripReader<'_> {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let remaining = self.data.len() - self.pos;
            let n = remaining.min(self.drip).min(buf.remaining());
            buf.put_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn read_response_chunked_bridge_line_split_inside_fingerprint() {
        let line =
            b"obfs4 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=aaaa/bbbb iat-mode=0\n";
        // Cut offsets land inside transport bytes and mid-fingerprint.
        let cuts = [10usize, 15, 36, 50, 60];
        let mut framed = Vec::new();
        let mut prev = 0usize;
        for &c in cuts.iter().chain(std::iter::once(&line.len())) {
            let piece = &line[prev..c];
            framed.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
            framed.extend_from_slice(piece);
            framed.extend_from_slice(b"\r\n");
            prev = c;
        }
        framed.extend_from_slice(b"0\r\n\r\n");

        let mut response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        response.extend_from_slice(&framed);

        let mut cursor = DripReader {
            data: &response,
            pos: 0,
            drip: 3,
        };
        let result = read_http_response(&mut cursor, TEST_MAX_BODY)
            .await
            .unwrap();
        match result {
            ResponseBody::Ok(body) => assert_eq!(body, String::from_utf8_lossy(line)),
            ResponseBody::Redirect(_) => panic!("expected Ok"),
        }
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

#[cfg(test)]
mod redirect_loopback;
