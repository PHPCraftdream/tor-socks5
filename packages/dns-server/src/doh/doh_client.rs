//! DNS-over-HTTPS (RFC 8484) client whose every exchange runs through the
//! live Tor tunnel ([`arti_wrapper::TorTunnel::connect`]) instead of the
//! direct network.
//!
//! Queries are encoded with `hickory-proto` (exactly one QUESTION per
//! message), POSTed as `application/dns-message` to a [`crate::DohProvider`]
//! over rustls+Tor, and the wire-format replies are decoded into a
//! [`crate::ResolvedAnswer`].
//!
//! The TCP connection is dialled by the provider's IP, so the provider's
//! hostname is never resolved -- locally or through the tunnel. The hostname
//! is used only for TLS SNI and the HTTP `Host` header.

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use arti_wrapper::TorTunnel;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing::debug;

use crate::error::DnsServerError;
use crate::{DohProvider, ResolvedAnswer};

/// Per-provider bound on the WHOLE lookup: Tor connect + TLS handshake + the
/// original-question exchange. Through a live Tor circuit a fresh stream and a TLS
/// handshake can each take several seconds, so this is far more generous
/// than the 4s `DOH_PROVIDER_TIMEOUT` the DIRECT path uses
/// (bridge-probe/src/dns.rs).
pub const DOH_PROVIDER_TIMEOUT: Duration = Duration::from_secs(20);

/// Upper bound for a DNS response body. A DNS message cannot exceed 64 KiB
/// per its own u16 length fields, so anything larger is a malicious or
/// broken server and is rejected instead of being read into memory.
pub(crate) const MAX_DNS_RESPONSE_BYTES: usize = 64 * 1024;

/// Upper bound for the HTTP header block before the response is abandoned.
const MAX_HEADER_BYTES: usize = 16 * 1024;

/// Number of HTTP header lines httparse will decode for us. DoH responses
/// carry a handful; hitting the cap yields a parse error, not a panic.
const MAX_HTTP_HEADERS: usize = 32;

/// Incremental read granularity, matching bridge-fetcher.
const READ_BUF_SIZE: usize = 8192;

/// Port every configured DoH provider listens on (HTTPS).
const DOH_PORT: u16 = 443;

/// A connected-and-encrypted byte stream, boxed so the exchange helpers stay
/// non-generic over how the TLS session was produced (same pattern as
/// bridge-fetcher).
type BoxedIo = Pin<Box<dyn AsyncStream>>;

trait AsyncStream: AsyncRead + AsyncWrite + Send {}
impl<T: AsyncRead + AsyncWrite + Send> AsyncStream for T {}

/// A DNS query ready for the wire: its transaction id and encoded bytes.
pub(crate) struct DnsQuery {
    pub(crate) id: u16,
    pub(crate) bytes: Vec<u8>,
    pub(crate) question: Query,
}

/// Build and cache the rustls client config (same pattern as
/// bridge-fetcher/src/http.rs: webpki roots, no client certificate).
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

/// Absolute budget for the entire ordered provider traversal.
pub const DOH_TOTAL_TIMEOUT: Duration = Duration::from_secs(30);

/// Resolve exactly the client's question through one provider.
/// cancel-safe: yes — connect/TLS/write/read state belongs to this attempt;
/// cancellation closes the stream, never resumes partially consumed framing.
pub async fn resolve(
    question: &Query,
    tor: &TorTunnel,
    provider: &DohProvider,
) -> Result<ResolvedAnswer, DnsServerError> {
    tokio::time::timeout(
        DOH_PROVIDER_TIMEOUT,
        resolve_with_provider(question, tor, provider),
    )
    .await
    .map_err(|_| DnsServerError::Timeout(DOH_PROVIDER_TIMEOUT))?
}

/// Ordered fallback for transport failures and temporary DNS failures only.
/// NXDOMAIN and NOERROR (including NODATA) are terminal answers.
/// cancel-safe: yes — all attempts own disposable streams; no detached work.
pub async fn resolve_with_pool(
    question: &Query,
    tor: &TorTunnel,
    providers: &[DohProvider],
) -> Result<ResolvedAnswer, DnsServerError> {
    ordered_pool(providers.len(), |index| {
        resolve(question, tor, &providers[index])
    })
    .await
}

/// Shared production traversal seam: tests can supply exchanges without Tor.
/// cancel-safe: yes — exchange futures must own disposable transport state.
async fn ordered_pool<F, Fut>(
    count: usize,
    mut attempt: F,
) -> Result<ResolvedAnswer, DnsServerError>
where
    F: FnMut(usize) -> Fut,
    Fut: std::future::Future<Output = Result<ResolvedAnswer, DnsServerError>>,
{
    let deadline = tokio::time::Instant::now() + DOH_TOTAL_TIMEOUT;
    for index in 0..count {
        let provider_deadline = (tokio::time::Instant::now() + DOH_PROVIDER_TIMEOUT).min(deadline);
        match tokio::time::timeout_at(provider_deadline, attempt(index)).await {
            Ok(Ok(answer)) if !temporary_response(&answer.message) => return Ok(answer),
            Ok(Ok(_)) => debug!(index, "temporary DNS failure; trying next provider"),
            Ok(Err(error)) => debug!(index, %error, "provider failed; trying next"),
            Err(_) => debug!(index, "provider deadline expired"),
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(DnsServerError::Timeout(DOH_TOTAL_TIMEOUT));
        }
    }
    Err(DnsServerError::AllProvidersFailed)
}

/// Only SERVFAIL is temporary; every other valid rcode is forwarded intact.
pub(crate) fn temporary_response(message: &Message) -> bool {
    message.metadata.response_code == ResponseCode::ServFail
}

/// cancel-safe: yes — the sole exchange owns its stream and is discarded on cancellation.
async fn resolve_with_provider(
    question: &Query,
    tor: &TorTunnel,
    provider: &DohProvider,
) -> Result<ResolvedAnswer, DnsServerError> {
    let query = build_query(question).map_err(DnsServerError::Wire)?;
    let body = exchange(tor, provider, &query).await?;
    parse_response(&query, &body)
}

/// RFC 1035 §4.1.2: preserve QNAME, QTYPE and QCLASS, including unknown codes.
pub(crate) fn build_query(question: &Query) -> Result<DnsQuery, String> {
    let mut message = Message::query();
    message.metadata.recursion_desired = true;
    message.add_query(question.clone());
    let bytes = message
        .to_vec()
        .map_err(|e| format!("encode DNS query: {e}"))?;
    Ok(DnsQuery {
        id: message.metadata.id,
        bytes,
        question: question.clone(),
    })
}

/// Dial the provider through the Tor tunnel BY IP and wrap the stream in TLS.
///
/// `tor.connect` receives the provider's IP as a string, so nothing is ever
/// resolved on the way (the tunnel would otherwise leak a plaintext DNS
/// lookup); the hostname feeds TLS SNI only. Tor errors map to
/// [`DnsServerError::TorConnect`], TLS errors to [`DnsServerError::Tls`].
async fn connect_through_tor(
    tor: &TorTunnel,
    provider: &DohProvider,
) -> Result<tokio_rustls::client::TlsStream<BoxedIo>, DnsServerError> {
    let dial_ip = provider.ip.to_string();
    let raw_stream = tor
        .connect(&dial_ip, DOH_PORT)
        .await
        .map_err(|e| DnsServerError::TorConnect(e.to_string()))?;
    let raw_io: BoxedIo = Box::pin(raw_stream.compat());

    let server_name =
        rustls::pki_types::ServerName::try_from(provider.hostname.clone()).map_err(|e| {
            DnsServerError::Tls(format!("invalid SNI hostname {:?}: {e}", provider.hostname))
        })?;
    tokio_rustls::TlsConnector::from(tls_config())
        .connect(server_name, raw_io)
        .await
        .map_err(|e| DnsServerError::Tls(e.to_string()))
}

/// One full DoH exchange: POST the encoded query, read the reply body.
/// Transport failures (write/read/HTTP-level) map to
/// [`DnsServerError::DohExchange`].
async fn exchange(
    tor: &TorTunnel,
    provider: &DohProvider,
    query: &DnsQuery,
) -> Result<Vec<u8>, DnsServerError> {
    let mut tls = connect_through_tor(tor, provider).await?;
    let request = build_post_request(&provider.hostname, &provider.path, &query.bytes);
    tls.write_all(&request)
        .await
        .map_err(|e| DnsServerError::DohExchange(format!("write DoH request: {e}")))?;
    tls.flush()
        .await
        .map_err(|e| DnsServerError::DohExchange(format!("flush DoH request: {e}")))?;
    read_dns_body(&mut tls).await
}

/// Build the RFC 8484 HTTP/1.1 POST: the raw DNS message is the body, both
/// `Accept` and `Content-Type` are `application/dns-message`. The provider's
/// hostname appears ONLY in `Host` (the TCP connection went to its IP).
fn build_post_request(hostname: &str, path: &str, dns_body: &[u8]) -> Vec<u8> {
    format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {hostname}\r\n\
         Accept: application/dns-message\r\n\
         Content-Type: application/dns-message\r\n\
         Content-Length: {}\r\n\
         User-Agent: tor-socks5/0.1\r\n\
         Connection: close\r\n\
         \r\n",
        dns_body.len()
    )
    .into_bytes()
    .into_iter()
    .chain(dns_body.iter().copied())
    .collect()
}

/// Read one HTTP response off the stream and return its body (the raw DNS
/// message).
///
/// Headers are parsed with httparse on the accumulating buffer; the body
/// starts EXACTLY at httparse's `header_len` (hand-slicing after a CRLFCRLF
/// search is what caused the off-by-4 bug this replaced). With
/// `Content-Length` the body is read to exactly that many bytes; without it,
/// `Connection: close` makes EOF the body terminator. Chunked framing is
/// rejected outright: DoH providers send small binary answers with
/// `Content-Length`, and ignoring the chunk framing would corrupt the DNS
/// message.
async fn read_dns_body<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>, DnsServerError> {
    let mut buf = vec![0u8; READ_BUF_SIZE];
    let mut filled = 0usize;

    let head = loop {
        if let Some(head) = parse_head(&buf[..filled])? {
            break head;
        }
        if filled == buf.len() {
            if buf.len() >= MAX_HEADER_BYTES {
                return Err(DnsServerError::DohExchange(format!(
                    "HTTP headers exceed the {MAX_HEADER_BYTES} byte limit"
                )));
            }
            buf.resize(buf.len() * 2, 0);
        }
        let n = stream
            .read(&mut buf[filled..])
            .await
            .map_err(|e| DnsServerError::DohExchange(format!("read HTTP headers: {e}")))?;
        if n == 0 {
            return Err(DnsServerError::DohExchange(
                "connection closed before HTTP headers completed".to_string(),
            ));
        }
        filled += n;
    };

    if head.status != 200 {
        return Err(DnsServerError::DohExchange(format!("HTTP {}", head.status)));
    }
    if head.chunked {
        return Err(DnsServerError::DohExchange(
            "chunked transfer-encoding is not supported for DoH".to_string(),
        ));
    }

    // The bytes that arrived together with the headers count against the cap
    // before any further read, so an over-limit body delivered whole with
    // EOF cannot slip through.
    let mut body = buf[head.header_len..filled].to_vec();
    if body.len() > MAX_DNS_RESPONSE_BYTES {
        return Err(DnsServerError::DohExchange(format!(
            "DNS response exceeds the {MAX_DNS_RESPONSE_BYTES} byte limit"
        )));
    }

    match head.content_length {
        Some(length) => {
            if length > MAX_DNS_RESPONSE_BYTES {
                return Err(DnsServerError::DohExchange(format!(
                    "DNS response of {length} bytes exceeds the {MAX_DNS_RESPONSE_BYTES} byte limit"
                )));
            }
            if body.len() > length {
                body.truncate(length);
            }
            while body.len() < length {
                let want = READ_BUF_SIZE.min(length - body.len());
                let mut chunk = vec![0u8; want];
                let n = stream
                    .read(&mut chunk)
                    .await
                    .map_err(|e| DnsServerError::DohExchange(format!("read HTTP body: {e}")))?;
                if n == 0 {
                    return Err(DnsServerError::DohExchange(format!(
                        "connection closed after {} of {length} body bytes",
                        body.len()
                    )));
                }
                body.extend_from_slice(&chunk[..n]);
            }
        }
        None => loop {
            let mut chunk = vec![0u8; READ_BUF_SIZE];
            let n = stream
                .read(&mut chunk)
                .await
                .map_err(|e| DnsServerError::DohExchange(format!("read HTTP body: {e}")))?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
            if body.len() > MAX_DNS_RESPONSE_BYTES {
                return Err(DnsServerError::DohExchange(format!(
                    "DNS response exceeds the {MAX_DNS_RESPONSE_BYTES} byte limit"
                )));
            }
        },
    }
    Ok(body)
}

/// HTTP response header block, decoded by httparse.
struct HttpHead {
    status: u16,
    content_length: Option<usize>,
    chunked: bool,
    /// Exact length of the header block INCLUDING the final CRLFCRLF -- the
    /// body begins at this offset, no magic offsets added.
    header_len: usize,
}

/// Try to parse a complete header block out of `buf`; `Ok(None)` means "need
/// more bytes". All HTTP framing problems are [`DnsServerError::DohExchange`].
fn parse_head(buf: &[u8]) -> Result<Option<HttpHead>, DnsServerError> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HTTP_HEADERS];
    let mut response = httparse::Response::new(&mut headers);
    match response.parse(buf) {
        Ok(httparse::Status::Complete(header_len)) => {
            let status = response.code.ok_or_else(|| {
                DnsServerError::DohExchange("HTTP response without status code".to_string())
            })?;
            let mut content_length = None;
            let mut chunked = false;
            for header in response.headers {
                if header.name.eq_ignore_ascii_case("content-length") {
                    if let Ok(value) = std::str::from_utf8(header.value) {
                        // An unparsable Content-Length falls back to the
                        // read-to-EOF path rather than inventing a length.
                        content_length = value.trim().parse::<usize>().ok();
                    }
                }
                if header.name.eq_ignore_ascii_case("transfer-encoding") {
                    if let Ok(value) = std::str::from_utf8(header.value) {
                        if value.split(',').any(|coding| {
                            coding
                                .split(';')
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
            Ok(Some(HttpHead {
                status,
                content_length,
                chunked,
                header_len,
            }))
        }
        Ok(httparse::Status::Partial) => Ok(None),
        Err(e) => Err(DnsServerError::DohExchange(format!(
            "malformed HTTP response: {e}"
        ))),
    }
}

/// RFC 5452 §9.1: validate the echoed question and transaction before using
/// any flags (especially TC) or records. Name comparison ignores ASCII case.
pub(crate) fn validate_response(query: &DnsQuery, body: &[u8]) -> Result<Message, DnsServerError> {
    let message = Message::from_vec(body)
        .map_err(|e| DnsServerError::Wire(format!("decode DNS response: {e}")))?;
    if message.metadata.id != query.id
        || message.metadata.message_type != MessageType::Response
        || message.metadata.op_code != OpCode::Query
        || message.queries.len() != 1
    {
        return Err(DnsServerError::DohExchange(
            "response transaction/header/question count mismatch".into(),
        ));
    }
    let echoed = &message.queries[0];
    if !echoed.name().eq_ignore_root(query.question.name())
        || echoed.query_type() != query.question.query_type()
        || echoed.query_class() != query.question.query_class()
    {
        return Err(DnsServerError::DohExchange(
            "response question mismatch".into(),
        ));
    }
    Ok(message)
}

pub(crate) fn parse_response(
    query: &DnsQuery,
    body: &[u8],
) -> Result<ResolvedAnswer, DnsServerError> {
    let mut message = validate_response(query, body)?;
    if message.metadata.truncation {
        return Err(DnsServerError::DohExchange(
            "incomplete DNS response (TC)".into(),
        ));
    }
    crate::types::normalize_negative_soa_ttl(&query.question, &mut message);
    let ttl = crate::types::cache_ttl(&query.question, &message).unwrap_or(Duration::ZERO);
    Ok(ResolvedAnswer {
        message,
        ttl,
        resolved_at: OffsetDateTime::now_utc(),
    })
}

#[cfg(test)]
#[path = "doh_http_tests.rs"]
mod http_tests;
#[cfg(test)]
#[path = "dns_wire_tests.rs"]
mod wire_tests;
