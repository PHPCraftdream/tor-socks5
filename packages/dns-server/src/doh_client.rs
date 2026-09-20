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
//! hostname is never resolved — locally or through the tunnel. The hostname
//! is used only for TLS SNI and the HTTP `Host` header.

use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use arti_wrapper::TorTunnel;
use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing::debug;

use crate::error::DnsServerError;
use crate::{DohProvider, ResolvedAnswer};

/// Per-provider bound on the WHOLE lookup: Tor connect + TLS handshake + the
/// A and AAAA exchanges. Through a live Tor circuit a fresh stream and a TLS
/// handshake can each take several seconds, so this is far more generous
/// than the 4s `DOH_PROVIDER_TIMEOUT` the DIRECT path uses
/// (bridge-probe/src/dns.rs).
pub const DOH_PROVIDER_TIMEOUT: Duration = Duration::from_secs(20);

/// Upper bound for a DNS response body. A DNS message cannot exceed 64 KiB
/// per its own u16 length fields, so anything larger is a malicious or
/// broken server and is rejected instead of being read into memory.
const MAX_DNS_RESPONSE_BYTES: usize = 64 * 1024;

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
struct DnsQuery {
    id: u16,
    bytes: Vec<u8>,
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

/// Resolve a hostname through one DoH provider, every byte over the Tor
/// tunnel.
///
/// The whole lookup — Tor connect, TLS handshake, and the A and AAAA
/// exchanges — is bounded by [`DOH_PROVIDER_TIMEOUT`]; on expiry
/// [`DnsServerError::Timeout`] is returned.
///
/// # Cancel-safety
/// cancel-safe: yes — stateless: dropping the future mid-exchange just drops
/// the connection.
pub async fn resolve(
    hostname: &str,
    tor: &TorTunnel,
    provider: &DohProvider,
) -> Result<ResolvedAnswer, DnsServerError> {
    tokio::time::timeout(
        DOH_PROVIDER_TIMEOUT,
        resolve_with_provider(hostname, tor, provider),
    )
    .await
    .map_err(|_| DnsServerError::Timeout(DOH_PROVIDER_TIMEOUT))?
}

/// Try a pool of providers in fixed order; the first success wins.
///
/// Individual provider failures (including per-attempt timeouts, which
/// surface as [`DnsServerError::Timeout`] before being consumed here) are
/// logged at `debug!` and the next provider is tried. An empty pool, or
/// every provider failing, yields [`DnsServerError::AllProvidersFailed`] —
/// there is deliberately no distinction between "all errored" and "all
/// timed out".
///
/// # Cancel-safety
/// cancel-safe: yes — each attempt is [`resolve`], which is cancel-safe, and
/// dropping the pool future between attempts drops nothing.
pub async fn resolve_with_pool(
    hostname: &str,
    tor: &TorTunnel,
    providers: &[DohProvider],
) -> Result<ResolvedAnswer, DnsServerError> {
    if providers.is_empty() {
        return Err(DnsServerError::AllProvidersFailed);
    }
    for (index, provider) in providers.iter().enumerate() {
        let attempt = tokio::time::timeout(
            DOH_PROVIDER_TIMEOUT,
            resolve_with_provider(hostname, tor, provider),
        )
        .await
        .map_err(|_| DnsServerError::Timeout(DOH_PROVIDER_TIMEOUT));
        match attempt {
            Ok(Ok(answer)) => return Ok(answer),
            Ok(Err(error)) | Err(error) => {
                debug!(
                    provider = %provider.hostname,
                    index,
                    error = %error,
                    "DoH provider failed; trying next"
                );
            }
        }
    }
    Err(DnsServerError::AllProvidersFailed)
}

/// One provider attempt: two concurrent DoH exchanges (A + AAAA), merged.
///
/// Concurrency: the exchanges are independent work — each opens its own Tor
/// stream and TLS session — so they run via [`tokio::try_join!`]. A
/// transport-level failure (Tor connect, TLS, HTTP) of either half fails the
/// attempt immediately: a tunnel broken for one half is broken for both.
/// DNS-level outcomes merge leniently (see the `match` below): the attempt
/// only fails when BOTH halves fail.
async fn resolve_with_provider(
    hostname: &str,
    tor: &TorTunnel,
    provider: &DohProvider,
) -> Result<ResolvedAnswer, DnsServerError> {
    // RFC 8484 practice: one QUESTION per message — resolvers answer only
    // the first question-section entry, so A and AAAA are two exchanges.
    let a_query = build_query(hostname, RecordType::A).map_err(DnsServerError::Wire)?;
    let aaaa_query = build_query(hostname, RecordType::AAAA).map_err(DnsServerError::Wire)?;

    let (a_body, aaaa_body) = tokio::try_join!(
        exchange(tor, provider, &a_query),
        exchange(tor, provider, &aaaa_query),
    )?;

    let a_result = parse_response(a_query.id, &a_body);
    let aaaa_result = parse_response(aaaa_query.id, &aaaa_body);
    match (a_result, aaaa_result) {
        // Only when BOTH halves fail does the attempt fail; the first error
        // is reported (the second adds no information a caller can act on).
        (Err(first), Err(_)) => Err(first),
        (Ok(a), Ok(aaaa)) => Ok(merge_exchanges(Some(a), Some(aaaa))),
        (Ok(a), Err(error)) => {
            debug!(
                provider = %provider.hostname,
                error = %error,
                "AAAA exchange failed; keeping A records"
            );
            Ok(merge_exchanges(Some(a), None))
        }
        (Err(error), Ok(aaaa)) => {
            debug!(
                provider = %provider.hostname,
                error = %error,
                "A exchange failed; keeping AAAA records"
            );
            Ok(merge_exchanges(None, Some(aaaa)))
        }
    }
}

/// Encode one DNS query message carrying exactly one QUESTION.
fn build_query(hostname: &str, query_type: RecordType) -> Result<DnsQuery, String> {
    let name: Name = hostname
        .parse()
        .map_err(|e| format!("invalid query hostname {hostname:?}: {e}"))?;
    // `Message::query()` randomizes the transaction id; RD is set because we
    // are asking a recursive public resolver.
    let mut message = Message::query();
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name, query_type));
    let bytes = message
        .to_vec()
        .map_err(|e| format!("encode DNS query: {e}"))?;
    Ok(DnsQuery {
        id: message.metadata.id,
        bytes,
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
    /// Exact length of the header block INCLUDING the final CRLFCRLF — the
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

/// Outcome of ONE validated DNS response.
#[derive(Debug, Clone)]
struct ExchangeResult {
    /// A/AAAA addresses carried by the answer records, in wire order.
    addrs: Vec<IpAddr>,
    /// Smallest TTL over ALL answer records; `None` only when the response
    /// carried zero answer records (NODATA), which contributes no TTL bound.
    min_ttl: Option<Duration>,
}

/// Decode and validate one DNS response against the query id that was sent.
fn parse_response(query_id: u16, body: &[u8]) -> Result<ExchangeResult, DnsServerError> {
    let message = Message::from_vec(body)
        .map_err(|e| DnsServerError::Wire(format!("decode DNS response: {e}")))?;
    if message.metadata.id != query_id {
        return Err(DnsServerError::DohExchange(format!(
            "transaction id mismatch: sent {query_id:#06x}, got {:#06x}",
            message.metadata.id
        )));
    }
    if message.metadata.response_code != ResponseCode::NoError {
        // `Display` renders the rcode's human string ("Non-Existent Domain",
        // "Query Refused", ...).
        return Err(DnsServerError::DohExchange(format!(
            "resolver returned {}",
            message.metadata.response_code
        )));
    }

    // The question/answer owner name is deliberately NOT compared here:
    // resolvers may 0x20-randomize the case of the query name they echo
    // (cache-insertion diversity), so a byte-for-byte name comparison would
    // reject perfectly valid answers. The transaction id is the integrity
    // check that matters.
    let mut result = ExchangeResult {
        addrs: Vec::new(),
        min_ttl: None,
    };
    for record in &message.answers {
        // `Record` exposes its ttl/data as public fields (the ttl()/data()
        // accessor methods belong to RecordRef in hickory-proto 0.26).
        let ttl = Duration::from_secs(u64::from(record.ttl));
        result.min_ttl = Some(match result.min_ttl {
            Some(current) => current.min(ttl),
            None => ttl,
        });
        match record.data {
            RData::A(a) => result.addrs.push(IpAddr::V4(a.0)),
            RData::AAAA(aaaa) => result.addrs.push(IpAddr::V6(aaaa.0)),
            // CNAME/SOA/etc: no address of their own, but the TTL taken
            // above still bounds how long the whole answer chain may be
            // cached — the lower bound is the safe caching bound.
            _ => {}
        }
    }
    Ok(result)
}

/// Merge the A and AAAA exchange outcomes into one answer.
///
/// Addresses are concatenated A-list first, then AAAA, without dedup — the
/// lists are independent answers and duplicates are harmless. The TTL is the
/// minimum over both halves (a missing half contributes nothing). When no
/// half carries ANY answer record (both NODATA), the TTL is
/// [`Duration::ZERO`] = "no TTL information reported"; the cache layer
/// decides its own floor. `resolved_at` is stamped once, here, after both
/// exchanges completed.
fn merge_exchanges(a: Option<ExchangeResult>, aaaa: Option<ExchangeResult>) -> ResolvedAnswer {
    let mut addrs = Vec::new();
    let mut min_ttl: Option<Duration> = None;
    for result in [a, aaaa].into_iter().flatten() {
        addrs.extend(result.addrs);
        min_ttl = match (min_ttl, result.min_ttl) {
            (None, ttl) | (ttl, None) => ttl,
            (Some(current), Some(ttl)) => Some(current.min(ttl)),
        };
    }
    ResolvedAnswer {
        addrs,
        ttl: min_ttl.unwrap_or(Duration::ZERO),
        resolved_at: OffsetDateTime::now_utc(),
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::task::{Context, Poll};

    use hickory_proto::op::{MessageType, OpCode};
    use hickory_proto::rr::rdata::{A, AAAA, CNAME};
    use hickory_proto::rr::{RData, Record};
    use tokio::io::ReadBuf;

    use super::*;

    fn test_name() -> Name {
        "example.com".parse().expect("valid test name")
    }

    fn test_response(id: u16) -> Message {
        Message::new(id, MessageType::Response, OpCode::Query)
    }

    #[test]
    fn build_query_carries_one_question_with_rd() {
        for query_type in [RecordType::A, RecordType::AAAA] {
            let query = build_query("example.com", query_type).expect("query builds");
            let message = Message::from_vec(&query.bytes).expect("query decodes");
            assert_eq!(message.queries.len(), 1, "one QUESTION per message");
            assert_eq!(message.queries[0].query_type(), query_type);
            assert_eq!(message.queries[0].name().to_string(), "example.com.");
            assert!(message.metadata.recursion_desired);
            assert_eq!(message.metadata.message_type, MessageType::Query);
            assert_eq!(message.metadata.op_code, OpCode::Query);
            assert_eq!(message.metadata.id, query.id, "returned id is the wire id");
        }
    }

    #[test]
    fn parse_response_collects_a_record() {
        let owner = test_name();
        let mut message = test_response(0x1F2E);
        message.add_query(Query::query(owner.clone(), RecordType::A));
        message.add_answer(Record::from_rdata(
            owner,
            120,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 7))),
        ));
        let bytes = message.to_vec().expect("response encodes");

        let parsed = parse_response(0x1F2E, &bytes).expect("response parses");
        assert_eq!(parsed.addrs, vec![IpAddr::from([192, 0, 2, 7])]);
        assert_eq!(parsed.min_ttl, Some(Duration::from_secs(120)));
    }

    #[test]
    fn parse_response_collects_aaaa_record() {
        let owner = test_name();
        let mut message = test_response(0x0B0B);
        message.add_query(Query::query(owner.clone(), RecordType::AAAA));
        message.add_answer(Record::from_rdata(
            owner,
            45,
            RData::AAAA(AAAA(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
        ));
        let bytes = message.to_vec().expect("response encodes");

        let parsed = parse_response(0x0B0B, &bytes).expect("response parses");
        assert_eq!(
            parsed.addrs,
            vec![IpAddr::from([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1])]
        );
        assert_eq!(parsed.min_ttl, Some(Duration::from_secs(45)));
    }

    #[test]
    fn parse_response_min_ttl_includes_cname() {
        let owner = test_name();
        let alias: Name = "alias.example.com".parse().expect("valid test name");
        let mut message = test_response(7);
        message.add_query(Query::query(owner.clone(), RecordType::A));
        message.add_answer(Record::from_rdata(
            owner.clone(),
            60,
            RData::CNAME(CNAME(alias.clone())),
        ));
        message.add_answer(Record::from_rdata(
            alias,
            300,
            RData::A(A(Ipv4Addr::new(203, 0, 113, 9))),
        ));
        let bytes = message.to_vec().expect("response encodes");

        let parsed = parse_response(7, &bytes).expect("response parses");
        // The CNAME contributes no address...
        assert_eq!(parsed.addrs, vec![IpAddr::from([203, 0, 113, 9])]);
        // ...but its smaller TTL bounds the whole answer chain.
        assert_eq!(parsed.min_ttl, Some(Duration::from_secs(60)));
    }

    #[test]
    fn parse_response_nxdomain_is_doh_exchange_error() {
        let mut message = test_response(9);
        message.metadata.response_code = ResponseCode::NXDomain;
        let bytes = message.to_vec().expect("response encodes");

        let error = parse_response(9, &bytes).expect_err("NXDomain must fail");
        assert!(
            matches!(error, DnsServerError::DohExchange(ref text) if text.contains("Non-Existent")),
            "error should carry the rcode: {error:?}"
        );
    }

    #[test]
    fn parse_response_rejects_id_mismatch() {
        let bytes = test_response(0x0102).to_vec().expect("response encodes");
        let error = parse_response(0x0304, &bytes).expect_err("id mismatch must fail");
        assert!(matches!(error, DnsServerError::DohExchange(_)));
    }

    #[test]
    fn nodata_on_both_halves_is_success_with_zero_ttl() {
        let mut message = test_response(3);
        message.add_query(Query::query(test_name(), RecordType::A));
        let bytes = message.to_vec().expect("response encodes");

        let nodata_a = parse_response(3, &bytes).expect("rcode 0 is a success");
        let nodata_aaaa = parse_response(3, &bytes).expect("rcode 0 is a success");
        assert!(nodata_a.addrs.is_empty());
        assert_eq!(nodata_a.min_ttl, None, "NODATA contributes no TTL bound");

        let answer = merge_exchanges(Some(nodata_a), Some(nodata_aaaa));
        assert!(answer.addrs.is_empty());
        assert_eq!(answer.ttl, Duration::ZERO, "ZERO means no TTL information");
    }

    #[test]
    fn merge_takes_minimum_ttl_and_keeps_both_lists() {
        let a = ExchangeResult {
            addrs: vec![IpAddr::from([192, 0, 2, 1])],
            min_ttl: Some(Duration::from_secs(90)),
        };
        let aaaa = ExchangeResult {
            addrs: vec![IpAddr::from([0x2001, 0xdb8, 0, 0, 0, 0, 0, 2])],
            min_ttl: Some(Duration::from_secs(30)),
        };
        let answer = merge_exchanges(Some(a), Some(aaaa));
        // A addresses first, then AAAA, no dedup.
        assert_eq!(
            answer.addrs,
            vec![
                IpAddr::from([192, 0, 2, 1]),
                IpAddr::from([0x2001, 0xdb8, 0, 0, 0, 0, 0, 2]),
            ]
        );
        assert_eq!(answer.ttl, Duration::from_secs(30));
    }

    #[test]
    fn post_request_carries_exact_headers_and_body() {
        let provider = DohProvider {
            ip: IpAddr::from([192, 0, 2, 1]),
            hostname: "dns.example".to_string(),
            path: "/dns-query".to_string(),
        };
        let body = b"\x12\x34abcd";
        let request = build_post_request(&provider.hostname, &provider.path, body);
        let mut expected = format!(
            "POST /dns-query HTTP/1.1\r\n\
             Host: dns.example\r\n\
             Accept: application/dns-message\r\n\
             Content-Type: application/dns-message\r\n\
             Content-Length: {}\r\n\
             User-Agent: tor-socks5/0.1\r\n\
             Connection: close\r\n\
             \r\n",
            body.len()
        )
        .into_bytes();
        expected.extend_from_slice(body);
        assert_eq!(request, expected);
    }

    /// AsyncRead over a fixed sequence of byte chunks: each poll_read hands
    /// out up to the remainder of the current chunk, then moves on; running
    /// dry is EOF.
    struct ChunkReader {
        chunks: Vec<Cursor<Vec<u8>>>,
        current: usize,
    }

    impl ChunkReader {
        fn new(chunks: &[&[u8]]) -> Self {
            Self {
                chunks: chunks
                    .iter()
                    .map(|chunk| Cursor::new(chunk.to_vec()))
                    .collect(),
                current: 0,
            }
        }
    }

    impl AsyncRead for ChunkReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            while this.current < this.chunks.len() {
                let cursor = &mut this.chunks[this.current];
                let position = cursor.position() as usize;
                let data = &cursor.get_ref()[position..];
                if data.is_empty() {
                    this.current += 1;
                    continue;
                }
                let take = data.len().min(buf.remaining());
                buf.put_slice(&data[..take]);
                cursor.set_position((position + take) as u64);
                return Poll::Ready(Ok(()));
            }
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn reads_whole_response_in_one_chunk() {
        let body = [0xABu8; 48];
        let mut wire = b"HTTP/1.1 200 OK\r\nContent-Length: 48\r\n\r\n".to_vec();
        wire.extend_from_slice(&body);
        let mut reader = ChunkReader::new(&[&wire]);
        let parsed = read_dns_body(&mut reader).await.expect("body read");
        assert_eq!(parsed, body);
    }

    #[tokio::test]
    async fn body_starts_exactly_at_httparse_header_len() {
        // THE off-by-4 regression case: headers and the first body bytes
        // arrive in one read, the rest split over two more. The body must
        // begin exactly at httparse's header_len — no bytes skipped.
        let body: Vec<u8> = (0..64u8).collect();
        let mut first = b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\n".to_vec();
        let header_len = first.len();
        first.extend_from_slice(&body[..3]);
        let mut reader = ChunkReader::new(&[&first, &body[3..40], &body[40..]]);

        let parsed = read_dns_body(&mut reader).await.expect("body read");
        assert_eq!(header_len, 39);
        assert_eq!(parsed, body);
    }

    #[tokio::test]
    async fn non_200_status_is_an_error() {
        let wire = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n";
        let mut reader = ChunkReader::new(&[wire]);
        let error = read_dns_body(&mut reader).await.expect_err("503 must fail");
        assert!(
            matches!(error, DnsServerError::DohExchange(ref text) if text.contains("503")),
            "error should carry the status: {error:?}"
        );
    }

    #[tokio::test]
    async fn oversized_content_length_is_rejected() {
        let oversized = MAX_DNS_RESPONSE_BYTES + 1;
        let wire = format!("HTTP/1.1 200 OK\r\nContent-Length: {oversized}\r\n\r\n");
        let mut reader = ChunkReader::new(&[wire.as_bytes()]);
        let error = read_dns_body(&mut reader)
            .await
            .expect_err("over-cap must fail");
        assert!(matches!(error, DnsServerError::DohExchange(_)));
    }

    #[tokio::test]
    async fn chunked_transfer_encoding_is_rejected() {
        let wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut reader = ChunkReader::new(&[wire]);
        let error = read_dns_body(&mut reader)
            .await
            .expect_err("chunked must fail");
        assert!(matches!(error, DnsServerError::DohExchange(_)));
    }
}
