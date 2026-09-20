//! Runtime DNS overrides: operator-listed host masks resolved OUTSIDE the
//! Tor tunnel.
//!
//! # Security framing
//!
//! The default path of this server resolves EVERY hostname through
//! DoH-over-Tor ([`crate::doh_client`]), so no DNS query ever leaves the
//! machine as plaintext and none is linkable to the operator's real
//! network. This module is the deliberate, operator-opted escape hatch:
//! only host masks explicitly configured as [`DnsOverride`] entries take
//! the escape routes, and both [`resolve_via_dns_server`] and
//! [`resolve_via_system`] purposefully leave the Tor tunnel — the former
//! speaks plain UDP/TCP DNS straight to the configured server, the latter
//! delegates to the operating-system resolver. Every hostname that matches
//! no mask keeps going through the tunnel; a mask is an operator decision
//! that leak-ability is acceptable (or preferable) for those names.
//!
//! Matching is a small, dependency-free hostname glob ([`matches`]) and
//! lookup is a first-match scan in list order ([`find_override`]) — the
//! same fixed-order convention as the DoH provider pool.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use hickory_proto::op::Message;
use hickory_proto::rr::{RData, RecordType};
use hickory_resolver::lookup::Lookup;
use hickory_resolver::TokioResolver;
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::debug;

use crate::doh_client::{
    build_query, merge_exchanges, parse_response, DnsQuery, ExchangeResult, MAX_DNS_RESPONSE_BYTES,
};
use crate::error::DnsServerError;
use crate::ResolvedAnswer;

/// Bound on the WHOLE direct lookup: the A and AAAA UDP exchanges (plus any
/// TCP retry for a truncated reply). The server is reached over the direct
/// network with no Tor round-trips, so a fraction of
/// [`DOH_PROVIDER_TIMEOUT`](crate::doh_client::DOH_PROVIDER_TIMEOUT)'s 20s
/// (Tor connect + TLS handshake + exchanges) is already generous.
pub const PLAIN_DNS_TIMEOUT: Duration = Duration::from_secs(5);

/// Bound on the WHOLE operating-system resolver lookup. OS resolvers walk
/// several configured nameservers with retries and their own timeouts, so
/// this budget is deliberately larger than the 5s direct-DNS bound
/// ([`PLAIN_DNS_TIMEOUT`]).
pub const SYSTEM_RESOLVER_TIMEOUT: Duration = Duration::from_secs(10);

/// One configured override: a hostname glob plus the resolver that should
/// handle matching hosts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsOverride {
    /// Hostname glob; `*` matches any run of characters (see [`matches`]).
    pub pattern: String,
    /// Which escape route matching hosts take.
    pub resolver: OverrideResolver,
}

/// The resolver an override routes matching hosts to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverrideResolver {
    /// The operating-system resolver (hickory-resolver reading
    /// `/etc/resolv.conf` / the Windows registry).
    System,
    /// A specific DNS server reached directly (plain UDP, TCP retry on
    /// truncation) — NOT through Tor, NOT DoH.
    Dns {
        /// Address of the DNS server to query.
        server: SocketAddr,
    },
}

/// Whether `host` matches the hostname glob `pattern`.
///
/// `*` matches any run of characters including none; matching is
/// case-insensitive and always against the WHOLE host (not per-label), so
/// `foo*.com` matches `foobar.com` and the bare `*` matches everything.
///
/// Deliberate edge case: `*.example.com` does NOT match `example.com`. The
/// pattern's literal `.` must appear in the host, so a mask for the
/// children of a domain never captures the bare parent domain itself; an
/// operator who wants both lists both entries.
///
/// Both inputs are lowercased with [`str::to_ascii_lowercase`] and then
/// compared as ASCII bytes. Hostnames are ASCII on the wire — international
/// names arrive punycode-encoded (`xn--…`) — so byte-wise ASCII matching
/// is exact, not an approximation.
///
/// Implementation: the classic greedy single-`*` backtracking walk over the
/// two byte slices (two pointers; on a mismatch after a star, extend the
/// star's match by one and retry). No regex or glob crates.
pub fn matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let host = host.to_ascii_lowercase();
    let pattern = pattern.as_bytes();
    let host = host.as_bytes();

    let mut pattern_index = 0usize;
    let mut host_index = 0usize;
    // The star seen so far and the host offset where its match currently
    // starts; on a later mismatch the star's match is extended by one byte
    // and the scan resumes from there.
    let mut star_index: Option<usize> = None;
    let mut star_match_start = 0usize;

    while host_index < host.len() {
        if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
            // `*` first tries to match zero characters: only the pattern
            // cursor advances here, so the very next byte of `host` is
            // re-checked against whatever follows the star.
            star_index = Some(pattern_index);
            star_match_start = host_index;
            pattern_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == host[host_index] {
            pattern_index += 1;
            host_index += 1;
        } else if let Some(star) = star_index {
            pattern_index = star + 1;
            star_match_start += 1;
            host_index = star_match_start;
        } else {
            return false;
        }
    }
    while pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

/// Find the first override whose pattern matches `host`.
///
/// Linear scan in list order; the FIRST match wins. This is the same
/// fixed-order convention as
/// [`providers::provider_pool`](crate::providers::provider_pool) and
/// [`doh_client::resolve_with_pool`](crate::doh_client::resolve_with_pool):
/// position is priority — no scoring, no racing — so an operator who
/// prepends an entry knows exactly when it is used.
pub fn find_override<'a>(overrides: &'a [DnsOverride], host: &str) -> Option<&'a DnsOverride> {
    overrides.iter().find(|entry| matches(&entry.pattern, host))
}

/// Resolve a hostname by speaking plain DNS (UDP, TCP retry on truncation)
/// directly to `server`.
///
/// This deliberately leaves the Tor tunnel: the exchange is a direct
/// network conversation with the configured server (NOT DoH, NOT through
/// Tor) — the operator opted this host mask into exactly that leak.
///
/// Structured like [`doh_client::resolve`](crate::doh_client::resolve):
/// the whole lookup is bounded by [`PLAIN_DNS_TIMEOUT`]; on expiry
/// [`DnsServerError::Timeout`] is returned.
///
/// # Cancel-safety
/// cancel-safe: yes — stateless: dropping the future mid-exchange just
/// drops the ephemeral socket.
pub async fn resolve_via_dns_server(
    hostname: &str,
    server: SocketAddr,
) -> Result<ResolvedAnswer, DnsServerError> {
    tokio::time::timeout(PLAIN_DNS_TIMEOUT, resolve_with_server(hostname, server))
        .await
        .map_err(|_| DnsServerError::Timeout(PLAIN_DNS_TIMEOUT))?
}

/// One direct-server attempt: two concurrent UDP exchanges (A + AAAA),
/// merged.
///
/// Concurrency and merge semantics are the same as
/// [`doh_client::resolve_with_provider`](crate::doh_client::resolve_with_provider):
/// the exchanges run via [`tokio::try_join!`] (a failure of either transport
/// half fails the attempt — one broken network is broken for both), and the
/// parsed DNS-level outcomes merge leniently: only when BOTH halves fail
/// does the lookup fail.
async fn resolve_with_server(
    hostname: &str,
    server: SocketAddr,
) -> Result<ResolvedAnswer, DnsServerError> {
    // One QUESTION per message (same rationale as doh_client): A and AAAA
    // are two exchanges.
    let a_query = build_query(hostname, RecordType::A).map_err(DnsServerError::Wire)?;
    let aaaa_query = build_query(hostname, RecordType::AAAA).map_err(DnsServerError::Wire)?;

    let (a_body, aaaa_body) = tokio::try_join!(
        udp_exchange(server, &a_query),
        udp_exchange(server, &aaaa_query),
    )?;

    let a_result = parse_plain(server, &a_query, &a_body).await;
    let aaaa_result = parse_plain(server, &aaaa_query, &aaaa_body).await;
    merge_lenient(server, a_result, aaaa_result)
}

/// Lenient merge of the two parsed exchange outcomes: only when BOTH halves
/// fail does the lookup fail (the first error is reported; the second adds
/// no information a caller can act on). Same match shape as
/// [`doh_client::resolve_with_provider`](crate::doh_client::resolve_with_provider).
fn merge_lenient(
    server: SocketAddr,
    a: Result<ExchangeResult, DnsServerError>,
    aaaa: Result<ExchangeResult, DnsServerError>,
) -> Result<ResolvedAnswer, DnsServerError> {
    match (a, aaaa) {
        (Err(first), Err(_)) => Err(first),
        (Ok(a), Ok(aaaa)) => Ok(merge_exchanges(Some(a), Some(aaaa))),
        (Ok(a), Err(error)) => {
            debug!(
                server = %server,
                error = %error,
                "AAAA exchange failed; keeping A records"
            );
            Ok(merge_exchanges(Some(a), None))
        }
        (Err(error), Ok(aaaa)) => {
            debug!(
                server = %server,
                error = %error,
                "A exchange failed; keeping AAAA records"
            );
            Ok(merge_exchanges(None, Some(aaaa)))
        }
    }
}

/// One plain UDP DNS exchange: fresh ephemeral socket, send, await a reply.
///
/// Datagrams whose first two bytes do not match the sent transaction id are
/// stray or late replies (spoofing noise, delayed answers to a previously
/// reused port) and are skipped; the loop simply waits for a match. The
/// outer [`PLAIN_DNS_TIMEOUT`] bounds this loop.
async fn udp_exchange(server: SocketAddr, query: &DnsQuery) -> Result<Vec<u8>, DnsServerError> {
    // A fresh socket per exchange: no port reuse across queries, so a reply
    // to an old port cannot be attributed to this query.
    let bind_addr = if server.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| DnsServerError::PlainDns(format!("bind ephemeral socket: {e}")))?;
    socket
        .send_to(&query.bytes, server)
        .await
        .map_err(|e| DnsServerError::PlainDns(format!("send DNS query: {e}")))?;

    let mut buf = vec![0u8; MAX_DNS_RESPONSE_BYTES];
    loop {
        let (n, _source) = socket
            .recv_from(&mut buf)
            .await
            .map_err(|e| DnsServerError::PlainDns(format!("receive DNS response: {e}")))?;
        if n < 2 || u16::from_be_bytes([buf[0], buf[1]]) != query.id {
            debug!(server = %server, "skipping datagram with a foreign transaction id");
            continue;
        }
        return Ok(buf[..n].to_vec());
    }
}

/// Parse one plain-DNS response, retrying over TCP when the UDP reply
/// carries the TC (truncation) bit.
///
/// A TC reply is not an answer, only a pointer to one: the message was cut
/// short at the UDP size limit. The same query is retried over TCP, where
/// the u16 length prefix removes any size pressure; the TCP reply is parsed
/// the same way. Errors keep [`parse_response`]'s messages but surface as
/// [`DnsServerError::PlainDns`] — the exchange was not a DoH exchange.
async fn parse_plain(
    server: SocketAddr,
    query: &DnsQuery,
    body: &[u8],
) -> Result<ExchangeResult, DnsServerError> {
    // A body that does not even decode falls through to `parse_response`,
    // which produces the canonical decode error; here only the TC bit
    // matters.
    let truncated = Message::from_vec(body)
        .map(|message| message.metadata.truncation)
        .unwrap_or(false);
    if truncated {
        debug!(server = %server, id = query.id, "UDP response truncated (TC); retrying over TCP");
        let tcp_body = tcp_exchange(server, query).await?;
        return parse_response(query.id, &tcp_body).map_err(plain_error);
    }
    parse_response(query.id, body).map_err(plain_error)
}

/// One plain TCP DNS exchange: connect, write the query behind a u16
/// big-endian length prefix, read a u16 length then exactly that many
/// response bytes.
async fn tcp_exchange(server: SocketAddr, query: &DnsQuery) -> Result<Vec<u8>, DnsServerError> {
    let mut stream = TcpStream::connect(server)
        .await
        .map_err(|e| DnsServerError::PlainDns(format!("tcp connect {server}: {e}")))?;

    let prefix = u16::try_from(query.bytes.len()).map_err(|_| {
        DnsServerError::PlainDns("query exceeds the u16 TCP length prefix".to_string())
    })?;
    let mut wire = Vec::with_capacity(query.bytes.len() + 2);
    wire.extend_from_slice(&prefix.to_be_bytes());
    wire.extend_from_slice(&query.bytes);
    stream
        .write_all(&wire)
        .await
        .map_err(|e| DnsServerError::PlainDns(format!("write TCP DNS query: {e}")))?;

    let mut length = [0u8; 2];
    stream
        .read_exact(&mut length)
        .await
        .map_err(|e| DnsServerError::PlainDns(format!("read TCP response length: {e}")))?;
    let length = usize::from(u16::from_be_bytes(length));
    if length > MAX_DNS_RESPONSE_BYTES {
        return Err(DnsServerError::PlainDns(format!(
            "DNS response of {length} bytes exceeds the {MAX_DNS_RESPONSE_BYTES} byte limit"
        )));
    }
    let mut body = vec![0u8; length];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|e| DnsServerError::PlainDns(format!("read TCP response: {e}")))?;
    Ok(body)
}

/// Map a shared doh_client error onto its plain-DNS twin, keeping the
/// message text: an exchange failure here is not a DoH failure.
fn plain_error(error: DnsServerError) -> DnsServerError {
    match error {
        DnsServerError::DohExchange(text) => DnsServerError::PlainDns(text),
        other => other,
    }
}

/// Resolve a hostname through the operating-system resolver.
///
/// This deliberately leaves the Tor tunnel: the OS resolver queries the
/// network's configured nameservers directly — the operator opted this host
/// mask into exactly that leak.
///
/// The resolver is built per call from the system configuration
/// (`TokioResolver::builder_tokio`): per-call construction re-reads the OS
/// configuration (`/etc/resolv.conf` / the Windows registry), which is the
/// correct behavior across network changes; the DNS-07 listener may hold a
/// long-lived resolver instead. The whole lookup is bounded by
/// [`SYSTEM_RESOLVER_TIMEOUT`]; on expiry [`DnsServerError::Timeout`] is
/// returned.
///
/// # Cancel-safety
/// cancel-safe: yes — stateless: dropping the future mid-lookup drops the
/// per-call resolver and its background tasks.
pub async fn resolve_via_system(hostname: &str) -> Result<ResolvedAnswer, DnsServerError> {
    tokio::time::timeout(SYSTEM_RESOLVER_TIMEOUT, system_lookup(hostname))
        .await
        .map_err(|_| DnsServerError::Timeout(SYSTEM_RESOLVER_TIMEOUT))?
}

/// One system-resolver attempt: concurrent A and AAAA lookups, merged
/// leniently (only both-fail fails — same semantics as the DoH path).
async fn system_lookup(hostname: &str) -> Result<ResolvedAnswer, DnsServerError> {
    let resolver = TokioResolver::builder_tokio()
        .and_then(|builder| builder.build())
        .map_err(|e| DnsServerError::SystemResolver(format!("build system resolver: {e}")))?;

    // `join!`, not `try_join!`: hickory fuses transport and DNS-level
    // failures into ONE error per lookup, so the lenient merge below needs
    // BOTH outcomes when only one half fails. (In doh_client the
    // `try_join!` shape works because transport failures fail the attempt
    // before any parsing; here there is no such split to exploit.)
    let (a, aaaa) = tokio::join!(
        system_lookup_half(&resolver, hostname, RecordType::A),
        system_lookup_half(&resolver, hostname, RecordType::AAAA),
    );

    match (a, aaaa) {
        (Err(first), Err(_)) => Err(first),
        (Ok(a), Ok(aaaa)) => Ok(answer_from_lookups(Some(a), Some(aaaa))),
        (Ok(a), Err(error)) => {
            debug!(
                hostname = %hostname,
                error = %error,
                "system AAAA lookup failed; keeping A records"
            );
            Ok(answer_from_lookups(Some(a), None))
        }
        (Err(error), Ok(aaaa)) => {
            debug!(
                hostname = %hostname,
                error = %error,
                "system A lookup failed; keeping AAAA records"
            );
            Ok(answer_from_lookups(None, Some(aaaa)))
        }
    }
}

/// One half of the system lookup: `hostname` at one record type, with the
/// error carrying the hostname and record type for context.
async fn system_lookup_half(
    resolver: &TokioResolver,
    hostname: &str,
    record_type: RecordType,
) -> Result<Lookup, DnsServerError> {
    resolver.lookup(hostname, record_type).await.map_err(|e| {
        DnsServerError::SystemResolver(format!("lookup {record_type} for {hostname:?}: {e}"))
    })
}

/// Assemble the answer from the OS resolver's A and AAAA lookups with the
/// same semantics as [`crate::doh_client::merge_exchanges`]: addresses in
/// wire order, A half first; the TTL is the minimum over ALL answer records
/// of both halves; when neither half carries ANY answer record, the TTL is
/// [`Duration::ZERO`] = "no TTL information reported".
fn answer_from_lookups(a: Option<Lookup>, aaaa: Option<Lookup>) -> ResolvedAnswer {
    let mut addrs = Vec::new();
    let mut min_ttl: Option<Duration> = None;
    for lookup in [a, aaaa].into_iter().flatten() {
        for record in lookup.answers() {
            // `Record` exposes its ttl/data as public fields (the ttl()/data()
            // accessor methods belong to RecordRef in hickory-proto 0.26).
            let ttl = Duration::from_secs(u64::from(record.ttl));
            min_ttl = Some(match min_ttl {
                Some(current) => current.min(ttl),
                None => ttl,
            });
            match &record.data {
                RData::A(a) => addrs.push(IpAddr::V4(a.0)),
                RData::AAAA(aaaa) => addrs.push(IpAddr::V6(aaaa.0)),
                // CNAME/SOA/etc: no address of their own, but the TTL taken
                // above still bounds how long the whole answer chain may be
                // cached (same convention as doh_client::parse_response).
                _ => {}
            }
        }
    }
    ResolvedAnswer {
        addrs,
        ttl: min_ttl.unwrap_or(Duration::ZERO),
        resolved_at: OffsetDateTime::now_utc(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use hickory_proto::op::{MessageType, OpCode, ResponseCode};
    use hickory_proto::rr::rdata::{A, AAAA, CNAME};
    use hickory_proto::rr::{Name, RData, Record};

    use super::*;

    fn test_name() -> Name {
        "example.com".parse().expect("valid test name")
    }

    fn test_query(record_type: RecordType) -> DnsQuery {
        build_query("example.com", record_type).expect("query builds")
    }

    fn test_response(id: u16) -> Message {
        Message::new(id, MessageType::Response, OpCode::Query)
    }

    /// A synthetic A response for the query `query`, carrying one record.
    fn a_response_bytes(query: &DnsQuery, ttl: u32, ip: Ipv4Addr) -> Vec<u8> {
        let owner = test_name();
        let mut message = test_response(query.id);
        message.add_query(hickory_proto::op::Query::query(
            owner.clone(),
            RecordType::A,
        ));
        message.add_answer(Record::from_rdata(owner, ttl, RData::A(A(ip))));
        message.to_vec().expect("response encodes")
    }

    /// A synthetic AAAA response for the query `query`, carrying one record.
    fn aaaa_response_bytes(query: &DnsQuery, ttl: u32, ip: Ipv6Addr) -> Vec<u8> {
        let owner = test_name();
        let mut message = test_response(query.id);
        message.add_query(hickory_proto::op::Query::query(
            owner.clone(),
            RecordType::AAAA,
        ));
        message.add_answer(Record::from_rdata(owner, ttl, RData::AAAA(AAAA(ip))));
        message.to_vec().expect("response encodes")
    }

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

    #[tokio::test]
    async fn plain_parse_and_merge_collects_both_families() {
        let server: SocketAddr = "192.0.2.53:53".parse().expect("test addr parses");
        let a_query = test_query(RecordType::A);
        let aaaa_query = test_query(RecordType::AAAA);

        let a_result = parse_plain(
            server,
            &a_query,
            &a_response_bytes(&a_query, 120, Ipv4Addr::new(192, 0, 2, 7)),
        )
        .await;
        let aaaa_result = parse_plain(
            server,
            &aaaa_query,
            &aaaa_response_bytes(
                &aaaa_query,
                45,
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            ),
        )
        .await;

        let answer = merge_lenient(server, a_result, aaaa_result).expect("both halves parse");
        // A addresses first, then AAAA (merge_exchanges convention).
        assert_eq!(
            answer.addrs,
            vec![
                IpAddr::from([192, 0, 2, 7]),
                IpAddr::from([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]),
            ]
        );
        assert_eq!(answer.ttl, Duration::from_secs(45), "minimum TTL wins");
    }

    #[tokio::test]
    async fn plain_parse_lenient_merge_keeps_surviving_half() {
        let server: SocketAddr = "192.0.2.53:53".parse().expect("test addr parses");
        let a_query = test_query(RecordType::A);
        let aaaa_query = test_query(RecordType::AAAA);

        let a_result = parse_plain(
            server,
            &a_query,
            &a_response_bytes(&a_query, 90, Ipv4Addr::new(192, 0, 2, 1)),
        )
        .await;
        // The AAAA half fails (id mismatch); the A half must still be kept.
        let foreign_id = aaaa_query.id ^ 0x5555;
        let aaaa_result = parse_plain(
            server,
            &aaaa_query,
            &test_response(foreign_id)
                .to_vec()
                .expect("response encodes"),
        )
        .await;

        let answer = merge_lenient(server, a_result, aaaa_result).expect("one half survives");
        assert_eq!(answer.addrs, vec![IpAddr::from([192, 0, 2, 1])]);
        assert_eq!(answer.ttl, Duration::from_secs(90));
    }

    #[tokio::test]
    async fn plain_parse_lenient_merge_fails_with_first_error_when_both_fail() {
        let server: SocketAddr = "192.0.2.53:53".parse().expect("test addr parses");
        let a_query = test_query(RecordType::A);
        let aaaa_query = test_query(RecordType::AAAA);

        let foreign_id = a_query.id ^ 0x5555;
        let a_result = parse_plain(
            server,
            &a_query,
            &test_response(foreign_id)
                .to_vec()
                .expect("response encodes"),
        )
        .await;
        let aaaa_result = parse_plain(
            server,
            &aaaa_query,
            &test_response(aaaa_query.id ^ 0xAAAA)
                .to_vec()
                .expect("response encodes"),
        )
        .await;

        let error = merge_lenient(server, a_result, aaaa_result).expect_err("both halves failed");
        assert!(matches!(error, DnsServerError::PlainDns(_)), "{error:?}");
    }

    #[tokio::test]
    async fn plain_parse_id_mismatch_is_plain_dns_error() {
        let server: SocketAddr = "192.0.2.53:53".parse().expect("test addr parses");
        let query = test_query(RecordType::A);
        let foreign_id = query.id ^ 0x5555;
        let bytes = test_response(foreign_id)
            .to_vec()
            .expect("response encodes");

        let error = parse_plain(server, &query, &bytes)
            .await
            .expect_err("id mismatch must fail");
        assert!(
            matches!(error, DnsServerError::PlainDns(ref text) if text.contains("transaction id mismatch")),
            "error should stay PlainDns with the original text: {error:?}"
        );
    }

    #[tokio::test]
    async fn plain_parse_nxdomain_is_plain_dns_error() {
        let server: SocketAddr = "192.0.2.53:53".parse().expect("test addr parses");
        let query = test_query(RecordType::A);
        let mut message = test_response(query.id);
        message.metadata.response_code = ResponseCode::NXDomain;
        let bytes = message.to_vec().expect("response encodes");

        let error = parse_plain(server, &query, &bytes)
            .await
            .expect_err("NXDomain must fail");
        assert!(
            matches!(error, DnsServerError::PlainDns(ref text) if text.contains("Non-Existent")),
            "error should stay PlainDns with the rcode text: {error:?}"
        );
    }

    #[test]
    fn truncated_flag_is_detected_on_the_wire() {
        // Detection-level test for the TC path: the flag survives
        // serialization and is visible where parse_plain looks for it.
        let mut message = test_response(0x1234);
        message.metadata.truncation = true;
        let bytes = message.to_vec().expect("response encodes");

        let decoded = Message::from_vec(&bytes).expect("response decodes");
        assert!(decoded.metadata.truncation, "TC bit must survive the wire");
        let clean = test_response(0x4321).to_vec().expect("response encodes");
        assert!(
            !Message::from_vec(&clean)
                .expect("decodes")
                .metadata
                .truncation,
            "a normal response must not be seen as truncated"
        );
    }

    fn lookup_with(records: Vec<Record>) -> Lookup {
        let query = hickory_proto::op::Query::query(test_name(), RecordType::A);
        Lookup::new_with_max_ttl(query, records)
    }

    #[test]
    fn answer_from_lookups_orders_a_then_aaaa_and_takes_min_ttl() {
        let name = test_name();
        let a_lookup = lookup_with(vec![
            // The CNAME contributes no address but its smaller TTL bounds
            // the whole answer chain (parse_response convention).
            Record::from_rdata(name.clone(), 30, RData::CNAME(CNAME(name.clone()))),
            Record::from_rdata(name.clone(), 90, RData::A(A(Ipv4Addr::new(192, 0, 2, 1)))),
        ]);
        let aaaa_query = hickory_proto::op::Query::query(name.clone(), RecordType::AAAA);
        let aaaa_lookup = Lookup::from_rdata(
            aaaa_query,
            RData::AAAA(AAAA(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2))),
        );

        let answer = answer_from_lookups(Some(a_lookup), Some(aaaa_lookup));
        // A addresses first, then AAAA.
        assert_eq!(
            answer.addrs,
            vec![
                IpAddr::from([192, 0, 2, 1]),
                IpAddr::from([0x2001, 0xdb8, 0, 0, 0, 0, 0, 2]),
            ]
        );
        assert_eq!(
            answer.ttl,
            Duration::from_secs(30),
            "minimum TTL across BOTH lookups"
        );
    }

    #[test]
    fn answer_from_lookups_all_nodata_is_zero_ttl() {
        let answer =
            answer_from_lookups(Some(lookup_with(Vec::new())), Some(lookup_with(Vec::new())));
        assert!(answer.addrs.is_empty());
        assert_eq!(
            answer.ttl,
            Duration::ZERO,
            "no answer records => no TTL information"
        );
    }
}
