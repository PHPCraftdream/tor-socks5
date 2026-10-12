//! Shared value types used across the cache, DoH client, provider pool,
//! and listener.

use std::net::IpAddr;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use time::OffsetDateTime;

/// One resolved answer, ready to be cached and served to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAnswer {
    /// Complete upstream packet, including non-address records and negative rcodes.
    pub message: Message,
    /// Lifetime of this packet from `resolved_at` (remaining lifetime on a cache hit).
    pub ttl: Duration,
    /// Epoch for this packet's TTLs (UTC); reception time for upstream packets,
    /// age-adjustment time for cached copies. Persistence retains the original epoch.
    pub resolved_at: OffsetDateTime,
}

/// Cache policy shared by all transports. Failure rcodes, referrals, empty
/// unproved negatives and truncated packets are not cacheable.
///
/// RFC 2308 §§2, 3, 5: follow CNAMEs to the terminal name; a negative needs
/// a covering, same-class SOA and uses min(SOA TTL, SOA.MINIMUM).
/// Whole-packet caching conservatively expires at the shortest ordinary RR TTL
/// so no retained authority/additional record is served past its lifetime.
pub(crate) fn cache_ttl(query: &Query, message: &Message) -> Option<Duration> {
    if message.metadata.message_type != MessageType::Response
        || message.metadata.op_code != OpCode::Query
        || message.metadata.truncation
        || message.signature.is_some()
        || message.queries.len() != 1
        || !message.queries[0].name().eq_ignore_root(query.name())
        || message.queries[0].query_type() != query.query_type()
        || message.queries[0].query_class() != query.query_class()
    {
        return None;
    }
    let rcode = message.metadata.response_code;
    if rcode != ResponseCode::NoError && rcode != ResponseCode::NXDomain {
        return None;
    }
    let (terminal, positive) = terminal_answer(query, &message.answers)?;
    // NXDOMAIN with a terminal positive RR is contradictory, not a success.
    if positive && rcode == ResponseCode::NXDomain {
        return None;
    }
    let negative_ttl = if !positive {
        Some(
            message
                .authorities
                .iter()
                .filter_map(|record| {
                    if record.dns_class == query.query_class() && record.name.zone_of(terminal) {
                        if let RData::SOA(soa) = &record.data {
                            return Some(record.ttl.min(soa.minimum));
                        }
                    }
                    None
                })
                .min()?,
        )
    } else {
        None
    };
    let ordinary_ttl = message
        .answers
        .iter()
        .chain(&message.authorities)
        .chain(&message.additionals)
        .filter(|record| record.record_type() != RecordType::OPT)
        .map(|record| record.ttl)
        .min()?;
    let ttl = negative_ttl.map_or(ordinary_ttl, |negative| negative.min(ordinary_ttl));
    (ttl != 0).then(|| Duration::from_secs(u64::from(ttl)))
}

/// RFC 2308 §3: normalize the covering negative SOA on the first response,
/// independently of cache admission or a shorter whole-packet cache lifetime.
/// Preserve every record and header flag; only relevant SOA TTLs are changed.
pub(crate) fn normalize_negative_soa_ttl(query: &Query, message: &mut Message) {
    if message.metadata.truncation
        || message.signature.is_some()
        || !matches!(
            message.metadata.response_code,
            ResponseCode::NoError | ResponseCode::NXDomain
        )
    {
        return;
    }
    // The helper borrows only answers (or query), leaving authorities available
    // for a disjoint mutable borrow; no cloned terminal name is needed.
    let Some((terminal, false)) = terminal_answer(query, &message.answers) else {
        return;
    };
    for record in &mut message.authorities {
        if record.dns_class == query.query_class() && record.name.zone_of(terminal) {
            if let RData::SOA(soa) = &record.data {
                record.ttl = record.ttl.min(soa.minimum);
            }
        }
    }
}

/// Borrow the terminal name and whether the requested RR exists there.
/// A terminating chain traverses at most `answers.len()` CNAME records. If
/// another hop is needed after that bound, the deterministic chain cycles.
/// This allocates nothing, including for the ordinary direct-positive path.
fn terminal_answer<'a>(query: &'a Query, answers: &'a [Record]) -> Option<(&'a Name, bool)> {
    let mut terminal = query.name();
    for _ in 0..=answers.len() {
        if answers.iter().any(|record| {
            record.name.eq_ignore_root(terminal)
                && record.dns_class == query.query_class()
                && (record.record_type() == query.query_type()
                    || (query.query_type() == RecordType::ANY
                        && record.record_type() != RecordType::OPT))
        }) {
            return Some((terminal, true));
        }
        let alias = answers.iter().find_map(|record| {
            if record.name.eq_ignore_root(terminal) && record.dns_class == query.query_class() {
                if let RData::CNAME(target) = &record.data {
                    return Some(&target.0);
                }
            }
            None
        });
        match alias {
            Some(target) => terminal = target,
            None => return Some((terminal, false)),
        }
    }
    None
}

/// One DoH provider: TCP address to reach through Tor, hostname for
/// SNI/HTTP Host, DoH endpoint path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DohProvider {
    /// IP address to open the TCP connection to (through Tor — the name is
    /// never resolved locally).
    pub ip: IpAddr,
    /// Hostname used for TLS SNI and the HTTP Host header.
    pub hostname: String,
    /// Path of the DoH endpoint (e.g. `/dns-query`).
    pub path: String,
}
