//! Local policy runs before cache, overrides, tunnel acquisition or admission.
use crate::types::ResolvedAnswer;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::{A, AAAA, PTR};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use time::OffsetDateTime;

use tokio::net::UdpSocket;
use tokio::time::timeout;

// One inline probe at a time per UDP listener, never a queued task. TCP probes
// are bounded by connection admission. No DNS payload or interface enumeration.
const LOCAL_PROBE_TIMEOUT: Duration = Duration::from_millis(100);

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}

/// cancel-safe: yes — bind/connect own only a temporary UDP socket; dropping
/// either future or the timeout closes it. connect selects a route, sends no data.
async fn route_source(ip: IpAddr) -> Option<IpAddr> {
    let bind = match ip {
        IpAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        IpAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    };
    let socket = UdpSocket::bind(bind).await.ok()?;
    socket.connect(SocketAddr::new(ip, 9)).await.ok()?;
    Some(socket.local_addr().ok()?.ip())
}

/// cancel-safe: yes — local results are synchronous; the only child probe is
/// owned and bounded, and has no payload or persistent side effects.
pub(super) type RouteProbe = std::sync::Arc<
    dyn Fn(IpAddr) -> futures::future::BoxFuture<'static, Option<IpAddr>> + Send + Sync,
>;

pub(super) fn route_probe() -> RouteProbe {
    std::sync::Arc::new(|ip| Box::pin(route_source(ip)))
}

pub(super) async fn preflight_with_probe<P, F>(
    question: &Query,
    host: &str,
    endpoints: &[SocketAddr],
    explicit_override: bool,
    probe: P,
) -> Option<ResolvedAnswer>
where
    P: FnOnce(IpAddr) -> F,
    F: std::future::Future<Output = Option<IpAddr>>,
{
    if let Some(answer) = answer(question, host, endpoints, explicit_override) {
        return Some(answer);
    }
    if explicit_override || question.query_type() != RecordType::PTR {
        return None;
    }
    let ip = canonical(reverse_ip(host)?);
    if ip.is_unspecified()
        || ip.is_loopback()
        || !endpoints.iter().any(|endpoint| {
            // Do not assume that an IPv6 wildcard is dual-stack: that depends on
            // the OS/socket configuration. Mapped addresses use IPv4 coverage.
            endpoint.ip().is_unspecified() && endpoint.ip().is_ipv4() == ip.is_ipv4()
        })
    {
        return None;
    }
    let source = timeout(LOCAL_PROBE_TIMEOUT, probe(ip))
        .await
        .ok()
        .flatten()?;
    if canonical(source) != ip {
        return None;
    }
    nodata(question)
}

fn nodata(question: &Query) -> Option<ResolvedAnswer> {
    let mut message = Message::new(0, MessageType::Response, OpCode::Query);
    message.add_query(question.clone());
    Some(ResolvedAnswer {
        message,
        ttl: Duration::from_secs(60),
        resolved_at: OffsetDateTime::now_utc(),
    })
}

pub(super) fn answer(
    question: &Query,
    host: &str,
    endpoints: &[SocketAddr],
    explicit_override: bool,
) -> Option<ResolvedAnswer> {
    let localhost = host == "localhost" || host.ends_with(".localhost");
    let reverse = reverse_ip(host).map(canonical);
    let loopback = reverse.is_some_and(|ip| ip.is_loopback());
    let own = question.query_type() == RecordType::PTR
        && reverse.is_some_and(|ip| {
            !ip.is_unspecified()
                && endpoints
                    .iter()
                    .any(|endpoint| canonical(endpoint.ip()) == ip)
        });
    if !localhost && !loopback && (!own || explicit_override) {
        return None;
    }
    let mut message = Message::new(0, MessageType::Response, OpCode::Query);
    message.add_query(question.clone());
    // RFC 6761 §6.3: localhost names are local; unsupported types are NODATA.
    // RFC 6303 §4: loopback reverse zones are locally served. Project policy
    // returns localhost PTR, while own non-loopback addresses return NODATA.
    if question.query_class() == DNSClass::IN {
        let data = match question.query_type() {
            RecordType::A if localhost => Some(RData::A(A(Ipv4Addr::LOCALHOST))),
            RecordType::AAAA if localhost => Some(RData::AAAA(AAAA(Ipv6Addr::LOCALHOST))),
            RecordType::PTR if loopback => {
                Some(RData::PTR(PTR(Name::from_ascii("localhost.").ok()?)))
            }
            _ => None,
        };
        if let Some(data) = data {
            message.add_answer(Record::from_rdata(question.name().clone(), 60, data));
        }
    }
    Some(ResolvedAnswer {
        message,
        ttl: Duration::from_secs(60),
        resolved_at: OffsetDateTime::now_utc(),
    })
}

fn reverse_ip(host: &str) -> Option<IpAddr> {
    if let Some(body) = host.strip_suffix(".in-addr.arpa") {
        let mut labels = body.rsplit('.');
        let mut octets = [0u8; 4];
        for octet in &mut octets {
            *octet = labels.next()?.parse().ok()?;
        }
        if labels.next().is_some() {
            return None;
        }
        return Some(IpAddr::V4(Ipv4Addr::from(octets)));
    }
    let body = host.strip_suffix(".ip6.arpa")?;
    let mut labels = body.rsplit('.');
    let mut value = 0u128;
    for _ in 0..32 {
        let label = labels.next()?;
        if label.len() != 1 {
            return None;
        }
        let digit = label.chars().next()?.to_digit(16)?;
        value = (value << 4) | u128::from(digit);
    }
    if labels.next().is_some() {
        return None;
    }
    // Only ::1 is covered, not all IPv6 addresses/private reverse zones.
    Some(IpAddr::V6(Ipv6Addr::from(value)))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Counterfactual: treating any route as local suppresses remote/private PTR;
    // ignoring family coverage probes IPv4 through an IPv6-only wildcard.
    #[tokio::test]
    async fn wildcard_ptr_probe_requires_local_source_and_matching_family() {
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 8));
        let v6: IpAddr = "2001:db8::8".parse().unwrap();
        let mapped: IpAddr = "::ffff:192.0.2.8".parse().unwrap();
        for (ip, endpoint, source, expected, calls) in [
            (v4, "0.0.0.0:53", Some(v4), true, 1),
            (
                v4,
                "0.0.0.0:53",
                Some("192.0.2.9".parse().unwrap()),
                false,
                1,
            ),
            (v4, "[::]:53", Some(v4), false, 0),
            (v6, "[::]:53", Some(v6), true, 1),
            (v6, "0.0.0.0:53", Some(v6), false, 0),
            (v6, "[::]:53", None, false, 1),
            (mapped, "0.0.0.0:53", Some(v4), true, 1),
            (mapped, "[::]:53", Some(v4), false, 0),
        ] {
            let host = match ip {
                IpAddr::V4(ip) => {
                    ip.octets()
                        .iter()
                        .rev()
                        .map(u8::to_string)
                        .collect::<Vec<_>>()
                        .join(".")
                        + ".in-addr.arpa"
                }
                IpAddr::V6(ip) => {
                    format!("{:032x}", u128::from(ip))
                        .chars()
                        .rev()
                        .map(|c| c.to_string())
                        .collect::<Vec<_>>()
                        .join(".")
                        + ".ip6.arpa"
                }
            };
            let q = Query::query(Name::from_ascii(&host).unwrap(), RecordType::PTR);
            let host = host.as_str();
            let count = std::cell::Cell::new(0);
            let result =
                preflight_with_probe(&q, host, &[endpoint.parse().unwrap()], false, |target| {
                    count.set(count.get() + 1);
                    assert_eq!(target, canonical(ip));
                    std::future::ready(source)
                })
                .await;
            assert_eq!(result.is_some(), expected, "{ip} on {endpoint}");
            assert_eq!(count.get(), calls);
            if let Some(answer) = result {
                assert_eq!(
                    answer.message.metadata.response_code,
                    hickory_proto::op::ResponseCode::NoError
                );
                assert!(answer.message.answers.is_empty());
            }
        }
    }

    #[tokio::test]
    async fn fastpaths_and_override_never_probe() {
        let endpoints = [
            "0.0.0.0:53".parse().unwrap(),
            "192.0.2.8:53".parse().unwrap(),
        ];
        for (host, explicit, expected) in [
            ("localhost", true, true),
            ("1.0.0.127.in-addr.arpa", true, true),
            ("8.2.0.192.in-addr.arpa", false, true),
            ("9.2.0.192.in-addr.arpa", true, false),
        ] {
            let q = Query::query(Name::from_ascii(host).unwrap(), RecordType::PTR);
            let answer = preflight_with_probe(&q, host, &endpoints, explicit, |_| async {
                panic!("fastpath or override unexpectedly probed")
            })
            .await;
            assert_eq!(answer.is_some(), expected);
        }
    }

    // Counterfactual: removing the private probe deadline leaves this pending;
    // exact paused timing belongs here, not in the real-socket regression.
    #[tokio::test(start_paused = true)]
    async fn stalled_local_probe_is_bounded_and_falls_through() {
        let host = "8.2.0.192.in-addr.arpa";
        let q = Query::query(Name::from_ascii(host).unwrap(), RecordType::PTR);
        let start = tokio::time::Instant::now();
        let result = timeout(
            Duration::from_secs(1),
            preflight_with_probe(&q, host, &["0.0.0.0:53".parse().unwrap()], false, |_| {
                std::future::pending::<Option<IpAddr>>()
            }),
        )
        .await
        .expect("local probe lost its private deadline");
        assert!(result.is_none());
        assert_eq!(tokio::time::Instant::now() - start, LOCAL_PROBE_TIMEOUT);
    }

    #[test]
    fn reverse_parser_requires_exact_label_counts_and_valid_octets_nibbles() {
        assert_eq!(
            reverse_ip("9.8.7.127.in-addr.arpa"),
            Some(IpAddr::V4(Ipv4Addr::new(127, 7, 8, 9)))
        );
        for host in [
            "1.2.3.in-addr.arpa",
            "0.1.2.3.127.in-addr.arpa",
            "256.2.3.127.in-addr.arpa",
            "1..3.127.in-addr.arpa",
        ] {
            assert!(reverse_ip(host).is_none(), "invalid reverse name: {host}");
        }
        let valid = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa";
        assert_eq!(reverse_ip(valid), Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        for host in [
            valid.replacen("1.", "g.", 1),
            valid.replacen("1.", "11.", 1),
            valid.replacen("1.", "", 1),
            format!("0.{valid}"),
        ] {
            assert!(reverse_ip(&host).is_none(), "invalid reverse name: {host}");
        }
    }
}
