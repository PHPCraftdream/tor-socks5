use crate::dns::*;
use crate::probe::dns_invalidation::*;
use crate::probe::*;
use crate::*;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn serial() -> (
    tokio::sync::MutexGuard<'static, ()>,
    tokio::sync::MutexGuard<'static, ()>,
) {
    let wave = super::probe_coalesce_tests::FAKE_WAVE_LOCK.lock().await;
    let store = super::DNS_GLOBAL_STORE_LOCK.lock().await;
    (wave, store)
}

fn ip(value: &str) -> IpAddr {
    value.parse().expect("test IP parses")
}

#[tokio::test]
async fn old_generation_failure_cannot_remove_fresh_answer() {
    let _serial = serial().await;
    let host = "dns-invalidate-generation.test.invalid";
    forget_dns_answer(host);
    remember_doh_answer(host, &[ip("203.0.113.10")], Duration::from_secs(300));
    let old = cached_doh_answer_observed(host).unwrap().1;

    flush_dns_cache();
    remember_doh_answer(host, &[ip("203.0.113.11")], Duration::from_secs(300));
    assert!(!invalidate_if_current(host, old, &[ip("203.0.113.10")]));
    match cached_doh_answer(host) {
        Some(CacheHit::Addrs(addrs)) => assert_eq!(addrs, vec![ip("203.0.113.11")]),
        _ => panic!("fresh-generation answer must remain cached"),
    }
    forget_dns_answer(host);
}

#[tokio::test]
async fn same_generation_replacement_cannot_be_removed_by_old_probe() {
    let _serial = serial().await;
    let host = "dns-invalidate-version.test.invalid";
    forget_dns_answer(host);
    let first = [ip("203.0.113.20")];
    let second = [ip("203.0.113.20")];
    remember_doh_answer(host, &first, Duration::from_secs(300));
    let old = cached_doh_answer_observed(host).unwrap().1;
    remember_doh_answer(host, &second, Duration::from_secs(300));

    assert!(!invalidate_if_current(host, old, &first));
    match cached_doh_answer(host) {
        Some(CacheHit::Addrs(addrs)) => assert_eq!(addrs, second),
        _ => panic!("same-generation replacement must remain cached"),
    }
    forget_dns_answer(host);
}

#[tokio::test]
async fn only_all_observed_failed_ips_invalidate_the_matching_entry() {
    let _serial = serial().await;
    let host = "dns-invalidate-addresses.test.invalid";
    forget_dns_answer(host);
    let addrs = [ip("203.0.113.30"), ip("203.0.113.31")];
    remember_doh_answer(host, &addrs, Duration::from_secs(300));
    let identity = cached_doh_answer_observed(host).unwrap().1;

    assert!(!invalidate_if_current(host, identity, &addrs[..1]));
    assert!(invalidate_if_current(host, identity, &addrs));
    assert!(cached_doh_answer(host).is_none());
}

#[tokio::test]
async fn protocol_failure_does_not_invalidate_dns_answer() {
    let _serial = serial().await;
    let host = "dns-invalidate-protocol.test.invalid";
    forget_dns_answer(host);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(stream.read_u8().await.unwrap());
        }
        stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
    });
    let resolved_ip = address.ip();
    let expected_host = host.to_owned();
    install_fake_doh_wave_search(Arc::new(move |query: &str| {
        assert_eq!(query, expected_host);
        Box::pin(async move { Some((vec![resolved_ip], Duration::from_secs(300))) })
            as std::pin::Pin<
                Box<dyn std::future::Future<Output = Option<(Vec<IpAddr>, Duration)>> + Send>,
            >
    }));
    let bridge: bridge_line::BridgeLine = format!(
        "webtunnel 192.0.2.1:443 1111111111111111111111111111111111111111 url=http://{host}:{}/x",
        address.port()
    )
    .parse()
    .unwrap();
    let outcome =
        resolve_and_probe(&bridge, Duration::from_secs(2), ResolverPolicy::default()).await;
    server.await.unwrap();
    assert!(matches!(outcome, Outcome::Unreachable { reason } if reason.contains("404")));
    assert!(
        matches!(cached_doh_answer(host), Some(CacheHit::Addrs(_))),
        "HTTP failure is protocol-level and must keep the DNS answer"
    );
    clear_fake_doh_wave_search();
    forget_dns_answer(host);
}
