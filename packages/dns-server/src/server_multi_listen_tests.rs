//! Multi-address binding exercises the production binder and owned listener lifecycle.
use super::*;

/// cancel-safe: yes — scoped networking and clients drop together on the guard.
async fn answers_on_pairs(bound: BoundListeners, expected: &[SocketAddr]) {
    let context = ctx(vec![], bound.2.clone());
    let shutdown = CancellationToken::new();
    let serving = serve_owned_lifecycle(
        (bound.0, bound.1),
        context,
        None,
        shutdown.clone(),
        |_| std::future::ready(Ok(())),
        || {},
        || std::future::ready(Ok(())),
    );
    let clients = async {
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for addr in expected {
            let req = request("localhost.", RecordType::A, 602);
            let mut stream = TcpStream::connect(addr).await.unwrap();
            for reply in [
                udp_exchange(&client, *addr, &req).await,
                tcp_exchange(&mut stream, &req).await,
            ] {
                assert_eq!(reply.metadata.id, 602);
                assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
                assert_eq!(reply.queries, req.queries);
                assert_eq!(reply.answers.len(), 1);
                assert_eq!(
                    reply.answers[0].data,
                    RData::A(A("127.0.0.1".parse().unwrap()))
                );
            }
        }
        shutdown.cancel();
    };
    let (result, ()) = tokio::join!(serving, clients);
    result.unwrap();
}

// Counterfactual: retaining only the first pair makes the second UDP/TCP exchange fail.
#[tokio::test]
async fn two_pairs_both_protocols_answer_and_publish_actual_endpoints() {
    timeout(CASE_BUDGET, async {
        let bound = bind_listeners(&["127.0.0.1:0".into(), "127.0.0.1:0".into()])
            .await
            .unwrap();
        assert_eq!(bound.0.len(), 2);
        assert_eq!(bound.1.len(), 2);
        let addresses: Vec<_> = bound.0.iter().map(|s| s.local_addr().unwrap()).collect();
        assert_ne!(addresses[0], addresses[1]);
        let mut expected = Vec::new();
        for (udp, tcp) in bound.0.iter().zip(&bound.1) {
            let addr = udp.local_addr().unwrap();
            assert_ne!(addr.port(), 0);
            assert_eq!(tcp.local_addr().unwrap(), addr);
            expected.extend([addr, addr]);
        }
        assert_eq!(bound.2, expected);
        answers_on_pairs(bound, &addresses).await;
    })
    .await
    .expect("30-second multi-listen case guard");
}

// Reserve both protocols via bind_pair before releasing just the chosen half.
// This avoids Windows protocol-specific excluded ephemeral bands in fixtures.
// Counterfactual: fail-fast binding stops before the good pair; leaked UDP half
// from the TCP failure makes the immediate UDP rebind fail.
#[tokio::test]
async fn occupied_udp_and_tcp_skip_pairs_release_halves_and_remaining_serves() {
    timeout(CASE_BUDGET, async {
        let (occupied_udp, free_tcp) = bind_pair("127.0.0.1:0").await.unwrap();
        let udp_addr = occupied_udp.local_addr().unwrap();
        let (free_udp, occupied_tcp) = bind_pair("127.0.0.1:0").await.unwrap();
        let tcp_addr = occupied_tcp.local_addr().unwrap();
        drop(free_tcp);
        drop(free_udp);
        let bound = bind_listeners(&[
            udp_addr.to_string(),
            tcp_addr.to_string(),
            "127.0.0.1:0".into(),
        ])
        .await
        .unwrap();
        assert_eq!(bound.0.len(), 1);
        assert_eq!(bound.1.len(), 1);
        let serving_addr = bound.0[0].local_addr().unwrap();
        assert_eq!(bound.2, vec![serving_addr, serving_addr]);
        // Verify neither skipped pair retained its otherwise available half.
        let rebound_tcp = TcpListener::bind(udp_addr).await.unwrap();
        let rebound_udp = UdpSocket::bind(tcp_addr).await.unwrap();
        answers_on_pairs(bound, &[serving_addr]).await;
        drop((occupied_udp, occupied_tcp, rebound_tcp, rebound_udp));
        // Both whole pairs are reusable once the intentional holders are gone.
        let _udp_pair = bind_pair(&udp_addr.to_string()).await.unwrap();
        let _tcp_pair = bind_pair(&tcp_addr.to_string()).await.unwrap();
    })
    .await
    .expect("30-second occupied-pairs case guard");
}

// Counterfactual: silently running no listeners or reporting only the last error
// loses the all-address diagnosis. Exercise run before any persistence starts.
#[tokio::test]
async fn none_bound_run_reports_every_address_and_protocol_reason() {
    timeout(CASE_BUDGET, async {
        let (udp, tcp_half) = bind_pair("127.0.0.1:0").await.unwrap();
        let udp_addr = udp.local_addr().unwrap();
        let (udp_half, tcp) = bind_pair("127.0.0.1:0").await.unwrap();
        let tcp_addr = tcp.local_addr().unwrap();
        drop((tcp_half, udp_half));
        let error = run(
            &[udp_addr.to_string(), tcp_addr.to_string()],
            || std::future::ready(None),
            Arc::new(DnsCache::new()),
            vec![],
            vec![],
            PathBuf::new(),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
        let diagnostic = format!("{error:#}");
        assert!(
            diagnostic.starts_with("no DNS listener pairs could be bound:"),
            "{diagnostic}"
        );
        assert!(
            diagnostic.contains(&format!(
                "{udp_addr}: failed to bind UDP DNS listener on {udp_addr}"
            )),
            "{diagnostic}"
        );
        assert!(
            diagnostic.contains(&format!(
                "{tcp_addr}: failed to bind TCP DNS listener on {tcp_addr}"
            )),
            "{diagnostic}"
        );
        // OS strings vary; compare to fresh errors from the same held sockets.
        for addr in [udp_addr, tcp_addr] {
            let original = bind_pair(&addr.to_string()).await.unwrap_err();
            assert!(
                diagnostic.contains(&original.root_cause().to_string()),
                "{diagnostic}"
            );
            let reason = original.downcast_ref::<std::io::Error>().unwrap();
            assert!(
                diagnostic.contains(&format!("{addr}: {original:#} (kind: {:?})", reason.kind())),
                "missing per-address ErrorKind: {diagnostic}"
            );
        }
        let _tcp_half = TcpListener::bind(udp_addr).await.unwrap();
        let _udp_half = UdpSocket::bind(tcp_addr).await.unwrap();
        drop((udp, tcp));
    })
    .await
    .expect("30-second none-bound case guard");
}

#[test]
fn skipped_reasons_allow_only_three_bind_kinds_and_preserve_os_reason() {
    use std::io::{Error, ErrorKind};
    for protocol in ["UDP", "TCP"] {
        for kind in [
            ErrorKind::AddrInUse,
            ErrorKind::PermissionDenied,
            ErrorKind::AddrNotAvailable,
        ] {
            let error = anyhow::Error::new(Error::new(kind, "OS reason sentinel")).context(
                format!("failed to bind {protocol} DNS listener on 127.0.0.1:53"),
            );
            let (actual_protocol, reason) = skipped_bind_reason(&error).unwrap();
            assert_eq!(actual_protocol, protocol);
            assert_eq!(reason.kind(), kind);
            assert_eq!(reason.to_string(), "OS reason sentinel");
        }
        for kind in [
            ErrorKind::InvalidInput,
            ErrorKind::InvalidData,
            ErrorKind::Other,
            ErrorKind::Interrupted,
            ErrorKind::Unsupported,
        ] {
            let error = anyhow::Error::new(Error::new(kind, "hard reason"))
                .context(format!("failed to bind {protocol} DNS listener on invalid"));
            assert!(skipped_bind_reason(&error).is_none());
            assert_eq!(
                error.to_string(),
                format!("failed to bind {protocol} DNS listener on invalid")
            );
        }
    }
    let getter_error = anyhow::Error::new(Error::from(ErrorKind::PermissionDenied))
        .context("failed to read DNS listener IPV6_V6ONLY on [::]:53");
    assert!(skipped_bind_reason(&getter_error).is_none());
    assert!(skipped_bind_reason(&anyhow::anyhow!("invalid address")).is_none());
}

#[tokio::test]
async fn empty_and_invalid_addresses_keep_hard_prior_wording() {
    timeout(CASE_BUDGET, async {
        assert_eq!(
            bind_listeners(&[]).await.unwrap_err().to_string(),
            "no listen addresses configured for the DNS server"
        );
        let original = bind_pair("not an address").await.unwrap_err();
        let actual = bind_listeners(&["127.0.0.1:0".into(), "not an address".into()])
            .await
            .unwrap_err();
        assert_eq!(format!("{actual:#}"), format!("{original:#}"));
    })
    .await
    .expect("30-second hard-errors case guard");
}

#[tokio::test]
async fn fixed_port_tcp_failure_is_immediate_and_udp_half_is_released() {
    timeout(CASE_BUDGET, async {
        let (udp, tcp) = bind_pair("127.0.0.1:0").await.unwrap();
        let addr = udp.local_addr().unwrap();
        drop((udp, tcp));
        let mut calls = 0;
        let error = bind_pair_with(&addr.to_string(), |_| {
            calls += 1;
            std::future::ready(Err(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied,
            )))
        })
        .await
        .unwrap_err();
        assert_eq!(calls, 1);
        assert_eq!(
            error.to_string(),
            format!("failed to bind TCP DNS listener on {addr}")
        );
        let _rebound = bind_pair(&addr.to_string()).await.unwrap();
    })
    .await
    .expect("30-second fixed-port case guard");
}
