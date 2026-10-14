use super::*;
use hickory_proto::op::{Message, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, HTTPS, MX, NULL, PTR, SOA, SVCB, TXT};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use tokio::net::TcpListener;

#[path = "plain_transport_fixtures.rs"]
mod fixtures;

fn question(kind: RecordType) -> Query {
    Query::query("example.test.".parse().unwrap(), kind)
}
fn response(request: &Message) -> Message {
    let mut message = Message::response(request.metadata.id, OpCode::Query);
    message.add_query(request.queries[0].clone());
    message
}
fn soa() -> Record {
    Record::from_rdata(
        "test.".parse().unwrap(),
        90,
        RData::SOA(SOA::new(
            "ns.test.".parse().unwrap(),
            "hostmaster.test.".parse().unwrap(),
            1,
            60,
            30,
            3600,
            45,
        )),
    )
}

#[tokio::test]
async fn udp_preserves_original_types_classes_and_full_record_sections() {
    let target: Name = "target.test.".parse().unwrap();
    let data = [
        RData::A(A(Ipv4Addr::new(192, 0, 2, 9))),
        RData::AAAA(AAAA("2001:db8::9".parse().unwrap())),
        RData::PTR(PTR(target.clone())),
        RData::MX(MX::new(10, target.clone())),
        RData::TXT(TXT::new(vec!["first".into(), "second".into()])),
        RData::HTTPS(HTTPS(SVCB::new(1, target.clone(), vec![]))),
        RData::SVCB(SVCB::new(1, target.clone(), vec![])),
        RData::Unknown {
            code: RecordType::Unknown(65400),
            rdata: NULL::with(vec![1, 2, 255]),
        },
    ];
    for rdata in data {
        let mut q = question(rdata.record_type());
        if q.query_type() == RecordType::Unknown(65400) {
            q.set_query_class(DNSClass::Unknown(65200));
        }
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = socket.local_addr().unwrap();
        let upstream = async {
            let mut buf = vec![0; MAX_DNS_RESPONSE_BYTES];
            let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
            let request = Message::from_vec(&buf[..n]).unwrap();
            assert_eq!(request.queries, vec![q.clone()]);
            let mut answer = response(&request);
            let mut record = Record::from_rdata(q.name().clone(), 120, rdata);
            record.dns_class = q.query_class();
            answer.add_answer(record);
            answer.add_authority(soa());
            answer.add_additional(Record::from_rdata(
                target.clone(),
                60,
                RData::A(A(Ipv4Addr::new(192, 0, 2, 10))),
            ));
            let bytes = answer.to_vec().unwrap();
            socket.send_to(&bytes, peer).await.unwrap();
            Message::from_vec(&bytes).unwrap()
        };
        let (actual, expected) = tokio::join!(resolve_via_dns_server(&q, server, &[]), upstream);
        assert_eq!(actual.unwrap().message, expected);
        // No second A/AAAA query may be synthesized by the transport.
        assert!(
            matches!(socket.try_recv_from(&mut [0; 512]), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
        );
    }
}

#[tokio::test]
async fn udp_negative_cname_soa_is_preserved_for_nxdomain_and_nodata() {
    for code in [ResponseCode::NXDomain, ResponseCode::NoError] {
        let q = question(RecordType::AAAA);
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = socket.local_addr().unwrap();
        let upstream = async {
            let mut buf = [0; 512];
            let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
            let mut message = response(&Message::from_vec(&buf[..n]).unwrap());
            message.metadata.response_code = code;
            message.add_answer(Record::from_rdata(
                q.name().clone(),
                30,
                RData::CNAME(CNAME("absent.test.".parse().unwrap())),
            ));
            message.add_authority(soa());
            socket
                .send_to(&message.to_vec().unwrap(), peer)
                .await
                .unwrap();
        };
        let (answer, ()) = tokio::join!(resolve_via_dns_server(&q, server, &[]), upstream);
        let answer = answer.unwrap();
        assert_eq!(answer.message.metadata.response_code, code);
        assert_eq!(answer.message.answers.len(), 1);
        let mut expected_soa = soa();
        expected_soa.ttl = 45;
        assert_eq!(answer.message.authorities, vec![expected_soa]);
        assert_eq!(answer.message.authorities[0].ttl, 45);
        // The CNAME's shorter packet lease must not replace SOA.MINIMUM.
        assert_eq!(answer.ttl, Duration::from_secs(30));
    }
}

#[tokio::test]
async fn validated_udp_tc_retries_same_question_tcp_with_fragmented_frame() {
    let (udp, tcp, server) = fixtures::udp_tcp_pair().await.unwrap();
    let q = question(RecordType::TXT);
    let upstream = async {
        let mut buf = [0; 512];
        let (n, peer) = udp.recv_from(&mut buf).await.unwrap();
        let request = Message::from_vec(&buf[..n]).unwrap();
        let mut tc = response(&request);
        tc.metadata.truncation = true;
        udp.send_to(&tc.to_vec().unwrap(), peer).await.unwrap();
        let (mut stream, _) = tcp.accept().await.unwrap();
        let mut prefix = [0; 2];
        stream.read_exact(&mut prefix).await.unwrap();
        let mut body = vec![0; usize::from(u16::from_be_bytes(prefix))];
        stream.read_exact(&mut body).await.unwrap();
        assert_eq!(Message::from_vec(&body).unwrap(), request);
        let mut full = response(&request);
        full.add_answer(Record::from_rdata(
            q.name().clone(),
            60,
            RData::TXT(TXT::new(vec!["tcp-only".into()])),
        ));
        let body = full.to_vec().unwrap();
        for byte in u16::try_from(body.len())
            .unwrap()
            .to_be_bytes()
            .into_iter()
            .chain(body)
        {
            stream.write_all(&[byte]).await.unwrap();
        }
        full
    };
    let (actual, expected) = tokio::join!(resolve_via_dns_server(&q, server, &[]), upstream);
    assert_eq!(actual.unwrap().message, expected);
}

#[tokio::test]
async fn foreign_source_and_wrong_question_tc_cannot_trigger_tcp() {
    let (udp, tcp, server) = fixtures::udp_tcp_pair().await.unwrap();
    let foreign = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let q = question(RecordType::MX);
    let upstream = async {
        let mut buf = [0; 512];
        let (n, peer) = udp.recv_from(&mut buf).await.unwrap();
        let request = Message::from_vec(&buf[..n]).unwrap();
        let full = response(&request);
        let mut tc = full.clone();
        tc.metadata.truncation = true;
        foreign.send_to(&tc.to_vec().unwrap(), peer).await.unwrap();
        tc.queries[0].set_query_type(RecordType::AAAA);
        udp.send_to(&tc.to_vec().unwrap(), peer).await.unwrap();
        udp.send_to(&full.to_vec().unwrap(), peer).await.unwrap();
        full
    };
    let (answer, expected) = tokio::join!(resolve_via_dns_server(&q, server, &[]), upstream);
    assert_eq!(answer.unwrap().message, expected);
    // Check the listener directly without a timing-dependent acceptance wait.
    let accepted = tokio::time::timeout(Duration::ZERO, tcp.accept()).await;
    assert!(accepted.is_err(), "invalid TC opened a TCP connection");
}

#[test]
fn self_reference_exact_wildcard_loopback_mapped_and_external_same_port() {
    let local: IpAddr = "192.0.2.7".parse().unwrap();
    for (target, bound, blocked) in [
        ("192.0.2.7:53", "192.0.2.7:53", true),
        ("192.0.2.7:53", "0.0.0.0:53", true),
        ("127.0.0.2:53", "127.0.0.1:53", false),
        ("[::1]:53", "127.0.0.1:53", false),
        ("[::ffff:127.0.0.1]:53", "127.0.0.1:53", true),
        ("[::ffff:127.0.0.1]:53", "0.0.0.0:53", true),
        ("[::1]:53", "[::]:53", true),
        ("127.0.0.1:53", "[::]:53", false),
        ("[::ffff:127.0.0.1]:53", "[::]:53", false),
        ("192.0.2.7:53", "[::]:53", false),
        ("[::ffff:192.0.2.7]:53", "192.0.2.7:53", true),
        ("192.0.2.7:53", "[::ffff:192.0.2.7]:53", true),
        ("8.8.8.8:53", "192.0.2.7:53", false),
        ("8.8.8.8:53", "0.0.0.0:53", false),
        ("8.8.8.8:53", "[::]:53", false),
        ("[2001:4860:4860::8888]:53", "[::]:53", false),
        ("127.0.0.1:54", "0.0.0.0:53", false),
    ] {
        assert_eq!(
            self_reference(target.parse().unwrap(), &[bound.parse().unwrap()], local),
            blocked,
            "{target} / {bound}"
        );
    }
    // The owner adds IPv4 coverage only after observing an actual dual-stack
    // wildcard socket. The backend seam remains &[SocketAddr].
    let dual_stack = ["[::]:53".parse().unwrap(), "0.0.0.0:53".parse().unwrap()];
    for target in ["127.0.0.1:53", "[::ffff:192.0.2.7]:53", "[::1]:53"] {
        assert!(self_reference(target.parse().unwrap(), &dual_stack, local));
    }
    assert!(!self_reference(
        "8.8.8.8:53".parse().unwrap(),
        &dual_stack,
        local,
    ));
}

#[tokio::test]
async fn self_reference_is_rejected_before_dns_send() {
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = udp.local_addr().unwrap();
    let result = resolve_via_dns_server(&question(RecordType::A), endpoint, &[endpoint]).await;
    assert!(matches!(result, Err(DnsServerError::PlainDns(_))));
    assert!(
        matches!(udp.try_recv_from(&mut [0; 512]), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
    );
}

#[tokio::test]
async fn system_configuration_is_fresh_each_call_and_all_terminal_rcodes_stop_fallback() {
    let q = question(RecordType::PTR);
    for code in [
        ResponseCode::NXDomain,
        ResponseCode::NoError,
        ResponseCode::Refused,
        ResponseCode::NotImp,
        ResponseCode::FormErr,
    ] {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let endpoint = udp.local_addr().unwrap();
        let unused = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let config = async { Ok(vec![endpoint, unused.local_addr().unwrap()]) };
        let upstream = async {
            let mut buf = [0; 512];
            let (n, peer) = udp.recv_from(&mut buf).await.unwrap();
            let mut answer = response(&Message::from_vec(&buf[..n]).unwrap());
            assert_eq!(answer.queries, vec![q.clone()]);
            answer.metadata.response_code = code;
            answer.add_authority(soa());
            udp.send_to(&answer.to_vec().unwrap(), peer).await.unwrap();
        };
        let (actual, ()) = tokio::join!(system_with_config(&q, &[], config), upstream);
        assert_eq!(actual.unwrap().message.metadata.response_code, code);
        assert!(
            matches!(
                unused.try_recv_from(&mut [0; 512]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
            ),
            "terminal {code:?} must not query another configured server"
        );
    }
    assert!(matches!(
        system_with_config(&q, &[], async { Ok(vec![]) }).await,
        Err(DnsServerError::SystemResolver(_))
    ));
}

#[tokio::test]
async fn plain_forwards_all_terminal_rcodes_without_retry() {
    for code in [
        ResponseCode::NoError,
        ResponseCode::NXDomain,
        ResponseCode::Refused,
        ResponseCode::NotImp,
        ResponseCode::FormErr,
    ] {
        let q = question(RecordType::MX);
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let endpoint = udp.local_addr().unwrap();
        let peer = async {
            let mut buf = [0; 512];
            let (n, addr) = udp.recv_from(&mut buf).await.unwrap();
            let mut answer = response(&Message::from_vec(&buf[..n]).unwrap());
            answer.metadata.response_code = code;
            let bytes = answer.to_vec().unwrap();
            udp.send_to(&bytes, addr).await.unwrap();
            Message::from_vec(&bytes).unwrap()
        };
        let (answer, expected) = tokio::join!(resolve_via_dns_server(&q, endpoint, &[]), peer);
        assert_eq!(answer.unwrap().message, expected);
        assert!(matches!(
            udp.try_recv_from(&mut [0; 512]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
        ));
    }
}

#[tokio::test]
async fn system_preflights_all_servers_before_any_dns_send() {
    let q = question(RecordType::A);
    let safe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let safe_endpoint = safe.local_addr().unwrap();
    let own_endpoint = listener.local_addr().unwrap();
    // Both positions matter: neither earlier success nor later fallback may
    // hide a recursive system configuration. No peer task is needed: the
    // preflight must fail without waiting for any DNS response.
    for bound in [
        own_endpoint,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), own_endpoint.port()),
    ] {
        for servers in [
            vec![safe_endpoint, own_endpoint],
            vec![own_endpoint, safe_endpoint],
        ] {
            let result = system_with_config(&q, &[bound], async { Ok(servers) }).await;
            assert!(matches!(
                result,
                Err(DnsServerError::SystemResolver(ref text)) if text.contains("refers to this listener")
            ));
            for socket in [&safe, &listener] {
                assert!(
                    matches!(
                        socket.try_recv_from(&mut [0; 512]),
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                    ),
                    "preflight must not send DNS to any configured server"
                );
            }
        }
    }
}

#[tokio::test]
async fn system_unreachable_first_preserves_safe_second_fallback() {
    let q = question(RecordType::MX);
    let safe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = safe.local_addr().unwrap();
    let unreachable: SocketAddr = "[2001:db8::53]:53".parse().unwrap();
    let probed = std::cell::RefCell::new(Vec::new());
    let probe = |server| {
        probed.borrow_mut().push(server);
        async move {
            if server == unreachable {
                Err(ProbeError::Transport(DnsServerError::PlainDns(
                    "injected IPv6 route unavailable".into(),
                )))
            } else {
                probe_upstream(server, &[]).await.map(|_| ())
            }
        }
    };
    let peer = async {
        let mut buf = [0; 512];
        let (n, addr) = safe.recv_from(&mut buf).await.unwrap();
        let request = Message::from_vec(&buf[..n]).unwrap();
        assert_eq!(request.queries, vec![q.clone()]);
        let answer = response(&request);
        safe.send_to(&answer.to_vec().unwrap(), addr).await.unwrap();
        answer
    };
    let (answer, expected) = tokio::join!(
        system_with_config_and_probe(&q, &[], async { Ok(vec![unreachable, endpoint]) }, probe,),
        peer
    );
    assert_eq!(answer.unwrap().message, expected);
    assert_eq!(*probed.borrow(), vec![unreachable, endpoint]);
}

#[tokio::test]
async fn system_unreachable_first_cannot_hide_later_unroutable_exact_self_reference() {
    let q = question(RecordType::A);
    let safe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = safe.local_addr().unwrap();
    let unreachable: SocketAddr = "[2001:db8::53]:53".parse().unwrap();
    let own: SocketAddr = "[2001:db8::99]:53".parse().unwrap();
    let probed = std::cell::RefCell::new(Vec::new());
    let probe = |server| {
        probed.borrow_mut().push(server);
        async move {
            assert_ne!(
                server, own,
                "exact self-reference must be caught before connect"
            );
            if server == unreachable {
                Err(ProbeError::Transport(DnsServerError::PlainDns(
                    "injected IPv6 route unavailable".into(),
                )))
            } else {
                probe_upstream(server, &[]).await.map(|_| ())
            }
        }
    };
    let result = system_with_config_and_probe(
        &q,
        &[own],
        async { Ok(vec![unreachable, endpoint, own]) },
        probe,
    )
    .await;
    assert!(matches!(result, Err(DnsServerError::SystemResolver(_))));
    assert_eq!(*probed.borrow(), vec![unreachable, endpoint]);
    assert!(
        matches!(
            safe.try_recv_from(&mut [0; 512]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
        ),
        "later recursion must prevent sending to earlier safe server"
    );
}

#[tokio::test]
async fn system_route_probe_self_reference_is_terminal_after_transport_error() {
    let q = question(RecordType::A);
    let safe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = safe.local_addr().unwrap();
    let unreachable: SocketAddr = "[2001:db8::53]:53".parse().unwrap();
    let routed_local: SocketAddr = "192.0.2.7:53".parse().unwrap();
    let result = system_with_config_and_probe(
        &q,
        &[],
        async { Ok(vec![unreachable, endpoint, routed_local]) },
        |server| async move {
            if server == unreachable {
                Err(ProbeError::Transport(DnsServerError::PlainDns(
                    "no route".into(),
                )))
            } else if server == routed_local {
                // Represents self-reference detected from the connected
                // socket's local address, rather than the static precheck.
                Err(ProbeError::SelfReference(server))
            } else {
                probe_upstream(server, &[]).await.map(|_| ())
            }
        },
    )
    .await;
    assert!(matches!(result, Err(DnsServerError::SystemResolver(_))));
    assert!(matches!(
        safe.try_recv_from(&mut [0; 512]),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
    ));
}

#[tokio::test]
async fn system_servfail_alone_falls_back_to_next_configured_server() {
    let q = question(RecordType::TXT);
    let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let servers = vec![first.local_addr().unwrap(), second.local_addr().unwrap()];
    let peer = async {
        for (socket, code) in [
            (&first, ResponseCode::ServFail),
            (&second, ResponseCode::Refused),
        ] {
            let mut buf = [0; 512];
            let (n, addr) = socket.recv_from(&mut buf).await.unwrap();
            let request = Message::from_vec(&buf[..n]).unwrap();
            assert_eq!(request.queries, vec![q.clone()]);
            let mut answer = response(&request);
            answer.metadata.response_code = code;
            socket
                .send_to(&answer.to_vec().unwrap(), addr)
                .await
                .unwrap();
        }
    };
    let (answer, ()) = tokio::join!(system_with_config(&q, &[], async { Ok(servers) }), peer);
    assert_eq!(
        answer.unwrap().message.metadata.response_code,
        ResponseCode::Refused
    );
}

#[tokio::test]
async fn silent_udp_upstream_observes_plain_exchange_deadline() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = socket.local_addr().unwrap();
    let q = question(RecordType::AAAA);
    // Pause only after the real socket receives the request: no real-I/O
    // readiness race can auto-advance the timer before the send is observed.
    let peer = async {
        let mut buf = [0; 512];
        let (n, _) = socket.recv_from(&mut buf).await.unwrap();
        assert_eq!(
            Message::from_vec(&buf[..n]).unwrap().queries,
            vec![q.clone()]
        );
        tokio::time::pause();
        tokio::time::advance(PLAIN_DNS_TIMEOUT).await;
    };
    let (result, ()) = tokio::join!(resolve_via_dns_server(&q, endpoint, &[]), peer);
    assert!(
        matches!(result, Err(DnsServerError::Timeout(duration)) if duration == PLAIN_DNS_TIMEOUT)
    );
}

#[tokio::test]
async fn partial_tcp_frame_deadline_closes_owned_stream() {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = tcp.local_addr().unwrap();
    let query = build_query(&question(RecordType::A)).unwrap();
    let exchange =
        async { tokio::time::timeout(PLAIN_DNS_TIMEOUT, tcp_exchange(endpoint, &query)).await };
    let peer = async {
        let (mut stream, _) = tcp.accept().await.unwrap();
        let mut prefix = [0; 2];
        stream.read_exact(&mut prefix).await.unwrap();
        let mut body = vec![0; usize::from(u16::from_be_bytes(prefix))];
        stream.read_exact(&mut body).await.unwrap();
        stream.write_all(&[0]).await.unwrap(); // partial response length
        tokio::time::pause();
        tokio::time::advance(PLAIN_DNS_TIMEOUT).await;
        let mut byte = [0];
        // Closing with the unread partial prefix still queued is a reset
        // (ConnectionReset on macOS, ConnectionAborted on Windows), without
        // it a clean FIN: all prove the client closed.
        match stream.read(&mut byte).await {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                ) => {}
            other => panic!("deadline must close connection, got {other:?}"),
        }
    };
    let (result, ()) = tokio::join!(exchange, peer);
    assert!(result.is_err());
}
