//! Real-socket regressions; private helpers stay under the defining module.
use super::*;
use hickory_proto::op::{MessageType, OpCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, HTTPS, MX, NULL, PTR, SOA, SVCB, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Whole-case hang guard for the real-socket tests. Each case takes about a
/// second alone, but dozens run in parallel and every statistics worker fsyncs
/// SQLite and snapshot files, so a tight budget only measures machine load.
const CASE_BUDGET: Duration = Duration::from_secs(30);

#[path = "server_contract_tests.rs"]
mod contracts;
#[path = "server_multi_listen_tests.rs"]
mod multi_listen;
#[path = "server_prefetch_tests.rs"]
mod prefetch;
#[path = "server_resource_tests.rs"]
mod resources;
#[path = "retry/mod.rs"]
mod retry;
#[path = "server_statistics_tests.rs"]
mod statistics;

fn question(host: &str, kind: RecordType) -> Query {
    Query::query(Name::from_ascii(host).unwrap(), kind)
}
fn request(host: &str, kind: RecordType, id: u16) -> Message {
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(question(host, kind));
    message
}

/// Counterfactual: without the retry roughly 8% of ephemeral binds on Windows
/// fail with `PermissionDenied` (ports reserved for TCP only); retrying every
/// error or a fixed port would mask real faults instead.
#[tokio::test]
async fn ephemeral_bind_pair_retries_only_tcp_port_collisions() {
    let mut calls = 0;
    let mut injected_failures = 0;
    let (udp, tcp) = bind_pair_with("127.0.0.1:0", |bound| {
        calls += 1;
        let refuse = injected_failures < 3;
        if refuse {
            injected_failures += 1;
        }
        async move {
            if refuse {
                Err(std::io::ErrorKind::PermissionDenied.into())
            } else {
                TcpListener::bind(bound).await
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(
        injected_failures, 3,
        "all three injected collisions retried"
    );
    // Subsequent real TCP binds may hit reserved OS bands, independently of
    // the exact injected-failure count. All calls share the production budget.
    assert!(
        (injected_failures + 1..=EPHEMERAL_BIND_ATTEMPTS).contains(&calls),
        "injected failures plus bounded real bind attempts, got {calls}"
    );
    let bound = udp.local_addr().unwrap();
    assert_ne!(bound.port(), 0, "the pair exposes the actual selected port");
    assert_eq!(bound.ip(), std::net::Ipv4Addr::LOCALHOST);
    assert_eq!(bound, tcp.local_addr().unwrap());
    assert_eq!(listener_endpoints(&udp, &tcp).unwrap(), vec![bound, bound]);

    let mut calls = 0;
    let error = bind_pair_with("127.0.0.1:0", |_| {
        calls += 1;
        async { Err(std::io::ErrorKind::PermissionDenied.into()) }
    })
    .await
    .unwrap_err();
    // One budget covers both protocols: a random port refused for UDP never
    // reaches the TCP step, so only most (not all) attempts call it.
    assert!(
        (EPHEMERAL_BIND_ATTEMPTS / 2..=EPHEMERAL_BIND_ATTEMPTS).contains(&calls),
        "bounded retries, got {calls}"
    );
    // The last attempt may fail on the UDP side of a random port instead, so
    // either protocol's bind error is a correct surfaced failure.
    let text = format!("{error:#}");
    assert!(
        text.contains("failed to bind TCP DNS listener")
            || text.contains("failed to bind UDP DNS listener"),
        "{text}"
    );

    let mut calls = 0;
    bind_pair_with("127.0.0.1:0", |_| {
        calls += 1;
        async { Err(std::io::ErrorKind::InvalidInput.into()) }
    })
    .await
    .unwrap_err();
    assert_eq!(calls, 1, "only port collisions are retried");
}

fn ctx(
    overrides: Vec<DnsOverride>,
    endpoints: Vec<SocketAddr>,
) -> QueryCtx<impl Fn() -> std::future::Ready<Option<TorTunnel>> + Clone + Send> {
    QueryCtx {
        tunnel: || panic!("local/override path consulted Tor"),
        cache: Arc::new(DnsCache::new()),
        providers: Arc::new(vec![]),
        overrides: Arc::new(overrides),
        endpoints: Arc::new(RwLock::new(endpoints)),
        route_probe: local::route_probe(),
        statistics: None,
    }
}
async fn udp_exchange(socket: &UdpSocket, addr: SocketAddr, message: &Message) -> Message {
    socket
        .send_to(&message.to_vec().unwrap(), addr)
        .await
        .unwrap();
    let mut bytes = vec![0; 65535];
    let (len, _) = timeout(Duration::from_secs(5), socket.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    Message::from_vec(&bytes[..len]).unwrap()
}
async fn tcp_exchange(stream: &mut TcpStream, message: &Message) -> Message {
    let bytes = message.to_vec().unwrap();
    // Deliberately split the length prefix and body, using real TCP. NODELAY
    // keeps every fragment its own segment; with Nagle on, each tiny write would
    // wait for the server's delayed ACK (about 40 ms each on Linux).
    stream.set_nodelay(true).unwrap();
    let prefix = u16::try_from(bytes.len()).unwrap().to_be_bytes();
    stream.write_all(&prefix[..1]).await.unwrap();
    stream.write_all(&prefix[1..]).await.unwrap();
    for chunk in bytes.chunks(3) {
        stream.write_all(chunk).await.unwrap();
    }
    let body = wire::read_framed_message(stream, Duration::from_secs(5))
        .await
        .unwrap()
        .unwrap();
    Message::from_vec(&body).unwrap()
}

/// Counterfactual: moving override/cache before local or merging A+AAAA gives
/// external work, mixed families, wrong PTR, or a nonempty unsupported answer.
#[tokio::test]
async fn local_udp_tcp_bypasses_tunnel_and_wildcard_override() {
    let (udp, tcp) = bind_pair("127.0.0.1:0").await.unwrap();
    let udp = Arc::new(udp);
    let addr = udp.local_addr().unwrap();
    let ctx = ctx(
        vec![DnsOverride {
            pattern: "*".into(),
            resolver: OverrideResolver::Dns {
                server: "127.0.0.1:1".parse().unwrap(),
            },
        }],
        vec![addr],
    );
    let backend = Arc::new(Semaphore::new(0));
    let mut loops = futures::future::join(
        Box::pin(listener::udp_loop(udp, ctx.clone(), backend.clone())),
        Box::pin(listener::tcp_loop(
            tcp,
            ctx,
            backend,
            Arc::new(Semaphore::new(listener::MAX_TCP_CONNECTIONS)),
        )),
    );
    let cases = async {
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut stream = TcpStream::connect(addr).await.unwrap();
        for (host, kind, expected) in [
            (
                "LOCALHOST.",
                RecordType::A,
                Some(RData::A(A("127.0.0.1".parse().unwrap()))),
            ),
            (
                "sub.LocalHost.",
                RecordType::AAAA,
                Some(RData::AAAA(AAAA("::1".parse().unwrap()))),
            ),
            ("sub.localhost.", RecordType::MX, None),
            (
                "9.8.7.127.in-addr.arpa.",
                RecordType::PTR,
                Some(RData::PTR(PTR(Name::from_ascii("localhost.").unwrap()))),
            ),
            (
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
                RecordType::PTR,
                Some(RData::PTR(PTR(Name::from_ascii("localhost.").unwrap()))),
            ),
        ] {
            let req = request(host, kind, 923);
            for reply in [
                udp_exchange(&client, addr, &req).await,
                tcp_exchange(&mut stream, &req).await,
            ] {
                assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
                assert_eq!(reply.metadata.id, 923);
                assert_eq!(reply.queries, req.queries);
                assert!(!reply.metadata.authentic_data);
                assert_eq!(reply.answers.len(), usize::from(expected.is_some()));
                if let Some(data) = &expected {
                    assert_eq!(&reply.answers[0].data, data);
                }
            }
        }
    };
    tokio::select! { _ = &mut loops => panic!("listener ended"), _ = cases => {} }
}

/// Counterfactual: blanket private reverse suppression drops unrelated routing;
/// forgetting actual bound addresses leaks own PTR; ignoring override blocks it.
#[test]
fn own_nonloopback_ptr_nodata_respects_override_not_unrelated_private() {
    let endpoints = vec![
        "192.0.2.8:1234".parse().unwrap(),
        "[2001:db8::1]:4567".parse().unwrap(),
    ];
    let own = question("8.2.0.192.in-addr.arpa.", RecordType::PTR);
    let answer = local::answer(&own, &wire::hostname_of(&own), &endpoints, false).unwrap();
    assert_eq!(answer.message.metadata.response_code, ResponseCode::NoError);
    assert!(answer.message.answers.is_empty());
    assert!(local::answer(&own, &wire::hostname_of(&own), &endpoints, true).is_none());
    assert!(local::answer(
        &question("7.2.0.192.in-addr.arpa.", RecordType::PTR),
        "7.2.0.192.in-addr.arpa",
        &endpoints,
        false
    )
    .is_none());
    assert!(local::answer(
        &question("1.0.0.10.in-addr.arpa.", RecordType::PTR),
        "1.0.0.10.in-addr.arpa",
        &endpoints,
        false
    )
    .is_none());
    assert!(local::answer(
        &question("8.2.0.192.in-addr.arpa.", RecordType::TXT),
        "8.2.0.192.in-addr.arpa",
        &endpoints,
        false
    )
    .is_none());
}

fn upstream_data(kind: RecordType) -> RData {
    let target = Name::from_ascii("target.example.").unwrap();
    match kind {
        RecordType::A => RData::A(A("192.0.2.17".parse().unwrap())),
        RecordType::AAAA => RData::AAAA(AAAA("2001:db8::17".parse().unwrap())),
        RecordType::PTR => RData::PTR(PTR(target)),
        RecordType::MX => RData::MX(MX::new(17, target)),
        RecordType::TXT => RData::TXT(TXT::new(vec!["opaque txt".into()])),
        RecordType::HTTPS => RData::HTTPS(HTTPS(SVCB::new(1, target, vec![]))),
        RecordType::SVCB => RData::SVCB(SVCB::new(1, target, vec![])),
        other => RData::Unknown {
            code: other,
            rdata: NULL::with(vec![0x80, 0, 0xff]),
        },
    }
}
fn upstream_reply(req: &Message) -> Message {
    let q = &req.queries[0];
    let host = wire::hostname_of(q);
    let mut message = Message::new(req.metadata.id, MessageType::Response, OpCode::Query);
    message.add_query(q.clone());
    message.metadata.authentic_data = true; // listener must clear it
    for (prefix, code) in [
        ("refused.", ResponseCode::Refused),
        ("notimp.", ResponseCode::NotImp),
        ("formerr.", ResponseCode::FormErr),
    ] {
        if host.starts_with(prefix) {
            message.metadata.response_code = code;
            return message;
        }
    }
    if host.starts_with("nx.") {
        message.metadata.response_code = ResponseCode::NXDomain;
    }
    let nodata = host.starts_with("nodata.")
        || (host.starts_with("aonly.") && q.query_type() == RecordType::AAAA);
    if !host.starts_with("nx.") && !nodata {
        let target = Name::from_ascii("target.example.").unwrap();
        message.add_answer(Record::from_rdata(
            q.name().clone(),
            60,
            RData::CNAME(CNAME(target.clone())),
        ));
        message.add_answer(Record::from_rdata(
            target,
            60,
            upstream_data(q.query_type()),
        ));
    }
    message.authorities.push(Record::from_rdata(
        Name::from_ascii("example.").unwrap(),
        60,
        RData::SOA(SOA::new(
            Name::from_ascii("ns.example.").unwrap(),
            Name::from_ascii("hostmaster.example.").unwrap(),
            1,
            60,
            60,
            3600,
            60,
        )),
    ));
    for record in message.answers.iter_mut().chain(&mut message.authorities) {
        record.dns_class = q.query_class();
    }
    message
}

/// Counterfactual: address-only reconstruction loses MX/TXT/SVCB/unknown data,
/// CNAME or SOA; forced NOERROR converts NXDOMAIN. Wrong keys mix query types.
#[tokio::test]
async fn real_upstream_udp_tcp_typed_packets_and_negative_cache() {
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server = upstream.local_addr().unwrap();
    let (udp, tcp) = bind_pair("127.0.0.1:0").await.unwrap();
    let udp = Arc::new(udp);
    let addr = udp.local_addr().unwrap();
    let ctx = ctx(
        vec![DnsOverride {
            pattern: "*".into(),
            resolver: OverrideResolver::Dns { server },
        }],
        vec![addr],
    );
    let cache = ctx.cache.clone();
    let backend = Arc::new(Semaphore::new(64));
    let mut loops = Box::pin(futures::future::join(
        listener::udp_loop(udp, ctx.clone(), backend.clone()),
        listener::tcp_loop(
            tcp,
            ctx,
            backend,
            Arc::new(Semaphore::new(listener::MAX_TCP_CONNECTIONS)),
        ),
    ));
    let upstream_loop = async {
        let mut bytes = vec![0; 65535];
        loop {
            let (len, peer) = upstream.recv_from(&mut bytes).await.unwrap();
            let req = Message::from_vec(&bytes[..len]).unwrap();
            upstream
                .send_to(&upstream_reply(&req).to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    };
    let cases = async {
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut stream = TcpStream::connect(addr).await.unwrap();
        for kind in [
            RecordType::A,
            RecordType::AAAA,
            RecordType::PTR,
            RecordType::MX,
            RecordType::TXT,
            RecordType::HTTPS,
            RecordType::SVCB,
            RecordType::Unknown(65400),
        ] {
            let req = request("typed.example.", kind, 111);
            let reply = udp_exchange(&client, addr, &req).await;
            assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
            assert_eq!(reply.answers.len(), 2);
            assert_eq!(reply.answers[1].data, upstream_data(kind));
            assert_eq!(reply.answers[0].record_type(), RecordType::CNAME);
            assert_eq!(reply.authorities[0].record_type(), RecordType::SOA);
            let req = request("typed.example.", kind, 222);
            let cached = tcp_exchange(&mut stream, &req).await;
            assert_eq!(cached.metadata.id, 222);
            assert_eq!(cached.queries, req.queries);
            assert_eq!(cached.answers[1].data, upstream_data(kind));
            assert!(!cached.metadata.authentic_data);
        }
        for (host, rcode) in [
            ("nx.example.", ResponseCode::NXDomain),
            ("nodata.example.", ResponseCode::NoError),
        ] {
            let req = request(host, RecordType::TXT, 333);
            let reply = udp_exchange(&client, addr, &req).await;
            assert_eq!(reply.metadata.response_code, rcode);
            assert!(reply.answers.is_empty());
            assert_eq!(reply.authorities.len(), 1);
            let stored = cache
                .get(&req.queries[0])
                .expect("negative result retained");
            assert_eq!(stored.message.metadata.response_code, rcode);
            let reply = tcp_exchange(&mut stream, &request(host, RecordType::TXT, 444)).await;
            assert_eq!(reply.metadata.id, 444);
            assert_eq!(reply.metadata.response_code, rcode);
            assert!(reply.answers.is_empty());
        }
    };
    tokio::select! { _ = &mut loops => panic!("listener ended"), _ = upstream_loop => panic!("upstream ended"), _ = cases => {} }
}

/// Counterfactual: awaiting backend admission in recv stalls both inline replies;
/// spawning before admission adds a 65th upstream exchange. Gate uses actual
/// network arrivals and a resource release channel, never sleep/CPU timing.
#[tokio::test]
async fn sixty_four_network_gated_misses_inline_hits_overload_release_resume() {
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server = upstream.local_addr().unwrap();
    let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = udp.local_addr().unwrap();
    let ctx = ctx(
        vec![DnsOverride {
            pattern: "*".into(),
            resolver: OverrideResolver::Dns { server },
        }],
        vec![addr],
    );
    let warm = request("warm.example.", RecordType::A, 0);
    ctx.cache.insert(
        &warm.queries[0],
        &ResolvedAnswer {
            message: upstream_reply(&warm),
            ttl: Duration::from_secs(60),
            resolved_at: time::OffsetDateTime::now_utc(),
        },
    );
    let backend = Arc::new(Semaphore::new(64));
    let (arrived_tx, mut arrived_rx) = tokio::sync::mpsc::channel(64);
    let (release_tx, mut release_rx) = tokio::sync::mpsc::channel(1);
    let mut loop_future = Box::pin(listener::udp_loop(udp, ctx, backend.clone()));
    let upstream_loop = async {
        let mut bytes = vec![0; 65535];
        let mut held = Vec::new();
        for _ in 0..64 {
            let (len, peer) = upstream.recv_from(&mut bytes).await.unwrap();
            held.push((Message::from_vec(&bytes[..len]).unwrap(), peer));
            arrived_tx.send(()).await.unwrap();
        }
        release_rx.recv().await.unwrap();
        for (req, peer) in held {
            upstream
                .send_to(&upstream_reply(&req).to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
        let (len, peer) = upstream.recv_from(&mut bytes).await.unwrap();
        let req = Message::from_vec(&bytes[..len]).unwrap();
        assert_eq!(
            wire::hostname_of(&req.queries[0]),
            "resumed.example",
            "no work allowed for overload"
        );
        upstream
            .send_to(&upstream_reply(&req).to_vec().unwrap(), peer)
            .await
            .unwrap();
        std::future::pending::<()>().await;
    };
    let cases = async {
        let miss_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for id in 0..64 {
            miss_client
                .send_to(
                    &request(&format!("miss{id}.example."), RecordType::A, id)
                        .to_vec()
                        .unwrap(),
                    addr,
                )
                .await
                .unwrap();
            arrived_rx.recv().await.unwrap();
        }
        assert_eq!(backend.available_permits(), 0);
        let inline = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert_eq!(
            udp_exchange(&inline, addr, &request("localhost.", RecordType::A, 70))
                .await
                .answers[0]
                .data,
            RData::A(A("127.0.0.1".parse().unwrap()))
        );
        assert_eq!(
            udp_exchange(&inline, addr, &request("warm.example.", RecordType::A, 71))
                .await
                .answers
                .len(),
            2
        );
        assert_eq!(
            udp_exchange(
                &inline,
                addr,
                &request("overload.example.", RecordType::A, 72)
            )
            .await
            .metadata
            .response_code,
            ResponseCode::ServFail
        );
        release_tx.send(()).await.unwrap();
        let mut bytes = vec![0; 4096];
        for _ in 0..64 {
            timeout(Duration::from_secs(5), miss_client.recv_from(&mut bytes))
                .await
                .unwrap()
                .unwrap();
        }
        assert_eq!(backend.available_permits(), 64);
        let reply = udp_exchange(
            &inline,
            addr,
            &request("resumed.example.", RecordType::A, 73),
        )
        .await;
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    };
    tokio::select! { _ = &mut loop_future => panic!("listener ended"), _ = upstream_loop => panic!("upstream ended"), _ = cases => {} }
    drop(loop_future);
    assert_eq!(backend.available_permits(), 64);
}

/// Counterfactual: timeout only around the provider omits tunnel acquisition;
/// a dropped scoped UDP loop retaining detached work would keep its permit.
#[tokio::test]
async fn expired_total_deadline_cancels_tunnel_acquisition() {
    let (entered, mut observed) = tokio::sync::mpsc::channel(1);
    let ctx = QueryCtx {
        tunnel: move || {
            let entered = entered.clone();
            async move {
                entered.send(()).await.unwrap();
                std::future::pending::<Option<TorTunnel>>().await
            }
        },
        cache: Arc::new(DnsCache::new()),
        providers: Arc::new(vec![]),
        overrides: Arc::new(vec![]),
        endpoints: Arc::new(RwLock::new(vec![])),
        route_probe: local::route_probe(),
        statistics: None,
    };
    let deadline = Instant::now();
    assert!(
        resolve_miss(ctx, question("deadline.example.", RecordType::A), deadline)
            .await
            .is_none()
    );
    assert!(
        observed.try_recv().is_ok(),
        "deadline covered pending tunnel acquisition"
    );
}

/// Counterfactual: detached resolution survives dropping the listener and holds
/// a permit; unavailable Tor converted to an empty success gives NOERROR.
#[tokio::test]
async fn scoped_cancellation_releases_pending_tunnel_and_unavailable_tor_servfail() {
    let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = udp.local_addr().unwrap();
    let backend = Arc::new(Semaphore::new(64));
    let (entered, mut observed) = tokio::sync::mpsc::channel(1);
    let ctx = QueryCtx {
        tunnel: move || {
            let entered = entered.clone();
            async move {
                entered.send(()).await.unwrap();
                std::future::pending::<Option<TorTunnel>>().await
            }
        },
        cache: Arc::new(DnsCache::new()),
        providers: Arc::new(vec![]),
        overrides: Arc::new(vec![]),
        endpoints: Arc::new(RwLock::new(vec![addr])),
        route_probe: local::route_probe(),
        statistics: None,
    };
    let mut service = Box::pin(listener::udp_loop(udp, ctx, backend.clone()));
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(
            &request("pending.example.", RecordType::TXT, 901)
                .to_vec()
                .unwrap(),
            addr,
        )
        .await
        .unwrap();
    tokio::select! { _ = &mut service => panic!("listener ended"), _ = observed.recv() => {} }
    assert_eq!(backend.available_permits(), 63);
    drop(service);
    assert_eq!(backend.available_permits(), 64);
    let ctx = QueryCtx {
        tunnel: || std::future::ready(None),
        cache: Arc::new(DnsCache::new()),
        providers: Arc::new(vec![]),
        overrides: Arc::new(vec![]),
        endpoints: Arc::new(RwLock::new(vec![])),
        route_probe: local::route_probe(),
        statistics: None,
    };
    let req = request("unavailable.example.", RecordType::TXT, 902);
    let answer = resolve_miss(
        ctx,
        req.queries[0].clone(),
        Instant::now() + RESOLUTION_TIMEOUT,
    )
    .await;
    let reply = response(&req, answer);
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(reply.metadata.id, 902);
    assert_eq!(reply.queries, req.queries);
}

/// Counterfactual: omitted cap returns >512 bytes; address reconstruction loses
/// TXT payload; AD preservation incorrectly claims validation after truncation.
#[test]
fn oversized_packet_truncates_and_malformed_packets_do_not_resolve() {
    let req = request("large.example.", RecordType::TXT, 9);
    let mut packet = upstream_reply(&req);
    for _ in 0..10 {
        packet.add_answer(Record::from_rdata(
            req.queries[0].name().clone(),
            60,
            RData::TXT(TXT::new(vec!["x".repeat(200)])),
        ));
    }
    let response_bytes = packet.to_vec().unwrap();
    let bytes = wire::encode_udp_response(wire::build_response(
        &req,
        Some(packet),
        ResponseCode::ServFail,
    ))
    .unwrap();
    assert!(bytes.len() <= 512);
    let reply = Message::from_vec(&bytes).unwrap();
    assert!(reply.metadata.truncation);
    assert!(!reply.metadata.authentic_data);
    assert!(reply.answers.is_empty());
    assert_eq!(reply.queries, req.queries);
    assert!(wire::parse_query(&[]).is_none());
    assert!(wire::parse_query(&[0xff; 20]).is_none());
    assert!(wire::parse_query(&response_bytes).is_none());
    let empty = Message::new(77, MessageType::Query, OpCode::Query);
    assert_eq!(
        wire::formerr(&empty).metadata.response_code,
        ResponseCode::FormErr
    );
}

/// Counterfactual: zero length acceptance or mid-prefix/body EOF continuation
/// retains a misaligned connection; an unchecked u16 cast accepts oversized output.
#[tokio::test]
async fn real_tcp_zero_partial_eof_and_oversized_write_guards() {
    for bytes in [vec![0, 0], vec![0], vec![0, 5, b'x']] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        client.write_all(&bytes).await.unwrap();
        client.shutdown().await.unwrap();
        assert!(
            wire::read_framed_message(&mut server, Duration::from_secs(5))
                .await
                .is_err()
        );
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (mut server, _) = listener.accept().await.unwrap();
    assert_eq!(
        wire::write_framed_message(&mut server, &vec![0; 65536], Duration::from_secs(5))
            .await
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidData
    );
    client.shutdown().await.unwrap();
    assert!(
        wire::read_framed_message(&mut server, Duration::from_secs(5))
            .await
            .unwrap()
            .is_none()
    );
}
