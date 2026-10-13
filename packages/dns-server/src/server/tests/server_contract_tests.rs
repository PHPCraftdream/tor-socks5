use super::*;
use hickory_proto::rr::DNSClass;
use std::cell::Cell;

#[tokio::test]
async fn listener_type_class_isolation_aonly_nodata_and_terminal_rcodes() {
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server = upstream.local_addr().unwrap();
    let (udp, tcp) = bind_pair("127.0.0.1:0").await.unwrap();
    let addr = udp.local_addr().unwrap();
    assert_ne!(addr.port(), 0);
    assert_eq!(tcp.local_addr().unwrap(), addr);
    let udp = Arc::new(udp);
    let ctx = ctx(
        vec![DnsOverride {
            pattern: "*".into(),
            resolver: OverrideResolver::Dns { server },
        }],
        vec![addr],
    );
    let cache = ctx.cache.clone();
    let backend = Arc::new(Semaphore::new(64));
    let count = Cell::new(0);
    let mut service = Box::pin(futures::future::join(
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
            count.set(count.get() + 1);
            let req = Message::from_vec(&bytes[..len]).unwrap();
            upstream
                .send_to(&upstream_reply(&req).to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    };
    let cases = async {
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut peer = TcpStream::connect(addr).await.unwrap();
        for (kind, class) in [
            (RecordType::A, DNSClass::IN),
            (RecordType::AAAA, DNSClass::IN),
            (RecordType::TXT, DNSClass::IN),
            (RecordType::TXT, DNSClass::CH),
        ] {
            let mut req = request("aonly.example.", kind, 14);
            req.queries[0].set_query_class(class);
            let reply = udp_exchange(&client, addr, &req).await;
            assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
            assert_eq!(reply.queries, req.queries);
            if kind == RecordType::AAAA {
                assert!(
                    reply.answers.is_empty(),
                    "A-only owner is AAAA NODATA, not mixed-family or NXDOMAIN"
                );
            } else {
                assert_eq!(reply.answers[1].record_type(), kind);
                assert_eq!(reply.answers[1].dns_class, class);
            }
            assert!(cache.get(&req.queries[0]).is_some());
            req.metadata.id = 15;
            let before = count.get();
            let cached = tcp_exchange(&mut peer, &req).await;
            assert_eq!(count.get(), before, "same tuple must hit cache");
            assert_eq!(cached.metadata.id, 15);
            assert_eq!(cached.queries, req.queries);
            assert_eq!(cached.answers.len(), reply.answers.len());
        }
        assert_eq!(
            count.get(),
            4,
            "different type/class tuples each resolve once"
        );
        for (host, code) in [
            ("refused.example.", ResponseCode::Refused),
            ("notimp.example.", ResponseCode::NotImp),
            ("formerr.example.", ResponseCode::FormErr),
        ] {
            let req = request(host, RecordType::TXT, 23);
            for reply in [
                udp_exchange(&client, addr, &req).await,
                tcp_exchange(&mut peer, &req).await,
            ] {
                assert_eq!(
                    reply.metadata.response_code, code,
                    "terminal DNS rcode is not outage"
                );
                assert_eq!(reply.metadata.id, 23);
                assert_eq!(reply.queries, req.queries);
                assert!(reply.answers.is_empty());
            }
            assert!(
                cache.get(&req.queries[0]).is_none(),
                "terminal failure is forwarded but not cached"
            );
        }
        assert_eq!(count.get(), 10);
    };
    tokio::select! { _ = &mut service => panic!("listener ended"), _ = upstream_loop => panic!("upstream ended"), _ = cases => {} }
}

#[tokio::test]
async fn actual_ephemeral_listener_self_recursion_sends_no_nested_dns() {
    let (udp, tcp) = bind_pair("127.0.0.1:0").await.unwrap();
    let addr = udp.local_addr().unwrap();
    assert_ne!(addr.port(), 0);
    assert_eq!(tcp.local_addr().unwrap(), addr);
    let udp = Arc::new(udp);
    let ctx = ctx(
        vec![DnsOverride {
            pattern: "*".into(),
            resolver: OverrideResolver::Dns { server: addr },
        }],
        vec![addr],
    );
    let backend = Arc::new(Semaphore::new(64));
    let observer = udp.clone();
    let receives = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = receives.clone();
    let mut service = Box::pin(futures::future::join(
        listener::udp_loop_observed(udp, ctx.clone(), backend.clone(), move |_| {
            observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }),
        listener::tcp_loop(
            tcp,
            ctx,
            backend.clone(),
            Arc::new(Semaphore::new(listener::MAX_TCP_CONNECTIONS)),
        ),
    ));
    let cases = async {
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let req = request("recursive.example.", RecordType::TXT, 417);
        let reply = udp_exchange(&client, addr, &req).await;
        assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(reply.metadata.id, 417);
        assert_eq!(backend.available_permits(), 64);
        let mut peer = TcpStream::connect(addr).await.unwrap();
        let reply = tcp_exchange(&mut peer, &req).await;
        assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(backend.available_permits(), 64);
        assert_eq!(
            receives.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "no nested DNS received during either exchange"
        );
        let mut bytes = vec![0; 65535];
        assert_eq!(
            observer.try_recv_from(&mut bytes).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "self-upstream guard must leave no nested DNS datagram"
        );
    };
    tokio::select! { _ = &mut service => panic!("listener ended"), _ = cases => {} }
}

#[tokio::test]
async fn unsupported_opcodes_and_transfers_udp_tcp_notimp_without_backend_work() {
    let (udp, tcp) = bind_pair("127.0.0.1:0").await.unwrap();
    let addr = udp.local_addr().unwrap();
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let context = ctx(
        vec![DnsOverride {
            pattern: "*".into(),
            resolver: OverrideResolver::Dns {
                server: upstream.local_addr().unwrap(),
            },
        }],
        vec![addr],
    );
    let backend = Arc::new(Semaphore::new(64));
    let mut service = Box::pin(futures::future::join(
        listener::udp_loop(Arc::new(udp), context.clone(), backend.clone()),
        listener::tcp_loop(
            tcp,
            context,
            backend.clone(),
            Arc::new(Semaphore::new(listener::MAX_TCP_CONNECTIONS)),
        ),
    ));
    let cases = async {
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut peer = TcpStream::connect(addr).await.unwrap();
        for (host, kind, opcode) in [
            ("localhost.", RecordType::A, OpCode::Status),
            ("external.example.", RecordType::TXT, OpCode::Notify),
            ("external.example.", RecordType::TXT, OpCode::Update),
            ("localhost.", RecordType::AXFR, OpCode::Query),
            ("external.example.", RecordType::IXFR, OpCode::Query),
        ] {
            let mut req = request(host, kind, 512);
            req.metadata.op_code = opcode;
            req.metadata.authentic_data = true;
            for reply in [
                udp_exchange(&client, addr, &req).await,
                tcp_exchange(&mut peer, &req).await,
            ] {
                assert_eq!(reply.metadata.response_code, ResponseCode::NotImp);
                assert_eq!(reply.metadata.id, 512);
                assert_eq!(reply.metadata.op_code, opcode);
                assert_eq!(reply.queries, req.queries);
                assert!(reply.answers.is_empty());
                assert!(!reply.metadata.authentic_data);
                assert_eq!(backend.available_permits(), 64);
            }
            assert_eq!(
                upstream.try_recv_from(&mut [0; 512]).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
        // QR=1 is still rejected, even when its opcode/type is unsupported.
        let mut response_packet = request("external.example.", RecordType::AXFR, 513);
        response_packet.metadata.message_type = MessageType::Response;
        response_packet.metadata.op_code = OpCode::Status;
        assert!(wire::parse_query(&response_packet.to_vec().unwrap()).is_none());
        // The same TCP session remains usable for ordinary local queries.
        let reply = tcp_exchange(&mut peer, &request("localhost.", RecordType::A, 514)).await;
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert_eq!(
            reply.answers[0].data,
            RData::A(A("127.0.0.1".parse().unwrap()))
        );
    };
    tokio::select! { _ = &mut service => panic!("listener ended"), _ = cases => {} }
}

#[tokio::test]
async fn own_nonloopback_ptr_listener_nodata_then_explicit_upstream_override() {
    let own_name = "8.2.0.192.in-addr.arpa.";
    let unrelated = "1.0.0.10.in-addr.arpa.";
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server = upstream.local_addr().unwrap();
    for explicit in [false, true] {
        let (udp, tcp) = bind_pair("127.0.0.1:0").await.unwrap();
        let addr = udp.local_addr().unwrap();
        let mut endpoints = vec![addr];
        // Model an additional non-loopback bind without requiring a particular
        // CI interface; the policy is exercised through real UDP/TCP listeners.
        endpoints.push("192.0.2.8:15353".parse().unwrap());
        let mut overrides = vec![DnsOverride {
            pattern: unrelated.trim_end_matches('.').into(),
            resolver: OverrideResolver::Dns { server },
        }];
        if explicit {
            overrides.push(DnsOverride {
                pattern: own_name.trim_end_matches('.').into(),
                resolver: OverrideResolver::Dns { server },
            });
        }
        let context = ctx(overrides, endpoints);
        let backend = Arc::new(Semaphore::new(64));
        let mut service = Box::pin(futures::future::join(
            listener::udp_loop(Arc::new(udp), context.clone(), backend.clone()),
            listener::tcp_loop(
                tcp,
                context,
                backend.clone(),
                Arc::new(Semaphore::new(listener::MAX_TCP_CONNECTIONS)),
            ),
        ));
        let calls = Cell::new(0);
        let upstream_loop = async {
            let mut bytes = vec![0; 4096];
            loop {
                let (len, peer) = upstream.recv_from(&mut bytes).await.unwrap();
                calls.set(calls.get() + 1);
                let req = Message::from_vec(&bytes[..len]).unwrap();
                assert_eq!(req.queries[0].query_type(), RecordType::PTR);
                assert!(
                    explicit
                        || wire::hostname_of(&req.queries[0]) == unrelated.trim_end_matches('.')
                );
                upstream
                    .send_to(&upstream_reply(&req).to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        };
        let cases = async {
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut peer = TcpStream::connect(addr).await.unwrap();
            let req = request(own_name, RecordType::PTR, 815);
            for reply in [
                udp_exchange(&client, addr, &req).await,
                tcp_exchange(&mut peer, &req).await,
            ] {
                assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
                assert_eq!(reply.metadata.id, 815);
                if explicit {
                    assert_eq!(reply.answers[1].data, upstream_data(RecordType::PTR));
                } else {
                    assert!(reply.answers.is_empty());
                    assert_eq!(
                        calls.get(),
                        0,
                        "own PTR without override is immediate NODATA"
                    );
                }
                assert_eq!(backend.available_permits(), 64);
            }
            let reply =
                udp_exchange(&client, addr, &request(unrelated, RecordType::PTR, 816)).await;
            assert_eq!(reply.answers[1].data, upstream_data(RecordType::PTR));
            assert_eq!(
                calls.get(),
                if explicit { 2 } else { 1 },
                "unrelated private PTR retains routing; explicit own result is cached"
            );
        };
        tokio::select! { _ = &mut service => panic!("listener ended"), _ = upstream_loop => panic!("upstream ended"), _ = cases => {} }
    }
}

/// Counterfactual: preflight after cache returns poisoned PTR; after admission
/// returns SERVFAIL with all 64 slots occupied. Both UDP and TCP must bypass.
#[tokio::test]
async fn wildcard_own_ptr_udp_tcp_bypasses_full_backend_and_cached_poison() {
    timeout(Duration::from_secs(15), async {
        let ip = std::net::Ipv4Addr::new(192, 0, 2, 8);
        let (udp, tcp) = bind_pair("0.0.0.0:0").await.unwrap();
        let bound = udp.local_addr().unwrap();
        let addr = SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            bound.port(),
        );
        let mut context = ctx(vec![], listener_endpoints(&udp, &tcp).unwrap());
        context.route_probe = Arc::new(move |target| {
            assert_eq!(target, std::net::IpAddr::V4(ip));
            Box::pin(std::future::ready(Some(target)))
        });
        let host = ip
            .octets()
            .iter()
            .rev()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(".")
            + ".in-addr.arpa.";
        let req = request(&host, RecordType::PTR, 817);
        context.cache.insert(
            &req.queries[0],
            &ResolvedAnswer {
                message: upstream_reply(&req),
                ttl: Duration::from_secs(60),
                resolved_at: time::OffsetDateTime::now_utc(),
            },
        );
        assert!(context.cache.get(&req.queries[0]).is_some());
        let backend = Arc::new(Semaphore::new(64));
        let _full = backend.clone().acquire_many_owned(64).await.unwrap();
        let mut service = Box::pin(futures::future::join(
            listener::udp_loop(Arc::new(udp), context.clone(), backend.clone()),
            listener::tcp_loop(
                tcp,
                context,
                backend.clone(),
                Arc::new(Semaphore::new(listener::MAX_TCP_CONNECTIONS)),
            ),
        ));
        let cases = async {
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut peer = TcpStream::connect(addr).await.unwrap();
            for _ in 0..100 {
                for reply in [
                    udp_exchange(&client, addr, &req).await,
                    tcp_exchange(&mut peer, &req).await,
                ] {
                    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
                    assert!(
                        reply.answers.is_empty(),
                        "local policy must precede poisoned cache"
                    );
                    assert_eq!(backend.available_permits(), 0);
                }
            }
        };
        tokio::select! { _ = &mut service => panic!("listener ended"), _ = cases => {} }
    })
    .await
    .expect("wildcard PTR full-backend fixture exceeded outer bound");
}

#[tokio::test]
async fn normalized_first_override_and_local_before_cached_poison() {
    let entries = vec![
        DnsOverride {
            pattern: "MiXeD.Example".into(),
            resolver: OverrideResolver::Dns {
                server: "192.0.2.1:53".parse().unwrap(),
            },
        },
        DnsOverride {
            pattern: "*".into(),
            resolver: OverrideResolver::System,
        },
    ];
    let q = question("MIXED.EXAMPLE.", RecordType::TXT);
    let host = wire::hostname_of(&q);
    assert_eq!(find_override(&entries, &host), Some(&entries[0]));
    let ctx = ctx(entries, vec![]);
    let req = request("localhost.", RecordType::A, 1);
    ctx.cache.insert(
        &req.queries[0],
        &ResolvedAnswer {
            message: upstream_reply(&req),
            ttl: Duration::from_secs(60),
            resolved_at: time::OffsetDateTime::now_utc(),
        },
    );
    let answer = inline_answer(&ctx, &req.queries[0]).await.unwrap();
    assert_eq!(answer.message.answers.len(), 1);
    assert_eq!(
        answer.message.answers[0].data,
        RData::A(A("127.0.0.1".parse().unwrap()))
    );
}

// UDP selects the endpoint first. Retry only a port collision, on a random
// dynamic port: the OS hands out ephemeral ports almost sequentially, so
// retrying port 0 stays inside one reserved band (Windows WSAEACCES on a
// TCP-only block). Option setters, listen, conversion and all other errors
// propagate.
fn explicit_ipv6_pair(udp_only: bool, tcp_only: bool) -> std::io::Result<(UdpSocket, TcpListener)> {
    use socket2::{Domain, Protocol, Socket, Type};
    let collision = |error: &std::io::Error| {
        error.kind() == std::io::ErrorKind::AddrInUse
            || (cfg!(windows) && error.raw_os_error() == Some(10013))
    };
    let mut port = 0;
    for attempt in 0..16 {
        let last = attempt == 15;
        let udp = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        udp.set_only_v6(udp_only)?;
        let want = SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port));
        if let Err(error) = udp.bind(&want.into()) {
            if port == 0 || !collision(&error) || last {
                return Err(error);
            }
            port = random_dynamic_port();
            continue;
        }
        udp.set_nonblocking(true)?;
        let udp = UdpSocket::from_std(udp.into())?;
        let bound = udp.local_addr()?;
        let tcp = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
        tcp.set_only_v6(tcp_only)?;
        if let Err(error) = tcp.bind(&bound.into()) {
            if !collision(&error) || last {
                return Err(error);
            }
            port = random_dynamic_port();
            continue;
        }
        tcp.listen(8)?;
        tcp.set_nonblocking(true)?;
        return Ok((udp, TcpListener::from_std(tcp.into())?));
    }
    unreachable!("final matching-port collision returns its original error")
}

// Counterfactual: inferring IPv4 coverage from the address alone makes the
// v6-only case suppress IPv4 PTR; ignoring only_v6 loses dual-stack coverage.
// Unsupported socket options/binds fail explicitly, never pass by skipping.
#[tokio::test]
async fn actual_ipv6_socket_options_define_udp_tcp_local_coverage() {
    for udp_only in [true, false] {
        for tcp_only in [true, false] {
            let (udp, tcp) = explicit_ipv6_pair(udp_only, tcp_only)
                .expect("host must support explicit UDP/TCP IPV6_V6ONLY and matching bind");
            let bound = udp.local_addr().unwrap();
            assert_eq!(
                socket_options::only_v6(&socket2::SockRef::from(&udp)).unwrap(),
                udp_only
            );
            assert_eq!(
                socket_options::only_v6(&socket2::SockRef::from(&tcp)).unwrap(),
                tcp_only
            );
            let endpoints = listener_endpoints(&udp, &tcp).unwrap();
            let v4 = SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, bound.port()));
            assert_eq!(
                endpoints.iter().filter(|e| **e == v4).count(),
                usize::from(!udp_only) + usize::from(!tcp_only)
            );
            assert_eq!(endpoints.iter().filter(|e| **e == bound).count(), 2);
            let q = question("8.2.0.192.in-addr.arpa.", RecordType::PTR);
            let result =
                local::preflight_with_probe(&q, &wire::hostname_of(&q), &endpoints, false, |ip| {
                    std::future::ready(Some(ip))
                })
                .await;
            assert_eq!(result.is_some(), !udp_only || !tcp_only);
            let v6 = std::net::SocketAddr::new(std::net::Ipv6Addr::LOCALHOST.into(), bound.port());
            // Feed the same actual socket-derived coverage to the production
            // recursion guard, not a separately reconstructed endpoint list.
            let route_local = "192.0.2.9".parse().unwrap();
            assert_eq!(
                crate::overrides::self_reference_for_test(
                    SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, bound.port())),
                    &endpoints,
                    route_local,
                ),
                !udp_only || !tcp_only,
                "IPv4 recursion coverage: UDP only_v6={udp_only}, TCP only_v6={tcp_only}"
            );
            assert!(crate::overrides::self_reference_for_test(
                v6,
                &endpoints,
                std::net::Ipv6Addr::LOCALHOST.into(),
            ));
            for (remote, source) in [
                ("192.0.2.8", route_local),
                ("2001:db8::8", "2001:db8::9".parse().unwrap()),
            ] {
                assert!(
                    !crate::overrides::self_reference_for_test(
                        SocketAddr::new(remote.parse().unwrap(), bound.port()),
                        &endpoints,
                        source,
                    ),
                    "remote same-port upstream must not be local: {remote}"
                );
            }
            let mut context = ctx(vec![], endpoints);
            context.route_probe = Arc::new(|ip| Box::pin(std::future::ready(Some(ip))));
            let backend = Arc::new(Semaphore::new(64));
            let _full = backend.clone().acquire_many_owned(64).await.unwrap();
            let mut service = Box::pin(futures::future::join(
                listener::udp_loop(Arc::new(udp), context.clone(), backend.clone()),
                listener::tcp_loop(tcp, context, backend.clone(), Arc::new(Semaphore::new(64))),
            ));
            let cases = async {
                let client = UdpSocket::bind("[::1]:0").await.unwrap();
                let mut peer = TcpStream::connect(v6).await.unwrap();
                let req = request("8.2.0.192.in-addr.arpa.", RecordType::PTR, 818);
                for reply in [
                    udp_exchange(&client, v6, &req).await,
                    tcp_exchange(&mut peer, &req).await,
                ] {
                    assert_eq!(
                        reply.metadata.response_code,
                        if !udp_only || !tcp_only {
                            ResponseCode::NoError
                        } else {
                            ResponseCode::ServFail
                        }
                    );
                    assert!(reply.answers.is_empty());
                    assert_eq!(backend.available_permits(), 0);
                }
            };
            timeout(CASE_BUDGET, async {
                tokio::select! { _ = &mut service => panic!("listener ended"), _ = cases => {} }
            })
            .await
            .expect("IPv6 UDP/TCP coverage fixture exceeded bound");
        }
    }
}

// Counterfactual: accepting any route source suppresses remote PTR; ignoring an
// explicit override suppresses its cached answer even with admission saturated.
// After release, fresh wildcard PTR questions must reach the actual upstream.
#[tokio::test]
async fn wildcard_routed_remote_and_explicit_override_retain_cached_answers() {
    for explicit in [false, true] {
        let (udp, tcp) = bind_pair("0.0.0.0:0").await.unwrap();
        let bound = udp.local_addr().unwrap();
        let addr = SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), bound.port());
        let req = request("8.2.0.192.in-addr.arpa.", RecordType::PTR, 819);
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let calls = Cell::new(0);
        let entries = if explicit {
            vec![DnsOverride {
                pattern: "*.in-addr.arpa".into(),
                resolver: OverrideResolver::Dns {
                    server: upstream.local_addr().unwrap(),
                },
            }]
        } else {
            vec![]
        };
        let mut context = ctx(entries, listener_endpoints(&udp, &tcp).unwrap());
        context.route_probe = Arc::new(move |_| {
            assert!(!explicit, "explicit override must bypass route probe");
            Box::pin(std::future::ready(Some("192.0.2.9".parse().unwrap())))
        });
        context.cache.insert(
            &req.queries[0],
            &ResolvedAnswer {
                message: upstream_reply(&req),
                ttl: Duration::from_secs(60),
                resolved_at: time::OffsetDateTime::now_utc(),
            },
        );
        assert!(context.cache.get(&req.queries[0]).is_some());
        let backend = Arc::new(Semaphore::new(64));
        let _full = backend.clone().acquire_many_owned(64).await.unwrap();
        let mut service = Box::pin(futures::future::join(
            listener::udp_loop(Arc::new(udp), context.clone(), backend.clone()),
            listener::tcp_loop(tcp, context, backend.clone(), Arc::new(Semaphore::new(64))),
        ));
        let cases = async {
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut peer = TcpStream::connect(addr).await.unwrap();
            for reply in [
                udp_exchange(&client, addr, &req).await,
                tcp_exchange(&mut peer, &req).await,
            ] {
                assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
                assert_eq!(reply.answers[1].data, upstream_data(RecordType::PTR));
                assert_eq!(backend.available_permits(), 0);
            }
            assert_eq!(calls.get(), 0, "saturated phase must use cached payload");
            drop(_full);
            if explicit {
                // Separate uncached names prove both client transports route,
                // rather than letting the second exchange use the first cache hit.
                for (host, via_tcp) in [
                    ("9.2.0.192.in-addr.arpa.", false),
                    ("10.2.0.192.in-addr.arpa.", true),
                ] {
                    let fresh = request(host, RecordType::PTR, 820);
                    let reply = if via_tcp {
                        tcp_exchange(&mut peer, &fresh).await
                    } else {
                        udp_exchange(&client, addr, &fresh).await
                    };
                    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
                    assert_eq!(reply.answers[1].data, upstream_data(RecordType::PTR));
                    assert_eq!(backend.available_permits(), 64);
                }
                assert_eq!(
                    calls.get(),
                    2,
                    "UDP and TCP misses must reach actual upstream"
                );
            }
        };
        let upstream_loop = async {
            let mut bytes = vec![0; 65535];
            loop {
                let (len, peer) = upstream.recv_from(&mut bytes).await.unwrap();
                calls.set(calls.get() + 1);
                let req = Message::from_vec(&bytes[..len]).unwrap();
                assert!(explicit, "remote cached fixture unexpectedly routed");
                upstream
                    .send_to(&upstream_reply(&req).to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        };
        timeout(CASE_BUDGET, async {
            tokio::select! {
                _ = &mut service => panic!("listener ended"),
                _ = upstream_loop => panic!("upstream ended"),
                _ = cases => {}
            }
        })
        .await
        .expect("routed remote/override fixture exceeded bound");
    }
}
