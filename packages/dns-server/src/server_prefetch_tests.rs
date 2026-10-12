//! Production refresh seam with real plain-DNS upstreams and scoped barriers.
use super::*;

#[test]
fn run_and_refresh_remain_send_with_non_sync_factory() {
    fn send<T: Send>(_: T) {}
    let cell = std::cell::Cell::new(0_u64);
    let factory = move || {
        cell.set(cell.get().saturating_add(1));
        std::future::ready(None)
    };
    let context = QueryCtx {
        tunnel: factory.clone(),
        cache: Arc::new(DnsCache::new()),
        providers: Arc::new(vec![]),
        overrides: Arc::new(vec![]),
        endpoints: Arc::new(vec![]),
        route_probe: local::route_probe(),
        statistics: None,
    };
    send(refresh_question(
        context,
        question("send.example.", RecordType::A),
        Arc::new(Semaphore::new(64)),
    ));
    send(run(
        &[],
        factory,
        Arc::new(DnsCache::new()),
        vec![],
        vec![],
        PathBuf::new(),
        CancellationToken::new(),
    ));
}

fn changed_reply(req: &Message) -> Message {
    let mut reply = upstream_reply(req);
    for record in reply.answers.iter_mut().chain(&mut reply.authorities) {
        record.ttl = 17;
        if record.record_type() == req.queries[0].query_type() {
            record.data = match req.queries[0].query_type() {
                RecordType::A => RData::A(A("192.0.2.99".parse().unwrap())),
                RecordType::AAAA => RData::AAAA(AAAA("2001:db8::99".parse().unwrap())),
                RecordType::TXT => RData::TXT(TXT::new(vec![if req.queries[0].query_class()
                    == hickory_proto::rr::DNSClass::CH
                {
                    "chaos-refreshed".into()
                } else {
                    "refreshed".into()
                }])),
                RecordType::HTTPS => RData::HTTPS(HTTPS(SVCB::new(
                    9,
                    Name::from_ascii("changed.example.").unwrap(),
                    vec![],
                ))),
                kind => upstream_data(kind),
            };
        }
    }
    reply
}

/// Counterfactual: using inline_answer returns the old fresh cache packet;
/// reconstructing addresses loses CNAME/TXT/HTTPS/SOA/NXDOMAIN; TTL inflation
/// or deleting valid entries on failure changes the explicit foreground reply.
#[tokio::test]
async fn real_udp_tcp_refresh_replaces_fresh_typed_alias_and_negative_answers() {
    timeout(CASE_BUDGET, async {
        let (upstream_udp, upstream_tcp) = bind_pair("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_udp.local_addr().unwrap();
        let (udp, tcp) = bind_pair("127.0.0.1:0").await.unwrap();
        let udp = Arc::new(udp);
        let addr = udp.local_addr().unwrap();
        let (dir, mut worker, handle) = statistics::store().await;
        let mut context = ctx(vec![DnsOverride { pattern: "*".into(), resolver: OverrideResolver::Dns { server: upstream_addr } }], vec![addr]);
        context.statistics = Some(handle);
        let backend = Arc::new(Semaphore::new(64));
        let mut listeners = Box::pin(futures::future::join(
            listener::udp_loop(udp, context.clone(), backend.clone()),
            listener::tcp_loop(tcp, context.clone(), backend.clone(), Arc::new(Semaphore::new(64))),
        ));
        let exchanges = std::cell::Cell::new(0_u64);
        let tcp_exchanges = std::cell::Cell::new(0_u64);
        let upstream = async {
            let mut bytes = vec![0; 65535];
            loop {
                let (len, peer) = upstream_udp.recv_from(&mut bytes).await.unwrap();
                let req = Message::from_vec(&bytes[..len]).unwrap();
                exchanges.set(exchanges.get() + 1);
                let mut truncated = changed_reply(&req);
                truncated.metadata.truncation = true;
                upstream_udp.send_to(&truncated.to_vec().unwrap(), peer).await.unwrap();
                let (mut stream, _) = upstream_tcp.accept().await.unwrap();
                let body = wire::read_framed_message(&mut stream, Duration::from_secs(5)).await.unwrap().unwrap();
                let tcp_req = Message::from_vec(&body).unwrap();
                tcp_exchanges.set(tcp_exchanges.get() + 1);
                assert_eq!(tcp_req.queries, req.queries);
                wire::write_framed_message(&mut stream, &changed_reply(&tcp_req).to_vec().unwrap(), Duration::from_secs(5)).await.unwrap();
            }
        };
        let mut upstream = Box::pin(upstream);
        let cases = async {
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut stream = TcpStream::connect(addr).await.unwrap();
            let cases = [
                ("popular.example.", RecordType::A),
                ("popular.example.", RecordType::AAAA),
                ("popular.example.", RecordType::TXT),
                ("popular.example.", RecordType::HTTPS),
                ("nx.example.", RecordType::A),
                ("nodata.example.", RecordType::AAAA),
            ];
            let mut requests = Vec::new();
            for (host, kind) in cases {
                requests.push(request(host, kind, 57));
            }
            let mut ch = request("popular.example.", RecordType::TXT, 58);
            ch.queries[0].set_query_class(hickory_proto::rr::DNSClass::CH);
            requests.push(ch);
            for req in &requests {
                context.cache.insert(&req.queries[0], &ResolvedAnswer { message: upstream_reply(req), ttl: Duration::from_secs(60), resolved_at: time::OffsetDateTime::now_utc() });
                for _ in 0..101 { udp_exchange(&client, addr, req).await; }
            }
            assert_eq!(exchanges.get(), 0, "seeding uses actual inbound cache hits");
            // Startup scheduler consumes the persistent observations. The barrier
            // is emitted only AFTER production resolve_miss inserted the answer.
            let stop = CancellationToken::new();
            let (completed, mut completion) = tokio::sync::mpsc::channel(requests.len());
            let refresh_ctx = context.clone();
            let refresh_backend = backend.clone();
            let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let active_refresh = active.clone();
            let mut scheduler = Box::pin(crate::popular_prefetch::run(&mut worker, move |q| {
                let ctx = refresh_ctx.clone();
                let backend = refresh_backend.clone();
                let completed = completed.clone();
                let active = active_refresh.clone();
                async move {
                    assert_eq!(active.fetch_add(1, std::sync::atomic::Ordering::SeqCst), 0, "one sequential background exchange");
                    let answer = refresh_question(ctx, q.clone(), backend).await;
                    let fresh = answer.as_ref().expect("real upstream refresh succeeded");
                    assert_eq!(fresh.ttl, Duration::from_secs(17));
                    assert!(fresh.message.answers.iter().chain(&fresh.message.authorities).all(|rr| rr.ttl == 17));
                    active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                    completed.send(q).await.unwrap();
                    answer
                }
            }, stop.clone()));
            let barriers = async {
                for _ in 0..requests.len() { completion.recv().await.unwrap(); }
            };
            tokio::select! { result = &mut scheduler => panic!("scheduler ended: {result:?}"), _ = barriers => {} }
            stop.cancel();
            scheduler.as_mut().await.unwrap();
            drop(scheduler);
            assert_eq!(active.load(std::sync::atomic::Ordering::SeqCst), 0);
            assert_eq!(exchanges.get(), 7);
            assert_eq!(tcp_exchanges.get(), 7);
            let snapshot = worker.refresh().await.unwrap();
            let targets = snapshot.page(None).await.unwrap();
            assert_eq!(targets.len(), 7);
            assert!(targets.iter().all(|target| target.count == 101), "prefetch is not client traffic");
            for req in &requests {
                let kind = req.queries[0].query_type();
                let negative = req.queries[0].name().to_ascii().starts_with("nx.") || req.queries[0].name().to_ascii().starts_with("nodata.");
                let expected = match kind {
                    RecordType::A => RData::A(A("192.0.2.99".parse().unwrap())),
                    RecordType::AAAA => RData::AAAA(AAAA("2001:db8::99".parse().unwrap())),
                    RecordType::TXT => RData::TXT(TXT::new(vec![if req.queries[0].query_class() == hickory_proto::rr::DNSClass::CH { "chaos-refreshed".into() } else { "refreshed".into() }])),
                    RecordType::HTTPS => RData::HTTPS(HTTPS(SVCB::new(9, Name::from_ascii("changed.example.").unwrap(), vec![]))),
                    _ => unreachable!("closed fixture corpus"),
                };
                let hit = context.cache.get(&req.queries[0]).unwrap();
                assert!(hit.ttl <= Duration::from_secs(17) && !hit.ttl.is_zero());
                for reply in [udp_exchange(&client, addr, req).await, tcp_exchange(&mut stream, req).await] {
                    assert_eq!(reply.metadata.response_code, if req.queries[0].name().to_ascii().starts_with("nx.") { ResponseCode::NXDomain } else { ResponseCode::NoError });
                    assert_eq!(reply.answers.len(), if negative { 0 } else { 2 });
                    if !negative {
                        assert_eq!(reply.answers[0].data, RData::CNAME(CNAME(Name::from_ascii("target.example.").unwrap())));
                        assert_eq!(reply.answers[1].data, expected);
                    }
                    assert_eq!(reply.authorities.len(), 1);
                    assert!(matches!(reply.authorities[0].data, RData::SOA(_)));
                    assert!(reply.answers.iter().chain(&reply.authorities).all(|rr| rr.ttl <= 17 && rr.dns_class == req.queries[0].query_class()));
                }
            }
            assert_eq!(exchanges.get(), 7, "subsequent UDP/TCP are cache hits, not extra exchanges");
            assert_eq!(tcp_exchanges.get(), 7, "no extra TCP upstream exchange on foreground hits");
        };
        tokio::select! { _ = &mut listeners => panic!("listener ended"), _ = &mut upstream => panic!("upstream ended"), _ = cases => {} }
        drop(listeners);
        drop(upstream);
        assert_eq!(backend.available_permits(), 64);
        worker.shutdown().await.unwrap();
        tokio::fs::remove_dir_all(dir).await.unwrap();
    }).await.unwrap();
}

/// Counterfactual: waiting for Tor inside a listener or taking the last slot
/// prevents foreground cache/local and another miss from completing. Detached
/// background resolution retains its slot after cancellation.
#[tokio::test]
async fn gated_background_leaves_foreground_responsive_and_cancel_releases_permit() {
    timeout(CASE_BUDGET, async {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let (udp, tcp) = bind_pair("127.0.0.1:0").await.unwrap();
        let udp = Arc::new(udp);
        let addr = udp.local_addr().unwrap();
        let (entered, mut observed) = tokio::sync::mpsc::channel(1);
        let context = QueryCtx {
            tunnel: move || {
                let entered = entered.clone();
                async move {
                    entered.send(()).await.unwrap();
                    std::future::pending::<Option<TorTunnel>>().await
                }
            },
            cache: Arc::new(DnsCache::new()),
            providers: Arc::new(vec![]),
            overrides: Arc::new(vec![DnsOverride { pattern: "foreground.example".into(), resolver: OverrideResolver::Dns { server: upstream_addr } }]),
            endpoints: Arc::new(vec![addr]),
            route_probe: local::route_probe(),
            statistics: None,
        };
        let warm = request("cached.example.", RecordType::TXT, 5);
        context.cache.insert(&warm.queries[0], &ResolvedAnswer { message: upstream_reply(&warm), ttl: Duration::from_secs(60), resolved_at: time::OffsetDateTime::now_utc() });
        let backend = Arc::new(Semaphore::new(2));
        let mut background = Box::pin(refresh_question(context.clone(), question("background.example.", RecordType::A), backend.clone()));
        tokio::select! { _ = &mut background => panic!("background ended"), _ = observed.recv() => {} }
        assert_eq!(backend.available_permits(), 1);
        let mut listeners = Box::pin(futures::future::join(
            listener::udp_loop(udp, context.clone(), backend.clone()),
            listener::tcp_loop(tcp, context, backend.clone(), Arc::new(Semaphore::new(64))),
        ));
        let upstream_work = async {
            let mut bytes = vec![0; 65535];
            let (len, peer) = upstream.recv_from(&mut bytes).await.unwrap();
            let req = Message::from_vec(&bytes[..len]).unwrap();
            upstream.send_to(&upstream_reply(&req).to_vec().unwrap(), peer).await.unwrap();
            std::future::pending::<()>().await;
        };
        let mut upstream_work = Box::pin(upstream_work);
        let cases = async {
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut stream = TcpStream::connect(addr).await.unwrap();
            assert_eq!(udp_exchange(&client, addr, &request("localhost.", RecordType::A, 1)).await.metadata.response_code, ResponseCode::NoError);
            assert_eq!(tcp_exchange(&mut stream, &warm).await.metadata.response_code, ResponseCode::NoError);
            assert_eq!(udp_exchange(&client, addr, &request("foreground.example.", RecordType::TXT, 2)).await.metadata.response_code, ResponseCode::NoError);
        };
        tokio::select! { _ = &mut background => panic!("background ended"), _ = &mut listeners => panic!("listener ended"), _ = &mut upstream_work => panic!("upstream ended"), _ = cases => {} }
        assert_eq!(backend.available_permits(), 1);
        drop(background);
        drop(listeners);
        drop(upstream_work);
        assert_eq!(backend.available_permits(), 2);
    }).await.unwrap();
}

/// Counterfactual: deadline only wraps exchange, omitting acquisition; a
/// timed-out refresh leaks its owned permit or replaces a previously valid hit.
#[tokio::test(start_paused = true)]
async fn expired_refresh_deadline_drops_pending_acquisition_and_preserves_cache() {
    // No sockets: virtual time proves the real whole-resolution deadline.
    {
        let (entered, mut observed) = tokio::sync::mpsc::channel(1);
        let context = QueryCtx {
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
            endpoints: Arc::new(vec![]),
            route_probe: local::route_probe(),
            statistics: None,
        };
        let req = request("deadline.example.", RecordType::A, 1);
        context.cache.insert(
            &req.queries[0],
            &ResolvedAnswer {
                message: upstream_reply(&req),
                ttl: Duration::from_secs(60),
                resolved_at: time::OffsetDateTime::now_utc(),
            },
        );
        let backend = Arc::new(Semaphore::new(64));
        let mut refresh = Box::pin(refresh_question_until(
            context.clone(),
            req.queries[0].clone(),
            backend.clone(),
            Instant::now() + RESOLUTION_TIMEOUT,
        ));
        tokio::select! { _ = &mut refresh => panic!("refresh ended before acquisition barrier"), _ = observed.recv() => {} }
        assert_eq!(backend.available_permits(), 63);
        tokio::time::advance(RESOLUTION_TIMEOUT).await;
        assert!(refresh.await.is_none());
        assert_eq!(backend.available_permits(), 64);
        assert_eq!(
            context.cache.get(&req.queries[0]).unwrap().message.answers[1].data,
            upstream_data(RecordType::A)
        );
    }
}

/// Counterfactual: failure inserts fake NODATA/deletes the fresh answer; routing
/// refresh through cache prevents a later recovered upstream from being used.
#[tokio::test]
async fn unavailable_tor_and_expired_admission_keep_cache_then_next_refresh_recovers() {
    timeout(CASE_BUDGET, async {
        let req = request("recover.example.", RecordType::A, 1);
        let context = QueryCtx {
            tunnel: || std::future::ready(None),
            cache: Arc::new(DnsCache::new()),
            providers: Arc::new(vec![]),
            overrides: Arc::new(vec![]),
            endpoints: Arc::new(vec![]),
            route_probe: local::route_probe(),
            statistics: None,
        };
        context.cache.insert(
            &req.queries[0],
            &ResolvedAnswer {
                message: upstream_reply(&req),
                ttl: Duration::from_secs(60),
                resolved_at: time::OffsetDateTime::now_utc(),
            },
        );
        let backend = Arc::new(Semaphore::new(64));
        assert!(
            refresh_question(context.clone(), req.queries[0].clone(), backend.clone())
                .await
                .is_none()
        );
        assert!(refresh_question_until(
            context.clone(),
            req.queries[0].clone(),
            Arc::new(Semaphore::new(1)),
            Instant::now()
        )
        .await
        .is_none());
        assert_eq!(
            context.cache.get(&req.queries[0]).unwrap().message.answers[1].data,
            upstream_data(RecordType::A)
        );
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = upstream.local_addr().unwrap();
        let failed_tcp = TcpListener::bind(server).await.unwrap();
        let mut recovered = context;
        recovered.overrides = Arc::new(vec![DnsOverride {
            pattern: "*".into(),
            resolver: OverrideResolver::Dns { server },
        }]);
        let failure = async {
            let mut bytes = vec![0; 65535];
            let (len, peer) = upstream.recv_from(&mut bytes).await.unwrap();
            let req = Message::from_vec(&bytes[..len]).unwrap();
            let mut tc = upstream_reply(&req);
            tc.metadata.truncation = true;
            upstream.send_to(&tc.to_vec().unwrap(), peer).await.unwrap();
            let (mut stream, _) = failed_tcp.accept().await.unwrap();
            wire::read_framed_message(&mut stream, Duration::from_secs(5))
                .await
                .unwrap()
                .unwrap();
            // A real TCP transport fails after accepting its complete request.
            drop(stream);
        };
        let (failed, ()) = tokio::join!(
            refresh_question(recovered.clone(), req.queries[0].clone(), backend.clone()),
            failure
        );
        assert!(failed.is_none());
        let retained = recovered.cache.get(&req.queries[0]).unwrap();
        assert_eq!(
            retained.message.answers[1].data,
            RData::A(A("192.0.2.17".parse().unwrap()))
        );
        assert!(retained.ttl <= Duration::from_secs(60) && !retained.ttl.is_zero());
        assert_eq!(backend.available_permits(), 64);
        drop(failed_tcp);
        let upstream_work = async {
            let mut bytes = vec![0; 65535];
            let (len, peer) = upstream.recv_from(&mut bytes).await.unwrap();
            let req = Message::from_vec(&bytes[..len]).unwrap();
            upstream
                .send_to(&changed_reply(&req).to_vec().unwrap(), peer)
                .await
                .unwrap();
        };
        let (answer, ()) = tokio::join!(
            refresh_question(recovered.clone(), req.queries[0].clone(), backend.clone()),
            upstream_work
        );
        assert_eq!(
            answer.unwrap().message.answers[1].data,
            RData::A(A("192.0.2.99".parse().unwrap()))
        );
        assert_eq!(
            recovered
                .cache
                .get(&req.queries[0])
                .unwrap()
                .message
                .answers[1]
                .data,
            RData::A(A("192.0.2.99".parse().unwrap()))
        );
        assert_eq!(backend.available_permits(), 64);
    })
    .await
    .unwrap();
}
