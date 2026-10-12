//! Listener accounting at the real UDP/TCP boundary, not backend invocations.
use super::*;
use crate::query_statistics::{StatisticsPaths, StatisticsWorker};
use hickory_proto::rr::DNSClass;

pub(super) async fn store() -> (
    PathBuf,
    StatisticsWorker,
    crate::query_statistics::QueryStatistics,
) {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "dns-listener-statistics-{}-{id}",
        std::process::id()
    ));
    tokio::fs::create_dir(&dir).await.unwrap();
    let (handle, worker) =
        StatisticsWorker::open(StatisticsPaths::from_cache_path(&dir.join("cache.bin")))
            .await
            .unwrap();
    (dir, worker, handle)
}

/// Counterfactual: count only cacheable/successful backend results drops valid
/// terminal REFUSED packets; counting retry attempts would inflate requests.
#[tokio::test]
async fn real_upstream_terminal_refused_counts_udp_and_tcp_requests() {
    timeout(Duration::from_secs(5), async {
        let (dir, mut worker, handle) = store().await;
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = upstream.local_addr().unwrap();
        let (udp, tcp) = bind_pair("127.0.0.1:0").await.unwrap();
        let udp = Arc::new(udp);
        let addr = udp.local_addr().unwrap();
        let mut context = ctx(vec![DnsOverride { pattern: "*".into(), resolver: OverrideResolver::Dns { server } }], vec![addr]);
        context.statistics = Some(handle);
        let mut loops = Box::pin(futures::future::join(
            listener::udp_loop(udp, context.clone(), Arc::new(Semaphore::new(64))),
            listener::tcp_loop(tcp, context, Arc::new(Semaphore::new(64)), Arc::new(Semaphore::new(64))),
        ));
        let fixture = async {
            let mut bytes = vec![0; 65535];
            loop {
                let (len, peer) = upstream.recv_from(&mut bytes).await.unwrap();
                let req = Message::from_vec(&bytes[..len]).unwrap();
                upstream.send_to(&upstream_reply(&req).to_vec().unwrap(), peer).await.unwrap();
            }
        };
        let mut fixture = Box::pin(fixture);
        let clients = async {
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut stream = TcpStream::connect(addr).await.unwrap();
            for id in 0..51 {
                let req = request("refused.example.", RecordType::TXT, id);
                assert_eq!(udp_exchange(&client, addr, &req).await.metadata.response_code, ResponseCode::Refused);
                assert_eq!(tcp_exchange(&mut stream, &req).await.metadata.response_code, ResponseCode::Refused);
            }
        };
        tokio::select! { _ = &mut loops => panic!("listener ended"), _ = &mut fixture => panic!("fixture ended"), _ = clients => {} }
        drop(loops);
        drop(fixture);
        let targets = worker.refresh().await.unwrap().page(None).await.unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].count, 102);
        assert_eq!(targets[0].question, question("refused.example.", RecordType::TXT));
        worker.shutdown().await.unwrap();
        tokio::fs::remove_dir_all(dir).await.unwrap();
    }).await.unwrap();
}

/// Precancelled startup republishes restored popularity and saves the cache.
/// This checks both outputs, not their relative publication order.
#[tokio::test]
async fn run_precancelled_republishes_restored_statistics_and_saves_cache() {
    timeout(Duration::from_secs(5), async {
        let (dir, worker, handle) = store().await;
        let cache_path = dir.join("cache.bin");
        let q = question("persist.example.", RecordType::A);
        for _ in 0..101 {
            handle.record(&q);
        }
        worker.shutdown().await.unwrap();
        drop(handle);
        let paths = StatisticsPaths::from_cache_path(&cache_path);
        tokio::fs::remove_file(&paths.snapshot).await.unwrap();
        let shutdown = CancellationToken::new();
        shutdown.cancel();
        run(
            &["127.0.0.1:0".into()],
            || std::future::ready(None),
            Arc::new(DnsCache::new()),
            vec![],
            vec![],
            cache_path.clone(),
            shutdown,
        )
        .await
        .unwrap();
        let popular = tokio::fs::read_to_string(paths.snapshot).await.unwrap();
        assert!(popular.starts_with("domain\tcount\trefreshed_at\n"));
        assert!(popular.contains("persist.example.\t101\t"));
        assert!(tokio::fs::metadata(cache_path).await.is_ok());
        tokio::fs::remove_dir_all(dir).await.unwrap();
    })
    .await
    .unwrap();
}

/// Counterfactual: saving cache before awaiting statistics drain makes the
/// cache-start receiver ready at the held-gate assertion (or loses drain-enter).
/// Real sockets remain active until cancellation; no sleep/paused socket clock.
#[tokio::test]
async fn owned_lifecycle_stops_network_then_drains_statistics_before_cache_save() {
    timeout(Duration::from_secs(5), async {
        use tokio::io::AsyncReadExt;
        use tokio::sync::oneshot;

        let (dir, worker, handle) = store().await;
        let cache_path = dir.join("cache.bin");
        let paths = StatisticsPaths::from_cache_path(&cache_path);
        let (udp, tcp) = bind_pair("127.0.0.1:0").await.unwrap();
        let addr = udp.local_addr().unwrap();
        let mut context = ctx(vec![], listener_endpoints(&udp, &tcp).unwrap());
        context.statistics = Some(handle.clone());
        let cache = context.cache.clone();
        let shutdown = CancellationToken::new();
        let (stopped_tx, stopped_rx) = oneshot::channel();
        let (entered_tx, entered_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let (cache_tx, mut cache_rx) = oneshot::channel();
        let mut cache_tx = Some(cache_tx);
        let service = serve_owned_lifecycle(
            (vec![Arc::new(udp)], vec![tcp]),
            context,
            Some(worker),
            shutdown.clone(),
            move |worker| async move {
                entered_tx.send(()).unwrap();
                release_rx.await.unwrap();
                worker.unwrap().shutdown().await
            },
            move || stopped_tx.send(()).unwrap(),
            || {
                // Observe invocation, not just completion or file existence.
                cache_tx
                    .take()
                    .expect("no periodic save in this bounded test")
                    .send(())
                    .unwrap();
                cache.save(&cache_path)
            },
        );
        let clients = async {
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut stream = TcpStream::connect(addr).await.unwrap();
            for id in 0..50 {
                let req = request("lifecycle.localhost.", RecordType::TXT, id);
                assert_eq!(
                    udp_exchange(&client, addr, &req)
                        .await
                        .metadata
                        .response_code,
                    ResponseCode::NoError
                );
                assert_eq!(
                    tcp_exchange(&mut stream, &req).await.metadata.response_code,
                    ResponseCode::NoError
                );
            }
            tcp_exchange(
                &mut stream,
                &request("lifecycle.localhost.", RecordType::TXT, 100),
            )
            .await;
            assert_eq!(handle.status().accepted, 101);
            shutdown.cancel();
            stopped_rx.await.unwrap();
            entered_rx.await.unwrap();
            // The helper has dropped its owned network future, including both
            // listeners and accepted connections, before entering the IO gate.
            let mut byte = [0];
            assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
            assert!(TcpStream::connect(addr).await.is_err());
            let rebound_udp = UdpSocket::bind(addr).await.unwrap();
            let rebound_tcp = TcpListener::bind(addr).await.unwrap();
            assert_eq!(
                cache_rx.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            );
            assert!(tokio::fs::metadata(&cache_path).await.is_err());
            drop((rebound_udp, rebound_tcp));
            release_tx.send(()).unwrap();
            cache_rx.await.unwrap();
            // Callback cannot run until the real worker shutdown has joined.
            let status = handle.status();
            assert_eq!(status.accepted, 101);
            assert_eq!(status.saved, 101);
            assert_eq!(
                (
                    status.expired,
                    status.unsaved,
                    status.pending,
                    status.dropped_full
                ),
                (0, 0, 0, 0)
            );
            assert!(status.last_error.is_none());
            let popular = tokio::fs::read_to_string(&paths.snapshot).await.unwrap();
            assert!(popular.starts_with("domain\tcount\trefreshed_at\n"));
            assert_eq!(popular.lines().count(), 2);
            assert!(popular
                .lines()
                .nth(1)
                .unwrap()
                .starts_with("lifecycle.localhost.\t101\t"));
            popular
        };
        let (result, popular) = tokio::join!(service, clients);
        result.unwrap();
        assert!(tokio::fs::metadata(&cache_path).await.is_ok());
        assert_eq!(
            tokio::fs::read_to_string(&paths.snapshot).await.unwrap(),
            popular
        );
        let database = paths.database.clone();
        let counts = tokio::task::spawn_blocking(move || {
            let db = rusqlite::Connection::open_with_flags(
                database,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .unwrap();
            let totals: (i64, i64, i64, i64) = db
                .query_row(
                    "SELECT accepted, saved, expired, unsaved FROM meta WHERE id=1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .unwrap();
            let retained: i64 = db
                .query_row("SELECT SUM(count) FROM query_seconds", [], |row| row.get(0))
                .unwrap();
            (totals, retained)
        })
        .await
        .unwrap();
        assert_eq!(counts, ((101, 101, 0, 0), 101));
        assert_eq!(handle.status().accepted, 101);
        assert_eq!(handle.status().pending, 0);
        drop(handle);
        tokio::fs::remove_dir_all(dir).await.unwrap();
    })
    .await
    .unwrap();
}

/// Counterfactual: malformed TCP input is retried or counted; only complete
/// supported questions before terminal disconnect enter the ledger.
#[tokio::test]
async fn malformed_tcp_is_terminal_and_not_counted() {
    timeout(Duration::from_secs(5), async {
        let (dir, mut worker, handle) = store().await;
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let mut context = ctx(vec![], vec![addr]);
        context.statistics = Some(handle);
        let mut service = Box::pin(listener::tcp_loop(
            tcp,
            context,
            Arc::new(Semaphore::new(0)),
            Arc::new(Semaphore::new(64)),
        ));
        let client = async {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            for id in 0..101 {
                tcp_exchange(&mut stream, &request("localhost.", RecordType::A, id)).await;
            }
            stream.write_all(&[0, 3, 0, 1, 2]).await.unwrap();
            use tokio::io::AsyncReadExt;
            let mut byte = [0];
            assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
        };
        tokio::select! { _ = &mut service => panic!("listener ended"), _ = client => {} }
        drop(service);
        let targets = worker.refresh().await.unwrap().page(None).await.unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].count, 101);
        worker.shutdown().await.unwrap();
        tokio::fs::remove_dir_all(dir).await.unwrap();
    })
    .await
    .unwrap();
}

/// Counterfactual: recording after cache/admission loses cache hits and overload;
/// recording before parse/support checks counts response garbage and transfers;
/// counting backend requests also incorrectly counts background refreshes.
#[tokio::test]
async fn udp_tcp_count_first_supported_question_once_before_cache_and_overload() {
    timeout(Duration::from_secs(5), async {
        let (dir, mut worker, handle) = store().await;
        let (udp, tcp) = bind_pair("127.0.0.1:0").await.unwrap();
        let udp = Arc::new(udp);
        let addr = udp.local_addr().unwrap();
        let mut context = ctx(vec![], vec![addr]);
        context.statistics = Some(handle);
        let warm = request("mixed.example.", RecordType::A, 1);
        context.cache.insert(
            &warm.queries[0],
            &ResolvedAnswer {
                message: upstream_reply(&warm),
                ttl: Duration::from_secs(60),
                resolved_at: time::OffsetDateTime::now_utc(),
            },
        );
        let mut loops = Box::pin(futures::future::join(
            listener::udp_loop(udp, context.clone(), Arc::new(Semaphore::new(0))),
            listener::tcp_loop(
                tcp,
                context,
                Arc::new(Semaphore::new(0)),
                Arc::new(Semaphore::new(64)),
            ),
        ));
        let clients = async {
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut stream = TcpStream::connect(addr).await.unwrap();
            for id in 0..51 {
                let mut cached = request("MiXeD.ExAmPlE.", RecordType::A, id);
                cached.add_query(question("ignored.example.", RecordType::A));
                assert_eq!(
                    udp_exchange(&client, addr, &cached)
                        .await
                        .metadata
                        .response_code,
                    ResponseCode::NoError
                );
                assert_eq!(
                    tcp_exchange(&mut stream, &cached)
                        .await
                        .metadata
                        .response_code,
                    ResponseCode::NoError
                );
            }
            for id in 0..101 {
                let mut overloaded = request("mixed.example.", RecordType::TXT, id);
                overloaded.queries[0].set_query_class(DNSClass::CH);
                assert_eq!(
                    udp_exchange(&client, addr, &overloaded)
                        .await
                        .metadata
                        .response_code,
                    ResponseCode::ServFail
                );
            }
            for id in 0..101 {
                let root = request(".", RecordType::AAAA, id);
                assert_eq!(
                    tcp_exchange(&mut stream, &root)
                        .await
                        .metadata
                        .response_code,
                    ResponseCode::ServFail
                );
            }
            for id in 0..101 {
                let terminal = request("negative.localhost.", RecordType::TXT, id);
                assert_eq!(
                    tcp_exchange(&mut stream, &terminal)
                        .await
                        .metadata
                        .response_code,
                    ResponseCode::NoError
                );
            }
            let mut unsupported = request("ignored.example.", RecordType::AXFR, 400);
            assert_eq!(
                udp_exchange(&client, addr, &unsupported)
                    .await
                    .metadata
                    .response_code,
                ResponseCode::NotImp
            );
            unsupported.queries[0].set_query_type(RecordType::A);
            unsupported.metadata.op_code = OpCode::Update;
            assert_eq!(
                tcp_exchange(&mut stream, &unsupported)
                    .await
                    .metadata
                    .response_code,
                ResponseCode::NotImp
            );
            let empty = Message::new(401, MessageType::Query, OpCode::Query);
            assert_eq!(
                udp_exchange(&client, addr, &empty)
                    .await
                    .metadata
                    .response_code,
                ResponseCode::FormErr
            );
            client.send_to(&[0, 1, 2], addr).await.unwrap();
            let mut garbage = request("ignored.example.", RecordType::A, 402);
            garbage.metadata.message_type = MessageType::Response;
            client
                .send_to(&garbage.to_vec().unwrap(), addr)
                .await
                .unwrap();
            // Same-peer datagram barrier proves preceding malformed/response frames
            // were processed, without sleeps or requiring replies to garbage.
            udp_exchange(&client, addr, &empty).await;
        };
        tokio::select! { _ = &mut loops => panic!("listener ended"), _ = clients => {} }
        drop(loops);
        let targets = worker.refresh().await.unwrap().page(None).await.unwrap();
        assert_eq!(targets.len(), 4);
        for (host, kind, class, count) in [
            ("mixed.example", RecordType::A, DNSClass::IN, 102),
            ("mixed.example", RecordType::TXT, DNSClass::CH, 101),
            ("", RecordType::AAAA, DNSClass::IN, 101),
            ("negative.localhost", RecordType::TXT, DNSClass::IN, 101),
        ] {
            let target = targets
                .iter()
                .find(|target| {
                    wire::hostname_of(&target.question) == host
                        && target.question.query_type() == kind
                        && target.question.query_class() == class
                })
                .unwrap();
            assert_eq!(target.count, count);
        }
        worker.shutdown().await.unwrap();
        tokio::fs::remove_dir_all(dir).await.unwrap();
    })
    .await
    .unwrap();
}
