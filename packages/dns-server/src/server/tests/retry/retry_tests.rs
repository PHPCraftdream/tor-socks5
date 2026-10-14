use super::*;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
struct Resource(Arc<AtomicUsize>);

impl Drop for Resource {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

type MockRecovery = Pin<Box<dyn Future<Output = (String, (&'static str, ()))>>>;

#[tokio::test(start_paused = true)]
async fn retries_generic_resource_until_success() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let bind_attempts = attempts.clone();
    let future = retry_listener_pair_with(
        "addr".into(),
        || tokio::time::sleep(Duration::from_secs(30)),
        move |_| {
            let attempt = bind_attempts.fetch_add(1, Ordering::SeqCst);
            async move {
                if attempt == 0 {
                    Err(std::io::Error::from(std::io::ErrorKind::AddrNotAvailable).into())
                } else {
                    Ok(("resource", Resource(Arc::new(AtomicUsize::new(0)))))
                }
            }
        },
    );
    tokio::pin!(future);
    assert!(futures::poll!(&mut future).is_pending());
    tokio::time::advance(Duration::from_secs(30)).await;
    assert!(futures::poll!(&mut future).is_pending());
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    tokio::time::advance(Duration::from_secs(30)).await;
    let (addr, (label, resource)) = future.await;
    assert_eq!(addr, "addr");
    assert_eq!(label, "resource");
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    drop(resource);
}

#[tokio::test(start_paused = true)]
async fn dropping_owned_pending_retry_drops_pending_binder_guard() {
    let drops = Arc::new(AtomicUsize::new(0));
    let binder_drops = drops.clone();
    let future = retry_listener_pair_with(
        "addr".into(),
        || std::future::ready(()),
        move |_| {
            let guard = Resource(binder_drops.clone());
            async move {
                let _guard = guard;
                std::future::pending::<Result<Resource>>().await
            }
        },
    );
    let mut future = Box::pin(future);
    assert!(futures::poll!(&mut future).is_pending());
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(future);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn independent_retries_allow_other_addresses_to_recover() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let never = retry_listener_pair_with(
        "unavailable".into(),
        || tokio::time::sleep(Duration::from_secs(30)),
        |_| std::future::ready(Err(anyhow::anyhow!("unavailable"))),
    );
    let recovery_attempts = attempts.clone();
    let recovers = retry_listener_pair_with(
        "recovered".into(),
        || tokio::time::sleep(Duration::from_secs(30)),
        move |_| {
            recovery_attempts.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok::<_, anyhow::Error>(("ok", ())))
        },
    );
    let mut retries: FuturesUnordered<MockRecovery> = FuturesUnordered::new();
    retries.push(Box::pin(never));
    retries.push(Box::pin(recovers));
    tokio::time::advance(Duration::from_secs(30)).await;
    let (addr, _) = retries.next().await.unwrap();
    assert_eq!(addr, "recovered");
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn production_networking_admits_recovered_pair_and_cancellation_releases_it() {
    timeout(CASE_BUDGET, async {
        let (initial_udp, initial_tcp) = bind_pair("127.0.0.1:0").await.unwrap();
        let (recovered_udp, recovered_tcp) = bind_pair("127.0.0.1:0").await.unwrap();
        let recovered_addr = recovered_udp.local_addr().unwrap();
        let recovery_drops = Arc::new(AtomicUsize::new(0));
        let recovery_guard = recovery_drops.clone();
        let context = ctx(vec![], vec![initial_udp.local_addr().unwrap()]);
        let backend = Arc::new(Semaphore::new(MAX_DNS_CONCURRENT_QUERIES));
        let connections = Arc::new(Semaphore::new(listener::MAX_TCP_CONNECTIONS));
        let existing = context.clone();
        let retry = async move {
            let _resource_guard = Resource(recovery_guard);
            ("recovered".to_owned(), recovered_udp, recovered_tcp)
        };
        let serving = run_networking(
            vec![Arc::new(initial_udp)],
            vec![initial_tcp],
            [retry],
            context,
            backend,
            connections,
        );
        let mut serving = Box::pin(serving);
        let service = async {
            let query = request("localhost.", RecordType::A, 871);
            let udp_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let udp_reply = udp_exchange(&udp_client, recovered_addr, &query).await;
            assert_eq!(udp_reply.metadata.response_code, ResponseCode::NoError);
            let mut stream = TcpStream::connect(recovered_addr).await.unwrap();
            let tcp_reply = tcp_exchange(&mut stream, &query).await;
            assert_eq!(tcp_reply.metadata.response_code, ResponseCode::NoError);
            assert!(existing.endpoints.read().unwrap().contains(&recovered_addr));
        };
        tokio::select! {
            biased;
            result = &mut serving => panic!("production networking exited: {result:?}"),
            () = service => (),
        }
        drop(serving);
        let _rebound = bind_pair(&recovered_addr.to_string()).await.unwrap();
    })
    .await
    .expect("recovered service guard");
}
