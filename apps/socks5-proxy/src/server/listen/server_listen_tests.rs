use super::*;
use futures::StreamExt;
use std::net::SocketAddr;
use tokio::io::AsyncReadExt;

/// cancel-safe: NO — partial wire I/O is not resumable; the test's outer
/// timeout is terminal and drops every owned socket/future on failure.
async fn exercise_listeners(listeners: Vec<TcpListener>) {
    let addresses = listeners
        .iter()
        .map(|l| l.local_addr().unwrap())
        .collect::<Vec<_>>();
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let destination = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = destination.local_addr().unwrap();
    let egress = Egress::Upstream(Arc::new(upstream::Upstream::new(
        upstream_listener.local_addr().unwrap().to_string(),
        None,
    )));
    let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    let ids = Arc::new(AtomicU64::new(1));
    let mut loops = listeners
        .into_iter()
        .map(|listener| {
            accept_loop(
                listener,
                egress.clone(),
                None,
                permits.clone(),
                ConnHealthCounters::default(),
                ids.clone(),
                false,
                AllowedClients::default(),
            )
        })
        .collect::<futures::stream::FuturesUnordered<_>>();
    let clients = async {
        for address in &addresses {
            let mut client = TcpStream::connect(address).await.unwrap();
            client.set_nodelay(true).unwrap();
            for byte in [5, 1, 0] {
                client.write_all(&[byte]).await.unwrap();
            }
            let mut method = [0; 2];
            client.read_exact(&mut method).await.unwrap();
            assert_eq!(method, [5, 0]);
            client.shutdown().await.unwrap();
            drop(client);

            let upstream = async {
                let (mut socket, _) = upstream_listener.accept().await.unwrap();
                let mut greeting = [0; 2];
                socket.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting[0], 5);
                let mut methods = vec![0; usize::from(greeting[1])];
                socket.read_exact(&mut methods).await.unwrap();
                assert!(methods.contains(&0));
                socket.write_all(&[5, 0]).await.unwrap();
                let mut request = [0; 10];
                socket.read_exact(&mut request).await.unwrap();
                assert_eq!(&request[..8], &[5, 1, 0, 1, 127, 0, 0, 1]);
                assert_eq!(u16::from_be_bytes([request[8], request[9]]), target.port());
                let mut remote = TcpStream::connect(target).await.unwrap();
                socket
                    .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
                tokio::io::copy_bidirectional(&mut socket, &mut remote)
                    .await
                    .unwrap();
            };
            let remote = async {
                let (mut remote, _) = destination.accept().await.unwrap();
                let mut data = Vec::new();
                remote.read_to_end(&mut data).await.unwrap();
                assert_eq!(data, b"request\x00\xff");
                remote.write_all(b"response\x00\xfe").await.unwrap();
                remote.shutdown().await.unwrap();
            };
            tokio::join!(http_connect(*address, target), upstream, remote);
        }
        // All handlers must have released the shared admission permits.
        let all = permits
            .clone()
            .acquire_many_owned(u32::try_from(MAX_CONCURRENT_CONNECTIONS).unwrap())
            .await
            .unwrap();
        assert_eq!(
            ids.load(Ordering::Relaxed),
            1 + 2 * u64::try_from(addresses.len()).unwrap()
        );
        drop(all);
    };
    tokio::select! {
        () = clients => {}
        _ = loops.next() => panic!("accept loop ended before clients completed"),
    }
}

/// cancel-safe: NO — fragmented writes/reads are terminal on test timeout.
async fn http_connect(address: SocketAddr, target: SocketAddr) {
    let mut client = TcpStream::connect(address).await.unwrap();
    client.set_nodelay(true).unwrap();
    for byte in format!("CONNECT {target} HTTP/1.1\r\n\r\n").bytes() {
        client.write_all(&[byte]).await.unwrap();
    }
    let expected = b"HTTP/1.1 200 Connection Established\r\n\r\n";
    let mut response = vec![0; expected.len()];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, expected);
    client.write_all(b"request\x00\xff").await.unwrap();
    client.shutdown().await.unwrap();
    response.clear();
    client.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"response\x00\xfe");
}

#[tokio::test]
async fn two_bound_listeners_each_serve_socks_greeting_and_real_http_connect() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let bound = binding::bind_listeners(&["127.0.0.1:0".into(), "127.0.0.1:0".into()])
            .await
            .unwrap();
        assert_eq!(bound.listeners.len(), 2);
        assert!(bound.skipped.is_empty());
        assert_ne!(
            bound.listeners[0].local_addr().unwrap(),
            bound.listeners[1].local_addr().unwrap()
        );
        exercise_listeners(bound.listeners).await;
    })
    .await
    .expect("two listeners must serve within 30s");
}

// Red with fail-on-first-bind: the occupied first address must not prevent service.
#[tokio::test]
async fn occupied_listener_is_untouched_while_other_serves_both_protocols() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let owner = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = owner.local_addr().unwrap().to_string();
        let bound = binding::bind_listeners(&[address.clone(), "127.0.0.1:0".into()])
            .await
            .unwrap();
        assert_eq!(bound.listeners.len(), 1);
        assert_eq!(bound.skipped.len(), 1);
        assert_eq!(bound.skipped[0].address, address);
        let error = &bound.skipped[0].error;
        assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied
            ),
            "{error}"
        );
        assert!(error.raw_os_error().is_some(), "{error}");
        let original = async {
            let mut client = TcpStream::connect(&address).await.unwrap();
            client.set_nodelay(true).unwrap();
            let (mut accepted, _) = owner.accept().await.unwrap();
            client.write_all(b"owner").await.unwrap();
            let mut data = [0; 5];
            accepted.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, b"owner");
            accepted.write_all(b"still accepting").await.unwrap();
            let mut response = [0; 15];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"still accepting");
        };
        tokio::join!(original, exercise_listeners(bound.listeners));
    })
    .await
    .expect("occupied owner and proxy must serve within 30s");
}
