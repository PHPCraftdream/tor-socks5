use super::*;

#[tokio::test(start_paused = true)]
async fn retry_address_waits_then_recovers_exactly_once() {
    use std::cell::Cell;

    let calls = Cell::new(0);
    let mut retry = Box::pin(retry::retry_address_with("mock".into(), |_| {
        let call = calls.get();
        calls.set(call + 1);
        async move {
            if call == 0 {
                Err(io::Error::from(ErrorKind::AddrNotAvailable))
            } else {
                Ok("resource")
            }
        }
    }));

    assert!(futures::poll!(&mut retry).is_pending());
    assert_eq!(calls.get(), 0);
    tokio::time::advance(retry::RETRY_DELAY).await;
    assert!(futures::poll!(&mut retry).is_pending());
    assert_eq!(calls.get(), 1);
    tokio::time::advance(retry::RETRY_DELAY).await;
    let (address, resource) = retry.await;
    assert_eq!(calls.get(), 2);
    assert_eq!(address, "mock");
    assert_eq!(resource, "resource");
}

#[tokio::test(start_paused = true)]
async fn pending_binder_cancellation_drops_binder_future() {
    use std::cell::Cell;
    use std::rc::Rc;

    struct DropFlag(Rc<Cell<bool>>);
    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }

    let entered = Rc::new(Cell::new(false));
    let entered_by_binder = entered.clone();
    let dropped = Rc::new(Cell::new(false));
    let dropped_by_binder = dropped.clone();
    let mut retry = Box::pin(retry::retry_address_with("mock".into(), move |_| {
        let entered = entered_by_binder.clone();
        let guard = DropFlag(dropped_by_binder.clone());
        async move {
            entered.set(true);
            let _guard = guard;
            std::future::pending::<io::Result<()>>().await
        }
    }));

    assert!(futures::poll!(&mut retry).is_pending());
    tokio::time::advance(retry::RETRY_DELAY).await;
    assert!(futures::poll!(&mut retry).is_pending());
    assert!(entered.get());
    assert!(!dropped.get());
    drop(retry);
    assert!(dropped.get());
}

#[tokio::test(start_paused = true)]
async fn recovered_mock_resource_drops_with_retry_result() {
    use std::cell::Cell;
    use std::rc::Rc;

    struct Resource(Rc<Cell<usize>>);
    impl Drop for Resource {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    let drops = Rc::new(Cell::new(0));
    let drops_by_binder = drops.clone();
    let retry = retry::retry_address_with("mock".into(), move |_| {
        let resource = Resource(drops_by_binder.clone());
        async move { Ok::<_, io::Error>(resource) }
    });
    tokio::pin!(retry);
    assert!(futures::poll!(retry.as_mut()).is_pending());
    tokio::time::advance(retry::RETRY_DELAY).await;
    let (_address, resource) = retry.await;
    assert_eq!(drops.get(), 0);
    drop(resource);
    assert_eq!(drops.get(), 1);
}

#[tokio::test(start_paused = true)]
async fn one_retry_future_does_not_block_another_address() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_b = attempts.clone();
    use futures::StreamExt;
    let pending = retry::retry_address_with("pending".into(), move |_| {
        attempts_b.fetch_add(1, Ordering::SeqCst);
        async { Err::<(), _>(io::Error::from(ErrorKind::AddrNotAvailable)) }
    });
    let ready = retry::retry_address_with("ready".into(), |_| async { Ok::<_, io::Error>(()) });
    let mut retries = futures::stream::FuturesUnordered::new();
    retries.push(Box::pin(pending) as futures::future::BoxFuture<'_, (String, ())>);
    retries.push(Box::pin(ready) as futures::future::BoxFuture<'_, (String, ())>);

    assert!(futures::poll!(retries.next()).is_pending());
    tokio::time::advance(retry::RETRY_DELAY).await;
    assert!(
        matches!(futures::poll!(retries.next()), std::task::Poll::Ready(Some((address, ()))) if address == "ready")
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
}

#[test]
fn only_local_availability_errors_are_skippable() {
    for kind in [
        ErrorKind::AddrInUse,
        ErrorKind::PermissionDenied,
        ErrorKind::AddrNotAvailable,
    ] {
        assert!(skippable(kind), "{kind:?}");
    }
    for kind in [
        ErrorKind::InvalidInput,
        ErrorKind::Other,
        ErrorKind::Interrupted,
        ErrorKind::TimedOut,
        ErrorKind::ConnectionRefused,
        ErrorKind::Unsupported,
    ] {
        assert!(!skippable(kind), "{kind:?}");
    }
}

#[tokio::test]
async fn empty_addresses_report_empty_reasons() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let error = bind_listeners(&[]).await.unwrap_err().to_string();
        assert!(error.contains("no listen addresses configured"), "{error}");
        assert!(error.contains("addresses/reasons: []"), "{error}");
    })
    .await
    .expect("empty bind must finish");
}

#[tokio::test]
async fn invalid_address_is_hard_error_with_original_context() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let error = bind_listeners(&["not-a-socket-address".into(), "127.0.0.1:0".into()])
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "failed to bind not-a-socket-address");
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            ErrorKind::InvalidInput
        );
    })
    .await
    .expect("invalid bind must finish");
}

#[tokio::test]
async fn all_occupied_errors_list_every_address_and_os_reason() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addresses = [
            first.local_addr().unwrap().to_string(),
            second.local_addr().unwrap().to_string(),
        ];
        let error = bind_listeners(&addresses).await.unwrap_err().to_string();
        assert!(
            error.contains("no SOCKS5 listen addresses could be bound"),
            "{error}"
        );
        for address in &addresses {
            let reason = error
                .split("; ")
                .find(|reason| reason.contains(address))
                .unwrap();
            assert!(
                reason.contains("AddrInUse") || reason.contains("PermissionDenied"),
                "{reason}"
            );
            assert!(reason.contains("os error"), "{reason}");
        }
        // The original owners remain alive, including after the all-skipped error.
        for listener in [&first, &second] {
            let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (_accepted, _) = listener.accept().await.unwrap();
            drop(client);
        }
    })
    .await
    .expect("occupied bind must finish");
}
