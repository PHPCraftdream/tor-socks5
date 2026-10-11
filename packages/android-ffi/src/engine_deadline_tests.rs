use super::*;

use tokio::io::{duplex, AsyncWriteExt};
use tokio::time::sleep;

/// Assert pending framing ends with the SDK's typed deadline error.
async fn assert_deadline_error(
    handle: &mut tokio::task::JoinHandle<std::result::Result<IncomingRequest, ServerError>>,
    wait_before_finish_check: Duration,
) {
    sleep(wait_before_finish_check).await;
    assert!(!handle.is_finished(), "handshake must still be pending");

    // Wait out the remainder of the deadline before polling completion.
    sleep(HANDSHAKE_DEADLINE).await;
    let result = tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("handshake task did not finish after the deadline")
        .expect("handshake task panicked");
    let err = result.expect_err("handshake must fail at the deadline");
    assert!(
        matches!(err, ServerError::Deadline),
        "unexpected error: {err:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn http_partial_framing_does_not_renew_absolute_deadline() {
    use std::future::Future;
    use std::task::Poll;
    let (mut client, mut server) = duplex(1024);
    let deadline = tokio::time::Instant::now() + HANDSHAKE_DEADLINE;
    let mut accepting = Box::pin(accept_with_deadline(&mut server, None));
    client.write_all(b"C").await.unwrap();
    assert!(std::future::poll_fn(|cx| Poll::Ready(accepting.as_mut().poll(cx).is_pending())).await);
    tokio::time::advance(Duration::from_secs(29)).await;
    client
        .write_all(b"ONNECT example.com:443 HTTP/1.1\r\n")
        .await
        .unwrap();
    assert!(std::future::poll_fn(|cx| Poll::Ready(accepting.as_mut().poll(cx).is_pending())).await);
    tokio::time::advance(Duration::from_secs(1)).await;
    let result = accepting.await;
    assert!(
        matches!(result, Err(ServerError::Deadline)),
        "unexpected result: {result:?}"
    );
    assert_eq!(tokio::time::Instant::now(), deadline);
}

#[tokio::test(start_paused = true)]
async fn silent_client_handshake_fails_at_deadline() {
    let (client, server) = duplex(64);
    let mut handle = tokio::spawn(async move {
        let mut server = server;
        accept_with_deadline(&mut server, None).await
    });

    // Client sends nothing and keeps the stream open (never dropped).
    drop(tokio::spawn(async move {
        sleep(Duration::from_secs(3600)).await;
        drop(client);
    }));

    assert_deadline_error(&mut handle, HANDSHAKE_DEADLINE / 2).await;
}

#[tokio::test(start_paused = true)]
async fn partial_handshake_header_fails_at_deadline() {
    let (mut client, server) = duplex(64);
    let mut handle = tokio::spawn(async move {
        let mut server = server;
        accept_with_deadline(&mut server, None).await
    });

    // Client writes only the VER byte — an incomplete method-negotiation
    // header — then holds the stream open.
    tokio::spawn(async move {
        client.write_all(&[0x05]).await.ok();
        sleep(Duration::from_secs(3600)).await;
    });

    assert_deadline_error(&mut handle, HANDSHAKE_DEADLINE / 2).await;
}

#[tokio::test(start_paused = true)]
async fn trickling_client_still_hits_absolute_deadline() {
    let (mut client, server) = duplex(64);
    let handle = tokio::spawn(async move {
        let mut server = server;
        accept_with_deadline(&mut server, None).await
    });

    // Trickling client: one valid byte every 12 s (HANDSHAKE_DEADLINE *
    // 2 / 5), then holds the stream forever. If the deadline were renewed
    // per byte, the handshake would never expire.
    let client_task = tokio::spawn(async move {
        client.write_all(&[0x05]).await.ok();
        sleep(HANDSHAKE_DEADLINE * 2 / 5).await;
        client.write_all(&[0x01]).await.ok();
        sleep(HANDSHAKE_DEADLINE * 2 / 5).await;
        client.write_all(&[0x00]).await.ok();
        sleep(Duration::from_secs(3600)).await;
    });

    // 20 s in: a renewal-per-read implementation would still be waiting
    // for the CONNECT request (last byte arrived at 24 s).
    sleep(HANDSHAKE_DEADLINE * 2 / 3).await;
    assert!(!handle.is_finished(), "handshake must still be pending");

    // Sleep past the absolute deadline (40 s total) before polling.
    sleep(HANDSHAKE_DEADLINE * 2 / 3).await;
    let result = tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("handshake task did not finish after the deadline")
        .expect("handshake task panicked");
    let err = result.expect_err("handshake must fail at the absolute deadline");
    assert!(
        matches!(err, ServerError::Deadline),
        "unexpected error: {err:?}"
    );

    client_task.abort();
}
