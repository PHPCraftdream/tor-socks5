use super::*;
use futures::FutureExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn assert_socks5_setup_timeout(prefix: &[u8]) {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
    let permit = semaphore.clone().acquire_owned().await.expect("permit");
    let (mut parent, lyrebird_side) = tokio::io::duplex(1024);
    parent
        .write_all(prefix)
        .await
        .expect("partial SOCKS5 write");
    let handler = async move {
        let _permit = permit;
        client_handle_connection(
            lyrebird_side,
            Obfs4PT::client_builder(),
            "127.0.0.1:9050".parse().expect("client address"),
        )
        .await
    };
    tokio::pin!(handler);

    assert!(handler.as_mut().now_or_never().is_none());
    let tick = std::time::Duration::from_millis(1);
    tokio::time::advance(SOCKS5_SETUP_TIMEOUT - tick).await;
    assert!(handler.as_mut().now_or_never().is_none());
    tokio::time::advance(tick).await;
    let error = handler
        .as_mut()
        .now_or_never()
        .expect("SOCKS5 handshake must finish at its deadline")
        .expect_err("silent SOCKS5 clients must time out");
    assert_eq!(
        error.to_string(),
        "SOCKS5 negotiation timed out",
        "only the setup deadline should terminate a silent client"
    );
    assert!(semaphore.try_acquire().is_ok(), "permit must be released");

    let mut byte = [0; 1];
    assert_eq!(parent.read(&mut byte).await.expect("socket read"), 0);
}

#[tokio::test(start_paused = true)]
async fn socks5_setup_timeout_drops_socket_and_releases_permit() {
    assert_socks5_setup_timeout(&[]).await;
}

#[tokio::test(start_paused = true)]
async fn partial_socks5_setup_timeout_drops_socket_and_releases_permit() {
    assert_socks5_setup_timeout(&[0x05]).await;
}
