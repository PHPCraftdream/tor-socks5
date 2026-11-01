//! E2E tests for the webtunnel HTTP upgrade handshake against a local
//! mock HTTP server (no TLS). Exercises the `upgrade_and_return` loop and
//! all error paths that pure unit tests on `parse_response` cannot reach.

use std::time::Duration;

use ptrs::args::Args;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use webtunnel::handshake::connect;
use webtunnel::WebTunnelConfig;

async fn make_config(port: u16) -> WebTunnelConfig {
    let mut args = Args::new();
    args.add("url", &format!("http://localhost:{}/path", port));
    args.add("addr", &format!("127.0.0.1:{}", port));
    WebTunnelConfig::from_args(&args).unwrap()
}

#[tokio::test]
async fn webtunnel_101_happy_path() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        // Read the HTTP upgrade request
        let mut buf = vec![0u8; 4096];
        let n = sock.read(&mut buf).await.unwrap();
        let req = String::from_utf8_lossy(&buf[..n]);
        assert!(req.contains("GET /path HTTP/1.1"), "bad request: {req}");
        assert!(req.contains("Upgrade: websocket"));

        // Respond with 101
        sock.write_all(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n",
        )
        .await
        .unwrap();
        sock.flush().await.unwrap();

        // Echo one message back
        let mut echo_buf = [0u8; 256];
        let n = sock.read(&mut echo_buf).await.unwrap();
        sock.write_all(&echo_buf[..n]).await.unwrap();
    });

    let config = make_config(port).await;
    let mut stream = connect(&config).await.unwrap();

    let msg = b"hello webtunnel";
    stream.write_all(msg).await.unwrap();
    stream.flush().await.unwrap();

    let mut buf = [0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(&buf[..n], msg);
}

#[tokio::test]
async fn webtunnel_non_101_returns_error() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        let _ = sock.read(&mut buf).await.unwrap();
        sock.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
    });

    let config = make_config(port).await;
    let result = connect(&config).await;
    assert!(result.is_err());
    match result {
        Ok(_) => panic!("expected Non101 error but got Ok"),
        Err(webtunnel::Error::Non101(_)) => {}
        Err(e) => panic!("expected Non101, got: {e:?}"),
    }
}

#[tokio::test]
async fn webtunnel_premature_close() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        drop(sock); // close immediately
    });

    let config = make_config(port).await;
    let result = connect(&config).await;
    assert!(result.is_err(), "premature close must produce error");
}

#[tokio::test]
async fn webtunnel_leftover_bytes_in_prefix() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let extra = b"LEFTOVER_DATA_123";

    let extra_clone = extra.to_vec();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        let _ = sock.read(&mut buf).await.unwrap();

        let mut response =
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n".to_vec();
        response.extend_from_slice(&extra_clone);
        sock.write_all(&response).await.unwrap();
        sock.flush().await.unwrap();

        // Keep connection open briefly so client can read
        tokio::time::sleep(Duration::from_millis(500)).await;
    });

    let config = make_config(port).await;
    let mut stream = connect(&config).await.unwrap();

    // The leftover bytes should be available immediately from PrefixStream
    let mut buf = [0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    assert_eq!(
        &buf[..n],
        extra,
        "leftover bytes must be preserved in PrefixStream"
    );
}

#[tokio::test]
async fn webtunnel_oversized_headers_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        let _ = sock.read(&mut buf).await.unwrap();

        // Send headers exceeding the internal 4096-byte buffer
        let mut response = String::from("HTTP/1.1 101 Switching Protocols\r\n");
        for i in 0..200 {
            response.push_str(&format!("X-Padding-{i}: {}\r\n", "A".repeat(50)));
        }
        response.push_str("\r\n");
        sock.write_all(response.as_bytes()).await.unwrap();
    });

    let config = make_config(port).await;
    let result = connect(&config).await;
    assert!(
        result.is_err(),
        "oversized response headers must be rejected"
    );
}
