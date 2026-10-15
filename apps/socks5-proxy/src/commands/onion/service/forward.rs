//! Bidirectional local forwarding for accepted onion-service streams.
//!
//! Deliberately Tor-free: `forward` is generic over any tokio
//! `AsyncRead + AsyncWrite + Unpin` pair, so it is unit-tested with
//! `tokio::io::duplex` and a real loopback echo listener, without arti.

use tokio::io::{AsyncRead, AsyncWrite};

/// Copy in both directions between an accepted onion stream and the local
/// target connection until both halves are closed.
///
/// `tokio::io::copy_bidirectional` (rather than two independent `copy`
/// halves) propagates half-close correctly: when the client sends FIN, the
/// target's write side is shut down while its remaining data still flows
/// back, and vice versa.
pub(crate) async fn forward<S, T>(mut client: S, mut target: T) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: AsyncRead + AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional(&mut client, &mut target).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::Semaphore;

    const BUF: usize = 4096;

    /// Echo task: copies everything back until EOF.
    async fn echo(mut stream: tokio::net::TcpStream) -> std::io::Result<()> {
        let mut buf = vec![0u8; BUF];
        loop {
            let read = stream.read(&mut buf).await?;
            if read == 0 {
                return Ok(());
            }
            stream.write_all(&buf[..read]).await?;
        }
    }

    #[tokio::test]
    async fn duplex_forward_moves_data_both_ways() {
        // forward() bridges two in-memory pipes: `client` plays the onion
        // client, `server` plays the local target.
        let (mut client, client_to_fwd) = tokio::io::duplex(BUF);
        let (fwd_to_server, mut server) = tokio::io::duplex(BUF);
        let task = tokio::spawn(forward(client_to_fwd, fwd_to_server));

        // Client → target.
        client.write_all(b"ping").await.expect("write");
        client.flush().await.expect("flush");
        let mut buf = [0u8; 4];
        server.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"ping");

        // Target → client.
        server.write_all(b"pong").await.expect("write");
        server.flush().await.expect("flush");
        client.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"pong");

        // duplex shutdown is a no-op: dropping both ends is the EOF signal
        drop(client);
        drop(server);
        task.await.expect("forward").expect("no io error");
    }

    #[tokio::test]
    async fn duplex_forward_propagates_close() {
        let (client, client_to_fwd) = tokio::io::duplex(BUF);
        let (fwd_to_server, server) = tokio::io::duplex(BUF);
        let task = tokio::spawn(forward(client_to_fwd, fwd_to_server));
        // Dropping one end must terminate the forward loop: the half-close
        // propagates EOF to the other side.
        drop(client);
        drop(server);
        task.await.expect("forward").expect("no io error");
    }

    #[tokio::test]
    async fn forward_over_real_tcp_listener_echoes_both_ways() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(echo(stream));
            }
        });

        let (client_side, target_side) = tokio::io::duplex(BUF);
        let target = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let fwd = tokio::spawn(forward(client_side, target));

        // Drive the "remote onion client" side of the duplex.
        let mut remote = target_side;
        remote.write_all(b"hello").await.expect("write");
        remote.flush().await.expect("flush");
        let mut buf = [0u8; 5];
        remote.read_exact(&mut buf).await.expect("read echo");
        assert_eq!(&buf, b"hello");
        remote.write_all(b"world").await.expect("write 2");
        remote.flush().await.expect("flush 2");
        let mut buf2 = [0u8; 5];
        remote.read_exact(&mut buf2).await.expect("read echo 2");
        assert_eq!(&buf2, b"world");

        // Close: forward must end cleanly.
        // Dropping the remote sends EOF through the duplex; forward then
        // shuts down the TCP write half, the echo exits, and its TCP EOF
        // completes the other direction, so copy_bidirectional returns.
        drop(remote);
        fwd.await.expect("join").expect("io ok");
    }

    #[tokio::test]
    async fn semaphore_caps_concurrent_forwards() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let max_in_handler = Arc::new(AtomicUsize::new(0));
        let current = Arc::new(AtomicUsize::new(0));
        // Handler that tracks concurrency.
        let h_max = max_in_handler.clone();
        let h_cur = current.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let h_max = h_max.clone();
                let h_cur = h_cur.clone();
                tokio::spawn(async move {
                    let now = h_cur.fetch_add(1, Ordering::SeqCst) + 1;
                    h_max.fetch_max(now, Ordering::SeqCst);
                    // Hold the connection briefly so overlap is observable.
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    let mut stream = stream;
                    let _ = stream.shutdown().await;
                    h_cur.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });

        let cap = Arc::new(Semaphore::new(2));
        let mut tasks = Vec::new();
        for _ in 0..6 {
            let permit = cap.clone().acquire_owned().await.expect("permit");
            let target = tokio::net::TcpStream::connect(addr).await.expect("connect");
            let (client_side, _remote) = tokio::io::duplex(BUF);
            tasks.push(tokio::spawn(async move {
                let _ = forward(client_side, target).await;
                drop(permit);
            }));
        }
        for task in tasks {
            task.await.expect("join");
        }
        assert!(
            max_in_handler.load(Ordering::SeqCst) <= 2,
            "more than the cap ran concurrently: {}",
            max_in_handler.load(Ordering::SeqCst)
        );
    }
}
