//! Bidirectional local forwarding for accepted onion-service streams.
//!
//! Deliberately Tor-free: `forward` is generic over any tokio
//! `AsyncRead + AsyncWrite + Unpin` pair, so it is unit-tested with
//! `tokio::io::duplex` and a real loopback echo listener, without arti.
//!
//! The copy is hand-rolled instead of `copy_bidirectional` so both halves
//! share one activity clock: a connection with no traffic in either
//! direction is torn down after [`FORWARD_IDLE_TIMEOUT`] (a hostile or
//! wedged client must not hold a permit and two sockets forever), while
//! active transfers run unbounded and half-close (FIN) still propagates.

use std::io::ErrorKind;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Idle time after which a forwarding pair with no traffic in either
/// direction is torn down.
const FORWARD_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Copy in both directions between an accepted onion stream and the local
/// target connection until both halves are closed or the pair goes idle.
pub(crate) async fn forward<S, T>(client: S, target: T) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: AsyncRead + AsyncWrite + Unpin,
{
    forward_with_idle_timeout(client, target, FORWARD_IDLE_TIMEOUT).await
}

/// Like [`forward`], with an explicit idle timeout (tests inject a short one
/// and drive a paused clock).
async fn forward_with_idle_timeout<S, T>(
    client: S,
    target: T,
    idle: Duration,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut target_read, mut target_write) = tokio::io::split(target);
    // Milliseconds since the pair started at the most recent completed
    // read/write in either direction — one shared activity clock.
    let last = Arc::new(AtomicU64::new(0));
    let start = tokio::time::Instant::now();
    let (client_to_target, target_to_client) = tokio::join!(
        copy_half(&mut client_read, &mut target_write, &last, start, idle),
        copy_half(&mut target_read, &mut client_write, &last, start, idle),
    );
    client_to_target?;
    target_to_client?;
    Ok(())
}

/// Copy one direction, resetting the shared activity clock after every
/// completed read and write. On EOF the peer's write half is shut down
/// (half-close semantics); on a full idle period with no activity in either
/// direction the half returns `TimedOut`.
///
/// The deadline is armed from a snapshot of `last` taken *before* the sleep:
/// if the clock moved while sleeping, the timer re-arms instead of firing, so
/// activity just before expiry can never be killed by a stale deadline.
async fn copy_half<R, W>(
    reader: &mut R,
    writer: &mut W,
    last: &AtomicU64,
    start: tokio::time::Instant,
    idle: Duration,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 8 * 1024];
    loop {
        let last_snapshot = last.load(Ordering::Relaxed);
        let deadline = start + Duration::from_millis(last_snapshot) + idle;
        let read = tokio::select! {
            biased;
            // Timer first: once the deadline has fired, later-arriving data
            // (or a dropped peer) must not mask the idle timeout.
            () = tokio::time::sleep_until(deadline) => {
                if last.load(Ordering::Relaxed) != last_snapshot {
                    continue; // activity happened while sleeping: re-arm
                }
                return Err(std::io::Error::new(
                    ErrorKind::TimedOut,
                    "onion service forwarding idle timeout",
                ));
            }
            read = reader.read(&mut buf) => read?,
        };
        if read == 0 {
            // EOF in this direction: propagate the half-close.
            return writer.shutdown().await;
        }
        last.store(elapsed_millis(start), Ordering::Relaxed);
        writer.write_all(&buf[..read]).await?;
        last.store(elapsed_millis(start), Ordering::Relaxed);
    }
}

fn elapsed_millis(start: tokio::time::Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::Semaphore;

    const BUF: usize = 4096;
    /// Short idle timeout used by the paused-clock tests.
    const TEST_IDLE: Duration = Duration::from_secs(10);

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

    /// Just under the idle window: advancing the full window would fire the
    /// deadline before the exchange can reset the shared clock.
    const NEAR_IDLE: Duration = Duration::from_millis(9_000);

    #[tokio::test(start_paused = true)]
    async fn an_active_pair_survives_repeated_near_idle_windows() {
        let (mut client, client_to_fwd) = tokio::io::duplex(BUF);
        let (fwd_to_server, mut server) = tokio::io::duplex(BUF);
        let task = tokio::spawn(forward_with_idle_timeout(
            client_to_fwd,
            fwd_to_server,
            TEST_IDLE,
        ));

        // Exchanges spaced almost one idle window apart keep the shared
        // clock alive: every completed write resets it.
        for round in 0..3u8 {
            tokio::time::advance(NEAR_IDLE).await;
            let payload = [round; 4];
            client.write_all(&payload).await.expect("write");
            client.flush().await.expect("flush");
            let mut buf = [0u8; 4];
            server.read_exact(&mut buf).await.expect("read");
            assert_eq!(&buf, &payload);
        }

        drop(client);
        drop(server);
        task.await.expect("join").expect("no io error");
    }

    #[tokio::test(start_paused = true)]
    async fn an_idle_pair_is_torn_down_with_a_timeout_error() {
        let (client, client_to_fwd) = tokio::io::duplex(BUF);
        let (fwd_to_server, server) = tokio::io::duplex(BUF);
        let task = tokio::spawn(forward_with_idle_timeout(
            client_to_fwd,
            fwd_to_server,
            TEST_IDLE,
        ));
        // Open and silent: the deadline fires with nothing to re-arm from.
        // Let the task poll once first so `start` is captured before the
        // clock advances.
        tokio::task::yield_now().await;
        tokio::time::advance(TEST_IDLE * 2).await;
        drop(client);
        drop(server);
        let error = task
            .await
            .expect("join")
            .expect_err("the idle pair must fail");
        assert_eq!(error.kind(), ErrorKind::TimedOut);
    }

    #[tokio::test(start_paused = true)]
    async fn a_silence_shorter_than_the_timeout_does_not_abort_the_pair() {
        let (mut client, client_to_fwd) = tokio::io::duplex(BUF);
        let (fwd_to_server, mut server) = tokio::io::duplex(BUF);
        let task = tokio::spawn(forward_with_idle_timeout(
            client_to_fwd,
            fwd_to_server,
            TEST_IDLE,
        ));

        // Half the idle window with no traffic, then traffic: the clock
        // resets and the pair continues.
        tokio::time::advance(TEST_IDLE / 2).await;
        client.write_all(b"late").await.expect("write");
        client.flush().await.expect("flush");
        let mut buf = [0u8; 4];
        server.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"late");

        // Another silence shorter than the timeout, then EOF: still fine.
        tokio::time::advance(TEST_IDLE / 2).await;
        drop(client);
        drop(server);
        task.await.expect("join").expect("no io error");
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
        // completes the other direction.
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
                    let now = h_cur.fetch_add(1, AtomicOrdering::SeqCst) + 1;
                    h_max.fetch_max(now, AtomicOrdering::SeqCst);
                    // Hold the connection briefly so overlap is observable.
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    let mut stream = stream;
                    let _ = stream.shutdown().await;
                    h_cur.fetch_sub(1, AtomicOrdering::SeqCst);
                });
            }
        });

        let cap = Arc::new(Semaphore::new(2));
        let mut tasks = Vec::new();
        for _ in 0..6 {
            let permit = cap.clone().acquire_owned().await.expect("permit");
            let target = tokio::net::TcpStream::connect(addr).await.expect("connect");
            let (client_side, remote) = tokio::io::duplex(BUF);
            tasks.push(tokio::spawn(async move {
                let _ = forward(client_side, target).await;
                drop(permit);
            }));
            // EOF on both ends so forward completes promptly and releases
            // its permit (the handler's own shutdown covers the TCP side).
            drop(remote);
        }
        for task in tasks {
            task.await.expect("join");
        }
        assert!(
            max_in_handler.load(AtomicOrdering::SeqCst) <= 2,
            "more than the cap ran concurrently: {}",
            max_in_handler.load(AtomicOrdering::SeqCst)
        );
    }
}
