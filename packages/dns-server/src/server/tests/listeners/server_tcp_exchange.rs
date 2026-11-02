use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use hickory_proto::op::Message;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::listener::{self, TcpIo};
use super::{wire, ReadObserver};

struct WriteCounter<'a, S> {
    stream: &'a mut S,
    written: usize,
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WriteCounter<'_, S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut *this.stream).poll_write(cx, bytes);
        if let Poll::Ready(Ok(written)) = &result {
            this.written = this.written.saturating_add(*written);
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().stream).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for WriteCounter<'_, S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().stream).poll_read(cx, buffer)
    }
}

/// cancel-safe: NO for resumable use — partial request/response framing is
/// abandoned on cancellation; the caller must not restart this exchange.
pub(super) async fn exchange_frame<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    bytes: &[u8],
    local: Option<SocketAddr>,
    peer: Option<SocketAddr>,
) -> io::Result<Option<Vec<u8>>> {
    let prefix = u16::try_from(bytes.len()).unwrap().to_be_bytes();
    let mut counted = WriteCounter { stream, written: 0 };
    let mut stage = "prefix_first";
    let mut read = 0;
    let mut started = None;

    let result = async {
        counted.write_all(&prefix[..1]).await?;
        stage = "prefix_second";
        counted.write_all(&prefix[1..]).await?;
        stage = "body";
        for chunk in bytes.chunks(3) {
            counted.write_all(chunk).await?;
        }
        stage = "response";
        started = Some(Instant::now());
        let mut observed = ReadObserver::new(&mut counted);
        let result = wire::read_framed_message(&mut observed, Duration::from_secs(5)).await;
        read = observed.read;
        result
    }
    .await;

    match &result {
        Err(error) => listener::emit_client_diag(&format!(
            "tcp_client: local={local:?} peer={peer:?} stage={stage} \
             outcome=error kind={:?} os={:?} observed_written={} \
             observed_read={read} read_elapsed={:?}",
            error.kind(),
            error.raw_os_error(),
            counted.written,
            started.map(|instant| instant.elapsed()),
        )),
        Ok(None) => listener::emit_client_diag(&format!(
            "tcp_client: local={local:?} peer={peer:?} stage={stage} \
             outcome=eof observed_written={} observed_read={read} \
             read_elapsed={:?}",
            counted.written,
            started.map(|instant| instant.elapsed()),
        )),
        Ok(Some(_)) => {}
    }
    result
}

/// cancel-safe: NO for resumable use — cancellation abandons partial framing;
/// the fixture must not resume this exchange on the same connection.
pub(super) async fn tcp_exchange<S: TcpIo>(stream: &mut S, message: &Message) -> Message {
    let bytes = message.to_vec().unwrap();
    stream
        .set_nodelay(true)
        .unwrap_or_else(|_| panic!("tcp NODELAY configuration failed"));
    let local = stream.local_addr().ok();
    let peer = stream.peer_addr().ok();

    match exchange_frame(stream, &bytes, local, peer).await {
        Ok(Some(body)) => {
            Message::from_vec(&body).unwrap_or_else(|_| panic!("tcp response decoding failed"))
        }
        Ok(None) => panic!("tcp response: EOF instead of reply; terminal record emitted"),
        Err(_) => panic!("tcp exchange I/O failed; terminal record emitted"),
    }
}
