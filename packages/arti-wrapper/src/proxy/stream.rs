use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{AsyncRead, AsyncWrite};
use resocks5_net::connect::AnyUpstream;
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};

/// An owning Tor stream, optionally wrapped by the SDK's post-proxy chain.
/// Both forms retain futures I/O so callers use the same Tokio compatibility seam.
pub struct RoutedStream {
    inner: Inner,
}

enum Inner {
    Direct(Box<crate::DataStream>),
    Proxy(Compat<AnyUpstream>),
}

impl RoutedStream {
    pub(crate) fn from_proxy(stream: AnyUpstream) -> Self {
        Self {
            inner: Inner::Proxy(stream.compat()),
        }
    }
}

impl From<crate::DataStream> for RoutedStream {
    fn from(stream: crate::DataStream) -> Self {
        Self {
            inner: Inner::Direct(Box::new(stream)),
        }
    }
}

impl std::fmt::Debug for RoutedStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RoutedStream")
    }
}

impl AsyncRead for RoutedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().inner {
            Inner::Direct(stream) => Pin::new(stream.as_mut()).poll_read(cx, buffer),
            Inner::Proxy(stream) => Pin::new(stream).poll_read(cx, buffer),
        }
    }
}

impl AsyncWrite for RoutedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().inner {
            Inner::Direct(stream) => Pin::new(stream.as_mut()).poll_write(cx, buffer),
            Inner::Proxy(stream) => Pin::new(stream).poll_write(cx, buffer),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            Inner::Direct(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
            Inner::Proxy(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            Inner::Direct(stream) => Pin::new(stream.as_mut()).poll_close(cx),
            Inner::Proxy(stream) => Pin::new(stream).poll_close(cx),
        }
    }
}
