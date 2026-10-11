use super::*;
use std::io::{self, Cursor};
use std::net::IpAddr;
use std::task::{Context, Poll};
use tokio::io::ReadBuf;
#[test]
fn post_request_carries_exact_headers_and_body() {
    let provider = DohProvider {
        ip: IpAddr::from([192, 0, 2, 1]),
        hostname: "dns.example".to_string(),
        path: "/dns-query".to_string(),
    };
    let body = b"\x12\x34abcd";
    let request = build_post_request(&provider.hostname, &provider.path, body);
    let mut expected = format!(
        "POST /dns-query HTTP/1.1\r\n\
             Host: dns.example\r\n\
             Accept: application/dns-message\r\n\
             Content-Type: application/dns-message\r\n\
             Content-Length: {}\r\n\
             User-Agent: tor-socks5/0.1\r\n\
             Connection: close\r\n\
             \r\n",
        body.len()
    )
    .into_bytes();
    expected.extend_from_slice(body);
    assert_eq!(request, expected);
}

/// AsyncRead over a fixed sequence of byte chunks: each poll_read hands
/// out up to the remainder of the current chunk, then moves on; running
/// dry is EOF.
struct ChunkReader {
    chunks: Vec<Cursor<Vec<u8>>>,
    current: usize,
}

impl ChunkReader {
    fn new(chunks: &[&[u8]]) -> Self {
        Self {
            chunks: chunks
                .iter()
                .map(|chunk| Cursor::new(chunk.to_vec()))
                .collect(),
            current: 0,
        }
    }
}

impl AsyncRead for ChunkReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while this.current < this.chunks.len() {
            let cursor = &mut this.chunks[this.current];
            let position = cursor.position() as usize;
            let data = &cursor.get_ref()[position..];
            if data.is_empty() {
                this.current += 1;
                continue;
            }
            let take = data.len().min(buf.remaining());
            buf.put_slice(&data[..take]);
            cursor.set_position((position + take) as u64);
            return Poll::Ready(Ok(()));
        }
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn reads_whole_response_in_one_chunk() {
    let body = [0xABu8; 48];
    let mut wire = b"HTTP/1.1 200 OK\r\nContent-Length: 48\r\n\r\n".to_vec();
    wire.extend_from_slice(&body);
    let mut reader = ChunkReader::new(&[&wire]);
    let parsed = read_dns_body(&mut reader).await.expect("body read");
    assert_eq!(parsed, body);
}

#[tokio::test]
async fn body_starts_exactly_at_httparse_header_len() {
    // THE off-by-4 regression case: headers and the first body bytes
    // arrive in one read, the rest split over two more. The body must
    // begin exactly at httparse's header_len — no bytes skipped.
    let body: Vec<u8> = (0..64u8).collect();
    let mut first = b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\n".to_vec();
    let header_len = first.len();
    first.extend_from_slice(&body[..3]);
    let mut reader = ChunkReader::new(&[&first, &body[3..40], &body[40..]]);

    let parsed = read_dns_body(&mut reader).await.expect("body read");
    assert!(header_len < first.len());
    assert_eq!(parsed, body);
}

#[tokio::test]
async fn non_200_status_is_an_error() {
    let wire = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n";
    let mut reader = ChunkReader::new(&[wire]);
    let error = read_dns_body(&mut reader).await.expect_err("503 must fail");
    assert!(
        matches!(error, DnsServerError::DohExchange(ref text) if text.contains("503")),
        "error should carry the status: {error:?}"
    );
}

#[tokio::test]
async fn oversized_content_length_is_rejected() {
    let oversized = MAX_DNS_RESPONSE_BYTES + 1;
    let wire = format!("HTTP/1.1 200 OK\r\nContent-Length: {oversized}\r\n\r\n");
    let mut reader = ChunkReader::new(&[wire.as_bytes()]);
    let error = read_dns_body(&mut reader)
        .await
        .expect_err("over-cap must fail");
    assert!(matches!(error, DnsServerError::DohExchange(_)));
}

#[tokio::test]
async fn chunked_transfer_encoding_is_rejected() {
    let wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
    let mut reader = ChunkReader::new(&[wire]);
    let error = read_dns_body(&mut reader)
        .await
        .expect_err("chunked must fail");
    assert!(matches!(error, DnsServerError::DohExchange(_)));
}
