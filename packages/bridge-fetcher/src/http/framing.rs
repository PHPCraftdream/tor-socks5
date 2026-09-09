//! Chunked transfer-encoding body decoder (RFC 9112 §7.1).

use tokio::io::AsyncReadExt;

use crate::error::FetchError;

/// Bound on one chunk-size line (hex digits + optional extensions).
const MAX_SIZE_LINE: usize = 1024;
/// Bound on one trailer line.
const MAX_TRAILER_LINE: usize = 8192;
/// Bound on the whole trailer section.
const MAX_TRAILERS_TOTAL: usize = 64 * 1024;

/// Incremental reader over `stream`, first consuming `pre` (bytes that
/// arrived together with the response headers). `pre` doubles as the
/// read_line refill buffer. Tolerates reads returning fewer bytes than
/// requested (partial TCP reads).
struct ChunkedReader<'a, S: AsyncReadExt + Unpin> {
    stream: &'a mut S,
    pre: Vec<u8>,
    pre_pos: usize,
}

impl<'a, S: AsyncReadExt + Unpin> ChunkedReader<'a, S> {
    fn new(stream: &'a mut S, pre: &[u8]) -> Self {
        Self {
            stream,
            pre: pre.to_vec(),
            pre_pos: 0,
        }
    }

    /// Read some bytes into `out`, draining the preloaded header-buffer
    /// bytes first. Returns 0 only at EOF.
    async fn read_some(&mut self, out: &mut [u8]) -> Result<usize, FetchError> {
        if self.pre_pos < self.pre.len() {
            let avail = (self.pre.len() - self.pre_pos).min(out.len());
            out[..avail].copy_from_slice(&self.pre[self.pre_pos..self.pre_pos + avail]);
            self.pre_pos += avail;
            return Ok(avail);
        }
        self.read_stream_block(out).await
    }

    /// One raw read from the underlying stream.
    async fn read_stream_block(&mut self, out: &mut [u8]) -> Result<usize, FetchError> {
        self.stream.read(out).await.map_err(|e| FetchError::Io {
            op: "read chunked body",
            source: e,
        })
    }

    /// Fill `out` completely; EOF before that is a framing error.
    async fn read_exact_into(&mut self, out: &mut [u8]) -> Result<(), FetchError> {
        let mut filled = 0usize;
        while filled < out.len() {
            let n = self.read_some(&mut out[filled..]).await?;
            if n == 0 {
                return Err(FetchError::ChunkedEncoding(
                    "connection closed mid-chunk".into(),
                ));
            }
            filled += n;
        }
        Ok(())
    }

    /// Read one CRLF-terminated line, bounded by `max`, scanning for `\n`
    /// in the shared `pre` buffer and refilling it in blocks (not byte at
    /// a time). Compacts the consumed prefix before every refill, so `pre`
    /// stays bounded by the unconsumed tail plus one block even when the
    /// next line's tail is already buffered.
    async fn read_line(&mut self, max: usize, what: &str) -> Result<Vec<u8>, FetchError> {
        if self.pre_pos >= self.pre.len() {
            self.pre.clear();
            self.pre_pos = 0;
        }
        let mut scratch = [0u8; 4096];
        let mut scan_from = self.pre_pos;
        loop {
            if let Some(off) = self.pre[scan_from..].iter().position(|&b| b == b'\n') {
                let nl = scan_from + off;
                if nl - self.pre_pos > max {
                    return Err(FetchError::ChunkedEncoding(format!("{what} too long")));
                }
                let mut line = self.pre[self.pre_pos..nl].to_vec();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                self.pre_pos = nl + 1;
                return Ok(line);
            }
            if self.pre.len() - self.pre_pos > max {
                return Err(FetchError::ChunkedEncoding(format!("{what} too long")));
            }
            scan_from = self.pre.len();
            let n = self.read_stream_block(&mut scratch).await?;
            if n == 0 {
                return Err(FetchError::ChunkedEncoding(format!(
                    "connection closed while reading {what}"
                )));
            }
            // Compact before refilling, not only at full drain: when the
            // next line's tail is already buffered (typical for many small
            // chunks), `pre_pos` never reaches `pre.len()`, and the consumed
            // prefix would be retained until the buffer happened to drain
            // completely — `pre` would grow with the whole wire stream.
            if self.pre_pos > 0 {
                self.pre.drain(..self.pre_pos);
                // `scan_from` was the pre-drain `pre.len()`; the retained
                // bytes and the new block shifted left by the same amount,
                // so subtract it to keep pointing at the first unread byte.
                scan_from -= self.pre_pos;
                self.pre_pos = 0;
            }
            self.pre.extend_from_slice(&scratch[..n]);
        }
    }
}

/// Decode a chunked body from `stream`, first consuming `preloaded` bytes
/// (those that arrived together with the response headers). Never allocates
/// from wire-supplied sizes before they are checked against
/// `max_body_bytes`, and all size arithmetic is overflow-checked.
pub(super) async fn decode_chunked_body<S>(
    stream: &mut S,
    preloaded: &[u8],
    max_body_bytes: usize,
) -> Result<Vec<u8>, FetchError>
where
    S: AsyncReadExt + Unpin,
{
    let mut rdr = ChunkedReader::new(stream, preloaded);
    let mut body: Vec<u8> = Vec::new();

    loop {
        let line = rdr.read_line(MAX_SIZE_LINE, "chunk size line").await?;
        // Discard chunk extensions (everything after the first ';').
        let digits = line.split(|&b| b == b';').next().unwrap_or(&[]);
        let digits = std::str::from_utf8(digits)
            .map_err(|_| FetchError::ChunkedEncoding("chunk size is not ASCII".into()))?
            .trim();
        let n = usize::from_str_radix(digits, 16)
            .map_err(|_| FetchError::ChunkedEncoding(format!("invalid chunk size: {digits:?}")))?;

        if n == 0 {
            // Terminal chunk: drain trailer section up to the empty line.
            let mut trailers_total = 0usize;
            loop {
                let t = rdr.read_line(MAX_TRAILER_LINE, "trailer line").await?;
                trailers_total += t.len() + 2;
                if trailers_total > MAX_TRAILERS_TOTAL {
                    return Err(FetchError::ChunkedEncoding(
                        "trailer section too large".into(),
                    ));
                }
                if t.is_empty() {
                    return Ok(body);
                }
            }
        }

        // Bound the decoded size BEFORE allocating (RFC 9112 §B26 / §B7):
        // checked arithmetic, and no allocation from wire sizes until the
        // limit is verified.
        let Some(total) = body.len().checked_add(n) else {
            return Err(FetchError::TooLarge {
                max_bytes: max_body_bytes,
            });
        };
        if total > max_body_bytes {
            return Err(FetchError::TooLarge {
                max_bytes: max_body_bytes,
            });
        }

        let start = body.len();
        body.resize(start + n, 0);
        rdr.read_exact_into(&mut body[start..]).await?;

        // CRLF after chunk data.
        let mut sep = [0u8; 2];
        if let Err(e) = rdr.read_exact_into(&mut sep).await {
            return match e {
                FetchError::ChunkedEncoding(_) => Err(FetchError::ChunkedEncoding(
                    "connection closed before CRLF after chunk data".into(),
                )),
                other => Err(other),
            };
        }
        if sep != *b"\r\n" {
            return Err(FetchError::ChunkedEncoding(
                "missing CRLF after chunk data".into(),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, ReadBuf};

    /// Deterministic fragmentation oracle: each `poll_read` copies at most
    /// `min(front_piece.len(), remaining)` bytes from the front piece,
    /// re-queuing any leftover so a caller reading in smaller increments
    /// than a piece (e.g. `read_line`'s byte-at-a-time reads) still gets
    /// every byte instead of silently losing the remainder.
    struct PieceReader(VecDeque<Vec<u8>>);

    impl AsyncRead for PieceReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            match self.0.pop_front() {
                Some(mut piece) => {
                    let n = piece.len().min(buf.remaining());
                    buf.put_slice(&piece[..n]);
                    if n < piece.len() {
                        piece.drain(..n);
                        self.0.push_front(piece);
                    }
                    Poll::Ready(Ok(()))
                }
                None => Poll::Ready(Ok(())),
            }
        }
    }

    fn pieces(v: &[&[u8]]) -> VecDeque<Vec<u8>> {
        v.iter().map(|p| p.to_vec()).collect()
    }

    fn framed(body: &[u8]) -> Vec<u8> {
        let mut out = format!("{:x}\r\n", body.len()).into_bytes();
        out.extend_from_slice(body);
        out.extend_from_slice(b"\r\n");
        out
    }

    async fn decode(data: &[u8]) -> Result<Vec<u8>, FetchError> {
        decode_chunked_body(&mut PieceReader(pieces(&[data])), &[], usize::MAX).await
    }

    #[tokio::test]
    async fn one_chunk() {
        assert_eq!(decode(b"5\r\nhello\r\n0\r\n\r\n").await.unwrap(), b"hello");
    }

    #[tokio::test]
    async fn multiple_chunks_with_extension() {
        assert_eq!(
            decode(b"3;ext=1\r\nabc\r\n2\r\nde\r\n0\r\n\r\n")
                .await
                .unwrap(),
            b"abcde"
        );
    }

    #[tokio::test]
    async fn uppercase_hex_size() {
        assert_eq!(
            decode(b"A\r\n0123456789\r\n0\r\n\r\n").await.unwrap(),
            b"0123456789"
        );
    }

    #[tokio::test]
    async fn preloaded_header_body_boundary() {
        let out = decode_chunked_body(
            &mut PieceReader(pieces(&[b"llo\r\n0\r\n\r\n"])),
            b"5\r\nhe",
            usize::MAX,
        )
        .await
        .unwrap();
        assert_eq!(out, b"hello");
    }

    #[tokio::test]
    async fn size_line_split_across_reads() {
        let out = decode_chunked_body(
            &mut PieceReader(pieces(&[
                b"3",
                b"\r\nab",
                b"c\r\n2\r\nde",
                b"\r\n0\r",
                b"\n\r\n",
            ])),
            &[],
            usize::MAX,
        )
        .await
        .unwrap();
        assert_eq!(out, b"abcde");
    }

    #[tokio::test]
    async fn trailers_drained_until_empty_line() {
        assert_eq!(
            decode(b"3\r\nabc\r\n0\r\nX-T: 1\r\nX-T2: 2\r\n\r\n")
                .await
                .unwrap(),
            b"abc"
        );
    }

    #[tokio::test]
    async fn empty_terminal_chunk() {
        assert_eq!(decode(b"0\r\n\r\n").await.unwrap(), b"");
    }

    #[tokio::test]
    async fn truncated_mid_chunk_is_error() {
        let err = decode(b"5\r\nabc").await.unwrap_err();
        assert!(err.to_string().contains("closed"), "{err}");
    }

    #[tokio::test]
    async fn invalid_hex_size_is_error() {
        let err = decode(b"zz\r\n").await.unwrap_err();
        assert!(err.to_string().contains("invalid chunk size"), "{err}");
    }

    #[tokio::test]
    async fn missing_crlf_after_chunk_is_error() {
        let err = decode(b"5\r\nhelloXX0\r\n\r\n").await.unwrap_err();
        assert!(err.to_string().contains("CRLF"), "{err}");
    }

    #[tokio::test]
    async fn decoded_body_over_limit_is_too_large() {
        let err = decode_chunked_body(
            &mut PieceReader(pieces(&[b"5\r\nhello\r\n0\r\n\r\n"])),
            &[],
            4,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("exceeds"), "{err}");
    }

    #[tokio::test]
    async fn oversized_size_line_is_error() {
        let data = vec![b'a'; 2000];
        // No newline at all.
        let err = decode(&data).await.unwrap_err();
        assert!(err.to_string().contains("too long"), "{err}");
    }

    /// Wraps a reader and counts how many `poll_read` calls it receives.
    struct CountingReader<R> {
        inner: R,
        reads: usize,
    }

    impl<R: AsyncRead + Unpin> AsyncRead for CountingReader<R> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            self.reads += 1;
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    #[tokio::test]
    async fn many_small_chunks_read_in_blocks() {
        // Mixed, realistic (TLS-record-like) layout, NOT aligned to lines:
        // 20 whole chunks as single 13-byte pieces, 17 chunks split across
        // two pieces on a metadata boundary, and one 39-byte piece holding
        // 3 chunks. Old byte-at-a-time code polls once per byte (~525+);
        // block-read code polls ~once per piece (~55), so the threshold
        // `reads * 3 < 525` fails it while passing the new one.
        let mut dq = VecDeque::new();
        let (whole, split, grouped) = (20, 17, 3);
        for _ in 0..whole {
            dq.push_back(b"8\r\n12345678\r\n".to_vec());
        }
        for _ in 0..split {
            dq.push_back(b"8\r".to_vec());
            dq.push_back(b"\n12345678\r\n".to_vec());
        }
        let mut big = Vec::new();
        for _ in 0..grouped {
            big.extend_from_slice(b"8\r\n12345678\r\n");
        }
        dq.push_back(big);
        dq.push_back(b"0\r\n\r\n".to_vec());
        let total_wire: usize = dq.iter().map(|p| p.len()).sum();
        assert_eq!(total_wire, 40 * 13 + 5);

        let mut r = CountingReader {
            inner: PieceReader(dq),
            reads: 0,
        };
        let out = decode_chunked_body(&mut r, &[], usize::MAX).await.unwrap();
        assert_eq!(out, vec![b"12345678".as_slice(); 40].concat());
        assert!(
            r.reads * 3 < total_wire,
            "reads={} for {total_wire} wire bytes: not block-read",
            r.reads
        );
    }

    #[tokio::test]
    async fn large_trailer_section_read_in_blocks() {
        let mut wire = b"0\r\nX-Big: ".to_vec();
        wire.extend(std::iter::repeat_n(b'a', 6000));
        wire.extend_from_slice(b"\r\n\r\n");
        let mut r = CountingReader {
            inner: PieceReader(pieces(&[&wire])),
            reads: 0,
        };
        let out = decode_chunked_body(&mut r, &[], usize::MAX).await.unwrap();
        assert!(out.is_empty());
        // New code: ~2-3 4096-block polls; old byte-at-a-time: ~6014.
        assert!(r.reads < 100, "reads={}: not block-read", r.reads);
    }

    #[tokio::test]
    async fn pre_buffer_stays_bounded_over_many_chunks() {
        let mut dq: VecDeque<Vec<u8>> = (0..40).map(|_| b"8\r\n12345678\r\n".to_vec()).collect();
        dq.push_back(b"0\r\n\r\n".to_vec());
        let mut counting = CountingReader {
            inner: PieceReader(dq),
            reads: 0,
        };
        let mut rdr = ChunkedReader::new(&mut counting, b"");
        for _ in 0..40 {
            assert_eq!(
                rdr.read_line(MAX_SIZE_LINE, "chunk size line")
                    .await
                    .unwrap(),
                b"8"
            );
            let mut body = [0u8; 8];
            rdr.read_exact_into(&mut body).await.unwrap();
            assert_eq!(&body, b"12345678");
            let mut sep = [0u8; 2];
            rdr.read_exact_into(&mut sep).await.unwrap();
            assert_eq!(&sep, b"\r\n");
        }
        assert_eq!(
            rdr.read_line(MAX_SIZE_LINE, "chunk size line")
                .await
                .unwrap(),
            b"0"
        );
        assert!(rdr
            .read_line(MAX_SIZE_LINE, "trailer line")
            .await
            .unwrap()
            .is_empty());
        assert!(rdr.pre.capacity() < 4096);
        assert!(rdr.pre_pos <= rdr.pre.len());
    }

    #[tokio::test]
    async fn pre_buffer_stays_bounded_when_next_size_line_tail_arrives_early() {
        // Wire layout from the round-5 review: the first segment carries
        // `1\r\na\r\n1` (size line, payload, CRLF and the START of the next
        // size line), every following one carries `\r\na\r\n1` (rest of a
        // size line, payload, CRLF, next size line start). After each chunk
        // a one-byte tail of the NEXT line is already buffered, so
        // `pre_pos < pre.len()` at every read_line entry and the old
        // compact-only-at-full-drain logic never fired: `pre` retained the
        // whole consumed wire (~6 bytes per chunk, O(K)). K=2000 puts
        // old-code retention (~12 KB) past the 8192 assert; a few dozen
        // repeats would stay under it and pass even with the bug present.
        const CHUNKS: usize = 2000;
        let mut dq = VecDeque::new();
        dq.push_back(b"1\r\na\r\n1".to_vec());
        for _ in 1..CHUNKS - 1 {
            dq.push_back(b"\r\na\r\n1".to_vec());
        }
        dq.push_back(b"\r\na\r\n0\r\n\r\n".to_vec());
        let mut pr = PieceReader(dq);
        let mut rdr = ChunkedReader::new(&mut pr, b"");
        let mut body = Vec::new();
        for i in 0..CHUNKS {
            assert_eq!(
                rdr.read_line(MAX_SIZE_LINE, "chunk size line")
                    .await
                    .unwrap(),
                b"1"
            );
            let mut payload = [0u8; 1];
            rdr.read_exact_into(&mut payload).await.unwrap();
            body.extend_from_slice(&payload);
            let mut sep = [0u8; 2];
            rdr.read_exact_into(&mut sep).await.unwrap();
            assert_eq!(&sep, b"\r\n");
            assert!(
                rdr.pre.len() < 8192,
                "chunk {i}: pre.len()={} grows with the wire stream",
                rdr.pre.len()
            );
            assert!(rdr.pre_pos <= rdr.pre.len());
        }
        assert_eq!(body, vec![b'a'; CHUNKS]);
        assert_eq!(
            rdr.read_line(MAX_SIZE_LINE, "chunk size line")
                .await
                .unwrap(),
            b"0"
        );
        assert!(rdr
            .read_line(MAX_SIZE_LINE, "trailer line")
            .await
            .unwrap()
            .is_empty());
        assert!(rdr.pre.capacity() < 8192);
    }

    #[tokio::test]
    async fn pre_buffer_stays_bounded_with_block_sized_refills() {
        // Same report layout, but the whole wire arrives as one stream so
        // each refill appends a full (up to 4096-byte) block onto the
        // drained tail: compaction must keep `pre` bounded in that shape
        // too. Capacity-based asserts are sensitive to Vec amortized
        // growth, so this variant pins `pre.len()` only.
        const CHUNKS: usize = 2000;
        let mut wire = b"1\r\na\r\n1".to_vec();
        for _ in 1..CHUNKS - 1 {
            wire.extend_from_slice(b"\r\na\r\n1");
        }
        wire.extend_from_slice(b"\r\na\r\n0\r\n\r\n");
        let mut pr = PieceReader(pieces(&[wire.as_slice()]));
        let mut rdr = ChunkedReader::new(&mut pr, b"");
        let mut body = Vec::new();
        for i in 0..CHUNKS {
            assert_eq!(
                rdr.read_line(MAX_SIZE_LINE, "chunk size line")
                    .await
                    .unwrap(),
                b"1"
            );
            let mut payload = [0u8; 1];
            rdr.read_exact_into(&mut payload).await.unwrap();
            body.extend_from_slice(&payload);
            let mut sep = [0u8; 2];
            rdr.read_exact_into(&mut sep).await.unwrap();
            assert_eq!(&sep, b"\r\n");
            assert!(
                rdr.pre.len() < 8192,
                "chunk {i}: pre.len()={} grows with the wire stream",
                rdr.pre.len()
            );
        }
        assert_eq!(body, vec![b'a'; CHUNKS]);
        assert_eq!(
            rdr.read_line(MAX_SIZE_LINE, "chunk size line")
                .await
                .unwrap(),
            b"0"
        );
        assert!(rdr
            .read_line(MAX_SIZE_LINE, "trailer line")
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn framed_helper_roundtrip() {
        let mut wire = framed(b"hello");
        wire.extend_from_slice(b"0\r\n\r\n");
        assert_eq!(decode(&wire).await.unwrap(), b"hello");
    }
}
