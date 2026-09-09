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
/// arrived together with the response headers). Tolerates reads returning
/// fewer bytes than requested (partial TCP reads).
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

    /// Read one CRLF-terminated line, byte at a time, bounded by `max`.
    async fn read_line(&mut self, max: usize, what: &str) -> Result<Vec<u8>, FetchError> {
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let n = self.read_some(&mut byte).await?;
            if n == 0 {
                return Err(FetchError::ChunkedEncoding(format!(
                    "connection closed while reading {what}"
                )));
            }
            if byte[0] == b'\n' {
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Ok(line);
            }
            line.push(byte[0]);
            if line.len() > max {
                return Err(FetchError::ChunkedEncoding(format!("{what} too long")));
            }
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

    #[tokio::test]
    async fn framed_helper_roundtrip() {
        let mut wire = framed(b"hello");
        wire.extend_from_slice(b"0\r\n\r\n");
        assert_eq!(decode(&wire).await.unwrap(), b"hello");
    }
}
