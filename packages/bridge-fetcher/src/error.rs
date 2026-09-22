//! Error type for the bridge-fetch pipeline.

use std::time::Duration;

use thiserror::Error;

use crate::http::MAX_REDIRECTS;

/// Everything that can abort a single-URL fetch.
///
/// Transport variants (`TorConnect`, `Resolve`, `Tls`, `Io`, `Timeout`) mean
/// no complete response was ever obtained; the rest mean a response arrived
/// but was rejected (unusable URL, bad status, broken framing, non-UTF-8
/// body). The batch wrappers [`crate::fetch_all`] and
/// [`crate::fetch_all_direct`] never propagate this type: each source's
/// error is flattened into the `error` string of its [`crate::FetchOutcome`]
/// via `Display`.
#[derive(Debug, Error)]
pub enum FetchError {
    /// The URL was unusable before any network work: it does not parse, the
    /// scheme is not `https` (the only one this client speaks), the host is
    /// missing, or no port can be determined. Raised by
    /// [`crate::parse_https_url`] for the initial URL and again for every
    /// redirect target.
    #[error("invalid url: {0}")]
    InvalidUrl(String),
    /// Dialling the target through the Tor tunnel failed; the message is
    /// `TorTunnel::connect`'s own error text. Only the Tor path
    /// ([`crate::fetch_one`]) produces this — the direct rescue path has no
    /// tunnel to fail.
    #[error("tor connection failed: {0}")]
    TorConnect(String),
    /// The direct (non-Tor) path could not get a TCP connection to the
    /// host: every pinned address and every DoH-resolved address refused
    /// the connection or timed out (each reported as `addr: reason`), the
    /// DoH lookup itself failed, or no candidate address existed at all.
    /// Never produced on the Tor path, where name resolution happens inside
    /// the tunnel.
    #[error("direct (non-Tor) resolve/connect failed: {0}")]
    Resolve(String),
    /// The TLS handshake with the target failed (untrusted certificate,
    /// protocol mismatch, …) or the host could not be turned into an SNI
    /// name. The message is rustls' error text.
    #[error("tls handshake failed: {0}")]
    Tls(String),
    /// Protocol-level failure that is neither a status nor a chunked-framing
    /// problem: the response head does not parse, the peer closed the
    /// connection before the head was complete, a redirect status arrived
    /// without a `Location` header, a `Location` uses a scheme this client
    /// cannot follow (only absolute `https://` and same-origin `/path`
    /// targets are supported), or the 200 body is not valid UTF-8.
    #[error("http error: {0}")]
    Http(String),
    /// The server answered with a final status that is neither 200 nor one
    /// of the redirects this client follows (301, 302, 307, 308). The
    /// message is the `HTTP <code>` line.
    #[error("non-200 status: {0}")]
    Non200(String),
    /// The response would exceed the fetch's byte budget. Checked before
    /// allocating wherever the size is knowable up front (a `Content-Length`
    /// over the cap, a chunk-size line pushing the decoded total past it)
    /// and after every read otherwise (head+body bytes, accumulated
    /// EOF-delimited body). `max_bytes` is the budget that was exceeded.
    #[error("response body exceeds {max_bytes} bytes")]
    TooLarge {
        /// The byte budget the response exceeded (the fetch's
        /// `max_body_bytes`), echoed for logging.
        max_bytes: usize,
    },
    /// The connection closed (clean EOF) after `Content-Length` promised
    /// more body bytes than had arrived: `expected` is the header's count,
    /// `got` what actually made it across. Aborted rather than returned so
    /// a truncated body cannot silently parse as a short bridge list.
    #[error("incomplete response body: expected {expected} bytes, got {got}")]
    IncompleteBody {
        /// Byte count promised by the response's `Content-Length` header.
        expected: usize,
        /// Body bytes actually received when the connection closed.
        got: usize,
    },
    /// The `Transfer-Encoding: chunked` body violates RFC 9112 §7.1
    /// framing: a chunk-size line that is not ASCII hex, a size or trailer
    /// line past its bound, EOF mid-chunk or mid-line, or a missing CRLF
    /// after chunk data. The message names the specific violation.
    #[error("invalid chunked encoding: {0}")]
    ChunkedEncoding(String),
    /// More than `MAX_REDIRECTS` (3) redirects were followed for one fetch
    /// without a final non-redirect response. Redirect loops are not
    /// detected specially; they surface here.
    #[error("too many redirects (>{MAX_REDIRECTS})")]
    TooManyRedirects,
    /// The whole single-URL fetch — dial, TLS, redirects, body — did not
    /// finish within the caller-supplied budget, carried as the payload.
    /// Enforced as an outer timeout around the fetch, so it fires no matter
    /// which inner await stalled.
    #[error("timeout after {0:?}")]
    Timeout(Duration),
    /// The socket broke mid-fetch. `op` names the phase — writing or
    /// flushing the request, reading the response head, reading a
    /// `Content-Length`-bounded body, reading until EOF, or reading the
    /// chunked body — and `source` is the underlying I/O error. A transport
    /// failure, not an HTTP-level one.
    #[error("{op}: {source}")]
    Io {
        /// The phase of the fetch the failed read/write belonged to; an
        /// exact, matchable string such as `"write request"`.
        op: &'static str,
        /// The underlying socket error.
        #[source]
        source: std::io::Error,
    },
}
