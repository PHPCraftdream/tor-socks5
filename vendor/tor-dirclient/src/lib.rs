#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![allow(renamed_and_removed_lints)] // @@REMOVE_WHEN(ci_arti_stable)
#![allow(unknown_lints)] // @@REMOVE_WHEN(ci_arti_nightly)
#![warn(missing_docs)]
#![warn(noop_method_call)]
#![warn(unreachable_pub)]
#![warn(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unchecked_time_subtraction)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::mod_module_files)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
#![allow(clippy::needless_lifetimes)] // See arti#1765
#![allow(mismatched_lifetime_syntaxes)] // temporary workaround for arti#2060
#![allow(clippy::collapsible_if)] // See arti#2342
#![deny(clippy::unused_async)]
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

// TODO probably remove this at some point - see tpo/core/arti#1060
#![cfg_attr(
    not(all(feature = "full", feature = "experimental")),
    allow(unused_imports)
)]

mod body;
mod err;
pub mod request;
mod response;
mod util;

use tor_circmgr::{CircMgr, DirInfo};
use tor_error::bad_api_usage;
use tor_rtcompat::{Runtime, SleepProvider, SleepProviderExt};

// Zlib is required; the others are optional.
#[cfg(feature = "xz")]
use async_compression::futures::bufread::XzDecoder;
use async_compression::futures::bufread::ZlibDecoder;
#[cfg(feature = "zstd")]
use async_compression::futures::bufread::ZstdDecoder;

use futures::FutureExt;
use futures::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use memchr::memchr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, instrument};

pub use err::{Error, RequestError, RequestFailedError};
pub use response::{DirResponse, SourceInfo};

/// Type for results returned in this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Type for internal results  containing a RequestError.
pub type RequestResult<T> = std::result::Result<T, RequestError>;

/// Flag to declare whether a request is always anonymized or not.
///
/// This is used by tor-dirclient to control whether *other* deanonymizing metadata
/// might be added to the request (eg in request headers):
/// Some requests (like those to download onion service descriptors) are always
/// anonymized, and should never be sent in a way that leaks information about
/// our settings or configuration.
///
/// It is up to the *caller* of `tor-dirclient` to ensure that
///
///   - every request whose anonymization status is `AnonymizedRequest::Direct`
///     is sent only over non-anonymous connections.
///
///     (Sending an `AnonymizedRequest::Direct` request over an anonymized connection
///     would weaken the connection's anonymity, and can therefore weaken the anonymity
///     of user traffic sharing the same circuit.)
///
///   - every request whose anonymization status is `AnonymizedRequest::Anonymized`
///     is sent over only anonymous connections (ie, multi-hop circuits).
///
///     (Sending an `AnonymizedRequest::Anonymized` request over a direct connection
///     would directly reveal user behaviour data to the directory server.)
///
/// TODO the calling code cannot easily be sure to get this right this because
/// the anonymization status is a run-time property and the choice of connection kind
/// is statically defined in the calling code.  (Perhaps this could be checked in tests?)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AnonymizedRequest {
    /// This request's content or semantics reveals or is correlated with sensitive information.
    ///
    /// For example, requests for hidden service descriptors reveal which hidden services
    /// the client is connecting to.
    ///
    /// The request must be sent over an anonymous circuit by the caller
    /// and no additional deanonymizing information should be added to it by `tor-dirclient`.
    /// (For example, no client-version-specific information should be
    /// sent in HTTP headers when the request is made.)
    Anonymized,

    /// Making this request does not reveal anything sensitive, nor any user behaviour.
    ///
    /// The request body is uncorrelated with such things as the websites the user might visit,
    /// the onion services the user is visiting or running, etc.
    ///
    /// For example, requests for all router microdescriptors are made by all clients,
    /// so which microdescriptor(s) are requested reveals nothing to any attacker.
    ///
    /// tor-dirclient is allowed to add include information about our capabilities
    /// when sending this request.
    /// The request must *not* be sent over an anonymous circuit by the caller
    /// (at least, not one used for anything else).
    Direct,
}

/// Fetch the resource described by `req` over the Tor network.
///
/// Circuits are built or found using `circ_mgr`, using paths
/// constructed using `dirinfo`.
///
/// For more fine-grained control over the circuit and stream used,
/// construct them yourself, and then call [`send_request`] instead.
///
/// # TODO
///
/// This is the only function in this crate that knows about CircMgr and
/// DirInfo.  Perhaps this function should move up a level into DirMgr?
#[instrument(level = "trace", skip_all)]
pub async fn get_resource<CR, R, SP>(
    req: &CR,
    dirinfo: DirInfo<'_>,
    runtime: &SP,
    circ_mgr: Arc<CircMgr<R>>,
) -> Result<DirResponse>
where
    CR: request::Requestable + ?Sized,
    R: Runtime,
    SP: SleepProvider,
{
    let tunnel = circ_mgr.get_or_launch_dir(dirinfo).await?;

    if req.anonymized() == AnonymizedRequest::Anonymized {
        return Err(bad_api_usage!("Tried to use get_resource for an anonymized request").into());
    }

    // TODO(nickm) This should be an option, and is too long.
    let begin_timeout = Duration::from_secs(5);
    let source = match SourceInfo::from_tunnel(&tunnel) {
        Ok(source) => source,
        Err(e) => {
            return Err(Error::RequestFailed(RequestFailedError {
                source: None,
                error: e.into(),
            }));
        }
    };

    let wrap_err = |error| {
        Error::RequestFailed(RequestFailedError {
            source: source.clone(),
            error,
        })
    };

    req.check_circuit(&tunnel).await.map_err(wrap_err)?;

    // Launch the stream.
    let mut stream = runtime
        .timeout(begin_timeout, tunnel.begin_dir_stream())
        .await
        .map_err(RequestError::from)
        .map_err(wrap_err)?
        .map_err(RequestError::from)
        .map_err(wrap_err)?; // TODO(nickm) handle fatalities here too

    // TODO: Perhaps we want separate timeouts for each phase of this.
    // For now, we just use higher-level timeouts in `dirmgr`.
    let r = send_request(runtime, req, &mut stream, source.clone()).await;

    if should_retire_circ(&r) {
        retire_circ(&circ_mgr, &tunnel.unique_id(), "Partial response");
    }

    r
}

/// Return true if `result` holds an error indicating that we should retire the
/// circuit used for the corresponding request.
fn should_retire_circ(result: &Result<DirResponse>) -> bool {
    match result {
        Err(e) => e.should_retire_circ(),
        Ok(dr) => dr.error().map(RequestError::should_retire_circ) == Some(true),
    }
}

/// Fetch a Tor directory object from a provided stream.
#[deprecated(since = "0.8.1", note = "Use send_request instead.")]
pub async fn download<R, S, SP>(
    runtime: &SP,
    req: &R,
    stream: &mut S,
    source: Option<SourceInfo>,
) -> Result<DirResponse>
where
    R: request::Requestable + ?Sized,
    S: AsyncRead + AsyncWrite + Send + Unpin,
    SP: SleepProvider,
{
    send_request(runtime, req, stream, source).await
}

/// Fetch or upload a Tor directory object using the provided stream.
///
/// To do this, we send a simple HTTP/1.0 request for the described
/// object in `req` over `stream`, and then wait for a response.  In
/// log messages, we describe the origin of the data as coming from
/// `source`.
///
/// # Notes
///
/// It's kind of bogus to have a 'source' field here at all; we may
/// eventually want to remove it.
///
/// This function doesn't close the stream; you may want to do that
/// yourself.
///
/// The only error variant returned is [`Error::RequestFailed`].
// TODO: should the error return type change to `RequestFailedError`?
// If so, that would simplify some code in_dirmgr::bridgedesc.
pub async fn send_request<R, S, SP>(
    runtime: &SP,
    req: &R,
    stream: &mut S,
    source: Option<SourceInfo>,
) -> Result<DirResponse>
where
    R: request::Requestable + ?Sized,
    S: AsyncRead + AsyncWrite + Send + Unpin,
    SP: SleepProvider,
{
    let wrap_err = |error| {
        Error::RequestFailed(RequestFailedError {
            source: source.clone(),
            error,
        })
    };

    let partial_ok = req.partial_response_body_ok();
    let maxlen = req.max_response_len();
    let anonymized = req.anonymized();
    let req = req.make_request().map_err(wrap_err)?;
    let method = req.method().clone();
    let encoded = util::encode_request(&req);

    // Write the request.
    for chunk in encoded.iter() {
        stream
            .write_all(chunk)
            .await
            .map_err(RequestError::from)
            .map_err(wrap_err)?;
    }
    stream
        .flush()
        .await
        .map_err(RequestError::from)
        .map_err(wrap_err)?;

    let mut buffered = BufReader::new(stream);

    // Handle the response
    // TODO: should there be a separate timeout here?
    let header = read_headers(&mut buffered).await.map_err(wrap_err)?;
    if header.status != Some(200) {
        return Ok(DirResponse::new(
            method,
            header.status.unwrap_or(0),
            header.status_message,
            None,
            vec![],
            source,
        ));
    }

    // tor-socks5 local patch: when the server gave us a Content-Length,
    // bound the (compressed) body read with `.take(len)` so the decoder
    // sees a clean EOF after exactly that many bytes — instead of blocking
    // until a stream-level RELAY_END that may never arrive over a slow
    // obfs4 circuit (the cause of spurious "Partial response" / DirTimeout).
    //
    // IMPORTANT: `AsyncReadExt::take(n)` reports EOF (`Ok(0)`) both when the
    // *declared* length is exhausted and when the *underlying* stream hits a
    // real EOF early. Those two are not the same thing: the second one means
    // the server promised `clen` bytes and delivered fewer, i.e. the body is
    // truncated. `read_and_decompress`'s `written_in_this_loop == 0 =>
    // return Ok(())` branch cannot tell them apart from inside the loop, so
    // we wrap the `Take` in `RemainingTracker` here and check its remaining
    // count after the read completes: a nonzero remainder means the stream
    // stopped short of the declared Content-Length, which must be treated as
    // an error, not a clean success (this was previously silently accepted —
    // see the `TruncatedBody` regression test for the "line truncated before
    // newline" symptom this produced in tor_netdoc for a full consensus
    // fetched over a PT bridge). `Arc<AtomicU64>` (not `Rc<Cell<_>>`) because
    // this future must stay `Send` -- dirmgr's bootstrap runs it inside a
    // spawned tokio task.
    use futures::io::AsyncReadExt as _;
    let mut remaining_counter: Option<Arc<std::sync::atomic::AtomicU64>> = None;
    let mut decoder = match header.length {
        Some(clen) => {
            let taken = buffered.take(clen as u64);
            let tracker = RemainingTracker::new(taken);
            remaining_counter = Some(tracker.remaining.clone());
            let bounded = BufReader::new(tracker);
            get_decoder(bounded, header.encoding.as_deref(), anonymized).map_err(wrap_err)?
        }
        None => get_decoder(buffered, header.encoding.as_deref(), anonymized).map_err(wrap_err)?,
    };

    let mut result = Vec::new();
    let mut ok = read_and_decompress(runtime, &mut decoder, maxlen, &mut result).await;

    // If we had a declared Content-Length and the body reader stopped
    // (cleanly, from the decoder's point of view) before consuming all of
    // it, the underlying stream gave us fewer bytes than promised: that's a
    // truncated body, not a complete document.
    if ok.is_ok() {
        if let Some(remaining) = &remaining_counter {
            let remaining = remaining.load(std::sync::atomic::Ordering::Acquire);
            if remaining > 0 {
                ok = Err(RequestError::TruncatedBody(remaining));
            }
        }
    }

    let ok = match (partial_ok, ok, result.len()) {
        (true, Err(e), n) if n > 0 => {
            // Note that we _don't_ return here: we want the partial response.
            Err(e)
        }
        (_, Err(e), _) => {
            return Err(wrap_err(e));
        }
        (_, Ok(()), _) => Ok(()),
    };

    Ok(DirResponse::new(
        method,
        200,
        None,
        ok.err(),
        result,
        source,
    ))
}

/// Maximum length for the HTTP headers in a single request or response.
///
/// Chosen more or less arbitrarily.
const MAX_HEADERS_LEN: usize = 16384;

/// Read and parse HTTP/1 headers from `stream`.
async fn read_headers<S>(stream: &mut S) -> RequestResult<HeaderStatus>
where
    S: AsyncBufRead + Unpin,
{
    let mut buf = Vec::with_capacity(1024);

    loop {
        // TODO: it's inefficient to do this a line at a time; it would
        // probably be better to read until the CRLF CRLF ending of the
        // response.  But this should be fast enough.
        let n = read_until_limited(stream, b'\n', 2048, &mut buf).await?;

        // TODO(nickm): Better maximum and/or let this expand.
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut response = httparse::Response::new(&mut headers);

        match response.parse(&buf[..])? {
            httparse::Status::Partial => {
                // We didn't get a whole response; we may need to try again.

                if n == 0 {
                    // We hit an EOF; no more progress can be made.
                    return Err(RequestError::TruncatedHeaders);
                }

                if buf.len() >= MAX_HEADERS_LEN {
                    return Err(RequestError::HeadersTooLong(buf.len()));
                }
            }
            httparse::Status::Complete(n_parsed) => {
                if response.code != Some(200) {
                    return Ok(HeaderStatus {
                        status: response.code,
                        status_message: response.reason.map(str::to_owned),
                        encoding: None,
                        length: None,
                    });
                }
                let encoding = if let Some(enc) = response
                    .headers
                    .iter()
                    .find(|h| h.name == "Content-Encoding")
                {
                    Some(String::from_utf8(enc.value.to_vec())?)
                } else {
                    None
                };
                // tor-socks5 local patch: parse Content-Length (arti upstream
                // leaves this commented out). Used to bound the body read.
                let length = if let Some(clen) =
                    response.headers.iter().find(|h| h.name == "Content-Length")
                {
                    std::str::from_utf8(clen.value).ok().and_then(|s| s.trim().parse::<usize>().ok())
                } else {
                    None
                };
                assert!(n_parsed == buf.len());
                return Ok(HeaderStatus {
                    status: Some(200),
                    status_message: None,
                    encoding,
                    length,
                });
            }
        }
        if n == 0 {
            return Err(RequestError::TruncatedHeaders);
        }
    }
}

/// Return value from read_headers
#[derive(Debug, Clone)]
struct HeaderStatus {
    /// HTTP status code.
    status: Option<u16>,
    /// HTTP status message associated with the status code.
    status_message: Option<String>,
    /// The Content-Encoding header, if any.
    encoding: Option<String>,
    /// The Content-Length header, if any (on-wire / compressed body length).
    /// tor-socks5 local patch: arti upstream ignores this; we use it to bound
    /// the body read so it terminates cleanly instead of waiting for a stream
    /// EOF that may never arrive over a slow obfs4 circuit.
    length: Option<usize>,
}

/// Helper: download directory information from `stream` and
/// decompress it into a result buffer.  Assumes that `buf` is empty.
///
/// If we get more than maxlen bytes after decompression, give an error.
///
/// Returns the status of our download attempt, stores any data that
/// we were able to download into `result`.  Existing contents of
/// `result` are overwritten.
async fn read_and_decompress<S, SP>(
    runtime: &SP,
    mut stream: S,
    maxlen: usize,
    result: &mut Vec<u8>,
) -> RequestResult<()>
where
    S: AsyncRead + Unpin,
    SP: SleepProvider,
{
    let buffer_window_size = 1024;
    let mut written_total: usize = 0;
    // tor-socks5 local patch: this used to be a single TOTAL timeout armed
    // once before the loop, which truncated big-but-healthy downloads (e.g.
    // a ~3MB consensus over a slow obfs4 bridge) into a DirTimeout /
    // "Partial response". Switched to an IDLE (inter-read) timeout: the
    // timer is rebuilt every iteration, so it only fires when no byte has
    // arrived for `idle_timeout` — a true stall, not merely a slow stream.
    let idle_timeout = Duration::from_secs(90);

    loop {
        // allocate buffer for next read
        result.resize(written_total + buffer_window_size, 0);
        let buf: &mut [u8] = &mut result[written_total..written_total + buffer_window_size];

        let timer = runtime.sleep(idle_timeout).fuse();
        futures::pin_mut!(timer);
        let status = futures::select! {
            status = stream.read(buf).fuse() => status,
            _ = timer => {
                result.resize(written_total, 0); // truncate as needed
                return Err(RequestError::DirTimeout);
            }
        };
        let written_in_this_loop = match status {
            Ok(n) => n,
            Err(other) => {
                result.resize(written_total, 0); // truncate as needed
                return Err(other.into());
            }
        };

        written_total += written_in_this_loop;

        // exit conditions below

        if written_in_this_loop == 0 {
            /*
            in case we read less than `buffer_window_size` in last `read`
            we need to shrink result because otherwise we'll return those
            un-read 0s
            */
            if written_total < result.len() {
                result.resize(written_total, 0);
            }
            return Ok(());
        }

        // TODO: It would be good to detect compression bombs, but
        // that would require access to the internal stream, which
        // would in turn require some tricky programming.  For now, we
        // use the maximum length here to prevent an attacker from
        // filling our RAM.
        if written_total > maxlen {
            result.resize(maxlen, 0);
            return Err(RequestError::ResponseTooLong(written_total));
        }
    }
}

/// Retire a directory circuit because of an error we've encountered on it.
fn retire_circ<R>(circ_mgr: &Arc<CircMgr<R>>, id: &tor_proto::circuit::UniqId, error: &str)
where
    R: Runtime,
{
    info!(
        "{}: Retiring circuit because of directory failure: {}",
        &id, &error
    );
    circ_mgr.retire_circ(id);
}

/// As AsyncBufReadExt::read_until, but stops after reading `max` bytes.
///
/// Note that this function might not actually read any byte of value
/// `byte`, since EOF might occur, or we might fill the buffer.
///
/// A return value of 0 indicates an end-of-file.
async fn read_until_limited<S>(
    stream: &mut S,
    byte: u8,
    max: usize,
    buf: &mut Vec<u8>,
) -> std::io::Result<usize>
where
    S: AsyncBufRead + Unpin,
{
    let mut n_added = 0;
    loop {
        let data = stream.fill_buf().await?;
        if data.is_empty() {
            // End-of-file has been reached.
            return Ok(n_added);
        }
        debug_assert!(n_added < max);
        let remaining_space = max - n_added;
        let (available, found_byte) = match memchr(byte, data) {
            Some(idx) => (idx + 1, true),
            None => (data.len(), false),
        };
        debug_assert!(available >= 1);
        let n_to_copy = std::cmp::min(remaining_space, available);
        buf.extend(&data[..n_to_copy]);
        stream.consume_unpin(n_to_copy);
        n_added += n_to_copy;
        if found_byte || n_added == max {
            return Ok(n_added);
        }
    }
}

/// tor-socks5 local patch: wraps a [`futures::io::Take`] and mirrors its
/// remaining-byte count into a shared, externally-readable counter.
///
/// `Take::limit()` is only reachable through the concrete `Take<S>` type; by
/// the time the reader is behind `get_decoder`'s `Box<dyn AsyncRead>` there is
/// no way to ask "did the declared `Content-Length` actually get fully
/// consumed, or did the stream stop early?" from outside. This wrapper keeps
/// that answer available via a cheap `Arc<AtomicU64>` snapshot updated after
/// every read, without needing to downcast the trait object.
///
/// `S` must be `Unpin` (true for every stream this crate uses `Take` over):
/// that lets this be a plain, non-pin-projected `AsyncRead` impl.
struct RemainingTracker<S> {
    /// The length-bounded inner reader.
    inner: futures::io::Take<S>,
    /// Bytes not yet consumed from `inner`'s original limit. Updated after
    /// every successful read; read by the caller once the response is fully
    /// processed to detect a stream that stopped before the declared
    /// `Content-Length` was reached.
    remaining: Arc<std::sync::atomic::AtomicU64>,
}

impl<S: AsyncRead + Unpin> RemainingTracker<S> {
    /// Wrap `inner`, initializing the shared counter from its current limit.
    fn new(inner: futures::io::Take<S>) -> Self {
        let remaining = Arc::new(std::sync::atomic::AtomicU64::new(inner.limit()));
        Self { inner, remaining }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for RemainingTracker<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let inner = std::pin::Pin::new(&mut this.inner);
        let poll = inner.poll_read(cx, buf);
        if let std::task::Poll::Ready(Ok(_)) = &poll {
            this.remaining
                .store(this.inner.limit(), std::sync::atomic::Ordering::Release);
        }
        poll
    }
}

/// Helper: Return a boxed decoder object that wraps the stream  $s.
macro_rules! decoder {
    ($dec:ident, $s:expr) => {{
        let mut decoder = $dec::new($s);
        decoder.multiple_members(true);
        Ok(Box::new(decoder))
    }};
}

/// Wrap `stream` in an appropriate type to undo the content encoding
/// as described in `encoding`.
fn get_decoder<'a, S: AsyncBufRead + Unpin + Send + 'a>(
    stream: S,
    encoding: Option<&str>,
    anonymized: AnonymizedRequest,
) -> RequestResult<Box<dyn AsyncRead + Unpin + Send + 'a>> {
    use AnonymizedRequest::Direct;
    match (encoding, anonymized) {
        (None | Some("identity"), _) => Ok(Box::new(stream)),
        (Some("deflate"), _) => decoder!(ZlibDecoder, stream),
        // We only admit to supporting these on a direct connection; otherwise,
        // a hostile directory could send them back even though we hadn't
        // requested them.
        #[cfg(feature = "xz")]
        (Some("x-tor-lzma"), Direct) => decoder!(XzDecoder, stream),
        #[cfg(feature = "zstd")]
        (Some("x-zstd"), Direct) => decoder!(ZstdDecoder, stream),
        (Some(other), _) => Err(RequestError::ContentEncoding(other.into())),
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod test;
