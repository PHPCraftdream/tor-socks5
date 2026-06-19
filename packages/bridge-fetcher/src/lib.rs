//! Fetch Tor bridge lines from HTTPS sources over a Tor circuit.
//!
//! The crate is split into focused modules:
//! * [`error`] — the [`FetchError`] type;
//! * [`url_parse`] — `https://` URL parsing;
//! * [`http`] — the HTTPS-over-Tor GET client (request, headers, body);
//! * [`parse`] — extracting `BridgeLine`s from a response body;
//! * [`dedup`] — deduplicating bridge lines;
//! * [`fetch`] — the parallel multi-source batch fetch.
//!
//! Pinned workspace versions: tokio 1, tokio-rustls 0.26, rustls 0.23,
//! httparse 1, url 2, webpki-roots 0.26, bridge-line (ptrs-gesher 0.2).

mod dedup;
mod error;
mod fetch;
mod http;
mod parse;
mod url_parse;

pub use dedup::dedup_bridges;
pub use error::FetchError;
pub use fetch::{fetch_all, FetchOutcome, Source};
pub use http::{build_get_request, fetch_one, parse_response_headers, HttpResponse};
pub use parse::parse_bridges_from_body;
pub use url_parse::{parse_https_url, UrlTarget};
