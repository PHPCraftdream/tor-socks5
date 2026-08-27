//! Fetch Tor bridge lines from HTTPS sources over a Tor circuit.
//!
//! The crate is split into focused modules:
//! * [`error`] — the [`FetchError`] type;
//! * [`url_parse`] — `https://` URL parsing;
//! * [`http`] — the HTTPS GET client (request, headers, body), over either a
//!   Tor circuit or, for the cold-start rescue path, a direct connection;
//! * [`direct`] — the direct (non-Tor) connector `http` uses for that rescue path;
//! * [`parse`] — extracting `BridgeLine`s from a response body;
//! * [`dedup`] — deduplicating bridge lines;
//! * [`fetch`] — the parallel multi-source batch fetch.
//!
//! Pinned workspace versions: tokio 1, tokio-rustls 0.26, rustls 0.23,
//! httparse 1, url 2, webpki-roots 0.26, bridge-line (ptrs-gesher 0.2).

mod dedup;
mod direct;
mod error;
mod fetch;
mod http;
mod parse;
mod url_parse;

pub use dedup::dedup_bridges;
pub use error::FetchError;
pub use fetch::{fetch_all, fetch_all_direct, FetchOutcome, Source};
pub use http::{build_get_request, fetch_one, fetch_one_direct, parse_response_headers, HttpResponse};
pub use parse::parse_bridges_from_body;
pub use url_parse::{parse_https_url, UrlTarget};
