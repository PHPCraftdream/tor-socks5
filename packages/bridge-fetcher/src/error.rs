//! Error type for the bridge-fetch pipeline.

use std::time::Duration;

use thiserror::Error;

use crate::http::MAX_REDIRECTS;

#[derive(Debug, Error)]
pub enum FetchError {
    #[error("invalid url: {0}")]
    InvalidUrl(String),
    #[error("tor connection failed: {0}")]
    TorConnect(String),
    #[error("tls handshake failed: {0}")]
    Tls(String),
    #[error("http error: {0}")]
    Http(String),
    #[error("non-200 status: {0}")]
    Non200(String),
    #[error("response body exceeds {max_bytes} bytes")]
    TooLarge { max_bytes: usize },
    #[error("too many redirects (>{MAX_REDIRECTS})")]
    TooManyRedirects,
    #[error("timeout after {0:?}")]
    Timeout(Duration),
    #[error("{op}: {source}")]
    Io {
        op: &'static str,
        #[source]
        source: std::io::Error,
    },
}
