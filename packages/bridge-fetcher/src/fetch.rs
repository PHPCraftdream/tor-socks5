//! Parallel batch fetch across multiple sources.

use std::time::Duration;

use arti_wrapper::TorTunnel;
use bridge_line::BridgeLine;
use tracing::{info, warn};

use crate::http::fetch_one;
use crate::parse::parse_bridges_from_body;

/// An HTTPS endpoint from which bridge lines can be fetched. `headers` and
/// `cookies` are optional per-source request customisation (e.g. an API
/// token or a session cookie a collector requires).
///
/// # Examples
///
/// ```text
/// let src = bridge_fetcher::Source {
///     label: "example".into(),
///     url: "https://example.com/bridges-obfs4".into(),
///     headers: vec!["Authorization: Bearer xyz".into()],
///     cookies: vec!["session=abc".into()],
/// };
/// assert_eq!(src.label, "example");
/// ```
#[derive(Debug, Clone)]
pub struct Source {
    pub label: String,
    pub url: String,
    /// Extra request headers, each a full `Name: Value` line.
    pub headers: Vec<String>,
    /// Cookies, each a `name=value` pair; folded into one `Cookie:` header.
    pub cookies: Vec<String>,
}

#[derive(Debug)]
pub struct FetchOutcome {
    pub label: String,
    pub bridges_extracted: usize,
    pub error: Option<String>,
}

/// cancel-safe: NO — spawns concurrent fetches that may be in-flight.
pub async fn fetch_all(
    tor: &TorTunnel,
    sources: &[Source],
    timeout: Duration,
    max_body_bytes: usize,
) -> (Vec<BridgeLine>, Vec<FetchOutcome>) {
    let mut handles = Vec::with_capacity(sources.len());

    for source in sources {
        let tor = tor.clone();
        let url = source.url.clone();
        let label = source.label.clone();
        let headers = source.headers.clone();
        let cookies = source.cookies.clone();
        handles.push(tokio::spawn(async move {
            let result = fetch_one(&tor, &url, timeout, max_body_bytes, &headers, &cookies).await;
            (label, result)
        }));
    }

    let mut all_bridges = Vec::new();
    let mut outcomes = Vec::new();

    for handle in handles {
        let (label, result) = match handle.await {
            Ok(pair) => pair,
            Err(e) => {
                warn!(error = %e, "fetch task panicked");
                continue;
            }
        };

        match result {
            Ok(body) => {
                let bridges = parse_bridges_from_body(&body);
                info!(
                    label = %label,
                    bridges = bridges.len(),
                    body_bytes = body.len(),
                    "source fetched successfully"
                );
                outcomes.push(FetchOutcome {
                    label,
                    bridges_extracted: bridges.len(),
                    error: None,
                });
                all_bridges.extend(bridges);
            }
            Err(e) => {
                warn!(label = %label, error = %e, "source fetch failed");
                outcomes.push(FetchOutcome {
                    label,
                    bridges_extracted: 0,
                    error: Some(e.to_string()),
                });
            }
        }
    }

    (all_bridges, outcomes)
}
