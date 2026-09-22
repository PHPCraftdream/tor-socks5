//! Parallel batch fetch across multiple sources.

use std::time::Duration;

use arti_wrapper::TorTunnel;
use bridge_line::BridgeLine;
use bridge_probe::ResolverPolicy;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::error::FetchError;
use crate::http::{fetch_one, fetch_one_direct};
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
///     allow_credentials_cross_origin: false,
/// };
/// assert_eq!(src.label, "example");
/// ```
#[derive(Debug, Clone)]
pub struct Source {
    /// Caller-chosen identifier for the source, copied into every
    /// [`FetchOutcome`] so results and log lines can be joined back to the
    /// configured collector. Never sent on the wire.
    pub label: String,
    /// The `https://` URL to GET. If it does not parse as an HTTPS URL the
    /// source fails with [`FetchError::InvalidUrl`] without any network
    /// attempt; redirects may then take the actual fetch elsewhere (see
    /// `allow_credentials_cross_origin` for what travels along).
    pub url: String,
    /// Extra request headers, each a full `Name: Value` line.
    pub headers: Vec<String>,
    /// Cookies, each a `name=value` pair; folded into one `Cookie:` header.
    pub cookies: Vec<String>,
    /// Send `headers`/`cookies` to redirect targets on other origins (different
    /// host or port). Default `false`: caller-supplied headers/cookies are sent
    /// only to the origin of `url`; a redirect to another origin is followed
    /// with an otherwise-identical request that carries none of them (RFC 9110
    /// §15.4). Set `true` only when the collector's cross-origin redirect chain
    /// is known and trusted.
    pub allow_credentials_cross_origin: bool,
}

/// Per-source result of a batch fetch: what one [`Source`] yielded,
/// successful or not. Exactly one outcome is produced per source, in input
/// order, so a failed source stays visible next to its successful peers
/// instead of silently vanishing from the merged bridge list.
#[derive(Debug)]
pub struct FetchOutcome {
    /// Copy of the source's `label`.
    pub label: String,
    /// How many bridge lines were extracted from the body (equals
    /// `bridges.len()`); always 0 when `error` is set. Zero is also legal
    /// without an error — a 200 response whose body parses to nothing.
    pub bridges_extracted: usize,
    /// `None` when this source's fetch succeeded; otherwise the `Display`
    /// string of the [`FetchError`] that killed it. One bad source never
    /// fails the batch.
    pub error: Option<String>,
    /// The lines this source contributed, kept alongside the count so a bridge
    /// can be attributed back to where it came from.
    ///
    /// Judging a collector by whether its fetch succeeded is not enough: one
    /// that has stopped regenerating still answers HTTP 200 with hundreds of
    /// lines. A source in this repo's defaults did exactly that for 27 days
    /// while contributing almost nothing that worked, and no transport-level
    /// health check could have noticed. Scoring a source by what it actually
    /// yields requires knowing which bridges were its.
    pub bridges: Vec<BridgeLine>,
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
        let allow_cross = source.allow_credentials_cross_origin;
        handles.push(tokio::spawn(async move {
            let result = fetch_one(
                &tor,
                &url,
                timeout,
                max_body_bytes,
                &headers,
                &cookies,
                allow_cross,
            )
            .await;
            (label, result)
        }));
    }

    collect_fetch_results(handles).await
}

/// Cold-start rescue fetch: same fan-out and collection as [`fetch_all`], but
/// every source is fetched directly (no Tor, hostnames resolved through
/// `bridge-probe`'s DoH pool) instead of over a `TorTunnel`. Only meant for
/// the narrow case where zero bridges are reachable yet -- see
/// [`crate::http::fetch_one_direct`].
///
/// cancel-safe: NO — same reason as `fetch_all`.
pub async fn fetch_all_direct(
    sources: &[Source],
    resolver_policy: ResolverPolicy,
    timeout: Duration,
    max_body_bytes: usize,
) -> (Vec<BridgeLine>, Vec<FetchOutcome>) {
    let mut handles = Vec::with_capacity(sources.len());

    for source in sources {
        let url = source.url.clone();
        let label = source.label.clone();
        let headers = source.headers.clone();
        let cookies = source.cookies.clone();
        let allow_cross = source.allow_credentials_cross_origin;
        handles.push(tokio::spawn(async move {
            let result = fetch_one_direct(
                resolver_policy,
                &url,
                timeout,
                max_body_bytes,
                &headers,
                &cookies,
                allow_cross,
            )
            .await;
            (label, result)
        }));
    }

    collect_fetch_results(handles).await
}

async fn collect_fetch_results(
    handles: Vec<JoinHandle<(String, Result<String, FetchError>)>>,
) -> (Vec<BridgeLine>, Vec<FetchOutcome>) {
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
                all_bridges.extend(bridges.iter().cloned());
                outcomes.push(FetchOutcome {
                    label,
                    bridges_extracted: bridges.len(),
                    error: None,
                    bridges,
                });
            }
            Err(e) => {
                warn!(label = %label, error = %e, "source fetch failed");
                outcomes.push(FetchOutcome {
                    label,
                    bridges_extracted: 0,
                    error: Some(e.to_string()),
                    bridges: Vec::new(),
                });
            }
        }
    }

    (all_bridges, outcomes)
}
