//! Bridge replenishment, split into three decoupled steps:
//!
//! 1. **refresh** ([`refresh_candidate_pool`]) — fetch the source lists over
//!    Tor, dedup, drop anything already in the working config, and stash the
//!    rest in the persistent [`CandidatePool`]. Touches the network to the
//!    public collectors; no bridge probing.
//! 2. **drain** ([`drain_pool`]) — walk the pool **lazily, one bridge at a
//!    time**, promote the reachable ones into the working config, and remove
//!    every probed candidate from the pool (alive → promoted, dead →
//!    discarded; unprobed stay for next time). Touches the network only to
//!    the bridges; needs no Tor.
//! 3. [`top_up_working`] ties them together: drain what we already have,
//!    and only fetch more if the pool can't cover the shortfall.
//!
//! Used by the startup auto-fetch, the periodic maintenance loop, and the
//! `bridges fetch` command.

use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use arti_wrapper::TorTunnel;
use bridge_line::BridgeLine;
use tracing::{info, warn};

use crate::candidate_pool::{key_of, CandidatePool, Key};
use crate::config::Config;

/// Per-bridge timeout for the **lazy** pool drain. Shorter than the startup
/// config probe ([`crate::tor_setup::BRIDGE_PROBE_TIMEOUT`]): a live bridge's
/// TCP/TLS target answers well under a second, and since we walk candidates
/// one at a time a tight timeout keeps the (gentle, sequential) walk from
/// stalling for seconds on each dead entry.
const LAZY_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Default per-source HTTPS fetch timeout for the background refresh.
const REFRESH_FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Shuffle in place using a `getrandom`-seeded xorshift (Fisher–Yates).
/// Non-cryptographic — only used so a drain batch mixes transports/sources
/// rather than probing a long run of one kind first. RNG failure → no-op.
fn shuffle<T>(v: &mut [T]) {
    if v.len() < 2 {
        return;
    }
    let mut seed = [0u8; 8];
    if getrandom::getrandom(&mut seed).is_err() {
        return;
    }
    let mut state = u64::from_le_bytes(seed) | 1; // never zero
    for i in (1..v.len()).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let j = (state % (i as u64 + 1)) as usize;
        v.swap(i, j);
    }
}

/// Dedup keys of the bridges currently in the working config.
fn working_keys(cfg: &Config) -> HashSet<Key> {
    match cfg.bridges.parsed() {
        Ok(parsed) => parsed.bridges.iter().map(key_of).collect(),
        Err(_) => HashSet::new(),
    }
}

/// Fetch every configured source over `tor`, log per-source outcomes, and
/// return the deduplicated bridges (both transports). No probing.
///
/// cancel-safe: NO — performs network I/O over Tor.
async fn fetch_sources(
    tor: &TorTunnel,
    cfg: &Config,
    fetch_timeout: Duration,
) -> Result<Vec<BridgeLine>> {
    let sources: Vec<bridge_fetcher::Source> = cfg
        .bridges
        .sources
        .iter()
        .map(|s| bridge_fetcher::Source {
            label: s.label.clone(),
            url: s.url.clone(),
            headers: s.headers.clone(),
            cookies: s.cookies.clone(),
        })
        .collect();
    if sources.is_empty() {
        return Ok(Vec::new());
    }

    let max_body_bytes = cfg.bridges.max_body_mib.saturating_mul(1024 * 1024);
    let (fetched, outcomes) =
        bridge_fetcher::fetch_all(tor, &sources, fetch_timeout, max_body_bytes).await;
    for o in &outcomes {
        if let Some(ref e) = o.error {
            warn!(label = %o.label, error = %e, "bridge source failed");
        } else {
            info!(label = %o.label, bridges = o.bridges_extracted, "bridge source OK");
        }
    }

    let (unique, dups) = bridge_fetcher::dedup_bridges(fetched);
    if dups > 0 {
        info!(
            unique = unique.len(),
            duplicates = dups,
            "deduplicated fetched bridges"
        );
    }
    Ok(unique)
}

/// Refresh the candidate pool: fetch the sources over `tor`, drop anything
/// already in the working config or already pooled, and persist the rest.
/// Returns how many new candidates were added.
///
/// cancel-safe: NO — performs network I/O over Tor and writes the pool.
pub(crate) async fn refresh_candidate_pool(
    tor: &TorTunnel,
    cfg: &Config,
    config_path: Option<&Path>,
    fetch_timeout: Duration,
) -> Result<usize> {
    let fetched = fetch_sources(tor, cfg, fetch_timeout).await?;
    if fetched.is_empty() {
        return Ok(0);
    }
    let exclude = working_keys(cfg);
    let mut pool = CandidatePool::load(CandidatePool::resolve_path(config_path))
        .context("loading candidate pool")?;
    let added = pool.merge(fetched, &exclude);
    pool.save().context("saving candidate pool")?;
    info!(
        added,
        pool = pool.len(),
        "refreshed candidate pool from sources"
    );
    Ok(added)
}

/// Drain the candidate pool: walk it lazily (one bridge at a time), promote
/// up to `target` reachable bridges into the working config, and remove
/// every probed candidate from the pool. Returns how many were promoted.
///
/// No Tor needed — this only probes bridge reachability directly.
///
/// cancel-safe: NO — probes the network and writes the pool + config.
pub(crate) async fn drain_pool(config_path: Option<&Path>, target: usize) -> Result<usize> {
    if target == 0 {
        return Ok(0);
    }
    let pool_path = CandidatePool::resolve_path(config_path);
    let mut pool = CandidatePool::load(pool_path).context("loading candidate pool")?;
    if pool.is_empty() {
        return Ok(0);
    }

    // Take a bounded batch (we never probe more than `max_attempts`), then
    // walk it one at a time. Dead candidates are dropped from the pool;
    // unprobed ones go back for next time. Because dead entries are removed,
    // the pool steadily advances across drains rather than re-probing a
    // dead head.
    let max_attempts = target.saturating_mul(50).max(50);
    let batch_size = max_attempts.min(pool.len());
    let mut batch = pool.take(batch_size);
    shuffle(&mut batch);

    let mut promoted: Vec<BridgeLine> = Vec::new();
    let mut unprobed: Vec<BridgeLine> = Vec::new();
    let mut attempts = 0usize;
    for bridge in batch {
        if promoted.len() >= target || attempts >= max_attempts {
            unprobed.push(bridge);
            continue;
        }
        attempts += 1;
        match bridge_probe::probe_one(&bridge, LAZY_PROBE_TIMEOUT).await {
            Some(latency) => {
                info!(
                    addr = %bridge.addr,
                    transport = ?bridge.transport,
                    latency_ms = latency.as_millis() as u64,
                    "candidate reachable — promoting to working bridges"
                );
                promoted.push(bridge);
            }
            None => { /* dead: already removed from the pool by take() */ }
        }
    }

    // Unprobed candidates return to the pool; probed (alive + dead) do not.
    pool.return_front(unprobed);
    pool.save().context("saving candidate pool after drain")?;
    info!(
        promoted = promoted.len(),
        probed = attempts,
        pool = pool.len(),
        "drained candidate pool"
    );

    if promoted.is_empty() {
        return Ok(0);
    }
    let Some(path) = config_path else {
        return Ok(0);
    };
    // Reload from disk so we don't clobber concurrent edits/prunes.
    let mut latest = Config::load_with_override(Some(path))
        .context("reloading config to promote bridges")?
        .into_config();
    let before = latest.bridges.lines.len();
    for b in &promoted {
        let line = b.to_string();
        if !latest.bridges.lines.contains(&line) {
            latest.bridges.lines.push(line);
        }
    }
    let added = latest.bridges.lines.len() - before;
    if added > 0 {
        latest
            .write(path)
            .context("writing config with promoted bridges")?;
    }
    Ok(added)
}

/// Top up the working bridge list by `target` reachable bridges: drain what
/// the pool already holds first (no fetch), and only refresh from the
/// sources over Tor if the pool couldn't cover the shortfall. Returns the
/// number promoted into the working config.
///
/// cancel-safe: NO.
pub(crate) async fn top_up_working(
    tor: &TorTunnel,
    cfg: &Config,
    config_path: Option<&Path>,
    target: usize,
) -> Result<usize> {
    if target == 0 {
        return Ok(0);
    }
    let mut promoted = drain_pool(config_path, target).await?;
    if promoted < target && !cfg.bridges.sources.is_empty() {
        info!(
            have = promoted,
            want = target,
            "pool short — refreshing candidates from sources over Tor"
        );
        refresh_candidate_pool(tor, cfg, config_path, REFRESH_FETCH_TIMEOUT).await?;
        promoted += drain_pool(config_path, target - promoted).await?;
    }
    Ok(promoted)
}
