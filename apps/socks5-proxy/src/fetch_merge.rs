//! Bridge replenishment, split into three decoupled steps:
//!
//! 1. **refresh** ([`refresh_candidate_pool`]) — fetch the source lists over
//!    Tor, dedup, drop anything already in the working config, and stash the
//!    rest in the persistent [`CandidatePool`]. Touches the network to the
//!    public collectors; no bridge probing.
//! 2. **drain** ([`drain_pool`]) — walk the pool **lazily, one bridge at a
//!    time**, promote the reachable ones into the working config, and remove
//!    removed
//!    from the pool (alive → promoted, dead → discarded; unprobed stay for
//!    next time). Touches the network to the bridges; when a live [`TorTunnel`]
//!    is available, admission also requires a real Tor channel to the bridge,
//!    so mere TCP-alive impostors are rejected.
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
use futures::future::BoxFuture;
use tracing::{info, warn};

use crate::candidate_pool::{key_of, CandidatePool, Key};
use crate::config::Config;
use persist_lock::{PathLock, CLI_LOCK_WAIT};

/// Per-bridge timeout for the **lazy** pool drain. Shorter than the startup
/// config probe ([`crate::tor_setup::BRIDGE_PROBE_TIMEOUT`]): a live bridge's
/// TCP/TLS target answers well under a second, and since we walk candidates
/// one at a time a tight timeout keeps the (gentle, sequential) walk from
/// stalling for seconds on each dead entry.
const LAZY_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Default per-source HTTPS fetch timeout for the background refresh.
const REFRESH_FETCH_TIMEOUT: Duration = Duration::from_secs(30);

const MAX_DRAIN_ATTEMPTS: usize = 12;
const DRAIN_BUDGET: Duration = Duration::from_secs(60);
const CHANNEL_CHECK_TIMEOUT: Duration = Duration::from_secs(15);
const ADMISSION_JOIN_MARGIN: Duration = Duration::from_millis(50);

fn current_source_url(url: &str) -> &str {
    match url {
        "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/main/bridges-webtunnel" =>
            "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector-v2/main/bridges/webtunnel_tested.txt",
        _ => url,
    }
}

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
            url: current_source_url(&s.url).to_owned(),
            headers: s.headers.clone(),
            cookies: s.cookies.clone(),
            allow_credentials_cross_origin: s.allow_credentials_cross_origin,
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
/// The pool update is one cross-process transaction, run off the async
/// worker so the lock wait cannot block it; on caller cancellation the job
/// finishes detached — a complete, lock-protected whole-file write.
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
    let pool_path = CandidatePool::resolve_path(config_path);
    let migration = cfg
        .bridges
        .sources
        .iter()
        .any(|source| current_source_url(&source.url) != source.url);
    let preferred_transport = cfg.bridges.preferred_transport().map(str::to_owned);
    let (added, pool_len) = tokio::task::spawn_blocking(move || {
        CandidatePool::transaction(&pool_path, |pool| {
            let added = pool.merge(fetched.iter().cloned(), &exclude);
            if migration {
                pool.prioritize(&fetched, preferred_transport.as_deref());
            }
            (added, pool.len())
        })
    })
    .await
    .map_err(|e| anyhow::anyhow!("candidate pool update task failed: {e}"))?
    .context("updating candidate pool")?;
    if migration {
        if let Some(path) = config_path {
            let path = path.to_path_buf();
            tokio::task::spawn_blocking(move || migrate_legacy_source(&path))
                .await
                .map_err(|e| anyhow::anyhow!("config migration task failed: {e}"))??;
            info!("updated the legacy WebTunnel source to the current tested list");
        }
    }
    info!(
        added,
        pool = pool_len,
        "refreshed candidate pool from sources"
    );
    Ok(added)
}

/// Injectable channel-admission check: wraps `TorTunnel::warm_bridge` so the
/// admission decision can be tested without a network. `true` means a real
/// Tor link handshake succeeded against the bridge.
type ChannelCheck<'a> =
    Box<dyn for<'b> Fn(&'b BridgeLine, Duration) -> BoxFuture<'b, bool> + Send + Sync + 'a>;

type ProbeCheck<'a> =
    Box<dyn for<'b> Fn(&'b BridgeLine) -> BoxFuture<'b, bridge_probe::Outcome> + Send + Sync + 'a>;

/// Two-layer admission for one pool candidate: the TCP probe must pass, and
/// when a channel check is available, the bridge must also accept a real Tor
/// channel. `channel: None` keeps the documented cold-start fallback alive:
/// before Tor bootstraps there is no `TorTunnel` to warm through, and getting
/// something TCP-alive beats waiting for full channel verification — TCP-only
/// admission is a documented fallback, not an omission.
async fn admits_candidate(
    tcp_latency: Option<Duration>,
    bridge: &BridgeLine,
    channel: Option<&ChannelCheck<'_>>,
    deadline: tokio::time::Instant,
) -> bool {
    let Some(latency) = tcp_latency else {
        // TCP-dead candidates are never admitted and never channel-checked:
        // a Tor link handshake to a dead address would only re-prove the
        // failure the probe just established.
        return false;
    };
    match channel {
        Some(check) => {
            let budget = deadline.saturating_duration_since(tokio::time::Instant::now());
            if budget.is_zero() {
                return false;
            }
            if check(bridge, budget).await {
                info!(
                    addr = %bridge.addr,
                    transport = ?bridge.transport,
                    latency_ms = latency.as_millis() as u64,
                    "candidate reachable — Tor channel verified, promoting to working bridges"
                );
                true
            } else {
                warn!(
                    addr = %bridge.addr,
                    transport = ?bridge.transport,
                    latency_ms = latency.as_millis() as u64,
                    "candidate channel verification failed; deferring"
                );
                false
            }
        }
        None => {
            info!(
                addr = %bridge.addr,
                transport = ?bridge.transport,
                latency_ms = latency.as_millis() as u64,
                "candidate reachable — promoting to working bridges (TCP-only, no channel check available)"
            );
            true
        }
    }
}

/// Drain the candidate pool: walk it lazily (one bridge at a time), promote
/// up to `target` reachable bridges into the working config, and remove
/// every probed candidate from the pool. Returns how many were promoted.
///
/// The pool access is one cross-process transaction: the write lock is held
/// from the initial load through the final save — across probe and admission —
/// so a concurrent refresh/drain waits instead of publishing over the
/// removals this drain is about to make. The guard is a plain file handle,
/// safe to hold across `.await`; cancellation drops it before any save,
/// leaving the pool file untouched.
///
/// Admission is two-layer: a TCP probe must pass, and when `tor` is `Some`,
/// the candidate must additionally accept a real Tor channel
/// (`TorTunnel::warm_bridge`), so any TCP-alive non-Tor service is rejected.
/// Passing `tor: None` deliberately falls back to TCP-only admission — that
/// is the cold-start path, where no live tunnel exists yet to warm through.
///
/// cancel-safe: NO — probes the network and writes the pool + config.
pub(crate) async fn drain_pool(
    config_path: Option<&Path>,
    target: usize,
    tor: Option<&TorTunnel>,
) -> Result<usize> {
    let admission_config = config_path.map(Path::to_path_buf);
    let checker: Option<ChannelCheck<'static>> = tor.map(|tor| -> ChannelCheck<'static> {
        // Clone the tunnel handle (cheap, Arc-backed) so the future owns its
        // data and the checker is HRTB over the bridge reference alone.
        let tor = tor.clone();
        let check: ChannelCheck<'static> = Box::new(
            move |bridge: &BridgeLine, budget: Duration| -> BoxFuture<'_, bool> {
                let tor = tor.clone();
                let admission_config = admission_config.clone();
                Box::pin(async move {
                    if bridge.transport.as_deref() == Some("webtunnel") {
                        return match crate::bridge_verifier::verify_for_admission(
                            bridge.clone(),
                            admission_config,
                            std::time::Instant::now()
                                + budget.saturating_sub(ADMISSION_JOIN_MARGIN),
                        )
                        .await
                        {
                            Ok(verified) => verified,
                            Err(error) => {
                                warn!(%error, "candidate HTTPS verification could not complete");
                                false
                            }
                        };
                    }
                    matches!(
                        tokio::time::timeout(CHANNEL_CHECK_TIMEOUT, tor.warm_bridge(bridge)).await,
                        Ok(Ok(true))
                    )
                })
            },
        );
        check
    });
    let cfg = Config::load_with_override(config_path)?.into_config();
    let policy = bridge_probe::ResolverPolicy {
        doh_enabled: cfg.dns.doh_enabled,
        system_fallback: cfg.dns.system_fallback,
    };
    let probe: ProbeCheck<'static> = Box::new(move |bridge| {
        Box::pin(async move {
            bridge_probe::probe_all_with_policy(vec![bridge.clone()], LAZY_PROBE_TIMEOUT, policy)
                .await
                .pop()
                .expect("one bridge produces one report")
                .outcome
        })
    });
    drain_pool_with(config_path, target, checker.as_ref(), &probe).await
}

async fn drain_pool_with(
    config_path: Option<&Path>,
    target: usize,
    checker: Option<&ChannelCheck<'_>>,
    probe: &ProbeCheck<'_>,
) -> Result<usize> {
    if target == 0 {
        return Ok(0);
    }
    let Some(path) = config_path else {
        return Ok(0);
    };
    let cfg = Config::load_with_override(Some(path))?.into_config();
    let pool_path = CandidatePool::resolve_path(config_path);
    // Test-only forcing point: park before the acquisition (blocking pool —
    // never block a worker on the gate).
    #[cfg(test)]
    {
        let seam_path = pool_path.clone();
        tokio::task::spawn_blocking(move || {
            crate::test_seams::park_if_armed(crate::test_seams::Site::PreAcquire, &seam_path)
        })
        .await
        .expect("pre-acquire park joined");
    }
    let pool_lock = CandidatePool::acquire_transaction_lock(&pool_path)
        .await
        .context("locking candidate pool for drain")?;
    let mut pool = CandidatePool::load(pool_path).context("loading candidate pool")?;
    if pool.is_empty() {
        return Ok(0);
    }

    // Take a bounded batch (we never probe more than `max_attempts`), then
    // walk it one at a time. Dead candidates are dropped from the pool;
    // unprobed ones go back for next time. Because dead entries are removed,
    // the pool steadily advances across drains rather than re-probing a
    // dead head.
    let max_attempts = target.saturating_mul(50).min(MAX_DRAIN_ATTEMPTS);
    let batch_size = max_attempts.min(pool.len());
    let mut batch = pool.take_transport(batch_size, cfg.bridges.preferred_transport());
    shuffle(&mut batch);

    let mut promoted: Vec<BridgeLine> = Vec::new();
    let mut channel_ok: Vec<BridgeLine> = Vec::new();
    let mut unprobed: Vec<BridgeLine> = Vec::new();
    let mut deferred = Vec::new();
    let mut reachable = Vec::new();
    let deadline = tokio::time::Instant::now() + DRAIN_BUDGET;
    let mut attempts = 0usize;
    for bridge in batch {
        if promoted.len() >= target
            || attempts >= max_attempts
            || tokio::time::Instant::now() >= deadline
        {
            unprobed.push(bridge);
            continue;
        }
        attempts += 1;
        let latency = match tokio::time::timeout_at(deadline, probe(&bridge)).await {
            Ok(bridge_probe::Outcome::Reachable { latency }) => Some(latency),
            Ok(bridge_probe::Outcome::Unreachable { reason }) => {
                tracing::debug!(transport = ?bridge.transport, %reason, "candidate probe failed");
                None
            }
            Ok(bridge_probe::Outcome::Unmeasured { reason }) => {
                tracing::debug!(transport = ?bridge.transport, %reason, "candidate probe deferred");
                deferred.push(bridge);
                continue;
            }
            Err(_) => {
                deferred.push(bridge);
                continue;
            }
        };
        // Admission receives the remaining drain budget. The outer deadline
        // also bounds injected checks that do not honor that budget.
        if tokio::time::timeout_at(
            deadline,
            admits_candidate(latency, &bridge, checker, deadline),
        )
        .await
        .unwrap_or(false)
        {
            promoted.push(bridge.clone());
            if let Some(latency) = latency {
                reachable.push((bridge.clone(), latency));
            }
            if latency.is_some() && checker.is_some() {
                channel_ok.push(bridge);
            }
        } else if latency.is_some() {
            deferred.push(bridge);
        }
        // Dead: already removed from the pool by take().
    }

    // Unprobed candidates return to the pool; probed (alive + dead) do not.
    // Still inside the drain's transaction: this save publishes the removals
    // together with the front-returns.
    pool.return_front(unprobed);
    pool.merge(deferred, &HashSet::new());
    pool.save().context("saving candidate pool after drain")?;
    drop(pool_lock);
    info!(
        promoted = promoted.len(),
        probed = attempts,
        pool = pool.len(),
        "drained candidate pool"
    );

    if promoted.is_empty() {
        return Ok(0);
    }

    // Best-effort record — routed through the single bridge-store writer.
    // This site runs both inside the daemon (maintenance auto-fetch via
    // `top_up_working`) and in the CLI `bridges fetch` subcommand, which is
    // a separate process and therefore takes the writer's inline fallback.
    // Only an unreadable on-disk store is logged here; publish failures are
    // the writer's retry problem.
    if !channel_ok.is_empty() {
        if let Err(e) = crate::bridge_store_writer::apply(config_path, {
            let promoted = promoted.clone();
            let reachable = reachable.clone();
            let channel_ok = channel_ok.clone();
            move |store| {
                let now = time::OffsetDateTime::now_utc();
                store.note_probe_round(
                    &promoted,
                    &reachable,
                    now,
                    Duration::ZERO,
                    u32::MAX,
                    u32::MAX,
                );
                for b in &channel_ok {
                    store.note_channel_success_at(b, now);
                    if b.transport.as_deref() == Some("webtunnel") {
                        store.note_circuit_verified_at(b, now);
                        store.note_circuit_success_at(b, now);
                    }
                }
            }
        })
        .await
        {
            warn!(error = %e, "could not record channel successes after drain");
        }
    }

    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || promote_bridges_in_config(&path, &promoted))
        .await
        .map_err(|e| anyhow::anyhow!("config promotion task failed: {e}"))?
        .context("promoting bridges in config")
}

/// Update the legacy source URL as one locked config transaction.
fn migrate_legacy_source(path: &Path) -> Result<()> {
    let _lock = PathLock::acquire_bounded(path, CLI_LOCK_WAIT)
        .context("config write lock while migrating bridge source")?;
    let mut latest = Config::load_with_override(Some(path))?.into_config();
    for source in &mut latest.bridges.sources {
        source.url = current_source_url(&source.url).to_owned();
    }
    latest
        .write(path)
        .context("writing migrated bridge source")?;
    Ok(())
}

/// Add promoted candidates to the latest config snapshot under its path lock.
fn promote_bridges_in_config(path: &Path, promoted: &[BridgeLine]) -> Result<usize> {
    let _lock = PathLock::acquire_bounded(path, CLI_LOCK_WAIT)
        .context("config write lock while promoting bridges")?;
    let mut latest = Config::load_with_override(Some(path))
        .context("reloading config to promote bridges")?
        .into_config();
    let before = latest.bridges.lines.len();
    for b in promoted {
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
    let mut promoted = drain_pool(config_path, target, Some(tor)).await?;
    if promoted < target && !cfg.bridges.sources.is_empty() {
        info!(
            have = promoted,
            want = target,
            "pool short — refreshing candidates from sources over Tor"
        );
        refresh_candidate_pool(tor, cfg, config_path, REFRESH_FETCH_TIMEOUT).await?;
        promoted += drain_pool(config_path, target - promoted, Some(tor)).await?;
    }
    Ok(promoted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_seams::{HANG_GUARD, UNBLOCK_GUARD};
    use bridge_store::BridgeStore;

    #[test]
    fn source_migration_only_changes_the_known_legacy_webtunnel_list() {
        let old = "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/main/bridges-webtunnel";
        let current = current_source_url(old);
        assert!(current.ends_with("Tor-Bridges-Collector-v2/main/bridges/webtunnel_tested.txt"));
        assert_eq!(current_source_url(current), current);
        let custom = "https://private.example/bridges-webtunnel";
        assert_eq!(current_source_url(custom), custom);
    }

    fn discovery_fixture() -> (tempfile::TempDir, std::path::PathBuf, BridgeLine) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proxy.ktav");
        let mut cfg = Config::default();
        cfg.bridges.transport = "webtunnel".into();
        cfg.bridges.lines = vec![bridge().to_string()];
        cfg.write(&path).unwrap();
        let wt: BridgeLine = "webtunnel [2001:db8::1]:443 0123456789ABCDEF0123456789ABCDEF01234567 url=https://example.com/bridge"
            .parse().unwrap();
        let mut pool = CandidatePool::load(CandidatePool::resolve_path(Some(&path))).unwrap();
        let obfs = (1..=100).map(|i| {
            format!("obfs4 1.2.4.{i}:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA")
                .parse::<BridgeLine>()
                .unwrap()
        });
        pool.merge(obfs.chain([wt.clone()]), &HashSet::new());
        pool.save().unwrap();
        (dir, path, wt)
    }

    fn reachable_probe() -> ProbeCheck<'static> {
        Box::new(|bridge| {
            assert_eq!(bridge.transport.as_deref(), Some("webtunnel"));
            Box::pin(async {
                bridge_probe::Outcome::Reachable {
                    latency: Duration::from_millis(10),
                }
            })
        })
    }

    #[test]
    fn working_set_with_stale_cert_does_not_exclude_fresh_cert() {
        // The server rotated its obfs4 key: the working config holds the old
        // cert, the source brings the fresh one. working_keys is built with
        // candidate_pool::key_of, which includes the cert, so the fresh
        // candidate must not be excluded — a pool merge keeps it.
        let stale: BridgeLine =
            "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=ZZZ iat-mode=0"
                .parse()
                .unwrap();
        let fresh: BridgeLine =
            "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=YYY iat-mode=0"
                .parse()
                .unwrap();
        let mut cfg = Config::default();
        cfg.bridges.lines = vec![stale.to_string()];
        let exclude = working_keys(&cfg);
        assert!(exclude.contains(&key_of(&stale)));
        assert!(
            !exclude.contains(&key_of(&fresh)),
            "fresh cert on the same relay must not be excluded by the stale one"
        );
        let dir = tempfile::tempdir().unwrap();
        let mut pool =
            CandidatePool::load(CandidatePool::resolve_path(Some(&dir.path().join("c.log"))))
                .unwrap();
        assert_eq!(pool.merge([fresh], &exclude), 1);
    }

    #[tokio::test]
    async fn discovery_promotes_webtunnel_and_records_channel_evidence() {
        let (_dir, path, wt) = discovery_fixture();
        let added = drain_pool_with(Some(&path), 1, Some(&check(true)), &reachable_probe())
            .await
            .unwrap();
        assert_eq!(added, 1);
        let cfg = Config::load_with_override(Some(&path))
            .unwrap()
            .into_config();
        assert!(cfg.bridges.parsed().unwrap().bridges.contains(&wt));
        let store = BridgeStore::load(BridgeStore::resolve_path(Some(&path))).unwrap();
        assert_eq!(store.channel_ok_count(&wt), 1);
        assert_eq!(store.ok_count(&wt), 1);
        let mut pool = CandidatePool::load(CandidatePool::resolve_path(Some(&path))).unwrap();
        assert_eq!(pool.len(), 100);
        assert!(pool
            .take(100)
            .iter()
            .all(|b| b.transport.as_deref() == Some("obfs4")));
    }

    #[tokio::test]
    async fn resolver_failure_keeps_webtunnel_for_a_later_successful_attempt() {
        let (_dir, path, wt) = discovery_fixture();
        let unavailable: ProbeCheck<'static> = Box::new(|_| {
            Box::pin(async {
                bridge_probe::Outcome::Unmeasured {
                    reason: "resolver unavailable".into(),
                }
            })
        });
        assert_eq!(
            drain_pool_with(Some(&path), 1, Some(&check(true)), &unavailable)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            CandidatePool::load(CandidatePool::resolve_path(Some(&path)))
                .unwrap()
                .len(),
            101
        );
        assert_eq!(
            drain_pool_with(Some(&path), 1, Some(&check(true)), &reachable_probe())
                .await
                .unwrap(),
            1
        );
        let cfg = Config::load_with_override(Some(&path))
            .unwrap()
            .into_config();
        assert!(cfg.bridges.parsed().unwrap().bridges.contains(&wt));
    }

    #[tokio::test]
    async fn transient_channel_failure_does_not_discard_a_candidate() {
        let (_dir, path, _) = discovery_fixture();
        assert_eq!(
            drain_pool_with(Some(&path), 1, Some(&check(false)), &reachable_probe())
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            drain_pool_with(Some(&path), 1, Some(&check(true)), &reachable_probe())
                .await
                .unwrap(),
            1
        );
    }

    fn check(ok: bool) -> ChannelCheck<'static> {
        Box::new(move |_: &BridgeLine, _: Duration| Box::pin(async move { ok }))
    }

    fn bridge() -> BridgeLine {
        "obfs4 1.2.3.4:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0"
            .parse()
            .expect("valid bridge line")
    }

    #[tokio::test]
    async fn tcp_ok_and_channel_ok_promotes() {
        let b = bridge();
        assert!(
            admits_candidate(
                Some(Duration::from_millis(120)),
                &b,
                Some(&check(true)),
                tokio::time::Instant::now() + Duration::from_secs(1),
            )
            .await
        );
    }

    #[tokio::test]
    async fn tcp_ok_but_channel_fails_rejects() {
        let b = bridge();
        assert!(
            !admits_candidate(
                Some(Duration::from_millis(120)),
                &b,
                Some(&check(false)),
                tokio::time::Instant::now() + Duration::from_secs(1),
            )
            .await
        );
    }

    #[tokio::test]
    async fn tcp_ok_with_no_channel_check_falls_back_to_tcp_only() {
        // Documented cold-start fallback: no live tunnel to warm through.
        let b = bridge();
        assert!(
            admits_candidate(
                Some(Duration::from_millis(120)),
                &b,
                None,
                tokio::time::Instant::now() + Duration::from_secs(1),
            )
            .await
        );
    }

    #[tokio::test]
    async fn tcp_dead_rejects_without_consulting_channel_check() {
        let consulted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = consulted.clone();
        let spy: ChannelCheck<'static> = Box::new(move |_: &BridgeLine, _: Duration| {
            let flag = flag.clone();
            Box::pin(async move {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
                true
            })
        });
        let b = bridge();
        assert!(
            !admits_candidate(
                None,
                &b,
                Some(&spy),
                tokio::time::Instant::now() + Duration::from_secs(1),
            )
            .await
        );
        assert!(!consulted.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn admission_timeout_returns_candidate_and_releases_pool_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proxy.ktav");
        let mut cfg = Config::default();
        cfg.bridges.transport = "webtunnel".into();
        cfg.write(&path).unwrap();
        let candidate: BridgeLine =
            "webtunnel [2001:db8::1]:443 0123456789ABCDEF0123456789ABCDEF01234567 url=https://example.com/bridge"
                .parse()
                .unwrap();
        let pool_path = CandidatePool::resolve_path(Some(&path));
        let mut pool = CandidatePool::load(pool_path.clone()).unwrap();
        assert_eq!(pool.merge([candidate.clone()], &HashSet::new()), 1);
        pool.save().unwrap();

        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let started_tx = std::sync::Arc::new(std::sync::Mutex::new(Some(started_tx)));
        let started_for_checker = started_tx.clone();
        let checker: ChannelCheck<'static> = Box::new(move |_: &BridgeLine, _: Duration| {
            if let Some(sender) = started_for_checker.lock().unwrap().take() {
                let _ = sender.send(());
            }
            Box::pin(std::future::pending::<bool>())
        });
        let probe: ProbeCheck<'static> = Box::new(|_| {
            Box::pin(async {
                bridge_probe::Outcome::Reachable {
                    latency: Duration::from_millis(1),
                }
            })
        });
        let task_path = path.clone();
        let task = tokio::spawn(async move {
            drain_pool_with(Some(&task_path), 1, Some(&checker), &probe).await
        });
        started_rx.await.unwrap();
        tokio::time::advance(DRAIN_BUDGET).await;
        assert_eq!(task.await.unwrap().unwrap(), 0);

        // The timed-out admission is deferred, and the pool transaction has
        // completed, so another writer can acquire the lock immediately.
        let added = tokio::task::spawn_blocking(move || {
            CandidatePool::transaction(&pool_path, |pool| {
                assert_eq!(pool.len(), 1);
                pool.merge([], &HashSet::new())
            })
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(added, 0);
        let restored = CandidatePool::load(CandidatePool::resolve_path(Some(&path)))
            .unwrap()
            .take(1);
        assert_eq!(restored, vec![candidate]);
    }

    /// Actual-caller overlap: a pool transaction (the refresh path) parked
    /// mid-flight owns the pool lock, so `drain_pool_with` — the
    /// maintenance/CLI drain — must wait and then build on its published
    /// state. Forcing: the drain is parked before its acquisition and
    /// released only while the transaction provably owns the lock (parked
    /// after its load, unreleased). The transaction's gate is released when
    /// the drain completes, or — when the drain is correctly still blocked —
    /// after a guard timeout; the timeout only picks the releaser, the lock
    /// itself orders the correct-mode outcome.
    #[tokio::test]
    async fn drain_waits_for_a_concurrent_pool_transaction_and_both_effects_survive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proxy.ktav");
        let mut cfg = Config::default();
        cfg.bridges.transport = "webtunnel".into();
        cfg.write(&path).unwrap();

        let wt: BridgeLine =
            "webtunnel [2001:db8::1]:443 0123456789ABCDEF0123456789ABCDEF01234567 url=https://example.com/bridge"
                .parse()
                .unwrap();
        let other: BridgeLine =
            "obfs4 1.2.3.4:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0"
                .parse()
                .unwrap();
        let newcomer: BridgeLine =
            "obfs4 1.2.3.9:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=CCC iat-mode=0"
                .parse()
                .unwrap();

        let pool_path = CandidatePool::resolve_path(Some(&path));
        let mut seed = CandidatePool::load(pool_path.clone()).unwrap();
        assert_eq!(
            seed.merge(vec![other.clone(), wt.clone()], &HashSet::new()),
            2
        );
        seed.save().unwrap();

        let pre =
            crate::test_seams::ParkedGate::arm(crate::test_seams::Site::PreAcquire, &pool_path);
        let post =
            crate::test_seams::ParkedGate::arm(crate::test_seams::Site::PostLoad, &pool_path);
        let post_for_drain = post.clone();
        let (drain_done_tx, drain_done_rx) = std::sync::mpsc::channel();
        let drain_path = path.clone();
        let drain_task = tokio::spawn(async move {
            let checker = check(true);
            let probe = reachable_probe();
            let out = drain_pool_with(Some(&drain_path), 1, Some(&checker), &probe).await;
            post_for_drain.release();
            let _ = drain_done_tx.send(());
            out
        });
        let pre_wait = pre.clone();
        tokio::task::spawn_blocking(move || pre_wait.wait_parked(HANG_GUARD))
            .await
            .unwrap();

        let tx_path = pool_path.clone();
        let newcomer_for_tx = newcomer.clone();
        let tx = std::thread::spawn(move || {
            CandidatePool::transaction(&tx_path, |p| {
                p.merge([newcomer_for_tx.clone()], &HashSet::new())
            })
        });
        let post_wait = post.clone();
        tokio::task::spawn_blocking(move || post_wait.wait_parked(HANG_GUARD))
            .await
            .unwrap();

        // The drain now reaches its acquisition while the transaction owns
        // the lock.
        pre.release();
        let drain_finished =
            tokio::task::spawn_blocking(move || drain_done_rx.recv_timeout(UNBLOCK_GUARD).is_ok())
                .await
                .unwrap();
        let _drain_finished = drain_finished;
        // Release the transaction in both modes. Correct locking leaves the
        // drain blocked; bypassing it lets the final assertions fail.
        post.release();

        let added = tx.join().unwrap().unwrap();
        let promoted = drain_task.await.unwrap().unwrap();
        assert_eq!(added, 1, "the parked transaction adds the newcomer");
        assert_eq!(promoted, 1, "the drain promotes the webtunnel candidate");

        let latest = Config::load_with_override(Some(&path))
            .unwrap()
            .into_config();
        assert!(
            latest.bridges.parsed().unwrap().bridges.contains(&wt),
            "the drain promoted the webtunnel candidate into the working config"
        );

        let mut pool = CandidatePool::load(pool_path).unwrap();
        assert_eq!(
            pool.take(10),
            vec![other, newcomer],
            "the parked transaction's addition survives; the consumed webtunnel candidate stays removed"
        );
    }
}
