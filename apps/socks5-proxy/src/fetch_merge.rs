//! Bridge replenishment, split into three decoupled steps:
//!
//! 1. **refresh** ([`refresh_candidate_pool`]) — fetch the source lists over
//!    Tor, dedup, drop anything already in the working config, and stash the
//!    rest in the persistent [`CandidatePool`]. Touches the network to the
//!    public collectors; no bridge probing.
//! 2. **drain** ([`drain_pool`]) — walk the pool **lazily, one bridge at a
//!    time**, promote the reachable ones into the working config, and shed
//!    probed candidates from the pool only once their outcome is durable
//!    (alive → promoted into the config, then removed; dead → discarded;
//!    attempted-deferred → rotated to the back of the queue; unprobed stay
//!    where they are). Touches the network to the
//!    bridges; when a live [`TorTunnel`]
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
/// up to `target` reachable bridges into the working config, and shed probed
/// candidates from the pool once their outcome is durable: dead candidates
/// are discarded, promoted ones only after the config write succeeds — on a
/// config-write failure they stay pooled for the next drain (TS17-08). The
/// same confirm moves attempted-deferred candidates behind the rest of the
/// queue, so a deferred batch cannot starve the candidates behind it.
/// Returns how many were promoted.
///
/// The real admission channel-check: webtunnel candidates go through the
/// blocking circuit verifier (bounded by the remaining drain budget minus
/// [`ADMISSION_JOIN_MARGIN`]), everything else through a live-tunnel channel
/// warm-up. `workers` collects any verification worker the decision outlives
/// — the drain joins them outside the pool transaction (TS17-02).
fn channel_checker(
    tor: &TorTunnel,
    admission_config: Option<std::path::PathBuf>,
    workers: std::sync::Arc<crate::bridge_verifier::AdmissionWorkers>,
) -> ChannelCheck<'static> {
    // Clone the tunnel handle (cheap, Arc-backed) so the future owns its
    // data and the checker is HRTB over the bridge reference alone.
    let tor = tor.clone();
    Box::new(
        move |bridge: &BridgeLine, budget: Duration| -> BoxFuture<'_, bool> {
            let tor = tor.clone();
            let admission_config = admission_config.clone();
            let workers = workers.clone();
            Box::pin(async move {
                if bridge.transport.as_deref() == Some("webtunnel") {
                    return match crate::bridge_verifier::verify_for_admission(
                        bridge.clone(),
                        admission_config,
                        std::time::Instant::now() + budget.saturating_sub(ADMISSION_JOIN_MARGIN),
                        &workers,
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
    )
}

/// The pool access is two cross-process transactions. The first holds the
/// write lock from the initial load through the probe/admission walk, so a
/// concurrent refresh/drain waits instead of taking the same batch — but it
/// saves NOTHING: `take_transport` mutates only the in-memory snapshot, and
/// the on-disk pool keeps every taken candidate. Publishing removals before
/// the config write is what lost verified candidates when that write then
/// failed (TS17-08). The second transaction runs after the config outcome is
/// known: it re-loads the pool fresh under the same cross-process lock and
/// removes exactly the candidates whose outcome is now durable elsewhere —
/// the dead always, the promoted only after a successful config promotion —
/// and rotates the attempted-deferred to the back of the freshly loaded
/// queue, merging with, never overwriting, whatever a concurrent writer
/// published in between. The pool lock is never held across the config write itself
/// (that long hold was removed in R-09/TS17-02).
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
    // One registry per drain: it owns every verification worker the
    // admission decision outlives, and `drain_pool_with` joins them after
    // the pool transaction closes (TS17-02).
    let workers = std::sync::Arc::new(crate::bridge_verifier::AdmissionWorkers::default());
    let checker: Option<ChannelCheck<'static>> =
        tor.map(|tor| channel_checker(tor, admission_config, workers.clone()));
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
    drain_pool_with(config_path, target, checker.as_ref(), &probe, &workers).await
}

async fn drain_pool_with(
    config_path: Option<&Path>,
    target: usize,
    checker: Option<&ChannelCheck<'_>>,
    probe: &ProbeCheck<'_>,
    workers: &crate::bridge_verifier::AdmissionWorkers,
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
    // Cloned: the confirm transaction below needs the same path after this
    // snapshot is consumed.
    let mut pool = CandidatePool::load(pool_path.clone()).context("loading candidate pool")?;
    if pool.is_empty() {
        return Ok(0);
    }

    // Take a bounded batch (we never probe more than `max_attempts`), then
    // walk it one at a time. Nothing is saved here: the on-disk pool keeps
    // the whole batch until the confirm transaction below knows each
    // candidate's outcome is durable elsewhere. Dead entries are shed by
    // that confirm, and attempted-deferred ones are rotated behind the rest
    // of the queue, so the pool still steadily advances across drains
    // rather than re-probing a dead or indefinitely deferred head.
    let max_attempts = target.saturating_mul(50).min(MAX_DRAIN_ATTEMPTS);
    let batch_size = max_attempts.min(pool.len());
    let mut batch = pool.take_transport(batch_size, cfg.bridges.preferred_transport());
    shuffle(&mut batch);

    let mut promoted: Vec<BridgeLine> = Vec::new();
    let mut channel_ok: Vec<BridgeLine> = Vec::new();
    let mut dead = Vec::new();
    let mut deferred = Vec::new();
    let mut reachable = Vec::new();
    let deadline = tokio::time::Instant::now() + DRAIN_BUDGET;
    let mut attempts = 0usize;
    for bridge in batch {
        if promoted.len() >= target
            || attempts >= max_attempts
            || tokio::time::Instant::now() >= deadline
        {
            continue; // stays pooled where it is; a later drain picks it up
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
                continue; // rotates to the back of the queue in the confirm below
            }
            Err(_) => {
                deferred.push(bridge);
                continue; // probe lost or timed out → rotated to the back by the confirm
            }
        };
        // Admission receives the remaining drain budget. The outer deadline
        // also bounds injected checks that do not honor that budget; the
        // webtunnel verifier path self-bounds the same way and hands any
        // outlived worker to `workers`, joined after the lock release below.
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
            // TCP-alive but admission not proven: the confirm below moves it
            // behind the rest of the queue.
            deferred.push(bridge);
        } else {
            dead.push(bridge);
        }
    }

    // TS17-08: nothing has been published yet. `take_transport` mutated only
    // the in-memory snapshot, so the on-disk pool still holds every taken
    // candidate — unprobed, deferred and promoted alike. The confirm below
    // sheds the durable outcomes and rotates the attempted-deferred. The old code saved
    // the removals HERE, before the config write, so a failed or timed-out
    // promotion left a verified candidate in neither store. Instead the pool
    // lock is released now (never held across the config write — that long
    // hold was removed in R-09/TS17-02) and the removals are committed by
    // one confirm transaction after the outcome is known.
    drop(pool_lock);
    // TS17-02: workers whose decision timed out are joined HERE — after the
    // pool transaction is closed. Worker completion is mandatory, but it
    // must not extend the pool lock (that would re-open the long hold R-09
    // removed); and it must not be skipped either, or the worker would keep
    // running detached under VERIFY_LOCK while the next check competes with
    // work its caller already considers finished.
    workers.join_all().await;
    info!(
        promoted = promoted.len(),
        probed = attempts,
        deferred = deferred.len(),
        "drained candidate pool"
    );

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

    // The config promotion decides whether the verified candidates are now
    // durable in the working config. `promote_bridges_in_config` is
    // idempotent (it skips lines already present), so a repeat after a
    // failed attempt cannot double a bridge.
    let promotion: Result<usize> = if promoted.is_empty() {
        Ok(0)
    } else {
        let path = path.to_path_buf();
        let for_config = promoted.clone();
        tokio::task::spawn_blocking(move || promote_bridges_in_config(&path, &for_config))
            .await
            .map_err(|e| anyhow::anyhow!("config promotion task failed: {e}"))
            .and_then(|added| added.context("promoting bridges in config"))
    };

    // The confirm: shed exactly the candidates whose outcome is now durable
    // — the dead always, the promoted only after a successful config write.
    // On a promotion failure the verified candidates are left pooled: the
    // file still holds them (nothing was saved after the take), so the next
    // drain re-probes and re-promotes them idempotently. The transaction
    // loads the pool FRESH under the cross-process lock, so a refresh that
    // merged newcomers while this drain was promoting is merged with, never
    // overwritten by, these removals (TS17-08).
    #[cfg(test)]
    {
        let seam_path = pool_path.clone();
        tokio::task::spawn_blocking(move || {
            crate::test_seams::park_if_armed(crate::test_seams::Site::PreRestore, &seam_path)
        })
        .await
        .expect("pre-restore park joined");
    }
    let mut discard = dead;
    if promotion.is_ok() {
        discard.extend(promoted.iter().cloned());
    }
    let confirmed = if discard.is_empty() && deferred.is_empty() {
        Ok(())
    } else {
        tokio::task::spawn_blocking({
            let pool_path = pool_path.clone();
            move || {
                CandidatePool::transaction(&pool_path, |fresh| {
                    fresh.remove_all(&discard);
                    fresh.rotate_to_back(&deferred);
                })
            }
        })
        .await
        .map_err(|e| anyhow::anyhow!("candidate pool confirm task failed: {e}"))
        .and_then(|inner| inner.map(|_| ()))
    };

    match promotion {
        Ok(added) => {
            if let Err(error) = confirmed {
                // The promotion is durable; the shed is not. The leftovers
                // stay pooled and the next drain sheds them (the promotion
                // it repeats is idempotent), so this is not data loss.
                warn!(%error, "promoted but could not confirm pool removals; the next drain will shed them");
            }
            Ok(added)
        }
        Err(error) => {
            if let Err(confirm_error) = confirmed {
                warn!(%confirm_error, "pool confirm failed too; the pool file keeps every candidate");
            }
            Err(error)
        }
    }
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

/// Add promoted candidates to the latest config snapshot under its path
/// lock. Idempotent: a line already in the working config is not added
/// again, and when nothing is new the config is not rewritten at all —
/// this is what makes the drain's retry after a failed promotion safe.
fn promote_bridges_in_config(path: &Path, promoted: &[BridgeLine]) -> Result<usize> {
    #[cfg(test)]
    if crate::test_seams::take_failure(crate::test_seams::Site::ConfigPromotion, path) {
        anyhow::bail!("injected config promotion failure");
    }
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
#[path = "fetch_merge_tests.rs"]
mod tests;
