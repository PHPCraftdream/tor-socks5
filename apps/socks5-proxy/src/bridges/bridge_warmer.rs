//! Background bridge-channel warming pool.
//!
//! Periodically opens (or reuses) Tor channels to the top-N healthiest
//! candidate bridges, ahead of any circuit actually needing them.
//!
//! ## Why this helps
//!
//! `tor-chanmgr` keys its channel cache by relay identity (see
//! `vendor/tor-chanmgr/src/mgr/state.rs`). If this task opens a channel to
//! bridge X via [`arti_wrapper::TorTunnel::warm_bridge`], and arti's own
//! guard manager later wants to build a circuit through the same bridge X,
//! it transparently reuses the already-open channel instead of paying for a
//! fresh obfs4/webtunnel handshake on the hot path. That reuse is entirely
//! automatic inside `ChanMgr` — this module only needs to *ask* for a
//! channel, not wire up anything extra.
//!
//! ## What this is not
//!
//! This task only warms channels. It does not change which bridge carries
//! traffic, and it does not fail over between bridges on degradation — that
//! is a separate, not-yet-built feature. A failed warm attempt is logged
//! and skipped; it never interrupts warming the remaining candidates, and
//! it never affects the live egress path.
//!
//! ## Candidate ranking
//!
//! Candidates are ranked by [`crate::bridge_rank`]: TCP-unreachable bridges
//! are excluded, the rest sort by fewest circuit failures, then most
//! verified circuits, then most successful probes.

use std::path::{Path, PathBuf};
use std::time::Duration;

use bridge_line::BridgeLine;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::bridge_rank::{candidates_with_health, select_top_n};
use crate::config::{Config, WarmPoolConfig};
use crate::tor_watchdog::TorHandle;

/// Spawn the background bridge-warming task as a detached tokio task.
///
/// Every `refresh_interval_secs` the task re-reads the configured bridges
/// and their health from the on-disk store, picks the top `pool_size`
/// candidates (see [`crate::bridge_rank::select_top_n`]), and calls
/// [`arti_wrapper::TorTunnel::warm_bridge`] for each in turn. A failed warm
/// attempt is logged at `warn!` and does not stop the remaining candidates
/// from being warmed this tick. `cfg.enabled == false` (the default)
/// disables the task entirely.
///
/// Shutdown: the `token` is selected against before every tick, so no new warm
/// batch starts after cancellation; a `warm_bridge` handshake already in flight
/// runs to completion and its successes are persisted before the caller joins
/// the handle and closes the bridge-store writer.
pub fn spawn_bridge_warmer(
    handle: TorHandle,
    config_path: Option<PathBuf>,
    cfg: WarmPoolConfig,
    token: CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    #[cfg(test)]
    crate::test_seams::forbid_producer("warmer");
    if !cfg.enabled {
        info!("bridge warm-pool disabled");
        return None;
    }
    if cfg.pool_size == 0 || cfg.refresh_interval_secs == 0 {
        info!("bridge warm-pool disabled (pool_size or refresh_interval_secs is 0)");
        return None;
    }

    let interval = Duration::from_secs(cfg.refresh_interval_secs);
    let pool_size = cfg.pool_size;

    info!(
        pool_size,
        refresh_interval_secs = cfg.refresh_interval_secs,
        "bridge warm-pool armed"
    );

    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await; // consume the immediate first tick

        loop {
            tokio::select! {
                biased;
                _ = token.cancelled() => break,
                _ = ticker.tick() => {},
            }

            let Some(tor) = handle.tunnel().await else {
                // Slot drained (shutdown in progress) — nothing to warm.
                continue;
            };

            let cfg = match Config::load_with_override(config_path.as_deref()) {
                Ok(loaded) => loaded.into_config(),
                Err(e) => {
                    warn!(error = %e, "warm-pool: could not reload config");
                    continue;
                }
            };

            let active = handle.active_bridges();
            let candidates: Vec<_> = candidates_with_health(&cfg, config_path.as_deref())
                .into_iter()
                .filter(|(bridge, _)| active.contains(bridge))
                .collect();
            if candidates.is_empty() {
                continue;
            }
            let selected = select_top_n(&candidates, pool_size);
            if selected.is_empty() {
                continue;
            }

            info!(
                count = selected.len(),
                "warm-pool: warming channels to top candidate bridges"
            );
            let mut warmed: Vec<BridgeLine> = Vec::new();
            for bridge in &selected {
                match tor.warm_bridge(bridge).await {
                    Ok(true) => {
                        info!(bridge = %bridge, "warm-pool: channel warmed");
                        warmed.push(bridge.clone());
                    }
                    // `warm_bridge` reused a channel opened through a
                    // different carrier sharing this bridge's relay
                    // identities; that proves nothing about this bridge
                    // line's own endpoint, so record nothing (and record no
                    // failure either — the check simply did not happen).
                    Ok(false) => {
                        debug!(bridge = %bridge, "warm-pool: channel reused from another endpoint; no channel proof");
                    }
                    Err(e) => {
                        warn!(bridge = %bridge, error = %e, "warm-pool: failed to warm channel");
                    }
                }
            }

            // Persist channel-warm successes to the on-disk store (best-effort).
            // Failures are deliberately not recorded: the store has no
            // channel-failure counters by design — `chseen`/`chok` only track
            // successes, because a failed channel warm is not proof a bridge is
            // dead (same convention as android's `persist_warm_results`, which
            // records successes and retirements only).
            if !warmed.is_empty() {
                persist_warm_successes(config_path.as_deref(), warmed).await;
            }
        }
    }))
}

/// Record channel-warm successes through the single writer (best-effort:
/// a load failure is only logged; publish failures are the writer's
/// retry problem).
async fn persist_warm_successes(config_path: Option<&Path>, warmed: Vec<BridgeLine>) {
    let result = crate::bridge_store_writer::apply(config_path, move |store| {
        let now = OffsetDateTime::now_utc();
        for bridge in &warmed {
            store.note_channel_success_at(bridge, now);
        }
    })
    .await;
    if let Err(error) = result {
        warn!(error = %error, "warm-pool: could not record channel-warm successes");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bridge_store::BridgeStore;

    fn bridge(line: &str) -> BridgeLine {
        line.parse().expect("test bridge line parses")
    }

    const OBFS4_A: &str =
        "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=ZZZ iat-mode=0";

    /// Routing proof: 16 concurrent recorders must all land (16 = count),
    /// which only the single-writer path can guarantee — racing inline
    /// load→mutate→save cycles would lose updates.
    #[tokio::test]
    async fn warm_successes_are_recorded_through_the_single_writer() {
        let _lifecycle = crate::bridge_store_writer::GLOBAL_WRITER_TEST_LOCK
            .lock()
            .await;
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("tor-socks5.ktav");
        let warmed_bridge = bridge(OBFS4_A);

        // Seed the store BEFORE initializing the global writer.
        let mut store = BridgeStore::load(BridgeStore::resolve_path(Some(config_path.as_path())))
            .expect("fresh store loads");
        store.note_source_at(&warmed_bridge, "test", OffsetDateTime::now_utc());
        store.save().expect("seed save");

        let _writer = crate::bridge_store_writer::init_global(Some(config_path.as_path()));

        let mut tasks = Vec::new();
        for _ in 0..16 {
            let config_path = config_path.clone();
            let warmed = warmed_bridge.clone();
            tasks.push(tokio::spawn(async move {
                persist_warm_successes(Some(config_path.as_path()), vec![warmed]).await;
            }));
        }
        for task in tasks {
            task.await.expect("task joins");
        }

        // apply() acks as soon as a mutation is absorbed in memory, before
        // the writer's (now offloaded, coalesced) disk publish runs — so the
        // 16th ack landing does not mean the 16th write has hit disk yet.
        // Poll for it, yielding every iteration so the writer's actor task
        // (on this single-threaded test runtime) actually gets to run.
        let mut count = 0;
        for _ in 0..5000 {
            count = BridgeStore::load(BridgeStore::resolve_path(Some(config_path.as_path())))
                .expect("reload store")
                .channel_ok_count(&warmed_bridge);
            if count == 16 {
                break;
            }
            tokio::task::yield_now().await;
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(count, 16, "no lost update through the single writer");
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read tempdir")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "tmp"))
            .collect();
        assert!(leftovers.is_empty(), "no leftover temp files");

        // Hand the global slot back: the writer must close cleanly so the
        // other global-slot test starts from an empty slot.
        crate::bridge_store_writer::close_global()
            .await
            .expect("close runs when a writer is up")
            .expect("global writer closes");
    }
}
