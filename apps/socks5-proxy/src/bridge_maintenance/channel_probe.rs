use std::collections::HashSet;
use std::future::Future;
use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use arti_wrapper::{Settings, TorTunnel};
use bridge_line::BridgeLine;
use bridge_store::BridgeStore;
use futures::StreamExt;
use tokio::time::Instant;
use tracing::{info, warn};

use crate::candidate_pool::key_of;
use crate::config::Config;

const PARALLEL_CHECKS: usize = 8;
const CHANNEL_TIMEOUT: Duration = Duration::from_secs(15);
const ROUND_TIMEOUT: Duration = Duration::from_secs(60);
const FALLBACK_POOL_SIZE: usize = 8;

fn candidates(configured: &[BridgeLine], selected: &[BridgeLine]) -> Vec<BridgeLine> {
    let mut seen = HashSet::new();
    selected
        .iter()
        .chain(configured)
        .filter(|bridge| bridge.transport.as_deref() == Some("obfs4"))
        .filter(|bridge| seen.insert(key_of(bridge)))
        .cloned()
        .collect()
}

/// Cancelled probes release their caller-owned channel requests.
async fn ready_pool<F, Fut>(
    mut bridges: Vec<BridgeLine>,
    cursor: &mut usize,
    check: F,
) -> Vec<(BridgeLine, Duration)>
where
    F: Fn(BridgeLine) -> Fut + Send + Sync,
    Fut: Future<Output = bool> + Send,
{
    let count = bridges.len();
    if count == 0 {
        return Vec::new();
    }
    bridges.rotate_left(*cursor % count);
    let mut started = 0;
    let mut checks = Box::pin(
        futures::stream::iter(bridges)
            .map(|bridge| {
                started += 1;
                let result = check(bridge.clone());
                async move {
                    let began = Instant::now();
                    match tokio::time::timeout(CHANNEL_TIMEOUT, result).await {
                        Ok(true) => Some((bridge, began.elapsed())),
                        _ => None,
                    }
                }
            })
            .buffer_unordered(PARALLEL_CHECKS),
    );
    let mut found = Vec::new();
    let _ = tokio::time::timeout(ROUND_TIMEOUT, async {
        while let Some(result) = checks.next().await {
            if let Some(result) = result {
                found.push(result);
                if found.len() == FALLBACK_POOL_SIZE {
                    break;
                }
            }
        }
    })
    .await;
    drop(checks);
    *cursor = (*cursor + started) % count;
    found
}

pub(super) async fn authenticate_fallback(
    tor: &TorTunnel,
    cfg: &Config,
    path: Option<&Path>,
    active: &Settings,
    selected: &mut Settings,
    cursor: &mut usize,
    prefer_current: bool,
) -> Result<bool> {
    if !selected
        .bridges
        .iter()
        .all(|bridge| bridge.transport.as_deref() == Some("obfs4"))
    {
        return Ok(true);
    }
    let mut configured = cfg.bridges.parsed()?.bridges;
    if let Ok(store) = BridgeStore::load(BridgeStore::resolve_path(path)) {
        configured.retain(|bridge| {
            !store.is_retired(bridge) && store.circuit_fails(bridge) < cfg.bridges.max_circuit_fails
        });
    }
    let pool = candidates(&configured, &selected.bridges);
    let current: Vec<_> = active
        .bridges
        .iter()
        .filter(|bridge| pool.contains(bridge))
        .cloned()
        .collect();
    let check = |bridge: BridgeLine| -> futures::future::BoxFuture<'static, bool> {
        let tor = tor.clone();
        Box::pin(async move {
            matches!(tor.bridge_is_disabled(&bridge), Ok(false))
                && tor.warm_bridge(&bridge).await.is_ok()
                && matches!(tor.bridge_is_disabled(&bridge), Ok(false))
        })
    };
    let mut current_cursor = 0;
    let current_ready = if prefer_current {
        ready_pool(current.clone(), &mut current_cursor, &check).await
    } else {
        Vec::new()
    };
    let found = if current_ready.is_empty() {
        let remaining = pool
            .into_iter()
            .filter(|bridge| !prefer_current || !current.contains(bridge))
            .collect();
        ready_pool(remaining, cursor, &check).await
    } else {
        current_ready
    };
    if found.is_empty() {
        return Ok(false);
    }
    let bridges: Vec<_> = found.iter().map(|(bridge, _)| bridge.clone()).collect();
    if !super::same_bridges(&active.bridges, &bridges) {
        if let Err(error) = crate::bridge_store_writer::apply(path, {
            let bridges = bridges.clone();
            let found = found.clone();
            move |store| {
                let now = time::OffsetDateTime::now_utc();
                store.note_probe_round(&bridges, &found, now, Duration::ZERO, u32::MAX, u32::MAX);
                for bridge in &bridges {
                    store.note_channel_success_at(bridge, now);
                }
            }
        })
        .await
        {
            warn!(%error, "could not persist authenticated fallback bridge");
        }
        info!(
            count = bridges.len(),
            "selected authenticated obfs4 fallback channels"
        );
    }
    selected.bridges = bridges;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(count: u16) -> Vec<BridgeLine> {
        (1..=count)
            .map(|port| {
                format!("obfs4 192.0.2.1:{port} 1111111111111111111111111111111111111111 cert=AAA")
                    .parse()
                    .unwrap()
            })
            .collect()
    }

    #[tokio::test]
    async fn tcp_only_top_thirty_do_not_hide_a_working_fallback() {
        let all = pool(40);
        let ordered = candidates(&all, &all[..30]);
        let mut cursor = 0;
        let found = ready_pool(ordered, &mut cursor, |bridge| async move {
            bridge.addr.port() == 35
        })
        .await;
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, all[34]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_timed_out_round_advances_past_stalled_candidates() {
        use std::sync::{Arc, Mutex};
        let all = pool(64);
        let tried = Arc::new(Mutex::new(HashSet::new()));
        let observed = tried.clone();
        let mut cursor = 0;
        let result = ready_pool(all.clone(), &mut cursor, move |bridge| {
            observed.lock().unwrap().insert(bridge.addr);
            std::future::pending::<bool>()
        })
        .await;
        assert!(result.is_empty());
        assert!(cursor > 0 && cursor < all.len());
        let found = ready_pool(all, &mut cursor, |_| std::future::ready(true)).await;
        assert_eq!(found.len(), FALLBACK_POOL_SIZE);
        assert!(!tried.lock().unwrap().contains(&found[0].0.addr));
    }

    #[tokio::test(start_paused = true)]
    async fn a_fast_channel_does_not_hide_alternative_guards() {
        let all = pool(3);
        let found = ready_pool(all.clone(), &mut 0, |bridge| async move {
            tokio::time::sleep(Duration::from_millis(u64::from(bridge.addr.port()))).await;
            true
        })
        .await;
        assert_eq!(
            found.iter().map(|(bridge, _)| bridge).collect::<Vec<_>>(),
            all.iter().collect::<Vec<_>>()
        );
    }
}
