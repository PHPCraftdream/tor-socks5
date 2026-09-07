//! One owner for startup, periodic, and connection-triggered bridge refreshes.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Result;
use arti_wrapper::Settings;
use bridge_line::BridgeLine;
use bridge_store::BridgeStore;
use time::OffsetDateTime;
use tokio::time::{Instant, MissedTickBehavior};
use tracing::{info, warn};

use crate::arti_observability::ObservationSink;
use crate::config::Config;
use crate::tor_watchdog::TorHandle;

const CONNECTION_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

pub(crate) fn preferred_missing(cfg: &Config, bridges: &[BridgeLine]) -> bool {
    cfg.bridges.preferred_transport().is_some_and(|transport| {
        !bridges
            .iter()
            .any(|bridge| bridge.transport.as_deref() == Some(transport))
    })
}

fn preferred_count(cfg: &Config, bridges: &[BridgeLine]) -> usize {
    bridges
        .iter()
        .filter(|bridge| {
            cfg.bridges
                .preferred_transport()
                .is_none_or(|transport| bridge.transport.as_deref() == Some(transport))
        })
        .count()
}

fn same_bridges(a: &[BridgeLine], b: &[BridgeLine]) -> bool {
    let keys = |bridges: &[BridgeLine]| {
        bridges
            .iter()
            .map(ToString::to_string)
            .collect::<HashSet<_>>()
    };
    keys(a) == keys(b)
}

fn apply_pool(
    active: &mut Settings,
    selected: Settings,
    apply: impl FnOnce(&Settings) -> Result<()>,
) -> Result<bool> {
    if selected.bridges.is_empty() || same_bridges(&active.bridges, &selected.bridges) {
        return Ok(false);
    }
    apply(&selected)?;
    *active = selected;
    Ok(true)
}

fn activate(
    handle: &TorHandle,
    active: &mut Settings,
    selected: Settings,
    tor: &arti_wrapper::TorTunnel,
) -> Result<()> {
    if apply_pool(active, selected, |settings| {
        Ok(tor.reconfigure_bridges(settings)?)
    })? {
        handle.set_active_bridges(active.bridges.clone());
        info!(count = active.bridges.len(),
            transport = ?active.bridges.first().and_then(|bridge| bridge.transport.as_deref()),
            "applied bridge pool to the running Tor client");
    }
    Ok(())
}

pub(crate) fn spawn(
    handle: TorHandle,
    config_path: Option<PathBuf>,
    interval_mins: u64,
    observations: ObservationSink,
    mut active: Settings,
) {
    // Detached by design; the server runtime owns this single maintenance worker.
    tokio::spawn(async move {
        let mut ticker =
            tokio::time::interval(Duration::from_secs(interval_mins.saturating_mul(60).max(1)));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        ticker.tick().await;
        let mut first = true;
        let mut next_allowed = Instant::now();
        loop {
            if !first {
                tokio::select! {
                    _ = ticker.tick(), if interval_mins != 0 => {},
                    _ = handle.bridge_refresh().notified() => {},
                }
                tokio::time::sleep_until(next_allowed).await;
            }
            first = false;
            if let Err(error) =
                refresh(&handle, config_path.as_deref(), &observations, &mut active).await
            {
                warn!(%error, "bridge refresh failed; keeping current routes");
            }
            next_allowed = Instant::now() + CONNECTION_REFRESH_INTERVAL;
        }
    });
}

async fn refresh(
    handle: &TorHandle,
    path: Option<&Path>,
    observations: &ObservationSink,
    active: &mut Settings,
) -> Result<()> {
    let cfg = Config::load_with_override(path)?.into_config();
    let Some(tor) = handle.tunnel().await else {
        return Ok(());
    };
    let configured = cfg.bridges.parsed()?.bridges;
    let mut store = BridgeStore::load(BridgeStore::resolve_path(path))?;
    let (failures, successes, unmatched) = observations.drain_into_store(
        &mut store,
        &configured,
        OffsetDateTime::now_utc(),
        Duration::from_secs(
            cfg.bridges
                .circuit_observation_window_mins
                .saturating_mul(60),
        ),
    );
    if failures + successes + unmatched > 0 {
        store.save()?;
        info!(
            failures,
            successes, unmatched, "drained circuit-layer guard observations"
        );
    }

    let usable = match crate::tor_setup::build_tor_settings(&cfg, path).await {
        Ok(selected) => {
            let count = preferred_count(&cfg, &selected.bridges);
            activate(handle, active, selected, &tor)?;
            count
        }
        Err(error) => {
            warn!(%error, "no configured route passed the probe; trying discovery");
            0
        }
    };
    handle.bridge_refresh().set_needed(
        cfg.bridges.auto_fetch && (usable == 0 || preferred_missing(&cfg, &active.bridges)),
    );
    let minimum = cfg
        .bridges
        .min_alive
        .max(usize::from(cfg.bridges.preferred_transport().is_some()));
    let deficit = crate::server::compute_deficit(minimum, usable, usable);
    info!(preferred = ?cfg.bridges.preferred_transport(), usable, deficit, "maintenance: preferred bridge health");

    if cfg.bridges.auto_fetch && deficit > 0 {
        // Return to the preferred transport as soon as its first bridge is admitted.
        let target = if preferred_missing(&cfg, &active.bridges) {
            1
        } else {
            deficit.min(3)
        };
        let added = crate::fetch_merge::top_up_working(&tor, &cfg, path, target).await?;
        if added > 0 {
            let latest = Config::load_with_override(path)?.into_config();
            let selected = crate::tor_setup::build_tor_settings(&latest, path).await?;
            activate(handle, active, selected, &tor)?;
        }
    }
    handle
        .bridge_refresh()
        .set_needed(cfg.bridges.auto_fetch && preferred_missing(&cfg, &active.bridges));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bridges() -> Vec<BridgeLine> {
        [
            "obfs4 192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA",
            "webtunnel [2001:db8::1]:1 0123456789ABCDEF0123456789ABCDEF01234567 url=https://example.com/bridge",
        ].into_iter().map(|line| line.parse().unwrap()).collect()
    }

    #[test]
    fn obfs4_does_not_fill_the_webtunnel_quota() {
        let mut cfg = Config::default();
        cfg.bridges.transport = "webtunnel".into();
        let bridges = bridges();
        assert_eq!(preferred_count(&cfg, &vec![bridges[0].clone(); 100]), 0);
        assert!(preferred_missing(&cfg, &bridges[..1]));
        assert_eq!(preferred_count(&cfg, &bridges), 1);
        assert!(!preferred_missing(&cfg, &bridges));
    }

    #[test]
    fn a_reordered_pool_does_not_retire_working_circuits() {
        let a = bridges();
        let mut b = a.clone();
        b.reverse();
        assert!(same_bridges(&a, &b));
        assert!(!same_bridges(&a, &b[..1]));
    }

    #[test]
    fn returning_to_webtunnel_reconfigures_without_obfs4() {
        let bridges = bridges();
        let mut active = Settings {
            bridges: vec![bridges[0].clone()],
            ..Default::default()
        };
        let selected = Settings {
            bridges: vec![bridges[1].clone()],
            ..Default::default()
        };
        let mut applied = Vec::new();
        assert!(apply_pool(&mut active, selected, |settings| {
            applied = settings.bridges.clone();
            Ok(())
        })
        .unwrap());
        assert_eq!(applied, vec![bridges[1].clone()]);
        assert_eq!(active.bridges, applied);
    }

    #[test]
    fn failed_reconfiguration_keeps_the_current_route() {
        let bridges = bridges();
        let mut active = Settings {
            bridges: vec![bridges[0].clone()],
            ..Default::default()
        };
        let selected = Settings {
            bridges: vec![bridges[1].clone()],
            ..Default::default()
        };
        assert!(apply_pool(&mut active, selected, |_| anyhow::bail!(
            "reconfigure failed"
        ))
        .is_err());
        assert_eq!(active.bridges, vec![bridges[0].clone()]);
    }

    #[test]
    fn an_empty_discovery_result_cannot_enable_direct_tor() {
        let bridges = bridges();
        let mut active = Settings {
            bridges: vec![bridges[0].clone()],
            ..Default::default()
        };
        assert!(!apply_pool(&mut active, Settings::default(), |_| panic!(
            "must keep bridge mode"
        ))
        .unwrap());
        assert_eq!(active.bridges, vec![bridges[0].clone()]);
    }

    #[tokio::test]
    async fn fallback_connections_coalesce_into_one_refresh() {
        use futures::FutureExt;
        let refresh = crate::tor_watchdog::BridgeRefresh::default();
        refresh.request();
        assert!(refresh.notified().now_or_never().is_none());
        refresh.set_needed(true);
        for _ in 0..8 {
            refresh.request();
        }
        assert!(refresh.notified().now_or_never().is_some());
        assert!(refresh.notified().now_or_never().is_none());
        refresh.set_needed(false);
        refresh.request();
        assert!(refresh.notified().now_or_never().is_none());
    }
}
