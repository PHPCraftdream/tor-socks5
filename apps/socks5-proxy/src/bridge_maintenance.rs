//! One owner for startup, periodic, and connection-triggered bridge refreshes.

use std::collections::HashSet;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;

use anyhow::Result;
use arti_wrapper::Settings;
use bridge_line::BridgeLine;
use time::OffsetDateTime;
use tokio::time::{Instant, MissedTickBehavior};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::arti_observability::ObservationSink;
use crate::config::Config;
use crate::tor_watchdog::TorHandle;

mod channel_probe;

const CONNECTION_REFRESH_INTERVAL: Duration = Duration::from_secs(60);
const RECOVERY_REFRESH_INTERVAL: Duration = Duration::from_secs(15);

enum DiscoveryEvent<T> {
    Finished(T),
    Recheck,
}

/// cancel-safe: yes — pending discovery and queued signals remain caller-owned.
async fn next_discovery_event<F: Future + ?Sized>(
    discovery: Pin<&mut F>,
    recovery: &tokio::sync::Notify,
    next_recheck: Instant,
) -> DiscoveryEvent<F::Output> {
    tokio::select! {
        biased;
        result = discovery => DiscoveryEvent::Finished(result),
        _ = async {
            tokio::time::sleep_until(next_recheck).await;
            recovery.notified().await;
        } => DiscoveryEvent::Recheck,
    }
}

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
    token: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    // The server runtime joins this handle at shutdown, so an in-flight refresh finishes and its store writes land before the bridge-store writer closes.
    tokio::spawn(async move {
        let mut ticker =
            tokio::time::interval(Duration::from_secs(interval_mins.saturating_mul(60).max(1)));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        ticker.tick().await;
        let mut first = true;
        let mut next_allowed = Instant::now();
        let mut next_recovery = Instant::now();
        let mut channel_cursor = 0;
        loop {
            if !first {
                tokio::select! {
                    biased;
                    _ = token.cancelled() => break,
                    _ = async {
                        tokio::time::sleep_until(next_recovery).await;
                        handle.bridge_refresh().recovery().notified().await;
                    } => {},
                    _ = ticker.tick(), if interval_mins != 0 => {},
                    _ = async {
                        tokio::time::sleep_until(next_allowed).await;
                        handle.bridge_refresh().notified().await;
                    } => {},
                }
            }
            first = false;
            let cycle: futures::future::BoxFuture<'_, Result<()>> = Box::pin(refresh(
                &handle,
                config_path.as_deref(),
                &observations,
                &mut active,
                &mut next_recovery,
                &mut channel_cursor,
            ));
            if let Err(error) = cycle.await {
                warn!(%error, "bridge refresh failed; keeping current routes");
            }
            next_allowed = Instant::now() + CONNECTION_REFRESH_INTERVAL;
        }
    })
}

async fn refresh(
    handle: &TorHandle,
    path: Option<&Path>,
    observations: &ObservationSink,
    active: &mut Settings,
    next_recovery: &mut Instant,
    channel_cursor: &mut usize,
) -> Result<()> {
    let cfg = Config::load_with_override(path)?.into_config();
    let Some(tor) = handle.tunnel().await else {
        return Ok(());
    };
    let mut usable = refresh_routes(
        handle,
        path,
        observations,
        active,
        &cfg,
        &tor,
        channel_cursor,
    )
    .await?;
    *next_recovery = Instant::now() + RECOVERY_REFRESH_INTERVAL;
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
        let target = if usable == 0 || preferred_missing(&cfg, &active.bridges) {
            1
        } else {
            deficit.min(3)
        };
        let mut discovery: futures::future::BoxFuture<'_, Result<usize>> =
            Box::pin(crate::fetch_merge::top_up_working(&tor, &cfg, path, target));
        let added = loop {
            match next_discovery_event(
                discovery.as_mut(),
                handle.bridge_refresh().recovery(),
                *next_recovery,
            )
            .await
            {
                DiscoveryEvent::Finished(result) => break result?,
                DiscoveryEvent::Recheck => {
                    info!("rechecking active bridges after a Tor failure");
                    match refresh_routes(
                        handle,
                        path,
                        observations,
                        active,
                        &cfg,
                        &tor,
                        channel_cursor,
                    )
                    .await
                    {
                        Ok(count) => usable = count,
                        Err(error) => {
                            warn!(%error, "bridge recovery recheck failed; keeping current routes");
                        }
                    }
                    handle.bridge_refresh().set_needed(
                        cfg.bridges.auto_fetch
                            && (usable == 0 || preferred_missing(&cfg, &active.bridges)),
                    );
                    *next_recovery = Instant::now() + RECOVERY_REFRESH_INTERVAL;
                }
            }
        };
        if added > 0 {
            let latest = Config::load_with_override(path)?.into_config();
            usable = refresh_routes(
                handle,
                path,
                observations,
                active,
                &latest,
                &tor,
                channel_cursor,
            )
            .await?;
        }
    }
    handle.bridge_refresh().set_needed(
        cfg.bridges.auto_fetch && (usable == 0 || preferred_missing(&cfg, &active.bridges)),
    );
    Ok(())
}

fn refresh_routes<'a>(
    handle: &'a TorHandle,
    path: Option<&'a Path>,
    observations: &'a ObservationSink,
    active: &'a mut Settings,
    cfg: &'a Config,
    tor: &'a arti_wrapper::TorTunnel,
    channel_cursor: &'a mut usize,
) -> futures::future::BoxFuture<'a, Result<usize>> {
    Box::pin(async move {
        let configured = cfg.bridges.parsed()?.bridges;
        // Through the single writer: a publish failure no longer aborts the
        // heal or loses the drained observations (they stay queued in the
        // writer and are retried with backoff). Err only means the on-disk
        // store was unreadable — the same surface today's `load(...)?` had.
        let window = Duration::from_secs(
            cfg.bridges
                .circuit_observation_window_mins
                .saturating_mul(60),
        );
        let observations = observations.clone();
        let configured_clone = configured.clone();
        let counts = std::sync::Arc::new(std::sync::Mutex::new(None));
        let counts_closure = counts.clone();
        crate::bridge_store_writer::apply(path, move |store| {
            *counts_closure.lock().unwrap() = Some(observations.drain_into_store(
                store,
                &configured_clone,
                OffsetDateTime::now_utc(),
                window,
            ));
        })
        .await?;
        if let Some((failures, successes, unmatched)) = *counts.lock().unwrap() {
            if failures + successes + unmatched > 0 {
                info!(
                    failures,
                    successes, unmatched, "drained circuit-layer guard observations"
                );
            }
        }
        let route_works = !active.bridges.is_empty()
            && active
                .bridges
                .iter()
                .all(|bridge| configured.contains(bridge))
            && live_route_works(tor, handle.health()).await;
        let keep_current = route_works && can_keep_current(cfg, &configured, &active.bridges);
        let live = if keep_current {
            active.bridges.as_slice()
        } else {
            &[]
        };
        match crate::tor_setup::build_tor_settings_preserving_live(cfg, path, live).await {
            Ok(mut selected) => {
                if keep_current {
                    info!("keeping the preferred route that still carries Tor traffic");
                    return Ok(preferred_count(cfg, &selected.bridges).max(1));
                }
                if !channel_probe::authenticate_fallback(
                    tor,
                    cfg,
                    path,
                    active,
                    &mut selected,
                    channel_cursor,
                    route_works || handle.route_is_settling(),
                )
                .await?
                {
                    warn!("no obfs4 candidate completed an authenticated Tor channel");
                    return Ok(0);
                }
                let count = preferred_count(cfg, &selected.bridges);
                activate(handle, active, selected, tor)?;
                Ok(count)
            }
            Err(error) => {
                if keep_current {
                    info!(%error, "keeping the working route despite failed new-connection probes");
                    return Ok(1);
                }
                warn!(%error, "no configured route passed the probe; trying discovery");
                Ok(0)
            }
        }
    })
}

fn can_keep_current(cfg: &Config, configured: &[BridgeLine], active: &[BridgeLine]) -> bool {
    !active.is_empty()
        && cfg.bridges.preferred_transport().is_none_or(|preferred| {
            active
                .iter()
                .all(|bridge| bridge.transport.as_deref() == Some(preferred))
        })
        && active.iter().all(|bridge| configured.contains(bridge))
}

async fn live_route_works(
    tor: &arti_wrapper::TorTunnel,
    health: &crate::tor_watchdog::TorHealth,
) -> bool {
    if health.successful_within(RECOVERY_REFRESH_INTERVAL) {
        return true;
    }
    if !tor.raw().bootstrap_status().ready_for_traffic() {
        return false;
    }
    let body = bridge_fetcher::fetch_one(
        tor,
        "https://check.torproject.org/api/ip",
        RECOVERY_REFRESH_INTERVAL,
        4096,
        &[],
        &[],
        false,
    )
    .await;
    if body
        .as_deref()
        .is_ok_and(crate::bridge_verifier::confirms_tor)
    {
        health.record_success();
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn stalled_connect_requests_recovery_without_dropping_the_attempt() {
        use futures::FutureExt;
        let refresh = crate::tor_watchdog::BridgeRefresh::default();
        let (finish, connection) = tokio::sync::oneshot::channel();
        let tracked = refresh.track_connection(async { connection.await.unwrap() });
        tokio::pin!(tracked);
        assert!(tracked.as_mut().now_or_never().is_none());
        tokio::time::advance(Duration::from_secs(15)).await;
        assert!(tracked.as_mut().now_or_never().is_none());
        assert!(refresh.recovery().notified().now_or_never().is_some());
        assert!(!finish.is_closed());
        finish.send(11).unwrap();
        assert_eq!(tracked.await, 11);
    }

    #[tokio::test(start_paused = true)]
    async fn recent_route_evidence_expires_on_the_monotonic_clock() {
        let health = crate::tor_watchdog::TorHealth::default();
        assert!(!health.successful_within(RECOVERY_REFRESH_INTERVAL));
        health.record_success();
        assert!(health.successful_within(RECOVERY_REFRESH_INTERVAL));
        tokio::time::advance(RECOVERY_REFRESH_INTERVAL).await;
        assert!(!health.successful_within(RECOVERY_REFRESH_INTERVAL));
    }

    #[test]
    fn retaining_live_traffic_still_honors_transport_and_config_changes() {
        let pool = bridges();
        let mut cfg = Config::default();
        cfg.bridges.transport = "webtunnel".into();
        assert!(can_keep_current(&cfg, &pool, &pool[1..]));
        assert!(!can_keep_current(&cfg, &pool, &pool));
        assert!(!can_keep_current(&cfg, &pool[..1], &pool[1..]));
        cfg.bridges.transport = "obfs4".into();
        assert!(!can_keep_current(&cfg, &pool, &pool[1..]));
    }

    #[tokio::test]
    async fn recovery_rechecks_without_cancelling_pending_discovery() {
        use futures::FutureExt;
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        struct OnDrop(Arc<AtomicBool>);
        impl Drop for OnDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = OnDrop(dropped.clone());
        let (done, receive) = tokio::sync::oneshot::channel();
        let discovery = async move {
            let _guard = guard;
            receive.await.unwrap()
        };
        tokio::pin!(discovery);
        let recovery = tokio::sync::Notify::new();
        let ready = Instant::now() - Duration::from_secs(1);
        assert!(next_discovery_event(discovery.as_mut(), &recovery, ready)
            .now_or_never()
            .is_none());
        for _ in 0..8 {
            recovery.notify_one();
        }
        assert!(matches!(
            next_discovery_event(discovery.as_mut(), &recovery, ready).now_or_never(),
            Some(DiscoveryEvent::Recheck)
        ));
        assert!(!dropped.load(Ordering::SeqCst));
        assert!(next_discovery_event(discovery.as_mut(), &recovery, ready)
            .now_or_never()
            .is_none());
        done.send(7).unwrap();
        assert!(matches!(
            next_discovery_event(discovery.as_mut(), &recovery, ready).await,
            DiscoveryEvent::Finished(7)
        ));
    }

    #[tokio::test]
    async fn recovery_cooldown_does_not_delay_discovery_or_consume_its_signal() {
        use futures::FutureExt;
        let (done, receive) = tokio::sync::oneshot::channel();
        let discovery = async { receive.await.unwrap() };
        tokio::pin!(discovery);
        let recovery = tokio::sync::Notify::new();
        recovery.notify_one();
        let later = Instant::now() + Duration::from_secs(60);
        assert!(next_discovery_event(discovery.as_mut(), &recovery, later)
            .now_or_never()
            .is_none());
        done.send(9).unwrap();
        assert!(matches!(
            next_discovery_event(discovery.as_mut(), &recovery, later).now_or_never(),
            Some(DiscoveryEvent::Finished(9))
        ));
        assert!(recovery.notified().now_or_never().is_some());
    }

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
