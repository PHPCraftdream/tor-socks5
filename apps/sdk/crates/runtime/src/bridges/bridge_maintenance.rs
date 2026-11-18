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

#[path = "bridge_maintenance/channel_probe.rs"]
mod channel_probe;

/// Test access to the channel-probe fallback store read (H15/TS19).
/// Consumers live in cfg(test) ts19_tests, so gate on cfg(test) only:
/// a test-seams lib build (no cfg(test)) would warn on an unused import.
#[cfg(test)]
pub(crate) use channel_probe::load_probe_store_off_worker;

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

pub fn preferred_missing(cfg: &Config, bridges: &[BridgeLine]) -> bool {
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

/// Spawns the maintenance producer with the given PT policy: the policy is
/// reused for every later owner-settings rebuild this task performs.
/// `PtBinary::Environment` resolves the documented `TOR_PT_BINARY` override,
/// else the current process executable.
pub fn spawn(
    handle: TorHandle,
    config_path: PathBuf,
    interval_mins: u64,
    observations: ObservationSink,
    mut active: Settings,
    pt_binary: crate::pt::PtBinary,
    token: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    #[cfg(any(test, feature = "test-seams"))]
    crate::test_seams::forbid_producer("maintenance");
    #[cfg(test)]
    let observer = crate::pt::sdk14_observer().map(|(_, sender)| sender);
    #[cfg(test)]
    let probe = PRE_PROBE.try_with(std::sync::Arc::clone).ok();
    #[cfg(test)]
    let control = LOOP_CONTROL.try_with(std::sync::Arc::clone).ok();
    // The server runtime joins this handle at shutdown, so an in-flight refresh finishes and its store writes land before the bridge-store writer closes.
    let run = async move {
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
                    _ = async {
                        #[cfg(test)]
                        if let Some(control) = &control {
                            control.idle().await;
                            return;
                        }
                        std::future::pending::<()>().await;
                    } => { continue; },
                    _ = ticker.tick(), if interval_mins != 0 => {},
                    _ = async {
                        tokio::time::sleep_until(next_allowed).await;
                        handle.bridge_refresh().notified().await;
                    } => {},
                }
            }
            first = false;
            #[cfg(test)]
            if let Some(control) = &control {
                control
                    .started
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            let cycle: futures::future::BoxFuture<'_, Result<()>> = Box::pin(refresh_with_pt(
                &handle,
                config_path.as_path(),
                &observations,
                &mut active,
                &mut next_recovery,
                &mut channel_cursor,
                &pt_binary,
            ));
            // Cancellation must cut off an in-flight refresh cycle (its long
            // network stages include discovery and live probes) instead of
            // waiting for the whole cycle. The cycle future holds `&mut
            // active`; dropping it mid-cycle leaves `active` at its last
            // completed apply, which is the on-disk/Tor state — safe.
            let outcome = tokio::select! {
                biased;
                _ = token.cancelled() => break,
                result = cycle => result,
            };
            if let Err(error) = outcome {
                warn!(%error, "bridge refresh failed; keeping current routes");
            }
            next_allowed = Instant::now() + CONNECTION_REFRESH_INTERVAL;
            #[cfg(test)]
            if let Some(control) = &control {
                control.completed().await;
            }
        }
    };
    #[cfg(test)]
    let run = {
        async move {
            if let Some(sender) = observer {
                crate::pt::SDK14_PT_OBSERVER
                    .scope(("maintenance", sender), run)
                    .await;
            } else {
                run.await;
            }
        }
    };
    #[cfg(test)]
    if let Some(probe) = probe {
        return tokio::spawn(PRE_PROBE.scope(probe, run));
    }
    tokio::spawn(run)
}

/// `Config::load_with_override` does blocking file I/O (config read plus
/// reader-side stale-temp cleanup); run it on Tokio's blocking pool so it
/// cannot stall an async worker (TS19-01).
pub(crate) async fn load_config_off_worker(path: &Path) -> Result<Config> {
    let path = path.to_path_buf();
    crate::workers::run_fallible_blocking(move || {
        #[cfg(any(test, feature = "test-seams"))]
        crate::test_seams::note_task_context(crate::test_seams::Site::MaintenanceConfigLoad, &path);
        #[cfg(any(test, feature = "test-seams"))]
        crate::test_seams::park_if_armed(crate::test_seams::Site::MaintenanceConfigLoad, &path);
        let loaded =
            crate::config::Config::load_with_override(Some(&path)).map(|l| l.into_config());
        #[cfg(any(test, feature = "test-seams"))]
        crate::test_seams::mark_worker_done(crate::test_seams::Site::MaintenanceConfigLoad, &path);
        loaded
    })
    .await
    .map_err(|e| anyhow::anyhow!("config load task failed: {e}"))?
}

#[cfg(test)]
async fn refresh(
    handle: &TorHandle,
    path: &Path,
    observations: &ObservationSink,
    active: &mut Settings,
    next_recovery: &mut Instant,
    channel_cursor: &mut usize,
) -> Result<()> {
    refresh_with_pt(
        handle,
        path,
        observations,
        active,
        next_recovery,
        channel_cursor,
        &crate::pt::PtBinary::Environment,
    )
    .await
}

async fn refresh_with_pt(
    handle: &TorHandle,
    path: &Path,
    observations: &ObservationSink,
    active: &mut Settings,
    next_recovery: &mut Instant,
    channel_cursor: &mut usize,
    pt_binary: &crate::pt::PtBinary,
) -> Result<()> {
    let cfg = load_config_off_worker(path).await?;
    let Some(tor) = handle.tunnel().await else {
        return Ok(());
    };
    if let Some(Some(endpoint)) = tor.configured_pre_endpoint() {
        let result =
            refresh_pre_with_pt(handle, path, active, &cfg, &tor, endpoint, pt_binary).await;
        *next_recovery = Instant::now() + RECOVERY_REFRESH_INTERVAL;
        return result;
    }
    if active.pre_endpoint.is_some() {
        anyhow::bail!("unknown route of the live client");
    }
    let mut usable = refresh_routes_with_pt(
        handle,
        path,
        observations,
        active,
        (&cfg, pt_binary),
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
    let deficit = compute_deficit(minimum, usable);
    info!(preferred = ?cfg.bridges.preferred_transport(), usable, deficit, "maintenance: preferred bridge health");

    if cfg.bridges.auto_fetch && deficit > 0 {
        // Return to the preferred transport as soon as its first bridge is admitted.
        let target = if usable == 0 || preferred_missing(&cfg, &active.bridges) {
            1
        } else {
            deficit.min(3)
        };
        let mut discovery: futures::future::BoxFuture<'_, Result<usize>> = Box::pin(
            crate::fetch_merge::top_up_working_with_pt(&tor, &cfg, path, target, pt_binary.clone()),
        );
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
                    match refresh_routes_with_pt(
                        handle,
                        path,
                        observations,
                        active,
                        (&cfg, pt_binary),
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
            let latest = load_tick_config_off_worker(path).await?;
            usable = refresh_routes_with_pt(
                handle,
                path,
                observations,
                active,
                (&latest, pt_binary),
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

#[cfg(test)]
async fn refresh_pre(
    handle: &TorHandle,
    path: &Path,
    active: &mut Settings,
    cfg: &Config,
    tor: &arti_wrapper::TorTunnel,
    endpoint: &arti_wrapper::Socks5PreEndpoint,
) -> Result<()> {
    refresh_pre_with_pt(
        handle,
        path,
        active,
        cfg,
        tor,
        endpoint,
        &crate::pt::PtBinary::Environment,
    )
    .await
}

async fn refresh_pre_with_pt(
    handle: &TorHandle,
    path: &Path,
    active: &mut Settings,
    cfg: &Config,
    tor: &arti_wrapper::TorTunnel,
    endpoint: &arti_wrapper::Socks5PreEndpoint,
    pt_binary: &crate::pt::PtBinary,
) -> Result<()> {
    let configured = cfg.pre_proxies.as_ref().is_some_and(|pool| {
        pool.members()
            .iter()
            .any(|member| &arti_wrapper::Socks5PreEndpoint::from_pool_member(member) == endpoint)
    });
    if !configured || active.pre_endpoint.as_ref() != Some(endpoint) {
        anyhow::bail!("pre endpoint change requires a restart");
    }
    if cfg.upstream.enabled {
        anyhow::bail!("pre endpoint is incompatible with upstream");
    }
    let validated = crate::tor_setup::restricted_owner_settings(cfg, path, pt_binary)?;
    let mut selected = active.clone();
    selected.bridges = validated.bridges;
    use futures::StreamExt;
    let ready: Vec<_> = futures::stream::iter(selected.bridges.iter().take(30).cloned())
        .map(|bridge| async move { pre_channel_ready(tor, &bridge).await.then_some(bridge) })
        .buffered(8)
        .filter_map(|bridge| async move { bridge })
        .collect()
        .await;
    if ready.is_empty() {
        anyhow::bail!("no confirmed channels via the pre endpoint; keeping the current route");
    }
    selected.bridges = ready;
    activate(handle, active, selected, tor)?;
    Ok(())
}

#[cfg(test)]
tokio::task_local! {
    static PRE_PROBE: std::sync::Arc<pre_tests::Probe>;
    static LOOP_CONTROL: std::sync::Arc<pre_tests::LoopControl>;
}

/// cancel-safe: да — отмена прекращает ожидание канала, владение клиентом не передаётся.
pub(crate) async fn pre_channel_ready(tor: &arti_wrapper::TorTunnel, bridge: &BridgeLine) -> bool {
    if !matches!(tor.configured_pre_endpoint(), Some(Some(_))) || bridge.transport.is_some() {
        return false;
    }
    #[cfg(test)]
    if let Ok(probe) = PRE_PROBE.try_with(std::sync::Arc::clone) {
        probe
            .entered
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        return probe.ready;
    }
    matches!(
        tokio::time::timeout(Duration::from_secs(15), tor.warm_bridge(bridge)).await,
        Ok(Ok(true))
    )
}

fn refresh_routes_with_pt<'a>(
    handle: &'a TorHandle,
    path: &'a Path,
    observations: &'a ObservationSink,
    active: &'a mut Settings,
    policy: (&'a Config, &'a crate::pt::PtBinary),
    tor: &'a arti_wrapper::TorTunnel,
    channel_cursor: &'a mut usize,
) -> futures::future::BoxFuture<'a, Result<usize>> {
    let (cfg, pt_binary) = policy;
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
        let path = path.to_path_buf();
        crate::bridge_store_writer::apply(&path, move |store| {
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
        match crate::tor_setup::build_tor_settings_preserving_live_with_pt(
            cfg,
            &path,
            live,
            pt_binary.clone(),
        )
        .await
        {
            Ok(mut selected) => {
                #[cfg(test)]
                if crate::pt::sdk14_observer().is_some() {
                    return Ok(preferred_count(cfg, &selected.bridges));
                }
                if keep_current {
                    info!("keeping the preferred route that still carries Tor traffic");
                    return Ok(preferred_count(cfg, &selected.bridges).max(1));
                }
                if !channel_probe::authenticate_fallback(
                    tor,
                    cfg,
                    &path,
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
    #[cfg(test)]
    if crate::pt::sdk14_observer().is_some() {
        return false;
    }
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

/// How many working bridges we are short of `min_alive`.
///
/// `healthy` is the count of bridges that can actually carry traffic —
/// TCP reachability already folded into the caller's usable count. Used by
/// the maintenance loop to decide whether to promote fresh candidates from
/// the pool into the working set.
fn compute_deficit(min_alive: usize, healthy: usize) -> usize {
    min_alive.saturating_sub(healthy)
}

#[cfg(test)]
#[path = "bridge_maintenance/real_channel_tests.rs"]
mod real_channel_tests;

#[cfg(test)]
#[path = "bridge_maintenance/pre_tests.rs"]
mod pre_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancelled_maintenance_load_keeps_its_worker_owned() {
        use crate::test_seams::{ParkedGate, Site, HANG_GUARD};
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proxy.ktav");
        Config::default().write(&path).unwrap();
        let gate = ParkedGate::arm(Site::MaintenanceConfigLoad, &path);
        let registry = Arc::new(crate::workers::TestWorkers::default());
        let owner = registry.clone();
        let outer = tokio::spawn(async move { owner.scope(load_config_off_worker(&path)).await });
        let wait = gate.clone();
        tokio::task::spawn_blocking(move || wait.wait_parked(HANG_GUARD))
            .await
            .unwrap();
        outer.abort();
        assert!(outer.await.unwrap_err().is_cancelled());
        assert_eq!(registry.pending_count().await, 1);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), registry.join())
                .await
                .is_err()
        );
        gate.release();
        tokio::time::timeout(HANG_GUARD, registry.join())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(registry.pending_count().await, 0);
    }

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

#[cfg(test)]
mod deficit_tests {
    use super::compute_deficit;

    #[test]
    fn compute_deficit_zero_when_enough_usable_bridges() {
        // 31 usable, minimum 8 → no deficit.
        assert_eq!(compute_deficit(8, 31), 0);
    }

    #[test]
    fn compute_deficit_triggers_when_usable_drops_below_minimum() {
        // Production incident shape: usable count fell below the minimum —
        // discovery must be triggered with the exact shortfall.
        assert_eq!(compute_deficit(8, 2), 6);
        assert_eq!(compute_deficit(8, 3), 5);
    }

    #[test]
    fn compute_deficit_boundary_exactly_at_min() {
        // usable == min_alive → exactly enough, no deficit.
        assert_eq!(compute_deficit(8, 8), 0);
    }

    #[test]
    fn compute_deficit_boundary_one_below_min() {
        // one short of min_alive → deficit of exactly 1.
        assert_eq!(compute_deficit(8, 7), 1);
    }

    #[test]
    fn compute_deficit_zero_usable_is_full_deficit() {
        assert_eq!(compute_deficit(8, 0), 8);
    }

    #[test]
    fn compute_deficit_saturates_at_zero_when_overhealthy() {
        // More usable than required → never goes negative.
        assert_eq!(compute_deficit(8, 40), 0);
    }
}

// --- H15/TS19 seam-aware blocking helper (moved here from `workers.rs`,
// which was over the 1000-line file gate; this module is visible to every
// former caller via `crate::bridge_maintenance`) ---

/// Prod stand-in for [`crate::test_seams::Site`] (which compiles away
/// outside test builds): keeps the seam-aware blocking helper's call sites
/// shape-stable across both configurations.
#[cfg(not(any(test, feature = "test-seams")))]
pub(crate) mod seam_site {
    #[derive(Clone, Copy)]
    pub(crate) enum Site {
        SetupStoreLoad,
        SetupSeedLoad,
        SetupProbeRank,
        WatchdogConfigLoad,
        WatchdogStoreLoad,
        MaintenanceTickConfigLoad,
        ProbeStoreLoad,
        WarmerConfigLoad,
        RankStoreLoad,
        FetchMergeDrainConfigLoad,
        FetchMergePoolLoad,
    }
}

/// Run a blocking file read via [`workers::run_fallible_blocking`] (H15/TS19):
/// the closure records its executing thread at `site` and marks the worker
/// done after `op` finished, so a test can prove the read left the async worker.
#[cfg(any(test, feature = "test-seams"))]
pub(crate) async fn run_blocking_at<T: Send + 'static>(
    site: crate::test_seams::Site,
    path: std::path::PathBuf,
    op: impl FnOnce(&Path) -> anyhow::Result<T> + Send + 'static,
) -> Result<T> {
    crate::workers::run_fallible_blocking(move || {
        crate::test_seams::note_task_context(site, &path);
        let loaded = op(&path);
        crate::test_seams::mark_worker_done(site, &path);
        loaded
    })
    .await
    .map_err(|e| anyhow::anyhow!("blocking read task failed: {e}"))?
}

/// Prod twin of [`run_blocking_at`]: identical blocking behavior, no seams.
#[cfg(not(any(test, feature = "test-seams")))]
pub(crate) async fn run_blocking_at<T: Send + 'static>(
    _site: seam_site::Site,
    path: std::path::PathBuf,
    op: impl FnOnce(&Path) -> anyhow::Result<T> + Send + 'static,
) -> Result<T> {
    crate::workers::run_fallible_blocking(move || op(&path))
        .await
        .map_err(|e| anyhow::anyhow!("blocking read task failed: {e}"))?
}

/// Post-discovery config reload inside the maintenance tick: a blocking
/// file read that must not stall the async worker (H15/TS19).
#[cfg(any(test, feature = "test-seams"))]
pub(crate) async fn load_tick_config_off_worker(path: &Path) -> Result<Config> {
    load_tick_config_off_worker_inner(crate::test_seams::Site::MaintenanceTickConfigLoad, path)
        .await
}

/// Prod twin of [`load_tick_config_off_worker`].
#[cfg(not(any(test, feature = "test-seams")))]
pub(crate) async fn load_tick_config_off_worker(path: &Path) -> Result<Config> {
    load_tick_config_off_worker_inner(seam_site::Site::MaintenanceTickConfigLoad, path).await
}

async fn load_tick_config_off_worker_inner(
    #[cfg(any(test, feature = "test-seams"))] site: crate::test_seams::Site,
    #[cfg(not(any(test, feature = "test-seams")))] site: seam_site::Site,
    path: &Path,
) -> Result<Config> {
    let path = path.to_path_buf();
    run_blocking_at(site, path, |p| {
        crate::config::Config::load_with_override(Some(p)).map(|loaded| loaded.into_config())
    })
    .await
}
