//! TS19-01 part 2 tests: blocking config/store file reads must run on
//! Tokio's blocking pool, never on the async worker that awaits them.
//!
//! The discriminator is thread identity, recorded by the seam in
//! `test_seams`: an inline call has no `.await` between the async fn's entry
//! and the blocking work, so it necessarily runs on the caller's own thread,
//! while `spawn_blocking` cannot. Tokio's `task::try_id()` would NOT work —
//! `spawn_blocking` polls its closure inside a real `BlockingTask` task, so
//! a task id is present on both sides.

use crate::bridge_maintenance::load_config_off_worker;
use crate::bridge_verifier::run_circuit_verify_tick;
use crate::config::Config;
use crate::test_seams::{ran_on_thread, worker_done_count, Site};
use bridge_store::BridgeStore;
use proxy_config::Socks5Endpoint;
use std::path::Path;

use crate::tor_setup::{
    build_tor_settings, build_tor_settings_preserving_live, FORBID_STARTUP_PROBE,
};

fn pre_config() -> Config {
    let mut cfg = Config {
        pre_proxies: Some(
            "127.0.0.1:1080|alice:secret"
                .parse::<Socks5Endpoint>()
                .unwrap()
                .into(),
        ),
        ..Config::default()
    };
    cfg.bridges.use_seeds = false;
    cfg.bridges.auto_fetch = false;
    cfg.bridges.lines = vec!["8.8.8.8:443 1111111111111111111111111111111111111111".into()];
    cfg
}

#[test]
fn restricted_owner_settings_are_network_free_and_reject_incompatible_options() {
    let mut cfg = pre_config();
    cfg.warm_pool.enabled = false;
    cfg.upstream.enabled = true;
    let settings = crate::tor_setup::restricted_owner_settings(
        &cfg,
        Path::new("tor-socks5.ktav"),
        &crate::pt::PtBinary::Environment,
    )
    .unwrap();
    assert_eq!(settings.bridges, cfg.bridges.parsed().unwrap().bridges);
    assert!(settings.pre_endpoint.is_none());
    assert!(settings.pt_binary.is_none());
    assert!(settings.extra_pt_protocols.is_empty());

    cfg.bridges.use_seeds = true;
    assert!(crate::tor_setup::restricted_owner_settings(
        &cfg,
        Path::new("tor-socks5.ktav"),
        &crate::pt::PtBinary::Environment,
    )
    .is_err());
    cfg.bridges.use_seeds = false;
    cfg.dns_server.enabled = true;
    assert!(crate::tor_setup::restricted_owner_settings(
        &cfg,
        Path::new("tor-socks5.ktav"),
        &crate::pt::PtBinary::Environment,
    )
    .is_err());
    cfg.dns_server.enabled = false;
    cfg.bridges
        .lines
        .push("unknownpt 8.8.4.4:443 2222222222222222222222222222222222222222 cert=AAA".into());
    assert!(crate::tor_setup::restricted_owner_settings(
        &cfg,
        Path::new("tor-socks5.ktav"),
        &crate::pt::PtBinary::Environment,
    )
    .unwrap_err()
    .to_string()
    .contains("unknown protocols"));

    cfg = pre_config();
    cfg.bridges.lines.extend([
        "obfs4 8.8.4.4:443 2222222222222222222222222222222222222222 cert=AAA iat-mode=0".into(),
        "webtunnel 8.8.8.8:443 3333333333333333333333333333333333333333 url=https://example.com/x ver=0.0.3".into(),
    ]);
    let expected = cfg.bridges.parsed().unwrap().bridges;
    let settings = crate::tor_setup::restricted_owner_settings(
        &cfg,
        Path::new("tor-socks5.ktav"),
        &crate::pt::PtBinary::Environment,
    )
    .unwrap();
    assert_eq!(settings.bridges, expected);
    assert!(settings.pre_endpoint.is_none());
    assert!(settings.stock_pt_proxy);
    assert_eq!(settings.pt_binary, Some(std::env::current_exe().unwrap()));
    settings.validate_stock_pt_proxy().unwrap();
}

#[tokio::test]
async fn pre_settings_use_configured_plain_bridges_without_probing() {
    FORBID_STARTUP_PROBE
        .scope((), async {
            let cfg = pre_config();
            let path = std::path::Path::new("config-dir/config.ktav");
            let settings = build_tor_settings(&cfg, path).await.unwrap();
            assert_eq!(settings.bridges, cfg.bridges.parsed().unwrap().bridges);
            assert_eq!(
                settings.state_dir,
                Some(path.parent().unwrap().join("arti-data"))
            );
            assert_eq!(
                settings.pre_endpoint,
                Some(arti_wrapper::Socks5PreEndpoint::new(
                    "127.0.0.1:1080".parse().unwrap(),
                    Some(("alice".into(), "secret".into()))
                ))
            );
            assert!(settings.pt_binary.is_none());
            assert!(settings.extra_pt_protocols.is_empty());
            let rebuilt = build_tor_settings_preserving_live(&cfg, path, &settings.bridges)
                .await
                .unwrap();
            assert_eq!(rebuilt.pre_endpoint, settings.pre_endpoint);
            assert_eq!(rebuilt.bridges, settings.bridges);
        })
        .await;
}

#[tokio::test]
async fn pre_settings_accept_stock_pt_bridges_without_probing() {
    FORBID_STARTUP_PROBE
        .scope((), async {
            let dir = tempfile::tempdir().expect("tempdir");
            let cfg_path = dir.path().join("ts19.ktav");
            for line in [
                "obfs4 8.8.4.4:443 2222222222222222222222222222222222222222 cert=AAA iat-mode=0",
                "webtunnel 8.8.8.8:443 3333333333333333333333333333333333333333 url=https://example.com/x ver=0.0.3",
            ] {
                let mut cfg = pre_config();
                cfg.bridges.lines.push(line.into());
                let parsed = cfg.bridges.parsed().unwrap();
                let settings = build_tor_settings(&cfg, &cfg_path).await.unwrap();

                assert_eq!(settings.bridges, parsed.bridges);
                assert_eq!(settings.bridges.len(), 2);
                assert!(settings.stock_pt_proxy);
                assert_eq!(settings.pt_binary, Some(std::env::current_exe().unwrap()));
                assert_eq!(
                    settings.pre_endpoint,
                    Some(arti_wrapper::Socks5PreEndpoint::new(
                        "127.0.0.1:1080".parse().unwrap(),
                        Some(("alice".into(), "secret".into()))
                    ))
                );
                assert!(settings.extra_pt_protocols.is_empty());
                settings.validate_stock_pt_proxy().unwrap();
            }
        })
        .await;
}

#[tokio::test]
async fn pre_rejects_pt_and_incompatible_configuration() {
    FORBID_STARTUP_PROBE
        .scope((), async {
            let dir = tempfile::tempdir().expect("tempdir");
            let cfg_path = dir.path().join("ts19.ktav");
            let mut cfg = pre_config();
            cfg.bridges.lines.push(
                "unknownpt 8.8.4.4:443 2222222222222222222222222222222222222222 cert=AAA".into(),
            );
            assert!(build_tor_settings(&cfg, &cfg_path)
                .await
                .unwrap_err()
                .to_string()
                .contains("unknown protocols"));
            cfg = pre_config();
            cfg.bridges.lines.clear();
            assert!(build_tor_settings(&cfg, &cfg_path)
                .await
                .unwrap_err()
                .to_string()
                .contains("usable bridge"));
            cfg = pre_config();
            cfg.bridges.use_seeds = true;
            assert!(build_tor_settings(&cfg, &cfg_path)
                .await
                .unwrap_err()
                .to_string()
                .contains("use_seeds"));
            cfg.bridges.use_seeds = false;
            cfg.bridges.auto_fetch = true;
            assert!(build_tor_settings(&cfg, &cfg_path)
                .await
                .unwrap_err()
                .to_string()
                .contains("auto_fetch"));
            cfg.bridges.auto_fetch = false;
            cfg.warm_pool.enabled = true;
            assert!(build_tor_settings(&cfg, &cfg_path)
                .await
                .unwrap_err()
                .to_string()
                .contains("warm_pool"));
        })
        .await;
}

#[tokio::test]
#[should_panic(expected = "unexpected app-owned bridge probe")]
async fn probe_forbidden_seam_intercepts_real_probe_entry() {
    FORBID_STARTUP_PROBE
        .scope(
            (),
            crate::tor_setup::probe_measured(Vec::new(), &Config::default()),
        )
        .await;
}

#[tokio::test]
async fn pre_hint_and_rejected_pt_cannot_bypass_validation() {
    FORBID_STARTUP_PROBE
        .scope((), async {
            let dir = tempfile::tempdir().expect("tempdir");
            let cfg_path = dir.path().join("ts19.ktav");
            let mut cfg = pre_config();
            cfg.bridges
                .lines
                .push("# xorbot:dns example.invalid 8.8.8.8 1".into());
            let settings = build_tor_settings(&cfg, &cfg_path).await.unwrap();
            assert_eq!(settings.bridges.len(), 1);
            assert!(settings.bridges.iter().all(|b| b.transport.is_none()));

            // A documentation-only stock PT address is filtered without activating PT.
            cfg.bridges.lines.push(
                "obfs4 [2001:db8::1]:443 2222222222222222222222222222222222222222 cert=AAA iat-mode=0"
                    .into(),
            );
            let parsed = cfg.bridges.parsed().unwrap();
            assert_eq!(parsed.rejected, 1);
            assert_eq!(parsed.duplicates, 0);
            assert_eq!(parsed.bridges, settings.bridges);
            let filtered_settings = build_tor_settings(&cfg, &cfg_path).await.unwrap();
            assert_eq!(filtered_settings.bridges, parsed.bridges);
            assert!(!filtered_settings.stock_pt_proxy);
            assert!(filtered_settings.pt_binary.is_none());

            // Unknown transports remain rejected even when their address is filtered.
            *cfg.bridges.lines.last_mut().expect("PT line exists") =
                "unknownpt [2001:db8::1]:443 2222222222222222222222222222222222222222".into();
            let parsed = cfg.bridges.parsed().unwrap();
            assert_eq!(parsed.rejected, 1);
            assert_eq!(parsed.duplicates, 0);
            assert_eq!(parsed.bridges, settings.bridges);
            assert!(build_tor_settings(&cfg, &cfg_path)
                .await
                .unwrap_err()
                .to_string()
                .contains("unknown protocols"));

            // An accepted address does not make an unknown protocol supported.
            *cfg.bridges.lines.last_mut().expect("PT line exists") =
                "unknownpt 127.0.0.1:443 2222222222222222222222222222222222222222".into();
            let parsed = cfg.bridges.parsed().unwrap();
            assert_eq!(parsed.rejected, 0);
            assert_eq!(parsed.duplicates, 0);
            assert_eq!(parsed.bridges.len(), 2);
            assert_eq!(parsed.bridges[0], settings.bridges[0]);
            assert!(parsed.bridges[1].transport.is_some());
            assert!(build_tor_settings(&cfg, &cfg_path)
                .await
                .unwrap_err()
                .to_string()
                .contains("unknown protocols"));

            cfg = pre_config();
            cfg.bridges
                .lines
                .push(" # xorbot:dns example.invalid 8.8.8.8 1".into());
            assert!(cfg.bridges.parsed().is_err());
            assert!(build_tor_settings(&cfg, &cfg_path).await.is_err());
        })
        .await;
}

#[tokio::test]
async fn absent_pre_keeps_existing_empty_pool_policy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg_path = dir.path().join("ts19.ktav");
    let mut cfg = pre_config();
    cfg.pre_proxies = None;
    cfg.bridges.lines.clear();
    let error = build_tor_settings(&cfg, &cfg_path)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("no reachable bridge"), "{error}");
}

#[tokio::test]
async fn config_load_runs_off_the_async_worker() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ts19-proxy.ktav");
    Config::default().write(&path).unwrap();

    let caller_thread = std::thread::current().id();
    let result = load_config_off_worker(path.as_path()).await;
    assert!(result.is_ok(), "config load failed: {:?}", result.err());

    let ran_on = ran_on_thread(Site::MaintenanceConfigLoad, &path).expect("the load must have run");
    assert_ne!(
        ran_on, caller_thread,
        "config load ran on the caller's async thread"
    );
    assert!(
        worker_done_count(Site::MaintenanceConfigLoad, &path) >= 1,
        "the blocking worker never reported completion"
    );
}

#[tokio::test]
async fn circuit_verify_store_load_runs_off_the_async_worker() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing-store-dir").join("proxy.ktav");

    let caller_thread = std::thread::current().id();
    // Missing file -> empty store -> cheap early return. The seam records at
    // the store path the production code resolves from the config path.
    let store_path = BridgeStore::resolve_path(&path);
    run_circuit_verify_tick(&path, &[]).await;

    let ran_on =
        ran_on_thread(Site::CircuitVerifyStoreLoad, &store_path).expect("the load must have run");
    assert_ne!(
        ran_on, caller_thread,
        "bridge-store load ran on the caller's async thread"
    );
    assert!(
        worker_done_count(Site::CircuitVerifyStoreLoad, &store_path) >= 1,
        "the blocking worker never reported completion"
    );
}

// --- H15/TS19 chunk 2: tor_setup and watchdog-runtime blocking reads ---

use crate::tor_watchdog::{live_bridge_count_off_worker, load_watchdog_config_off_worker};

/// Startup-probe shortcut: with the SDK14 PT observer installed,
/// `probe_measured` reports every bridge alive without touching the
/// network, so `build_tor_settings` runs end-to-end network-free. A drain
/// task holds the observer receiver open across the await — a PT resolution
/// send to a closed channel panics.
async fn with_probe_shortcut(fut: impl std::future::Future<Output = ()>) {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(&'static str, std::path::PathBuf)>(1);
    let drain = tokio::spawn(async move { while rx.recv().await.is_some() {} });
    FORBID_STARTUP_PROBE
        .scope((), crate::test_seams::sdk14_pt_scope("ts19-h15", tx, fut))
        .await;
    drain.abort();
}

#[tokio::test]
async fn setup_store_load_runs_off_the_async_worker() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ts19.ktav");
    let mut cfg = pre_config();
    cfg.pre_proxies = None;
    let store_path = BridgeStore::resolve_path(&path);
    let caller_thread = std::thread::current().id();
    with_probe_shortcut(async {
        // The store load fires before probing; the result is irrelevant.
        let _ = build_tor_settings(&cfg, &path).await;
    })
    .await;
    let ran_on = ran_on_thread(Site::SetupStoreLoad, &store_path).expect("the load must have run");
    assert_ne!(
        ran_on, caller_thread,
        "bridge-store load ran on the caller's async thread"
    );
    assert!(
        worker_done_count(Site::SetupStoreLoad, &store_path) >= 1,
        "the blocking worker never reported completion"
    );
}

#[tokio::test]
async fn setup_seed_load_runs_off_the_async_worker() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ts19.ktav");
    let seed_path = crate::seed::resolve_seed_path(&path);
    std::fs::write(
        &seed_path,
        "obfs4 8.8.4.4:443 2222222222222222222222222222222222222222 cert=AAA iat-mode=0\n",
    )
    .unwrap();
    let mut cfg = pre_config();
    cfg.pre_proxies = None;
    cfg.bridges.lines.clear();
    cfg.bridges.use_seeds = true;
    let caller_thread = std::thread::current().id();
    with_probe_shortcut(async {
        // No configured bridges: the seeds fallback branch must fire.
        let _ = build_tor_settings(&cfg, &path).await;
    })
    .await;
    let ran_on = ran_on_thread(Site::SetupSeedLoad, &seed_path).expect("the load must have run");
    assert_ne!(
        ran_on, caller_thread,
        ".seeds read ran on the caller's async thread"
    );
    assert!(
        worker_done_count(Site::SetupSeedLoad, &seed_path) >= 1,
        "the blocking worker never reported completion"
    );
}

#[tokio::test]
async fn setup_probe_rank_store_load_runs_off_the_async_worker() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ts19.ktav");
    let mut cfg = pre_config();
    cfg.pre_proxies = None;
    // More than MAX_ACTIVE_BRIDGES configured: the ranking store load fires.
    cfg.bridges.lines = (0..40u16)
        .map(|i| format!("10.0.0.{i}:443 1111111111111111111111111111111111111111"))
        .collect();
    let store_path = BridgeStore::resolve_path(&path);
    let caller_thread = std::thread::current().id();
    with_probe_shortcut(async {
        let _ = build_tor_settings(&cfg, &path).await;
    })
    .await;
    let ran_on = ran_on_thread(Site::SetupProbeRank, &store_path).expect("the load must have run");
    assert_ne!(
        ran_on, caller_thread,
        "probe-ranking store load ran on the caller's async thread"
    );
    assert!(
        worker_done_count(Site::SetupProbeRank, &store_path) >= 1,
        "the blocking worker never reported completion"
    );
}

#[tokio::test]
async fn watchdog_config_load_runs_off_the_async_worker() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ts19-watchdog.ktav");
    Config::default().write(&path).unwrap();
    let caller_thread = std::thread::current().id();
    let loaded = load_watchdog_config_off_worker(&path).await;
    assert!(loaded.is_some(), "watchdog config reload failed");
    let ran_on = ran_on_thread(Site::WatchdogConfigLoad, &path).expect("the load must have run");
    assert_ne!(
        ran_on, caller_thread,
        "watchdog config reload ran on the caller's async thread"
    );
    assert!(
        worker_done_count(Site::WatchdogConfigLoad, &path) >= 1,
        "the blocking worker never reported completion"
    );
}

#[tokio::test]
async fn watchdog_store_load_runs_off_the_async_worker() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ts19-watchdog-store.ktav");
    let store_path = BridgeStore::resolve_path(&path);
    let caller_thread = std::thread::current().id();
    let count = live_bridge_count_off_worker(&path).await;
    assert_eq!(count, 0, "no health store exists yet");
    let ran_on =
        ran_on_thread(Site::WatchdogStoreLoad, &store_path).expect("the load must have run");
    assert_ne!(
        ran_on, caller_thread,
        "live-bridge store read ran on the caller's async thread"
    );
    assert!(
        worker_done_count(Site::WatchdogStoreLoad, &store_path) >= 1,
        "the blocking worker never reported completion"
    );
}

// --- H15/TS19 chunk 3: maintenance tick, channel probe, warm pool, rank ---

#[tokio::test]
async fn maintenance_tick_config_load_runs_off_the_async_worker() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ts19-tick.ktav");
    Config::default().write(&path).unwrap();

    let caller_thread = std::thread::current().id();
    let result = crate::bridge_maintenance::load_tick_config_off_worker(&path).await;
    assert!(
        result.is_ok(),
        "tick config reload failed: {:?}",
        result.err()
    );

    let ran_on =
        ran_on_thread(Site::MaintenanceTickConfigLoad, &path).expect("the load must have run");
    assert_ne!(
        ran_on, caller_thread,
        "tick config reload ran on the caller's async thread"
    );
    assert!(
        worker_done_count(Site::MaintenanceTickConfigLoad, &path) >= 1,
        "the blocking worker never reported completion"
    );
}

#[tokio::test]
async fn probe_store_load_runs_off_the_async_worker() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing-store-dir").join("ts19-probe.ktav");
    let store_path = BridgeStore::resolve_path(&path);

    let caller_thread = std::thread::current().id();
    let store = crate::bridge_maintenance::load_probe_store_off_worker(&path).await;
    assert!(store.is_some(), "probe fallback store load failed");

    let ran_on = ran_on_thread(Site::ProbeStoreLoad, &store_path).expect("the load must have run");
    assert_ne!(
        ran_on, caller_thread,
        "probe store read ran on the caller's async thread"
    );
    assert!(
        worker_done_count(Site::ProbeStoreLoad, &store_path) >= 1,
        "the blocking worker never reported completion"
    );
}

#[tokio::test]
async fn warmer_config_load_runs_off_the_async_worker() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ts19-warmer.ktav");
    Config::default().write(&path).unwrap();

    let caller_thread = std::thread::current().id();
    let loaded = crate::bridge_warmer::load_warmer_config_off_worker(&path).await;
    assert!(loaded.is_some(), "warmer config reload failed");

    let ran_on = ran_on_thread(Site::WarmerConfigLoad, &path).expect("the load must have run");
    assert_ne!(
        ran_on, caller_thread,
        "warmer config reload ran on the caller's async thread"
    );
    assert!(
        worker_done_count(Site::WarmerConfigLoad, &path) >= 1,
        "the blocking worker never reported completion"
    );
}

#[tokio::test]
async fn rank_store_load_runs_off_the_async_worker() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ts19-rank.ktav");
    let mut cfg = Config::default();
    cfg.bridges.lines = vec!["8.8.8.8:443 1111111111111111111111111111111111111111".into()];
    cfg.write(&path).unwrap();
    let store_path = BridgeStore::resolve_path(&path);

    let caller_thread = std::thread::current().id();
    let candidates = crate::bridge_rank::candidates_with_health(&cfg, &path).await;
    assert_eq!(candidates.len(), 1, "the configured bridge must be ranked");

    let ran_on = ran_on_thread(Site::RankStoreLoad, &store_path).expect("the load must have run");
    assert_ne!(
        ran_on, caller_thread,
        "rank store read ran on the caller's async thread"
    );
    assert!(
        worker_done_count(Site::RankStoreLoad, &store_path) >= 1,
        "the blocking worker never reported completion"
    );
}

// --- H15/TS19 chunk 4: fetch_merge drain loads, bridge_manager pool loads ---

#[tokio::test]
async fn fetch_merge_drain_config_load_runs_off_the_async_worker() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ts19-drain.ktav");
    Config::default().write(&path).unwrap();

    let caller_thread = std::thread::current().id();
    let result = crate::fetch_merge::load_drain_config_off_worker(&path).await;
    assert!(
        result.is_ok(),
        "drain config load failed: {:?}",
        result.err()
    );

    let ran_on =
        ran_on_thread(Site::FetchMergeDrainConfigLoad, &path).expect("the load must have run");
    assert_ne!(
        ran_on, caller_thread,
        "drain config load ran on the caller's async thread"
    );
    assert!(
        worker_done_count(Site::FetchMergeDrainConfigLoad, &path) >= 1,
        "the blocking worker never reported completion"
    );
}

#[tokio::test]
async fn fetch_merge_pool_load_runs_off_the_async_worker() {
    let dir = tempfile::tempdir().unwrap();
    // A pool file that does not exist yet: `CandidatePool::load` returns an
    // empty pool — the seam still records the executing thread.
    let pool_path =
        crate::candidate_pool::CandidatePool::resolve_path(&dir.path().join("ts19-pool.ktav"));

    let caller_thread = std::thread::current().id();
    let pool = crate::fetch_merge::load_pool_off_worker(&pool_path).await;
    assert!(pool.is_ok(), "pool load failed: {:?}", pool.err());
    assert!(pool.unwrap().is_empty(), "a missing pool must load empty");

    let ran_on =
        ran_on_thread(Site::FetchMergePoolLoad, &pool_path).expect("the load must have run");
    assert_ne!(
        ran_on, caller_thread,
        "candidate pool load ran on the caller's async thread"
    );
    assert!(
        worker_done_count(Site::FetchMergePoolLoad, &pool_path) >= 1,
        "the blocking worker never reported completion"
    );
}
