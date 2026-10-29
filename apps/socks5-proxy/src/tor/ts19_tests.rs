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
use crate::test_seams::{ran_on_thread, Site};

use crate::tor_setup::{
    build_tor_settings, build_tor_settings_preserving_live, FORBID_STARTUP_PROBE,
};

fn pre_config() -> Config {
    let mut cfg = Config::default();
    cfg.pre_socks5 = Some(proxy_config::EndpointOverride::Endpoint(
        "127.0.0.1:1080|alice:secret".parse().unwrap(),
    ));
    cfg.bridges.use_seeds = false;
    cfg.bridges.auto_fetch = false;
    cfg.bridges.lines = vec!["8.8.8.8:443 1111111111111111111111111111111111111111".into()];
    cfg
}

#[tokio::test]
async fn pre_settings_use_configured_plain_bridges_without_probing() {
    FORBID_STARTUP_PROBE
        .scope((), async {
            let cfg = pre_config();
            let path = std::path::Path::new("config-dir/config.ktav");
            let settings = build_tor_settings(&cfg, Some(path)).await.unwrap();
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
            let rebuilt = build_tor_settings_preserving_live(&cfg, Some(path), &settings.bridges)
                .await
                .unwrap();
            assert_eq!(rebuilt.pre_endpoint, settings.pre_endpoint);
            assert_eq!(rebuilt.bridges, settings.bridges);
        })
        .await;
}

#[tokio::test]
async fn pre_rejects_pt_and_incompatible_configuration() {
    FORBID_STARTUP_PROBE
        .scope((), async {
            let mut cfg = pre_config();
            cfg.bridges.lines.push(
                "obfs4 8.8.4.4:443 2222222222222222222222222222222222222222 cert=AAA iat-mode=0"
                    .into(),
            );
            assert!(build_tor_settings(&cfg, None)
                .await
                .unwrap_err()
                .to_string()
                .contains("pluggable transport"));
            cfg = pre_config();
            cfg.bridges.lines.clear();
            assert!(build_tor_settings(&cfg, None)
                .await
                .unwrap_err()
                .to_string()
                .contains("plain bridge"));
            cfg = pre_config();
            cfg.bridges.use_seeds = true;
            assert!(build_tor_settings(&cfg, None)
                .await
                .unwrap_err()
                .to_string()
                .contains("use_seeds"));
            cfg.bridges.use_seeds = false;
            cfg.bridges.auto_fetch = true;
            assert!(build_tor_settings(&cfg, None)
                .await
                .unwrap_err()
                .to_string()
                .contains("auto_fetch"));
            cfg.bridges.auto_fetch = false;
            cfg.warm_pool.enabled = true;
            assert!(build_tor_settings(&cfg, None)
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
            let mut cfg = pre_config();
            cfg.bridges
                .lines
                .push("# xorbot:dns example.invalid 8.8.8.8 1".into());
            let settings = build_tor_settings(&cfg, None).await.unwrap();
            assert_eq!(settings.bridges.len(), 1);
            assert!(settings.bridges.iter().all(|b| b.transport.is_none()));

            // Обычный парсер отбрасывает локальные адреса, но режим pre должен
            // отклонить PT до того, как эта фильтрация сможет его скрыть.
            cfg.bridges.lines.push(
                "obfs4 127.0.0.1:443 2222222222222222222222222222222222222222 cert=AAA iat-mode=0"
                    .into(),
            );
            let parsed = cfg.bridges.parsed().unwrap();
            assert_eq!(parsed.rejected, 1);
            assert!(build_tor_settings(&cfg, None)
                .await
                .unwrap_err()
                .to_string()
                .contains("pluggable transport"));

            cfg = pre_config();
            cfg.bridges
                .lines
                .push(" # xorbot:dns example.invalid 8.8.8.8 1".into());
            assert!(cfg.bridges.parsed().is_err());
            assert!(build_tor_settings(&cfg, None).await.is_err());
        })
        .await;
}

#[tokio::test]
async fn absent_and_disabled_pre_keep_existing_empty_pool_policy() {
    for pre in [None, Some(proxy_config::EndpointOverride::Disabled)] {
        let mut cfg = pre_config();
        cfg.pre_socks5 = pre;
        cfg.bridges.lines.clear();
        let error = build_tor_settings(&cfg, None)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("no reachable bridge"), "{error}");
    }
}

#[tokio::test]
async fn config_load_runs_off_the_async_worker() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ts19-proxy.ktav");
    Config::default().write(&path).unwrap();

    let caller_thread = std::thread::current().id();
    let result = load_config_off_worker(Some(path.as_path())).await;
    assert!(result.is_ok(), "config load failed: {:?}", result.err());

    let ran_on = ran_on_thread(Site::MaintenanceConfigLoad).expect("the load must have run");
    assert_ne!(
        ran_on, caller_thread,
        "config load ran on the caller's async thread"
    );
}

#[tokio::test]
async fn circuit_verify_store_load_runs_off_the_async_worker() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing-store-dir").join("proxy.ktav");

    let caller_thread = std::thread::current().id();
    // Missing file -> empty store -> cheap early return.
    run_circuit_verify_tick(Some(path.as_path()), &[]).await;

    let ran_on = ran_on_thread(Site::CircuitVerifyStoreLoad).expect("the load must have run");
    assert_ne!(
        ran_on, caller_thread,
        "bridge-store load ran on the caller's async thread"
    );
}
