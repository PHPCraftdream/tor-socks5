//! `launch_producers` tests: producer ownership, the refresh-needed
//! wiring, and the producer-boundary guard (H14 chunk 1).

use super::*;
use arti_wrapper::TorTunnel;
use proxy_config::Socks5Endpoint;

fn ensure_crypto_provider() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn smoke_cfg() -> Config {
    let mut cfg = Config::default();
    cfg.bridges.use_seeds = false;
    cfg.bridges.auto_fetch = false;
    cfg.bridges.lines = vec!["8.8.8.8:443 1111111111111111111111111111111111111111".into()];
    cfg.pre_proxies = Some("127.0.0.1:1080".parse::<Socks5Endpoint>().unwrap().into());
    cfg.watchdog.enabled = true;
    cfg.watchdog.check_interval_secs = 45;
    cfg.warm_pool.enabled = true;
    cfg
}

#[tokio::test]
async fn launch_producers_tasks_are_directly_owned_by_producer_vec() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = smoke_cfg();
    let mut valid = cfg.clone();
    valid.warm_pool.enabled = false;
    let settings = crate::tor_setup::build_tor_settings(&valid, dir.path())
        .await
        .unwrap();
    ensure_crypto_provider();
    let tor = TorTunnel::create_unbootstrapped_with(settings.clone()).unwrap();
    let token = CancellationToken::new();
    let mut tasks = Vec::new();
    launch_producers(
        TorHandle::new_with_settings(tor, &settings),
        dir.path().join("missing.ktav"),
        &cfg,
        crate::arti_observability::ObservationSink::new(),
        settings,
        crate::pt::PtBinary::Environment,
        token.clone(),
        &mut tasks,
    );
    assert_eq!(
        tasks.len(),
        2,
        "maintenance and watchdog tasks are directly supervised"
    );
    token.cancel();
    for task in tasks {
        task.await.unwrap();
    }
}

#[tokio::test]
async fn set_needed_is_set_when_preferred_transport_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = smoke_cfg();
    cfg.bridges.auto_fetch = true;
    cfg.bridges.transport = "obfs4".into();
    // `auto_fetch` is incompatible with the `pre_proxies` pool.
    cfg.pre_proxies = None;

    // Plain (transport-less) bridge line; settings built directly so no
    // live reachability probe runs (the probe would fail offline and the
    // acceptance only needs the config/settings wiring).
    let bridge: bridge_line::BridgeLine = "8.8.8.8:443 1111111111111111111111111111111111111111"
        .parse()
        .unwrap();
    let settings = arti_wrapper::Settings {
        state_dir: Some(dir.path().to_path_buf()),
        bridges: vec![bridge],
        ..Default::default()
    };
    ensure_crypto_provider();
    let tor = TorTunnel::create_unbootstrapped_with(settings.clone()).unwrap();
    let handle = TorHandle::new_with_settings(tor, &settings);
    let token = CancellationToken::new();
    let pt_binary = crate::pt::PtBinary::Environment;
    let mut tasks = Vec::new();
    launch_producers(
        handle.clone(),
        dir.path().join("missing.ktav"),
        &cfg,
        crate::arti_observability::ObservationSink::new(),
        settings.clone(),
        pt_binary.clone(),
        token.clone(),
        &mut tasks,
    );
    assert!(
        handle.bridge_refresh().is_needed(),
        "the plain bridge line lacks the preferred obfs4 transport, so a refresh is pre-armed"
    );
    token.cancel();
    for task in tasks {
        task.await.unwrap();
    }

    // Control case: no transport preference, no refresh needed.
    let mut plain_cfg = cfg;
    plain_cfg.bridges.transport = String::new();
    let plain_settings = settings.clone();
    let tor = TorTunnel::create_unbootstrapped_with(plain_settings.clone()).unwrap();
    let handle = TorHandle::new_with_settings(tor, &plain_settings);
    let token = CancellationToken::new();
    let mut tasks = Vec::new();
    launch_producers(
        handle.clone(),
        dir.path().join("missing.ktav"),
        &plain_cfg,
        crate::arti_observability::ObservationSink::new(),
        plain_settings,
        pt_binary,
        token.clone(),
        &mut tasks,
    );
    assert!(!handle.bridge_refresh().is_needed());
    token.cancel();
    for task in tasks {
        task.await.unwrap();
    }
}

#[tokio::test]
async fn producer_boundaries_remain_guarded() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = smoke_cfg();
    let path = dir.path().join("proxy.ktav");
    let mut build_cfg = cfg.clone();
    build_cfg.warm_pool.enabled = false;
    let settings = crate::tor_setup::build_tor_settings(&build_cfg, &path)
        .await
        .unwrap();
    assert!(settings.pre_endpoint.is_some());
    assert_eq!(settings.bridges.len(), 1);
    ensure_crypto_provider();
    let tor = TorTunnel::create_unbootstrapped_with(settings.clone()).unwrap();
    let handle = TorHandle::new_with_settings(tor, &settings);
    crate::test_seams::FORBID_PRODUCER
        .scope((), async {
            let mut producers = Vec::new();
            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                launch_producers(
                    handle.clone(),
                    path.clone(),
                    &cfg,
                    crate::arti_observability::ObservationSink::new(),
                    settings.clone(),
                    crate::pt::PtBinary::Environment,
                    CancellationToken::new(),
                    &mut producers,
                );
            }))
            .unwrap_err();
            assert_eq!(panic.downcast_ref::<&'static str>(), Some(&"maintenance"));
            assert!(producers.is_empty());
        })
        .await;
}
