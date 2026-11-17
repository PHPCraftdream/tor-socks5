use super::*;
use proxy_config::Socks5Endpoint;

fn ensure_crypto_provider() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Smoke test: checks the producer count and cooperative completion only.
/// It does not prove descendant ownership after abort; a trampoline
/// implementation would also pass.
#[tokio::test]
async fn sdk11_server_bridge_tasks_are_directly_owned_by_producer_vec() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.bridges.use_seeds = false;
    cfg.bridges.auto_fetch = false;
    cfg.bridges.lines = vec!["8.8.8.8:443 1111111111111111111111111111111111111111".into()];
    cfg.pre_proxies = Some("127.0.0.1:1080".parse::<Socks5Endpoint>().unwrap().into());
    cfg.watchdog.enabled = true;
    cfg.watchdog.check_interval_secs = 45;
    cfg.warm_pool.enabled = true;
    let mut valid = cfg.clone();
    valid.warm_pool.enabled = false;
    let settings = tor_socks5_runtime::tor_setup::build_tor_settings(&valid, dir.path())
        .await
        .unwrap();
    ensure_crypto_provider();
    let tor = TorTunnel::create_unbootstrapped_with(settings.clone()).unwrap();
    let token = CancellationToken::new();
    let mut tasks = Vec::new();
    launch(
        TorHandle::new(tor),
        dir.path().join("missing.ktav"),
        &cfg,
        tor_socks5_runtime::arti_observability::ObservationSink::new(),
        settings,
        tor_socks5_runtime::pt::PtBinary::Environment,
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
async fn producer_boundaries_remain_guarded() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config {
        pre_proxies: Some("127.0.0.1:1080".parse::<Socks5Endpoint>().unwrap().into()),
        ..Config::default()
    };
    cfg.bridges.use_seeds = false;
    cfg.bridges.auto_fetch = false;
    cfg.bridges.lines = vec!["8.8.8.8:443 1111111111111111111111111111111111111111".into()];
    let path = dir.path().join("proxy.ktav");
    let settings = tor_socks5_runtime::tor_setup::build_tor_settings(&cfg, &path)
        .await
        .unwrap();
    assert!(settings.pre_endpoint.is_some());
    assert_eq!(settings.bridges.len(), 1);
    ensure_crypto_provider();
    let tor = TorTunnel::create_unbootstrapped_with(settings.clone()).unwrap();
    let handle = TorHandle::new(tor);
    tor_socks5_runtime::test_seams::FORBID_PRODUCER
        .scope((), async {
            let mut producers = Vec::new();
            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                launch(
                    handle.clone(),
                    path.clone(),
                    &cfg,
                    tor_socks5_runtime::arti_observability::ObservationSink::new(),
                    settings.clone(),
                    tor_socks5_runtime::pt::PtBinary::Environment,
                    CancellationToken::new(),
                    &mut producers,
                );
            }))
            .unwrap_err();
            assert_eq!(panic.downcast_ref::<&'static str>(), Some(&"maintenance"));
            assert!(producers.is_empty());

            cfg.pre_proxies = None;
            // Туннель остаётся с pre; проверка доходит только до границы запуска.
            let mut default_settings = settings;
            default_settings.pre_endpoint = None;
            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                launch(
                    handle.clone(),
                    path.clone(),
                    &cfg,
                    tor_socks5_runtime::arti_observability::ObservationSink::new(),
                    default_settings,
                    tor_socks5_runtime::pt::PtBinary::Environment,
                    CancellationToken::new(),
                    &mut producers,
                );
            }))
            .unwrap_err();
            assert_eq!(panic.downcast_ref::<&'static str>(), Some(&"maintenance"));
            assert!(producers.is_empty());

            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _handle = tor_socks5_runtime::bridge_verifier::spawn_bridge_circuit_verifier(
                    path.clone(),
                    handle.clone(),
                    tor_socks5_runtime::pt::PtBinary::Environment,
                    CancellationToken::new(),
                );
            }))
            .unwrap_err();
            assert_eq!(panic.downcast_ref::<&'static str>(), Some(&"verifier"));

            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _handle = tor_socks5_runtime::bridge_warmer::spawn_bridge_warmer(
                    handle.clone(),
                    path.clone(),
                    cfg.warm_pool,
                    CancellationToken::new(),
                );
            }))
            .unwrap_err();
            assert_eq!(panic.downcast_ref::<&'static str>(), Some(&"warmer"));

            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _run = spawn_tor_watchdog(
                    handle.clone(),
                    path.clone(),
                    cfg.watchdog,
                    CancellationToken::new(),
                );
            }))
            .unwrap_err();
            assert_eq!(panic.downcast_ref::<&'static str>(), Some(&"watchdog"));

            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _handle = spawn_bridge_failover_watchdog(
                    handle,
                    path,
                    cfg.watchdog,
                    CancellationToken::new(),
                );
            }))
            .unwrap_err();
            assert_eq!(panic.downcast_ref::<&'static str>(), Some(&"failover"));
        })
        .await;
}
