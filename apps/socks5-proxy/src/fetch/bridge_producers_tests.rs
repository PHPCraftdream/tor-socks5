use super::*;

fn ensure_crypto_provider() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[tokio::test]
async fn pre_skips_real_producer_launches_and_default_reaches_boundaries() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default();
    cfg.pre_socks5 = Some(proxy_config::EndpointOverride::Endpoint(
        "127.0.0.1:1080".parse().unwrap(),
    ));
    cfg.bridges.use_seeds = false;
    cfg.bridges.auto_fetch = false;
    cfg.bridges.lines = vec!["8.8.8.8:443 1111111111111111111111111111111111111111".into()];
    let path = dir.path().join("proxy.ktav");
    let settings = crate::tor_setup::build_tor_settings(&cfg, Some(&path))
        .await
        .unwrap();
    assert!(settings.pre_endpoint.is_some());
    assert_eq!(settings.bridges.len(), 1);
    ensure_crypto_provider();
    let tor = TorTunnel::create_unbootstrapped_with(settings.clone()).unwrap();
    let handle = TorHandle::new(tor);
    crate::test_seams::FORBID_PRODUCER
        .scope((), async {
            let mut producers = Vec::new();
            launch(
                handle.clone(),
                Some(path.clone()),
                &cfg,
                crate::arti_observability::ObservationSink::new(),
                settings.clone(),
                CancellationToken::new(),
                &mut producers,
            );
            assert!(producers.is_empty());

            cfg.pre_socks5 = None;
            // Туннель остаётся с pre; проверка доходит только до границы запуска.
            let mut default_settings = settings;
            default_settings.pre_endpoint = None;
            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                launch(
                    handle.clone(),
                    Some(path.clone()),
                    &cfg,
                    crate::arti_observability::ObservationSink::new(),
                    default_settings,
                    CancellationToken::new(),
                    &mut producers,
                );
            }))
            .unwrap_err();
            assert_eq!(panic.downcast_ref::<&'static str>(), Some(&"maintenance"));
            assert!(producers.is_empty());

            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _handle = crate::bridge_verifier::spawn_bridge_circuit_verifier(
                    Some(path.clone()),
                    handle.clone(),
                    CancellationToken::new(),
                );
            }))
            .unwrap_err();
            assert_eq!(panic.downcast_ref::<&'static str>(), Some(&"verifier"));

            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _handle = crate::bridge_warmer::spawn_bridge_warmer(
                    handle.clone(),
                    Some(path.clone()),
                    cfg.warm_pool,
                    CancellationToken::new(),
                );
            }))
            .unwrap_err();
            assert_eq!(panic.downcast_ref::<&'static str>(), Some(&"warmer"));

            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _handle = spawn_tor_watchdog(
                    handle.clone(),
                    Some(path.clone()),
                    cfg.watchdog,
                    CancellationToken::new(),
                );
            }))
            .unwrap_err();
            assert_eq!(panic.downcast_ref::<&'static str>(), Some(&"watchdog"));

            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _handle = spawn_bridge_failover_watchdog(
                    handle,
                    Some(path),
                    cfg.watchdog,
                    CancellationToken::new(),
                );
            }))
            .unwrap_err();
            assert_eq!(panic.downcast_ref::<&'static str>(), Some(&"failover"));
        })
        .await;
}
