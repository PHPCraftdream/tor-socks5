//! `bridge_manager` integration-style tests (moved out of the
//! implementation file to keep it under the 1000-line limit).

use super::*;

/// Fetch params for pre-flight tests: `probe` on, live token.
fn params() -> FetchBridgesParams {
    FetchBridgesParams {
        timeout: Duration::from_secs(1),
        count: 1,
        probe: true,
        pt_binary: crate::pt::PtBinary::Environment,
        cancel: CancellationToken::new(),
    }
}

#[tokio::test]
async fn empty_sources_bails_before_any_tor_or_io() {
    // The default config carries the built-in sources, so clear them.
    let mut cfg = Config::default();
    cfg.bridges.sources.clear();
    let dir = tempfile::tempdir().expect("temporary config directory");
    let path = dir.path().join("proxy.ktav");
    cfg.write(&path).expect("write isolated config");
    let error = fetch_bridges(&cfg, Some(&path), params())
        .await
        .expect_err("no sources configured");
    assert_eq!(
        error.to_string(),
        "no bridge sources configured in the `sources` list of the bridges file — nothing to fetch"
    );
}

/// Config with the built-in sources left in place, written to a temp file.
fn sourced_config(path: &std::path::Path) -> Config {
    let cfg = Config::default();
    cfg.write(path).expect("write isolated config");
    cfg
}

#[tokio::test]
async fn h10_pre_cancelled_token_cancels_before_any_io() {
    // Regression (H10-1): a pre-cancelled token returns `Cancelled` from
    // the entry check, before settings build, bootstrap or any I/O.
    let dir = tempfile::tempdir().expect("temporary config directory");
    let path = dir.path().join("proxy.ktav");
    let cfg = sourced_config(&path);
    assert!(!cfg.bridges.sources.is_empty());
    let p = params();
    p.cancel.cancel();
    let error = fetch_bridges(&cfg, Some(&path), p)
        .await
        .expect_err("pre-cancelled token");
    assert!(matches!(error, FetchBridgesError::Cancelled), "{error:?}");
}

#[tokio::test]
async fn h10_pre_proxies_is_a_typed_sdk_error_before_tor_work() {
    // Regression (H10-3): a global `pre_proxies` pool is rejected by the
    // SDK itself, synchronously before any Tor/network work (previously
    // the check lived only in the CLI, and the SDK fetched straight from
    // the host, bypassing the pre-proxy).
    let dir = tempfile::tempdir().expect("temporary config directory");
    let path = dir.path().join("proxy.ktav");
    let mut cfg = sourced_config(&path);
    cfg.pre_proxies = Some(
        "127.0.0.1:1080"
            .parse::<proxy_config::Socks5Endpoint>()
            .expect("valid endpoint")
            .into(),
    );
    let before = std::fs::read(&path).expect("config readable before the call");
    let error = fetch_bridges(&cfg, Some(&path), params())
        .await
        .expect_err("pre_proxies configured");
    assert!(matches!(error, FetchBridgesError::PreProxies), "{error:?}");
    assert_eq!(
        error.to_string(),
        "bridges fetch global pre_proxies proxy pool is not supported; remove it"
    );
    let after = std::fs::read(&path).expect("config readable after the call");
    assert_eq!(before, after, "the config file must be untouched");
}

#[tokio::test]
async fn h10_none_config_path_errors_without_creating_a_default_file() {
    // Regression (D-H1/H10-5): `config_path: None` is a typed
    // `NoConfigFile` error — never `Some(0)`, never a fresh default
    // config file created in the current directory.
    let default_path = Config::resolve_path(None);
    assert!(
        !default_path.exists(),
        "precondition: no default config file at {}",
        default_path.display()
    );
    let cfg = Config::default();
    assert!(!cfg.bridges.sources.is_empty());
    let error = fetch_bridges(&cfg, None, params())
        .await
        .expect_err("None config path");
    assert!(
        matches!(error, FetchBridgesError::NoConfigFile),
        "{error:?}"
    );
    assert_eq!(
        error.to_string(),
        "no config file found; run the server once to create defaults"
    );
    assert!(
        !default_path.exists(),
        "no default config file may be created by fetch_bridges(None)"
    );
}

#[tokio::test(start_paused = true)]
async fn h10_pt_binary_reaches_the_bootstrap_settings() {
    // Regression (H10-2): `pt_binary` flows into
    // `build_tor_settings_with_pt`. The test PT observer makes the
    // settings build network-free and records the resolved PT path; a
    // missing explicit binary resolves to exactly that path, and the
    // fetch is cancelled before bootstrap does network work.
    use crate::pt::SDK14_PT_OBSERVER;

    let dir = tempfile::tempdir().expect("temporary config directory");
    let path = dir.path().join("proxy.ktav");
    let mut cfg = sourced_config(&path);
    cfg.bridges.lines =
        vec!["obfs4 8.8.8.8:443 1414141414141414141414141414141414141414 cert=AAA".into()];
    cfg.bridges.use_seeds = false;
    let missing_pt = dir.path().join("definitely-missing-pt-binary");
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let cancel = CancellationToken::new();
    let mut p = params();
    p.pt_binary = crate::pt::PtBinary::Explicit(missing_pt.clone());
    p.cancel = cancel.clone();
    let fetch = tokio::spawn(SDK14_PT_OBSERVER.scope(("fetch", tx), async move {
        fetch_bridges(&cfg, Some(&path), p).await
    }));
    let (role, resolved) = tokio::time::timeout(Duration::from_secs(3600), rx.recv())
        .await
        .expect("the settings build reported its PT resolution in time")
        .expect("observer channel still open");
    assert_eq!(role, "fetch");
    assert_eq!(
        resolved, missing_pt,
        "fetch_bridges must pass params.pt_binary to build_tor_settings_with_pt"
    );
    cancel.cancel();
    let result = fetch.await.expect("fetch task joined");
    // The missing PT binary fails the bootstrap itself (arti rejects a
    // non-existent `pt_binary` before any network work) — and names the
    // path in the error chain, again proving the param arrived.
    match result {
        Err(FetchBridgesError::Other(error)) => assert!(
            format!("{error:#}").contains("definitely-missing-pt-binary"),
            "error chain must name the PT binary: {error:#}"
        ),
        Err(FetchBridgesError::Cancelled) => {}
        other => panic!("expected Other/Cancelled, got {other:?}"),
    }
}

#[tokio::test]
async fn shutdown_sets_cancelled_and_reports_producers() {
    let token = CancellationToken::new();
    let (status_tx, status_rx) = watch::channel(BridgeManagerStatus {
        producers: vec!["maintenance".into()],
        cancelled: false,
    });
    let handle = BridgeManagerHandle {
        token: token.clone(),
        status_tx,
        status_rx,
        handles: Vec::new(),
        tasks_transferred: false,
    };
    assert_eq!(handle.status().producers, vec!["maintenance".to_string()]);
    assert!(!handle.status().cancelled);
    assert!(!token.is_cancelled());

    let status_rx = handle.subscribe();
    let outcomes = handle.shutdown_with_timeout(Duration::from_secs(5)).await;
    assert!(outcomes.iter().all(|o| o.outcome.is_ok()));
    assert!(token.is_cancelled());
    // H9.8: cancellation must also be visible via the status receiver.
    assert!(status_rx.borrow().cancelled);
}

#[tokio::test]
async fn shutdown_reports_panicking_producer() {
    let task = tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(10)).await;
        panic!("producer exploded");
    });
    let manager = test_manager(CancellationToken::new(), vec![("bad", task)]);
    let outcomes = manager.shutdown_with_timeout(Duration::from_secs(5)).await;
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].producer, "bad");
    assert_eq!(
        outcomes[0].outcome.as_ref().unwrap_err(),
        "producer exploded"
    );
}

#[tokio::test]
async fn shutdown_with_timeout_bounds_hung_producer() {
    let task = tokio::spawn(async {
        // Does not respond to cancellation at all.
        std::future::pending::<()>().await;
    });
    let manager = test_manager(CancellationToken::new(), vec![("hung", task)]);
    let started = std::time::Instant::now();
    let outcomes = manager
        .shutdown_with_timeout(Duration::from_millis(200))
        .await;
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].producer, "hung");
    assert_eq!(
        outcomes[0].outcome.as_ref().unwrap_err(),
        "shutdown budget exceeded"
    );
}

#[tokio::test]
async fn drop_cancels_token_without_blocking() {
    let (status_tx, status_rx) = watch::channel(BridgeManagerStatus {
        producers: Vec::new(),
        cancelled: false,
    });
    let token = CancellationToken::new();
    let handle = BridgeManagerHandle {
        token: token.clone(),
        status_tx,
        status_rx,
        handles: Vec::new(),
        tasks_transferred: false,
    };
    drop(handle);
    assert!(token.is_cancelled());
}

struct DropSignal(Option<tokio::sync::oneshot::Sender<()>>);

impl Drop for DropSignal {
    fn drop(&mut self) {
        if let Some(signal) = self.0.take() {
            let _ = signal.send(());
        }
    }
}

async fn guarded_task(
    wait_for: Option<CancellationToken>,
) -> (JoinHandle<()>, tokio::sync::oneshot::Receiver<()>) {
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(async move {
        let _guard = DropSignal(Some(dropped_tx));
        let _ = started_tx.send(());
        match wait_for {
            Some(token) => token.cancelled().await,
            None => std::future::pending::<()>().await,
        }
    });
    started_rx.await.expect("task reached its pending point");
    (handle, dropped_rx)
}

fn test_manager(
    token: CancellationToken,
    handles: Vec<(&str, JoinHandle<()>)>,
) -> BridgeManagerHandle {
    let (status_tx, status_rx) = watch::channel(BridgeManagerStatus {
        producers: Vec::new(),
        cancelled: false,
    });
    BridgeManagerHandle {
        token,
        status_tx,
        status_rx,
        handles: handles
            .into_iter()
            .map(|(name, handle)| (name.to_string(), handle))
            .collect(),
        tasks_transferred: false,
    }
}

#[tokio::test]
async fn sdk14_dropping_manager_aborts_pending_tasks() {
    let (task, dropped) = guarded_task(None).await;
    drop(test_manager(CancellationToken::new(), vec![("task", task)]));
    tokio::time::timeout(Duration::from_secs(10), dropped)
        .await
        .expect("manager drop aborts its pending task within 10s")
        .expect("aborted task dropped its guard");
}

#[tokio::test]
async fn sdk14_cancelling_polled_shutdown_aborts_pending_tasks() {
    use std::future::Future;

    let (task, dropped) = guarded_task(None).await;
    let token = CancellationToken::new();
    let mut shutdown = Box::pin(
        test_manager(token.clone(), vec![("task", task)])
            .shutdown_with_timeout(Duration::from_secs(30)),
    );
    std::future::poll_fn(|cx| match shutdown.as_mut().poll(cx) {
        std::task::Poll::Pending => std::task::Poll::Ready(()),
        std::task::Poll::Ready(_) => panic!("shutdown unexpectedly completed"),
    })
    .await;
    assert!(token.is_cancelled());
    drop(shutdown);
    tokio::time::timeout(Duration::from_secs(10), dropped)
        .await
        .expect("cancelled shutdown aborts its pending task within 10s")
        .expect("cancelled shutdown aborted its task");
}

// Synthetic handles and tokens cover transfer and token-tree behavior;
// this does not exercise start_with_parent_token's production wiring.
#[tokio::test]
async fn sdk14_synthetic_child_cancellation_does_not_cancel_parent() {
    let parent = CancellationToken::new();
    let child = parent.child_token();
    test_manager(child.clone(), Vec::new())
        .shutdown_with_timeout(Duration::from_secs(5))
        .await;
    assert!(child.is_cancelled());
    assert!(!parent.is_cancelled());
}

#[tokio::test]
async fn sdk14_transferred_synthetic_task_lives_until_parent_cancellation() {
    let parent = CancellationToken::new();
    let child = parent.child_token();
    let (task, mut dropped) = guarded_task(Some(child.clone())).await;
    let manager = test_manager(child.clone(), vec![("task", task)]);
    let mut destination = Vec::new();
    manager.transfer_tasks(&mut destination);

    assert_eq!(destination.len(), 1);
    assert!(!destination[0].is_finished());
    assert!(matches!(
        dropped.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));

    parent.cancel();
    assert!(child.is_cancelled());
    for task in destination {
        task.await.expect("cooperatively cancelled task completed");
    }
    dropped
        .await
        .expect("task completed after parent cancellation");
}

#[tokio::test(start_paused = true)]
async fn sdk14_manager_explicit_pt_reaches_maintenance_and_verifier() {
    use std::sync::Once;

    static CRYPTO_PROVIDER: Once = Once::new();
    CRYPTO_PROVIDER.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });

    let dir = tempfile::tempdir().expect("temporary config directory");
    let config_path = dir.path().join("proxy.ktav");
    let bridge: bridge_line::BridgeLine =
        "obfs4 8.8.8.8:443 1414141414141414141414141414141414141414 cert=AAA"
            .parse()
            .expect("valid public obfs4 bridge");
    let mut cfg = Config::default();
    cfg.bridges.lines = vec![bridge.to_string()];
    cfg.bridges.sources.clear();
    cfg.bridges.use_seeds = false;
    cfg.bridges.auto_fetch = false;
    cfg.bridges.recheck_interval_mins = 0;
    cfg.warm_pool.enabled = false;
    cfg.write(&config_path).expect("write isolated config");
    cfg.write_bridges(&config_path)
        .expect("write isolated bridge lines");

    let expected_pt = dir.path().join("explicit-host-pt");
    assert_ne!(
        expected_pt,
        std::env::current_exe().expect("current executable")
    );
    let state_dir = dir.path().join("client-state");
    let initial_settings = arti_wrapper::Settings {
        state_dir: Some(state_dir.clone()),
        bridges: vec![bridge.clone()],
        pt_binary: Some(expected_pt.clone()),
        ..Default::default()
    };
    let tunnel = TorTunnel::create_unbootstrapped_with(arti_wrapper::Settings {
        state_dir: Some(state_dir),
        ..Default::default()
    })
    .expect("create transport-free unbootstrapped tunnel");
    let handle = crate::tor_watchdog::TorHandle::new_with_settings(tunnel, &initial_settings);

    let store_path = bridge_store::BridgeStore::resolve_path(Some(&config_path));
    let mut store = bridge_store::BridgeStore::load(store_path).expect("load bridge store");
    let now = time::OffsetDateTime::now_utc();
    let alive = [(bridge.clone(), Duration::from_millis(1))];
    store.note_probe_round(
        std::slice::from_ref(&bridge),
        &alive,
        now,
        Duration::ZERO,
        u32::MAX,
        u32::MAX,
    );
    store.note_channel_success_at(&bridge, now);
    store
        .save()
        .expect("seed channel-proven verifier candidate");

    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let manager = crate::pt::SDK14_PT_OBSERVER
        .scope(("manager", tx), async {
            start(
                handle,
                Some(config_path),
                &cfg,
                ObservationSink::default(),
                BridgeManagerConfig {
                    settings: initial_settings,
                    pt_binary: crate::pt::PtBinary::Explicit(expected_pt.clone()),
                },
            )
        })
        .await;

    let mut observed = Vec::new();
    tokio::time::timeout(Duration::from_secs(3600), async {
        while !observed.iter().any(|(role, _)| *role == "maintenance")
            || !observed.iter().any(|(role, _)| *role == "verifier")
        {
            observed.push(rx.recv().await.expect("producer PT resolution report"));
        }
    })
    .await
    .expect("maintenance and >30-minute verifier tick report within one hour");

    manager.shutdown_with_timeout(Duration::from_secs(30)).await;
    for (role, path) in observed {
        assert!(matches!(role, "maintenance" | "verifier"));
        assert_eq!(path, expected_pt, "{role} must retain manager PT policy");
    }
}

#[tokio::test(start_paused = true)]
async fn sdk14_manager_explicit_pt_reaches_maintenance_after_transport_free_start() {
    use std::sync::Once;

    static CRYPTO_PROVIDER: Once = Once::new();
    CRYPTO_PROVIDER.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });

    let dir = tempfile::tempdir().expect("temporary config directory");
    let config_path = dir.path().join("proxy.ktav");
    let bridge: bridge_line::BridgeLine =
        "obfs4 8.8.8.8:443 1414141414141414141414141414141414141414 cert=AAA"
            .parse()
            .expect("valid public obfs4 bridge");
    let mut cfg = Config::default();
    cfg.bridges.lines = vec![bridge.to_string()];
    cfg.bridges.sources.clear();
    cfg.bridges.use_seeds = false;
    cfg.bridges.auto_fetch = false;
    cfg.bridges.recheck_interval_mins = 0;
    cfg.warm_pool.enabled = false;
    cfg.write(&config_path).expect("write isolated config");
    cfg.write_bridges(&config_path)
        .expect("write isolated bridge lines");

    let expected_pt = dir.path().join("explicit-host-pt");
    let state_dir = dir.path().join("client-state");
    let initial_settings = arti_wrapper::Settings {
        state_dir: Some(state_dir.clone()),
        bridges: Vec::new(),
        pt_binary: None,
        ..Default::default()
    };
    let tunnel = TorTunnel::create_unbootstrapped_with(arti_wrapper::Settings {
        state_dir: Some(state_dir),
        ..Default::default()
    })
    .expect("create transport-free unbootstrapped tunnel");
    let handle = crate::tor_watchdog::TorHandle::new_with_settings(tunnel, &initial_settings);

    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let manager = crate::pt::SDK14_PT_OBSERVER
        .scope(("manager", tx), async {
            start(
                handle,
                Some(config_path),
                &cfg,
                ObservationSink::default(),
                BridgeManagerConfig {
                    settings: initial_settings,
                    pt_binary: crate::pt::PtBinary::Explicit(expected_pt.clone()),
                },
            )
        })
        .await;

    let mut observed = Vec::new();
    tokio::time::timeout(Duration::from_secs(3600), async {
        while !observed.iter().any(|(role, _)| *role == "maintenance") {
            observed.push(rx.recv().await.expect("maintenance PT resolution report"));
        }
    })
    .await
    .expect("maintenance PT resolution report within one hour");

    manager.shutdown_with_timeout(Duration::from_secs(30)).await;
    assert_eq!(observed, vec![("maintenance", expected_pt)]);
}
