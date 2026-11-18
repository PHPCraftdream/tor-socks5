use super::*;
use tor_socks5::config::Socks5Endpoint;

fn action() -> BridgesAction {
    BridgesAction::Fetch {
        dry_run: false,
        no_probe: false,
        timeout_secs: 1,
        count: 1,
    }
}

#[tokio::test]
async fn fetch_rejects_pre_before_network_startup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("proxy.ktav");
    let mut cfg = Config {
        pre_proxies: Some("127.0.0.1:1080".parse::<Socks5Endpoint>().unwrap().into()),
        ..Config::default()
    };
    cfg.bridges.use_seeds = false;
    cfg.bridges.auto_fetch = false;
    cfg.bridges.lines = vec!["8.8.8.8:443 1111111111111111111111111111111111111111".into()];
    assert!(!cfg.bridges.sources.is_empty());
    cfg.write(&path).unwrap();
    cfg.write_bridges(&path).unwrap();
    let loaded = Config::load_with_override(Some(&path))
        .unwrap()
        .into_config();
    let settings = build_tor_settings(&loaded, &path).await.unwrap();
    assert!(settings.pre_endpoint.is_some());
    assert_eq!(settings.bridges.len(), 1);

    FETCH_BOUNDARY
        .scope(std::cell::Cell::new(false), async {
            // H10: the SDK rejects `pre_proxies` with the typed error and
            // the CLI propagates it; no CLI-side pool check remains.
            let error = cmd_bridges(action(), Some(&path)).await.unwrap_err();
            assert_eq!(
                error.to_string(),
                "bridges fetch global pre_proxies proxy pool is not supported; remove it"
            );
            FETCH_BOUNDARY.with(|hit| assert!(!hit.get()));

            cfg.pre_proxies = None;
            cfg.write(&path).unwrap();
            let error = cmd_bridges(action(), Some(&path)).await.unwrap_err();
            assert_eq!(error.to_string(), "test stopped before fetch startup");
            FETCH_BOUNDARY.with(|hit| assert!(hit.get()));
        })
        .await;
}

/// ROLLBACK THAT FAILS THIS: handing `fetch_bridges` a token nothing cancels
/// (the previous `CancellationToken::new()`) means a stop signal never
/// reaches the fetch; here the token stays live after the signal resolves.
#[tokio::test]
async fn a_stop_signal_cancels_the_fetch_token() {
    let cancel = CancellationToken::new();
    let (signal, stop) = tokio::sync::oneshot::channel::<()>();
    let stopper = tokio::spawn(cancel_on_signal(cancel.clone(), async move {
        stop.await.ok();
        "test signal"
    }));
    tokio::task::yield_now().await;
    assert!(!cancel.is_cancelled(), "nothing was signalled yet");
    signal.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(30), cancel.cancelled())
        .await
        .expect("the signal must cancel the fetch token");
    stopper.await.unwrap();
}
