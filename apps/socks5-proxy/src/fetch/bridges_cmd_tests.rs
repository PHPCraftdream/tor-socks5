use super::*;

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
    let mut cfg = Config::default();
    cfg.pre_socks5 = Some(proxy_config::EndpointOverride::Endpoint(
        "127.0.0.1:1080".parse().unwrap(),
    ));
    cfg.bridges.use_seeds = false;
    cfg.bridges.auto_fetch = false;
    cfg.bridges.lines = vec!["8.8.8.8:443 1111111111111111111111111111111111111111".into()];
    assert!(!cfg.bridges.sources.is_empty());
    cfg.write(&path).unwrap();
    cfg.write_bridges(&path).unwrap();
    let loaded = Config::load_with_override(Some(&path))
        .unwrap()
        .into_config();
    let settings = build_tor_settings(&loaded, Some(&path)).await.unwrap();
    assert!(settings.pre_endpoint.is_some());
    assert_eq!(settings.bridges.len(), 1);

    FETCH_BOUNDARY.scope(std::cell::Cell::new(false), async {
        let error = cmd_bridges(action(), Some(&path)).await.unwrap_err();
        assert_eq!(error.to_string(), "bridges fetch global pre_socks5 SOCKS5 endpoint is not supported yet; remove it or set it to `none`");
        FETCH_BOUNDARY.with(|hit| assert!(!hit.get()));

        cfg.pre_socks5 = None;
        cfg.write(&path).unwrap();
        let error = cmd_bridges(action(), Some(&path)).await.unwrap_err();
        assert_eq!(error.to_string(), "test stopped before fetch startup");
        FETCH_BOUNDARY.with(|hit| assert!(hit.get()));
    }).await;
}
