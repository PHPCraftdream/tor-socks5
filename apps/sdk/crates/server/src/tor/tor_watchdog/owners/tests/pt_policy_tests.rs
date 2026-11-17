//! H11 acceptance: the server's PT policy reaches the production settings
//! builders (`restricted_owner_settings` for the owner template and
//! `build_tor_settings_with_pt` inside `SettingsInit`). The network stages
//! of startup are parked by the `RUN_SERVER_STARTUP` gate, so this is not an
//! end-to-end Tor test — but the settings resolutions observed here run the
//! real production code paths.

use super::*;

use crate::server::{global_init, run_server, ServerArgs};

/// Aborts the spawned server task on drop, like the parked-startup harness.
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);
impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Runs the real `run_server` startup with the settings stage parked by the
/// `RUN_SERVER_STARTUP` gate and asserts the SDK14 PT observer saw `expected`
/// resolved under the given policy before the gate was reached.
async fn parked_startup_reports_pt(pt: tor_socks5_runtime::pt::PtBinary) {
    let _serial = TEST_LIFECYCLE.lock().await;
    let dir = tempfile::tempdir().unwrap();
    // Reserve a port the same way the parked-startup harness does.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let mut cfg = crate::config::Config {
        listen: vec![address.to_string()],
        ..Default::default()
    };
    // `pre_proxies` + an obfs4 bridge make the owner template resolve a PT
    // binary (needs_pt) without any network access.
    cfg.bridges.use_seeds = false;
    cfg.bridges.auto_fetch = false;
    cfg.bridges.lines =
        vec!["obfs4 8.8.8.8:443 1414141414141414141414141414141414141414 cert=AAA".into()];
    cfg.pre_proxies = Some(
        "127.0.0.1:1080"
            .parse::<proxy_config::Socks5Endpoint>()
            .unwrap()
            .into(),
    );
    let path = dir.path().join("server.ktav");
    let settings = Settings {
        bridges: vec!["192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01"
            .parse()
            .unwrap()],
        state_dir: Some(dir.path().join("state")),
        ..Default::default()
    };
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let hook = Arc::new(global_init::StartupHook {
        settings,
        park_global: false,
        gate: std::sync::Mutex::new(Some((entered_tx, release_rx))),
        async_gate: std::sync::Mutex::new(None),
    });
    // The config is passed in memory; the path only anchors the (optional)
    // users-registry resolution. The template stage must be constructible
    // from it — this is the same eager call `run_server` makes before the
    // startup gate.
    let config_path = Some(path);
    let template = tor_socks5_runtime::tor_setup::restricted_owner_settings(
        &cfg,
        config_path.as_deref(),
        &tor_socks5_runtime::pt::PtBinary::Environment,
    );
    assert!(
        template.is_ok(),
        "the parked template config must resolve a PT binary: {:?}",
        template.err()
    );
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args = ServerArgs {
        config: cfg,
        config_path: config_path.clone(),
        obs_sink: tor_socks5_runtime::arti_observability::ObservationSink::new(),
        upstream_addr: None,
        upstream_user: None,
        upstream_pass: None,
        no_upstream: false,
        pt_binary: pt,
        dns_startup_policy: crate::api::DnsStartupPolicy::Required,
    };
    let expected = match &args.pt_binary {
        tor_socks5_runtime::pt::PtBinary::Explicit(path) => path.clone(),
        tor_socks5_runtime::pt::PtBinary::Environment => std::env::current_exe().unwrap(),
    };
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let (pt_tx, mut pt_rx) = tokio::sync::mpsc::channel(8);
    let mut server = AbortOnDrop(tokio::spawn(global_init::RUN_SERVER_STARTUP.scope(
        hook,
        async move {
            tor_socks5_runtime::test_seams::sdk14_pt_scope("server", pt_tx, async move {
                run_server(args, async {
                    let _ = shutdown_rx.await;
                })
                .await
            })
            .await
        },
    )));
    let entered = tokio::time::timeout(Duration::from_secs(10), entered_rx).await;
    assert!(
        matches!(entered, Ok(Ok(()))),
        "server did not reach the settings startup stage"
    );
    let observed = tokio::time::timeout(Duration::from_secs(5), pt_rx.recv())
        .await
        .expect("PT resolution must be reported before the startup gate");
    assert_eq!(
        observed,
        Some(("server", expected)),
        "the server's PT policy must reach the owner settings resolution"
    );
    // The parked gate holds startup; shutdown must unwind it as a typed
    // cancellation, exactly like the parked-startup harness.
    shutdown_tx.send(()).unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), &mut server.0).await;
    if result.is_err() {
        server.0.abort();
        let _ = (&mut server.0).await;
    }
    let _ = release_tx.send(());
    global_init::recover_startup().await.unwrap();
    assert!(
        !global_init::startup_snapshot(false).0,
        "startup registry must be clean after recovery"
    );
}

/// Explicit host policy: the PT binary resolved for the owner template (and,
/// through the same shared helper, for the main client's settings init) is
/// exactly the `PtBinary::Explicit` executable the builder was given.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_pt_policy_reaches_the_owner_settings_resolution() {
    let dir = tempfile::tempdir().unwrap();
    parked_startup_reports_pt(tor_socks5_runtime::pt::PtBinary::Explicit(
        dir.path().join("host-pt-helper"),
    ))
    .await;
}

/// Default policy: behaviour is unchanged — the resolved PT binary is the
/// current process executable (the busybox-style PT dispatcher), matching the
/// pre-H11 resolution.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn environment_pt_policy_resolves_the_current_process_executable() {
    parked_startup_reports_pt(tor_socks5_runtime::pt::PtBinary::Environment).await;
}
