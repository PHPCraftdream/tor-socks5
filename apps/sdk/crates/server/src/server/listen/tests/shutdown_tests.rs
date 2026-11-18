//! TS3-04 shutdown-choreography regressions driven through the PROD
//! `phases::phase_shutdown` and the injected `TestRunHooks` seam.

use super::*;

// -- shutdown_producers choreography ----------------------------------------

/// Reload the on-disk bridge store for a test config path.
fn reload_store(config_path: &Path) -> BridgeStore {
    BridgeStore::load(BridgeStore::resolve_path(config_path)).expect("reload store")
}

fn test_bridge_line() -> BridgeLine {
    "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0"
        .parse()
        .expect("test bridge line parses")
}

// -- phase_shutdown producer choreography (TS3-04, prod path) ---------------

use crate::server::global_init::{ShutdownHooks, TestRunHooks};
use crate::server::producers::{LaunchGuard, ProducerTasks};

/// Drive the PROD `phase_shutdown` on a `RunContext` shaped for it: a real
/// Tor handle (unbootstrapped tunnel — the shutdown path never bootstraps),
/// no owner registry (close is skipped exactly as in an upstream-style run)
/// and the given test hooks.
async fn run_phase_shutdown(
    dir: std::path::PathBuf,
    hooks: Option<Arc<TestRunHooks>>,
    owner: Arc<ProducerTasks>,
) -> anyhow::Result<()> {
    let dir = &*dir;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let settings = arti_wrapper::Settings {
        bridges: vec!["192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01"
            .parse()
            .unwrap()],
        state_dir: Some(dir.join("state")),
        ..Default::default()
    };
    let tunnel = arti_wrapper::TorTunnel::create_unbootstrapped_with(settings.clone()).unwrap();
    let handle = tor_socks5_runtime::tor_watchdog::TorHandle::new_with_settings(tunnel, &settings);
    let mut set_stage = |_stage: crate::api::ServerStage| {};
    let mut on_ready = |_: Vec<std::net::SocketAddr>| {};
    let writer_started = std::sync::atomic::AtomicBool::new(false);
    let mut shutdown = std::pin::pin!(std::future::pending::<()>());
    let mut ctx = crate::server::phases::RunContext {
        handler_guard: None,
        registry_guard: None,
        producer_guard: None,
        egress: Some(Egress::Tor(TorEgress {
            handle,
            global_pre: None,
            global_post: None,
            dns_enabled: false,
            registry: None,
            pools: Arc::new(arti_wrapper::PostPools::new()),
        })),
        binding: None,
        actual_addresses: Vec::new(),
        auth_state: None,
        owner_template: None,
        pre_socks: None,
        post_socks: None,
        obs_sink: tor_socks5_runtime::arti_observability::ObservationSink::new(),
        upstream_addr: None,
        upstream_user: None,
        upstream_pass: None,
        no_upstream: false,
        pt_binary: tor_socks5_runtime::pt::PtBinary::Environment,
        dns_startup_policy: crate::api::DnsStartupPolicy::Required,
        hooks,
        cfg: Config::default(),
        config_path: dir.to_path_buf(),
        set_stage: &mut set_stage,
        on_ready: &mut on_ready,
        writer_started: &writer_started,
        startup_cancellation: tokio_util::sync::CancellationToken::new(),
        cancelled: false,
        accept_loop_exited: false,
        shutdown: shutdown.as_mut(),
    };
    super::phases::phase_shutdown(
        &mut ctx,
        &owner,
        &Arc::new(crate::server::handlers::HandlerTasks::new()),
    )
    .await
}

/// Regression (TS3-04) driven through the PROD `phase_shutdown`: a producer
/// caught mid-operation when the choreography cancels must finish its writer
/// apply before `close_store_writer` closes the injected writer, and the
/// shutdown phase must fold the whole sequence into one Ok result.
#[tokio::test]
async fn phase_shutdown_delayed_write_lands_before_writer_close() {
    let _serial = owners::TEST_LIFECYCLE.lock().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let bridge = test_bridge_line();
    let config_path = dir.path().join("tor-socks5.ktav");
    let mut store = reload_store(&config_path);
    store.note_source_at(&bridge, "test", OffsetDateTime::now_utc());
    store.save().expect("seed save");

    // The same real writer actor the producers write through, injected via
    // the hook seam so `close_store_writer` closes it inside phase_shutdown.
    let writer = tor_socks5_runtime::bridge_store_writer::StoreWriter::spawn(
        BridgeStore::resolve_path(&config_path),
        Arc::new(|s| s.save()),
        Duration::from_secs(1),
    );
    let hooks = Arc::new(TestRunHooks {
        startup: None,
        shutdown: Some(ShutdownHooks {
            settings: arti_wrapper::Settings::default(),
            writer: Some(writer.clone()),
            failure: None,
            ready: std::sync::Mutex::new(None),
            launch_background: false,
        }),
        force_accept_loop_exit: false,
    });

    // Real retained producer owner + committed producer through LaunchGuard —
    // the exact launch machinery phase_bootstrap uses.
    let owner = ProducerTasks::retain().expect("retain producers");
    let mut launch = LaunchGuard::new(owner.clone());
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let iterations = Arc::new(AtomicUsize::new(0));
    let apply_ok = Arc::new(AtomicBool::new(false));
    let producer = {
        let barrier = barrier.clone();
        let iterations = iterations.clone();
        let apply_ok = apply_ok.clone();
        let bridge = bridge.clone();
        let writer = writer.clone();
        tokio::spawn(async move {
            // In-flight operation, held by the barrier across cancellation.
            barrier.wait().await;
            let result = writer
                .apply(move |s| {
                    s.note_channel_success_at(&bridge, OffsetDateTime::now_utc());
                })
                .await;
            apply_ok.store(result.is_ok(), Ordering::SeqCst);
            iterations.fetch_add(1, Ordering::SeqCst);
        })
    };
    launch.handles = vec![producer, tokio::spawn(async {})];
    launch.commit();

    tor_socks5_runtime::workers::begin_run_group().expect("run group");
    let choreography = {
        let dir = dir.path().to_path_buf();
        let hooks = hooks.clone();
        let owner = owner.clone();
        tokio::spawn(run_phase_shutdown(dir.clone(), Some(hooks), owner))
    };
    // The choreography always cancels first; hold the barrier until it has,
    // so the producer's operation provably spans the cancellation.
    while !owner.token().is_cancelled() {
        tokio::task::yield_now().await;
    }
    barrier.wait().await;

    let result = choreography
        .await
        .expect("phase_shutdown task must not panic");
    assert!(
        result.is_ok(),
        "phase_shutdown must succeed with a delayed write: {result:?}"
    );
    assert!(
        apply_ok.load(Ordering::SeqCst),
        "the delayed write must be accepted by the still-open writer"
    );
    assert_eq!(iterations.load(Ordering::SeqCst), 1);
    // The write landed on disk before the choreography's final close.
    assert_eq!(
        reload_store(&config_path).channel_ok_count(&bridge),
        1,
        "the delayed write must persist through the close"
    );
    // The choreography closed the injected writer: further applies fail.
    assert!(
        writer.apply(|_| {}).await.is_err(),
        "the injected writer must be closed by phase_shutdown"
    );
    tor_socks5_runtime::workers::end_run_group(Duration::from_secs(10))
        .await
        .expect("run group must drain");
}

/// Regression (TS3-04) through the PROD `phase_shutdown`: after cancellation
/// a producer must not run another iteration — the join completes without a
/// further tick even though the ticker is long overdue (paused clock).
#[tokio::test(start_paused = true)]
async fn phase_shutdown_no_new_iteration_after_cancel() {
    let _serial = owners::TEST_LIFECYCLE.lock().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let owner = ProducerTasks::retain().expect("retain producers");
    let iterations = Arc::new(AtomicUsize::new(0));
    let mut launch = LaunchGuard::new(owner.clone());
    let producer = {
        let token = owner.token();
        let iterations = iterations.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(1));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            ticker.tick().await; // consume the immediate first tick
            loop {
                tokio::select! {
                    biased;
                    _ = token.cancelled() => break,
                    _ = ticker.tick() => {
                        iterations.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
        })
    };
    launch.handles = vec![producer];
    launch.commit();
    // Let three real iterations run on the paused clock before shutdown.
    while iterations.load(Ordering::SeqCst) < 3 {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let choreography = {
        let dir = dir.path().to_path_buf();
        let owner = owner.clone();
        tokio::spawn(run_phase_shutdown(dir.clone(), None, owner))
    };
    let result = choreography
        .await
        .expect("phase_shutdown task must not panic");
    assert!(
        result.is_ok(),
        "phase_shutdown must succeed after cancellation: {result:?}"
    );
    let before = iterations.load(Ordering::SeqCst);
    assert!(before >= 3);
    // The producer loop broke at its next cancellation check; no further
    // iteration, even with the ticker long overdue.
    tokio::time::sleep(Duration::from_secs(3600)).await;
    assert_eq!(
        iterations.load(Ordering::SeqCst),
        before,
        "no iteration may start after cancellation"
    );
}

/// Regression (TS3-04) through the PROD `phase_shutdown`: a producer that
/// never finishes hits the bounded 120s join budget; the choreography aborts
/// it and still completes, reporting the timeout (paused clock drives the
/// virtual budgets instantly).
#[tokio::test(start_paused = true)]
async fn phase_shutdown_hung_producer_hits_join_budget() {
    let _serial = owners::TEST_LIFECYCLE.lock().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let owner = ProducerTasks::retain().expect("retain producers");
    let mut launch = LaunchGuard::new(owner.clone());
    launch.handles = vec![tokio::spawn(async {
        std::future::pending::<()>().await;
    })];
    launch.commit();

    let choreography = {
        let dir = dir.path().to_path_buf();
        let owner = owner.clone();
        tokio::spawn(run_phase_shutdown(dir.clone(), None, owner))
    };
    let result = choreography
        .await
        .expect("phase_shutdown task must not panic");
    let error = result.expect_err("a hung producer must surface the join budget");
    assert!(
        format!("{error:#}").contains("producer shutdown timed out"),
        "unexpected error: {error:#}"
    );
    assert!(
        owner.token().is_cancelled(),
        "cancellation must have fired before the join wait"
    );
    assert!(!ProducerTasks::is_retained(), "abort released the registry");
}

/// TS3-04 acceptance: a full `builder(...).test_hooks(...)` run with fake Tor
/// settings (shutdown-style settings + unbootstrapped tunnel) that still
/// launches the REAL background producers, then shuts down through the prod
/// `phase_shutdown` with the registry close and the injected writer close.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_run_launches_producers_and_shuts_down_through_phase_shutdown() {
    let _serial = owners::TEST_LIFECYCLE.lock().await;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("server.ktav");
    let mut cfg = Config {
        listen: vec!["127.0.0.1:0".to_owned()],
        ..Default::default()
    };
    cfg.bridges.use_seeds = false;
    cfg.bridges.auto_fetch = false;
    cfg.bridges.lines = vec!["8.8.8.8:443 1111111111111111111111111111111111111111".into()];
    std::fs::write(&path, ktav::to_string(&cfg).unwrap()).unwrap();
    let config = match crate::config::Config::load_with_override(Some(&path)).unwrap() {
        crate::config::Loaded::FromFile { config, .. } => config,
        crate::config::Loaded::Defaults(config) => config,
    };

    // Injected writer + fake settings; `launch_background: true` lets the
    // prod bootstrap phase launch the real `bridge_producers` tasks.
    let writer = tor_socks5_runtime::bridge_store_writer::StoreWriter::spawn(
        BridgeStore::resolve_path(&path),
        Arc::new(|s| s.save()),
        Duration::from_secs(1),
    );
    let settings = arti_wrapper::Settings {
        bridges: vec!["192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01"
            .parse()
            .unwrap()],
        state_dir: Some(dir.path().join("state")),
        ..Default::default()
    };
    let hooks = Arc::new(TestRunHooks {
        startup: None,
        shutdown: Some(ShutdownHooks {
            settings,
            writer: Some(writer.clone()),
            failure: None,
            ready: std::sync::Mutex::new(None),
            launch_background: true,
        }),
        force_accept_loop_exit: false,
    });

    let builder = crate::Server::builder(config)
        .config_path(path)
        .test_hooks(hooks);
    let handle = tokio::time::timeout(Duration::from_secs(60), builder.start())
        .await
        .expect("startup must finish")
        .expect("fake-Tor startup must succeed");
    assert!(matches!(
        handle.status(),
        crate::ServerStatus::Running { .. }
    ));
    assert!(
        ProducerTasks::is_retained(),
        "the real producers must be launched and retained"
    );

    tokio::time::timeout(Duration::from_secs(60), handle.shutdown())
        .await
        .expect("shutdown must complete through phase_shutdown")
        .expect("shutdown must succeed");

    // Producers released, run writer slot untouched (the injected writer was
    // closed by the choreography), and the closed writer rejects new applies.
    assert!(
        !ProducerTasks::is_retained(),
        "the producer registry must be released by the shutdown"
    );
    assert!(tor_socks5_runtime::bridge_store_writer::run_is_idle());
    assert!(
        writer.apply(|_| {}).await.is_err(),
        "the injected writer must be closed by the shutdown choreography"
    );
}
