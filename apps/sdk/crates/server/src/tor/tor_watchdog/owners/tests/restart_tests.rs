// D5: один живой экземпляр на процесс, последовательный перезапуск работает.
// Сеть Tor подменена хуком `RUN_SERVER_SHUTDOWN` (туннель не загружается), всё
// остальное — SDK `Server::builder`: привязка портов, процессные слоты, остановка.

use super::*;
use std::future::Future;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn wait_for_status(
    status: &mut tokio::sync::watch::Receiver<ServerStatus>,
    predicate: impl Fn(&ServerStatus) -> bool,
) -> ServerStatus {
    loop {
        let current = status.borrow_and_update().clone();
        if predicate(&current) {
            return current;
        }
        status
            .changed()
            .await
            .expect("server status channel closed");
    }
}

async fn start_immediately_after_release(
    config: crate::config::Config,
    config_path: Option<std::path::PathBuf>,
    settings: Settings,
    upstream: bool,
) -> crate::ServerHandle {
    start_server(config, config_path, settings, upstream)
        .await
        .unwrap_or_else(|error| panic!("immediate restart after Stopped failed: {error}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdk11_server_dns_bind_failure_is_required_and_releases_slots() {
    let _serial = TEST_LIFECYCLE.lock().await;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let (config_path, mut config) = test_config(dir.path(), 0);
    let occupied = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = occupied.local_addr().unwrap();
    config.dns_server.enabled = true;
    config.dns_server.listen = vec![address.to_string()];
    assert_slots_free().await;

    let error = match start_server(
        config.clone(),
        config_path.clone(),
        test_settings(dir.path()),
        false,
    )
    .await
    {
        Err(error) => error,
        Ok(handle) => {
            handle.shutdown().await.unwrap();
            panic!("required DNS bind failure must fail startup");
        }
    };
    assert!(matches!(&error, ServerError::Bind(_)));
    assert_eq!(error.stage(), Some(crate::ServerStage::Bind));
    assert!(error.to_string().contains("DNS listener"));
    assert_slots_free().await;

    let background = global_init::RUN_SERVER_SHUTDOWN
        .scope(
            shutdown_hook(test_settings(dir.path()), None),
            builder(config.clone(), config_path.clone(), false)
                .dns_startup_policy(crate::DnsStartupPolicy::Background)
                .start(),
        )
        .await
        .expect("background DNS bind failure must remain non-fatal");
    assert!(matches!(background.status(), ServerStatus::Running { .. }));
    background.shutdown().await.unwrap();
    assert_slots_free().await;
    drop(occupied);

    let retry = start_server(
        crate::config::Config {
            dns_server: Default::default(),
            ..config
        },
        config_path,
        test_settings(dir.path()),
        true,
    )
    .await
    .expect("failed DNS startup must release admission");
    retry.shutdown().await.unwrap();
    assert_slots_free().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdk11_server_required_dns_readiness_reports_udp_tcp_addresses() {
    let _serial = TEST_LIFECYCLE.lock().await;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let (config_path, mut config) = test_config(dir.path(), 0);
    config.dns_server.enabled = true;
    config.dns_server.listen = vec!["127.0.0.1:0".into()];

    let handle = start_server(config, config_path, test_settings(dir.path()), false)
        .await
        .expect("successful DNS bind must satisfy default required policy");
    let ServerStatus::Running { listen_addrs } = handle.status() else {
        panic!("server did not publish Running");
    };
    assert_eq!(listen_addrs.len(), 3, "SOCKS TCP plus DNS UDP/TCP");
    assert_ne!(listen_addrs[0].port(), 0);
    assert_ne!(listen_addrs[1].port(), 0);
    assert_ne!(listen_addrs[2].port(), 0);
    assert_eq!(listen_addrs[1], listen_addrs[2]);
    assert_eq!(listen_addrs[1].ip(), std::net::Ipv4Addr::LOCALHOST);
    handle.shutdown().await.unwrap();
    assert_slots_free().await;
}

/// One full run through the SDK API: ready, in-cycle slot ownership, and a
/// bounded stop. A parked registry worker spawned via the free wrappers during
/// the run is foreign to the run's worker group, so neither start nor shutdown
/// waits for it; the run's own group workers are still joined by the producer
/// choreography, and the process registry is drained explicitly at the end.
async fn run_once(dir: &std::path::Path, port: u16, upstream: bool) -> (Slots, anyhow::Result<()>) {
    let (config_path, config) = test_config(dir, port);
    let settings = test_settings(dir);
    let handle = match start_server(config, config_path, settings, upstream).await {
        Ok(handle) => handle,
        Err(error) => return (slots().await, Err(error.into_anyhow())),
    };
    let running = slots().await;
    assert_running_at(&handle, Some(port));
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let worker = tokio::spawn(workers::run_fallible_blocking(move || {
        let _ = release_rx.recv();
        Ok(())
    }));
    while workers::global_busy_count().await == 0 {
        tokio::task::yield_now().await;
    }

    let status = handle.subscribe();
    // The parked worker lives in the process registry, not the run group:
    // shutdown must complete without releasing it first.
    let result = tokio::time::timeout(Duration::from_secs(30), handle.shutdown())
        .await
        .expect("shutdown must not wait for a foreign parked worker")
        .map_err(ServerError::into_anyhow);
    assert!(matches!(
        status.borrow().clone(),
        ServerStatus::Stopped { .. }
    ));
    release_tx.send(()).unwrap();
    worker.await.unwrap().unwrap().unwrap();
    workers::join_blocking_workers()
        .await
        .expect("process registry must drain after releasing the worker");
    (running, result)
}

async fn restart_twice(upstream: bool) {
    let _serial = TEST_LIFECYCLE.lock().await;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let port = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let quarantine = quarantine_held();
    assert_eq!(slots().await, free(quarantine), "слоты заняты до запуска");
    // Слот писателя и реестр владельцев занимает только Tor-ветка.
    let expected_running = Slots {
        producers: true,
        handlers: true,
        registry: !upstream,
        writer: !upstream,
        ..free(quarantine)
    };
    tokio::time::timeout(Duration::from_secs(120), async {
        for run in 1..=2 {
            let (running, result) = run_once(dir.path(), port, upstream).await;
            result.unwrap_or_else(|error| panic!("запуск {run} завершился ошибкой: {error:#}"));
            assert_eq!(running, expected_running, "запуск {run}: слоты в цикле");
            assert_eq!(
                slots().await,
                free(quarantine),
                "слоты остались занятыми после остановки запуска {run}"
            );
        }
    })
    .await
    .expect("тайм-аут перезапуска сервера");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdk11_server_restart_in_one_process_frees_and_retakes_tor_slots() {
    restart_twice(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdk11_server_restart_in_one_process_frees_and_retakes_upstream_slots() {
    restart_twice(true).await;
}

async fn start_server_with_failure(
    config: crate::config::Config,
    config_path: Option<std::path::PathBuf>,
    settings: Settings,
    failure: global_init::BootstrapFailure,
) -> std::result::Result<crate::ServerHandle, ServerError> {
    global_init::RUN_SERVER_SHUTDOWN
        .scope(
            shutdown_hook(settings, Some(failure)),
            builder(config, config_path, false).start(),
        )
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdk11_server_bootstrap_error_cleans_writer_and_releases_admission() {
    let _serial = TEST_LIFECYCLE.lock().await;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let (config_path, config) = test_config(dir.path(), 0);
    let settings = test_settings(dir.path());
    assert_slots_free().await;

    let error = match start_server_with_failure(
        config.clone(),
        config_path.clone(),
        settings.clone(),
        global_init::BootstrapFailure::Error,
    )
    .await
    {
        Err(error) => error,
        Ok(handle) => {
            handle.shutdown().await.unwrap();
            panic!("synthetic bootstrap error unexpectedly started server");
        }
    };
    assert!(matches!(&error, ServerError::Startup(_)));
    let cli_error = error.into_anyhow();
    assert_eq!(cli_error.to_string(), "failed to bootstrap Tor");
    assert!(format!("{cli_error:#}").contains("sdk11 synthetic bootstrap failure"));
    assert_eq!(slots().await, free(quarantine_held()));

    let retry = start_server(config, config_path, settings, true)
        .await
        .expect("bootstrap failure must release admission and writer");
    retry.shutdown().await.unwrap();
    assert_slots_free().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdk11_server_bootstrap_panic_cleans_writer_and_releases_admission() {
    let _serial = TEST_LIFECYCLE.lock().await;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let (config_path, config) = test_config(dir.path(), 0);
    let settings = test_settings(dir.path());
    assert_slots_free().await;

    let error = match start_server_with_failure(
        config.clone(),
        config_path.clone(),
        settings.clone(),
        global_init::BootstrapFailure::Panic,
    )
    .await
    {
        Err(error) => error,
        Ok(handle) => {
            handle.shutdown().await.unwrap();
            panic!("synthetic bootstrap panic unexpectedly started server");
        }
    };
    assert!(matches!(&error, ServerError::Startup(_)));
    assert!(error.to_string().contains("failed to bootstrap Tor"));
    assert_eq!(slots().await, free(quarantine_held()));

    let retry = start_server(config, config_path, settings, true)
        .await
        .expect("bootstrap panic must release admission and writer");
    retry.shutdown().await.unwrap();
    assert_slots_free().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdk11_server_ready_address_completes_socks5_greeting() {
    let _serial = TEST_LIFECYCLE.lock().await;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let (config_path, config) = test_config(dir.path(), 0);
    let settings = test_settings(dir.path());
    let handle = start_server(config, config_path, settings, true)
        .await
        .unwrap();
    let ServerStatus::Running { listen_addrs } = handle.status() else {
        panic!("server did not publish Running");
    };
    let mut client = tokio::net::TcpStream::connect(listen_addrs[0])
        .await
        .unwrap();
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut reply = [0; 2];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut reply))
        .await
        .expect("listener did not accept SOCKS5 greeting")
        .unwrap();
    assert_eq!(reply, [5, 0]);
    drop(client);
    handle.shutdown().await.unwrap();
    assert_slots_free().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdk11_server_rejects_concurrent_start_as_already_running() {
    let _serial = TEST_LIFECYCLE.lock().await;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let (config_path, config) = test_config(dir.path(), 0);
    let settings = test_settings(dir.path());
    let first = start_server(config.clone(), config_path.clone(), settings.clone(), true)
        .await
        .unwrap();
    let first_slots = slots().await;
    assert_running_at(&first, None);

    let rejected_builder = builder(config.clone(), config_path.clone(), true);
    let rejected_status = rejected_builder.subscribe();
    let error = match rejected_builder.start().await {
        Err(error) => error,
        Ok(handle) => {
            handle.shutdown().await.unwrap();
            panic!("second start must be rejected while first server is active");
        }
    };
    assert!(matches!(&error, ServerError::AlreadyRunning));
    assert!(matches!(
        rejected_status.borrow().clone(),
        ServerStatus::Stopped { .. }
    ));
    assert_eq!(error.stage(), None);
    assert_eq!(
        slots().await,
        first_slots,
        "rejected start must not change slots"
    );
    assert_running_at(&first, None);
    first.shutdown().await.unwrap();
    assert_slots_free().await;

    let retry = start_immediately_after_release(config, config_path, settings, true).await;
    assert_running_at(&retry, None);
    retry.shutdown().await.unwrap();
    assert_slots_free().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdk11_server_wait_pending_does_not_cancel_token() {
    let _serial = TEST_LIFECYCLE.lock().await;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let (config_path, config) = test_config(dir.path(), 0);
    let settings = test_settings(dir.path());
    let parent = tokio_util::sync::CancellationToken::new();
    let cancellation = parent.clone();
    let handle_future = builder(config.clone(), config_path.clone(), true)
        .cancellation_token(parent.clone())
        .start();
    let handle = global_init::RUN_SERVER_SHUTDOWN
        .scope(shutdown_hook(settings, None), handle_future)
        .await
        .unwrap();
    let mut wait = Box::pin(handle.wait());
    assert!(
        std::future::poll_fn(|cx| { std::task::Poll::Ready(wait.as_mut().poll(cx).is_pending()) })
            .await
    );
    assert!(
        !parent.is_cancelled(),
        "pending wait must not cancel caller's token"
    );
    cancellation.cancel();
    wait.await.unwrap();
    assert!(parent.is_cancelled());
    assert_slots_free().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdk11_server_precancelled_start_returns_cancelled_and_allows_retry() {
    let _serial = TEST_LIFECYCLE.lock().await;
    let _ = rustls::crypto::ring::default_provider().install_default();
    tokio::time::timeout(Duration::from_secs(120), async {
        let dir = tempfile::tempdir().unwrap();
        let (config_path, config) = test_config(dir.path(), 0);
        let settings = test_settings(dir.path());
        let pre_cancelled = tokio_util::sync::CancellationToken::new();
        pre_cancelled.cancel();
        let pre_cancelled_result = global_init::RUN_SERVER_SHUTDOWN
            .scope(
                shutdown_hook(settings.clone(), None),
                builder(config.clone(), config_path.clone(), true)
                    .cancellation_token(pre_cancelled.clone())
                    .start(),
            )
            .await;
        assert!(matches!(pre_cancelled_result, Err(ServerError::Cancelled)));
        assert!(pre_cancelled.is_cancelled());

        let token = tokio_util::sync::CancellationToken::new();
        let start_builder =
            builder(config.clone(), config_path.clone(), true).cancellation_token(token.clone());
        let mut status = start_builder.subscribe();
        let mut start = Box::pin(
            global_init::RUN_SERVER_SHUTDOWN
                .scope(shutdown_hook(settings.clone(), None), start_builder.start()),
        );
        assert!(
            std::future::poll_fn(|cx| {
                std::task::Poll::Ready(start.as_mut().poll(cx).is_pending())
            })
            .await
        );
        drop(start);
        assert!(
            !token.is_cancelled(),
            "dropping start must cancel only its child token, not its parent"
        );
        let stopped = wait_for_status(&mut status, |status| {
            matches!(status, ServerStatus::Stopped { .. })
        })
        .await;
        assert!(matches!(stopped, ServerStatus::Stopped { .. }));

        let parent = tokio_util::sync::CancellationToken::new();
        let run_parent = parent.clone();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let run_builder = builder(config.clone(), config_path.clone(), true)
            .cancellation_token(run_parent.clone());
        let mut run_status = run_builder.subscribe();
        let run_settings = settings.clone();
        let run_shutdown = global_init::RUN_SERVER_SHUTDOWN.scope(
            shutdown_hook(run_settings, None),
            run_builder.run_until(async {
                let _ = shutdown_rx.await;
            }),
        );
        let run = tokio::spawn(run_shutdown);
        assert!(matches!(
            wait_for_status(&mut run_status, |status| matches!(
                status,
                ServerStatus::Running { .. }
            ))
            .await,
            ServerStatus::Running { .. }
        ));
        shutdown_tx.send(()).unwrap();
        assert!(matches!(run.await.unwrap(), Ok(())));
        assert!(
            !run_parent.is_cancelled(),
            "run_until shutdown must not cancel the caller's parent token"
        );

        let retry = start_immediately_after_release(
            config.clone(),
            config_path.clone(),
            settings.clone(),
            true,
        )
        .await;
        retry.shutdown().await.unwrap();
        assert_slots_free().await;

        // Natural terminal publication through the caller token beats a still-pending
        // shutdown future; run_until joins and returns the server result.
        let external = tokio_util::sync::CancellationToken::new();
        let run_builder =
            builder(config.clone(), config_path.clone(), true).cancellation_token(external.clone());
        let mut natural_status = run_builder.subscribe();
        let (never_tx, never_rx) = tokio::sync::oneshot::channel::<()>();
        let natural = tokio::spawn(global_init::RUN_SERVER_SHUTDOWN.scope(
            shutdown_hook(test_settings(dir.path()), None),
            run_builder.run_until(async {
                let _ = never_rx.await;
            }),
        ));
        assert!(matches!(
            wait_for_status(&mut natural_status, |status| matches!(
                status,
                ServerStatus::Running { .. }
            ))
            .await,
            ServerStatus::Running { .. }
        ));
        external.cancel();
        let natural_result = natural.await.unwrap();
        assert!(
            matches!(natural_result, Ok(())),
            "natural terminal wait should return the worker result: {natural_result:?}"
        );
        assert!(external.is_cancelled());
        drop(never_tx);
        assert_slots_free().await;

        // An already-resolved shutdown future during startup is treated as a
        // clean requested cancellation, while the caller's parent token remains live.
        let parent = tokio_util::sync::CancellationToken::new();
        let immediate = builder(config, config_path, true).cancellation_token(parent.clone());
        let result = global_init::RUN_SERVER_SHUTDOWN
            .scope(
                shutdown_hook(test_settings(dir.path()), None),
                immediate.run_until(std::future::ready(())),
            )
            .await;
        assert!(
            matches!(result, Ok(())),
            "requested cancellation alone should map to Ok"
        );
        assert!(!parent.is_cancelled());
        assert_slots_free().await;
    })
    .await
    .expect("pre-cancelled start test timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdk11_server_bind_failure_releases_admission_for_retry() {
    let _serial = TEST_LIFECYCLE.lock().await;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = occupied.local_addr().unwrap().port();
    let (config_path, config) = test_config(dir.path(), port);
    let settings = test_settings(dir.path());

    let error =
        match start_server(config.clone(), config_path.clone(), settings.clone(), true).await {
            Ok(handle) => {
                handle.shutdown().await.unwrap();
                panic!("occupied port unexpectedly started the server");
            }
            Err(error) => error,
        };
    assert!(matches!(&error, ServerError::Bind(_)));
    assert_eq!(error.stage(), Some(crate::ServerStage::Bind));
    drop(occupied);

    let handle = start_immediately_after_release(config, config_path, settings, true).await;
    assert_running_at(&handle, Some(port));
    handle.shutdown().await.unwrap();
    assert_slots_free().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdk11_server_handle_drop_cancels_and_allows_retry_after_stopped() {
    let _serial = TEST_LIFECYCLE.lock().await;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let (config_path, config) = test_config(dir.path(), 0);
    let settings = test_settings(dir.path());
    let parent = tokio_util::sync::CancellationToken::new();
    let handle = global_init::RUN_SERVER_SHUTDOWN
        .scope(
            shutdown_hook(settings.clone(), None),
            builder(config.clone(), config_path.clone(), true)
                .cancellation_token(parent.clone())
                .start(),
        )
        .await
        .unwrap();
    let child_token = handle.token();
    let mut status = handle.subscribe();
    assert!(matches!(handle.status(), ServerStatus::Running { .. }));

    drop(handle);
    assert!(
        child_token.is_cancelled(),
        "Drop must cancel the server child token"
    );
    assert!(
        !parent.is_cancelled(),
        "Drop must not cancel the caller's parent token"
    );
    let stopped = wait_for_status(&mut status, |status| {
        matches!(status, ServerStatus::Stopped { .. })
    })
    .await;
    assert!(matches!(stopped, ServerStatus::Stopped { .. }));

    // Admission is released before Stopped; this single attempt is red before H7.2.
    let retry = start_immediately_after_release(
        config.clone(),
        config_path.clone(),
        settings.clone(),
        true,
    )
    .await;
    assert_running_at(&retry, None);
    retry.shutdown().await.unwrap();
    assert_slots_free().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdk11_server_watch_reports_starting_running_stopping_and_stopped() {
    let _serial = TEST_LIFECYCLE.lock().await;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let (config_path, config) = test_config(dir.path(), 0);
    let path = dir.path().join("writer-gate.ktav");
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let entered = std::sync::Mutex::new(Some(entered_tx));
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let release = std::sync::Mutex::new(Some(release_rx));
    let writer = bridge_store_writer::StoreWriter::spawn(
        bridge_store::BridgeStore::resolve_path(Some(&path)),
        Arc::new(move |store| {
            if let Some(entered) = entered.lock().unwrap().take() {
                let _ = entered.send(());
                release.lock().unwrap().take().unwrap().recv().unwrap();
            }
            store.save()
        }),
        Duration::from_secs(3600),
    );
    let builder = Server::builder(config)
        .config_path(config_path)
        .upstream(None, None, None);
    let mut status = builder.subscribe();
    assert_eq!(status.borrow().clone(), ServerStatus::Starting);
    let hook = Arc::new(global_init::ShutdownHook {
        settings: test_settings(dir.path()),
        writer: Some(writer.clone()),
        failure: None,
        ready: std::sync::Mutex::new(None),
    });
    let handle = match tokio::time::timeout(
        Duration::from_secs(10),
        global_init::RUN_SERVER_SHUTDOWN.scope(hook, builder.start()),
    )
    .await
    {
        Ok(result) => result.unwrap(),
        Err(_) => {
            let _ = release_tx.send(());
            panic!("startup must not close the run-scoped writer before returning a handle");
        }
    };
    let running = match status.borrow().clone() {
        ServerStatus::Running { listen_addrs } => {
            assert_eq!(listen_addrs.len(), 1);
            assert_ne!(listen_addrs[0].port(), 0);
            listen_addrs
        }
        status => panic!("expected Running, got {status:?}"),
    };

    tokio::time::timeout(Duration::from_secs(10), writer.apply(|_| {}))
        .await
        .expect("writer apply timed out")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), entered_rx)
        .await
        .expect("writer publish did not enter")
        .unwrap();

    let mut shutdown = Box::pin(handle.shutdown());
    assert!(
        std::future::poll_fn(|cx| {
            std::task::Poll::Ready(shutdown.as_mut().poll(cx).is_pending())
        })
        .await
    );
    let stopping = wait_for_status(&mut status, |status| {
        matches!(status, ServerStatus::Stopping { .. })
    })
    .await;
    assert!(matches!(
        stopping,
        ServerStatus::Stopping { listen_addrs } if listen_addrs == running
    ));
    assert!(
        std::future::poll_fn(|cx| {
            std::task::Poll::Ready(shutdown.as_mut().poll(cx).is_pending())
        })
        .await,
        "blocked writer must keep shutdown pending at Stopping"
    );
    // The hung flush lives in the injected hook writer; `close_store_writer`'s
    // hook branch closes it directly with the deadline (the run slot is never
    // occupied here). The close signal bypasses the mutation queue, so shutdown
    // usually completes clean despite the hung flush; if it does wait, it must
    // give up at the deadline and report the retained writer. Either way the
    // hung flush may not hold shutdown longer than the bounded budget.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let outcome = tokio::time::timeout_at(deadline, shutdown)
        .await
        .expect("hung flush held shutdown longer than the bounded cleanup budget");
    if let Err(error) = outcome {
        let chain = format!("{:#}", error.into_anyhow());
        assert!(
            chain.contains("did not finish within the deadline"),
            "unexpected shutdown error: {chain}"
        );
    }
    release_tx.send(()).unwrap();
    // The released publish leaves a finished job in the process registry;
    // drain it the way the app would so later runs see a clear registry.
    tokio::time::timeout(Duration::from_secs(10), async {
        while workers::global_busy_count().await > 0 {
            let _ =
                tokio::time::timeout(Duration::from_millis(500), workers::join_blocking_workers())
                    .await;
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("process registry did not drain after releasing the publisher");
    let stopped = wait_for_status(&mut status, |status| {
        matches!(status, ServerStatus::Stopped { .. })
    })
    .await;
    assert!(matches!(
        stopped,
        ServerStatus::Stopped { listen_addrs } if listen_addrs == running
    ));
    // The injected writer never occupied the run slot, so once the workers
    // drain all slots are free again.
    assert_slots_free().await;
}
