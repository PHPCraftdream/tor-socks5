// D5: один живой экземпляр на процесс, последовательный перезапуск работает.
// Сеть Tor подменена хуком `RUN_SERVER_SHUTDOWN` (туннель не загружается), всё
// остальное — SDK `Server::builder`: привязка портов, процессные слоты, остановка.

use super::storage::quarantine_held;
use super::*;
use crate::server::handlers::HandlerTasks;
use crate::server::{global_init, producers};
use crate::{Server, ServerError, ServerStatus};
use std::future::Future;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tor_socks5_runtime::{bridge_store_writer, workers};

#[derive(Debug, PartialEq)]
struct Slots {
    settings: bool,
    global_init: bool,
    producers: bool,
    handlers: bool,
    registry: bool,
    writer: bool,
    workers_busy: usize,
    quarantine: usize,
}

async fn slots() -> Slots {
    Slots {
        settings: global_init::startup_snapshot(false).0,
        global_init: global_init::startup_snapshot(true).0,
        producers: producers::ProducerTasks::is_retained(),
        handlers: HandlerTasks::retained().is_some(),
        registry: OwnerRegistry::is_retained(),
        writer: !bridge_store_writer::global_is_idle(),
        workers_busy: workers::global_busy_count().await,
        quarantine: quarantine_held(),
    }
}

fn free(quarantine: usize) -> Slots {
    Slots {
        settings: false,
        global_init: false,
        producers: false,
        handlers: false,
        registry: false,
        writer: false,
        workers_busy: 0,
        quarantine,
    }
}

fn test_config(
    dir: &std::path::Path,
    port: u16,
) -> (Option<std::path::PathBuf>, crate::config::Config) {
    let config = crate::config::Config {
        listen: vec![format!("127.0.0.1:{port}")],
        ..Default::default()
    };
    let path = dir.join("server.ktav");
    std::fs::write(&path, ktav::to_string(&config).unwrap()).unwrap();
    match crate::config::Config::load_with_override(Some(&path)).unwrap() {
        crate::config::Loaded::FromFile { path, config } => (Some(path), config),
        crate::config::Loaded::Defaults(config) => (None, config),
    }
}

fn test_settings(dir: &std::path::Path) -> Settings {
    Settings {
        bridges: vec!["192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01"
            .parse()
            .unwrap()],
        state_dir: Some(dir.join("state")),
        ..Default::default()
    }
}

fn shutdown_hook(
    settings: Settings,
    failure: Option<global_init::BootstrapFailure>,
) -> Arc<global_init::ShutdownHook> {
    Arc::new(global_init::ShutdownHook {
        settings,
        writer: None,
        failure,
        ready: std::sync::Mutex::new(None),
    })
}

fn builder(
    config: crate::config::Config,
    config_path: Option<std::path::PathBuf>,
    upstream: bool,
) -> crate::ServerBuilder {
    Server::builder(config).config_path(config_path).upstream(
        upstream.then(|| "127.0.0.1:1".to_string()),
        None,
        None,
    )
}

async fn start_server(
    config: crate::config::Config,
    config_path: Option<std::path::PathBuf>,
    settings: Settings,
    upstream: bool,
) -> std::result::Result<crate::ServerHandle, ServerError> {
    global_init::RUN_SERVER_SHUTDOWN
        .scope(
            shutdown_hook(settings, None),
            builder(config, config_path, upstream).start(),
        )
        .await
}

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

async fn start_after_release(
    config: crate::config::Config,
    config_path: Option<std::path::PathBuf>,
    settings: Settings,
    upstream: bool,
) -> crate::ServerHandle {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match start_server(
                config.clone(),
                config_path.clone(),
                settings.clone(),
                upstream,
            )
            .await
            {
                Ok(handle) => return handle,
                Err(ServerError::AlreadyRunning) => tokio::task::yield_now().await,
                Err(error) => panic!("повторный запуск завершился ошибкой: {error}"),
            }
        }
    })
    .await
    .expect("admission was not released after terminal status")
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

/// One full run through the SDK API: ready, in-cycle slot ownership, and
/// ожидание реального блокирующего работника при graceful shutdown.
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

    let mut status = handle.subscribe();
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
    assert!(matches!(stopping, ServerStatus::Stopping { .. }));
    assert!(
        std::future::poll_fn(|cx| {
            std::task::Poll::Ready(shutdown.as_mut().poll(cx).is_pending())
        })
        .await,
        "shutdown must join the registered blocking worker"
    );
    release_tx.send(()).unwrap();
    worker.await.unwrap().unwrap().unwrap();
    let result = shutdown.await.map_err(ServerError::into_anyhow);
    assert!(matches!(
        status.borrow().clone(),
        ServerStatus::Stopped { .. }
    ));
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

fn assert_running_at(handle: &crate::ServerHandle, port: Option<u16>) {
    match handle.status() {
        ServerStatus::Running { listen_addrs } => {
            assert!(!listen_addrs.is_empty());
            assert_eq!(listen_addrs[0].ip(), std::net::Ipv4Addr::LOCALHOST);
            if let Some(port) = port {
                assert_eq!(listen_addrs[0].port(), port);
            } else {
                assert_ne!(
                    listen_addrs[0].port(),
                    0,
                    "port zero must report its bound port"
                );
            }
        }
        status => panic!("expected Running with actual bound address, got {status:?}"),
    }
}

async fn assert_slots_free() {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let current = slots().await;
            if current == free(current.quarantine) {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("server resources remained retained after shutdown");
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

    let second = start_server(config.clone(), config_path.clone(), settings.clone(), true).await;
    let Err(error) = second else {
        panic!("second start must be rejected while the first server is alive");
    };
    assert!(matches!(&error, ServerError::AlreadyRunning));
    assert_eq!(error.stage(), None);
    assert_eq!(
        slots().await,
        first_slots,
        "rejected start must not change slots"
    );
    assert_running_at(&first, None);
    first.shutdown().await.unwrap();
    assert_slots_free().await;

    let retry = start_after_release(config, config_path, settings, true).await;
    assert_running_at(&retry, None);
    retry.shutdown().await.unwrap();
    assert_slots_free().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdk11_server_wait_pending_does_not_cancel_token() {
    let _serial = TEST_LIFECYCLE.lock().await;
    let _ = rustls::crypto::ring::default_provider().install_default();
    tokio::time::timeout(Duration::from_secs(120), async {
        let dir = tempfile::tempdir().unwrap();
        let (config_path, config) = test_config(dir.path(), 0);
        let settings = test_settings(dir.path());
        let handle = start_server(config, config_path, settings, true)
            .await
            .unwrap();
        let token = handle.token();
        let mut wait = Box::pin(handle.wait());
        assert!(
            std::future::poll_fn(|cx| {
                std::task::Poll::Ready(wait.as_mut().poll(cx).is_pending())
            })
            .await
        );
        assert!(
            !token.is_cancelled(),
            "pending wait must not cancel the server"
        );
        token.cancel();
        wait.await.unwrap();
        assert!(token.is_cancelled());
        assert_slots_free().await;
    })
    .await
    .expect("wait lifecycle test timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdk11_server_precancelled_start_returns_cancelled_and_allows_retry() {
    let _serial = TEST_LIFECYCLE.lock().await;
    let _ = rustls::crypto::ring::default_provider().install_default();
    tokio::time::timeout(Duration::from_secs(120), async {
        let dir = tempfile::tempdir().unwrap();
        let (config_path, config) = test_config(dir.path(), 0);
        let settings = test_settings(dir.path());
        let token = tokio_util::sync::CancellationToken::new();
        token.cancel();

        let result = builder(config.clone(), config_path.clone(), true)
            .cancellation_token(token)
            .start()
            .await;
        assert!(matches!(result, Err(ServerError::Cancelled)));

        let retry = start_after_release(config, config_path, settings, true).await;
        assert_running_at(&retry, None);
        retry.shutdown().await.unwrap();
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

    let handle = start_after_release(config, config_path, settings, true).await;
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
    let handle = start_server(config.clone(), config_path.clone(), settings.clone(), true)
        .await
        .unwrap();
    let token = handle.token();
    let mut status = handle.subscribe();
    assert!(matches!(handle.status(), ServerStatus::Running { .. }));

    drop(handle);
    assert!(token.is_cancelled(), "Drop must cancel synchronously");
    let stopped = wait_for_status(&mut status, |status| {
        matches!(status, ServerStatus::Stopped { .. })
    })
    .await;
    assert!(matches!(stopped, ServerStatus::Stopped { .. }));
    assert_slots_free().await;

    let retry = start_after_release(config, config_path, settings, true).await;
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
    release_tx.send(()).unwrap();
    shutdown.await.unwrap();
    let stopped = wait_for_status(&mut status, |status| {
        matches!(status, ServerStatus::Stopped { .. })
    })
    .await;
    assert!(matches!(
        stopped,
        ServerStatus::Stopped { listen_addrs } if listen_addrs == running
    ));
    assert_slots_free().await;
}
