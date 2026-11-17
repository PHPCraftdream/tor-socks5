use super::*;

use std::future::Future;

fn endpoint(password: &str) -> Socks5PreEndpoint {
    Socks5PreEndpoint::new(
        "127.0.0.1:1080".parse().unwrap(),
        Some(("alice".into(), password.into())),
    )
}

fn registry(dir: &std::path::Path) -> OwnerRegistry {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let settings = Settings {
        pre_endpoint: Some(endpoint("global")),
        bridges: vec!["192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01"
            .parse()
            .unwrap()],
        state_dir: Some(dir.join("global")),
        ..Default::default()
    };
    let tor = TorTunnel::create_unbootstrapped_with(settings.clone()).unwrap();
    OwnerRegistry::new(TorHandle::new(tor), settings).unwrap()
}

#[tokio::test]
async fn the_main_clients_own_endpoint_selects_the_main_client() {
    let dir = tempfile::tempdir().unwrap();
    let registry = registry(dir.path());
    let owner = registry
        .select_endpoint(Some(endpoint("global")))
        .await
        .unwrap();
    assert!(owner.global_handle().is_some());
    assert!(registry.state.lock().await.entries.is_empty());
}

async fn failed_entry_with_tunnel(
    registry: &OwnerRegistry,
    dir: &std::path::Path,
    name: &str,
) -> Arc<Entry> {
    let entry = registry
        .reserve(Some(endpoint(name)))
        .await
        .unwrap()
        .unwrap();
    let mut settings = registry.settings.as_ref().unwrap().clone();
    settings.state_dir = Some(dir.join(name));
    let tunnel = TorTunnel::create_unbootstrapped_with(settings).unwrap();
    {
        let mut state = entry.state.lock().await;
        state.attempted = true;
        state.failed = true;
        state.slot = Some(1);
        state.tunnel = Some(tunnel);
    }
    entry
}

#[tokio::test]
async fn readiness_follows_the_state_of_the_owner() {
    let dir = tempfile::tempdir().unwrap();
    let registry = registry(dir.path());
    assert!(registry.is_ready(&Some(endpoint("global"))).await);
    assert!(!registry.is_ready(&Some(endpoint("unknown"))).await);
    let entry = failed_entry_with_tunnel(&registry, dir.path(), "owner").await;
    let pre = Some(endpoint("owner"));
    assert!(
        !registry.is_ready(&pre).await,
        "a failed owner is not ready"
    );
    entry.state.lock().await.failed = false;
    entry
        .ready
        .store(true, std::sync::atomic::Ordering::Release);
    assert!(registry.is_ready(&pre).await);
    let busy = entry.state.lock().await;
    assert!(
        registry.is_ready(&pre).await,
        "readiness is answered even while the state lock is held"
    );
    drop(busy);
}

/// `is_ready` must not depend on the entry state lock: it answers via the
/// atomic readiness flag even while a selection holds the entry locked.
#[tokio::test]
async fn is_ready_answers_while_an_entry_state_lock_is_held() {
    let dir = tempfile::tempdir().unwrap();
    let registry = Arc::new(registry(dir.path()));
    let pre = endpoint("adopted");
    let mut settings = registry.settings.as_ref().unwrap().clone();
    settings.state_dir = Some(dir.path().join("adopted"));
    let tunnel = TorTunnel::create_unbootstrapped_with(settings).unwrap();
    registry.adopt_started(pre.clone(), tunnel, false).await;
    assert!(registry.is_ready(&Some(pre.clone())).await);
    let entry = registry
        .state
        .lock()
        .await
        .entries
        .iter()
        .find(|entry| entry.pre == Some(pre.clone()))
        .cloned()
        .unwrap();
    let guard = entry.state.lock().await;
    assert!(
        registry.is_ready(&Some(pre)).await,
        "readiness must not depend on the entry state lock"
    );
    drop(guard);
    registry.close().await.unwrap();
}

#[tokio::test]
async fn sdk11_server_revive_tasks_are_retained_deduplicated_and_joined() {
    let dir = tempfile::tempdir().unwrap();
    let mut registry = registry(dir.path());
    registry.revive_hook = Some(Arc::new(|| Box::pin(std::future::pending())));
    let entry = failed_entry_with_tunnel(&registry, dir.path(), "sdk11-revive").await;
    let registry = Arc::new(registry);

    registry.revive(endpoint("sdk11-revive")).await;
    assert_eq!(registry.state.lock().await.revivals.len(), 1);
    registry.revive(endpoint("sdk11-revive")).await;
    assert_eq!(
        registry.state.lock().await.revivals.len(),
        1,
        "only one retry is retained for an endpoint"
    );

    registry
        .close_with_deadline(Instant::now() + Duration::from_secs(30))
        .await
        .unwrap();
    assert!(registry.state.lock().await.revivals.is_empty());
    assert!(entry.state.lock().await.tunnel.is_none());
}

#[tokio::test]
async fn a_successful_retry_revives_a_failed_owner_without_a_new_slot() {
    let dir = tempfile::tempdir().unwrap();
    let mut registry = registry(dir.path());
    registry.revive_hook = Some(Arc::new(|| Box::pin(async { Ok(()) })));
    let entry = failed_entry_with_tunnel(&registry, dir.path(), "revive").await;
    registry.revive_inner(endpoint("revive")).await;
    let state = entry.state.lock().await;
    assert!(!state.failed);
    assert_eq!(state.slot, Some(1), "the storage slot is reused");
    assert!(state.tunnel.is_some());
}

#[tokio::test]
async fn a_failed_retry_keeps_the_owner_failed() {
    let dir = tempfile::tempdir().unwrap();
    let mut registry = registry(dir.path());
    registry.revive_hook = Some(Arc::new(|| {
        Box::pin(async { Err(anyhow!("still unreachable")) })
    }));
    let entry = failed_entry_with_tunnel(&registry, dir.path(), "still-down").await;
    registry.revive_inner(endpoint("still-down")).await;
    assert!(entry.state.lock().await.failed);
}

#[tokio::test]
async fn retry_ignores_owners_that_never_built_a_tunnel() {
    let dir = tempfile::tempdir().unwrap();
    let mut registry = registry(dir.path());
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = calls.clone();
    registry.revive_hook = Some(Arc::new(move || {
        counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }));
    let entry = registry
        .reserve(Some(endpoint("no-tunnel")))
        .await
        .unwrap()
        .unwrap();
    {
        let mut state = entry.state.lock().await;
        state.attempted = true;
        state.failed = true;
    }
    registry.revive_inner(endpoint("no-tunnel")).await;
    registry.revive_inner(endpoint("never-reserved")).await;
    assert!(entry.state.lock().await.failed);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn background_start_builds_only_clients_that_are_not_started() {
    let dir = tempfile::tempdir().unwrap();
    let mut registry = registry(dir.path());
    registry.bootstrap_hook = Some(Arc::new(|| Box::pin(async {})));
    let registry = Arc::new(registry);
    assert!(
        registry
            .start_background(vec![endpoint("global")])
            .await
            .is_none(),
        "the main client needs no owner"
    );
    let handle = registry
        .start_background(vec![endpoint("first"), endpoint("second")])
        .await
        .expect("two fresh clients");
    handle.await.unwrap();
    assert!(registry.is_ready(&Some(endpoint("first"))).await);
    assert!(registry.is_ready(&Some(endpoint("second"))).await);
    assert!(
        registry
            .start_background(vec![endpoint("first"), endpoint("second")])
            .await
            .is_none(),
        "started clients are not started again"
    );
    registry
        .close_with_deadline(Instant::now() + Duration::from_secs(30))
        .await
        .unwrap();
}

#[tokio::test]
async fn reservation_distinguishes_credentials_and_global_from_direct() {
    let dir = tempfile::tempdir().unwrap();
    let registry = registry(dir.path());
    assert!(registry
        .reserve(Some(endpoint("global")))
        .await
        .unwrap()
        .is_none());
    let direct = registry.reserve(None).await.unwrap().unwrap();
    let first = registry
        .reserve(Some(endpoint("first")))
        .await
        .unwrap()
        .unwrap();
    let again = registry
        .reserve(Some(endpoint("first")))
        .await
        .unwrap()
        .unwrap();
    let second = registry
        .reserve(Some(endpoint("second")))
        .await
        .unwrap()
        .unwrap();
    assert!(Arc::ptr_eq(&first, &again));
    assert!(!Arc::ptr_eq(&first, &second));
    assert!(!Arc::ptr_eq(&first, &direct));
    assert!(first.state.lock().await.slot.is_none());
    assert!(second.state.lock().await.slot.is_none());
    assert!(!first.state.lock().await.attempted);
}

#[tokio::test]
async fn reserved_entries_count_toward_capacity_and_close_blocks_reserve() {
    let dir = tempfile::tempdir().unwrap();
    let registry = registry(dir.path());
    for n in 0..CAPACITY - 1 {
        let entry = registry
            .reserve(Some(endpoint(&n.to_string())))
            .await
            .unwrap()
            .unwrap();
        // Неудачная попытка также удерживает слот.
        entry.state.lock().await.attempted = true;
    }
    assert!(registry.reserve(Some(endpoint("overflow"))).await.is_err());
    assert!(registry
        .reserve(Some(endpoint("0")))
        .await
        .unwrap()
        .is_some());
    registry.close().await.unwrap();
    assert!(registry.reserve(Some(endpoint("global"))).await.is_err());
    assert!(registry.reserve(Some(endpoint("0"))).await.is_err());
}

#[tokio::test]
async fn production_constructor_retained_after_selection_cancel() {
    let dir = tempfile::tempdir().unwrap();
    let mut registry = registry(dir.path());
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let gate = std::sync::Mutex::new(Some((started_tx, release_rx)));
    registry.bootstrap_hook = Some(Arc::new(move || {
        let (started, release) = gate.lock().unwrap().take().unwrap();
        Box::pin(async move {
            let _ = started.send(());
            let _ = release.await;
        })
    }));
    let pre = Some(endpoint("production"));
    let mut selection = Box::pin(registry.select_inner(pre.clone()));
    tokio::select! {
        result = &mut selection => panic!("неожиданное завершение: {}", result.err().unwrap()),
        result = started_rx => result.unwrap(),
    }
    drop(selection);
    let entry = registry.reserve(pre).await.unwrap().unwrap();
    assert!(entry.state.lock().await.constructing.is_some());
    registry
        .close_with_deadline(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    assert!(entry.state.lock().await.constructing.is_none());
    assert!(entry.state.lock().await.tunnel.is_none());
    drop(release_tx);
}

#[tokio::test]
async fn close_deadline_retains_handle_for_retry() {
    let dir = tempfile::tempdir().unwrap();
    let registry = registry(dir.path());
    let entry = registry
        .reserve(Some(endpoint("blocked-close")))
        .await
        .unwrap()
        .unwrap();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    {
        let mut state = entry.state.lock().await;
        state.attempted = true;
        state.constructing = Some(tokio::task::spawn_blocking(move || {
            let _ = started_tx.send(());
            let _ = release_rx.recv();
            Err(anyhow!("конструктор остановлен"))
        }));
    }
    started_rx.await.unwrap();
    assert!(registry
        .close_with_deadline(Instant::now() + Duration::from_millis(20))
        .await
        .is_err());
    assert!(entry.state.lock().await.constructing.is_some());
    assert!(registry.reserve(Some(endpoint("global"))).await.is_err());
    release_tx.send(()).unwrap();
    assert!(registry
        .close_with_deadline(Instant::now() + Duration::from_secs(5))
        .await
        .is_err());
    registry
        .close_with_deadline(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    assert!(entry.state.lock().await.constructing.is_none());
}

// Проверяется только сохранение вручную установленного дескриптора.
#[tokio::test]
async fn cancelled_wait_retains_blocking_constructor_until_close() {
    let dir = tempfile::tempdir().unwrap();
    let registry = Arc::new(registry(dir.path()));
    let pre = Some(endpoint("blocked"));
    let entry = registry.reserve(pre.clone()).await.unwrap().unwrap();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    {
        let mut state = entry.state.lock().await;
        state.attempted = true;
        state.constructing = Some(tokio::task::spawn_blocking(move || {
            let _ = started_tx.send(());
            let _ = release_rx.recv();
            Err(anyhow!("конструктор остановлен"))
        }));
    }
    started_rx.await.unwrap();
    let mut selection = Box::pin(registry.select_inner(pre));
    assert!(
        std::future::poll_fn(|cx| std::task::Poll::Ready(selection.as_mut().poll(cx).is_pending()))
            .await
    );
    drop(selection);
    assert!(entry.state.lock().await.constructing.is_some());
    let closing = tokio::spawn({
        let registry = registry.clone();
        async move { registry.close().await }
    });
    registry.cancelled().await;
    assert!(!closing.is_finished());
    release_tx.send(()).unwrap();
    assert!(closing.await.unwrap().is_err());
    registry.close().await.unwrap();
    assert!(entry.state.lock().await.constructing.is_none());
}
#[tokio::test]
async fn close_reports_constructed_outcome_failure_after_teardown() {
    let dir = tempfile::tempdir().unwrap();
    let registry = registry(dir.path());
    let entry = registry
        .reserve(Some(endpoint("failed-outcome")))
        .await
        .unwrap()
        .unwrap();
    let mut settings = registry.settings.as_ref().unwrap().clone();
    settings.state_dir = Some(dir.path().join("constructed-outcome"));
    let tunnel = TorTunnel::create_unbootstrapped_with(settings).unwrap();
    {
        let mut state = entry.state.lock().await;
        state.attempted = true;
        state.constructing = Some(tokio::task::spawn_blocking(move || {
            Ok(Constructed {
                tunnel,
                slot: 1,
                outcome: Err(anyhow!("bootstrap failed")),
            })
        }));
    }

    assert!(registry.close().await.is_err());
    let state = entry.state.lock().await;
    assert!(state.constructing.is_none());
    assert_eq!(state.slot, Some(1));
    assert!(state.tunnel.is_none());
    assert!(state.teardown.is_none());
    drop(state);
    registry.close().await.unwrap();
}

#[cfg(test)]
mod pre_policy_tests {
    use crate::startup::validate_pre_compatibility;

    #[test]
    fn rejects_independent_egress_only_with_global_pre() {
        for (dns, onion, upstream) in [
            (true, false, false),
            (false, true, false),
            (false, false, true),
        ] {
            assert!(validate_pre_compatibility(true, dns, onion, upstream).is_err());
            assert!(validate_pre_compatibility(false, dns, onion, upstream).is_ok());
        }
        assert!(validate_pre_compatibility(true, false, false, false).is_ok());
    }
}

#[cfg(test)]
mod pt_policy_tests;

#[cfg(test)]
#[path = "restart_tests.rs"]
mod restart_tests;

#[cfg(test)]
#[path = "isolation_tests.rs"]
mod isolation_tests;

// Helpers shared by the restart and isolation suites below.
use crate::server::handlers::HandlerTasks;
use crate::server::{global_init, producers};
use crate::{Server, ServerError, ServerStatus};
use tor_socks5_runtime::{bridge_store_writer, workers};

use super::storage::quarantine_held;

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
        // The server owns the run slot (init_run/close_run); the app's global
        // writer slot is covered by isolation_tests.
        writer: !bridge_store_writer::run_is_idle(),
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

async fn assert_slots_free() {
    let mut last = None;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            // Reap finished registry slots (as the app's join would) so late
            // worker exits from the previous run do not mask a clear state.
            if workers::global_busy_count().await > 0 {
                let _ = tokio::time::timeout(
                    Duration::from_millis(500),
                    workers::join_blocking_workers(),
                )
                .await;
            }
            let current = slots().await;
            if current == free(current.quarantine) {
                return;
            }
            last = Some(current);
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "server resources remained retained after shutdown: {:?}",
            last
        )
    });
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
