use super::super::{handle_client_with_connector, ConnHealthCounters, Egress, TorConnector};
use super::*;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug)]
struct FinalFlushSentinel(u32);

#[derive(Debug)]
struct InitialPublishError;
impl std::fmt::Display for InitialPublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("initial publish failed")
    }
}
impl std::error::Error for InitialPublishError {}

// Bootstrap подменён; проверяется завершение сервера, а не сеть Tor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_server_reports_final_flush_worker_panic() {
    let _serial = TEST_LIFECYCLE.lock().await;
    tokio::time::timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = crate::config::Config::default();
        cfg.listen = vec!["127.0.0.1:0".into()];
        cfg.log.ansi = true;
        let path = dir.path().join("server.ktav");
        std::fs::write(&path, ktav::to_string(&cfg).unwrap()).unwrap();
        let settings = Settings {
            bridges: vec!["192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01"
                .parse()
                .unwrap()],
            state_dir: Some(dir.path().join("state")),
            ..Default::default()
        };
        let registry = Arc::new(crate::bridge_verifier::TestWorkers::default());
        registry
            .scope(async {
                let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                let publisher_calls = calls.clone();
                let (first_tx, first_rx) = tokio::sync::oneshot::channel();
                let first = std::sync::Mutex::new(Some(first_tx));
                let writer = crate::bridge_store_writer::StoreWriter::spawn(
                    bridge_store::BridgeStore::resolve_path(Some(&path)),
                    Arc::new(move |_| {
                        if publisher_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                            let _ = first.lock().unwrap().take().unwrap().send(());
                            Err(anyhow::Error::new(InitialPublishError))
                        } else {
                            std::panic::panic_any(FinalFlushSentinel(777))
                        }
                    }),
                    Duration::from_secs(3600),
                );
                writer.apply(|_| {}).await.unwrap();
                first_rx.await.unwrap();
                let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
                let hook = Arc::new(super::super::global_init::ShutdownHook {
                    settings,
                    writer,
                    ready: std::sync::Mutex::new(Some(ready_tx)),
                });
                let args = super::super::ServerArgs {
                    config_override: Some(path),
                    upstream_addr: None,
                    upstream_user: None,
                    upstream_pass: None,
                    no_upstream: false,
                };
                let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
                let server = super::super::global_init::RUN_SERVER_SHUTDOWN.scope(hook, async {
                    super::super::run_server(args, async {
                        let _ = shutdown_rx.await;
                    })
                    .await
                });
                let trigger = async {
                    ready_rx.await.expect("сервер не достиг основного цикла");
                    shutdown_tx.send(()).unwrap();
                };
                let (result, ()) = tokio::join!(server, trigger);
                let errors = result
                    .unwrap_err()
                    .downcast::<super::super::producers::ProducerFailures>()
                    .unwrap()
                    .into_errors();
                let worker_errors = errors
                    .into_iter()
                    .filter_map(|error| {
                        error
                            .downcast::<crate::bridge_verifier::WorkerFailures>()
                            .ok()
                    })
                    .flat_map(|failures| failures.into_errors());
                let panic = worker_errors
                    .filter_map(|error| error.downcast::<tokio::task::JoinError>().ok())
                    .find(|error| error.is_panic())
                    .expect("паника финальной публикации отсутствует в результате сервера");
                assert_eq!(
                    panic
                        .into_panic()
                        .downcast::<FinalFlushSentinel>()
                        .unwrap()
                        .0,
                    777
                );
                assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
            })
            .await;
    })
    .await
    .expect("тайм-аут завершения сервера");
}

// Сетевые этапы запуска подменены барьером; это не сквозной тест Tor.
async fn parked_server_startup(global: bool) {
    let _serial = TEST_LIFECYCLE.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let mut cfg = crate::config::Config::default();
    cfg.listen = vec![address.to_string()];
    cfg.log.ansi = true;
    let path = dir.path().join("server.ktav");
    std::fs::write(&path, ktav::to_string(&cfg).unwrap()).unwrap();
    let settings = Settings {
        bridges: vec!["192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01"
            .parse()
            .unwrap()],
        state_dir: Some(dir.path().join("state")),
        ..Default::default()
    };
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let hook = Arc::new(super::super::global_init::StartupHook {
        settings,
        park_global: global,
        gate: std::sync::Mutex::new(Some((entered_tx, release_rx))),
    });
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let args = super::super::ServerArgs {
        config_override: Some(path),
        upstream_addr: None,
        upstream_user: None,
        upstream_pass: None,
        no_upstream: false,
    };
    let mut server = AbortOnDrop(tokio::spawn(
        super::super::global_init::RUN_SERVER_STARTUP.scope(hook, async move {
            super::super::run_server(args, async {
                let _ = shutdown_rx.await;
            })
            .await
        }),
    ));
    let entered = tokio::time::timeout(Duration::from_secs(10), entered_rx).await;
    let _ = shutdown_tx.send(());
    let result = tokio::time::timeout(Duration::from_secs(2), &mut server.0).await;
    let snapshot = super::super::global_init::startup_snapshot(global);
    if result.is_err() {
        server.0.abort();
        let _ = (&mut server.0).await;
    }
    let _ = release_tx.send(());
    let recovery = super::super::global_init::recover_startup().await;
    assert!(
        matches!(entered, Ok(Ok(()))),
        "сервер не достиг ожидаемой стадии"
    );
    assert!(result
        .expect("сервер проигнорировал завершение")
        .expect("задача сервера прервана")
        .is_err());
    assert!(snapshot.0, "корень незавершённой задачи потерян");
    if global {
        assert!(snapshot.1, "запуск Tor не отменён");
    }
    recovery.unwrap();
    assert!(!super::super::global_init::startup_snapshot(global).0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_server_shutdown_during_parked_settings() {
    parked_server_startup(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_server_shutdown_during_parked_global_init() {
    parked_server_startup(true).await;
}

// Сетевой bootstrap остановлен барьером; это не сквозной тест Tor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tracked_handler_shutdown_joins_pending_owner_constructor() {
    let _serial = TEST_LIFECYCLE.lock().await;
    tokio::time::timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();
        let (_, handle, mut registry, path, mut users, _) = handler_setup(dir.path());
        let observer = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        observer.set_nonblocking(true).unwrap();
        users.users[0].pre_socks5 = Some(proxy_config::EndpointOverride::Endpoint(
            format!("{}|alice:first", observer.local_addr().unwrap()).parse().unwrap(),
        ));
        users.save(&path).unwrap();
        let auth = Arc::new(auth::AuthState::build_persistent(&users, path).unwrap());
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
        let registry = Arc::new(registry);
        registry.retain_for_shutdown().unwrap();
        assert!(Arc::ptr_eq(RETAINED.lock().unwrap().as_ref().unwrap(), &registry));
        let handlers = Arc::new(super::super::handlers::HandlerTasks::new());
        handlers.retain().unwrap();
        assert!(Arc::ptr_eq(&super::super::handlers::HandlerTasks::retained().unwrap(), &handlers));
        let permits = Arc::new(tokio::sync::Semaphore::new(1));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut accept = AbortOnDrop(tokio::spawn(super::super::handlers::accept_loop_tracked(
            listener, Egress::Tor(handle, None, None, false, Some(registry.clone())),
            Some(auth), permits.clone(), ConnHealthCounters::default(),
            Arc::new(std::sync::atomic::AtomicU64::new(1)), Default::default(), handlers.clone(),
        )));
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic YWxpY2U6cHc=\r\n\r\n").await.unwrap();
        started_rx.await.unwrap();
        assert_eq!(permits.available_permits(), 0);
        let entries = registry.state.lock().await.entries.clone();
        assert_eq!(entries.len(), 1);
        // Выбор держит mutex записи, пока ожидает конструктор.
        assert!(entries[0].state.try_lock().is_err());
        accept.0.abort();
        assert!((&mut accept.0).await.unwrap_err().is_cancelled());
        registry.begin_close();
        handlers.shutdown().await.unwrap();
        assert!(entries[0].state.lock().await.constructing.is_some());
        registry.close_with_deadline(Instant::now() + Duration::from_secs(5)).await.unwrap();
        assert_eq!(permits.available_permits(), 1);
        assert!(matches!(observer.accept(), Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock));
        for entry in entries {
            let state = entry.state.lock().await;
            assert!(state.constructing.is_none());
            assert!(state.teardown.is_none());
            assert!(state.tunnel.is_none());
        }
        assert!(registry.reserve(Some(endpoint("late"))).await.is_err());
        assert!(RETAINED.lock().unwrap().is_none());
        assert!(super::super::handlers::HandlerTasks::retained().is_none());
        assert!(release_tx.send(()).is_err());
    }).await.expect("превышено время завершения обработчика и владельца");
}

// Сетевой запуск Tor заменён заглушкой; это не сквозной тест Tor.
struct Observe {
    tx: Option<tokio::sync::oneshot::Sender<(usize, bool, bool)>>,
    expected: Settings,
}

impl TorConnector for Observe {
    async fn connect<'a>(
        &'a mut self,
        tor: &'a TorTunnel,
        _post: Option<&'a proxy_config::EndpointOverride>,
        _host: &'a str,
        _port: u16,
    ) -> arti_wrapper::Result<arti_wrapper::DataStream> {
        let mut wrong = self.expected.clone();
        wrong.pre_endpoint = Some(Socks5PreEndpoint::new(
            "127.0.0.1:1080".parse().unwrap(),
            Some(("alice".into(), "wrong".into())),
        ));
        let immutable_guard = |result: arti_wrapper::Result<()>| {
            matches!(result, Err(arti_wrapper::TorError::BuildConfig(ref message))
                if message == "cannot change the pre endpoint on a shared client")
        };
        let route_matches = !immutable_guard(tor.reconfigure_bridges(&self.expected));
        let immutable = immutable_guard(tor.reconfigure_bridges(&wrong));
        self.tx
            .take()
            .unwrap()
            .send((tor.raw() as *const _ as usize, route_matches, immutable))
            .unwrap();
        Err(arti_wrapper::TorError::PostSocks(
            socks5_proto::client::Error::InvalidInput,
        ))
    }
}

fn endpoint(password: &str) -> Socks5PreEndpoint {
    Socks5PreEndpoint::new(
        "127.0.0.1:1080".parse().unwrap(),
        Some(("alice".into(), password.into())),
    )
}

struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn request(
    registry: Arc<OwnerRegistry>,
    handle: TorHandle,
    auth: Arc<auth::AuthState>,
    global_pre: Option<proxy_config::EndpointOverride>,
    expected: Settings,
) -> (usize, bool, bool) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    client
        .write_all(
            b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic YWxpY2U6cHc=\r\n\r\n",
        )
        .await
        .unwrap();
    let mut handler = AbortOnDrop(tokio::spawn(handle_client_with_connector(
        server,
        Egress::Tor(
            handle,
            global_pre.map(Arc::new),
            None,
            false,
            Some(registry),
        ),
        Some(auth),
        ConnHealthCounters::default(),
        false,
        1,
        Observe {
            tx: Some(tx),
            expected,
        },
    )));
    let observed = rx.await.expect("handler must reach connector");
    assert!((&mut handler.0).await.unwrap().is_err());
    observed
}

#[tokio::test]
async fn production_handler_account_endpoint_without_global() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let settings = Settings {
            pre_endpoint: None,
            bridges: vec!["192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01"
                .parse()
                .unwrap()],
            state_dir: Some(dir.path().join("global")),
            ..Default::default()
        };
        let global = TorTunnel::create_unbootstrapped_with(settings.clone()).unwrap();
        let global_id = global.raw() as *const _ as usize;
        let handle = TorHandle::new(global);
        let mut registry = OwnerRegistry::new(handle.clone(), settings.clone()).unwrap();
        registry.bootstrap_hook = Some(Arc::new(|| Box::pin(async {})));
        let registry = Arc::new(registry);
        let path = dir.path().join("users.ktav");
        let route_a =
            proxy_config::EndpointOverride::Endpoint("127.0.0.1:1080|alice:first".parse().unwrap());
        let route_b = proxy_config::EndpointOverride::Endpoint(
            "127.0.0.1:1080|alice:second".parse().unwrap(),
        );
        let mut users = auth::UsersConfig {
            users: vec![auth::User {
                name: "alice".into(),
                hash: auth::INIT_SENTINEL.into(),
                is_enabled: true,
                allowed_onion: false,
                allowed_clients: None,
                pre_socks5: Some(route_a.clone()),
                post_socks5: None,
            }],
        };
        users.save(&path).unwrap();
        let auth = Arc::new(auth::AuthState::build_persistent(&users, path.clone()).unwrap());
        let routes = [
            (Some(route_a.clone()), Some(endpoint("first"))),
            (Some(route_a), Some(endpoint("first"))),
            (Some(route_b), Some(endpoint("second"))),
            (Some(proxy_config::EndpointOverride::Disabled), None),
            (None, None),
        ];
        let mut ids = Vec::new();
        for (index, (route, pre)) in routes.into_iter().enumerate() {
            if index != 0 {
                users.users[0].pre_socks5 = route.clone();
                users.save(&path).unwrap();
                let state = auth.clone();
                tokio::task::spawn_blocking(move || state.reload())
                    .await
                    .unwrap()
                    .unwrap();
            }
            let mut expected = settings.clone();
            expected.pre_endpoint = pre.clone();
            let (id, route_matches, immutable) = request(
                registry.clone(),
                handle.clone(),
                auth.clone(),
                None,
                expected,
            )
            .await;
            assert!(route_matches);
            assert!(immutable);
            if index == 0 {
                users = auth::UsersConfig::load(&path).unwrap();
                assert_ne!(users.users[0].hash, auth::INIT_SENTINEL);
            }
            let state = auth.clone();
            let proof = tokio::task::spawn_blocking(move || state.verify_proof("alice", "pw"))
                .await
                .unwrap()
                .unwrap();
            {
                let lease = auth.admit(&proof).await.unwrap();
                assert!(lease.pre_socks5() == route.as_ref());
            }
            if let Some(pre) = pre {
                let entries = registry.state.lock().await.entries.clone();
                let entry = entries
                    .iter()
                    .find(|entry| entry.pre.as_ref() == Some(&pre))
                    .unwrap();
                let state = entry.state.lock().await;
                let cached_id = state.tunnel.as_ref().unwrap().raw() as *const _ as usize;
                assert_eq!(id, cached_id);
            } else {
                assert_eq!(id, global_id);
            }
            ids.push(id);
        }
        assert_ne!(ids[0], global_id);
        assert_eq!(ids[0], ids[1]);
        assert_ne!(ids[0], ids[2]);
        assert_ne!(ids[2], global_id);
        assert_eq!(ids[3], global_id);
        assert_eq!(ids[4], global_id);
        assert_eq!(registry.state.lock().await.entries.len(), 2);
        registry.close().await.unwrap();
    })
    .await
    .expect("handler owner regression timed out");
}

#[tokio::test]
async fn production_handler_selects_cached_owners_by_full_route() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let settings = Settings {
            pre_endpoint: Some(endpoint("global")),
            bridges: vec!["192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01"
                .parse()
                .unwrap()],
            state_dir: Some(dir.path().join("global")),
            ..Default::default()
        };
        let global = TorTunnel::create_unbootstrapped_with(settings.clone()).unwrap();
        let global_id = global.raw() as *const _ as usize;
        let handle = TorHandle::new(global);
        let mut registry = OwnerRegistry::new(handle.clone(), settings.clone()).unwrap();
        // Заменяется только ожидание сети, не выбор и не создание владельца.
        registry.bootstrap_hook = Some(Arc::new(|| Box::pin(async {})));
        let registry = Arc::new(registry);
        let global_pre = proxy_config::EndpointOverride::Endpoint(
            "127.0.0.1:1080|alice:global".parse().unwrap(),
        );
        let path = dir.path().join("users.ktav");
        let mut users = auth::UsersConfig {
            users: vec![auth::User {
                name: "alice".into(),
                hash: auth::compute_hash("pw").unwrap(),
                is_enabled: true,
                allowed_onion: false,
                allowed_clients: None,
                pre_socks5: None,
                post_socks5: None,
            }],
        };
        users.save(&path).unwrap();
        let auth = Arc::new(auth::AuthState::build_persistent(&users, path.clone()).unwrap());
        let mut ids = Vec::new();
        for pre in [
            None,
            Some("first"),
            Some("first"),
            Some("second"),
            Some("direct"),
        ] {
            users.users[0].pre_socks5 = match pre {
                None => None,
                Some("direct") => Some(proxy_config::EndpointOverride::Disabled),
                Some(password) => Some(proxy_config::EndpointOverride::Endpoint(
                    format!("127.0.0.1:1080|alice:{password}").parse().unwrap(),
                )),
            };
            users.save(&path).unwrap();
            let state = auth.clone();
            tokio::task::spawn_blocking(move || state.reload())
                .await
                .unwrap()
                .unwrap();
            let mut expected = settings.clone();
            expected.pre_endpoint = match pre {
                None => Some(endpoint("global")),
                Some("direct") => None,
                Some(password) => Some(endpoint(password)),
            };
            let (id, route_matches, immutable) = request(
                registry.clone(),
                handle.clone(),
                auth.clone(),
                Some(global_pre.clone()),
                expected,
            )
            .await;
            assert!(route_matches);
            assert!(immutable);
            ids.push(id);
        }
        assert_eq!(ids[0], global_id);
        assert_ne!(
            ids[1], global_id,
            "account route must not bypass owner selection"
        );
        assert_eq!(ids[1], ids[2], "identical routes must reuse the client");
        assert_ne!(ids[1], ids[3], "credentials are part of the owner key");
        assert_ne!(ids[1], ids[4]);
        assert_ne!(ids[3], ids[4]);
        assert_ne!(ids[4], global_id);
        let state = registry.state.lock().await;
        assert_eq!(state.entries.len(), 3);
        let entries = state.entries.clone();
        drop(state);
        let mut slots = Vec::new();
        for entry in entries {
            let state = entry.state.lock().await;
            slots.push(state.slot.unwrap());
            assert!(state.tunnel.is_some());
        }
        slots.sort_unstable();
        slots.dedup();
        assert_eq!(slots.len(), 3);
        registry.close().await.unwrap();
    })
    .await
    .expect("handler owner regression timed out");
}

// Заменяется только сетевой bootstrap и dial; это не сквозной тест Tor.
struct Park {
    observe: Observe,
    release: Option<tokio::sync::oneshot::Receiver<()>>,
}

impl TorConnector for Park {
    async fn connect<'a>(
        &'a mut self,
        tor: &'a TorTunnel,
        post: Option<&'a proxy_config::EndpointOverride>,
        host: &'a str,
        port: u16,
    ) -> arti_wrapper::Result<arti_wrapper::DataStream> {
        let result = self.observe.connect(tor, post, host, port).await;
        let _ = self.release.take().unwrap().await;
        result
    }
}

async fn start_handler<C: TorConnector + Send + 'static>(
    registry: Arc<OwnerRegistry>,
    handle: TorHandle,
    auth: Arc<auth::AuthState>,
    connector: C,
) -> (TcpStream, AbortOnDrop<anyhow::Result<()>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    client
        .write_all(
            b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic YWxpY2U6cHc=\r\n\r\n",
        )
        .await
        .unwrap();
    let handler = AbortOnDrop(tokio::spawn(handle_client_with_connector(
        server,
        Egress::Tor(handle, None, None, false, Some(registry)),
        Some(auth),
        ConnHealthCounters::default(),
        false,
        1,
        connector,
    )));
    (client, handler)
}

fn handler_setup(
    dir: &std::path::Path,
) -> (
    Settings,
    TorHandle,
    OwnerRegistry,
    std::path::PathBuf,
    auth::UsersConfig,
    Arc<auth::AuthState>,
) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let settings = Settings {
        pre_endpoint: None,
        bridges: vec!["192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01"
            .parse()
            .unwrap()],
        state_dir: Some(dir.join("global")),
        ..Default::default()
    };
    let handle = TorHandle::new(TorTunnel::create_unbootstrapped_with(settings.clone()).unwrap());
    let registry = OwnerRegistry::new(handle.clone(), settings.clone()).unwrap();
    let path = dir.join("users.ktav");
    let users = auth::UsersConfig {
        users: vec![auth::User {
            name: "alice".into(),
            hash: auth::compute_hash("pw").unwrap(),
            is_enabled: true,
            allowed_onion: false,
            allowed_clients: None,
            pre_socks5: Some(proxy_config::EndpointOverride::Endpoint(
                "127.0.0.1:1080|alice:first".parse().unwrap(),
            )),
            post_socks5: None,
        }],
    };
    users.save(&path).unwrap();
    let auth = Arc::new(auth::AuthState::build_persistent(&users, path.clone()).unwrap());
    (settings, handle, registry, path, users, auth)
}

#[tokio::test]
async fn production_handler_cancelled_initialization_reuses_job_and_releases_lease() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();
        let (settings, handle, mut registry, path, users, auth) = handler_setup(dir.path());
        let global_id = handle.tunnel().await.unwrap().raw() as *const _ as usize;
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let gate = std::sync::Mutex::new(Some((started_tx, release_rx)));
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = calls.clone();
        registry.bootstrap_hook = Some(Arc::new(move || {
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let (started, release) = gate.lock().unwrap().take().unwrap();
            Box::pin(async move {
                let _ = started.send(());
                let _ = release.await;
            })
        }));
        let registry = Arc::new(registry);
        let mut expected = settings.clone();
        expected.pre_endpoint = Some(endpoint("first"));
        let (tx, _rx) = tokio::sync::oneshot::channel();
        let (_client, mut handler) = start_handler(
            registry.clone(),
            handle.clone(),
            auth.clone(),
            Observe {
                tx: Some(tx),
                expected: expected.clone(),
            },
        )
        .await;
        started_rx.await.unwrap();
        handler.0.abort();
        assert!((&mut handler.0).await.unwrap_err().is_cancelled());
        let entries = registry.state.lock().await.entries.clone();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].pre, Some(endpoint("first")));
        assert!(entries[0].state.lock().await.constructing.is_some());
        users.save(&path).unwrap();
        let state = auth.clone();
        let mut reload = AbortOnDrop(tokio::task::spawn_blocking(move || state.reload()));
        (&mut reload.0).await.unwrap().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let (_client, mut retry) = start_handler(
            registry.clone(),
            handle.clone(),
            auth.clone(),
            Observe {
                tx: Some(tx),
                expected,
            },
        )
        .await;
        release_tx.send(()).unwrap();
        let (id, matches, immutable) = rx.await.unwrap();
        assert_ne!(id, global_id);
        assert!(matches && immutable);
        assert!((&mut retry.0).await.unwrap().is_err());
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(
            id,
            entries[0].state.lock().await.tunnel.as_ref().unwrap().raw() as *const _ as usize
        );
        registry.close().await.unwrap();
    })
    .await
    .expect("handler cancellation regression timed out");
}

#[tokio::test]
async fn production_handler_reload_waits_through_alternate_dial() {
    use std::future::Future;
    tokio::time::timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();
        let (settings, handle, mut registry, path, mut users, auth) = handler_setup(dir.path());
        registry.bootstrap_hook = Some(Arc::new(|| Box::pin(async {})));
        let registry = Arc::new(registry);
        let state = auth.clone();
        let mut verify = AbortOnDrop(tokio::task::spawn_blocking(move || {
            state.verify_proof("alice", "pw")
        }));
        let proof = (&mut verify.0).await.unwrap().unwrap();
        let mut expected = settings.clone();
        expected.pre_endpoint = Some(endpoint("first"));
        let (tx, rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let (_client, mut handler) = start_handler(
            registry.clone(),
            handle.clone(),
            auth.clone(),
            Park {
                observe: Observe {
                    tx: Some(tx),
                    expected,
                },
                release: Some(release_rx),
            },
        )
        .await;
        let (id_a, matches, immutable) = rx.await.unwrap();
        assert!(matches && immutable);
        users.users[0].pre_socks5 = Some(proxy_config::EndpointOverride::Endpoint(
            "127.0.0.1:1080|alice:second".parse().unwrap(),
        ));
        users.save(&path).unwrap();
        let state = auth.clone();
        let mut reload = AbortOnDrop(tokio::task::spawn_blocking(move || state.reload()));
        loop {
            let mut admission = Box::pin(auth.admit(&proof));
            let queued = std::future::poll_fn(|cx| {
                std::task::Poll::Ready(match admission.as_mut().poll(cx) {
                    std::task::Poll::Pending => true,
                    std::task::Poll::Ready(Some(lease)) => {
                        drop(lease);
                        false
                    }
                    std::task::Poll::Ready(None) => panic!("proof устарел до освобождения lease"),
                })
            })
            .await;
            drop(admission);
            if queued {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(!reload.0.is_finished());
        release_tx.send(()).unwrap();
        assert!((&mut handler.0).await.unwrap().is_err());
        (&mut reload.0).await.unwrap().unwrap();
        assert!(auth.admit(&proof).await.is_none());
        let mut expected = settings.clone();
        expected.pre_endpoint = Some(endpoint("second"));
        let (id_b, matches, immutable) =
            request(registry.clone(), handle, auth, None, expected).await;
        assert_ne!(id_a, id_b);
        assert!(matches && immutable);
        registry.close().await.unwrap();
    })
    .await
    .expect("handler reload regression timed out");
}
