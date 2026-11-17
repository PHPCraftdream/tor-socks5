use super::*;

// Retry-spread scaling (pure, no runtime).
#[test]
fn the_spread_stays_within_twenty_percent() {
    assert_eq!(spread_millis(30_000, 0), 24_000);
    // u64::MAX % 40 == 15 → step 15 → factor 0.95.
    assert_eq!(spread_millis(30_000, u64::MAX), 28_500);
    assert_eq!(spread_millis(300_000, 0), 240_000);

    // Monotone non-decreasing across the 40-step period.
    let mut previous = spread_millis(30_000, 0);
    for unit in 1..40u64 {
        let current = spread_millis(30_000, unit);
        assert!(current >= previous, "spread regressed at unit {unit}");
        previous = current;
    }

    // Real samples: the unit comes from the OS RNG, so only bounds and
    // variety are asserted — no wall-clock anywhere.
    let mut distinct = std::collections::HashSet::new();
    for _ in 0..50 {
        let delay = backoff_spread(Duration::from_secs(30));
        assert!(
            delay >= Duration::from_secs(24),
            "below the -20% floor: {delay:?}"
        );
        assert!(
            delay < Duration::from_secs(36),
            "above the +20% ceiling: {delay:?}"
        );
        distinct.insert(delay);
    }
    assert!(distinct.len() >= 2, "the spread produces variety");
}

#[test]
fn the_soft_limit_warning_starts_above_ten_services() {
    assert!(!beyond_soft_limit(1));
    assert!(!beyond_soft_limit(10));
    assert!(beyond_soft_limit(11));
    assert!(beyond_soft_limit(100));
}

#[test]
fn build_config_accepts_valid_nickname() {
    let nick = keys::nickname("svc-one").expect("nickname");
    let config = build_config(nick).expect("config");
    assert_eq!(config.nickname().to_string(), "svc-one");
    // `enabled` defaults to true, so arti will actually start it.
    assert!(config.enabled());
}

#[test]
fn invalid_nickname_is_rejected_before_launch() {
    let entry = OnionServiceEntry {
        nickname: "not a nickname".to_owned(),
        enabled: true,
        address: None,
        key: None,
        circuit_hops: 4,
        ports: Vec::new(),
    };
    // The manager returns without launching when the nickname is invalid;
    // validate that path directly via the keys helper it uses.
    assert!(keys::nickname(&entry.nickname).is_err());
}

fn service(nickname: &str) -> OnionServiceEntry {
    OnionServiceEntry {
        nickname: nickname.to_owned(),
        enabled: true,
        address: None,
        key: None,
        circuit_hops: 4,
        ports: vec![proxy_config::OnionServicePort {
            onion_port: 80,
            target: "127.0.0.1:8080".to_owned(),
        }],
    }
}

fn temp_config() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = dir.path().join("tor-socks5.ktav");
    let keystore = dir.path().join("keystore");
    (dir, config, keystore)
}

fn keystore_address(keystore: &std::path::Path, nickname: &str) -> Option<String> {
    let keymgr = keys::store::open(keystore).expect("keystore");
    keys::store::address(&keymgr, &keys::nickname(nickname).expect("nickname")).expect("address")
}

#[test]
fn a_launchable_identity_is_prepared_and_the_file_completed() {
    let (_tmp, config, keystore) = temp_config();
    let entry = service("web");
    proxy_config::Config::write_onion_services(&config, std::slice::from_ref(&entry))
        .expect("write");

    let prepared = keys::prepare_all(Some(&config), &keystore, &[entry]);
    let address = prepared[0].address.clone().expect("the service may start");

    let stored = proxy_config::Config::read_onion_services(&config).expect("read");
    assert_eq!(stored[0].address.as_deref(), Some(address.as_str()));
    assert!(stored[0].key.is_some(), "the new key is recorded");
    assert_eq!(keystore_address(&keystore, "web"), Some(address));
}

#[test]
fn an_address_the_key_does_not_give_keeps_the_service_from_starting() {
    let (_tmp, config, keystore) = temp_config();
    let (key, _address) = keys::fresh_identity("web", _tmp.path());
    let (_other_key, other_address) = keys::fresh_identity("web", _tmp.path());
    let mut entry = service("web");
    entry.key = Some(proxy_config::IdentityKey::new(key).expect("key text"));
    entry.address = Some(other_address);
    proxy_config::Config::write_onion_services(&config, std::slice::from_ref(&entry))
        .expect("write");

    let prepared = keys::prepare_all(Some(&config), &keystore, &[entry]);
    assert_eq!(prepared[0].address, None);
    assert_eq!(
        prepared[0].failure,
        Some(PreparationFailure::AddressMismatch)
    );
    assert_eq!(
        keystore_address(&keystore, "web"),
        None,
        "nothing was published"
    );
}

#[test]
fn a_key_that_is_not_an_identity_keeps_the_service_from_starting() {
    let (_tmp, config, keystore) = temp_config();
    let mut entry = service("web");
    entry.key = Some(
        proxy_config::IdentityKey::new(keys::store::encode_key(b"not a key")).expect("key text"),
    );
    proxy_config::Config::write_onion_services(&config, std::slice::from_ref(&entry))
        .expect("write");

    let prepared = keys::prepare_all(Some(&config), &keystore, &[entry]);
    assert_eq!(prepared[0].address, None);
}

// --- New host-API regression tests (deterministic, no wall-clock). ---

/// Install rustls's process-wide `CryptoProvider` exactly once for this
/// test binary (copied verbatim from
/// `tor_watchdog_tests.rs`): a fresh `state_dir` reaches further into
/// arti's directory-manager setup, and that path expects a crypto
/// provider to already be installed. `install_default()` errors if
/// called twice in the same process, so the error is discarded.
fn ensure_crypto_provider() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn test_handle(state_dir: &std::path::Path) -> TorHandle {
    ensure_crypto_provider();
    // A fresh tempdir `state_dir` (owned by the caller so it outlives the
    // tunnel): `None` would fall back to arti's shared per-user OS
    // location, which is flaky on CI.
    let settings = arti_wrapper::Settings {
        state_dir: Some(state_dir.to_path_buf()),
        ..Default::default()
    };
    let tor = arti_wrapper::TorTunnel::create_unbootstrapped_with(settings)
        .expect("unbootstrapped tunnel");
    TorHandle::new(tor)
}

fn disabled_entry() -> OnionServiceEntry {
    let mut entry = service("off");
    entry.enabled = false;
    entry
}

/// With no enabled entries the producer exits immediately (it never
/// touches the blocking pool) and the status stays empty. This runs on
/// the default `#[tokio::test]` flavor (current-thread): `tokio::spawn`
/// works there, and the safe path is that zero enabled entries keep the
/// producer off the blocking pool entirely.
#[cfg(test)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_without_enabled_services_starts_and_shuts_down() {
    let dir = tempfile::tempdir().expect("temp dir");
    let keystore = std::env::temp_dir().join("tor-socks5-onion-host-empty-test");
    let config = OnionHostConfig::new(test_handle(dir.path()), keystore, CancellationToken::new())
        .with_entries(vec![disabled_entry()]);
    let host_handle = OnionHost::new(config).start();
    assert!(
        host_handle.status().services.is_empty(),
        "no enabled services, empty status"
    );
    host_handle.shutdown().await;
}

/// Run real host choreography with a private Tor state directory.
/// Run the real host choreography against an isolated Tor state directory.
async fn host_for_test(
    state_dir: &std::path::Path,
    keystore: PathBuf,
    config_path: Option<PathBuf>,
    entry: OnionServiceEntry,
    token: CancellationToken,
    hooks: Option<HostTestHooks>,
) -> OnionHostHandle {
    let mut config = OnionHostConfig::new(test_handle(state_dir), keystore, token)
        .with_entries(vec![entry])
        .with_config_path(config_path);
    config.test_hooks = hooks;
    OnionHost::new(config).start()
}

async fn wait_for_status(
    host: &OnionHostHandle,
    nickname: &str,
    status: ServiceStatus,
) -> ServiceState {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let state = host.status().services[nickname].clone();
            if state.status == status {
                return state;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("host status reached expected terminal state")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_while_keystore_lock_is_held_does_not_wait_or_prepare() {
    let (tmp, config_path, keystore) = temp_config();
    let entry = service("web");
    let services_path = proxy_config::Config::onion_path(&config_path);
    proxy_config::Config::write_onion_services(&config_path, std::slice::from_ref(&entry))
        .expect("write services file");
    let original = std::fs::read(&services_path).expect("read original services file");
    let held = persist_lock::PathLock::acquire_bounded(&keystore, Duration::from_secs(1))
        .expect("hold keystore lock");
    let probes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let probe_count = probes.clone();
    let hooks = HostTestHooks {
        lock_probe: Some(Arc::new(move |path| {
            probe_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            probe_keystore_lock(path)
        })),
        ..Default::default()
    };
    let token = CancellationToken::new();
    let host = host_for_test(
        tmp.path(),
        keystore.clone(),
        Some(config_path.clone()),
        entry,
        token.clone(),
        Some(hooks),
    )
    .await;
    tokio::time::timeout(Duration::from_millis(500), async {
        while probes.load(std::sync::atomic::Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("lock probe started");

    let began = tokio::time::Instant::now();
    token.cancel();
    tokio::time::timeout(Duration::from_millis(500), host.shutdown())
        .await
        .expect("shutdown while the real lock is held");
    assert!(began.elapsed() < Duration::from_secs(1));
    assert_eq!(
        std::fs::read(&services_path).expect("read services file after cancellation"),
        original
    );
    assert_eq!(keystore_address(&keystore, "web"), None);
    assert!(
        matches!(probe_keystore_lock(&keystore), LockProbe::Busy),
        "the held external lock remains held"
    );
    drop(held);
    let LockProbe::Acquired(reacquired) = probe_keystore_lock(&keystore) else {
        panic!("no cancelled waiter remains after releasing the lock");
    };
    drop(reacquired);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preparation_panic_sets_every_host_status_to_internal() {
    let (tmp, config_path, keystore) = temp_config();
    let entries = vec![service("web"), service("relay")];
    proxy_config::Config::write_onion_services(&config_path, &entries)
        .expect("write services file");
    let hooks = HostTestHooks {
        prepare_all: Some(Arc::new(|_, _, _| -> Vec<keys::PreparedService> {
            panic!("prepare panic seam")
        })),
        ..Default::default()
    };
    let mut config =
        OnionHostConfig::new(test_handle(tmp.path()), keystore, CancellationToken::new())
            .with_entries(entries)
            .with_config_path(Some(config_path));
    config.test_hooks = Some(hooks);
    let host = OnionHost::new(config).start();
    for nickname in ["web", "relay"] {
        let state = wait_for_status(&host, nickname, ServiceStatus::Failed).await;
        assert_eq!(state.failure, Some(ServiceFailure::Internal));
    }
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lock_probe_panic_is_internal_and_lock_errors_are_typed() {
    let (tmp, _config_path, keystore) = temp_config();
    let entry = service("web");
    let hooks = HostTestHooks {
        lock_probe: Some(Arc::new(|_| panic!("lock probe panic seam"))),
        ..Default::default()
    };
    let host = host_for_test(
        tmp.path(),
        keystore,
        None,
        entry,
        CancellationToken::new(),
        Some(hooks),
    )
    .await;
    let state = wait_for_status(&host, "web", ServiceStatus::Failed).await;
    assert_eq!(state.failure, Some(ServiceFailure::Internal));
    host.shutdown().await;

    let (tmp, _config_path, keystore) = temp_config();
    let entry = service("web");
    let held = persist_lock::PathLock::acquire_bounded(&keystore, Duration::from_secs(1))
        .expect("hold lock");
    let host = host_for_test(
        tmp.path(),
        keystore,
        None,
        entry,
        CancellationToken::new(),
        Some(HostTestHooks {
            lock_wait: Some(Duration::ZERO),
            ..Default::default()
        }),
    )
    .await;
    let state = wait_for_status(&host, "web", ServiceStatus::Failed).await;
    assert_eq!(state.failure, Some(ServiceFailure::KeystoreLockHeld));
    host.shutdown().await;
    drop(held);

    let (tmp, _config_path, base) = temp_config();
    std::fs::write(&base, b"not a directory").expect("create blocking parent file");
    let unavailable = base.join("keystore");
    let host = host_for_test(
        tmp.path(),
        unavailable,
        None,
        service("web"),
        CancellationToken::new(),
        Some(HostTestHooks {
            lock_wait: Some(Duration::ZERO),
            ..Default::default()
        }),
    )
    .await;
    let state = wait_for_status(&host, "web", ServiceStatus::Failed).await;
    assert_eq!(state.failure, Some(ServiceFailure::KeystoreUnavailable));
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preparation_failure_reason_reaches_host_status() {
    let (tmp, _config_path, keystore) = temp_config();
    let entry = service("not a valid nickname");
    let host = host_for_test(
        tmp.path(),
        keystore,
        None,
        entry,
        CancellationToken::new(),
        None,
    )
    .await;
    let state = wait_for_status(&host, "not a valid nickname", ServiceStatus::Failed).await;
    assert_eq!(state.failure, Some(ServiceFailure::InvalidNickname));
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_arti_address_mismatch_fails_and_releases_the_service_without_serving() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let config_path = tmp.path().join("tor-socks5.ktav");
    let keystore = tmp.path().join("state").join("keystore");
    let entry = service("web");
    proxy_config::Config::write_onion_services(&config_path, std::slice::from_ref(&entry))
        .expect("write services file");

    let service_weak = Arc::new(std::sync::Mutex::new(
        None::<std::sync::Weak<tor_hsservice::RunningOnionService>>,
    ));
    let captured_service = service_weak.clone();
    let served = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let served_count = served.clone();
    let prepare_entry = entry.clone();
    let hooks = HostTestHooks {
        prepare_all: Some(Arc::new(move |path, keystore, entries| {
            let mut prepared = keys::prepare_all(path, keystore, entries);
            let expected_address = prepared[0].address.clone();
            assert!(expected_address.is_some());
            prepared[0].address = Some("expected-address-does-not-match".to_owned());
            prepared
        })),
        service_launched: Some(Arc::new(move |service| {
            *captured_service.lock().expect("capture mutex") = Some(Arc::downgrade(service));
        })),
        serve_started: Some(Arc::new(move || {
            served_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        })),
        ..Default::default()
    };
    let host = host_for_test(
        tmp.path(),
        keystore,
        Some(config_path),
        prepare_entry,
        CancellationToken::new(),
        Some(hooks),
    )
    .await;
    let state = tokio::time::timeout(
        Duration::from_secs(20),
        wait_for_status(&host, "web", ServiceStatus::Failed),
    )
    .await
    .expect("arti returns the actual onion address");
    assert_eq!(state.failure, Some(ServiceFailure::AddressMismatch));
    assert_eq!(served.load(std::sync::atomic::Ordering::SeqCst), 0);
    let weak = service_weak
        .lock()
        .expect("capture mutex")
        .clone()
        .expect("service was actually launched");
    assert!(weak.upgrade().is_none(), "mismatched service was dropped");
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_after_preparation_marks_unlaunched_entry_stopped() {
    let (tmp, _config_path, keystore) = temp_config();
    let entry = service("web");
    let token = CancellationToken::new();
    let prepare_token = token.clone();
    let prepared_entry = entry.clone();
    let launches = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let launch_count = launches.clone();
    let hooks = HostTestHooks {
        prepare_all: Some(Arc::new(move |_, _, _| {
            prepare_token.cancel();
            vec![keys::PreparedService {
                entry: prepared_entry.clone(),
                address: Some("expected-address".to_owned()),
                failure: None,
            }]
        })),
        service_launched: Some(Arc::new(move |_| {
            launch_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        })),
        ..Default::default()
    };
    let host = host_for_test(tmp.path(), keystore, None, entry, token, Some(hooks)).await;
    let state = wait_for_status(&host, "web", ServiceStatus::Stopped).await;
    assert_eq!(state.failure, None);
    assert_eq!(launches.load(std::sync::atomic::Ordering::SeqCst), 0);
    host.shutdown().await;
}

#[tokio::test]
async fn dropping_the_handle_cancels_the_token() {
    let dir = tempfile::tempdir().expect("temp dir");
    let keystore = std::env::temp_dir().join("tor-socks5-onion-host-drop-test");
    let config = OnionHostConfig::new(test_handle(dir.path()), keystore, CancellationToken::new());
    let host_handle = OnionHost::new(config).start();
    let token = host_handle.token().clone();
    assert!(!token.is_cancelled());
    std::mem::drop(host_handle);
    assert!(token.is_cancelled(), "Drop cancelled the token");
}
