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
async fn route_argument_comes_from_admission_lease() {
    let dir = tempfile::tempdir().unwrap();
    let registry = registry(dir.path());
    let path = dir.path().join("users.ktav");
    let pre =
        proxy_config::EndpointOverride::Endpoint("127.0.0.1:1080|alice:global".parse().unwrap());
    let users = auth::UsersConfig {
        users: vec![auth::User {
            name: "test".into(),
            hash: auth::compute_hash("pw").unwrap(),
            is_enabled: true,
            allowed_onion: false,
            allowed_clients: None,
            pre_socks5: Some(pre),
            post_socks5: None,
        }],
    };
    users.save(&path).unwrap();
    let auth = Arc::new(auth::AuthState::build_persistent(&users, path).unwrap());
    let proof = auth.verify_proof("test", "pw").unwrap();
    let lease = auth.admit(&proof).await.unwrap();
    let owner = registry.select_admitted(&lease).await.unwrap();
    assert!(owner.global_handle().is_some());
    assert!(registry.state.lock().await.entries.is_empty());
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
    assert!(entry.state.lock().await.constructing.is_none());
    assert!(entry.state.lock().await.tunnel.is_none());
    registry
        .close_with_deadline(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    assert!(entry.state.lock().await.constructing.is_none());
}

#[tokio::test]
async fn close_reports_panicked_constructor_then_retry_completes() {
    let dir = tempfile::tempdir().unwrap();
    let registry = registry(dir.path());
    let entry = registry
        .reserve(Some(endpoint("panicked-close")))
        .await
        .unwrap()
        .unwrap();
    {
        let mut state = entry.state.lock().await;
        state.attempted = true;
        state.constructing = Some(tokio::task::spawn_blocking(|| -> Result<Constructed> {
            panic!("constructor panic secret");
        }));
    }

    let error = registry
        .close_with_deadline(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "задача владельца завершилась ошибкой при закрытии"
    );
    assert!(!error.to_string().contains("constructor panic secret"));
    assert!(entry.state.lock().await.constructing.is_none());
    assert!(entry.state.lock().await.tunnel.is_none());
    registry
        .close_with_deadline(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
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
    assert!(entry.state.lock().await.constructing.is_none());
    assert!(entry.state.lock().await.tunnel.is_none());
    registry.close().await.unwrap();
    assert!(entry.state.lock().await.constructing.is_none());
}
#[cfg(test)]
mod pre_policy_tests {
    use super::super::super::validate_pre_compatibility;

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
