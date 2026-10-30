use super::*;
use tokio::io::AsyncReadExt;

async fn proxy_connection(
    mut stream: TcpStream,
    events: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
) {
    let mut header = [0; 2];
    stream.read_exact(&mut header).await.unwrap();
    assert_eq!(header[0], 5);
    let mut methods = vec![0; header[1] as usize];
    stream.read_exact(&mut methods).await.unwrap();
    assert!(methods.contains(&2));
    stream.write_all(&[5, 2]).await.unwrap();
    stream.read_exact(&mut header).await.unwrap();
    assert_eq!(header[0], 1);
    let mut user = vec![0; header[1] as usize];
    stream.read_exact(&mut user).await.unwrap();
    let pass_len = stream.read_u8().await.unwrap();
    let mut pass = vec![0; pass_len as usize];
    stream.read_exact(&mut pass).await.unwrap();
    assert_eq!(user, b"alice");
    assert!(pass == b"first" || pass == b"second");
    stream.write_all(&[1, 0]).await.unwrap();
    let mut request = [0; 4];
    stream.read_exact(&mut request).await.unwrap();
    assert_eq!(request, [5, 1, 0, 1]);
    let mut address = [0; 6];
    stream.read_exact(&mut address).await.unwrap();
    assert_eq!(address, [127, 0, 0, 77, 1, 187]);
    stream
        .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut carrier = [0; 1];
    stream.read_exact(&mut carrier).await.unwrap();
    events.send(pass).unwrap();
    let mut discard = [0; 1024];
    while stream.read(&mut discard).await.unwrap_or(0) != 0 {}
}

fn pids(dir: &std::path::Path, found: &mut Vec<(std::path::PathBuf, u32)>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pids(&path, found);
            } else if path
                .file_name()
                .is_some_and(|name| name == "owner-contract-pid")
            {
                found.push((
                    path.clone(),
                    std::fs::read_to_string(path).unwrap().parse().unwrap(),
                ));
            }
        }
    }
}

// Уровень проверки: производственная граница OwnerRegistry/admission (реальный
// обработчик владельцев из src), с реальными штатными дочерними процессами
// lyrebird (obfs4), запущенными настоящим PT-менеджером. Сетевой bootstrap Tor
// и маршрут supplied-CLI/конфиг -> обработчик НЕ покрываются; это не сквозной
// тест Tor. WebTunnel проверяется отдельно на уровне дочернего процесса в
// .github/pt_proxy/contract.py.
pub(crate) async fn run_pt_owner_contract() {
    tokio::time::timeout(Duration::from_secs(90), async {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy.local_addr().unwrap();
        let direct = TcpListener::bind("127.0.0.77:443").await.unwrap();
        let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut proxy_task = AbortOnDrop(tokio::spawn(async move {
            let mut workers = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = proxy.accept() => {
                        let (stream, _) = accepted.unwrap();
                        workers.spawn(proxy_connection(stream, events_tx.clone()));
                    }
                    Some(result) = workers.join_next(), if !workers.is_empty() => { result.unwrap(); }
                }
            }
        }));
        let (direct_tx, direct_rx) = tokio::sync::oneshot::channel();
        let mut direct_task = AbortOnDrop(tokio::spawn(async move {
            let (mut stream, _) = direct.accept().await.unwrap();
            let mut byte = [0; 1];
            stream.read_exact(&mut byte).await.unwrap();
            direct_tx.send(()).unwrap();
            let mut discard = [0; 1024];
            while stream.read(&mut discard).await.unwrap_or(0) != 0 {}
        }));
        let settings = Settings {
            pre_endpoint: Some(Socks5PreEndpoint::new(proxy_address, Some(("alice".into(), "global".into())))),
            pt_binary: Some(std::env::current_exe().unwrap()),
            stock_pt_proxy: true,
            bridges: vec!["obfs4 127.0.0.77:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=EREREREREREREREREREREREREREiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIg iat-mode=0".parse().unwrap()],
            state_dir: Some(dir.path().join("global")),
            ..Default::default()
        };
        let global = TorTunnel::create_unbootstrapped_with(settings.clone()).unwrap();
        let registry = OwnerRegistry::new(TorHandle::new(global), settings).unwrap();
        let path = dir.path().join("users.ktav");
        let users = auth::UsersConfig { users: [("one", Some("first")), ("two", Some("second")), ("direct", None)].into_iter().map(|(name, password)| auth::User {
            name: name.into(), hash: auth::compute_hash("pw").unwrap(), is_enabled: true,
            allowed_onion: false, allowed_clients: None,
            pre_socks5: Some(match password {
                Some(password) => proxy_config::EndpointOverride::Endpoint(format!("{proxy_address}|alice:{password}").parse().unwrap()),
                None => proxy_config::EndpointOverride::Disabled,
            }),
            post_socks5: None,
        }).collect() };
        users.save(&path).unwrap();
        let auth = Arc::new(auth::AuthState::build_persistent(&users, path).unwrap());
        let state = auth.clone();
        let proofs = tokio::task::spawn_blocking(move || ["one", "two", "direct"].map(|name| state.verify_proof(name, "pw").unwrap())).await.unwrap();
        let a = auth.admit(&proofs[0]).await.unwrap();
        let b = auth.admit(&proofs[1]).await.unwrap();
        let c = auth.admit(&proofs[2]).await.unwrap();
        let duplicate = auth.admit(&proofs[0]).await.unwrap();
        let mut select_a = Box::pin(registry.select_admitted(&a));
        let mut select_b = Box::pin(registry.select_admitted(&b));
        let mut select_c = Box::pin(registry.select_admitted(&c));
        let mut select_duplicate = Box::pin(registry.select_admitted(&duplicate));
        tokio::select! {
            result = &mut select_a => panic!("first owner completed: {}", result.is_ok()),
            result = &mut select_b => panic!("second owner completed: {}", result.is_ok()),
            result = &mut select_c => panic!("direct owner completed: {}", result.is_ok()),
            result = &mut select_duplicate => panic!("duplicate owner completed: {}", result.is_ok()),
            result = &mut proxy_task.0 => panic!("proxy stopped: {result:?}"),
            result = &mut direct_task.0 => panic!("direct trap stopped: {result:?}"),
            _ = async {
                let mut seen = vec![events_rx.recv().await.unwrap(), events_rx.recv().await.unwrap()];
                seen.sort();
                assert_eq!(seen, vec![b"first".to_vec(), b"second".to_vec()]);
                direct_rx.await.unwrap();
            } => {}
        }
        let entries = registry.state.lock().await.entries.clone();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries.iter().filter(|e| e.pre.is_none()).count(), 1);
        let mut children = Vec::new();
        pids(dir.path(), &mut children);
        assert_eq!(children.len(), 3);
        children.sort();
        let mut ids: Vec<_> = children.iter().map(|(_, pid)| *pid).collect();
        for (path, _) in &children {
            assert!(path.starts_with(dir.path().join("global/owners-v1")));
        }
        let mut owner_paths: Vec<_> = children.iter().map(|(path, _)| path.parent().unwrap().to_path_buf()).collect();
        owner_paths.sort();
        owner_paths.dedup();
        assert_eq!(owner_paths.len(), 3);
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 3);
        assert!(ids.iter().all(|pid| std::path::Path::new(&format!("/proc/{pid}")).exists()));
        drop((select_a, select_b, select_c, select_duplicate));
        drop((a, b, c, duplicate));
        registry.close_with_deadline(Instant::now() + Duration::from_secs(20)).await.unwrap();
        (&mut direct_task.0).await.unwrap();
        proxy_task.0.abort();
        let _ = (&mut proxy_task.0).await;
        for pid in ids { assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists(), "PT child {pid} survived shutdown"); }
    }).await.expect("owner PT contract timed out");
}
