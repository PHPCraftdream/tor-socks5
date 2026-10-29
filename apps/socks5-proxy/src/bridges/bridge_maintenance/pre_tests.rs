use super::*;

pub(super) struct LoopControl {
    pub(super) started: std::sync::atomic::AtomicUsize,
    request: tokio::sync::Notify,
    events: tokio::sync::mpsc::Sender<&'static str>,
    ack: tokio::sync::Semaphore,
}

impl LoopControl {
    pub(super) async fn completed(&self) {
        self.events.send("completed").await.unwrap();
        self.ack.acquire().await.unwrap().forget();
    }

    pub(super) async fn idle(&self) {
        self.request.notified().await;
        self.events.send("idle").await.unwrap();
        self.ack.acquire().await.unwrap().forget();
    }
}

pub(super) struct Probe {
    pub(super) entered: std::sync::atomic::AtomicUsize,
    pub(super) ready: bool,
}

pub(super) fn probe(ready: bool) -> std::sync::Arc<Probe> {
    std::sync::Arc::new(Probe {
        entered: std::sync::atomic::AtomicUsize::new(0),
        ready,
    })
}

async fn observe_pre(mut peer: tokio::net::TcpStream, credentials: bool) -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut greeting = [0; 2];
    peer.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting[0], 5);
    let mut methods = vec![0; usize::from(greeting[1])];
    peer.read_exact(&mut methods).await.unwrap();
    let method = if credentials { 2 } else { 0 };
    assert!(methods.contains(&method));
    peer.write_all(&[5, method]).await.unwrap();
    if credentials {
        let mut header = [0; 2];
        peer.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], 1);
        let mut user = vec![0; usize::from(header[1])];
        peer.read_exact(&mut user).await.unwrap();
        let mut length = [0; 1];
        peer.read_exact(&mut length).await.unwrap();
        let mut password = vec![0; usize::from(length[0])];
        peer.read_exact(&mut password).await.unwrap();
        assert_eq!(user, b"alice");
        assert_eq!(password, b"secret");
        peer.write_all(&[1, 0]).await.unwrap();
    }
    let mut request = [0; 10];
    peer.read_exact(&mut request).await.unwrap();
    assert_eq!(&request[..8], &[5, 1, 0, 1, 127, 0, 0, 1]);
    let port = u16::from_be_bytes([request[8], request[9]]);
    peer.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    port
}

/// cancel-safe: НЕТ — при отмене закрываются частично обработанные соединения наблюдателя.
async fn drive_observer<F: Future>(
    operation: F,
    proxy: &tokio::net::TcpListener,
    directs: &[tokio::net::TcpListener; 3],
    credentials: bool,
    expected: [u16; 2],
) -> F::Output {
    use futures::StreamExt;
    let mut exchanges = futures::stream::FuturesUnordered::new();
    let mut operation = Box::pin(operation);
    let mut result = None;
    let mut seen = [false; 2];
    tokio::time::timeout(Duration::from_secs(40), async {
        loop {
            if result.is_some() && seen.iter().all(|value| *value) && exchanges.is_empty() {
                break;
            }
            tokio::select! {
                value = &mut operation, if result.is_none() => result = Some(value),
                accepted = proxy.accept(), if exchanges.len() < 16 => {
                    let (peer, _) = accepted.unwrap();
                    exchanges.push(observe_pre(peer, credentials));
                },
                Some(port) = exchanges.next(), if !exchanges.is_empty() => {
                    assert!(directs.iter().any(|listener| listener.local_addr().unwrap().port() == port));
                    for (index, expected_port) in expected.iter().enumerate() {
                        seen[index] |= port == *expected_port;
                    }
                },
                accepted = directs[0].accept() => panic!("прямое подключение: {accepted:?}"),
                accepted = directs[1].accept() => panic!("прямое подключение: {accepted:?}"),
                accepted = directs[2].accept() => panic!("прямое подключение: {accepted:?}"),
            }
        }
    }).await.expect("наблюдение не завершилось");
    result.unwrap()
}

#[tokio::test]
async fn pre_refresh_and_heal_relaunch_through_same_proxy() {
    use futures::FutureExt;
    let _ = rustls::crypto::ring::default_provider().install_default();
    for credentials in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let directs = [
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(),
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(),
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(),
        ];
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = directs[1].local_addr().unwrap();
        let initial = directs[0].local_addr().unwrap();
        let later = directs[2].local_addr().unwrap();
        let endpoint = if credentials {
            format!("{}|alice:secret", proxy.local_addr().unwrap())
        } else {
            proxy.local_addr().unwrap().to_string()
        };
        let mut cfg = Config::default();
        cfg.pre_socks5 = Some(proxy_config::EndpointOverride::Endpoint(
            endpoint.parse().unwrap(),
        ));
        cfg.bridges.use_seeds = false;
        cfg.bridges.auto_fetch = false;
        cfg.bridges.lines = vec![format!(
            "{address} 1111111111111111111111111111111111111111"
        )];
        let path = dir.path().join("proxy.ktav");
        cfg.write(&path).unwrap();
        let mut active = crate::tor_setup::build_tor_settings(&cfg, Some(&path))
            .await
            .unwrap();
        // Bootstrap использует отдельный адрес и идентичность от проверяемого кандидата.
        active.bridges = vec![
            format!("{initial} 3333333333333333333333333333333333333333")
                .parse()
                .unwrap(),
        ];
        let tor = arti_wrapper::TorTunnel::create_unbootstrapped_with(active.clone()).unwrap();
        // Инициализируем менеджер как в обычном bootstrap; ожидание сохраняется до конца проверки.
        let mut bootstrap = Box::pin(tor.wait_bootstrapped());
        assert!(futures::poll!(bootstrap.as_mut()).is_pending());
        let handle = TorHandle::new(tor.clone());
        let original = active.bridges.clone();
        let mut next_recovery = Instant::now();
        let mut cursor = 0;
        let observations = ObservationSink::new();
        let bridge: BridgeLine = format!("{later} 4444444444444444444444444444444444444444")
            .parse()
            .unwrap();
        drive_observer(
            async {
                let result = refresh(
                    &handle,
                    Some(&path),
                    &observations,
                    &mut active,
                    &mut next_recovery,
                    &mut cursor,
                )
                .await;
                assert!(result.is_err());
                assert_eq!(active.bridges, original);
                assert!(crate::tor_watchdog::test_heal(&tor).await);
                let ready = crate::tor_watchdog::route_bridge_count(
                    &tor,
                    std::slice::from_ref(&bridge),
                    Some(&path),
                )
                .await;
                assert_eq!(ready, 0);
            },
            &proxy,
            &directs,
            credentials,
            [address.port(), later.port()],
        )
        .await;
        assert!(directs
            .iter()
            .all(|listener| listener.accept().now_or_never().is_none()));

        // Ошибочные перезагрузки проверяются на отдельном клиенте без bootstrap.
        let isolated = tempfile::tempdir().unwrap();
        let quiet_proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let quiet_endpoint = quiet_proxy.local_addr().unwrap().to_string();
        cfg.pre_socks5 = Some(proxy_config::EndpointOverride::Endpoint(
            quiet_endpoint.parse().unwrap(),
        ));
        let mut active = crate::tor_setup::build_tor_settings(&cfg, Some(isolated.path()))
            .await
            .unwrap();
        let tor = arti_wrapper::TorTunnel::create_unbootstrapped_with(active.clone()).unwrap();
        let handle = TorHandle::new(tor.clone());
        cfg.bridges.use_seeds = true;
        assert!(refresh_pre(
            &handle,
            Some(dir.path()),
            &mut active,
            &cfg,
            &tor,
            tor.configured_pre_endpoint().unwrap().unwrap()
        )
        .await
        .is_err());
        assert!(quiet_proxy.accept().now_or_never().is_none());
        cfg.bridges.use_seeds = false;
        cfg.pre_socks5 = Some(proxy_config::EndpointOverride::Disabled);
        assert!(refresh_pre(
            &handle,
            Some(dir.path()),
            &mut active,
            &cfg,
            &tor,
            tor.configured_pre_endpoint().unwrap().unwrap()
        )
        .await
        .is_err());
        cfg.pre_socks5 = Some(proxy_config::EndpointOverride::Endpoint(
            quiet_endpoint.parse().unwrap(),
        ));
        cfg.bridges.lines.push(format!(
            "obfs4 {address} 2222222222222222222222222222222222222222 cert=AAA"
        ));
        assert!(refresh_pre(
            &handle,
            Some(dir.path()),
            &mut active,
            &cfg,
            &tor,
            tor.configured_pre_endpoint().unwrap().unwrap()
        )
        .await
        .is_err());
        assert!(quiet_proxy.accept().now_or_never().is_none());
        assert!(directs
            .iter()
            .all(|listener| listener.accept().now_or_never().is_none()));
    }
}

#[tokio::test]
async fn refresh_activates_selected_route_and_preserves_credentials() {
    use futures::FutureExt;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("proxy.ktav");
    let direct = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let candidate: BridgeLine = format!(
        "{} 2222222222222222222222222222222222222222",
        direct.local_addr().unwrap()
    )
    .parse()
    .unwrap();
    let mut cfg = Config::default();
    cfg.bridges.use_seeds = false;
    cfg.bridges.auto_fetch = false;
    cfg.bridges.lines = vec![candidate.to_string()];
    cfg.pre_socks5 = Some(proxy_config::EndpointOverride::Endpoint(
        format!("{}|alice:secret", proxy.local_addr().unwrap())
            .parse()
            .unwrap(),
    ));
    cfg.write(&path).unwrap();
    let mut active = crate::tor_setup::build_tor_settings(&cfg, Some(&path))
        .await
        .unwrap();
    active.bridges = vec!["8.8.8.8:443 1111111111111111111111111111111111111111"
        .parse()
        .unwrap()];
    let tor = arti_wrapper::TorTunnel::create_unbootstrapped_with(active.clone()).unwrap();
    let handle = TorHandle::new(tor.clone());
    let probe = probe(true);
    let mut next = Instant::now();
    let mut cursor = 0;
    PRE_PROBE
        .scope(
            probe.clone(),
            refresh(
                &handle,
                Some(&path),
                &ObservationSink::new(),
                &mut active,
                &mut next,
                &mut cursor,
            ),
        )
        .await
        .unwrap();
    assert_eq!(probe.entered.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(active.bridges, vec![candidate.clone()]);
    assert_eq!(handle.active_bridges(), vec![candidate.clone()]);
    assert_eq!(
        active.pre_endpoint.as_ref(),
        tor.configured_pre_endpoint().unwrap()
    );
    let mut bootstrap = Box::pin(tor.wait_bootstrapped());
    assert!(futures::poll!(bootstrap.as_mut()).is_pending());
    let warm = tor.warm_bridge(&candidate);
    tokio::pin!(warm);
    let mut exchanges = futures::stream::FuturesUnordered::new();
    use futures::StreamExt;
    let mut seen = false;
    let mut finished = false;
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if finished && seen && exchanges.is_empty() { break; }
            tokio::select! {
                result = &mut warm, if !finished => { assert!(result.is_err()); finished = true; },
                result = direct.accept() => panic!("прямое подключение: {result:?}"),
                result = proxy.accept(), if exchanges.len() < 8 => exchanges.push(observe_pre(result.unwrap().0, true)),
                Some(port) = exchanges.next(), if !exchanges.is_empty() => { assert_eq!(port, direct.local_addr().unwrap().port()); seen = true; },
            }
        }
    }).await.unwrap();
    assert!(seen);
    assert!(direct.accept().now_or_never().is_none());
}

#[tokio::test(start_paused = true)]
async fn failed_pre_refresh_delays_recovery_notification() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("proxy.ktav");
    let mut cfg = Config::default();
    cfg.bridges.use_seeds = false;
    cfg.bridges.auto_fetch = false;
    cfg.bridges.lines = vec!["8.8.8.8:443 1111111111111111111111111111111111111111".into()];
    cfg.pre_socks5 = Some(proxy_config::EndpointOverride::Endpoint(
        "127.0.0.1:1080".parse().unwrap(),
    ));
    cfg.write(&path).unwrap();
    let active = crate::tor_setup::build_tor_settings(&cfg, Some(&path))
        .await
        .unwrap();
    let handle = TorHandle::new(
        arti_wrapper::TorTunnel::create_unbootstrapped_with(active.clone()).unwrap(),
    );
    let probe = probe(false);
    let (events, mut received) = tokio::sync::mpsc::channel(4);
    let control = std::sync::Arc::new(LoopControl {
        started: AtomicUsize::new(0),
        request: tokio::sync::Notify::new(),
        events,
        ack: tokio::sync::Semaphore::new(0),
    });
    let token = CancellationToken::new();
    let task = LOOP_CONTROL
        .scope(
            control.clone(),
            PRE_PROBE.scope(probe.clone(), async {
                spawn(
                    handle.clone(),
                    Some(path),
                    0,
                    ObservationSink::new(),
                    active,
                    token.clone(),
                )
            }),
        )
        .await;
    assert_eq!(received.recv().await, Some("completed"));
    assert_eq!(probe.entered.load(Ordering::SeqCst), 1);
    handle.bridge_refresh().recovery().notify_one();
    handle.bridge_refresh().recovery().notify_one();
    control.ack.add_permits(1);
    tokio::time::advance(Duration::from_secs(14)).await;
    control.request.notify_one();
    assert_eq!(received.recv().await, Some("idle"));
    assert_eq!(control.started.load(Ordering::SeqCst), 1);
    control.ack.add_permits(1);
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(received.recv().await, Some("completed"));
    assert_eq!(control.started.load(Ordering::SeqCst), 2);
    assert_eq!(probe.entered.load(Ordering::SeqCst), 2);
    token.cancel();
    control.ack.add_permits(1);
    task.await.unwrap();
}

#[tokio::test]
async fn invalid_reload_fails_before_readiness() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("proxy.ktav");
    let mut cfg = Config::default();
    cfg.bridges.use_seeds = false;
    cfg.bridges.auto_fetch = false;
    cfg.bridges.lines = vec!["8.8.8.8:443 1111111111111111111111111111111111111111".into()];
    cfg.pre_socks5 = Some(proxy_config::EndpointOverride::Endpoint(
        "127.0.0.1:1080|alice:secret".parse().unwrap(),
    ));
    let mut active = crate::tor_setup::build_tor_settings(&cfg, Some(&path))
        .await
        .unwrap();
    let tor = arti_wrapper::TorTunnel::create_unbootstrapped_with(active.clone()).unwrap();
    let handle = TorHandle::new(tor);
    let original = active.bridges.clone();
    for (case, expected) in [
        (0, "изменение pre требует перезапуска"),
        (
            1,
            "pre_socks5 requires bridges.use_seeds and bridges.auto_fetch to be disabled",
        ),
        (2, "pre_socks5 does not support pluggable transport bridges"),
        (3, "pre_socks5 is incompatible with warm_pool.enabled"),
        (4, "pre несовместим с upstream"),
        (
            5,
            "pre_socks5 requires bridges.use_seeds and bridges.auto_fetch to be disabled",
        ),
        (6, "изменение pre требует перезапуска"),
    ] {
        let mut changed = cfg.clone();
        match case {
            0 => changed.pre_socks5 = Some(proxy_config::EndpointOverride::Disabled),
            1 => changed.bridges.use_seeds = true,
            2 => changed
                .bridges
                .lines
                .push("obfs4 8.8.4.4:443 2222222222222222222222222222222222222222 cert=AAA".into()),
            3 => changed.warm_pool.enabled = true,
            4 => changed.upstream.enabled = true,
            5 => changed.bridges.auto_fetch = true,
            _ => {
                changed.pre_socks5 = Some(proxy_config::EndpointOverride::Endpoint(
                    "127.0.0.1:1080|alice:changed".parse().unwrap(),
                ))
            }
        }
        changed.write(&path).unwrap();
        let probe = probe(true);
        let mut next = Instant::now();
        let mut cursor = 0;
        let error = PRE_PROBE
            .scope(
                probe.clone(),
                refresh(
                    &handle,
                    Some(&path),
                    &ObservationSink::new(),
                    &mut active,
                    &mut next,
                    &mut cursor,
                ),
            )
            .await
            .unwrap_err();
        assert_eq!(error.root_cause().to_string(), expected);
        assert_eq!(probe.entered.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(active.bridges, original);
    }
}

#[tokio::test]
async fn pre_activate_reconfigures_real_client_and_rejects_route_removal() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let first: BridgeLine = "8.8.8.8:443 1111111111111111111111111111111111111111"
        .parse()
        .unwrap();
    let second: BridgeLine = "8.8.4.4:443 2222222222222222222222222222222222222222"
        .parse()
        .unwrap();
    let mut active = Settings {
        state_dir: Some(dir.path().into()),
        bridges: vec![first.clone()],
        pre_endpoint: Some(arti_wrapper::Socks5PreEndpoint::new(
            "127.0.0.1:1080".parse().unwrap(),
            Some(("alice".into(), "secret".into())),
        )),
        ..Settings::default()
    };
    let tor = arti_wrapper::TorTunnel::create_unbootstrapped_with(active.clone()).unwrap();
    let handle = TorHandle::new(tor.clone());
    let mut selected = active.clone();
    selected.bridges = vec![second.clone()];
    let mut without_pre = selected.clone();
    without_pre.pre_endpoint = None;
    assert!(activate(&handle, &mut active, without_pre, &tor).is_err());
    assert_eq!(active.bridges, vec![first]);
    activate(&handle, &mut active, selected, &tor).unwrap();
    assert_eq!(active.bridges, vec![second.clone()]);
    assert_eq!(handle.active_bridges(), vec![second]);
    assert_eq!(
        tor.configured_pre_endpoint().unwrap(),
        active.pre_endpoint.as_ref()
    );
}
