use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

#[derive(Debug)]
enum Event {
    Open(usize, u16),
    Closed(usize, Option<std::io::ErrorKind>),
}

async fn exchange(mut client: TcpStream, id: usize, events: mpsc::Sender<Event>) {
    let mut upstream =
        tokio::time::timeout(Duration::from_secs(15), handshake(&mut client, id, &events))
            .await
            .expect("тайм-аут SOCKS");
    let close_error = match tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
        Ok(_) => None,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::UnexpectedEof
            ) =>
        {
            Some(error.kind())
        }
        Err(error) => panic!("ошибка передачи SOCKS: {error}"),
    };
    events
        .send(Event::Closed(id, close_error))
        .await
        .expect("наблюдатель событий закрыт");
}

async fn handshake(client: &mut TcpStream, id: usize, events: &mpsc::Sender<Event>) -> TcpStream {
    let mut header = [0; 2];
    client.read_exact(&mut header).await.unwrap();
    assert_eq!(header[0], 5);
    let mut methods = vec![0; usize::from(header[1])];
    client.read_exact(&mut methods).await.unwrap();
    assert!(methods.contains(&2));
    client.write_all(&[5, 2]).await.unwrap();
    client.read_exact(&mut header).await.unwrap();
    assert_eq!(header[0], 1);
    let mut user = vec![0; usize::from(header[1])];
    client.read_exact(&mut user).await.unwrap();
    let length = client.read_u8().await.unwrap();
    let mut password = vec![0; usize::from(length)];
    client.read_exact(&mut password).await.unwrap();
    assert_eq!(user, b"alice");
    assert_eq!(password, b"secret");
    client.write_all(&[1, 0]).await.unwrap();
    let mut request = [0; 10];
    client.read_exact(&mut request).await.unwrap();
    assert_eq!(&request[..8], &[5, 1, 0, 1, 127, 0, 0, 1]);
    let port = u16::from_be_bytes([request[8], request[9]]);
    let allowed = ["TOR_REAL_A_PORT", "TOR_REAL_B_PORT"]
        .map(|name| std::env::var(name).unwrap().parse::<u16>().unwrap());
    assert!(allowed.contains(&port));
    let upstream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    client
        .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
        .await
        .unwrap();
    events.send(Event::Open(id, port)).await.unwrap();
    upstream
}

async fn proxy(listener: TcpListener, events: mpsc::Sender<Event>, token: CancellationToken) {
    let mut children = tokio::task::JoinSet::new();
    let mut id = 0;
    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            accepted = listener.accept(), if children.len() < 16 => {
                let (stream, _) = accepted.unwrap();
                id += 1;
                children.spawn(exchange(stream, id, events.clone()));
            },
            result = children.join_next(), if !children.is_empty() => { result.unwrap().unwrap(); },
        }
    }
    children.abort_all();
    while let Some(result) = children.join_next().await {
        if let Err(error) = result {
            assert!(error.is_cancelled(), "{error}");
        }
    }
}

async fn wait_open(events: &mut mpsc::Receiver<Event>, port: u16) -> usize {
    tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            match events.recv().await.expect("наблюдатель завершился") {
                Event::Open(id, actual) if actual == port => return id,
                Event::Open(_, actual) => panic!("неожиданный мост: {actual}"),
                Event::Closed(_, _) => {}
            }
        }
    })
    .await
    .expect("нет подключения к мосту")
}

#[tokio::test]
#[ignore = "изолированная сеть GitHub CI"]
async fn real_channel_heal_and_config_selection() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let a = std::env::var("TOR_REAL_A_BRIDGE").expect("нет локального моста A");
    let b = std::env::var("TOR_REAL_B_BRIDGE").expect("нет локального моста B");
    let a_port: u16 = std::env::var("TOR_REAL_A_PORT").unwrap().parse().unwrap();
    let b_port: u16 = std::env::var("TOR_REAL_B_PORT").unwrap().parse().unwrap();
    let a_bridge: BridgeLine = a.parse().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("proxy.ktav");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("{}|alice:secret", listener.local_addr().unwrap());
    let (tx, mut rx) = mpsc::channel(64);
    let token = CancellationToken::new();
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(proxy(listener, tx, token.clone()));
    let mut cfg = Config {
        pre_socks5: Some(proxy_config::EndpointOverride::Endpoint(
            endpoint.parse().unwrap(),
        )),
        ..Config::default()
    };
    cfg.bridges.use_seeds = false;
    cfg.bridges.auto_fetch = false;
    cfg.bridges.lines = vec![a.clone()];
    cfg.write(&path).unwrap();
    let mut active = crate::tor_setup::build_tor_settings(&cfg, Some(&path))
        .await
        .unwrap();
    let tor = arti_wrapper::TorTunnel::create_unbootstrapped_with(active.clone()).unwrap();
    let handle = TorHandle::new(tor.clone());
    let boot_tor = tor.clone();
    let bootstrap = tasks.spawn(async move {
        let _ = boot_tor.wait_bootstrapped().await;
    });
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if tor.raw().chanmgr().is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("менеджер каналов не запущен");
    assert!(
        tokio::time::timeout(Duration::from_secs(90), tor.warm_bridge(&a_bridge))
            .await
            .unwrap()
            .unwrap()
    );
    let target = a
        .parse::<arti_wrapper::BridgeConfigBuilder>()
        .unwrap()
        .build()
        .unwrap();
    let manager = tor.raw().chanmgr().unwrap();
    let (channel, _) = tokio::time::timeout(
        Duration::from_secs(90),
        manager.get_or_launch(&target, arti_wrapper::ChannelUsage::UserTraffic),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!channel.is_closing(), "канал закрыт до восстановления");
    let mut open = std::collections::HashSet::new();
    open.insert(wait_open(&mut rx, a_port).await);
    while let Ok(event) = rx.try_recv() {
        match event {
            Event::Open(id, port) => {
                assert_eq!(port, a_port);
                open.insert(id);
            }
            Event::Closed(id, _) => {
                open.remove(&id);
            }
        }
    }
    assert!(
        !open.is_empty(),
        "нет открытого соединения до восстановления"
    );
    let old = open.clone();
    let mut reopened = std::collections::HashMap::new();
    let (before_heal, _) = tokio::time::timeout(
        Duration::from_secs(20),
        manager.get_or_launch(&target, arti_wrapper::ChannelUsage::UserTraffic),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        std::sync::Arc::ptr_eq(&channel, &before_heal),
        "исходный канал не переиспользуется"
    );
    assert!(!channel.is_closing(), "канал закрылся до восстановления");
    assert!(crate::tor_watchdog::test_heal(&tor).await);
    tokio::time::timeout(Duration::from_secs(20), async {
        while !channel.is_closing() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("исходный канал менеджера не закрыт");
    tokio::time::timeout(Duration::from_secs(20), async {
        while !open.is_empty() {
            match rx.recv().await.expect("наблюдатель завершился") {
                Event::Closed(id, reason) => {
                    open.remove(&id);
                    reopened.remove(&id);
                    if let Some(reason) = reason {
                        eprintln!("соединение {id} закрыто: {reason:?}");
                    }
                }
                Event::Open(id, port) => {
                    assert_eq!(port, a_port);
                    reopened.insert(id, port);
                }
            }
        }
    })
    .await
    .expect("исходные соединения не закрыты");
    assert!(
        tokio::time::timeout(Duration::from_secs(90), tor.warm_bridge(&a_bridge))
            .await
            .unwrap()
            .unwrap()
    );
    let (replacement, _) = tokio::time::timeout(
        Duration::from_secs(90),
        manager.get_or_launch(&target, arti_wrapper::ChannelUsage::UserTraffic),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!replacement.is_closing());
    assert!(
        !std::sync::Arc::ptr_eq(&channel, &replacement),
        "менеджер вернул старый канал"
    );
    while let Ok(event) = rx.try_recv() {
        match event {
            Event::Open(id, port) => {
                assert_eq!(port, a_port);
                reopened.insert(id, port);
            }
            Event::Closed(id, _) => {
                reopened.remove(&id);
            }
        }
    }
    let second = match reopened.keys().next().copied() {
        Some(id) => id,
        None => wait_open(&mut rx, a_port).await,
    };
    assert!(!old.contains(&second));
    while let Ok(event) = rx.try_recv() {
        if let Event::Open(_, port) = event {
            assert_eq!(port, a_port, "мост B появился до перезагрузки");
        }
    }
    cfg.bridges.lines = vec![b];
    cfg.write(&path).unwrap();
    let probe = super::pre_tests::probe(true);
    let mut next = Instant::now();
    let mut cursor = 0;
    PRE_PROBE
        .scope(
            probe,
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
    assert_eq!(active.bridges.len(), 1);
    assert_eq!(active.bridges[0].to_string(), cfg.bridges.lines[0]);
    assert_eq!(
        active.pre_endpoint.as_ref(),
        tor.configured_pre_endpoint().unwrap()
    );
    assert_eq!(handle.active_bridges(), active.bridges);
    // Наблюдаем запрос дескриптора, выбранного внутренней конфигурацией Arti.
    tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            if matches!(rx.recv().await.expect("наблюдатель завершился"), Event::Open(_, port) if port == b_port) { break; }
        }
    }).await.expect("Arti не выбрал новый мост");
    bootstrap.abort();
    token.cancel();
    while let Some(result) = tasks.join_next().await {
        if let Err(error) = result {
            assert!(error.is_cancelled(), "{error}");
        }
    }
    drop(handle);
    drop(tor);
}
