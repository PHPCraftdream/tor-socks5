// Перед запросом снимается пустой PID-снимок; затем успешный резерв none и
// Записанный StorageAssigned link для plain сверяется с принятым TCP-носителем
// и kernel inode ownership; cumulative watch используется только как readiness.
// Бюджеты — detection deadlines, не строгая общая длительность при OS block:
// async stages используют absolute 55с/40с. Terminal wait удерживает handles,
// поэтому может превысить deadline; failure сохраняется. Sync setup не обещает
// wallclock bound; при просрочке явный guard запрещает spawn. Execution pending.
use super::child_processes::{scan_child_pids, verify_children_gone, KnownChildren};
use super::pt_contract::{
    cleanup_supplied_scenario, read_closed, socks_auth, socks_connect, spawn_supplied_recorder,
    spawn_supplied_trap, tcp_source_owned_by, Overruns,
};
use super::scenario_resources::{RecorderCounters, ScenarioCleanup};
use super::*;
use crate::server::owners::SelectionOutcome;
use futures::FutureExt;
use tokio::io::AsyncReadExt;

// Спецификация pre-override пользователя БЕЗ адресов: supplied_setup сам
// знает proxy/proxy2 адреса и строит Endpoint-override'ы (use-before-decl
// исключён интерфейсом).
#[derive(Clone, Copy)]
enum PreSpec {
    /// Наследовать global-pre (рекордер1/secret).
    Inherit,
    /// Явно отключить наследование ("none", PT ветка None -> прямой dial ловушки).
    Disabled,
    /// Endpoint на ВТОРОЙ рекордер: ЗАМЕНА адреса+пароля СОВМЕСТНО.
    Alt(&'static str),
    /// Endpoint на ПЕРВЫЙ рекордер: тот же address, другой пароль = отдельный владелец.
    SameAddr(&'static str),
}

// Результат supplied_setup — именованная структура вместо кортежа.
struct SuppliedSetup {
    config_path: std::path::PathBuf,
    listener_address: std::net::SocketAddr,
    proxy2_address: std::net::SocketAddr,
    proxy: TcpListener,
    proxy2: TcpListener,
    direct: TcpListener,
}

// Каркас supplied-прогона, общий для обоих сценариев (одна копия): конфиг,
// пользователи, слушатели. Слушатель SOCKS-сервера bind-ится заранее и
// освобождается — порт зафиксирован против гонок.
async fn supplied_setup(
    dir: &std::path::Path,
    specs: Vec<(&'static str, PreSpec)>,
) -> SuppliedSetup {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_address = proxy.local_addr().unwrap();
    // Второй рекордер: alt обязан использовать ЗАМЕНЁННЫЙ адрес+пароль.
    let proxy2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy2_address = proxy2.local_addr().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener_address = listener.local_addr().unwrap();
    drop(listener);
    let mut cfg = crate::config::Config {
        listen: vec![listener_address.to_string()],
        pre_socks5: Some(proxy_config::EndpointOverride::Endpoint(
            format!("{proxy_address}|alice:secret").parse().unwrap(),
        )),
        ..Default::default()
    };
    cfg.log.ansi = true;
    let config_path = dir.join("supplied.ktav");
    std::fs::write(&config_path, ktav::to_string(&cfg).unwrap()).unwrap();
    let loaded = crate::config::Config::load_with_override(Some(&config_path)).unwrap();
    let mut bridges = loaded.into_config();
    bridges.bridges.lines = vec!["obfs4 127.0.0.77:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=EREREREREREREREREREREREREREiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIg iat-mode=0".into()];
    // Guards restricted_owner_settings (owner_settings.rs:24-28) требуют
    // выключенные seeds/auto_fetch в supplied-конфиге.
    bridges.bridges.use_seeds = false;
    bridges.bridges.auto_fetch = false;
    bridges.write_bridges(&config_path).unwrap();
    let users_path = auth::UsersConfig::resolve_path(Some(&config_path));
    let users = auth::UsersConfig {
        users: specs
            .into_iter()
            .map(|(name, spec)| {
                let pre = match spec {
                    PreSpec::Inherit => None,
                    PreSpec::Disabled => Some(proxy_config::EndpointOverride::Disabled),
                    PreSpec::Alt(password) => Some(proxy_config::EndpointOverride::Endpoint(
                        format!("{proxy2_address}|alice:{password}")
                            .parse()
                            .unwrap(),
                    )),
                    PreSpec::SameAddr(password) => Some(proxy_config::EndpointOverride::Endpoint(
                        format!("{proxy_address}|alice:{password}").parse().unwrap(),
                    )),
                };
                auth::User {
                    name: name.into(),
                    hash: auth::compute_hash("pw").unwrap(),
                    is_enabled: true,
                    allowed_onion: false,
                    allowed_clients: None,
                    pre_socks5: pre,
                    post_socks5: None,
                }
            })
            .collect(),
    };
    users.save(&users_path).unwrap();
    SuppliedSetup {
        config_path,
        listener_address,
        proxy2_address,
        proxy,
        proxy2,
        direct: TcpListener::bind("127.0.0.77:443").await.unwrap(),
    }
}

const ALT_USER_ALLOWED: &[&[u8]] = &[b"second"];
const GLOBAL_USER_ALLOWED: &[&[u8]] = &[b"secret", b"secret2"];

// ловушки нет (см. (ii) в комментарии модуля).
pub(crate) async fn run_supplied_config_positive() {
    let _serial = crate::server::owners::TEST_LIFECYCLE.lock().await;
    let total_deadline = tokio::time::Instant::now() + Duration::from_secs(55);
    let body_deadline = total_deadline - Duration::from_secs(18);
    let graceful_deadline = total_deadline - Duration::from_secs(7);
    let terminal_deadline = total_deadline - Duration::from_secs(5);
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let mut known_children = KnownChildren::default();
    let overruns = Overruns::default();
    let panic_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let panic_messages = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let worker_timeouts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let worker_errors = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let aborted_workers = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let trap_accepts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (trap_accepts_tx, mut trap_accepts_rx) = tokio::sync::watch::channel(0usize);
    let setup = supplied_setup(
        dir.path(),
        vec![
            // global наследует global-pre (рекордер1/secret); plain отключает
            // наследование ("none", PT ветка None -> прямой dial ловушки);
            // alt заменяет адрес+учётные данные рекордера СОВМЕСТНО
            // (рекордер2/second); sameaddr — тот же address, другой пароль =
            // отдельный владелец (reserve сравнивает pre целиком).
            ("global", PreSpec::Inherit),
            ("plain", PreSpec::Disabled),
            ("alt", PreSpec::Alt("second")),
            ("sameaddr", PreSpec::SameAddr("secret2")),
        ],
    )
    .await;
    assert!(
        tokio::time::Instant::now() < body_deadline,
        "подготовка превысила body deadline"
    );
    let listener_address = setup.listener_address;
    let alt_route = setup.proxy2_address.to_string();
    let (events1_tx, mut events1_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let (events2_tx, mut events2_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let (traps_tx, mut traps_rx) = tokio::sync::mpsc::channel::<TcpStream>(64);
    let (stop1_tx, stop1_rx) = tokio::sync::watch::channel(());
    // Хэндлы задач и сендеры — ВНЕ таймируемого региона (см. шапку модуля).
    let mut recorder1 = spawn_supplied_recorder(
        setup.proxy,
        stop1_rx,
        GLOBAL_USER_ALLOWED,
        "рекордер1",
        events1_tx,
        RecorderCounters {
            accept_overrun: overruns.recorder1.clone(),
            events_overrun: overruns.events.clone(),
            panic_count: panic_count.clone(),
            panic_messages: panic_messages.clone(),
            worker_timeouts: worker_timeouts.clone(),
            worker_errors: worker_errors.clone(),
            aborted_workers: aborted_workers.clone(),
        },
        None,
    );
    let (stop2_tx, stop2_rx) = tokio::sync::watch::channel(());
    let mut recorder2 = spawn_supplied_recorder(
        setup.proxy2,
        stop2_rx,
        ALT_USER_ALLOWED,
        "рекордер2",
        events2_tx,
        RecorderCounters {
            accept_overrun: overruns.recorder2.clone(),
            events_overrun: overruns.events.clone(),
            panic_count: panic_count.clone(),
            panic_messages: panic_messages.clone(),
            worker_timeouts: worker_timeouts.clone(),
            worker_errors: worker_errors.clone(),
            aborted_workers: aborted_workers.clone(),
        },
        None,
    );
    let direct = Arc::new(setup.direct);
    let mut trap = spawn_supplied_trap(
        Arc::clone(&direct),
        trap_accepts.clone(),
        trap_accepts_tx,
        traps_tx,
        overruns.trap.clone(),
    );
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    // Сендер shutdown — Option: тело positive забирает его для shutdown-
    // свидетеля; cleanup досылает только если тело не дошло до отправки.
    let mut shutdown_tx = Some(shutdown_tx);
    let writer = crate::bridge_store_writer::StoreWriter::spawn(
        bridge_store::BridgeStore::resolve_path(Some(&setup.config_path)),
        Arc::new(|_| Ok(())),
        Duration::from_secs(3600),
    );
    let hook = Arc::new(super::super::super::global_init::ShutdownHook {
        settings: Settings::default(),
        writer,
        ready: std::sync::Mutex::new(Some(ready_tx)),
    });
    let args = super::super::super::ServerArgs {
        config_override: Some(setup.config_path.clone()),
        upstream_addr: None,
        upstream_user: None,
        upstream_pass: None,
        no_upstream: false,
    };
    let mut server = AbortOnDrop(tokio::spawn(
        super::super::super::global_init::RUN_SERVER_CONFIG.scope((), async move {
            super::super::super::global_init::RUN_SERVER_SHUTDOWN
                .scope(hook, async move {
                    super::super::super::run_server(args, async {
                        let _ = shutdown_rx.await;
                    })
                    .await
                })
                .await
        }),
    ));
    // Таймируемый регион — ТОЛЬКО тело сценария; Err вместо unwrap где
    // практично (непрактичные unwrap внутри socks_auth/proxy-помощников —
    // fail-loud, см. шапку).
    let body = async {
        tokio::time::timeout(Duration::from_secs(15), ready_rx)
            .await
            .map_err(|_| "готовность не наступила (15с)")?
            .map_err(|_| "отправитель готовности упал вместе с сервером")?;
        // Перед plain ещё не было клиентских запросов: global/alt CONNECT
        // не должны предшествовать explicit-none attribution carrier.
        known_children
            .refresh(dir.path())
            .map_err(|_| "PT PID scan failed")?;
        let before_plain = scan_child_pids(dir.path())?;
        if !before_plain.is_empty() {
            return Err("PT-процессы существовали до plain carrier".into());
        }
        let probe = crate::server::owners::test_selection_probe();
        let mut plain = socks_auth("plain", "pw", listener_address).await;
        socks_connect(&mut plain).await;
        tokio::time::timeout(Duration::from_secs(8), async {
            while *trap_accepts_rx.borrow_and_update() == 0 {
                trap_accepts_rx
                    .changed()
                    .await
                    .map_err(|_| "отправитель trap_accepts закрылся")?;
            }
            Ok::<(), String>(())
        })
        .await
        .map_err(|_| "ловушка не набрана после plain CONNECT (8с)")??;
        let (plain_observations, dropped) = probe.snapshot();
        let plain_observation = plain_observations
            .iter()
            .rev()
            .find(|o| {
                o.route == "none"
                    && o.event == crate::server::owners::SelectionEvent::Reserved
                    && o.outcome == SelectionOutcome::Reserved
            })
            .ok_or("не найдено успешное наблюдение резервирования explicit-none")?;
        if dropped != 0
            || plain_observation.identity.is_none()
            || plain_observation.storage_slot.is_some()
        {
            return Err("резервирование explicit-none без identity или переполнен журнал".into());
        }
        known_children
            .refresh(dir.path())
            .map_err(|_| "PT PID scan failed")?;
        let plain_pids = scan_child_pids(dir.path())?;
        let plain_slot = plain_observations
            .iter()
            .rev()
            .find(|o| {
                o.request_id == plain_observation.request_id
                    && o.event == crate::server::owners::SelectionEvent::StorageAssigned
                    && o.identity == plain_observation.identity
                    && o.storage_slot.is_some()
            })
            .and_then(|o| o.storage_slot)
            .ok_or("нет события связи записи с storage slot")?;
        let plain_slot_name = plain_slot.to_string();
        let plain_storage = plain_observations
            .iter()
            .rev()
            .find(|o| {
                o.request_id == plain_observation.request_id
                    && o.event == crate::server::owners::SelectionEvent::StorageAssigned
                    && o.outcome == SelectionOutcome::Reserved
                    && o.route == "none"
                    && o.identity == plain_observation.identity
                    && o.storage_slot == Some(plain_slot)
            })
            .ok_or("storage slot не связан с тем же explicit-none reserve")?;
        if plain_storage.request_id != plain_observation.request_id {
            return Err("request_id storage slot не совпал с reserve".into());
        }
        let expected_pt_state =
            crate::tor_setup::arti_base_dir(Some(&dir.path().join("supplied.ktav")))
                .join("owners-v1")
                .join(&plain_slot_name)
                .join("state")
                .join("pt_state");
        let plain_owners = plain_pids
            .iter()
            .filter(|(path, _)| {
                path.strip_prefix(&expected_pt_state).is_ok_and(|suffix| {
                    !suffix.as_os_str().is_empty()
                        && suffix
                            .file_name()
                            .is_some_and(|name| name == "owner-contract-pid")
                })
            })
            .collect::<Vec<_>>();
        if plain_owners.len() != 1 || plain_pids.len() != 1 {
            return Err("plain carrier не создал единственный PT child owners-v1".into());
        }
        let carrier = tokio::time::timeout_at(body_deadline, traps_rx.recv())
            .await
            .map_err(|_| "не пришёл TCP-носитель plain")?
            .ok_or("закрыт канал TCP-носителей")?;
        tcp_source_owned_by(&carrier, plain_owners[0].1)
            .map_err(|_| "TCP-носитель не принадлежит PT explicit-none")?;
        // Наследование global подтверждается отдельным более поздним носителем.
        let mut global_client = socks_auth("global", "pw", listener_address).await;
        socks_connect(&mut global_client).await;
        let secret = tokio::time::timeout(Duration::from_secs(10), events1_rx.recv())
            .await
            .map_err(|_| "носитель secret не пришёл (10с)")?
            .ok_or("рекордер1 закрыт без носителя secret")?;
        // REDACTED-ассерт: пароль-байты не печатаются (только длина).
        if secret.as_slice() != b"secret" {
            return Err(format!(
                "наследуемый носитель не secret: {} байт, не совпало",
                secret.len()
            ));
        }
        known_children
            .refresh(dir.path())
            .map_err(|_| "PT PID scan failed")?;
        // Замена адреса+учётных данных: alt -> отдельный владелец; носитель
        // обязан прийти именно на ВТОРОЙ адрес рекордера (иначе замены нет).
        let mut alt = socks_auth("alt", "pw", listener_address).await;
        socks_connect(&mut alt).await;
        let second_found = tokio::time::timeout(Duration::from_secs(10), async {
            let mut found = false;
            while let Some(carrier) = events2_rx.recv().await {
                if carrier == b"second" {
                    found = true;
                    break;
                }
            }
            found
        })
        .await
        .map_err(|_| "носитель second не пришёл (10с)")?;
        if !second_found {
            return Err("рекордер2 закрыт без носителя second".into());
        }
        known_children
            .refresh(dir.path())
            .map_err(|_| "PT PID scan failed")?;
        // Reuse-оракул по НАБЛЮДЕНИЯМ фактического резервирования: probe
        // публикует observation ТОЛЬКО после возврата reserve, поэтому
        // наблюдение alt-записи ОБЯЗАНО уже существовать. Базлайн — из
        // bounded-снапшота журнала. Identity — opaque Arc::as_ptr записи:
        // reuse того же Arc даёт тот же pointer, NEW-запись — другой.
        // route-label хранит ТОЛЬКО адрес, credentials не хранятся и не
        // печатаются.
        let probe = crate::server::owners::test_selection_probe();
        let mut obs_rx = probe.subscribe();
        let (baseline, baseline_dropped) = probe.snapshot();
        let baseline_len = baseline.len();
        let (alt_identity, alt_request_id) = baseline
            .iter()
            .rev()
            .find(|o| o.route == alt_route && o.outcome == SelectionOutcome::Reserved)
            .and_then(|hit| hit.identity.map(|id| (id, hit.request_id)))
            .ok_or("наблюдение резервирования alt отсутствует или без identity записи")?;
        if baseline_dropped != 0 {
            return Err("переполнение журнала наблюдений".into());
        }
        // Повторный допуск alt переиспользует владельца: reserve дедуплицирует
        // по ТОМУ ЖЕ ключу address+password. Мутации: парковка дубликата после
        // record до reserve — НОВОГО наблюдения нет; ошибочный реальный
        // reserve-выбор — identity != alt_identity; errored reserve —
        // outcome != Reserved. Отказ вместо reuse дал бы ранние байты.
        let mut duplicate = socks_auth("alt", "pw", listener_address).await;
        socks_connect(&mut duplicate).await;
        let early = tokio::time::timeout(Duration::from_secs(4), async {
            let mut reply = [0u8; 2];
            duplicate.read_exact(&mut reply).await.unwrap_or_default();
        })
        .await;
        if early.is_ok() {
            return Err("ранние байты дубликату: отказ вместо переиспользования".into());
        }
        // Событийное ожидание НОВОГО observation (watch длины журнала).
        tokio::time::timeout(Duration::from_secs(8), async {
            while *obs_rx.borrow_and_update() <= baseline_len {
                obs_rx
                    .changed()
                    .await
                    .map_err(|_| "журнал наблюдений закрылся")?;
            }
            Ok::<(), String>(())
        })
        .await
        .map_err(|_| "нового наблюдения резервирования нет (8с)")??;
        let (after, after_dropped) = probe.snapshot();
        if after_dropped != baseline_dropped {
            return Err("переполнение журнала наблюдений".into());
        }
        if !after[baseline_len..].iter().any(|o| {
            o.route == alt_route
                && o.request_id > alt_request_id
                && o.identity == Some(alt_identity)
                && o.outcome == SelectionOutcome::Reserved
        }) {
            return Err("нового наблюдения резервирования ТОЙ ЖЕ записи нет".into());
        }
        let child_snapshot = scan_child_pids(dir.path())?;
        if child_snapshot
            .iter()
            .filter(|(path, _)| path.components().any(|c| c.as_os_str() == "owners-v1"))
            .count()
            != 2
        {
            return Err("дубликат породил нового владельца".into());
        }
        // sameaddr: тот же address, другой пароль -> ОТДЕЛЬНЫЙ владелец;
        // его PT-ребёнок аутентифицируется на рекордере1 как secret2.
        let mut sameaddr = socks_auth("sameaddr", "pw", listener_address).await;
        socks_connect(&mut sameaddr).await;
        let secret2_found = tokio::time::timeout(Duration::from_secs(10), async {
            let mut found = false;
            while let Some(carrier) = events1_rx.recv().await {
                if carrier == b"secret2" {
                    found = true;
                    break;
                }
            }
            found
        })
        .await
        .map_err(|_| "носитель secret2 не пришёл (10с)")?;
        if !secret2_found {
            return Err("рекордер1 закрыт без носителя secret2".into());
        }
        known_children
            .refresh(dir.path())
            .map_err(|_| "PT PID scan failed")?;
        let child_snapshot = scan_child_pids(dir.path())?;
        if child_snapshot
            .iter()
            .filter(|(path, _)| path.components().any(|c| c.as_os_str() == "owners-v1"))
            .count()
            != 3
        {
            return Err("sameaddr обязан дать отдельного владельца (alt, sameaddr)".into());
        }
        // Shutdown-свидетель (наблюдение обрыва клиентских сокетов — в теле,
        // само завершение сервера — bounded join в cleanup): обработчики
        // abort_all роняют сокеты, клиенты видят ОБРЫВ в ограниченном окне.
        let _ = shutdown_tx
            .take()
            .expect("shutdown-сендер уже забран")
            .send(());
        let clients_closed = tokio::time::timeout(Duration::from_secs(12), async {
            assert!(
                read_closed(&mut duplicate).await,
                "дубликат не закрыт при shutdown"
            );
            assert!(read_closed(&mut alt).await, "alt не закрыт при shutdown");
        })
        .await;
        if clients_closed.is_err() {
            return Err("соединения дубликата/alt не закрыты при shutdown (12с)".into());
        }
        Ok(())
    };
    let outcome = tokio::time::timeout_at(
        body_deadline,
        std::panic::AssertUnwindSafe(body).catch_unwind(),
    )
    .await;
    let _ = known_children.refresh(dir.path());
    // Cleanup ВНЕ таймируемого региона: гарантирован на timeout/Err-путях
    // тела (см. шапку модуля и cleanup_supplied_scenario).
    let cleanup = cleanup_supplied_scenario(ScenarioCleanup {
        shutdown_tx: shutdown_tx.take(),
        stop1_tx,
        stop2_tx,
        server: &mut server,
        recorder1: &mut recorder1,
        recorder2: &mut recorder2,
        trap: &mut trap,
        trap_listener: direct,
        trap_accepts: &trap_accepts,
        trap_overrun: &overruns.trap,
        events1_rx,
        events2_rx,
        traps_rx,
        graceful_deadline,
        terminal_deadline,
    })
    .await;
    let terminal_errors = if cleanup.server.is_err() {
        super::super::super::global_init::recover_contract_terminal().await
    } else {
        Vec::new()
    };
    let children_gone = verify_children_gone(
        &mut known_children,
        dir.path(),
        tokio::time::Instant::now() + Duration::from_secs(55),
    )
    .await;
    assert!(
        children_gone.is_ok(),
        "не удалось подтвердить завершение PT-процессов"
    );
    assert!(
        terminal_errors.is_empty(),
        "ошибки восстановления terminal: {terminal_errors:?}"
    );
    assert!(cleanup.server.is_ok(), "ошибка завершения сервера");
    assert!(cleanup.backlog.is_ok(), "не удалось осушить backlog");
    assert!(
        cleanup.recorder1.is_ok(),
        "{}",
        cleanup.recorder1.unwrap_err()
    );
    assert!(
        cleanup.recorder2.is_ok(),
        "{}",
        cleanup.recorder2.unwrap_err()
    );
    assert!(
        cleanup.trap_cancelled,
        "ловушка: join после abort — только отмена допустима"
    );
    assert!(cleanup.drains_ok, "каналы не осушены");
    match outcome {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(message))) => panic!("supplied positive: ошибка тела: {message}"),
        Ok(Err(_)) => panic!("supplied positive: паника в теле сценария"),
        Err(_) => panic!("supplied positive: timeout тела сценария"),
    }
    // Оракул паник: терминальный счётчик; сообщения — bounded (кап 16,
    let panics_total = panic_count.load(std::sync::atomic::Ordering::Relaxed);
    let panics_stored = panic_messages.lock().unwrap().clone();
    assert_eq!(
        panics_total, 0,
        "паники воркеров рекордеров: {panics_total}, первые: {panics_stored:?}"
    );
    // Счётчики воркеров после cleanup: таймауты/прочие ошибки/аборты == 0.
    // aborted_workers == 0 — выбор оракула: bounded drain 10с внутри
    // 15с-окна join обязан успевать; abort означал бы потерю факта сессии.
    assert_eq!(
        worker_timeouts.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "воркеры превысили per-worker дедлайн 60с"
    );
    assert_eq!(
        worker_errors.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "переговорные/записные ошибки воркеров рекордеров"
    );
    assert_eq!(
        aborted_workers.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "воркеры рекордеров были абортированы при drain"
    );
    // Разгонные guard-и: капы/переполнения ограничивают рост при штормах
    // повторных dial chanmgr (ожидаемое поведение), границы щедрые.
    assert!(
        overruns
            .recorder1
            .load(std::sync::atomic::Ordering::Relaxed)
            <= 256,
        "рекордер1: шторм соединений"
    );
    assert!(
        overruns
            .recorder2
            .load(std::sync::atomic::Ordering::Relaxed)
            <= 256,
        "рекордер2: шторм соединений"
    );
    assert!(
        overruns.trap.load(std::sync::atomic::Ordering::Relaxed) <= 256,
        "ловушка: шторм соединений"
    );
    assert!(
        overruns.events.load(std::sync::atomic::Ordering::Relaxed) <= 256,
        "каналы носителей: шторм"
    );
    // Владельцев owners-v1 ровно 3 (plain, alt, sameaddr): duplicate reuse.
    let owners = scan_child_pids(dir.path())
        .expect("redacted PT PID snapshot failed")
        .iter()
        .filter(|(path, _)| path.components().any(|c| c.as_os_str() == "owners-v1"))
        .count();
    assert_eq!(owners, 3, "владельцы в owners-v1: plain, alt и sameaddr");
    // Полный набор PT-детей: глобальный владелец наследует pre, его ребёнок
    // пишет owner-contract-pid в state-dir арта (tor_setup.rs:270-274,
    // owner_settings.rs:62), ВНЕ owners-v1 (storage.rs:59).
    let all_children = scan_child_pids(dir.path()).expect("redacted PT PID snapshot failed");
    assert_eq!(
        all_children.len(),
        owners + 1,
        "ожидаются 3 альтернативных PT-ребёнка + глобальный вне owners-v1"
    );
}

// NEGATIVE-сценарий
pub(crate) async fn run_supplied_config_negative() {
    let _serial = crate::server::owners::TEST_LIFECYCLE.lock().await;
    let total_deadline = tokio::time::Instant::now() + Duration::from_secs(40);
    let body_deadline = total_deadline - Duration::from_secs(18);
    let graceful_deadline = total_deadline - Duration::from_secs(7);
    let terminal_deadline = total_deadline - Duration::from_secs(5);
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let mut known_children = KnownChildren::default();
    let overruns = Overruns::default();
    let panic_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let panic_messages = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let worker_timeouts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let worker_errors = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let aborted_workers = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let trap_accepts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (trap_accepts_tx, _trap_accepts_rx) = tokio::sync::watch::channel(0usize);
    let setup = supplied_setup(
        dir.path(),
        vec![
            // ПОЛЬЗОВАТЕЛЯ plain НЕТ: ни одна сессия не должна dial-ить
            // ловушку напрямую; фазы plain нет — приписывать нечего.
            ("global", PreSpec::Inherit),
            ("alt", PreSpec::Alt("second")),
            ("sameaddr", PreSpec::SameAddr("secret2")),
        ],
    )
    .await;
    assert!(
        tokio::time::Instant::now() < body_deadline,
        "подготовка превысила body deadline"
    );
    let listener_address = setup.listener_address;
    let (events1_tx, mut events1_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let (events2_tx, mut events2_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let (traps_tx, traps_rx) = tokio::sync::mpsc::channel::<TcpStream>(64);
    let (stop1_tx, stop1_rx) = tokio::sync::watch::channel(());
    let mut recorder1 = spawn_supplied_recorder(
        setup.proxy,
        stop1_rx,
        GLOBAL_USER_ALLOWED,
        "рекордер1",
        events1_tx,
        RecorderCounters {
            accept_overrun: overruns.recorder1.clone(),
            events_overrun: overruns.events.clone(),
            panic_count: panic_count.clone(),
            panic_messages: panic_messages.clone(),
            worker_timeouts: worker_timeouts.clone(),
            worker_errors: worker_errors.clone(),
            aborted_workers: aborted_workers.clone(),
        },
        None,
    );
    let (stop2_tx, stop2_rx) = tokio::sync::watch::channel(());
    let mut recorder2 = spawn_supplied_recorder(
        setup.proxy2,
        stop2_rx,
        ALT_USER_ALLOWED,
        "рекордер2",
        events2_tx,
        RecorderCounters {
            accept_overrun: overruns.recorder2.clone(),
            events_overrun: overruns.events.clone(),
            panic_count: panic_count.clone(),
            panic_messages: panic_messages.clone(),
            worker_timeouts: worker_timeouts.clone(),
            worker_errors: worker_errors.clone(),
            aborted_workers: aborted_workers.clone(),
        },
        None,
    );
    let direct = Arc::new(setup.direct);
    let mut trap = spawn_supplied_trap(
        Arc::clone(&direct),
        trap_accepts.clone(),
        trap_accepts_tx,
        traps_tx,
        overruns.trap.clone(),
    );
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let writer = crate::bridge_store_writer::StoreWriter::spawn(
        bridge_store::BridgeStore::resolve_path(Some(&setup.config_path)),
        Arc::new(|_| Ok(())),
        Duration::from_secs(3600),
    );
    let hook = Arc::new(super::super::super::global_init::ShutdownHook {
        settings: Settings::default(),
        writer,
        ready: std::sync::Mutex::new(Some(ready_tx)),
    });
    let args = super::super::super::ServerArgs {
        config_override: Some(setup.config_path.clone()),
        upstream_addr: None,
        upstream_user: None,
        upstream_pass: None,
        no_upstream: false,
    };
    let mut server = AbortOnDrop(tokio::spawn(
        super::super::super::global_init::RUN_SERVER_CONFIG.scope((), async move {
            super::super::super::global_init::RUN_SERVER_SHUTDOWN
                .scope(hook, async move {
                    super::super::super::run_server(args, async {
                        let _ = shutdown_rx.await;
                    })
                    .await
                })
                .await
        }),
    ));
    // Таймируемый регион — ТОЛЬКО тело сценария.
    let body = async {
        tokio::time::timeout(Duration::from_secs(15), ready_rx)
            .await
            .map_err(|_| "готовность не наступила (15с)")?
            .map_err(|_| "отправитель готовности упал вместе с сервером")?;
        // Полный прогон владельцев: global (secret), alt (second), sameaddr
        // (secret2) — каждый носитель с капом.
        let mut global_client = socks_auth("global", "pw", listener_address).await;
        socks_connect(&mut global_client).await;
        let secret = tokio::time::timeout(Duration::from_secs(8), events1_rx.recv())
            .await
            .map_err(|_| "носитель secret не пришёл (8с)")?
            .ok_or("рекордер1 закрыт без носителя secret")?;
        if secret.as_slice() != b"secret" {
            return Err(format!(
                "наследуемый носитель не secret: {} байт, не совпало",
                secret.len()
            ));
        }
        let mut alt = socks_auth("alt", "pw", listener_address).await;
        socks_connect(&mut alt).await;
        if !tokio::time::timeout(Duration::from_secs(8), async {
            let mut found = false;
            while let Some(carrier) = events2_rx.recv().await {
                if carrier == b"second" {
                    found = true;
                    break;
                }
            }
            found
        })
        .await
        .map_err(|_| "носитель second не пришёл (8с)")?
        {
            return Err("рекордер2 закрыт без носителя second".into());
        }
        known_children
            .refresh(dir.path())
            .map_err(|_| "PT PID scan failed")?;
        let mut sameaddr = socks_auth("sameaddr", "pw", listener_address).await;
        socks_connect(&mut sameaddr).await;
        if !tokio::time::timeout(Duration::from_secs(8), async {
            let mut found = false;
            while let Some(carrier) = events1_rx.recv().await {
                if carrier == b"secret2" {
                    found = true;
                    break;
                }
            }
            found
        })
        .await
        .map_err(|_| "носитель secret2 не пришёл (8с)")?
        {
            return Err("рекордер1 закрыт без носителя secret2".into());
        }
        known_children
            .refresh(dir.path())
            .map_err(|_| "PT PID scan failed")?;
        // Дрейн очередей носителей до пустоты: наблюдение свежих носителей
        // привязано к НОВЫМ CONNECT, а не к событиям, уже лежавшим в каналах.
        while events1_rx.try_recv().is_ok() {}
        while events2_rx.try_recv().is_ok() {}
        // Свежие носители = liveness-доказательство: global и alt живы и
        // маршрутизируются через рекордеры прямо сейчас.
        known_children
            .refresh(dir.path())
            .map_err(|_| "PT PID scan failed")?;
        let mut global_alive = socks_auth("global", "pw", listener_address).await;
        socks_connect(&mut global_alive).await;
        if !tokio::time::timeout(Duration::from_secs(8), async {
            let mut found = false;
            while let Some(carrier) = events1_rx.recv().await {
                if carrier == b"secret" {
                    found = true;
                    break;
                }
            }
            found
        })
        .await
        .map_err(|_| "свежий носитель secret не пришёл (8с)")?
        {
            return Err("рекордер1 закрыт без свежего носителя secret".into());
        }
        known_children
            .refresh(dir.path())
            .map_err(|_| "PT PID scan failed")?;
        let mut alt_alive = socks_auth("alt", "pw", listener_address).await;
        socks_connect(&mut alt_alive).await;
        if !tokio::time::timeout(Duration::from_secs(8), async {
            let mut found = false;
            while let Some(carrier) = events2_rx.recv().await {
                if carrier == b"second" {
                    found = true;
                    break;
                }
            }
            found
        })
        .await
        .map_err(|_| "свежий носитель second не пришёл (8с)")?
        {
            return Err("рекордер2 закрыт без свежего носителя second".into());
        }
        Ok(())
    };
    let outcome = tokio::time::timeout_at(
        body_deadline,
        std::panic::AssertUnwindSafe(body).catch_unwind(),
    )
    .await;
    let _ = known_children.refresh(dir.path());
    // Cleanup ВНЕ таймируемого региона (см. шапку модуля).
    let cleanup = cleanup_supplied_scenario(ScenarioCleanup {
        shutdown_tx: Some(shutdown_tx),
        stop1_tx,
        stop2_tx,
        server: &mut server,
        recorder1: &mut recorder1,
        recorder2: &mut recorder2,
        trap: &mut trap,
        trap_listener: direct,
        trap_accepts: &trap_accepts,
        trap_overrun: &overruns.trap,
        events1_rx,
        events2_rx,
        traps_rx,
        graceful_deadline,
        terminal_deadline,
    })
    .await;
    let terminal_errors = if cleanup.server.is_err() {
        super::super::super::global_init::recover_contract_terminal().await
    } else {
        Vec::new()
    };
    let children_gone = verify_children_gone(
        &mut known_children,
        dir.path(),
        tokio::time::Instant::now() + Duration::from_secs(40),
    )
    .await;
    assert!(
        children_gone.is_ok(),
        "не удалось подтвердить завершение PT-процессов"
    );
    assert!(
        terminal_errors.is_empty(),
        "ошибки восстановления terminal: {terminal_errors:?}"
    );
    assert!(cleanup.server.is_ok(), "ошибка завершения сервера");
    assert!(cleanup.backlog.is_ok(), "не удалось осушить backlog");
    assert!(
        cleanup.recorder1.is_ok(),
        "{}",
        cleanup.recorder1.unwrap_err()
    );
    assert!(
        cleanup.recorder2.is_ok(),
        "{}",
        cleanup.recorder2.unwrap_err()
    );
    assert!(
        cleanup.trap_cancelled,
        "ловушка: join после abort — только отмена допустима"
    );
    assert!(cleanup.drains_ok, "каналы не осушены");
    match outcome {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(message))) => panic!("supplied negative: ошибка тела: {message}"),
        Ok(Err(_)) => panic!("supplied negative: паника в теле сценария"),
        Err(_) => panic!("supplied negative: timeout тела сценария"),
    }
    // ФИНАЛЬНЫЙ ассерт ПО ИСТОРИИ ВСЕГО прогона: trap_accepts считает КАЖДЫЙ
    // accept ловушки с момента старта (инкремент до отправки в канал) И
    // backlog-drain после abort ловушки (непринятое запрещённое подключение
    // обязательно считается до этого ассерта) — любой accept когда-либо =
    // нарушение; поздний pre-accept (kernel-backlog) не приписывается ничему,
    // потому что plain-фазы нет. Мутация «global/alt dial-ят ловушку» и
    // negative-оракул ловит любой accept; positive-атрибуция описана выше.
    assert_eq!(
        trap_accepts.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "ловушка набрана без plain-пользователя"
    );
    // Оракул паник (auth-before-success сохранён: чужой пароль = паника).
    let panics_total = panic_count.load(std::sync::atomic::Ordering::Relaxed);
    let panics_stored = panic_messages.lock().unwrap().clone();
    assert_eq!(
        panics_total, 0,
        "паники воркеров рекордеров: {panics_total}, первые: {panics_stored:?}"
    );
    assert_eq!(
        worker_timeouts.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "воркеры превысили per-worker дедлайн 60с"
    );
    assert_eq!(
        worker_errors.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "переговорные/записные ошибки воркеров рекордеров"
    );
    assert_eq!(
        aborted_workers.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "воркеры рекордеров были абортированы при drain"
    );
    // Переполнений ограниченных каналов нет: потоки носителей дрейнированы.
    assert!(
        overruns.events.load(std::sync::atomic::Ordering::Relaxed) <= 256,
        "каналы носителей: шторм"
    );
    assert!(
        overruns.trap.load(std::sync::atomic::Ordering::Relaxed) <= 256,
        "ловушка: шторм соединений"
    );
    let owners = scan_child_pids(dir.path())
        .expect("redacted PT PID snapshot failed")
        .iter()
        .filter(|(path, _)| path.components().any(|c| c.as_os_str() == "owners-v1"))
        .count();
    assert_eq!(owners, 2, "владельцы в owners-v1: alt и sameaddr");
    let all_children = scan_child_pids(dir.path()).expect("redacted PT PID snapshot failed");
    assert_eq!(
        all_children.len(),
        owners + 1,
        "ожидаются 2 альтернативных PT-ребёнка + глобальный вне owners-v1"
    );
}
