use super::*;
use futures::FutureExt;
use tokio::io::AsyncReadExt;

// Оракулы supplied-контракта (все counterfactual, выполнение — только CI netns;
// заявлений о PASS не делается). Сами supplied-сценарии разделены на два
// независимых (negative/positive) и живут в supplied_contract.rs; здесь —
// общие помощники (одна копия), старый fixture (run_pt_owner_contract, HEAD
// semantics — не менять) и seeds-reject.
// 1) носители: secret на рекордере1 (наследование global-pre), second на
//    рекордере2 (замена address+password СОВМЕСТНО), secret2 на рекордере1
//    (тот же address, другой пароль = отдельный владелец: reserve сравнивает
//    pre целиком); мутация «ключ только по адресу» оставила бы global-ребёнка
//    с паролем secret — secret2 не пришёл бы;
// 2) чужой пароль на рекордере -> паника воркера -> терминальный счётчик
//    panic_count (никогда не дропается; первые 16 сообщений — в bounded-
//    хранилище, переполнение только растит счётчик); финальный ассерт
//    panic_count == 0; сообщения паник НЕ содержат паролей;
// 3) reuse-свидетель дубликата alt: cfg(test)-наблюдение ФАКТИЧЕСКОГО
//    резервирования (crate::server::owners::SelectionProbe, публикация строго
//    ПОСЛЕ возврата reserve (task-local SELECTION_OBS, публикация строго
//    после фактического результата reserve; identity = opaque
//    Arc::as_ptr записи; route-label только адрес, без credentials).
//    Резервирование ≠ завершённый Owner return: выдача state.tunnel без
//    Tor-сети не наблюдаема — ассертится именно резервирование той же записи;
// 4) trap-граница разделена: negative-сценарий (без plain-пользователя,
//    trap_accepts == 0 по истории всего прогона) и positive-сценарий
//    (trap_accepts >= 1 после plain CONNECT) — см. supplied_contract.rs;
// 5) shutdown (positive): обрыв клиентских сокетов (abort_all,
//    handlers.rs:103-123), выход сервера, исчезновение /proc у ВСЕХ PT-детей.
// Счётчики переполнения ограниченных каналов и капов воркеров рекордеров.
// Arc-поля: задачи рекордеров/ловушки держат свои счётчики независимо.
#[derive(Default, Clone)]
pub(crate) struct Overruns {
    pub(crate) recorder1: Arc<std::sync::atomic::AtomicUsize>,
    pub(crate) recorder2: Arc<std::sync::atomic::AtomicUsize>,
    pub(crate) trap: Arc<std::sync::atomic::AtomicUsize>,
    pub(crate) events: Arc<std::sync::atomic::AtomicUsize>,
}

// Учёт паники воркера: терминальный счётчик + bounded-хранилище (кап 16,
// переполнение только растит счётчик). Сообщения без credentials.
pub(crate) fn record_panic(
    count: &std::sync::atomic::AtomicUsize,
    store: &std::sync::Mutex<Vec<String>>,
    label: &str,
    error: &tokio::task::JoinError,
) {
    count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut guard = store.lock().unwrap();
    if guard.len() < 16 {
        guard.push(format!("{label}: {error}"));
    }
}

// Разбор результата воркера: паника -> счётчик паник; Err -> превышение
// per-worker дедлайна (60с) -> worker_timeouts; ЛЮБАЯ другая Ok(Err(_))
// (negotiate/write ошибки) -> ОТДЕЛЬНЫЙ счётчик worker_errors (не паника и
// не таймаут, факт не теряется); оба счётчика после cleanup ассертятся == 0.
pub(crate) fn handle_worker_result(
    result: Result<Result<(), &'static str>, tokio::task::JoinError>,
    label: &str,
    panic_count: &std::sync::atomic::AtomicUsize,
    panic_messages: &std::sync::Mutex<Vec<String>>,
    worker_timeouts: &std::sync::atomic::AtomicUsize,
    worker_errors: &std::sync::atomic::AtomicUsize,
) {
    match result {
        Err(error) if error.is_panic() => record_panic(panic_count, panic_messages, label, &error),
        Err(_) => {}
        Ok(Err(msg)) if msg == WORKER_DEADLINE_MSG => {
            worker_timeouts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(Err(_)) => {
            worker_errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(Ok(())) => {}
    }
}

// Bounded drain воркеров рекордера после stop-сигнала: 10с на успех; не
// успевшие (сетевой read без конечного срока) — abort + join, счётчик
// aborted_workers сохраняет факт без потери сообщений (они в bounded-хранилище).
pub(crate) async fn drain_workers_bounded(
    workers: &mut tokio::task::JoinSet<Result<(), &'static str>>,
    label: &str,
    panic_count: &std::sync::atomic::AtomicUsize,
    panic_messages: &std::sync::Mutex<Vec<String>>,
    worker_timeouts: &std::sync::atomic::AtomicUsize,
    worker_errors: &std::sync::atomic::AtomicUsize,
    aborted_workers: &std::sync::atomic::AtomicUsize,
) {
    let drain = async {
        while let Some(result) = workers.join_next().await {
            handle_worker_result(
                result,
                label,
                panic_count,
                panic_messages,
                worker_timeouts,
                worker_errors,
            );
        }
    };
    if tokio::time::timeout(Duration::from_secs(10), drain)
        .await
        .is_err()
    {
        workers.abort_all();
        while let Some(result) = workers.join_next().await {
            match result {
                Err(error) if error.is_cancelled() => {
                    aborted_workers.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                other => handle_worker_result(
                    other,
                    label,
                    panic_count,
                    panic_messages,
                    worker_timeouts,
                    worker_errors,
                ),
            }
        }
    }
}

// Тестовые ошибки recorder accept loop; параметры фиксируются до spawn.
#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) enum RecorderFault {
    AcceptError,
    PanicAfterSpawn,
}

// воркеров, остановка через watch-сигнал, полный bounded drain. Паника воркера
// (чужие учётные данные) растит терминальный счётчик.
pub(crate) fn spawn_supplied_recorder(
    listener: TcpListener,
    stop_rx: tokio::sync::watch::Receiver<()>,
    allowed: &'static [&'static [u8]],
    label: &'static str,
    events_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    accept_overrun: Arc<std::sync::atomic::AtomicUsize>,
    events_overrun: Arc<std::sync::atomic::AtomicUsize>,
    panic_count: Arc<std::sync::atomic::AtomicUsize>,
    panic_messages: Arc<std::sync::Mutex<Vec<String>>>,
    worker_timeouts: Arc<std::sync::atomic::AtomicUsize>,
    worker_errors: Arc<std::sync::atomic::AtomicUsize>,
    aborted_workers: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(test)] fault: Option<RecorderFault>,
) -> AbortOnDrop<()> {
    AbortOnDrop(tokio::spawn(async move {
        let mut stop_rx = stop_rx;
        #[cfg(test)]
        let fault = fault;
        let mut workers = tokio::task::JoinSet::new();
        #[cfg(test)]
        let mut spawned = false;
        let accept_loop = async {
            loop {
                tokio::select! {
                    _ = stop_rx.changed() => break,
                    accepted = async {
                        #[cfg(test)]
                        if spawned && matches!(fault, Some(RecorderFault::AcceptError)) {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                "искусственный отказ accept",
                            ));
                        }
                        listener.accept().await
                    } => {
                        let (stream, _) = match accepted {
                            Ok(accepted) => accepted,
                            Err(_) => {
                                worker_errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                break;
                            }
                        };
                        if workers.len() >= 8 {
                            accept_overrun.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            drop(stream);
                            continue;
                        }
                        workers.spawn(proxy_connection_checked(stream, allowed, label, {
                            let events_tx = events_tx.clone();
                            let events_overrun = events_overrun.clone();
                            move |pass| {
                                if events_tx.try_send(pass).is_err() {
                                    events_overrun.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                }
                            }
                        }));
                        #[cfg(test)]
                        {
                            spawned = true;
                        }
                        #[cfg(test)]
                        if matches!(fault, Some(RecorderFault::PanicAfterSpawn)) {
                            panic!("искусственный отказ accept-loop");
                        }
                    }
                    Some(result) = workers.join_next(), if !workers.is_empty() => {
                        handle_worker_result(result, label, &panic_count, &panic_messages,
                            &worker_timeouts, &worker_errors);
                    }
                }
            }
        };
        if std::panic::AssertUnwindSafe(accept_loop)
            .catch_unwind()
            .await
            .is_err()
        {
            // Payload не читается и не журналируется: он может содержать секреты.
            panic_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        drain_workers_bounded(
            &mut workers,
            label,
            &panic_count,
            &panic_messages,
            &worker_timeouts,
            &worker_errors,
            &aborted_workers,
        )
        .await;
    }))
}

#[cfg(test)]
async fn recorder_rejection_case(fault: RecorderFault) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(());
    let worker_errors = Arc::new(AtomicUsize::new(0));
    let worker_timeouts = Arc::new(AtomicUsize::new(0));
    let aborted = Arc::new(AtomicUsize::new(0));
    let panics = Arc::new(AtomicUsize::new(0));
    let recorder = spawn_supplied_recorder(
        listener,
        stop_rx,
        &[],
        "control",
        tokio::sync::mpsc::channel(1).0,
        Arc::new(AtomicUsize::new(0)),
        Arc::new(AtomicUsize::new(0)),
        panics.clone(),
        Arc::new(std::sync::Mutex::new(Vec::new())),
        worker_timeouts.clone(),
        worker_errors.clone(),
        aborted.clone(),
        Some(fault),
    );
    let mut recorder = recorder;
    let mut client = TcpStream::connect(address).await.unwrap();
    client.write_all(&[5, 1, 2]).await.unwrap();
    let mut reply = [0; 2];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    drop(client);
    let detection = tokio::time::timeout(Duration::from_secs(15), &mut recorder.0).await;
    let detection_failed = detection.is_err();
    if detection_failed {
        let terminal = (&mut recorder.0).await;
        assert!(
            terminal.is_ok(),
            "рекордер не завершился после срока обнаружения: {terminal:?}"
        );
    } else {
        detection.unwrap().unwrap();
    }
    assert!(recorder.0.is_finished());
    assert_eq!(
        worker_errors.load(Ordering::Relaxed),
        if matches!(fault, RecorderFault::AcceptError) {
            2
        } else {
            1
        }
    );
    assert_eq!(worker_timeouts.load(Ordering::Relaxed), 0);
    assert_eq!(
        panics.load(Ordering::Relaxed),
        if matches!(fault, RecorderFault::PanicAfterSpawn) {
            1
        } else {
            0
        }
    );
    assert_eq!(aborted.load(Ordering::Relaxed), 0);
    assert!(
        !detection_failed,
        "отказ recorder-loop обнаружен только после срока"
    );
    let _ = stop_tx.send(());
}

#[cfg(test)]
#[tokio::test]
async fn recorder_accept_error_drains_live_worker() {
    recorder_rejection_case(RecorderFault::AcceptError).await;
}

#[cfg(test)]
#[tokio::test]
async fn recorder_accept_panic_drains_live_worker() {
    recorder_rejection_case(RecorderFault::PanicAfterSpawn).await;
}

// История accept: инкремент на КАЖДОМ accept ДО отправки в канал; watch —
// событийный сигнал наблюдателю. Задача держит Arc<TcpListener>, НЕ владея им:
// после abort тест дрейнит kernel-backlog через СВОЙ Arc (см.
// drain_trap_backlog), непринятое запрещённое подключение не теряется.
pub(crate) fn spawn_supplied_trap(
    listener: std::sync::Arc<TcpListener>,
    trap_accepts: Arc<std::sync::atomic::AtomicUsize>,
    trap_accepts_tx: tokio::sync::watch::Sender<usize>,
    traps_tx: tokio::sync::mpsc::Sender<TcpStream>,
    trap_overrun: Arc<std::sync::atomic::AtomicUsize>,
) -> AbortOnDrop<()> {
    AbortOnDrop(tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            trap_accepts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let _ = trap_accepts_tx.send(trap_accepts.load(std::sync::atomic::Ordering::Relaxed));
            if traps_tx.try_send(stream).is_err() {
                trap_overrun.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }))
}

// Bounded drain kernel-backlog ловушки после abort trap-задачи: до 500мс на
// попытку accept, суммарно не более 2с, до исчерпания (нет входящих за окно
// или Err/Closed). КАЖДЫЙ принятый инкрементирует ТОТ ЖЕ trap_accepts —
// непринятое запрещённое подключение обязательно учитывается до финального
// ассерта trap_accepts == 0 (negative).
#[derive(Debug)]
pub(crate) enum DrainOutcome {
    Idle,
}

pub(crate) async fn drain_trap_backlog(
    listener: &TcpListener,
    trap_accepts: &std::sync::atomic::AtomicUsize,
    trap_overrun: &std::sync::atomic::AtomicUsize,
) -> Result<DrainOutcome, String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err("истёк срок осушения backlog".to_string());
        }
        match tokio::time::timeout_at(
            std::cmp::min(deadline, now + Duration::from_millis(500)),
            listener.accept(),
        )
        .await
        {
            Err(_) if tokio::time::Instant::now() >= deadline => {
                return Err("истёк срок осушения backlog".to_string())
            }
            Err(_) => return Ok(DrainOutcome::Idle),
            Ok(Err(error)) => return Err(format!("ошибка accept ловушки: {}", error.kind())),
            Ok(Ok((_, _))) => {
                trap_accepts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                trap_overrun.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }
}

// Итог cleanup supplied-сценария: факты join'ов для финальных ассертов.
pub(crate) struct SuppliedCleanup {
    pub(crate) server: Result<(), String>,
    pub(crate) recorder1: Result<(), String>,
    pub(crate) recorder2: Result<(), String>,
    pub(crate) trap_cancelled: bool,
    pub(crate) drains_ok: bool,
    pub(crate) backlog: Result<DrainOutcome, String>,
}

// Cleanup использует абсолютные сроки сценария; незавершённые задачи остаются
// в scope при terminal timeout, и такой исход явно отражается в результате.
pub(crate) async fn cleanup_supplied_scenario(
    mut shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    stop1_tx: tokio::sync::watch::Sender<()>,
    stop2_tx: tokio::sync::watch::Sender<()>,
    server: &mut AbortOnDrop<anyhow::Result<()>>,
    recorder1: &mut AbortOnDrop<()>,
    recorder2: &mut AbortOnDrop<()>,
    trap: &mut AbortOnDrop<()>,
    trap_listener: std::sync::Arc<TcpListener>,
    trap_accepts: &std::sync::atomic::AtomicUsize,
    trap_overrun: &std::sync::atomic::AtomicUsize,
    mut events1_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    mut events2_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    mut traps_rx: tokio::sync::mpsc::Receiver<TcpStream>,
    graceful_deadline: tokio::time::Instant,
    terminal_deadline: tokio::time::Instant,
) -> SuppliedCleanup {
    if let Some(shutdown_tx) = shutdown_tx.take() {
        let _ = shutdown_tx.send(());
    }
    let _ = stop1_tx.send(());
    let _ = stop2_tx.send(());
    // Сроки — обнаружение отказа, а не право терять владение задачей:
    // после них удерживаем join до терминального исхода. Абсолютный предел
    // при неисправимом блокировании ОС не обещается.
    let (mut server_join, mut recorder1_join, mut recorder2_join) = tokio::join!(
        tokio::time::timeout_at(graceful_deadline, &mut server.0),
        tokio::time::timeout_at(graceful_deadline, &mut recorder1.0),
        tokio::time::timeout_at(graceful_deadline, &mut recorder2.0),
    );
    let server_deadline_failed = server_join.is_err();
    let recorder1_deadline_failed = recorder1_join.is_err();
    let recorder2_deadline_failed = recorder2_join.is_err();
    if server_deadline_failed {
        server.0.abort();
    }
    if recorder1_deadline_failed {
        let _ = stop1_tx.send(());
    }
    if recorder2_deadline_failed {
        let _ = stop2_tx.send(());
    }
    if server_deadline_failed {
        let terminal = tokio::time::timeout_at(terminal_deadline, &mut server.0).await;
        server_join = if terminal.is_err() {
            Ok((&mut server.0).await)
        } else {
            terminal
        };
    }
    let server_failed = server_deadline_failed || !matches!(&server_join, Ok(Ok(Ok(()))));
    let recovery_errors = if server_failed {
        super::super::super::global_init::recover_contract_all().await
    } else {
        Vec::new()
    };
    if recorder1_deadline_failed {
        let terminal = tokio::time::timeout_at(terminal_deadline, &mut recorder1.0).await;
        recorder1_join = if terminal.is_err() {
            Ok((&mut recorder1.0).await)
        } else {
            terminal
        };
    }
    if recorder2_deadline_failed {
        let terminal = tokio::time::timeout_at(terminal_deadline, &mut recorder2.0).await;
        recorder2_join = if terminal.is_err() {
            Ok((&mut recorder2.0).await)
        } else {
            terminal
        };
    }

    trap.0.abort();
    let trap_join = (&mut trap.0).await;
    let trap_cancelled = matches!(trap_join, Err(ref error) if error.is_cancelled());
    let backlog = drain_trap_backlog(&trap_listener, trap_accepts, trap_overrun).await;
    drop(trap_listener);
    while events1_rx.try_recv().is_ok() {}
    while events2_rx.try_recv().is_ok() {}
    while traps_rx.try_recv().is_ok() {}
    let drains_ok = events1_rx.is_closed()
        && events1_rx.is_empty()
        && events2_rx.is_closed()
        && events2_rx.is_empty()
        && traps_rx.is_closed()
        && traps_rx.is_empty();
    let describe_recorder =
        |name: &str, join: Result<Result<(), tokio::task::JoinError>, _>| match join {
            Ok(Ok(())) => Ok(()),
            other => Err(format!("{name}: неожиданный исход {other:?}")),
        };
    let server = if server_deadline_failed {
        Err(format!("сервер превысил срок; терминальный исход: {server_join:?}; recovery stages: {recovery_errors:?}"))
    } else {
        match server_join {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(_))) => Err(format!(
                "сервер завершился с ошибкой; recovery stages: {recovery_errors:?}"
            )),
            other => Err(format!(
                "сервер: неожиданный исход {other:?}; recovery stages: {recovery_errors:?}"
            )),
        }
    };
    let recorder1 = if recorder1_deadline_failed {
        Err("рекордер1 превысил срок".to_string())
    } else {
        describe_recorder("рекордер1", recorder1_join)
    };
    let recorder2 = if recorder2_deadline_failed {
        Err("рекордер2 превысил срок".to_string())
    } else {
        describe_recorder("рекордер2", recorder2_join)
    };
    SuppliedCleanup {
        server,
        recorder1,
        recorder2,
        trap_cancelled,
        drains_ok,
        backlog,
    }
}

// owner-contract-pid файлы владельцев в owners-v1 под каталогом состояния.
pub(crate) fn owner_pids(dir: &std::path::Path) -> Vec<(std::path::PathBuf, u32)> {
    let mut found = Vec::new();
    pids(dir, &mut found);
    found
        .into_iter()
        .filter(|(path, _)| path.to_string_lossy().contains("owners-v1"))
        .collect()
}

// Положительный свидетель shutdown: обработчики abort_all роняют сокеты —
// клиент видит 0 байт либо ошибку соединения.
pub(crate) async fn read_closed(client: &mut TcpStream) -> bool {
    let mut byte = [0u8; 1];
    match client.read(&mut byte).await {
        Ok(0) | Err(_) => true,
        Ok(_) => false,
    }
}

// Аутентификация SOCKS5-клиента (USER/PASS) на производственном слушателе.
pub(crate) async fn socks_auth(user: &str, pass: &str, address: std::net::SocketAddr) -> TcpStream {
    let mut client = TcpStream::connect(address).await.unwrap();
    client.write_all(&[5, 1, 2]).await.unwrap();
    let mut reply = [0; 2];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 2]);
    let mut request = vec![1, user.len() as u8];
    request.extend_from_slice(user.as_bytes());
    request.push(pass.len() as u8);
    request.extend_from_slice(pass.as_bytes());
    client.write_all(&request).await.unwrap();
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [1, 0]);
    client
}

// CONNECT к 1.1.1.1:443: публичный unicast, проходит адресный фильтр
// (address.rs:316-328, 507-533), иначе отказ до bootstrap; рекордер при этом
// видит адрес МОСТА 127.0.0.77:443 (передаётся PT in-band).
pub(crate) async fn socks_connect(client: &mut TcpStream) {
    client
        .write_all(&[5, 1, 0, 1, 1, 1, 1, 1, 1, 187])
        .await
        .unwrap();
}

// Рукопожатие pre-proxy до проверки пароля: возвращает пароль носителя;
// auth-success [1,0] НЕ отправляет — решение за проверяющим адаптером
// (порядок как в HEAD: проверка пароля до [1,0]).
pub(crate) async fn proxy_negotiate(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut header = [0; 2];
    stream.read_exact(&mut header).await?;
    assert_eq!(header[0], 5);
    let mut methods = vec![0; header[1] as usize];
    stream.read_exact(&mut methods).await?;
    assert!(methods.contains(&2));
    stream.write_all(&[5, 2]).await?;
    stream.read_exact(&mut header).await?;
    assert_eq!(header[0], 1);
    let mut user = vec![0; header[1] as usize];
    stream.read_exact(&mut user).await?;
    let pass_len = stream.read_u8().await?;
    let mut pass = vec![0; pass_len as usize];
    stream.read_exact(&mut pass).await?;
    assert_eq!(user, b"alice");
    Ok(pass)
}

// Тело сессии после аутентификации: CONNECT к ловушке, носитель, дрейн.
pub(crate) async fn proxy_serve(stream: &mut TcpStream, pass: Vec<u8>, report: impl Fn(Vec<u8>)) {
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
    // Репортёр носителя: паника/переполнение решаются на месте вызова.
    report(pass);
    let mut discard = [0; 1024];
    while stream.read(&mut discard).await.unwrap_or(0) != 0 {}
}

// Kernel-backed witness: /proc/net/tcp общий для network namespace, а не
// PID-specific; inode из таблицы связывается с fd именно указанного процесса.
pub(crate) fn tcp_source_owned_by(stream: &TcpStream, pid: u32) -> Result<(), &'static str> {
    use std::io::Read;
    use std::net::{Ipv4Addr, SocketAddr};

    fn decode_endpoint(value: &str) -> Result<(Ipv4Addr, u16), &'static str> {
        let (address, port) = value.split_once(':').ok_or("malformed tcp endpoint")?;
        if address.len() != 8 || port.len() != 4 {
            return Err("malformed tcp endpoint");
        }
        let address = u32::from_str_radix(address, 16).map_err(|_| "malformed tcp endpoint")?;
        let port = u16::from_str_radix(port, 16).map_err(|_| "malformed tcp endpoint")?;
        Ok((Ipv4Addr::from(address.to_le_bytes()), port))
    }

    let source = match stream
        .peer_addr()
        .map_err(|_| "socket address unavailable")?
    {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => return Err("non-IPv4 socket"),
    };
    let destination = match stream
        .local_addr()
        .map_err(|_| "socket address unavailable")?
    {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => return Err("non-IPv4 socket"),
    };

    let file = std::fs::File::open("/proc/net/tcp").map_err(|_| "tcp table unavailable")?;
    let mut contents = String::new();
    file.take(1024 * 1024 + 1)
        .read_to_string(&mut contents)
        .map_err(|_| "tcp table unreadable")?;
    if contents.len() > 1024 * 1024 {
        return Err("tcp table exceeds limit");
    }
    let mut lines = contents.lines();
    let _header = lines.next().ok_or("tcp table malformed")?;
    let mut line_count = 1usize;
    let mut matching_inode = None;
    let mut matches = 0usize;
    for line in lines {
        line_count += 1;
        if line_count > 8192 {
            return Err("tcp table exceeds line limit");
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() <= 9 {
            return Err("tcp table malformed");
        }
        if fields[3] != "01" {
            continue;
        }
        let local = decode_endpoint(fields[1])?;
        let remote = decode_endpoint(fields[2])?;
        if local == (*source.ip(), source.port())
            && remote == (*destination.ip(), destination.port())
        {
            let inode = fields[9]
                .parse::<u64>()
                .map_err(|_| "tcp table malformed")?;
            matches += 1;
            matching_inode = Some(inode);
        }
    }
    if matches != 1 {
        return Err("accepted socket not uniquely found");
    }
    let inode = matching_inode.ok_or("accepted socket not found")?;
    let fd_dir =
        std::fs::read_dir(format!("/proc/{pid}/fd")).map_err(|_| "process fds unavailable")?;
    let mut fd_count = 0usize;
    let mut owned = false;
    for entry in fd_dir {
        let entry = entry.map_err(|_| "process fd listing failed")?;
        fd_count += 1;
        if fd_count > 256 {
            return Err("process fd limit exceeded");
        }
        let target = std::fs::read_link(entry.path()).map_err(|_| "process fd unreadable")?;
        if target.to_str() == Some(format!("socket:[{inode}]").as_str()) {
            owned = true;
        }
    }
    if owned {
        Ok(())
    } else {
        Err("socket not owned by process")
    }
}

// Старый fixture: порядок и call semantics как в HEAD — допустимы ТОЛЬКО
// first/second, проверка пароля ДО отправки auth-success [1,0]; паника при
// чужих учётных данных (поведение не менялось).
async fn proxy_connection(stream: TcpStream, report: impl Fn(Vec<u8>)) {
    let mut stream = stream;
    let pass = proxy_negotiate(&mut stream).await.unwrap();
    assert!(
        pass == b"first" || pass == b"second",
        "чужие учётные данные"
    );
    stream.write_all(&[1, 0]).await.unwrap();
    proxy_serve(&mut stream, pass, report).await;
}

// Endpoint-specific проверка supplied-сценариев: чужой пароль -> паника
// воркера -> терминальный счётчик паник. Порядок как в HEAD: проверка ДО [1,0].
// Порядок как в HEAD: проверка ДО [1,0].
// В сообщении паники пароля нет — только opaque label рекордера. ВЕСЬ сеанс
// (negotiate+serve) накрыт per-worker дедлайном 60с: воркер гарантированно
// завершается сам (Err -> счётчик worker_timeouts, не внешний timeout).
pub(crate) const WORKER_DEADLINE_MSG: &str = "воркер превысил per-worker дедлайн 60с";

pub(crate) async fn proxy_connection_checked(
    stream: TcpStream,
    allowed: &[&[u8]],
    label: &'static str,
    report: impl Fn(Vec<u8>),
) -> Result<(), &'static str> {
    match tokio::time::timeout(Duration::from_secs(60), async {
        let mut stream = stream;
        let pass = proxy_negotiate(&mut stream)
            .await
            .map_err(|_| "pre-negotiate не удалась")?;
        if !allowed.contains(&pass.as_slice()) {
            // Паника = терминальный маркер чужих учётных данных.
            panic!("чужие учётные данные на {label}");
        }
        stream
            .write_all(&[1, 0])
            .await
            .map_err(|_| "auth-success не отправлен")?;
        proxy_serve(&mut stream, pass, report).await;
        Ok(())
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(WORKER_DEADLINE_MSG),
    }
}

pub(crate) fn pids(dir: &std::path::Path, found: &mut Vec<(std::path::PathBuf, u32)>) {
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
                        workers.spawn(proxy_connection(stream, {
                            // Клон на итерацию: оригинал остаётся в задаче
                            // (иначе E0382 на 2-й итерации move-in-loop).
                            let events_tx = events_tx.clone();
                            move |pass| {
                                // Семантика прежняя: паника при закрытом unbounded-канале.
                                events_tx.send(pass).unwrap();
                            }
                        }));
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

// Fail-closed: bridges.use_seeds=true по умолчанию (proxy-config/src/lib.rs:
// 733-734) — restricted_owner_settings (owner_settings.rs:24-25) отвергает
// конфиг на этапе ПОДГОТОВКИ settings: server.rs:143 сохраняет Result без ?,
// bind_listeners (server.rs:168) УСПЕШНО поднимает слушатель, и только
// SettingsInit::start/wait_startup (server.rs:231-237 -> tor_setup.rs:70)
// возвращает Err ДО GlobalInit/PT/сети (GlobalInit: server.rs:258).
// run_server возвращает Err с "use_seeds"; готовность (server_ready,
// server.rs:457) не наступает, PT-ребёнок не запускается.
pub(crate) async fn run_supplied_config_seeds_rejected() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let _serial = crate::server::owners::TEST_LIFECYCLE.lock().await;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_address = listener.local_addr().unwrap();
        drop(listener);
        let mut cfg = crate::config::Config {
            listen: vec![listener_address.to_string()],
            pre_socks5: Some(proxy_config::EndpointOverride::Endpoint(
                "127.0.0.1:1080".parse().unwrap(),
            )),
            ..Default::default()
        };
        cfg.log.ansi = true;
        let config_path = dir.path().join("seeds.ktav");
        std::fs::write(&config_path, ktav::to_string(&cfg).unwrap()).unwrap();
        // bridges.use_seeds/auto_fetch намеренно оставлены по умолчанию (true).
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let writer = crate::bridge_store_writer::StoreWriter::spawn(
            bridge_store::BridgeStore::resolve_path(Some(&config_path)),
            Arc::new(|_| Ok(())),
            Duration::from_secs(3600),
        );
        let hook = Arc::new(super::super::super::global_init::ShutdownHook {
            settings: Settings::default(),
            writer,
            ready: std::sync::Mutex::new(Some(ready_tx)),
        });
        let args = super::super::super::ServerArgs {
            config_override: Some(config_path.clone()),
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
        let result = tokio::time::timeout(Duration::from_secs(20), &mut server.0)
            .await
            .unwrap()
            .unwrap();
        let error = result.expect_err("use_seeds=true обязан отклоняться");
        assert!(
            error.to_string().contains("use_seeds"),
            "неожиданная ошибка: {error}"
        );
        // Отказ на этапе settings: готовность не наступала (server_ready —
        // server.rs:457, после отказной стадии 231-237); отправитель готовности
        // упал вместе с задачей сервера.
        let readiness = tokio::time::timeout(Duration::from_secs(5), ready_rx)
            .await
            .unwrap();
        assert!(
            readiness.is_err(),
            "готовность наступила несмотря на отказ settings"
        );
        // Ни один PT-ребёнок не запускался: pid-файлов владельцев нет вообще.
        let mut children = Vec::new();
        pids(dir.path(), &mut children);
        assert!(
            children.is_empty(),
            "PT-ребёнок при отказе settings: {children:?}"
        );
        let _ = shutdown_tx.send(());
    })
    .await
    .expect("seeds-reject contract timed out");
}
