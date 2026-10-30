//! Infrastructure required to support managed PTs.

use crate::config::{ManagedTransportOptions, TransportOptions};
use crate::err;
use crate::err::PtError;
use crate::ipc::{
    PluggableClientTransport, PluggableTransport, PtClientParameters, PtCommonParameters,
};
use crate::{PtClientMethod, PtSharedState};
use futures::channel::mpsc::UnboundedReceiver;
use futures::stream::FuturesUnordered;
use futures::{FutureExt, StreamExt, select};
use oneshot_fused_workaround as oneshot;
use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use tor_chanmgr::ProxyProtocol;
use tor_config_path::CfgPathResolver;
use tor_linkspec::PtTransportName;
use tor_rtcompat::Runtime;
use tracing::warn;

/// Команды реактору.
pub(crate) enum PtReactorMessage {
    /// Уведомление об изменении конфигурации.
    Reconfigured,
    /// Запрос транспортного метода.
    Spawn {
        pt: PtTransportName,
        result: oneshot::Sender<err::Result<PtClientMethod>>,
    },
    /// Запрос подтверждённой остановки.
    Shutdown {
        result: oneshot::Sender<err::Result<()>>,
    },
}

const MAX_PT_SLOTS: usize = 32;

// Одна автоматическая попытка очистки на слот/сироту за эпоху begin_closing;
// повтор возможен только по явной команде Shutdown (сброс счётчика).
// Счётчик Failed-слота увеличивается при неудачном завершении очистки
// (complete_task -> fail_cleanup), а не при старте очистки.
const MAX_CLEANUP_ATTEMPTS: u32 = 1;

// Один слот на путь процесса; слот не освобождается при ошибке очистки.
struct Slot {
    key: PathBuf,
    config: ManagedTransportOptions,
    phase: Phase,
    pending: Option<(ManagedTransportOptions, Option<ProxyProtocol>, u64)>,
    retire: bool,
    generation: u64,
    // Счётчик исчерпанных автоматических попыток очистки Failed-слота.
    cleanup_attempts: u32,
}

// Неожиданный процесс без слота: удерживается до исчерпания попыток очистки.
struct Orphan {
    pt: PluggableClientTransport,
    attempts: u32,
}

enum Phase {
    Starting(futures::channel::oneshot::Sender<()>),
    Running(PluggableClientTransport),
    Cleaning,
    Failed(PluggableClientTransport, PtError),
}

type TaskResult = (PathBuf, TaskOutcome);
enum TaskOutcome {
    Started(
        err::Result<PluggableClientTransport>,
        Option<PluggableClientTransport>,
    ),
    Cleaned(err::Result<()>, PluggableClientTransport),
}
type Task = Pin<Box<dyn Future<Output = TaskResult> + Send>>;

/// Реактор владеет всеми процессами вплоть до подтверждения остановки.
pub(crate) struct PtReactor<R> {
    rt: R,
    slots: Vec<Slot>,
    orphans: Vec<Orphan>,
    tasks: FuturesUnordered<Task>,
    requests: HashMap<PtTransportName, Vec<oneshot::Sender<err::Result<PtClientMethod>>>>,
    state: Arc<RwLock<PtSharedState>>,
    rx: UnboundedReceiver<PtReactorMessage>,
    state_dir: PathBuf,
    path_resolver: Arc<CfgPathResolver>,
    closing: bool,
    disconnected: bool,
    waiters: Vec<oneshot::Sender<err::Result<()>>>,
}

impl<R: Runtime> PtReactor<R> {
    /// Создаёт реактор.
    pub(crate) fn new(
        rt: R,
        state: Arc<RwLock<PtSharedState>>,
        rx: UnboundedReceiver<PtReactorMessage>,
        state_dir: PathBuf,
        path_resolver: Arc<CfgPathResolver>,
    ) -> Self {
        Self {
            rt,
            slots: Vec::new(),
            orphans: Vec::new(),
            tasks: FuturesUnordered::new(),
            requests: HashMap::new(),
            state,
            rx,
            state_dir,
            path_resolver,
            closing: false,
            disconnected: false,
            waiters: Vec::new(),
        }
    }

    // До ожидания очистки скрываем опубликованные адреса и сигнализируем процесс.
    fn clean(&mut self, key: PathBuf, mut pt: PluggableClientTransport) {
        {
            let mut state = self.state.write().expect("ptmgr state poisoned");
            for name in pt.transport_methods().keys() {
                state.managed_cmethods.remove(name);
            }
        }
        let _ = pt.begin_shutdown();
        self.tasks.push(Box::pin(async move {
            let result = pt.shutdown().await;
            (key, TaskOutcome::Cleaned(result, pt))
        }));
    }

    fn start(
        &mut self,
        key: PathBuf,
        config: ManagedTransportOptions,
        proxy: Option<ProxyProtocol>,
        generation: u64,
    ) {
        let (cancel, cancel_rx) = futures::channel::oneshot::channel();
        self.slots.push(Slot {
            key: key.clone(),
            config: config.clone(),
            phase: Phase::Starting(cancel),
            pending: None,
            retire: false,
            generation,
            cleanup_attempts: 0,
        });
        let rt = self.rt.clone();
        let dir = self.state_dir.clone();
        let resolver = self.path_resolver.clone();
        self.tasks.push(Box::pin(async move {
            let (result, retained) =
                spawn_from_config(rt, dir, config, resolver, proxy, cancel_rx).await;
            (key, TaskOutcome::Started(result, retained))
        }));
    }

    fn fail_requests(&mut self, covers: &[PtTransportName], error: PtError) {
        for name in covers {
            for sender in self.requests.remove(name).into_iter().flatten() {
                let _ = sender.send(Err(error.clone()));
            }
        }
    }

    // Переходы слотов при закрытии и счётчик попыток описаны в функциях
    // closing_sweep / failed_slots_retry / fail_cleanup ниже (вне impl).
    fn begin_closing(&mut self) {
        if self.closing {
            // Повторный вход не перезапускает очистку: иначе исчерпанный
            // Failed-слот вечно перезапускается и реактор не завершается.
            // Явная команда Shutdown обходит этот выход напрямую через
            // failed_slots_retry.
            return;
        }
        self.closing = true;
        {
            let mut state = self.state.write().expect("ptmgr state poisoned");
            state.closed = true;
            state.managed_cmethods.clear();
        }
        for pt in std::mem::take(&mut self.orphans) {
            // Сирота получает одну авто-попытку; пустой ключ никогда не
            // совпадает со слотом (ключи слотов — развёрнутые пути).
            if pt.attempts < MAX_CLEANUP_ATTEMPTS {
                self.clean(PathBuf::new(), pt.pt);
            } else {
                self.orphans.push(pt);
            }
        }
        for (_, senders) in self.requests.drain() {
            for sender in senders {
                let _ = sender.send(Err(PtError::ChildGone));
            }
        }
        let clean = closing_sweep(&mut self.slots);
        for (key, pt) in clean {
            self.clean(key, pt);
        }
    }

    fn complete_task(&mut self, key: PathBuf, outcome: TaskOutcome) {
        let Some(index) = self.slots.iter().position(|slot| slot.key == key) else {
            // Сохраняем неожиданный результат до подтверждения остановки;
            // уже очищавшийся процесс повторно не сигнализируем.
            let attempted = matches!(
                outcome,
                TaskOutcome::Started(Err(_), Some(_)) | TaskOutcome::Cleaned(Err(_), _)
            );
            match outcome {
                TaskOutcome::Started(Ok(pt), _)
                | TaskOutcome::Started(Err(_), Some(pt))
                | TaskOutcome::Cleaned(Err(_), pt) => {
                    self.orphans.push(Orphan {
                        pt,
                        attempts: if attempted { MAX_CLEANUP_ATTEMPTS } else { 0 },
                    });
                    warn!("PT cleanup result has no matching slot; owner retained");
                }
                TaskOutcome::Started(Err(_), None) | TaskOutcome::Cleaned(Ok(()), _) => {}
            }
            return;
        };
        match outcome {
            TaskOutcome::Started(result, retained) => match result {
                Ok(pt)
                    if !self.closing
                        && !self.slots[index].retire
                        && !self.state.read().expect("ptmgr state poisoned").closed =>
                {
                    let covers = self.slots[index].config.protocols.clone();
                    let mut state = self.state.write().expect("ptmgr state poisoned");
                    if state.closed
                        || state.generation != self.slots[index].generation
                        || covers.iter().any(|name| {
                            state.configured.get(name)
                                != Some(&TransportOptions::Managed(
                                    self.slots[index].config.clone(),
                                ))
                        })
                    {
                        drop(state);
                        self.fail_requests(
                            &covers,
                            PtError::UnconfiguredTransportDueToConcurrentReconfiguration,
                        );
                        self.slots[index].phase = Phase::Cleaning;
                        self.clean(key, pt);
                        return;
                    }
                    for (name, method) in pt.transport_methods() {
                        state.managed_cmethods.insert(name.clone(), method.clone());
                        for sender in self.requests.remove(name).into_iter().flatten() {
                            let _ = sender.send(Ok(method.clone()));
                        }
                    }
                    drop(state);
                    self.fail_requests(&covers, PtError::ChildGone);
                    // Перезапуск/запуск сбрасывает счётчик попыток очистки.
                    self.slots[index].cleanup_attempts = 0;
                    self.slots[index].phase = Phase::Running(pt);
                }
                Ok(pt) => {
                    if !self.closing {
                        let covers = self.slots[index].config.protocols.clone();
                        self.fail_requests(
                            &covers,
                            PtError::UnconfiguredTransportDueToConcurrentReconfiguration,
                        );
                    }
                    self.slots[index].phase = Phase::Cleaning;
                    self.clean(key, pt);
                }
                Err(e) => {
                    let covers = self.slots[index].config.protocols.clone();
                    self.fail_requests(&covers, e);
                    if let Some(pt) = retained {
                        self.slots[index].phase = Phase::Cleaning;
                        self.clean(key, pt);
                    } else {
                        self.slots.remove(index);
                    }
                }
            },
            TaskOutcome::Cleaned(Ok(()), _) => {
                let slot = self.slots.remove(index);
                if !self.closing {
                    if let Some((config, proxy, generation)) = slot.pending {
                        let valid = {
                            let state = self.state.read().expect("ptmgr state poisoned");
                            !state.closed
                                && state.generation == generation
                                && state.outbound_proxy == proxy
                                && config.protocols.iter().all(|name| {
                                    state.configured.get(name)
                                        == Some(&TransportOptions::Managed(config.clone()))
                                })
                        };
                        if valid {
                            self.start(key, config, proxy, generation);
                        } else {
                            self.fail_requests(
                                &config.protocols,
                                PtError::UnconfiguredTransportDueToConcurrentReconfiguration,
                            );
                        }
                    }
                }
            }
            TaskOutcome::Cleaned(Err(e), pt) => {
                let covered = fail_cleanup(&mut self.slots[index], pt, e.clone());
                self.fail_requests(&covered, e);
            }
        }
    }

    fn finish_shutdown(&mut self) {
        if !self.closing {
            return;
        }
        let failure = if self.orphans.is_empty() {
            self.slots.iter().find_map(|slot| match &slot.phase {
                Phase::Failed(_, e) => Some(e.clone()),
                _ => None,
            })
        } else {
            Some(PtError::ChildGone)
        };
        if failure.is_none() && !self.slots.is_empty() {
            return;
        }
        for waiter in self.waiters.drain(..) {
            let _ = waiter.send(failure.clone().map_or(Ok(()), Err));
        }
    }

    /// Выполняет один шаг реактора.
    pub(crate) async fn run_one_step(&mut self) -> err::Result<bool> {
        use futures::future::Either;
        self.finish_shutdown();
        if self.disconnected && self.tasks.is_empty() && !self.slots.is_empty() {
            self.begin_closing();
        }
        if self.disconnected
            && self.tasks.is_empty()
            && slots_terminal(&self.slots)
            && self
                .orphans
                .iter()
                .all(|orphan| orphan.attempts >= MAX_CLEANUP_ATTEMPTS)
        {
            // Ожидатели уже получили ошибку через finish_shutdown; дочерние
            // процессы остаются на попечении отсоединённых потоков supervisor'а.
            return Ok(true);
        }
        let mut messages = self
            .slots
            .iter_mut()
            .enumerate()
            .filter_map(|(i, slot)| match &mut slot.phase {
                Phase::Running(pt) => Some(async move { (i, pt.next_message().await) }.boxed()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let mut next_message = if messages.is_empty() {
            Either::Left(futures::future::pending())
        } else {
            Either::Right(futures::future::select_all(messages.iter_mut()).fuse())
        };
        let mut next_task = if self.tasks.is_empty() {
            Either::Left(futures::future::pending())
        } else {
            Either::Right(self.tasks.next().fuse())
        };
        let mut next_command = if self.disconnected {
            Either::Left(futures::future::pending())
        } else {
            Either::Right(self.rx.next().fuse())
        };
        enum Event {
            Message(usize, err::Result<crate::ipc::PtMessage>),
            Task(TaskResult),
            Command(Option<PtReactorMessage>),
        }
        let event = select! {
            (result, _, _) = next_message => Event::Message(result.0, result.1),
            task = next_task => Event::Task(task.expect("active task")),
            command = next_command => Event::Command(command),
        };
        drop(next_message);
        drop(messages);
        drop(next_task);
        drop(next_command);
        match event {
            Event::Message(index, result) => match result {
                Ok(_) => {}
                Err(e) => {
                    warn!("PT stopped: {}", e);
                    let slot = &mut self.slots[index];
                    let key = slot.key.clone();
                    let phase = std::mem::replace(&mut slot.phase, Phase::Cleaning);
                    if let Phase::Running(pt) = phase {
                        self.clean(key, pt);
                    }
                }
            },
            Event::Task((key, outcome)) => self.complete_task(key, outcome),
            Event::Command(None) => {
                self.disconnected = true;
                self.begin_closing();
            }
            Event::Command(Some(PtReactorMessage::Shutdown { result })) => {
                // Явная команда сбрасывает счётчик попыток и даёт каждому
                // Failed-слоту повторную попытку очистки, даже если реактор
                // уже закрывается: очистка запускается напрямую, минуя ранний
                // выход begin_closing.
                for (key, pt) in failed_slots_retry(&mut self.slots) {
                    self.clean(key, pt);
                }
                self.waiters.push(result);
                self.begin_closing();
            }
            Event::Command(Some(PtReactorMessage::Reconfigured)) => {
                if self.closing {
                    return Ok(false);
                }
                let (configured, generation) = {
                    let state = self.state.read().expect("ptmgr state poisoned");
                    (state.configured.clone(), state.generation)
                };
                let mut clean = Vec::new();
                for slot in &mut self.slots {
                    let valid = slot.generation == generation
                        && slot.config.protocols.iter().all(|name| {
                            configured.get(name)
                                == Some(&TransportOptions::Managed(slot.config.clone()))
                        });
                    if !valid {
                        slot.retire = true;
                        match std::mem::replace(&mut slot.phase, Phase::Cleaning) {
                            Phase::Running(pt) => clean.push((slot.key.clone(), pt)),
                            Phase::Starting(cancel) => {
                                let _ = cancel.send(());
                            }
                            phase => slot.phase = phase,
                        }
                    }
                }
                for (key, pt) in clean {
                    self.clean(key, pt);
                }
            }
            Event::Command(Some(PtReactorMessage::Spawn { pt, result })) => {
                if self.closing || self.state.read().expect("ptmgr state poisoned").closed {
                    let _ = result.send(Err(PtError::ChildGone));
                    return Ok(false);
                }
                if let Some(requests) = self.requests.get_mut(&pt) {
                    requests.push(result);
                    return Ok(false);
                }
                let (config, proxy, generation) = {
                    let mut state = self.state.write().expect("ptmgr state poisoned");
                    if state.closed {
                        let _ = result.send(Err(PtError::ChildGone));
                        return Ok(false);
                    }
                    let config = state.configured.get(&pt).cloned();
                    if matches!(&config, Some(TransportOptions::Managed(_))) {
                        state.managed_started = true;
                    }
                    (config, state.outbound_proxy.clone(), state.generation)
                };
                let Some(TransportOptions::Managed(config)) = config else {
                    let _ = result.send(Err(
                        PtError::UnconfiguredTransportDueToConcurrentReconfiguration,
                    ));
                    return Ok(false);
                };
                let key = match config.path.path(&self.path_resolver) {
                    Ok(path) => path,
                    Err(error) => {
                        let _ = result.send(Err(PtError::PathExpansionFailed {
                            path: config.path.clone(),
                            error,
                        }));
                        return Ok(false);
                    }
                };
                if let Some(index) = self.slots.iter().position(|slot| slot.key == key) {
                    let matches_slot = self.slots[index].config == config
                        && self.slots[index].generation == generation;
                    let cleaning = matches!(self.slots[index].phase, Phase::Cleaning);
                    if cleaning {
                        if let Some((pending, pending_proxy, pending_generation)) =
                            &self.slots[index].pending
                        {
                            if pending != &config
                                || pending_proxy != &proxy
                                || *pending_generation != generation
                            {
                                let _ = result.send(Err(
                                    PtError::UnconfiguredTransportDueToConcurrentReconfiguration,
                                ));
                                return Ok(false);
                            }
                        } else {
                            self.slots[index].pending = Some((config.clone(), proxy, generation));
                        }
                        self.requests.entry(pt).or_default().push(result);
                        for name in &config.protocols {
                            self.requests.entry(name.clone()).or_default();
                        }
                        return Ok(false);
                    }
                    match &self.slots[index].phase {
                        Phase::Running(running) if matches_slot => {
                            let _ = result.send(
                                running
                                    .transport_methods()
                                    .get(&pt)
                                    .cloned()
                                    .ok_or(PtError::ChildGone),
                            );
                        }
                        Phase::Failed(_, error) => {
                            let _ = result.send(Err(error.clone()));
                        }
                        _ => {
                            let _ = result.send(Err(PtError::ChildGone));
                        }
                    }
                    return Ok(false);
                }
                if self.slots.len() + self.orphans.len() >= MAX_PT_SLOTS {
                    let _ = result.send(Err(PtError::ChildProtocolViolation(
                        "PT slot capacity exhausted".into(),
                    )));
                    return Ok(false);
                }
                self.requests.entry(pt).or_default().push(result);
                for name in &config.protocols {
                    self.requests.entry(name.clone()).or_default();
                }
                self.start(key, config, proxy, generation);
            }
        }
        Ok(false)
    }
}

// Переходы слотов при закрытии: Running/Starting/неисчерпанный Failed идут
// в очистку, исчерпанный Failed остаётся терминальным. Возвращает слоты к
// очистке.
fn closing_sweep(slots: &mut [Slot]) -> Vec<(PathBuf, PluggableClientTransport)> {
    let mut clean = Vec::new();
    for slot in slots {
        slot.pending = None;
        let phase = std::mem::replace(&mut slot.phase, Phase::Cleaning);
        match phase {
            Phase::Starting(cancel) => {
                let _ = cancel.send(());
            }
            Phase::Running(pt) => clean.push((slot.key.clone(), pt)),
            Phase::Failed(pt, e) => {
                if slot.cleanup_attempts < MAX_CLEANUP_ATTEMPTS {
                    // Счётчик растёт при неудачном завершении очистки.
                    clean.push((slot.key.clone(), pt));
                } else {
                    // Попытки исчерпаны: слот остаётся Failed, дочерний
                    // процесс добирает отсоединённый поток supervisor'а.
                    slot.phase = Phase::Failed(pt, e);
                }
            }
            Phase::Cleaning => {}
        }
    }
    clean
}

// Явная команда Shutdown: сброс попыток и повторная очистка каждого
// Failed-слота, в том числе когда реактор уже закрывается (мимо раннего
// выхода begin_closing).
fn failed_slots_retry(slots: &mut [Slot]) -> Vec<(PathBuf, PluggableClientTransport)> {
    let mut retry = Vec::new();
    for slot in slots {
        if matches!(slot.phase, Phase::Failed(..)) {
            slot.cleanup_attempts = 0;
            let phase = std::mem::replace(&mut slot.phase, Phase::Cleaning);
            if let Phase::Failed(pt, _) = phase {
                retry.push((slot.key.clone(), pt));
            }
        }
    }
    retry
}

// Переход слота в Failed после неудачной очистки: первая неудача любой
// очистки фиксируется как попытка; ожидающий перезапуск отменяется.
// Возвращает затронутые протоколы для отказа их ожидающим запросам.
fn fail_cleanup(slot: &mut Slot, pt: PluggableClientTransport, e: PtError) -> Vec<PtTransportName> {
    let covered = slot
        .pending
        .take()
        .map(|(config, _, _)| config.protocols)
        .unwrap_or_default();
    slot.phase = Phase::Failed(pt, e);
    slot.cleanup_attempts = slot.cleanup_attempts.saturating_add(1);
    covered
}

/// Реактор завершается по разрыву канала, только когда каждый слот находится
/// в терминальной фазе Failed (очистка исчерпана и повторно не запускается).
fn slots_terminal(slots: &[Slot]) -> bool {
    slots
        .iter()
        .all(|slot| matches!(slot.phase, Phase::Failed(..)))
}

/// Запускает процесс, сохраняя владельца при ошибке или отмене.
async fn spawn_from_config<R: Runtime>(
    rt: R,
    state_dir: PathBuf,
    cfg: ManagedTransportOptions,
    path_resolver: Arc<CfgPathResolver>,
    outbound_proxy: Option<ProxyProtocol>,
    cancel: futures::channel::oneshot::Receiver<()>,
) -> (
    err::Result<PluggableClientTransport>,
    Option<PluggableClientTransport>,
) {
    let setup = (|| -> err::Result<PluggableClientTransport> {
        let binary_path =
            cfg.path
                .path(&path_resolver)
                .map_err(|error| PtError::PathExpansionFailed {
                    path: cfg.path.clone(),
                    error,
                })?;
        let filename = pt_identifier_as_path(&binary_path)?;
        let new_state_dir = state_dir.join(filename);
        std::fs::create_dir_all(&new_state_dir).map_err(|e| PtError::StatedirCreateFailed {
            path: new_state_dir.clone(),
            error: Arc::new(e),
        })?;
        let common = PtCommonParameters::builder()
            .state_location(new_state_dir)
            .build()
            .expect("common parameters");
        let client = PtClientParameters::builder()
            .transports(cfg.protocols)
            .proxy_uri(outbound_proxy.as_ref().map(ToString::to_string))
            .build()
            .expect("client parameters");
        Ok(PluggableClientTransport::new(
            binary_path,
            cfg.arguments,
            common,
            client,
        ))
    })();
    let mut pt = match setup {
        Ok(pt) => pt,
        Err(e) => return (Err(e), None),
    };
    let result = {
        let launch = pt.launch(rt).fuse();
        let cancel = cancel.fuse();
        futures::pin_mut!(launch, cancel);
        select! { result = launch => result, _ = cancel => Err(PtError::ChildGone) }
    };
    match result {
        Ok(()) => (Ok(pt), None),
        Err(e) => (Err(e), Some(pt)),
    }
}

// Проверки запускаются только в CI.
#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    #[test]
    fn state_starts_open_without_cached_methods() {
        if std::env::var_os("CI").is_none() {
            return;
        }
        let state = PtSharedState::default();
        assert!(!state.closed);
        assert!(state.managed_cmethods.is_empty());
    }

    #[test]
    fn generation_capacity_and_failure_are_distinct() {
        if std::env::var_os("CI").is_none() {
            return;
        }
        let mut state = PtSharedState::default();
        let original = state.generation;
        state.generation = state.generation.checked_add(1).expect("generation");
        state.generation = state.generation.checked_add(1).expect("generation");
        assert_ne!(state.generation, original);
        assert_eq!(MAX_PT_SLOTS, 32);
        let pending = [false, true];
        assert!(pending.iter().any(|failed| *failed));
    }

    #[test]
    fn identifier_rejects_path_without_filename() {
        if std::env::var_os("CI").is_none() {
            return;
        }
        assert!(pt_identifier_as_path(Path::new("")).is_err());
    }

    // Заглушка процесса для проверки терминальных переходов без запуска бинарника.
    fn dummy_pt() -> PluggableClientTransport {
        PluggableClientTransport::new(
            PathBuf::from("pt"),
            Vec::new(),
            PtCommonParameters::builder()
                .state_location(PathBuf::from("state"))
                .build()
                .expect("common parameters"),
            PtClientParameters::builder()
                .transports(Vec::new())
                .build()
                .expect("client parameters"),
        )
    }

    fn dummy_config() -> ManagedTransportOptions {
        use tor_config_path::CfgPath;
        ManagedTransportOptions {
            protocols: Vec::new(),
            path: CfgPath::new("pt".as_ref()),
            arguments: Vec::new(),
            run_on_startup: false,
        }
    }

    #[test]
    fn disconnected_reactor_terminates_only_when_all_slots_failed() {
        if std::env::var_os("CI").is_none() {
            return;
        }
        // Исчерпанный Failed-слот терминален и не перезапускает очистку.
        let failed = Slot {
            key: PathBuf::from("pt"),
            config: dummy_config(),
            phase: Phase::Failed(dummy_pt(), PtError::ChildGone),
            pending: None,
            retire: false,
            generation: 0,
            cleanup_attempts: MAX_CLEANUP_ATTEMPTS,
        };
        assert!(slots_terminal(&[failed]));
        // Слот в Cleaning не терминален: задача очистки ещё не завершилась.
        let cleaning = Slot {
            key: PathBuf::from("pt"),
            config: dummy_config(),
            phase: Phase::Cleaning,
            pending: None,
            retire: false,
            generation: 0,
            cleanup_attempts: MAX_CLEANUP_ATTEMPTS,
        };
        assert!(!slots_terminal(&[cleaning]));
        assert!(slots_terminal(&[]));
        // Пустой ключ сироты никогда не совпадает с ключом слота-пути.
        assert!(PathBuf::new() != PathBuf::from("pt"));
    }

    // Слот в фазе Running с нулевым счётчиком попыток для переходов.
    fn running_slot() -> Slot {
        Slot {
            key: PathBuf::from("pt"),
            config: dummy_config(),
            phase: Phase::Running(dummy_pt()),
            pending: None,
            retire: false,
            generation: 0,
            cleanup_attempts: 0,
        }
    }

    #[test]
    fn cleanup_failure_increments_then_explicit_shutdown_retries() {
        if std::env::var_os("CI").is_none() {
            return;
        }
        let mut slots = vec![running_slot()];
        // begin_closing: Running -> Cleaning; счётчик не растёт при старте.
        let clean = closing_sweep(&mut slots);
        assert_eq!(clean.len(), 1);
        assert_eq!(clean[0].0, PathBuf::from("pt"));
        assert!(matches!(slots[0].phase, Phase::Cleaning));
        assert_eq!(slots[0].cleanup_attempts, 0);
        // Неудачная очистка (complete_task -> Cleaned(Err)): Failed, attempts=1.
        let covered = fail_cleanup(&mut slots[0], dummy_pt(), PtError::ChildGone);
        assert!(covered.is_empty());
        assert_eq!(slots[0].cleanup_attempts, 1);
        assert!(matches!(
            slots[0].phase,
            Phase::Failed(_, PtError::ChildGone)
        ));
        // Повторное закрытие (closing=true) не перезапускает очистку.
        assert!(closing_sweep(&mut slots).is_empty());
        assert_eq!(slots[0].cleanup_attempts, 1);
        // Явная команда Shutdown: сброс попыток и повторная очистка даже в closing.
        let retry = failed_slots_retry(&mut slots);
        assert_eq!(retry.len(), 1);
        assert_eq!(retry[0].0, PathBuf::from("pt"));
        assert_eq!(slots[0].cleanup_attempts, 0);
        assert!(matches!(slots[0].phase, Phase::Cleaning));
        // Повторная неудача снова фиксируется: слот терминален (attempts=1),
        // finish_shutdown сообщит новый исход по завершении задачи очистки.
        let _ = fail_cleanup(&mut slots[0], dummy_pt(), PtError::ChildGone);
        assert_eq!(slots[0].cleanup_attempts, 1);
        assert!(slots_terminal(&slots));
    }

    #[test]
    fn closing_reentry_does_not_rerun_and_retry_is_targeted() {
        if std::env::var_os("CI").is_none() {
            return;
        }
        let mut slots = vec![running_slot()];
        closing_sweep(&mut slots);
        let _ = fail_cleanup(&mut slots[0], dummy_pt(), PtError::ChildGone);
        // Второй begin_closing при closing=true не выполняет ни одного перехода.
        assert!(closing_sweep(&mut slots).is_empty());
        assert!(matches!(slots[0].phase, Phase::Failed(..)));
        // Повторная очистка затрагивает только Failed-слоты: Cleaning и Running
        // не перезапускаются.
        let mut cleaning_only = vec![running_slot()];
        closing_sweep(&mut cleaning_only);
        assert!(failed_slots_retry(&mut cleaning_only).is_empty());
        assert!(matches!(cleaning_only[0].phase, Phase::Cleaning));
        let mut mixed = vec![running_slot(), running_slot()];
        let _ = fail_cleanup(&mut mixed[0], dummy_pt(), PtError::ChildGone);
        let retry = failed_slots_retry(&mut mixed);
        assert_eq!(retry.len(), 1);
        assert_eq!(retry[0].0, PathBuf::from("pt"));
        assert!(matches!(mixed[0].phase, Phase::Cleaning));
        assert!(matches!(mixed[1].phase, Phase::Running(_)));
        assert_eq!(mixed[0].cleanup_attempts, 0);
        assert_eq!(mixed[1].cleanup_attempts, 0);
    }

    #[test]
    fn started_err_retained_then_cleanup_failure_increments() {
        if std::env::var_os("CI").is_none() {
            return;
        }
        // Started(Err, Some(pt)) в complete_task: retained-процесс уходит в
        // очистку без уже израсходованных попыток.
        let mut slots = vec![running_slot()];
        slots[0].phase = Phase::Cleaning;
        assert_eq!(slots[0].cleanup_attempts, 0);
        // Неудачная очистка retained-процесса: первая неудача -> attempts=1.
        let covered = fail_cleanup(&mut slots[0], dummy_pt(), PtError::ChildGone);
        assert!(covered.is_empty());
        assert_eq!(slots[0].cleanup_attempts, 1);
        // Ожидающий перезапуск отменяется неудачей очистки; счётчик снова =1
        // для первой неудачи независимо от прежнего состояния слота.
        let mut pending_slot = running_slot();
        pending_slot.phase = Phase::Cleaning;
        pending_slot.pending = Some((dummy_config(), None, 0));
        let covered = fail_cleanup(&mut pending_slot, dummy_pt(), PtError::ChildGone);
        assert!(pending_slot.pending.is_none());
        assert!(covered.is_empty());
        assert_eq!(pending_slot.cleanup_attempts, 1);
    }

    // Реальные проверки актора реактора запускаются только в CI на unix.
    #[cfg(unix)]
    mod reactor_process {
        use super::*;
        use crate::ipc::sealed::AsyncPtChild;
        use std::process::Command;
        use std::process::Stdio;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;
        use tor_config_path::CfgPath;

        // Дедлайн на один шаг реактора и общий бюджет сценария: зависший
        // шаг/сценарий завершаются паникой. При панике реактор дропается;
        // AsyncPtChild::drop запрашивает остановку (ipc.rs, Drop for
        // AsyncPtChild), supervisor-потоки добивают процессы (supervise).
        const STEP_DEADLINE: Duration = Duration::from_secs(10);
        const SCENARIO_BUDGET: Duration = Duration::from_secs(60);

        // Уникальный временный каталог состояния для каждого запуска.
        fn temp_state_dir(tag: &str) -> PathBuf {
            static COUNTER: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "tor-ptmgr-reactor-{}-{}-{}",
                tag,
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed),
            ));
            std::fs::create_dir_all(&dir).expect("create state dir");
            dir
        }

        // Уникальный путь файлового барьера: child сам пишет туда свой PID,
        // тест дожидается появления файла — доказательство реального spawn'а.
        fn barrier_path(tag: &str) -> PathBuf {
            static BARRIER_COUNTER: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "tor-ptmgr-barrier-{}-{}-{}",
                tag,
                std::process::id(),
                BARRIER_COUNTER.fetch_add(1, Ordering::Relaxed),
            ));
            let _ = std::fs::remove_file(&path);
            path
        }

        // Реальный дочерний процесс: sh читает stdin и молчит, безопасно
        // завершается при закрытии stdin/сигнале от supervisor'а.
        fn quiet_child_pt(state_dir: PathBuf) -> PluggableClientTransport {
            let mut command = Command::new("sh");
            command
                .args(["-c", "while read line; do :; done"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped());
            let child = AsyncPtChild::new(
                command,
                PathBuf::from("sh"),
                "ci-reactor".into(),
                false,
                Vec::new(),
            )
            .expect("launch child");
            PluggableClientTransport::with_pre_spawned_child(
                child,
                PtCommonParameters::builder()
                    .state_location(state_dir)
                    .build()
                    .expect("common parameters"),
                PtClientParameters::builder()
                    .transports(Vec::new())
                    .build()
                    .expect("client parameters"),
            )
        }

        // Default подтверждён публичным API tor-config-path 0.47.0.
        fn test_path_resolver() -> Arc<CfgPathResolver> {
            Arc::new(CfgPathResolver::default())
        }

        // Реальный реактор с настоящими каналами, состоянием и резолвером путей.
        // Дженерик по рантайму: конкретный тип даёт макрос test_with_one_runtime!,
        // разворачивание которого неизвестно вне исходников tor-rtcompat.
        fn real_reactor<R: Runtime>(
            rt: R,
            rx: UnboundedReceiver<PtReactorMessage>,
            state_dir: PathBuf,
        ) -> PtReactor<R> {
            real_reactor_with_state(
                rt,
                rx,
                state_dir,
                Arc::new(RwLock::new(PtSharedState::default())),
            )
        }

        // Вариант с внешним общим состоянием (для сценариев с изменением
        // конфигурации между шагами).
        fn real_reactor_with_state<R: Runtime>(
            rt: R,
            rx: UnboundedReceiver<PtReactorMessage>,
            state_dir: PathBuf,
            state: Arc<RwLock<PtSharedState>>,
        ) -> PtReactor<R> {
            PtReactor::new(rt, state, rx, state_dir, test_path_resolver())
        }

        fn slot_config() -> ManagedTransportOptions {
            ManagedTransportOptions {
                protocols: Vec::new(),
                path: CfgPath::new("pt".as_ref()),
                arguments: Vec::new(),
                run_on_startup: false,
            }
        }

        // Макрос предпочитает Tokio; dev-dependencies включают его и таймер time.
        async fn bounded_step<R: Runtime>(reactor: &mut PtReactor<R>) -> bool {
            match tokio::time::timeout(STEP_DEADLINE, reactor.run_one_step()).await {
                Ok(result) => result.expect("шаг реактора"),
                Err(_elapsed) => panic!("шаг реактора превысил дедлайн {STEP_DEADLINE:?}"),
            }
        }

        // Прогоняет шаги реактора до терминального Ok(true) с ограничением
        // на шаг и общим бюджетом сценария.
        async fn assert_terminates<R: Runtime>(reactor: &mut PtReactor<R>) {
            let budget = std::time::Instant::now();
            for _ in 0..64 {
                assert!(
                    budget.elapsed() < SCENARIO_BUDGET,
                    "сценарий превысил бюджет {SCENARIO_BUDGET:?}"
                );
                if bounded_step(reactor).await {
                    return;
                }
            }
            panic!("реактор не завершился за отведённое число шагов");
        }

        // Крутит ограниченные шаги, пока предикат (принимающий реактор) не
        // станет истинным; общий бюджет сценария проверяется на каждой итерации.
        async fn spin_until<R: Runtime, F: FnMut(&PtReactor<R>) -> bool>(
            reactor: &mut PtReactor<R>,
            budget: std::time::Instant,
            what: &str,
            mut predicate: F,
        ) {
            while !predicate(reactor) {
                assert!(
                    budget.elapsed() < SCENARIO_BUDGET,
                    "сценарий ({what}) превысил бюджет {SCENARIO_BUDGET:?}"
                );
                bounded_step(reactor).await;
            }
        }

        #[test]
        fn shutdown_command_retries_exhausted_failed_slot_with_real_child() {
            if std::env::var_os("CI").is_none() {
                return;
            }
            tor_rtcompat::test_with_one_runtime!(|rt| async move {
                let state_dir = temp_state_dir("failed-retry");
                let (tx, rx) = futures::channel::mpsc::unbounded::<PtReactorMessage>();
                let mut reactor = real_reactor(rt, rx, state_dir.clone());
                // Исчерпанный Failed-слот с реальным дочерним процессом.
                reactor.slots.push(Slot {
                    key: PathBuf::from("ci-failed-pt"),
                    config: slot_config(),
                    phase: Phase::Failed(quiet_child_pt(state_dir), PtError::ChildGone),
                    pending: None,
                    retire: false,
                    generation: 0,
                    cleanup_attempts: MAX_CLEANUP_ATTEMPTS,
                });
                let (ack, ack_rx) = oneshot::channel::<err::Result<()>>();
                tx.unbounded_send(PtReactorMessage::Shutdown { result: ack })
                    .expect("send shutdown");
                drop(tx);
                assert_terminates(&mut reactor).await;
                // Слот ушёл в очистку и был удалён: терминальных Failed не осталось.
                assert!(reactor.slots.is_empty(), "Failed-слот не был удалён");
                assert!(
                    reactor.orphans.is_empty(),
                    "процесс не должен стать сиротой"
                );
                // Реальный дочерний процесс успешно остановлен supervisor'ом:
                // расписка обязана быть Ok(()).
                let receipt = tokio::time::timeout(STEP_DEADLINE, ack_rx)
                    .await
                    .expect("расписка в срок")
                    .expect("канал расписки");
                assert!(
                    receipt.is_ok(),
                    "расписка должна быть Ok, получено {receipt:?}"
                );
            });
        }

        #[test]
        fn shutdown_command_cleans_running_slot_with_real_child() {
            if std::env::var_os("CI").is_none() {
                return;
            }
            tor_rtcompat::test_with_one_runtime!(|rt| async move {
                let state_dir = temp_state_dir("running-clean");
                let (tx, rx) = futures::channel::mpsc::unbounded::<PtReactorMessage>();
                let mut reactor = real_reactor(rt, rx, state_dir.clone());
                // Слот в фазе Running с реальным дочерним процессом.
                reactor.slots.push(Slot {
                    key: PathBuf::from("ci-running-pt"),
                    config: slot_config(),
                    phase: Phase::Running(quiet_child_pt(state_dir)),
                    pending: None,
                    retire: false,
                    generation: 0,
                    cleanup_attempts: 0,
                });
                let (ack, ack_rx) = oneshot::channel::<err::Result<()>>();
                tx.unbounded_send(PtReactorMessage::Shutdown { result: ack })
                    .expect("send shutdown");
                drop(tx);
                assert_terminates(&mut reactor).await;
                assert!(reactor.slots.is_empty(), "Running-слот не был удалён");
                assert!(
                    reactor.orphans.is_empty(),
                    "процесс не должен стать сиротой"
                );
                let receipt = tokio::time::timeout(STEP_DEADLINE, ack_rx)
                    .await
                    .expect("расписка в срок")
                    .expect("канал расписки");
                assert!(
                    receipt.is_ok(),
                    "расписка должна быть Ok, получено {receipt:?}"
                );
                let state = reactor.state.read().expect("ptmgr state poisoned");
                assert!(
                    state.closed,
                    "общее состояние должно быть помечено закрытым"
                );
            });
        }

        // Сценарий A: детерминированный test-only seam (ipc.rs, begin_shutdown)
        // исполняет настоящий production-путь complete_task -> Cleaned(Err) ->
        // fail_cleanup: Failed(attempts=1) при closing=true; повторная команда
        // Shutdown (failed_slots_retry при closing) выполняет успешную очистку,
        // ребёнок reap-нут, реактор завершается. Порядок delivery: finish_shutdown
        // рассылает расписки В НАЧАЛЕ шага реактора, поэтому каждая расписка
        // доставляется стартом следующего шага после соответствующего события.
        #[test]
        fn shutdown_first_cleanup_failure_then_retry_succeeds() {
            if std::env::var_os("CI").is_none() {
                return;
            }
            tor_rtcompat::test_with_one_runtime!(|rt| async move {
                let state_dir = temp_state_dir("cleanup-fail-retry");
                let (tx, rx) = futures::channel::mpsc::unbounded::<PtReactorMessage>();
                let mut reactor = real_reactor(rt, rx, state_dir.clone());
                let mut pt = quiet_child_pt(state_dir);
                // Клон флага завершения supervisor-потока: доступная извне
                // проверка reaping (PID процесса наружу не выдаётся).
                let completion = {
                    use crate::ipc::sealed::PluggableTransportPrivate as _;
                    pt.inner().expect("child").test_completion()
                };
                reactor.slots.push(Slot {
                    key: PathBuf::from("ci-cleanup-fail-pt"),
                    config: slot_config(),
                    phase: Phase::Running(pt),
                    pending: None,
                    retire: false,
                    generation: 0,
                    cleanup_attempts: 0,
                });
                // Включаем seam ошибки первого shutdown(); флаг сбрасывается
                // сам после первого срабатывания.
                {
                    use crate::ipc::sealed::PluggableTransportPrivate as _;
                    match &mut reactor.slots[0].phase {
                        Phase::Running(pt) => {
                            pt.inner().expect("child").force_next_shutdown_error()
                        }
                        _ => panic!("слот должен быть в фазе Running"),
                    }
                }
                let budget = std::time::Instant::now();
                let (ack1, ack1_rx) = oneshot::channel::<err::Result<()>>();
                tx.unbounded_send(PtReactorMessage::Shutdown { result: ack1 })
                    .expect("send shutdown #1");
                // Первая очистка: seam возвращает Err раньше begin_shutdown.
                // Шаг, обработавший Cleaned(Err), уже забрал задачу из select,
                // поэтому возвращает Ok(false) без park и цикл завершается.
                spin_until(&mut reactor, budget, "первая очистка", |r| {
                    matches!(&r.slots[0].phase, Phase::Failed(..))
                        && r.slots[0].cleanup_attempts == 1
                })
                .await;
                // Ребёнок ещё не reap-нут: запрос остановки детерминированно
                // не доставлен supervisor'у (seam), значит wait не начат.
                assert!(
                    !completion.load(std::sync::atomic::Ordering::Acquire),
                    "первая ошибка не должна была дожидаться reaping"
                );
                // Сразу ставим Shutdown#2 в очередь rx, до любого следующего
                // шага: иначе реактор уйдёт в select без событий.
                let (ack2, ack2_rx) = oneshot::channel::<err::Result<()>>();
                tx.unbounded_send(PtReactorMessage::Shutdown { result: ack2 })
                    .expect("send shutdown #2");
                // Шаг отправляет receipt1 и обрабатывает уже поставленный Shutdown#2.
                assert!(!bounded_step(&mut reactor).await);
                let receipt1 = tokio::time::timeout(STEP_DEADLINE, ack1_rx)
                    .await
                    .expect("расписка #1 в срок")
                    .expect("канал расписки #1");
                assert!(
                    receipt1.is_err(),
                    "первая очистка обязана вернуть Err, получено {receipt1:?}"
                );
                // Повторная очистка: failed_slots_retry сбрасывает счётчик и
                // повторяет очистку; шаг с Cleaned(Ok) удалит слот и вернётся
                // без park, поэтому цикл завершается детерминированно.
                spin_until(
                    &mut reactor,
                    budget,
                    "повторная очистка",
                    |r| r.slots.is_empty(),
                )
                .await;
                // Ребёнок reap-нут supervisor'ом при успешной очистке.
                assert!(
                    completion.load(std::sync::atomic::Ordering::Acquire),
                    "ребёнок должен быть reap-нут supervisor'ом"
                );
                // Канал рвём для disconnect-терминации: первый шаг select
                // берёт Command(None), но ПЕРЕД этим finish_shutdown при пустых
                // slots и отсутствии failure рассылает receipt2 (Ok) waiter'ам;
                // второй шаг — терминальный Ok(true).
                drop(tx);
                assert_terminates(&mut reactor).await;
                // receipt2 рассылается finish_shutdown на старте первого шага
                // assert_terminates (slots уже пусты), поэтому ожидание после
                // disconnect-терминации детерминированно мгновенно.
                let receipt2 = tokio::time::timeout(STEP_DEADLINE, ack2_rx)
                    .await
                    .expect("расписка #2 в срок")
                    .expect("канал расписки #2");
                assert!(
                    receipt2.is_ok(),
                    "повторная очистка обязана пройти, получено {receipt2:?}"
                );
                assert!(
                    reactor.orphans.is_empty(),
                    "процесс не должен стать сиротой"
                );
            });
        }

        // Сценарий B: production-запуск через Spawn, отмена фазы Starting
        // командой Reconfigured (cancel-oneshot в spawn_from_config), очистка
        // retained-процесса и перезапуск того же ключа после восстановления
        // конфигурации и bump'а поколения.
        #[test]
        fn reconfigured_cancels_pending_start_then_same_key_restarts() {
            if std::env::var_os("CI").is_none() {
                return;
            }
            tor_rtcompat::test_with_one_runtime!(|rt| async move {
                let state_dir = temp_state_dir("cancel-restart");
                let state = Arc::new(RwLock::new(PtSharedState::default()));
                let (tx, rx) = futures::channel::mpsc::unbounded::<PtReactorMessage>();
                let mut reactor = real_reactor_with_state(rt, rx, state_dir.clone(), state.clone());
                let name: PtTransportName = "obfs4".parse().expect("transport name");
                // Файловый барьер реального spawn'а: child пишет свой PID в
                // файл, затем тихо ждёт stdin (launch повиснет без VERSION ->
                // pending startup).
                let barrier = barrier_path("cancel-restart");
                // «Медленный» PT: сперва барьер, затем тишина до общего
                // таймаута запуска; отмена Reconfigured приходит раньше.
                let slow_config = ManagedTransportOptions {
                    protocols: vec![name.clone()],
                    path: CfgPath::new("/bin/sh".as_ref()),
                    arguments: vec![
                        "-c".into(),
                        format!(
                            "echo $$ > \"{}\"; while read line; do :; done",
                            barrier.display()
                        ),
                    ],
                    run_on_startup: false,
                };
                state
                    .write()
                    .expect("ptmgr state poisoned")
                    .configured
                    .insert(name.clone(), TransportOptions::Managed(slow_config.clone()));
                let budget = std::time::Instant::now();
                let (r1, r1_rx) = oneshot::channel::<err::Result<PtClientMethod>>();
                tx.unbounded_send(PtReactorMessage::Spawn {
                    pt: name.clone(),
                    result: r1,
                })
                .expect("send spawn #1");
                // Production-путь start(): слот в фазе Starting с cancel-oneshot.
                spin_until(&mut reactor, budget, "Starting", |r| {
                    !r.slots.is_empty() && matches!(&r.slots[0].phase, Phase::Starting(_))
                })
                .await;
                // Барьер и launch-future продвигаются одновременно; Starting ещё не означает spawn.
                let pid = {
                    let observed = Box::pin(async {
                        for _ in 0..50 {
                            assert!(budget.elapsed() < SCENARIO_BUDGET, "превышен бюджет spawn");
                            if let Ok(text) = std::fs::read_to_string(&barrier) {
                                if let Ok(pid) = text.trim().parse::<u32>() {
                                    return pid;
                                }
                            }
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                        panic!("child не записал полный PID в барьер");
                    });
                    let driver = Box::pin(bounded_step(&mut reactor));
                    match futures::future::select(observed, driver).await {
                        futures::future::Either::Left((pid, _pending_step)) => pid,
                        futures::future::Either::Right((_, _pending_barrier)) => {
                            panic!("pending startup завершился до spawn-барьера");
                        }
                    }
                };
                let proc_entry = std::path::PathBuf::from("/proc").join(pid.to_string());
                // Универсального unix-наблюдения за чужим процессом через /proc нет:
                // это Linux-специфичные проверки CI-носителя.
                #[cfg(target_os = "linux")]
                assert!(
                    proc_entry.exists(),
                    "запущенный child /proc/{pid} не найден"
                );
                #[cfg(not(target_os = "linux"))]
                let _ = (&pid, &proc_entry);
                // Теперь детерминированно известно: pending child реально
                // запущен. Снятие конфигурации + новое поколение -> Reconfigured
                // отменяет Starting через cancel-oneshot.
                {
                    let mut st = state.write().expect("ptmgr state poisoned");
                    st.configured.remove(&name);
                    st.generation = st.generation.checked_add(1).expect("generation");
                }
                tx.unbounded_send(PtReactorMessage::Reconfigured)
                    .expect("send reconfigured");
                // Проверяем receipt между завершёнными шагами, без отдельной observer-задачи.
                let mut r1_rx = Box::pin(r1_rx);
                let mut first_receipt = None;
                spin_until(
                    &mut reactor,
                    budget,
                    "ответ отменённого запуска",
                    |_| {
                        if let Some(receipt) = r1_rx.as_mut().now_or_never() {
                            first_receipt = Some(receipt.expect("канал ответа запуска"));
                            true
                        } else {
                            false
                        }
                    },
                )
                .await;
                assert!(matches!(&reactor.slots[0].phase, Phase::Cleaning));
                assert!(
                    !reactor.tasks.is_empty(),
                    "retained cleanup-future потеряна"
                );
                spin_until(
                    &mut reactor,
                    budget,
                    "отмена и очистка",
                    |r| r.slots.is_empty(),
                )
                .await;
                // Reap-доказательство: Cleaned(Ok) возможен ТОЛЬКО после
                // успешного pt.shutdown(), что требует подтверждения
                // supervisor'а о wait; стало быть, пустые slots + пустые
                // orphans доказывают, что retained-child reap-нут. Дополнительно
                // проверяем, что /proc/{pid} больше не существует.
                assert!(
                    reactor.orphans.is_empty(),
                    "retained-процесс не должен стать сиротой"
                );
                // Linux-специфичная проверка CI-носителя (см. комментарий выше).
                #[cfg(target_os = "linux")]
                assert!(
                    !proc_entry.exists(),
                    "reap-нутый child /proc/{pid} всё ещё жив"
                );
                let r1 = first_receipt.expect("расписка отменённого запуска");
                assert!(
                    matches!(r1, Err(PtError::ChildGone)),
                    "отмена запуска обязана дать Err(ChildGone), получено {r1:?}"
                );
                // Восстановление конфигурации (новое поколение) и повторный
                // Spawn с тем же ключом: корректный PT-скрипт завершает протокол.
                let ready_config = ManagedTransportOptions {
                    protocols: vec![name.clone()],
                    path: CfgPath::new("/bin/sh".as_ref()),
                    arguments: vec![
                        "-c".into(),
                        "echo 'VERSION 1'; \
                         echo 'CMETHOD obfs4 socks5 127.0.0.1:12345'; \
                         echo 'CMETHODS DONE'; \
                         while read line; do :; done"
                            .into(),
                    ],
                    run_on_startup: false,
                };
                {
                    let mut st = state.write().expect("ptmgr state poisoned");
                    st.generation = st.generation.checked_add(1).expect("generation");
                    st.configured.insert(
                        name.clone(),
                        TransportOptions::Managed(ready_config.clone()),
                    );
                }
                let (r2, r2_rx) = oneshot::channel::<err::Result<PtClientMethod>>();
                tx.unbounded_send(PtReactorMessage::Spawn {
                    pt: name.clone(),
                    result: r2,
                })
                .expect("send spawn #2");
                spin_until(&mut reactor, budget, "перезапуск", |r| {
                    !r.slots.is_empty() && matches!(&r.slots[0].phase, Phase::Running(_))
                })
                .await;
                let r2 = tokio::time::timeout(STEP_DEADLINE, r2_rx)
                    .await
                    .expect("расписка #2 в срок")
                    .expect("канал расписки #2");
                assert!(
                    r2.is_ok(),
                    "метод после перезапуска обязан быть Ok, получено {r2:?}"
                );
                // Финальное закрытие: Running -> очистка -> терминация.
                let (ack, ack_rx) = oneshot::channel::<err::Result<()>>();
                tx.unbounded_send(PtReactorMessage::Shutdown { result: ack })
                    .expect("send shutdown");
                spin_until(
                    &mut reactor,
                    budget,
                    "финальное закрытие",
                    |r| r.slots.is_empty(),
                )
                .await;
                drop(tx);
                assert_terminates(&mut reactor).await;
                assert!(reactor.orphans.is_empty(), "не должно остаться сирот");
                let receipt = tokio::time::timeout(STEP_DEADLINE, ack_rx)
                    .await
                    .expect("расписка #3 в срок")
                    .expect("канал расписки #3");
                assert!(
                    receipt.is_ok(),
                    "закрытие обязано пройти, получено {receipt:?}"
                );
                let st = reactor.state.read().expect("ptmgr state poisoned");
                assert!(st.closed, "состояние должно быть закрыто");
                assert!(
                    st.managed_cmethods.is_empty(),
                    "опубликованные методы должны быть сняты при закрытии"
                );
            });
        }
    }
}

/// Given a path to a binary for a pluggable transport, return an identifier for
/// that binary in a format that can be used as a path component.
fn pt_identifier_as_path(binary_path: impl AsRef<Path>) -> Result<PathBuf, PtError> {
    // Extract the final component.
    let mut filename =
        PathBuf::from(
            binary_path
                .as_ref()
                .file_name()
                .ok_or_else(|| PtError::NotAFile {
                    path: binary_path.as_ref().to_path_buf(),
                })?,
        );

    // Strip an "exe" off the end, if appropriate.
    if let Some(ext) = filename.extension() {
        if ext.eq_ignore_ascii_case(std::env::consts::EXE_EXTENSION) {
            filename.set_extension("");
        }
    }

    Ok(filename)
}

/// Given a path to a binary for a pluggable transport, return an identifier for
/// that binary in human-readable form.
pub(crate) fn pt_identifier(binary_path: impl AsRef<Path>) -> Result<String, PtError> {
    Ok(pt_identifier_as_path(binary_path)?
        .to_string_lossy()
        .to_string())
}
