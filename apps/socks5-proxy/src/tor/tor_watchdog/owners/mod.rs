use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use arti_wrapper::{Settings, Socks5PreEndpoint, TorTunnel};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::tor_watchdog::TorHandle;

#[cfg(all(test, target_os = "linux"))]
#[path = "test_support/construction/construction_consumer.rs"]
pub(crate) mod construction_consumer;
#[cfg(all(test, target_os = "linux"))]
#[path = "test_support/construction/construction_driver.rs"]
pub(crate) mod construction_driver;
#[cfg(test)]
#[path = "test_support/construction/construction_export.rs"]
pub(crate) mod construction_export;
#[cfg(all(test, target_os = "linux"))]
#[path = "test_support/construction/construction_wire.rs"]
pub(crate) mod construction_wire;
#[cfg(all(test, target_os = "linux"))]
#[path = "test_support/gates/direct_child_gate.rs"]
pub(crate) mod direct_child_gate;
#[cfg(all(test, target_os = "linux"))]
#[path = "test_support/gates/owner_budget.rs"]
mod owner_budget;
#[cfg(all(test, target_os = "linux"))]
#[path = "test_support/gates/owner_intent.rs"]
pub(crate) mod owner_intent;
mod storage;

static RETAINED: std::sync::Mutex<Option<Arc<OwnerRegistry>>> = std::sync::Mutex::new(None);

#[cfg(test)]
pub(super) static TEST_LIFECYCLE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// cfg(test)-инструментация production select_admitted: наблюдение ФАКТИЧЕСКОГО
/// резервирования, публикуемое ТОЛЬКО после возврата reserve внутри
/// select_inner (не shadow-предсказание до reserve). Credentials не хранятся:
/// route-label — только адрес (SocketAddr::to_string) либо "global"/"none".
/// outcome: Reserved (reserve вернул запись), ReserveFailed (reserve вернул
/// Err — НЕ успешное резервирование), Global (reserve вернул None).
/// Честно: резервирование ≠ завершённый Owner return — выдача state.tunnel
/// без Tor-сети не наблюдаема.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SelectionObservation {
    pub(crate) request_id: usize,
    pub(crate) route: String,
    pub(crate) identity: Option<usize>,
    pub(crate) storage_slot: Option<usize>,
    pub(crate) outcome: SelectionOutcome,
    pub(crate) event: SelectionEvent,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SelectionOutcome {
    Reserved,
    ReserveFailed,
    Global,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SelectionEvent {
    Reserved,
    ReserveFailed,
    Global,
    StorageAssigned,
}

/// Наблюдение фактического результата reserve (см. reserve/select_inner).
#[cfg(test)]
pub(crate) struct SelectionProbe {
    next_request_id: std::sync::atomic::AtomicUsize,
    /// bounded-журнал: кап 64 записей; при переполнении растёт только счётчик.
    observations: std::sync::Mutex<(Vec<SelectionObservation>, usize)>,
    construction_export: construction_export::Export,
    #[cfg(target_os = "linux")]
    registry_retention:
        std::sync::Mutex<Option<std::sync::Weak<construction_driver::RetainedRegistry>>>,
    /// watch-счётчик длины журнала. tokio 1.52.3 (локальные исходники
    /// ~/.cargo/registry .../tokio-1.52.3/src/sync/watch.rs): Sender::send
    /// возвращает SendError только при receiver_count() == 0 (watch.rs:1064-1066),
    /// поэтому probe ДЕРЖИТ собственный Receiver с момента конструктора —
    /// send замкнутым не бывает и значения сохраняются независимо от теста.
    events_tx: tokio::sync::watch::Sender<usize>,
    _events_rx: tokio::sync::watch::Receiver<usize>,
}

#[cfg(test)]
static LAST_SELECTION_PROBE: std::sync::Mutex<Option<Arc<SelectionProbe>>> =
    std::sync::Mutex::new(None);

/// Кап журнала наблюдений; переполнение инкрементирует счётчик dropped.
#[cfg(test)]
const OBSERVATION_CAP: usize = 64;

#[cfg(test)]
impl SelectionProbe {
    pub(crate) fn new() -> Self {
        let (events_tx, _events_rx) = tokio::sync::watch::channel(0usize);
        Self {
            next_request_id: std::sync::atomic::AtomicUsize::new(0),
            observations: std::sync::Mutex::new((Vec::new(), 0)),
            construction_export: construction_export::Export::default(),
            #[cfg(target_os = "linux")]
            registry_retention: std::sync::Mutex::new(None),
            events_tx,
            _events_rx,
        }
    }

    /// Монотонный id запроса выбора.
    fn next_request_id(&self) -> usize {
        self.next_request_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Публикация наблюдения + событие (watch = длина журнала).
    pub(crate) fn publish(&self, observation: SelectionObservation) {
        let mut log = self.observations.lock().unwrap();
        let (items, dropped) = &mut *log;
        if items.len() < OBSERVATION_CAP {
            items.push(observation);
        } else {
            *dropped += 1;
        }
        let _ = self.events_tx.send(items.len());
    }

    /// Событийное ожидание новых наблюдений (watch, без sleep-поллинга).
    pub(crate) fn subscribe(&self) -> tokio::sync::watch::Receiver<usize> {
        self.events_tx.subscribe()
    }

    /// Снапшот журнала (основа тест-базлайнов) + счётчик переполнений.
    pub(crate) fn snapshot(&self) -> (Vec<SelectionObservation>, usize) {
        self.observations.lock().unwrap().clone()
    }
}

/// Проб последнего созданного реестра (реестры сериализуются TEST_LIFECYCLE).
#[cfg(test)]
pub(crate) fn test_selection_probe() -> Arc<SelectionProbe> {
    LAST_SELECTION_PROBE
        .lock()
        .unwrap()
        .clone()
        .expect("реестр ещё не создан")
}

/// Synthetic controls must hold TEST_LIFECYCLE until this guard is dropped.
#[cfg(test)]
pub(crate) fn scoped_selection_probe(probe: Arc<SelectionProbe>) -> impl Drop {
    struct Restore(Option<Arc<SelectionProbe>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let mut slot = LAST_SELECTION_PROBE
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *slot = self.0.take();
        }
    }
    let previous = LAST_SELECTION_PROBE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .replace(probe);
    Restore(previous)
}

// Task-local доставка наблюдения из select_admitted в reserve.
// Production-сигнатуры прежние; вне cfg(test) публикации нет.
#[cfg(test)]
tokio::task_local! {
    static SELECTION_OBS: Option<(usize, String, bool)>;
}

const CAPACITY: usize = 16;
pub(super) const SETUP_DEADLINE: Duration = Duration::from_secs(120);

struct Entry {
    pre: Option<Socks5PreEndpoint>,
    state: Mutex<EntryState>,
}

#[derive(Debug)]
struct ConstructorCancelled;

impl std::fmt::Display for ConstructorCancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("запуск Tor владельца отменён")
    }
}
impl std::error::Error for ConstructorCancelled {}

struct Constructed {
    tunnel: TorTunnel,
    slot: usize,
    outcome: Result<()>,
}

struct EntryState {
    constructing: Option<JoinHandle<Result<Constructed>>>,
    teardown: Option<JoinHandle<()>>,
    slot: Option<usize>,
    tunnel: Option<TorTunnel>,
    attempted: bool,
    failed: bool,
}

struct State {
    closed: bool,
    entries: Vec<Arc<Entry>>,
}

#[cfg(test)]
type BootstrapHook =
    Arc<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send + Sync>;

pub(super) struct OwnerRegistry {
    global_pre: Option<Socks5PreEndpoint>,
    global: TorHandle,
    settings: Option<Settings>,
    state: Mutex<State>,
    cancel: CancellationToken,
    close_failed: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    storage_quarantine: Arc<std::sync::Mutex<Vec<std::fs::File>>>,
    #[cfg(test)]
    bootstrap_hook: Option<BootstrapHook>,
    #[cfg(test)]
    selection_probe: Arc<SelectionProbe>,
}

pub(super) struct Owner {
    global: Option<TorHandle>,
    alternate: Option<Arc<Entry>>,
    selected: Option<TorTunnel>,
}

impl OwnerRegistry {
    #[cfg(test)]
    pub(super) fn new(global: TorHandle, settings: Settings) -> Result<Self> {
        let global_pre = settings.pre_endpoint.clone();
        Self::new_with_template(global, global_pre, Ok(settings))
    }

    pub(super) fn new_with_template(
        global: TorHandle,
        global_pre: Option<Socks5PreEndpoint>,
        template: Result<Settings>,
    ) -> Result<Self> {
        // new_with_template используется и в production; инструментация — только
        // под cfg(test), чтобы не трогать production-путь.
        #[cfg(test)]
        let selection_probe = Arc::new(SelectionProbe::new());
        let registry = Self {
            global_pre,
            global,
            settings: template.ok(),
            state: Mutex::new(State {
                closed: false,
                entries: Vec::new(),
            }),
            cancel: CancellationToken::new(),
            close_failed: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            storage_quarantine: Arc::new(std::sync::Mutex::new(Vec::new())),
            #[cfg(test)]
            bootstrap_hook: None,
            #[cfg(test)]
            selection_probe,
        };
        #[cfg(all(test, target_os = "linux"))]
        construction_driver::attach(&registry)?;
        #[cfg(test)]
        {
            *LAST_SELECTION_PROBE.lock().unwrap() = Some(Arc::clone(&registry.selection_probe));
        }
        Ok(registry)
    }

    /// cancel-safe: NO with a test export — cancellation retains failed acknowledgements.
    /// Without an export, cancellation retains registry-owned constructors.
    pub(super) async fn select_admitted(&self, lease: &auth::AdmissionLease) -> Result<Owner> {
        let pre = match lease.pre_socks5() {
            None => self.global_pre.clone(),
            Some(proxy_config::EndpointOverride::Disabled) => None,
            Some(proxy_config::EndpointOverride::Endpoint(endpoint)) => {
                Some(Socks5PreEndpoint::new(
                    endpoint.address(),
                    endpoint
                        .credentials()
                        .map(|(user, pass)| (user.to_owned(), pass.to_owned())),
                ))
            }
        };
        // Наблюдаемость production caller path (только cfg(test)): id и
        // route-label БЕЗ credentials вычисляются до маппинга pre и доставляются
        // в reserve через task-local; сама публикация происходит ПОСЛЕ
        // фактического возврата reserve (см. reserve).
        #[cfg(test)]
        let observation = {
            let route = match lease.pre_socks5() {
                None => "global".to_string(),
                Some(proxy_config::EndpointOverride::Disabled) => "none".to_string(),
                Some(proxy_config::EndpointOverride::Endpoint(endpoint)) => {
                    endpoint.address().to_string()
                }
            };
            let request_id = self.selection_probe.next_request_id();
            let explicit_disabled = matches!(
                lease.pre_socks5(),
                Some(proxy_config::EndpointOverride::Disabled)
            );
            Some((request_id, route, explicit_disabled))
        };
        let selection = async {
            tokio::select! {
                biased;
                _ = self.cancel.cancelled() => bail!("реестр закрыт"),
                result = self.select_inner(pre) => result,
            }
        };
        // Под cfg(test) наблюдение доставляется task-local scope'ом; под
        // not(test) — прежний путь без scope, семантика выбора не меняется.
        #[cfg(test)]
        let result = SELECTION_OBS.scope(observation, selection).await;
        #[cfg(not(test))]
        let result = selection.await;
        result
    }

    pub(super) async fn cancelled(&self) {
        self.cancel.cancelled().await;
    }

    /// With an export installed, cancellation after reserve retains its journal fact and a failed acknowledgement.
    async fn reserve(&self, pre: Option<Socks5PreEndpoint>) -> Result<Option<Arc<Entry>>> {
        let result = self.reserve_inner(pre).await;
        // Публикация наблюдения ТОЛЬКО ПОСЛЕ фактического результата reserve;
        // отсутствие task-local scope (unit-тесты owners/tests.rs вызывают
        // select_inner напрямую) — публикация пропускается.
        #[cfg(test)]
        self.publish_reserve_outcome(&result).await?;
        result
    }

    #[cfg(test)]
    /// Публикация исхода reserve через task-local: Ok(None) -> Global,
    /// Err -> ReserveFailed, Ok(Some(entry)) -> Reserved с identity =
    /// opaque Arc::as_ptr записи. Route-label — только адрес, credentials
    /// не хранятся.
    async fn publish_reserve_outcome(&self, result: &Result<Option<Arc<Entry>>>) -> Result<()> {
        self.export_reserve_outcome(result).await
    }

    /// Тело reserve без публикаций (вся логика прежняя).
    async fn reserve_inner(&self, pre: Option<Socks5PreEndpoint>) -> Result<Option<Arc<Entry>>> {
        {
            let mut state = self.state.lock().await;
            if state.closed || self.cancel.is_cancelled() {
                bail!("реестр закрыт");
            }
            if pre == self.global_pre {
                return Ok(None);
            }
            let settings = self
                .settings
                .as_ref()
                .ok_or_else(|| anyhow!("шаблон альтернативного владельца недействителен"))?;
            settings.validate_stock_pt_proxy()?;
            if settings.state_dir.is_none() {
                bail!("нет каталога состояния для альтернативного владельца");
            }
            if let Some(entry) = state.entries.iter().find(|entry| entry.pre == pre) {
                Ok(Some(Arc::clone(entry)))
            } else {
                if state.entries.len() >= CAPACITY - 1 {
                    bail!("достигнут предел владельцев; требуется перезапуск");
                }
                let entry = Arc::new(Entry {
                    pre,
                    state: Mutex::new(EntryState {
                        slot: None,
                        constructing: None,
                        teardown: None,
                        tunnel: None,
                        attempted: false,
                        failed: false,
                    }),
                });
                state.entries.push(Arc::clone(&entry));
                Ok(Some(entry))
            }
        }
    }

    /// cancel-safe: NO with a test export — cancellation may fail its acknowledgement.
    /// Constructors remain owned by the entry after selection cancellation.
    /// An installed test export adds a cancellable reserve acknowledgement.
    /// Cancellation there preserves the reservation and journal observation,
    /// marks the export failed, and does not start this request's constructor.
    /// Production builds have no export or additional acknowledgement boundary.
    async fn select_inner(&self, pre: Option<Socks5PreEndpoint>) -> Result<Owner> {
        let entry = match self.reserve(pre).await {
            // global-путь: reserve вернул None — отдельный исход (не резервирование записи).
            Ok(None) => {
                return Ok(Owner {
                    global: Some(self.global.clone()),
                    alternate: None,
                    selected: None,
                });
            }
            Ok(Some(entry)) => entry,
            Err(error) => {
                // reserve вернул Err — НЕ успешное резервирование (публикация в reserve).
                return Err(error);
            }
        };
        let mut state = entry.state.lock().await;
        if self.cancel.is_cancelled() {
            bail!("реестр закрыт");
        }
        if state.failed {
            bail!("конструктор Tor владельца завершился ошибкой");
        }
        if !state.attempted {
            let mut settings = self
                .settings
                .as_ref()
                .ok_or_else(|| anyhow!("нет шаблона владельца"))?
                .clone();
            settings.pre_endpoint = entry.pre.clone();
            let base = settings
                .state_dir
                .clone()
                .ok_or_else(|| anyhow!("нет каталога состояния"))?;
            let runtime = tokio::runtime::Handle::current();
            let cancel = self.cancel.clone();
            #[cfg(test)]
            let bootstrap_hook = self.bootstrap_hook.clone();
            #[cfg(test)]
            let quarantine = Arc::clone(&self.storage_quarantine);
            #[cfg(test)]
            let selection_probe = Arc::clone(&self.selection_probe);
            #[cfg(test)]
            let entry_identity = Arc::as_ptr(&entry) as usize;
            #[cfg(test)]
            let selection = SELECTION_OBS.try_with(|obs| obs.clone()).ok().flatten();
            state.attempted = true;
            state.constructing = Some(tokio::task::spawn_blocking(move || {
                // Системный вызов нельзя прервать, пока он выполняется.
                let _guard = runtime.enter();
                let deadline = Instant::now() + SETUP_DEADLINE;
                #[cfg(test)]
                let storage = storage::acquire_with_quarantine(&base, &quarantine)?;
                #[cfg(not(test))]
                let storage = storage::acquire(&base)?;
                #[cfg(test)]
                let selection_probe = selection_probe;
                #[cfg(test)]
                if let Some((request_id, route, explicit_disabled)) = selection {
                    runtime.block_on(selection_probe.export_storage(
                        (request_id, route, explicit_disabled),
                        entry_identity,
                        construction_export::StorageEvidence {
                            base: base.clone(),
                            allocated: storage.state.clone(),
                            slot: storage.slot,
                        },
                        settings.pre_endpoint.is_none(),
                        deadline,
                    ))?;
                } else {
                    selection_probe
                        .construction_export
                        .require_observed_construction()?;
                }
                settings.state_dir = Some(storage.state);
                settings.cache_dir = Some(storage.cache);
                #[cfg(test)]
                let tunnel = construction_export::create_tunnel(&selection_probe, settings)?;
                #[cfg(not(test))]
                let tunnel = TorTunnel::create_unbootstrapped_with(settings)
                    .map_err(|_| anyhow!("не удалось создать Tor владельца"))?;
                runtime.block_on(async {
                    let outcome = tokio::select! {
                        biased;
                        _ = cancel.cancelled() => Err(anyhow::Error::new(ConstructorCancelled)),
                        result = tokio::time::timeout_at(deadline, async {
                            #[cfg(test)]
                            if let Some(hook) = bootstrap_hook {
                                hook().await;
                                return Ok(());
                            }
                            tunnel.wait_bootstrapped().await
                                .map_err(|_| anyhow!("не удалось запустить Tor владельца"))
                        }) => result.map_err(|_| anyhow!("истёк срок запуска Tor владельца")).and_then(|result| result),
                    };
                    Ok(Constructed {
                        tunnel,
                        slot: storage.slot,
                        outcome,
                    })
                })
            }));
        }
        if let Some(handle) = state.constructing.as_mut() {
            // Ожидание по ссылке безопасно при отмене: дескриптор остаётся в записи до завершения.
            let result = handle.await;
            state.constructing.take();
            let constructed = match result {
                Ok(Ok(value)) => value,
                _ => {
                    state.failed = true;
                    bail!("конструктор Tor завершился ошибкой");
                }
            };
            state.slot = Some(constructed.slot);
            state.tunnel = Some(constructed.tunnel);
            if let Err(error) = constructed.outcome {
                state.failed = true;
                return Err(error);
            }
        }
        if state.tunnel.is_none() {
            bail!("конструктор Tor владельца завершился ошибкой");
        }
        let selected = state.tunnel.clone();
        drop(state);
        Ok(Owner {
            global: None,
            alternate: Some(entry),
            selected,
        })
    }

    pub(super) fn begin_close(&self) {
        self.cancel.cancel();
    }

    pub(super) fn retain_for_shutdown(self: &Arc<Self>) -> Result<()> {
        let mut retained = RETAINED
            .lock()
            .map_err(|_| anyhow!("хранилище реестра повреждено"))?;
        if retained.is_some() {
            bail!("предыдущий реестр ещё удерживается");
        }
        *retained = Some(Arc::clone(self));
        Ok(())
    }

    pub(super) async fn recover_retained_with_deadline(deadline: Instant) -> Result<()> {
        let registry = RETAINED
            .lock()
            .map_err(|_| anyhow!("хранилище реестра повреждено"))?
            .clone();
        if let Some(registry) = registry {
            registry.close_with_deadline(deadline).await?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) async fn recover_retained_terminal() -> Result<()> {
        let registry = RETAINED
            .lock()
            .map_err(|_| anyhow!("хранилище реестра повреждено"))?
            .clone();
        if let Some(registry) = registry {
            registry.begin_close();
            let entries = {
                let mut state = registry.state.lock().await;
                state.closed = true;
                state.entries.clone()
            };
            let mut errors = Vec::new();
            let mut global_shutdown_succeeded = true;
            for entry in entries {
                let mut state = entry.state.lock().await;
                if let Some(handle) = state.constructing.as_mut() {
                    let result = handle.await;
                    state.constructing.take();
                    match result {
                        Ok(Ok(constructed)) => {
                            if let Err(error) = constructed.outcome {
                                if !error.is::<ConstructorCancelled>() {
                                    errors
                                        .push(anyhow!("ошибка запуска Tor владельца при закрытии"));
                                }
                            }
                            state.slot = Some(constructed.slot);
                            state.tunnel = Some(constructed.tunnel);
                        }
                        Ok(Err(error)) if error.is::<ConstructorCancelled>() => {}
                        Ok(Err(_)) | Err(_) => {
                            errors.push(anyhow!("ошибка создания Tor владельца при закрытии"))
                        }
                    }
                }
                if let Some(handle) = state.teardown.as_mut() {
                    let result = handle.await;
                    state.teardown.take();
                    if result.is_err() {
                        errors.push(anyhow!("ошибка освобождения Tor"));
                    }
                }
                if let Some(tunnel) = state.tunnel.as_ref() {
                    if tunnel.shutdown().await.is_err() {
                        errors.push(anyhow!("ошибка завершения PT"));
                    } else if let Some(tunnel) = state.tunnel.take() {
                        state.teardown = Some(tokio::task::spawn_blocking(move || drop(tunnel)));
                    }
                }
                if let Some(handle) = state.teardown.as_mut() {
                    let result = handle.await;
                    state.teardown.take();
                    if result.is_err() {
                        errors.push(anyhow!("ошибка освобождения Tor"));
                    }
                }
            }
            if let Some(tunnel) = registry.global.tunnel().await {
                if tunnel.shutdown().await.is_err() {
                    global_shutdown_succeeded = false;
                    errors.push(anyhow!("ошибка завершения глобального PT"));
                }
            }
            if registry
                .close_failed
                .swap(false, std::sync::atomic::Ordering::Relaxed)
            {
                errors.push(anyhow!("задача владельца завершилась ошибкой при закрытии"));
            }
            let drained = {
                let state = registry.state.lock().await;
                state.entries.iter().all(|entry| {
                    entry.state.try_lock().is_ok_and(|entry_state| {
                        entry_state.constructing.is_none()
                            && entry_state.teardown.is_none()
                            && entry_state.tunnel.is_none()
                    })
                })
            };
            if !drained && errors.is_empty() {
                errors.push(anyhow!("реестр владельцев не освобождён полностью"));
            }
            if drained && global_shutdown_succeeded {
                let mut retained = RETAINED
                    .lock()
                    .map_err(|_| anyhow!("хранилище реестра повреждено"))?;
                if retained
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(current, &registry))
                {
                    *retained = None;
                }
            }
            if !errors.is_empty() {
                return Err(anyhow!(
                    "ошибки терминального закрытия реестра владельцев: {}",
                    errors
                        .into_iter()
                        .map(|error| error.to_string())
                        .collect::<Vec<_>>()
                        .join("; ")
                ));
            }
        }
        Ok(())
    }

    pub(super) async fn close_with_deadline(&self, deadline: Instant) -> Result<()> {
        self.begin_close();
        tokio::time::timeout_at(deadline, self.close())
            .await
            .map_err(|_| {
                anyhow!("истёк срок закрытия реестра; сохраните реестр для повторного ожидания")
            })??;
        let mut retained = RETAINED
            .lock()
            .map_err(|_| anyhow!("хранилище реестра повреждено"))?;
        if retained
            .as_ref()
            .is_some_and(|registry| std::ptr::eq(registry.as_ref(), self))
        {
            *retained = None;
        }
        Ok(())
    }

    // Повторный вызов после отмены продолжает ожидать сохранённые конструкторы.
    // Блокирующий вызов ОС может не завершиться: конечный срок закрытия не гарантируется.
    pub(super) async fn close(&self) -> Result<()> {
        self.begin_close();
        let entries = {
            let mut state = self.state.lock().await;
            state.closed = true;
            state.entries.clone()
        };
        Self::close_entries(&self.global, &self.close_failed, entries).await
    }

    async fn close_entries(
        global_handle: &TorHandle,
        close_failed: &std::sync::atomic::AtomicBool,
        entries: Vec<Arc<Entry>>,
    ) -> Result<()> {
        use futures::stream::{FuturesUnordered, StreamExt};
        let mut pending = FuturesUnordered::new();
        for entry in entries {
            pending.push(async move {
                let mut state = entry.state.lock().await;
                if let Some(handle) = state.constructing.as_mut() {
                    let result = handle.await;
                    state.constructing.take();
                    match result {
                        Ok(Ok(constructed)) => {
                            state.slot = Some(constructed.slot);
                            state.tunnel = Some(constructed.tunnel);
                        }
                        Ok(Err(error)) if error.is::<ConstructorCancelled>() => {}
                        Ok(Err(_)) | Err(_) => {
                            return Err(anyhow!("ошибка создания Tor владельца при закрытии"));
                        }
                    }
                }
                if let Some(tunnel) = state.tunnel.as_ref() {
                    tunnel
                        .shutdown()
                        .await
                        .map_err(|_| anyhow!("ошибка завершения PT"))?;
                }
                if let Some(tunnel) = state.tunnel.take() {
                    let span = tracing::Span::current();
                    state.teardown = Some(tokio::task::spawn_blocking(move || {
                        let _entered = span.enter();
                        drop(tunnel);
                    }));
                }
                if let Some(handle) = state.teardown.as_mut() {
                    let result = handle.await;
                    state.teardown.take();
                    result.map_err(|_| anyhow!("ошибка освобождения Tor"))?;
                }
                Ok::<(), anyhow::Error>(())
            });
        }
        // Global handle remains in its shared slot on receipt failure or cancellation.
        let global = async {
            if let Some(tunnel) = global_handle.tunnel().await {
                tunnel
                    .shutdown()
                    .await
                    .map_err(|_| anyhow!("ошибка завершения глобального PT"))?;
            }
            Ok::<(), anyhow::Error>(())
        };
        let (global_result, ()) = tokio::join!(global, async {
            while let Some(result) = pending.next().await {
                if result.is_err() {
                    close_failed.store(true, std::sync::atomic::Ordering::Relaxed);
                }
            }
        });
        global_result?;
        if close_failed.swap(false, std::sync::atomic::Ordering::Relaxed) {
            bail!("задача владельца завершилась ошибкой при закрытии");
        }
        Ok(())
    }
}

impl Owner {
    pub(super) fn global_handle(&self) -> Option<&TorHandle> {
        self.global.as_ref()
    }

    pub(super) async fn tunnel(&self) -> Option<TorTunnel> {
        if let Some(global) = &self.global {
            global.tunnel().await
        } else if self.alternate.is_some() {
            self.selected.clone()
        } else {
            None
        }
    }
}

#[cfg(test)]
pub(crate) mod handler_tests;
#[cfg(test)]
#[path = "test_support/mod.rs"]
mod tests;
