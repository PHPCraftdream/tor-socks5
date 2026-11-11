use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use arti_wrapper::{Settings, Socks5PreEndpoint, TorTunnel};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::tor_watchdog::TorHandle;

mod storage;

static RETAINED: std::sync::Mutex<Option<Arc<OwnerRegistry>>> = std::sync::Mutex::new(None);

#[cfg(test)]
pub(super) static TEST_LIFECYCLE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const CAPACITY: usize = 16;

pub(super) const SETUP_DEADLINE: Duration = Duration::from_secs(120);

/// Clients started at the same time when a pool is brought up in the background.
const START_CONCURRENCY: usize = 3;

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

#[cfg(test)]
type ReviveHook = Arc<
    dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>
        + Send
        + Sync,
>;

pub(super) struct OwnerRegistry {
    global_pre: Option<Socks5PreEndpoint>,
    global: TorHandle,
    settings: Option<Settings>,
    state: Mutex<State>,
    cancel: CancellationToken,
    close_failed: std::sync::atomic::AtomicBool,
    /// Rotation state of the pre pools in use; owners are its members' clients.
    pre_scopes: route_pool::ScopeMap,
    #[cfg(test)]
    storage_quarantine: Arc<std::sync::Mutex<Vec<std::fs::File>>>,
    #[cfg(test)]
    bootstrap_hook: Option<BootstrapHook>,
    #[cfg(test)]
    revive_hook: Option<ReviveHook>,
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
        Ok(Self {
            global_pre,
            global,
            settings: template.ok(),
            state: Mutex::new(State {
                closed: false,
                entries: Vec::new(),
            }),
            cancel: CancellationToken::new(),
            close_failed: std::sync::atomic::AtomicBool::new(false),
            pre_scopes: route_pool::ScopeMap::new(),
            #[cfg(test)]
            storage_quarantine: Arc::new(std::sync::Mutex::new(Vec::new())),
            #[cfg(test)]
            bootstrap_hook: None,
            #[cfg(test)]
            revive_hook: None,
        })
    }

    /// The client for a pre endpoint: the main one when it is the main
    /// client's own endpoint, otherwise an owner that is built on first use.
    /// `None` selects a client without a pre proxy.
    ///
    /// cancel-safe: YES — отмена сохраняет запущенный конструктор в записи реестра.
    pub(super) async fn select_endpoint(&self, pre: Option<Socks5PreEndpoint>) -> Result<Owner> {
        tokio::select! {
            biased;
            _ = self.cancel.cancelled() => bail!("реестр закрыт"),
            result = self.select_inner(pre) => result,
        }
    }

    pub(super) fn pre_scopes(&self) -> &route_pool::ScopeMap {
        &self.pre_scopes
    }

    pub(super) fn is_closing(&self) -> bool {
        self.cancel.is_cancelled()
    }

    /// Whether the client for `pre` can carry a connection right now: it is
    /// the main client, or its owner finished starting and is not failed.
    pub(super) async fn is_ready(&self, pre: &Option<Socks5PreEndpoint>) -> bool {
        if *pre == self.global_pre {
            return true;
        }
        let entry = {
            let state = self.state.lock().await;
            state
                .entries
                .iter()
                .find(|entry| entry.pre == *pre)
                .cloned()
        };
        entry.is_some_and(|entry| {
            entry.state.try_lock().is_ok_and(|state| {
                state.tunnel.is_some() && !state.failed && state.constructing.is_none()
            })
        })
    }

    /// Starts the clients of `pres` in the background, a few at a time, and
    /// returns the task doing it. Endpoints whose client was already started,
    /// or that no client is needed for, are skipped; if nothing is left there
    /// is no task. Endpoints beyond the capacity stay unavailable.
    pub(super) async fn start_background(
        self: &Arc<Self>,
        pres: Vec<Socks5PreEndpoint>,
    ) -> Option<JoinHandle<()>> {
        let mut fresh = Vec::new();
        for pre in pres {
            if let Ok(Some(entry)) = self.reserve(Some(pre.clone())).await {
                if entry.state.try_lock().is_ok_and(|state| !state.attempted) {
                    fresh.push(pre);
                }
            }
        }
        if fresh.is_empty() {
            return None;
        }
        let registry = Arc::clone(self);
        Some(tokio::spawn(async move {
            use futures::StreamExt;
            futures::stream::iter(fresh)
                .for_each_concurrent(START_CONCURRENCY, |pre| {
                    let registry = &registry;
                    async move {
                        let _ = registry.select_endpoint(Some(pre)).await;
                    }
                })
                .await;
        }))
    }

    /// Retries, in the background, a client that failed to finish starting.
    /// Does nothing for the main client or a client in any other state.
    pub(super) fn revive(self: &Arc<Self>, pre: Socks5PreEndpoint) {
        let registry = Arc::clone(self);
        tokio::spawn(async move { registry.revive_inner(pre).await });
    }

    /// cancel-safe: YES — the entry keeps its tunnel; a cancelled retry leaves it failed.
    async fn revive_inner(&self, pre: Socks5PreEndpoint) {
        let entry = {
            let state = self.state.lock().await;
            state
                .entries
                .iter()
                .find(|entry| entry.pre.as_ref() == Some(&pre))
                .cloned()
        };
        let Some(entry) = entry else { return };
        let mut state = entry.state.lock().await;
        if !state.failed || state.constructing.is_some() {
            return;
        }
        let Some(tunnel) = state.tunnel.clone() else {
            return;
        };
        let deadline = Instant::now() + SETUP_DEADLINE;
        let retry = tokio::time::timeout_at(deadline, async {
            #[cfg(test)]
            if let Some(hook) = &self.revive_hook {
                return hook().await;
            }
            tunnel
                .wait_bootstrapped()
                .await
                .map_err(|_| anyhow!("не удалось запустить Tor владельца"))
        });
        tokio::select! {
            biased;
            _ = self.cancel.cancelled() => {}
            result = retry => {
                if matches!(result, Ok(Ok(()))) {
                    state.failed = false;
                }
            }
        }
    }

    pub(super) async fn cancelled(&self) {
        self.cancel.cancelled().await;
    }

    /// Отмена до завершения резервирования не создаёт частичную запись.
    async fn reserve(&self, pre: Option<Socks5PreEndpoint>) -> Result<Option<Arc<Entry>>> {
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

    /// cancel-safe: YES — резервирование атомарно, а конструктор остаётся в записи;
    /// повторное ожидание продолжит работу или сообщит ошибку.
    async fn select_inner(&self, pre: Option<Socks5PreEndpoint>) -> Result<Owner> {
        let Some(entry) = self.reserve(pre).await? else {
            return Ok(Owner {
                global: Some(self.global.clone()),
                alternate: None,
                selected: None,
            });
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
            state.attempted = true;
            state.constructing = Some(tokio::task::spawn_blocking(move || {
                // Системный вызов нельзя прервать, пока он выполняется.
                let _guard = runtime.enter();
                let deadline = Instant::now() + SETUP_DEADLINE;
                #[cfg(test)]
                let storage = storage::acquire_with_quarantine(&base, &quarantine)?;
                #[cfg(not(test))]
                let storage = storage::acquire(&base)?;
                let _slot = storage.slot;
                settings.state_dir = Some(storage.state);
                settings.cache_dir = Some(storage.cache);
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
        use futures::stream::{FuturesUnordered, StreamExt};
        let mut pending = FuturesUnordered::new();
        for entry in entries {
            let close_failed = &self.close_failed;
            pending.push(async move {
                let mut state = entry.state.lock().await;
                if let Some(handle) = state.constructing.as_mut() {
                    let result = handle.await;
                    state.constructing.take();
                    match result {
                        Ok(Ok(Constructed {
                            tunnel,
                            slot,
                            outcome,
                        })) => {
                            state.slot = Some(slot);
                            state.tunnel = Some(tunnel);
                            if let Err(error) = &outcome {
                                if error.downcast_ref::<ConstructorCancelled>().is_none() {
                                    close_failed.store(true, std::sync::atomic::Ordering::Relaxed);
                                }
                            }
                        }
                        Ok(Err(error)) => {
                            if error.downcast_ref::<ConstructorCancelled>().is_none() {
                                close_failed.store(true, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                        Err(_) => {
                            close_failed.store(true, std::sync::atomic::Ordering::Relaxed);
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
                    state.teardown = Some(tokio::task::spawn_blocking(move || drop(tunnel)));
                }
                if let Some(handle) = state.teardown.as_mut() {
                    let result = handle.await;
                    state.teardown.take();
                    if result.is_err() {
                        close_failed.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                Ok::<(), anyhow::Error>(())
            });
        }
        // Global handle remains in its shared slot on receipt failure or cancellation.
        let global = async {
            if let Some(tunnel) = self.global.tunnel().await {
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
                    self.close_failed
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                }
            }
        });
        global_result?;
        if self
            .close_failed
            .swap(false, std::sync::atomic::Ordering::Relaxed)
        {
            bail!("задача владельца завершилась ошибкой при закрытии");
        }
        Ok(())
    }
}

impl Owner {
    /// The main client, selected without a registry.
    pub(super) fn global(handle: TorHandle) -> Self {
        Self {
            global: Some(handle),
            alternate: None,
            selected: None,
        }
    }

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
impl OwnerRegistry {
    /// Test seam: an owner whose client has already been started.
    pub(super) async fn adopt_started(
        &self,
        pre: Socks5PreEndpoint,
        tunnel: TorTunnel,
        failed: bool,
    ) {
        let entry = self.reserve(Some(pre)).await.unwrap().unwrap();
        let mut state = entry.state.lock().await;
        state.attempted = true;
        state.failed = failed;
        state.slot = Some(1);
        state.tunnel = Some(tunnel);
    }
}

#[cfg(test)]
pub(crate) mod handler_tests;
#[cfg(test)]
mod tests;
