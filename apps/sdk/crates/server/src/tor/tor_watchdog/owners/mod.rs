use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use arti_wrapper::{Settings, Socks5PreEndpoint, TorTunnel};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use tor_socks5_runtime::tor_watchdog::TorHandle;

mod storage;

static RETAINED: std::sync::Mutex<Option<Arc<OwnerRegistry>>> = std::sync::Mutex::new(None);

#[cfg(test)]
pub(super) static TEST_LIFECYCLE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Extra Tor clients ("owners") the process can host besides the main one.
/// One shared limit: `route::MAX_PRE_OWNERS` (route admission) and `storage`
/// (slot locks) both derive from it.
pub(crate) const MAX_OWNERS: usize = crate::route::MAX_PRE_OWNERS;
const CAPACITY: usize = MAX_OWNERS + 1;

pub(super) const SETUP_DEADLINE: Duration = Duration::from_secs(120);

/// Clients started at the same time when a pool is brought up in the background.
const START_CONCURRENCY: usize = 3;

struct Entry {
    pre: Option<Socks5PreEndpoint>,
    state: Mutex<EntryState>,
    /// Set when the owner's client can carry a connection: the constructor
    /// finished successfully (or the entry was adopted in tests) and no close
    /// is in progress. Read without the state lock by `is_ready`.
    ready: std::sync::atomic::AtomicBool,
}

#[derive(Debug)]
struct ConstructorCancelled;

impl std::fmt::Display for ConstructorCancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("owner Tor startup cancelled")
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
    /// Revive retries are owned here until close joins them. At most one
    /// unfinished retry is retained per owner endpoint.
    revivals: Vec<(Socks5PreEndpoint, Option<JoinHandle<()>>)>,
    /// Background start tasks; joined on close like the revivals.
    backgrounds: Vec<Option<JoinHandle<()>>>,
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
                revivals: Vec::new(),
                backgrounds: Vec::new(),
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
            _ = self.cancel.cancelled() => bail!("registry is closed"),
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
        entry.is_some_and(|entry| entry.ready.load(std::sync::atomic::Ordering::Acquire))
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
        // The registry keeps the real task handle so close() can join it; the
        // returned handle is a completion monitor (a JoinHandle cannot be
        // stored and handed out at once). Callers only track completion.
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            use futures::StreamExt;
            futures::stream::iter(fresh)
                .for_each_concurrent(START_CONCURRENCY, |pre| {
                    let registry = &registry;
                    async move {
                        let _ = registry.select_endpoint(Some(pre)).await;
                    }
                })
                .await;
            let _ = done_tx.send(());
        });
        let handle = tokio::spawn(async move {
            let _ = done_rx.await;
        });
        {
            let mut state = self.state.lock().await;
            if state.closed {
                drop(state);
                task.abort();
                handle.abort();
                return None;
            }
            state.backgrounds.push(Some(task));
        }
        Some(handle)
    }

    pub(crate) async fn revive(self: &Arc<Self>, pre: Socks5PreEndpoint) {
        let mut state = self.state.lock().await;
        if state.closed || self.cancel.is_cancelled() {
            return;
        }
        let mut index = 0;
        while index < state.revivals.len() {
            if state.revivals[index]
                .1
                .as_ref()
                .is_some_and(JoinHandle::is_finished)
            {
                let (_, task) = state.revivals.swap_remove(index);
                if task
                    .expect("finished retry handle remains stored")
                    .await
                    .is_err()
                {
                    self.close_failed
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                }
            } else {
                index += 1;
            }
        }
        if state.revivals.iter().any(|(endpoint, task)| {
            endpoint == &pre && task.as_ref().is_some_and(|task| !task.is_finished())
        }) {
            return;
        }
        let Some(entry) = state
            .entries
            .iter()
            .find(|entry| entry.pre.as_ref() == Some(&pre))
            .cloned()
        else {
            return;
        };
        let registry = Arc::clone(self);
        let task = tokio::spawn(async move { registry.revive_entry_inner(entry).await });
        state.revivals.push((pre, Some(task)));
    }

    /// cancel-safe: YES — the entry keeps its tunnel; a cancelled retry leaves it failed.
    #[cfg(test)]
    async fn revive_inner(&self, pre: Socks5PreEndpoint) {
        let entry = {
            let state = self.state.lock().await;
            state
                .entries
                .iter()
                .find(|entry| entry.pre.as_ref() == Some(&pre))
                .cloned()
        };
        if let Some(entry) = entry {
            self.revive_entry_inner(entry).await;
        }
    }

    async fn revive_entry_inner(&self, entry: Arc<Entry>) {
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
                .map_err(|_| anyhow!("failed to start the owner Tor"))
        });
        tokio::select! {
            biased;
            _ = self.cancel.cancelled() => {}
            result = retry => {
                if matches!(result, Ok(Ok(()))) {
                    state.failed = false;
                    entry
                        .ready
                        .store(true, std::sync::atomic::Ordering::Release);
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
                bail!("registry is closed");
            }
            if pre == self.global_pre {
                return Ok(None);
            }
            let settings = self
                .settings
                .as_ref()
                .ok_or_else(|| anyhow!("alternate owner template is invalid"))?;
            settings.validate_stock_pt_proxy()?;
            if settings.state_dir.is_none() {
                bail!("no state directory for the alternate owner");
            }
            if let Some(entry) = state.entries.iter().find(|entry| entry.pre == pre) {
                Ok(Some(Arc::clone(entry)))
            } else {
                if state.entries.len() >= CAPACITY - 1 {
                    bail!("owner limit reached; restart required");
                }
                let entry = Arc::new(Entry {
                    pre,
                    ready: std::sync::atomic::AtomicBool::new(false),
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
            bail!("registry is closed");
        }
        if state.failed {
            bail!("owner Tor constructor failed");
        }
        if !state.attempted {
            let mut settings = self
                .settings
                .as_ref()
                .ok_or_else(|| anyhow!("no owner template"))?
                .clone();
            settings.pre_endpoint = entry.pre.clone();
            let base = settings
                .state_dir
                .clone()
                .ok_or_else(|| anyhow!("no state directory"))?;
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
                    .map_err(|_| anyhow!("failed to create the owner Tor"))?;
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
                                .map_err(|_| anyhow!("failed to start the owner Tor"))
                        }) => result.map_err(|_| anyhow!("owner Tor startup timed out")).and_then(|result| result),
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
                    entry
                        .ready
                        .store(false, std::sync::atomic::Ordering::Release);
                    bail!("Tor constructor failed");
                }
            };
            state.slot = Some(constructed.slot);
            state.tunnel = Some(constructed.tunnel);
            if let Err(error) = constructed.outcome {
                state.failed = true;
                entry
                    .ready
                    .store(false, std::sync::atomic::Ordering::Release);
                return Err(error);
            }
        }
        if state.tunnel.is_none() {
            entry
                .ready
                .store(false, std::sync::atomic::Ordering::Release);
            bail!("owner Tor constructor failed");
        }
        entry
            .ready
            .store(true, std::sync::atomic::Ordering::Release);
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
        // A closing registry is not ready. Best effort: if the state lock is
        // held by a selection in flight, that selection observes the
        // cancellation itself; new selections bail at once.
        if let Ok(state) = self.state.try_lock() {
            for entry in &state.entries {
                entry
                    .ready
                    .store(false, std::sync::atomic::Ordering::Release);
            }
        }
    }

    pub(super) fn retain_for_shutdown(self: &Arc<Self>) -> Result<()> {
        let mut retained = RETAINED
            .lock()
            .map_err(|_| anyhow!("registry storage is corrupted"))?;
        if retained.is_some() {
            bail!("a previous registry is still held");
        }
        *retained = Some(Arc::clone(self));
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn is_retained() -> bool {
        RETAINED.lock().unwrap_or_else(|e| e.into_inner()).is_some()
    }

    pub(super) async fn recover_retained_with_deadline(deadline: Instant) -> Result<()> {
        let registry = RETAINED
            .lock()
            .map_err(|_| anyhow!("registry storage is corrupted"))?
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
                anyhow!("registry close timed out; persist the registry to wait again")
            })??;
        let mut retained = RETAINED
            .lock()
            .map_err(|_| anyhow!("registry storage is corrupted"))?;
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
            // Keep handles in the registry while awaiting them: cancellation
            // of close leaves them available for a later close attempt.
            for (_, task) in &mut state.revivals {
                if let Some(handle) = task.as_mut() {
                    let result = handle.await;
                    *task = None;
                    if result.is_err() {
                        self.close_failed
                            .store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
            state.revivals.clear();
            // Same retention pattern as revivals: join finished background
            // starts, keep the rest for a later close attempt.
            for handle in &mut state.backgrounds {
                if let Some(task) = handle.as_mut() {
                    if task.is_finished() {
                        let result = task.await;
                        *handle = None;
                        if result.is_err() {
                            self.close_failed
                                .store(true, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                }
            }
            state.backgrounds.retain(Option::is_some);
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
                        .map_err(|_| anyhow!("PT shutdown error"))?;
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
                    .map_err(|_| anyhow!("global PT shutdown error"))?;
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
            bail!("owner task failed during shutdown");
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
        entry
            .ready
            .store(!failed, std::sync::atomic::Ordering::Release);
        state.slot = Some(1);
        state.tunnel = Some(tunnel);
    }
}

#[cfg(test)]
pub(crate) mod handler_tests;
#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
