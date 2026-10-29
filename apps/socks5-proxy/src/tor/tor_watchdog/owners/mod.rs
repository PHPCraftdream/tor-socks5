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
}

struct EntryState {
    constructing: Option<JoinHandle<Result<Constructed>>>,
    teardown: Option<JoinHandle<()>>,
    slot: Option<usize>,
    tunnel: Option<TorTunnel>,
    attempted: bool,
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
            #[cfg(test)]
            storage_quarantine: Arc::new(std::sync::Mutex::new(Vec::new())),
            #[cfg(test)]
            bootstrap_hook: None,
        })
    }

    /// cancel-safe: YES — отмена сохраняет запущенный конструктор в записи реестра.
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
        tokio::select! {
            biased;
            _ = self.cancel.cancelled() => bail!("реестр закрыт"),
            result = self.select_inner(pre) => result,
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
            if settings.pt_binary.is_some()
                || !settings.extra_pt_protocols.is_empty()
                || settings
                    .bridges
                    .iter()
                    .any(|bridge| bridge.transport.is_some())
            {
                bail!("альтернативным владельцам разрешены только обычные мосты");
            }
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
                    tokio::select! {
                        biased;
                        _ = cancel.cancelled() => return Err(anyhow::Error::new(ConstructorCancelled)),
                        result = tokio::time::timeout_at(deadline, async {
                            #[cfg(test)]
                            if let Some(hook) = bootstrap_hook {
                                hook().await;
                                return Ok(());
                            }
                            tunnel.wait_bootstrapped().await
                                .map_err(|_| anyhow!("не удалось запустить Tor владельца"))
                        }) => result.map_err(|_| anyhow!("истёк срок запуска Tor владельца"))??,
                    }
                    Ok(Constructed {
                        tunnel,
                        slot: storage.slot,
                    })
                })
            }));
        }
        if let Some(handle) = state.constructing.as_mut() {
            // Ожидание по ссылке безопасно при отмене: дескриптор остаётся в записи до завершения.
            let result = handle.await;
            state.constructing.take();
            let constructed =
                result.map_err(|_| anyhow!("конструктор Tor завершился аварийно"))??;
            state.slot = Some(constructed.slot);
            state.tunnel = Some(constructed.tunnel);
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
        for entry in entries {
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
                    _ => self
                        .close_failed
                        .store(true, std::sync::atomic::Ordering::Relaxed),
                }
            }
            if let Some(tunnel) = state.tunnel.take() {
                state.teardown = Some(tokio::task::spawn_blocking(move || drop(tunnel)));
            }
            if let Some(handle) = state.teardown.as_mut() {
                let result = handle.await;
                state.teardown.take();
                if result.is_err() {
                    self.close_failed
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
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
mod handler_tests;
#[cfg(test)]
mod tests;
