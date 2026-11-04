use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use arti_wrapper::{Settings, TorTunnel};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

static RETAINED: StdMutex<Option<Arc<GlobalInit>>> = StdMutex::new(None);
static SETTINGS: StdMutex<Option<Arc<SettingsInit>>> = StdMutex::new(None);

// Подменяет сетевые этапы запуска; проверка не является сквозным тестом Tor.
#[cfg(test)]
pub(super) struct StartupHook {
    pub settings: Settings,
    pub park_global: bool,
    pub gate: StdMutex<
        Option<(
            tokio::sync::oneshot::Sender<()>,
            std::sync::mpsc::Receiver<()>,
        )>,
    >,
}

#[cfg(test)]
tokio::task_local! {
    pub(super) static RUN_SERVER_STARTUP: Arc<StartupHook>;
    pub(super) static RUN_SERVER_SHUTDOWN: Arc<ShutdownHook>;
}

#[cfg(test)]
pub(super) struct ShutdownHook {
    pub settings: Settings,
    pub writer: crate::bridge_store_writer::StoreWriter,
    pub ready: StdMutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

pub(super) fn launch_background() -> bool {
    #[cfg(test)]
    if RUN_SERVER_SHUTDOWN.try_with(|_| ()).is_ok() {
        return false;
    }
    true
}

pub(super) fn server_ready() {
    #[cfg(test)]
    let _ = RUN_SERVER_SHUTDOWN.try_with(|hook| {
        if let Some(ready) = hook.ready.lock().unwrap().take() {
            let _ = ready.send(());
        }
    });
}

pub(super) fn init_server_tracing(
    cfg: &crate::config::Config,
) -> (
    Option<tracing_appender::non_blocking::WorkerGuard>,
    crate::arti_observability::ObservationSink,
) {
    #[cfg(test)]
    if RUN_SERVER_STARTUP.try_with(|_| ()).is_ok() || RUN_SERVER_SHUTDOWN.try_with(|_| ()).is_ok() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        return (None, crate::arti_observability::ObservationSink::new());
    }
    let (guard, sink) = crate::startup::init_tracing(cfg);
    crate::startup::install_crypto_provider();
    (Some(guard), sink)
}

pub(super) fn init_store_writer(path: Option<&std::path::Path>) {
    #[cfg(test)]
    if RUN_SERVER_STARTUP.try_with(|_| ()).is_ok() || RUN_SERVER_SHUTDOWN.try_with(|_| ()).is_ok() {
        return;
    }
    crate::bridge_store_writer::init_global(path);
}

pub(super) async fn close_store_writer() -> Option<Result<()>> {
    #[cfg(test)]
    if let Ok(writer) = RUN_SERVER_SHUTDOWN.try_with(|hook| hook.writer.clone()) {
        return Some(writer.close().await);
    }
    #[cfg(test)]
    if RUN_SERVER_STARTUP.try_with(|_| ()).is_ok() {
        return None;
    }
    crate::bridge_store_writer::close_global().await
}

fn cleanup_budget() -> Duration {
    #[cfg(test)]
    if RUN_SERVER_STARTUP.try_with(|_| ()).is_ok() {
        return Duration::from_millis(20);
    }
    Duration::from_secs(5)
}

pub(super) struct SettingsInit {
    handle: Mutex<Option<JoinHandle<Result<Settings>>>>,
}

impl SettingsInit {
    pub(super) fn start(
        cfg: crate::config::Config,
        path: Option<std::path::PathBuf>,
    ) -> Result<Arc<Self>> {
        #[cfg(test)]
        if let Ok(hook) = RUN_SERVER_STARTUP.try_with(Arc::clone) {
            return Self::start_job(move || {
                if !hook.park_global {
                    let (entered, release) = hook.gate.lock().unwrap().take().unwrap();
                    let _ = entered.send(());
                    let _ = release.recv();
                }
                Ok(hook.settings.clone())
            });
        }
        #[cfg(test)]
        if let Ok(settings) = RUN_SERVER_SHUTDOWN.try_with(|hook| hook.settings.clone()) {
            return Self::start_job(move || Ok(settings));
        }
        let runtime = tokio::runtime::Handle::current();
        Self::start_job(move || {
            runtime.block_on(crate::tor_setup::build_tor_settings(&cfg, path.as_deref()))
        })
    }

    fn start_job(job: impl FnOnce() -> Result<Settings> + Send + 'static) -> Result<Arc<Self>> {
        let mut root = SETTINGS
            .lock()
            .map_err(|_| anyhow!("хранилище настроек повреждено"))?;
        if root.is_some() {
            bail!("предыдущая подготовка настроек ещё сохраняется");
        }
        let init = Arc::new(Self {
            handle: Mutex::new(None),
        });
        let mut slot = init.handle.try_lock().expect("новый слот свободен");
        *root = Some(init.clone());
        // Задача продолжает опрос подготовки, пока не завершатся её вложенные операции.
        *slot = Some(tokio::task::spawn_blocking(job));
        drop(slot);
        Ok(init)
    }

    /// cancel-safe: да — дескриптор остаётся в корневом слоте при отмене ожидания.
    pub(super) async fn wait(self: &Arc<Self>) -> Result<Settings> {
        let mut slot = self.handle.lock().await;
        let result = slot
            .as_mut()
            .ok_or_else(|| anyhow!("настройки уже получены"))?
            .await;
        slot.take();
        self.release()?;
        result.context("задача подготовки настроек завершилась аварийно")?
    }

    fn release(self: &Arc<Self>) -> Result<()> {
        let mut root = SETTINGS
            .lock()
            .map_err(|_| anyhow!("хранилище настроек повреждено"))?;
        if root
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, self))
        {
            *root = None;
        }
        Ok(())
    }

    pub(super) async fn recover(deadline: Instant) -> Result<()> {
        let init = SETTINGS
            .lock()
            .map_err(|_| anyhow!("хранилище настроек повреждено"))?
            .clone();
        let Some(init) = init else {
            return Ok(());
        };
        let mut slot = tokio::time::timeout_at(deadline, init.handle.lock())
            .await
            .context("истёк срок ожидания подготовки настроек")?;
        if let Some(handle) = slot.as_mut() {
            let result = tokio::time::timeout_at(deadline, handle)
                .await
                .context("истёк срок ожидания подготовки настроек")?;
            slot.take();
            init.release()?;
            result.context("задача подготовки настроек завершилась аварийно")??;
        } else {
            init.release()?;
        }
        Ok(())
    }
}

pub(super) async fn recover_startup() -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    SettingsInit::recover(deadline).await?;
    GlobalInit::recover(deadline).await?;
    super::producers::ProducerTasks::recover().await?;
    super::handlers::HandlerTasks::recover().await?;
    super::owners::OwnerRegistry::recover_retained_with_deadline(deadline).await
}

/// Ожидает задачу запуска или восстанавливает её после сигнала завершения.
/// Очистка создаётся только после сигнала, поэтому её срок начинается тогда же.
pub(super) async fn wait_startup<T, C, F>(
    shutdown: &mut (impl std::future::Future<Output = ()> + Unpin),
    stage: impl std::future::Future<Output = Result<T>>,
    cleanup: C,
) -> Result<Option<T>>
where
    C: FnOnce() -> F,
    F: std::future::Future<Output = Result<()>>,
{
    let outcome = {
        tokio::select! {
            biased;
            () = shutdown => None,
            result = stage => Some(result),
        }
    };
    match outcome {
        None => {
            cleanup().await?;
            Ok(None)
        }
        Some(result) => result.map(Some),
    }
}

pub(super) async fn stop_startup() -> Result<()> {
    // Подготовка настроек и запуск Tor делят пять секунд; восстановление
    // производителей имеет отдельные пять секунд (всего не более десяти).
    let deadline = Instant::now() + cleanup_budget();
    let settings = SettingsInit::recover(deadline).await;
    let global = GlobalInit::recover(deadline).await;
    let producers = super::producers::ProducerTasks::recover().await;
    settings?;
    global?;
    producers
}
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(300);

struct Constructed {
    tunnel: TorTunnel,
    outcome: Result<()>,
}

pub(super) struct GlobalInit {
    cancel: CancellationToken,
    handle: Mutex<Option<JoinHandle<Result<Constructed>>>>,
    cleanup: Mutex<Option<JoinHandle<()>>>,
    tunnel: Mutex<Option<TorTunnel>>,
}

pub(super) struct InitGuard(pub(super) Arc<GlobalInit>);

impl Drop for InitGuard {
    fn drop(&mut self) {
        self.0.cancel.cancel();
    }
}

#[derive(Debug)]
struct ConstructorCancelled;
impl std::fmt::Display for ConstructorCancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("запуск глобального Tor отменён")
    }
}
impl std::error::Error for ConstructorCancelled {}

impl GlobalInit {
    pub(super) fn cancel(&self) {
        self.cancel.cancel();
    }

    pub(super) fn start(settings: Settings) -> Result<Arc<Self>> {
        #[cfg(test)]
        if let Ok(hook) = RUN_SERVER_STARTUP.try_with(Arc::clone) {
            if hook.park_global {
                let runtime = tokio::runtime::Handle::current();
                return Self::start_job(move |_cancel| {
                    let _entered = runtime.enter();
                    let tunnel = TorTunnel::create_unbootstrapped_with(settings)?;
                    let (entered, release) = hook.gate.lock().unwrap().take().unwrap();
                    let _ = entered.send(());
                    let _ = release.recv();
                    Ok(Constructed {
                        tunnel,
                        outcome: Err(anyhow::Error::new(ConstructorCancelled)),
                    })
                });
            }
        }
        #[cfg(test)]
        if RUN_SERVER_SHUTDOWN.try_with(|_| ()).is_ok() {
            let runtime = tokio::runtime::Handle::current();
            return Self::start_job(move |_| {
                let _entered = runtime.enter();
                Ok(Constructed {
                    tunnel: TorTunnel::create_unbootstrapped_with(settings)?,
                    outcome: Ok(()),
                })
            });
        }
        let runtime = tokio::runtime::Handle::current();
        Self::start_job(move |cancel| {
            let _entered = runtime.enter();
            let deadline = Instant::now() + BOOTSTRAP_TIMEOUT;
            let tunnel = TorTunnel::create_unbootstrapped_with(settings)?;
            runtime.block_on(async {
                let outcome = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => Err(anyhow::Error::new(ConstructorCancelled)),
                    result = tokio::time::timeout_at(deadline, tunnel.wait_bootstrapped()) => {
                        result.context("истёк срок запуска глобального Tor").and_then(|result| result.map_err(anyhow::Error::from))
                    }
                };
                Ok(Constructed { tunnel, outcome })
            })
        })
    }

    fn start_job(
        job: impl FnOnce(CancellationToken) -> Result<Constructed> + Send + 'static,
    ) -> Result<Arc<Self>> {
        let mut root = RETAINED
            .lock()
            .map_err(|_| anyhow!("хранилище запуска Tor повреждено"))?;
        if root.is_some() {
            bail!("предыдущий запуск глобального Tor ещё сохраняется");
        }
        let init = Arc::new(Self {
            cancel: CancellationToken::new(),
            handle: Mutex::new(None),
            cleanup: Mutex::new(None),
            tunnel: Mutex::new(None),
        });
        // Корень устанавливается до запуска; между установкой и сохранением дескриптора нет await.
        let mut handle = init.handle.try_lock().expect("новый слот свободен");
        *root = Some(init.clone());
        let cancel = init.cancel.clone();
        *handle = Some(tokio::task::spawn_blocking(move || job(cancel)));
        drop(handle);
        Ok(init)
    }

    /// cancel-safe: да — дескриптор остаётся в корневом слоте при отмене ожидания.
    pub(super) async fn wait(self: &Arc<Self>) -> Result<TorTunnel> {
        let mut slot = self.handle.lock().await;
        let handle = slot
            .as_mut()
            .ok_or_else(|| anyhow!("запуск Tor уже завершён"))?;
        // При отмене ожидания дескриптор остаётся в корневом слоте.
        let result = handle.await;
        slot.take();
        let constructed = match result.context("задача запуска Tor завершилась аварийно")?
        {
            Ok(value) => value,
            Err(error) => {
                self.release()?;
                return Err(error);
            }
        };
        if let Err(error) = constructed.outcome {
            *self.tunnel.try_lock().expect("слот запуска свободен") = Some(constructed.tunnel);
            drop(slot);
            Self::recover(Instant::now() + cleanup_budget()).await?;
            return Err(error);
        }
        *self.tunnel.try_lock().expect("слот запуска свободен") = Some(constructed.tunnel.clone());
        Ok(constructed.tunnel)
    }

    pub(super) fn complete_handoff(self: &Arc<Self>) -> Result<()> {
        self.release()?;
        self.tunnel
            .try_lock()
            .expect("слот запуска свободен")
            .take();
        Ok(())
    }

    fn release(self: &Arc<Self>) -> Result<()> {
        let mut root = RETAINED
            .lock()
            .map_err(|_| anyhow!("хранилище запуска Tor повреждено"))?;
        if root
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, self))
        {
            *root = None;
        }
        Ok(())
    }

    pub(super) async fn recover(deadline: Instant) -> Result<()> {
        let init = RETAINED
            .lock()
            .map_err(|_| anyhow!("хранилище запуска Tor повреждено"))?
            .clone();
        let Some(init) = init else {
            return Ok(());
        };
        init.cancel.cancel();
        let mut slot = tokio::time::timeout_at(deadline, init.handle.lock())
            .await
            .context("истёк срок ожидания запуска глобального Tor")?;
        let mut cleanup = tokio::time::timeout_at(deadline, init.cleanup.lock())
            .await
            .context("истёк срок ожидания очистки глобального Tor")?;
        if let Some(handle) = slot.as_mut() {
            let result = tokio::time::timeout_at(deadline, handle)
                .await
                .context("истёк срок ожидания запуска глобального Tor")?;
            slot.take();
            match result.context("задача запуска Tor завершилась аварийно")?
            {
                Ok(constructed) => {
                    *init.tunnel.try_lock().expect("слот запуска свободен") =
                        Some(constructed.tunnel);
                }
                Err(error) if error.is::<ConstructorCancelled>() => {}
                Err(error) => {
                    init.release()?;
                    return Err(error);
                }
            }
        }
        {
            let mut tunnel = tokio::time::timeout_at(deadline, init.tunnel.lock())
                .await
                .context("истёк срок ожидания очистки глобального Tor")?;
            if let Some(current) = tunnel.as_ref() {
                tokio::time::timeout_at(deadline, current.shutdown())
                    .await
                    .context("истёк срок завершения глобального PT")??;
            }
            if let Some(current) = tunnel.take() {
                *cleanup = Some(tokio::task::spawn_blocking(move || drop(current)));
            }
        }
        if let Some(handle) = cleanup.as_mut() {
            let result = tokio::time::timeout_at(deadline, handle)
                .await
                .context("истёк срок очистки глобального Tor")?;
            cleanup.take();
            result.context("задача очистки глобального Tor завершилась аварийно")?;
        }
        init.release()?;
        Ok(())
    }
}

#[cfg(test)]
pub(super) fn startup_snapshot(global: bool) -> (bool, bool) {
    if global {
        let root = RETAINED.lock().unwrap();
        (
            root.is_some(),
            root.as_ref().is_some_and(|init| init.cancel.is_cancelled()),
        )
    } else {
        (SETTINGS.lock().unwrap().is_some(), false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_during_settings_retains_blocked_job() {
        let _lifecycle = super::super::owners::TEST_LIFECYCLE.lock().await;
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let init = SettingsInit::start_job(move || {
            let _ = entered_tx.send(());
            let _ = release_rx.recv();
            Ok(Settings::default())
        })
        .unwrap();
        entered_rx.await.unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let mut shutdown = Box::pin(async {
            let _ = shutdown_rx.await;
        });
        shutdown_tx.send(()).unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            wait_startup(&mut shutdown, init.wait(), || {
                SettingsInit::recover(Instant::now() + Duration::ZERO)
            }),
        )
        .await;
        let retained = SETTINGS
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|root| Arc::ptr_eq(root, &init));
        release_tx.send(()).unwrap();
        SettingsInit::recover(Instant::now() + Duration::from_secs(5))
            .await
            .unwrap();
        assert!(result.expect("shutdown was ignored").is_err());
        assert!(retained);
        assert!(SETTINGS.lock().unwrap().is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_during_global_init_cancels_and_retains_blocked_job() {
        let _lifecycle = super::super::owners::TEST_LIFECYCLE.lock().await;
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let init = GlobalInit::start_job(move |cancel| {
            let _ = entered_tx.send(());
            let _ = release_rx.recv();
            assert!(cancel.is_cancelled());
            Err(anyhow::Error::new(ConstructorCancelled))
        })
        .unwrap();
        let _guard = InitGuard(init.clone());
        entered_rx.await.unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let mut shutdown = Box::pin(async {
            let _ = shutdown_rx.await;
        });
        shutdown_tx.send(()).unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            wait_startup(&mut shutdown, init.wait(), || async {
                init.cancel();
                GlobalInit::recover(Instant::now() + Duration::ZERO).await
            }),
        )
        .await;
        let cancelled = init.cancel.is_cancelled();
        let retained = RETAINED
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|root| Arc::ptr_eq(root, &init));
        init.cancel();
        release_tx.send(()).unwrap();
        GlobalInit::recover(Instant::now() + Duration::from_secs(5))
            .await
            .unwrap();
        assert!(result.expect("shutdown was ignored").is_err());
        assert!(cancelled && retained);
        assert!(RETAINED.lock().unwrap().is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handoff_keeps_tunnel_rooted_until_recovery() {
        let _lifecycle = super::super::owners::TEST_LIFECYCLE.lock().await;
        let runtime = tokio::runtime::Handle::current();
        let init = GlobalInit::start_job(move |_| {
            let _entered = runtime.enter();
            Ok(Constructed {
                tunnel: TorTunnel::create_unbootstrapped_with(Settings::default())?,
                outcome: Ok(()),
            })
        })
        .unwrap();
        let tunnel = init.wait().await.unwrap();
        assert!(RETAINED
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|root| Arc::ptr_eq(root, &init)));
        assert!(init.tunnel.lock().await.is_some());
        drop(tunnel);
        GlobalInit::recover(Instant::now() + Duration::from_secs(5))
            .await
            .unwrap();
        assert!(RETAINED.lock().unwrap().is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_wait_retains_job_until_recovery() {
        let _lifecycle = super::super::owners::TEST_LIFECYCLE.lock().await;
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let init = GlobalInit::start_job(move |_| {
            entered_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            Err(anyhow::Error::new(ConstructorCancelled))
        })
        .unwrap();
        let guard = InitGuard(init.clone());
        tokio::task::spawn_blocking(move || entered_rx.recv().unwrap())
            .await
            .unwrap();
        let waiter = tokio::spawn({
            let init = init.clone();
            async move { init.wait().await }
        });
        waiter.abort();
        let _ = waiter.await;
        drop(guard);
        assert!(init.cancel.is_cancelled());
        assert!(GlobalInit::start_job(|_| Err(anyhow!("не должен запускаться"))).is_err());
        assert!(
            GlobalInit::recover(Instant::now() + Duration::from_millis(10))
                .await
                .is_err()
        );
        assert!(RETAINED.lock().unwrap().is_some());
        release_tx.send(()).unwrap();
        GlobalInit::recover(Instant::now() + Duration::from_secs(5))
            .await
            .unwrap();
        assert!(RETAINED.lock().unwrap().is_none());
    }
}
