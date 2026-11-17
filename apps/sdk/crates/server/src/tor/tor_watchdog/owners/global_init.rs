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
    pub async_gate: StdMutex<
        Option<(
            tokio::sync::oneshot::Sender<()>,
            tokio::sync::oneshot::Receiver<()>,
        )>,
    >,
}

#[cfg(test)]
tokio::task_local! {
    pub(super) static RUN_SERVER_STARTUP: Arc<StartupHook>;
    pub(super) static RUN_SERVER_SHUTDOWN: Arc<ShutdownHook>;
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BootstrapFailure {
    Error,
    Panic,
}

#[cfg(test)]
pub(super) struct ShutdownHook {
    pub settings: Settings,
    /// `None` отдаёт запись настоящему процессному слоту `WRITER`.
    pub writer: Option<tor_socks5_runtime::bridge_store_writer::StoreWriter>,
    pub failure: Option<BootstrapFailure>,
    pub ready: StdMutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

pub(super) fn launch_background() -> bool {
    #[cfg(test)]
    {
        RUN_SERVER_SHUTDOWN.try_with(|_| ()).is_err()
    }
    #[cfg(not(test))]
    {
        true
    }
}

pub(super) fn server_ready() {
    #[cfg(test)]
    let _ = RUN_SERVER_SHUTDOWN.try_with(|hook| {
        if let Some(ready) = hook.ready.lock().unwrap().take() {
            let _ = ready.send(());
        }
    });
}

pub(super) fn init_store_writer(path: Option<&std::path::Path>) {
    #[cfg(test)]
    if RUN_SERVER_STARTUP.try_with(|_| ()).is_ok()
        || RUN_SERVER_SHUTDOWN
            .try_with(|hook| hook.writer.is_some())
            .unwrap_or(false)
    {
        return;
    }
    tor_socks5_runtime::bridge_store_writer::init_run(path);
}

pub(super) async fn close_store_writer(
    deadline: Option<tokio::time::Instant>,
) -> Option<Result<()>> {
    #[cfg(test)]
    if let Ok(Some(writer)) = RUN_SERVER_SHUTDOWN.try_with(|hook| hook.writer.clone()) {
        let close = writer.close();
        return Some(match deadline {
            Some(deadline) => tokio::time::timeout_at(deadline, close).await.unwrap_or_else(|_| {
                Err(anyhow::anyhow!(
                    "bridge store writer close did not finish within the deadline; writer retained in the closing slot"
                ))
            }),
            None => close.await,
        });
    }
    #[cfg(test)]
    if RUN_SERVER_STARTUP.try_with(|_| ()).is_ok() {
        return None;
    }
    tor_socks5_runtime::bridge_store_writer::close_run(deadline).await
}

fn cleanup_budget() -> Duration {
    #[cfg(test)]
    if RUN_SERVER_STARTUP.try_with(|_| ()).is_ok() {
        return Duration::from_millis(20);
    }
    Duration::from_secs(5)
}

pub(super) struct SettingsInit {
    cancel: CancellationToken,
    handle: Mutex<Option<JoinHandle<Result<Settings>>>>,
}

impl SettingsInit {
    pub(super) fn start(
        cfg: crate::config::Config,
        path: Option<std::path::PathBuf>,
        cancellation: CancellationToken,
    ) -> Result<Arc<Self>> {
        #[cfg(test)]
        if let Ok(hook) = RUN_SERVER_STARTUP.try_with(Arc::clone) {
            let stage: std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<Settings>> + Send>,
            > = if hook.park_global {
                let settings = hook.settings.clone();
                Box::pin(std::future::ready(Ok(settings)))
            } else if let Some((entered, release)) = hook.async_gate.lock().unwrap().take() {
                let settings = hook.settings.clone();
                Box::pin(async move {
                    let _ = entered.send(());
                    release.await.context("settings startup test gate closed")?;
                    Ok(settings)
                })
            } else {
                let (entered, release) = hook.gate.lock().unwrap().take().unwrap();
                let settings = hook.settings.clone();
                Box::pin(async move {
                    let _ = entered.send(());
                    let _ = release.recv();
                    Ok(settings)
                })
            };
            return Self::start_job(cancellation, stage);
        }
        #[cfg(test)]
        if let Ok(settings) = RUN_SERVER_SHUTDOWN.try_with(|hook| hook.settings.clone()) {
            return Self::start_job(cancellation, std::future::ready(Ok(settings)));
        }
        let stage = async move {
            tor_socks5_runtime::tor_setup::build_tor_settings(&cfg, path.as_deref()).await
        };
        Self::start_job(cancellation, stage)
    }

    fn start_job<F>(cancellation: CancellationToken, stage: F) -> Result<Arc<Self>>
    where
        F: std::future::Future<Output = Result<Settings>> + Send + 'static,
    {
        let mut root = SETTINGS
            .lock()
            .map_err(|_| anyhow!("settings registry is poisoned"))?;
        if root.is_some() {
            bail!("previous settings preparation is still retained");
        }
        let init = Arc::new(Self {
            cancel: cancellation.child_token(),
            handle: Mutex::new(None),
        });
        let mut slot = init.handle.try_lock().expect("new slot is free");
        *root = Some(init.clone());
        let cancel = init.cancel.clone();
        let runtime = tokio::runtime::Handle::current();
        *slot = Some(tokio::task::spawn_blocking(move || {
            runtime.block_on(async move {
                tokio::select! {
                    biased;
                    () = cancel.cancelled() => Err(anyhow::Error::new(StartupFailure::cancelled())),
                    result = stage => result,
                }
            })
        }));
        drop(slot);
        Ok(init)
    }

    #[cfg(test)]
    pub(super) fn cancel(&self) {
        self.cancel.cancel();
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
            .map_err(|_| anyhow!("settings registry is poisoned"))?
            .clone();
        let Some(init) = init else {
            return Ok(());
        };
        init.cancel.cancel();
        let mut slot = tokio::time::timeout_at(deadline, init.handle.lock())
            .await
            .context("settings preparation recovery timed out")?;
        if let Some(handle) = slot.as_mut() {
            let result = tokio::time::timeout_at(deadline, handle)
                .await
                .context("settings preparation recovery timed out")?;
            slot.take();
            init.release()?;
            let result = result.context("settings preparation task failed")?;
            if let Err(error) = result {
                let cancelled = error
                    .downcast_ref::<StartupFailure>()
                    .is_some_and(StartupFailure::is_cancelled);
                if !cancelled {
                    return Err(error);
                }
            }
        } else {
            init.release()?;
        }
        Ok(())
    }
}

pub(super) async fn recover_startup() -> Result<()> {
    aggregate_errors(recover_startup_all().await)
}

fn aggregate_errors(errors: impl IntoIterator<Item = anyhow::Error>) -> Result<()> {
    let mut failures = super::producers::ProducerFailures::default();
    for error in errors {
        failures.push(error);
    }
    failures.into_result()
}

/// Recover every retained startup/runtime owner, preserving each failure so
/// failed-run cleanup can continue through the remaining stages.
pub(super) async fn recover_startup_all() -> Vec<anyhow::Error> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut errors = Vec::new();
    if let Err(error) = SettingsInit::recover(deadline).await {
        errors.push(error);
    }
    if let Err(error) = GlobalInit::recover(deadline).await {
        errors.push(error);
    }
    if let Err(error) = super::producers::ProducerTasks::recover().await {
        errors.push(error);
    }
    if let Err(error) = super::handlers::HandlerTasks::recover().await {
        errors.push(error);
    }
    if let Err(error) = super::owners::OwnerRegistry::recover_retained_with_deadline(deadline).await
    {
        errors.push(error);
    }
    // Clear a run group retained by an earlier hung shutdown (Ok(()) when none).
    if let Err(error) = tor_socks5_runtime::workers::end_run_group(Duration::from_secs(5)).await {
        errors.push(error);
    }
    errors
}

/// Close a writer left by an earlier run after its retained owners recovered.
pub(super) async fn close_orphaned_store_writer() -> Option<Result<()>> {
    // Bounded so startup cannot hang on a stuck flush; the writer stays in
    // its closing slot on timeout and late flushes still land.
    tor_socks5_runtime::bridge_store_writer::close_run(Some(
        Instant::now() + Duration::from_secs(5),
    ))
    .await
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
            let cleanup = cleanup().await.err();
            let primary = StartupPrimary::Cancelled;
            let failure = match cleanup {
                Some(cleanup) => StartupFailure::with_cleanup(primary, cleanup),
                None => StartupFailure::cancelled(),
            };
            Err(anyhow::Error::new(failure))
        }
        Some(result) => result.map(Some),
    }
}

pub(super) async fn stop_startup() -> Result<()> {
    // Settings and global init share five seconds; producer recovery has its own budget.
    let deadline = Instant::now() + cleanup_budget();
    let settings = SettingsInit::recover(deadline).await;
    let global = GlobalInit::recover(deadline).await;
    let producers = super::producers::ProducerTasks::recover().await;
    let mut errors = Vec::new();
    if let Err(error) = settings {
        errors.push(error);
    }
    if let Err(error) = global {
        errors.push(error);
    }
    if let Err(error) = producers {
        errors.push(error);
    }
    aggregate_errors(errors)
}
#[derive(Debug)]
pub(super) enum StartupPrimary {
    Cancelled,
    Error(anyhow::Error),
}

/// Keeps the primary startup result separate from every cleanup failure.
#[derive(Debug)]
pub(super) struct StartupFailure {
    pub(super) primary: StartupPrimary,
    pub(super) cleanup: Option<anyhow::Error>,
}

impl StartupFailure {
    pub(super) fn cancelled() -> Self {
        Self {
            primary: StartupPrimary::Cancelled,
            cleanup: None,
        }
    }

    pub(super) fn with_cleanup(primary: StartupPrimary, cleanup: anyhow::Error) -> Self {
        Self {
            primary,
            cleanup: Some(cleanup),
        }
    }

    #[cfg(test)]
    pub(super) fn cleanup_error(&self) -> Option<&anyhow::Error> {
        self.cleanup.as_ref()
    }

    #[cfg(test)]
    pub(super) fn primary(&self) -> &StartupPrimary {
        &self.primary
    }

    pub(super) fn is_cancelled(&self) -> bool {
        matches!(self.primary, StartupPrimary::Cancelled)
    }
}

impl std::fmt::Display for StartupFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.primary {
            StartupPrimary::Cancelled => f.write_str("server startup cancelled"),
            StartupPrimary::Error(_) => f.write_str("server startup failed"),
        }
    }
}

impl std::error::Error for StartupFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.primary {
            StartupPrimary::Cancelled => None,
            StartupPrimary::Error(primary) => Some(primary.as_ref()),
        }
    }
}

fn global_init_failure(primary: StartupPrimary, cleanup: Result<()>) -> anyhow::Error {
    match cleanup {
        Ok(()) => match primary {
            StartupPrimary::Cancelled => anyhow::Error::new(StartupFailure::cancelled()),
            StartupPrimary::Error(error) => error,
        },
        Err(cleanup) => anyhow::Error::new(StartupFailure::with_cleanup(primary, cleanup)),
    }
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
        if let Ok(Some(failure)) = RUN_SERVER_SHUTDOWN.try_with(|hook| hook.failure) {
            return Self::start_job(move |_| match failure {
                BootstrapFailure::Error => Err(anyhow!("sdk11 synthetic bootstrap failure")),
                BootstrapFailure::Panic => panic!("sdk11 synthetic bootstrap panic"),
            });
        }
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
            *self.tunnel.try_lock().expect("startup slot is free") = Some(constructed.tunnel);
            drop(slot);
            let primary = if error.is::<ConstructorCancelled>() {
                StartupPrimary::Cancelled
            } else {
                StartupPrimary::Error(error)
            };
            return Err(global_init_failure(
                primary,
                Self::recover(Instant::now() + cleanup_budget()).await,
            ));
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
                .context("global Tor startup timed out")?;
            slot.take();
            match result.context("global Tor startup task failed")? {
                Ok(constructed) => {
                    *init.tunnel.try_lock().expect("startup slot is free") =
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
    async fn settings_init_select_observes_cancellation() {
        let _lifecycle = super::super::owners::TEST_LIFECYCLE.lock().await;
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let hook = Arc::new(StartupHook {
            settings: Settings::default(),
            park_global: false,
            gate: StdMutex::new(None),
            async_gate: StdMutex::new(Some((entered_tx, release_rx))),
        });
        let cancellation = CancellationToken::new();
        let init = RUN_SERVER_STARTUP
            .scope(hook, async {
                SettingsInit::start(crate::config::Config::default(), None, cancellation.clone())
            })
            .await
            .unwrap();
        entered_rx.await.unwrap();

        cancellation.cancel();
        let failure = init
            .wait()
            .await
            .expect_err("cancellation returns an error");
        let failure = failure.downcast_ref::<StartupFailure>().unwrap();
        assert!(failure.is_cancelled());
        assert!(failure.cleanup_error().is_none());
        drop(release_tx);
        assert!(SETTINGS.lock().unwrap().is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_during_blocked_settings_retains_job_and_cleanup_timeout() {
        let _lifecycle = super::super::owners::TEST_LIFECYCLE.lock().await;
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let hook = Arc::new(StartupHook {
            settings: Settings::default(),
            park_global: false,
            gate: StdMutex::new(Some((entered_tx, release_rx))),
            async_gate: StdMutex::new(None),
        });
        let cancellation = CancellationToken::new();
        let init = RUN_SERVER_STARTUP
            .scope(hook, async {
                SettingsInit::start(crate::config::Config::default(), None, cancellation.clone())
            })
            .await
            .unwrap();
        tokio::task::spawn_blocking(move || entered_rx.blocking_recv().unwrap())
            .await
            .unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let mut shutdown = Box::pin(async {
            let _ = shutdown_rx.await;
        });
        shutdown_tx.send(()).unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            wait_startup(&mut shutdown, init.wait(), || {
                init.cancel();
                SettingsInit::recover(Instant::now() + Duration::from_millis(20))
            }),
        )
        .await
        .unwrap();
        let retained = SETTINGS
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|root| Arc::ptr_eq(root, &init));

        let failure = result.expect_err("shutdown returns an error");
        let failure = failure.downcast_ref::<StartupFailure>().unwrap();
        assert!(failure.is_cancelled());
        assert!(failure
            .cleanup_error()
            .unwrap()
            .to_string()
            .contains("settings preparation recovery timed out"));
        assert!(retained, "timed-out blocking work must remain retained");

        release_tx.send(()).unwrap();
        SettingsInit::recover(Instant::now() + Duration::from_secs(5))
            .await
            .unwrap();
        assert!(SETTINGS.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn global_init_preserves_primary_when_cleanup_fails() {
        let primary = anyhow!("bootstrap failure").context("bootstrap context");
        let cleanup = anyhow!("cleanup timed out");
        let error = global_init_failure(StartupPrimary::Error(primary), Err(cleanup));
        let failure = error.downcast_ref::<StartupFailure>().unwrap();
        let StartupPrimary::Error(primary) = failure.primary() else {
            panic!("cleanup failure replaced the primary bootstrap error");
        };
        let primary_chain = format!("{primary:#}");
        assert_eq!(primary_chain.matches("bootstrap context").count(), 1);
        assert_eq!(primary_chain.matches("bootstrap failure").count(), 1);
        assert_eq!(
            failure.cleanup_error().unwrap().to_string(),
            "cleanup timed out"
        );
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
        let failure = result
            .expect("shutdown was ignored")
            .err()
            .expect("shutdown returns an error");
        assert!(failure
            .downcast_ref::<StartupFailure>()
            .is_some_and(StartupFailure::is_cancelled));
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
