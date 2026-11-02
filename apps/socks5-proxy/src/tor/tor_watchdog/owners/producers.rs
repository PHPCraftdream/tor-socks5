use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use tokio::task::{AbortHandle, JoinHandle};
use tokio_util::sync::CancellationToken;

#[derive(Default)]
pub(super) struct ProducerFailures(Vec<anyhow::Error>);
impl ProducerFailures {
    #[cfg(test)]
    pub(super) fn into_errors(self) -> Vec<anyhow::Error> {
        self.0
    }
    pub(super) fn errors(&self) -> &[anyhow::Error] {
        &self.0
    }
    pub(super) fn into_result(self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(anyhow::Error::new(self))
        }
    }
    pub(super) fn push(&mut self, error: anyhow::Error) {
        self.0.push(error);
    }
}
impl std::fmt::Display for ProducerFailures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "shutdown failures ({})", self.errors().len())
    }
}
impl std::fmt::Debug for ProducerFailures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for ProducerFailures {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.errors().first().map(|error| error.as_ref())
    }
}

// После close последняя публикация тоже должна попасть в терминальный join.
pub(super) async fn join_final_workers() -> Result<()> {
    tokio::time::timeout(
        Duration::from_secs(5),
        crate::bridge_verifier::join_blocking_workers(),
    )
    .await
    .map_err(|_| anyhow!("final blocking worker shutdown timed out; process registry retained"))?
}

static RETAINED: Mutex<Option<Arc<ProducerTasks>>> = Mutex::new(None);

struct Task {
    abort: AbortHandle,
    handle: tokio::sync::Mutex<Option<JoinHandle<()>>>,
}

pub(super) struct ProducerTasks {
    token: CancellationToken,
    tasks: Mutex<Vec<Arc<Task>>>,
    failure: Mutex<ProducerFailures>,
    #[cfg(test)]
    children: Option<Arc<crate::bridge_verifier::TestWorkers>>,
}

impl ProducerTasks {
    pub(super) fn retain() -> Result<Arc<Self>> {
        let mut retained = RETAINED
            .lock()
            .map_err(|_| anyhow!("producer registry poisoned"))?;
        if retained.is_some() {
            bail!("previous producers are still retained");
        }
        let owner = Arc::new(Self {
            token: CancellationToken::new(),
            tasks: Mutex::new(Vec::new()),
            failure: Mutex::new(ProducerFailures::default()),
            #[cfg(test)]
            children: None,
        });
        *retained = Some(owner.clone());
        Ok(owner)
    }

    #[cfg(test)]
    pub(super) fn for_test(token: CancellationToken) -> Arc<Self> {
        Arc::new(Self {
            token,
            tasks: Mutex::new(Vec::new()),
            failure: Mutex::new(ProducerFailures::default()),
            children: Some(Arc::new(crate::bridge_verifier::TestWorkers::default())),
        })
    }

    #[cfg(test)]
    pub(super) async fn has_retained_handle(&self) -> bool {
        let tasks = self.tasks.lock().unwrap_or_else(|e| e.into_inner()).clone();
        for task in tasks {
            if task.handle.lock().await.is_some() {
                return true;
            }
        }
        false
    }

    pub(super) fn token(&self) -> CancellationToken {
        self.token.clone()
    }

    fn install(&self, handles: &mut Vec<JoinHandle<()>>) {
        let mut tasks = self.tasks.lock().unwrap_or_else(|e| e.into_inner());
        for handle in handles.drain(..) {
            tasks.push(Arc::new(Task {
                abort: handle.abort_handle(),
                handle: tokio::sync::Mutex::new(Some(handle)),
            }));
        }
    }

    pub(super) fn add(&self, handle: JoinHandle<()>) {
        self.install(&mut vec![handle]);
    }

    pub(super) fn cancel(&self) {
        self.token.cancel();
    }

    pub(super) fn abort(&self) {
        self.cancel();
        let tasks = self.tasks.lock().unwrap_or_else(|e| e.into_inner());
        for task in tasks.iter() {
            task.abort.abort();
        }
    }

    #[cfg(test)]
    pub(super) async fn recover_terminal() -> Result<()> {
        let retained = RETAINED
            .lock()
            .map_err(|_| anyhow!("producer registry poisoned"))?
            .clone();
        if let Some(owner) = retained {
            owner.abort();
            let tasks = owner
                .tasks
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            for task in tasks {
                let mut slot = task.handle.lock().await;
                if let Some(handle) = slot.as_mut() {
                    let result = handle.await;
                    slot.take();
                    if let Err(error) = result {
                        if !error.is_cancelled() {
                            owner
                                .failure
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .push(anyhow::Error::new(error));
                        }
                    }
                }
            }

            let terminal_children = match &owner.children {
                Some(children) => match children.join().await {
                    Ok(()) => true,
                    Err(error) if error.is::<crate::bridge_verifier::WorkerFailures>() => {
                        owner
                            .failure
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .push(error);
                        true
                    }
                    Err(error) => {
                        owner
                            .failure
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .push(error);
                        false
                    }
                },
                None => match crate::bridge_verifier::join_blocking_workers().await {
                    Ok(()) => true,
                    Err(error) if error.is::<crate::bridge_verifier::WorkerFailures>() => {
                        owner
                            .failure
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .push(error);
                        true
                    }
                    Err(error) => {
                        owner
                            .failure
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .push(error);
                        false
                    }
                },
            };
            if !terminal_children {
                return Err(anyhow!(
                    "producer recovery retained non-terminal child failure"
                ));
            }

            let mut root = RETAINED
                .lock()
                .map_err(|_| anyhow!("producer registry poisoned"))?;
            if root
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &owner))
            {
                *root = None;
            }
            let failure =
                std::mem::take(&mut *owner.failure.lock().unwrap_or_else(|e| e.into_inner()));
            failure.into_result()
        } else {
            Ok(())
        }
    }

    pub(super) async fn recover() -> Result<()> {
        let owner = RETAINED
            .lock()
            .map_err(|_| anyhow!("producer registry poisoned"))?
            .clone();
        if let Some(owner) = owner {
            owner.abort();
            owner.join(Duration::from_secs(5)).await?;
        }
        Ok(())
    }

    /// cancel-safe: да — ожидания сохраняют дескрипторы и ошибки для повтора.
    pub(super) async fn join(&self, budget: Duration) -> Result<()> {
        let tasks = self.tasks.lock().unwrap_or_else(|e| e.into_inner()).clone();
        tokio::time::timeout(budget, async {
            for task in tasks {
                let mut slot = task.handle.lock().await;
                if let Some(handle) = slot.as_mut() {
                    let result = handle.await;
                    slot.take();
                    if let Err(error) = result {
                        if !error.is_cancelled() {
                            tracing::warn!("producer task failed");
                            self.failure
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .push(anyhow::Error::new(error));
                        }
                    }
                }
            }
            #[cfg(not(test))]
            let children_result = crate::bridge_verifier::join_blocking_workers().await;
            #[cfg(test)]
            let children_result = match &self.children {
                Some(children) => children.join().await,
                None => crate::bridge_verifier::join_blocking_workers().await,
            };
            if let Err(error) = children_result {
                self.failure
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(error);
            }
        })
        .await
        .map_err(|_| anyhow!("producer shutdown timed out; handles retained"))?;
        let mut retained = RETAINED
            .lock()
            .map_err(|_| anyhow!("producer registry poisoned"))?;
        if retained
            .as_ref()
            .is_some_and(|owner| std::ptr::eq(owner.as_ref(), self))
        {
            *retained = None;
        }
        let failure = std::mem::take(&mut *self.failure.lock().unwrap_or_else(|e| e.into_inner()));
        failure.into_result()
    }
}

// Старому запуску нужен изменяемый Vec. Передаём его и при раскрутке стека,
// и при успехе, до любой точки приостановки или возможной ошибки запуска.
// Число задач ограничено фиксированными производителями и числом onion-служб
// из доверенной конфигурации; подключения клиентов не увеличивают этот список.
pub(super) struct LaunchGuard {
    owner: Arc<ProducerTasks>,
    pub(super) handles: Vec<JoinHandle<()>>,
    committed: bool,
}
impl LaunchGuard {
    pub(super) fn new(owner: Arc<ProducerTasks>) -> Self {
        Self {
            owner,
            handles: Vec::new(),
            committed: false,
        }
    }
    pub(super) fn commit(mut self) {
        self.owner.install(&mut self.handles);
        self.committed = true;
    }
}
impl Drop for LaunchGuard {
    fn drop(&mut self) {
        self.owner.install(&mut self.handles);
        if !self.committed {
            self.owner.abort();
        }
    }
}

pub(super) struct RunGuard(pub(super) Arc<ProducerTasks>);
impl Drop for RunGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;

    fn owner() -> Arc<ProducerTasks> {
        ProducerTasks::for_test(CancellationToken::new())
    }

    fn gated() -> (oneshot::Sender<()>, JoinHandle<()>) {
        let (tx, rx) = oneshot::channel();
        (
            tx,
            tokio::spawn(async move {
                let _ = rx.await;
            }),
        )
    }

    #[derive(Debug)]
    struct First;
    #[derive(Debug)]
    struct Second;
    impl std::fmt::Display for First {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "first secret")
        }
    }
    impl std::fmt::Display for Second {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "second secret")
        }
    }
    impl std::error::Error for First {}
    impl std::error::Error for Second {}

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pre_launch_cancellation_retains_parked_maintenance_until_join() {
        use crate::test_seams::{ParkedGate, Site, HANG_GUARD};
        let _serial = super::super::owners::TEST_LIFECYCLE.lock().await;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proxy.ktav");
        let mut cfg = crate::config::Config::default();
        cfg.bridges.use_seeds = false;
        cfg.bridges.auto_fetch = false;
        cfg.bridges.lines = vec!["8.8.8.8:443 1111111111111111111111111111111111111111".into()];
        cfg.pre_socks5 = Some(proxy_config::EndpointOverride::Endpoint(
            "127.0.0.1:1080".parse().unwrap(),
        ));
        cfg.write(&path).unwrap();
        let settings = crate::tor_setup::build_tor_settings(&cfg, Some(&path))
            .await
            .unwrap();
        let tunnel = arti_wrapper::TorTunnel::create_unbootstrapped_with(settings.clone()).unwrap();
        let gate = ParkedGate::arm(Site::MaintenanceConfigLoad, &path);
        let owner = ProducerTasks::retain().unwrap();
        let mut launch = LaunchGuard::new(owner.clone());
        super::super::bridge_producers::launch(
            crate::tor_watchdog::TorHandle::new(tunnel),
            Some(path),
            &cfg,
            crate::arti_observability::ObservationSink::new(),
            settings,
            owner.token(),
            &mut launch.handles,
        );
        launch.commit();
        let waiter = gate.clone();
        tokio::task::spawn_blocking(move || waiter.wait_parked(HANG_GUARD))
            .await
            .unwrap();
        owner.cancel();
        assert!(owner.join(Duration::ZERO).await.is_err());
        assert!(owner.has_retained_handle().await);
        gate.release();
        owner.join(Duration::from_secs(10)).await.unwrap();
        assert!(!owner.has_retained_handle().await);
    }

    #[tokio::test]
    async fn cancelled_join_preserves_outer_and_distinct_child_failures() {
        use std::error::Error as _;
        let owner = owner();
        let children = owner.children.as_ref().unwrap().clone();
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel::<()>(1);
        let caller = tokio::spawn(async move {
            let first = children
                .spawn_fallible(|| Err::<(), _>(anyhow::Error::new(First).context("first context")))
                .await
                .unwrap();
            let second = children
                .spawn_fallible(move || {
                    let _ = started_tx.send(());
                    let _ = release_rx.recv();
                    Err::<(), _>(anyhow::Error::new(Second).context("second context"))
                })
                .await
                .unwrap();
            let _receivers = (first, second);
            std::future::pending::<()>().await;
        });
        started_rx.await.unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        let panic = tokio::spawn(async {
            panic!("outer secret");
        });
        owner.add(panic);
        let mut join = Box::pin(owner.join(Duration::from_secs(30)));
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(join.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(join);
        release_tx.send(()).unwrap();
        let error = owner.join(Duration::from_secs(5)).await.unwrap_err();
        let failures = error.downcast_ref::<ProducerFailures>().unwrap();
        assert_eq!(failures.errors().len(), 2);
        assert!(failures.source().unwrap().is::<tokio::task::JoinError>());
        assert!(failures.errors()[0]
            .downcast_ref::<tokio::task::JoinError>()
            .unwrap()
            .is_panic());
        let children = failures.errors()[1]
            .downcast_ref::<crate::bridge_verifier::WorkerFailures>()
            .unwrap();
        assert_eq!(children.errors().len(), 2);
        assert!(children
            .errors()
            .iter()
            .any(|e| e.chain().any(|cause| cause.is::<First>())));
        assert!(children
            .errors()
            .iter()
            .any(|e| e.chain().any(|cause| cause.is::<Second>())));
        assert!(children
            .errors()
            .iter()
            .any(|e| e.chain().any(|cause| cause.to_string() == "first context")));
        assert!(children
            .errors()
            .iter()
            .any(|e| e.chain().any(|cause| cause.to_string() == "second context")));
        assert!(!format!("{error}").contains("secret"));
        let mut terminal = ProducerFailures::default();
        terminal.push(anyhow!("other shutdown error"));
        terminal.push(error);
        let terminal = terminal.into_result().unwrap_err();
        let terminal = terminal.downcast_ref::<ProducerFailures>().unwrap();
        assert!(terminal.errors()[1]
            .downcast_ref::<ProducerFailures>()
            .is_some());
        owner.join(Duration::from_secs(5)).await.unwrap();
    }

    #[tokio::test]
    async fn launch_guard_retains_on_unwind() {
        let owner = owner();
        let (_tx, handle) = gated();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut guard = LaunchGuard::new(owner.clone());
            guard.handles.push(handle);
            panic!("проверка раскрутки");
        }));
        assert!(result.is_err());
        assert!(owner.token.is_cancelled());
        assert_eq!(owner.tasks.lock().unwrap().len(), 1);
        owner.join(Duration::from_secs(5)).await.unwrap();
    }

    #[tokio::test]
    async fn launch_guard_retains_on_cancel() {
        let owner = owner();
        let (ready_tx, ready_rx) = oneshot::channel();
        let (_tx, handle) = gated();
        let owner_clone = owner.clone();
        let launch = tokio::spawn(async move {
            let mut guard = LaunchGuard::new(owner_clone);
            guard.handles.push(handle);
            let _ = ready_tx.send(());
            std::future::pending::<()>().await;
        });
        ready_rx.await.unwrap();
        launch.abort();
        let _ = launch.await;
        assert!(owner.token.is_cancelled());
        assert_eq!(owner.tasks.lock().unwrap().len(), 1);
        owner.join(Duration::from_secs(5)).await.unwrap();
    }

    #[tokio::test]
    async fn timeout_retains_handle_for_retry() {
        let owner = owner();
        let (tx, handle) = gated();
        owner.add(handle);
        assert!(owner.join(Duration::ZERO).await.is_err());
        let task = owner.tasks.lock().unwrap()[0].clone();
        assert!(task.handle.lock().await.is_some());
        tx.send(()).unwrap();
        owner.join(Duration::from_secs(5)).await.unwrap();
        assert!(task.handle.lock().await.is_none());
    }

    #[tokio::test]
    async fn run_guard_cancels_and_retains_handle() {
        let owner = owner();
        let (_tx, handle) = gated();
        owner.add(handle);
        let (ready_tx, ready_rx) = oneshot::channel();
        let owner_clone = owner.clone();
        let run = tokio::spawn(async move {
            let _guard = RunGuard(owner_clone);
            let _ = ready_tx.send(());
            std::future::pending::<()>().await;
        });
        ready_rx.await.unwrap();
        run.abort();
        let _ = run.await;
        assert!(owner.token.is_cancelled());
        assert_eq!(owner.tasks.lock().unwrap().len(), 1);
        owner.join(Duration::from_secs(5)).await.unwrap();
    }

    #[tokio::test]
    async fn aborted_outer_retains_blocking_child_until_joined() {
        let owner = owner();
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel::<()>(1);
        let children = owner.children.as_ref().unwrap().clone();
        owner.add(tokio::spawn(async move {
            let result = children
                .spawn(move || {
                    let _ = started_tx.send(());
                    let _ = release_rx.recv();
                })
                .await
                .unwrap();
            let _ = result.await;
        }));
        started_rx.await.unwrap();
        owner.abort();
        let task = owner.tasks.lock().unwrap()[0].clone();
        {
            let mut slot = task.handle.lock().await;
            let _ = slot.as_mut().unwrap().await;
            slot.take();
        }
        assert!(owner.join(Duration::ZERO).await.is_err());
        release_tx.send(()).unwrap();
        owner.join(Duration::from_secs(5)).await.unwrap();
    }

    #[tokio::test]
    async fn panic_is_reported_after_all_handles_are_reaped() {
        let owner = owner();
        owner.add(tokio::spawn(async {
            panic!("проверка ошибки");
        }));
        let (tx, handle) = gated();
        owner.add(handle);
        assert!(owner.join(Duration::ZERO).await.is_err());
        tx.send(()).unwrap();
        assert!(owner.join(Duration::from_secs(5)).await.is_err());
        let tasks = owner.tasks.lock().unwrap().clone();
        for task in tasks {
            assert!(task.handle.lock().await.is_none());
        }
    }
}
