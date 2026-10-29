use std::sync::{Arc, LazyLock, Mutex};
use tracing::warn;

// Неполученные ошибки занимают ячейки до терминального join.
const BLOCKING_WORKER_LIMIT: usize = 64;
pub(crate) type WorkerSlot = Arc<tokio::sync::Mutex<WorkerState>>;
#[derive(Default)]
pub(crate) struct WorkerState {
    handle: Option<tokio::task::JoinHandle<()>>,
    failure: Arc<Mutex<Option<anyhow::Error>>>,
}
#[derive(Debug)]
pub(crate) struct WorkerFailures(Vec<anyhow::Error>);
impl WorkerFailures {
    #[cfg(test)]
    pub(crate) fn into_errors(self) -> Vec<anyhow::Error> {
        self.0
    }
    pub(crate) fn errors(&self) -> &[anyhow::Error] {
        &self.0
    }
}
impl std::fmt::Display for WorkerFailures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "verifier blocking workers failed ({})", self.0.len())
    }
}
impl std::error::Error for WorkerFailures {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.first().map(|error| error.as_ref())
    }
}
#[derive(Default)]
struct WorkerRegistry {
    slots: Mutex<Vec<WorkerSlot>>,
}
#[cfg(test)]
thread_local! { static CURRENT_SLOT: std::cell::RefCell<Option<WorkerSlot>> = const { std::cell::RefCell::new(None) }; }
#[cfg(test)]
pub(crate) fn current_slot() -> Option<WorkerSlot> {
    CURRENT_SLOT.with(|slot| slot.borrow().clone())
}
#[cfg(test)]
struct SlotGuard;
#[cfg(test)]
impl Drop for SlotGuard {
    fn drop(&mut self) {
        CURRENT_SLOT.with(|slot| *slot.borrow_mut() = None);
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SharedWorkerError(Arc<anyhow::Error>);
impl std::fmt::Display for SharedWorkerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}
impl std::error::Error for SharedWorkerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref().as_ref())
    }
}
pub(crate) fn share_error(error: anyhow::Error) -> (anyhow::Error, anyhow::Error) {
    let shared = SharedWorkerError(Arc::new(error));
    (
        anyhow::Error::new(shared.clone()),
        anyhow::Error::new(shared),
    )
}
pub(crate) struct Delivery<T> {
    result: anyhow::Result<T>,
    failure: Arc<Mutex<Option<anyhow::Error>>>,
    acknowledge: bool,
}
impl<T> Delivery<T> {
    pub(crate) fn new(
        result: anyhow::Result<T>,
        failure: Arc<Mutex<Option<anyhow::Error>>>,
    ) -> Self {
        let result = result.map_err(|error| {
            let (retained, returned) = share_error(error);
            record_failure(&failure, retained);
            returned
        });
        Self {
            result,
            failure,
            acknowledge: true,
        }
    }
    pub(crate) fn panic(
        result: anyhow::Result<T>,
        failure: Arc<Mutex<Option<anyhow::Error>>>,
    ) -> Self {
        let mut delivery = Self::new(result, failure);
        delivery.acknowledge = false;
        delivery
    }
    pub(crate) fn absorb(self) -> anyhow::Result<T> {
        if self.acknowledge {
            if let Err(error) = &self.result {
                let mut retained = self.failure.lock().unwrap_or_else(|e| e.into_inner());
                let same = retained
                    .as_ref()
                    .and_then(|e| e.downcast_ref::<SharedWorkerError>())
                    .zip(error.downcast_ref::<SharedWorkerError>())
                    .is_some_and(|(a, b)| Arc::ptr_eq(&a.0, &b.0));
                if same {
                    retained.take();
                }
            }
        }
        self.result
    }
}
pub(crate) struct FallibleReceiver<T>(tokio::sync::oneshot::Receiver<Delivery<T>>);
impl<T> std::future::Future for FallibleReceiver<T> {
    type Output = Result<anyhow::Result<T>, tokio::sync::oneshot::error::RecvError>;
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        // Ожидание и пробуждение обеспечивает внутренний oneshot; передача без await.
        match std::pin::Pin::new(&mut self.0).poll(cx) {
            std::task::Poll::Ready(Ok(delivery)) => std::task::Poll::Ready(Ok(delivery.absorb())),
            std::task::Poll::Ready(Err(error)) => std::task::Poll::Ready(Err(error)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}
pub(crate) fn record_failure(failure: &Mutex<Option<anyhow::Error>>, error: anyhow::Error) {
    let mut failure = failure.lock().unwrap_or_else(|e| e.into_inner());
    if failure.is_none() {
        *failure = Some(error);
    }
}
static BLOCKING_WORKERS: LazyLock<WorkerRegistry> = LazyLock::new(WorkerRegistry::default);

impl WorkerRegistry {
    async fn reap(&self, slots: Vec<WorkerSlot>, finished_only: bool) {
        Self::reap_slots(slots, finished_only).await;
    }
    async fn reap_slots(slots: Vec<WorkerSlot>, finished_only: bool) {
        for slot in slots {
            let mut handle = if finished_only {
                match slot.try_lock() {
                    Ok(handle) => handle,
                    Err(_) => continue,
                }
            } else {
                slot.lock().await
            };
            if let Some(worker) = handle.handle.as_mut() {
                if finished_only && !worker.is_finished() {
                    continue;
                }
                let result = worker.await;
                handle.handle.take();
                if let Err(error) = result {
                    record_failure(&handle.failure, anyhow::Error::new(error));
                }
            }
        }
    }
    fn snapshot(&self) -> anyhow::Result<Vec<WorkerSlot>> {
        Ok(self
            .slots
            .lock()
            .map_err(|_| anyhow::anyhow!("verifier registry poisoned"))?
            .clone())
    }
    async fn join(&self) -> anyhow::Result<()> {
        let slots = self.snapshot()?;
        self.reap(slots.clone(), false).await;
        let mut states = Vec::new();
        for slot in &slots {
            states.push(slot.lock().await);
        }
        let mut errors = Vec::new();
        for state in states {
            if let Some(error) = state
                .failure
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
            {
                errors.push(error);
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(anyhow::Error::new(WorkerFailures(errors)))
        }
    }
    async fn run<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> anyhow::Result<T> {
        self.spawn(work, None)
            .await?
            .await
            .map_err(|error| anyhow::anyhow!("blocking worker result unavailable: {error}"))
    }

    async fn run_fallible<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> anyhow::Result<T> + Send + 'static,
    ) -> anyhow::Result<anyhow::Result<T>> {
        self.spawn_fallible(work, None)
            .await?
            .await
            .map_err(|error| anyhow::anyhow!("blocking worker result unavailable: {error}"))
    }
    async fn spawn_fallible<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> anyhow::Result<T> + Send + 'static,
        group: Option<&AdmissionWorkers>,
    ) -> anyhow::Result<FallibleReceiver<T>> {
        let rx = self
            .spawn_with_failure(move |failure| Delivery::new(work(), failure), group)
            .await?;
        Ok(FallibleReceiver(rx))
    }

    async fn spawn<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
        group: Option<&AdmissionWorkers>,
    ) -> anyhow::Result<tokio::sync::oneshot::Receiver<T>> {
        self.spawn_with_failure(move |_| work(), group).await
    }

    async fn spawn_with_failure<T: Send + 'static>(
        &self,
        work: impl FnOnce(Arc<Mutex<Option<anyhow::Error>>>) -> T + Send + 'static,
        group: Option<&AdmissionWorkers>,
    ) -> anyhow::Result<tokio::sync::oneshot::Receiver<T>> {
        self.reap(self.snapshot()?, true).await;
        let mut slots = self
            .slots
            .lock()
            .map_err(|_| anyhow::anyhow!("verifier registry poisoned"))?;
        let vacant = slots.iter().position(|slot| {
            slot.try_lock().is_ok_and(|state| {
                state.handle.is_none()
                    && state
                        .failure
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .is_none()
            })
        });
        if vacant.is_none() && slots.len() >= BLOCKING_WORKER_LIMIT {
            anyhow::bail!("verifier blocking worker registry full");
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        let span = tracing::Span::current();
        let state = WorkerState::default();
        let failure = state.failure.clone();
        let slot = Arc::new(tokio::sync::Mutex::new(state));
        #[cfg(test)]
        let current = slot.clone();
        let worker = tokio::task::spawn_blocking(move || {
            let _guard = span.enter();
            #[cfg(test)]
            let _slot_guard = {
                CURRENT_SLOT.with(|slot| *slot.borrow_mut() = Some(current));
                SlotGuard
            };
            let _ = tx.send(work(failure));
        });
        slot.try_lock().expect("новая ячейка свободна").handle = Some(worker);
        if let Some(index) = vacant {
            slots[index] = slot.clone();
        } else {
            slots.push(slot.clone());
        }
        if let Some(group) = group {
            group.add(slot);
        }
        Ok(rx)
    }
}

// Отдельный реестр исключает влияние параллельных тестов на общий бюджет ожидания.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct TestWorkers(WorkerRegistry);

#[cfg(test)]
tokio::task_local! {
    static TEST_WORKERS: Arc<TestWorkers>;
}

#[cfg(test)]
pub(crate) fn test_registry() -> Option<Arc<TestWorkers>> {
    TEST_WORKERS.try_with(Arc::clone).ok()
}

#[cfg(test)]
impl TestWorkers {
    // Область действует только в текущей задаче, а не в её потомках.
    pub(crate) async fn scope<F: std::future::Future>(self: &Arc<Self>, future: F) -> F::Output {
        TEST_WORKERS.scope(self.clone(), future).await
    }

    pub(crate) async fn owns_pending(&self, target: &WorkerSlot) -> bool {
        let owns = self
            .0
            .snapshot()
            .expect("test registry")
            .iter()
            .any(|slot| Arc::ptr_eq(slot, target));
        owns && target
            .lock()
            .await
            .handle
            .as_ref()
            .is_some_and(|handle| !handle.is_finished())
    }
    pub(crate) async fn cleared(&self, target: &WorkerSlot) -> bool {
        target.lock().await.handle.is_none()
    }

    pub(crate) async fn pending_count(&self) -> usize {
        let mut count = 0;
        for slot in self.0.snapshot().expect("test registry") {
            count += usize::from(slot.lock().await.handle.is_some());
        }
        count
    }

    pub(crate) async fn spawn<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> anyhow::Result<tokio::sync::oneshot::Receiver<T>> {
        self.0.spawn(work, None).await
    }

    pub(crate) async fn spawn_fallible<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> anyhow::Result<T> + Send + 'static,
    ) -> anyhow::Result<FallibleReceiver<T>> {
        self.0.spawn_fallible(work, None).await
    }

    pub(crate) async fn join(&self) -> anyhow::Result<()> {
        self.0.join().await
    }
}

// Отмена ожидания не удаляет дескрипторы и сохранённые ошибки.
pub(crate) async fn join_blocking_workers() -> anyhow::Result<()> {
    #[cfg(test)]
    if let Ok(registry) = TEST_WORKERS.try_with(Arc::clone) {
        return registry.0.join().await;
    }
    BLOCKING_WORKERS.join().await
}

pub(crate) async fn spawn_tracked_blocking<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> anyhow::Result<tokio::sync::oneshot::Receiver<T>> {
    #[cfg(test)]
    if let Ok(registry) = TEST_WORKERS.try_with(Arc::clone) {
        return registry.0.spawn(work, None).await;
    }
    BLOCKING_WORKERS.spawn(work, None).await
}

pub(crate) async fn run_tracked_blocking<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> anyhow::Result<T> {
    #[cfg(test)]
    if let Ok(registry) = TEST_WORKERS.try_with(Arc::clone) {
        return registry.0.run(work).await;
    }
    BLOCKING_WORKERS.run(work).await
}

pub(crate) async fn spawn_blocking_with_failure<T: Send + 'static>(
    work: impl FnOnce(Arc<Mutex<Option<anyhow::Error>>>) -> T + Send + 'static,
) -> anyhow::Result<tokio::sync::oneshot::Receiver<T>> {
    #[cfg(test)]
    if let Ok(registry) = TEST_WORKERS.try_with(Arc::clone) {
        return registry.0.spawn_with_failure(work, None).await;
    }
    BLOCKING_WORKERS.spawn_with_failure(work, None).await
}

pub(crate) async fn run_fallible_blocking<T: Send + 'static>(
    work: impl FnOnce() -> anyhow::Result<T> + Send + 'static,
) -> anyhow::Result<anyhow::Result<T>> {
    #[cfg(test)]
    if let Ok(registry) = TEST_WORKERS.try_with(Arc::clone) {
        return registry.0.run_fallible(work).await;
    }
    BLOCKING_WORKERS.run_fallible(work).await
}
pub(crate) async fn spawn_fallible_blocking<T: Send + 'static>(
    work: impl FnOnce() -> anyhow::Result<T> + Send + 'static,
) -> anyhow::Result<FallibleReceiver<T>> {
    #[cfg(test)]
    if let Ok(registry) = TEST_WORKERS.try_with(Arc::clone) {
        return registry.0.spawn_fallible(work, None).await;
    }
    BLOCKING_WORKERS.spawn_fallible(work, None).await
}

/// Группа ожидает только свои задачи; корневой реестр сохраняет их при отмене.
#[derive(Default)]
pub(crate) struct AdmissionWorkers {
    slots: Mutex<Vec<WorkerSlot>>,
}
impl AdmissionWorkers {
    fn add(&self, slot: WorkerSlot) {
        let mut slots = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        // Удаляем только уже собранные ячейки; занятые остаются под наблюдением.
        // Число последовательных проверок за проход ограничено целью из доверенной конфигурации.
        slots.retain(|entry| !entry.try_lock().is_ok_and(|state| state.handle.is_none()));
        slots.push(slot);
    }

    // Совместимость с существующим тестом, передающим готовый дескриптор.
    #[cfg(test)]
    pub(crate) fn track(&self, handle: tokio::task::JoinHandle<anyhow::Result<bool>>) {
        let worker = tokio::spawn(async move {
            match handle.await {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => warn!(%error, "circuit-verify: admission worker failed"),
                Err(error) => panic!("admission worker failed: {error}"),
            }
        });
        let slot = Arc::new(tokio::sync::Mutex::new(WorkerState {
            handle: Some(worker),
            ..WorkerState::default()
        }));
        BLOCKING_WORKERS
            .slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(slot.clone());
        self.add(slot);
    }

    /// Отмена ожидания не отделяет задачи от корневого владельца.
    pub(crate) async fn join_all(&self) {
        let slots = self.slots.lock().unwrap_or_else(|e| e.into_inner()).clone();
        WorkerRegistry::reap_slots(slots, false).await;
    }
}

pub(super) async fn spawn_for_admission<T: Send + 'static>(
    work: impl FnOnce() -> anyhow::Result<T> + Send + 'static,
    group: &AdmissionWorkers,
) -> anyhow::Result<FallibleReceiver<T>> {
    #[cfg(test)]
    if let Ok(registry) = TEST_WORKERS.try_with(Arc::clone) {
        return registry.0.spawn_fallible(work, Some(group)).await;
    }
    BLOCKING_WORKERS.spawn_fallible(work, Some(group)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[derive(Debug)]
    struct Marker;
    impl std::fmt::Display for Marker {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "marker")
        }
    }
    impl std::error::Error for Marker {}

    fn assert_marker(error: &anyhow::Error) {
        assert!(error.chain().any(|source| source.is::<Marker>()));
    }

    #[tokio::test]
    async fn distinct_failures_survive_cancelled_caller() {
        let registry = Arc::new(WorkerRegistry::default());
        let first = registry
            .spawn_fallible(|| Err::<(), _>(anyhow::anyhow!("first failure")), None)
            .await
            .unwrap();
        drop(first);
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, gate) = std::sync::mpsc::channel();
        let owner = registry.clone();
        let caller = tokio::spawn(async move {
            owner
                .run_fallible(move || {
                    let _ = started.send(());
                    let _ = gate.recv();
                    Err::<(), _>(anyhow::anyhow!("second failure"))
                })
                .await
        });
        ready.await.unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        let mut join = Box::pin(registry.join());
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(join.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(join);
        release.send(()).unwrap();
        let error = registry.join().await.unwrap_err();
        let failures = error.downcast_ref::<WorkerFailures>().unwrap().errors();
        assert_eq!(failures.len(), 2);
        assert!(failures.iter().any(|e| e.to_string() == "first failure"));
        assert!(failures.iter().any(|e| e.to_string() == "second failure"));
        registry.join().await.unwrap();
    }

    #[tokio::test]
    async fn retained_failures_exhaust_capacity_until_join() {
        let registry = WorkerRegistry::default();
        for index in 0..BLOCKING_WORKER_LIMIT {
            let rx = registry
                .spawn_fallible(
                    move || Err::<(), _>(anyhow::anyhow!("failure {index}")),
                    None,
                )
                .await
                .unwrap();
            drop(rx);
        }
        registry.reap(registry.snapshot().unwrap(), false).await;
        let executed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = executed.clone();
        assert!(registry
            .spawn(
                move || flag.store(true, std::sync::atomic::Ordering::SeqCst),
                None
            )
            .await
            .is_err());
        assert!(!executed.load(std::sync::atomic::Ordering::SeqCst));
        let error = registry.join().await.unwrap_err();
        let failures = error.downcast_ref::<WorkerFailures>().unwrap().errors();
        assert_eq!(failures.len(), BLOCKING_WORKER_LIMIT);
        for index in 0..BLOCKING_WORKER_LIMIT {
            assert!(failures
                .iter()
                .any(|error| error.to_string() == format!("failure {index}")));
        }
        let rx = registry.spawn(|| 42, None).await.unwrap();
        assert_eq!(rx.await.unwrap(), 42);
        registry.join().await.unwrap();
    }

    #[tokio::test]
    async fn admission_panic_stays_in_test_registry() {
        let registry = Arc::new(TestWorkers::default());
        let group = AdmissionWorkers::default();
        registry
            .scope(async {
                let rx =
                    spawn_for_admission(|| -> anyhow::Result<()> { panic!("group panic") }, &group)
                        .await
                        .unwrap();
                assert!(rx.await.is_err());
                group.join_all().await;
            })
            .await;
        let error = registry.join().await.unwrap_err();
        let failures = error.downcast_ref::<WorkerFailures>().unwrap().errors();
        assert_eq!(failures.len(), 1);
        assert!(failures[0]
            .downcast_ref::<tokio::task::JoinError>()
            .unwrap()
            .is_panic());
    }

    #[tokio::test]
    async fn fallible_live_caller_and_reap_keep_source() {
        let registry = WorkerRegistry::default();
        let result = registry
            .run_fallible(|| Err::<(), _>(anyhow::Error::new(Marker)))
            .await
            .unwrap()
            .unwrap_err();
        assert_marker(&result);
        registry.reap(registry.snapshot().unwrap(), false).await;
        let rx = registry.spawn(|| (), None).await.unwrap();
        rx.await.unwrap();
        registry.join().await.unwrap();
    }

    #[tokio::test]
    async fn fallible_caller_abort_and_cancelled_join_keep_source() {
        let registry = Arc::new(WorkerRegistry::default());
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, gate) = std::sync::mpsc::channel();
        let owner = registry.clone();
        let caller = tokio::spawn(async move {
            owner
                .run_fallible(move || {
                    let _ = started.send(());
                    let _ = gate.recv();
                    Err::<(), _>(anyhow::Error::new(Marker))
                })
                .await
        });
        ready.await.unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        let mut join = Box::pin(registry.join());
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(join.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(join);
        release.send(()).unwrap();
        assert_marker(&registry.join().await.unwrap_err());
    }

    #[tokio::test]
    async fn live_failures_release_capacity() {
        let registry = WorkerRegistry::default();
        for _ in 0..(BLOCKING_WORKER_LIMIT + 8) {
            let error = registry
                .run_fallible(|| Err::<(), _>(anyhow::Error::new(Marker)))
                .await
                .unwrap()
                .unwrap_err();
            assert_marker(&error);
        }
        assert_eq!(registry.run(|| 42).await.unwrap(), 42);
        registry.join().await.unwrap();
    }

    #[tokio::test]
    async fn maintenance_load_recovers_capacity() {
        let registry = Arc::new(TestWorkers::default());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.ktav");
        registry
            .scope(async {
                for _ in 0..72 {
                    assert!(
                        crate::bridge_maintenance::load_config_off_worker(Some(&path))
                            .await
                            .is_err()
                    );
                }
                crate::config::Config::default().write(&path).unwrap();
                crate::bridge_maintenance::load_config_off_worker(Some(&path))
                    .await
                    .unwrap();
            })
            .await;
        registry.join().await.unwrap();
    }

    #[tokio::test]
    async fn sent_error_survives_receiver_drop() {
        let registry = WorkerRegistry::default();
        let rx = registry
            .spawn_fallible(|| Err::<(), _>(anyhow::Error::new(Marker)), None)
            .await
            .unwrap();
        registry.reap(registry.snapshot().unwrap(), false).await;
        drop(rx);
        assert_marker(&registry.join().await.unwrap_err());
    }

    // Проверки используют отдельный реестр и реальные блокирующие задачи.
    #[tokio::test]
    async fn busy_reaper_does_not_block_other_groups_or_spawn() {
        let registry = Arc::new(WorkerRegistry::default());
        let group = AdmissionWorkers::default();
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, gate) = std::sync::mpsc::channel();
        registry
            .spawn(
                move || {
                    let _ = started.send(());
                    let _ = gate.recv();
                },
                None,
            )
            .await
            .unwrap();
        ready.await.unwrap();
        let slots = registry.snapshot().unwrap();
        let locked = slots[0].lock().await;
        let rx = tokio::time::timeout(Duration::from_secs(1), registry.spawn(|| 42, Some(&group)))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rx.await.unwrap(), 42);
        let own = group.slots.lock().unwrap().clone();
        tokio::time::timeout(Duration::from_secs(1), registry.reap(own, false))
            .await
            .unwrap();
        drop(locked);
        release.send(()).unwrap();
        registry.join().await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_run_retains_worker_and_panic_for_join() {
        let registry = Arc::new(WorkerRegistry::default());
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, gate) = std::sync::mpsc::channel();
        let owner = registry.clone();
        let outer = tokio::spawn(async move {
            owner
                .run(move || {
                    let _ = started.send(());
                    let _ = gate.recv();
                    panic!("проверка дочерней задачи");
                })
                .await
        });
        ready.await.unwrap();
        outer.abort();
        assert!(outer.await.unwrap_err().is_cancelled());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), registry.join())
                .await
                .is_err()
        );
        release.send(()).unwrap();
        assert!(registry.join().await.is_err());
    }

    #[tokio::test]
    async fn panic_survives_cancelled_join() {
        let registry = WorkerRegistry::default();
        let rx = registry.spawn(|| panic!("проверка"), None).await.unwrap();
        assert!(rx.await.is_err());
        let (release, gate) = std::sync::mpsc::channel();
        registry
            .spawn(
                move || {
                    let _ = gate.recv();
                },
                None,
            )
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), registry.join())
                .await
                .is_err()
        );
        release.send(()).unwrap();
        assert!(registry.join().await.is_err());
    }
}
