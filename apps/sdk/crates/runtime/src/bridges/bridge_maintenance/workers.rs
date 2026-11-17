use std::sync::{Arc, LazyLock, Mutex};

// The registry may retain 64 active jobs plus 64 overflow-failure slots (128 slots max);
// the separate report buffer retains up to 128 more failures.
const BLOCKING_WORKER_LIMIT: usize = 64;
const FAILURE_REPORT_LIMIT: usize = 128;
const WORKER_SLOT_LIMIT: usize = BLOCKING_WORKER_LIMIT * 2;
const RETAINED_FAILURE_LIMIT: usize = FAILURE_REPORT_LIMIT + BLOCKING_WORKER_LIMIT;
type WorkerFailure = Arc<Mutex<Option<anyhow::Error>>>;
pub type WorkerSlot = Arc<tokio::sync::Mutex<WorkerState>>;
#[derive(Default)]
pub struct WorkerState {
    handle: Option<tokio::task::JoinHandle<()>>,
    failure: WorkerFailure,
}
#[derive(Debug)]
pub struct WorkerFailures(Vec<anyhow::Error>);
impl WorkerFailures {
    pub(crate) fn new(errors: Vec<anyhow::Error>) -> Self {
        Self(errors)
    }

    #[cfg(any(test, feature = "test-seams"))]
    pub fn into_errors(self) -> Vec<anyhow::Error> {
        self.0
    }
    pub fn errors(&self) -> &[anyhow::Error] {
        &self.0
    }
}
impl std::fmt::Display for WorkerFailures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "blocking workers failed ({})", self.errors().len())
    }
}
impl std::error::Error for WorkerFailures {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.errors().first().map(|error| error.as_ref())
    }
}
#[derive(Default)]
struct WorkerRegistry {
    slots: Mutex<Vec<WorkerSlot>>,
    reports: Mutex<Vec<WorkerFailure>>,
}
#[cfg(any(test, feature = "test-seams"))]
thread_local! { static CURRENT_SLOT: std::cell::RefCell<Option<WorkerSlot>> = const { std::cell::RefCell::new(None) }; }
#[cfg(any(test, feature = "test-seams"))]
pub(crate) fn current_slot() -> Option<WorkerSlot> {
    CURRENT_SLOT.with(|slot| slot.borrow().clone())
}
#[cfg(any(test, feature = "test-seams"))]
struct SlotGuard;
#[cfg(any(test, feature = "test-seams"))]
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
    failure: WorkerFailure,
    acknowledge: bool,
}
impl<T> Delivery<T> {
    pub(crate) fn new(result: anyhow::Result<T>, failure: WorkerFailure) -> Self {
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
    pub(crate) fn panic(result: anyhow::Result<T>, failure: WorkerFailure) -> Self {
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
pub struct FallibleReceiver<T>(tokio::sync::oneshot::Receiver<Delivery<T>>);
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
    async fn reap_slots(
        slots: Vec<WorkerSlot>,
        finished_only: bool,
        reports: Option<&Mutex<Vec<WorkerFailure>>>,
    ) {
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
            if let Some(reports) = reports {
                Self::report_failure(&mut handle, reports);
            }
        }
    }
    fn report_failure(state: &mut WorkerState, reports: &Mutex<Vec<WorkerFailure>>) {
        let failure = Arc::clone(&state.failure);
        let error = failure
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(ToString::to_string);
        let Some(error) = error else {
            return;
        };
        let mut reports = reports.lock().unwrap_or_else(|e| e.into_inner());
        reports.retain(|failure| failure.lock().unwrap_or_else(|e| e.into_inner()).is_some());
        if reports.len() >= FAILURE_REPORT_LIMIT {
            tracing::warn!(
                error = %error,
                capacity = FAILURE_REPORT_LIMIT,
                "blocking worker failure report buffer full; retaining failure in its slot"
            );
            return;
        }
        tracing::warn!(error = %error, "blocking worker failed; retaining it for registry join");
        reports.push(failure);
        state.failure = Arc::new(Mutex::new(None));
    }
    fn snapshot(&self) -> anyhow::Result<Vec<WorkerSlot>> {
        Ok(self
            .slots
            .lock()
            .map_err(|_| anyhow::anyhow!("blocking worker registry poisoned"))?
            .clone())
    }
    /// cancel-safe: yes — cancellation leaves unfinished workers and uncollected failures in the registry.
    async fn join(&self) -> anyhow::Result<()> {
        let slots = self.snapshot()?;
        Self::reap_slots(slots.clone(), false, Some(&self.reports)).await;
        let mut states = Vec::new();
        for slot in &slots {
            states.push(slot.lock().await);
        }
        let mut errors = Vec::new();
        for failure in self
            .reports
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
        {
            if let Some(error) = failure.lock().unwrap_or_else(|e| e.into_inner()).take() {
                errors.push(error);
            }
        }
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
            Err(anyhow::Error::new(crate::workers::WorkerFailures::new(
                errors,
            )))
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

    /// cancel-safe: yes — reaped failures stay registered, and no new worker is added before the await completes.
    async fn spawn_with_failure<T: Send + 'static>(
        &self,
        work: impl FnOnce(WorkerFailure) -> T + Send + 'static,
        group: Option<&AdmissionWorkers>,
    ) -> anyhow::Result<tokio::sync::oneshot::Receiver<T>> {
        Self::reap_slots(self.snapshot()?, true, Some(&self.reports)).await;
        let mut slots = self
            .slots
            .lock()
            .map_err(|_| anyhow::anyhow!("blocking worker registry poisoned"))?;
        let active = slots
            .iter()
            .filter(|slot| match slot.try_lock() {
                Ok(state) => state.handle.is_some(),
                Err(_) => true,
            })
            .count();
        let report_count = {
            let mut reports = self.reports.lock().unwrap_or_else(|e| e.into_inner());
            reports.retain(|failure| failure.lock().unwrap_or_else(|e| e.into_inner()).is_some());
            reports.len()
        };
        let retained_failures = slots
            .iter()
            .filter(|slot| {
                slot.try_lock().is_ok_and(|state| {
                    state.handle.is_none()
                        && state
                            .failure
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .is_some()
                })
            })
            .count();
        if report_count.saturating_add(retained_failures) >= RETAINED_FAILURE_LIMIT {
            anyhow::bail!("blocking worker failure capacity full; join workers to collect reports");
        }
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
        if active >= BLOCKING_WORKER_LIMIT {
            anyhow::bail!("blocking worker registry full");
        }
        if vacant.is_none() && slots.len() >= WORKER_SLOT_LIMIT {
            anyhow::bail!("blocking worker registry full; join workers to collect failures");
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        let span = tracing::Span::current();
        let state = WorkerState::default();
        let failure = state.failure.clone();
        let slot = Arc::new(tokio::sync::Mutex::new(state));
        #[cfg(any(test, feature = "test-seams"))]
        let current = slot.clone();
        let worker = tokio::task::spawn_blocking(move || {
            let _guard = span.enter();
            #[cfg(any(test, feature = "test-seams"))]
            let _slot_guard = {
                CURRENT_SLOT.with(|slot| *slot.borrow_mut() = Some(current));
                SlotGuard
            };
            let _ = tx.send(work(failure));
        });
        slot.try_lock().expect("new slot is unlocked").handle = Some(worker);
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
#[cfg(any(test, feature = "test-seams"))]
#[derive(Default)]
pub struct TestWorkers(WorkerRegistry);

#[cfg(any(test, feature = "test-seams"))]
tokio::task_local! {
    static TEST_WORKERS: Arc<TestWorkers>;
}

#[cfg(any(test, feature = "test-seams"))]
pub fn test_registry() -> Option<Arc<TestWorkers>> {
    TEST_WORKERS.try_with(Arc::clone).ok()
}

#[cfg(any(test, feature = "test-seams"))]
impl TestWorkers {
    // Область действует только в текущей задаче, а не в её потомках.
    pub async fn scope<F: std::future::Future>(self: &Arc<Self>, future: F) -> F::Output {
        TEST_WORKERS.scope(self.clone(), future).await
    }

    pub async fn owns_pending(&self, target: &WorkerSlot) -> bool {
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
    pub async fn cleared(&self, target: &WorkerSlot) -> bool {
        target.lock().await.handle.is_none()
    }

    pub async fn pending_count(&self) -> usize {
        let mut count = 0;
        for slot in self.0.snapshot().expect("test registry") {
            count += usize::from(slot.lock().await.handle.is_some());
        }
        count
    }

    pub async fn spawn<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> anyhow::Result<tokio::sync::oneshot::Receiver<T>> {
        self.0.spawn(work, None).await
    }

    pub async fn spawn_fallible<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> anyhow::Result<T> + Send + 'static,
    ) -> anyhow::Result<FallibleReceiver<T>> {
        self.0.spawn_fallible(work, None).await
    }

    pub async fn join(&self) -> anyhow::Result<()> {
        self.0.join().await
    }
}

/// Occupied registry slots: unfinished workers, overflow failures, or unacknowledged errors.
/// Zero after server shutdown means the registry is clear for the next run.
#[cfg(any(test, feature = "test-seams"))]
pub async fn global_busy_count() -> usize {
    let mut busy = 0;
    for slot in BLOCKING_WORKERS.snapshot().expect("process registry") {
        let state = slot.lock().await;
        let failed = state
            .failure
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some();
        busy += usize::from(state.handle.is_some() || failed);
    }
    let reports = BLOCKING_WORKERS
        .reports
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    busy += reports
        .iter()
        .filter(|failure| failure.lock().unwrap_or_else(|e| e.into_inner()).is_some())
        .count();
    busy
}

// Отмена ожидания не удаляет дескрипторы и сохранённые ошибки.
pub async fn join_blocking_workers() -> anyhow::Result<()> {
    #[cfg(any(test, feature = "test-seams"))]
    if let Ok(registry) = TEST_WORKERS.try_with(Arc::clone) {
        return registry.0.join().await;
    }
    BLOCKING_WORKERS.join().await
}

pub(crate) async fn spawn_tracked_blocking<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> anyhow::Result<tokio::sync::oneshot::Receiver<T>> {
    #[cfg(any(test, feature = "test-seams"))]
    if let Ok(registry) = TEST_WORKERS.try_with(Arc::clone) {
        return registry.0.spawn(work, None).await;
    }
    BLOCKING_WORKERS.spawn(work, None).await
}

pub(crate) async fn run_tracked_blocking<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> anyhow::Result<T> {
    #[cfg(any(test, feature = "test-seams"))]
    if let Ok(registry) = TEST_WORKERS.try_with(Arc::clone) {
        return registry.0.run(work).await;
    }
    BLOCKING_WORKERS.run(work).await
}

pub(crate) async fn spawn_blocking_with_failure<T: Send + 'static>(
    work: impl FnOnce(WorkerFailure) -> T + Send + 'static,
) -> anyhow::Result<tokio::sync::oneshot::Receiver<T>> {
    #[cfg(any(test, feature = "test-seams"))]
    if let Ok(registry) = TEST_WORKERS.try_with(Arc::clone) {
        return registry.0.spawn_with_failure(work, None).await;
    }
    BLOCKING_WORKERS.spawn_with_failure(work, None).await
}

pub async fn run_fallible_blocking<T: Send + 'static>(
    work: impl FnOnce() -> anyhow::Result<T> + Send + 'static,
) -> anyhow::Result<anyhow::Result<T>> {
    #[cfg(any(test, feature = "test-seams"))]
    if let Ok(registry) = TEST_WORKERS.try_with(Arc::clone) {
        return registry.0.run_fallible(work).await;
    }
    BLOCKING_WORKERS.run_fallible(work).await
}
pub(crate) async fn spawn_fallible_blocking<T: Send + 'static>(
    work: impl FnOnce() -> anyhow::Result<T> + Send + 'static,
) -> anyhow::Result<FallibleReceiver<T>> {
    #[cfg(any(test, feature = "test-seams"))]
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
                Ok(Err(error)) => tracing::warn!(%error, "admission worker failed"),
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
        WorkerRegistry::reap_slots(slots, false, None).await;
    }
}

pub(super) async fn spawn_for_admission<T: Send + 'static>(
    work: impl FnOnce() -> anyhow::Result<T> + Send + 'static,
    group: &AdmissionWorkers,
) -> anyhow::Result<FallibleReceiver<T>> {
    #[cfg(any(test, feature = "test-seams"))]
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
    async fn completed_panics_release_active_capacity() {
        let registry = WorkerRegistry::default();
        for _ in 0..BLOCKING_WORKER_LIMIT + 1 {
            let rx = registry
                .spawn(|| panic!("blocking task panic"), None)
                .await
                .unwrap();
            assert!(rx.await.is_err());
            WorkerRegistry::reap_slots(
                registry.snapshot().unwrap(),
                false,
                Some(&registry.reports),
            )
            .await;
        }
        let rx = registry.spawn(|| 42, None).await.unwrap();
        assert_eq!(rx.await.unwrap(), 42);
        let error = registry.join().await.unwrap_err();
        let failures = error.downcast_ref::<WorkerFailures>().unwrap().errors();
        assert_eq!(failures.len(), BLOCKING_WORKER_LIMIT + 1);
        assert!(failures.iter().all(|error| {
            error
                .downcast_ref::<tokio::task::JoinError>()
                .is_some_and(tokio::task::JoinError::is_panic)
        }));
        registry.join().await.unwrap();
    }

    #[tokio::test]
    async fn report_buffer_overflow_is_bounded_and_lossless() {
        let registry = WorkerRegistry::default();
        for index in 0..RETAINED_FAILURE_LIMIT {
            let rx = registry
                .spawn_fallible(
                    move || Err::<(), _>(anyhow::anyhow!("overflow {index}")),
                    None,
                )
                .await
                .unwrap();
            drop(rx);
            WorkerRegistry::reap_slots(
                registry.snapshot().unwrap(),
                false,
                Some(&registry.reports),
            )
            .await;
        }
        assert_eq!(registry.reports.lock().unwrap().len(), FAILURE_REPORT_LIMIT);
        let slots = registry.snapshot().unwrap();
        assert!(slots.len() <= WORKER_SLOT_LIMIT);
        let report_failures = registry
            .reports
            .lock()
            .unwrap()
            .iter()
            .filter(|failure| failure.lock().unwrap().is_some())
            .count();
        let slot_failures = {
            let mut count = 0;
            for slot in &slots {
                if slot.lock().await.failure.lock().unwrap().is_some() {
                    count += 1;
                }
            }
            count
        };
        assert_eq!(slot_failures, BLOCKING_WORKER_LIMIT);
        assert_eq!(
            report_failures + slot_failures,
            RETAINED_FAILURE_LIMIT,
            "every failed worker must be retained in a report or overflow slot"
        );
        let admission_error = registry
            .spawn(|| (), None)
            .await
            .expect_err("admission must stop when retained failure capacity is full");
        assert!(admission_error
            .to_string()
            .contains("failure capacity full"));

        let error = registry.join().await.unwrap_err();
        let failures = error.downcast_ref::<WorkerFailures>().unwrap().errors();
        assert_eq!(failures.len(), RETAINED_FAILURE_LIMIT);
        for index in 0..RETAINED_FAILURE_LIMIT {
            assert!(failures
                .iter()
                .any(|error| error.to_string() == format!("overflow {index}")));
        }

        let rx = registry
            .spawn(|| 42, None)
            .await
            .expect("admission recovers after collecting retained failures");
        assert_eq!(rx.await.unwrap(), 42);
        registry.join().await.unwrap();
    }

    #[tokio::test]
    async fn acknowledged_report_is_cleared_before_join() {
        let registry = WorkerRegistry::default();
        let rx = registry
            .spawn_fallible(|| Err::<(), _>(anyhow::Error::new(Marker)), None)
            .await
            .unwrap();
        let slots = registry.snapshot().unwrap();
        WorkerRegistry::reap_slots(slots, false, Some(&registry.reports)).await;
        assert_marker(&rx.await.unwrap().unwrap_err());
        assert!(registry.reports.lock().unwrap()[0]
            .lock()
            .unwrap()
            .is_none());
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
        WorkerRegistry::reap_slots(registry.snapshot().unwrap(), false, Some(&registry.reports))
            .await;
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
        WorkerRegistry::reap_slots(registry.snapshot().unwrap(), false, Some(&registry.reports))
            .await;
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
        tokio::time::timeout(
            Duration::from_secs(1),
            WorkerRegistry::reap_slots(own, false, None),
        )
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
                    panic!("child task panic");
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
        let rx = registry
            .spawn(|| panic!("blocking task panic"), None)
            .await
            .unwrap();
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
