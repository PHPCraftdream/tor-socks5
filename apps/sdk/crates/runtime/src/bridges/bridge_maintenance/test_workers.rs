//! Test-only per-task worker registry. A separate registry keeps
//! parallel tests from contending for the shared blocking-worker budget;
//! it compiles away outside `cfg(test)` and the `test-seams` feature.

use std::sync::Arc;

use super::{FallibleReceiver, WorkerRegistry, WorkerSlot};

/// Registry whose workers live only for the current task, not its
/// descendants, so each test owns its own worker set.
#[derive(Default)]
pub struct TestWorkers(pub(crate) WorkerRegistry);

tokio::task_local! {
    pub(crate) static TEST_WORKERS: Arc<TestWorkers>;
}

/// Returns the current task's test registry, if running inside
/// [`TestWorkers::scope`].
pub fn test_registry() -> Option<Arc<TestWorkers>> {
    TEST_WORKERS.try_with(Arc::clone).ok()
}

impl TestWorkers {
    // Область действует только в текущей задаче, а не в её потомках.
    /// Runs `future` with this registry installed; only the current task
    /// (not its spawned descendants) resolves to it.
    pub async fn scope<F: std::future::Future>(self: &Arc<Self>, future: F) -> F::Output {
        TEST_WORKERS.scope(self.clone(), future).await
    }

    /// True when `target` belongs to this registry and its worker has
    /// not finished yet.
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

    /// True when the worker behind `target` has been joined and removed.
    pub async fn cleared(&self, target: &WorkerSlot) -> bool {
        target.lock().await.handle.is_none()
    }

    /// Number of registry workers that have not finished yet.
    pub async fn pending_count(&self) -> usize {
        let mut count = 0;
        for slot in self.0.snapshot().expect("test registry") {
            count += usize::from(slot.lock().await.handle.is_some());
        }
        count
    }

    /// Spawns `work` in this registry, returning its result receiver.
    pub async fn spawn<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> anyhow::Result<tokio::sync::oneshot::Receiver<T>> {
        self.0.spawn(work, None).await
    }

    /// Like [`TestWorkers::spawn`] for fallible work; the receiver
    /// resolves to the worker's own `Result` instead of panicking it.
    pub async fn spawn_fallible<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> anyhow::Result<T> + Send + 'static,
    ) -> anyhow::Result<FallibleReceiver<T>> {
        self.0.spawn_fallible(work, None).await
    }

    /// Waits for every registry worker, reporting collected failures.
    pub async fn join(&self) -> anyhow::Result<()> {
        self.0.join().await
    }
}
