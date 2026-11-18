//! Run-scoped blocking-worker group. The SDK server installs its own
//! [`AdmissionWorkers`] group per run and joins only those slots at
//! shutdown, never the process registry used by the CLI.

use std::sync::{Arc, Mutex};

use super::{AdmissionWorkers, WorkerFailures, WorkerRegistry, WorkerSlot};

static RUN_GROUP: Mutex<Option<Arc<AdmissionWorkers>>> = Mutex::new(None);

/// The run group installed for the current server run, if any.
pub(crate) fn current() -> Option<Arc<AdmissionWorkers>> {
    RUN_GROUP.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Install a fresh blocking-worker group for this server run. Fails when a
/// previous run still retains its group (its workers have not been joined).
pub fn begin_run_group() -> anyhow::Result<()> {
    let mut group = RUN_GROUP.lock().unwrap_or_else(|e| e.into_inner());
    if group.is_some() {
        anyhow::bail!("previous server run still retains its blocking-worker group");
    }
    *group = Some(Arc::new(AdmissionWorkers::default()));
    Ok(())
}

/// Join exactly the given group's slots and collect their retained failures.
/// Mirrors [`WorkerRegistry::join`] without touching the root reports buffer.
pub(crate) async fn join_group(group: &AdmissionWorkers) -> anyhow::Result<()> {
    let slots: Vec<WorkerSlot> = group
        .slots
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    WorkerRegistry::reap_slots(slots.clone(), false, None).await;
    let mut errors = Vec::new();
    for slot in &slots {
        if let Some(error) = slot
            .lock()
            .await
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
        Err(anyhow::Error::new(WorkerFailures::new(errors)))
    }
}

/// Join the current run group, if one is installed.
pub(crate) async fn join_run_group() -> anyhow::Result<()> {
    match current() {
        None => Ok(()),
        Some(group) => join_group(&group).await,
    }
}

/// Join and remove the run group within `budget`. On timeout the group is
/// put back so a later join or recovery can still collect its workers.
///
/// cancel-safe: yes — the group is removed only after all workers joined.
pub async fn end_run_group(budget: std::time::Duration) -> anyhow::Result<()> {
    let group = RUN_GROUP.lock().unwrap_or_else(|e| e.into_inner()).take();
    let Some(group) = group else {
        return Ok(());
    };
    match tokio::time::timeout(budget, join_group(&group)).await {
        Ok(result) => result,
        Err(_) => {
            *RUN_GROUP.lock().unwrap_or_else(|e| e.into_inner()) = Some(group);
            anyhow::bail!(
                "server run blocking workers did not finish within the shutdown budget; \
                 group retained for recovery"
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workers::{join_blocking_workers, spawn_tracked_blocking};
    use std::time::Duration;

    // Uses real blocking workers through the free wrapper: the run group
    // must receive the slot, and end_run_group must join only that group.
    // One test only: the group is process-global, so parallel tests would
    // race over it.
    #[tokio::test]
    async fn run_group_joins_wrapped_spawn_and_refuses_rebegin() {
        // Without a group, end_run_group is a no-op.
        assert!(current().is_none());
        end_run_group(Duration::from_secs(1)).await.unwrap();
        begin_run_group().unwrap();
        assert!(begin_run_group().is_err(), "second begin must be refused");
        let rx = spawn_tracked_blocking(|| 7u32).await.unwrap();
        assert_eq!(rx.await.unwrap(), 7);
        let group = current().expect("run group installed");
        end_run_group(Duration::from_secs(5)).await.unwrap();
        assert!(current().is_none());
        assert!(group
            .slots
            .lock()
            .unwrap()
            .iter()
            .all(|slot| slot.try_lock().is_ok_and(|state| state.handle.is_none())));
        // The process registry still holds the slot; reap it to stay clean
        // for other tests. Failures retained by other tests in a shared
        // process are theirs, so the result is deliberately not asserted.
        let _ = join_blocking_workers().await;
    }
}
