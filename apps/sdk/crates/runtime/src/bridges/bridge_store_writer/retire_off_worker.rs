//! Retire an old snapshot's `Arc` on the blocking pool instead of dropping
//! it inline in the actor's `select!` loop: when the actor's handle is the
//! last strong reference (no mutation job or publish job holds a clone at
//! that moment), the drop deallocates the whole `BridgeStore` map, and that
//! free() must not run synchronously on an async worker. Fire-and-forget on
//! purpose: there is nothing to observe about a plain deallocation and
//! `Drop` cannot meaningfully fail here, so nobody awaits the handle — the
//! `JoinHandle` is discarded explicitly because it is `#[must_use]`.
//!
//! The per-writer retirement log lets `retirement_tests.rs` assert that
//! each retirement actually runs on a blocking-pool thread, not on the
//! actor's async worker thread.

use std::sync::Arc;

use bridge_store::BridgeStore;

/// The actor hands [`drop_off_worker`] a settle sender under test builds (a
/// watch sender is not `Clone`, so it is shared through `Arc`); a no-op
/// token elsewhere.
#[cfg(test)]
pub(super) type RetireSignal = Arc<tokio::sync::watch::Sender<u64>>;
#[cfg(not(test))]
pub(super) type RetireSignal = Arc<()>;

/// TS6-04 test hook: per-writer log of the threads on which retired
/// snapshot `Arc`s were actually dropped. Kept per `StoreWriter` (not
/// process-global) so parallel tests in one binary never observe each
/// other's retirements. In non-test builds nothing is ever pushed.
pub(super) type RetirementLog = Arc<Mutex<Vec<std::thread::ThreadId>>>;

use std::sync::Mutex;

/// Retire one snapshot off-worker, recording the blocking-pool thread under
/// test builds (record first, then bump the retire-settle epoch, so a test
/// awaiting the epoch knows the record is already visible).
pub(super) fn drop_off_worker(
    old: Option<Arc<BridgeStore>>,
    retirements: RetirementLog,
    retire_signal: RetireSignal,
) {
    if let Some(old) = old {
        drop(tokio::task::spawn_blocking(move || {
            #[cfg(test)]
            {
                retirements
                    .lock()
                    .expect("retirement recorder poisoned")
                    .push(std::thread::current().id());
                retire_signal.send_modify(|epoch| *epoch += 1);
            }
            #[cfg(not(test))]
            {
                let _ = &retirements;
                drop(retire_signal);
            }
            drop(old);
        }));
    }
}
