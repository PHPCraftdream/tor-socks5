//! The launch-phase gate: at most MAX_STARTING services hold a launch slot
//! at the same time, so a small pool of bridges is not stampeded by every
//! service's circuit pool filling at once. A slot is held from just before
//! `launch_onion_service` until the service reports a terminal status
//! (Running / DegradedReachable / Broken), or the slot cap elapses, or
//! shutdown — then it is released and the next service launches; the service
//! itself keeps running.

use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

/// Keep the launch stampede small: a handful of services fill their circuit
/// pools concurrently, the rest wait for a slot. Deliberately a constant,
/// not a config key.
pub(crate) const MAX_STARTING: usize = 4;

/// A service keeps its slot at most this long without reporting a terminal
/// status; the cap covers the whole launch phase (launch, address wait,
/// status wait), not just the tail.
const START_SLOT_TIMEOUT: Duration = Duration::from_secs(90);

/// Hands out the launch slots. `Clone` shares one semaphore.
#[derive(Clone)]
pub(crate) struct StartGate {
    permits: Arc<tokio::sync::Semaphore>,
    slots: usize,
}

impl StartGate {
    pub(crate) fn new() -> Self {
        Self::with_slots(MAX_STARTING)
    }

    fn with_slots(slots: usize) -> Self {
        Self {
            permits: Arc::new(tokio::sync::Semaphore::new(slots)),
            slots,
        }
    }

    /// Slots held right now (for the launch log lines).
    pub(crate) fn in_use(&self) -> usize {
        self.slots.saturating_sub(self.permits.available_permits())
    }

    /// Wait for a launch slot; `None` on shutdown or a closed semaphore.
    ///
    /// cancel-safe: a cancelled waiter never holds a slot (tokio's
    /// `acquire_owned` is cancel-safe — a losing future never takes a
    /// permit). Order: freed permits are handed to waiters FIFO by tokio's
    /// semaphore, so managers spawned in services-file order acquire slots
    /// in file order.
    pub(crate) async fn acquire(&self, token: &CancellationToken) -> Option<StartSlot> {
        tokio::select! {
            biased;
            () = token.cancelled() => None,
            permit = self.permits.clone().acquire_owned() => {
                // A closed semaphore gives no slot either.
                permit.ok().map(|permit| {
                    let acquired_at = tokio::time::Instant::now();
                    StartSlot {
                        _permit: permit,
                        acquired_at,
                        deadline: acquired_at + START_SLOT_TIMEOUT,
                    }
                })
            }
        }
    }

    #[cfg(test)]
    fn available_permits(&self) -> usize {
        self.permits.available_permits()
    }
}

/// Why a launch slot was given back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SlotRelease {
    /// The service reported a terminal status (or its status task is gone).
    Status,
    /// The slot cap elapsed with no terminal status.
    Cap,
    /// Shutdown.
    Shutdown,
}

impl SlotRelease {
    /// The value of the `reason` log field.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Cap => "cap",
            Self::Shutdown => "shutdown",
        }
    }
}

/// One launch slot; dropping it releases the permit back to the gate.
pub(crate) struct StartSlot {
    // Kept (never read) for its Drop: dropping the slot releases the permit.
    _permit: tokio::sync::OwnedSemaphorePermit,
    acquired_at: tokio::time::Instant,
    deadline: tokio::time::Instant,
}

impl StartSlot {
    /// Hold the slot until the service first reports started (`started`
    /// fires or its sender drops), the slot cap elapses, or shutdown — then
    /// return why and for how long it was held, dropping `self` and releasing
    /// the slot for the next service. The token is taken by value so the
    /// future stays `'static` when spawned.
    ///
    /// cancel-safe: dropping the future (or the returned slot being dropped)
    /// releases the slot.
    pub(crate) async fn hold_until_started(
        self,
        started: tokio::sync::oneshot::Receiver<()>,
        token: CancellationToken,
    ) -> (SlotRelease, Duration) {
        let reason = tokio::select! {
            biased;
            () = token.cancelled() => SlotRelease::Shutdown,
            // Ok: the service first reported a terminal status; Err: the
            // status task is gone. Either way the launch is over.
            _ = started => SlotRelease::Status,
            () = tokio::time::sleep_until(self.deadline) => SlotRelease::Cap,
        };
        (reason, self.acquired_at.elapsed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn a_fifth_service_waits_for_a_slot() {
        let gate = StartGate::new();
        let token = CancellationToken::new();
        let one = gate.acquire(&token).await.expect("slot 1");
        let two = gate.acquire(&token).await.expect("slot 2");
        let three = gate.acquire(&token).await.expect("slot 3");
        let four = gate.acquire(&token).await.expect("slot 4");
        assert_eq!(gate.available_permits(), 0);

        let (done_tx, mut done_rx) = tokio::sync::oneshot::channel();
        let token2 = CancellationToken::new();
        let waiter_gate = gate.clone();
        let waiter = tokio::spawn(async move {
            let slot = waiter_gate.acquire(&token2).await;
            let _ = done_tx.send(slot); // the receiver is always alive
        });

        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(
            done_rx.try_recv().is_err(),
            "no slot free: the fifth service still waits"
        );

        drop(three); // one held slot is released
        assert!(
            matches!(done_rx.await, Ok(Some(_))),
            "the freed slot reaches the waiting fifth service"
        );
        waiter.await.expect("waiter task joins");
        drop((one, two, four));
    }

    #[tokio::test(start_paused = true)]
    async fn the_slot_is_released_when_the_service_reports_started() {
        // One slot: the next acquire succeeds only if the holder released it.
        let gate = StartGate::with_slots(1);
        let token = CancellationToken::new();
        let slot = gate.acquire(&token).await.expect("slot");
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let token2 = CancellationToken::new();
        let holder = tokio::spawn(slot.hold_until_started(started_rx, token2));
        started_tx.send(()).expect("the holder still listens");

        // No time advance: the release is driven by the status signal, not
        // by the 90 s slot cap.
        let token3 = CancellationToken::new();
        assert!(
            gate.acquire(&token3).await.is_some(),
            "the started signal released the slot"
        );
        holder.await.expect("holder task joins");
    }

    #[tokio::test(start_paused = true)]
    async fn the_slot_is_released_at_the_ninety_second_cap() {
        // One slot: the watcher can only acquire after the cap released it.
        let gate = StartGate::with_slots(1);
        let token = CancellationToken::new();
        let slot = gate.acquire(&token).await.expect("slot");
        // The sender stays alive and never sends: only the cap can release.
        let (_started_tx, started_rx) = tokio::sync::oneshot::channel();
        let token2 = CancellationToken::new();
        let holder = tokio::spawn(slot.hold_until_started(started_rx, token2));

        let (done_tx, mut done_rx) = tokio::sync::oneshot::channel();
        let token3 = CancellationToken::new();
        let watcher_gate = gate.clone();
        let watcher = tokio::spawn(async move {
            let slot = watcher_gate.acquire(&token3).await;
            let _ = done_tx.send(slot.is_some()); // the receiver is always alive
        });

        tokio::time::advance(START_SLOT_TIMEOUT - Duration::from_secs(1)).await;
        assert!(
            done_rx.try_recv().is_err(),
            "one second before the cap the slot is still held"
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(
            done_rx.await.expect("the watcher reports"),
            "the 90 s cap released the slot"
        );
        holder.await.expect("holder task joins");
        watcher.await.expect("watcher task joins");
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_releases_the_slot() {
        // One slot: the next acquire succeeds only if shutdown released it.
        let gate = StartGate::with_slots(1);
        let token = CancellationToken::new();
        let slot = gate.acquire(&token).await.expect("slot");
        let (_never_tx, started_rx) = tokio::sync::oneshot::channel(); // never sent
        let holder = tokio::spawn(slot.hold_until_started(started_rx, token.clone()));

        token.cancel();
        let token3 = CancellationToken::new();
        assert!(
            gate.acquire(&token3).await.is_some(),
            "shutdown released the slot"
        );
        holder.await.expect("holder task joins");
    }

    #[tokio::test(start_paused = true)]
    async fn a_cancelled_waiter_never_holds_a_slot() {
        let gate = StartGate::new();
        let token = CancellationToken::new();
        let one = gate.acquire(&token).await.expect("slot 1");
        let two = gate.acquire(&token).await.expect("slot 2");
        let three = gate.acquire(&token).await.expect("slot 3");
        let four = gate.acquire(&token).await.expect("slot 4");
        assert_eq!(gate.available_permits(), 0);

        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let waiter_token = CancellationToken::new();
        let waiter_gate = gate.clone();
        let waiter = tokio::spawn({
            let waiter_token = waiter_token.clone();
            async move {
                let slot = waiter_gate.acquire(&waiter_token).await;
                let _ = done_tx.send(slot.is_none()); // the receiver is always alive
            }
        });

        waiter_token.cancel();
        assert!(
            done_rx.await.expect("the waiter reports"),
            "the cancelled waiter got no slot"
        );
        assert_eq!(
            gate.available_permits(),
            0,
            "the cancelled waiter consumed no permit"
        );
        drop(one);
        assert_eq!(
            gate.available_permits(),
            1,
            "the freed permit is available, not bound to the cancelled waiter"
        );
        waiter.await.expect("waiter task joins");
        drop((two, three, four));
    }

    #[tokio::test(start_paused = true)]
    async fn in_use_counts_the_held_slots() {
        let gate = StartGate::new();
        assert_eq!(gate.in_use(), 0);
        let token = CancellationToken::new();
        let one = gate.acquire(&token).await.expect("slot 1");
        let two = gate.acquire(&token).await.expect("slot 2");
        assert_eq!(gate.in_use(), 2);
        drop(one);
        assert_eq!(gate.in_use(), 1);
        drop(two);
        assert_eq!(gate.in_use(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_terminal_status_is_reported_as_the_release_reason_with_the_hold_time() {
        let gate = StartGate::with_slots(1);
        let token = CancellationToken::new();
        let slot = gate.acquire(&token).await.expect("slot");
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let holder = tokio::spawn(slot.hold_until_started(started_rx, token.clone()));

        tokio::time::advance(Duration::from_secs(7)).await;
        started_tx.send(()).expect("the holder still listens");
        let (reason, held) = holder.await.expect("holder task joins");
        assert_eq!(reason, SlotRelease::Status);
        assert_eq!(held, Duration::from_secs(7));
    }

    #[tokio::test(start_paused = true)]
    async fn the_cap_is_reported_as_the_release_reason_with_the_full_hold() {
        let gate = StartGate::with_slots(1);
        let token = CancellationToken::new();
        let slot = gate.acquire(&token).await.expect("slot");
        let (_never_tx, started_rx) = tokio::sync::oneshot::channel::<()>(); // never sent
        let holder = tokio::spawn(slot.hold_until_started(started_rx, token.clone()));

        let (reason, held) = holder.await.expect("holder task joins");
        assert_eq!(reason, SlotRelease::Cap);
        assert_eq!(held, START_SLOT_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_is_reported_as_the_release_reason() {
        let gate = StartGate::with_slots(1);
        let token = CancellationToken::new();
        let slot = gate.acquire(&token).await.expect("slot");
        let (_never_tx, started_rx) = tokio::sync::oneshot::channel::<()>(); // never sent
        let holder = tokio::spawn(slot.hold_until_started(started_rx, token.clone()));

        token.cancel();
        let (reason, _held) = holder.await.expect("holder task joins");
        assert_eq!(reason, SlotRelease::Shutdown);
        assert_eq!(SlotRelease::Shutdown.as_str(), "shutdown");
        assert_eq!(SlotRelease::Status.as_str(), "status");
        assert_eq!(SlotRelease::Cap.as_str(), "cap");
    }
}
