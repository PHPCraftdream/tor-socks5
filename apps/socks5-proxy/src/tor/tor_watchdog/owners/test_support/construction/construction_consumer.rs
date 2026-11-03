use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::time::{timeout_at, Instant};

use super::construction_export::{Acknowledgement, Envelope, Evidence, ExportSnapshot};
use super::construction_wire::{
    Client, Context, Error as WireError, Frame, Operation, Receipt, State,
};
use super::{SelectionEvent, SelectionProbe};

const CAPACITY: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Wire(WireError),
    Deadline,
    ReceiverClosed,
    Lifecycle,
    ReceiptMismatch,
    ProducerGone,
    ProducerIncomplete,
}

#[derive(Clone, Debug)]
pub(crate) struct Delivery {
    pub(crate) evidence: Evidence,
    pub(crate) receipt: Option<Receipt>,
    pub(crate) producer_ack_sent: bool,
    pub(crate) failure: Option<Error>,
}

#[derive(Clone, Debug)]
pub(crate) struct Terminal {
    pub(crate) journal_count: usize,
    pub(crate) dropped: usize,
    pub(crate) snapshot: ExportSnapshot,
    pub(crate) local_finish_ok: bool,
    pub(crate) wire_receipt: Option<Receipt>,
    pub(crate) successful: bool,
}

pub(crate) struct Consumer {
    probe: Arc<SelectionProbe>,
    receiver: mpsc::Receiver<Envelope>,
    context: Context,
    registry: u64,
    deadline: Instant,
    opened: bool,
    stopped: bool,
    pending: Option<Envelope>,
    deliveries: Vec<Delivery>,
    failure: Option<Error>,
    terminal: Option<Terminal>,
}

impl Consumer {
    pub(crate) fn install(
        probe: Arc<SelectionProbe>,
        registry: u64,
        phase: u8,
        deadline: Instant,
    ) -> anyhow::Result<Self> {
        let context = Context::new(registry, phase)
            .map_err(|_| anyhow::anyhow!("invalid construction consumer context"))?;
        let receiver = probe.install_construction_export(deadline)?;
        Ok(Self {
            probe,
            receiver,
            context,
            registry,
            deadline,
            opened: false,
            stopped: false,
            pending: None,
            deliveries: Vec::new(),
            failure: None,
            terminal: None,
        })
    }

    pub(crate) fn failure(&self) -> Option<&Error> {
        self.failure.as_ref()
    }

    pub(crate) fn deliveries(&self) -> &[Delivery] {
        &self.deliveries
    }

    pub(crate) fn terminal(&self) -> Option<&Terminal> {
        self.terminal.as_ref()
    }

    pub(super) fn append_failure_projection(&self, output: &mut String, record: usize) {
        use std::fmt::Write as _;

        let _ = writeln!(
            output,
            "consumer record={} registry={} opened={} stopped={} pending_envelope={} delivery_count={} failed={} terminal_present={}",
            record,
            self.registry,
            self.opened,
            self.stopped,
            self.pending.is_some(),
            self.deliveries.len(),
            self.failure.is_some(),
            self.terminal.is_some(),
        );
        for delivery in self.deliveries.iter().take(CAPACITY) {
            let evidence = &delivery.evidence;
            let operation =
                delivery
                    .receipt
                    .as_ref()
                    .map_or("absent", |receipt| match receipt.operation {
                        Operation::Open => "open",
                        Operation::Reserved => "reserved",
                        Operation::Assigned => "assigned",
                        Operation::Global => "global",
                        Operation::Failed => "failed",
                        Operation::End => "end",
                        Operation::Finish => "finish",
                    });
            let _ = writeln!(
                output,
                "delivery record={} request={} journal={} identity={:?} slot={:?} receipt_present={} receipt_registry={:?} receipt_transaction={:?} receipt_journal={:?} receipt_operation={} producer_ack_sent_local={} failed={}",
                record,
                evidence.request_id,
                evidence.journal_sequence,
                evidence.identity,
                evidence.storage.as_ref().map(|storage| storage.slot),
                delivery.receipt.is_some(),
                delivery.receipt.as_ref().map(|receipt| receipt.registry),
                delivery.receipt.as_ref().map(|receipt| receipt.transaction),
                delivery.receipt.as_ref().map(|receipt| receipt.journal_sequence),
                operation,
                delivery.producer_ack_sent,
                delivery.failure.is_some(),
            );
        }
    }

    fn fail(&mut self, error: Error) -> Error {
        self.failure.get_or_insert(error.clone());
        error
    }

    fn receipt_matches(&self, receipt: &Receipt, operation: Operation, sequence: usize) -> bool {
        receipt.registry == self.registry
            && receipt.operation == operation
            && receipt.journal_sequence == sequence
            && receipt.transaction > 0
    }

    /// cancel-safe: NO — Client retains InFlight after an interrupted wire transaction.
    /// The caller must retain both objects and explicitly resolve pending producers.
    pub(crate) async fn open(&mut self, client: &mut Client) -> Result<(), Error> {
        if self.opened || self.stopped || self.failure.is_some() {
            return Err(self.fail(Error::Lifecycle));
        }
        let frame = self.context.open().map_err(Error::Wire)?;
        let receipt = match timeout_at(self.deadline, client.send(&frame)).await {
            Err(_) => return Err(self.fail(Error::Deadline)),
            Ok(Err(error)) => return Err(self.fail(Error::Wire(error))),
            Ok(Ok(receipt)) => receipt,
        };
        if !self.receipt_matches(&receipt, Operation::Open, 0) {
            return Err(self.fail(Error::ReceiptMismatch));
        }
        self.opened = true;
        Ok(())
    }

    /// Poll only readiness; the caller supplies its existing absolute deadline.
    /// A ready envelope stays owned here until delivery or explicit rejection.
    pub(crate) fn poll_receive(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Error>> {
        if !self.opened
            || self.stopped
            || self.failure.is_some()
            || self.pending.is_some()
            || self.deliveries.len() >= CAPACITY
        {
            return std::task::Poll::Ready(Err(self.fail(Error::Lifecycle)));
        }
        let envelope = match self.receiver.poll_recv(cx) {
            std::task::Poll::Pending => return std::task::Poll::Pending,
            std::task::Poll::Ready(None) => {
                return std::task::Poll::Ready(Err(self.fail(Error::ReceiverClosed)));
            }
            std::task::Poll::Ready(Some(envelope)) => envelope,
        };
        let evidence = envelope.evidence.clone();
        self.pending = Some(envelope);
        self.deliveries.push(Delivery {
            evidence,
            receipt: None,
            producer_ack_sent: false,
            failure: None,
        });
        std::task::Poll::Ready(Ok(()))
    }

    pub(crate) fn has_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// cancel-safe: NO after receipt of an Envelope.
    /// The Envelope and its sender remain in self.pending across cancellation.
    /// Never retry an interrupted Client transaction; reject and settle instead.
    pub(crate) async fn next(&mut self, client: &mut Client) -> Result<Receipt, Error> {
        match timeout_at(
            self.deadline,
            std::future::poll_fn(|cx| self.poll_receive(cx)),
        )
        .await
        {
            Err(_) => return Err(self.fail(Error::Deadline)),
            Ok(result) => result?,
        }
        self.deliver(client).await
    }

    /// cancel-safe: NO — retain this consumer and the Client after interruption.
    pub(crate) async fn deliver(&mut self, client: &mut Client) -> Result<Receipt, Error> {
        if !self.opened || self.stopped || self.failure.is_some() || self.pending.is_none() {
            return Err(self.fail(Error::Lifecycle));
        }
        let evidence = self.pending.as_ref().unwrap().evidence.clone();
        let frame = match self.context.event(&evidence) {
            Ok(frame) => frame,
            Err(error) => {
                let error = self.fail(Error::Wire(error));
                self.deliveries.last_mut().unwrap().failure = Some(error.clone());
                return Err(error);
            }
        };
        let result = timeout_at(self.deadline, client.send(&frame)).await;
        let receipt = match result {
            Err(_) => {
                let error = self.fail(Error::Deadline);
                self.deliveries.last_mut().unwrap().failure = Some(error.clone());
                return Err(error);
            }
            Ok(Err(error)) => {
                let error = self.fail(Error::Wire(error));
                self.deliveries.last_mut().unwrap().failure = Some(error.clone());
                return Err(error);
            }
            Ok(Ok(receipt)) => receipt,
        };
        let operation = match evidence.event {
            SelectionEvent::Reserved => Operation::Reserved,
            SelectionEvent::StorageAssigned => Operation::Assigned,
            SelectionEvent::Global => Operation::Global,
            SelectionEvent::ReserveFailed => Operation::Failed,
        };
        if !self.receipt_matches(&receipt, operation, evidence.journal_sequence) {
            let error = self.fail(Error::ReceiptMismatch);
            self.deliveries.last_mut().unwrap().failure = Some(error.clone());
            return Err(error);
        }
        self.deliveries.last_mut().unwrap().receipt = Some(receipt.clone());
        let envelope = self.pending.take().unwrap();
        if envelope
            .acknowledgement
            .send(Acknowledgement {
                journal_sequence: evidence.journal_sequence,
                accepted: true,
            })
            .is_err()
        {
            let error = self.fail(Error::ProducerGone);
            self.deliveries.last_mut().unwrap().failure = Some(error.clone());
            return Err(error);
        }
        self.deliveries.last_mut().unwrap().producer_ack_sent = true;
        Ok(receipt)
    }

    /// Synchronous rejection resolves the retained sender without claiming delivery success.
    pub(crate) fn reject_pending(&mut self) {
        if let Some(envelope) = self.pending.take() {
            let sequence = envelope.evidence.journal_sequence;
            let sent = envelope
                .acknowledgement
                .send(Acknowledgement {
                    journal_sequence: sequence,
                    accepted: false,
                })
                .is_ok();
            let error = if sent {
                Error::ProducerIncomplete
            } else {
                Error::ProducerGone
            };
            self.fail(error.clone());
            if let Some(delivery) = self.deliveries.last_mut() {
                delivery.failure.get_or_insert(error);
            }
        }
    }

    /// Stop new delivery, then reject already buffered producers.
    /// The caller must first stop/join producers before treating this as a stable drain.
    pub(crate) fn reject_buffered(&mut self) {
        self.stopped = true;
        self.receiver.close();
        self.reject_pending();
        while let Ok(envelope) = self.receiver.try_recv() {
            let sequence = envelope.evidence.journal_sequence;
            let sent = envelope
                .acknowledgement
                .send(Acknowledgement {
                    journal_sequence: sequence,
                    accepted: false,
                })
                .is_ok();
            self.fail(if sent {
                Error::ProducerIncomplete
            } else {
                Error::ProducerGone
            });
        }
    }

    /// cancel-safe: NO during END transmission; the Client remains unusable if interrupted.
    /// Call only after producers and registry shutdown are joined, with no future publication.
    /// The resulting actual snapshot is retained before any wire await.
    pub(crate) async fn finish(&mut self, client: &mut Client) -> Result<(), Error> {
        if self.terminal.is_some() {
            return Err(self.fail(Error::Lifecycle));
        }
        self.reject_buffered();

        let local_finish_ok = self.probe.finish_construction_export().is_ok();
        let (journal, dropped) = self.probe.snapshot();
        let snapshot = self.probe.construction_export_snapshot();
        let progress_ok = snapshot
            .progress
            .iter()
            .all(|item| item.queued && item.acknowledged && item.failure.is_none());
        let local_ok = local_finish_ok
            && snapshot.installed
            && snapshot.closed
            && snapshot.failure.is_none()
            && dropped == 0
            && journal.len() == snapshot.progress.len()
            && self.deliveries.len() == journal.len()
            && self.deliveries.iter().all(|delivery| {
                delivery.producer_ack_sent
                    && delivery.receipt.is_some()
                    && delivery.failure.is_none()
            })
            && progress_ok
            && self.failure.is_none();

        let frame = self.context.end(&snapshot, journal.len(), dropped);
        self.terminal = Some(Terminal {
            journal_count: journal.len(),
            dropped,
            snapshot,
            local_finish_ok,
            wire_receipt: None,
            successful: false,
        });

        if !self.opened || client.state() != State::Ready {
            return Err(self.fail(Error::ProducerIncomplete));
        }
        let frame = match frame {
            Ok(frame) => frame,
            Err(error) => return Err(self.fail(Error::Wire(error))),
        };
        let receipt = match timeout_at(self.deadline, client.send(&frame)).await {
            Err(_) => return Err(self.fail(Error::Deadline)),
            Ok(Err(error)) => return Err(self.fail(Error::Wire(error))),
            Ok(Ok(receipt)) => receipt,
        };
        if !self.receipt_matches(&receipt, Operation::End, 0) {
            return Err(self.fail(Error::ReceiptMismatch));
        }
        self.terminal.as_mut().unwrap().wire_receipt = Some(receipt);
        if !local_ok {
            return Err(self.fail(Error::ProducerIncomplete));
        }
        self.terminal.as_mut().unwrap().successful = true;
        Ok(())
    }
}

/// cancel-safe: NO — cancellation retains Client::InFlight.
/// The caller invokes this only after all Consumer terminal receipts were obtained.
/// A wire FINISH receipt does not override any Consumer's retained failure.
pub(crate) async fn finish_stream(
    client: &mut Client,
    deadline: Instant,
) -> Result<Receipt, Error> {
    let frame = Frame::finish().map_err(Error::Wire)?;
    let receipt = timeout_at(deadline, client.send(&frame))
        .await
        .map_err(|_| Error::Deadline)?
        .map_err(Error::Wire)?;
    if receipt.registry != 0
        || receipt.operation != Operation::Finish
        || receipt.journal_sequence != 0
        || receipt.transaction == 0
    {
        return Err(Error::ReceiptMismatch);
    }
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    include!("tests/construction_consumer_tests.rs");
}
