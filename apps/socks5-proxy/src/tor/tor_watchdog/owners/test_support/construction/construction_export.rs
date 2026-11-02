use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{anyhow, bail, Result};
use arti_wrapper::{Settings, TorTunnel};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

use super::{
    Entry, OwnerRegistry, SelectionEvent, SelectionObservation, SelectionOutcome, SelectionProbe,
    OBSERVATION_CAP, SELECTION_OBS,
};

const PATH_LIMIT: usize = 2048;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StorageEvidence {
    pub(crate) base: PathBuf,
    pub(crate) allocated: PathBuf,
    pub(crate) slot: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Evidence {
    pub(crate) journal_sequence: usize,
    pub(crate) request_id: usize,
    pub(crate) identity: Option<usize>,
    pub(crate) event: SelectionEvent,
    pub(crate) outcome: SelectionOutcome,
    pub(crate) explicit_disabled: bool,
    pub(crate) effective_none: Option<bool>,
    pub(crate) storage: Option<StorageEvidence>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Acknowledgement {
    pub(crate) journal_sequence: usize,
    pub(crate) accepted: bool,
}

pub(crate) struct Envelope {
    pub(crate) evidence: Evidence,
    pub(crate) acknowledgement: oneshot::Sender<Acknowledgement>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Progress {
    pub(crate) evidence: Evidence,
    pub(crate) queued: bool,
    pub(crate) acknowledged: bool,
    pub(crate) failure: Option<&'static str>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ExportSnapshot {
    pub(crate) installed: bool,
    pub(crate) closed: bool,
    pub(crate) failure: Option<&'static str>,
    pub(crate) creation_attempts: usize,
    pub(crate) progress: Vec<Progress>,
}

struct Session {
    deadline: Instant,
    sender: Option<mpsc::Sender<Envelope>>,
    closed: bool,
    failure: Option<&'static str>,
    creation_attempts: usize,
    progress: Vec<Progress>,
}

#[derive(Default)]
pub(super) struct Export {
    session: Mutex<Option<Session>>,
}

struct Ticket {
    sequence: usize,
    deadline: Instant,
    response: oneshot::Receiver<Acknowledgement>,
}

struct Awaiting<'a> {
    export: &'a Export,
    sequence: usize,
    armed: bool,
}

impl Drop for Awaiting<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.export.record_failure(
                self.sequence,
                "construction export acknowledgement cancelled",
            );
        }
    }
}

fn fail(session: &mut Session, reason: &'static str) -> anyhow::Error {
    session.failure.get_or_insert(reason);
    anyhow!(reason)
}

fn path_valid(path: &Path) -> bool {
    let bytes = path.as_os_str().as_encoded_bytes();
    path.is_absolute() && !bytes.is_empty() && bytes.len() <= PATH_LIMIT && !bytes.contains(&0)
}

fn validate(session: &Session, evidence: &Evidence) -> Result<()> {
    if evidence.journal_sequence != session.progress.len() + 1 {
        bail!("construction export journal sequence gap");
    }
    if evidence.explicit_disabled
        && evidence.effective_none == Some(false)
        && evidence.outcome != SelectionOutcome::ReserveFailed
    {
        bail!("construction export Disabled selection contradiction");
    }
    match evidence.event {
        SelectionEvent::Reserved | SelectionEvent::Global => {
            let reserved = evidence.event == SelectionEvent::Reserved;
            let expected = if reserved {
                SelectionOutcome::Reserved
            } else {
                SelectionOutcome::Global
            };
            if evidence.outcome != expected
                || evidence.identity.is_some() != reserved
                || evidence.effective_none.is_none()
                || evidence.storage.is_some()
            {
                bail!("construction export invalid reservation");
            }
        }
        SelectionEvent::ReserveFailed => {
            if evidence.outcome != SelectionOutcome::ReserveFailed
                || evidence.identity.is_some()
                || evidence.effective_none.is_some()
                || evidence.storage.is_some()
            {
                bail!("construction export invalid failed reservation");
            }
        }
        SelectionEvent::StorageAssigned => {
            let storage = evidence
                .storage
                .as_ref()
                .ok_or_else(|| anyhow!("construction export missing storage"))?;
            if evidence.outcome != SelectionOutcome::Reserved
                || evidence.identity.is_none()
                || evidence.effective_none.is_none()
                || !(1..=15).contains(&storage.slot)
                || !path_valid(&storage.base)
                || !path_valid(&storage.allocated)
                || storage.allocated
                    != storage
                        .base
                        .join("owners-v1")
                        .join(storage.slot.to_string())
            {
                bail!("construction export invalid storage");
            }
            let reserved = session
                .progress
                .iter()
                .find(|progress| {
                    progress.evidence.event == SelectionEvent::Reserved
                        && progress.evidence.request_id == evidence.request_id
                })
                .ok_or_else(|| anyhow!("construction export missing reservation"))?;
            if !reserved.acknowledged
                || reserved.evidence.identity != evidence.identity
                || reserved.evidence.explicit_disabled != evidence.explicit_disabled
                || reserved.evidence.effective_none != evidence.effective_none
            {
                bail!("construction export reservation mismatch");
            }
            if session.progress.iter().any(|progress| {
                progress.evidence.event == SelectionEvent::StorageAssigned
                    && (progress.evidence.identity == evidence.identity
                        || progress
                            .evidence
                            .storage
                            .as_ref()
                            .is_some_and(|old| old.allocated == storage.allocated))
            }) {
                bail!("construction export duplicate storage assignment");
            }
        }
    }
    if evidence.event != SelectionEvent::StorageAssigned
        && session.progress.iter().any(|progress| {
            progress.evidence.event != SelectionEvent::StorageAssigned
                && progress.evidence.request_id == evidence.request_id
        })
    {
        bail!("construction export duplicate request");
    }
    Ok(())
}

impl Export {
    fn install(&self, deadline: Instant) -> Result<mpsc::Receiver<Envelope>> {
        let mut slot = self.session.lock().unwrap();
        if slot.is_some() || Instant::now() >= deadline {
            bail!("construction export installation rejected");
        }
        let (sender, receiver) = mpsc::channel(OBSERVATION_CAP);
        *slot = Some(Session {
            deadline,
            sender: Some(sender),
            closed: false,
            failure: None,
            creation_attempts: 0,
            progress: Vec::new(),
        });
        Ok(receiver)
    }

    fn enqueue(
        &self,
        sequence: Option<usize>,
        dropped: usize,
        observation: SelectionObservation,
        explicit_disabled: bool,
        effective_none: Option<bool>,
        storage: Option<StorageEvidence>,
        constructor_deadline: Option<Instant>,
    ) -> Result<Option<Ticket>> {
        let mut slot = self.session.lock().unwrap();
        let Some(session) = slot.as_mut() else {
            return Ok(None);
        };
        if session.closed || session.failure.is_some() {
            return Err(fail(session, "construction export unavailable"));
        }
        let deadline =
            constructor_deadline.map_or(session.deadline, |limit| limit.min(session.deadline));
        if Instant::now() >= deadline {
            return Err(fail(session, "construction export deadline"));
        }
        let Some(sequence) = sequence else {
            return Err(fail(session, "construction export journal dropped"));
        };
        if dropped != 0 || session.progress.len() >= OBSERVATION_CAP {
            return Err(fail(session, "construction export journal dropped"));
        }
        let evidence = Evidence {
            journal_sequence: sequence,
            request_id: observation.request_id,
            identity: observation.identity,
            event: observation.event,
            outcome: observation.outcome,
            explicit_disabled,
            effective_none,
            storage,
        };
        if validate(session, &evidence).is_err() {
            return Err(fail(session, "construction export invalid evidence"));
        }
        let (acknowledgement, response) = oneshot::channel();
        session.progress.push(Progress {
            evidence: evidence.clone(),
            queued: false,
            acknowledged: false,
            failure: None,
        });
        let sent = session.sender.as_ref().is_some_and(|sender| {
            sender
                .try_send(Envelope {
                    evidence,
                    acknowledgement,
                })
                .is_ok()
        });
        let progress = session.progress.last_mut().unwrap();
        if !sent {
            progress.failure = Some("construction export delivery failed");
            return Err(fail(session, "construction export delivery failed"));
        }
        progress.queued = true;
        Ok(Some(Ticket {
            sequence,
            deadline,
            response,
        }))
    }

    fn record_failure(&self, sequence: usize, reason: &'static str) {
        let mut slot = self.session.lock().unwrap();
        if let Some(session) = slot.as_mut() {
            session.failure.get_or_insert(reason);
            if let Some(progress) = session
                .progress
                .iter_mut()
                .find(|progress| progress.evidence.journal_sequence == sequence)
            {
                progress.failure.get_or_insert(reason);
            }
        }
    }

    async fn acknowledge(&self, ticket: Ticket) -> Result<()> {
        let mut awaiting = Awaiting {
            export: self,
            sequence: ticket.sequence,
            armed: true,
        };
        let response = tokio::time::timeout_at(ticket.deadline, ticket.response).await;
        let reason = match response {
            Err(_) => Some("construction export acknowledgement deadline"),
            Ok(Err(_)) => Some("construction export acknowledgement lost"),
            Ok(Ok(ack)) if ack.journal_sequence != ticket.sequence => {
                Some("construction export acknowledgement mismatch")
            }
            Ok(Ok(ack)) if !ack.accepted => Some("construction export acknowledgement rejected"),
            Ok(Ok(_)) if Instant::now() >= ticket.deadline => {
                Some("construction export acknowledgement deadline")
            }
            Ok(Ok(_)) => None,
        };
        if let Some(reason) = reason {
            self.record_failure(ticket.sequence, reason);
            awaiting.armed = false;
            bail!(reason);
        }
        {
            let mut slot = self.session.lock().unwrap();
            let session = slot
                .as_mut()
                .ok_or_else(|| anyhow!("construction export session missing"))?;
            if session.closed || session.failure.is_some() {
                let reason = "construction export unavailable";
                if let Some(progress) = session
                    .progress
                    .iter_mut()
                    .find(|progress| progress.evidence.journal_sequence == ticket.sequence)
                {
                    progress.failure.get_or_insert(reason);
                }
                awaiting.armed = false;
                return Err(fail(session, reason));
            }
            let progress = session
                .progress
                .iter_mut()
                .find(|progress| progress.evidence.journal_sequence == ticket.sequence)
                .ok_or_else(|| anyhow!("construction export progress missing"))?;
            progress.acknowledged = true;
        }
        awaiting.armed = false;
        Ok(())
    }

    pub(super) fn require_observed_construction(&self) -> Result<()> {
        let mut slot = self.session.lock().unwrap();
        if let Some(session) = slot.as_mut() {
            return Err(fail(
                session,
                "construction export admission evidence missing",
            ));
        }
        Ok(())
    }

    fn snapshot(&self) -> ExportSnapshot {
        let slot = self.session.lock().unwrap();
        match slot.as_ref() {
            None => ExportSnapshot::default(),
            Some(session) => ExportSnapshot {
                installed: true,
                closed: session.closed,
                failure: session.failure,
                creation_attempts: session.creation_attempts,
                progress: session.progress.clone(),
            },
        }
    }

    fn finish(&self, journal_len: usize, dropped: usize) -> Result<()> {
        let mut slot = self.session.lock().unwrap();
        let Some(session) = slot.as_mut() else {
            bail!("construction export not installed");
        };
        session.closed = true;
        session.sender.take();
        if session.failure.is_some()
            || dropped != 0
            || journal_len != session.progress.len()
            || session
                .progress
                .iter()
                .any(|progress| !progress.queued || !progress.acknowledged)
        {
            return Err(fail(session, "construction export incomplete"));
        }
        Ok(())
    }

    fn creation_attempt(&self) {
        let mut slot = self.session.lock().unwrap();
        if let Some(session) = slot.as_mut() {
            session.creation_attempts += 1;
        }
    }
}

pub(super) fn create_tunnel(probe: &SelectionProbe, settings: Settings) -> Result<TorTunnel> {
    probe.construction_export.creation_attempt();
    TorTunnel::create_unbootstrapped_with(settings)
        .map_err(|_| anyhow!("не удалось создать Tor владельца"))
}

impl SelectionProbe {
    pub(crate) fn install_construction_export(
        &self,
        deadline: Instant,
    ) -> Result<mpsc::Receiver<Envelope>> {
        let log = self.observations.lock().unwrap();
        if !log.0.is_empty() || log.1 != 0 {
            bail!("construction export must precede journal publication");
        }
        self.construction_export.install(deadline)
    }

    pub(crate) fn construction_export_snapshot(&self) -> ExportSnapshot {
        self.construction_export.snapshot()
    }

    pub(crate) fn finish_construction_export(&self) -> Result<()> {
        let log = self.observations.lock().unwrap();
        self.construction_export.finish(log.0.len(), log.1)
    }

    /// cancel-safe: NO — cancellation preserves the journal and marks the queued frame failed.
    pub(super) async fn publish_construction(
        &self,
        observation: SelectionObservation,
        explicit_disabled: bool,
        effective_none: Option<bool>,
        storage: Option<StorageEvidence>,
        constructor_deadline: Option<Instant>,
    ) -> Result<()> {
        let ticket = {
            let mut log = self.observations.lock().unwrap();
            let (items, dropped) = &mut *log;
            let sequence = if items.len() < OBSERVATION_CAP {
                items.push(observation.clone());
                Some(items.len())
            } else {
                *dropped += 1;
                None
            };
            let _ = self.events_tx.send(items.len());
            self.construction_export.enqueue(
                sequence,
                *dropped,
                observation,
                explicit_disabled,
                effective_none,
                storage,
                constructor_deadline,
            )?
        };
        if let Some(ticket) = ticket {
            self.construction_export.acknowledge(ticket).await?;
        }
        Ok(())
    }

    pub(super) async fn export_storage(
        &self,
        request_id: usize,
        route: String,
        explicit_disabled: bool,
        identity: usize,
        base: &Path,
        allocated: &Path,
        slot: usize,
        effective_none: bool,
        deadline: Instant,
    ) -> Result<()> {
        self.publish_construction(
            SelectionObservation {
                request_id,
                route,
                identity: Some(identity),
                storage_slot: Some(slot),
                outcome: SelectionOutcome::Reserved,
                event: SelectionEvent::StorageAssigned,
            },
            explicit_disabled,
            Some(effective_none),
            Some(StorageEvidence {
                base: base.to_path_buf(),
                allocated: allocated.to_path_buf(),
                slot,
            }),
            Some(deadline),
        )
        .await
    }
}

impl OwnerRegistry {
    // After the journal publication, cancellation fails the export without undoing reserve.
    pub(super) async fn export_reserve_outcome(
        &self,
        result: &Result<Option<std::sync::Arc<Entry>>>,
    ) -> Result<()> {
        let selection = SELECTION_OBS.try_with(|obs| obs.clone()).ok().flatten();
        let Some((request_id, route, explicit_disabled)) = selection else {
            return Ok(());
        };
        let (identity, outcome, effective_none) = match result {
            Ok(None) => (
                None,
                SelectionOutcome::Global,
                Some(self.global_pre.is_none()),
            ),
            Ok(Some(entry)) => (
                Some(std::sync::Arc::as_ptr(entry) as usize),
                SelectionOutcome::Reserved,
                Some(entry.pre.is_none()),
            ),
            Err(_) => (None, SelectionOutcome::ReserveFailed, None),
        };
        #[cfg(target_os = "linux")]
        if let Ok(Some(entry)) = result {
            super::construction_driver::retain_entry(&self.selection_probe, entry)?;
        }
        self.selection_probe
            .publish_construction(
                SelectionObservation {
                    request_id,
                    route,
                    identity,
                    storage_slot: None,
                    outcome,
                    event: match outcome {
                        SelectionOutcome::Reserved => SelectionEvent::Reserved,
                        SelectionOutcome::ReserveFailed => SelectionEvent::ReserveFailed,
                        SelectionOutcome::Global => SelectionEvent::Global,
                    },
                },
                explicit_disabled,
                effective_none,
                None,
                None,
            )
            .await?;
        #[cfg(target_os = "linux")]
        super::handler_tests::carrier_oracle::reserved(request_id, identity, result.is_ok());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    include!("tests/construction_export_tests.rs");
}
