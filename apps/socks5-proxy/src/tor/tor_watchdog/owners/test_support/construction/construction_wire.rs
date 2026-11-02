use std::collections::BTreeMap;
use std::path::Path;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout_at, Instant};

use super::construction_export::{Evidence, ExportSnapshot};
use super::{SelectionEvent, SelectionOutcome};

const HEADER_SIZE: usize = 49;
const STATUS_SIZE: usize = 28;
const PROGRESS_SIZE: usize = 11;
const MAX_PATH: usize = 2048;
const MAX_EVENTS: usize = 64;
const MAX_REGISTRIES: usize = 16;
const MAX_CHUNK: usize = 48;
const MAX_LINE: usize = 128;
const MAX_BODY: usize = HEADER_SIZE + 2 * MAX_PATH + STATUS_SIZE + MAX_EVENTS * PROGRESS_SIZE;
const MAX_TRANSACTIONS: usize = MAX_REGISTRIES * (MAX_EVENTS + 2) + 1;

const FAILURES: [Option<&str>; 13] = [
    None,
    Some("construction export acknowledgement cancelled"),
    Some("construction export unavailable"),
    Some("construction export deadline"),
    Some("construction export journal dropped"),
    Some("construction export invalid evidence"),
    Some("construction export delivery failed"),
    Some("construction export acknowledgement deadline"),
    Some("construction export acknowledgement lost"),
    Some("construction export acknowledgement mismatch"),
    Some("construction export acknowledgement rejected"),
    Some("construction export admission evidence missing"),
    Some("construction export incomplete"),
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Invalid(&'static str),
    Deadline,
    Io(std::io::ErrorKind),
    Eof,
    ReplyBound,
    WrongReply,
    Denied(String),
    Unusable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Operation {
    Open,
    Reserved,
    Assigned,
    Global,
    Failed,
    End,
    Finish,
}

impl Operation {
    fn byte(self) -> u8 {
        match self {
            Self::Open => b'O',
            Self::Reserved => b'R',
            Self::Assigned => b'S',
            Self::Global => b'G',
            Self::Failed => b'F',
            Self::End => b'X',
            Self::Finish => b'Z',
        }
    }

    fn event(self) -> bool {
        matches!(
            self,
            Self::Reserved | Self::Assigned | Self::Global | Self::Failed
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Context {
    registry: u64,
    phase: u8,
}

impl Context {
    pub(crate) fn new(registry: u64, phase: u8) -> Result<Self, Error> {
        if registry == 0 || phase > 1 {
            return Err(Error::Invalid("registry context"));
        }
        Ok(Self { registry, phase })
    }

    pub(crate) fn open(self) -> Result<Frame, Error> {
        Frame::build(self, Operation::Open, Source::Context, None)
    }

    pub(crate) fn event(self, evidence: &Evidence) -> Result<Frame, Error> {
        validate_evidence(evidence)?;
        let operation = match evidence.event {
            SelectionEvent::Reserved => Operation::Reserved,
            SelectionEvent::StorageAssigned => Operation::Assigned,
            SelectionEvent::Global => Operation::Global,
            SelectionEvent::ReserveFailed => Operation::Failed,
        };
        Frame::build(
            self,
            operation,
            Source::Event(evidence.clone()),
            Some(evidence),
        )
    }

    pub(crate) fn end(
        self,
        snapshot: &ExportSnapshot,
        journal_count: usize,
        dropped: usize,
    ) -> Result<Frame, Error> {
        if journal_count > MAX_EVENTS || snapshot.progress.len() > MAX_EVENTS {
            return Err(Error::Invalid("terminal count bound"));
        }
        let mut frame = Frame::build(
            self,
            Operation::End,
            Source::Terminal {
                snapshot: snapshot.clone(),
                journal_count,
                dropped,
            },
            None,
        )?;
        frame.bytes.extend_from_slice(&[
            u8::from(snapshot.installed),
            u8::from(snapshot.closed),
            failure_code(snapshot.failure)?,
        ]);
        put_usize(&mut frame.bytes, journal_count)?;
        put_usize(&mut frame.bytes, dropped)?;
        put_usize(&mut frame.bytes, snapshot.creation_attempts)?;
        frame.bytes.push(
            u8::try_from(snapshot.progress.len()).map_err(|_| Error::Invalid("progress count"))?,
        );
        for progress in &snapshot.progress {
            put_usize(&mut frame.bytes, progress.evidence.journal_sequence)?;
            frame.bytes.extend_from_slice(&[
                u8::from(progress.queued),
                u8::from(progress.acknowledged),
                failure_code(progress.failure)?,
            ]);
        }
        if frame.bytes.len() > MAX_BODY {
            return Err(Error::Invalid("body bound"));
        }
        Ok(frame)
    }
}

#[derive(Clone, Debug)]
pub(crate) enum Source {
    Context,
    Event(Evidence),
    Terminal {
        snapshot: ExportSnapshot,
        journal_count: usize,
        dropped: usize,
    },
    Finish,
}

#[derive(Clone, Debug)]
pub(crate) struct Frame {
    bytes: Vec<u8>,
    context: Context,
    operation: Operation,
    sequence: usize,
    source: Source,
}

impl Frame {
    fn build(
        context: Context,
        operation: Operation,
        source: Source,
        evidence: Option<&Evidence>,
    ) -> Result<Self, Error> {
        let mut bytes = vec![2, operation.byte(), context.phase];
        bytes.extend_from_slice(&context.registry.to_be_bytes());
        let (sequence, request, identity, slot, disabled, effective) = match evidence {
            Some(evidence) => (
                evidence.journal_sequence,
                evidence.request_id,
                evidence.identity.unwrap_or(0),
                evidence.storage.as_ref().map_or(0, |storage| storage.slot),
                evidence.explicit_disabled,
                match evidence.effective_none {
                    Some(false) => 0,
                    Some(true) => 1,
                    None => 2,
                },
            ),
            None => (0, 0, 0, 0, false, 2),
        };
        for value in [sequence, request, identity, slot] {
            put_usize(&mut bytes, value)?;
        }
        bytes.extend_from_slice(&[u8::from(disabled), effective]);
        let (base, allocated) = match evidence.and_then(|item| item.storage.as_ref()) {
            Some(storage) => (path_bytes(&storage.base)?, path_bytes(&storage.allocated)?),
            None => (&[][..], &[][..]),
        };
        for length in [base.len(), allocated.len()] {
            bytes.extend_from_slice(
                &u16::try_from(length)
                    .map_err(|_| Error::Invalid("path length"))?
                    .to_be_bytes(),
            );
        }
        bytes.extend_from_slice(base);
        bytes.extend_from_slice(allocated);
        Ok(Self {
            bytes,
            context,
            operation,
            sequence,
            source,
        })
    }

    pub(crate) fn finish() -> Result<Self, Error> {
        Self::build(
            Context {
                registry: 0,
                phase: 0,
            },
            Operation::Finish,
            Source::Finish,
            None,
        )
    }

    pub(crate) fn source(&self) -> &Source {
        &self.source
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

fn put_usize(bytes: &mut Vec<u8>, value: usize) -> Result<(), Error> {
    bytes.extend_from_slice(
        &u64::try_from(value)
            .map_err(|_| Error::Invalid("integer representation"))?
            .to_be_bytes(),
    );
    Ok(())
}

fn path_bytes(path: &Path) -> Result<&[u8], Error> {
    let bytes = path.as_os_str().as_encoded_bytes();
    if !path.is_absolute() || bytes.is_empty() || bytes.len() > MAX_PATH || bytes.contains(&0) {
        return Err(Error::Invalid("path representation"));
    }
    Ok(bytes)
}

fn failure_code(reason: Option<&str>) -> Result<u8, Error> {
    let index = FAILURES
        .iter()
        .position(|known| *known == reason)
        .ok_or(Error::Invalid("unknown producer failure"))?;
    u8::try_from(index).map_err(|_| Error::Invalid("failure representation"))
}

fn validate_evidence(evidence: &Evidence) -> Result<(), Error> {
    if evidence.journal_sequence == 0 || evidence.journal_sequence > MAX_EVENTS {
        return Err(Error::Invalid("journal sequence"));
    }
    let shape = match evidence.event {
        SelectionEvent::Reserved => {
            evidence.outcome == SelectionOutcome::Reserved
                && evidence.identity.is_some_and(|identity| identity > 0)
                && evidence.effective_none.is_some()
                && evidence.storage.is_none()
        }
        SelectionEvent::StorageAssigned => {
            evidence.outcome == SelectionOutcome::Reserved
                && evidence.identity.is_some_and(|identity| identity > 0)
                && evidence.effective_none.is_some()
                && evidence.storage.as_ref().is_some_and(|storage| {
                    (1..=15).contains(&storage.slot)
                        && storage.allocated
                            == storage
                                .base
                                .join("owners-v1")
                                .join(storage.slot.to_string())
                })
        }
        SelectionEvent::Global => {
            evidence.outcome == SelectionOutcome::Global
                && evidence.identity.is_none()
                && evidence.effective_none.is_some()
                && evidence.storage.is_none()
        }
        SelectionEvent::ReserveFailed => {
            evidence.outcome == SelectionOutcome::ReserveFailed
                && evidence.identity.is_none()
                && evidence.effective_none.is_none()
                && evidence.storage.is_none()
        }
    };
    if !shape
        || (evidence.explicit_disabled
            && evidence.effective_none == Some(false)
            && evidence.event != SelectionEvent::ReserveFailed)
    {
        return Err(Error::Invalid("event shape"));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum State {
    Ready,
    InFlight,
    Failed,
    Finished,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Receipt {
    pub(crate) transaction: usize,
    pub(crate) registry: u64,
    pub(crate) operation: Operation,
    pub(crate) journal_sequence: usize,
}

#[derive(Clone, Copy)]
struct SentContext {
    phase: u8,
    events: usize,
    ended: bool,
}

pub(crate) struct Client {
    stream: TcpStream,
    deadline: Instant,
    state: State,
    completed: usize,
    contexts: BTreeMap<u64, SentContext>,
    last_error: Option<Error>,
}

impl Client {
    pub(crate) fn new(stream: TcpStream, deadline: Instant) -> Self {
        Self {
            stream,
            deadline,
            state: State::Ready,
            completed: 0,
            contexts: BTreeMap::new(),
            last_error: None,
        }
    }

    pub(crate) fn state(&self) -> State {
        self.state
    }

    pub(crate) fn last_error(&self) -> Option<&Error> {
        self.last_error.as_ref()
    }

    pub(crate) fn into_stream(self) -> TcpStream {
        self.stream
    }

    fn budget(&self) -> Result<(), Error> {
        if Instant::now() >= self.deadline {
            return Err(Error::Deadline);
        }
        Ok(())
    }

    fn validate_frame(&self, frame: &Frame) -> Result<(), Error> {
        if self.completed >= MAX_TRANSACTIONS
            || !(HEADER_SIZE..=MAX_BODY).contains(&frame.bytes.len())
        {
            return Err(Error::Invalid("transaction bound"));
        }
        if frame.operation == Operation::Finish {
            if self.contexts.is_empty() || self.contexts.values().any(|context| !context.ended) {
                return Err(Error::Invalid("unfinished contexts"));
            }
            return Ok(());
        }
        let context = self.contexts.get(&frame.context.registry);
        if frame.operation == Operation::Open {
            if context.is_some() || self.contexts.len() >= MAX_REGISTRIES {
                return Err(Error::Invalid("context open"));
            }
            return Ok(());
        }
        let context = context.ok_or(Error::Invalid("unknown context"))?;
        if context.ended || context.phase != frame.context.phase {
            return Err(Error::Invalid("context lifecycle"));
        }
        if frame.operation.event()
            && (context.events >= MAX_EVENTS || frame.sequence != context.events + 1)
        {
            return Err(Error::Invalid("event order"));
        }
        Ok(())
    }

    async fn write(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.budget()?;
        timeout_at(self.deadline, self.stream.write_all(bytes))
            .await
            .map_err(|_| Error::Deadline)?
            .map_err(|error| Error::Io(error.kind()))?;
        self.budget()
    }

    async fn expect(&mut self, expected: &[u8]) -> Result<(), Error> {
        let mut reply = Vec::with_capacity(MAX_LINE);
        loop {
            self.budget()?;
            let mut byte = [0];
            timeout_at(self.deadline, self.stream.read_exact(&mut byte))
                .await
                .map_err(|_| Error::Deadline)?
                .map_err(|error| {
                    if error.kind() == std::io::ErrorKind::UnexpectedEof {
                        Error::Eof
                    } else {
                        Error::Io(error.kind())
                    }
                })?;
            self.budget()?;
            reply.push(byte[0]);
            if byte[0] == b'\n' {
                break;
            }
            if reply.len() == MAX_LINE {
                return Err(Error::ReplyBound);
            }
        }
        if reply == expected {
            return Ok(());
        }
        if let Some(reason) = reply
            .strip_prefix(b"DENY ")
            .and_then(|value| value.strip_suffix(b"\n"))
        {
            if !reason.is_empty()
                && reason
                    .iter()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
            {
                return Err(Error::Denied(
                    String::from_utf8(reason.to_vec()).map_err(|_| Error::WrongReply)?,
                ));
            }
        }
        Err(Error::WrongReply)
    }

    async fn exchange(&mut self, frame: &Frame, number: usize) -> Result<(), Error> {
        self.write(format!("CE START {number} {}\n", frame.bytes.len()).as_bytes())
            .await?;
        self.expect(format!("CE READY {number}\n").as_bytes())
            .await?;
        for (index, chunk) in frame.bytes.chunks(MAX_CHUNK).enumerate() {
            let offset = index * MAX_CHUNK;
            let mut hex = String::with_capacity(chunk.len() * 2);
            for byte in chunk {
                use std::fmt::Write;
                write!(&mut hex, "{byte:02x}").map_err(|_| Error::Invalid("hex formatting"))?;
            }
            let request = format!("CE DATA {number} {offset} {hex}\n");
            if request.len() > MAX_LINE {
                return Err(Error::Invalid("fragment line bound"));
            }
            self.write(request.as_bytes()).await?;
            self.expect(format!("CE NEXT {number} {}\n", offset + chunk.len()).as_bytes())
                .await?;
        }
        self.write(format!("CE COMMIT {number}\n").as_bytes())
            .await?;
        self.expect(format!("CE ACCEPT {number}\n").as_bytes())
            .await?;
        self.write(format!("CE CONFIRM {number}\n").as_bytes())
            .await?;
        self.expect(format!("CE CONFIRMED {number}\n").as_bytes())
            .await
    }

    /// cancel-safe: NO — cancellation leaves InFlight permanently unusable.
    /// The caller retains this client, records failure, and drains or closes its stream.
    pub(crate) async fn send(&mut self, frame: &Frame) -> Result<Receipt, Error> {
        if self.state != State::Ready {
            return Err(Error::Unusable);
        }
        if let Err(error) = self.validate_frame(frame).and_then(|()| self.budget()) {
            self.state = State::Failed;
            self.last_error = Some(error.clone());
            return Err(error);
        }
        self.state = State::InFlight;
        let number = self.completed + 1;
        if let Err(error) = self.exchange(frame, number).await {
            self.state = State::Failed;
            self.last_error = Some(error.clone());
            return Err(error);
        }
        match frame.operation {
            Operation::Open => {
                self.contexts.insert(
                    frame.context.registry,
                    SentContext {
                        phase: frame.context.phase,
                        events: 0,
                        ended: false,
                    },
                );
            }
            Operation::End => {
                self.contexts
                    .get_mut(&frame.context.registry)
                    .unwrap()
                    .ended = true;
            }
            operation if operation.event() => {
                self.contexts
                    .get_mut(&frame.context.registry)
                    .unwrap()
                    .events += 1;
            }
            Operation::Finish => {}
            _ => return Err(Error::Invalid("operation")),
        }
        self.completed = number;
        self.state = if frame.operation == Operation::Finish {
            State::Finished
        } else {
            State::Ready
        };
        Ok(Receipt {
            transaction: number,
            registry: frame.context.registry,
            operation: frame.operation,
            journal_sequence: frame.sequence,
        })
    }
}

#[cfg(test)]
mod tests {
    include!("tests/construction_wire_tests.rs");
}
