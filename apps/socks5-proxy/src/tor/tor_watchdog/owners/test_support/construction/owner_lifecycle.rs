use std::io::Write;
use std::sync::Mutex;

const SLOT_COUNT: usize = 24;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Context {
    pub(super) probe: usize,
    pub(super) entry: usize,
    pub(super) initiator: Option<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Stage {
    Worker,
    Storage,
    Export,
    Create,
    Bootstrap,
    Select,
    Close,
    Recover,
}

impl Stage {
    fn index(self) -> usize {
        match self {
            Self::Worker => 0,
            Self::Storage => 1,
            Self::Export => 2,
            Self::Create => 3,
            Self::Bootstrap => 4,
            Self::Select => 5,
            Self::Close => 6,
            Self::Recover => 7,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Begin,
    Abandoned,
    Returned,
}

impl Kind {
    fn index(self) -> usize {
        match self {
            Self::Begin => 0,
            Self::Abandoned => 1,
            Self::Returned => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    Begin,
    Ok,
    Error,
    Cancelled,
    Deadline,
    JoinCancelled,
    JoinPanic,
    Dropped,
}

impl Outcome {
    fn failure(self) -> bool {
        matches!(
            self,
            Self::Error | Self::Cancelled | Self::Deadline | Self::JoinCancelled | Self::JoinPanic
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Record {
    pub(super) sequence: usize,
    pub(super) context: Context,
    pub(super) stage: Stage,
    pub(super) kind: Kind,
    pub(super) outcome: Outcome,
    pub(super) waiter: Option<usize>,
}

pub(super) struct Snapshot {
    pub(super) records: Vec<Record>,
    pub(super) suppressed: usize,
    pub(super) suppression_reported: bool,
    pub(super) first_failure: Option<Record>,
}

struct State {
    context: Option<Context>,
    slots: [Option<Record>; SLOT_COUNT],
    sequence: usize,
    suppressed: usize,
    suppression_reported: bool,
    first_failure: Option<Record>,
}

pub(super) struct Journal {
    state: Mutex<State>,
}

impl Default for Journal {
    fn default() -> Self {
        Self {
            state: Mutex::new(State {
                context: None,
                slots: [None; SLOT_COUNT],
                sequence: 0,
                suppressed: 0,
                suppression_reported: false,
                first_failure: None,
            }),
        }
    }
}

pub(super) fn render(record: &Record) -> String {
    format!(
        "owner_lifecycle sequence={} probe={} entry={} initiator={:?} \
         stage={:?} kind={:?} outcome={:?} waiter={:?}",
        record.sequence,
        record.context.probe,
        record.context.entry,
        record.context.initiator,
        record.stage,
        record.kind,
        record.outcome,
        record.waiter,
    )
}

fn emit(line: &str) {
    let _ = writeln!(std::io::stderr().lock(), "{line}");
}

impl Journal {
    pub(super) fn start(&self, context: Context) {
        if let Ok(mut state) = self.state.lock() {
            state.context.get_or_insert(context);
        }
    }

    pub(super) fn snapshot(&self) -> Snapshot {
        let state = self.state.lock().unwrap();
        let mut records: Vec<_> = state.slots.iter().flatten().copied().collect();
        records.sort_by_key(|record| record.sequence);
        Snapshot {
            records,
            suppressed: state.suppressed,
            suppression_reported: state.suppression_reported,
            first_failure: state.first_failure,
        }
    }

    fn record(&self, stage: Stage, kind: Kind, outcome: Outcome, waiter: Option<usize>) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let Some(context) = state.context else {
            return;
        };
        let index = stage.index() * 3 + kind.index();
        let duplicate = state.slots[index].is_some();
        let first_failure = outcome.failure() && state.first_failure.is_none();
        let record = Record {
            sequence: state.sequence,
            context,
            stage,
            kind,
            outcome,
            waiter,
        };
        if !duplicate || first_failure {
            state.sequence = state.sequence.saturating_add(1);
        }
        if first_failure {
            state.first_failure = Some(record);
        }
        if duplicate {
            state.suppressed = state.suppressed.saturating_add(1);
            if !state.suppression_reported {
                state.suppression_reported = true;
                emit(&format!(
                    "owner_lifecycle probe={} entry={} initiator={:?} \
                     suppression=at_least_one_duplicate terminal_slots_reserved=true",
                    context.probe, context.entry, context.initiator,
                ));
            }
            if first_failure {
                emit(&format!("{} reserved_first_failure=true", render(&record)));
            }
            return;
        }
        state.slots[index] = Some(record);
        emit(&render(&record));
    }

    pub(super) fn begin(&self, stage: Stage, waiter: Option<usize>) -> Guard<'_> {
        self.record(stage, Kind::Begin, Outcome::Begin, waiter);
        Guard {
            journal: self,
            stage,
            waiter,
            finished: false,
        }
    }

    pub(super) fn sync<T, E>(
        &self,
        stage: Stage,
        operation: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        let guard = self.begin(stage, None);
        let result = operation();
        guard.finish_result(&result);
        result
    }
}

pub(super) struct Guard<'a> {
    journal: &'a Journal,
    stage: Stage,
    waiter: Option<usize>,
    finished: bool,
}

impl Guard<'_> {
    pub(super) fn finish(mut self, outcome: Outcome) {
        self.journal
            .record(self.stage, Kind::Returned, outcome, self.waiter);
        self.finished = true;
    }

    pub(super) fn finish_result<T, E>(self, result: &Result<T, E>) {
        self.finish(if result.is_ok() {
            Outcome::Ok
        } else {
            Outcome::Error
        });
    }

    pub(super) fn finish_join<T, E>(self, result: &Result<Result<T, E>, tokio::task::JoinError>) {
        self.finish(match result {
            Ok(Ok(_)) => Outcome::Ok,
            Ok(Err(_)) => Outcome::Error,
            Err(error) if error.is_cancelled() => Outcome::JoinCancelled,
            Err(_) => Outcome::JoinPanic,
        });
    }
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.journal
                .record(self.stage, Kind::Abandoned, Outcome::Dropped, self.waiter);
        }
    }
}

/// cancel-safe: yes for terminal abandonment — this owns no tunnel or task
/// handle; dropping it abandons the existing bootstrap wait, not its owner.
pub(super) async fn bootstrap<F>(
    journal: &Journal,
    cancel: &tokio_util::sync::CancellationToken,
    deadline: tokio::time::Instant,
    work: F,
) -> anyhow::Result<()>
where
    F: std::future::Future<Output = anyhow::Result<()>>,
{
    let guard = journal.begin(Stage::Bootstrap, None);
    let (result, outcome) = tokio::select! {
        biased;
        _ = cancel.cancelled() => (
            Err(anyhow::Error::new(super::ConstructorCancelled)),
            Outcome::Cancelled,
        ),
        result = tokio::time::timeout_at(deadline, work) => match result {
            Err(_) => (
                Err(anyhow::anyhow!("истёк срок запуска Tor владельца")),
                Outcome::Deadline,
            ),
            Ok(result) => {
                let outcome = if result.is_ok() { Outcome::Ok } else { Outcome::Error };
                (result, outcome)
            }
        },
    };
    guard.finish(outcome);
    result
}
