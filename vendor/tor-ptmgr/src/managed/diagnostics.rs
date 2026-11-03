//! Bounded scalar observations for one managed-reactor transaction.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Opaque identity, absent after diagnostic identity exhaustion.
pub(super) type Id = Option<usize>;

/// Next diagnostic identity; independent of configuration generations.
static NEXT_ID: AtomicUsize = AtomicUsize::new(1);

/// Allocate an identity without wrapping or changing product state.
pub(super) fn id() -> Id {
    NEXT_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .ok()
}

/// Immutable ownership context captured when work is queued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Context {
    /// Reactor lifetime identity.
    pub(super) manager: Id,
    /// Launch, cleanup, or message transaction identity.
    pub(super) transaction: Id,
    /// Matching slot lifetime identity, when one exists.
    pub(super) slot: Id,
    /// Slot generation captured before the transaction starts.
    pub(super) generation: Option<u64>,
    /// Whether this transaction performs cleanup.
    pub(super) cleanup: bool,
}

/// Independently reserved observation positions within a transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Stage {
    /// Work has been placed under reactor ownership.
    Queued,
    /// The owned worker has actually begun polling.
    Worker,
    /// Configuration and storage setup has begun.
    SetupBegin,
    /// Setup has returned.
    SetupEnd,
    /// The existing launch operation is about to be awaited.
    LaunchBegin,
    /// Launch returned or its existing cancellation branch won.
    LaunchEnd,
    /// The existing nonblocking shutdown request returned.
    Signal,
    /// The worker returned its original result and ownership.
    WorkerReturn,
    /// The reactor received the completed worker result.
    Receipt,
    /// Existing publication validation selected its result.
    Validation,
    /// Methods were inserted into local shared state.
    Publication,
    /// Existing pending-generation validation selected its result.
    Pending,
    /// The original completion branch applied its disposition.
    Apply,
    /// Owned work disappeared without an observed application.
    Abandoned,
    /// A running transport's actual message operation failed.
    Message,
    /// Successful local method-result sender calls were counted.
    Reserved,
}

impl Stage {
    /// Return the fixed storage position reserved for this stage.
    fn index(self) -> usize {
        match self {
            Self::Queued => 0,
            Self::Worker => 1,
            Self::SetupBegin => 2,
            Self::SetupEnd => 3,
            Self::LaunchBegin => 4,
            Self::LaunchEnd => 5,
            Self::Signal => 6,
            Self::WorkerReturn => 7,
            Self::Receipt => 8,
            Self::Validation => 9,
            Self::Publication => 10,
            Self::Pending => 11,
            Self::Apply => 12,
            Self::Abandoned => 13,
            Self::Message => 14,
            Self::Reserved => 15,
        }
    }
}

/// Safe result categories; none contains an arbitrary error value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    /// Operation entry, not completion.
    Begin,
    /// The observed operation returned success.
    Ok,
    /// The observed operation returned an error.
    Error,
    /// The existing cancellation branch was selected.
    Cancelled,
    /// The existing launch operation returned its timeout variant.
    Deadline,
    /// Existing validation rejected publication or pending restart.
    Rejected,
    /// Local methods were published.
    Published,
    /// Returned ownership was retained by the reactor.
    Retained,
    /// Returned ownership was not retained after application.
    Removed,
    /// Work was abandoned without an observed application.
    Dropped,
}

impl Outcome {
    /// Identify actual failures eligible for the independent first-failure slot.
    fn failure(self) -> bool {
        matches!(
            self,
            Self::Error | Self::Cancelled | Self::Deadline | Self::Rejected
        )
    }
}

/// Scalar facts observed at one specific boundary.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Facts {
    /// Generation of the matching slot at this boundary.
    pub(super) slot_generation: Option<u64>,
    /// Current generation read under the original validation guard.
    pub(super) state_generation: Option<u64>,
    /// Pending configuration's generation, when validated.
    pub(super) pending_generation: Option<u64>,
    /// Presence or retention in the ownership scope named by the stage.
    pub(super) owner_present: Option<bool>,
    /// Finite local method or successful sender-call count.
    pub(super) count: usize,
}

/// One allowlisted observation with transaction-local ordering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Record {
    /// Transaction-local order of accepted observations.
    pub(super) sequence: usize,
    /// Immutable queued-work context.
    pub(super) context: Context,
    /// Actual lifecycle boundary.
    pub(super) stage: Stage,
    /// Boundary result category.
    pub(super) outcome: Outcome,
    /// Boundary-specific scalar facts.
    pub(super) facts: Facts,
}

/// Fixed-capacity recording and emission policy.
struct State {
    /// First observation at each independently reserved stage.
    records: [Option<Record>; 16],
    /// Next accepted observation sequence.
    sequence: usize,
    /// Number of suppressed duplicate-stage observations.
    suppressed: usize,
    /// Whether the single suppression notice has been emitted.
    suppression_reported: bool,
    /// First actual failure, independent of ordinary stage occupancy.
    first_failure: Option<Record>,
    /// Lines accepted by the actual production emission policy.
    #[cfg(test)]
    emitted: Vec<String>,
}

/// Shared observation state for one retained transaction.
pub(super) struct Trace {
    /// Context captured before worker polling.
    context: Context,
    /// Synchronous diagnostic state; never held across an await.
    state: Mutex<State>,
}

/// Read-only test receipt from the same policy that emits production lines.
#[cfg(test)]
pub(super) struct Snapshot {
    /// Ordinary accepted records in observation order.
    pub(super) records: Vec<Record>,
    /// Suppressed duplicate-stage count.
    pub(super) suppressed: usize,
    /// Independently retained first failure.
    pub(super) first_failure: Option<Record>,
    /// Exact lines offered to tracing, independently of subscriber filtering or delivery.
    pub(super) emitted: Vec<String>,
}

/// Render only reviewed scalar fields.
pub(super) fn render(record: &Record) -> String {
    format!(
        "managed_pt sequence={} manager={:?} transaction={:?} slot={:?} \
         captured_generation={:?} cleanup={} stage={:?} outcome={:?} \
         slot_generation={:?} state_generation={:?} pending_generation={:?} \
         owner_present={:?} count={}",
        record.sequence,
        record.context.manager,
        record.context.transaction,
        record.context.slot,
        record.context.generation,
        record.context.cleanup,
        record.stage,
        record.outcome,
        record.facts.slot_generation,
        record.facts.state_generation,
        record.facts.pending_generation,
        record.facts.owner_present,
        record.facts.count,
    )
}

/// Send an accepted line through the common bounded-output path.
fn emit(state: &mut State, line: String) {
    #[cfg(test)]
    state.emitted.push(line.clone());
    #[cfg(not(test))]
    let _ = state;
    tracing::info!(
        target: "tor_ptmgr::managed_diagnostics",
        parent: None,
        message = %line,
    );
}

impl Trace {
    /// Allocate fixed transaction state without a process-global journal.
    fn new(context: Context) -> Arc<Self> {
        Arc::new(Self {
            context,
            state: Mutex::new(State {
                records: [None; 16],
                sequence: 0,
                suppressed: 0,
                suppression_reported: false,
                first_failure: None,
                #[cfg(test)]
                emitted: Vec::new(),
            }),
        })
    }

    /// Expose captured identity only to integration assertions.
    #[cfg(test)]
    pub(super) fn context(&self) -> Context {
        self.context
    }

    /// Record and emit a boundary without inspecting its resource or error.
    pub(super) fn event(&self, stage: Stage, outcome: Outcome, facts: Facts) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let duplicate = state.records[stage.index()].is_some();
        let first_failure = outcome.failure() && state.first_failure.is_none();
        let record = Record {
            sequence: state.sequence,
            context: self.context,
            stage,
            outcome,
            facts,
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
                emit(
                    &mut state,
                    format!(
                        "managed_pt manager={:?} transaction={:?} \
                         suppression=at_least_one_duplicate terminal_stage_reserved=true",
                        self.context.manager, self.context.transaction,
                    ),
                );
            }
            if first_failure {
                emit(
                    &mut state,
                    format!("{} reserved_first_failure=true", render(&record)),
                );
            }
            return;
        }
        state.records[stage.index()] = Some(record);
        emit(&mut state, render(&record));
    }

    /// Obtain a test receipt without consuming any product observation.
    #[cfg(test)]
    pub(super) fn snapshot(&self) -> Snapshot {
        let state = self.state.lock().expect("diagnostic test state");
        let mut records: Vec<_> = state.records.iter().flatten().copied().collect();
        records.sort_by_key(|record| record.sequence);
        Snapshot {
            records,
            suppressed: state.suppressed,
            first_failure: state.first_failure,
            emitted: state.emitted.clone(),
        }
    }
}

/// Diagnostic ownership carried beside the original worker result.
pub(super) struct Ticket {
    /// Shared observation state for this transaction.
    pub(super) trace: Arc<Trace>,
    /// Whether an application disposition has been observed.
    finished: bool,
}

impl Ticket {
    /// Capture queued ownership before the worker's first poll.
    pub(super) fn new(context: Context) -> Self {
        let trace = Trace::new(context);
        trace.event(Stage::Queued, Outcome::Begin, Facts::default());
        Self {
            trace,
            finished: false,
        }
    }

    /// Observe the original completion branch's final ownership disposition.
    pub(super) fn finish(&mut self, outcome: Outcome, facts: Facts) {
        self.trace.event(Stage::Apply, outcome, facts);
        self.finished = true;
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        if !self.finished {
            self.trace
                .event(Stage::Abandoned, Outcome::Dropped, Facts::default());
        }
    }
}
