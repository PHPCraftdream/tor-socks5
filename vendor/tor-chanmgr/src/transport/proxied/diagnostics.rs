//! Bounded scalar observations for a selected PT connector attempt.

use std::sync::atomic::{AtomicUsize, Ordering};

/// Next attempt identity, unrelated to product configuration generations.
static NEXT_ID: AtomicUsize = AtomicUsize::new(1);

/// Allocate an opaque identity without wrapping.
fn identity() -> Option<usize> {
    let mut current = NEXT_ID.load(Ordering::Relaxed);
    loop {
        let next = current.checked_add(1)?;
        match NEXT_ID.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(value) => return Some(value),
            Err(observed) => current = observed,
        }
    }
}

/// Existing boundary owned by the connector.
#[derive(Clone, Copy, Debug)]
pub(super) enum Stage {
    /// Validate and encode the selected transport request.
    Prepare,
    /// Await the existing proxy connection.
    Dial,
    /// Construct and drive the SOCKS handshake.
    Negotiate,
    /// Await an existing handshake write.
    Send,
    /// Await an existing handshake flush.
    Flush,
    /// Await an existing handshake read.
    Receive,
    /// Advance or finish the existing handshake parser.
    Decode,
    /// Check the proxy's final status.
    Status,
    /// Return the negotiated stream.
    Returned,
}

impl Stage {
    /// Fixed pair of observation positions reserved for this stage.
    fn index(self) -> u32 {
        match self {
            Self::Prepare => 0,
            Self::Dial => 1,
            Self::Negotiate => 2,
            Self::Send => 3,
            Self::Flush => 4,
            Self::Receive => 5,
            Self::Decode => 6,
            Self::Status => 7,
            Self::Returned => 8,
        }
    }
}

/// Fixed classifications without error text or protocol data.
#[derive(Clone, Copy, Debug)]
pub(super) enum Outcome {
    /// Boundary entry.
    Begin,
    /// Boundary returned successfully.
    Ok,
    /// Existing proxy dial returned an I/O error.
    DialError,
    /// Existing handshake I/O returned an error.
    IoError,
    /// Existing SOCKS parser returned an error.
    ProtocolError,
    /// Proxy returned an unsuccessful final status.
    Rejected,
    /// Existing request preparation rejected the input.
    Invalid,
    /// Observation ended without an observed returned result.
    Abandoned,
}

/// Stack-local observation state with nineteen independently reserved records.
pub(super) struct Attempt {
    /// Identity of this retained attempt.
    id: Option<usize>,
    /// Order of accepted observations.
    sequence: usize,
    /// First begin and success observations for each fixed stage.
    seen: u32,
    /// Most recently entered existing boundary.
    current: Stage,
    /// Whether the first terminal observation has been recorded.
    terminal: bool,
}

impl Attempt {
    /// Begin observing a selected connector when its future starts executing.
    pub(super) fn new() -> Self {
        let mut attempt = Self {
            id: identity(),
            sequence: 0,
            seen: 0,
            current: Stage::Prepare,
            terminal: false,
        };
        attempt.begin(Stage::Prepare);
        attempt
    }

    /// Record first entry while retaining the latest active boundary.
    pub(super) fn begin(&mut self, stage: Stage) {
        if !self.terminal {
            self.current = stage;
            self.boundary(stage, Outcome::Begin, false);
        }
    }

    /// Record the first successful return at this stage.
    pub(super) fn ok(&mut self, stage: Stage) {
        if !self.terminal {
            self.boundary(stage, Outcome::Ok, true);
        }
    }

    /// Record only the first terminal result.
    pub(super) fn finish(&mut self, outcome: Outcome) {
        if !self.terminal {
            self.terminal = true;
            self.record(self.current, outcome, true);
        }
    }

    /// Reserve one begin and one success position per stage.
    fn boundary(&mut self, stage: Stage, outcome: Outcome, success: bool) {
        let bit = 1_u32 << (stage.index() * 2 + u32::from(success));
        if self.seen & bit == 0 {
            self.seen |= bit;
            self.record(stage, outcome, false);
        }
    }

    /// Render only reviewed attempt-local scalar facts.
    fn record(&mut self, stage: Stage, outcome: Outcome, terminal: bool) {
        let line = format!(
            "pt_connector attempt={:?} sequence={} stage={:?} outcome={:?} terminal={}",
            self.id, self.sequence, stage, outcome, terminal,
        );
        self.sequence = self.sequence.saturating_add(1);
        emit(&line);
    }
}

impl Drop for Attempt {
    fn drop(&mut self) {
        self.finish(Outcome::Abandoned);
    }
}

/// Record entry only for a selected PT attempt.
pub(super) fn begin(attempt: &mut Option<Attempt>, stage: Stage) {
    if let Some(attempt) = attempt {
        attempt.begin(stage);
    }
}

/// Record successful return only for a selected PT attempt.
pub(super) fn ok(attempt: &mut Option<Attempt>, stage: Stage) {
    if let Some(attempt) = attempt {
        attempt.ok(stage);
    }
}

/// Preserve the first terminal result without inspecting its payload.
pub(super) fn finish(attempt: &mut Option<Attempt>, outcome: Outcome) {
    if let Some(attempt) = attempt {
        attempt.finish(outcome);
    }
}

/// Register fixed metadata outside the dispatcher callback.
fn emission_callsite() -> &'static tracing::callsite::DefaultCallsite {
    tracing::callsite! {
        name: "pt_connector",
        kind: tracing::metadata::Kind::EVENT,
        target: "tor_chanmgr::pt_connector_diagnostics",
        level: tracing::Level::INFO,
        fields: message,
    }
}

/// Respect the current subscriber without a cached-interest emission veto.
fn emit(line: &str) {
    if tracing::Level::INFO > tracing::level_filters::STATIC_MAX_LEVEL {
        return;
    }
    let callsite = emission_callsite();
    let metadata = tracing::callsite::Callsite::metadata(callsite);
    tracing::dispatcher::get_default(|dispatch| {
        if !dispatch.enabled(metadata) {
            return;
        }
        let message = metadata
            .fields()
            .field("message")
            .expect("connector metadata includes message");
        let displayed = tracing::field::display(line);
        let fields = [(&message, Some(&displayed as &dyn tracing::field::Value))];
        let values = metadata.fields().value_set(&fields);
        let event = tracing::Event::new_child_of(None, metadata, &values);
        dispatch.event(&event);
    });
}
