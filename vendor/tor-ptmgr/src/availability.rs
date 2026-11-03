//! Bounded observations for one factory consumer request.

use crate::err::PtError;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Next identity for an actual retained consumer request.
static NEXT_ID: AtomicUsize = AtomicUsize::new(1);

/// Allocate an identity independently of configuration generations.
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

/// Retained observation for one factory request, with at most four records.
pub(super) struct Request {
    /// Opaque identity local to this consumer lifetime.
    id: Option<usize>,
    /// Next record sequence.
    sequence: usize,
    /// Whether a returned outcome has already been observed.
    terminal: bool,
}

impl Request {
    /// Observe actual entry when the factory future begins executing.
    pub(super) fn new() -> Self {
        let mut request = Self {
            id: identity(),
            sequence: 0,
            terminal: false,
        };
        request.record("Request", "Begin", false);
        request.record("Lookup", "Begin", false);
        request
    }

    /// Observe that the existing lookup returned a method.
    pub(super) fn method(&mut self) {
        self.record("Lookup", "Method", false);
    }

    /// Classify a borrowed original error before its existing allocation/conversion.
    pub(super) fn error(&mut self, error: &PtError) {
        let outcome = match error {
            PtError::Timeout => "Timeout",
            PtError::ChildGone => "ChildGone",
            PtError::ChildReadFailed(_) => "ReadError",
            _ => "Error",
        };
        self.finish("Lookup", outcome);
    }

    /// Observe an actual absent result.
    pub(super) fn absent(&mut self) {
        self.finish("Lookup", "None");
    }

    /// Observe that the factory object has been constructed for return.
    pub(super) fn factory(&mut self) {
        self.finish("Factory", "Returned");
    }

    /// Preserve the first returned or abandoned outcome.
    fn finish(&mut self, stage: &'static str, outcome: &'static str) {
        if !self.terminal {
            self.terminal = true;
            self.record(stage, outcome, true);
        }
    }

    /// Render only fixed labels and request-local scalar facts.
    fn record(&mut self, stage: &'static str, outcome: &'static str, terminal: bool) {
        let line = format!(
            "pt_availability request={:?} sequence={} stage={} outcome={} terminal={}",
            self.id, self.sequence, stage, outcome, terminal,
        );
        self.sequence = self.sequence.saturating_add(1);
        emit(&line);
    }
}

impl Drop for Request {
    fn drop(&mut self) {
        self.finish("Request", "Abandoned");
    }
}

/// Register fixed metadata before entering the dispatcher callback.
pub(super) fn emission_callsite() -> &'static tracing::callsite::DefaultCallsite {
    tracing::callsite! {
        name: "pt_availability",
        kind: tracing::metadata::Kind::EVENT,
        target: "tor_ptmgr::availability_diagnostics",
        level: tracing::Level::INFO,
        fields: message,
    }
}

/// Deliver a root event through the current subscriber's actual filters and sink.
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
            .expect("availability metadata includes message");
        let displayed = tracing::field::display(line);
        let fields = [(&message, Some(&displayed as &dyn tracing::field::Value))];
        let values = metadata.fields().value_set(&fields);
        let event = tracing::Event::new_child_of(None, metadata, &values);
        dispatch.event(&event);
    });
}
