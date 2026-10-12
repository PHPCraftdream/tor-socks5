//! Tracing-based passive observation of per-guard usability events from
//! arti, used to drive bridge-store circuit-failure pruning.
//!
//! arti does not expose a per-bridge runtime-status API in its public
//! crates as of 0.43. What it *does* expose, generously, is structured
//! `tracing` events from `tor_guardmgr` containing the guard identity.
//! We listen for **two** complementary events:
//!
//! ```text
//! // tor-guardmgr/src/lib.rs — fires on GuardStatus::Success path only,
//! // when the circuit attempt against a guard completes and arti can
//! // answer whether the guard is usable for the pending request.
//! trace!(?guard_id, usable, "Known usability status");
//!
//! // tor-guardmgr/src/guard.rs — fires symmetrically on every
//! // Reachable-enum transition, including Untried→Unreachable and
//! // Reachable→Unreachable. This is the failure signal we need: the
//! // "Known usability status" event has no symmetric counterpart on
//! // GuardStatus::Failure (record_failure + pending.reply(false) skips
//! // any trace emission), so without it we never see fail signals.
//! trace!(guard_id = ?self.id, old=?self.reachable, new=?r,
//!        "Guard status changed.");
//! ```
//!
//! Mapping into [`GuardObservation`]:
//! - `"Known usability status"` → `usable = <bool field>`.
//! - `"Guard status changed."`  → `usable = (new == "Reachable")`; events
//!   with `new = "Untried"` (initial state) are ignored.
//!
//! **Known limitation — purpose-filter rejection.** arti 0.43 does NOT
//! emit any per-guard event when a configured bridge is rejected at the
//! **purpose-filter** stage of `select_guard` (the aggregate `"Couldn't
//! select guard ... N/M as unsuitable to purpose"` is not per-guard
//! structured). That class of rejection — typically a descriptor/
//! fingerprint mismatch — is invisible to this layer; the TCP-probe
//! failure counter remains the only signal for it. See `docs/bridges.md`.
//!
//! **Known limitation — channel & PT-handshake timeouts.** A bridge whose
//! TCP works but whose obfs4/webtunnel handshake times out (the live
//! signature: `lyrebird: handshake failed: HandshakeTimeout` plus
//! `tor_chanmgr`'s `Channel for [scrubbed] timed out`) is **not** linkable
//! to a specific bridge through this layer. Verified against arti 0.43:
//!
//! * `tor-chanmgr`/`tor-circmgr` wrap the failing peer in
//!   `LoggedChanTarget`, which is `safelog::BoxSensitive<OwnedChanTarget>`
//!   (`tor-linkspec-0.43/src/owned.rs`): its Display/Debug render as
//!   `[scrubbed]`, so neither the address nor the fingerprint is
//!   recoverable from the error — by design.
//! * every `tor-chanmgr` `#[instrument]` uses `skip_all`, so the channel
//!   target never appears as a typed field either, only in the scrubbed
//!   Display message.
//! * `tor-ptmgr` re-emits the PT child's own log lines as free-form
//!   messages (`"[pt {}] {}", pt_name, message`, `tor-ptmgr-0.43/src/
//!   ipc.rs`) carrying only the PT *name* as structure — the `address=`
//!   substring is unstructured text controlled by the child binary, not a
//!   typed field and not a fingerprint.
//!
//! A `handshake_fails` counter fed from these events is therefore not
//! buildable without either disabling arti's safe-logging (a security
//! regression) or free-text-scraping the PT child's message (brittle,
//! child-controlled and unversioned). The only fingerprint-linked failure
//! signal remains the guardmgr reachability transition captured here into
//! `circuit_fails` — which is why a TCP-alive / handshake-dead bridge is
//! pruned slowly (rate-limited: one bump per
//! `circuit_observation_window`, threshold `max_circuit_fails`), not
//! instantly.
//!
//! We install a [`tracing_subscriber::Layer`] that listens for these
//! events (and only these), extracts the RSA identity fingerprint from
//! the Debug-formatted `guard_id`, and pushes a [`GuardObservation`]
//! into a shared sink. The sink is a bounded ring buffer: if the
//! consumer stops draining (e.g. a persistent config load failure), the
//! oldest observations are dropped in favor of the most recent ones
//! rather than letting memory grow without bound. The proxy's
//! maintenance loop periodically drains the sink into [`BridgeStore`], where consecutive failures eventually
//! prune the bridge from the working config — exactly like TCP-probe
//! failures, but observed from the cell layer instead of TCP.
//!
//! Why structured tracing rather than parsing log strings: the
//! `guard_id` and `usable` fields are emitted as typed values, so we
//! receive them through the `tracing::field::Visit` trait without any
//! formatting round-trip. The only fragile part is the **Debug shape**
//! of `RelayIds` — we match `RsaIdentity { $<40 hex> }` with a regex.
//! That shape has been stable across tor-* 0.25 → 0.42; a unit test
//! pins the exact format we depend on, so an upstream change is caught
//! by CI rather than silently breaking observation in production.
//!
//! Coupling: this module knows nothing about [`BridgeStore`] — it only
//! produces observations. The consumer side ([`crate::server`]) decides
//! when and how to apply them.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bridge_line::BridgeLine;
use time::OffsetDateTime;
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, Layer};

use bridge_store::BridgeStore;

thread_local! {
    static IGNORE_GUARD_OBSERVATIONS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Isolate a throwaway client's current-thread runtime from live guard health.
pub(crate) fn without_guard_observations<T>(run: impl FnOnce() -> T) -> T {
    IGNORE_GUARD_OBSERVATIONS.with(|flag| {
        struct Restore<'a>(&'a std::cell::Cell<bool>, bool);
        impl Drop for Restore<'_> {
            fn drop(&mut self) {
                self.0.set(self.1);
            }
        }
        let _restore = Restore(flag, flag.replace(true));
        run()
    })
}

/// The tracing target prefix we listen on. Pinned to `tor_guardmgr` —
/// the only crate that emits per-guard usability status with a
/// structured `guard_id` field in arti 0.42.
const ARTI_GUARDMGR_TARGET: &str = "tor_guardmgr";

/// arti's success-path usability event. Emitted from
/// `GuardMgr::handle_msg` on `GuardStatus::Success` only; carries an
/// explicit `usable: bool` field.
const USABILITY_MESSAGE: &str = "Known usability status";

/// arti's symmetric reachability-transition event. Emitted from
/// `Guard::set_reachable` on every change of `Reachable` enum state;
/// carries `old`/`new` fields whose Debug-form is the variant name
/// (`"Reachable"`, `"Unreachable"`, `"Untried"`).
const STATUS_CHANGED_MESSAGE: &str = "Guard status changed.";

/// A single per-guard usability observation, lifted out of an arti
/// tracing event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardObservation {
    /// RSA identity (the guard's bridge fingerprint), uppercase 40 hex
    /// chars — the same form that lives in `BridgeLine.fingerprint`.
    pub fingerprint: String,
    /// `true` → arti considers this guard usable. `false` → not.
    pub usable: bool,
}

/// Capacity of the observation queue. Guardmgr emits far fewer events
/// between maintenance drains (drains happen every maintenance cycle),
/// so reaching this cap means the consumer is stuck (e.g. persistent
/// config load failure). On overflow we drop the OLDEST observations,
/// preserving the most recent contiguous suffix of the event sequence;
/// the queue is capped so memory cannot grow unboundedly.
const OBSERVATION_QUEUE_CAP: usize = 1024;

/// Shared, drainable sink of observations captured by the layer.
///
/// Cheap to clone (`Arc<Mutex<VecDeque<...>>>`). Backed by a bounded
/// ring buffer of [`OBSERVATION_QUEUE_CAP`] entries with drop-oldest
/// eviction: when full, the oldest observation is discarded to make room
/// for the newest, so memory stays bounded even if the consumer never
/// drains. Producer side: the tracing layer pushes into this. Consumer
/// side: the maintenance loop calls [`Self::drain`] to take whatever has
/// accumulated and feed it to the bridge store.
#[derive(Debug, Clone, Default)]
pub struct ObservationSink {
    inner: Arc<Mutex<std::collections::VecDeque<GuardObservation>>>,
    recovery: Arc<Mutex<Option<std::sync::Weak<tokio::sync::Notify>>>>,
}

impl ObservationSink {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_recovery_notifier(&self, notifier: &Arc<tokio::sync::Notify>) {
        if let Ok(mut recovery) = self.recovery.lock() {
            *recovery = Some(Arc::downgrade(notifier));
        }
    }

    /// Take every observation accumulated so far. The sink is empty
    /// after this returns. Safe to call from any thread.
    #[must_use]
    pub fn drain(&self) -> Vec<GuardObservation> {
        match self.inner.lock() {
            Ok(mut g) => std::mem::take(&mut *g).into(),
            // Poisoned lock — drop the contents (whoever poisoned us
            // was already in an unrecoverable spot). Observation is
            // best-effort; losing a batch is fine.
            Err(poisoned) => {
                let mut g = poisoned.into_inner();
                std::mem::take(&mut *g).into()
            }
        }
    }

    /// Drain accumulated observations into `store`, matching each one to
    /// `BridgeLine`s from `known` by uppercase RSA fingerprint. Failures
    /// bump `circuit_fails` (rate-limited by `window`); successes reset
    /// it. Observations whose fingerprint matches nothing in `known`
    /// (e.g. arti reporting on a public guard) are silently dropped —
    /// the store tracks only configured bridges.
    ///
    /// **Shared-fate broadcast policy.** Guard-level observations are
    /// keyed by RSA fingerprint, which identifies the GUARD, not any
    /// specific endpoint: arti does not attribute them to a bridge line
    /// (see the module docs — channel targets are scrubbed). When two or
    /// more configured bridge lines share one fingerprint (same guard,
    /// several addresses/URLs), an observation is applied to EVERY such
    /// endpoint. This is deterministic and independent of config line
    /// order — the previous last-line-wins behavior was order-dependent
    /// and could credit or penalize the wrong endpoint. Per-endpoint
    /// discrimination remains the TCP-probe layer's job
    /// (`BridgeStore::note_probe_round`, keyed by full bridge identity),
    /// so a dead address of a multi-address guard is still pruned by
    /// probes even while guard-level successes keep resetting its circuit
    /// counter. Each endpoint's counter is rate-limited independently, so
    /// one failure observation bumps each matching endpoint at most once
    /// per `window`.
    ///
    /// Returns a `(failures_recorded, successes_recorded, unmatched)`
    /// tuple for caller-side logging: `failures` counts observations that
    /// incremented at least one endpoint's `circuit_fails` (per-
    /// observation, so an already-rate-limited observation does not
    /// count); `successes` counts matched success observations; and
    /// `unmatched` counts observations with no matching fingerprint.
    /// Side effects on `store` are committed in place; the caller decides
    /// when to `store.save()`.
    ///
    /// Pure w.r.t. `now` for unit testing.
    pub fn drain_into_store(
        &self,
        store: &mut BridgeStore,
        known: &[BridgeLine],
        now: OffsetDateTime,
        window: Duration,
    ) -> (usize, usize, usize) {
        let mut by_fp: std::collections::HashMap<String, Vec<&BridgeLine>> =
            std::collections::HashMap::with_capacity(known.len());
        for b in known {
            if let Some(fp) = b.fingerprint.as_deref() {
                by_fp.entry(fp.to_ascii_uppercase()).or_default().push(b);
            }
        }
        let mut failures = 0usize;
        let mut successes = 0usize;
        let mut unmatched = 0usize;
        for obs in self.drain() {
            let Some(group) = by_fp.get(&obs.fingerprint) else {
                unmatched += 1;
                continue;
            };
            if obs.usable {
                for bridge in group {
                    store.note_circuit_success_at(bridge, now);
                }
                successes += 1;
            } else {
                let mut counted = false;
                for bridge in group {
                    if store.note_circuit_failure_at(bridge, now, window) {
                        counted = true;
                    }
                }
                if counted {
                    failures += 1;
                }
            }
        }
        (failures, successes, unmatched)
    }

    /// Test/diagnostic helper: how many observations are queued without
    /// removing them.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().map(|g| g.len()).unwrap_or(0)
    }

    fn push(&self, obs: GuardObservation) {
        let failed = !obs.usable;
        if let Ok(mut g) = self.inner.lock() {
            // Drop-oldest eviction: push_back, then shed from the front
            // until within cap. Retained events keep their relative
            // order, so the consumer sees an order-preserving suffix of
            // the true failure/success sequence — never reordered or
            // interleaved.
            g.push_back(obs);
            while g.len() > OBSERVATION_QUEUE_CAP {
                g.pop_front();
            }
        }
        if failed {
            let notifier = self
                .recovery
                .lock()
                .ok()
                .and_then(|guard| guard.as_ref().and_then(std::sync::Weak::upgrade));
            if let Some(notifier) = notifier {
                notifier.notify_one();
            }
        }
    }
}

/// `tracing_subscriber::Layer` that captures arti's per-guard usability
/// events and pushes them into a shared [`ObservationSink`].
///
/// Install it next to the regular fmt layer (e.g. via
/// `tracing_subscriber::registry().with(fmt_layer).with(layer)`). It
/// emits no log output of its own. It also does **not** raise the
/// global filter level — to be reached by arti's `trace!(...)` events,
/// the layer needs a per-layer `EnvFilter::new("tor_guardmgr=trace")`
/// applied on top of it; see [`Self::with_default_filter`] for the
/// ready-made wrapper.
#[derive(Debug, Clone)]
pub struct GuardObservabilityLayer {
    sink: ObservationSink,
}

impl GuardObservabilityLayer {
    /// Build a layer that pushes observations into `sink`.
    #[must_use]
    pub fn new(sink: ObservationSink) -> Self {
        Self { sink }
    }
}

impl<S> Layer<S> for GuardObservabilityLayer
where
    S: tracing::Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        if IGNORE_GUARD_OBSERVATIONS.get() {
            return;
        }
        let metadata = event.metadata();
        // Cheap target filter first — bail before allocating the visitor.
        if !metadata.target().starts_with(ARTI_GUARDMGR_TARGET) {
            return;
        }

        let mut v = GuardEventVisitor::default();
        event.record(&mut v);

        let Some(message) = v.message.as_deref() else {
            return;
        };
        let Some(fingerprint) = v.fingerprint else {
            return;
        };

        let usable = match message {
            USABILITY_MESSAGE => match v.usable {
                Some(b) => b,
                None => return,
            },
            STATUS_CHANGED_MESSAGE => match v.new_reachable.as_deref() {
                Some("Reachable") => true,
                Some("Unreachable") => false,
                // `Untried` (initial state) and any future variant we
                // don't recognise carry no usability signal.
                _ => return,
            },
            _ => return,
        };

        self.sink.push(GuardObservation {
            fingerprint,
            usable,
        });
    }
}

/// Visits a tracing event's fields and pulls out everything we may need
/// across the two supported events: `message`, `guard_id`
/// (Debug-formatted — we regex out the RSA fingerprint), `usable: bool`
/// for `"Known usability status"`, and `new` (Debug-formatted Reachable
/// variant) for `"Guard status changed."`.
#[derive(Default)]
struct GuardEventVisitor {
    message: Option<String>,
    fingerprint: Option<String>,
    usable: Option<bool>,
    new_reachable: Option<String>,
}

impl Visit for GuardEventVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        }
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        if field.name() == "usable" {
            self.usable = Some(value);
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let name = field.name();
        // The `message` field arrives as Debug when the event uses a
        // literal format string; capture its string form too.
        if name == "message" && self.message.is_none() {
            self.message = Some(format!("{value:?}"));
            return;
        }
        if name == "guard_id" {
            let dbg = format!("{value:?}");
            self.fingerprint = extract_rsa_fingerprint(&dbg);
            return;
        }
        if name == "new" {
            // `new` is `?r` on a `Reachable` enum; its Debug rendering is
            // just the variant name (e.g. "Reachable", "Unreachable",
            // "Untried"). Capture it for STATUS_CHANGED_MESSAGE.
            self.new_reachable = Some(format!("{value:?}"));
        }
    }
}

/// Extract the 40-hex-char RSA identity from a Debug-formatted
/// `RelayIds` / `FirstHopId` value. The fragment we look for is
/// `RsaIdentity { $<40 hex> }`, which is the Debug shape produced by
/// tor-linkspec 0.25–0.42.
///
/// Returns the fingerprint in **uppercase** to match the form stored
/// in `BridgeLine.fingerprint`.
fn extract_rsa_fingerprint(dbg: &str) -> Option<String> {
    // Locate the marker `RsaIdentity { $`; the next 40 hex chars are
    // the fingerprint. Doing this by string scan instead of pulling in
    // a regex crate keeps the dependency footprint small and the cost
    // O(len) on each event — fine for the volume of guardmgr events.
    const MARKER: &str = "RsaIdentity { $";
    let start = dbg.find(MARKER)? + MARKER.len();
    let rest = &dbg[start..];
    let hex: String = rest
        .chars()
        .take(40)
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    if hex.len() == 40 {
        Some(hex.to_uppercase())
    } else {
        None
    }
}

#[cfg(test)]
#[path = "arti_observability_tests.rs"]
mod tests;
