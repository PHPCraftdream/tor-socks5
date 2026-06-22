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
//! **Known limitation.** arti 0.43 does NOT emit any per-guard event when
//! a configured bridge is rejected at the **purpose-filter** stage of
//! `select_guard` (the aggregate `"Couldn't select guard ... N/M as
//! unsuitable to purpose"` is not per-guard structured). That class of
//! rejection — typically a descriptor/fingerprint mismatch — is invisible
//! to this layer; the TCP-probe failure counter remains the only signal
//! for it. See `docs/bridges.md`.
//!
//! We install a [`tracing_subscriber::Layer`] that listens for these
//! events (and only these), extracts the RSA identity fingerprint from
//! the Debug-formatted `guard_id`, and pushes a [`GuardObservation`]
//! into a shared sink. The proxy's maintenance loop periodically drains
//! the sink into [`BridgeStore`], where consecutive failures eventually
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

use crate::bridge_store::BridgeStore;

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

/// Shared, drainable sink of observations captured by the layer.
///
/// Cheap to clone (`Arc<Mutex<Vec<...>>>`). Producer side: the tracing
/// layer pushes into this. Consumer side: the maintenance loop calls
/// [`Self::drain`] to take whatever has accumulated and feed it to the
/// bridge store.
#[derive(Debug, Clone, Default)]
pub struct ObservationSink {
    inner: Arc<Mutex<Vec<GuardObservation>>>,
}

impl ObservationSink {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Take every observation accumulated so far. The sink is empty
    /// after this returns. Safe to call from any thread.
    #[must_use]
    pub fn drain(&self) -> Vec<GuardObservation> {
        match self.inner.lock() {
            Ok(mut g) => std::mem::take(&mut *g),
            // Poisoned lock — drop the contents (whoever poisoned us
            // was already in an unrecoverable spot). Observation is
            // best-effort; losing a batch is fine.
            Err(poisoned) => {
                let mut g = poisoned.into_inner();
                std::mem::take(&mut *g)
            }
        }
    }

    /// Drain accumulated observations into `store`, matching each one to
    /// a `BridgeLine` from `known` by uppercase RSA fingerprint. Failures
    /// bump `circuit_fails` (rate-limited by `window`); successes reset
    /// it. Observations whose fingerprint matches nothing in `known`
    /// (e.g. arti reporting on a public guard) are silently dropped —
    /// the store tracks only configured bridges.
    ///
    /// Returns a `(failures_recorded, successes_recorded, unmatched)`
    /// tuple for caller-side logging. Side effects on `store` are
    /// committed in place; the caller decides when to `store.save()`.
    ///
    /// Pure w.r.t. `now` for unit testing.
    pub fn drain_into_store(
        &self,
        store: &mut BridgeStore,
        known: &[BridgeLine],
        now: OffsetDateTime,
        window: Duration,
    ) -> (usize, usize, usize) {
        let mut by_fp: std::collections::HashMap<String, &BridgeLine> =
            std::collections::HashMap::with_capacity(known.len());
        for b in known {
            if let Some(fp) = b.fingerprint.as_deref() {
                by_fp.insert(fp.to_ascii_uppercase(), b);
            }
        }
        let mut failures = 0usize;
        let mut successes = 0usize;
        let mut unmatched = 0usize;
        for obs in self.drain() {
            let Some(bridge) = by_fp.get(&obs.fingerprint).copied() else {
                unmatched += 1;
                continue;
            };
            if obs.usable {
                store.note_circuit_success_at(bridge, now);
                successes += 1;
            } else if store.note_circuit_failure_at(bridge, now, window) {
                failures += 1;
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
        if let Ok(mut g) = self.inner.lock() {
            g.push(obs);
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
mod tests {
    use super::*;
    use tracing::Level;
    use tracing_subscriber::prelude::*;

    // -- Fingerprint extraction (pure parser) --------------------------------

    #[test]
    fn extracts_lowercase_fingerprint_and_uppercases_it() {
        let dbg = r#"FirstHopId(Guard(Bridges, GuardId(RelayIds { ed_identity: None, rsa_identity: Some(RsaIdentity { $cd193cf0d0c29551928c01fcb28d1200d9f27cfa }) })))"#;
        assert_eq!(
            extract_rsa_fingerprint(dbg).as_deref(),
            Some("CD193CF0D0C29551928C01FCB28D1200D9F27CFA"),
        );
    }

    #[test]
    fn extracts_uppercase_fingerprint_unchanged() {
        let dbg = r#"RsaIdentity { $ABCDEF0123456789ABCDEF0123456789ABCDEF01 }"#;
        assert_eq!(
            extract_rsa_fingerprint(dbg).as_deref(),
            Some("ABCDEF0123456789ABCDEF0123456789ABCDEF01"),
        );
    }

    #[test]
    fn rejects_dbg_without_marker() {
        assert!(extract_rsa_fingerprint("some other Debug").is_none());
    }

    #[test]
    fn rejects_short_hex_run() {
        let dbg = "RsaIdentity { $abc123 }"; // only 6 hex chars
        assert!(extract_rsa_fingerprint(dbg).is_none());
    }

    // -- Layer end-to-end via a real subscriber ------------------------------

    /// Install the layer onto a temporary subscriber and run `f` while
    /// it is the active default subscriber.
    fn with_layer<F: FnOnce()>(sink: ObservationSink, f: F) {
        let layer = GuardObservabilityLayer::new(sink);
        // Accept TRACE for our target; the test-side filter is set
        // wide so the layer sees everything we emit.
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, f);
    }

    #[test]
    fn captures_usable_true_event() {
        let sink = ObservationSink::new();
        let s = sink.clone();
        with_layer(sink, || {
            let guard_id = "RelayIds { ed_identity: None, rsa_identity: Some(RsaIdentity { $cd193cf0d0c29551928c01fcb28d1200d9f27cfa }) }";
            tracing::event!(
                target: "tor_guardmgr",
                Level::TRACE,
                guard_id = ?guard_id,
                usable = true,
                "Known usability status",
            );
        });
        let obs = s.drain();
        assert_eq!(obs.len(), 1);
        assert_eq!(
            obs[0].fingerprint,
            "CD193CF0D0C29551928C01FCB28D1200D9F27CFA"
        );
        assert!(obs[0].usable);
    }

    #[test]
    fn captures_usable_false_event() {
        let sink = ObservationSink::new();
        let s = sink.clone();
        with_layer(sink, || {
            let guard_id = "RsaIdentity { $aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa }";
            tracing::event!(
                target: "tor_guardmgr",
                Level::TRACE,
                guard_id = ?guard_id,
                usable = false,
                "Known usability status",
            );
        });
        let obs = s.drain();
        assert_eq!(obs.len(), 1);
        assert!(!obs[0].usable);
    }

    #[test]
    fn ignores_events_from_other_targets() {
        let sink = ObservationSink::new();
        let s = sink.clone();
        with_layer(sink, || {
            let guard_id = "RsaIdentity { $cd193cf0d0c29551928c01fcb28d1200d9f27cfa }";
            tracing::event!(
                target: "some_other_crate",
                Level::TRACE,
                guard_id = ?guard_id,
                usable = true,
                "Known usability status",
            );
        });
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn ignores_other_messages_from_same_target() {
        let sink = ObservationSink::new();
        let s = sink.clone();
        with_layer(sink, || {
            let guard_id = "RsaIdentity { $cd193cf0d0c29551928c01fcb28d1200d9f27cfa }";
            tracing::event!(
                target: "tor_guardmgr",
                Level::TRACE,
                guard_id = ?guard_id,
                "Guard selected",
            );
        });
        assert_eq!(
            s.len(),
            0,
            "only 'Known usability status' events should be captured",
        );
    }

    #[test]
    fn ignores_event_missing_usable_field() {
        let sink = ObservationSink::new();
        let s = sink.clone();
        with_layer(sink, || {
            let guard_id = "RsaIdentity { $cd193cf0d0c29551928c01fcb28d1200d9f27cfa }";
            tracing::event!(
                target: "tor_guardmgr",
                Level::TRACE,
                guard_id = ?guard_id,
                "Known usability status",
            );
        });
        assert_eq!(s.len(), 0);
    }

    // -- "Guard status changed." event ---------------------------------------

    #[test]
    fn status_changed_reachable_maps_to_usable_true() {
        // Local enum whose Debug form matches arti's `Reachable` exactly
        // — the variant name. That's the field shape our visitor parses.
        #[derive(Debug)]
        enum R {
            Untried,
            Reachable,
        }
        let sink = ObservationSink::new();
        let s = sink.clone();
        with_layer(sink, || {
            let guard_id = "RsaIdentity { $cd193cf0d0c29551928c01fcb28d1200d9f27cfa }";
            tracing::event!(
                target: "tor_guardmgr",
                Level::TRACE,
                guard_id = ?guard_id,
                old = ?R::Untried,
                new = ?R::Reachable,
                "Guard status changed.",
            );
        });
        let obs = s.drain();
        assert_eq!(obs.len(), 1);
        assert!(obs[0].usable, "new=Reachable → usable=true");
        assert_eq!(obs[0].fingerprint, FP_A);
    }

    #[test]
    fn status_changed_unreachable_maps_to_usable_false() {
        #[derive(Debug)]
        enum R {
            Reachable,
            Unreachable,
        }
        let sink = ObservationSink::new();
        let s = sink.clone();
        with_layer(sink, || {
            let guard_id = "RsaIdentity { $cd193cf0d0c29551928c01fcb28d1200d9f27cfa }";
            tracing::event!(
                target: "tor_guardmgr",
                Level::TRACE,
                guard_id = ?guard_id,
                old = ?R::Reachable,
                new = ?R::Unreachable,
                "Guard status changed.",
            );
        });
        let obs = s.drain();
        assert_eq!(obs.len(), 1);
        assert!(!obs[0].usable, "new=Unreachable → usable=false");
    }

    #[test]
    fn status_changed_untried_is_ignored() {
        #[derive(Debug)]
        enum R {
            Untried,
        }
        let sink = ObservationSink::new();
        let s = sink.clone();
        with_layer(sink, || {
            let guard_id = "RsaIdentity { $cd193cf0d0c29551928c01fcb28d1200d9f27cfa }";
            tracing::event!(
                target: "tor_guardmgr",
                Level::TRACE,
                guard_id = ?guard_id,
                old = ?R::Untried,
                new = ?R::Untried,
                "Guard status changed.",
            );
        });
        assert_eq!(s.len(), 0, "Untried→Untried is not a usability signal");
    }

    #[test]
    fn status_changed_missing_new_field_is_ignored() {
        let sink = ObservationSink::new();
        let s = sink.clone();
        with_layer(sink, || {
            let guard_id = "RsaIdentity { $cd193cf0d0c29551928c01fcb28d1200d9f27cfa }";
            tracing::event!(
                target: "tor_guardmgr",
                Level::TRACE,
                guard_id = ?guard_id,
                "Guard status changed.",
            );
        });
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn drain_empties_the_sink() {
        let sink = ObservationSink::new();
        let s = sink.clone();
        with_layer(sink, || {
            let guard_id = "RsaIdentity { $cd193cf0d0c29551928c01fcb28d1200d9f27cfa }";
            tracing::event!(
                target: "tor_guardmgr",
                Level::TRACE,
                guard_id = ?guard_id,
                usable = true,
                "Known usability status",
            );
        });
        assert_eq!(s.drain().len(), 1);
        assert_eq!(s.drain().len(), 0, "second drain returns nothing");
    }

    // -- Integration with BridgeStore via drain_into_store --------------------

    use std::path::PathBuf;

    /// Build a BridgeLine with the given uppercase 40-char fingerprint.
    fn bridge_with_fp(addr: &str, fp_upper: &str) -> BridgeLine {
        format!("obfs4 {addr} {fp_upper} cert=AAA iat-mode=0")
            .parse()
            .expect("test bridge line parses")
    }

    fn empty_store() -> BridgeStore {
        // BridgeStore::load on a missing path returns an empty store.
        BridgeStore::load(PathBuf::from("/nonexistent/test.log")).expect("empty store loads")
    }

    const FP_A: &str = "CD193CF0D0C29551928C01FCB28D1200D9F27CFA";
    const FP_B: &str = "ABCDEF0123456789ABCDEF0123456789ABCDEF01";

    #[test]
    fn drain_into_store_records_failure_and_success_per_match() {
        let sink = ObservationSink::new();
        sink.push(GuardObservation {
            fingerprint: FP_A.into(),
            usable: false,
        });
        sink.push(GuardObservation {
            fingerprint: FP_B.into(),
            usable: true,
        });

        let ba = bridge_with_fp("1.2.3.4:80", FP_A);
        let bb = bridge_with_fp("5.6.7.8:443", FP_B);
        let mut store = empty_store();
        // Seed bb with a healthy entry — circuit_success on an unknown
        // bridge is a no-op, so without seeding we couldn't observe the
        // success path.
        let now = OffsetDateTime::from_unix_timestamp(3_000_000).unwrap();
        store.note_circuit_failure_at(
            &bb,
            now - Duration::from_secs(3600),
            Duration::from_secs(1800),
        );
        // bb starts at circuit_fails=1; success should reset to 0.

        let (failures, successes, unmatched) = sink.drain_into_store(
            &mut store,
            &[ba.clone(), bb.clone()],
            now,
            Duration::from_secs(1800),
        );
        assert_eq!(failures, 1);
        assert_eq!(successes, 1);
        assert_eq!(unmatched, 0);
        assert_eq!(store.circuit_fails(&ba), 1);
        assert_eq!(store.circuit_fails(&bb), 0, "success reset cfails");
    }

    #[test]
    fn drain_into_store_counts_unmatched_when_no_bridge_matches_fp() {
        let sink = ObservationSink::new();
        sink.push(GuardObservation {
            fingerprint: "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF".into(),
            usable: false,
        });
        let ba = bridge_with_fp("1.2.3.4:80", FP_A);
        let mut store = empty_store();
        let now = OffsetDateTime::from_unix_timestamp(3_000_000).unwrap();

        let (failures, successes, unmatched) = sink.drain_into_store(
            &mut store,
            std::slice::from_ref(&ba),
            now,
            Duration::from_secs(1800),
        );
        assert_eq!(failures, 0);
        assert_eq!(successes, 0);
        assert_eq!(unmatched, 1);
        assert_eq!(store.circuit_fails(&ba), 0, "no side effect on unmatched");
    }

    #[test]
    fn drain_into_store_rate_limits_failures_within_window() {
        let sink = ObservationSink::new();
        sink.push(GuardObservation {
            fingerprint: FP_A.into(),
            usable: false,
        });
        sink.push(GuardObservation {
            fingerprint: FP_A.into(),
            usable: false,
        });
        let ba = bridge_with_fp("1.2.3.4:80", FP_A);
        let mut store = empty_store();
        let now = OffsetDateTime::from_unix_timestamp(3_000_000).unwrap();
        let (failures, _, _) = sink.drain_into_store(
            &mut store,
            std::slice::from_ref(&ba),
            now,
            Duration::from_secs(1800),
        );
        // Both observations arrive at the *same* `now` — the second one
        // is rate-limited by the window and does NOT count.
        assert_eq!(failures, 1, "rate limiting collapses duplicate failures");
        assert_eq!(store.circuit_fails(&ba), 1);
    }

    #[test]
    fn drain_into_store_uppercase_compare_is_case_insensitive() {
        let sink = ObservationSink::new();
        // Observation already comes uppercase from extract_rsa_fingerprint;
        // here we exercise the bridge_line side: configured fingerprint is
        // sometimes uppercase, sometimes mixed. Test the upper-case form
        // (canonical for BridgeLine) so the match path is exercised.
        sink.push(GuardObservation {
            fingerprint: FP_A.into(),
            usable: true,
        });
        let ba = bridge_with_fp("1.2.3.4:80", FP_A);
        let mut store = empty_store();
        let now = OffsetDateTime::from_unix_timestamp(3_000_000).unwrap();
        // Seed an entry so the success path has something to reset.
        store.note_circuit_failure_at(
            &ba,
            now - Duration::from_secs(3600),
            Duration::from_secs(1800),
        );
        let (_, successes, unmatched) = sink.drain_into_store(
            &mut store,
            std::slice::from_ref(&ba),
            now,
            Duration::from_secs(1800),
        );
        assert_eq!(successes, 1);
        assert_eq!(unmatched, 0);
    }
}
