use super::*;
use tracing::Level;
use tracing_subscriber::prelude::*;

#[tokio::test]
async fn live_guard_failure_requests_recovery_with_a_preferred_route_active() {
    use futures::FutureExt;
    let refresh = crate::tor_watchdog::BridgeRefresh::default();
    refresh.set_needed(false);
    let sink = ObservationSink::new();
    sink.set_recovery_notifier(refresh.recovery());
    sink.push(GuardObservation {
        fingerprint: "1111111111111111111111111111111111111111".into(),
        usable: true,
    });
    assert!(refresh.recovery().notified().now_or_never().is_none());
    sink.push(GuardObservation {
        fingerprint: "1111111111111111111111111111111111111111".into(),
        usable: false,
    });
    assert!(refresh.recovery().notified().now_or_never().is_some());
    assert!(refresh.recovery().notified().now_or_never().is_none());
}

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
fn throwaway_runtime_cannot_change_live_guard_health() {
    use futures::FutureExt;
    let sink = ObservationSink::new();
    let recovery = Arc::new(tokio::sync::Notify::new());
    sink.set_recovery_notifier(&recovery);
    let captured = sink.clone();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let emit = || {
        let guard_id = "RsaIdentity { $aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa }";
        tracing::event!(target: "tor_guardmgr", Level::TRACE,
            guard_id = ?guard_id, usable = false, "Known usability status");
    };
    with_layer(sink, || {
        without_guard_observations(|| {
            runtime.block_on(async {
                tokio::spawn(async move {
                    emit();
                })
                .await
                .unwrap();
            })
        });
        assert!(captured.drain().is_empty());
        assert!(recovery.notified().now_or_never().is_none());
        emit();
    });
    let events = captured.drain();
    assert_eq!(
        events.len(),
        1,
        "live observations must resume after verification"
    );
    assert!(!events[0].usable);
    assert!(recovery.notified().now_or_never().is_some());
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

#[test]
fn drain_into_store_broadcasts_to_all_endpoints_sharing_a_fingerprint() {
    // Same guard, two configured addresses: a guard-level observation
    // is a signal about the GUARD, so it must reach BOTH endpoints —
    // not just whichever line happens to come last in the config.
    let ba = bridge_with_fp("1.2.3.4:80", FP_A);
    let bb = bridge_with_fp("5.6.7.8:443", FP_A);
    let now = OffsetDateTime::from_unix_timestamp(3_000_000).unwrap();
    let window = Duration::from_secs(1800);

    let sink = ObservationSink::new();
    sink.push(GuardObservation {
        fingerprint: FP_A.into(),
        usable: false,
    });
    let mut store = empty_store();
    let (failures, successes, unmatched) =
        sink.drain_into_store(&mut store, &[ba.clone(), bb.clone()], now, window);
    assert_eq!(failures, 1, "one observation counts once in the tuple");
    assert_eq!(successes, 0);
    assert_eq!(unmatched, 0);
    assert_eq!(store.circuit_fails(&ba), 1);
    assert_eq!(store.circuit_fails(&bb), 1);

    // A subsequent success resets both endpoints.
    sink.push(GuardObservation {
        fingerprint: FP_A.into(),
        usable: true,
    });
    let (failures, successes, unmatched) =
        sink.drain_into_store(&mut store, &[ba.clone(), bb.clone()], now, window);
    assert_eq!(failures, 0);
    assert_eq!(successes, 1);
    assert_eq!(unmatched, 0);
    assert_eq!(store.circuit_fails(&ba), 0, "success reset cfails");
    assert_eq!(store.circuit_fails(&bb), 0, "success reset cfails");
}

#[test]
fn drain_into_store_attribution_is_independent_of_config_line_order() {
    // THE regression test for shared-fingerprint attribution: ba and
    // bc share FP_A, bb has FP_B. Under the old last-wins map, which
    // endpoint received each observation depended on config line
    // order; under the broadcast policy it must not.
    fn run_with_order(order: [&str; 3]) -> (u32, u32, u32) {
        let ba = bridge_with_fp("1.2.3.4:80", FP_A);
        let bb = bridge_with_fp("5.6.7.8:443", FP_B);
        let bc = bridge_with_fp("9.10.11.12:80", FP_A);
        let pick = |name: &str| match name {
            "ba" => ba.clone(),
            "bb" => bb.clone(),
            _ => bc.clone(),
        };
        let lines: Vec<BridgeLine> = order.iter().map(|n| pick(n)).collect();

        let sink = ObservationSink::new();
        let mut store = empty_store();
        let window = Duration::from_secs(1800);
        let start = OffsetDateTime::from_unix_timestamp(3_000_000).unwrap();
        // One observation per maintenance cycle, one `window` apart:
        // the same-`now` rate limit must not swallow any step, so the
        // failure/success sequence lands exactly as pushed — F(A), F(B),
        // S(A), F(A) leaves each FP_A endpoint at 1 → 0 → 1.
        let steps = [
            (FP_A, false, 0u32),
            (FP_B, false, 1),
            (FP_A, true, 2),
            (FP_A, false, 3),
        ];
        for (fp, usable, cycle) in steps {
            sink.push(GuardObservation {
                fingerprint: fp.into(),
                usable,
            });
            sink.drain_into_store(&mut store, &lines, start + window * cycle, window);
        }
        (
            store.circuit_fails(&ba),
            store.circuit_fails(&bb),
            store.circuit_fails(&bc),
        )
    }

    let forward = run_with_order(["ba", "bb", "bc"]);
    let reversed = run_with_order(["bc", "bb", "ba"]);
    assert_eq!(
        forward, reversed,
        "attribution must not depend on config line order"
    );
    // Broadcast property: both FP_A endpoints share the identical
    // counter, and the post-success failure still registers once the
    // window has elapsed. Under the old last-wins map the FP_A bump
    // would have landed on a single order-dependent endpoint instead
    // (forward (0, 1, 1) vs reversed (1, 1, 0)).
    let (fa, fb, fc) = forward;
    assert_eq!(fa, fc, "shared-fingerprint endpoints share fate");
    assert_eq!(fa, 1);
    assert_eq!(fb, 1);
}

#[test]
fn observation_queue_is_bounded_and_keeps_the_most_recent_suffix() {
    let sink = ObservationSink::new();
    let total = OBSERVATION_QUEUE_CAP + 100;
    for i in 0..total {
        sink.push(GuardObservation {
            fingerprint: format!("{:040X}", i),
            usable: i % 2 == 0,
        });
        assert!(
            sink.len() <= OBSERVATION_QUEUE_CAP,
            "queue must never exceed the cap"
        );
    }
    assert_eq!(sink.len(), OBSERVATION_QUEUE_CAP, "queue is bounded");
    let drained = sink.drain();
    assert_eq!(drained.len(), OBSERVATION_QUEUE_CAP);
    // The retained suffix must be exactly the last CAP observations,
    // in original order, with the usable/failure alternation intact —
    // drop-oldest, never reordered or interleaved.
    for (i, obs) in drained.iter().enumerate() {
        assert_eq!(obs.fingerprint, format!("{:040X}", 100 + i));
        assert_eq!(obs.usable, (100 + i) % 2 == 0);
    }
}
