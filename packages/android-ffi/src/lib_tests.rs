use super::*;

fn outcome(label: &str, error: Option<&str>) -> bridge_fetcher::FetchOutcome {
    bridge_fetcher::FetchOutcome {
        label: label.to_owned(),
        bridges_extracted: 0,
        error: error.map(str::to_owned),
        bridges: Vec::new(),
    }
}

#[test]
fn dns_hints_for_lines_is_empty_when_nothing_is_cached() {
    let lines = "webtunnel 192.0.2.3:1 0123456789ABCDEF0123456789ABCDEF01234567 \
                  url=https://never-cached.example.test/x";
    assert_eq!(dns_hints_for_lines(lines), "");
}

#[test]
fn dns_hints_for_lines_is_empty_for_ip_only_bridges() {
    // obfs4 without a hostname target has nothing worth hinting at.
    let lines = "obfs4 192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0";
    assert_eq!(dns_hints_for_lines(lines), "");
}

#[test]
fn dns_hints_for_lines_finds_a_cached_webtunnel_host() {
    let host = "cached-for-export.example.test";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    bridge_probe::seed_disk_fallback(&[bridge_probe::DnsHint {
        host: host.to_owned(),
        addrs: vec!["203.0.113.77".parse().unwrap()],
        resolved_at_unix: now,
    }]);
    let lines = format!(
        "webtunnel 192.0.2.3:1 0123456789ABCDEF0123456789ABCDEF01234567 url=https://{host}/x"
    );
    let result = dns_hints_for_lines(&lines);
    assert!(
        result.starts_with(bridge_probe::DNS_HINT_PREFIX),
        "got: {result:?}"
    );
    let parsed = bridge_probe::parse_dns_hint_line(&result).expect("must parse back");
    assert_eq!(parsed.host, host);
}

#[test]
fn dns_hints_for_lines_ignores_unparseable_lines() {
    // A garbage line must not abort the whole call -- other lines still
    // get a chance.
    let lines = "not a bridge line at all\nalso garbage";
    assert_eq!(dns_hints_for_lines(lines), "");
}

#[test]
fn refresh_reports_all_source_failures() {
    let message = refresh_sources_failure(&[
        outcome("primary", Some("timeout")),
        outcome("backup", Some("403")),
    ])
    .expect("all failed sources should produce an error");
    assert!(message.contains("primary: timeout"));
    assert!(message.contains("backup: 403"));
}

#[test]
fn refresh_keeps_no_new_bridges_for_successful_sources() {
    assert!(refresh_sources_failure(&[outcome("primary", None)]).is_none());
    assert!(refresh_sources_failure(&[]).is_some());
}

#[test]
fn test_status_formatting() {
    assert_eq!(EngineStatus::Off.to_string(), "Off");
    assert_eq!(EngineStatus::Starting(50).to_string(), "Starting:50");
    assert_eq!(
        EngineStatus::On("127.0.0.1:1080".parse().unwrap()).to_string(),
        "On:127.0.0.1:1080"
    );
    assert_eq!(EngineStatus::Stopping.to_string(), "Stopping");
    assert_eq!(
        EngineStatus::Error("test error".into()).to_string(),
        "Error:test error"
    );
}

#[test]
fn test_progress_to_percent() {
    // Test the clamp and rounding logic used in status mapping
    let test_cases = [
        (-0.5f32, 0u8),
        (0.0, 0),
        (0.25, 25),
        (0.5, 50),
        (0.75, 75),
        (1.0, 100),
        (1.5, 100),
    ];

    for (fraction, expected) in test_cases {
        let clamped = fraction.clamp(0.0, 1.0);
        let percent = (clamped * 100.0).round() as u8;
        assert_eq!(percent, expected, "fraction={}", fraction);
    }
}

/// TS3-05 regression -- the core state-machine choreography: an engine that
/// is wedged on teardown (its worker thread is still parked, `done_rx` never
/// fires) must keep the slot in `Stopping`, so a parallel `nativeStart` is
/// refused both mid-stop and after the 10s join timeout, while the parked
/// handle stays available for a follow-up `nativeStop` to finish the job.
///
/// HOW the counterfactual fails: the old code's stop guard did
/// `slot.take()` -> `None` as soon as the stop began, i.e. the slot went back
/// to `Idle` (or a fresh start saw `Idle`) while the engine thread was still
/// alive -- a parallel start would then win the slot and two engines would
/// run concurrently. Here the mid-stop slot must be `Stopping(None)` and
/// every `acquire_engine_slot_for_start` until the join completes must fail.
///
/// The tests deliberately use LOCAL `EngineSlot` values, not the global
/// `ENGINE` static, so they can run in parallel with everything else.
#[test]
fn start_is_refused_until_a_parked_stop_resolves() {
    use std::sync::mpsc::RecvTimeoutError;
    use std::time::Duration;

    /// A live `EngineHandle` wired to channels the test controls: the
    /// "engine" thread parks on `release_rx` until `release_tx` is dropped,
    /// and `done_rx` only fires when the test sends on `done_tx`. No Tor,
    /// no JVM -- exactly the shape `nativeStart` builds, minus the Tor work.
    fn fake_engine_handle() -> (
        EngineHandle,
        std::sync::mpsc::Sender<()>,
        std::sync::mpsc::Sender<()>,
    ) {
        let (stop_tx, _stop_rx) = tokio::sync::watch::channel(false);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::Builder::new()
            .name("ts3-05-test-engine".into())
            .spawn(move || {
                let _ = release_rx.recv();
            })
            .expect("spawn test engine thread");
        (
            EngineHandle {
                stop_tx,
                done_rx,
                thread,
            },
            release_tx,
            done_tx,
        )
    }

    // 1. A live engine owns the slot.
    let (handle, _release_tx, done_tx) = fake_engine_handle();
    let mut slot = EngineSlot::Running(handle);

    // 2. A parallel start on the live engine is refused.
    match acquire_engine_slot_for_start(&mut slot) {
        Err(msg) => assert!(
            msg.contains("already running"),
            "expected 'already running' refusal, got: {msg:?}"
        ),
        Ok(()) => panic!("start must be refused while an engine is running"),
    }

    // 3. First nativeStop: the handle is checked out for teardown, and the
    //    slot does NOT return to Idle while the thread is still alive --
    //    this is the old bug's exact failure (`guard.take()` -> `None`).
    let handle = match begin_engine_stop(&mut slot) {
        StopHandoff::Checkout(h) => h,
        other => panic!("expected Checkout, got: {other:?}"),
    };
    assert!(
        matches!(slot, EngineSlot::Stopping(None)),
        "mid-stop slot must be Stopping(None), not Idle"
    );

    // 4. Parallel-start analogue on the mid-stop slot: refused.
    match acquire_engine_slot_for_start(&mut slot) {
        Err(msg) => assert!(
            msg.contains("still stopping"),
            "expected 'still stopping' refusal mid-stop, got: {msg:?}"
        ),
        Ok(()) => panic!("start must be refused while stopping"),
    }

    // 5. Simulate the wedged join wait without the production 10s: the
    //    engine thread has not signalled done, so the wait times out.
    match handle.done_rx.recv_timeout(Duration::from_millis(1)) {
        Err(RecvTimeoutError::Timeout) => {}
        other => panic!("expected RecvTimeoutError::Timeout, got: {other:?}"),
    }

    // 6. Post-timeout park -- what `StoppingParker`'s Drop does in
    //    production: the checked-out handle goes back into the slot.
    slot = EngineSlot::Stopping(Some(handle));

    // 7. Start is STILL refused on the parked slot.
    match acquire_engine_slot_for_start(&mut slot) {
        Err(msg) => assert!(
            msg.contains("still stopping"),
            "expected 'still stopping' refusal on parked stop, got: {msg:?}"
        ),
        Ok(()) => panic!("start must be refused while a stop is parked"),
    }

    // 8. Follow-up nativeStop re-acquires the SAME handle: nothing was
    //    lost or replaced, and the thread is still the live one.
    let handle = match begin_engine_stop(&mut slot) {
        StopHandoff::Checkout(h) => h,
        other => panic!("expected Checkout again, got: {other:?}"),
    };
    assert!(
        !handle.thread.is_finished(),
        "the re-acquired handle must still be the live engine thread"
    );

    // 9. Resolve the stop: the engine signals done and exits. The fake
    //    thread body only returns once `_release_tx` is dropped -- release
    //    it here, before joining, or the join below hangs forever.
    done_tx.send(()).expect("send done");
    assert_eq!(handle.done_rx.recv(), Ok(()), "done must fire");
    drop(_release_tx);
    handle.thread.join().expect("engine thread exits cleanly");

    // 10. Complete the stop as production does; now start succeeds.
    slot = EngineSlot::Idle;
    acquire_engine_slot_for_start(&mut slot).expect("start must succeed once the slot is Idle");
}

/// `begin_engine_stop` on an `EngineSlot::Idle` slot must be a no-op: it
/// reports `StopHandoff::Idle` (nothing to tear down) and leaves the slot
/// `Idle` -- counterfactually, an early `return` that overwrote the slot or
/// returned `InProgress` would make the caller wait forever for a teardown
/// that never started.
#[test]
fn begin_engine_stop_on_idle_slot_is_a_noop() {
    let mut slot = EngineSlot::Idle;
    let handoff = begin_engine_stop(&mut slot);
    assert!(
        matches!(handoff, StopHandoff::Idle),
        "stop on Idle must report Idle, got: {handoff:?}"
    );
    assert!(
        matches!(slot, EngineSlot::Idle),
        "stop on Idle must leave the slot Idle"
    );
}
