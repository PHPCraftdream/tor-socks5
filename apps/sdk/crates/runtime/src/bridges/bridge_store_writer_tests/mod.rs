mod backoff_tests;
mod coalescing_tests;
mod cross_process_lock_tests;
mod external_cli_tests;
mod panic_tests;
mod retirement_tests;

use super::*;
use bridge_line::BridgeLine;
use std::sync::atomic::{AtomicUsize, Ordering};
use time::OffsetDateTime;

fn test_bridge() -> BridgeLine {
    "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0"
        .parse()
        .expect("test bridge line parses")
}

fn config_path(dir: &Path) -> PathBuf {
    dir.join("tor-socks5.ktav")
}

fn seed_store(config_path: &Path, bridge: &BridgeLine) {
    let mut store =
        BridgeStore::load(BridgeStore::resolve_path(config_path)).expect("fresh store loads");
    store.note_source_at(bridge, "test", OffsetDateTime::now_utc());
    store.save().expect("seed save");
}

fn reload(config_path: &Path) -> BridgeStore {
    BridgeStore::load(BridgeStore::resolve_path(config_path)).expect("reload store")
}

fn leftover_tmp_files(dir: &Path) -> Vec<std::fs::DirEntry> {
    std::fs::read_dir(dir)
        .expect("read tempdir")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "tmp"))
        .collect()
}

/// Publisher entry signal: a watch bumped AT ENTRY of each publisher
/// invocation, before any work — so "called / started / blocked on a gate"
/// semantics are preserved for the gate tests. Watch notifications are real
/// waker events, so awaiting them is deterministic on the current-thread
/// test runtime (and works under a paused clock too).
type CallSignal = tokio::sync::watch::Sender<u64>;

fn entry_signal() -> (CallSignal, tokio::sync::watch::Receiver<u64>) {
    tokio::sync::watch::channel(0)
}

/// Wrap a publisher so each invocation bumps `signal` at entry, then runs
/// `publisher` unchanged.
fn with_entry_signal(signal: CallSignal, publisher: Publisher) -> Publisher {
    Arc::new(move |store: &BridgeStore| {
        signal.send_modify(|calls| *calls += 1);
        publisher(store)
    })
}

/// Fail-first publisher with a call counter (call 0 errors, rest save) and
/// an entry signal for deterministic waiting.
fn fail_first_publisher(calls: Arc<AtomicUsize>, signal: CallSignal) -> Publisher {
    Arc::new(move |s: &BridgeStore| {
        signal.send_modify(|n| *n += 1);
        if calls.fetch_add(1, Ordering::SeqCst) == 0 {
            Err(anyhow!("injected publish failure"))
        } else {
            s.save()
        }
    })
}

/// Await until the publisher entry signal reached `expected` invocations.
/// No timeout, no sleep: the current-thread runtime wakes the awaiting test
/// exactly when the actor/publisher runs.
async fn wait_calls(rx: &mut tokio::sync::watch::Receiver<u64>, expected: u64, what: &str) {
    while *rx.borrow_and_update() < expected {
        rx.changed().await.unwrap_or_else(|_| {
            panic!("publisher entry signal closed before {expected} calls: {what}")
        });
    }
}

/// Await the writer's settle epoch reaching `expected`: `expected` clean
/// publishes are durably on disk AND the actor has retired its snapshot
/// (`store = None`, so the next op re-reads the file). Fully deterministic
/// replacement for polling the file or sleeping after an ack.
async fn wait_settled(rx: &mut tokio::sync::watch::Receiver<u64>, expected: u64, what: &str) {
    while *rx.borrow_and_update() < expected {
        rx.changed().await.unwrap_or_else(|_| {
            panic!("writer settle signal closed before epoch {expected}: {what}")
        });
    }
}
