mod backoff_tests;
mod coalescing_tests;
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
        BridgeStore::load(BridgeStore::resolve_path(Some(config_path))).expect("fresh store loads");
    store.note_source_at(bridge, "test", OffsetDateTime::now_utc());
    store.save().expect("seed save");
}

fn reload(config_path: &Path) -> BridgeStore {
    BridgeStore::load(BridgeStore::resolve_path(Some(config_path))).expect("reload store")
}

fn leftover_tmp_files(dir: &Path) -> Vec<std::fs::DirEntry> {
    std::fs::read_dir(dir)
        .expect("read tempdir")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "tmp"))
        .collect()
}

/// Poll until the on-disk store reports `expected` channel successes for
/// `bridge`. Publishes now complete asynchronously (ack precedes the disk
/// write), so tests wait instead of asserting immediately. Uses a real
/// (non-async) sleep so paused-clock tests keep their virtual timeline
/// while the spawn_blocking publisher progresses in real time; yields
/// each iteration so the actor task (which must be polled to drain
/// `done_rx` and start a coalesced follow-up publish) actually gets to
/// run on a single-threaded test runtime, even when the caller has no
/// other `.await` between triggering the publish and this wait.
async fn wait_for_file_count(path: &Path, bridge: &BridgeLine, expected: u32, what: &str) {
    for _ in 0..5000 {
        if reload(path).channel_ok_count(bridge) == expected {
            return;
        }
        tokio::task::yield_now().await;
        std::thread::sleep(Duration::from_millis(2));
    }
    panic!("store never reached count {expected}: {what}");
}

/// Poll until the injected publisher has been called `expected` times.
/// See [`wait_for_file_count`] for why this yields every iteration.
async fn wait_for_calls(calls: &AtomicUsize, expected: usize, what: &str) {
    for _ in 0..5000 {
        if calls.load(Ordering::SeqCst) >= expected {
            return;
        }
        tokio::task::yield_now().await;
        std::thread::sleep(Duration::from_millis(2));
    }
    panic!("publisher never reached {expected} calls: {what}");
}

/// Fail-first publisher with a call counter (call 0 errors, rest save).
fn fail_first_publisher(calls: Arc<AtomicUsize>) -> Publisher {
    Arc::new(move |s: &BridgeStore| {
        if calls.fetch_add(1, Ordering::SeqCst) == 0 {
            Err(anyhow!("injected publish failure"))
        } else {
            s.save()
        }
    })
}

/// Give the actor a few real scheduling turns to retire a publish
/// completion (drop its snapshot) after the file write has been observed
/// on disk. Used in wall-clock tests only.
async fn wait_a_real_moment() {
    for _ in 0..20 {
        tokio::task::yield_now().await;
        std::thread::sleep(Duration::from_millis(2));
    }
}
