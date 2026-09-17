use crate::dns::{dns_load_thread_recorded, load_persisted_dns_cache_async};

/// TS19-01: the async wrapper must run the (blocking) DNS cache load on
/// Tokio's blocking pool, never on the caller's async thread. The seam in
/// `dns.rs` records the thread that actually executed the load; an inline
/// call would necessarily record the caller's own thread, because there is
/// no `.await` between the wrapper's entry and the blocking work.
///
/// Note on discriminators: `tokio::task::try_id()` looks like the natural
/// check and is wrong here — `spawn_blocking` wraps the closure in a
/// `BlockingTask` future polled as a real task, so a task id is present on
/// the blocking pool too. Thread identity is what actually separates them.
#[tokio::test]
async fn load_persisted_dns_cache_async_runs_off_the_caller_thread() {
    let _dns_serial = super::DNS_GLOBAL_TEST_LOCK.lock().await;

    // Missing file is fine: the load still runs and the seam still records.
    let path =
        std::env::temp_dir().join(format!("dns-load-async-missing-{}.txt", std::process::id()));

    let caller_thread = std::thread::current().id();
    load_persisted_dns_cache_async(&path).await;

    let ran_on = dns_load_thread_recorded().expect("the load must have been executed");
    assert_ne!(
        ran_on, caller_thread,
        "load_persisted_dns_cache_async must execute the blocking load off the caller's thread"
    );
}
