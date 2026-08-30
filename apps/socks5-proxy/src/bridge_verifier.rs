//! Periodic circuit-level bridge verification (background task).
//!
//! CLI counterpart of `packages/android-ffi/src/engine.rs`'s background
//! circuit-verify tick (engine.rs:1203-1266): every
//! [`CIRCUIT_VERIFY_INTERVAL`] it picks a small batch of channel-proven
//! bridges (`BridgeStore::needing_circuit_verification` — oldest/never
//! verified first, never retired), verifies each one for real end-to-end
//! reachability via a throwaway arti client
//! ([`arti_wrapper::TorTunnel::verify_bridge_reachable`]), and records the
//! successes back into the [`bridge_store::BridgeStore`]. This is what turns
//! a `channel_ok_count > 0` ("the TCP/channel layer works") observation into
//! a `verified_count > 0` observation ("a live Tor circuit through this
//! bridge actually reached the open internet") without any user action —
//! without it, the desktop CLI's store would never record end-to-end
//! verification at all.
//!
//! The verifier never touches the live tunnel or its `TorHandle`: it builds
//! entirely throwaway clients (one per bridge), so it cannot disturb the
//! egress path. It is fully self-paced by store state — a tick with an empty
//! due batch costs one small file read.
//!
//! Ported from `android-ffi`'s `verify_bridges_sequential`
//! (lib.rs:1534-1597) and `persist_circuit_verify_results`
//! (engine.rs:1825-1849); see the per-item comments below for the deliberate
//! deviations from the android original.

use std::path::{Path, PathBuf};
use std::time::Duration;

use bridge_line::BridgeLine;
use bridge_store::BridgeStore;
use time::OffsetDateTime;
use tokio::time::MissedTickBehavior;
use tracing::{info, warn};

/// Cadence of the background circuit-verify tick. Matches android's
/// `CIRCUIT_VERIFY_INTERVAL` (engine.rs:84). Deliberately long: a full check
/// (throwaway client, PT handshake, circuit build, live probe) costs real
/// Tor network resources per bridge, so it runs against a slow trickle of
/// the already channel-proven pool, not the whole pool every round.
const CIRCUIT_VERIFY_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// How many channel-proven bridges one tick checks. Matches android's
/// `CIRCUIT_VERIFY_BATCH` (engine.rs:90); the whole pool is covered
/// gradually, oldest/never-verified first.
const CIRCUIT_VERIFY_BATCH: usize = 2;

/// A bridge verified within this window is not due again yet. Matches
/// android's `CIRCUIT_VERIFY_MAX_AGE` (engine.rs:92).
const CIRCUIT_VERIFY_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// Bootstrap budget per throwaway check client — a cold descriptor fetch for
/// a never-contacted bridge needs real patience. Matches android's
/// `CIRCUIT_VERIFY_BOOTSTRAP_TIMEOUT` (engine.rs:94).
const CIRCUIT_VERIFY_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(60);

/// Live-probe budget per check. Matches android's
/// `CIRCUIT_VERIFY_PROBE_TIMEOUT` (engine.rs:96): a bridge that times out
/// here simply stays due and is retried next tick, so there is no reason to
/// chase the worst-case patience a user actively watching a scan result
/// needs.
const CIRCUIT_VERIFY_PROBE_TIMEOUT: Duration = Duration::from_secs(90);

/// How long each per-bridge throwaway tokio runtime gets to drain after its
/// check, before the verifier moves on. Matches android's
/// `VERIFY_BRIDGE_RUNTIME_SHUTDOWN_GRACE` (lib.rs:1459-1463).
const VERIFY_RUNTIME_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Host the check client's exit circuit must reach live. Matches android's
/// `LIVE_PROBE_TARGET`/`LIVE_PROBE_PORT` (engine.rs:756-757): a plain HTTPS
/// endpoint that answers a real Tor circuit, not a local socket.
const LIVE_PROBE_TARGET: &str = "check.torproject.org";
const LIVE_PROBE_PORT: u16 = 443;

/// Spawn the detached background circuit-verify task.
///
/// Deliberately differs from android's engine on the *first* tick: android's
/// tick is due immediately, but at CLI boot the main client is still
/// bootstrapping and the channel-proven pool is empty anyway, so the first
/// interval is consumed (same pattern as `spawn_bridge_warmer` /
/// `spawn_bridge_maintenance`) and checks only start one interval in.
pub(crate) fn spawn_bridge_circuit_verifier(config_path: Option<PathBuf>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(CIRCUIT_VERIFY_INTERVAL);
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        tick.tick().await; // consume the immediate first tick (see doc above)

        loop {
            tick.tick().await;
            run_circuit_verify_tick(config_path.as_deref()).await;
        }
    });
}

/// One tick: pick the due batch, verify it, persist the results.
async fn run_circuit_verify_tick(config_path: Option<&Path>) {
    let due = match BridgeStore::load(BridgeStore::resolve_path(config_path)) {
        Ok(store) => store.needing_circuit_verification(
            OffsetDateTime::now_utc(),
            CIRCUIT_VERIFY_MAX_AGE,
            CIRCUIT_VERIFY_BATCH,
        ),
        Err(error) => {
            warn!(error = %error, "circuit-verify: failed to load bridge store");
            return;
        }
    };
    if due.is_empty() {
        return; // cheap tick
    }

    // Only resolve the PT binary when the batch actually needs one — the
    // resolver inspects the current executable / env and is not free.
    let pt_binary = if due.iter().any(|b| b.transport.is_some()) {
        match crate::tor_setup::resolve_pt_binary() {
            Ok(pt) => Some(pt),
            Err(error) => {
                warn!(error = %error, "circuit-verify: could not resolve PT binary");
                return;
            }
        }
    } else {
        None
    };

    // The live client's cache dir, derived from the same base dir
    // `build_tor_settings` uses (see `tor_setup::arti_base_dir`), so the
    // snapshot below is always taken from the client that is actually
    // running. Must stay in sync — hence the shared helper.
    let live_cache_dir = crate::tor_setup::arti_base_dir(config_path).join("cache");
    let scratch_base =
        std::env::temp_dir().join(format!("torsocks5-circuit-verify-{}", std::process::id()));

    // `verify_bridges_sequential` blocks its calling thread (it builds and
    // drives its own throwaway per-bridge tokio runtimes internally), so it
    // must run off this runtime's async worker threads.
    let results = tokio::task::spawn_blocking(move || {
        let mut results = Vec::new();
        verify_bridges_sequential(
            &live_cache_dir,
            &scratch_base,
            due,
            pt_binary,
            CIRCUIT_VERIFY_BOOTSTRAP_TIMEOUT,
            CIRCUIT_VERIFY_PROBE_TIMEOUT,
            |bridge, result| results.push((bridge.clone(), result.is_ok())),
        );
        let _ = std::fs::remove_dir_all(&scratch_base);
        results
    })
    .await
    .unwrap_or_default();

    let verified = results.iter().filter(|(_, ok)| *ok).count();
    info!(
        checked = results.len(),
        verified, "circuit-verify: tick complete"
    );
    persist_circuit_verify_results(&results, config_path);
}

/// Recursively copies every regular file under `src` into `dest` (creating
/// directories as needed). Ported verbatim from android-ffi's
/// `snapshot_cache_dir` (lib.rs:1482-1497). Used to snapshot the live
/// client's directory cache for [`verify_bridges_sequential`] — a snapshot,
/// not the live directory, is what a throwaway check client gets: tor-dirmgr
/// storage is a single sqlite file, and a second client opening the live one
/// contends with the main client's routine writes (`SQLITE_BUSY`), while a
/// one-time copy both avoids that contention and still skips the cold
/// consensus fetch. Best-effort: any I/O error simply means the caller falls
/// back to no shared cache for this batch, not a hard failure.
fn snapshot_cache_dir(src: &Path, dest: &Path) -> bool {
    fn copy_recursive(src: &Path, dest: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dest)?;
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let dest_path = dest.join(entry.file_name());
            if entry.file_type()?.is_dir() {
                copy_recursive(&entry.path(), &dest_path)?;
            } else {
                std::fs::copy(entry.path(), &dest_path)?;
            }
        }
        Ok(())
    }
    copy_recursive(src, dest).is_ok()
}

/// Verifies each of `bridges` for real end-to-end reachability, sequentially,
/// sharing one cache-dir snapshot taken once up front from `live_cache_dir`
/// (if it exists). Calls `on_result` as each bridge's check completes, with
/// `Err` carrying a human-readable reason.
///
/// Ported from android-ffi's `verify_bridges_sequential` (lib.rs:1534-1597),
/// keeping its hard-won structure:
///
/// - **One throwaway tokio runtime *per bridge*, explicitly shut down right
///   after** ([`VERIFY_RUNTIME_SHUTDOWN_GRACE`]). `arti_client::TorClient::
///   bootstrap` spawns long-lived background tasks onto whatever runtime it
///   is given; with one shared runtime for the whole batch, every checked
///   bridge's `libtorpthelper` child would leak until the entire batch
///   finished (android lib.rs:1553-1573 doc).
/// - **A cache snapshot, not the live directory** — see
///   [`snapshot_cache_dir`].
///
/// Ported: android's `pt_reap` child-kill helper (lib.rs:1599-1660), now as
/// the Win32-based [`pt_reap`] module below. It exists because `tor-ptmgr`
/// 0.43's graceful-shutdown thread is a plain OS thread blocked in a
/// synchronous read of the PT child's stdout, so an idle PT child is never
/// noticed or terminated. Here the child is our own binary re-invoked with
/// `TOR_PT_MANAGED_TRANSPORT_VER`, and it survives every throwaway client's
/// drop and runtime shutdown. The process-wide Job Object only fires at
/// whole-process exit, so it cannot bound per-tick growth in a long-lived
/// service (production: 22 orphaned processes after ~13h, 1-2 per tick). The
/// snapshot-before/diff-and-kill-after pairing per bridge check is narrow by
/// construction: the main engine's own long-lived PT predates the baseline
/// and is never a candidate.
#[cfg(windows)]
mod pt_reap {
    use std::collections::HashSet;

    /// PIDs of live children of this process, read from the Win32 process
    /// snapshot. Like /proc on Linux, the process tree has no concept of
    /// "which logical client spawned this" — every child of our own PID shows
    /// up here regardless of which throwaway `TorTunnel` (or the long-lived
    /// main engine) started it, which is why callers snapshot this immediately
    /// before their own check and diff against a fresh snapshot after, rather
    /// than trusting any single call's result alone.
    pub(crate) fn own_child_pids() -> HashSet<u32> {
        use std::mem::{size_of, zeroed};

        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };
        use windows_sys::Win32::System::Threading::GetCurrentProcessId;

        // SAFETY: CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) per its
        // documented contract takes a snapshot of every process on the system;
        // INVALID_HANDLE_VALUE means failure and there is nothing to clean up.
        // Best-effort, like android's /proc read-failure path: return empty.
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot.is_null() || snapshot == INVALID_HANDLE_VALUE {
            return HashSet::new();
        }

        let mut children = HashSet::new();
        // SAFETY: `entry` is a fully-initialized PROCESSENTRY32W (the all-zero
        // bit pattern from `zeroed()` is valid — all fields are integers or
        // fixed-size arrays), with dwSize set to its exact size before the
        // first Process32FirstW call, as the contract requires.
        let mut entry: PROCESSENTRY32W = unsafe { zeroed() };
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;

        // SAFETY: Process32FirstW/Process32NextW iterate the snapshot handle
        // from CreateToolhelp32Snapshot above, filling `entry` (dwSize kept
        // set) until Next reports there are no more entries.
        unsafe {
            if Process32FirstW(snapshot, &mut entry) != 0 {
                let my_pid = GetCurrentProcessId();
                loop {
                    if entry.th32ParentProcessID == my_pid {
                        children.insert(entry.th32ProcessID);
                    }
                    if Process32NextW(snapshot, &mut entry) == 0 {
                        break;
                    }
                }
            }

            // SAFETY: `snapshot` is a live handle we own from
            // CreateToolhelp32Snapshot; unlike shutdown.rs's job object it is
            // not meant to leak, so close it when done iterating.
            CloseHandle(snapshot);
        }
        children
    }

    /// Kills (`TerminateProcess`) every currently-live child not present in
    /// `baseline`. Narrow by construction, not by filtering on process name:
    /// a caller that snapshots `baseline` immediately before its own check,
    /// and calls this immediately after, only ever sees its own check's child
    /// as "new" — the main engine's own long-lived PT child was already
    /// running before the snapshot and is therefore never a candidate.
    pub(crate) fn kill_new_children(baseline: &HashSet<u32>) {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, TerminateProcess, PROCESS_TERMINATE,
        };

        for pid in own_child_pids() {
            if baseline.contains(&pid) {
                continue;
            }
            // SAFETY: `pid` was just observed as our own child in a fresh
            // snapshot; we only ask for PROCESS_TERMINATE. A null return means
            // the process already exited between the snapshots — that is the
            // expected race, and failure is not an error worth surfacing: the
            // end state either way is "not running". Otherwise we terminate
            // with an arbitrary non-zero exit code (matching android's
            // SIGKILL) and close the handle we opened.
            let handle = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
            if handle.is_null() {
                continue;
            }
            unsafe {
                TerminateProcess(handle, 1);
                CloseHandle(handle);
            }
            tracing::info!(pid, "circuit-verify: killed leaked PT child process");
        }
    }
}

/// Non-Windows stub: mirrors android-ffi's non-android stub. Host builds
/// (`cargo test`) never spawn a real PT child, so there is nothing to reap.
/// See the `#[cfg(windows)]` module above for the Win32 implementation and
/// `packages/android-ffi/src/lib.rs` (`#[cfg(target_os = "android")]`) for
/// the original.
#[cfg(not(windows))]
mod pt_reap {
    use std::collections::HashSet;

    pub(crate) fn own_child_pids() -> HashSet<u32> {
        HashSet::new()
    }

    pub(crate) fn kill_new_children(_baseline: &HashSet<u32>) {}
}

pub(crate) fn verify_bridges_sequential(
    live_cache_dir: &Path,
    scratch_base: &Path,
    bridges: Vec<BridgeLine>,
    pt_binary: Option<PathBuf>,
    bootstrap_timeout: Duration,
    probe_timeout: Duration,
    mut on_result: impl FnMut(&BridgeLine, Result<Duration, String>),
) {
    let cache_snapshot = scratch_base.join("cache-snapshot");
    let cache_dir = (live_cache_dir.is_dir()
        && snapshot_cache_dir(live_cache_dir, &cache_snapshot))
    .then_some(cache_snapshot);

    for (idx, bridge) in bridges.into_iter().enumerate() {
        if bridge.transport.is_some() && pt_binary.is_none() {
            on_result(
                &bridge,
                Err("bridge requires a pluggable transport, but none is available".to_owned()),
            );
            continue;
        }

        let check_dir = scratch_base.join(idx.to_string());
        if let Err(e) = std::fs::create_dir_all(&check_dir) {
            on_result(
                &bridge,
                Err(format!("could not create scratch directory: {e}")),
            );
            continue;
        }

        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                on_result(&bridge, Err(format!("failed to create runtime: {e}")));
                let _ = std::fs::remove_dir_all(&check_dir);
                continue;
            }
        };

        let check = arti_wrapper::BridgeCheckSettings {
            bridge: bridge.clone(),
            pt_binary: pt_binary.clone(),
            cache_dir: cache_dir.clone(),
            state_dir: check_dir.clone(),
        };
        let baseline_children = pt_reap::own_child_pids();
        let result = rt.block_on(arti_wrapper::TorTunnel::verify_bridge_reachable(
            check,
            (LIVE_PROBE_TARGET, LIVE_PROBE_PORT),
            bootstrap_timeout,
            probe_timeout,
        ));
        rt.shutdown_timeout(VERIFY_RUNTIME_SHUTDOWN_GRACE);
        pt_reap::kill_new_children(&baseline_children);

        on_result(&bridge, result.map_err(|e| e.to_string()));
        let _ = std::fs::remove_dir_all(&check_dir);
    }
}

/// Persist the tick's results. Ported from android's
/// `persist_circuit_verify_results` (engine.rs:1825-1849) with ONE deliberate
/// deviation: on success BOTH `note_circuit_verified_at` AND
/// `note_circuit_success_at` are recorded.
///
/// Why the double call: `note_circuit_verified_at` only bumps
/// `verified_count` and stamps `last_verified` — it never resets
/// `circuit_fails`. Bridges punished by the Phase 1 failover signaler
/// (`tor_watchdog.rs`) would therefore have no rehabilitation path at all.
/// `note_circuit_success_at` is the existing reset primitive (the same one
/// the passive circuit observer uses in `arti_observability.rs`), so a
/// verified bridge gets its `circuit_fails` back to 0. Android doesn't need
/// this because its failover machinery differs.
///
/// As on android, failures are deliberately not recorded: a single timeout is
/// routine rather than proof the bridge is bad, so a failed check simply
/// leaves the bridge due for the next tick instead of demoting it.
fn persist_circuit_verify_results(results: &[(BridgeLine, bool)], config_path: Option<&Path>) {
    if results.is_empty() {
        return;
    }
    let path = BridgeStore::resolve_path(config_path);
    let mut store = match BridgeStore::load(path) {
        Ok(store) => store,
        Err(error) => {
            warn!(error = %error, "circuit-verify: could not load bridge health store");
            return;
        }
    };
    let now = OffsetDateTime::now_utc();
    for (bridge, ok) in results {
        if *ok {
            store.note_circuit_verified_at(bridge, now);
            store.note_circuit_success_at(bridge, now);
        }
    }
    if let Err(error) = store.save() {
        warn!(error = %error, "circuit-verify: could not persist results");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration as StdDuration;

    #[test]
    fn own_child_pids_never_contains_self() {
        assert!(!pt_reap::own_child_pids().contains(&std::process::id()));
    }

    fn seed_failed_bridge(dir: &Path, bridge: &BridgeLine) -> Option<PathBuf> {
        let config_path = Some(dir.join("tor-socks5.ktav"));
        let mut store = BridgeStore::load(BridgeStore::resolve_path(config_path.as_deref()))
            .expect("load fresh store");
        let t0 = OffsetDateTime::now_utc();
        // Inserts the (unknown) bridge with `circuit_fails = 1`.
        store.note_circuit_failure_at(bridge, t0, StdDuration::from_secs(60));
        store.note_channel_success_at(bridge, t0);
        store.save().expect("save store");
        config_path
    }

    /// The critical behavioral pin: a successful verification must both
    /// record the verification stamp AND reset the circuit-failure counter
    /// (the double call in `persist_circuit_verify_results`), while leaving
    /// the channel-success signal untouched.
    #[test]
    fn verified_bridge_resets_circuit_fails_and_records_verification() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bridge: BridgeLine = "1.2.3.4:9101 DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"
            .parse()
            .expect("bridge line");
        let config_path = seed_failed_bridge(dir.path(), &bridge);

        persist_circuit_verify_results(&[(bridge.clone(), true)], config_path.as_deref());

        let store = BridgeStore::load(BridgeStore::resolve_path(config_path.as_deref()))
            .expect("reload store");
        assert_eq!(store.verified_count(&bridge), 1, "verification recorded");
        assert_eq!(store.circuit_fails(&bridge), 0, "circuit_fails reset");
        assert_eq!(
            store.channel_ok_count(&bridge),
            1,
            "channel signal untouched"
        );
    }

    /// Android parity: a failed check records nothing — the bridge simply
    /// stays due, with its failure counters exactly as they were.
    #[test]
    fn failed_verification_changes_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bridge: BridgeLine = "5.6.7.8:9103 FEEDFACEFEEDFACEFEEDFACEFEEDFACEFEEDFACE"
            .parse()
            .expect("bridge line");
        let config_path = seed_failed_bridge(dir.path(), &bridge);

        persist_circuit_verify_results(&[(bridge.clone(), false)], config_path.as_deref());

        let store = BridgeStore::load(BridgeStore::resolve_path(config_path.as_deref()))
            .expect("reload store");
        assert_eq!(store.circuit_fails(&bridge), 1, "circuit_fails unchanged");
        assert_eq!(store.verified_count(&bridge), 0, "no verification recorded");
    }

    #[test]
    fn snapshot_cache_dir_copies_files_recursively() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("src");
        std::fs::create_dir_all(src.join("a/b")).expect("mkdir");
        std::fs::write(src.join("top.txt"), b"top").expect("write");
        std::fs::write(src.join("a/b/deep.txt"), b"deep").expect("write");

        let dest = dir.path().join("dest");
        assert!(snapshot_cache_dir(&src, &dest));
        assert_eq!(
            std::fs::read(dest.join("top.txt")).expect("read top"),
            b"top"
        );
        assert_eq!(
            std::fs::read(dest.join("a/b/deep.txt")).expect("read deep"),
            b"deep"
        );
    }

    #[test]
    fn snapshot_cache_dir_fails_on_missing_source() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("dest");
        assert!(!snapshot_cache_dir(
            &dir.path().join("does-not-exist"),
            &dest
        ));
    }
}
