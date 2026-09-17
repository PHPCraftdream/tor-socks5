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
use std::sync::Mutex;
use std::time::Duration;

use bridge_line::BridgeLine;
use bridge_store::BridgeStore;
use time::OffsetDateTime;
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;
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
const LIVE_PROBE_URL: &str = "https://check.torproject.org/api/ip";
static VERIFY_LOCK: Mutex<()> = Mutex::new(());

pub(crate) fn confirms_tor(body: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("IsTor").and_then(serde_json::Value::as_bool))
        == Some(true)
}

/// Registry of admission-verification workers whose owning decision already
/// returned. TS17-02: the admission decision has a deadline, but the blocking
/// worker behind it cannot be cancelled — dropping its `spawn_blocking`
/// `JoinHandle` would detach it (rust-intel §B21), letting it keep
/// `VERIFY_LOCK` and copy files while the caller has already released the
/// candidate-pool lock and moved on. So `verify_for_admission` registers
/// every worker here synchronously right after spawn — before any `.await`,
/// so cancellation cannot separate the two — and the drain joins the whole
/// registry (`join_all`) once the pool transaction is done, OUTSIDE the pool
/// lock: worker completion is mandatory, but it must not extend the pool
/// transaction (that would re-open the long pool-lock hold R-09 removed).
///
/// The join is deliberately unbounded: every phase of the worker is
/// internally bounded by the decision deadline (VERIFY_LOCK wait; snapshot,
/// which now honors the same deadline between copy steps; bootstrap/probe
/// within their own per-check budgets; runtime shutdown within its grace),
/// so the join always terminates — a hang here is a bug this join surfaces
/// instead of hiding. A worker that starts late (blocking-pool queue) finds
/// the deadline already expired and exits fast.
///
/// Residual scope: if the drain task itself is ABORTED before `join_all`
/// runs, the handles drop and the workers detach — the reviewed timeout path
/// no longer does this, and such a worker still finishes and cleans up via
/// RAII (temp dir, lock guard); it is merely no longer observed.
#[derive(Default)]
pub(crate) struct AdmissionWorkers {
    handles: Mutex<Vec<tokio::task::JoinHandle<anyhow::Result<bool>>>>,
}

impl AdmissionWorkers {
    /// Registers a freshly spawned worker. Synchronous on purpose: must run
    /// before the spawning future can be cancelled.
    pub(crate) fn track(&self, handle: tokio::task::JoinHandle<anyhow::Result<bool>>) {
        self.handles
            .lock()
            .unwrap_or_else(|error| {
                self.handles.clear_poison();
                error.into_inner()
            })
            .push(handle);
    }

    /// Waits for every tracked worker to completion, in spawn order. A
    /// failed or panicked worker is logged, not propagated — it only means
    /// its candidate was not verified.
    pub(crate) async fn join_all(&self) {
        let handles: Vec<_> = {
            let mut handles = self.handles.lock().unwrap_or_else(|error| {
                self.handles.clear_poison();
                error.into_inner()
            });
            std::mem::take(&mut *handles)
        };
        for handle in handles {
            match handle.await {
                Ok(Ok(verified)) => {
                    tracing::debug!(verified, "circuit-verify: admission worker joined");
                }
                Ok(Err(error)) => {
                    warn!(error = %error, "circuit-verify: admission worker failed");
                }
                Err(join_error) => {
                    warn!(error = %join_error, "circuit-verify: admission worker panicked");
                }
            }
        }
    }
}

/// Runs the blocking verifier for one admission decision, split into two
/// deadlines (TS17-02):
///
/// - `deadline` bounds the DECISION: when it passes, this returns `Ok(false)`
///   and the caller defers the candidate — but the worker behind the decision
///   keeps running, owned by `workers` until `join_all` is awaited.
/// - worker COMPLETION gets no deadline of its own: every worker phase is
///   internally bounded by `deadline` (see [`AdmissionWorkers`]), so
///   completion follows shortly after without anyone waiting on it under the
///   pool lock.
///
/// The `JoinHandle` is never dropped: it is registered with `workers`
/// synchronously after spawn (before the first `.await`, so cancellation
/// cannot orphan the worker), and the decision is consumed from a oneshot
/// instead. A oneshot send to an already-timed-out decision is a legitimate
/// best-effort drop — the receiver vanished exactly because the decision
/// deadline expired, and the full result still travels through the joined
/// handle.
///
/// cancel-safe: yes — cancellation after `track()` leaves the worker owned
/// by `workers`; nothing is lost by dropping this future mid-`await`.
pub(crate) async fn verify_for_admission(
    bridge: BridgeLine,
    config_path: Option<PathBuf>,
    deadline: std::time::Instant,
    workers: &AdmissionWorkers,
) -> anyhow::Result<bool> {
    let live_cache = crate::tor_setup::arti_base_dir(config_path.as_deref()).join("cache");
    let (decision_tx, decision_rx) = tokio::sync::oneshot::channel();
    let worker = tokio::task::spawn_blocking(move || {
        let verified = admission_verification(bridge, live_cache, deadline);
        // Best-effort: the decision receiver is gone once the decision
        // deadline expired; the joined handle still carries the result.
        let _ = decision_tx.send(verified.as_ref().is_ok_and(|verified| *verified));
        verified
    });
    workers.track(worker);

    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    match tokio::time::timeout(remaining, decision_rx).await {
        Ok(Ok(verified)) => Ok(verified),
        // The worker died without sending a decision (e.g. it panicked and
        // the sender was dropped with it).
        Ok(Err(_)) => Err(anyhow::anyhow!(
            "admission verifier worker ended without a decision"
        )),
        // Decision deadline: the candidate is deferred by the caller; the
        // worker stays tracked and is joined outside the pool transaction.
        Err(_elapsed) => Ok(false),
    }
}

/// The blocking body of one admission verification. `Err` means "not
/// verified" and reaches both the decision (via the oneshot) and the join
/// log (via the registry's handle). Resolving the PT binary here keeps sync
/// path probing off the async caller and turns a resolution failure into a
/// normal worker error.
fn admission_verification(
    bridge: BridgeLine,
    live_cache: PathBuf,
    deadline: std::time::Instant,
) -> anyhow::Result<bool> {
    let scratch = tempfile::Builder::new()
        .prefix("tor-socks5-admission-")
        .tempdir()?;
    let pt = Some(crate::tor_setup::resolve_pt_binary()?);
    let mut verified = false;
    verify_bridges_sequential(
        &live_cache,
        scratch.path(),
        vec![bridge],
        pt,
        CIRCUIT_VERIFY_BOOTSTRAP_TIMEOUT,
        CIRCUIT_VERIFY_PROBE_TIMEOUT,
        Some(deadline),
        |_, result| verified = result.is_ok(),
    );
    // Test-visible completion event, set by the worker itself (NOT the
    // caller) after `verify_bridges_sequential` returned — i.e. after its
    // VERIFY_LOCK guard was dropped.
    #[cfg(test)]
    crate::test_seams::mark_worker_done(
        crate::test_seams::Site::AdmissionVerifyPostLock,
        &live_cache,
    );
    Ok(verified)
}

/// Spawn the background circuit-verify task, returning its join handle for the shutdown join.
///
/// Deliberately differs from android's engine on the *first* tick: android's
/// tick is due immediately, but at CLI boot the main client is still
/// bootstrapping and the channel-proven pool is empty anyway, so the first
/// interval is consumed (same pattern as `spawn_bridge_warmer` /
/// `spawn_bridge_maintenance`) and checks only start one interval in.
///
/// Shutdown: the `token` is selected against before every tick, so no new
/// verification batch starts after cancellation; a batch already in flight (a
/// non-cancellable `spawn_blocking` job) runs to completion and its results are
/// persisted before the caller joins the handle and closes the bridge-store
/// writer.
pub(crate) fn spawn_bridge_circuit_verifier(
    config_path: Option<PathBuf>,
    handle: crate::tor_watchdog::TorHandle,
    token: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(CIRCUIT_VERIFY_INTERVAL);
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        tick.tick().await; // consume the immediate first tick (see doc above)

        loop {
            tokio::select! {
                biased;
                _ = token.cancelled() => break,
                _ = tick.tick() => {},
            }
            run_circuit_verify_tick(config_path.as_deref(), &handle.active_bridges()).await;
        }
    })
}

/// One tick: pick the due batch, verify it, persist the results.
async fn run_circuit_verify_tick(config_path: Option<&Path>, active: &[BridgeLine]) {
    let due = match BridgeStore::load(BridgeStore::resolve_path(config_path)) {
        Ok(store) => store.needing_circuit_verification(
            OffsetDateTime::now_utc(),
            CIRCUIT_VERIFY_MAX_AGE,
            CIRCUIT_VERIFY_BATCH,
            // Filter to the currently-active set BEFORE bounded selection: ranking
            // the whole due pool down to the batch first could fill the batch with
            // inactive bridges and starve the actives.
            |bridge| active.contains(bridge),
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
            None,
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
    persist_circuit_verify_results(&results, config_path).await;
}

/// Thin delegate to the shared implementation in `bridge-verify-core`, keeping
/// this crate's historical `"circuit-verify: "` log prefix. See the shared
/// `snapshot_cache_dir` doc for the full contract.
fn snapshot_cache_dir(src: &Path, dest: &Path, deadline: Option<std::time::Instant>) -> bool {
    bridge_verify_core::snapshot::snapshot_cache_dir(src, dest, "circuit-verify: ", deadline)
}

/// Verifies each of `bridges` for real end-to-end reachability, sequentially,
/// sharing one cache-dir snapshot taken once up front from `live_cache_dir`
/// (if it exists). Calls `on_result` as each bridge's check completes, with
/// `Err` carrying a human-readable reason.
///
/// `max_deadline` bounds verifier-lock wait and all per-bridge work when the
/// caller has a transaction lock that must not be held through an unbounded
/// verification. `None` keeps the normal background verifier budgets.
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
/// service (production: 22 orphaned processes after ~13h, 1-2 per tick).
///
/// The kill is ownership-based, not time-of-appearance-based: before the
/// batch, [`pt_reap::create_kill_marker`] makes a per-batch uniquely named
/// executable copy of the PT binary (hard link where the volume allows,
/// copy otherwise) and registers its file name in a module-level FIFO
/// registry. The check is launched with that copy as its `pt_binary`, so
/// whatever PT child `tor-ptmgr` spawns from it is identifiable by exe
/// file name alone; after each check [`pt_reap::kill_marked_children`]
/// terminates only own children whose exe name matches a registered
/// marker. An earlier version snapshotted child PIDs before each check
/// and killed anything "new" after — but the main engine's PT transport
/// (also spawned by tor-ptmgr inside this process) can RESTART inside
/// the check window and would then appear "new" and get killed, taking
/// the user's live tunnels down with the cleanup. A restarted main PT
/// child has the normal exe name and can never match a marker. See
/// `docs/stability-review-2026-09-08.md` section 2.
///
/// Deliberate tradeoffs: the marker copy costs one file link/copy per
/// batch (cheap, and the scratch dir is wiped with the batch); the
/// registry never shrinks mid-process so children that escaped their own
/// call's kill keep getting reaped by later calls (capped at 128 names,
/// FIFO); and a `%TEMP%` marker file may occasionally survive if a child
/// could not be terminated and the file is locked — cleanup is
/// best-effort with ignored errors.
#[cfg(windows)]
mod pt_reap {
    use std::collections::{HashMap, HashSet};
    use std::path::Path;

    // The marker registry (statics, FIFO cap, registration) and the pure
    // kill decision live in `bridge-verify-core::pt_reap`; this module keeps
    // only the Win32 platform parts: the Toolhelp32 snapshot, the marker
    // file creation (Windows `pt-{:016x}.exe` naming, hard link with copy
    // fallback), and the `TerminateProcess` sweep.

    /// Creates a uniquely named executable copy of `pt_binary` inside
    /// `scratch_base` (which must already exist) and registers its file
    /// name. Hard link first (cheap, same-volume case), fall back to a full
    /// copy. Returns the marker FILE NAME (not the path) on success, None
    /// on any failure — callers must treat None as "leak reaping disabled
    /// for this batch", never as "fall back to diff-based killing".
    pub(crate) fn create_kill_marker(pt_binary: &Path, scratch_base: &Path) -> Option<String> {
        let marker_name = format!(
            "pt-{:016x}.exe",
            bridge_verify_core::pt_reap::unique_marker_bits()
        );
        let marker_path = scratch_base.join(&marker_name);
        let created = std::fs::hard_link(pt_binary, &marker_path)
            .or_else(|_| std::fs::copy(pt_binary, &marker_path).map(|_| ()));
        if let Err(error) = created {
            tracing::warn!(%error, marker = %marker_name,
                "circuit-verify: could not create PT kill marker; \
                 leaked-child reaping disabled for this batch");
            return None;
        }
        Some(bridge_verify_core::pt_reap::register_kill_marker(
            marker_name,
        ))
    }

    /// Snapshot of the currently registered marker names (test-visible via
    /// `pub(crate)`); the registry itself is shared, in
    /// `bridge-verify-core::pt_reap`.
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn current_markers() -> HashSet<String> {
        bridge_verify_core::pt_reap::current_markers()
    }

    /// Live children of this process as (pid, exe-file-name) pairs, read
    /// from the Win32 process snapshot. Like /proc on Linux, the process
    /// tree has no concept of "which logical client spawned this" — every
    /// child of our own PID shows up here regardless of which throwaway
    /// `TorTunnel` (or the long-lived main engine) started it. Ownership is
    /// therefore established by the exe file name (see [`create_kill_marker`]).
    fn own_children_with_names() -> HashMap<u32, String> {
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
            return HashMap::new();
        }

        let mut children = HashMap::new();
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
                        let len = entry
                            .szExeFile
                            .iter()
                            .position(|&unit| unit == 0)
                            .unwrap_or(entry.szExeFile.len());
                        children.insert(
                            entry.th32ProcessID,
                            String::from_utf16_lossy(&entry.szExeFile[..len]),
                        );
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

    /// PIDs of live children of this process. Test-only: production code
    /// identifies ownership via [`create_kill_marker`]/[`kill_marked_children`].
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn own_child_pids() -> HashSet<u32> {
        own_children_with_names().into_keys().collect()
    }

    /// Terminates every currently-live own child whose exe file name matches
    /// a registered kill marker (see [`create_kill_marker`]). A no-op while
    /// the registry is empty. Deliberately name-verified, not
    /// time-of-appearance-verified: the main engine's PT child — however
    /// freshly restarted — carries the normal exe name and can never match.
    pub(crate) fn kill_marked_children() {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            GetCurrentProcessId, OpenProcess, TerminateProcess, PROCESS_TERMINATE,
        };

        // The snapshot only yields own children, so each child's ppid is
        // `my_pid`; names and marker names are both normalized to lowercase
        // bytes so the shared decision's exact byte match equals the former
        // case-insensitive comparison (marker names are generated lowercase).
        let markers: HashSet<Vec<u8>> = bridge_verify_core::pt_reap::current_markers()
            .into_iter()
            .map(|marker| marker.to_ascii_lowercase().into_bytes())
            .collect();
        if markers.is_empty() {
            return;
        }
        // SAFETY: GetCurrentProcessId takes no arguments and cannot fail.
        let my_pid = unsafe { GetCurrentProcessId() };
        let targets = bridge_verify_core::pt_reap::kill_targets(
            own_children_with_names()
                .into_iter()
                .map(|(pid, exe)| (pid, my_pid, exe.to_ascii_lowercase().into_bytes())),
            my_pid,
            &markers,
        );

        for pid in targets {
            // SAFETY: `pid` was just observed as our own child in a fresh
            // snapshot AND its exe name matches one of the marker copies we
            // created ourselves; we only ask for PROCESS_TERMINATE. A null
            // return means the process already exited between the snapshot
            // and here — that is the expected race, and failure is not an
            // error worth surfacing: the end state either way is "not
            // running". Otherwise we terminate with an arbitrary non-zero
            // exit code (matching android's SIGKILL) and close the handle
            // we opened.
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
/// `bridge-verify-core::pt_reap` for the shared registry/decision logic the
/// platforms' real implementations both use.
#[cfg(not(windows))]
mod pt_reap {
    use std::collections::HashSet;
    use std::path::Path;

    /// Test-only: production code identifies ownership via
    /// `create_kill_marker`/`kill_marked_children`.
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn own_child_pids() -> HashSet<u32> {
        HashSet::new()
    }

    pub(crate) fn create_kill_marker(_pt_binary: &Path, _scratch_base: &Path) -> Option<String> {
        None
    }

    pub(crate) fn kill_marked_children() {}
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_bridges_sequential(
    live_cache_dir: &Path,
    scratch_base: &Path,
    bridges: Vec<BridgeLine>,
    pt_binary: Option<PathBuf>,
    bootstrap_timeout: Duration,
    probe_timeout: Duration,
    max_deadline: Option<std::time::Instant>,
    mut on_result: impl FnMut(&BridgeLine, Result<Duration, String>),
) {
    let deadline = max_deadline;
    // Only mutual exclusion is stored; each check owns its resources. An
    // admission check must also bound waiting for the shared verifier lock,
    // because its caller holds the candidate-pool lock until this returns.
    let _serial = if let Some(deadline) = deadline {
        loop {
            match VERIFY_LOCK.try_lock() {
                Ok(guard) => break guard,
                Err(std::sync::TryLockError::Poisoned(error)) => {
                    VERIFY_LOCK.clear_poison();
                    break error.into_inner();
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                    if remaining.is_zero() {
                        for bridge in &bridges {
                            on_result(
                                bridge,
                                Err("bridge verification budget exhausted waiting for verifier lock".to_owned()),
                            );
                        }
                        return;
                    }
                    std::thread::sleep(remaining.min(Duration::from_millis(10)));
                }
            }
        }
    } else {
        VERIFY_LOCK.lock().unwrap_or_else(|error| {
            VERIFY_LOCK.clear_poison();
            error.into_inner()
        })
    };
    // Test seam (TS17-02): parks the worker while it HOLDS VERIFY_LOCK, so a
    // test can pin an admission worker mid-run deterministically. Placed
    // after the guard acquisition on purpose: a worker parked here is a
    // worker that owns the verifier lock.
    #[cfg(test)]
    crate::test_seams::park_if_armed(
        crate::test_seams::Site::AdmissionVerifyPostLock,
        live_cache_dir,
    );
    let cache_snapshot = scratch_base.join("cache-snapshot");
    let cache_dir =
        snapshot_cache_dir(live_cache_dir, &cache_snapshot, deadline).then_some(cache_snapshot);

    // Ownership marker for this batch (Windows; see `pt_reap` module docs).
    // Created once per batch, before the Vec is consumed, only when a PT is
    // actually in play: the marker is the uniquely named executable copy the
    // checks below launch instead of the shared PT binary, and its file name
    // is what the post-check kill sweep verifies against. If creation fails,
    // no diff-based fallback runs on purpose: killing collateral (the main
    // engine's PT) is worse than a leak, so reaping is simply disabled for
    // this batch.
    let needs_pt = pt_binary.is_some() && bridges.iter().any(|b| b.transport.is_some());
    let kill_marker = if needs_pt {
        pt_reap::create_kill_marker(pt_binary.as_ref().expect("checked above"), scratch_base)
    } else {
        None
    };
    let kill_marker_path = kill_marker.as_ref().map(|name| scratch_base.join(name));
    if needs_pt && kill_marker.is_none() {
        tracing::warn!(
            "circuit-verify: no PT ownership marker could be created; \
             leaked-child reaping is disabled for this batch"
        );
    }

    for (idx, bridge) in bridges.into_iter().enumerate() {
        if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
            on_result(
                &bridge,
                Err("bridge verification budget exhausted".to_owned()),
            );
            continue;
        }
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
            // The check's effective PT binary is the batch's unique marker
            // copy when one exists — that is what makes its spawned child
            // identifiable as OURS by exe name (see `pt_reap`).
            pt_binary: kill_marker_path.clone().or_else(|| pt_binary.clone()),
            cache_dir: cache_dir.clone(),
            state_dir: check_dir.clone(),
        };
        let result: anyhow::Result<Duration> =
            crate::arti_observability::without_guard_observations(|| {
                rt.block_on(async {
                    let remaining = || {
                        deadline.map_or(Duration::MAX, |deadline| {
                            deadline.saturating_duration_since(std::time::Instant::now())
                        })
                    };
                    let tunnel = arti_wrapper::TorTunnel::create_unbootstrapped_with(
                        arti_wrapper::Settings {
                            bridges: vec![check.bridge],
                            pt_binary: check.pt_binary,
                            state_dir: Some(check.state_dir),
                            cache_dir: check.cache_dir,
                            disable_preemptive_circuits: true,
                            ..Default::default()
                        },
                    )?;
                    let bootstrap_limit = bootstrap_timeout.min(remaining());
                    anyhow::ensure!(
                        !bootstrap_limit.is_zero(),
                        "bridge verification budget exhausted before bootstrap"
                    );
                    tokio::time::timeout(bootstrap_limit, tunnel.wait_bootstrapped()).await??;
                    let started = std::time::Instant::now();
                    let probe_limit = probe_timeout.min(remaining());
                    anyhow::ensure!(
                        !probe_limit.is_zero(),
                        "bridge verification budget exhausted before live probe"
                    );
                    let body = bridge_fetcher::fetch_one(
                        &tunnel,
                        LIVE_PROBE_URL,
                        probe_limit,
                        4096,
                        &[],
                        &[],
                        false,
                    )
                    .await?;
                    anyhow::ensure!(
                        confirms_tor(&body),
                        "HTTPS canary did not confirm Tor egress"
                    );
                    Ok(started.elapsed())
                })
            });
        let shutdown_grace = deadline.map_or(VERIFY_RUNTIME_SHUTDOWN_GRACE, |deadline| {
            VERIFY_RUNTIME_SHUTDOWN_GRACE
                .min(deadline.saturating_duration_since(std::time::Instant::now()))
        });
        rt.shutdown_timeout(shutdown_grace);
        pt_reap::kill_marked_children();

        if let Err(error) = &result {
            warn!(transport = ?bridge.transport, addr = %bridge.addr, %error,
                "circuit-verify: bridge check failed");
        }
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
/// Failed attempts advance the queue without demoting the live bridge.
/// Routed through the single bridge-store writer: an unreadable on-disk
/// store is logged (as before), while publish failures are the writer's
/// retry problem.
async fn persist_circuit_verify_results(
    results: &[(BridgeLine, bool)],
    config_path: Option<&Path>,
) {
    if results.is_empty() {
        return;
    }
    let results = results.to_vec();
    if let Err(error) = crate::bridge_store_writer::apply(config_path, move |store| {
        let now = OffsetDateTime::now_utc();
        for (bridge, ok) in &results {
            store.note_verification_attempt_at(bridge, now);
            if *ok {
                store.note_circuit_verified_at(bridge, now);
                store.note_circuit_success_at(bridge, now);
            }
        }
    })
    .await
    {
        warn!(error = %error, "circuit-verify: could not load bridge health store");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration as StdDuration;

    #[test]
    fn canary_requires_a_real_positive_tor_response() {
        assert!(confirms_tor(r#"{ "IsTor": true, "IP": "192.0.2.1" }"#));
        for body in [
            r#"{"IsTor":false}"#,
            r#"{"IsTor":"true"}"#,
            "{}",
            "<html>OK</html>",
        ] {
            assert!(!confirms_tor(body), "must reject {body}");
        }
    }

    #[test]
    fn own_child_pids_never_contains_self() {
        assert!(!pt_reap::own_child_pids().contains(&std::process::id()));
    }

    /// The P1 regression pin (stability review 2026-09-08 §2) and its sibling
    /// kill-decision scenarios moved to `bridge-verify-core::pt_reap`'s tests
    /// (suffix `_cli`) when the decision logic was extracted.
    #[cfg(windows)]
    #[test]
    fn create_kill_marker_makes_unique_executable_names() {
        let dir = tempfile::tempdir().expect("tempdir");
        let scratch = dir.path().join("scratch");
        std::fs::create_dir_all(&scratch).expect("mkdir scratch");
        let fake_pt = dir.path().join("fake-pt.exe");
        std::fs::write(&fake_pt, b"pretend PT binary").expect("write fake pt");

        let marker_a = pt_reap::create_kill_marker(&fake_pt, &scratch).expect("marker a");
        let marker_b = pt_reap::create_kill_marker(&fake_pt, &scratch).expect("marker b");
        assert_ne!(marker_a, marker_b, "names must be unique per call");
        assert!(marker_a.starts_with("pt-") && marker_a.ends_with(".exe"));

        let content = std::fs::read(&fake_pt).expect("read fake pt");
        assert_eq!(
            std::fs::read(scratch.join(&marker_a)).expect("read marker a"),
            content
        );
        assert_eq!(
            std::fs::read(scratch.join(&marker_b)).expect("read marker b"),
            content
        );
        let markers = pt_reap::current_markers();
        assert!(markers.contains(&marker_a));
        assert!(markers.contains(&marker_b));
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
    #[tokio::test]
    async fn verified_bridge_resets_circuit_fails_and_records_verification() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bridge: BridgeLine = "1.2.3.4:9101 DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"
            .parse()
            .expect("bridge line");
        let config_path = seed_failed_bridge(dir.path(), &bridge);

        persist_circuit_verify_results(&[(bridge.clone(), true)], config_path.as_deref()).await;

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
    #[tokio::test]
    async fn failed_verification_changes_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bridge: BridgeLine = "5.6.7.8:9103 FEEDFACEFEEDFACEFEEDFACEFEEDFACEFEEDFACE"
            .parse()
            .expect("bridge line");
        let config_path = seed_failed_bridge(dir.path(), &bridge);

        persist_circuit_verify_results(&[(bridge.clone(), false)], config_path.as_deref()).await;

        let store = BridgeStore::load(BridgeStore::resolve_path(config_path.as_deref()))
            .expect("reload store");
        assert_eq!(store.circuit_fails(&bridge), 1, "circuit_fails unchanged");
        assert_eq!(store.verified_count(&bridge), 0, "no verification recorded");
    }
}
