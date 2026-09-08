use super::*;

/// JNI entry point:
/// `nativeVerifyBridges(String configPath, String bridgeLines, String ptBinaryPath, BridgeCheckCallback callback)`
///
/// Asynchronous, like `nativeStart`: spawns a dedicated thread and returns immediately.
/// For each of `bridgeLines` (newline-joined), checks whether it can carry real Tor traffic
/// to the open internet -- a live end-to-end probe to `check.torproject.org`
/// (see [`arti_wrapper::TorTunnel::verify_bridge_reachable`]), not merely a TCP handshake or
/// an open channel -- and calls back `onBridgeChecked` as each result comes in, then
/// `onCheckComplete` once the whole batch is done.
///
/// Checks run **sequentially** (deliberately -- each one is a throwaway Tor client; running
/// several at once would multiply memory/CPU/network load on what may be a phone with a
/// live connection already running), each against its own fresh scratch state directory
/// (removed immediately after), but all sharing `configPath`'s own already-populated
/// consensus/microdescriptor cache when the engine has ever bootstrapped from it -- see
/// [`arti_wrapper::Settings::cache_dir`]'s doc for why sharing it is safe and turns a
/// from-scratch multi-minute directory fetch into a near-instant hit for the common case
/// where the user already has a live connection while scanning a QR code.
///
/// A bridge requiring a pluggable transport is reported unreachable immediately (no bootstrap
/// attempt) when `ptBinaryPath` is empty/null, mirroring `nativeStart`'s own
/// `TOR_PT_BINARY`-required contract.
///
/// - **Threading:** Returns immediately; all work happens on a dedicated background thread.
///   `onBridgeChecked`/`onCheckComplete` are invoked from that thread -- callback
///   implementations must be thread-safe the same way `BootstrapCallback`'s already are.
/// - **Error Signaling:** Does not throw. An unparseable bridge line is silently skipped (not
///   reported via callback at all -- there is nothing to check). A malformed
///   `configPath`/`callback` yields zero callback invocations and returns without error.
#[no_mangle]
pub extern "system" fn Java_org_torproject_android_service_TorSocks5Bridge_nativeVerifyBridges(
    mut env: JNIEnv,
    _class: JClass,
    config_path: JString,
    bridge_lines: JString,
    pt_binary_path: JString,
    callback: JObject,
) {
    let config_path_str: String = match env.get_string(&config_path) {
        Ok(s) => s.into(),
        Err(_) => return,
    };
    let lines_str: String = match env.get_string(&bridge_lines) {
        Ok(s) => s.into(),
        Err(_) => return,
    };
    let pt_binary: Option<std::path::PathBuf> = env
        .get_string(&pt_binary_path)
        .ok()
        .map(String::from)
        .filter(|s| !s.is_empty())
        .map(std::path::PathBuf::from);

    let vm = match env.get_java_vm() {
        Ok(vm) => vm,
        Err(e) => {
            error!("nativeVerifyBridges: failed to get Java VM: {e}");
            return;
        }
    };
    let global = match env.new_global_ref(callback) {
        Ok(g) => g,
        Err(e) => {
            error!("nativeVerifyBridges: failed to create global ref to callback: {e}");
            return;
        }
    };
    let java_callback = Arc::new(callback::JavaBridgeCheckCallback::new(vm, global));

    let bridges: Vec<bridge_line::BridgeLine> = lines_str
        .lines()
        .filter_map(|line| line.trim().parse().ok())
        .collect();

    if std::thread::Builder::new()
        .name("torsocks5-bridge-verify".into())
        .spawn(move || {
            verify_bridges_blocking(&config_path_str, bridges, pt_binary, &java_callback)
        })
        .is_err()
    {
        error!("nativeVerifyBridges: failed to spawn verification thread");
    }
}

/// How long [`verify_bridges_sequential`] waits for a checked bridge's tokio runtime to drain
/// after each check, before moving on. Not the PT-process cleanup mechanism itself (that is
/// `pt_reap`'s explicit kill, right after this) -- just a bounded moment for the runtime's own
/// async tasks to unwind normally first, so the abort isn't the *only* thing that ever happens.
pub(super) const VERIFY_BRIDGE_RUNTIME_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Layout `nativeStart`/`arti_wrapper::build_config` use: `<config file's directory>/arti-data/cache`.
/// Shared by [`verify_bridges_blocking`] (the QR-scan flow) and `engine`'s background
/// circuit-verify tick, both of which need the live engine's own cache to snapshot.
pub(crate) fn arti_cache_dir(config_path: &std::path::Path) -> std::path::PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("arti-data")
        .join("cache")
}

/// A scratch directory for [`verify_bridges_sequential`]'s per-bridge check state and cache-dir
/// snapshot, named `<config file's directory>/verify-scratch/<name>`. Deliberately *not*
/// `std::env::temp_dir()`: that resolves to `/tmp` on Android (via `TMPDIR`'s absence), a path
/// no app is allowed to write to under SELinux -- confirmed on a retail device (`create_dir_all`
/// fails there, though not on the emulator, which is looser). `config_path`'s own directory is
/// always inside the app's private storage, so it is guaranteed writable.
pub(crate) fn scratch_dir(config_path: &std::path::Path, name: &str) -> std::path::PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("verify-scratch")
        .join(name)
}

/// Recursively copies every regular file under `src` into `dest` (creating
/// directories as needed). Used to snapshot the live engine's directory
/// cache for [`verify_bridges_sequential`] -- see that function's doc for why
/// a snapshot, not the live directory, is what gets shared with a throwaway
/// check client. Best-effort: any I/O error simply means the caller falls
/// back to no shared cache for this batch, not a hard failure.
pub(super) fn snapshot_cache_dir(src: &std::path::Path, dest: &std::path::Path) -> bool {
    fn copy_recursive(src: &std::path::Path, dest: &std::path::Path) -> std::io::Result<()> {
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

/// Verifies each of `bridges` for real end-to-end reachability, one at a time, sharing one
/// cache-dir snapshot taken once up front from `live_cache_dir` (if it exists). Calls
/// `on_result` as each bridge's check completes, with `Err` carrying a human-readable reason
/// (not necessarily from a live network attempt -- e.g. "no pt_binary available").
///
/// One caller: `engine`'s background circuit-verify tick (reporting into `bridge-store`), which
/// checks at most a couple of bridges per tick and has no user watching a progress bar, so
/// serializing them costs nothing worth avoiding. The QR-scan flow instead calls
/// [`verify_bridges_parallel`] just below -- same per-bridge check, same hard-won fixes (both
/// share [`check_one_bridge`] and `pt_reap`), different batching:
///
/// - **One throwaway tokio runtime *per bridge*, explicitly shut down right after, plus an
///   explicit kill of the PT process it managed.** `arti_client::TorClient::bootstrap` spawns
///   long-lived background tasks onto whatever runtime it is given, holding their own clones of
///   the client's internal managers (including `tor_ptmgr`'s pluggable-transport child process
///   handle) that only stop when that runtime is torn down -- with one shared runtime for the
///   whole batch, every checked bridge's `libtorpthelper` child leaked until the *entire batch*
///   finished. `Runtime::shutdown_timeout` per bridge fixes that half. It does not, on its own,
///   fix the other half: `tor_ptmgr`'s own graceful-shutdown thread (`tor-ptmgr::ipc`'s
///   `AsyncPtChild::new`) is a plain OS thread blocked in a *synchronous* read of the child's
///   stdout, and only checks whether its side of the channel has been dropped when the child
///   itself writes a new line -- which an already-initialized, otherwise-idle obfs4 proxy has no
///   reason to do. Dropping every Arc that points at it, or shutting the whole runtime down,
///   does nothing to wake that thread up; confirmed on device, the child stayed alive minutes
///   after the runtime it belonged to was gone. So this also reaps its own PT children
///   explicitly, by *ownership* rather than time of appearance: per batch,
///   [`pt_reap::create_kill_marker`] makes a uniquely named executable copy of the PT binary
///   (hard link where possible, copy otherwise) inside the batch's scratch dir (`scratch_dir`
///   under the config directory -- the only writable place under SELinux) and registers its
///   file name in a module-level FIFO registry. The marker name is sized to exactly 15 bytes
///   ("pt-" + 12 hex) so the kernel's `comm` truncation (TASK_COMM_LEN = 15) keeps the whole
///   unique id visible. Checks are launched with that copy as their effective `pt_binary`, so
///   the PT child `tor_ptmgr` spawns from it is identifiable by `comm` alone; after each check
///   [`pt_reap::kill_marked_children`] `SIGKILL`s only own children whose `comm` matches a
///   registered marker. An earlier version snapshotted child PIDs *and their kernel start
///   times* before each check and killed every still-alive PT-named child absent from the
///   baseline -- but the main engine's PT transport can RESTART inside the check window (new
///   pid, new start_time, same binary name), and that diff killed it, taking the user's live
///   tunnels down with the cleanup. A restarted main PT child carries the normal binary name
///   and can never match a marker. See `docs/stability-review-2026-09-08.md` section 2 for the
///   full ownership analysis. Marker-creation failure disables reaping for the batch on
///   purpose (never a diff fallback: killing collateral is worse than a leak). Tradeoffs: one
///   link/copy per batch (cheap); the registry never shrinks mid-process (capped at 128 names,
///   FIFO eviction); marker files are wiped with the batch's scratch dir.
/// - **A cache *snapshot*, not the live directory.** `tor_dirmgr`'s storage is a single sqlite
///   file, opened with its own fresh `rusqlite::Connection` here, completely independent of the
///   main engine's already-open connection to that same file. Sqlite's default `busy_timeout`
///   is zero, so with the main engine writing to it every fraction of a second (routine
///   consensus/microdescriptor upkeep), a throwaway client sharing the live file hits
///   `SQLITE_BUSY` on nearly every read or write of its own -- including storing the fetched
///   bridge descriptor, so the guard's directory info never completes and every check times out
///   waiting on a circuit that can never build, regardless of the bridge's real reachability. A
///   one-time copy, taken before the batch starts, gets the same "skip the cold consensus
///   fetch" speed benefit without contending with the live writer.
pub(crate) fn verify_bridges_sequential(
    live_cache_dir: &std::path::Path,
    scratch_base: &std::path::Path,
    bridges: Vec<bridge_line::BridgeLine>,
    pt_binary: Option<std::path::PathBuf>,
    bootstrap_timeout: Duration,
    probe_timeout: Duration,
    mut on_result: impl FnMut(&bridge_line::BridgeLine, std::result::Result<Duration, String>),
) {
    let cache_dir = shared_cache_snapshot(live_cache_dir, scratch_base);

    // Ownership marker for this batch: the uniquely named executable copy the
    // checks below launch instead of the shared PT binary, so their spawned
    // PT children are identifiable as OURS by `comm` alone (see `pt_reap`).
    // Created only when a PT is actually in play. If creation fails, no
    // diff-based fallback runs on purpose: killing collateral (the main
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
        warn!(
            "bridge-verify: no PT ownership marker could be created; \
             leaked-child reaping is disabled for this batch"
        );
    }

    for (idx, bridge) in bridges.into_iter().enumerate() {
        let check_dir = scratch_base.join(idx.to_string());
        let result = check_one_bridge(
            &bridge,
            &check_dir,
            cache_dir.clone(),
            kill_marker_path.clone().or_else(|| pt_binary.clone()),
            bootstrap_timeout,
            probe_timeout,
        );
        pt_reap::kill_marked_children();
        on_result(&bridge, result);
    }
}

/// Same real end-to-end check as [`verify_bridges_sequential`], but runs up to `concurrency`
/// bridges at once, each on its own OS thread -- for the QR-scan flow, where a scanned batch is
/// often mostly-dead bridges and checking them one at a time means the user watches the whole
/// batch's timeout budget serialize even though each check is fully independent.
///
/// The `pt_reap` marker/kill (see `verify_bridges_sequential`'s doc for why it exists at all)
/// brackets the *whole* batch here instead of each bridge individually: the kill runs once,
/// after `std::thread::scope` joins, because every marker-named child is a verify child --
/// including ones still in use by concurrent checks -- so killing after one thread's check
/// finishes would SIGKILL another thread's still-needed PT child. Correctness costs a little
/// promptness -- a leaked helper from an early-finishing check survives until the slowest
/// check in the batch completes, not until its own check does.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_bridges_parallel(
    live_cache_dir: &std::path::Path,
    scratch_base: &std::path::Path,
    bridges: Vec<bridge_line::BridgeLine>,
    pt_binary: Option<std::path::PathBuf>,
    bootstrap_timeout: Duration,
    probe_timeout: Duration,
    concurrency: usize,
    on_result: impl Fn(&bridge_line::BridgeLine, std::result::Result<Duration, String>) + Sync,
) {
    let cache_dir = shared_cache_snapshot(live_cache_dir, scratch_base);

    // Same per-batch ownership marker as the sequential path, computed BEFORE `bridges` is
    // moved into the queue (and before any thread runs). See `verify_bridges_sequential` and
    // the `pt_reap` module docs for why creation failure disables reaping instead of falling
    // back to a diff-based kill.
    let needs_pt = pt_binary.is_some() && bridges.iter().any(|b| b.transport.is_some());
    let kill_marker = if needs_pt {
        pt_reap::create_kill_marker(pt_binary.as_ref().expect("checked above"), scratch_base)
    } else {
        None
    };
    let kill_marker_path = kill_marker.as_ref().map(|name| scratch_base.join(name));
    if needs_pt && kill_marker.is_none() {
        warn!(
            "bridge-verify: no PT ownership marker could be created; \
             leaked-child reaping is disabled for this batch"
        );
    }

    let queue = Mutex::new(bridges.into_iter().enumerate());

    std::thread::scope(|scope| {
        for _ in 0..concurrency.max(1) {
            let queue = &queue;
            let cache_dir = cache_dir.clone();
            let pt_binary = pt_binary.clone();
            let kill_marker_path = kill_marker_path.clone();
            let on_result = &on_result;
            scope.spawn(move || loop {
                let Some((idx, bridge)) = queue.lock().unwrap().next() else {
                    break;
                };
                let check_dir = scratch_base.join(idx.to_string());
                let result = check_one_bridge(
                    &bridge,
                    &check_dir,
                    cache_dir.clone(),
                    kill_marker_path.clone().or_else(|| pt_binary.clone()),
                    bootstrap_timeout,
                    probe_timeout,
                );
                on_result(&bridge, result);
            });
        }
    });

    // One kill sweep for the WHOLE batch, after the scope joins: every marker-named child is
    // a verify child, including ones still in use by concurrent checks, so killing after one
    // thread's check would SIGKILL another thread's still-needed PT child.
    pt_reap::kill_marked_children();
}

/// One-time cache-dir snapshot shared by every check in a batch -- see
/// [`verify_bridges_sequential`]'s doc for why a snapshot, not the live directory.
pub(super) fn shared_cache_snapshot(
    live_cache_dir: &std::path::Path,
    scratch_base: &std::path::Path,
) -> Option<std::path::PathBuf> {
    let cache_snapshot = scratch_base.join("cache-snapshot");
    (live_cache_dir.is_dir() && snapshot_cache_dir(live_cache_dir, &cache_snapshot))
        .then_some(cache_snapshot)
}

/// Checks exactly one bridge for real end-to-end reachability: a throwaway single-thread tokio
/// runtime, `arti_wrapper::TorTunnel::verify_bridge_reachable`, then an explicit shutdown. Does
/// *not* reap PT processes itself -- see [`verify_bridges_sequential`] and
/// [`verify_bridges_parallel`], which bracket their own `pt_reap` marker-create/kill around
/// one or more calls to this, at different granularity.
pub(super) fn check_one_bridge(
    bridge: &bridge_line::BridgeLine,
    check_dir: &std::path::Path,
    cache_dir: Option<std::path::PathBuf>,
    pt_binary: Option<std::path::PathBuf>,
    bootstrap_timeout: Duration,
    probe_timeout: Duration,
) -> std::result::Result<Duration, String> {
    if bridge.transport.is_some() && pt_binary.is_none() {
        return Err("bridge requires a pluggable transport, but none is available".to_owned());
    }

    if let Err(e) = std::fs::create_dir_all(check_dir) {
        return Err(format!("could not create scratch directory: {e}"));
    }

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            let _ = std::fs::remove_dir_all(check_dir);
            return Err(format!("failed to create runtime: {e}"));
        }
    };

    let check = arti_wrapper::BridgeCheckSettings {
        bridge: bridge.clone(),
        pt_binary,
        cache_dir,
        state_dir: check_dir.to_path_buf(),
    };
    let result = rt.block_on(arti_wrapper::TorTunnel::verify_bridge_reachable(
        check,
        (engine::LIVE_PROBE_TARGET, engine::LIVE_PROBE_PORT),
        bootstrap_timeout,
        probe_timeout,
    ));
    rt.shutdown_timeout(VERIFY_BRIDGE_RUNTIME_SHUTDOWN_GRACE);

    let _ = std::fs::remove_dir_all(check_dir);
    result.map_err(|e| e.to_string())
}

/// First `TASK_COMM_LEN - 1` (15) bytes of `path`'s file name -- what Linux would report as the
/// process's `comm` (field 2 of `/proc/<pid>/stat`, truncated by the kernel to exactly this) if
/// it exec'd `path`. Used by [`reap_targets`] to compare each child's `comm` against the
/// *registered marker* names -- a marker is a uniquely named copy WE created of the PT binary,
/// so a `comm` match is proof of ownership, not of mere resemblance. An empty/parentless path
/// yields an empty vec, which (together with the empty-registry rule) keeps the reap a no-op
/// in the no-marker case.
#[cfg_attr(all(not(target_os = "android"), not(test)), expect(dead_code))]
fn pt_binary_comm(pt_binary: &std::path::Path) -> Vec<u8> {
    #[cfg(unix)]
    let name = pt_binary
        .file_name()
        .map(std::os::unix::ffi::OsStrExt::as_bytes)
        .unwrap_or(&[])
        .to_vec();
    #[cfg(not(unix))]
    let name = pt_binary
        .file_name()
        .map(|n| n.to_string_lossy().into_owned().into_bytes())
        .unwrap_or_default();
    name.into_iter().take(15).collect()
}

/// One live process as observed in `/proc` -- see the android `pt_reap::own_child_procs` for the
/// source. Deliberately defined outside the cfg'd module so the pure selection logic below (and
/// its tests) compile and run on host builds too.
#[cfg_attr(all(not(target_os = "android"), not(test)), expect(dead_code))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ChildProc {
    pub pid: u32,
    pub ppid: u32,
    /// First 15 bytes of the executable's basename (kernel TASK_COMM_LEN truncation), from the
    /// `comm` field of `/proc/<pid>/stat`. For a verify-spawned PT child this is the marker
    /// name we registered -- the ownership proof.
    pub comm: Vec<u8>,
}

/// Pure decision core of [`pt_reap::kill_marked_children`], kept cfg-free and OS-free for
/// testability. `pid` should be killed iff it is currently a child of `my_pid` AND its `comm`
/// matches a registered marker. Guard by guard:
/// - empty `markers`: kill nothing -- the copy-failure degenerate path must never regress to
///   guessing (a diff-based fallback would kill collateral).
/// - `ppid == my_pid`: only ever touch our own children -- never another app's or the system's
///   processes, however marker-named.
/// - `pid != my_pid`: never target ourselves.
/// - `comm` in `marker_comms`: only marker-named children. A marker is a uniquely named copy
///   WE created of the PT binary, so an exact-byte `comm` match is proof of ownership.
///   Deliberately name-verified, NOT time-of-appearance-verified: the main engine's PT child
///   -- however freshly restarted -- carries the normal binary name and can never match a
///   marker. See docs/stability-review-2026-09-08.md section 2.
#[cfg_attr(all(not(target_os = "android"), not(test)), expect(dead_code))]
fn reap_targets(
    children: &[ChildProc],
    my_pid: u32,
    markers: &std::collections::HashSet<String>,
) -> Vec<u32> {
    if markers.is_empty() {
        return Vec::new();
    }
    let marker_comms: std::collections::HashSet<Vec<u8>> = markers
        .iter()
        .map(|m| pt_binary_comm(std::path::Path::new(m)))
        .collect();
    children
        .iter()
        .filter(|c| c.ppid == my_pid && c.pid != my_pid && marker_comms.contains(&c.comm))
        .map(|c| c.pid)
        .collect()
}

/// Reaps the PT processes a throwaway verify client's arti client leaves running --
/// see [`verify_bridges_sequential`]'s doc for why nothing short of an explicit kill reliably
/// stops them. Ownership is marker-based, not time-of-appearance-based, so the pure parts
/// (registry, [`create_kill_marker`], [`current_markers`]) are compiled and tested on every
/// target; only the /proc snapshot and `kill(2)` sweep are android-specific (host builds never
/// spawn a real PT child, so there is nothing to reap).
mod pt_reap {
    use std::collections::HashSet;
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    use super::ChildProc;

    /// FIFO registry of marker file names that identify "our" PT children.
    /// Never shrinks per-check: a leaked child that escaped its own call's
    /// kill sweep keeps matching (and gets reaped) on every later call.
    static KILL_MARKERS: Mutex<Vec<String>> = Mutex::new(Vec::new());

    /// Distinguishes markers created within the same nanosecond tick.
    static MARKER_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// 128 registered names is far beyond anything a long-lived service can
    /// accumulate (each batch adds at most one); the cap just guarantees the
    /// registry cannot grow without bound over a multi-day process.
    const KILL_MARKERS_CAP: usize = 128;

    /// Creates a uniquely named executable copy of `pt_binary` inside
    /// `scratch_base` and registers its file name. `scratch_base` must be the
    /// batch's scratch dir (`scratch_dir` under the config directory -- the
    /// only guaranteed-writable location under SELinux on Android, never
    /// `std::env::temp_dir()`). Hard link first (shares the source inode, and
    /// thus its SELinux label and executability), fall back to a full copy;
    /// on unix the copy is made executable, because a non-executable marker
    /// would fail the check itself -- and a copied marker may in any case be
    /// denied exec on newer Android under W^X policy on some devices, in
    /// which case the check itself fails visibly. Returns the marker FILE
    /// NAME (not the path) on success, `None` on ANY failure -- callers must
    /// treat `None` as "leak reaping disabled for this batch", NEVER as
    /// "fall back to diff-based killing": killing collateral (the main
    /// engine's PT) is worse than a leak. The name is exactly 15 bytes
    /// ("pt-" + 12 hex) so the kernel's `comm` truncation (TASK_COMM_LEN =
    /// 15) keeps the whole unique id visible; no ".exe" suffix (Linux, and
    /// suffix bytes would be cut off by the truncation anyway).
    pub(crate) fn create_kill_marker(pt_binary: &Path, scratch_base: &Path) -> Option<String> {
        if let Err(error) = std::fs::create_dir_all(scratch_base) {
            tracing::warn!(%error, "bridge-verify: could not create PT marker scratch dir");
            return None;
        }
        // `{:012x}` is a MINIMUM width, not a fixed one -- a full 64-bit value
        // can need up to 16 hex digits, overflowing the 12 this depends on
        // (marker name = exactly TASK_COMM_LEN-1 bytes, see below). Mask to
        // the low 48 bits so the formatted width is always exactly 12.
        let unique = format!(
            "{:012x}",
            ((std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0)
                ^ (u64::from(std::process::id()) << 32))
                ^ MARKER_COUNTER.fetch_add(1, Ordering::Relaxed))
                & 0xFFFF_FFFF_FFFF
        );
        let marker_name = format!("pt-{unique}");
        let marker_path = scratch_base.join(&marker_name);
        let linked = std::fs::hard_link(pt_binary, &marker_path);
        if linked.is_ok() {
            // Hard link shares the source inode -- nothing to chmod.
        } else {
            if let Err(error) = std::fs::copy(pt_binary, &marker_path).map(|_| ()) {
                tracing::warn!(%error, marker = %marker_name,
                    "bridge-verify: could not create PT kill marker; \
                     leaked-child reaping disabled for this batch");
                return None;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let source_mode = std::fs::metadata(pt_binary)
                    .map(|m| m.permissions().mode())
                    .ok()?;
                if std::fs::set_permissions(
                    &marker_path,
                    std::fs::Permissions::from_mode(source_mode | 0o111),
                )
                .is_err()
                {
                    // A non-executable marker copy would fail the check
                    // itself; disabling reaping instead keeps checks working.
                    tracing::warn!(
                        "bridge-verify: could not make PT marker copy executable; \
                         leaked-child reaping disabled for this batch"
                    );
                    return None;
                }
            }
        }

        let mut markers = KILL_MARKERS.lock().unwrap_or_else(|error| {
            KILL_MARKERS.clear_poison();
            error.into_inner()
        });
        if !markers.contains(&marker_name) {
            markers.push(marker_name.clone());
            if markers.len() > KILL_MARKERS_CAP {
                markers.remove(0); // FIFO eviction of the oldest name
            }
        }
        Some(marker_name)
    }

    /// Snapshot of the currently registered marker names (test-visible via
    /// `pub(crate)`).
    #[cfg_attr(all(not(target_os = "android"), not(test)), expect(dead_code))]
    pub(crate) fn current_markers() -> HashSet<String> {
        let markers = KILL_MARKERS.lock().unwrap_or_else(|error| {
            KILL_MARKERS.clear_poison();
            error.into_inner()
        });
        markers.iter().cloned().collect()
    }

    /// Live children of this process, read from `/proc`. Linux's process tree has no concept of
    /// "which logical client spawned this" -- every child of our own PID shows up here
    /// regardless of which throwaway `TorTunnel` (or the long-lived main engine) started it.
    /// Ownership is therefore established by `comm` against the registered markers (see
    /// [`super::reap_targets`]), not by this listing.
    #[cfg(target_os = "android")]
    pub(crate) fn own_child_procs() -> Vec<ChildProc> {
        let my_pid = std::process::id();
        let mut children = Vec::new();
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return children;
        };
        for entry in entries.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
                continue;
            };
            // Format: "pid (comm) state ppid ...". `comm` can itself contain spaces or
            // parentheses, so take the bytes between the *first* '(' and the *last* ')'
            // before splitting the remaining fields.
            let Some((_, comm_and_rest)) = stat.split_once('(') else {
                continue;
            };
            let Some((comm, after_comm)) = comm_and_rest.rsplit_once(')') else {
                continue;
            };
            let mut fields = after_comm.split_whitespace();
            let _state = fields.next(); // field 3
            let Some(ppid) = fields.next().and_then(|s| s.parse::<u32>().ok()) else {
                continue; // field 4
            };
            if ppid == my_pid {
                children.push(ChildProc {
                    pid,
                    ppid,
                    comm: comm.as_bytes().iter().copied().take(15).collect(),
                });
            }
        }
        children
    }

    /// Host stub: host builds never spawn a real PT child, so there is nothing to reap.
    #[cfg_attr(not(target_os = "android"), expect(dead_code))]
    #[cfg(not(target_os = "android"))]
    pub(crate) fn own_child_procs() -> Vec<ChildProc> {
        Vec::new()
    }

    /// `SIGKILL`s every currently-live own child whose `comm` matches a registered kill marker
    /// (see [`create_kill_marker`]). A no-op while the registry is empty. Deliberately
    /// name-verified, not time-of-appearance-verified: the main engine's PT child -- however
    /// freshly restarted -- carries the normal binary name and can never match. The selection
    /// itself is [`super::reap_targets`].
    #[cfg(target_os = "android")]
    pub(crate) fn kill_marked_children() {
        let markers = current_markers();
        if markers.is_empty() {
            return;
        }
        for pid in super::reap_targets(&own_child_procs(), std::process::id(), &markers) {
            // Safety: `kill(2)` on a PID we just observed as our own child in a fresh /proc
            // scan AND whose `comm` matches one of the marker copies we created ourselves.
            // Failure (the process already exited on its own between the scan and this call)
            // is not an error worth surfacing -- the end state either way is "not running".
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGKILL);
            }
        }
    }

    /// Host stub -- see [`own_child_procs`].
    #[cfg(not(target_os = "android"))]
    pub(crate) fn kill_marked_children() {}
}

/// How many bridges [`verify_bridges_blocking`] checks at once. The QR-scan flow has a user
/// actively watching a live progress list, often of a batch that turns out to be mostly dead --
/// unlike the background circuit-verify tick (`engine.rs`), which has no one waiting and checks
/// at most a couple of bridges every half hour, this one is worth parallelizing. Kept modest:
/// each check runs its own `arti_client` (guard selection, consensus/microdescriptor lookups),
/// not just a socket, so unbounded concurrency would trade wall-clock for phone memory/CPU.
pub(super) const QR_VERIFY_CONCURRENCY: usize = 4;

/// Worker behind [`nativeVerifyBridges`]. Called from a dedicated OS thread, never from the main
/// engine's own runtime, so the two never contend.
pub(super) fn verify_bridges_blocking(
    config_path: &str,
    bridges: Vec<bridge_line::BridgeLine>,
    pt_binary: Option<std::path::PathBuf>,
    callback: &callback::JavaBridgeCheckCallback,
) {
    let config_path = std::path::Path::new(config_path);
    let live_cache_dir = arti_cache_dir(config_path);
    let scratch_base = scratch_dir(config_path, &format!("bridge-check-{}", std::process::id()));

    let emit = |bridge: &bridge_line::BridgeLine, result: std::result::Result<Duration, String>| {
        let bridge_text = bridge.to_string();
        match result {
            Ok(latency) => {
                callback.emit_checked(&bridge_text, true, latency.as_millis() as i64, None)
            }
            Err(e) => callback.emit_checked(&bridge_text, false, 0, Some(&e)),
        }
    };

    // A bridge whose most recent probe today already failed is skipped outright rather than
    // re-run through a live check: the store already answered this exact question a few hours
    // (at most) ago, and re-running it just makes the user wait through another timeout for a
    // bridge that has not had a chance to change. Reported through the same callback as a real
    // check would be, so the QR bottom sheet's row still updates (and the bridge stays out of
    // the set that gets added), just without a fresh network attempt.
    let store = BridgeStore::load(BridgeStore::resolve_path(Some(config_path))).ok();
    let today = time::OffsetDateTime::now_utc();
    let (dead_today, to_check): (Vec<_>, Vec<_>) = bridges
        .into_iter()
        .partition(|b| store.as_ref().is_some_and(|s| s.failed_today(b, today)));
    for bridge in &dead_today {
        emit(
            bridge,
            Err("this bridge already failed a check earlier today".to_owned()),
        );
    }

    verify_bridges_parallel(
        &live_cache_dir,
        &scratch_base,
        to_check,
        pt_binary,
        VERIFY_BRIDGE_BOOTSTRAP_TIMEOUT,
        VERIFY_BRIDGE_PROBE_TIMEOUT,
        QR_VERIFY_CONCURRENCY,
        emit,
    );

    let _ = std::fs::remove_dir_all(&scratch_base);
    callback.emit_done();
}
#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashSet;

    const MARKER: &str = "pt-0123456789ab";

    fn child(pid: u32, ppid: u32, comm: &[u8]) -> ChildProc {
        ChildProc {
            pid,
            ppid,
            comm: comm.to_vec(),
        }
    }

    fn markers() -> HashSet<String> {
        HashSet::from([MARKER.to_owned()])
    }

    /// The stability-review section 2 scenario: the main engine's PT restarted
    /// mid-check (brand-new pid, normal binary name, no marker). The old
    /// baseline-diff killed exactly this child; marker-based ownership makes
    /// that impossible regardless of how "new" it is.
    #[test]
    fn kill_targets_spares_restarted_main_pt() {
        let children = [child(80, 7, b"libtorpthelper")];
        assert!(reap_targets(&children, 7, &markers()).is_empty());
    }

    #[test]
    fn kill_targets_kills_only_marker_named_children() {
        let children = [
            child(80, 7, MARKER.as_bytes()),
            child(81, 7, b"libtorpthelper"),
            child(82, 7, b"somethingelse"),
        ];
        assert_eq!(reap_targets(&children, 7, &markers()), vec![80]);
    }

    #[test]
    fn kill_targets_spares_non_children() {
        // Marker-named but not our child: never touched, full stop.
        let children = [child(80, 8, MARKER.as_bytes())];
        assert!(reap_targets(&children, 7, &markers()).is_empty());
    }

    #[test]
    fn kill_targets_never_targets_self() {
        let my_pid = std::process::id();
        let children = [child(my_pid, 1, MARKER.as_bytes())];
        assert!(reap_targets(&children, my_pid, &markers()).is_empty());
    }

    #[test]
    fn kill_targets_empty_registry_kills_nothing() {
        // The copy-failure degenerate path never kills: no regression to guessing.
        let children = [child(80, 7, MARKER.as_bytes())];
        assert!(reap_targets(&children, 7, &HashSet::new()).is_empty());
    }

    /// Cheap unique temp dir without `tempfile` (not a dev-dependency here).
    fn unique_temp_dir(tag: &str) -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "jni-verify-test-{}-{}-{}-{tag}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir temp dir");
        dir
    }

    #[test]
    fn create_kill_marker_makes_unique_registered_names() {
        let base = unique_temp_dir("marker");
        let scratch = base.join("scratch");
        let fake_pt = base.join("fake-pt");
        std::fs::write(&fake_pt, b"pretend PT binary").expect("write fake pt");

        let marker_a = pt_reap::create_kill_marker(&fake_pt, &scratch).expect("marker a");
        let marker_b = pt_reap::create_kill_marker(&fake_pt, &scratch).expect("marker b");
        assert_ne!(marker_a, marker_b, "names must be unique per call");
        for name in [&marker_a, &marker_b] {
            assert_eq!(name.len(), 15, "must be exactly TASK_COMM_LEN-1 bytes");
            assert!(name.starts_with("pt-"), "must carry the pt- prefix");
        }

        let content = std::fs::read(&fake_pt).expect("read fake pt");
        assert_eq!(
            std::fs::read(scratch.join(&marker_a)).expect("read marker a"),
            content
        );
        assert_eq!(
            std::fs::read(scratch.join(&marker_b)).expect("read marker b"),
            content
        );
        let registered = pt_reap::current_markers();
        assert!(registered.contains(&marker_a));
        assert!(registered.contains(&marker_b));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn pt_binary_comm_truncates_to_15_bytes() {
        // "libtorpthelper.so" is 18 bytes; the first 15 cut mid-extension.
        let comm = pt_binary_comm(std::path::Path::new(
            "/data/app/org.torproject/lib/libtorpthelper.so",
        ));
        assert_eq!(comm, b"libtorpthelper.");
        assert_eq!(comm.len(), 15);
    }
}
