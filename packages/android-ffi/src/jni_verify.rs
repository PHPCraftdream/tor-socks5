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
///   after the runtime it belonged to was gone. So this also snapshots this process's own child
///   PIDs before the check and kills (`SIGKILL`) whatever new one is still alive after --
///   Android-only (`pt_reap` below), a no-op elsewhere.
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

    for (idx, bridge) in bridges.into_iter().enumerate() {
        let check_dir = scratch_base.join(idx.to_string());
        let baseline_children = pt_reap::own_child_pids();
        let result = check_one_bridge(
            &bridge,
            &check_dir,
            cache_dir.clone(),
            pt_binary.clone(),
            bootstrap_timeout,
            probe_timeout,
        );
        pt_reap::kill_new_children(&baseline_children);
        on_result(&bridge, result);
    }
}

/// Same real end-to-end check as [`verify_bridges_sequential`], but runs up to `concurrency`
/// bridges at once, each on its own OS thread -- for the QR-scan flow, where a scanned batch is
/// often mostly-dead bridges and checking them one at a time means the user watches the whole
/// batch's timeout budget serialize even though each check is fully independent.
///
/// The `pt_reap` snapshot/kill (see `verify_bridges_sequential`'s doc for why it exists at all)
/// brackets the *whole* batch here instead of each bridge individually: killing "every child new
/// since the last snapshot" after one thread's check finishes isn't safe when another thread's
/// check is still running concurrently and may itself have just spawned its own still-needed PT
/// child. Correctness costs a little promptness -- a leaked helper from an early-finishing check
/// survives until the slowest check in the batch completes, not until its own check does.
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
    let queue = Mutex::new(bridges.into_iter().enumerate());
    let baseline_children = pt_reap::own_child_pids();

    std::thread::scope(|scope| {
        for _ in 0..concurrency.max(1) {
            let queue = &queue;
            let cache_dir = cache_dir.clone();
            let pt_binary = pt_binary.clone();
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
                    pt_binary.clone(),
                    bootstrap_timeout,
                    probe_timeout,
                );
                on_result(&bridge, result);
            });
        }
    });

    pt_reap::kill_new_children(&baseline_children);
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
/// [`verify_bridges_parallel`], which bracket their own `pt_reap` snapshot/kill around one or
/// more calls to this, at different granularity.
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

/// Reaps `libtorpthelper` processes a throwaway verify client's arti client leaves running --
/// see [`verify_bridges_sequential`]'s doc for why nothing short of an explicit kill reliably
/// stops them. `target_os = "android"`-only (mirrors `android_log.rs`'s split): host builds
/// (`cargo test`) never spawn a real PT child, so there is nothing to reap.
#[cfg(target_os = "android")]
mod pt_reap {
    use std::collections::HashSet;
    use std::fs;

    /// PIDs of live children of this process, read from `/proc`. Linux's process tree has no
    /// concept of "which logical client spawned this" -- every child of our own PID shows up
    /// here regardless of which throwaway `TorTunnel` (or the long-lived main engine) started
    /// it, which is why callers snapshot this immediately before their own check and diff
    /// against a fresh snapshot after, rather than trusting any single call's result alone.
    pub(crate) fn own_child_pids() -> HashSet<u32> {
        let my_pid = std::process::id();
        let mut children = HashSet::new();
        let Ok(entries) = fs::read_dir("/proc") else {
            return children;
        };
        for entry in entries.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let Ok(stat) = fs::read_to_string(entry.path().join("stat")) else {
                continue;
            };
            // Format: "pid (comm) state ppid ...". `comm` can itself contain spaces or
            // parentheses, so find the *last* ')' before splitting the remaining fields.
            let Some(after_comm) = stat.rsplit_once(')').map(|(_, rest)| rest) else {
                continue;
            };
            let mut fields = after_comm.split_whitespace();
            let _state = fields.next();
            let Some(ppid) = fields.next().and_then(|s| s.parse::<u32>().ok()) else {
                continue;
            };
            if ppid == my_pid {
                children.insert(pid);
            }
        }
        children
    }

    /// Kills (`SIGKILL`) every currently-live child not present in `baseline`. Narrow by
    /// construction, not by filtering on process name: a caller that snapshots `baseline`
    /// immediately before its own check, and calls this immediately after, only ever sees its
    /// own check's child as "new" -- the main engine's own long-lived PT helper was already
    /// running before the snapshot and is therefore never a candidate.
    pub(crate) fn kill_new_children(baseline: &HashSet<u32>) {
        for pid in own_child_pids() {
            if !baseline.contains(&pid) {
                // Safety: `kill(2)` on a PID we just observed as our own child. Failure (the
                // process already exited on its own between the scan and this call) is not an
                // error worth surfacing -- the end state either way is "not running".
                unsafe {
                    libc::kill(pid as libc::pid_t, libc::SIGKILL);
                }
            }
        }
    }
}

#[cfg(not(target_os = "android"))]
mod pt_reap {
    use std::collections::HashSet;

    pub(crate) fn own_child_pids() -> HashSet<u32> {
        HashSet::new()
    }

    pub(crate) fn kill_new_children(_baseline: &HashSet<u32>) {}
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
