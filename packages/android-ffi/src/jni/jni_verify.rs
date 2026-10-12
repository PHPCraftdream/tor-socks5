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

/// Per-process monotonic sequence for scratch directory names.
static SCRATCH_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Guaranteed-fresh per-call scratch dir: `<base>/<kind>-<pid>-<seq>` created
/// EXCLUSIVELY. The pid disambiguates live processes; a stale dir left by a
/// previous run of the same pid collides with an early sequence value and is
/// skipped because `create_dir` refuses to share — each retry advances the
/// monotonic counter, so any finite set of stale names is exhausted and two
/// calls can never share a directory. Real setup errors surface as `Err`.
pub(crate) fn batch_scratch_dir(
    config_path: Option<&std::path::Path>,
    kind: &str,
) -> std::io::Result<std::path::PathBuf> {
    let base = match config_path {
        Some(config_path) => scratch_dir(config_path, kind),
        None => std::path::Path::new("verify-scratch").join(kind),
    };
    create_exclusive_scratch(&base, kind, &SCRATCH_SEQ)
}

/// Core allocator with an injectable counter for deterministic tests.
pub(crate) fn create_exclusive_scratch(
    base: &std::path::Path,
    kind: &str,
    counter: &std::sync::atomic::AtomicU64,
) -> std::io::Result<std::path::PathBuf> {
    std::fs::create_dir_all(base)?;
    loop {
        let seq = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let candidate = base.join(format!("{kind}-{}-{seq}", std::process::id()));
        match std::fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            // Exclusive creation: an existing dir OR file at the path means a
            // stale entry, never a shareable directory — try the next value.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
}
/// The exact TOR_PT_STATE_LOCATION byte token (see
/// bridge_verify_core::pt_reap::pt_state_location_token); an empty token makes
/// the sweep a no-op (it is always invoked).
pub(super) fn pt_kill_token(check_dir: &std::path::Path, pt_binary: &std::path::Path) -> Vec<u8> {
    bridge_verify_core::pt_reap::pt_state_location_token(check_dir, pt_binary)
        .into_os_string()
        .into_encoded_bytes()
}

/// Thin delegate to the shared implementation in `bridge-verify-core`, keeping
/// this crate's historical `"bridge-verify: "` log prefix. See the shared
/// `snapshot_cache_dir` doc for the full contract. Android has no shared
/// admission deadline, so the snapshot keeps only its own backup budget.
pub(super) fn snapshot_cache_dir(src: &std::path::Path, dest: &std::path::Path) -> bool {
    bridge_verify_core::snapshot::snapshot_cache_dir(src, dest, "bridge-verify: ", None)
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
///   explicitly, by *ownership* rather than time of appearance: each check launches the
///   ORIGINAL PT binary path (never a copy: Android W^X forbids executing a scratch copy --
///   observed `PermissionDenied` os error 13 on MIUI), and tor-ptmgr passes that check a
///   `TOR_PT_STATE_LOCATION` derived from the check's own state dir, so each check's PT child
///   carries a *unique* exact byte token in `/proc/<pid>/environ` (see
///   [`pt_kill_token`]). After a check's runtime is shut down,
///   [`pt_reap::kill_own_state_children`] `SIGKILL`s the children whose environ carries that
///   exact token. Fail closed: unprovable ownership is never killed (and warned about); there
///   is no global registry, so overlapping batches, sibling parallel checks, and the main
///   engine's PT can never match -- their state locations differ by construction.
///   See `docs/stability-review-2026-09-08.md` section 2 for the ownership analysis.
/// - **A cache *snapshot*, not the live directory.** `tor_dirmgr`'s storage is a single sqlite
///   file, opened with its own fresh `rusqlite::Connection` here, completely independent of the
///   main engine's already-open connection to that same file. Sqlite's default `busy_timeout`
///   is zero, so with the main engine writing to it every fraction of a second (routine
///   consensus/microdescriptor upkeep), a throwaway client sharing the live file hits
///   `SQLITE_BUSY` on nearly every read or write of its own -- including storing the fetched
///   bridge descriptor, so the guard's directory info never completes and every check times out
///   waiting on a circuit that can never build, regardless of the bridge's real reachability. An
///   SQLite Online Backup API snapshot (`sqlite3_backup_*` via `rusqlite::backup`), taken before
///   the batch starts, gets the same "skip the cold consensus fetch" speed benefit without
///   contending with the live writer; if no consistent snapshot can be produced (missing or
///   unreadable source database, backup timeout/error), the batch falls back to an explicitly
///   clean empty cache dir the check client cold-starts in.
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
        // The ORIGINAL PT executable path, never a copy: Android W^X makes a
        // scratch copy unexecutable (PermissionDenied os error 13 on MIUI).
        // Ownership of the spawned PT child rests on its unique per-check
        // state-location token, established inside `check_one_bridge`.
        let result = check_one_bridge(
            &bridge,
            &check_dir,
            cache_dir.clone(),
            pt_binary.clone(),
            bootstrap_timeout,
            probe_timeout,
        );
        on_result(&bridge, result);
    }
}

/// Same real end-to-end check as [`verify_bridges_sequential`], but runs up to `concurrency`
/// bridges at once, each on its own OS thread -- for the QR-scan flow, where a scanned batch is
/// often mostly-dead bridges and checking them one at a time means the user watches the whole
/// batch's timeout budget serialize even though each check is fully independent.
///
/// PT-child reaping needs no batch-level bracket here: each check's ownership token is unique
/// per check dir, so the per-check sweep inside [`execute_bridge_check`] (driven by
/// [`check_one_bridge`]'s runner wiring) is safe mid-batch -- a thread's sweep cannot match another thread's still-running child (different check dir,
/// different `TOR_PT_STATE_LOCATION`). That restores the promptness the old one-sweep-after-join
/// scheme gave up: a leaked helper is reaped when ITS check ends, not when the slowest one does.
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
                // The ORIGINAL PT executable path, never a marker copy (see
                // `verify_bridges_sequential` for why copies are off-limits).
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
}

/// One-time cache-dir snapshot shared by every check in a batch -- see
/// [`verify_bridges_sequential`]'s doc for why a snapshot, not the live directory.
pub(super) fn shared_cache_snapshot(
    live_cache_dir: &std::path::Path,
    scratch_base: &std::path::Path,
) -> Option<std::path::PathBuf> {
    let cache_snapshot = scratch_base.join("cache-snapshot");
    snapshot_cache_dir(live_cache_dir, &cache_snapshot).then_some(cache_snapshot)
}

/// Real check lifecycle: fresh current-thread runtime, future polled to
/// completion (timeouts live inside the verification future), bounded
/// `shutdown_timeout` on EVERY exit — success, error, and panic caught here
/// and surfaced as Err — so cleanup never relies on an implicit Runtime::drop.
pub(super) fn drive_check_future<E>(
    fut: impl std::future::Future<Output = std::result::Result<Duration, E>>,
) -> std::result::Result<Duration, String>
where
    E: std::fmt::Display,
{
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("failed to create runtime: {e}"))?;
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| rt.block_on(fut)));
    rt.shutdown_timeout(VERIFY_BRIDGE_RUNTIME_SHUTDOWN_GRACE);
    match outcome {
        Ok(result) => result.map_err(|e| e.to_string()),
        Err(payload) => {
            tracing::warn!(panic = ?payload, "bridge check panicked; runtime shut down");
            Err("bridge check panicked".to_owned())
        }
    }
}

/// Runner for one check: production builds the throwaway current-thread
/// Runner for one check: production wraps the real verification in
/// [`drive_check_future`]. Injected so host tests can capture the
/// constructed config and observe ordering.
pub(super) type CheckRun<'a> =
    dyn Fn(arti_wrapper::BridgeCheckSettings) -> std::result::Result<Duration, String> + 'a;
/// Owned-child cleanup backend (production: `pt_reap::kill_own_state_children`).
pub(super) type ChildReap<'a> = dyn Fn(&[u8], &[u8]) -> pt_reap::KillReport + 'a;

/// The two seams [`execute_bridge_check`] drives, in order: `run` then (via
/// the cleanup guard) `reap`.
pub(super) struct CheckRunners<'a> {
    pub run: &'a CheckRun<'a>,
    pub reap: &'a ChildReap<'a>,
}

/// Runs the owned-child sweep and scratch removal EXACTLY ONCE, when dropped:
/// after the runner returned (runtime already shut down) or after an unwind
/// dropped the runtime — so teardown always precedes cleanup. Panic-free body.
struct CheckCleanupGuard<'a> {
    check_dir: &'a std::path::Path,
    token: &'a [u8],
    pt_name: &'a [u8],
    reap: &'a ChildReap<'a>,
}
impl Drop for CheckCleanupGuard<'_> {
    fn drop(&mut self) {
        let report = (self.reap)(self.token, self.pt_name);
        if report.killed > 0 || report.already_gone > 0 {
            tracing::debug!(
                killed = report.killed,
                already_gone = report.already_gone,
                "reaped leaked PT children by state-location token"
            );
        }
        if !report.failures.is_empty() {
            tracing::warn!(count = report.failures.len(), failures = ?report.failures,
                "PT child cleanup failure; leak possible (fail-closed, no numeric-kill fallback)");
        }
        let _ = std::fs::remove_dir_all(self.check_dir);
    }
}

/// Runs one bridge check with lifecycle guarantees: the runner owns
/// bootstrap/probe/timeout (and the runtime shutdown, via [`drive_check_future`]),
/// the guard owns cleanup, and a panic in the runner is caught, surfaced as a
/// check failure, and STILL cleaned up before the guard's sweep runs.
pub(super) fn execute_bridge_check(
    bridge: &bridge_line::BridgeLine,
    check_dir: &std::path::Path,
    cache_dir: Option<std::path::PathBuf>,
    pt_binary: Option<std::path::PathBuf>,
    runners: &CheckRunners<'_>,
) -> std::result::Result<Duration, String> {
    if bridge.transport.is_some() && pt_binary.is_none() {
        return Err("bridge requires a pluggable transport, but none is available".to_owned());
    }
    // Derive the check's identity BEFORE `pt_binary` moves into the settings.
    let kill_token = pt_binary
        .as_ref()
        .map(|pb| pt_kill_token(check_dir, pb))
        .unwrap_or_default();
    let pt_name = pt_binary
        .as_ref()
        .map(|pb| pt_reap::pt_binary_comm(pb))
        .unwrap_or_default();
    if let Err(e) = std::fs::create_dir_all(check_dir) {
        return Err(format!("could not create scratch directory: {e}"));
    }
    // Held for its Drop.
    let _check_cleanup = CheckCleanupGuard {
        check_dir,
        token: &kill_token,
        pt_name: &pt_name,
        reap: runners.reap,
    };
    let check = arti_wrapper::BridgeCheckSettings {
        bridge: bridge.clone(),
        pt_binary,
        cache_dir,
        state_dir: check_dir.to_path_buf(),
    };
    // AssertUnwindSafe: the closure owns only throwaway check state — there
    // is no shared invariant to poison, and cleanup is token-based and
    // revalidated, so resuming after a panic is safe.
    let outcome =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || (runners.run)(check)));
    let result = match outcome {
        Ok(result) => result,
        Err(payload) => {
            tracing::warn!(panic = ?payload, "bridge check panicked; runtime dropped, cleanup continues");
            Err("bridge check panicked".to_owned())
        }
    };
    result // guard drops HERE, on every path
}

/// Checks exactly one bridge for real end-to-end reachability: production
/// wiring around [`execute_bridge_check`], supplying the real runner
/// ([`drive_check_future`]) and the real owned-child sweep.
pub(super) fn check_one_bridge(
    bridge: &bridge_line::BridgeLine,
    check_dir: &std::path::Path,
    cache_dir: Option<std::path::PathBuf>,
    pt_binary: Option<std::path::PathBuf>,
    bootstrap_timeout: Duration,
    probe_timeout: Duration,
) -> std::result::Result<Duration, String> {
    let run = |check: arti_wrapper::BridgeCheckSettings| {
        drive_check_future(arti_wrapper::TorTunnel::verify_bridge_reachable(
            check,
            (engine::LIVE_PROBE_TARGET, engine::LIVE_PROBE_PORT),
            bootstrap_timeout,
            probe_timeout,
        ))
    };
    let reap = |token: &[u8], name: &[u8]| pt_reap::kill_own_state_children(token, name);
    execute_bridge_check(
        bridge,
        check_dir,
        cache_dir,
        pt_binary,
        &CheckRunners {
            run: &run,
            reap: &reap,
        },
    )
}

/// How many bridges [`verify_bridges_blocking`] checks at once. The QR-scan flow has a user
/// actively watching a live progress list, often of a batch that turns out to be mostly dead --
/// unlike the background circuit-verify tick (`engine.rs`), which has no one waiting and checks
/// at most a couple of bridges every half hour, this one is worth parallelizing. Kept modest:
/// each check runs its own `arti_client` (guard selection, consensus/microdescriptor lookups),
/// not just a socket, so unbounded concurrency would trade wall-clock for phone memory/CPU.
pub(super) const QR_VERIFY_CONCURRENCY: usize = 4;

/// Worker behind [`nativeVerifyBridges`]. Called from a dedicated OS thread, never from the main
/// engine's own runtime, so the two never contend. Its scratch base is guaranteed-fresh via
/// exclusive creation (see [`batch_scratch_dir`]), so overlapping invocations (two manual QR
/// scans, or a scan overlapping the background tick) can neither collide on check dirs nor
/// delete each other's scratch. A scratch setup failure is reported per-bridge as an
/// unavailable verdict rather than silently skipped.
pub(super) fn verify_bridges_blocking(
    config_path: &str,
    bridges: Vec<bridge_line::BridgeLine>,
    pt_binary: Option<std::path::PathBuf>,
    callback: &callback::JavaBridgeCheckCallback,
) {
    let config_path = std::path::Path::new(config_path);
    let live_cache_dir = arti_cache_dir(config_path);

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

    let scratch_base = match batch_scratch_dir(Some(config_path), "bridge-check") {
        Ok(dir) => dir,
        Err(e) => {
            tracing::error!(error = %e, "bridge-verify: could not create scratch directory");
            for bridge in &to_check {
                emit(
                    bridge,
                    Err(format!(
                        "verification unavailable: could not create scratch directory: {e}"
                    )),
                );
            }
            callback.emit_done();
            return;
        }
    };
    // Batch scratch cleanup on every path: success, error, or unwind.
    let _scratch_guard = BatchScratchGuard(&scratch_base);

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

    callback.emit_done();
}

/// Removes the batch scratch dir when dropped — success, error, or unwind.
struct BatchScratchGuard<'a>(&'a std::path::Path);
impl Drop for BatchScratchGuard<'_> {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.0);
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    // Device-only limits: the /proc environ kill path and the real spawn
    // contract can only be validated on an Android device. Host tests cover
    // the pure decision (in `bridge-verify-core`), the token wiring, and
    // scratch isolation below.

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
    fn pt_kill_token_is_exact_state_location() {
        // Pins the wiring actually used by check_one_bridge. ".so" survives
        // on every platform because "so" never equals EXE_EXTENSION.
        let token = pt_kill_token(
            std::path::Path::new("check-A"),
            std::path::Path::new("native/libtorpthelper.so"),
        );
        let expected = std::path::PathBuf::from("check-A")
            .join("state")
            .join("pt_state")
            .join("libtorpthelper.so")
            .into_os_string()
            .into_encoded_bytes();
        assert_eq!(token, expected);

        // A binary with no file name ("../") yields no identifier component:
        // the token is just base/state/pt_state bytes (PathBuf::new() join
        // adds nothing), matching tor-ptmgr's NotAFile refusal degenerate.
        let token = pt_kill_token(std::path::Path::new("check-A"), std::path::Path::new("../"));
        // Raw-byte comparison, so the expected value must go through the
        // identical join chain -- joining an empty identifier appends a
        // trailing separator, which is part of the bytes on every platform.
        let expected = std::path::PathBuf::from("check-A")
            .join("state")
            .join("pt_state")
            .join(std::path::PathBuf::new())
            .into_os_string()
            .into_encoded_bytes();
        assert_eq!(token, expected);
    }

    /// (token, pt_name) seen by the fake reap.
    type ReapedArgs = Option<(Vec<u8>, Vec<u8>)>;
    #[derive(Default, Clone)]
    struct Harness {
        events: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        captured: std::sync::Arc<std::sync::Mutex<Option<arti_wrapper::BridgeCheckSettings>>>,
        // Kept out of `events` so the ordering assertions stay exact.
        reaped: std::sync::Arc<std::sync::Mutex<ReapedArgs>>,
    }

    /// Set to true when the wrapped value is dropped.
    struct DropSentinel(std::sync::Arc<std::sync::atomic::AtomicBool>);
    impl Drop for DropSentinel {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }

    fn push(harness: &Harness, event: &str) {
        harness
            .events
            .lock()
            .expect("event lock")
            .push(event.to_owned());
    }

    /// Fake run closure: records the call and captures the constructed
    /// settings; outcome injected per test.
    fn fake_run(
        harness: &Harness,
        outcome: std::result::Result<Duration, String>,
    ) -> impl Fn(arti_wrapper::BridgeCheckSettings) -> std::result::Result<Duration, String> + Clone
    {
        let harness = harness.clone();
        move |check| {
            push(&harness, "run");
            *harness.captured.lock().expect("captured lock") = Some(check);
            outcome.clone()
        }
    }

    /// Fake reap closure: records the sweep, asserts the check dir still
    /// exists at sweep time (scratch removal must happen AFTER the sweep),
    /// and records the received token/pt_name.
    fn fake_reap(
        harness: &Harness,
        check_dir: std::path::PathBuf,
    ) -> impl Fn(&[u8], &[u8]) -> pt_reap::KillReport + Clone {
        let harness = harness.clone();
        move |token, pt_name| {
            push(&harness, "sweep");
            std::assert!(check_dir.exists(), "sweep must run before scratch removal");
            *harness.reaped.lock().expect("reaped lock") = Some((token.to_vec(), pt_name.to_vec()));
            pt_reap::KillReport::default()
        }
    }

    fn events_of(harness: &Harness) -> Vec<String> {
        harness.events.lock().expect("event lock").clone()
    }

    #[test]
    fn execute_bridge_check_forwards_original_pt_binary() {
        let harness = Harness::default();
        let check_dir = unique_temp_dir("forward");
        std::fs::create_dir_all(&check_dir).expect("mkdir check dir");
        let original = std::path::PathBuf::from("fake-pt/libtorpthelper.so");
        let bridge: bridge_line::BridgeLine =
            "1.2.3.4:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01"
                .parse()
                .expect("bridge line");
        let run = fake_run(&harness, Ok(Duration::ZERO));
        let reap = fake_reap(&harness, check_dir.clone());
        let result = execute_bridge_check(
            &bridge,
            &check_dir,
            None,
            Some(original.clone()),
            &CheckRunners {
                run: &run,
                reap: &reap,
            },
        );
        std::assert!(result.is_ok());
        let captured = harness
            .captured
            .lock()
            .expect("captured lock")
            .take()
            .expect("runner was called");
        // The ORIGINAL executable path is forwarded verbatim into the check
        // settings (never a copy), and the state dir is the check's own.
        std::assert_eq!(captured.pt_binary.as_deref(), Some(original.as_path()));
        std::assert_eq!(captured.state_dir, check_dir);
        std::assert_eq!(captured.bridge.to_string(), bridge.to_string());
        // The sweep saw the token/comm derived from the SAME original path.
        let (token, pt_name) = harness
            .reaped
            .lock()
            .expect("reaped lock")
            .take()
            .expect("reap was called");
        std::assert_eq!(token, pt_kill_token(&check_dir, &original));
        std::assert_eq!(pt_name, pt_reap::pt_binary_comm(&original));
        let _ = std::fs::remove_dir_all(&check_dir);
    }

    #[test]
    fn drive_check_future_shuts_runtime_before_returning() {
        let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let inner = std::sync::Arc::clone(&flag);
        let result = drive_check_future(async move {
            let sentinel = DropSentinel(inner);
            tokio::spawn(async move {
                let _keep_alive = sentinel;
                std::future::pending::<()>().await;
            });
            Ok::<Duration, std::convert::Infallible>(Duration::from_millis(1))
        });
        std::assert!(result.is_ok());
        std::assert!(
            flag.load(std::sync::atomic::Ordering::Relaxed),
            "spawned task dropped by shutdown_timeout before the helper returned"
        );
    }

    #[test]
    fn drive_check_future_surfaces_timeout_of_pending_future() {
        let result = drive_check_future(async {
            tokio::time::timeout(Duration::from_millis(50), std::future::pending::<()>())
                .await
                .map(|_: ()| Duration::ZERO)
        });
        match result {
            Err(e) => std::assert!(e.contains("elapsed"), "timeout surfaced: {e}"),
            Ok(_) => panic!("expected Err for a pending future"),
        }
    }

    #[test]
    fn drive_check_future_catches_panic_and_still_shuts_down() {
        let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let inner = std::sync::Arc::clone(&flag);
        let result = drive_check_future::<std::convert::Infallible>(async move {
            let sentinel = DropSentinel(inner);
            tokio::spawn(async move {
                let _keep_alive = sentinel;
                std::future::pending::<()>().await;
            });
            panic!("boom")
        });
        match result {
            Err(e) => std::assert!(e.contains("panicked"), "panic surfaced: {e}"),
            Ok(_) => panic!("expected Err after panic"),
        }
        std::assert!(
            flag.load(std::sync::atomic::Ordering::Relaxed),
            "spawned task dropped by shutdown_timeout despite the panic"
        );
    }

    #[test]
    fn execute_bridge_check_reaps_after_runtime_shutdown() {
        let harness = Harness::default();
        let check_dir = unique_temp_dir("reap");
        std::fs::create_dir_all(&check_dir).expect("mkdir check dir");
        let bridge: bridge_line::BridgeLine =
            "1.2.3.4:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01"
                .parse()
                .expect("bridge line");
        let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let run_flag = std::sync::Arc::clone(&flag);
        let run = move |_check: arti_wrapper::BridgeCheckSettings| {
            let spawned_flag = std::sync::Arc::clone(&run_flag);
            drive_check_future::<std::convert::Infallible>(async move {
                let sentinel = DropSentinel(spawned_flag);
                tokio::spawn(async move {
                    let _keep_alive = sentinel;
                    std::future::pending::<()>().await;
                });
                panic!("boom")
            })
        };
        let reap = |token: &[u8], pt_name: &[u8]| {
            push(&harness, "sweep");
            std::assert!(
                flag.load(std::sync::atomic::Ordering::Relaxed),
                "spawned task dropped before reap"
            );
            *harness.reaped.lock().expect("reaped lock") = Some((token.to_vec(), pt_name.to_vec()));
            pt_reap::KillReport::default()
        };
        let result = execute_bridge_check(
            &bridge,
            &check_dir,
            None,
            None,
            &CheckRunners {
                run: &run,
                reap: &reap,
            },
        );
        match result {
            Err(e) => std::assert!(e.contains("panicked"), "panic surfaced: {e}"),
            Ok(_) => panic!("expected Err after panic"),
        }
        // No "shutdown" events: the real shutdown is proven by the sentinel
        // flag, observed true at reap time above.
        std::assert_eq!(events_of(&harness), vec!["sweep"]);
        std::assert!(!check_dir.exists(), "scratch removed after the sweep");
        let _ = std::fs::remove_dir_all(&check_dir);
    }

    #[test]
    fn create_exclusive_scratch_skips_existing_collision() {
        let base = unique_temp_dir("scratch-base");
        let counter = std::sync::atomic::AtomicU64::new(0);
        let first = create_exclusive_scratch(&base, "kind", &counter).expect("first alloc");
        let name = first.file_name().unwrap().to_string_lossy().into_owned();
        std::assert_eq!(
            name,
            format!("kind-{}-0", std::process::id()),
            "first call takes sequence 0"
        );
        // Process restart reusing the pid: counter back at 0 while the stale
        // -0 dir still exists -- the forced-collision regression case.
        counter.store(0, std::sync::atomic::Ordering::Relaxed);
        let second = create_exclusive_scratch(&base, "kind", &counter).expect("second alloc");
        std::assert!(first.exists(), "stale -0 dir left untouched");
        std::assert_ne!(first, second, "collision must be skipped, not shared");
        std::assert!(
            second
                .file_name()
                .unwrap()
                .to_string_lossy()
                .ends_with("-1"),
            "retry advanced the counter past the stale name: {second:?}"
        );
        let third = create_exclusive_scratch(&base, "kind", &counter).expect("third alloc");
        let fourth = create_exclusive_scratch(&base, "kind", &counter).expect("fourth alloc");
        std::assert_ne!(third, fourth);
        std::assert_ne!(second, third);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn create_exclusive_scratch_surfaces_setup_errors() {
        // An existing FILE at the base path: create_dir_all must fail and the
        // error must surface, not be swallowed as "retry forever".
        let base = unique_temp_dir("setup-err");
        let blocker = base.join("not-a-dir");
        std::fs::write(&blocker, b"x").expect("write blocker file");
        let counter = std::sync::atomic::AtomicU64::new(0);
        let result = create_exclusive_scratch(&blocker, "kind", &counter);
        std::assert!(result.is_err(), "setup error must surface as Err");
        let _ = std::fs::remove_dir_all(&base);
    }
}
