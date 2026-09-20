use super::*;

/// How long `nativeStop` waits for the engine thread (unchanged 10s contract).
const STOP_JOIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Build the settings used by the Android MAIN engine. Keeping this in one
/// helper makes startup and any future in-process reconfiguration share the
/// same stream-open policy; bridge verifiers do not call it.
pub(crate) fn main_engine_settings(
    bridges: Vec<bridge_line::BridgeLine>,
    pt_binary: Option<std::path::PathBuf>,
    state_dir: std::path::PathBuf,
    obfs4_iat_mode: Option<u8>,
) -> arti_wrapper::Settings {
    arti_wrapper::Settings {
        bridges,
        pt_binary,
        state_dir: Some(state_dir),
        obfs4_iat_mode,
        initial_connect_timeout: Some(Duration::from_secs(4)),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::main_engine_settings;

    #[test]
    fn main_engine_settings_opts_into_fast_first_exit_attempt() {
        let settings = main_engine_settings(Vec::new(), None, "state".into(), None);
        assert_eq!(
            settings.initial_connect_timeout,
            Some(std::time::Duration::from_secs(4))
        );
        assert!(!settings.is_default());
    }
}

/// First phase of `nativeStop`, run under the ENGINE lock. Pure state
/// transition — no status writes, no waiting (side-effect-free so it is
/// directly unit-testable).
pub(crate) fn begin_engine_stop(slot: &mut EngineSlot) -> StopHandoff {
    if matches!(slot, EngineSlot::Stopping(None)) {
        return StopHandoff::InProgress;
    }
    let owned = std::mem::replace(slot, EngineSlot::Stopping(None));
    match owned {
        EngineSlot::Idle => {
            *slot = EngineSlot::Idle;
            StopHandoff::Idle
        }
        EngineSlot::Running(handle) | EngineSlot::Stopping(Some(handle)) => {
            StopHandoff::Checkout(handle)
        }
        EngineSlot::Stopping(None) => {
            unreachable!("Stopping(None) handled above: another nativeStop already owns the handle")
        }
    }
}

/// Second phase of `nativeStart`'s slot check, run under the ENGINE lock.
/// Pure state transition (the join of a finished thread is the only effect,
/// and it cannot block: the thread is already dead). `Err` carries the exact
/// `IllegalStateException` message for the JNI caller.
pub(crate) fn acquire_engine_slot_for_start(slot: &mut EngineSlot) -> Result<(), &'static str> {
    match slot {
        EngineSlot::Idle => Ok(()),
        EngineSlot::Running(handle) => {
            if handle.thread.is_finished() {
                // Clean up the finished thread before reusing the slot.
                let handle = std::mem::replace(slot, EngineSlot::Idle);
                if let EngineSlot::Running(handle) = handle {
                    let _ = handle.thread.join();
                }
                Ok(())
            } else {
                Err("torsocks5 engine already running; call nativeStop first")
            }
        }
        EngineSlot::Stopping(_) => {
            Err("torsocks5 engine is still stopping; call nativeStop again or wait")
        }
    }
}

/// While a checked-out engine handle is parked here, a `Drop` (normal or
/// unwind) returns it to the slot as `Stopping(Some(_))` so the handle is
/// never lost.
struct StoppingParker(Option<EngineHandle>);

impl Drop for StoppingParker {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            let engine_guard = get_engine().lock().unwrap_or_else(|p| p.into_inner());
            let mut engine_guard = engine_guard;
            if matches!(*engine_guard, EngineSlot::Stopping(None)) {
                *engine_guard = EngineSlot::Stopping(Some(handle));
            } else {
                // Defensive: unreachable — only the `nativeStop` that checked
                // the handle out can move the slot out of `Stopping(None)`.
                let _ = handle.thread.join();
            }
        }
    }
}

impl StoppingParker {
    /// Take the handle out so `Drop` becomes a no-op for the normal paths.
    fn release(mut self) -> Option<EngineHandle> {
        self.0.take()
    }
}

#[derive(Debug)]
pub(crate) enum StopHandoff {
    /// Slot was `Idle`: nothing to stop.
    Idle,
    /// Slot was `Stopping(None)`: another `nativeStop` is already waiting on
    /// the checked-out handle. Caller returns quietly (status is already
    /// owned by that waiter).
    InProgress,
    /// The handle was checked out of the slot (slot is now
    /// `Stopping(None)`); caller owns it until it parks it back or drops it.
    Checkout(EngineHandle),
}

/// JNI entry point: `nativeStart(String configPath, BootstrapCallback callback)`
///
/// See the crate-level documentation for the contract and error semantics.
#[no_mangle]
pub extern "system" fn Java_org_torproject_android_service_TorSocks5Bridge_nativeStart(
    mut env: JNIEnv,
    _class: JClass,
    config_path: JString,
    callback: JObject,
) {
    // SAFETY: The entire body is wrapped in catch_unwind. If a panic occurs,
    // we convert it to a Java exception and return. No panic unwinds across the FFI boundary.
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        // 1. Read and validate config path
        let config_path_str: String = env
            .get_string(&config_path)
            .inspect_err(|_| {
                env.throw_new(
                    "java/lang/IllegalArgumentException",
                    "configPath is null or invalid",
                )
                .ok();
            })?
            .into();

        // 2. Lock ENGINE and check the slot: refuse while a previous engine
        // is still live or a stop is still in flight.
        let mut engine_guard = get_engine().lock().unwrap_or_else(|p| p.into_inner());
        if let Err(msg) = acquire_engine_slot_for_start(&mut engine_guard) {
            let _ = env.throw_new("java/lang/IllegalStateException", msg);
            return Err(anyhow::anyhow!("{msg}"));
        }

        // 3. Load config synchronously
        let loaded = Config::load_with_override(Some(std::path::Path::new(&config_path_str)))
            .with_context(|| format!("loading config from {}", config_path_str))
            .map_err(|e| {
                let msg = format!("{:#}", e);
                let _ = env.throw_new("java/lang/RuntimeException", &msg);
                e
            })?;

        let cfg = match &loaded {
            Loaded::FromFile { config, .. } => config,
            Loaded::Defaults(_) => {
                let _ = env.throw_new(
                    "java/lang/IllegalStateException",
                    "config file not found; must load from an explicit path on Android",
                );
                return Err(anyhow::anyhow!(
                    "config must be loaded from file on Android"
                ));
            }
        };

        // 3a. One-time process init. Must run before any `tracing::info!`/
        // `warn!`/`error!` call below (step 7a's auth-decision logging in
        // particular): with no global `tracing` subscriber installed yet,
        // `tracing` macros are silent no-ops (nothing buffered, nothing
        // deferred — the event is simply dropped at the callsite), so on
        // the very first `nativeStart` in a process, logging anything
        // before this point would vanish even though the code "runs
        // unconditionally and synchronously".
        ensure_crypto_provider();
        ensure_tracing_subscriber(cfg);

        // 4. Parse bridges
        let parsed_bridges = cfg
            .bridges
            .parsed()
            .context("parsing bridges from config")
            .map_err(|e| {
                let msg = format!("{:#}", e);
                let _ = env.throw_new("java/lang/RuntimeException", &msg);
                e
            })?;
        if parsed_bridges.rejected > 0 {
            warn!(
                rejected = parsed_bridges.rejected,
                configured = cfg.bridges.lines.len(),
                "ignored documentation/local-only bridge addresses"
            );
        }
        // Seed any DNS hints carried alongside the configured bridges (e.g.
        // from a QR-imported bridge whose exporter already had it resolved)
        // into the DNS fallback store. Safe regardless of call order versus
        // `engine_async`'s own `load_persisted_dns_cache` -- both merge by
        // recency (see `bridge_probe::seed_disk_fallback`).
        if !parsed_bridges.dns_hints.is_empty() {
            info!(
                hints = parsed_bridges.dns_hints.len(),
                "seeding DNS fallback cache from configured bridge hints"
            );
            bridge_probe::seed_disk_fallback(&parsed_bridges.dns_hints);
        }

        // 5. Parse listen address. The Android engine binds exactly ONE
        // listener (`engine.rs` takes a single SocketAddr, the status
        // string is "On:ADDR", one VPN tun interface points at it), so
        // only the first configured address is used even when the config
        // lists several.
        let listen_addr: std::net::SocketAddr = cfg
            .listen
            .first()
            .with_context(|| "listen: no addresses configured (set `listen` in the config)")?
            .parse()
            .context("parsing listen address")
            .map_err(|e| {
                let msg = format!("{:#}", e);
                let _ = env.throw_new("java/lang/RuntimeException", &msg);
                e
            })?;

        // 6. Pre-validate PT binary requirement
        let needs_pt = parsed_bridges.bridges.iter().any(|b| b.transport.is_some());
        let pt_binary = if needs_pt {
            if let Some(path) = std::env::var_os("TOR_PT_BINARY") {
                if !path.is_empty() {
                    Some(std::path::PathBuf::from(path))
                } else {
                    let _ = env.throw_new(
                        "java/lang/IllegalStateException",
                        "bridges require a pluggable transport, but TOR_PT_BINARY env var is empty; \
                         must point at the lyrebird/obfs4proxy binary shipped in the APK's nativeLibraryDir",
                    );
                    return Err(anyhow::anyhow!("TOR_PT_BINARY is empty"));
                }
            } else {
                let _ = env.throw_new(
                    "java/lang/IllegalStateException",
                    "bridges require a pluggable transport, but TOR_PT_BINARY env var is not set; \
                     must point at the lyrebird/obfs4proxy binary shipped in the APK's nativeLibraryDir",
                );
                return Err(anyhow::anyhow!("TOR_PT_BINARY not set"));
            }
        } else {
            None
        };

        // 7. Resolve state directory (config dir + "arti-data")
        let config_dir = std::path::Path::new(&config_path_str)
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        let state_dir = config_dir.join("arti-data");

        // 7a. Resolve local SOCKS5 (RFC 1929) authentication. Mirrors the
        // CLI's `server.rs`: a users registry that exists and is
        // non-empty switches the listener from anonymous NO_AUTH to
        // USER/PASS. `cfg.auth.enabled = false` is an explicit escape
        // hatch that forces NO_AUTH even if a registry is present; the
        // registry path defaults to the standard sibling-file convention
        // (`{config_stem}.users.ktav` next to `configPath`) but can be
        // overridden via `cfg.auth.users_file`. Either way the decision
        // is logged — this proxy must never silently fall back to
        // anonymous access.
        let auth_state: Option<Arc<AuthState>> = if !cfg.auth.enabled {
            info!("auth: disabled via config (auth.enabled: false) — SOCKS5 will accept anonymous clients");
            None
        } else {
            let users_path = if cfg.auth.users_file.is_empty() {
                UsersConfig::resolve_path(Some(std::path::Path::new(&config_path_str)))
            } else {
                std::path::PathBuf::from(&cfg.auth.users_file)
            };
            let users = UsersConfig::load(&users_path)
                .with_context(|| format!("loading users registry from {}", users_path.display()))
                .map_err(|e| {
                    let msg = format!("{:#}", e);
                    let _ = env.throw_new("java/lang/RuntimeException", &msg);
                    e
                })?;
            if users.users.is_empty() {
                let msg = format!(
                    "auth is enabled but the users registry is empty: {}",
                    users_path.display()
                );
                error!(path = %users_path.display(), "auth: refusing to start an anonymous Android SOCKS5 listener");
                let _ = env.throw_new("java/lang/RuntimeException", &msg);
                return Err(anyhow::anyhow!(msg));
            } else {
                let state = AuthState::build_persistent(&users, users_path.clone())
                    .context("building auth state")
                    .map_err(|e| {
                        let msg = format!("{:#}", e);
                        let _ = env.throw_new("java/lang/RuntimeException", &msg);
                        e
                    })?;
                info!(
                    path = %users_path.display(),
                    users = state.len(),
                    "auth: SOCKS5 will require USER/PASS authentication"
                );
                Some(Arc::new(state))
            }
        };

        // 8. Build Settings
        let settings = main_engine_settings(
            parsed_bridges.bridges,
            pt_binary,
            state_dir,
            cfg.bridges.iat_mode_override(),
        );
        let block_onion = cfg.security.block_onion;
        // Captured before `loaded`/`cfg` go out of scope: the engine thread
        // needs its own owned copies to persist/rank bridge health via the
        // shared `bridge-store` crate (see `engine::engine_async`).
        let bridges_cfg = cfg.bridges.clone();
        let resolver_policy = cfg.dns.resolver_policy();
        let engine_config_path = std::path::PathBuf::from(&config_path_str);

        // 9. Get Java VM and create global reference to callback
        let vm = env.get_java_vm().map_err(|e| {
            let msg = format!("failed to get Java VM: {e}");
            let _ = env.throw_new("java/lang/RuntimeException", &msg);
            anyhow::anyhow!(msg)
        })?;
        let global = env.new_global_ref(callback).map_err(|e| {
            let msg = format!("failed to create global ref to callback: {e}");
            let _ = env.throw_new("java/lang/RuntimeException", &msg);
            anyhow::anyhow!(msg)
        })?;

        // 10. Create Arc<JavaCallback>
        let java_callback = callback::JavaCallback::new(vm, global).into_arc();

        // 11. Create channels for engine thread communication
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let (done_tx, done_rx) = std::sync::mpsc::channel();

        // 12. Set status to Starting
        set_status(EngineStatus::Starting(0));

        // 13. Spawn engine thread. The generation is bumped strictly BEFORE
        // the spawn: bumping after would leave a window where the fresh
        // thread's early teardown sees a stale global generation and wrongly
        // skips its own error status. If the spawn fails the bump is simply
        // unused — harmless (the slot is `Idle`, no live engine exists to be
        // affected).
        let generation = crate::next_engine_generation();
        let thread = match std::thread::Builder::new()
            .name("torsocks5-engine".into())
            .spawn(move || {
                engine::engine_main(
                    settings,
                    listen_addr,
                    engine::ConnectionPolicy {
                        auth_state,
                        block_onion,
                    },
                    stop_rx,
                    done_tx,
                    java_callback,
                    engine::BridgeHealthContext {
                        config_path: Some(engine_config_path),
                        bridges_cfg,
                        resolver_policy,
                    },
                    generation,
                )
            }) {
            Ok(thread) => thread,
            Err(e) => {
                // Roll the status back: the engine never started, so the
                // Starting(0) set above must not linger forever.
                set_status(EngineStatus::Error(format!(
                    "failed to spawn engine thread: {e}"
                )));
                let msg = format!("failed to spawn engine thread: {e}");
                let _ = env.throw_new("java/lang/RuntimeException", &msg);
                return Err(anyhow::anyhow!(msg));
            }
        };

        // 14. Store handle
        *engine_guard = EngineSlot::Running(EngineHandle {
            stop_tx,
            done_rx,
            thread,
        });

        Ok(())
    }));

    if let Err(e) = result {
        let panic_msg = if e.is::<String>() {
            e.downcast_ref::<String>()
                .map(|s| s.as_str())
                .unwrap_or("unknown panic")
        } else if e.is::<&str>() {
            e.downcast_ref::<&str>().copied().unwrap_or("unknown panic")
        } else {
            "unknown panic"
        };
        error!("nativeStart panic: {}", panic_msg);
        set_status(EngineStatus::Error(format!(
            "nativeStart panicked: {}",
            panic_msg
        )));
    }
}

/// JNI entry point: `nativeStop()`
///
/// See the crate-level documentation for the contract and error semantics.
#[no_mangle]
pub extern "system" fn Java_org_torproject_android_service_TorSocks5Bridge_nativeStop(
    mut env: JNIEnv,
    _class: JClass,
) {
    // SAFETY: Wrapped in catch_unwind to prevent panic unwinding across FFI.
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
        // Phase 1 (under the lock): pure slot transition.
        let handoff = {
            let mut guard = get_engine().lock().unwrap_or_else(|p| p.into_inner());
            begin_engine_stop(&mut guard)
        };

        let parker = match handoff {
            StopHandoff::Idle => {
                // Idempotent: already stopped or never started
                set_status(EngineStatus::Off);
                return;
            }
            StopHandoff::InProgress => {
                // Another nativeStop already owns the handle and the status.
                return;
            }
            StopHandoff::Checkout(handle) => {
                // Set status to Stopping
                set_status(EngineStatus::Stopping);

                // Signal the engine thread to stop (ignore errors if already
                // exited; re-sending on a re-attempt is harmless — same
                // watch-channel value).
                let _ = handle.stop_tx.send(true);
                StoppingParker(Some(handle))
            }
        };

        // Wait for the engine thread to finish (with timeout), outside the lock.
        let outcome = parker
            .0
            .as_ref()
            .expect("parked above")
            .done_rx
            .recv_timeout(STOP_JOIN_TIMEOUT);
        match outcome {
            Ok(()) => {
                // Thread exited normally
                let handle = parker.release().expect("parked above");
                let _ = handle.thread.join();
                let mut engine_guard = get_engine().lock().unwrap_or_else(|p| p.into_inner());
                *engine_guard = EngineSlot::Idle;
                set_status(EngineStatus::Off);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // Thread is wedged. Dropping the parker returns the handle to
                // the slot as `Stopping(Some(_))` — it is NOT lost; a repeated
                // `nativeStop` re-waits on it and `nativeStart` stays refused.
                drop(parker);
                error!("nativeStop timed out waiting for engine thread to exit");
                set_status(EngineStatus::Error(
                    "nativeStop timed out waiting for the engine thread".into(),
                ));
                let _ = env.throw_new(
                    "java/lang/RuntimeException",
                    "nativeStop timed out waiting for the engine thread",
                );
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                // Thread panicked or was terminated abnormally
                let handle = parker.release().expect("parked above");
                let _ = handle.thread.join();
                let mut engine_guard = get_engine().lock().unwrap_or_else(|p| p.into_inner());
                *engine_guard = EngineSlot::Idle;
                set_status(EngineStatus::Error(
                    "engine thread terminated abnormally".into(),
                ));
            }
        }
    }));
}

/// JNI entry point: `nativeGetStatus()`
///
/// See the crate-level documentation for the contract and error semantics.
#[no_mangle]
pub extern "system" fn Java_org_torproject_android_service_TorSocks5Bridge_nativeGetStatus(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    // SAFETY: Wrapped in catch_unwind to prevent panic unwinding across FFI.
    match panic::catch_unwind(AssertUnwindSafe(|| {
        let status = {
            let guard = get_status().lock().unwrap_or_else(|p| p.into_inner());
            guard.clone()
        };

        let text = status.to_string();
        env.new_string(text).map(|s| s.into_raw()).map_err(|e| {
            error!("failed to create Java string for status: {e}");
            e
        })
    })) {
        Ok(Ok(jstr)) => jstr,
        Ok(Err(_)) | Err(_) => std::ptr::null_mut(),
    }
}

/// JNI entry point: `nativeTakePrunedBridges()`
///
/// Drains and returns the bridges the engine has pruned (crossed `max_fails`/
/// `max_circuit_fails` during a TCP-probe round -- see `BridgeStore::note_probe_round`) since
/// the last call, newline-joined one `BridgeLine` per line. Returns an empty string if none
/// have been pruned since the last drain. `Prefs.bridgesList` on the Kotlin side stays the
/// actual source of truth for what gets probed/bootstrapped next -- this call is purely the
/// handoff so Kotlin can remove these specific lines from that list (subject to its own "never
/// prune below a floor" check) and log the removal to the connect-screen journal. See
/// docs/android-bridge-freshness-plan.md's Phase 1.
///
/// - **Threading:** May be called from any thread. Cheap (a mutex lock and a `mem::take`), safe
///   to call on every `start()`.
/// - **Error Signaling:** Does not throw. Returns `null` only on a Java string allocation
///   failure; an empty string (not `null`) means "nothing pruned since the last call".
#[no_mangle]
pub extern "system" fn Java_org_torproject_android_service_TorSocks5Bridge_nativeTakePrunedBridges(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    match panic::catch_unwind(AssertUnwindSafe(|| {
        let pruned = engine::take_pruned_bridges();
        let joined = pruned
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        env.new_string(joined).map(|s| s.into_raw()).map_err(|e| {
            error!("failed to create Java string for pruned bridges: {e}");
            e
        })
    })) {
        Ok(Ok(jstr)) => jstr,
        Ok(Err(_)) | Err(_) => std::ptr::null_mut(),
    }
}

/// JNI entry point: `nativeTakeAutoFetchedBridges()`
///
/// Drains and returns bridges the engine's own background watchdog auto-fetched (when the
/// alive pool fell below `bridges.min_alive` and `bridges.auto_fetch` is enabled -- see
/// `engine::stall_watchdog`) since the last call, newline-joined one `BridgeLine` per line, or
/// an empty string if none. Same shape and same "only helps the *next* start" caveat as
/// `nativeRefreshBridges`'s manual equivalent, just triggered automatically. See
/// docs/android-bridge-freshness-plan.md's Phase 2.
///
/// - **Threading:** May be called from any thread. Cheap (a mutex lock and a `mem::take`), safe
///   to call on every `start()` alongside `nativeTakePrunedBridges`.
/// - **Error Signaling:** Does not throw. Returns `null` only on a Java string allocation
///   failure; an empty string (not `null`) means "nothing auto-fetched since the last call".
#[no_mangle]
pub extern "system" fn Java_org_torproject_android_service_TorSocks5Bridge_nativeTakeAutoFetchedBridges(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    match panic::catch_unwind(AssertUnwindSafe(|| {
        let fetched = engine::take_auto_fetched_bridges();
        let joined = fetched
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        env.new_string(joined).map(|s| s.into_raw()).map_err(|e| {
            error!("failed to create Java string for auto-fetched bridges: {e}");
            e
        })
    })) {
        Ok(Ok(jstr)) => jstr,
        Ok(Err(_)) | Err(_) => std::ptr::null_mut(),
    }
}

/// JNI entry point: `nativeGetHealthyBridges(String configPath, int limit)`
///
/// Reads the on-disk bridge-health store (`BridgeStore::resolve_path`, the same file
/// `persist_and_rank_probe` writes after a probe round) and returns up to `limit` bridges known
/// reachable at the last probe, ranked best-first by proven stability then latency (see
/// `BridgeStore::healthiest_bridges`). Newline-joined, one `BridgeLine` per line; an empty
/// string if the store doesn't exist yet, is empty, or nothing has ever probed reachable --
/// callers should fall back to the full configured list in that case.
///
/// Pure file read: unlike `nativeRefreshBridges`, this does **not** require the engine to be
/// running.
///
/// - **Threading:** Cheap, safe to call from the main thread.
/// - **Error Signaling:** Does not throw. Returns `null` only on a Java string allocation
///   failure.
#[no_mangle]
pub extern "system" fn Java_org_torproject_android_service_TorSocks5Bridge_nativeGetHealthyBridges(
    mut env: JNIEnv,
    _class: JClass,
    config_path: JString,
    limit: jint,
) -> jstring {
    match panic::catch_unwind(AssertUnwindSafe(|| {
        let config_path_str: Option<String> = env.get_string(&config_path).ok().map(|s| s.into());
        let store_path =
            BridgeStore::resolve_path(config_path_str.as_ref().map(std::path::Path::new));
        let joined = match BridgeStore::load(store_path) {
            Ok(store) => store
                .healthiest_bridges(limit.max(0) as usize)
                .iter()
                .map(|b| b.to_string())
                .collect::<Vec<_>>()
                .join("\n"),
            Err(_) => String::new(),
        };
        env.new_string(joined).map(|s| s.into_raw()).map_err(|e| {
            error!("failed to create Java string for healthy bridges: {e}");
            e
        })
    })) {
        Ok(Ok(jstr)) => jstr,
        Ok(Err(_)) | Err(_) => std::ptr::null_mut(),
    }
}

/// JNI entry point: `nativeGetActiveBridges(String configPath)`
///
/// Returns the bridges this session has proven can carry a Tor channel,
/// newline-joined, or an empty string when nothing is connected.
///
/// This is deliberately not the configured pool nor the probe-alive set. Those
/// answer "what might work"; a UI showing which transport the user is *on* has
/// to answer "what did". The two diverge routinely -- with a transport
/// preference of "any", after a rotation, or whenever a probe-alive bridge
/// turns out to be a website with no relay behind it.
///
/// Narrows as the connection matures: the bridges the working circuit was built
/// from at first, then just those that completed a channel warm-up.
///
/// Reads the same file `set_active_bridges` writes (see [`active_bridges_path`]'s doc for why
/// this has to be file-based rather than an in-memory static): works whether the caller is in
/// the `:tor` process (where the engine actually runs) or the main UI process.
///
/// - **Threading:** Cheap, safe to call from the main thread; a small file read.
/// - **Error Signaling:** Does not throw. Returns `null` only on a Java string
///   allocation failure; a missing/unreadable file reads back as empty.
#[no_mangle]
pub extern "system" fn Java_org_torproject_android_service_TorSocks5Bridge_nativeGetActiveBridges(
    mut env: JNIEnv,
    _class: JClass,
    config_path: JString,
) -> jstring {
    match panic::catch_unwind(AssertUnwindSafe(|| {
        let config_path_str: Option<String> = env.get_string(&config_path).ok().map(|s| s.into());
        let path = active_bridges_path(config_path_str.as_ref().map(std::path::Path::new));
        let joined = std::fs::read_to_string(&path).unwrap_or_default();
        env.new_string(joined).map(|s| s.into_raw()).map_err(|e| {
            error!("failed to create Java string for active bridges: {e}");
            e
        })
    })) {
        Ok(Ok(jstr)) => jstr,
        Ok(Err(_)) | Err(_) => std::ptr::null_mut(),
    }
}

/// JNI entry point: `nativeGetBridgeStats(String configPath)`
///
/// Per-transport health summary as one `|`-separated line per transport:
/// `transport|known|alive|channel_proven|retired|last_probe_ok|last_channel_ok`
/// where the two timestamps are Unix seconds, or `0` when never.
///
/// Computed here rather than by re-parsing the store's log format on the Java
/// side, so the two cannot disagree about what "alive" means — a distinction
/// that matters because the counts deliberately differ: `alive` is reachability,
/// `channel_proven` is a completed Tor channel, and a transport can have plenty
/// of the former and none of the latter.
///
/// Pure file read: works whether or not the engine is running.
///
/// - **Threading:** Reads a file; call off the main thread if the store is large.
/// - **Error Signaling:** Does not throw. Empty string when the store is absent.
#[no_mangle]
pub extern "system" fn Java_org_torproject_android_service_TorSocks5Bridge_nativeGetBridgeStats(
    mut env: JNIEnv,
    _class: JClass,
    config_path: JString,
) -> jstring {
    match panic::catch_unwind(AssertUnwindSafe(|| {
        let config_path_str: Option<String> = env.get_string(&config_path).ok().map(|s| s.into());
        let store_path =
            BridgeStore::resolve_path(config_path_str.as_ref().map(std::path::Path::new));
        let joined = match BridgeStore::load(store_path) {
            Ok(store) => store
                .transport_summary()
                .iter()
                .map(|s| {
                    format!(
                        "{}|{}|{}|{}|{}|{}|{}",
                        s.transport,
                        s.known,
                        s.alive,
                        s.channel_proven,
                        s.retired,
                        s.last_probe_ok.map(|t| t.unix_timestamp()).unwrap_or(0),
                        s.last_channel_ok.map(|t| t.unix_timestamp()).unwrap_or(0),
                    )
                })
                .collect::<Vec<_>>()
                .join("\n"),
            Err(_) => String::new(),
        };
        env.new_string(joined).map(|s| s.into_raw()).map_err(|e| {
            error!("failed to create Java string for bridge stats: {e}");
            e
        })
    })) {
        Ok(Ok(jstr)) => jstr,
        Ok(Err(_)) | Err(_) => std::ptr::null_mut(),
    }
}

/// JNI entry point: `nativeNoteBridgeSource(String configPath, String label, String lines)`
///
/// Credits `label` with the newline-separated bridge `lines`, so bridges
/// obtained outside the engine's own fetcher still carry attribution.
///
/// Needed because not every bridge arrives through `bridge_fetcher`: moat is
/// driven from Kotlin, and without this its bridges would be indistinguishable
/// from scraped ones — invisible to the per-source verdict and to the
/// barren-source scoring, despite being the only ones not already burned.
///
/// - **Threading:** Reads and writes a file; call off the main thread.
/// - **Error Signaling:** Does not throw. Silently does nothing when the store
///   cannot be loaded, since attribution must never break bridge acquisition.
#[no_mangle]
pub extern "system" fn Java_org_torproject_android_service_TorSocks5Bridge_nativeNoteBridgeSource(
    mut env: JNIEnv,
    _class: JClass,
    config_path: JString,
    label: JString,
    lines: JString,
) {
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
        let config_path_str: Option<String> = env.get_string(&config_path).ok().map(|s| s.into());
        let Ok(label) = env.get_string(&label).map(String::from) else {
            return;
        };
        let Ok(lines) = env.get_string(&lines).map(String::from) else {
            return;
        };
        let bridges: Vec<bridge_line::BridgeLine> = lines
            .lines()
            .filter_map(|l| l.trim().parse().ok())
            .collect();
        if bridges.is_empty() {
            return;
        }
        let _store_write = crate::engine::bridge_store_write_lock();
        let store_path =
            BridgeStore::resolve_path(config_path_str.as_ref().map(std::path::Path::new));
        let Ok(mut store) = BridgeStore::load(store_path) else {
            return;
        };
        let now = time::OffsetDateTime::now_utc();
        for bridge in &bridges {
            store.note_source_at(bridge, &label, now);
        }
        if let Err(e) = store.save() {
            error!("could not persist bridge source attribution: {e}");
        }
    }));
}

/// JNI entry point: `nativeGetProvenBridges(String configPath, int limit)`
///
/// Bridges that have actually carried a Tor channel, most recent first,
/// newline-joined.
///
/// Stricter than `nativeGetHealthyBridges`, which also admits bridges that only
/// answered a reachability probe. The distinction matters when handing bridges
/// to someone else: they are usually offline at import and cannot verify
/// anything, so a shared code must carry bridges already known to work rather
/// than ones that merely look plausible.
///
/// - **Threading:** Reads a file; call off the main thread if the store is large.
/// - **Error Signaling:** Does not throw. Empty string when nothing qualifies.
#[no_mangle]
pub extern "system" fn Java_org_torproject_android_service_TorSocks5Bridge_nativeGetProvenBridges(
    mut env: JNIEnv,
    _class: JClass,
    config_path: JString,
    limit: jint,
) -> jstring {
    match panic::catch_unwind(AssertUnwindSafe(|| {
        let config_path_str: Option<String> = env.get_string(&config_path).ok().map(|s| s.into());
        let store_path =
            BridgeStore::resolve_path(config_path_str.as_ref().map(std::path::Path::new));
        let joined = match BridgeStore::load(store_path) {
            Ok(store) => store
                .channel_proven_bridges(limit.max(0) as usize)
                .iter()
                .map(|b| b.to_string())
                .collect::<Vec<_>>()
                .join("\n"),
            Err(_) => String::new(),
        };
        env.new_string(joined).map(|s| s.into_raw()).map_err(|e| {
            error!("failed to create Java string for proven bridges: {e}");
            e
        })
    })) {
        Ok(Ok(jstr)) => jstr,
        Ok(Err(_)) | Err(_) => std::ptr::null_mut(),
    }
}

/// JNI entry point: `nativeGetSourceStats(String configPath)`
///
/// Per-source yield as one `|`-separated line each:
/// `label|offered|alive|channel_proven|retired`
///
/// Lets the sources screen show what a collector actually contributes. Fetch
/// success is not that: a source that has stopped regenerating keeps answering
/// HTTP 200 with a full list, so "it works" and "it is useful" have to be
/// displayed as different things.
///
/// - **Threading:** Reads a file; call off the main thread if the store is large.
/// - **Error Signaling:** Does not throw. Empty string when the store is absent.
#[no_mangle]
pub extern "system" fn Java_org_torproject_android_service_TorSocks5Bridge_nativeGetSourceStats(
    mut env: JNIEnv,
    _class: JClass,
    config_path: JString,
) -> jstring {
    match panic::catch_unwind(AssertUnwindSafe(|| {
        let config_path_str: Option<String> = env.get_string(&config_path).ok().map(|s| s.into());
        let store_path =
            BridgeStore::resolve_path(config_path_str.as_ref().map(std::path::Path::new));
        let joined = match BridgeStore::load(store_path) {
            Ok(store) => store
                .source_summary()
                .iter()
                .map(|s| {
                    format!(
                        "{}|{}|{}|{}|{}",
                        s.label, s.offered, s.alive, s.channel_proven, s.retired
                    )
                })
                .collect::<Vec<_>>()
                .join("\n"),
            Err(_) => String::new(),
        };
        env.new_string(joined).map(|s| s.into_raw()).map_err(|e| {
            error!("failed to create Java string for source stats: {e}");
            e
        })
    })) {
        Ok(Ok(jstr)) => jstr,
        Ok(Err(_)) | Err(_) => std::ptr::null_mut(),
    }
}
