//! Android JNI FFI crate for tor-socks5.
//!
//! This crate provides a native library (`libtorsocks5.so`) that can be loaded from
//! Android Java/Kotlin code via JNI to start, stop, and monitor a Tor SOCKS5 proxy.
//!
//! # Java/Kotlin Contract (WORKING ASSUMPTION)
//!
//! **IMPORTANT:** The Java package/class name is a WORKING ASSUMPTION that has not yet
//! been agreed with the Kotlin side. If it changes, the `Java_org_torproject_...` symbol
//! names below must be renamed to match (`javah`-style mangling: `_` for `.`, `_1` for `_`).
//!
//! Java class: `org.torproject.android.service.TorSocks5Bridge`
//!
//! ## Native Methods
//!
//! ### `nativeStart`
//!
//! ```java
//! public static native void nativeStart(String configPath, BootstrapCallback callback);
//! ```
//!
//! - **Threading:** May be called from any thread (typically Android main thread).
//! - **Behavior:** Asynchronous — starts the Tor bootstrap and SOCKS5 listener on a background
//!   native thread and returns immediately. The callback receives progress updates.
//! - **Error Signaling:** Throws:
//!   - `java.lang.IllegalArgumentException` — if `configPath` is null or unreadable as a string.
//!   - `java.lang.IllegalStateException` — if the engine is already running (call `nativeStop` first),
//!     or if bridges require a pluggable transport but `TOR_PT_BINARY` env var is not set.
//!   - `java.lang.RuntimeException` — if the config file is missing/malformed/unparseable, or the
//!     engine thread could not be spawned, or a panic occurs.
//!
//! ### `nativeStop`
//!
//! ```java
//! public static native void nativeStop();
//! ```
//!
//! - **Threading:** May be called from any thread.
//! - **Behavior:** Stops the engine gracefully. Idempotent — safe to call when already stopped.
//! - **Error Signaling:** Throws `java.lang.RuntimeException` if the engine thread did not
//!   exit within the 10s shutdown timeout (the engine stays wedged, holding the Tor state
//!   directory; the process usually needs to be restarted at that point). Never throws
//!   otherwise; status becomes `Error:<message>` on the timeout path.
//!
//! ### `nativeGetStatus`
//!
//! ```java
//! public static native String nativeGetStatus();
//! ```
//!
//! - **Threading:** May be called from any thread.
//! - **Behavior:** Returns a status string as described below. Returns `null` on error.
//! - **Error Signaling:** Does not throw. Returns `null` and logs the error.
//!
//! ## Callback Interface
//!
//! The callback object passed to `nativeStart` must expose these methods:
//!
//! ### `onProgress`
//!
//! ```java
//! void onProgress(float fraction);  // signature: (F)V
//! ```
//!
//! Called with bootstrap progress from `0.0` to `1.0`.
//!
//! ### `onReady`
//!
//! ```java
//! void onReady();  // signature: ()V
//! ```
//!
//! Called when Tor is fully bootstrapped and the SOCKS5 listener is accepting connections.
//!
//! ### `onBlocked`
//!
//! ```java
//! void onBlocked(String reason);  // signature: (Ljava/lang/String;)V
//! ```
//!
//! Called when Tor reports it cannot make forward progress (non-fatal, may recover).
//!
//! ### `onFailed`
//!
//! ```java
//! void onFailed(String error);  // signature: (Ljava/lang/String;)V
//! ```
//!
//! Called when Tor bootstrap fails fatally, or when a non-bootstrap error occurs.
//!
//! # Status Text Protocol
//!
//! `nativeGetStatus` returns one of the following exact strings:
//!
//! - `"Off"` — Engine is not running and no error state.
//! - `"Starting:N"` — Engine is starting, where `N` is an integer from `0` to `100` representing
//!   bootstrap progress percentage.
//! - `"On:ADDR"` — Engine is fully operational, listening on `ADDR` (e.g., `"On:127.0.0.1:1080"`).
//! - `"Stopping"` — Engine is shutting down.
//! - `"Error:MESSAGE"` — Engine encountered an error; `MESSAGE` is a human-readable description.
//!
//! # Design Notes
//!
//! ## Why `nativeStart` is Asynchronous
//!
//! Tor bootstrap can take tens of seconds, especially over censored networks using pluggable
//! transports. Blocking the Android main thread (which calls JNI) would freeze the UI and risk
//! an ANR (Application Not Responding). Therefore, `nativeStart` spawns a dedicated native
//! thread that runs the entire async runtime and returns immediately.
//!
//! ## Thread Safety
//!
//! - JNI entry points are wrapped in `catch_unwind` to prevent panics from crossing the
//!   FFI boundary (Rust 1.81+ aborts the process otherwise).
//! - Global state is protected by `std::sync::Mutex` and is never held across `.await` points.
//! - The callback runs on Tokio worker threads; each invocation attaches to the JVM, dispatches
//!   the Java method, and detaches immediately (low event rate makes this acceptable).
//!
//! ## Resource Cleanup
//!
//! On shutdown, the engine:
//! 1. Drops the `TorTunnel`, which terminates PT child processes.
//! 2. Sleeps 500ms to allow arti's reactor to release its state directory lock.
//! 3. Exits the thread and notifies `nativeStop` via a channel.
//!
//! This ensures the state directory lock is released before the next start, avoiding
//! "state directory is in use" errors.
//!
//! ## Local SOCKS5 Authentication
//!
//! The SOCKS5 listener started by `nativeStart` shares the exact same RFC 1929
//! USERNAME/PASSWORD authenticator (`auth::AuthState`, Argon2id + HMAC success cache) as the CLI
//! (`apps/socks5-proxy`) — see `docs/auth.md` for the full design. Resolution happens once,
//! synchronously, inside `nativeStart` (step 7a below), *before* the engine thread is spawned:
//!
//! 1. `cfg.auth.enabled == false` → anonymous NO_AUTH, logged at `info`.
//! 2. Otherwise resolve the users-registry path: `cfg.auth.users_file` if non-empty, else
//!    `auth::UsersConfig::resolve_path(configPath)` (same directory + filename stem as
//!    `configPath`, `.users.ktav` suffix — identical convention to the CLI).
//! 3. Load that file with `auth::UsersConfig::load` (a missing file is not an error — empty
//!    registry) and, if non-empty, build `auth::AuthState::build_persistent` and require
//!    USER/PASS; if empty, fall back to anonymous NO_AUTH.
//!
//! Every branch above logs its decision — this proxy never silently falls back to an
//! unauthenticated listener. The resulting `Option<Arc<AuthState>>` is threaded through
//! `engine::engine_main` → `engine_async` → `accept_loop`, cloned once per accepted connection,
//! and handed to `socks5_proto::handshake` exactly as the CLI does in `server.rs`.

mod android_log;
mod callback;
mod engine;

use std::panic::{self, AssertUnwindSafe};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::Context;
use auth::{AuthState, UsersConfig};
use bridge_store::BridgeStore;
use engine::{EngineHandle, EngineStatus};
use jni::objects::{JClass, JObject, JString};
use jni::sys::{jint, jstring};
use jni::JNIEnv;
use proxy_config::{Config, Loaded};
use std::sync::Arc;
use std::sync::OnceLock;
use tracing::{error, info, warn};

/// Global engine handle. Accessed via `OnceLock::get_or_init` for lazy initialization.
/// Uses `std::sync::Mutex` (not Tokio's) because JNI entry points are synchronous.
static ENGINE: OnceLock<Mutex<Option<EngineHandle>>> = OnceLock::new();

/// Global engine status. This is what `nativeGetStatus` reads.
static STATUS: OnceLock<Mutex<EngineStatus>> = OnceLock::new();

/// One-time initialization guards for process-wide setup.
static CRYPTO_PROVIDER_INSTALLED: OnceLock<()> = OnceLock::new();
static TRACING_SUBSCRIBER_INITED: OnceLock<()> = OnceLock::new();

/// Get or initialize the global status, defaulting to `EngineStatus::Off`.
fn get_status() -> &'static Mutex<EngineStatus> {
    STATUS.get_or_init(|| Mutex::new(EngineStatus::Off))
}

/// Get or initialize the global engine handle, defaulting to `None`.
fn get_engine() -> &'static Mutex<Option<EngineHandle>> {
    ENGINE.get_or_init(|| Mutex::new(None))
}

/// Bridges this session has proven can carry a Tor channel, newline-joined.
///
/// Distinct from the configured pool and from the probe-alive set: those say
/// what might work, this says what did. Read by `nativeGetActiveBridges` so the
/// UI can state which transport is actually in use rather than which one was
/// preferred -- with a preference of "any", or after a rotation, the two are
/// routinely different.
static ACTIVE_BRIDGES: OnceLock<Mutex<String>> = OnceLock::new();

pub(crate) fn active_bridges() -> &'static Mutex<String> {
    ACTIVE_BRIDGES.get_or_init(|| Mutex::new(String::new()))
}

/// Publish the bridges known to be carrying, or `&[]` to clear on teardown.
pub(crate) fn set_active_bridges(bridges: &[bridge_line::BridgeLine]) {
    let joined = bridges
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    *active_bridges().lock().unwrap_or_else(|p| p.into_inner()) = joined;
}

/// Helper: update the global status.
/// Poisoning-tolerant: a panicked holder must not brick status updates forever.
fn set_status(status: EngineStatus) {
    *get_status().lock().unwrap_or_else(|p| p.into_inner()) = status;
}

/// Helper: install the rustls crypto provider (idempotent).
fn ensure_crypto_provider() {
    let _ = CRYPTO_PROVIDER_INSTALLED.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Helper: initialize the tracing subscriber (idempotent, uses config log settings).
///
/// `nativeStart` may be called many times over the life of an Android
/// process (start/stop cycles), but `tracing::subscriber::set_global_default`
/// (which `tracing_subscriber::fmt()...try_init()` calls under the hood)
/// panics on a second call — the `OnceLock` below ensures the subscriber
/// is installed exactly once per process, regardless of how many times
/// `nativeStart` runs. See [`android_log`] for where the records actually
/// go (`logcat` on Android, `stderr` on host builds).
fn ensure_tracing_subscriber(cfg: &Config) {
    let _ = TRACING_SUBSCRIBER_INITED.get_or_init(|| {
        android_log::init(cfg);
    });
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

        // 2. Lock ENGINE and check if already running
        let mut engine_guard = get_engine().lock().unwrap_or_else(|p| p.into_inner());

        // If a previous handle exists and its thread is finished, clean it up
        if let Some(handle) = engine_guard.as_ref() {
            if handle.thread.is_finished() {
                let old = engine_guard.take().unwrap();
                let _ = old.thread.join();
            } else {
                // Engine still running
                let _ = env.throw_new(
                    "java/lang/IllegalStateException",
                    "torsocks5 engine already running; call nativeStop first",
                );
                return Err(anyhow::anyhow!("engine already running"));
            }
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

        // 5. Parse listen address
        let listen_addr: std::net::SocketAddr = cfg
            .listen
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
        let settings = arti_wrapper::Settings {
            bridges: parsed_bridges.bridges,
            pt_binary,
            state_dir: Some(state_dir),
            obfs4_iat_mode: cfg.bridges.iat_mode_override(),
            ..Default::default()
        };
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

        // 13. Spawn engine thread
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
        *engine_guard = Some(EngineHandle {
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
        // Take the handle out of the global lock (if present)
        let handle = {
            let mut guard = get_engine().lock().unwrap_or_else(|p| p.into_inner());
            guard.take()
        };

        if handle.is_none() {
            // Idempotent: already stopped or never started
            set_status(EngineStatus::Off);
            return;
        }

        let handle = handle.unwrap();

        // Set status to Stopping
        set_status(EngineStatus::Stopping);

        // Signal the engine thread to stop (ignore errors if already exited)
        let _ = handle.stop_tx.send(true);

        // Wait for the engine thread to finish (with timeout)
        match handle.done_rx.recv_timeout(Duration::from_secs(10)) {
            Ok(()) => {
                // Thread exited normally
                let _ = handle.thread.join();
                set_status(EngineStatus::Off);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // Thread is wedged
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
                let _ = handle.thread.join();
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

/// JNI entry point: `nativeGetActiveBridges()`
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
/// - **Threading:** Cheap, safe to call from the main thread; reads a mutex.
/// - **Error Signaling:** Does not throw. Returns `null` only on a Java string
///   allocation failure.
#[no_mangle]
pub extern "system" fn Java_org_torproject_android_service_TorSocks5Bridge_nativeGetActiveBridges(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    match panic::catch_unwind(AssertUnwindSafe(|| {
        let joined = active_bridges()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
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

fn refresh_sources_failure(outcomes: &[bridge_fetcher::FetchOutcome]) -> Option<String> {
    if outcomes.is_empty() || outcomes.iter().all(|outcome| outcome.error.is_some()) {
        let details = outcomes
            .iter()
            .map(|outcome| {
                format!(
                    "{}: {}",
                    outcome.label,
                    outcome.error.as_deref().unwrap_or("source task failed")
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        Some(if details.is_empty() {
            "all configured bridge sources failed".to_owned()
        } else {
            format!("all configured bridge sources failed: {details}")
        })
    } else {
        None
    }
}

/// JNI entry point: `nativeRefreshBridges(String configPath)`
///
/// Fetches fresh bridge lines from `configPath`'s `bridges.sources` over the
/// **currently running** engine's live `TorTunnel` (see
/// [`engine::get_current_tunnel`]) and returns them newline-joined, one
/// `BridgeLine` per line, ready to append to `bridges.lines` on the Kotlin
/// side. Returns an empty string (not an error) if no sources are configured
/// or none of them yielded anything usable.
///
/// This is a one-shot refresh, not a background/keep-alive task: it must be
/// called again by Kotlin whenever a fresh list is wanted. It intentionally
/// does *not* touch the running engine's own bridge set or config file --
/// `bridge_fetcher::fetch_all` has no path that doesn't require an
/// already-live Tor circuit, so this can only ever help populate bridges for
/// the *next* start (or a future retry), never the current bootstrap.
///
/// - **Threading:** Blocks the calling thread for up to the fetch timeout
///   (30s) -- call off the Android main thread.
/// - **Error Signaling:** Throws `java.lang.IllegalStateException` if the
///   engine isn't currently `On` (no live tunnel to fetch through),
///   `java.lang.RuntimeException` if `configPath` can't be read/parsed, or if
///   every configured source fails to fetch.
#[no_mangle]
pub extern "system" fn Java_org_torproject_android_service_TorSocks5Bridge_nativeRefreshBridges(
    mut env: JNIEnv,
    _class: JClass,
    config_path: JString,
) -> jstring {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
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

        let Some(tunnel) = engine::get_current_tunnel() else {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                "engine is not running; bridges can only be refreshed over a live Tor circuit",
            );
            return Err(anyhow::anyhow!("engine not running"));
        };

        let loaded = Config::load_with_override(Some(std::path::Path::new(&config_path_str)))
            .with_context(|| format!("loading config from {}", config_path_str))
            .map_err(|e| {
                let msg = format!("{:#}", e);
                let _ = env.throw_new("java/lang/RuntimeException", &msg);
                e
            })?;
        let cfg = match &loaded {
            Loaded::FromFile { config, .. } => config,
            Loaded::Defaults(config) => config,
        };

        let sources: Vec<bridge_fetcher::Source> = cfg
            .bridges
            .sources
            .iter()
            .map(|s| bridge_fetcher::Source {
                label: s.label.clone(),
                url: s.url.clone(),
                headers: s.headers.clone(),
                cookies: s.cookies.clone(),
            })
            .collect();

        if sources.is_empty() {
            return env.new_string("").map(|s| s.into_raw()).map_err(|e| {
                error!("failed to create Java string for empty bridge refresh: {e}");
                anyhow::anyhow!(e)
            });
        }

        let max_body_bytes = cfg.bridges.max_body_mib.saturating_mul(1024 * 1024);

        // A fresh, minimal runtime for this one-shot blocking call -- the
        // engine's own multi-worker runtime lives on the engine thread's
        // stack and isn't reachable from here (this JNI call runs on
        // whatever thread Kotlin invoked it from).
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| {
                let msg = format!("failed to create refresh runtime: {e}");
                let _ = env.throw_new("java/lang/RuntimeException", &msg);
                anyhow::anyhow!(msg)
            })?;

        let (fetched, outcomes) = rt.block_on(bridge_fetcher::fetch_all(
            &tunnel,
            &sources,
            Duration::from_secs(30),
            max_body_bytes,
        ));

        for outcome in &outcomes {
            if let Some(err) = &outcome.error {
                tracing::warn!(label = %outcome.label, error = %err, "bridge source failed");
            } else {
                info!(
                    label = %outcome.label,
                    bridges = outcome.bridges_extracted,
                    "bridge source OK"
                );
            }
        }

        // An empty result is normally a valid "no new bridges" response, but
        // it is misleading when every source failed. Surface that distinction
        // to Kotlin so the UI can report a refresh failure instead of silently
        // claiming that no new bridges exist.
        if let Some(message) = refresh_sources_failure(&outcomes) {
            let _ = env.throw_new("java/lang/RuntimeException", &message);
            return Err(anyhow::anyhow!(message));
        }

        let (unique, duplicates) = bridge_fetcher::dedup_bridges(fetched);
        info!(unique = unique.len(), duplicates, "bridge refresh complete");

        let joined = unique
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        env.new_string(joined).map(|s| s.into_raw()).map_err(|e| {
            error!("failed to create Java string for refreshed bridges: {e}");
            anyhow::anyhow!(e)
        })
    }));

    match result {
        Ok(Ok(jstr)) => jstr,
        Ok(Err(_)) | Err(_) => std::ptr::null_mut(),
    }
}

/// JNI entry point: `nativeProbeBridgeTransport(String configPath, String transport)`
///
/// An on-demand reachability probe over raw sockets -- unlike `nativeRefreshBridges`, this needs
/// no live Tor connection, the same way the bootstrap-time probe in `engine::engine_async` runs
/// before any circuit exists. Filters `configPath`'s configured bridges to `transport`
/// (`"obfs4"`/`"webtunnel"`; an empty string probes every configured bridge), probes them, and
/// persists the outcome to the same health store every other probe round writes to -- a manual
/// check from the UI improves the *next* connect's ranking exactly like the automatic rounds do.
///
/// Returns `"<alive>|<total>|<unmeasured>"`, or throws on a config error.
///
/// - **Threading:** Blocks the calling thread for the probe's duration (a per-bridge timeout of a
///   few seconds times however many candidates match `transport`) -- call off the Android main
///   thread, same convention as `nativeRefreshBridges`.
/// - **Error Signaling:** Throws `java.lang.IllegalArgumentException` if `configPath` is invalid,
///   `java.lang.RuntimeException` if the config or its bridge lines can't be parsed.
#[no_mangle]
pub extern "system" fn Java_org_torproject_android_service_TorSocks5Bridge_nativeProbeBridgeTransport(
    mut env: JNIEnv,
    _class: JClass,
    config_path: JString,
    transport: JString,
) -> jstring {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
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
        let transport_str: String = env
            .get_string(&transport)
            .map(|s| s.into())
            .unwrap_or_default();

        let loaded = Config::load_with_override(Some(std::path::Path::new(&config_path_str)))
            .with_context(|| format!("loading config from {}", config_path_str))
            .map_err(|e| {
                let msg = format!("{:#}", e);
                let _ = env.throw_new("java/lang/RuntimeException", &msg);
                e
            })?;
        let cfg = match &loaded {
            Loaded::FromFile { config, .. } => config,
            Loaded::Defaults(config) => config,
        };

        let parsed = cfg.bridges.parsed().map_err(|e| {
            let msg = format!("{:#}", e);
            let _ = env.throw_new("java/lang/RuntimeException", &msg);
            e
        })?;
        let candidates: Vec<bridge_line::BridgeLine> = parsed
            .bridges
            .into_iter()
            .filter(|b| {
                transport_str.is_empty() || b.transport.as_deref() == Some(transport_str.as_str())
            })
            .collect();
        let total = candidates.len();

        let bridge_health = engine::BridgeHealthContext {
            config_path: Some(std::path::PathBuf::from(&config_path_str)),
            bridges_cfg: cfg.bridges.clone(),
            resolver_policy: cfg.dns.resolver_policy(),
        };

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| {
                let msg = format!("failed to create probe runtime: {e}");
                let _ = env.throw_new("java/lang/RuntimeException", &msg);
                anyhow::anyhow!(msg)
            })?;

        let mut round = rt.block_on(bridge_probe::probe_round_with_policy(
            candidates.clone(),
            Duration::from_secs(5),
            bridge_health.resolver_policy,
        ));
        let alive = round.alive.len();
        let unmeasured = round.unmeasured.len();
        engine::persist_and_rank_probe(&candidates, &mut round, &bridge_health);

        info!(
            transport = %transport_str,
            alive,
            total,
            unmeasured,
            "on-demand bridge probe complete"
        );

        env.new_string(format!("{alive}|{total}|{unmeasured}"))
            .map(|s| s.into_raw())
            .map_err(|e| {
                error!("failed to create Java string for probe result: {e}");
                anyhow::anyhow!(e)
            })
    }));

    match result {
        Ok(Ok(jstr)) => jstr,
        Ok(Err(_)) | Err(_) => std::ptr::null_mut(),
    }
}

#[cfg(test)]
mod tests {
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
}
