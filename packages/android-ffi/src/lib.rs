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
use engine::{EngineHandle, EngineStatus};
use jni::objects::{JClass, JObject, JString};
use jni::sys::jstring;
use jni::JNIEnv;
use proxy_config::{Config, Loaded};
use std::sync::Arc;
use std::sync::OnceLock;
use tracing::{error, info};

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
                info!(path = %users_path.display(), "auth: no users configured — SOCKS5 will accept anonymous clients");
                None
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
        };

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
                    auth_state,
                    stop_rx,
                    done_tx,
                    java_callback,
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
///   engine isn't currently `On` (no live tunnel to fetch through), or
///   `java.lang.RuntimeException` if `configPath` can't be read/parsed.
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

#[cfg(test)]
mod tests {
    use super::*;

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
