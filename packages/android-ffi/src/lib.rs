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

/// Path to the small file that carries "bridges known to be carrying traffic right now"
/// between processes, next to the config -- same `<stem>.<suffix>` convention as
/// `BridgeStore::resolve_path`'s `<stem>.alive-bridges.log`.
///
/// This used to be a plain in-memory static, which is wrong for what it's used for:
/// `XorbotService` runs in `android:process=":tor"`, a separate Android process from the UI
/// (`XorbotActivity` has no process override), and each process gets its own independent copy
/// of the loaded native library's statics. The engine thread published to *its* process's copy;
/// `nativeGetActiveBridges` called from a UI fragment read a different, permanently-empty copy
/// in the *main* process -- so the bridge-status sheet said "not connected" no matter how many
/// bridges the engine had actually warmed. Every other cross-process getter in this file
/// (bridge stats, source stats, healthy bridges) already reads a file next to the config for
/// exactly this reason; this makes active-bridges consistent with them instead of the one
/// in-memory exception.
fn active_bridges_path(config_path: Option<&std::path::Path>) -> std::path::PathBuf {
    match config_path {
        Some(cfg) => {
            let dir = cfg.parent().unwrap_or_else(|| std::path::Path::new("."));
            let stem = cfg
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "tor-socks5".to_string());
            dir.join(format!("{stem}.active-bridges"))
        }
        None => std::path::PathBuf::from("tor-socks5.active-bridges"),
    }
}

/// Publish the bridges known to be carrying, or `&[]` to clear on teardown.
///
/// Best-effort: a write failure here must not fail engine startup/shutdown over what is purely
/// a UI signal -- nothing inside the engine reads this back.
pub(crate) fn set_active_bridges(
    config_path: Option<&std::path::Path>,
    bridges: &[bridge_line::BridgeLine],
) {
    let joined = bridges
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    let path = active_bridges_path(config_path);
    if let Err(e) = std::fs::write(&path, joined) {
        warn!(path = %path.display(), error = %e, "could not persist active bridges");
    }
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

mod jni_bridges;
mod jni_engine;
mod jni_verify;

pub use jni_bridges::*;
pub use jni_engine::*;
pub use jni_verify::*;

#[cfg(test)]
mod lib_tests;
