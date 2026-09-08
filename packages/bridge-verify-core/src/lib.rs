//! Shared bridge-verification support logic, extracted from the two
//! line-by-line-identical copies that used to live in the CLI daemon
//! (`apps/socks5-proxy/src/bridge_verifier.rs`) and the Android JNI engine
//! (`packages/android-ffi/src/jni_verify.rs`):
//!
//! - [`snapshot`]: consistent SQLite cache-dir snapshotting for a throwaway
//!   check client.
//! - [`pt_reap`]: the marker-based PT child-ownership registry and the pure
//!   kill decision behind both platforms' leak-reaping sweeps.
//!
//! Platform-specific parts (the Win32 Toolhelp32 snapshot + `TerminateProcess`
//! sweep, the Android `/proc` snapshot + `kill(2)` sweep, and each platform's
//! marker file creation) stay in the consumers as thin adapters.

pub mod pt_reap;
pub mod snapshot;
