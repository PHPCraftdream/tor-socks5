//! Compatibility re-export: the Ktav config schema lives in the
//! `proxy-config` workspace crate (shared with the Android JNI FFI
//! crate). This shim keeps the historical `crate::config` path.
pub use proxy_config::*;
