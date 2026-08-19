//! Compatibility re-export: the SOCKS5 server protocol lives in the
//! `socks5-proto` workspace crate (shared with the Android JNI FFI
//! crate). This shim keeps the historical `crate::socks5` path.
pub use socks5_proto::*;
