//! Routes this crate's `tracing` output to Android's `logcat` via
//! `__android_log_write`, so bootstrap events, bridge errors, config
//! parsing, and auth decisions (all logged elsewhere in `engine.rs`/
//! `lib.rs` through `tracing::info!`/`warn!`/`error!`) show up under
//! `adb logcat -s torsocks5:V` instead of vanishing (there is no
//! terminal/file attached to an embedded Android process).
//!
//! # Design
//!
//! This crate already uses `tracing` natively (not the `log` facade), so
//! rather than pulling in `android_logger` (a `log`-facade sink) plus a
//! `tracing-log` bridge, we give `tracing_subscriber::fmt` a
//! [`std::io::Write`] implementation that forwards each formatted line to
//! `__android_log_write`. This reuses all of `fmt::Layer`'s existing
//! field/span formatting — no hand-rolled `tracing_subscriber::Layer` or
//! `Visit` implementation needed — and keeps the exact same
//! `EnvFilter`-driven filtering the crate already had.
//!
//! `__android_log_write` is declared directly via `libc` (already present
//! transitively in the workspace's lockfile) rather than adding a new
//! Android-specific logging crate.
//!
//! # Tag
//!
//! All records are logged under the fixed tag `"torsocks5"`, so on-device
//! debugging can filter with:
//!
//! ```text
//! adb logcat -s torsocks5:V
//! ```
//!
//! # Host builds
//!
//! `__android_log_write` does not exist off-device, so everything in this
//! module is `cfg(target_os = "android")`-gated. [`init`] falls back to
//! the previous plain `stderr` writer on host targets (used by
//! `cargo build --workspace`/`cargo test -p android-ffi` off-device).

use proxy_config::Config;

/// Initialize the process-wide `tracing` subscriber for this crate.
///
/// Must only be called once per process — callers are responsible for
/// idempotency (see `ensure_tracing_subscriber` in `lib.rs`, which guards
/// this behind a `OnceLock`, since `nativeStart` may run many times per
/// process but a global subscriber can only be installed once).
///
/// - On `target_os = "android"`: logs go to `logcat` under the
///   `"torsocks5"` tag via [`AndroidLogWriter`].
/// - Elsewhere (host builds, `cargo test`): falls back to the previous
///   plain-`stderr` writer, unchanged from before this module existed.
pub(crate) fn init(cfg: &Config) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(cfg.log.to_filter()));

    #[cfg(target_os = "android")]
    {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .without_time() // logcat already timestamps every line
            .with_writer(android::AndroidLogMakeWriter)
            .try_init()
            .ok(); // "already registered" on a hypothetical second call — ignore
    }

    #[cfg(not(target_os = "android"))]
    {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .try_init()
            .ok();
    }
}

#[cfg(target_os = "android")]
mod android {
    //! `target_os = "android"`-only pieces: the raw `__android_log_write`
    //! FFI declaration and the `Write`/`MakeWriter` glue that lets
    //! `tracing_subscriber::fmt` drive it.

    use std::ffi::CString;
    use std::io;

    use tracing_subscriber::fmt::MakeWriter;

    /// Fixed logcat tag for every record this crate emits — filter on
    /// device with `adb logcat -s torsocks5:V`.
    const LOG_TAG: &str = "torsocks5";

    /// `android/log.h` priority levels used by `__android_log_write`.
    const ANDROID_LOG_INFO: libc::c_int = 4;

    extern "C" {
        /// Writes one message to the Android system log (`logcat`).
        ///
        /// Declared directly against `liblog.so` (always present on
        /// Android, implicitly linked into every NDK binary) via `libc`'s
        /// C type aliases, rather than pulling in a dedicated crate for a
        /// single FFI symbol.
        fn __android_log_write(
            prio: libc::c_int,
            tag: *const libc::c_char,
            text: *const libc::c_char,
        ) -> libc::c_int;
    }

    /// Writes bytes to `logcat`, one `__android_log_write` call per
    /// complete line.
    ///
    /// `tracing_subscriber::fmt` writes a full formatted record (fields +
    /// message) followed by `\n` per event/span, so buffering-and-
    /// flushing on `\n` (rather than calling `__android_log_write` per
    /// `write()` chunk) keeps each logcat entry as one coherent line
    /// instead of being split across multiple log lines.
    pub(super) struct AndroidLogWriter {
        buf: Vec<u8>,
    }

    impl AndroidLogWriter {
        fn new() -> Self {
            Self { buf: Vec::with_capacity(256) }
        }

        /// Send one already-newline-stripped line to `logcat`.
        ///
        /// A NUL byte in `line` would truncate the C string early; this
        /// is tracing-formatted text (source code identifiers, config
        /// values, error messages), not attacker-controlled binary data,
        /// so a lossy strip is an acceptable degradation rather than a
        /// correctness bug worth failing the whole log call over.
        fn emit_line(line: &[u8]) {
            if line.is_empty() {
                return;
            }
            let sanitized: Vec<u8> = line.iter().copied().filter(|&b| b != 0).collect();
            let Ok(text) = CString::new(sanitized) else { return };
            let Ok(tag) = CString::new(LOG_TAG) else { return };
            // SAFETY: `text` and `tag` are valid, NUL-terminated C strings
            // owned by this function for the duration of the call;
            // `__android_log_write` does not retain either pointer past
            // its return (it copies into the log buffer internally).
            unsafe {
                __android_log_write(ANDROID_LOG_INFO, tag.as_ptr(), text.as_ptr());
            }
        }
    }

    impl io::Write for AndroidLogWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.buf.extend_from_slice(buf);
            while let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = self.buf.drain(..=pos).collect();
                Self::emit_line(&line[..line.len() - 1]); // drop trailing '\n'
            }
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            if !self.buf.is_empty() {
                let line = std::mem::take(&mut self.buf);
                Self::emit_line(&line);
            }
            Ok(())
        }
    }

    impl Drop for AndroidLogWriter {
        fn drop(&mut self) {
            // Flush any partial trailing line (no final '\n') rather than
            // silently dropping it.
            let _ = io::Write::flush(self);
        }
    }

    /// [`MakeWriter`] that hands `tracing_subscriber::fmt` a fresh
    /// [`AndroidLogWriter`] per record. `fmt::Layer` calls `make_writer()`
    /// once per event and writes+flushes it, so a short-lived writer per
    /// call is the normal (and cheap) pattern here — mirrors how
    /// `MakeWriter for fn() -> io::Stderr` behaves upstream.
    pub(super) struct AndroidLogMakeWriter;

    impl<'a> MakeWriter<'a> for AndroidLogMakeWriter {
        type Writer = AndroidLogWriter;

        fn make_writer(&'a self) -> Self::Writer {
            AndroidLogWriter::new()
        }
    }
}
