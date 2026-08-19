//! Daemon-mode support (Unix, not Android).
//!
//! Gates entirely behind `#[cfg(all(unix, not(target_os = "android")))]`; on Windows
//! and Android this module is empty and `--daemon` is rejected at runtime in
//! [`crate::main`] with a pointer at `service install` (Android: JNI-embedded builds
//! must not daemonize).

#[cfg(all(unix, not(target_os = "android")))]
use std::path::Path;

#[cfg(all(unix, not(target_os = "android")))]
use anyhow::Context;

/// Detach the process from the controlling terminal and run in the
/// background as a daemon.
///
/// # When to call this
///
/// **Before** the Tokio runtime is built. `fork(2)` in a multithreaded
/// process leaves only the calling thread alive in the child: every other
/// thread (including all of Tokio's worker threads and the threads arti
/// spawns) silently disappears mid-work, with locks held, buffers
/// half-flushed, and destructors never run. The resulting child is in an
/// unrecoverable state. By daemonising *first*, we fork a single-threaded
/// process and only then bring the async runtime up inside the child, so
/// every worker thread that ever exists is created post-fork.
///
/// # What it does
///
/// Uses the [`daemonize`](https://crates.io/crates/daemonize) crate, which
/// performs the classic double-fork: `fork` → `setsid` → `fork`, then
/// redirects stdin/stdout/stderr to `/dev/null` and `chdir("/")`. The
/// crate's defaults already cover working directory `/`, umask `0o027`,
/// and `/dev/null` stdio — we set `working_directory("/")` and
/// `umask(0o027)` explicitly only for self-documentation; everything else
/// is the crate default. When `pid_file` is `Some`, a locked PID file is
/// written there holding the daemon's PID.
///
/// `start()` returns to the *child* process only; the parent exits.
#[cfg(all(unix, not(target_os = "android")))]
pub fn daemonize(pid_file: Option<&Path>) -> anyhow::Result<()> {
    let mut daemonize = daemonize::Daemonize::new()
        .working_directory("/")
        .umask(0o027);
    if let Some(path) = pid_file {
        daemonize = daemonize.pid_file(path);
    }
    daemonize
        .start()
        .context("detaching into daemon mode (fork/setsid/stdio redirect)")
}
