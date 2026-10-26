//! Angel-mode support (Unix, not Android).
//!
//! Gates entirely behind `#[cfg(all(unix, not(target_os = "android")))]`; on Windows
//! and Android this module is empty and `--angel` is rejected at runtime in
//! [`crate::main`] with a pointer at `service install` (Android: JNI-embedded builds
//! must not angelize).

#[cfg(all(unix, not(target_os = "android")))]
use std::path::Path;

#[cfg(all(unix, not(target_os = "android")))]
use anyhow::Context;

/// Detach the process from the controlling terminal and run in the
/// background as an angel.
///
/// # When to call this
///
/// **Before** the Tokio runtime is built. `fork(2)` in a multithreaded
/// process leaves only the calling thread alive in the child: every other
/// thread (including all of Tokio's worker threads and the threads arti
/// spawns) silently disappears mid-work, with locks held, buffers
/// half-flushed, and destructors never run. The resulting child is in an
/// unrecoverable state. By angelising *first*, we fork a single-threaded
/// process and only then bring the async runtime up inside the child, so
/// every worker thread that ever exists is created post-fork.
///
/// # What it does
///
/// Использует [`angelize`](https://crates.io/crates/daemonize):
/// `fork` → `setsid` → `fork`, перенаправление stdio в `/dev/null` и umask `0o027`.
/// Каталог запуска фиксируется до fork и сохраняется в потомке: относительные
/// пути конфига, PID-файла, логов и данных разрешаются так же, как в foreground.
/// При `pid_file = Some` записывается заблокированный PID-файл ангела.
///
/// `start()` returns to the *child* process only; the parent exits.
#[cfg(all(unix, not(target_os = "android")))]
pub fn angelize(pid_file: Option<&Path>) -> anyhow::Result<()> {
    use angelize::Daemonize as Angelize;
    // Сохраняем привязку относительных путей к каталогу запуска.
    let working_dir = std::env::current_dir()
        .context("определение каталога запуска перед уходом в фоновый режим")?;
    let mut angelize = Angelize::new().working_directory(&working_dir).umask(0o027);
    if let Some(path) = pid_file {
        angelize = angelize.pid_file(path);
    }
    angelize
        .start()
        .context("detaching into angel mode (fork/setsid/stdio redirect)")
}
