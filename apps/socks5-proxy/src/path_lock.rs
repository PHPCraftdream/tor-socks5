//! Cross-process advisory write lock for whole-file read-modify-write
//! transactions on the bridge persistence files (`<stem>.alive-bridges.log`,
//! `<stem>.candidates.log`).
//!
//! Writers compute their mutation from a `load` snapshot and publish it with
//! an atomic temp-file rename; two overlapping read-modify-write cycles (e.g.
//! daemon writer vs a `tor-socks5 bridges fetch` CLI process) can still
//! publish over each other's snapshot and silently drop a mutation. Holding
//! this lock across load→mutate→save serializes them: the loser waits and
//! builds on the winner's published state.
//!
//! The lock file is a sibling (`<target>.lock`) because saves replace the
//! target by rename — a lock on the old inode would protect nothing. Lock
//! files are never deleted: unlinking a held lock file would let a late
//! opener lock a fresh inode alongside the existing holder.
//!
//! `std::fs::File::{lock, try_lock}` (stable since Rust 1.89, the workspace
//! MSRV) — no new dependency. Locks are advisory and owned by the open file
//! handle: they contend across processes and across handles within one
//! process, and the kernel releases them when the holder dies.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

/// How often [`PathLock::acquire_bounded`] re-polls `try_lock`.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Wait bound for CLI-side store transactions. A healthy daemon holds the
/// lock only for the length of one publish; a daemon stuck retrying a
/// failing publish holds it longer, and a CLI must fail with a clear error
/// instead of hanging indefinitely behind it.
pub(crate) const CLI_LOCK_WAIT: Duration = Duration::from_secs(60);

/// Wait bound for candidate-pool transactions. A drain holds the pool lock
/// across its probe phase, which `fetch_merge` caps with `DRAIN_BUDGET`
/// (60s); the bound leaves headroom for a competing transaction to finish
/// before giving up with an error.
pub(crate) const POOL_LOCK_WAIT: Duration = Duration::from_secs(120);

/// An exclusive advisory lock on the sibling `.lock` file of a target path.
/// Held for the whole read-modify-write cycle; dropping it releases the lock.
pub(crate) struct PathLock {
    // The lock lives in this open handle; closing it releases what is left.
    file: File,
}

impl PathLock {
    /// Sibling lock file for `target`.
    pub(crate) fn lock_path(target: &Path) -> PathBuf {
        let mut name = target.as_os_str().to_os_string();
        name.push(".lock");
        PathBuf::from(name)
    }

    fn open(target: &Path) -> io::Result<File> {
        let lock_path = Self::lock_path(target);
        if let Some(dir) = lock_path.parent() {
            if !dir.as_os_str().is_empty() {
                // Same best-effort policy as the persistence writers.
                fs::create_dir_all(dir).ok();
            }
        }
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
    }

    /// Acquire, blocking until the current holder is done. For the daemon
    /// writer: the holder is a live process mid-transaction and the mutation
    /// must not be failed. Blocking — run it off the async runtime.
    pub(crate) fn acquire(target: &Path) -> Result<Self> {
        let lock_path = Self::lock_path(target);
        let file = Self::open(target).with_context(|| format!("open {}", lock_path.display()))?;
        file.lock()
            .with_context(|| format!("lock {}", lock_path.display()))?;
        Ok(Self { file })
    }

    /// Acquire, giving up after `wait` with an error naming the lock file.
    /// For CLI-side transactions: a bounded wait beats hanging behind a
    /// daemon that keeps failing (and retrying) its own publish.
    pub(crate) fn acquire_bounded(target: &Path, wait: Duration) -> Result<Self> {
        let lock_path = Self::lock_path(target);
        let file = Self::open(target).with_context(|| format!("open {}", lock_path.display()))?;
        let deadline = Instant::now() + wait;
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(Self { file }),
                Err(TryLockError::WouldBlock) => {}
                Err(TryLockError::Error(e)) => {
                    return Err(e).with_context(|| format!("lock {}", lock_path.display()))
                }
            }
            if Instant::now() >= deadline {
                return Err(anyhow::anyhow!(
                    "{} is busy: another process holds the write lock (waited {wait:?})",
                    lock_path.display()
                ));
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    /// Non-blocking probe used by tests to prove two handles contend.
    #[cfg(test)]
    fn try_acquire(target: &Path) -> Result<Option<Self>> {
        let lock_path = Self::lock_path(target);
        let file = Self::open(target).with_context(|| format!("open {}", lock_path.display()))?;
        match file.try_lock() {
            Ok(()) => Ok(Some(Self { file })),
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Error(e)) => {
                Err(e).with_context(|| format!("lock {}", lock_path.display()))
            }
        }
    }
}

impl Drop for PathLock {
    fn drop(&mut self) {
        // Best effort: the kernel also releases the lock when the handle
        // closes (or the process exits), so a failed unlock must not panic.
        let _ = self.file.unlock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir() -> PathBuf {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "tor-socks5-pathlock-test-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn lock_path_is_a_sibling_with_a_lock_suffix() {
        assert_eq!(
            PathLock::lock_path(Path::new("/data/tor-socks5.ktav")).file_name(),
            Some(std::ffi::OsStr::new("tor-socks5.ktav.lock"))
        );
    }

    #[test]
    fn second_handle_cannot_take_the_lock_while_it_is_held() {
        let dir = tmp_dir();
        let target = dir.join("store.log");
        let first = PathLock::acquire(&target).expect("first acquire");
        assert!(
            PathLock::try_acquire(&target).expect("try").is_none(),
            "a second handle must be excluded while the lock is held"
        );
        drop(first);
        assert!(
            PathLock::try_acquire(&target).expect("try").is_some(),
            "the lock must be acquirable again after release"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
