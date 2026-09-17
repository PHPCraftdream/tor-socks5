//! Owned temp-file save guards and reader-side stale-temp cleanup.
//!
//! # Why pid-based staleness is wrong (TS17-01)
//!
//! Reader-side cleanup helpers historically inferred staleness from
//! `pid != std::process::id()`. That is unsound twice over: another pid is
//! not a dead process (the owner may be a live daemon or CLI mid-save), and
//! a malformed pid suffix parses to `None`, which the old code treated as
//! stale and deleted. Both cases delete a temp file belonging to a LIVE
//! writer, which then fails its rename.
//!
//! # The ownership protocol
//!
//! Every writer holds an advisory exclusive [`std::fs::File::lock`] for the
//! whole create→rename span. Advisory locks are released by the kernel when
//! the holder dies, so a cleanup can delete a temp **iff it can acquire that
//! lock**: lock-acquirable means provably ownerless. PIDs never infer
//! liveness — they only make names unique.
//!
//! The lock is held on a *companion* file (`.name.pid.seq.tmp.lock`), never
//! on the temp file itself. This matters on Windows, where `File::lock` is a
//! mandatory byte-range lock (`LockFileEx`) rather than an advisory one: a
//! lock held on the temp would still be in force for the few instructions
//! between the publishing rename and the handle's close, and every reader
//! that opened the freshly published file in that window failed with
//! `ERROR_LOCK_VIOLATION` (os error 33). Locking a companion instead keeps
//! the published file lock-free at all times, on every platform.
//!
//! The companion is created and locked *before* the temp file exists, and is
//! removed only after the temp is gone (renamed onto the target, or deleted
//! by the guard's `Drop`), so there is no window in which a canonical temp
//! exists without a live owner's lock behind it.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Suffix of the companion lock file that carries a temp's ownership.
const LOCK_SUFFIX: &str = ".lock";

/// Pure name builder: canonical temp-file name for a target whose file name
/// is `target_name`. ONE source of truth for the format; [`parse_temp_name`]
/// is its exact inverse (recogniser), so a writer and every reader can never
/// drift apart (TS17-04).
pub fn temp_file_name(target_name: &str, pid: u32, seq: u64) -> String {
    format!(".{target_name}.{pid}.{seq}.tmp")
}

/// Pure recogniser: `Some((pid, seq))` iff `entry_name` is EXACTLY the
/// canonical temp name for `target_name`. Malformed suffixes (non-numeric or
/// out-of-range pid, missing/extra segments, wrong extension, missing pid
/// segment) must return None — they are never "our" temps and are never
/// cleaned (TS17-01). A companion lock file ends in an extra `.lock`
/// segment, so it is rejected here and never mistaken for a temp.
pub fn parse_temp_name(entry_name: &str, target_name: &str) -> Option<(u32, u64)> {
    let rest = entry_name
        .strip_prefix('.')?
        .strip_prefix(target_name)?
        .strip_prefix('.')?;
    let mut parts = rest.split('.');
    let pid = parts.next()?.parse::<u32>().ok()?;
    let seq = parts.next()?.parse::<u64>().ok()?;
    match parts.next()? {
        "tmp" => {}
        _ => return None,
    }
    parts.next().is_none().then_some((pid, seq))
}

/// Companion lock path carrying ownership of `temp`.
fn lock_path_for(temp: &Path) -> PathBuf {
    let mut name = temp.as_os_str().to_os_string();
    name.push(LOCK_SUFFIX);
    PathBuf::from(name)
}

/// Wrap an io error with the operation and path, preserving the ErrorKind.
fn with_context(e: io::Error, op: &str, path: &Path) -> io::Error {
    io::Error::new(e.kind(), format!("{op} {}: {e}", path.display()))
}

/// Sibling temp path for `target` with the caller's unique `seq`.
/// Returns InvalidInput if `target` has no file name.
pub fn temp_path_for(target: &Path, seq: u64) -> io::Result<PathBuf> {
    let name = target.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("no file name in {}", target.display()),
        )
    })?;
    Ok(target.with_file_name(temp_file_name(name, std::process::id(), seq)))
}

/// An owned temp file on the way to `target`, with its ownership proven by
/// an exclusive lock on a companion file.
///
/// Ownership protocol (TS17-01): the guard holds an advisory exclusive
/// `File::lock` on `<temp>.lock` from before the temp file exists until
/// after the temp is gone. A concurrent reader's cleanup deletes a canonical
/// temp only when it can acquire that companion's lock — the kernel releases
/// advisory locks when the holder process dies, so lock-acquirable means
/// provably ownerless. PID is never used to infer liveness; it only makes
/// names unique.
///
/// The lock deliberately lives on the companion rather than on the temp
/// itself: on Windows `File::lock` is a mandatory byte-range lock, so a lock
/// held on the temp would still apply to the *target* for the moments
/// between the publishing rename and the handle's close, failing concurrent
/// readers with os error 33.
pub struct TempFileGuard {
    /// Data handle. Taken (closed) before the publishing rename.
    file: Option<File>,
    /// Companion handle holding the ownership lock. Closed on drop, which is
    /// what releases the lock.
    _lock: File,
    temp: PathBuf,
    lock_path: PathBuf,
    target: PathBuf,
    done: bool,
}

impl TempFileGuard {
    /// Create and lock the companion, then create the temp file.
    /// Best-effort `create_dir_all` on the parent like the existing writers.
    /// Every error path removes what it created and is reported as io::Error
    /// with the operation and path in the message, preserving the original
    /// ErrorKind.
    pub fn create(target: &Path, seq: u64) -> io::Result<Self> {
        let name = target.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("no file name in {}", target.display()),
            )
        })?;
        let pid = std::process::id();
        let temp = target.with_file_name(temp_file_name(name, pid, seq));
        let lock_path = lock_path_for(&temp);

        if let Some(dir) = target.parent() {
            if !dir.as_os_str().is_empty() {
                fs::create_dir_all(dir).ok();
            }
        }

        // The companion is created (not create_new: a dead owner may have
        // left one behind) and locked BEFORE the temp exists, so the temp is
        // never visible without a live owner's lock standing behind it.
        let lock = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| with_context(e, "create", &lock_path))?;
        // try_lock, not lock: (pid, seq) is unique per live writer, so a held
        // companion means a name collision that must be reported rather than
        // waited on.
        if lock.try_lock().is_err() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("temp {} is owned by a live writer", temp.display()),
            ));
        }

        // Truncating is safe: the companion lock above already proves we own
        // this name, so any leftover content belongs to a dead writer.
        let file = match OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp)
        {
            Ok(file) => file,
            Err(e) => {
                drop(lock);
                let _ = fs::remove_file(&lock_path);
                return Err(with_context(e, "create", &temp));
            }
        };

        Ok(Self {
            file: Some(file),
            _lock: lock,
            temp,
            lock_path,
            target: target.to_path_buf(),
            done: false,
        })
    }

    /// The canonical temp path this guard owns.
    pub fn temp_path(&self) -> &Path {
        &self.temp
    }

    /// Write the whole buffer to the temp file.
    pub fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        let temp = &self.temp;
        self.file
            .as_mut()
            .ok_or_else(|| io::Error::other(format!("write after publish {}", temp.display())))?
            .write_all(data)
            .map_err(|e| with_context(e, "write", temp))
    }

    /// fsync the temp data (call before [`Self::rename_into_target`] when
    /// the rename must happen inside a caller-owned critical section).
    pub fn fsync(&mut self) -> io::Result<()> {
        let temp = &self.temp;
        self.file
            .as_mut()
            .ok_or_else(|| io::Error::other(format!("fsync after publish {}", temp.display())))?
            .sync_all()
            .map_err(|e| with_context(e, "fsync", temp))
    }

    /// fsync + rename temp → target + parent-dir fsync. Marks the guard
    /// done on success; on error the guard's Drop still removes the temp.
    pub fn finish(mut self) -> io::Result<()> {
        self.fsync()?;
        self.rename_into_target()
    }

    /// rename temp → target + parent-dir fsync without fsync of the data
    /// (caller fsynced earlier). Same done/error semantics as [`Self::finish`].
    pub fn rename_into_target(mut self) -> io::Result<()> {
        // Close the data handle first: the published target must carry no
        // open handle of ours into the reader's hands.
        self.file.take();
        fs::rename(&self.temp, &self.target).map_err(|e| with_context(e, "rename", &self.temp))?;
        #[cfg(unix)]
        {
            let dir = crate::parent_dir(&self.target).to_path_buf();
            fs::File::open(&dir)
                .and_then(|d| d.sync_all())
                .map_err(|e| with_context(e, "fsync dir", &dir))?;
        }
        self.done = true;
        Ok(())
    }
}

impl Drop for TempFileGuard {
    /// Best-effort removal of an uncommitted temp, then of the companion.
    /// The companion goes last and its lock is released only when `_lock`
    /// closes right after, so no cleanup can see the temp unowned.
    fn drop(&mut self) {
        self.file.take();
        if !self.done {
            let _ = fs::remove_file(&self.temp);
        }
        let _ = fs::remove_file(&self.lock_path);
    }
}

/// Lock-disciplined delete: remove `path` iff its companion lock can be
/// acquired, or no companion exists at all (the writer creates the companion
/// before the temp, so a temp without one is provably ownerless). Never
/// blocks. Returns true if the file is gone afterwards (including NotFound),
/// false if a live owner holds it or the attempt errored.
pub fn remove_temp_if_unlocked(path: &Path) -> bool {
    let lock_path = lock_path_for(path);
    match OpenOptions::new().write(true).open(&lock_path) {
        Ok(lock) => {
            if lock.try_lock().is_err() {
                return false;
            }
            drop(lock);
            let _ = fs::remove_file(&lock_path);
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return false,
    }
    match fs::remove_file(path) {
        Ok(()) => true,
        Err(e) if e.kind() == io::ErrorKind::NotFound => true,
        Err(_) => false,
    }
}

/// Reader-side cleanup of canonical temps for `target`: exact-name match via
/// [`parse_temp_name`], every candidate through
/// [`remove_temp_if_unlocked`]. Read-only with respect to any live writer.
/// Best-effort overall: a missing directory or unreadable entries are
/// silently ignored (same policy as the helpers this replaces).
pub fn cleanup_temp_files(target: &Path) {
    cleanup_temp_files_with(target, |_| false);
}

/// Same, additionally offering legacy-format names to the same lock
/// discipline (migration path for temps written by older name formats; the
/// predicate receives each directory entry's file name as `&str`).
pub fn cleanup_temp_files_with(target: &Path, legacy_match: impl Fn(&str) -> bool) {
    let Some(dir) = fs::read_dir(crate::parent_dir(target)).ok() else {
        return;
    };
    let Some(name) = target.file_name().and_then(|n| n.to_str()) else {
        return;
    };
    // Companions whose temp is already gone: a dead writer that got as far as
    // the rename leaves one behind, and nothing else would ever remove it.
    let mut orphan_locks = Vec::new();
    for entry in dir.flatten() {
        let Ok(file_name) = entry.file_name().into_string() else {
            continue;
        };
        if let Some(temp_name) = file_name.strip_suffix(LOCK_SUFFIX) {
            if parse_temp_name(temp_name, name).is_some() {
                orphan_locks.push((entry.path(), entry.path().with_file_name(temp_name)));
            }
            continue;
        }
        let is_candidate = parse_temp_name(&file_name, name).is_some() || legacy_match(&file_name);
        if is_candidate {
            remove_temp_if_unlocked(&entry.path());
        }
    }
    for (lock, temp) in orphan_locks {
        if temp.exists() {
            // Handled above (or owned by a live writer); not an orphan.
            continue;
        }
        let Ok(handle) = OpenOptions::new().write(true).open(&lock) else {
            continue;
        };
        if handle.try_lock().is_ok() {
            drop(handle);
            let _ = fs::remove_file(&lock);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir() -> PathBuf {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "tor-socks5-persist-lock-test-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn temp_name_round_trips_through_parse() {
        for target in ["store.log", "tor-socks5.ktav", "data", "a.b.c"] {
            for (pid, seq) in [(1u32, 0u64), (4_294_967_295, 18_446_744_073_709_551_615)] {
                let name = temp_file_name(target, pid, seq);
                assert_eq!(parse_temp_name(&name, target), Some((pid, seq)));
            }
        }
    }

    #[test]
    fn parse_rejects_malformed_names() {
        let negatives = [
            ".t.xyz.1.tmp",         // garbage pid
            ".t.99999999999.1.tmp", // pid > u32::MAX
            ".t.1.abc.tmp",         // non-numeric seq
            ".t.1.tmp",             // missing seq
            ".t.1.2.3.tmp",         // extra segment
            ".t.1.2.tmpx",          // wrong extension
            ".t.1.2.tmp.bak",       // extra segment after extension
            ".t.1.2.tmp.lock",      // the companion, not a temp
            ".other.1.2.tmp",       // different target prefix
            "t.1.2.tmp",            // no leading dot
        ];
        for name in negatives {
            assert_eq!(parse_temp_name(name, "t"), None, "{name}");
        }
    }

    #[test]
    fn guard_finish_publishes_and_leaves_no_temp() {
        let dir = tmp_dir();
        let target = dir.join("store.log");
        let mut guard = TempFileGuard::create(&target, 1).unwrap();
        let temp = guard.temp_path().to_path_buf();
        assert!(temp.exists());
        assert!(
            parse_temp_name(temp.file_name().unwrap().to_str().unwrap(), "store.log").is_some()
        );
        guard.write_all(b"hello").unwrap();
        guard.finish().unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"hello");
        assert!(!temp.exists());
        assert_eq!(
            fs::read_dir(&dir).unwrap().count(),
            1,
            "no temp and no companion left"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// The published file must be readable the instant `finish` returns. A
    /// lock held on the temp itself stayed in force on the target for the
    /// moments between the rename and the handle's close, and on Windows —
    /// where `File::lock` is mandatory — every reader in that window failed
    /// with os error 33. The lock lives on a companion precisely so this
    /// cannot happen.
    #[test]
    fn published_target_is_immediately_readable() {
        let dir = tmp_dir();
        let target = dir.join("store.log");
        for seq in 0..50 {
            let mut guard = TempFileGuard::create(&target, seq).unwrap();
            guard.write_all(b"published").unwrap();
            guard.finish().unwrap();
            assert_eq!(
                fs::read(&target).expect("published target reads without a lock conflict"),
                b"published"
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }

    /// Readers must also be able to read the PREVIOUS contents of the target
    /// while a writer is mid-save, which is the normal steady state.
    #[test]
    fn target_stays_readable_while_a_guard_is_open() {
        let dir = tmp_dir();
        let target = dir.join("store.log");
        fs::write(&target, b"old").unwrap();
        let mut guard = TempFileGuard::create(&target, 7).unwrap();
        guard.write_all(b"new").unwrap();
        assert_eq!(
            fs::read(&target).expect("target reads while a save is in flight"),
            b"old"
        );
        guard.finish().unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"new");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn guard_drop_without_finish_removes_temp_and_keeps_target() {
        let dir = tmp_dir();
        let target = dir.join("store.log");
        fs::write(&target, b"keep").unwrap();
        let temp;
        {
            let mut guard = TempFileGuard::create(&target, 2).unwrap();
            temp = guard.temp_path().to_path_buf();
            guard.write_all(b"partial").unwrap();
        }
        assert!(!temp.exists());
        assert!(!lock_path_for(&temp).exists(), "companion removed too");
        assert_eq!(fs::read(&target).unwrap(), b"keep");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unlocked_file_is_removed_locked_file_survives() {
        let dir = tmp_dir();
        let target = dir.join("store.log");
        let plain = dir.join(".store.log.1.9.tmp");
        fs::write(&plain, b"dead owner").unwrap();
        assert!(remove_temp_if_unlocked(&plain));
        assert!(!plain.exists());

        let guard = TempFileGuard::create(&target, 3).unwrap();
        assert!(!remove_temp_if_unlocked(guard.temp_path()));
        assert!(guard.temp_path().exists());
        drop(guard);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cleanup_skips_live_temp_and_removes_dead_one() {
        let dir = tmp_dir();
        let target = dir.join("store.log");
        let guard = TempFileGuard::create(&target, 4).unwrap();
        let dead = dir.join(temp_file_name("store.log", 12345, 77));
        fs::write(&dead, b"dead").unwrap();

        cleanup_temp_files(&target);

        assert!(guard.temp_path().exists(), "live writer's temp survives");
        assert!(
            lock_path_for(guard.temp_path()).exists(),
            "live writer's companion survives"
        );
        assert!(!dead.exists(), "ownerless temp is cleaned");
        drop(guard);
        let _ = fs::remove_dir_all(&dir);
    }

    /// A dead writer that got as far as the rename leaves its companion
    /// behind with no temp next to it. Nothing else would ever remove it, so
    /// cleanup has to — but only when its lock can be acquired.
    #[test]
    fn cleanup_removes_an_orphan_companion_but_spares_a_live_one() {
        let dir = tmp_dir();
        let target = dir.join("store.log");
        let orphan = lock_path_for(&dir.join(temp_file_name("store.log", 4242, 5)));
        fs::write(&orphan, b"").unwrap();

        let guard = TempFileGuard::create(&target, 6).unwrap();
        let live_lock = lock_path_for(guard.temp_path());

        cleanup_temp_files(&target);

        assert!(!orphan.exists(), "orphan companion is cleaned");
        assert!(live_lock.exists(), "live writer's companion survives");
        assert!(guard.temp_path().exists(), "live writer's temp survives");
        drop(guard);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cleanup_with_legacy_removes_legacy_and_malformed_survives_both() {
        let dir = tmp_dir();
        let target = dir.join("store.log");
        let legacy = dir.join(".store.log.tmp.old");
        fs::write(&legacy, b"legacy").unwrap();
        let malformed = dir.join(".store.log.not-a-pid.1.tmp");
        fs::write(&malformed, b"garbage").unwrap();

        cleanup_temp_files_with(&target, |n| n == ".store.log.tmp.old");
        assert!(!legacy.exists(), "legacy temp cleaned");
        assert!(malformed.exists(), "malformed name survives first cleanup");

        cleanup_temp_files(&target);
        assert!(malformed.exists(), "malformed name survives second cleanup");
        let _ = fs::remove_dir_all(&dir);
    }
}
