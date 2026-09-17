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
//! Every writer holds an advisory exclusive [`std::fs::File::lock`] on its
//! own temp file for the whole create→rename span. Advisory locks are
//! released by the kernel when the holder dies, so a cleanup can delete a
//! temp **iff it can acquire that lock**: lock-acquirable means provably
//! ownerless. PIDs never infer liveness — they only make names unique.
//!
//! The canonical temp name (`.name.pid.seq.tmp`) becomes visible via a
//! rename from a staging name (`.name.pid.seq.stage`) that the temp pattern
//! never matches, and the lock is taken on the staging handle *before* that
//! rename — there is no window in which a live writer's canonical temp is
//! unlocked.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

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
/// cleaned (TS17-01).
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

/// An owned, exclusively-locked temp file on the way to `target`.
///
/// Ownership protocol (TS17-01): the guard holds an advisory exclusive
/// `File::lock` on the temp file from before it is visible under its
/// canonical name until the final rename completes. A concurrent reader's
/// cleanup can only delete a canonical temp whose lock it can acquire — the
/// kernel releases advisory locks when the holder process dies, so
/// lock-acquirable means provably ownerless. PID is never used to infer
/// liveness; it only makes names unique.
///
/// The canonical temp becomes visible via a rename from a staging name
/// (`.name.pid.seq.stage`) that the temp pattern never matches, and the
/// lock is taken on the staging handle before that rename: there is no
/// window in which a live writer's canonical temp is unlocked.
pub struct TempFileGuard {
    file: File,
    temp: PathBuf,
    target: PathBuf,
    done: bool,
}

impl TempFileGuard {
    /// Create the staging file (create_new → exclusive), lock it, rename it
    /// to the canonical temp name. Best-effort `create_dir_all` on the
    /// parent like the existing writers. Every error path removes the
    /// staging file and is reported as io::Error with the operation and
    /// path in the message, preserving the original ErrorKind.
    pub fn create(target: &Path, seq: u64) -> io::Result<Self> {
        let name = target.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("no file name in {}", target.display()),
            )
        })?;
        let pid = std::process::id();
        let staging = target.with_file_name(format!(".{name}.{pid}.{seq}.stage"));
        let temp = target.with_file_name(temp_file_name(name, pid, seq));

        if let Some(dir) = target.parent() {
            if !dir.as_os_str().is_empty() {
                fs::create_dir_all(dir).ok();
            }
        }

        let run = || -> io::Result<Self> {
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&staging)
                .map_err(|e| with_context(e, "create", &staging))?;
            file.lock().map_err(|e| with_context(e, "lock", &staging))?;
            fs::rename(&staging, &temp).map_err(|e| with_context(e, "rename", &staging))?;
            Ok(Self {
                file,
                temp,
                target: target.to_path_buf(),
                done: false,
            })
        };

        match run() {
            Ok(guard) => Ok(guard),
            Err(e) => {
                let _ = fs::remove_file(&staging);
                Err(e)
            }
        }
    }

    /// The canonical temp path this guard owns.
    pub fn temp_path(&self) -> &Path {
        &self.temp
    }

    /// Write the whole buffer through the locked handle.
    pub fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        self.file
            .write_all(data)
            .map_err(|e| with_context(e, "write", &self.temp))
    }

    /// fsync the temp data (call before [`Self::rename_into_target`] when
    /// the rename must happen inside a caller-owned critical section).
    pub fn fsync(&mut self) -> io::Result<()> {
        self.file
            .sync_all()
            .map_err(|e| with_context(e, "fsync", &self.temp))
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
    /// Best-effort removal of an uncommitted temp (the lock releases when
    /// the handle closes right after).
    fn drop(&mut self) {
        if !self.done {
            let _ = fs::remove_file(&self.temp);
        }
    }
}

/// Lock-disciplined delete: remove `path` iff its exclusive lock can be
/// acquired (owner provably dead). Never blocks. Returns true if the file
/// is gone afterwards (including NotFound), false if a live owner holds it
/// or the attempt errored. Drops the acquired handle BEFORE removing.
pub fn remove_temp_if_unlocked(path: &Path) -> bool {
    let file = match OpenOptions::new().write(true).open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return true,
        Err(_) => return false,
    };
    match file.try_lock() {
        Ok(()) => {}
        Err(_) => return false,
    }
    drop(file);
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
    for entry in dir.flatten() {
        let Ok(file_name) = entry.file_name().into_string() else {
            continue;
        };
        let is_candidate = parse_temp_name(&file_name, name).is_some() || legacy_match(&file_name);
        if is_candidate {
            remove_temp_if_unlocked(&entry.path());
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
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1, "no staging left");
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
        assert!(!dead.exists(), "ownerless temp is cleaned");
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
