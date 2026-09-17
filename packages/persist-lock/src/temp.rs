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
//!
//! # Why the companion alone is not enough (TS18-01)
//!
//! The companion lock lives on an *unlinkable* name: cleanup removes the
//! companion file after acquiring its lock, but unlink does not disturb an
//! already-open locked handle, and a new opener gets a fresh inode — mutual
//! exclusion breaks (TS18-01). The stable, never-unlinked
//! `<target>.templock` file (precedent: `path_lock.rs`) serialises every
//! (companion, temp) name-state transition: creation (companion open +
//! `try_lock` + temp create), companion/temp removal in `Drop` and cleanup,
//! and the cleanup candidate/orphan decisions. Long work (writes, fsyncs,
//! the publishing rename) stays outside the section, so writers of one
//! target do not serialise their payloads. Ownership of a specific temp is
//! STILL proven exclusively by its companion's advisory lock (the kernel
//! releases it on holder death; a PID is never liveness evidence).
//!
//! # Migration boundary (known limitation)
//!
//! A temp written by an OLD binary has no companion. In mixed old/new
//! deployments a missing companion does NOT prove the writer is dead, and
//! cleanup's delete-on-missing-companion rule must not be read as a
//! guarantee over foreign writers.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Test-only interleaving seams for the TS18-01 forcing tests. `park` is a
/// no-op outside the crate's own unit-test build, so production code carries
/// no synchronization. A forcing test arms a slot, parks a participant at an
/// exact interleaving point, and releases it deterministically.
#[cfg(test)]
pub(crate) mod seam {
    use std::cell::Cell;
    use std::collections::HashMap;
    use std::sync::{Condvar, Mutex, OnceLock};
    use std::time::Duration;

    /// How long a participant parks before proceeding on its own. A timeout
    /// here is a DESIGNED outcome: in the fixed protocol the parked writer
    /// holds the state-transition lock and the forcing test's cleanup cannot
    /// reach the release point, so the writer must proceed when the bound
    /// expires.
    pub const PARK_TIMEOUT: Duration = Duration::from_secs(5);
    /// How long a test waits for a participant to reach a slot before
    /// concluding it never will.
    pub const WAIT_PARKED_TIMEOUT: Duration = Duration::from_secs(10);

    /// `TempFileGuard::create`: parked before the writer can establish
    /// ownership of the companion (before its `try_lock`; in the pre-TS18-01
    /// protocol the companion is already open at this point, in the fixed
    /// protocol this sits just before the critical section that wraps
    /// open+try_lock).
    pub const CREATE_BEFORE_OWNERSHIP: usize = 0;
    /// `remove_temp_if_unlocked`: parked between `drop(lock)` and
    /// `remove_file(lock_path)` — the unlocked-name unlink window.
    pub const UNLOCKED_BEFORE_UNLINK: usize = 1;

    #[derive(Default)]
    struct Slot {
        armed: bool,
        parked: bool,
        released: bool,
    }

    fn slots() -> &'static Mutex<HashMap<usize, Slot>> {
        static SLOTS: OnceLock<Mutex<HashMap<usize, Slot>>> = OnceLock::new();
        SLOTS.get_or_init(|| Mutex::new(HashMap::new()))
    }

    fn slot(slots: &mut HashMap<usize, Slot>, idx: usize) -> &mut Slot {
        slots.entry(idx).or_default()
    }

    /// Arm (or re-arm) a slot; clears any stale state from a previous test.
    pub fn arm(idx: usize) {
        let mut guard = slots().lock().unwrap();
        let s = slot(&mut guard, idx);
        *s = Slot {
            armed: true,
            parked: false,
            released: false,
        };
        drop(guard);
    }

    pub fn disarm(idx: usize) {
        if let Ok(mut slots) = slots().lock() {
            slots.remove(&idx);
        }
    }

    thread_local! {
        /// Only threads that opted in as forcing-test participants may park;
        /// concurrent ordinary tests never block even while a slot is armed.
        static ENABLED: Cell<bool> = const { Cell::new(false) };
    }

    /// Mark the calling thread as a forcing-test participant that may park on
    /// armed slots. Must be the first statement of a spawned participant.
    pub fn enable() {
        ENABLED.with(|e| e.set(true));
    }

    /// Block the calling thread iff this thread opted in AND the slot is
    /// armed AND it has not already been sticky-released; otherwise return at
    /// once. Bounded by [`PARK_TIMEOUT`]: returns whether someone released
    /// us. A timeout is not an error (see PARK_TIMEOUT).
    pub fn park(idx: usize) -> bool {
        if !ENABLED.with(|e| e.get()) {
            return true;
        }
        let mut guard = slots().lock().unwrap();
        if !guard.get(&idx).is_some_and(|s| s.armed) {
            return true;
        }
        let s = slot(&mut guard, idx);
        if s.released {
            // Sticky release: released before we arrived; sail through.
            s.parked = false;
            s.released = false;
            return true;
        }
        s.parked = true;
        drop(guard);
        CONDVAR.notify_all();
        let deadline = std::time::Instant::now() + PARK_TIMEOUT;
        let mut slots = slots().lock().unwrap();
        let released = loop {
            if slots.get(&idx).is_some_and(|s| s.released) {
                break true;
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                break false;
            }
            let (s, _t) = CONDVAR.wait_timeout(slots, deadline - now).unwrap();
            slots = s;
        };
        {
            let mut guard = slots;
            let s = slot(&mut guard, idx);
            s.parked = false;
            s.released = false;
        }
        released
    }

    /// Wait until some thread is parked at `idx`, bounded by
    /// [`WAIT_PARKED_TIMEOUT`]; `false` on timeout (no stale parked flag is
    /// left behind).
    pub fn wait_parked(idx: usize) -> bool {
        let deadline = std::time::Instant::now() + WAIT_PARKED_TIMEOUT;
        let mut slots = slots().lock().unwrap();
        loop {
            if slots.get(&idx).is_some_and(|s| s.parked) {
                return true;
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                if let Some(s) = slots.get_mut(&idx) {
                    s.parked = false;
                }
                return false;
            }
            let (s, _t) = CONDVAR.wait_timeout(slots, deadline - now).unwrap();
            slots = s;
        }
    }

    /// Release the thread parked at `idx`.
    pub fn release(idx: usize) {
        let mut slots = slots().lock().unwrap();
        if let Some(s) = slots.get_mut(&idx) {
            s.released = true;
        }
        drop(slots);
        CONDVAR.notify_all();
    }

    static CONDVAR: Condvar = Condvar::new();
}

#[cfg(not(test))]
pub(crate) mod seam {
    pub const CREATE_BEFORE_OWNERSHIP: usize = 0;
    pub const UNLOCKED_BEFORE_UNLINK: usize = 1;
    pub fn park(_idx: usize) -> bool {
        true
    }
}

/// Suffix of the companion lock file that carries a temp's ownership.
const LOCK_SUFFIX: &str = ".lock";

/// Suffix of the stable, NEVER-unlinked critical-section lock file that
/// serialises every (companion, temp) name-state transition for one target.
const TEMPLOCK_SUFFIX: &str = ".templock";

/// Sibling critical-section lock path for `target` (same style as
/// [`crate::path_lock::PathLock::lock_path`]).
fn templock_path_for(target: &Path) -> PathBuf {
    let mut name = target.as_os_str().to_os_string();
    name.push(TEMPLOCK_SUFFIX);
    PathBuf::from(name)
}

/// A short critical-section lock over the (companion, temp) name state of
/// one target. Unlike the companion, this file is created on demand and
/// NEVER unlinked (same rule as [`crate::path_lock::PathLock`]'s sibling
/// `.lock`): unlinking a lock file that someone still holds open lets a
/// later opener lock a fresh inode alongside the existing holder — exactly
/// the TS18-01 substitution. Holding it covers only name-state transitions
/// (a few syscalls); writes, fsyncs and the publishing rename stay outside,
/// so writers of one target do not serialize their payloads.
struct TempLock {
    file: File,
}

impl TempLock {
    fn acquire(target: &Path) -> io::Result<Self> {
        let templock_path = templock_path_for(target);
        if let Some(dir) = templock_path.parent() {
            if !dir.as_os_str().is_empty() {
                fs::create_dir_all(dir).ok();
            }
        }
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&templock_path)
            .map_err(|e| with_context(e, "create", &templock_path))?;
        // Blocking: the holder keeps it only for a few syscalls, and the
        // kernel releases it if the holder dies.
        file.lock()
            .map_err(|e| with_context(e, "lock", &templock_path))?;
        Ok(Self { file })
    }
}

impl Drop for TempLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

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

        // Critical section: while the ownership of (companion, temp) is
        // established, no cleanup may observe or mutate those names. The
        // seam park is INSIDE the section — a parked writer holds the
        // templock, so cleanup physically cannot interleave.
        let _templock = TempLock::acquire(target)?;
        let _ = seam::park(seam::CREATE_BEFORE_OWNERSHIP);

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
        // waited on. The templock guard drops on return, releasing the
        // section.
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
                let _ = fs::remove_file(&lock_path); // still inside the section
                return Err(with_context(e, "create", &temp));
            }
        };

        // Ownership established; leave the critical section before any long
        // work.
        drop(_templock);

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
    /// Best-effort removal of an uncommitted temp, then of the companion,
    /// under the templock critical section. If the section cannot be
    /// acquired we degrade to removals without it, which is benign: the
    /// guard still holds the companion's advisory lock until this struct's
    /// fields drop, so a concurrent cleanup's `try_lock` still fails — and
    /// on this path both sides want the files gone anyway. The companion
    /// goes last and its lock is released only when `_lock` closes right
    /// after, so no cleanup can see the temp unowned.
    fn drop(&mut self) {
        self.file.take();
        let _section = TempLock::acquire(&self.target).ok();
        if !self.done {
            let _ = fs::remove_file(&self.temp);
        }
        let _ = fs::remove_file(&self.lock_path);
    }
}

/// Lock-disciplined delete: remove `path` iff its companion lock can be
/// acquired, or no companion exists at all (the writer creates the companion
/// before the temp, so a temp without one is provably ownerless). The whole
/// decision+act runs under the `<target>.templock` critical section (`target`
/// keys it), which makes the lock-acquisition decision and the unlinks atomic
/// against writers and other cleanups; the advisory companion lock remains
/// the liveness proof (the kernel releases it on holder death). Never blocks
/// on the companion: returns true if the file is gone afterwards (including
/// NotFound), false if a live owner holds it or the attempt errored.
pub fn remove_temp_if_unlocked(target: &Path, temp: &Path) -> bool {
    let Ok(_section) = TempLock::acquire(target) else {
        return false;
    };
    let lock_path = lock_path_for(temp);
    match OpenOptions::new().write(true).open(&lock_path) {
        Ok(lock) => {
            if lock.try_lock().is_err() {
                return false;
            }
            drop(lock);
            let _ = seam::park(seam::UNLOCKED_BEFORE_UNLINK);
            let _ = fs::remove_file(&lock_path);
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return false,
    }
    match fs::remove_file(temp) {
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
        // A `*.templock` name can never be a canonical temp (those end in
        // `.tmp`) nor a companion (those end in `.lock`), but a caller-supplied
        // legacy predicate must not be able to nominate it either.
        if file_name.ends_with(TEMPLOCK_SUFFIX) {
            continue;
        }
        let is_candidate = parse_temp_name(&file_name, name).is_some() || legacy_match(&file_name);
        if is_candidate {
            remove_temp_if_unlocked(target, &entry.path());
        }
    }
    for (lock, temp) in orphan_locks {
        // Re-check orphanhood INSIDE the section: a writer may have created
        // the temp between the scan above and now.
        let Ok(_section) = TempLock::acquire(target) else {
            continue;
        };
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
#[path = "temp_tests.rs"]
mod tests;
