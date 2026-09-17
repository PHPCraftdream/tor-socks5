//! Cross-process file-lock plumbing shared by all persistence writers:
//! whole-file transaction locks, owned temp-file save guards, reader-side
//! stale-temp cleanup, parent-directory fsync.
//!
//! # Why this crate exists (TS17-01)
//!
//! Reader-side "cleanup temp files" helpers used to delete temp files whose
//! embedded pid differed from `std::process::id()`. That reasoning is wrong:
//! another pid is a LIVE process just as often as a dead one (a daemon or a
//! concurrent CLI mid-save), and a malformed pid suffix (which parses to
//! `None`) was treated as stale too. Cleanup deleted temp files belonging to
//! live writers, which then failed their final rename and lost their save.
//!
//! # The ownership protocol
//!
//! Every writer instead holds an advisory exclusive [`std::fs::File::lock`]
//! (stable since Rust 1.89) on its own temp file for the whole
//! create→rename span — see [`TempFileGuard`]. The kernel releases advisory
//! locks when the holder dies, so a reader's cleanup can delete a temp iff
//! it can acquire that lock ([`remove_temp_if_unlocked`]):
//! lock-acquirable = provably dead owner. PIDs never infer liveness; they
//! only make names unique ([`temp_file_name`] / [`parse_temp_name`] are an
//! exact builder/recogniser pair, TS17-04).
//!
//! The canonical temp name becomes visible via a rename from a staging name
//! the temp pattern never matches, and the lock is taken on the staging
//! handle before that rename — a live writer's canonical temp is never
//! unlocked, so cleanup can never race the window into deletion.
//!
//! [`PathLock`] (in [`path_lock`]) is the sibling `.lock`-file transaction
//! lock that serialises whole read-modify-write cycles on a target.
//!
//! [`parent_dir`] / [`sync_parent_dir`] fix TS17-05: a bare relative file
//! name has an *empty* parent, which `File::open("")` cannot open — the
//! parent-directory fsync guarantee was silently skipped for the default
//! configuration. Empty parents are normalised to `.`.

mod dir;
pub mod path_lock;
mod temp;

pub use dir::{parent_dir, sync_parent_dir};
pub use path_lock::{PathLock, CLI_LOCK_WAIT, POOL_LOCK_WAIT};
pub use temp::{
    cleanup_temp_files, cleanup_temp_files_with, parse_temp_name, remove_temp_if_unlocked,
    temp_file_name, temp_path_for, TempFileGuard,
};
