//! The atomic read-modify-write pattern `persist-lock` exists for:
//!
//! 1. take a cross-process advisory [`persist_lock::PathLock`] on the
//!    target's sibling `.lock` file, so overlapping transactions (a daemon
//!    writer and a CLI process) queue instead of publishing over each
//!    other's snapshot;
//! 2. stage the new content in a [`persist_lock::TempFileGuard`] temp file
//!    whose ownership is proven by an advisory lock, never by a pid;
//! 3. publish with `finish()`'s fsync + atomic temp-to-target rename.
//!
//! Run with: `cargo run --example atomic_save -p persist-lock`

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use persist_lock::{
    cleanup_temp_files, parse_temp_name, temp_file_name, PathLock, TempFileGuard, CLI_LOCK_WAIT,
};

fn main() -> Result<()> {
    let dir = std::env::temp_dir().join(format!("persist-lock-example-{}", std::process::id()));
    fs::create_dir_all(&dir)?;
    let target: PathBuf = dir.join("state.json");

    println!("target:       {}", target.display());
    println!("sibling lock: {}", PathLock::lock_path(&target).display());

    // Transaction lock: serialises whole read-modify-write cycles across
    // processes. Bounded so a CLI fails with a clear error instead of
    // hanging behind a stuck daemon. Released when `tx` is dropped.
    let tx = PathLock::acquire_bounded(&target, CLI_LOCK_WAIT)
        .context("acquiring the transaction lock")?;

    // Read the previous state (first run: none) and compute the mutation.
    let saves = match fs::read_to_string(&target) {
        Ok(prev) => prev
            .strip_prefix("saves = ")
            .and_then(|rest| rest.trim().parse::<u32>().ok())
            .context("corrupt counter in the existing state file")?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => return Err(e).context("reading the previous state"),
    };
    let next = saves + 1;

    // A canonical temp name embeds pid + seq for uniqueness only, never
    // for liveness. `parse_temp_name` is the exact recogniser for names
    // `temp_file_name` builds (TS17-04), so writers and readers cannot
    // drift apart.
    let canonical = temp_file_name("state.json", std::process::id(), 0);
    println!("temp name:    {canonical}");
    println!(
        "recognised:   {:?}",
        parse_temp_name(&canonical, "state.json")
    );

    // Stage the new content. `create` holds an advisory exclusive lock on
    // a companion file for the whole create-to-rename span, so a
    // concurrent reader's stale-temp cleanup only deletes temps whose
    // owner provably died (the kernel releases the lock on death).
    let mut guard = TempFileGuard::create(&target, 0).context("creating the temp guard")?;
    println!("staging:      {}", guard.temp_path().display());
    guard
        .write_all(format!("saves = {next}\n").as_bytes())
        .context("writing the temp")?;
    guard.finish().context("publishing (fsync + rename)")?;

    // The publish is a rename: readers see the old or the new file, never
    // a torn one. Dropping the guard without `finish` would have removed
    // the temp instead.
    println!("published:    {}", fs::read_to_string(&target)?.trim());

    // Reader-side sweep of temps left behind by dead writers. Best-effort
    // and read-only with respect to live writers; here it finds nothing.
    cleanup_temp_files(&target);
    println!("cleanup sweep ran (nothing left to remove)");

    drop(tx); // release the transaction lock
    fs::remove_dir_all(&dir).context("removing the scratch dir")?;
    Ok(())
}
