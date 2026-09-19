# persist-lock

Cross-process file-lock plumbing for crash-safe whole-file persistence: transaction locks on a target's sibling `.lock` file, temp-file save guards whose ownership is proven by an advisory lock, reader-side stale-temp cleanup, and parent-directory fsync.

It exists for applications where a long-lived daemon and short-lived CLI tools save to the same state files and a torn or lost save is unacceptable. The core rule: **pids never infer liveness** — an embedded pid belongs to a live process just as often as to a dead one. Instead, every writer holds an advisory exclusive lock on its own temp file for the whole create→rename span; the kernel releases the lock when the holder dies, so a cleanup sweep deletes a temp file if and only if it can acquire that lock.

## Usage

The atomic save pattern the crate is built around:

```rust
use anyhow::Result;
use persist_lock::{PathLock, TempFileGuard, CLI_LOCK_WAIT};

fn save_state(target: &std::path::Path) -> Result<()> {
    // 1. Transaction lock: overlapping writers queue instead of
    //    publishing over each other's snapshot. Bounded, so a CLI
    //    fails with a clear error instead of hanging behind a
    //    stuck daemon.
    let tx = PathLock::acquire_bounded(target, CLI_LOCK_WAIT)?;

    // 2. Stage the new content in a lock-owned temp file.
    let mut guard = TempFileGuard::create(target, 0)?;
    guard.write_all(b"{\"ok\": true}\n")?;

    // 3. Publish: fsync + atomic temp-to-target rename. Readers
    //    see the old or the new file, never a torn one.
    guard.finish()?;
    drop(tx);
    Ok(())
}
```

On the read side, `cleanup_temp_files` sweeps temps left behind by provably dead writers, and `temp_file_name`/`parse_temp_name` form an exact builder/recogniser pair so writers and readers cannot drift apart.

## Example

`cargo run --example atomic_save` walks the full pattern against a scratch file: lock acquisition, temp-name round-trip, guarded save, cleanup sweep.
