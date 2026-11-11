# tor-dirmgr: recover poisoned shared directory access

**Status:** prepared for review; not sent. Verification passed as documented below; tests were not executed.

## Problem observed

The pristine `SharedMutArc` unwraps poisoned `RwLock` guards, so a panic while `mutate` holds the lock prevents subsequent access. The vendor README summarizes the carried change as poison recovery with possible staleness. Panic propagation and lack of rollback are stated in the patched Rust API comment, not in the README or provenance record (`vendor/tor-dirmgr/src/shared_ref.rs`).

## Proposed mechanism

Recover poisoned guards with `PoisonError::into_inner` in get, replace, clear and mutate. The original panic still propagates, and partial mutations are not rolled back. A previously cloned Arc snapshot remains unchanged under copy-on-write; the stored value can retain mutations completed before the panic.

## Compatibility and coverage

No API/configuration/default change. The copied regression induces a panic after a vector mutation and asserts subsequent get/mutate/replace/clear behavior, the old snapshot and partial mutation; it was compile-checked, not executed.

## Check status

`verify.py --prepare --individual`: PASS (8 patches). `verify.py --cargo-check --individual`: PASS (8 patches), including compile-only `cargo check --tests`. No tests were executed.
