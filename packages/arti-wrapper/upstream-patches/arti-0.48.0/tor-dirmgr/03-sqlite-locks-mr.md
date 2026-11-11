# tor-dirmgr: classify SQLite lock contention as cache access

**Status:** prepared for review; not sent. Verification passed as documented below; tests were not executed.

## Problem observed

The pristine SQLite classifier maps `DatabaseBusy` and `DatabaseLocked` to `Internal`; conversion then treats `Internal` as a programming bug. The vendor README describes Windows AV/indexer/sync file locks as a plausible explanation for transient contention, but cannot identify the process behind any particular lock. The provenance record documents the 0.48.0 archive baseline and source-comparison scope, not the cause of lock contention; see [vendor README](../../../../../vendor/README.md) and [provenance](../../../../../vendor/PROVENANCE.md).

## Proposed mechanism

Map SQLite `DatabaseBusy` and `DatabaseLocked` to `CacheAccessFailed`, so conversion preserves a `SqliteError` with cache-access classification instead of turning ordinary contention into a fatal internal bug.

## Compatibility and coverage

No API/configuration/default change. The copied regression tests classify both codes directly and through `Error::kind`, plus neighboring error cases; they were compile-checked, not executed.

## Check status

`verify.py --prepare --individual`: PASS (8 patches). `verify.py --cargo-check --individual`: PASS (8 patches), including compile-only `cargo check --tests`. No tests were executed.
