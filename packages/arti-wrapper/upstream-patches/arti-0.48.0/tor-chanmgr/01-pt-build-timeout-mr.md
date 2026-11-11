# tor-chanmgr: allow longer pluggable transport channel builds

**Status:** prepared for review; not sent. Verification passed as documented below; tests were not executed.

## Problem observed

The pristine builder applies a 10-second total timeout to non-direct channel construction, including the opaque pluggable-transport handshake, and maps expiry to the existing `ChanTimeout`. The vendor README lists the carried 10-to-45-second change. The provenance record identifies the 0.48.0 archive baseline and observed source-file differences; it does not document the timeout rationale. See [vendor README](../../../../../vendor/README.md) and [provenance](../../../../../vendor/PROVENANCE.md).

## Proposed mechanism

Raise only the non-direct channel-build total timeout from 10 to 45 seconds. Keep the direct timeout at 5 seconds and preserve existing error handling; do not add termination or change other APIs.

## Compatibility and coverage

No public API or configuration surface changes, but the hard-coded non-direct default budget changes from 10 to 45 seconds (direct remains five seconds). Slow pluggable transports are less likely to fail prematurely, at the cost of allowing a slow build to occupy resources and wait up to 35 seconds longer. The copied vendor unit tests `connect_build_timeout_direct` and `connect_build_timeout_non_direct` pin the selected budgets; they do not exercise a complete PT handshake. Tests were compile-checked, not executed.

## Check status

`verify.py --prepare --individual`: PASS (8 patches). `verify.py --cargo-check --individual`: PASS (8 patches), including compile-only `cargo check --tests`. No tests were executed.
