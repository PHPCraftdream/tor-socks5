# tor-dirmgr: bound bridge descriptor fetch time

**Status:** prepared for review; not sent. Verification passed as documented below; tests were not executed.

## Problem observed

The pristine bridge descriptor request performs circuit launch, stream creation and response reading without a total deadline for the complete attempt. A bounded sub-operation does not bound the cumulative bridge fetch. The vendor README records the 30-second whole-attempt timeout separately from bridge-pool policy. The provenance record identifies the 0.48.0 archive baseline and source comparison scope; it does not establish timeout behavior. See [vendor README](../../../../../vendor/README.md) and [provenance](../../../../../vendor/PROVENANCE.md).

## Proposed mechanism

Wrap the complete bridge descriptor attempt in a 30-second runtime timeout and convert expiry to the existing `RequestFailed(DirTimeout)` error. This patch changes the hard-coded attempt budget from unbounded to 30 seconds; it adds no API or configuration surface and leaves bridge-pool defaults/policy unchanged.

## Compatibility and coverage

The copied vendor mock-runtime regression `bridge_download_hard_timeout` was compile-checked but not executed. The separate `bridge_download_defaults` test is not included or claimed as covered; this patch does not change the 12/5-second pool policy.

## Check status

`verify.py --prepare --individual`: PASS (8 patches). `verify.py --cargo-check --individual`: PASS (8 patches), including compile-only `cargo check --tests`. No tests were executed.
