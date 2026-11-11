# tor-guardmgr: retry descriptorless Data guard selections

**Status:** prepared for review; not sent. Verification passed as documented below; tests were not executed.

## Observed source behavior

In 0.48.0, `GuardMgrInner::select_guard_with_expand` retried its selection after refreshing the active guard set only when the refresh extended the sample. However, refresh also recomputes a bridge guard's `dir_info_missing`/Data eligibility, so the selection can become valid without sample growth. In `select_guard_once`, a selected bridge lacking a live circuit target for `Data` usage was classified as `Internal`, even though bridge descriptor acquisition is asynchronous. This turns a transient descriptor state into a non-retriable selection failure. The vendor README summarizes the carried descriptorless-Data retry change. The provenance record identifies the 0.48.0 archive baseline and differing source paths; it does not establish these behavior claims.

## Proposed mechanism

Retry once after the refreshed guard-set state regardless of whether the sample grew. When a `Data` bridge selection still lacks a circuit target, return the existing `PickGuardError::AllGuardsDown` variant with no retry deadline rather than `Internal`; this uses existing retry classification without adding a signal, event, or public API.

The existing `bridge_descriptorless_guard_is_retriable_not_internal` regression test is included. The `Debug` derive for `GuardUsable` is supplied by this patch; the test-only state-injection helpers (`GuardSet::guards_for_test`, `GuardSet::set_all_guards_dir_info_missing_for_test`, and `Guard::set_dir_info_missing_for_test`) are supplied by prerequisite recovery patch 01 and intentionally are not duplicated here.

## Compatibility and coverage

No public API or default/configuration changes. The behavior change is limited to bridge `Data` selections with a missing descriptor/circuit target and to retrying after a refreshed guard set. The included regression asserts `AllGuardsDown` rather than `Internal`; its stale-state setup does **not** directly test refresh retry when sample size is unchanged. Tests were compile-checked, not executed.

This patch and its regression test are constructed against the source state after patch 01. The production changes are semantically independent, but this test requires patch 01's shared test-only state-injection helpers.

## Final verification status

`verify.py --prepare --individual`: PASS (8 patches). `verify.py --cargo-check --individual`: PASS (8 patches), including compile-only `cargo check --tests`. No tests were executed.

## Ordering and dependency

Apply `01-bridge-recovery.patch` first, then this patch. The production changes are semantically independent, but this test requires patch 01's shared test-only state-injection helpers. Applying patch 02 directly to pristine is therefore not supported; this exact test-support dependency is the sole ordering edge.
