# tor-dirclient: replace the total body-read timeout with an idle timeout

**Status:** prepared for review; not sent. Verification passed as documented below; tests were not executed.

## Summary

`read_and_decompress` currently starts one 10-second timer before its read loop. That bounds the entire body download, so a response can time out even while each read is making progress. This patch changes that timer to a fresh 90-second idle timer for each read. The existing independent 10-second header-read timeout is unchanged.

The vendor README describes the 90-second idle timeout as allowing healthy-but-slow obfs4/webtunnel consensus downloads to survive; it does not provide independent runtime evidence for the symptom. The regression assertions cover repeated body progress spanning longer than 10 seconds while each read progresses, and the 90-second stalled-read timeout. Tests were compile-checked, not executed.

## Scope and compatibility

- Only body-read timeout behavior changes; the default idle bound is 90 seconds.
- The header timeout remains 10 seconds and remains a total timeout for header parsing.
- No public API, manifest, or dependency changes.
- The test additions are copied from the existing vendored regressions: `body_progress_resets_idle_timeout`, `body_idle_timeout`, and `stalled_headers_timeout_independently`.

## Test plan

- Tests were not executed. The verification command `--cargo-check --individual` passed for all eight patches, compiling test targets only; no Cargo build/test command was run.
- Execute the listed regression tests in the project's CI/testing workflow after review.

## Background

The local 0.48.0 behavior and patch inventory are documented in the [vendor README](../../../../../vendor/README.md#tor-dirclient-0480). The base archive identity and provenance limitations are recorded in [vendor provenance](../../../../../vendor/PROVENANCE.md#baseline-evidence). This draft is prepared, not sent. It does not assert legal authorship, licensing clearance, or approval.

## Final verification status

`verify.py --prepare --individual`: PASS (8 patches). `verify.py --cargo-check --individual`: PASS (8 patches), including compile-only `cargo check --tests`. No tests were executed.
