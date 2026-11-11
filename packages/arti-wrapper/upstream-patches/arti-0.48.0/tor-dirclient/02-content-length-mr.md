# tor-dirclient: bound response bodies by Content-Length

**Status:** prepared for review; not sent. Verification passed as documented below; tests were not executed.

## Summary

The client currently reads a successful response body until decoder EOF, without using the HTTP `Content-Length` value (the pristine source has a commented-out parsing sketch). When a valid length is present, this patch bounds the on-wire body to that many bytes. It also tracks the remaining wire bytes across the decoder and reports early EOF as `RequestError::TruncatedBody`, including the number of missing bytes. Malformed lengths and conflicting duplicates are rejected. Responses without `Content-Length` retain the existing EOF-delimited behavior.

The vendor README describes the change as bounding `Content-Length` and no longer trusting a truncated directory body. The regression assertions cover declared-length completion on an open connection, exclusion of bytes beyond the declared body, and early EOF producing `TruncatedBody`; the behavior was not tested at runtime. The existing test name `test_content_length_undercount_truncates_silently` is a test name, not runtime evidence.

## Scope and compatibility

- `Content-Length` is parsed as an unsigned wire length; equal duplicate values are accepted, inconsistent duplicates and invalid values are rejected.
- Adds the public, non-exhaustive `RequestError::TruncatedBody(u64)` variant and maps it to `TorProtocolViolation`; anonymous requests classify it as suspicious. Downstream exhaustive matches over this `#[non_exhaustive]` enum already require a fallback, but consumers matching known variants may still need to account for this new error value.
- Because this is a public error-enum addition, upstream commit/semver and release-note policy is **to be clarified before submission**. No manifest dependency or semver file is changed here.
- Includes the existing vendored Content-Length regression cases: `content_length_completes_on_open_connection`, `content_length_early_eof`, `test_content_length_undercount_truncates_silently`, and `content_length_is_strict`.

## Test plan

- Tests were not executed. `verify.py --cargo-check --individual` passed for all eight patches, compiling test targets only; no Cargo build/test command was run.
- This patch is ordered after `01-idle-body.patch` because both patches share the added `src/local_test.rs` test module; apply `01-idle-body.patch` first. Its test support also relies on the shared `test::run_download_test` helper made `pub(super)` here.
- Execute the listed regression tests in the project's CI/testing workflow after review.

## Background

The local 0.48.0 behavior and patch inventory are documented in the [vendor README](../../../../../vendor/README.md#tor-dirclient-0480). The base archive identity and provenance limitations are recorded in [vendor provenance](../../../../../vendor/PROVENANCE.md#baseline-evidence). This draft is prepared, not sent. It does not assert legal authorship, licensing clearance, or approval.

## Final verification status

`verify.py --prepare --individual`: PASS (8 patches). `verify.py --cargo-check --individual`: PASS (8 patches), including compile-only `cargo check --tests`. No tests were executed.
