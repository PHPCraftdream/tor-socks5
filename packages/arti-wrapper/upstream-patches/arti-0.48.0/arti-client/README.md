# arti-client 0.48.0: blocked upstream-patch item

**Status:** needs design; no patch emitted; not sent — **подготовлено, не отправлено**. The mechanical patch and compile checks passed for the eight packaged patches; item 8 has no patch and was not checked.

The requested eighth item is bounded exit-stream retry alone; the current vendor implementation couples it to the explicitly excluded optional `initial_connect_timeout` budget. It is intentionally not represented by an `.patch`: the local vendor implementation cannot be copied verbatim onto the pristine 0.48.0 archive.

## Concrete compatibility blocker

In the vendor-only [`stream_retry.rs`](../../../../../vendor/arti-client/src/client/stream_retry.rs#L28-L33), `snapshot_exit_stream_timeouts` reads both `config.initial_connect_timeout` and `config.connect_timeout` from `StreamTimeoutConfig`. The vendor caller in [`client.rs`](../../../../../vendor/arti-client/src/client.rs#L1694-L1697) snapshots those budgets and passes them to the retry helper at [`client.rs`](../../../../../vendor/arti-client/src/client.rs#L1732-L1735). The pristine `arti-client-0.48.0` archive has no `initial_connect_timeout` field (and no corresponding vendor-added `stream_retry.rs`). Removing the field reference is not enough: it requires a new helper interface and corresponding call-site/default wiring. No such implementation is assumed or fabricated here; it needs a separately designed and author-approved change against the pristine API before a patch can be prepared.

The vendor helper contains tests named `stream_retry_retires_the_failed_circuit_before_opening_again`, `stream_retry_is_bounded_and_retires_the_last_failed_circuit`, `stream_retry_leaves_permanent_errors_alone`, `stream_retry_default_budget_bounds_both_attempts`, `request_timeout_snapshot_survives_reconfigure_during_first_attempt`, `stream_retry_initial_timeout_does_not_retire_circuit`, and `stream_retry_caps_fast_timer_at_shorter_ordinary_budget`. These are observations of tests in the local vendor-only file, not tests of the pristine crate or of an upstream patch. With no patch emitted, there is no extracted-pristine patch test to run; no tests were run here. Revisit this item only after the implementation is designed and approved, then add the appropriate test coverage and CI validation.

## Verification status

The eight packaged patches passed `verify.py --prepare --individual` and `verify.py --cargo-check --individual`; the latter compiled test targets only. Item 8 has no patch and is not included in those checks. No tests were executed.
