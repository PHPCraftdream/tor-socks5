# tor-guardmgr: recover configured bridges and request missing descriptors

**Status:** prepared for review; not sent. Verification passed as documented below; tests were not executed.

## Observed source behavior

In the 0.48.0 source, `GuardMgrInner::replace_bridge_config` changes the active bridge set, while `GuardSet::descriptors_to_request` previously requested up to `max(data_parallelism, 2)` guards only when `Guard::usable()` (which excludes unlisted guards), and had no predicate ensuring a candidate was still in the configured bridge set. A descriptor can contribute the directory information that resolves a reintroduced guard's previously learned identities; using a cached descriptor outside the active configuration can also consume the request cutoff. `Guard::disabled` is a separate persisted security exclusion. The vendor README summarizes the carried bridge-recovery changes. The provenance record identifies the 0.48.0 archive baseline and differing source paths; it does not establish these behavior claims.

## Proposed mechanism

When bridge configuration changes, mark retriable only identities newly present relative to the previous configured list; this preserves active failure history for bridges that remain configured. Descriptor selection now receives a configured-bridge predicate, excludes security-disabled, unreachable, not-ready, unconfigured, or filtered candidates, and can request beyond the usual cap when there is no usable candidate with complete directory information. Once one is available, it returns to the normal cap and preserves a usable descriptor-bearing candidate just past the cutoff if needed to avoid discarding it during request-set narrowing. Security-disabled guards remain excluded; this does not clear or reset disabled state.

The patch also carries only the private `Guard::is_disabled` and `Guard::has_complete_dir_info` predicates needed by this logic. It adds no public/readiness event or signal API.

## Compatibility and coverage

No public API or default/configuration value changes. Descriptor fetching remains behind `bridge-client`; the ordinary descriptor request cap still applies when a usable descriptor-bearing candidate exists. The included regression tests were compile-checked, not executed. Readiness-helper assertions were removed from the latter sample tests, but descriptor-request, eligibility, or guard-selection assertions remain; this patch does not directly cover the excluded readiness signal behavior.

The patch artifact is constructed from pristine `tor-guardmgr-0.48.0`; every added source line was checked for verbatim presence in its matching `vendor/tor-guardmgr/src/...` file.

## Final verification status

`verify.py --prepare --individual`: PASS (8 patches). `verify.py --cargo-check --individual`: PASS (8 patches), including compile-only `cargo check --tests`. No tests were executed.

## Ordering

Independent of `02-descriptorless-data.patch`; apply this patch directly to pristine `tor-guardmgr-0.48.0`.
