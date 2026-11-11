# Arti 0.48.0 upstream-patch preparation bundle

**Status:** prepared for review, not sent (**подготовлено, не отправлено**). This bundle has no upstream MR URLs. The eight patch artifacts are ready for review based on compile validation only; `arti-client` item 8 remains blocked pending design. Upstream commit-identity and semver/release-note rules are **to be clarified before submission**.

## Bundle contents and review status

The bundle root contains exactly seven entries: this README, `verify.py`, and the five crate directories (`arti-client/`, `tor-chanmgr/`, `tor-dirclient/`, `tor-dirmgr/`, `tor-guardmgr/`). The eight patches add 960 lines total, all validated against the corresponding vendored source files. Item 8 has no patch.

| Patch / note | Review status |
|---|---|
| [`tor-dirclient/01-idle-body.patch`](tor-dirclient/01-idle-body.patch) · [note](tor-dirclient/01-idle-body-mr.md) | Ready for review; compile validation passed. Sets a 90-second body-read idle timeout while retaining the separate header timeout. Regression tests are included but were not executed. |
| [`tor-dirclient/02-content-length.patch`](tor-dirclient/02-content-length.patch) · [note](tor-dirclient/02-content-length-mr.md) | Ready for review; compile validation passed. Bounds reads by `Content-Length` and reports premature EOF. Depends on 01 for the shared `local_test` module. Public error-enum addition: upstream commit/semver policy is **to be clarified before submission**. |
| [`tor-dirmgr/01-descriptor-timeout.patch`](tor-dirmgr/01-descriptor-timeout.patch) · [note](tor-dirmgr/01-descriptor-timeout-mr.md) | Ready for review; compile validation passed. Adds a 30-second total bridge-descriptor attempt deadline; does not change or cover bridge-pool defaults. |
| [`tor-dirmgr/02-poison-recovery.patch`](tor-dirmgr/02-poison-recovery.patch) · [note](tor-dirmgr/02-poison-recovery-mr.md) | Ready for review; compile validation passed. Recovers poisoned shared-directory locks; panic propagation and possible partial mutation remain. |
| [`tor-dirmgr/03-sqlite-locks.patch`](tor-dirmgr/03-sqlite-locks.patch) · [note](tor-dirmgr/03-sqlite-locks-mr.md) | Ready for review; compile validation passed. Classifies SQLite `DatabaseBusy`/`DatabaseLocked` as cache-access failures. |
| [`tor-chanmgr/01-pt-build-timeout.patch`](tor-chanmgr/01-pt-build-timeout.patch) · [note](tor-chanmgr/01-pt-build-timeout-mr.md) | Ready for review; compile validation passed. Sets non-direct channel-build timeout to 45 seconds (direct remains 5 seconds); budget tests do not exercise a complete PT handshake. |
| [`tor-guardmgr/01-bridge-recovery.patch`](tor-guardmgr/01-bridge-recovery.patch) · [note](tor-guardmgr/01-bridge-recovery-mr.md) | Ready for review; compile validation passed. Restricts descriptor recovery to eligible/configured bridges and retries explicitly re-enabled bridges. |
| [`tor-guardmgr/02-descriptorless-data.patch`](tor-guardmgr/02-descriptorless-data.patch) · [note](tor-guardmgr/02-descriptorless-data-mr.md) | Ready for review; compile validation passed. Makes descriptorless Data-guard selection retriable. Depends on 01 for shared test helpers; its regression does **not** directly test refresh retry without sample growth. |
| [`arti-client/README.md`](arti-client/README.md) | **Item 8: needs design.** No patch or direct test; do not count it among the eight patches. |

The production changes are independent, but two patches have test-support ordering dependencies: dirclient 01 → 02 share `local_test`; guardmgr 01 → 02 share test helpers. Six patches apply directly to pristine source; these two require their prerequisite first. The dirmgr and chanmgr patches apply individually to pristine source.

## Verification results

Observed verifier results (all commands exited 0):

- `python packages/arti-wrapper/upstream-patches/arti-0.48.0/verify.py --prepare --individual` — **PASS, 8 patches**.
- `python packages/arti-wrapper/upstream-patches/arti-0.48.0/verify.py --cargo-check --individual` — **PASS, 8 patches**; includes the same patch/archive checks plus compile-only Cargo checks.
- Five pristine archive SHA-256 hashes and all 115 extracted archive files validated. The eight patches' 960 added source lines matched vendored files.

Compile-only Cargo commands, each exited 0:

```sh
cargo check --manifest-path target/arti-pristine/combined/Cargo.toml -p tor-chanmgr --tests --jobs 2 --target-dir target/arti-pristine/cargo-target --features pt-client
cargo check --manifest-path target/arti-pristine/combined/Cargo.toml -p tor-dirclient --tests --jobs 2 --target-dir target/arti-pristine/cargo-target --features hs-client,hs-service
cargo check --manifest-path target/arti-pristine/combined/Cargo.toml -p tor-dirmgr --tests --jobs 2 --target-dir target/arti-pristine/cargo-target --features bridge-client,static
cargo check --manifest-path target/arti-pristine/combined/Cargo.toml -p tor-guardmgr --tests --jobs 2 --target-dir target/arti-pristine/cargo-target --features bridge-client,pt-client
```

These checks compile test targets; **no tests were executed**. No `cargo build` or `cargo test` was run. Cargo may emit warnings; no blanket warning-free claim is made. The verifier report and Cargo logs are under ignored `target/arti-pristine/` and are not bundle files.

## Pristine archive identity and retrieval

The expected SHA-256 values are the 0.48.0 `.crate.gz` hashes in [`vendor/PROVENANCE.md`](../../../../vendor/PROVENANCE.md). Retrieve archives from `https://static.crates.io/crates/<name>/<name>-<version>.crate`; the verifier requires archives under `target/arti-pristine/archives/` and byte-identical extracted package roots under `target/arti-pristine/base/<crate>-0.48.0/`.

| Crate | SHA-256 |
|---|---|
| `tor-dirclient` | `3a0b528c94c6df7ea4084ceedfc370266f5b004c0827258b4cd081bf5fd81852` |
| `tor-dirmgr` | `86f7ac56b491b26a6f2b73f0f16fa7a0c66b507163e0f0ed850334b86169b326` |
| `tor-chanmgr` | `6d6086ead3951f0af897d593a33e1c9ed411e8b3d97d82da971ed08838382108` |
| `tor-guardmgr` | `4a300b7ee657f837bfd7fa71c546fb3a53b291d84a7c0bf2086a53ab5de79b90` |
| `arti-client` | `5bb17a5096e30f2b2bf9f7493ff7577ac66ed7059b8e435658a2884546afe70c` |

The verifier does not download archives. [`vendor/PROVENANCE.md`](../../../../vendor/PROVENANCE.md) records bounded archive/license evidence, not global license clearance or legal approval.

## Patch format and scope

The `.patch` files are manually prepared git-format-patch-compatible mbox messages with placeholder all-zero object IDs and neutral noreply maintainer identities. Confirm actual author identity and submission authority before sending. This bundle omits adjacent vendor changes, including dirmgr bridge-pool policy, chanmgr termination/proxy-warning behavior, guardmgr readiness and persisted-disabled-guard migration/reset behavior, arti-client readiness/retry work, and circmgr policy. The arti-client omission is a blocker, not an assertion that the vendor changes were upstreamed.

## Before sending

- **Marker comments.** Six patches add 38 `// tor-socks5 local patch: <name>` provenance tags (`grep -c "tor-socks5 local patch" */*.patch`). They stay because `verify.py` proves that every added line is identical to the tested vendor source, but they are not for Arti: regenerate each patch from a clean pristine tree without the markers (for example with `git format-patch`) and re-run the compile-only checks.
- **Links.** The MR notes point at this repository's `vendor/README.md` and `vendor/PROVENANCE.md`; replace them with self-contained evidence in the text sent upstream.
- **Identity and policy.** Confirm the commit author and the upstream semver/release-note rules (see above) first.
