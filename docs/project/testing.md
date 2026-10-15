# Testing — tiered test model

The workspace runs about 1300 tests; running all of them on every push costs minutes
and turns any flaky socket test into a release blocker. Tests are therefore tiered
T0–T3: cheap structural checks always run, package-level tests run on what changed,
and the full workspace (plus the flaky-hunt contour) runs rarely. The full
specification, decisions and data live in
[`docs/plans/test-tiers.md`](../plans/test-tiers.md).

| Tier | What runs | When | Rough cost |
|---|---|---|---|
| **T0** | `cargo fmt --all -- --check`; `check-line-limit.sh`, `check-dir-entries.sh`, `check-publish-guard.sh`; packageability, MSRV, Android (CI only) | always, on every hook run and CI run | seconds |
| **T1** | T0 + tests, doctests and clippy of **affected packages and their reverse dependencies** (`scripts/testing/test-affected.sh`) | pre-push by default; PRs in CI (ubuntu + windows) | ~1 package: well under a minute after build |
| **T2** | full `cargo nextest run --workspace` (profile `ci`) + `cargo test --doc --workspace` + clippy `--workspace`, on all three OS | push to `main`, tags, `upstream-*`, `FULL=1`, any `workflow_dispatch` | minutes on CI |
| **T3** | T2 + flaky-hunt profile repeats + tests of the vendor crates that are **not** workspace members (`tor-chanmgr`, `tor-dirmgr`, `tor-dirclient`) + per-feature runs + a report | nightly schedule, see `.github/workflows/nightly.yml` | long; unattended |

## Local workflow

Enable the pre-push hook once per clone:

```bash
git config core.hooksPath .githooks
```

The hook (`.githooks/pre-push`) always runs fmt, then:

- **T1 (default)** — asks `scripts/testing/test-affected.sh` for the affected packages and runs
  clippy + tests + doctests for them only. A new ref uses `merge-base HEAD origin/main`;
  missing `origin/main`, unavailable remote SHA, shallow history or multiple remote bases
  force T2.
- **T2 (`FULL=1`)** — full workspace run. Also forced when pushing `main`,
  `upstream-*` or tags, or when the package selection fails (fail-safe: never
  push untested because a script broke).

`git push --no-verify` bypasses the hook — use it only in an emergency (e.g. a
known-broken unrelated package), and fix the cause immediately after.

Useful variables:

```bash
TEST_AFFECTED_DRY=1 git push   # print the commands instead of running them
FULL=1 git push                # force the full T2 run
```

### `--all-features` and vendored crates

Run `--all-features` for a vendored crate in its own cargo invocation, e.g.
`cargo test -p tor-circmgr --all-features` (as the nightly job does). Never
combine it with an app package (`cargo clippy -p tor-circmgr -p socks5-proxy
--all-features`): `--all-features` applies only to the listed packages, so
`tor-circmgr` gets `vanguards`/`geoip` while `arti-client` does not, and
`arti-client` fails to compile (`missing vanguard_config`, extra `country_code`
argument). This is an upstream non-additive feature combination (see the
`TODO GEOIP` note in `tor-circmgr`); `cargo check -p socks5-proxy --all-features`
on its own builds fine.

## Selecting affected packages

`scripts/testing/test-affected.sh` computes what to test:

```bash
scripts/testing/test-affected.sh --base origin/main                 # list affected packages
scripts/testing/test-affected.sh --mode args                        # print "-p a -p b ..."
scripts/testing/test-affected.sh --mode run --kind all              # test + doctests + clippy
scripts/testing/test-affected.sh --mode run --kind test             # tests only
scripts/testing/test-affected.sh --full                             # force T2
```

Selection rules:

1. Changed files = `git diff --name-only --no-renames <base>` (both sides of a rename;
   read NUL-delimited with `core.quotePath=false` so spaces/non-ASCII paths survive).
   Base = merge-base with upstream/`origin/main`/`main`, or `--base <ref>`; plus staged
   and untracked files.
2. A file inside a workspace member selects that package, then the closure over
   **reverse** dependencies (normal + dev) is added — editing `persist-lock`
   runs the tests of the eight packages that depend on it.
3. Data files read by tests are mapped explicitly: `README.md` and
   `tor-socks5.example.ktav` → `tor-socks5-config` + `socks5-proxy`;
   `docs/architecture.md` and `docs/guide/**` → `socks5-proxy`;
   `packages/proxy-config/examples/**` → `tor-socks5-config`.
4. **Always FULL (T2):** root/member `Cargo.toml` or `Cargo.lock`, `rust-toolchain*`,
   `.cargo/**`, `.config/**`, `scripts/testing/test-affected.sh`, `scripts/testing/**`, and
   **any edit under `vendor/**`** — workspace member or not. Vendored crates reach the
   workspace through registry coordinates too (e.g. `saturating-time` → `tor-netdoc` →
   `tor-circmgr`), which member-prefix mapping alone would miss; one dependency/feature
   graph means such edits can break unrelated packages.
5. `docs/**` not listed above, `.github/**`, `.githooks/**`, other `scripts/**`:
   no tests (T0 only). Empty selection prints "nothing to test" and exits 0.
- `jq` failure, empty members, or Git/cargo-metadata failure means FULL (or a non-zero
  exit translated to FULL by the hook/CI), never a silent empty plan.
- Without explicit `--base`, detached HEAD and shallow clones force FULL even if Git
  could return a merge-base. An explicit base must resolve to a local commit; otherwise
  selection is FULL with a reason.

## Pre-push hook: pushed commit vs working tree

The hook tests the **working tree**. Before running anything it reads the pushed refs
from stdin and compares each pushed `local_sha` with `git rev-parse HEAD`:

- if the pushed commit differs from the checked-out one, the push is **rejected** with a
  warning — a green run would prove nothing about what is being pushed. Switch to the
  branch first (`git switch <branch>`);
- a push updating refs at several different commits is rejected outright;
- branch deletions (null local sha) are skipped; a deletion-only push exits before fmt/tests;
- emergencies: `git push --no-verify` only.

`cargo nextest` does not run doctests — the hook, the script and CI run
`cargo test --doc` separately. To test one package by hand:

```bash
cargo nextest run -p tor-socks5-config
cargo test --doc -p tor-socks5-config
```

`saturating-time` is excluded from doctest runs: its examples call `SystemTime::max_value()`, whose limit search never terminates on Windows (`doctest = false` in its manifest, but `cargo test --doc` ignores that flag and would hang).

## CI

`.github/workflows/ci.yml` mirrors the tiers:

- **plan** — runs `scripts/testing/test-affected.sh` (against the PR base sha) and publishes
  the chosen tier and package list to the job summary; selection failure forces T2.
- **fmt / clippy / test** — T1 jobs on PRs (ubuntu + windows, affected packages only),
  T2 jobs (ubuntu + macOS + windows, `--workspace`, profile `ci`) on pushes to `main`
  and on any manual dispatch (no reliable base to diff against); doctests run as a
  separate step. The plan job also runs `scripts/testing/selftest.sh` (no cargo build).
- Test jobs upload JUnit reports as artifacts `junit-t1-<os>` / `junit-t2-<os>`.
- CI-only structural jobs: line-limit, dir-entries, publish-guard, packageability,
  MSRV 1.89, Android arm64 build.

The nightly contour (`.github/workflows/nightly.yml`) runs T3 on a schedule and, on
failure, updates a single tracking issue **Nightly tests failed** instead of opening
a new one per run; the issue is closed as recovered only when **every** job of the run
succeeded — a run with skipped jobs counts as incomplete and leaves the issue (if any)
untouched — see the workflow file for the current schedule and scope.

## Flaky tests

- A failing test is fixed where it stands; `retries` stay at 0 in the `ci` profile so
  flakes cannot be masked.
- To investigate: `cargo nextest run --profile flaky-hunt --stress-count N` (repeat
  the whole run N times) or `--stress-duration 1h`; the profile prints every test's
  output.
- Suites with real sockets or paused clocks (`tor-socks5-dns`, `tor-circmgr`,
  `tor-guardmgr`, `socks5-proxy`) run in the `sockets-and-clocks` nextest group capped
  at 4 threads in every profile.
- Typical causes here: Windows port reuse, clock pause/resume races, RST instead of
  FIN on abrupt closes.

## Convention for rush/wrush phases

Agent-driven work phases test only their own packages (`cargo nextest run -p …`);
one full T2 run (`FULL=1 git push` or the CI T2 on `main`) before merging covers the
rest.
