# vendor/ — locally-patched forks of upstream arti crates

This directory holds **full source copies** of upstream crates from the
[arti](https://gitlab.torproject.org/tpo/core/arti) workspace, wired into the
build via `[patch.crates-io]` in the workspace `Cargo.toml`. The build is
self-contained: none of our fixes need to be accepted upstream.

**Base line: Arti 0.47.0 (arti 2.7.0), synced 2026-10-13.**
Workspace MSRV is 1.92 (up from 1.89 on the 0.43 line).

Vendored crates (7): `arti-client`, `tor-chanmgr`, `tor-circmgr`,
`tor-dirclient`, `tor-dirmgr`, `tor-guardmgr` — all at **0.47.0** — and
`saturating-time` at **0.5.0**.

`ptrs-gesher` (the obfs4/webtunnel PT client and `bridge-line` parser) is
**not** vendored here. Its crates.io release does not yet target `tor-*`
0.47, so the root `Cargo.toml` currently carries a **TEMPORARY**
`[patch.crates-io]` section pointing the `ptrs-gesher-*` crates at a sibling
ptrs-gesher checkout. Switch these back to crates.io as soon as a release
against `tor-*` 0.47 is published.

### Onion-service server (not vendored)

The `onion-service-service` feature is enabled via `arti-wrapper/onion-service`.
`tor-hsservice`, `tor-keymgr` and `tor-hsrproxy` are **not** vendored: they
come from crates.io 0.47.x. If a fork is ever needed (e.g. SVH hop
shortening), it must be added as a new full vendor copy plus a
`[patch.crates-io]` entry here.

## Why each crate is vendored

### `saturating-time` (0.5.0)

The root-cause fix for the bridge outage: `saturating_add`/`saturating_sub`
eagerly forced a `LazyLock` min/max binary search that never terminates on
Windows `SystemTime`, so bridge descriptors were never parsed and no circuit
could be built. We ship a lazy `unwrap_or_else` limit and regression tests (one with a
test-only termination watchdog). A direct limit query or genuine overflow still
runs the unbounded `find_limit` search on Windows. Upstream's !4414 merely imported
the crate into arti without the lazy fix; crates.io 0.5.0 still has the eager
`unwrap_or`.

### `tor-dirclient` (0.47.0)

A 90-second **idle** (inter-read) body timeout instead of the 10-second total
timeout, so healthy-but-slow obfs4/webtunnel consensus downloads survive.
Upstream 0.47 adds a new 10-second *header-read* timeout
(#2688 / TROVE-2026-046), which is a different mechanism and is kept as-is —
it covers headers only. Also carried: a `Content-Length` body bound
(`RemainingTracker` + `TruncatedBody`), so a truncated directory body is no
longer trusted.

### `tor-dirmgr` (0.47.0)

Four fixes: a hard 30-second total timeout on the whole bridge-descriptor
fetch (0.47 still has no overall fetch timeout); parallelism 12 / initial
retry 5 s defaults for the bridge pool (small-pool policy, not a security
fix); `SharedMutArc` poison recovery instead of bricking the netdir on any
panic inside `mutate()` (recover-with-possible-staleness); and
`SQLITE_BUSY`/`SQLITE_LOCKED` reclassified from fatal `Internal` to
`CacheAccessFailed` — an honest classification of transient AV/indexer/sync
file locks on Windows.

### `tor-chanmgr` (0.47.0)

`ChanMgr::terminate_all_channels()` lets the app force-close half-open
channels after sleep/resume or a network change without a cold `TorClient`
rebuild. Also: the non-direct (PT) channel-build total timeout is raised
10 s → 45 s — a full pluggable-transport handshake budget.

### `tor-guardmgr` (0.47.0)

A guard-readiness signal pair (`any_guard_usable_for_traffic()` +
`usable_guard_events()`) distinguishes "dir bootstrapped" from "dir
bootstrapped but every guard descriptor-naked"; paired with `arti-client`.
Bridge-recovery corrections: descriptor eligibility considers only
configured, security-enabled candidates; a reintroduced bridge may fetch a
descriptor while unlisted; retries touch only explicitly re-enabled bridges;
descriptor requests widen adaptively while no guard is usable. A
descriptorless `Data` guard is retried after a guardset refresh, with
`AllGuardsDown` instead of `Internal` on residual failure.

`reset_disabled_guards()` survives, but its **role changed in 0.47**:
upstream !4426 raised the pathbias-lite disable threshold to an effectively
unreachable value, so new automatic disables practically never happen.
`disabled` is still a persisted field, so the hook is retained primarily as a
**manual migration/recovery handle for old persisted state** (0.43-era state
is not auto-cleared). Automatic recovery never calls it; security-disabled
bridges stay excluded from recovery.

### `arti-client` (0.47.0)

`ready_for_traffic()` now ANDs in the guards-usable stream (default `false`
until the first guard-sample refresh) — upstream 0.47's `BootstrapSetting`
still ignores guards. Plus: a `FatalProtocolErrorHandler` hook for
observability of arti's intentional fast-zombie `process::exit(1)` (the exit
itself is not weakened); a `note_external_guard_failure()` passthrough with
re-exports of `tor_guardmgr::ExternalActivity` and `tor_linkspec::HasRelayIds`;
`reset_disabled_guards()` / `guard_is_disabled()` passthroughs; a bounded
exit-stream retry of `begin_stream` (0.47 still does a single attempt); and
an optional `initial_connect_timeout` config field (Android sets 4 s for a
fast-first budget).

### `tor-circmgr` (0.47.0)

Opt-in bandwidth floor for middle/exit relay selection; client HS stems honor
`PathConfig::circuit_hops` in Disabled mode; ordinary exit paths ignore it
(always three hops: exits refuse a two-hop circuit that starts at a bridge);
service stems honor `PathConfig::service_circuit_hops` (2..=4, default 4 =
stock; stem = value − 1, a 1-hop stem is guard-only) in Disabled mode; vanguard
modes retain upstream behavior.

## Patch table

One row per patch group. Marker names are the identifiers in the
`tor-socks5 local patch: <name>` comments.

| Patch | Crate | File(s) | Purpose | Status in 0.47 |
|---|---|---|---|---|
| `lazy_add_limit` / `lazy_sub_limit` | saturating-time 0.5.0 | src/lib.rs | lazy limits instead of eager `unwrap_or` (Windows `SystemTime` hang) | carried (not upstream; 0.5.0 still eager) |
| watchdog + test hygiene | saturating-time | src/lib.rs, src/internal.rs | test-only termination watchdog around `find_limit` (the search itself stays unbounded); doctests off; 3 limit-forcing tests ignored | carried |
| `body_idle_timeout` / `reset_body_idle` | tor-dirclient | src/lib.rs | 90 s idle body timeout for slow PT consensus downloads | carried (upstream's 10 s header timeout is a different mechanism, kept) |
| `RemainingTracker` / `TruncatedBody` | tor-dirclient | src/lib.rs, src/err.rs, src/local_test.rs | enforce `Content-Length`; distrust truncated bodies | carried |
| descriptor-fetch total timeout | tor-dirmgr | src/bridgedesc.rs | hard 30 s total on bridge-descriptor fetch, `RequestFailed(DirTimeout)` | carried (0.47 has no overall fetch timeout) |
| pool parallelism/retry defaults | tor-dirmgr | src/bridgedesc.rs | parallelism 12, initial retry 5 s | carried (0.47 keeps 4 / 30 s; small-pool policy) |
| `SharedMutArc` poison recovery | tor-dirmgr | src/shared_ref.rs | `unwrap_or_else(into_inner)` instead of panic on `mutate()` | carried (0.47 still bricks the netdir) |
| sqlite lock classification | tor-dirmgr | src/err.rs | `SQLITE_BUSY`/`SQLITE_LOCKED` → `CacheAccessFailed`, not fatal `Internal` | carried |
| `terminate_all_channels` | tor-chanmgr | src/lib.rs, src/mgr.rs, src/mgr/state.rs, src/builder.rs | force-close half-open channels after sleep/resume / network change | carried |
| `connect_build_timeout` | tor-chanmgr | src/builder.rs | non-direct channel-build total 10 s → 45 s (PT handshake budget) | carried |
| guard-readiness signal | tor-guardmgr | src/sample.rs, src/events.rs, src/lib.rs | `any_guard_usable_for_traffic()` + `usable_guard_events()` watch stream | carried (0.47 `BootstrapSetting` ignores guards) |
| bridge-recovery corrections | tor-guardmgr | src/sample.rs, src/lib.rs | eligibility, reintroduction, retry and adaptive-widening semantics | carried |
| `reset_disabled_guards` / `guard_is_disabled` | tor-guardmgr | src/guard.rs, src/sample.rs, src/lib.rs | manual recovery hook for persisted `disabled` state | carried (role changed: manual migration handle; !4426 made new automatic disables practically impossible) |
| descriptorless `Data` retriable | tor-guardmgr | src/lib.rs, src/pending.rs | retry after guardset refresh; `AllGuardsDown` not `Internal` | carried |
| guards-usable readiness | arti-client | src/status.rs, src/client.rs | `ready_for_traffic()` ANDs the guards-usable stream | carried |
| `FatalProtocolErrorHandler` | arti-client | src/builder.rs, src/client.rs, src/lib.rs | observability hook for fast-zombie `process::exit(1)`; exit not weakened | carried |
| external-guard-failure passthrough | arti-client | src/client.rs, src/lib.rs | `note_external_guard_failure()` + re-exports; `reset_disabled_guards`/`guard_is_disabled` passthroughs | carried |
| exit-stream retry | arti-client | src/client.rs, src/client/stream_retry.rs | one bounded `begin_stream` retry, narrow retryable set, snapshot budgets | carried (0.47 Exit branch is single-attempt) |
| `initial_connect_timeout` | arti-client | src/config.rs; packages/android-ffi | optional fast-first budget; Android sets 4 s; inactive when `None` | carried |
| `min_bandwidth_percentile` | tor-circmgr | src/config.rs, src/path.rs, src/path/exitpath.rs, src/path/hspath.rs | opt-in bandwidth floor for middle/exit; default 0 = stock | carried |
| `hs_circuit_hops` | tor-circmgr | src/hspool.rs, src/hspool/pool.rs, src/path.rs, src/path/hspath.rs | role-aware client lengths, exact-length pool targets, epoch-safe retirement | local |
| service stem length | tor-circmgr | src/config.rs, src/hspool.rs, src/hspool/pool.rs, src/path.rs, src/path/hspath.rs | `service_circuit_hops` for Svc stems (Disabled mode), guard-only 1-hop path, pool retargeting on change | local |

**None of the functional patches above were accepted upstream in 0.47.**

## Cross-cutting notes

* All seven forks set `publish = false`.
* `arti-client` gains the tokio `test-util` dev feature.
* New local files: `arti-client/src/client/stream_retry.rs` and
  `tor-dirclient/src/local_test.rs` (patch regression tests).

## Verifying a patch is present

```sh
# every local change is marked
grep -rn "tor-socks5 local patch" vendor/
# a specific patch
grep -rn "tor-socks5 local patch: body_idle_timeout" vendor/tor-dirclient/
```

## Doing the next sync

1. Download the clean crates.io releases of the new arti line.
2. For each crate, **start from the clean sources** — never keep the old
   fork's tree.
3. Re-apply each patch by locating its marker name in the old fork and
   re-implementing it at the new location. **Do not apply whole old files
   over new ones**: 0.47 reworked areas such as the dirclient header reader,
   and whole-file moves silently drop upstream security fixes.
4. Keep `publish = false` and the `tor-socks5 local patch: <name>` marker
   comments.
5. Build the workspace and run the test suites.
6. Drop a patch only after verifying the fix landed upstream in the **actual
   sources**, not just the changelog.
7. Update the patch table above and `CHANGELOG.md`.
