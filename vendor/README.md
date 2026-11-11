# vendor/ — locally-patched forks of upstream arti crates

This directory holds **full source copies** of upstream crates from the
[arti](https://gitlab.torproject.org/tpo/core/arti) workspace. The root
`Cargo.toml` applies `[patch.crates-io]` overrides to the eight crates under
`vendor/`; the build does not depend on these fixes being accepted upstream.

**Base line: Arti 0.48.0 (arti 2.8.0), synced 2026-11-10.**
Workspace MSRV is 1.92 (up from 1.89 on the 0.43 line).

## Using these patches in your own project

Add this to the **final binary's or workspace's root** `Cargo.toml`:

```toml
[patch.crates-io]
arti-client = { git = "https://github.com/PHPCraftdream/tor-socks5", tag = "arti-patches-0.48.0" }
tor-chanmgr = { git = "https://github.com/PHPCraftdream/tor-socks5", tag = "arti-patches-0.48.0" }
tor-circmgr = { git = "https://github.com/PHPCraftdream/tor-socks5", tag = "arti-patches-0.48.0" }
tor-dirclient = { git = "https://github.com/PHPCraftdream/tor-socks5", tag = "arti-patches-0.48.0" }
tor-dirmgr = { git = "https://github.com/PHPCraftdream/tor-socks5", tag = "arti-patches-0.48.0" }
tor-guardmgr = { git = "https://github.com/PHPCraftdream/tor-socks5", tag = "arti-patches-0.48.0" }
tor-ptmgr = { git = "https://github.com/PHPCraftdream/tor-socks5", tag = "arti-patches-0.48.0" }
saturating-time = { git = "https://github.com/PHPCraftdream/tor-socks5", tag = "arti-patches-0.48.0" }
```

Tags follow `arti-patches-<Arti version>`, with one tag per Arti line. This is
Arti 0.48.x: seven crates are 0.48.0 and `saturating-time` is 0.6.0; the MSRV
is Rust 1.92. These patches are not renamed crates.io releases: the crates must
be patched together to keep cross-crate types consistent. Exact dependency
versions must match; future compatible releases are not guaranteed to resolve
to this patch set.

`[patch]` belongs in the final binary/workspace root, is not inherited by
libraries, and selects the source only: it does not enable features, so
`pt-client` and the other `arti-client` features stay as you declare them on
your own dependency. Keep the consumer's `Cargo.lock` (which records the
resolved git SHA), inspect the result with `cargo tree -i <crate>`, and do not
run `cargo update` blindly.

A crate depending on these git sources cannot be published to crates.io as-is.
Root-only patches are omitted or ignored when publishing a library, so its end
users must add the patches themselves; a published library cannot promise its
consumers the patched API.

Default changes, in brief:

* **Correctness/recovery fixes:** reject truncated `Content-Length` bodies;
  bound bridge descriptor fetches to 30 s total; correct bridge recovery and
  guard-readiness handling; retry exit-stream creation once within a bound;
  classify SQLite busy locks as transient; redact proxy warning credentials.
  Old persisted security-disabled guards still require a manual reset.
* **Local policy:** directory body timeout is 90 s idle rather than the upstream
  10 s total, with the 10 s header timeout retained; PT channel build is 45 s
  rather than 10 s; bridge pool defaults are 12 parallel / 5 s retry rather
  than 4 / 30 s. Poison recovery may expose stale state.
* Added APIs must be called to take effect: PT shutdown receipt, channel
  termination, manual guard reset, and fatal-exit observability. Fatal protocol
  errors still call `process::exit(1)`; that behavior remains unchanged.
  Defaults stay stock: `min_bandwidth_percentile = 0`, `initial_connect_timeout = None`
  (Android's 4 s is not the consumer default), client circuit hops 3 and
  service circuit hops 4. Hop shortening applies only in Disabled vanguard
  mode and trades anonymity for shorter paths; ordinary exits remain 3 hops,
  and SvcHsDir stems have a 2-hop minimum.

See [Why each crate is vendored](#why-each-crate-is-vendored) and the
[patch table](#patch-table) for details. Upstream `saturating-time` 0.6.0
accepted the lazy limits and termination check; its remaining differences are
marker/test changes. The other local functional patches were not accepted in
Arti 0.48.

The crates' original `MIT OR Apache-2.0` offers and source notices are
preserved, and prominent change notices were added. The standard Apache-2.0
license text is delivered in each crate; this is not represented as upstream
license retrieval. The pinned upstream GitLab
retrievals for `LICENSE-MIT` and `LICENSE-APACHE` returned HTTP 403; no
standalone MIT text was delivered. Whether any particular §4(c) source notice
applies is not established, and §4(b) notice completeness is not claimed.
Differences from upstream alone do not establish patch authorship or licensing.
See [PROVENANCE.md](PROVENANCE.md) for scope and evidence; this is not legal
approval or global clearance. No compatibility, support, or security guarantees
are made. Report issues at
[the patch repository](https://github.com/PHPCraftdream/tor-socks5/issues).

Vendored crates (8): `arti-client`, `tor-chanmgr`, `tor-circmgr`,
`tor-dirclient`, `tor-dirmgr`, `tor-guardmgr`, `tor-ptmgr` — all at **0.48.0** — and
`saturating-time` at **0.6.0**.

`ptrs-gesher` (the obfs4/webtunnel PT client and `bridge-line` parser) is
not vendored here. The root `Cargo.toml` declares its crates.io packages
(`ptrs-gesher-bridge-line` and `ptrs-gesher-lyrebird`) as workspace
dependencies; there is no sibling-checkout `[patch.crates-io]` override.

See [PROVENANCE.md](PROVENANCE.md) for the eight published README license
offers, byte-identical standard Apache-2.0 license copies, the bounded source
basis, the unresolved upstream GitLab 403 and §4(c) applicability, and the
record of nine files now carrying prominent §4(b) change-notice comments. This
does not claim legal approval or global clearance.

### Onion-service server (not vendored)

The app's `onion-service` feature enables `arti-wrapper/onion-service`
(which enables `arti-client/onion-service-service`) and optional
`tor-hsservice`/`tor-keymgr` dependencies. `tor-hsservice`, `tor-keymgr`,
`tor-hscrypto`, `tor-llcrypto`, `fs-mistrust`, `safelog`, `tor-cell`,
`tor-proto`, and `tor-hsrproxy` are not vendored. SVH hop shortening is
implemented in the vendored `tor-circmgr`; `tor-hsrproxy` is not a direct
application dependency. A new fork, if needed, must be added under `vendor/`
and patched in the root `Cargo.toml`.

## Why each crate is vendored

### `tor-ptmgr` (0.48.0)

The local manager exposes an awaited PT shutdown receipt, retains unfinished
child cleanup across cancellation, and rejects new launches after shutdown.
The paired `arti-client` shutdown method closes channels and awaits that receipt;
application owners retain their tunnels until shutdown succeeds.

The source baseline is the crates.io `tor-ptmgr` 0.48.0 archive, SHA-256
`e5a85e68659fc0627daa90cb7c1993461801ace009fc22aec230a62cdef27747`.
The same-version patch is derived from the existing PT owner implementation;
it does not add another Tor topology or transport. Remove the override only
when upstream provides the equivalent shutdown contract. PT process tests are
not proof of a complete pre/Tor/post application exchange.

### `saturating-time` (0.6.0)

The original root-cause fix for the bridge outage: `saturating_add`/
`saturating_sub` eagerly forced a `LazyLock` min/max binary search that never
terminates on Windows `SystemTime`, so bridge descriptors were never parsed and
no circuit could be built. **Upstream 0.6.0 adopted both halves of the fix**:
the lazy `unwrap_or_else` limits, and a termination check of the limit search
(a step that returns the unchanged value counts as a miss, working around
rust-lang/rust#149995). What the override still carries is small: marker
comments, the `#[ignore]` on the three tests that force a `SystemTime` limit
search, and the `saturating_add_sub_does_not_hang` regression test with its
termination watchdog. It is a removal candidate once the upstream limit search
has been verified on Windows CI.

### `tor-dirclient` (0.48.0)

A 90-second **idle** (inter-read) body timeout instead of the 10-second total
timeout, so healthy-but-slow obfs4/webtunnel consensus downloads survive.
Upstream 0.47 adds a new 10-second *header-read* timeout
(#2688 / TROVE-2026-046), which is a different mechanism and is kept as-is —
it covers headers only. Also carried: a `Content-Length` body bound
(`RemainingTracker` + `TruncatedBody`), so a truncated directory body is no
longer trusted.

### `tor-dirmgr` (0.48.0)

Four fixes: a hard 30-second total timeout on the whole bridge-descriptor
fetch (0.48 still has no overall fetch timeout); parallelism 12 / initial
retry 5 s defaults for the bridge pool (small-pool policy, not a security
fix); `SharedMutArc` poison recovery instead of bricking the netdir on any
panic inside `mutate()` (recover-with-possible-staleness); and
`SQLITE_BUSY`/`SQLITE_LOCKED` reclassified from fatal `Internal` to
`CacheAccessFailed` — an honest classification of transient AV/indexer/sync
file locks on Windows.

### `tor-chanmgr` (0.48.0)

`ChanMgr::terminate_all_channels()` lets the app force-close half-open
channels after sleep/resume or a network change without a cold `TorClient`
rebuild. Also: the non-direct (PT) channel-build total timeout is raised
10 s → 45 s — a full pluggable-transport handshake budget.

Предупреждение о нелокальном прокси записывает схему и адрес без учётных
данных; формат `Display` и сериализация `ProxyProtocol` не изменены.

### `tor-guardmgr` (0.48.0)

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

### `arti-client` (0.48.0)

`ready_for_traffic()` now ANDs in the guards-usable stream (default `false`
until the first guard-sample refresh) — upstream 0.48's `BootstrapSetting`
still ignores guards. Plus: a `FatalProtocolErrorHandler` hook for
observability of arti's intentional fast-zombie `process::exit(1)` (the exit
itself is not weakened); a `note_external_guard_failure()` passthrough with
re-exports of `tor_guardmgr::ExternalActivity` and `tor_linkspec::HasRelayIds`;
`reset_disabled_guards()` / `guard_is_disabled()` passthroughs; a bounded
exit-stream retry of `begin_stream` (0.48 still does a single attempt); and
an optional `initial_connect_timeout` config field (Android sets 4 s for a
fast-first budget).

### `tor-circmgr` (0.48.0)

Opt-in bandwidth floor for middle/exit relay selection; client HS stems honor
`PathConfig::circuit_hops` in Disabled mode; ordinary exit paths ignore it
(always three hops: exits refuse a two-hop circuit that starts at a bridge);
service stems honor `PathConfig::service_circuit_hops` (2..=4, default 4 =
stock; stem = value − 1, a 1-hop stem is guard-only) in Disabled mode; vanguard
modes retain upstream behavior. SvcHsDir stems never drop below 2 hops: C-tor
HsDirs reject descriptor posts whose previous hop is a client (a bridge).

## Patch table

One row per patch group. Marker names are the identifiers in the
`tor-socks5 local patch: <name>` comments.

| Patch | Crate | File(s) | Purpose | Status in 0.48 |
|---|---|---|---|---|
| `lazy_add_limit` / `lazy_sub_limit` | saturating-time 0.6.0 | src/lib.rs | lazy limits instead of eager `unwrap_or` (Windows `SystemTime` hang) | upstream in 0.6.0; only the marker comments remain |
| watchdog + test hygiene | saturating-time | src/lib.rs, src/internal.rs | test-only termination watchdog around `find_limit`; doctests off; 3 limit-forcing tests ignored (upstream 0.6.0 now also terminates the search itself) | carried |
| `body_idle_timeout` / `reset_body_idle` | tor-dirclient | src/lib.rs | 90 s idle body timeout for slow PT consensus downloads | carried (upstream's 10 s header timeout is a different mechanism, kept) |
| `RemainingTracker` / `TruncatedBody` | tor-dirclient | src/lib.rs, src/err.rs, src/local_test.rs | enforce `Content-Length`; distrust truncated bodies | carried |
| descriptor-fetch total timeout | tor-dirmgr | src/bridgedesc.rs | hard 30 s total on bridge-descriptor fetch, `RequestFailed(DirTimeout)` | carried (0.48 has no overall fetch timeout) |
| pool parallelism/retry defaults | tor-dirmgr | src/bridgedesc.rs | parallelism 12, initial retry 5 s | carried (0.48 keeps 4 / 30 s; small-pool policy) |
| `SharedMutArc` poison recovery | tor-dirmgr | src/shared_ref.rs | `unwrap_or_else(into_inner)` instead of panic on `mutate()` | carried (0.48 still bricks the netdir) |
| sqlite lock classification | tor-dirmgr | src/err.rs | `SQLITE_BUSY`/`SQLITE_LOCKED` → `CacheAccessFailed`, not fatal `Internal` | carried |
| `terminate_all_channels` | tor-chanmgr | src/lib.rs, src/mgr.rs, src/mgr/state.rs, src/builder.rs | force-close half-open channels after sleep/resume / network change | carried |
| `connect_build_timeout` | tor-chanmgr | src/builder.rs | non-direct channel-build total 10 s → 45 s (PT handshake budget) | carried |
| `proxy_warning_redaction` | tor-chanmgr | src/lib.rs | предупреждение о нелокальном прокси без учётных данных | локальный |
| guard-readiness signal | tor-guardmgr | src/sample.rs, src/events.rs, src/lib.rs | `any_guard_usable_for_traffic()` + `usable_guard_events()` watch stream | carried (0.48 `BootstrapSetting` ignores guards) |
| bridge-recovery corrections | tor-guardmgr | src/sample.rs, src/lib.rs | eligibility, reintroduction, retry and adaptive-widening semantics | carried |
| `reset_disabled_guards` / `guard_is_disabled` | tor-guardmgr | src/guard.rs, src/sample.rs, src/lib.rs | manual recovery hook for persisted `disabled` state | carried (role changed: manual migration handle; !4426 made new automatic disables practically impossible) |
| descriptorless `Data` retriable | tor-guardmgr | src/lib.rs, src/pending.rs | retry after guardset refresh; `AllGuardsDown` not `Internal` | carried |
| guards-usable readiness | arti-client | src/status.rs, src/client.rs | `ready_for_traffic()` ANDs the guards-usable stream | carried |
| `FatalProtocolErrorHandler` | arti-client | src/builder.rs, src/client.rs, src/lib.rs | observability hook for fast-zombie `process::exit(1)`; exit not weakened | carried |
| external-guard-failure passthrough | arti-client | src/client.rs, src/lib.rs | `note_external_guard_failure()` + re-exports; `reset_disabled_guards`/`guard_is_disabled` passthroughs | carried |
| exit-stream retry | arti-client | src/client.rs, src/client/stream_retry.rs | one bounded `begin_stream` retry, narrow retryable set, snapshot budgets | carried (0.48 Exit branch is single-attempt) |
| `initial_connect_timeout` | arti-client | src/config.rs; packages/android-ffi | optional fast-first budget; Android sets 4 s; inactive when `None` | carried |
| `min_bandwidth_percentile` | tor-circmgr | src/config.rs, src/path.rs, src/path/exitpath.rs, src/path/hspath.rs | opt-in bandwidth floor for middle/exit; default 0 = stock | carried |
| `hs_circuit_hops` | tor-circmgr | src/config.rs, src/hspool.rs, src/hspool/pool.rs, src/path.rs, src/path/exitpath.rs, src/path/hspath.rs | role-aware client lengths, exact-length pool targets, epoch-safe retirement | local |
| service stem length | tor-circmgr | src/config.rs, src/hspool.rs, src/hspool/pool.rs, src/path.rs, src/path/exitpath.rs, src/path/hspath.rs | `service_circuit_hops` for Svc stems (Disabled mode), guard-only 1-hop path, pool retargeting on change | local |
| Pareto timeout normalization | tor-circmgr | src/timeouts/pareto.rs | normalize completed short-path observations to canonical three-hop work so timeout estimates remain comparable | local |

**None of the functional patches above were accepted upstream in 0.48**, except the
lazy `saturating_add`/`saturating_sub` limits, which `saturating-time` 0.6.0 adopted.

## Cross-cutting notes

* All seven forks set `publish = false`.
* `arti-client` gains the tokio `test-util` dev feature.
* The vendored source also carries cross-cutting lint allowances where upstream
  code would otherwise fail the workspace lint configuration; these are build
  compatibility adjustments, not functional patches.
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
5. Build the workspace and run the test suites. The 0.48.0 sync started from
   per-file three-way merges (`git merge-file`; base: the pristine 0.47.0
   archive whose SHA-256 matched PROVENANCE.md, ours: `vendor/`, theirs: the new
   archive) and then reviewed every file that changed on both sides; only the
   manifests' `version` lines conflicted.
6. Drop a patch only after verifying the fix landed upstream in the **actual
   sources**, not just the changelog.
7. Update the patch table above and `CHANGELOG.md`.
