# vendor/ — locally-maintained forks of upstream crates

These are **full source copies** of upstream crates, with local fixes applied,
committed into this repository and wired in via `[patch.crates-io]` in the
workspace `Cargo.toml`.

Why they live here: the build must be self-contained and must NOT depend on
our fixes being accepted upstream. Everything needed to build is in git.

> Note: the `ptrs-gesher-*` crates are **not** vendored here — they are our own
> project, consumed from the sibling `../ptrs-gesher` checkout via
> `[patch.crates-io]`. Only third-party / upstream crates we had to fix are
> vendored in this directory.

## What's here and why

### `saturating-time` (0.3.0) — the root-cause fix
`saturating_add`/`saturating_sub` used an **eager** `unwrap_or(max_value())`,
so `max_value()` ran on every call and forced a `LazyLock` whose `find_max`
binary search **never terminates on Windows `SystemTime`** (100% CPU forever).
That hung `tor_netdoc::RouterDesc::parse` — used only for **bridge
descriptors** — so a fetched descriptor was never parsed/stored, every bridge
stayed `dir_info_missing` → "unsuitable to purpose", and no circuit could be
built. Fix: lazy `unwrap_or_else`; regression test added; the doctests and the
two limit-forcing unit tests are disabled/ignored on the affected platform.

### `tor-dirclient` (0.43.0)
Directory reads used a single **total** timeout that truncated a big-but-slow
consensus over an obfs4 bridge. Switched to an **idle** (inter-read) timeout
(90s) so a healthy-but-slow download is not killed.

### `tor-dirmgr` (0.43.0)
The bridge-descriptor fetch (`bridgedesc.rs`) had **no timeout** and could hang
forever. Added a hard per-attempt timeout, faster retry, and gentle
(non-flooding) parallelism for the bridge pool.

Second fix — the `SharedMutArc` netdir handle (`shared_ref.rs`) was permanently
bricked by **any** panic inside `mutate()`'s closure. `replace()`/`clear()`/
`get()`/`mutate()` all used `.write()/.read().expect("Poisoned lock for
directory reference")` on a plain `std::sync::RwLock`. A panic inside the
closure (e.g. an edge-case microdescriptor parse inside `DirMgr`'s
`add_microdesc` loop, which runs roughly hourly for the lifetime of the
process) poisons that `RwLock` forever — standard `std::sync::RwLock`
semantics — and the `.expect()` then re-panics on **every** subsequent
`get()`/`replace()`/`mutate()`. The process stays alive (a panic in a spawned
tokio task doesn't tear down the runtime by default) but the netdir becomes
unreadable for all later operations, with no external signal beyond a stream
of panics in the log. For a long-lived headless process with no supervisor to
restart it, that converts one non-fatal panic into permanent degradation until
a manual restart. `mutate()`'s own doc comment already flagged this (`# No
panic-safety ... TODO: Fix this.`). Fix: replaced the four `.expect(...)` sites
with `.unwrap_or_else(|e| e.into_inner())` — exactly the pattern already in use
in this repo's `apps/socks5-proxy/src/tor_watchdog.rs` for the same class of
problem. `into_inner()` hands back the guard over whatever data survived the
panic; it does **not** roll back a partial mutation performed before the panic
(recover-with-possible-staleness beats permanent panic-on-every-access — a
full `catch_unwind` rollback was deliberately left out as the larger, optional
second step). Regression test added: a panicking closure no longer poisons the
next `get()`/`mutate()`.

Third fix — `sqlite_error_kind()` (`err.rs`) mapped `SQLITE_BUSY` /
`SQLITE_LOCKED` (`rusqlite::ErrorCode::DatabaseBusy`/`DatabaseLocked`) into
`ErrorKind::Internal`, so `impl From<rusqlite::Error> for Error` wrapped them
as `tor_error::Bug::from_error(..., "sqlite detected bug")` and
`bootstrap_action()` then returned `BootstrapAction::Fatal`. On a long-lived
Windows desktop process the directory cache db is routinely locked for a few
milliseconds by antivirus real-time scanning, Windows Search indexing, or
OneDrive/backup sync over the cache directory — exactly the transient,
fully-recoverable contention that `SQLITE_BUSY`/`SQLITE_LOCKED` semantically
mean ("try again later"). A transient file lock was thus mislabeled and
mis-handled as a programming bug, fatally aborting the bootstrap. Fix: moved
`DatabaseBusy`/`DatabaseLocked` out of the `EK::Internal` match arm and into
`EK::CacheAccessFailed` — the same bucket already used for the analogous
environmental cache-access IO failures (`FileLockingProtocolFailed`,
`SystemIoFailure`, `CannotOpen`, `PermissionDenied`, ...) — so they become a
plain `Error::SqliteError` instead of an `Error::Bug`. Note: both `Bug` and
`SqliteError` map to `BootstrapAction::Fatal`, so this is primarily an
honest-classification fix (a transient lock is no longer reported as a
"detected bug") that also sets up correct semantics for a future retry-with-
backoff on `CacheAccessFailed`, deliberately left as the larger, optional
second step. `OperationInterrupted`/`OperationAborted` were deliberately left
in `Internal` (explicit cancel/abort signals, not file-lock contention).
Regression tests added covering both the direct `sqlite_error_kind()`
classification and the end-to-end `From<rusqlite::Error>` path.

### `tor-chanmgr` (0.43.0)
`ChanMgr` tracks open channels but only ever retires one automatically via
`expire_channels()`, which requires the channel to have been *idle* past a
randomized 180-270s `max_unused_duration` (`mgr/state.rs`). A channel left
half-open by a silent network change (e.g. laptop sleep/resume, Wi-Fi to
cellular handoff) is never "idle" — a stuck circuit keeps hopelessly
retrying against it — so it is never expired, and nothing else in `ChanMgr`
could force it closed. The underlying primitive to do that already exists
and is already public one layer down
(`tor_proto::channel::Channel::terminate()`), but `ChanMgr`'s public surface
had no way to reach the channels it holds from the outside to call it. This
is exactly the gap `tor_watchdog.rs`'s doc comments describe working around
with a whole-`TorClient` rebuild into a pool of alternate state-dir slots.

Fix: added `terminate(&self)` to the crate-private `AbstractChannel` trait
(`mgr.rs`), implemented on the concrete `tor_proto::channel::Channel` by
delegating to its own already-public `terminate()` (`builder.rs`). Added
`MgrState::terminate_all_channels()` (`mgr/state.rs`), which reuses the same
`self.inner.lock()...channels.retain(...)` iteration pattern as
`expire_channels()`, but instead of checking `ready_to_expire`,
unconditionally calls `.terminate()` on every open channel before dropping
it from the map (pending/`Building` entries are left untouched — there is no
live channel there yet). Exposed as `pub(crate) AbstractChanMgr::
terminate_all_channels()` (`mgr.rs`) and finally as the public
`ChanMgr::terminate_all_channels(&self)` (`lib.rs`).

This lets a caller (the application's stale-channel watchdog) force every
tracked channel closed in place — the same way a real TCP RST would — and
let `ChanMgr`'s own `get_or_launch` machinery reconnect through the *same*
`TorClient`, same state dir, same warm guard/bridge-descriptor cache. No
cold rebuild slot, no guard-exhaustion spiral risk from a cold rebuild. Pure
addition: one new trait method, one new impl, two new `pub(crate)`/`pub`
methods reusing an existing iteration pattern — no existing line changed.
`tor-circmgr` needs no matching patch: it holds the concrete channel type
directly, not a long-lived cache that a `terminate_all_channels()` call
would strand (confirmed in
`docs/upstream/arti-vendor-integration-plan.md` §1.3).

Second fix — the channel-build **connect timeout**. `connect_via_transport`
armed a single TOTAL timeout (5s for `is_direct()`, 10s for everything
else) around the whole of `connect_no_timeout`. `is_direct()` is false for
*every* pluggable-transport channel, so in this client's bridge-only
operation 100% of channel builds were bounded by that 10s ceiling — for the
full PT handshake (bridge TCP connect + obfs4/webtunnel client handshake +
Tor TLS + Tor link handshake, ~10+ round trips). That is too tight for a
healthy-but-slow / high-latency bridge path, and because `Error::ChanTimeout`
maps to `RetryTime::Immediate` (`err.rs`), the guard manager retried at once
and just hit the same 10s ceiling again. The PT total was raised 10s → 45s
(extracted as the unit-tested `connect_build_timeout(is_direct)` helper).
This is a single generous **total**, not the idle/total split applied in
`tor-dirclient`'s `read_and_decompress`: that split relies on a read loop
with per-byte progress, whereas here the slow phase (the PT handshake) lives
entirely inside the opaque `TransportImplHelper::connect` call with no
progress callback, and the only progress boundaries visible at this level
(phase completions reported via the `BootstrapReporter`) bracket the PT
handshake rather than sample within it — so an idle timer reset there would
degenerate to a per-phase total. A genuine idle/total fix for the PT
handshake belongs one layer down, in the PT transport (`tor-ptmgr` / the PT
child), which is out of scope for this crate.

### `tor-guardmgr` (0.43.0)
A guard is only eligible for a data circuit once it has complete directory
information (`dir_info_missing == false`), but `GuardMgr` never aggregated
this into a system-wide "do we have any usable guard at all" signal — so
nothing downstream could tell "directory bootstrapped" apart from "directory
bootstrapped, but every guard is still descriptor-naked". Added
`GuardSet::any_guard_usable_for_traffic()` (true iff at least one guard in the
active sample is `usable()` and has complete directory information) and
`GuardMgr::usable_guard_events()`, a `postage::watch`-backed stream
(mirroring the existing `skew_events()` plumbing) that republishes this
aggregate every time the guard sample is refreshed. Consumed by the matching
`arti-client` change below. Vendored and patched together with `arti-client`
as a **mandatory pair** — see
`docs/upstream/arti-vendor-integration-plan.md` §1.4/§2.

Second fix — the indeterminate-failure **permanent disable** with no recovery
path. `record_indeterminate_result()` sets `Guard::disabled` once the guard's
*lifetime* indeterminate-failure ratio (`n_indeterminate / (n_successes +
n_indeterminate)`) crosses `0.7`. That `disabled` field is **persisted**
(serialized to the state file) and nothing in the crate ever clears it — its
own TODO admits "we'll need a way to make ancient history expire" but no such
mechanism exists. `GuardStatus::Indeterminate` is exactly the "circuit failed
beyond the guard" class (second-hop/exit timeouts) that the
guard-exhaustion-watchdog-spiral incident logged by the hundred-per-minute;
in bridge-only operation, where traffic is split across 2-6 hand-configured
bridges instead of thousands of sampled relays, one such storm can drive a
bridge's ratio over the threshold and disable it *for good* (surviving
restarts), with no automatic re-enable. Added a manual escape hatch the
application watchdog can invoke on its own policy ("too few usable bridges
remain, don't let this one stay dead"): `Guard::reset_disabled()` clears
`disabled` **and** resets `CircHistory`/`suspicious_behavior_warned` (so the
next indeterminate result doesn't immediately re-trip the threshold on the
stale numerator), surfaced as `GuardSet::reset_disabled_guards()` (counting
re-enabled guards, leaving healthy guards' history untouched),
`GuardMgr::reset_disabled_guards()`, and a `TorClient::reset_disabled_guards()`
passthrough (gated `experimental-api`, mirroring the existing
`dirmgr()`/`circmgr()`/`chanmgr()` accessors). The detection logic and its
security threshold are left untouched — this is purely an additive override
hook, exactly paralleling `tor-chanmgr`'s `terminate_all_channels()`.

Third fix — adaptive parallelism for the bridge-descriptor fetch.
`GuardSet::descriptors_to_request()` caps the guards it hands to the
descriptor manager at `maximum = max(params.data_parallelism, 2)`. That
conservative cap is correct in normal operation, but during a total
guard-exhaustion state (every guard `dir_info_missing`, i.e. no usable guard
for traffic — exactly the condition surfaced by the first fix's
`any_guard_usable_for_traffic`) it becomes the bottleneck: the eligible
guards are still listed, reachable, and not in backoff (a failed descriptor
fetch is invisible to the guard layer — it never trips
`record_failure`/`retry_at`), so they all pass the filter and are then
truncated by `take(maximum)`, leaving a client requesting descriptors for
only its top 2 bridges while the rest of the sample that could recover it is
never asked. This is the mechanism behind the 12-minute outage analyzed in
`docs/upstream/guard-exhaustion-watchdog-spiral.md` §2.4, and it also starved
the `tor-dirmgr` parallelism raise (the `BridgeDescMgr` can only fetch
bridges the guard layer hands it via `set_bridges`, so a 12-wide ceiling was
never reached while only 2 were ever requested). Fix: while
`any_guard_usable_for_traffic()` is false, widen `take_n` to the whole
eligible sample (`usize::MAX`, naturally bounded by the sample size); snap
back to the conservative `maximum` the moment the first guard becomes usable.
No flood risk: the lower layer independently caps concurrent fetches
(`BridgeDescDownloadConfig::parallelism`) and backs off per-bridge retries,
so requesting more candidates here cannot exceed that budget — it only stops
starving it. One-line conditional inside `descriptors_to_request`, no
signature change; unit test added mirroring
`any_guard_usable_for_traffic_aggregation`.

Fourth fix — a descriptor-less bridge guard hard-erroring an entire circuit
attempt instead of being retried. `select_guard_once()` picks a guard from
the sample, then (for `UniverseType::BridgeSet`) tries to attach circuit-
target info from the latest bridge set; if the picked guard's `BridgeDesc`
hasn't been fetched yet (an ordinary, expected-to-happen-sometimes race —
descriptor fetch is async, independent of guard sampling) and the usage is
`GuardUsageKind::Data`, it returned `PickGuardError::Internal` — a variant
whose `retry_time()` is `RetryTime::Never`, so `tor-circmgr`'s outer retry
loop (confirmed by reading its `mgr.rs`: `Internal`'s `AbsRetryTime::Never`
triggers an immediate `break`) aborted the *entire* circuit-build request
after this single guard pick, rather than trying a different guard or
waiting the ~100ms a descriptor fetch typically takes. Observed live in
production as `Tried to return a non-circtarget guard with Data usage!`
warnings bursting to ~17/hour (historical baseline ~2/day) and contributing
to real circuit-build timeouts. Two-part fix: (1) `select_guard_with_expand`
now retries `select_guard_once` unconditionally after
`update_guardset_internal()` refreshes each guard's `dir_info_missing` /
`conforms_to_usage`, instead of only when the sample was actually *extended*
(`ExtendedStatus::Yes`) — the old gate discarded the freshly-recomputed
"this guard isn't suitable yet" state even when it correctly filters the
descriptor-less guard out in favor of the next preferred candidate; (2) the
residual failure (no valid candidate at all) now returns
`PickGuardError::AllGuardsDown` instead of `Internal`, which *is* retriable
(`RetryTime::AfterWaiting`), so the outer loop gets another chance instead of
aborting outright. `GuardUsable` (in `pending.rs`) gained `#[derive(Debug)]`,
needed only to satisfy the new regression test's assertion formatting — no
functional change. New test `bridge_descriptorless_guard_is_retriable_not_internal`
injects the exact stale state (a sampled bridge with `dir_info_missing`
artificially cleared while its descriptor is genuinely absent) and asserts
`AllGuardsDown`, not `Internal`. `tor-circmgr` itself is not vendored and was
not touched — the whole fix lives inside this already-patched crate.

### `arti-client` (0.43.0)
`BootstrapStatus::ready_for_traffic()` used to report "ready" once directory
bootstrap completed, without regard to whether any guard actually had usable
descriptors — the root cause of a guard-exhaustion spiral where a client
looked "ready" while still unable to build a single data circuit for
minutes. `ready_for_traffic()` now ANDs in a third signal,
`tor-guardmgr`'s new `usable_guard_events()` stream (wired into
`RunningInner::new`/`report_status` as a fourth event source alongside
`conn_status`/`dir_status`/`skew_status`), defaulting to `false` so a freshly
constructed client is never considered ready before the first guard-sample
refresh reports in. Only this crate is overridden here; its internal `tor-*`
dependencies keep resolving from crates.io / already-patched sources as
before (the published manifest carries version-only deps, no `path`).

Second fix — observability for the intentional protocol-mismatch shutdown.
Arti's ["fast zombies"][fz] defense (Tor proposal 266) calls
`std::process::exit(1)` when the live consensus marks a subprotocol our
build lacks as required — deliberate, not a bug, and **not** weakened here
(same reasoning as the `safelog` item in `CHANGELOG.md`'s Known
limitations). The problem was purely observability: the shutdown wrote only
an `eprintln!` to stderr, invisible in a deploy model with no
supervisor/systemd/Docker to notice the process died. Added
`FatalProtocolErrorHandler` (a `Fn(&Error) + Send + Sync` trait with a
blanket impl for closures) and `TorClientBuilder::fatal_protocol_error_handler()`
to install it; `RunningInner::new`'s `on_fatal` closure now invokes the hook
(via the unit-tested seam `notify_fatal_protocol_error`) immediately before
its existing `eprintln!`/`sleep`/`process::exit(1)` sequence, which is
otherwise unchanged. `packages/arti-wrapper` wires every `TorClient`
construction path through a `tor_builder()` helper that installs a
`tracing::error!` marker as the hook, so the event now lands in this
project's normal logging pipeline instead of being silent.

[fz]: https://spec.torproject.org/proposals/266-removing-current-obsolete-clients.html

Third fix — expose `tor-guardmgr`'s `GuardMgr::note_external_failure()`
through `TorClient`. `tor-guardmgr` already has a public, battle-tested entry
point for reporting that some activity *outside* of `tor-guardmgr`'s own
circuit-build bookkeeping failed against a given guard (feeding directly into
the same primary/confirmed/sample guard-state machine, prop271, that circuit
failures use) — but nothing on `arti-client`'s public surface reached it.
Added `TorClient::note_external_guard_failure(&self, identity, activity)`
(gated `experimental-api`, mirroring the existing
`dirmgr()`/`circmgr()`/`chanmgr()`/`reset_disabled_guards()` accessors), a
thin delegate to `GuardMgr::note_external_failure()` with no `tor-guardmgr`
changes at all. Also re-exports `tor_guardmgr::ExternalActivity` and
`tor_linkspec::HasRelayIds` from the crate root so callers don't need a direct
dependency on either crate just to name the types at the call site. This is
purely the API entry point — no policy for *when* to call it (e.g. detecting
an unhealthy pluggable-transport bridge whose circuits build but whose
traffic stalls) is included here.

## Maintenance

- Versions match the exact crates.io releases the dependency graph resolves
  (currently the arti 0.43 line). When upgrading arti, re-vendor these crates
  at the new version and re-apply the diffs above, or drop a patch entirely if
  the fix has landed upstream.
- All local changes are marked with a `tor-socks5 local patch` comment near the
  edit so they are easy to find and re-apply.
