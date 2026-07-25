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

## Maintenance

- Versions match the exact crates.io releases the dependency graph resolves
  (currently the arti 0.43 line). When upgrading arti, re-vendor these crates
  at the new version and re-apply the diffs above, or drop a patch entirely if
  the fix has landed upstream.
- All local changes are marked with a `tor-socks5 local patch` comment near the
  edit so they are easy to find and re-apply.
