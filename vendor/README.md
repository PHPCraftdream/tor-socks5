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

### `tor-guardmgr` (0.43.0)
Vendored as a **baseline** ahead of an aggregated guard-usable signal patch —
no behavior change yet. The planned fix adds a new
`usable_guard_events()` stream to `GuardMgr` (mirroring the existing
`skew_events()` / `postage::watch` plumbing already in this crate), published
whenever a primary/preferred guard's `dir_info_missing` flag flips, plus the
matching `arti-client` change that wires it into `BootstrapStatus`. This
commit only adds the unmodified 0.43.0 source so the path override compiles
identically; the actual fix lands in the next commit.

### `arti-client` (0.43.0)
Vendored as a **baseline** ahead of the guard-usable signal patch — no
behavior change yet. Vendored as a **mandatory pair** with `tor-guardmgr`:
neither crate's half is useful on its own (`tor-guardmgr`'s new stream has no
consumer; `arti-client`'s `BootstrapStatus` change has no stream to consume —
see `docs/upstream/arti-vendor-integration-plan.md` §2). Only this crate is
overridden here; its internal `tor-*` dependencies keep resolving from
crates.io / already-patched sources as before (the published manifest carries
version-only deps, no `path`). This commit only adds the unmodified 0.43.0
source so the path override compiles identically; the actual fix lands in the
next commit.

## Maintenance

- Versions match the exact crates.io releases the dependency graph resolves
  (currently the arti 0.43 line). When upgrading arti, re-vendor these crates
  at the new version and re-apply the diffs above, or drop a patch entirely if
  the fix has landed upstream.
- All local changes are marked with a `tor-socks5 local patch` comment near the
  edit so they are easy to find and re-apply.
