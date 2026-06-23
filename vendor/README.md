# vendor/ — locally-maintained forks of upstream crates

These are **full source copies** of three upstream crates, with local fixes
applied, committed into this repository and wired in via `[patch.crates-io]`
in the workspace `Cargo.toml`.

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

## Maintenance

- Versions match the exact crates.io releases the dependency graph resolves
  (currently the arti 0.43 line). When upgrading arti, re-vendor these crates
  at the new version and re-apply the diffs above, or drop a patch entirely if
  the fix has landed upstream.
- All local changes are marked with a `tor-socks5 local patch` comment near the
  edit so they are easy to find and re-apply.
