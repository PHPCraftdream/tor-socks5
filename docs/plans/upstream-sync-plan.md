# Plan: upstream sync — vendor rebases (0.47 UPS-06, then 0.48)

Status: **done** — the vendored set was rebased from Arti 0.43.0 (arti 2.4.0)
to 0.47.0 (arti 2.7.0), synced 2026-10-13, and then to 0.48.0 (arti 2.8.0),
synced 2026-11-10 (per-file three-way merge against the pristine archives;
see `vendor/PROVENANCE.md`). Patch details live in `vendor/README.md`. The
sections below record the 0.47 decision and are kept as history; where a
statement changed with 0.48 it says so.

**Decision, 2026-11-11: no more upstream submissions.** Upstream does not
accept agent-written code, so the carried patches stay in `vendor/`. Other
projects that want them take the patch-kit (`vendor/README.md`, "Using these
patches in your own project", tag `arti-patches-0.48.0`).

## Decision: rebase to 0.47 ("path B"), not backport onto 0.43

The choice was between staying on the 0.43 vendored line and backporting the
Arti 2.5.0–2.7.0 security fixes, or moving the whole vendored set to 0.47 and
carrying our local patches forward. **Path B was taken.**

Rationale: the must-carry security fixes of the 2.5.0–2.7.0 window live
mostly in crates we do **not** vendor — `tor-proto`, `tor-netdoc`,
`tor-consdiff`:

* TROVE-2026-047 (#2683) — half-stream memory / side-channel
* #2599/#2600 (TROVE-2026-028/029) — consensus and consensus-diff memory limits
* #2680 (TROVE-2026-048) — stricter consensus parser compatibility
* TROVE-2026-024 (#2566) — tor-netdoc parser crash
* #2688 (TROVE-2026-046) — dirclient header-read timeout
* #2694 (TROVE-2026-044) — RESOLVED local-address filtering
* #2684 — channel-handshake decode
* #2687 (TROVE-2026-045) — LZMA 16 MiB dictionary limit (kept since upstream)
* #2650 — XON rate bytes-vs-bits
* !4426 — pathbias-lite guard-disable hardening

Hand-backporting these onto 0.43 is far riskier than a coordinated move to
the 0.47 set, where they arrive upstream-tested.

## What 0.47 gives us by moving

* New HTTP header reader with a 10-second header timeout and
  `take(MAX_HEADERS_LEN)` in `tor-dirclient` (#2688).
* LZMA memory limit (#2685 / 045 series).
* RESOLVED local-address filtering (#2694).
* Effectively unreachable pathbias disable threshold (!4426).
* `BootstrapSetting` / manual-bootstrap plumbing.

## What had to be carried

All local vendor patches were carried onto 0.47 (one-line enumeration):
saturating-time lazy limits; dirclient idle-body timeout + Content-Length
bound; dirmgr fetch timeout, pool parallelism/retry, poison recovery and
sqlite lock classification; chanmgr `terminate_all_channels` + 45 s
non-direct build timeout; guardmgr readiness signal, recovery corrections
and `reset_disabled_guards`; arti-client guards-usable readiness,
fatal-protocol-error hook, external guard failure passthrough, exit-stream
retry and `initial_connect_timeout`; circmgr opt-in bandwidth floor.
**None were accepted upstream in 0.47**, and in 0.48 only the lazy
`saturating_add`/`saturating_sub` limits were (`saturating-time` 0.6.0). The
full table with statuses is in `vendor/README.md`.

## Still open / known risks

* Old persisted guard `disabled` state from the 0.43 era is not auto-cleared;
  `reset_disabled_guards` is the manual migration handle (0.47's !4426 made
  new automatic disables practically impossible).
* Guard readiness recovers after a backoff only when something calls
  `select_guard` (upstream runs `consider_all_retries` only there);
  a consumer that waits for `any_guard_usable_for_traffic` before asking for
  any circuit could wait indefinitely. Not observed in practice (bootstrap and
  preemptive circuits keep selecting guards); revisit if it shows up.
* Our 30 s descriptor-fetch total and 45 s channel-build total budgets are
  not mutually reconciled.
* #2601 / TROVE-2026-027 applicability was never confirmed.
* RUSTSEC-2026-0285 and the other dependency advisories: now checked in CI by
  `cargo deny check advisories` (the `license-audit` job; ignores and their
  reasons are in `.github/deny.toml`).
* ~~onion-service-host fixes #2681/#2748 become mandatory if service hosting is
  ever enabled~~ — **resolved 2026-11-11.** Hosting is built by default now
  (the `onion-service` feature; services only start when `onion_services` is
  configured), so this was checked against the sources. Both fixes shipped in
  Arti 2.7.0 and are in 0.48.0, which we use unpatched for these crates:
  #2748 (TROVE-2026-063, `tor-proto` `hs_ntor`: the INTRODUCE2 length underflow
  is gone, `take_all_but(HS_MAC_LEN)` in 0.47.0 and 0.48.0 but not in 0.43.0)
  and #2681 (TROVE-2026-068, `tor-hsservice` `pow/v1.rs`: the effort-conversion
  panic). The proof-of-work code only compiles with `hs-pow-full`, which our
  build does not enable. The 2.8.0 hosting fixes #2779 (TROVE-2026-069) and
  #2747 are in 0.48.0 as well. The issue pages were not readable (GitLab
  answers 403 to non-browser clients); the titles come from the Arti CHANGELOG
  and commit messages on the public cgit mirror, and the code was compared in
  the crates.io sources.
* Full semantic equivalence of the carried patches after the mechanical
  rebase was not re-proven beyond the existing regression tests.

## Sync cadence

Align with arti release trains, which are roughly quarterly (2.4 → 2.7
spanned the 0.43 → 0.47 window). Do a vendor sync per minor arti line, or
immediately on a security release affecting vendored or client-path crates.

## Upstream-watch policy (agreement)

> Note: this upstream-watch workflow is **not implemented, awaiting a
> decision**.

Watch sources: arti releases on GitLab
(gitlab.torproject.org/tpo/core/arti) and crates.io, the arti CHANGELOG,
TROVE/ security advisories and RUSTSEC advisories, torproject-announce.

On a security release: assess applicability to our vendored crates and the
client path within days. If affected, ship a vendor sync — or a targeted
backport if the fix is in a vendored crate and the release train is far —
rather than waiting for the regular cadence.
