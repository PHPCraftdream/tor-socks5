# Plan: upstream sync — vendor rebase to Arti 0.47 (UPS-06)

Status: **done** — the vendored set was rebased from Arti 0.43.0 (arti 2.4.0)
to 0.47.0 (arti 2.7.0), synced 2026-10-13. Patch details live in
`vendor/README.md`.

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
**None were accepted upstream in 0.47.** The full table with statuses is in
`vendor/README.md`.

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
* RUSTSEC-2026-0285 dependency-advisory check before release.
* onion-service-host fixes #2681/#2748 become mandatory if service hosting is
  ever enabled (today only onion-service-client is used).
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
