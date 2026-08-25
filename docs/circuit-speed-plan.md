# Plan: circuit speed knobs — bridge ranking and fast-relay preference

Status: **bridge ranking and bandwidth-floor relay selection are implemented**. Companion to
`docs/bridges.md` and `docs/android-bridge-freshness-plan.md`.

Context: this fork is explicitly a personal-stability client, not an anonymity-preserving one
("анонимность понижаем — делаем для себя"). The knobs below trade anonymity for latency; they
would be unacceptable in upstream Tor/arti and are only defensible under that framing.

## Established facts (verified in source, arti 0.43.0)

Two things the request conflated, which are not the same knob:

| | what it is | minimum | today |
|---|---|---|---|
| **Bridges** (`bridges.lines`) | the *entry point* — a bridge is hop #1 (the guard) | **1** — no hardcoded floor of 2 (`tor-guardmgr/src/config.rs:67-70`: `bridges_enabled()` is just `!self.bridges.is_empty()`) | N configured; extras are failover redundancy, **not** extra hops |
| **Hops** | relays a circuit traverses | 3 for ordinary traffic | 3 |

1. **Hop count is structural, not a variable.** `tor-circmgr/src/path.rs:305-382`, `pick_path()`
   builds `vec![guard, MaybeOwnedRelay::from(middle), MaybeOwnedRelay::from(exit)]`. There is no
   loop and no count — "3" is just how many steps the function performs. (The 1-hop directory
   path is a separate code path, `dirpath.rs`, used for `OneHopDirectory` usage only.)
2. **Relay selection is already bandwidth-weighted.** `path.rs:367` / `path/exitpath.rs:175` call
   `selector.select_relay()` → `tor-relay-selection/src/selector.rs:277-279` →
   `netdir.pick_relay(rng, role, ...)`, the standard consensus-bandwidth-weighted choice. So
   "prefer fast relays" is **already the default behaviour** — a naive toggle for it would be a
   no-op.
3. **Latency data exists but never feeds selection.** `tor-circmgr/src/timeouts/pareto.rs`
   (`note_hop_completed`, line 566) models per-hop build times purely to decide *when to give up*
   on a circuit build. Nothing routes it back into which relay gets picked.

## What is worth building, in cost order

### Tier 1 — periodic bridge re-probe + persisted ranking (cheap, infrastructure exists)

Almost entirely already built, just not wired for continuous operation on Android:

- `bridge-probe` already measures per-bridge TCP latency and returns them sorted
  (`probe_and_sort`, `packages/bridge-probe/src/lib.rs:177`).
- `bridge-store` already persists `last_latency`, `ok_count`, TCP/circuit failure counters per
  bridge, and `engine.rs` already sorts the alive set by `ok_count` after each probe round.

Missing: the probe is **one-shot per connect** on Android. Make it periodic (reuse the existing
`stall_watchdog` timer in `packages/android-ffi/src/engine.rs`), so the persisted ranking stays
current and the next connect starts from the genuinely fastest known bridge. This is the
"фоновый ленивый поиск + локальный кэш" idea, scoped to bridges — where it is both cheap and
already 80% implemented. Overlaps tasks #27/#28.

**Risk note:** probe frequency must stay low. An earlier revision that widened bridge concurrency
triggered bridges' flood protection and got connections reset (documented in
`packages/arti-wrapper/src/lib.rs`'s `build_config`). Same discipline applies here.

### Tier 2 — bandwidth floor for middle/exit relays (moderate, needs vendoring)

Bandwidth weighting is probabilistic: a slow relay is *unlikely* but not *impossible* to be
picked, and one slow middle hop dominates the whole circuit's latency. A hard filter — "only
consider relays above the Nth percentile of consensus bandwidth" — converts that from
"usually fast" to "never slow".

Requires vendoring `tor-circmgr` and adding a predicate to the `RelaySelector` usable-filter for
middle/exit roles, driven by a new config field. Config-only escape hatch: default off, so the
stock behaviour is unchanged unless enabled.

**Caveat:** shrinking the candidate set concentrates traffic on a smaller relay population —
directly reduces anonymity, and if set too aggressively can cause circuit-build failures when
the filtered set is too small. Needs a floor on set size, mirroring the "never prune below a
floor" rule already adopted for bridges.

### Explicitly out of scope

- **Client-side latency probing of middle/exit relays.** Actively measuring public relays from
  the client is slow, produces a distinctive traffic pattern (fingerprintable), and duplicates
  what the directory authorities' bandwidth scanners already publish in the consensus — which
  selection already consumes. Circuit-build timings we *already* collect
  (`timeouts::pareto`) are the sane source if per-relay scoring is ever wanted; a fresh probing
  subsystem is not.
- Changing the guard/bridge count semantics. One bridge already works; "more bridges" is a
  failover knob, not a speed or hop knob, and is already exposed in the UI.

## Suggested order

Tier 1 first — it is nearly free, carries no anonymity cost beyond what the fork already accepts,
and its effect (always starting from the fastest live bridge) is the one most likely to fix the
symptom actually observed on device: slow/stalled bootstraps behind a marginal first hop. Only
then evaluate whether Tier 2 is still needed, with Tier 1's measurements as the baseline.
