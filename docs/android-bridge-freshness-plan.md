# Plan: keep the Android engine's bridge list — and arti's guard sample — fresh automatically

Status: **planned, not implemented**. Companion to `docs/bridges.md` (the CLI daemon's already-shipping
bridge lifecycle) and `docs/checkpoints/obfs4-connect-investigation.md` (orbot-rs repo — the livelock
investigation that surfaced this gap).

## Problem

The CLI daemon (`apps/socks5-proxy`) already has a full, documented, working bridge lifecycle
(`docs/bridges.md`): TCP-probe health tracking, automatic pruning of dead bridges past `max_fails`/
`max_circuit_fails`, a candidate pool fed from `bridges.sources`, and `auto_fetch`/`min_alive` to keep
the working list topped up. None of that maintenance loop runs on Android — `packages/android-ffi`'s
`engine_async` does a **one-shot** TCP-probe + bootstrap per connect attempt:

- `BridgeStore::note_probe_round` (`engine.rs`) already computes which bridges crossed `max_fails`/
  `max_circuit_fails` and returns them as a pruned `Vec<BridgeLine>` — **the return value is discarded**
  (see `engine.rs`, the `store.note_probe_round(...)` call has no `let pruned = `). Dead bridges are
  never removed from `Prefs.bridgesList` (the Kotlin side's source of truth), so every future connect
  attempt keeps retrying them.
- `nativeRefreshBridges`/`TorSocks5Bridge.refreshBridges()` (fetches from `bridges.sources`, merges new
  bridges into `Prefs.bridgesList`) exists and works, but is **only triggered by a manual tap** on the
  "Refresh Bridges" menu item. `BridgesConfig.min_alive` is parsed from config but nothing on Android
  acts on it.

Symptom this produces in practice: `arti-data/state/state/guards.json` accumulates guard entries for
bridges that stopped working days/sessions ago, biasing fresh guard selection toward poisoned
candidates (confirmed live: a stuck cold start went from failing outright to bootstrapping in ~13s
after **manually deleting** the file). Deleting the file is not a real fix — it throws away good guard
history along with the bad, and doesn't stop the same staleness from re-accumulating.

## Why we don't touch `guards.json` directly

Confirmed by reading `vendor/tor-guardmgr`:

- `GuardSet::extend_sample_as_needed` (`sample.rs:365`) is **purely additive** — it only adds guards
  when the usable count is below `min_filtered_sample_size`. It never removes anything.
- `GuardSet::update_status_from_dir` (`sample.rs:499`) is what actually reconciles the sample against
  the current "universe" (for bridges, the configured `bridges.lines` set): a guard no longer present
  gets `unlisted_since` stamped (`guard.rs:641-643`).
- `Guard`'s expiry check (`guard.rs:676-677`) removes a guard once `unlisted_since` has been set for
  longer than `params.lifetime_unlisted`.

So arti **already** ages out guards that fall out of the configured bridge set — we don't need to hand-edit
`guards.json`. We only need to keep `bridges.lines` (i.e. `Prefs.bridgesList` on Android) itself
accurate: remove entries that have proven dead, add entries that are known-good. `guards.json` then
self-cleans on its own schedule.

## Plan

### Phase 1 — prune dead bridges from `Prefs.bridgesList` (task #28, first half)

1. In `engine.rs`, capture `note_probe_round`'s return value:
   ```rust
   let pruned = store.note_probe_round(&settings.bridges, &alive, now, fail_window,
       bridges_cfg.max_fails, bridges_cfg.max_circuit_fails);
   ```
2. Surface `pruned` to Kotlin. Two viable mechanisms, pick one:
   - **(a) New JNI call**, mirroring `nativeRefreshBridges`'s shape: e.g.
     `nativeTakePrunedBridges(configPath) -> String` (newline-joined `BridgeLine`s), backed by a
     process-wide `OnceLock<Mutex<Vec<BridgeLine>>>` (same pattern as `CURRENT_TUNNEL` in
     `engine.rs`) that `engine_async` appends to on every probe round and the JNI call drains. Kotlin
     polls it after each connect attempt (`OrbotService`/`TorSocks5Bridge.start()`), removes the
     returned lines from `Prefs.bridgesList`.
   - **(b) Journal/callback event**: extend `BootstrapCallback` (or reuse `onBlocked`) with the pruned
     list piggybacked in the message text, parsed Kotlin-side. Simpler wiring, but overloads an
     existing callback with a second meaning — (a) is cleaner.
   - Recommendation: **(a)**, it reuses an already-proven pattern (`nativeRefreshBridges`) instead of
     inventing a new protocol on top of the bootstrap-event callback.
3. Kotlin side: after `nativeStart`/on next `start()`, call the new JNI accessor, diff against
   `Prefs.bridgesList`, persist the removal. Log each removal to the connect-screen journal (same
   dedup'd per-stream logging `OrbotService` already has for bootstrap/blocked messages) so the user
   can see bridges getting dropped, not just silently losing them.
4. Never prune below a floor (e.g. keep at least 1-2 bridges even if all are flagged dead) — losing the
   entire configured list would make the *next* connect attempt fail immediately with "no bridges
   configured" instead of degrading gracefully. Mirrors the CLI's own seed-fallback safety net
   (`use_seeds`), which Android doesn't have — until Android gets an equivalent, the floor check is a
   cheap substitute.

### Phase 2 — auto-fetch new bridges when the pool shrinks (task #27)

1. Track the alive count from each probe round (already computed as `alive.len()` in `engine_async`).
2. When `alive.len() < bridges_cfg.min_alive`, trigger a refresh. Two trigger points, not mutually
   exclusive:
   - Right after a probe round with too few alive bridges, before giving up on bootstrap.
   - From `stall_watchdog` (already polling every 45s once `On`) — if the tunnel is up but the
     underlying bridge pool is thin, refresh proactively rather than waiting for the next full stall.
3. Requires an already-live circuit (`bridge_fetcher::fetch_all` fetches `bridges.sources` *over* Tor)
   — same chicken-and-egg limit `nativeRefreshBridges` already documents. This phase only helps
   *after* a connection has been established at least once; it does not help the very first cold
   bootstrap when the configured pool is already too thin to succeed at all.
4. Reuse the existing `TorSocks5Bridge.refreshBridges()` Kotlin path (dedup against `Prefs.bridgesList`,
   merge new lines) — just need a caller that fires automatically instead of only from the menu tap.

### What Phase 1 + Phase 2 together buy

- Dead bridges stop being retried forever (Phase 1) — bounded, self-correcting `bridges.lines`.
- The pool replenishes itself as bridges die and new ones come online (Phase 2) — no manual "Refresh
  Bridges" tap needed for steady-state operation.
- `guards.json` inherits the freshness for free, via arti's own `unlisted_since`/`lifetime_unlisted`
  expiry — no direct file surgery, ever.
- Net effect matches the CLI daemon's already-proven `use_seeds`/`auto_fetch`/`min_alive`/`max_fails`
  lifecycle (`docs/bridges.md`), scoped to what Android's one-shot `engine_async` architecture needs —
  not a full port of `bridge_warmer.rs`/`tor_watchdog.rs`'s channel-warming and failover machinery
  (that remains a separate, larger effort if still wanted later).

## Explicitly out of scope for this plan

- Editing `arti-data/state/state/guards.json` directly (unnecessary per the analysis above, and risky
  — it's arti's own internal format, not ours).
- Porting the CLI's `bridge_warmer.rs` (channel pre-warming) or `tor_watchdog.rs` (circuit-failure
  signature gating, bridge-failover signaling) — separate, larger scope; `stall_watchdog`
  (`engine.rs`) already covers the minimal "force a rebuild after a sustained stall" case.
- Lowering `max_fails`/`max_circuit_fails`/`fail_window_mins`/`min_alive` defaults for Android
  specifically — start with the CLI's proven defaults, tune later only if live data shows Android's
  smaller bridge pool needs different thresholds.

## Verification plan (once implemented)

1. Unit tests: `BridgeStore::note_probe_round`'s pruning is already covered
   (`packages/bridge-store/src/lib.rs` tests) — no new Rust-side test needed for the pruning logic
   itself, only for the new JNI surface (if (a) is chosen) and the min_alive trigger condition.
2. Live device test: seed `Prefs.bridgesList` with a mix of known-dead and known-alive bridges (reuse
   the reference CLI's `tor-socks5.alive-bridges.log` for a currently-alive set, as done in this
   session's investigation), connect repeatedly, confirm dead ones disappear from `Prefs.bridgesList`
   over a few connect cycles and the journal logs each removal.
3. Confirm `guards.json` entry count stays bounded over many connect/disconnect cycles instead of
   growing monotonically (compare entry count before/after a day of testing).
