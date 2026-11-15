# tor-socks5-runtime

The internal runtime module tree of the `tor-socks5` proxy binary — Tor bootstrap setup, bridge maintenance (ranking, channel probes, candidate pooling), bridge store writing, circuit verification, warming, fetch merging, conn health counters and the Tor watchdog — moved as-is out of the binary (SDK-6, docs/plans/sdk-coverage-plan.md). Behavior-neutral: the binary links this crate and keeps its own CLI/server/commands code.

Not published: the release artifact is the single `tor-socks5` package; consumers take the facade by git. The public surface is the Tor client API of SDK-9 (see below); the bridge health writer and observation layer (SDK-7) and the bridge manager (SDK-8, see below) are also open.

The `test-seams` feature is dev-only: it is enabled solely through consumers' dev-dependencies so tests in other crates can drive the same internal seams the binary's tests use (R10). Never enable it in default/full builds.

## Tor client API (SDK-9)

The SDK-9 step opens the Tor client surface of this crate. Everything below
is public now:

- `tor_setup` — builds arti `Settings` from the ktav config file with
  `build_tor_settings(cfg, config_path)`; the probing of bridges, the
  preferred-pool fallbacks and the built-in seed fallbacks, the health-store
  updates and the pruning of dead bridges all happen inside.
  `build_tor_settings_with_pt(cfg, config_path, pt)` takes the
  pluggable-transport binary as an argument; `arti_base_dir` and
  `restricted_owner_settings`/`validate_owner_routes` cover the state dir
  and the owner-routing relatives.
- `pt` — the pluggable-transport entry point, `PtBinary`. `Environment` (the
  default) resolves `TOR_PT_BINARY` or else spawns the process's own
  executable, which busybox-dispatches on `TOR_PT_MANAGED_TRANSPORT_VER`;
  `Explicit(path)` is the dispatcher of the embedding host, such as this
  repository's `apps/pt-helper` build. The path's existence is not checked
  here — arti validates it later and reports `TorError::InvalidPt`.
- `tor_watchdog` — the live-client handle (`TorHandle`), the health reading
  (`TorHealth`, including `last_success_secs` and `attempt_count`), the
  bridge-refresh signal (`BridgeRefresh`) and the watchdog spawns:
  `spawn_tor_watchdog` returns `None` when disabled or a `WatchdogRun`
  whose `join` is joined at shutdown and whose `status` is a
  `tokio::sync::watch::Receiver<WatchdogStatus>` (checks started,
  consecutive heal failures, the last `HealOutcome`); 
  `spawn_bridge_failover_watchdog` for the soft-failover signals;
  `classify_and_record` for failure classification.
- `conn_health` — `ConnHealthCounters` with windowed
  `ConnHealthSnapshot`s via `snapshot_and_reset()`, the error/stage kinds
  (`ConnErrorKind`, `ConnStage`), the pending-connection guard and the
  optional periodic logger (`spawn_conn_health_logger`).

Restart contract (plan decision D5): what this surface opens is one live Tor
client per process; sequential stop-then-start works. Concurrent clients or
restart-in-parallel are not supported.

The bridge health writer and the guard-observation layer (SDK-7) are part of
the facade's `runtime` module too; the bridge manager (SDK-8) — see below.

## Bridge manager (SDK-8)

The SDK-8 step opens the bridge manager: one handle owning the runtime's
background bridge producers, plus the `bridges fetch` core as a library
function.

- `bridge_manager::start(handle, config_path, cfg, observations, settings)`
  spawns the producers the binary would spawn — `bridge_maintenance`, plus
  `bridge_warmer` and `bridge_verifier` when the pre-endpoint branch is not
  active (there only maintenance runs, and the same warning is logged) — and
  returns a `BridgeManagerHandle`: `token()` (the cancellation token driving
  every producer), `status()`/`subscribe()` (`BridgeManagerStatus` via a
  `tokio::sync::watch`: producer names and whether shutdown happened) and
  `shutdown().await`, which cancels the token and awaits every producer so
  in-flight work (probe batches, store writes) lands. Dropping the handle
  cancels the token without blocking.
- `bridge_manager::fetch_bridges(cfg, config_path, FetchBridgesParams)` is
  the core of the CLI's `bridges fetch` command: bootstrap Tor from the
  configured bridges (built-in seeds as fallback), refresh the candidate
  pool from the configured HTTPS sources, optionally probe-and-promote
  (`FetchBridgesParams { timeout, count, probe, cancel }`), and merge into
  the config; returns `FetchBridgesOutcome { added, promoted, pool_len }`.
  Not cancel-safe: cancellation aborts network I/O and file writes mid-way
  and skips the trailing 200 ms post-drop sleep.

The watchdog producers (`spawn_tor_watchdog`,
`spawn_bridge_failover_watchdog`) belong to the server tree, not to this
manager; a host composes them alongside. Shutdown order for a correct
restart: `shutdown()` first, then `bridge_store_writer::close_global`.

Restart contract (plan decision D5): one live manager per process — the
producers' shared state (writer slot, blocking-worker registry, verify lock,
save counter) is process-wide; sequential stop-then-start works.

## Patched Arti (patch-kit)

This crate reaches Arti through `arti-wrapper`; the workspace builds only
with the vendored forks under `vendor/`, applied by the root
`[patch.crates-io]` (8 crates, see `vendor/README.md`). An application that
links this crate — directly, or through the facade's `runtime` feature —
takes it by git, not crates.io, and **must** carry the `[patch.crates-io]`
block from `vendor/README.md` in its final binary/workspace root. Without
it Cargo silently resolves stock Arti and the local fixes are lost: the
bounded bridge-descriptor fetch, stale-channel termination, PT shutdown
receipt, guard readiness and the Windows saturating-time loop. Verify with
`cargo tree -i tor-dirclient`.
