//! Bridge reachability probing and arti `Settings` construction.
//!
//! Shared by the server startup path ([`crate::server::run_server`]) and
//! the `bridges fetch` command ([`crate::bridges_cmd::cmd_bridges`]).

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use arti_wrapper::Settings;
use bridge_line::BridgeLine;
use time::OffsetDateTime;
use tracing::{info, warn};

use crate::bridge_store::BridgeStore;
use crate::config::Config;

/// How long each bridge gets to complete a TCP handshake before we declare
/// it unreachable for this startup. The probes run in parallel, so the
/// total wait is bounded by this value, not multiplied by the bridge count.
pub(crate) const BRIDGE_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Parse the configured bridges, probe them for reachability, persist the
/// live ones to the alive-bridges log, and assemble arti [`Settings`]
/// (including pointing the PT manager at our own binary when needed).
pub(crate) async fn build_tor_settings(
    cfg: &Config,
    config_path: Option<&Path>,
) -> Result<Settings> {
    let parsed = cfg
        .bridges
        .parsed()
        .context("parsing bridges from config")?;
    if parsed.duplicates > 0 {
        warn!(
            duplicates = parsed.duplicates,
            unique = parsed.bridges.len(),
            "config contains duplicate bridge entries — skipped"
        );
    }
    let parsed_bridges = parsed.bridges;
    // Everything we attempt this round, for the health store. Starts with
    // the configured bridges (covers both obfs4 and webtunnel — the store
    // is transport-agnostic) and grows if we fall back to seeds.
    let mut probed: Vec<BridgeLine> = parsed_bridges.clone();

    // Probe configured bridges and keep only the reachable ones, sorted
    // by latency (fastest first). Arti's guard manager tries bridges
    // roughly in list order with long per-bridge back-offs, so a list
    // pre-filtered by reachability dramatically speeds up cold start when
    // some configured bridges are dead.
    let mut alive = if parsed_bridges.is_empty() {
        Vec::new()
    } else {
        info!(
            count = parsed_bridges.len(),
            timeout_ms = BRIDGE_PROBE_TIMEOUT.as_millis() as u64,
            "probing configured bridge reachability"
        );
        bridge_probe::probe_and_sort(parsed_bridges, BRIDGE_PROBE_TIMEOUT).await
    };

    // Chicken-and-egg fallback: if no configured bridge is reachable,
    // probe the binary's built-in seed bridges so a fresh or stale config
    // can still bootstrap. `auto_fetch` will then replenish the config.
    if alive.is_empty() && cfg.bridges.use_seeds {
        let seeds = crate::seed::seed_bridges(config_path);
        if !seeds.is_empty() {
            warn!(
                count = seeds.len(),
                "no configured bridge is reachable — falling back to seed bridges (*.seeds)"
            );
            probed.extend(seeds.clone());
            alive = bridge_probe::probe_and_sort(seeds, BRIDGE_PROBE_TIMEOUT).await;
        }
    }

    // Update bridge health (success resets, failure bumps once per window)
    // and prune any bridge that reached `max_fails` — from both the store
    // and the config. Best-effort: never fails the bootstrap.
    // Bootstrap path: no observation sink yet — arti hasn't started
    // emitting per-guard usability events when build_tor_settings runs.
    let store = update_health_and_prune(config_path, &probed, &alive, cfg, None);

    // Order the reachable bridges — obfs4 and webtunnel together — by
    // stability then ping: most-proven first (`ok_count`), ties broken by
    // lowest latency. arti tries bridges roughly in list order, so the most
    // reliable + fastest bridge becomes the first guard it reaches for.
    if let Some(store) = &store {
        alive.sort_by(|(ba, la), (bb, lb)| {
            store
                .ok_count(bb)
                .cmp(&store.ok_count(ba))
                .then_with(|| la.cmp(lb))
        });
    }

    if alive.is_empty() {
        bail!(
            "no reachable bridge responded to a TCP handshake within {BRIDGE_PROBE_TIMEOUT:?} \
             (configured bridges{})",
            if cfg.bridges.use_seeds {
                " and built-in seeds"
            } else {
                ""
            }
        );
    }

    let bridges: Vec<_> = alive.into_iter().map(|(bridge, _)| bridge).collect();

    // When any bridge needs a pluggable transport we point arti's
    // `tor-ptmgr` at our own executable: re-spawning it with the
    // standard `TOR_PT_*` env vars trips the busybox dispatch at the
    // top of `main()` and runs the in-process lyrebird PT loop.
    let needs_pt = bridges.iter().any(|b| b.transport.is_some());
    let pt_binary = if needs_pt {
        Some(resolve_pt_binary()?)
    } else {
        None
    };

    // Keep arti's state/cache app-local (next to the config when we have a
    // path, else `./arti-data`). Shared OS-default arti dirs persist a guard
    // sample / cached consensus across runs that can shadow our bridges.
    let arti_base = match config_path.and_then(Path::parent) {
        Some(dir) if !dir.as_os_str().is_empty() => dir.join("arti-data"),
        _ => std::path::PathBuf::from("arti-data"),
    };

    Ok(Settings {
        bridges,
        pt_binary,
        state_dir: Some(arti_base),
    })
}

/// Update the on-disk bridge health store with this probe round's outcome
/// and prune bridges that have reached `max_fails` — both from the store
/// and from the config file. Best-effort: logs and returns on any error,
/// never propagating (bootstrap must not fail because health bookkeeping
/// did).
pub(crate) fn update_health_and_prune(
    config_path: Option<&Path>,
    probed: &[BridgeLine],
    alive: &[(BridgeLine, Duration)],
    cfg: &Config,
    observation_sink: Option<&crate::arti_observability::ObservationSink>,
) -> Option<BridgeStore> {
    let store_path = BridgeStore::resolve_path(config_path);
    let mut store = match BridgeStore::load(store_path.clone()) {
        Ok(s) => s,
        Err(e) => {
            warn!(path = %store_path.display(), error = %e, "could not load bridge health store");
            return None;
        }
    };

    let now = OffsetDateTime::now_utc();
    let window = Duration::from_secs(cfg.bridges.fail_window_mins.saturating_mul(60));
    let circuit_window = Duration::from_secs(
        cfg.bridges
            .circuit_observation_window_mins
            .saturating_mul(60),
    );

    // Phase 1: TCP-layer health (probe round). Bumps `fails` once per
    // `fail_window`, resets on TCP success. Also handles circuit-layer
    // pruning via `cfg.bridges.max_circuit_fails`.
    let pruned = store.note_probe_round(
        probed,
        alive,
        now,
        window,
        cfg.bridges.max_fails,
        cfg.bridges.max_circuit_fails,
    );

    // Phase 2: circuit-layer observations from arti's tracing. Drain the
    // sink into the store so accumulated per-guard usability events bump
    // `circuit_fails` (rate-limited by `circuit_observation_window`) or
    // reset it. The sink is best-effort: a maintenance loop without one
    // (e.g. unit tests, the `bridges fetch` command) simply skips this
    // step.
    if let Some(sink) = observation_sink {
        let (failures, successes, unmatched) =
            sink.drain_into_store(&mut store, probed, now, circuit_window);
        if failures + successes + unmatched > 0 {
            info!(
                failures,
                successes, unmatched, "drained circuit-layer guard observations"
            );
        }
    }

    match store.save() {
        Ok(()) => info!(
            path = %store.path().display(),
            total = store.len(),
            "bridge health store updated"
        ),
        Err(e) => warn!(error = %e, "could not persist bridge health store"),
    }

    if !pruned.is_empty() {
        if let Some(path) = config_path {
            match prune_bridges_from_config(path, &pruned) {
                Ok(n) if n > 0 => info!(
                    removed = n,
                    path = %path.display(),
                    "removed dead bridges (reached max_fails) from config"
                ),
                Ok(_) => {}
                Err(e) => warn!(error = %e, "could not prune dead bridges from config"),
            }
        }
    }

    Some(store)
}

/// Remove the given (dead) bridges from `bridges.lines` in the config file
/// on disk, matched by `(transport, addr, fingerprint)`. Unparseable lines
/// are left untouched. Returns the number of lines removed.
fn prune_bridges_from_config(path: &Path, dead: &[BridgeLine]) -> Result<usize> {
    use std::collections::HashSet;
    let dead_keys: HashSet<(Option<String>, SocketAddr, Option<String>)> = dead
        .iter()
        .map(|b| (b.transport.clone(), b.addr, b.fingerprint.clone()))
        .collect();

    let mut cfg = Config::load_with_override(Some(path))
        .context("reloading config to prune dead bridges")?
        .into_config();
    let before = cfg.bridges.lines.len();
    cfg.bridges
        .lines
        .retain(|line| match line.parse::<BridgeLine>() {
            Ok(b) => !dead_keys.contains(&(b.transport.clone(), b.addr, b.fingerprint.clone())),
            Err(_) => true,
        });
    let removed = before - cfg.bridges.lines.len();
    if removed > 0 {
        cfg.write(path).context("writing pruned config")?;
    }
    Ok(removed)
}

/// Pure decision function: extract PT binary path from an optional env var value.
/// Returns `None` for `None` or empty `OsStr`; `Some(PathBuf)` for non-empty values.
/// This is testable without touching process state.
fn pt_binary_override_from(value: Option<&std::ffi::OsStr>) -> Option<std::path::PathBuf> {
    match value {
        Some(v) if !v.is_empty() => Some(std::path::PathBuf::from(v)),
        _ => None,
    }
}

/// Resolve the PT binary path for arti's `tor-ptmgr` to spawn.
///
/// Precedence:
/// 1. `TOR_PT_BINARY` env var (non-empty) — used for embedding hosts (Android JNI)
///    and packaging layouts that rename/split the binary. Both control the process
///    environment before startup, and `TOR_PT_*` env vars are this codebase's idiom
///    for PT concerns (see the `TOR_PT_MANAGED_TRANSPORT_VER` busybox dispatch in
///    `main.rs`). The ktav config file is a CLI-app concern.
/// 2. Fallback: `std::env::current_exe()` — the busybox dispatch (same binary,
///    invoked with `TOR_PT_*` env vars to run lyrebird in-process).
///
/// Library consumers already have the programmatic override
/// `arti_wrapper::Settings::pt_binary` and are unaffected.
///
/// Returns an error only if `current_exe()` fails (e.g., on wasm or stripped
/// binaries without runtime metadata). Existence validation is deferred to
/// `arti_wrapper::build_config`, which rejects a non-existent path with
/// `TorError::InvalidPt`.
fn resolve_pt_binary() -> anyhow::Result<std::path::PathBuf> {
    if let Some(path) = pt_binary_override_from(std::env::var_os("TOR_PT_BINARY").as_deref()) {
        info!(path = %path.display(), "using TOR_PT_BINARY override as PT binary");
        return Ok(path);
    }

    let exe = std::env::current_exe().context("resolving current_exe for PT")?;
    info!(path = %exe.display(), "using own binary as PT (busybox dispatch)");
    Ok(exe)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pt_binary_override_from_set() {
        let path = std::path::PathBuf::from("/usr/bin/obfs4proxy");
        let result = pt_binary_override_from(Some(path.as_os_str()));
        assert_eq!(result, Some(path));
    }

    #[test]
    fn test_pt_binary_override_from_none() {
        let result = pt_binary_override_from(None);
        assert_eq!(result, None);
    }

    #[test]
    fn test_pt_binary_override_from_empty() {
        let result = pt_binary_override_from(Some(std::ffi::OsStr::new("")));
        assert_eq!(result, None);
    }
}
