//! Bridge reachability probing and arti `Settings` construction.
//!
//! Shared by the server startup path ([`crate::server::run_server`]) and
//! the `bridges fetch` command ([`crate::bridges_cmd::cmd_bridges`]).

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use arti_wrapper::Settings;
use bridge_line::BridgeLine;
use bridge_probe::{bridge_identity, BridgeIdentity};
use time::OffsetDateTime;
use tracing::{info, warn};

use crate::config::Config;
use crate::path_lock::{PathLock, CLI_LOCK_WAIT};
use bridge_store::BridgeStore;

/// How long each bridge gets to complete a TCP handshake before we declare
/// it unreachable for this startup. The probes run in parallel, so the
/// total wait is bounded by this value, not multiplied by the bridge count.
pub(crate) const BRIDGE_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Keep the startup probe bounded when the configured list is large (a
/// full auto-fetched pool can run into the thousands). The complete list
/// remains the background pool that `spawn_bridge_maintenance` re-probes
/// periodically; only the best-known slice participates in the
/// latency-sensitive startup path. Mirrors `android-ffi`'s
/// `MAX_ACTIVE_BRIDGES`.
const MAX_ACTIVE_BRIDGES: usize = 30;

/// Parse the configured bridges, probe them for reachability, persist the
/// live ones to the alive-bridges log, and assemble arti [`Settings`]
/// (including pointing the PT manager at our own binary when needed).
pub(crate) async fn build_tor_settings(
    cfg: &Config,
    config_path: Option<&Path>,
) -> Result<Settings> {
    build_tor_settings_preserving_live(cfg, config_path, &[]).await
}

pub(crate) async fn build_tor_settings_preserving_live(
    cfg: &Config,
    config_path: Option<&Path>,
    live: &[BridgeLine],
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
    if parsed.rejected > 0 {
        warn!(
            rejected = parsed.rejected,
            configured = cfg.bridges.lines.len(),
            "ignored documentation/local-only bridge addresses"
        );
    }
    let mut parsed_bridges = parsed.bridges;
    if let Ok(store) = BridgeStore::load(BridgeStore::resolve_path(config_path)) {
        parsed_bridges.retain(|bridge| {
            !store.is_retired(bridge) && store.circuit_fails(bridge) < cfg.bridges.max_circuit_fails
        });
    }

    // Exhaust the preferred pool before considering obfs4 fallback.
    let preferred_bridges = preferred_transport_bridges(&parsed_bridges, cfg);
    let active_probe_bridges = select_active_probe_bridges(&preferred_bridges, config_path);
    let probing_all_preferred = active_probe_bridges.len() == preferred_bridges.len();

    // Everything we attempt this round, for the health store. Starts with
    // the bridges actually probed this round (covers both obfs4 and
    // webtunnel — the store is transport-agnostic) and grows if we fall
    // back to the full preferred pool or to seeds.
    let mut probed: Vec<BridgeLine> = Vec::new();

    // Probe the active pool and keep only the reachable ones, sorted by
    // latency (fastest first). Arti's guard manager tries bridges roughly
    // in list order with long per-bridge back-offs, so a list pre-filtered
    // by reachability dramatically speeds up cold start when some
    // configured bridges are dead.
    let mut alive = if active_probe_bridges.is_empty() {
        Vec::new()
    } else {
        info!(
            count = active_probe_bridges.len(),
            configured = parsed_bridges.len(),
            timeout_ms = BRIDGE_PROBE_TIMEOUT.as_millis() as u64,
            "probing active bridge pool for reachability"
        );
        let (measured, alive) = probe_measured(active_probe_bridges, cfg).await;
        probed.extend(measured);
        alive
    };

    // Check the rest of the preferred pool before declaring it unavailable.
    if let Some(pool) =
        fallback_probe_pool(alive.is_empty(), &preferred_bridges, probing_all_preferred)
    {
        info!(
            count = pool.len(),
            "active bridge pool was unreachable; probing full preferred pool as fallback"
        );
        let (measured, fallback_alive) = probe_measured(pool, cfg).await;
        probed.extend(measured);
        alive = fallback_alive;
    }

    if alive.is_empty() && live.is_empty() && cfg.bridges.preferred_transport() == Some("webtunnel")
    {
        let probed_keys: HashSet<BridgeIdentity> = probed.iter().map(bridge_identity).collect();
        let fallback: Vec<_> = parsed_bridges
            .iter()
            .filter(|b| {
                b.transport.as_deref() == Some("obfs4")
                    && !probed_keys.contains(&bridge_identity(b))
            })
            .cloned()
            .collect();
        if !fallback.is_empty() {
            warn!("no reachable WebTunnel bridges; probing obfs4 fallback");
            let (measured, fallback_alive) = probe_measured(fallback, cfg).await;
            probed.extend(measured);
            alive = fallback_alive;
        }
    }

    // Chicken-and-egg fallback: if no configured bridge is reachable,
    // probe the binary's built-in seed bridges so a fresh or stale config
    // can still bootstrap. `auto_fetch` will then replenish the config.
    if alive.is_empty() && live.is_empty() && cfg.bridges.use_seeds {
        let seeds = crate::seed::seed_bridges(config_path);
        if !seeds.is_empty() {
            warn!(
                count = seeds.len(),
                "no configured bridge is reachable — falling back to seed bridges (*.seeds)"
            );
            let (measured, seed_alive) = probe_measured(seeds, cfg).await;
            probed.extend(measured);
            alive = seed_alive;
        }
    }

    // Update bridge health (success resets, failure bumps once per window)
    // and prune any bridge that reached `max_fails` — from both the store
    // and the config. Best-effort: never fails the bootstrap.
    // Bootstrap path: no observation sink yet — arti hasn't started
    // emitting per-guard usability events when build_tor_settings runs.
    // Failure to open another transport connection does not invalidate live traffic.
    retain_probe_observations(&mut probed, live, &alive);
    // note_probe_round must see the original pre-retain probe results.
    let probed_alive = alive.clone();
    let allowed = preferred_transport_bridges(
        &alive
            .iter()
            .map(|(bridge, _)| bridge.clone())
            .collect::<Vec<_>>(),
        cfg,
    );
    retain_allowed_alive(&mut alive, &allowed);
    let candidates: Vec<_> = alive.iter().map(|(bridge, _)| bridge.clone()).collect();

    // Update bridge health (success resets, failure bumps once per window)
    // and prune any bridge that reached `max_fails` — from both the store
    // and the config. Routed through the single bridge-store writer.
    // Best-effort: never fails the bootstrap.
    // Bootstrap path: no observation sink yet — arti hasn't started
    // emitting per-guard usability events when build_tor_settings runs.
    // Failure to open another transport connection does not invalidate live traffic.
    if let Some(ranked) =
        update_health_and_prune(config_path, &probed, &probed_alive, cfg, None, &candidates).await
    {
        // Full-circuit and channel evidence outrank repeated TCP probes.
        retain_and_rank_alive(&mut alive, &ranked);
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
    let arti_base = arti_base_dir(config_path);

    Ok(Settings {
        bridges,
        pt_binary,
        extra_pt_protocols: if pt_binary_override_from(std::env::var_os("TOR_PT_BINARY").as_deref())
            .is_none()
        {
            vec!["obfs4".into(), "webtunnel".into()]
        } else {
            cfg.bridges
                .preferred_transport()
                .into_iter()
                .map(str::to_owned)
                .collect()
        },
        state_dir: Some(arti_base),
        obfs4_iat_mode: cfg.bridges.iat_mode_override(),
        ..Default::default()
    })
}

/// The arti state base dir `build_tor_settings` hands to arti: next to the
/// config file when we have a path, else `./arti-data`. Extracted so the
/// background circuit-verify task (`bridge_verifier.rs`) derives the live
/// client's cache dir (`base.join("cache")`, per `arti_wrapper::build_config`)
/// from the same logic and cannot drift from the actually-running client.
pub(crate) fn arti_base_dir(config_path: Option<&Path>) -> std::path::PathBuf {
    match config_path.and_then(Path::parent) {
        Some(dir) if !dir.as_os_str().is_empty() => dir.join("arti-data"),
        _ => std::path::PathBuf::from("arti-data"),
    }
}

/// Narrow the startup pool to the configured preferred transport, if any.
///
/// Deliberately a preference, not a filter: an unmatched preference
/// (nothing configured uses it) falls back to the full list rather than
/// probing nothing — asking for a transport the pool does not contain
/// should not amount to asking for nothing. The reverse does not hold: a
/// preference matching bridges that then all fail at probing is not
/// rescued by other transports — it fails through to the seeds branch or
/// the hard error.
pub(crate) fn preferred_transport_bridges(
    configured: &[BridgeLine],
    cfg: &Config,
) -> Vec<BridgeLine> {
    let Some(preferred) = cfg.bridges.preferred_transport() else {
        return configured.to_vec();
    };
    let matching: Vec<BridgeLine> = configured
        .iter()
        .filter(|bridge| bridge.transport.as_deref() == Some(preferred))
        .cloned()
        .collect();
    if matching.is_empty() {
        warn!(
            preferred,
            configured = configured.len(),
            "no bridge uses the preferred transport; using the full pool"
        );
        return configured
            .iter()
            .filter(|bridge| {
                preferred != "webtunnel" || bridge.transport.as_deref() == Some("obfs4")
            })
            .cloned()
            .collect();
    }
    info!(
        preferred,
        matching = matching.len(),
        configured = configured.len(),
        "restricted startup pool to the preferred transport"
    );
    matching
}

pub(crate) async fn probe_measured(
    bridges: Vec<BridgeLine>,
    cfg: &Config,
) -> (Vec<BridgeLine>, Vec<(BridgeLine, Duration)>) {
    let round = bridge_probe::probe_round_with_policy(
        bridges.clone(),
        BRIDGE_PROBE_TIMEOUT,
        bridge_probe::ResolverPolicy {
            doh_enabled: cfg.dns.doh_enabled,
            system_fallback: cfg.dns.system_fallback,
        },
    )
    .await;
    let measured = filter_measured(bridges, &round.unmeasured);
    (measured, round.alive)
}

fn filter_measured(bridges: Vec<BridgeLine>, unmeasured: &[BridgeLine]) -> Vec<BridgeLine> {
    let unmeasured_keys: HashSet<BridgeIdentity> = unmeasured.iter().map(bridge_identity).collect();
    bridges
        .into_iter()
        .filter(|bridge| !unmeasured_keys.contains(&bridge_identity(bridge)))
        .collect()
}

fn retain_probe_observations(
    probed: &mut Vec<BridgeLine>,
    live: &[BridgeLine],
    alive: &[(BridgeLine, Duration)],
) {
    let live_keys: HashSet<BridgeIdentity> = live.iter().map(bridge_identity).collect();
    let alive_keys: HashSet<BridgeIdentity> = alive
        .iter()
        .map(|(bridge, _)| bridge_identity(bridge))
        .collect();
    probed.retain(|bridge| {
        let key = bridge_identity(bridge);
        !live_keys.contains(&key) || alive_keys.contains(&key)
    });
}

fn retain_allowed_alive(alive: &mut Vec<(BridgeLine, Duration)>, allowed: &[BridgeLine]) {
    let allowed_keys: HashSet<BridgeIdentity> = allowed.iter().map(bridge_identity).collect();
    alive.retain(|(bridge, _)| allowed_keys.contains(&bridge_identity(bridge)));
}

fn retain_and_rank_alive(alive: &mut Vec<(BridgeLine, Duration)>, ranked: &[BridgeLine]) {
    let mut rank_by_identity = HashMap::with_capacity(ranked.len());
    for (rank, bridge) in ranked.iter().enumerate() {
        rank_by_identity
            .entry(bridge_identity(bridge))
            .or_insert(rank);
    }
    alive.retain(|(bridge, _)| rank_by_identity.contains_key(&bridge_identity(bridge)));
    alive.sort_by_cached_key(|(bridge, _)| {
        rank_by_identity
            .get(&bridge_identity(bridge))
            .copied()
            .unwrap_or(usize::MAX)
    });
}

/// Choose the small, latency-sensitive startup pool from the persisted
/// bridge ranking (mirrors `android-ffi`'s `select_active_probe_bridges`).
///
/// `configured` is intentionally not reduced beyond the returned slice for
/// anyone else's bookkeeping: `build_tor_settings`'s fallback sees the
/// complete preferred list, while `spawn_bridge_maintenance`'s periodic
/// re-probe still sees the complete configured list. A missing or stale
/// health store falls back to the first
/// bounded slice; the caller performs a full probe only when that slice
/// produces no reachable bridge.
fn select_active_probe_bridges(
    configured: &[BridgeLine],
    config_path: Option<&Path>,
) -> Vec<BridgeLine> {
    if configured.len() <= MAX_ACTIVE_BRIDGES {
        return configured.to_vec();
    }

    let by_text: HashMap<String, BridgeLine> = configured
        .iter()
        .map(|bridge| (bridge.to_string(), bridge.clone()))
        .collect();
    let store_path = BridgeStore::resolve_path(config_path);
    if let Ok(store) = BridgeStore::load(store_path) {
        let ranked: Vec<BridgeLine> = store
            .healthiest_among(configured, MAX_ACTIVE_BRIDGES)
            .into_iter()
            .filter_map(|bridge| by_text.get(&bridge.to_string()).cloned())
            .collect();
        if !ranked.is_empty() {
            return ranked;
        }
    }

    configured
        .iter()
        .take(MAX_ACTIVE_BRIDGES)
        .cloned()
        .collect()
}

/// The pool to re-probe when the active slice produced no reachable bridge:
/// the complete preferred-transport list, or `None` when no fallback probe
/// is due.
///
/// Deliberately never the full configured list: when a transport preference
/// matched anything, a currently-dead preferred slice must not widen the
/// fallback across transports (upstream `82a3d76` — a matching preference
/// that fails is reported as-is, not silently answered by another
/// transport). When the preference matched nothing, `preferred_bridges`
/// already IS the full pool, so nothing widens there either. `None` is
/// returned when the active slice is still alive, or when the startup
/// probe already covered the whole preferred pool (a retry could only
/// repeat it).
fn fallback_probe_pool(
    active_slice_dead: bool,
    preferred_bridges: &[BridgeLine],
    probing_all_preferred: bool,
) -> Option<Vec<BridgeLine>> {
    if !active_slice_dead || probing_all_preferred {
        return None;
    }
    Some(preferred_bridges.to_vec())
}

/// Update the bridge health store (via the single writer) with this probe
/// round's outcome, drain any observation sink, and prune bridges that have
/// reached `max_fails` — both from the store and from the config file.
/// Returns the ranked candidate list, or `None` when the on-disk store
/// could not be read (publish failures are the writer's retry problem).
/// Best-effort: never fails the bootstrap.
pub(crate) async fn update_health_and_prune(
    config_path: Option<&Path>,
    probed: &[BridgeLine],
    alive: &[(BridgeLine, Duration)],
    cfg: &Config,
    observation_sink: Option<&crate::arti_observability::ObservationSink>,
    candidates: &[BridgeLine],
) -> Option<Vec<BridgeLine>> {
    let window = Duration::from_secs(cfg.bridges.fail_window_mins.saturating_mul(60));
    let circuit_window = Duration::from_secs(
        cfg.bridges
            .circuit_observation_window_mins
            .saturating_mul(60),
    );
    let max_fails = cfg.bridges.max_fails;
    let max_circuit_fails = cfg.bridges.max_circuit_fails;

    let probed = probed.to_vec();
    let alive = alive.to_vec();
    let candidates = candidates.to_vec();
    let sink = observation_sink.cloned();
    let pruned = Arc::new(Mutex::new(Vec::new()));
    let ranked = Arc::new(Mutex::new(Vec::new()));
    let total = Arc::new(Mutex::new(0usize));
    let result = crate::bridge_store_writer::apply(config_path, {
        let pruned = pruned.clone();
        let ranked = ranked.clone();
        let total = total.clone();
        move |store| {
            let now = OffsetDateTime::now_utc();

            // Phase 1: TCP-layer health (probe round). Bumps `fails` once per
            // `fail_window`, resets on TCP success. Also handles circuit-layer
            // pruning via `max_circuit_fails`.
            *pruned.lock().unwrap() =
                store.note_probe_round(&probed, &alive, now, window, max_fails, max_circuit_fails);

            // Phase 2: circuit-layer observations from arti's tracing. Drain the
            // sink into the store so accumulated per-guard usability events bump
            // `circuit_fails` (rate-limited by `circuit_observation_window`) or
            // reset it. The sink is best-effort: a maintenance loop without one
            // (e.g. unit tests, the `bridges fetch` command) simply skips this
            // step.
            if let Some(sink) = &sink {
                let (failures, successes, unmatched) =
                    sink.drain_into_store(store, &probed, now, circuit_window);
                if failures + successes + unmatched > 0 {
                    info!(
                        failures,
                        successes, unmatched, "drained circuit-layer guard observations"
                    );
                }
            }

            *ranked.lock().unwrap() = store.healthiest_among(&candidates, MAX_ACTIVE_BRIDGES);
            *total.lock().unwrap() = store.len();
        }
    })
    .await;
    match result {
        Ok(()) => info!(
            total = *total.lock().unwrap(),
            "bridge health store updated"
        ),
        Err(e) => {
            warn!(error = %e, "could not update bridge health store");
            return None;
        }
    }

    let pruned = Arc::try_unwrap(pruned)
        .map(|lock| lock.into_inner().unwrap())
        .unwrap_or_default();
    if !pruned.is_empty() {
        if let Some(path) = config_path {
            let path = path.to_path_buf();
            let log_path = path.clone();
            let dead = pruned.clone();
            match tokio::task::spawn_blocking(move || prune_bridges_from_config(&path, &dead)).await
            {
                Ok(Ok(n)) if n > 0 => info!(
                    removed = n,
                    path = %log_path.display(),
                    "removed dead bridges (reached max_fails) from config"
                ),
                Ok(Ok(_)) => {}
                Ok(Err(e)) => warn!(error = %e, "could not prune dead bridges from config"),
                Err(e) => warn!(error = %e, "config prune task failed"),
            }
        }
    }

    let ranked = Arc::try_unwrap(ranked)
        .map(|lock| lock.into_inner().unwrap())
        .unwrap_or_default();
    Some(ranked)
}

/// Remove the given (dead) bridges from `bridges.lines` in the config file
/// on disk, matched by the full shared bridge identity. Unparseable lines are
/// left untouched. Returns the number of lines removed.
fn prune_bridges_from_config(path: &Path, dead: &[BridgeLine]) -> Result<usize> {
    use std::collections::HashSet;
    let dead_keys: HashSet<_> = dead.iter().map(bridge_identity).collect();

    let _lock = PathLock::acquire_bounded(path, CLI_LOCK_WAIT)
        .context("config write lock while pruning dead bridges")?;
    let mut cfg = Config::load_with_override(Some(path))
        .context("reloading config to prune dead bridges")?
        .into_config();
    let before = cfg.bridges.lines.len();
    cfg.bridges
        .lines
        .retain(|line| match line.parse::<BridgeLine>() {
            Ok(b) => !dead_keys.contains(&bridge_identity(&b)),
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
pub(crate) fn resolve_pt_binary() -> anyhow::Result<std::path::PathBuf> {
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

    fn obfs4_line(addr: &str) -> BridgeLine {
        format!("obfs4 {addr} ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0")
            .parse()
            .expect("valid obfs4 bridge line")
    }

    fn webtunnel_line(addr: &str) -> BridgeLine {
        format!(
            "webtunnel {addr} ABCDEF0123456789ABCDEF0123456789ABCDEF01 url=https://example.com/x"
        )
        .parse()
        .expect("valid webtunnel bridge line")
    }

    const CERT_OLD: &str = "EREREREREREREREREREREREREREiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIg";
    const CERT_NEW: &str = "EREREREREREREREREREREREREREzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMw";

    fn prune_test_config_path() -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("tor-socks5-prune-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create prune test directory");
        dir.join("config.ktav")
    }

    fn webtunnel_variant(path: &str) -> BridgeLine {
        format!(
            "webtunnel 192.0.2.10:443 1111111111111111111111111111111111111111 url=https://edge.example{path}"
        )
        .parse()
        .expect("valid WebTunnel bridge line")
    }

    fn obfs4_variant(cert: &str) -> BridgeLine {
        format!(
            "obfs4 192.0.2.20:443 2222222222222222222222222222222222222222 cert={cert} iat-mode=0"
        )
        .parse()
        .expect("valid obfs4 bridge line")
    }

    #[test]
    fn prune_removes_only_dead_full_identity_and_preserves_neighbors() {
        let path = prune_test_config_path();
        let old_webtunnel = webtunnel_variant("/old");
        let new_webtunnel = webtunnel_variant("/new");
        let old_obfs4 = obfs4_variant(CERT_OLD);
        let new_obfs4 = obfs4_variant(CERT_NEW);
        let other_transport: BridgeLine = "192.0.2.20:443 2222222222222222222222222222222222222222"
            .parse()
            .expect("valid plain bridge line");
        let invalid = "this is not a bridge";

        let mut cfg = Config::default();
        cfg.bridges.lines = vec![
            old_webtunnel.to_string(),
            new_webtunnel.to_string(),
            old_obfs4.to_string(),
            new_obfs4.to_string(),
            other_transport.to_string(),
            invalid.to_owned(),
        ];
        cfg.write(&path).expect("save prune test config");

        let removed = prune_bridges_from_config(&path, &[old_webtunnel, old_obfs4])
            .expect("prune dead bridges");
        assert_eq!(removed, 2);

        let loaded = Config::load_with_override(Some(&path))
            .expect("reload pruned config")
            .into_config();
        assert_eq!(loaded.bridges.lines.len(), 4);
        assert!(loaded.bridges.lines.iter().any(|line| line == invalid));
        let parsed: Vec<BridgeLine> = loaded
            .bridges
            .lines
            .iter()
            .filter_map(|line| line.parse().ok())
            .collect();
        assert!(parsed.contains(&new_webtunnel));
        assert!(parsed.contains(&new_obfs4));
        assert!(parsed.contains(&other_transport));
        assert!(!parsed.contains(&webtunnel_variant("/old")));
        assert!(!parsed.contains(&obfs4_variant(CERT_OLD)));
        let _ = std::fs::remove_dir_all(path.parent().expect("test config parent"));
    }

    #[test]
    fn prune_waits_for_config_transaction_and_preserves_its_concurrent_addition() {
        let dir = tempfile::tempdir().expect("create config directory");
        let path = dir.path().join("config.ktav");
        let dead = webtunnel_variant("/dead");
        let survivor = webtunnel_variant("/survivor");
        let newcomer = obfs4_variant(CERT_NEW);
        let mut cfg = Config::default();
        cfg.bridges.lines = vec![dead.to_string(), survivor.to_string()];
        cfg.write(&path).expect("save config");

        // Hold the same path lock that a promotion/migration writer uses.
        // The prune worker must load after this transaction publishes, so the
        // newcomer cannot be lost to a stale snapshot.
        let lock = PathLock::acquire(&path).expect("acquire config lock");
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let prune_path = path.clone();
        let dead_for_worker = dead.clone();
        let worker = std::thread::spawn(move || {
            started_tx.send(()).expect("signal prune start");
            prune_bridges_from_config(&prune_path, std::slice::from_ref(&dead_for_worker))
        });
        started_rx.recv().expect("wait for prune worker");

        let mut latest = Config::load_with_override(Some(&path))
            .expect("load config under transaction lock")
            .into_config();
        latest.bridges.lines.push(newcomer.to_string());
        latest.write(&path).expect("publish concurrent addition");
        drop(lock);

        assert_eq!(worker.join().expect("join prune worker").unwrap(), 1);
        let final_cfg = Config::load_with_override(Some(&path))
            .expect("reload final config")
            .into_config();
        let parsed = final_cfg.bridges.parsed().expect("parse final bridges");
        assert!(!parsed.bridges.contains(&dead));
        assert!(parsed.bridges.contains(&survivor));
        assert!(parsed.bridges.contains(&newcomer));
    }

    #[test]
    fn preferred_transport_bridges_no_preference_keeps_full_list() {
        let bridges = vec![obfs4_line("1.2.3.4:443"), webtunnel_line("5.6.7.8:443")];
        let cfg = Config::default();
        assert_eq!(cfg.bridges.transport, "any");
        assert_eq!(preferred_transport_bridges(&bridges, &cfg), bridges);
    }

    #[test]
    fn preferred_transport_bridges_narrows_to_matching_transport() {
        let bridges = vec![
            obfs4_line("1.2.3.4:443"),
            webtunnel_line("5.6.7.8:443"),
            obfs4_line("9.10.11.12:443"),
        ];
        let cfg = Config {
            bridges: proxy_config::BridgesConfig {
                transport: "webtunnel".to_owned(),
                ..Default::default()
            },
            ..Default::default()
        };
        let narrowed = preferred_transport_bridges(&bridges, &cfg);
        assert_eq!(narrowed.len(), 1);
        assert_eq!(narrowed[0].transport.as_deref(), Some("webtunnel"));
    }

    #[test]
    fn preferred_transport_bridges_falls_back_when_nothing_matches() {
        let bridges = vec![obfs4_line("1.2.3.4:443")];
        let cfg = Config {
            bridges: proxy_config::BridgesConfig {
                transport: "webtunnel".to_owned(),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(preferred_transport_bridges(&bridges, &cfg), bridges);
    }

    #[test]
    fn select_active_probe_bridges_keeps_small_list_unchanged() {
        let bridges: Vec<BridgeLine> = (0..5)
            .map(|i| obfs4_line(&format!("10.0.0.{i}:443")))
            .collect();
        assert_eq!(select_active_probe_bridges(&bridges, None), bridges);
    }

    #[test]
    fn select_active_probe_bridges_bounds_large_list_without_a_health_store() {
        let bridges: Vec<BridgeLine> = (0..(MAX_ACTIVE_BRIDGES + 10))
            .map(|i| obfs4_line(&format!("10.0.{}.{}:443", i / 256, i % 256)))
            .collect();
        // A path with no sibling `.alive-bridges.log` behaves like a fresh
        // install: the health store loads empty, so this falls back to the
        // first `MAX_ACTIVE_BRIDGES` bridges in configured order.
        let missing_config = Path::new("/nonexistent/does-not-exist/tor-socks5.ktav");
        let active = select_active_probe_bridges(&bridges, Some(missing_config));
        assert_eq!(active.len(), MAX_ACTIVE_BRIDGES);
        assert_eq!(active, bridges[..MAX_ACTIVE_BRIDGES]);
    }

    #[test]
    fn fallback_probe_pool_stays_within_formed_preferred_transport() {
        // The webtunnel preference matched (the slice is non-empty), but the
        // whole slice comes back unreachable at probing, while live obfs4
        // bridges exist in the full configured pool. The fallback re-probe
        // must stay inside the preferred slice — never widen to obfs4.
        let configured = vec![
            obfs4_line("1.2.3.4:443"),
            webtunnel_line("5.6.7.8:443"),
            webtunnel_line("9.10.11.12:443"),
            obfs4_line("13.14.15.16:443"),
        ];
        let cfg = Config {
            bridges: proxy_config::BridgesConfig {
                transport: "webtunnel".to_owned(),
                ..Default::default()
            },
            ..Default::default()
        };
        let preferred_bridges = preferred_transport_bridges(&configured, &cfg);
        assert_eq!(preferred_bridges.len(), 2);

        let pool = fallback_probe_pool(true, &preferred_bridges, false)
            .expect("dead preferred slice must produce a fallback probe");
        assert_eq!(pool, preferred_bridges);
        assert!(
            pool.iter()
                .all(|b| b.transport.as_deref() == Some("webtunnel")),
            "fallback must not widen to other transports"
        );
    }

    #[test]
    fn fallback_probe_pool_skips_when_nothing_new_to_probe() {
        let preferred = vec![webtunnel_line("5.6.7.8:443")];
        // The startup probe already covered the whole preferred pool.
        assert_eq!(fallback_probe_pool(true, &preferred, true), None);
        // A still-live active slice never triggers the fallback.
        assert_eq!(fallback_probe_pool(false, &preferred, false), None);
    }

    #[test]
    fn probe_indexes_keep_full_endpoint_identity_and_rank_order() {
        let old_webtunnel = webtunnel_variant("/old");
        let new_webtunnel = webtunnel_variant("/new");
        let old_obfs4 = obfs4_variant(CERT_OLD);
        let new_obfs4 = obfs4_variant(CERT_NEW);

        let measured = filter_measured(
            vec![
                old_webtunnel.clone(),
                new_webtunnel.clone(),
                old_obfs4.clone(),
                new_obfs4.clone(),
            ],
            &[old_webtunnel.clone(), old_obfs4.clone()],
        );
        assert_eq!(measured, vec![new_webtunnel.clone(), new_obfs4.clone()]);

        let mut probed = vec![old_webtunnel.clone(), new_webtunnel.clone()];
        retain_probe_observations(
            &mut probed,
            std::slice::from_ref(&old_webtunnel),
            &[(new_webtunnel.clone(), Duration::from_millis(1))],
        );
        assert_eq!(probed, vec![new_webtunnel.clone()]);

        let mut allowed = vec![
            (old_webtunnel.clone(), Duration::from_millis(4)),
            (new_webtunnel.clone(), Duration::from_millis(4)),
        ];
        retain_allowed_alive(&mut allowed, std::slice::from_ref(&new_webtunnel));
        assert_eq!(allowed.len(), 1);
        assert_eq!(allowed[0].0, new_webtunnel);

        let mut ranked = vec![
            (old_obfs4.clone(), Duration::from_millis(2)),
            (new_obfs4.clone(), Duration::from_millis(2)),
        ];
        retain_and_rank_alive(&mut ranked, &[new_obfs4.clone(), old_obfs4.clone()]);
        assert_eq!(ranked[0].0, new_obfs4);
        assert_eq!(ranked[1].0, old_obfs4);

        let mut duplicate = vec![
            (new_obfs4.clone(), Duration::from_millis(1)),
            (old_obfs4.clone(), Duration::from_millis(9)),
            (old_obfs4.clone(), Duration::from_millis(3)),
        ];
        retain_and_rank_alive(&mut duplicate, &[old_obfs4.clone(), new_obfs4, old_obfs4]);
        assert_eq!(
            duplicate
                .iter()
                .map(|(_, latency)| *latency)
                .collect::<Vec<_>>(),
            vec![
                Duration::from_millis(9),
                Duration::from_millis(3),
                Duration::from_millis(1)
            ]
        );
    }
}
