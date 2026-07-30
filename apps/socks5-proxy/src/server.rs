//! The SOCKS5 listener runtime: egress selection, the accept loop, and
//! the per-connection handler.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use arti_wrapper::TorTunnel;
use auth::{AuthState, UsersConfig};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing::{debug, error, info, warn};

use crate::config::{Config, Loaded, UpstreamConfig};
use crate::conn_health::{spawn_conn_health_logger, ConnHealthCounters};
use crate::socks5::{self, Reply};
use crate::startup::{init_tracing, install_crypto_provider};
use crate::tor_setup::build_tor_settings;
use crate::tor_watchdog::{spawn_bridge_failover_watchdog, spawn_tor_watchdog, TorHandle};
use crate::{shutdown, upstream};

/// Maximum concurrent SOCKS5 connections. Each may run an Argon2id verify
/// (~5 MiB working memory, 2 passes), so unbounded spawns risk resource
/// exhaustion under connection floods.
const MAX_CONCURRENT_CONNECTIONS: usize = 256;

/// Where accepted connections egress. An enabled upstream SOCKS5 proxy
/// replaces Tor entirely.
#[derive(Clone)]
enum Egress {
    Tor(TorHandle),
    Upstream(Arc<upstream::Upstream>),
}

/// Inputs needed to run the SOCKS5 server, gathered from the CLI (or, in
/// the Windows-service case, synthesised from the installed image path).
pub(crate) struct ServerArgs {
    pub config_override: Option<std::path::PathBuf>,
    pub upstream_addr: Option<String>,
    pub upstream_user: Option<String>,
    pub upstream_pass: Option<String>,
    pub no_upstream: bool,
}

/// Run the proxy until `shutdown` resolves. Factored out of `main` so the
/// Windows-service runtime can drive it with an SCM-triggered shutdown
/// instead of a console signal.
pub(crate) async fn run_server(
    args: ServerArgs,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    let loaded = Config::load_with_override(args.config_override.as_deref())?;
    let (config_path, source) = match &loaded {
        Loaded::FromFile { path, .. } => (Some(path.clone()), format!("file: {}", path.display())),
        Loaded::Defaults(_) => (None, "built-in defaults".to_string()),
    };
    let cfg = loaded.into_config();

    // Held until the server shuts down so the non-blocking log writer
    // keeps flushing for the whole run. The observation sink captures
    // per-guard usability events from arti's tracing layer for the
    // bridge maintenance loop to drain into the health store.
    let (_log_guard, obs_sink) = init_tracing(&cfg);
    install_crypto_provider();
    shutdown::bind_child_processes_to_self();

    // The PT child (busybox dispatch, re-exec of this same binary) inherits
    // our environment and sets up its own tracing subscriber independently
    // of `cfg.log`. Propagate our own ansi choice via the NO_COLOR
    // convention (https://no-color.org) so a `log.ansi: false` config also
    // silences the child's colored output, not just ours.
    if !cfg.log.ansi {
        std::env::set_var("NO_COLOR", "1");
    }

    info!(%source, "loaded configuration");

    // Load the users registry (sits next to the main config). The file
    // is optional — when absent or empty, the SOCKS5 listener falls
    // back to the legacy NO_AUTH path.
    let users_path = UsersConfig::resolve_path(config_path.as_deref());
    let users = UsersConfig::load(&users_path).context("loading users registry")?;
    let auth_state = if users.users.is_empty() {
        info!(path = %users_path.display(), "no users configured — SOCKS5 will accept anonymous clients");
        None
    } else {
        let state = AuthState::build_persistent(&users, users_path.clone())
            .context("building auth state")?;
        info!(
            path = %users_path.display(),
            users = state.len(),
            "SOCKS5 will require USER/PASS authentication"
        );
        Some(Arc::new(state))
    };

    // Resolve the egress. An enabled upstream SOCKS5 proxy (config or
    // CLI) takes over entirely and the Tor bootstrap is skipped;
    // otherwise we bootstrap Tor with the configured bridges as before.
    let egress = match pick_upstream(
        &cfg.upstream,
        args.upstream_addr.as_deref(),
        args.upstream_user.as_deref(),
        args.upstream_pass.as_deref(),
        args.no_upstream,
    )? {
        Some(up) => {
            info!(
                upstream = %up.address(),
                auth = up.has_auth(),
                "egress via upstream SOCKS5 proxy — Tor is disabled"
            );
            Egress::Upstream(Arc::new(up))
        }
        None => {
            let settings = build_tor_settings(&cfg, config_path.as_deref()).await?;
            if settings.bridges.is_empty() {
                bail!(
                    "no bridges configured in {} — add at least one `bridges.lines: [ obfs4 ... ]` entry",
                    config_path
                        .as_deref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "<defaults>".to_string())
                );
            }
            let alive = settings.bridges.len();
            info!(count = alive, "using bridges");

            let tor = TorTunnel::bootstrap_with(settings)
                .await
                .context("failed to bootstrap Tor")?;

            // Auto-fetch enrichment: when we bootstrapped on few bridges
            // (or fell back to seeds), top up the working list in the
            // background — drain the candidate pool first, fetching fresh
            // candidates over the now-live Tor only if the pool is short.
            // One-shot: takes a direct `TorTunnel` clone and runs to
            // completion long before the watchdog could ever fire.
            let deficit = cfg.bridges.min_alive.saturating_sub(alive);
            if cfg.bridges.auto_fetch && deficit > 0 {
                spawn_auto_fetch(tor.clone(), cfg.clone(), config_path.clone(), deficit);
            }

            // Single indirection point for the live `TorClient`: the accept
            // loop and the maintenance loop read the *current* tunnel
            // through this handle, so a watchdog rebuild becomes visible to
            // both without re-distribution. Cheap to clone (one
            // `Arc<RwLock<_>>` + two atomics).
            let handle = TorHandle::new(tor);

            // Periodic upkeep: re-probe, prune dead bridges, top up when short,
            // drain circuit-layer observations from arti's tracing into the
            // health store so descriptor-mismatch / unsuitable bridges are
            // pruned alongside the TCP-dead ones. Reads the tunnel through
            // the handle so pool refreshes follow a watchdog rebuild.
            spawn_bridge_maintenance(
                handle.clone(),
                config_path.clone(),
                cfg.bridges.recheck_interval_mins,
                obs_sink.clone(),
            );

            // Stale-channel watchdog: rebuilds the `TorClient` when circuits
            // keep failing against TCP-reachable bridges (the half-open
            // channel scenario). Detached; disabled by config when unwanted.
            spawn_tor_watchdog(handle.clone(), config_path.clone(), cfg.watchdog);

            // Soft-failover watchdog: nudges arti's guard manager away from
            // a specific bridge whose own circuit-layer health has degraded
            // past a threshold, when a meaningfully healthier configured
            // alternative exists. Shares the `[watchdog]` config section and
            // check cadence with the stale-channel watchdog above; disabled
            // by the same `enabled`/`check_interval_secs` switches.
            spawn_bridge_failover_watchdog(handle.clone(), config_path.clone(), cfg.watchdog);

            // Bridge-channel warm-pool: keeps channels to the healthiest
            // candidate bridges open in the background, so a future
            // switch-over (not built here) does not pay for a cold
            // obfs4/webtunnel handshake. Opt-in; disabled by default.
            crate::bridge_warmer::spawn_bridge_warmer(
                handle.clone(),
                config_path.clone(),
                cfg.warm_pool,
            );

            Egress::Tor(handle)
        }
    };

    // Periodic connection-health summary: drains a rolling window of
    // accept-loop counters (attempts, established, errors by kind) into one
    // structured log line per interval. Pure observation — wired for both
    // the Tor and upstream egress paths alike. Enabled by default (unlike
    // `warm_pool`), since it changes nothing about live traffic.
    let conn_health = ConnHealthCounters::default();
    spawn_conn_health_logger(conn_health.clone(), cfg.conn_health);

    let listener = TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("failed to bind {}", cfg.listen))?;
    info!(listen_addr = %cfg.listen, "SOCKS5 proxy is listening");

    tokio::select! {
        biased;
        () = shutdown => {}
        _ = accept_loop(listener, egress.clone(), auth_state.clone(), Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS)), conn_health.clone()) => {
            // The accept loop is unbounded: this branch means the listener
            // died (probably an OS error we already logged).
            warn!("accept loop exited unexpectedly");
        }
    }

    // For the Tor egress, draining the handle takes the tunnel out of the
    // shared slot; dropping it triggers `tor-ptmgr` to terminate PT
    // subprocesses and releases arti's exclusive lock on its state
    // directory. The Job Object installed at startup kills anything that
    // leaks past this point. The upstream egress holds no such resources.
    if let Egress::Tor(handle) = egress {
        info!("stopping Tor client and pluggable transports");
        drop(handle.drain().await);
        // Give arti's reactor a brief moment to flush the shutdown.
        // Empirically this is enough for the state-dir lock to be released
        // before the next run starts.
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    info!("bye");
    Ok(())
}

/// Decide whether to use an upstream SOCKS5 egress, applying the rule
/// "CLI overrides config". Returns `Ok(None)` to fall back to Tor.
fn pick_upstream(
    cfg: &UpstreamConfig,
    cli_address: Option<&str>,
    cli_user: Option<&str>,
    cli_pass: Option<&str>,
    no_upstream: bool,
) -> Result<Option<upstream::Upstream>> {
    if no_upstream {
        return Ok(None);
    }
    // Presence of `--upstream` enables it regardless of the config flag.
    let enabled = cli_address.is_some() || cfg.enabled;
    if !enabled {
        return Ok(None);
    }

    let address = cli_address
        .map(str::to_string)
        .unwrap_or_else(|| cfg.address.clone());
    if address.trim().is_empty() {
        bail!("upstream proxy is enabled but no address is set (config `upstream.address` or --upstream HOST:PORT)");
    }

    // A username from either source switches on auth; the password
    // follows from the same precedence (CLI over config).
    let username = cli_user
        .map(str::to_string)
        .or_else(|| (!cfg.username.is_empty()).then(|| cfg.username.clone()));
    let password = cli_pass
        .map(str::to_string)
        .or_else(|| (!cfg.password.is_empty()).then(|| cfg.password.clone()));
    let credentials = username.map(|u| (u, password.unwrap_or_default()));

    Ok(Some(upstream::Upstream::new(address, credentials)))
}

async fn accept_loop(
    listener: TcpListener,
    egress: Egress,
    auth: Option<Arc<AuthState>>,
    permits: Arc<tokio::sync::Semaphore>,
    conn_health: ConnHealthCounters,
) {
    loop {
        let (client, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!(?e, "accept failed");
                return;
            }
        };
        let egress = egress.clone();
        let auth = auth.clone();
        let conn_health = conn_health.clone();
        let permit = permits
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore not closed");
        tokio::spawn(async move {
            debug!(%peer, "new connection");
            conn_health.record_attempt();
            if let Err(e) = handle_client(client, egress, auth, conn_health.clone()).await {
                let kind = classify_conn_error(&e);
                conn_health.record_error(kind);
                warn!(%peer, error = %e, kind = ?kind, "connection finished with error");
            }
            drop(permit);
        });
    }
}

/// Coarse classification of a [`handle_client`] failure, so operators can
/// tell "the client misbehaved" from "Tor is having a bad time" from
/// "something else" without grepping the error text — see [`ConnErrorKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnErrorKind {
    /// The client side of the SOCKS5 session misbehaved or disconnected —
    /// e.g. it dropped the TCP connection mid-handshake. Not a proxy or Tor
    /// problem; normal for clients that churn through many parallel
    /// connections (Telegram and similar).
    Client,
    /// A Tor-side failure building a circuit/stream — an
    /// `arti_wrapper::TorError::Connect` anywhere in the error's cause
    /// chain. Finer-grained classification (which `tor_error::ErrorKind`)
    /// already happens in [`crate::tor_watchdog::classify_and_record`]; this
    /// variant only answers "is this Tor's problem at all".
    Tor,
    /// Anything else: I/O errors unrelated to the SOCKS5 handshake, bugs,
    /// or failures that don't fit either bucket above.
    Other,
}

/// Classify a [`handle_client`] failure by the *type* of its root cause,
/// never by string-matching the rendered error message (message text is
/// not a stable classification key — see the module-level rationale for
/// why this exists).
///
/// Order of checks:
/// 1. Any `arti_wrapper::TorError::Connect` in the chain → [`ConnErrorKind::Tor`].
///    Checked first because a Tor connect failure is unambiguous and takes
///    priority over any incidental I/O wrapping.
/// 2. A `std::io::Error` in the chain whose kind indicates the client
///    dropped/reset the connection (`ConnectionReset`, `ConnectionAborted`,
///    `BrokenPipe`, `UnexpectedEof`), *or* any error in the chain carrying
///    the `"SOCKS5 handshake"` context tag `handle_client` attaches to the
///    handshake step → [`ConnErrorKind::Client`].
/// 3. Otherwise → [`ConnErrorKind::Other`].
pub(crate) fn classify_conn_error(err: &anyhow::Error) -> ConnErrorKind {
    for cause in err.chain() {
        if let Some(tor_err) = cause.downcast_ref::<arti_wrapper::TorError>() {
            if matches!(tor_err, arti_wrapper::TorError::Connect { .. }) {
                return ConnErrorKind::Tor;
            }
        }
    }

    for cause in err.chain() {
        if let Some(io_err) = cause.downcast_ref::<std::io::Error>() {
            if matches!(
                io_err.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::UnexpectedEof
            ) {
                return ConnErrorKind::Client;
            }
        }
    }

    if err
        .chain()
        .any(|cause| cause.to_string() == "SOCKS5 handshake")
    {
        return ConnErrorKind::Client;
    }

    ConnErrorKind::Other
}

async fn handle_client(
    mut client: TcpStream,
    egress: Egress,
    auth: Option<Arc<AuthState>>,
    conn_health: ConnHealthCounters,
) -> Result<()> {
    let req = socks5::handshake(&mut client, auth.clone())
        .await
        .context("SOCKS5 handshake")?;

    // Per-account onion gate: a `.onion` destination is allowed only
    // when the authenticated account carries `allowed_onion`. Anonymous
    // (NO_AUTH) clients are unrestricted — there is no account to gate
    // on, and the operator deliberately ran without auth.
    if req.is_onion() && !onion_permitted(auth.as_deref(), req.authed_user.as_deref()) {
        warn!(
            host = %req.host,
            user = ?req.authed_user,
            "refused .onion connection: account not permitted (allowed_onion = false)"
        );
        socks5::reply(&mut client, Reply::ConnectionNotAllowed)
            .await
            .ok();
        return Ok(());
    }

    match egress {
        Egress::Tor(handle) => {
            info!(host = ?req.host, port = req.port, "tunneling through Tor");
            // Read the *current* tunnel through the handle: a watchdog
            // rebuild swaps the slot, and new connections must pick up the
            // replacement. Returns None only while the server is draining
            // the slot at shutdown.
            let tor = match handle.tunnel().await {
                Some(t) => t,
                None => {
                    socks5::reply(&mut client, Reply::GeneralFailure).await.ok();
                    bail!("tor tunnel unavailable (shutting down?)");
                }
            };
            // Feed the watchdog: every attempt bumps the counter (so it can
            // tell "no traffic" from "circuits failing"), a success stamps
            // the last-good time it compares against.
            handle.health().record_attempt();
            let tor_stream = match tor.connect(&req.host, req.port).await {
                Ok(s) => {
                    handle.health().record_success();
                    handle.health().record_success_target(&req.host, req.port);
                    conn_health.record_established();
                    info!(host = ?req.host, port = req.port, "tor connection established");
                    s
                }
                Err(e) => {
                    // Classify the failure into the three `ErrorKind`s the
                    // watchdog cares about (see `classify_and_record`'s doc
                    // comment) — data collection only, no gating here.
                    crate::tor_watchdog::classify_and_record(&e, handle.health());
                    // We don't try to map the underlying cause to a specific
                    // SOCKS5 code; GeneralFailure is enough to tell the client
                    // we refused.
                    socks5::reply(&mut client, Reply::GeneralFailure).await.ok();
                    return Err(e.into());
                }
            };
            socks5::reply(&mut client, Reply::Success).await?;
            // `DataStream` implements `futures::AsyncRead/Write`; wrap it for tokio.
            let mut tor_compat = tor_stream.compat();
            tokio::io::copy_bidirectional(&mut client, &mut tor_compat).await?;
        }
        Egress::Upstream(up) => {
            info!(host = ?req.host, port = req.port, "forwarding through upstream SOCKS5");
            let mut upstream_stream = match up.connect(&req.host, req.port).await {
                Ok(s) => s,
                Err(e) => {
                    socks5::reply(&mut client, Reply::GeneralFailure).await.ok();
                    return Err(e);
                }
            };
            socks5::reply(&mut client, Reply::Success).await?;
            tokio::io::copy_bidirectional(&mut client, &mut upstream_stream).await?;
        }
    }
    Ok(())
}

/// Decide whether a `.onion` connection is allowed for this request.
///
/// * No authenticator (anonymous proxy) → allowed: there is no account
///   to gate on.
/// * Authenticated → allowed iff the named account carries
///   `allowed_onion` (and is still enabled).
/// * Auth required but no account on the request (should not happen for
///   a completed handshake) → denied, fail-closed.
fn onion_permitted(auth: Option<&AuthState>, authed_user: Option<&str>) -> bool {
    match (auth, authed_user) {
        (None, _) => true,
        (Some(state), Some(name)) => state.allowed_onion(name),
        (Some(_), None) => false,
    }
}

/// Spawn a detached one-shot task that tops up the working bridge list by
/// `deficit` bridges: it drains the candidate pool first and only fetches
/// fresh candidates over the live Tor circuit if the pool falls short.
/// Fire-and-forget: a dropped `JoinHandle` does not cancel it, failures
/// only log.
fn spawn_auto_fetch(
    tor: TorTunnel,
    cfg: Config,
    config_path: Option<std::path::PathBuf>,
    deficit: usize,
) {
    tokio::spawn(async move {
        info!(
            want = deficit,
            "auto-fetch: topping up working bridges in the background"
        );
        match crate::fetch_merge::top_up_working(&tor, &cfg, config_path.as_deref(), deficit).await
        {
            Ok(0) => info!("auto-fetch: no new reachable bridges promoted"),
            Ok(n) => info!(
                promoted = n,
                "auto-fetch: promoted fresh bridges into config"
            ),
            Err(e) => warn!(error = %e, "auto-fetch failed"),
        }
    });
}

/// Spawn the periodic bridge-maintenance loop: every
/// `interval_mins` it re-probes our configured bridges (both obfs4 and
/// webtunnel), updates the health store, prunes bridges that reached
/// `max_fails`, and — if we are short on healthy bridges — fetches more
/// from the configured sources. `interval_mins == 0` disables it.
///
/// Deliberately gentle to avoid network flood: a generous default
/// interval, bounded-concurrency probing, the once-per-window failure
/// counter, and a top-up fetch only when actually short.
fn spawn_bridge_maintenance(
    handle: TorHandle,
    config_path: Option<std::path::PathBuf>,
    interval_mins: u64,
    obs_sink: crate::arti_observability::ObservationSink,
) {
    if interval_mins == 0 {
        info!("bridge maintenance disabled (recheck_interval_mins = 0)");
        return;
    }
    let interval = Duration::from_secs(interval_mins.saturating_mul(60));
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await; // consume the immediate first tick

        loop {
            ticker.tick().await;

            let cfg = match Config::load_with_override(config_path.as_deref()) {
                Ok(loaded) => loaded.into_config(),
                Err(e) => {
                    warn!(error = %e, "maintenance: could not reload config");
                    continue;
                }
            };
            let parsed = match cfg.bridges.parsed() {
                Ok(p) => p.bridges,
                Err(e) => {
                    warn!(error = %e, "maintenance: config has invalid bridges");
                    continue;
                }
            };
            if parsed.is_empty() {
                continue;
            }

            info!(
                count = parsed.len(),
                "maintenance: re-probing configured bridges"
            );
            let alive = bridge_probe::probe_and_sort(
                parsed.clone(),
                crate::tor_setup::BRIDGE_PROBE_TIMEOUT,
            )
            .await;
            let store = crate::tor_setup::update_health_and_prune(
                config_path.as_deref(),
                &parsed,
                &alive,
                &cfg,
                Some(&obs_sink),
            );

            if cfg.bridges.auto_fetch && !cfg.bridges.sources.is_empty() {
                // Periodically refresh the candidate pool from the sources
                // (over Tor) — keeps it fresh and drops anything that has
                // since become a working bridge. Snapshot the *current*
                // tunnel through the handle so a refresh follows a watchdog
                // rebuild rather than pinning the dying original.
                if let Some(tor) = handle.tunnel().await {
                    if let Err(e) = crate::fetch_merge::refresh_candidate_pool(
                        &tor,
                        &cfg,
                        config_path.as_deref(),
                        Duration::from_secs(30),
                    )
                    .await
                    {
                        warn!(error = %e, "maintenance: pool refresh failed");
                    }
                }
            }

            // A bridge counts toward the healthy working set only if it is
            // reachable at BOTH layers: TCP-alive (already filtered by
            // `alive`) AND not saturated with circuit-layer failures. TCP
            // probes stay green while the obfs4/circuit layer is degraded
            // (e.g. DPI interference on the transport handshake), so
            // counting only TCP-alive bridges here would mask a total
            // outage and never trigger a pool top-up.
            let circuit_healthy = match &store {
                Some(s) => alive
                    .iter()
                    .filter(|(b, _)| s.circuit_fails(b) < cfg.bridges.max_circuit_fails)
                    .count(),
                // No store → no circuit signal; fall back to the TCP-only
                // behaviour so a missing store never blocks a top-up the
                // TCP layer alone would have requested.
                None => alive.len(),
            };

            info!(
                tcp_alive = alive.len(),
                circuit_healthy,
                min = cfg.bridges.min_alive,
                "maintenance: bridge health snapshot"
            );

            // Top up the working list from the pool when we are short on
            // genuinely healthy bridges (lazy probe, no fetch — the refresh
            // above already filled the pool).
            let deficit = compute_deficit(cfg.bridges.min_alive, alive.len(), circuit_healthy);
            if deficit > 0 {
                info!(
                    tcp_alive = alive.len(),
                    circuit_healthy,
                    min = cfg.bridges.min_alive,
                    want = deficit,
                    "maintenance: short on healthy bridges — draining candidate pool"
                );
                match crate::fetch_merge::drain_pool(config_path.as_deref(), deficit).await {
                    Ok(n) if n > 0 => info!(promoted = n, "maintenance: promoted fresh bridges"),
                    Ok(_) => {}
                    Err(e) => warn!(error = %e, "maintenance: drain failed"),
                }
            }
        }
    });
}

/// How many working bridges we are short of, accounting for *both* layers
/// of bridge health: TCP reachability and circuit-layer usability.
///
/// `tcp_alive` is the count of bridges that answered a TCP probe;
/// `circuit_healthy` is the subset of those whose accumulated circuit-
/// layer failures are still below the pruning threshold. Only a bridge
/// healthy at *both* layers can actually carry traffic, so the deficit is
/// driven by the smaller (circuit-aware) count. Used by
/// [`spawn_bridge_maintenance`] to decide whether to promote fresh
/// candidates from the pool into the working set.
fn compute_deficit(min_alive: usize, tcp_alive: usize, circuit_healthy: usize) -> usize {
    // `circuit_healthy` is by construction a subset of `tcp_alive`, but
    // take the min defensively: a caller passing independent counts must
    // never over-report healthy bridges.
    let effective_healthy = tcp_alive.min(circuit_healthy);
    min_alive.saturating_sub(effective_healthy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn disabled_cfg() -> UpstreamConfig {
        UpstreamConfig::default()
    }

    #[test]
    fn pick_upstream_disabled_by_default() {
        let up = pick_upstream(&disabled_cfg(), None, None, None, false).unwrap();
        assert!(up.is_none(), "no config, no CLI → Tor egress");
    }

    #[test]
    fn pick_upstream_cli_address_enables_and_overrides() {
        let cfg = disabled_cfg();
        let up = pick_upstream(&cfg, Some("127.0.0.1:9050"), None, None, false)
            .unwrap()
            .expect("CLI --upstream should enable");
        assert_eq!(up.address(), "127.0.0.1:9050");
        assert!(!up.has_auth());
    }

    #[test]
    fn pick_upstream_config_enabled_is_used() {
        let cfg = UpstreamConfig {
            enabled: true,
            address: "10.0.0.1:1080".into(),
            username: String::new(),
            password: String::new(),
        };
        let up = pick_upstream(&cfg, None, None, None, false)
            .unwrap()
            .unwrap();
        assert_eq!(up.address(), "10.0.0.1:1080");
        assert!(!up.has_auth());
    }

    #[test]
    fn pick_upstream_no_upstream_flag_forces_tor() {
        let cfg = UpstreamConfig {
            enabled: true,
            address: "10.0.0.1:1080".into(),
            username: String::new(),
            password: String::new(),
        };
        let up = pick_upstream(&cfg, Some("1.2.3.4:1080"), None, None, true).unwrap();
        assert!(up.is_none(), "--no-upstream wins over everything");
    }

    #[test]
    fn pick_upstream_cli_credentials_override_config() {
        let cfg = UpstreamConfig {
            enabled: true,
            address: "10.0.0.1:1080".into(),
            username: "cfg-user".into(),
            password: "cfg-pass".into(),
        };
        let up = pick_upstream(&cfg, None, Some("cli-user"), Some("cli-pass"), false)
            .unwrap()
            .unwrap();
        assert!(up.has_auth());
    }

    #[test]
    fn pick_upstream_enabled_without_address_errors() {
        let cfg = UpstreamConfig {
            enabled: true,
            address: String::new(),
            username: String::new(),
            password: String::new(),
        };
        let err = pick_upstream(&cfg, None, None, None, false).unwrap_err();
        assert!(format!("{err}").contains("no address"));
    }

    fn onion_state(name: &str, enabled: bool, allowed_onion: bool) -> AuthState {
        let user = auth::User {
            name: name.into(),
            hash: auth::compute_hash("pw").unwrap(),
            is_enabled: enabled,
            allowed_onion,
        };
        AuthState::build(&UsersConfig { users: vec![user] }).unwrap()
    }

    #[test]
    fn onion_anonymous_is_unrestricted() {
        assert!(onion_permitted(None, None));
        assert!(onion_permitted(None, Some("anyone")));
    }

    #[test]
    fn onion_requires_granted_account() {
        let granted = onion_state("alice", true, true);
        let plain = onion_state("bob", true, false);
        assert!(onion_permitted(Some(&granted), Some("alice")));
        assert!(!onion_permitted(Some(&plain), Some("bob")));
    }

    #[test]
    fn onion_denied_for_disabled_or_unknown_or_missing_name() {
        let disabled = onion_state("carol", false, true);
        assert!(!onion_permitted(Some(&disabled), Some("carol")));
        assert!(!onion_permitted(Some(&disabled), Some("ghost")));
        // Auth required but the request carries no account: fail-closed.
        assert!(!onion_permitted(Some(&disabled), None));
    }

    #[tokio::test]
    async fn accept_loop_respects_concurrency_cap() {
        // Two facts to prove deterministically: (1) the cap lets exactly
        // two tasks run concurrently, and (2) it refuses a third while two
        // permits are held. No real-time sleep — synchronization is explicit.
        let permits = Arc::new(tokio::sync::Semaphore::new(2));
        let active = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        // Barrier sized to the cap: the two permit-holders rendezvous here,
        // which can only happen if they are simultaneously in-flight. We
        // spawn exactly two tasks so every barrier participant is a holder
        // (a third task would block on the barrier forever).
        let barrier = Arc::new(tokio::sync::Barrier::new(2));

        let mut handles = Vec::new();
        for _ in 0..2 {
            let permits = permits.clone();
            let active = active.clone();
            let max_seen = max_seen.clone();
            let barrier = barrier.clone();
            handles.push(tokio::spawn(async move {
                let permit = permits.acquire_owned().await.unwrap();
                let count = active.fetch_add(1, Ordering::SeqCst) + 1;
                // Track the maximum concurrent count via CAS.
                loop {
                    let current = max_seen.load(Ordering::SeqCst);
                    if count <= current
                        || max_seen
                            .compare_exchange(current, count, Ordering::SeqCst, Ordering::SeqCst)
                            .is_ok()
                    {
                        break;
                    }
                }
                // Both holders meet here, proving concurrent in-flight.
                barrier.wait().await;
                active.fetch_sub(1, Ordering::SeqCst);
                drop(permit);
            }));
        }

        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(
            max_seen.load(Ordering::SeqCst),
            2,
            "the cap must allow exactly two tasks to run concurrently"
        );

        // Cap enforcement: with two permits held, a third must be refused;
        // releasing one must free a slot.
        let p1 = permits.clone().acquire_owned().await.unwrap();
        let _p2 = permits.clone().acquire_owned().await.unwrap();
        assert!(
            permits.clone().try_acquire_owned().is_err(),
            "a third concurrent permit must be refused by the cap of 2"
        );
        drop(p1);
        assert!(
            permits.try_acquire_owned().is_ok(),
            "releasing a permit must free a slot"
        );
    }

    #[test]
    fn compute_deficit_zero_when_both_layers_healthy() {
        // 31 TCP-alive, all circuit-healthy, min 8 → no deficit.
        assert_eq!(compute_deficit(8, 31, 31), 0);
    }

    #[test]
    fn compute_deficit_triggers_on_circuit_degradation_with_full_tcp() {
        // Reproduces the production incident: every bridge TCP-alive but
        // most saturated with circuit-layer failures — deficit must follow
        // the circuit-healthy count, not the TCP count.
        assert_eq!(compute_deficit(8, 31, 2), 6);
    }

    #[test]
    fn compute_deficit_uses_lower_count_when_both_layers_low() {
        // TCP itself is scarce; circuit-healthy is the binding constraint.
        assert_eq!(compute_deficit(8, 3, 2), 6);
    }

    #[test]
    fn compute_deficit_boundary_exactly_at_min() {
        // circuit_healthy == min_alive → exactly enough, no deficit.
        assert_eq!(compute_deficit(8, 31, 8), 0);
    }

    #[test]
    fn compute_deficit_boundary_one_below_min() {
        // circuit_healthy one short of min_alive → deficit of exactly 1.
        assert_eq!(compute_deficit(8, 31, 7), 1);
    }

    #[test]
    fn compute_deficit_zero_circuit_healthy_is_full_deficit() {
        // Every bridge circuit-degraded → full deficit regardless of TCP.
        assert_eq!(compute_deficit(8, 31, 0), 8);
    }

    #[test]
    fn compute_deficit_saturates_at_zero_when_overhealthy() {
        // More healthy than required → never goes negative.
        assert_eq!(compute_deficit(8, 40, 40), 0);
    }

    // -- classify_conn_error --------------------------------------------------

    /// Install rustls's process-wide `CryptoProvider` exactly once for this
    /// test binary — mirrors the same helper in `tor_watchdog.rs` /
    /// `arti-wrapper`'s own tests. Needed because
    /// `real_tor_connect_error_downcasts_as_tor` below builds a real,
    /// unbootstrapped `TorTunnel` against a fresh tempdir state dir, which
    /// reaches far enough into arti's directory-manager setup to expect a
    /// crypto provider already installed. `install_default()` errors if
    /// called twice in the same process, so the error is intentionally
    /// discarded.
    fn ensure_crypto_provider() {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    /// A real `arti_wrapper::TorError::Connect` wrapping a real
    /// `arti_client::Error`, without any network activity: an unbootstrapped
    /// `TorTunnel`'s `connect()` parses its target address (`IntoTorAddr`)
    /// before ever touching the bootstrap state, and an invalid hostname
    /// (embedded space — not a valid IP, `.onion`, or DNS hostname) fails
    /// that parse synchronously, surfacing as `arti_client::Error`
    /// (`TorAddrError::InvalidHostname` via its public `From` impl) wrapped
    /// in `TorError::Connect` by `TorTunnel::connect`. This is a genuine
    /// instance of the error type this classifier cares about, not a mock.
    async fn real_tor_connect_error() -> arti_wrapper::TorError {
        ensure_crypto_provider();
        let dir = tempfile::tempdir().unwrap();
        let settings = arti_wrapper::Settings {
            state_dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        let tor = arti_wrapper::TorTunnel::create_unbootstrapped_with(settings)
            .expect("synchronous, no-I/O construction must succeed");
        tor.connect("not a valid host", 443)
            .await
            .expect_err("an invalid hostname must fail address parsing before any network I/O")
    }

    #[tokio::test]
    async fn classify_conn_error_tor_connect_is_tor() {
        let tor_err = real_tor_connect_error().await;
        assert!(matches!(tor_err, arti_wrapper::TorError::Connect { .. }));
        let err = anyhow::Error::new(tor_err);
        assert_eq!(classify_conn_error(&err), ConnErrorKind::Tor);
    }

    #[tokio::test]
    async fn classify_conn_error_tor_connect_wrapped_in_context_is_still_tor() {
        // A `.context(...)` call anywhere above the real cause must not
        // shadow the underlying Tor error — `classify_conn_error` walks the
        // whole chain, not just the top frame.
        let tor_err = real_tor_connect_error().await;
        let err = anyhow::Error::new(tor_err).context("tunneling through Tor");
        assert_eq!(classify_conn_error(&err), ConnErrorKind::Tor);
    }

    #[test]
    fn classify_conn_error_io_reset_during_handshake_is_client() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "peer reset");
        let err = anyhow::Error::new(io_err).context("SOCKS5 handshake");
        assert_eq!(classify_conn_error(&err), ConnErrorKind::Client);
    }

    #[test]
    fn classify_conn_error_unexpected_eof_during_handshake_is_client() {
        let io_err = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof");
        let err = anyhow::Error::new(io_err).context("SOCKS5 handshake");
        assert_eq!(classify_conn_error(&err), ConnErrorKind::Client);
    }

    #[test]
    fn classify_conn_error_broken_pipe_without_handshake_context_is_still_client() {
        // The io::ErrorKind alone is enough — the "SOCKS5 handshake" context
        // string is a secondary signal, not required.
        let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe closed");
        let err = anyhow::Error::new(io_err);
        assert_eq!(classify_conn_error(&err), ConnErrorKind::Client);
    }

    #[test]
    fn classify_conn_error_other_io_kind_is_other() {
        // An I/O error whose kind is unrelated to a client disconnect (and
        // with no "SOCKS5 handshake" context) must not be misclassified as
        // Client.
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let err = anyhow::Error::new(io_err);
        assert_eq!(classify_conn_error(&err), ConnErrorKind::Other);
    }

    #[test]
    fn classify_conn_error_arbitrary_other_is_other() {
        let err = anyhow::anyhow!("some unrelated failure");
        assert_eq!(classify_conn_error(&err), ConnErrorKind::Other);
    }
}
