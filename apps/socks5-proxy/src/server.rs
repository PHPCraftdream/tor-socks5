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
use crate::socks5::{self, Reply};
use crate::startup::{init_tracing, install_crypto_provider};
use crate::tor_setup::build_tor_settings;
use crate::{shutdown, upstream};

/// Maximum concurrent SOCKS5 connections. Each may run an Argon2id verify
/// (~5 MiB working memory, 2 passes), so unbounded spawns risk resource
/// exhaustion under connection floods.
const MAX_CONCURRENT_CONNECTIONS: usize = 256;

/// Where accepted connections egress. An enabled upstream SOCKS5 proxy
/// replaces Tor entirely.
#[derive(Clone)]
enum Egress {
    Tor(TorTunnel),
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
            let deficit = cfg.bridges.min_alive.saturating_sub(alive);
            if cfg.bridges.auto_fetch && deficit > 0 {
                spawn_auto_fetch(tor.clone(), cfg.clone(), config_path.clone(), deficit);
            }

            // Periodic upkeep: re-probe, prune dead bridges, top up when short,
            // drain circuit-layer observations from arti's tracing into the
            // health store so descriptor-mismatch / unsuitable bridges are
            // pruned alongside the TCP-dead ones.
            spawn_bridge_maintenance(
                tor.clone(),
                config_path.clone(),
                cfg.bridges.recheck_interval_mins,
                obs_sink.clone(),
            );

            Egress::Tor(tor)
        }
    };

    let listener = TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("failed to bind {}", cfg.listen))?;
    info!(listen_addr = %cfg.listen, "SOCKS5 proxy is listening");

    tokio::select! {
        biased;
        () = shutdown => {}
        _ = accept_loop(listener, egress.clone(), auth_state.clone(), Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS))) => {
            // The accept loop is unbounded: this branch means the listener
            // died (probably an OS error we already logged).
            warn!("accept loop exited unexpectedly");
        }
    }

    // For the Tor egress, dropping the tunnel triggers `tor-ptmgr` to
    // terminate PT subprocesses and releases arti's exclusive lock on its
    // state directory. The Job Object installed at startup kills anything
    // that leaks past this point. The upstream egress holds no such
    // resources.
    if let Egress::Tor(tor) = egress {
        info!("stopping Tor client and pluggable transports");
        drop(tor);
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
        let permit = permits
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore not closed");
        tokio::spawn(async move {
            debug!(%peer, "new connection");
            if let Err(e) = handle_client(client, egress, auth).await {
                warn!(%peer, error = %e, "connection finished with error");
            }
            drop(permit);
        });
    }
}

async fn handle_client(
    mut client: TcpStream,
    egress: Egress,
    auth: Option<Arc<AuthState>>,
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
        Egress::Tor(tor) => {
            info!(host = ?req.host, port = req.port, "tunneling through Tor");
            let tor_stream = match tor.connect(&req.host, req.port).await {
                Ok(s) => s,
                Err(e) => {
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
    tor: TorTunnel,
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
            let _ = crate::tor_setup::update_health_and_prune(
                config_path.as_deref(),
                &parsed,
                &alive,
                &cfg,
                Some(&obs_sink),
            );

            if cfg.bridges.auto_fetch && !cfg.bridges.sources.is_empty() {
                // Periodically refresh the candidate pool from the sources
                // (over Tor) — keeps it fresh and drops anything that has
                // since become a working bridge.
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

            // Top up the working list from the pool when we are short on
            // healthy bridges (lazy probe, no fetch — the refresh above
            // already filled the pool).
            let deficit = cfg.bridges.min_alive.saturating_sub(alive.len());
            if deficit > 0 {
                info!(
                    alive = alive.len(),
                    min = cfg.bridges.min_alive,
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
}
