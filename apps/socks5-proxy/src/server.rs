//! The SOCKS5 listener runtime: egress selection, the accept loop, and
//! the per-connection handler.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
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

/// Absolute deadline for the entire SOCKS5 handshake: method negotiation,
/// RFC 1929 USER/PASS auth (including the Argon2 verify) and the CONNECT
/// request. Armed once when the handshake starts and never renewed — a
/// client trickling valid bytes one at a time still hits it. On expiry the
/// client socket is dropped and the connection task exits, releasing its
/// `MAX_CONCURRENT_CONNECTIONS` permit.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(30);

/// Pause before retrying after a failed `accept()`. Any accept error is
/// treated as transient: the loop logs it and retries instead of tearing
/// down the whole server. The sleep also prevents a busy-spin (and a log
/// flood) if the error is persistent.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(500);

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

            // One process-wide single writer for the bridge health store: the bootstrap
            // probe below and every background task spawned after it (maintenance,
            // warmer, circuit verifier) record store updates through it.
            crate::bridge_store_writer::init_global(config_path.as_deref());

            let tor = TorTunnel::bootstrap_with(settings.clone())
                .await
                .context("failed to bootstrap Tor")?;

            // Single indirection point for the live `TorClient`: the accept
            // loop and the maintenance loop read the *current* tunnel
            // through this handle, so a watchdog rebuild becomes visible to
            // both without re-distribution. Cheap to clone (one
            // `Arc<RwLock<_>>` + two atomics).
            let handle = TorHandle::new(tor);
            obs_sink.set_recovery_notifier(handle.bridge_refresh().recovery());
            handle.set_active_bridges(settings.bridges.clone());
            handle.bridge_refresh().set_needed(
                cfg.bridges.auto_fetch
                    && crate::bridge_maintenance::preferred_missing(&cfg, &settings.bridges),
            );

            // Periodic upkeep: re-probe, prune dead bridges, top up when short,
            // drain circuit-layer observations from arti's tracing into the
            // health store so descriptor-mismatch / unsuitable bridges are
            // pruned alongside the TCP-dead ones. Reads the tunnel through
            // the handle so pool refreshes follow a watchdog rebuild.
            crate::bridge_maintenance::spawn(
                handle.clone(),
                config_path.clone(),
                cfg.bridges.recheck_interval_mins,
                obs_sink.clone(),
                settings,
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

            // Periodic circuit-level bridge verification: every 30 min, checks
            // a small batch of channel-proven bridges for real end-to-end
            // reachability (throwaway clients, live probe) and records the
            // successes into the bridge store. This is the CLI counterpart of
            // android-ffi's background circuit-verify tick; it is self-paced
            // by store state (a tick with no due bridges is nearly free) and
            // uses the active pool but verifies through separate clients.
            crate::bridge_verifier::spawn_bridge_circuit_verifier(
                config_path.clone(),
                handle.clone(),
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
        _ = accept_loop(listener, egress.clone(), auth_state.clone(), Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS)), conn_health.clone(), cfg.security.block_onion) => {
            // The accept loop retries accept errors internally with a
            // backoff, so this branch means the loop itself ended.
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

        // The bridge store writer's producers (maintenance, watchdogs,
        // warmer, verifier) all read the Tor client through the handle just
        // drained above, so they stop generating new updates here. Wait for
        // the writer last: flush any retained snapshot and join its actor
        // task, so a publish that only recovered after the last mutation
        // is not silently lost when the runtime tears down.
        if let Some(Err(error)) = crate::bridge_store_writer::close_global().await {
            warn!(error = %error, "bridge health store had unpublished updates at shutdown");
        }
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
    block_onion: bool,
) {
    // Monotonic per-connection identifier for log correlation. Wraps only
    // after 2^64 connections — never, in practice.
    let next_conn_id = AtomicU64::new(1);
    loop {
        let (client, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!(?e, "accept failed; retrying in {ACCEPT_ERROR_BACKOFF:?}");
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                continue;
            }
        };
        let conn_id = next_conn_id.fetch_add(1, Ordering::Relaxed);
        let egress = egress.clone();
        let auth = auth.clone();
        let conn_health = conn_health.clone();
        let permit = permits
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore not closed");
        tokio::spawn(async move {
            debug!(conn_id, %peer, "new connection");
            // RAII gauge: moved into the task so `pending` is decremented
            // wherever the task ends — error, success, or panic.
            let pending_guard = conn_health.record_started();
            if let Err(e) = handle_client(
                client,
                egress,
                auth,
                conn_health.clone(),
                block_onion,
                conn_id,
            )
            .await
            {
                let (stage, kind) = classify_conn_failure(&e);
                conn_health.record_failure(stage, kind);
                // `{:#}` (anyhow's alternate Display) prints the full cause
                // chain ("top: cause1: cause2: ..."); plain `%e` would only
                // print the outermost context tag (e.g. "SOCKS5 handshake")
                // and silently swallow the real root cause.
                warn!(
                    conn_id,
                    %peer,
                    stage = ?stage,
                    kind = ?kind,
                    error = format!("{:#}", e),
                    "connection finished with error"
                );
            }
            drop(permit);
            drop(pending_guard);
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
    /// relay-stage I/O failure. Deliberately NOT Client:
    /// `tokio::io::copy_bidirectional` does not expose WHICH end errored, so the
    /// client-vs-Tor direction of a mid-relay reset is indeterminate; what is
    /// determinate is the stage, and a relay-stage reset must not inflate the
    /// client-misbehavior count. Per-direction byte counts exist only on
    /// success.
    Relay,
    /// Anything else: I/O errors unrelated to the SOCKS5 handshake, bugs,
    /// or failures that don't fit any bucket above.
    Other,
}

/// Which protocol stage a connection failed at. Discriminating on stage (an
/// internal, stable anyhow context tag — see the `STAGE_*` constants) rather
/// than on error text lets the same I/O condition be attributed differently:
/// a ConnectionReset during the handshake is the client's doing, while the
/// identical reset mid-relay is reported as [`ConnStage::Relay`] so it does
/// not inflate the client-misbehavior count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnStage {
    /// SOCKS5 method negotiation / auth / CONNECT request.
    Handshake,
    /// Establishing the egress (Tor circuit or upstream proxy) connection.
    Connect,
    /// Bidirectional data transfer between client and egress.
    Relay,
    /// No stage context tag found in the error chain.
    Other,
}

/// Internal, stable context tags `handle_client` attaches to each stage.
/// Classification string-matches ONLY these — never arbitrary error message
/// text (message text is not a stable classification key).
const STAGE_HANDSHAKE: &str = "SOCKS5 handshake";
const STAGE_CONNECT_TOR: &str = "tor connect";
const STAGE_CONNECT_UPSTREAM: &str = "upstream connect";
const STAGE_RELAY: &str = "relay";

/// Classify a [`handle_client`] failure into a stage and an error kind, by
/// the *type* of its root cause and the stage context tag in the chain,
/// never by string-matching arbitrary rendered error message text (only the
/// internal `STAGE_*` context tags above are matched — message text is not a
/// stable classification key).
///
/// Order of checks:
/// 1. Stage: the first chain cause matching a `STAGE_*` tag wins (relay →
///    handshake → connect → other).
/// 2. Kind: any `arti_wrapper::TorError::Connect` in the chain →
///    [`ConnErrorKind::Tor`], regardless of stage (a Tor connect failure is
///    unambiguous and takes priority over any incidental I/O wrapping).
/// 3. Otherwise by stage: handshake → Client (everything escaping the
///    handshake phase is client-side, including the deadline); relay →
///    Relay when a chain cause is a client-drop-ish `io::Error`
///    (ConnectionReset/Aborted/BrokenPipe/UnexpectedEof), else Other;
///    connect → Other (a non-Tor connect failure is not attributable to the
///    SOCKS client — the `connect_failed` counter carries the stage signal);
///    other stage → Client when a chain cause is a drop-ish `io::Error`
///    (after the stage tags the only untagged I/O escape path is the SOCKS
///    reply writes, which are client-side), else Other.
pub(crate) fn classify_conn_failure(err: &anyhow::Error) -> (ConnStage, ConnErrorKind) {
    let stage = if err.chain().any(|cause| cause.to_string() == STAGE_RELAY) {
        ConnStage::Relay
    } else if err
        .chain()
        .any(|cause| cause.to_string() == STAGE_HANDSHAKE)
    {
        ConnStage::Handshake
    } else if err.chain().any(|cause| {
        cause.to_string() == STAGE_CONNECT_TOR || cause.to_string() == STAGE_CONNECT_UPSTREAM
    }) {
        ConnStage::Connect
    } else {
        ConnStage::Other
    };

    let is_dropish_io = err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io_err| {
                matches!(
                    io_err.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::UnexpectedEof
                )
            })
    });

    for cause in err.chain() {
        if let Some(tor_err) = cause.downcast_ref::<arti_wrapper::TorError>() {
            if matches!(tor_err, arti_wrapper::TorError::Connect { .. }) {
                return (stage, ConnErrorKind::Tor);
            }
        }
    }

    let kind = match stage {
        ConnStage::Handshake => ConnErrorKind::Client,
        ConnStage::Relay => {
            if is_dropish_io {
                ConnErrorKind::Relay
            } else {
                ConnErrorKind::Other
            }
        }
        ConnStage::Connect => ConnErrorKind::Other,
        ConnStage::Other => {
            if is_dropish_io {
                ConnErrorKind::Client
            } else {
                ConnErrorKind::Other
            }
        }
    };
    (stage, kind)
}

async fn handle_client(
    mut client: TcpStream,
    egress: Egress,
    auth: Option<Arc<AuthState>>,
    conn_health: ConnHealthCounters,
    block_onion: bool,
    conn_id: u64,
) -> Result<()> {
    let started_at = std::time::Instant::now();
    // Absolute deadline for the whole handshake chain — armed once here and
    // never renewed per read.
    let handshake = tokio::time::timeout(
        HANDSHAKE_DEADLINE,
        socks5::handshake(&mut client, auth.clone()),
    )
    .await;
    // BOTH arms carry the stage tag: the classifier keys on it, and the
    // deadline branch is just as much a handshake-stage failure as an I/O
    // error inside `socks5::handshake`.
    let req = match handshake {
        Ok(res) => res.context(STAGE_HANDSHAKE)?,
        Err(_elapsed) => {
            return Err(
                anyhow!("handshake deadline of {HANDSHAKE_DEADLINE:?} exceeded")
                    .context(STAGE_HANDSHAKE),
            )
        }
    };

    // Global onion gate comes first. The per-account gate below remains
    // useful for CLI deployments that grant onion access selectively.
    if block_onion && req.is_onion() {
        warn!(host = %req.host, "refused .onion connection: blocked by security.block_onion");
        socks5::reply(&mut client, Reply::ConnectionNotAllowed)
            .await
            .ok();
        return Ok(());
    }

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
            handle.bridge_refresh().request();
            info!(host = ?req.host, port = req.port, "tunneling through Tor");
            // Read the *current* tunnel through the handle: a watchdog
            // rebuild swaps the slot, and new connections must pick up the
            // replacement. Returns None only while the server is draining
            // the slot at shutdown.
            let tor = match handle.tunnel().await {
                Some(t) => t,
                None => {
                    socks5::reply(&mut client, Reply::GeneralFailure).await.ok();
                    conn_health.record_connect_failed();
                    return Err(anyhow!("tor tunnel unavailable (shutting down?)")
                        .context(STAGE_CONNECT_TOR));
                }
            };
            // Feed the watchdog: every attempt bumps the counter (so it can
            // tell "no traffic" from "circuits failing"), a success stamps
            // the last-good time it compares against.
            handle.health().record_attempt();
            let tor_stream = match handle
                .bridge_refresh()
                .track_connection(tor.connect(&req.host, req.port))
                .await
            {
                Ok(s) => {
                    handle.health().record_success();
                    handle.health().record_success_target(&req.host, req.port);
                    conn_health.record_connect_ok();
                    info!(host = ?req.host, port = req.port, "tor connection established");
                    s
                }
                Err(e) => {
                    // Classify the failure into the three `ErrorKind`s the
                    // watchdog cares about (see `classify_and_record`'s doc
                    // comment) — data collection only, no gating here.
                    crate::tor_watchdog::classify_and_record(&e, handle.health());
                    // The watchdog needs the RAW `TorError` type — pass the
                    // un-wrapped error, not a context-wrapped one.
                    handle.bridge_refresh().request_after_failure(&e);
                    // We don't try to map the underlying cause to a specific
                    // SOCKS5 code; GeneralFailure is enough to tell the client
                    // we refused.
                    socks5::reply(&mut client, Reply::GeneralFailure).await.ok();
                    conn_health.record_connect_failed();
                    return Err(anyhow::Error::new(e).context(STAGE_CONNECT_TOR));
                }
            };
            socks5::reply(&mut client, Reply::Success).await?;
            // `DataStream` implements `futures::AsyncRead/Write`; wrap it for tokio.
            let mut tor_compat = tor_stream.compat();
            // `copy_bidirectional` returns `(a_to_b, b_to_a)` where `a` is
            // the client stream — hence the field names below. A success here
            // (not merely a successful connect) is the real transfer
            // outcome; `relay_errors` is bumped in `accept_loop` via
            // classification of the STAGE_RELAY-tagged error below.
            match tokio::io::copy_bidirectional(&mut client, &mut tor_compat).await {
                Ok((sent, recv)) => {
                    conn_health.record_relay_closed();
                    info!(
                        conn_id,
                        host = ?req.host,
                        port = req.port,
                        elapsed = ?started_at.elapsed(),
                        bytes_client_to_remote = sent,
                        bytes_remote_to_client = recv,
                        "relay finished"
                    );
                }
                Err(e) => {
                    return Err(anyhow::Error::new(e).context(STAGE_RELAY));
                }
            }
        }
        Egress::Upstream(up) => {
            info!(host = ?req.host, port = req.port, "forwarding through upstream SOCKS5");
            let mut upstream_stream = match up.connect(&req.host, req.port).await {
                Ok(s) => s,
                Err(e) => {
                    socks5::reply(&mut client, Reply::GeneralFailure).await.ok();
                    conn_health.record_connect_failed();
                    return Err(e.context(STAGE_CONNECT_UPSTREAM));
                }
            };
            socks5::reply(&mut client, Reply::Success).await?;
            // See the Tor branch for the field/counter semantics.
            match tokio::io::copy_bidirectional(&mut client, &mut upstream_stream).await {
                Ok((sent, recv)) => {
                    conn_health.record_relay_closed();
                    info!(
                        conn_id,
                        host = ?req.host,
                        port = req.port,
                        elapsed = ?started_at.elapsed(),
                        bytes_client_to_remote = sent,
                        bytes_remote_to_client = recv,
                        "relay finished"
                    );
                }
                Err(e) => {
                    return Err(anyhow::Error::new(e).context(STAGE_RELAY));
                }
            }
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

/// How many working bridges we are short of, accounting for *both* layers
/// of bridge health: TCP reachability and circuit-layer usability.
///
/// `tcp_alive` is the count of bridges that answered a TCP probe;
/// `circuit_healthy` is the subset of those whose accumulated circuit-
/// layer failures are still below the pruning threshold. Only a bridge
/// healthy at *both* layers can actually carry traffic, so the deficit is
/// driven by the smaller (circuit-aware) count. Used by
/// [`crate::bridge_maintenance`] to decide whether to promote fresh
/// candidates from the pool into the working set.
pub(crate) fn compute_deficit(min_alive: usize, tcp_alive: usize, circuit_healthy: usize) -> usize {
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

    #[test]
    fn accept_error_backoff_is_sane() {
        assert!(ACCEPT_ERROR_BACKOFF > Duration::ZERO);
        assert!(ACCEPT_ERROR_BACKOFF <= Duration::from_secs(5));
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

    // -- classify_conn_failure -------------------------------------------------

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
    async fn classify_conn_failure_tor_connect_is_other_stage_tor_kind() {
        let tor_err = real_tor_connect_error().await;
        assert!(matches!(tor_err, arti_wrapper::TorError::Connect { .. }));
        let err = anyhow::Error::new(tor_err);
        // Bare: no stage tag in the chain → Other stage; the kind is Tor.
        assert_eq!(
            classify_conn_failure(&err),
            (ConnStage::Other, ConnErrorKind::Tor)
        );
    }

    #[tokio::test]
    async fn classify_conn_failure_tor_connect_wrapped_in_context_is_still_tor() {
        // A `.context(...)` call anywhere above the real cause must not
        // shadow the underlying Tor error — `classify_conn_failure` walks
        // the whole chain, not just the top frame. "tunneling through Tor"
        // is not a stage const, so the stage stays Other; the kind must stay
        // Tor.
        let tor_err = real_tor_connect_error().await;
        let err = anyhow::Error::new(tor_err).context("tunneling through Tor");
        assert_eq!(
            classify_conn_failure(&err),
            (ConnStage::Other, ConnErrorKind::Tor)
        );
    }

    #[test]
    fn classify_conn_failure_io_reset_during_handshake_is_client() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "peer reset");
        let err = anyhow::Error::new(io_err).context(STAGE_HANDSHAKE);
        assert_eq!(
            classify_conn_failure(&err),
            (ConnStage::Handshake, ConnErrorKind::Client)
        );
    }

    #[test]
    fn classify_conn_failure_unexpected_eof_during_handshake_is_client() {
        let io_err = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof");
        let err = anyhow::Error::new(io_err).context(STAGE_HANDSHAKE);
        assert_eq!(
            classify_conn_failure(&err),
            (ConnStage::Handshake, ConnErrorKind::Client)
        );
    }

    #[test]
    fn classify_conn_failure_broken_pipe_without_stage_context_is_client() {
        // After the stage tags, the only untagged I/O escape path is the
        // SOCKS reply writes — which are client-side — so a bare drop-ish
        // io::Error still classifies Client.
        let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe closed");
        let err = anyhow::Error::new(io_err);
        assert_eq!(
            classify_conn_failure(&err),
            (ConnStage::Other, ConnErrorKind::Client)
        );
    }

    #[test]
    fn classify_conn_failure_other_io_kind_is_other() {
        // An I/O error whose kind is unrelated to a client disconnect (and
        // with no stage context) must not be misclassified as Client.
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let err = anyhow::Error::new(io_err);
        assert_eq!(
            classify_conn_failure(&err),
            (ConnStage::Other, ConnErrorKind::Other)
        );
    }

    #[test]
    fn classify_conn_failure_arbitrary_other_is_other() {
        let err = anyhow::anyhow!("some unrelated failure");
        assert_eq!(
            classify_conn_failure(&err),
            (ConnStage::Other, ConnErrorKind::Other)
        );
    }

    #[test]
    fn relay_stage_reset_is_relay_not_client() {
        // The heart of the P2 fix: a Tor-side reset during data transfer is
        // no longer counted as client misbehavior — it lands in relay_errors
        // instead of client_errors.
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "peer reset");
        let err = anyhow::Error::new(io_err).context(STAGE_RELAY);
        assert_eq!(
            classify_conn_failure(&err),
            (ConnStage::Relay, ConnErrorKind::Relay)
        );
    }

    #[test]
    fn relay_stage_non_io_error_is_other() {
        let err = anyhow::anyhow!("mid-relay failure").context(STAGE_RELAY);
        assert_eq!(
            classify_conn_failure(&err),
            (ConnStage::Relay, ConnErrorKind::Other)
        );
    }

    #[test]
    fn connect_stage_upstream_reset_is_connect_other() {
        // A reset during the upstream connect is not attributable to the
        // SOCKS client; the connect_failed counter carries the stage signal.
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "peer reset");
        let err = anyhow::Error::new(io_err).context(STAGE_CONNECT_UPSTREAM);
        assert_eq!(
            classify_conn_failure(&err),
            (ConnStage::Connect, ConnErrorKind::Other)
        );
    }

    #[tokio::test]
    async fn connect_stage_tor_error_is_connect_tor() {
        let tor_err = real_tor_connect_error().await;
        let err = anyhow::Error::new(tor_err).context(STAGE_CONNECT_TOR);
        assert_eq!(
            classify_conn_failure(&err),
            (ConnStage::Connect, ConnErrorKind::Tor)
        );
    }

    #[test]
    fn same_reset_different_stage_classifies_differently() {
        // The stage-discrimination regression test: the IDENTICAL
        // io::ErrorKind::ConnectionReset classifies Client at the handshake
        // stage and Relay mid-transfer. A client-end-vs-Tor-end
        // discrimination test is deliberately NOT written here:
        // `tokio::io::copy_bidirectional` does not report WHICH side of the
        // relay errored, so that split is indeterminate by design (see
        // `ConnErrorKind::Relay`'s doc).
        let handshake_err = anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "peer reset",
        ))
        .context(STAGE_HANDSHAKE);
        assert_eq!(
            classify_conn_failure(&handshake_err),
            (ConnStage::Handshake, ConnErrorKind::Client)
        );

        let relay_err = anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "peer reset",
        ))
        .context(STAGE_RELAY);
        assert_eq!(
            classify_conn_failure(&relay_err),
            (ConnStage::Relay, ConnErrorKind::Relay)
        );
    }

    // -- absolute handshake deadline ------------------------------------------

    /// Server-under-test driving the REAL `accept_loop` over a loopback
    /// listener, with a one-permit semaphore so a single stuck handshake is
    /// observable as `available_permits() == 0`.
    async fn spawn_test_server() -> (
        std::net::SocketAddr,
        Arc<tokio::sync::Semaphore>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let permits = Arc::new(tokio::sync::Semaphore::new(1));
        // The egress never gets used: the deadline always fires first.
        let egress = Egress::Upstream(Arc::new(upstream::Upstream::new(
            "127.0.0.1:1".into(),
            None,
        )));
        let handle = tokio::spawn(accept_loop(
            listener,
            egress,
            None,
            permits.clone(),
            ConnHealthCounters::default(),
            false,
        ));
        (addr, permits, handle)
    }

    /// Deterministic (clock-free) wait for the server task to take the
    /// permit: the current-thread runtime only makes progress via yields.
    async fn wait_for_permit_taken(permits: &Arc<tokio::sync::Semaphore>) {
        for _ in 0..200 {
            if permits.available_permits() == 0 {
                return;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            permits.available_permits(),
            0,
            "server must hold the permit"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn silent_client_permit_released_at_handshake_deadline() {
        let (addr, permits, server) = spawn_test_server().await;
        // Connects and then sends nothing at all, holding the stream open.
        let _client = tokio::net::TcpStream::connect(addr).await.unwrap();
        wait_for_permit_taken(&permits).await;
        assert_eq!(
            permits.available_permits(),
            0,
            "permit must be held before the deadline"
        );

        tokio::time::sleep(HANDSHAKE_DEADLINE + Duration::from_secs(5)).await;
        let _permit = tokio::time::timeout(Duration::from_secs(10), permits.acquire())
            .await
            .expect("permit must be released by the absolute handshake deadline");
        server.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn partial_handshake_header_permit_released_at_deadline() {
        use tokio::io::AsyncWriteExt;
        let (addr, permits, server) = spawn_test_server().await;
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Only the VER byte — an incomplete method-negotiation header.
        client.write_all(&[0x05]).await.unwrap();
        wait_for_permit_taken(&permits).await;
        assert_eq!(
            permits.available_permits(),
            0,
            "permit must be held before the deadline"
        );

        tokio::time::sleep(HANDSHAKE_DEADLINE + Duration::from_secs(5)).await;
        let _permit = tokio::time::timeout(Duration::from_secs(10), permits.acquire())
            .await
            .expect("permit must be released by the absolute handshake deadline");
        server.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn trickling_client_permit_released_despite_valid_bytes() {
        use tokio::io::AsyncWriteExt;
        let (addr, permits, server) = spawn_test_server().await;
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();

        // Trickle valid handshake bytes, each gap half the deadline, then
        // hang forever — the client never finishes the handshake and never
        // closes. Write errors are ignored: the server may drop the socket
        // mid-trickle once the deadline fires.
        let client_task = tokio::spawn(async move {
            client.write_all(&[0x05]).await.ok();
            tokio::time::sleep(HANDSHAKE_DEADLINE / 2).await;
            client.write_all(&[0x01]).await.ok();
            tokio::time::sleep(HANDSHAKE_DEADLINE / 2).await;
            client.write_all(&[0x00]).await.ok();
            tokio::time::sleep(Duration::from_secs(3600)).await;
        });

        wait_for_permit_taken(&permits).await;
        tokio::time::sleep(HANDSHAKE_DEADLINE * 2 / 3).await;
        assert_eq!(
            permits.available_permits(),
            0,
            "permit must still be held mid-trickle, before the deadline"
        );

        // Now past the deadline while the client is still alive and
        // mid-handshake — a per-read renewal would keep the permit held.
        tokio::time::sleep(HANDSHAKE_DEADLINE * 2 / 3).await;
        let _permit = tokio::time::timeout(Duration::from_secs(10), permits.acquire())
            .await
            .expect("permit must be released despite valid trickling bytes");
        server.abort();
        client_task.abort();
    }

    #[test]
    fn handshake_deadline_error_is_classified_as_client() {
        // Mirrors the exact error shape produced by `handle_client`: the
        // deadline branch is now wrapped with the `STAGE_HANDSHAKE` context
        // just like the Ok arm, so the test shape matches production
        // exactly.
        let err = anyhow::anyhow!("handshake deadline of {HANDSHAKE_DEADLINE:?} exceeded")
            .context(STAGE_HANDSHAKE);
        assert_eq!(
            classify_conn_failure(&err),
            (ConnStage::Handshake, ConnErrorKind::Client),
            "a deadline expiry is client-side misbehavior, not Other"
        );
    }
}
