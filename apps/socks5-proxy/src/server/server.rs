//! The shared SOCKS5/HTTP CONNECT listener runtime: egress selection, the accept loop, and
//! the per-connection handler.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use arti_wrapper::TorTunnel;
use auth::{AuthState, UsersConfig};
use resocks5_net::connect::HostPort;
use resocks5_net::server::Reply;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::config::{Config, Loaded, SecurityConfig};
use crate::conn_health::{spawn_conn_health_logger, ConnHealthCounters};
use crate::dns_wiring::{convert_custom_doh_providers, convert_dns_overrides, dns_cache_path};
use crate::startup::{
    connect_tor_route, init_tracing, install_crypto_provider, reject_unsupported_endpoint,
    resolve_admitted_route, validate_account_routes, validate_post_compatibility,
    AuthStateVerifier,
};
use crate::tor_setup::build_tor_settings;
use crate::tor_watchdog::{spawn_bridge_failover_watchdog, spawn_tor_watchdog, TorHandle};
use crate::{shutdown, upstream};

/// Maximum concurrent SOCKS5 connections. Each may run an Argon2id verify
/// (~5 MiB working memory, 2 passes), so unbounded spawns risk resource
/// exhaustion under connection floods.
const MAX_CONCURRENT_CONNECTIONS: usize = 256;

/// Absolute deadline for the entire SOCKS5/HTTP CONNECT handshake, including
/// method negotiation, password authentication (including Argon2 verification),
/// and the CONNECT request. Armed once when the handshake starts and never renewed — a
/// client trickling valid bytes one at a time still hits it. On expiry the
/// client socket is dropped and the connection task exits, releasing its
/// `MAX_CONCURRENT_CONNECTIONS` permit.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(30);

/// Pause before retrying after a failed `accept()`. Any accept error is
/// treated as transient: the loop logs it and retries instead of tearing
/// down the whole server. The sleep also prevents a busy-spin (and a log
/// flood) if the error is persistent.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(500);

/// Upper bound on waiting for the background bridge-store producers
/// (maintenance, watchdogs, warmer, circuit verifier) to finish their
/// in-flight operation after cancellation. Must comfortably cover one
/// in-flight verifier batch over a slow network, yet keep a stuck
/// shutdown bounded: a producer still running past this budget is
/// abandoned with a warning, and its racing store write is then rejected
/// by the already-closed writer (logged there) rather than blocking
/// shutdown forever.
const PRODUCER_JOIN_TIMEOUT: Duration = Duration::from_secs(120);

/// Where accepted connections egress. An enabled upstream SOCKS5 proxy
/// replaces Tor entirely.
#[derive(Clone)]
enum Egress {
    Tor(TorHandle, Option<Arc<proxy_config::EndpointOverride>>, bool),
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
    reject_unsupported_endpoint(&cfg.pre_socks5, "global pre_socks5")?;
    let post_socks = cfg
        .post_socks5
        .clone()
        .filter(|setting| matches!(setting, proxy_config::EndpointOverride::Endpoint(_)))
        .map(Arc::new);
    validate_post_compatibility(post_socks.is_some(), cfg.dns_server.enabled, false)?;

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
    if let Some(path) = &config_path {
        crate::startup::ensure_bridges_file(&cfg, path);
    }

    // Load the users registry (sits next to the main config). The file
    // is optional — when absent or empty, the SOCKS5 listener falls
    // back to the legacy NO_AUTH path.
    let users_path = UsersConfig::resolve_path(config_path.as_deref());
    let users = UsersConfig::load(&users_path).context("loading users registry")?;
    validate_account_routes(
        &users,
        cfg.pre_socks5.as_ref(),
        cfg.post_socks5.as_ref(),
        cfg.dns_server.enabled,
        false,
    )?;
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

    // Cancellation + join plumbing for the Tor-side background producers.
    // Only the Tor egress spawns producers; the token and the collected
    // join handles stay unused (and empty) on the upstream path. Created
    // here so they outlive the egress match and are reachable from the
    // shutdown path below.
    let producer_token = CancellationToken::new();
    let mut producers: Vec<tokio::task::JoinHandle<()>> = Vec::new();

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
            validate_post_compatibility(post_socks.is_some(), false, true)?;
            validate_account_routes(
                &users,
                cfg.pre_socks5.as_ref(),
                cfg.post_socks5.as_ref(),
                false,
                true,
            )?;
            info!(
                upstream = %up.address(),
                auth = up.has_auth(),
                "egress via upstream SOCKS5 proxy — Tor is disabled"
            );
            Egress::Upstream(Arc::new(up))
        }
        None => {
            if cfg.tor.circuit_hops == 2 {
                warn!("tor.circuit_hops=2 reduces anonymity: onion-service circuits have no middle relay. Ordinary exit circuits stay at 3 hops. Intended for censorship circumvention, not anonymity.");
            }
            // Vanguards are compiled out (no `vanguards` feature anywhere in the
            // workspace), so Disabled mode is always in effect and the per-service
            // field fully controls the server circuit length.
            let service_circuit_hops = cfg
                .onion_services
                .iter()
                .find(|svc| svc.enabled)
                .map(|svc| svc.circuit_hops)
                .unwrap_or(4);
            if service_circuit_hops < 4 {
                let chain = if service_circuit_hops == 2 {
                    "[bridge, target] (descriptor uploads keep a middle relay)"
                } else {
                    "[bridge, middle, target]"
                };
                warn!(
                    "onion_services.circuit_hops={service_circuit_hops} reduces anonymity: server onion circuits are {chain}. Intended for censorship circumvention, not anonymity."
                );
            }
            let settings = build_tor_settings(&cfg, config_path.as_deref()).await?;
            if settings.bridges.is_empty() {
                bail!(
                    "no bridges configured in {} — add at least one `lines: [ obfs4 ... ]` entry",
                    config_path
                        .as_deref()
                        .map(|p| Config::bridges_path(p).display().to_string())
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
            producers.push(crate::bridge_maintenance::spawn(
                handle.clone(),
                config_path.clone(),
                cfg.bridges.recheck_interval_mins,
                obs_sink.clone(),
                settings,
                producer_token.clone(),
            ));

            // Stale-channel watchdog: rebuilds the `TorClient` when circuits
            // keep failing against TCP-reachable bridges (the half-open
            // channel scenario). Joined at shutdown; disabled by config when unwanted.
            producers.extend(spawn_tor_watchdog(
                handle.clone(),
                config_path.clone(),
                cfg.watchdog,
                producer_token.clone(),
            ));

            // Soft-failover watchdog: nudges arti's guard manager away from
            // a specific bridge whose own circuit-layer health has degraded
            // past a threshold, when a meaningfully healthier configured
            // alternative exists. Shares the `[watchdog]` config section and
            // check cadence with the stale-channel watchdog above; disabled
            // by the same `enabled`/`check_interval_secs` switches.
            producers.extend(spawn_bridge_failover_watchdog(
                handle.clone(),
                config_path.clone(),
                cfg.watchdog,
                producer_token.clone(),
            ));

            // Bridge-channel warm-pool: keeps channels to the healthiest
            // candidate bridges open in the background, so a future
            // switch-over (not built here) does not pay for a cold
            // obfs4/webtunnel handshake. Opt-in; disabled by default.
            producers.extend(crate::bridge_warmer::spawn_bridge_warmer(
                handle.clone(),
                config_path.clone(),
                cfg.warm_pool,
                producer_token.clone(),
            ));

            // Periodic circuit-level bridge verification: every 30 min, checks
            // a small batch of channel-proven bridges for real end-to-end
            // reachability (throwaway clients, live probe) and records the
            // successes into the bridge store. This is the CLI counterpart of
            // android-ffi's background circuit-verify tick; it is self-paced
            // by store state (a tick with no due bridges is nearly free) and
            // uses the active pool but verifies through separate clients.
            producers.push(crate::bridge_verifier::spawn_bridge_circuit_verifier(
                config_path.clone(),
                handle.clone(),
                producer_token.clone(),
            ));

            // Onion services from the config: one more producer (launches
            // each enabled service, forwards its virtual ports to local
            // targets, holds the onion keystore lock for their lifetime).
            // Gated on the `onion-service` feature; a build without it only
            // warns — missing support is not an error.
            #[cfg(feature = "onion-service")]
            crate::onion::service::spawn_services(
                handle.clone(),
                &cfg.onion_services,
                config_path.as_deref(),
                producer_token.clone(),
                &mut producers,
            );
            #[cfg(not(feature = "onion-service"))]
            {
                let enabled = cfg
                    .onion_services
                    .iter()
                    .filter(|service| service.enabled)
                    .count();
                if enabled > 0 {
                    warn!("built without onion-service support; {enabled} onion service(s) not started");
                }
            }

            Egress::Tor(handle, post_socks, cfg.dns_server.enabled)
        }
    };

    // Optional local DNS listener (opt-in, default OFF). Every DoH exchange
    // it performs is tunnelled through the live Tor tunnel, so the feature
    // requires the Tor egress: behind an upstream SOCKS5 proxy the premise
    // ("client DNS leaves the machine only inside Tor") cannot be honoured,
    // and refusing to start beats silently leaking plaintext queries.
    if cfg.dns_server.enabled {
        let Egress::Tor(handle, _, _) = &egress else {
            bail!(
                "dns_server.enabled requires Tor egress, not an upstream SOCKS5 proxy — \
                 disable dns_server or remove the upstream"
            );
        };
        let custom = convert_custom_doh_providers(&cfg.dns_server.custom_doh_providers);
        let pool =
            dns_server::providers::provider_pool(&custom, cfg.dns_server.disable_builtin_providers);
        let overrides = convert_dns_overrides(&cfg.dns_server.overrides);
        let cache_path = dns_cache_path(config_path.as_deref());
        let cache = Arc::new(dns_server::cache::DnsCache::load(&cache_path).await);
        info!(
            listen = ?cfg.dns_server.listen,
            cache = %cache_path.display(),
            providers = pool.len(),
            "starting DNS-over-Tor listener"
        );
        // One more producer beside the bridge-upkeep tasks: cancelled and
        // joined by the same shutdown choreography; error exit is not fatal.
        let dns_listen = cfg.dns_server.listen.clone();
        let dns_client_access = crate::dns_wiring::dns_client_access(&cfg);
        let producer_handle = handle.clone();
        let dns_token = producer_token.clone();
        producers.push(tokio::spawn(async move {
            // The inner per-call clone makes the future 'static: the closure
            // owns its handle, and `tunnel()` snapshots the current slot so a
            // watchdog rebuild is picked up on the next query.
            let tunnel = move || {
                let handle = producer_handle.clone();
                async move { handle.tunnel().await }
            };
            if let Err(error) = dns_server::server::run_with_client_access(
                &dns_listen,
                tunnel,
                cache,
                pool,
                overrides,
                cache_path,
                dns_token,
                dns_client_access,
            )
            .await
            {
                error!(%error, "dns server exited");
            }
        }));
    }

    // Periodic connection-health summary: drains a rolling window of
    // accept-loop counters (attempts, established, errors by kind) into one
    // structured log line per interval. Pure observation — wired for both
    // the Tor and upstream egress paths alike. Enabled by default (unlike
    // `warm_pool`), since it changes nothing about live traffic.
    let conn_health = ConnHealthCounters::default();
    spawn_conn_health_logger(conn_health.clone(), cfg.conn_health);

    // Skip only local availability failures, visibly; fail fast if none bind
    // or an unexpected error occurs. Every successful listener shares admission.
    let binding = binding::bind_listeners(&cfg.listen).await?;
    let retry_addresses = binding
        .skipped
        .iter()
        .filter(|skipped| skipped.error.kind() == std::io::ErrorKind::AddrNotAvailable)
        .map(|skipped| skipped.address.clone())
        .collect::<Vec<_>>();
    let listeners = binding.listeners;

    // One accept loop per listener, polled concurrently. The futures are
    // kept on this task (FuturesUnordered) rather than spawned per
    // address: on shutdown the `() = shutdown` branch wins the select and
    // the whole FuturesUnordered is dropped, dropping every accept loop —
    // and with it its `TcpListener`, so new accepts stop immediately.
    // Detached spawned loops would keep accepting through teardown and
    // need explicit aborts. Every loop runs forever, so `next()` can only
    // ever complete via shutdown, never `None`.
    use futures::StreamExt;
    let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    // Shared across all listeners so log-correlation conn_ids stay unique.
    let next_conn_id = Arc::new(AtomicU64::new(1));
    let mut accept_loops = futures::stream::FuturesUnordered::new();
    for listener in listeners {
        accept_loops.push(accept_loop(
            listener,
            egress.clone(),
            auth_state.clone(),
            permits.clone(),
            conn_health.clone(),
            next_conn_id.clone(),
            cfg.security.clone(),
        ));
    }
    let mut retries = retry_addresses
        .into_iter()
        .map(|address| binding::retry::retry_address_with(address, TcpListener::bind))
        .collect::<futures::stream::FuturesUnordered<_>>();

    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            biased;
            () = &mut shutdown => break,
            _ = accept_loops.next(), if !accept_loops.is_empty() => {
                warn!("accept loop exited unexpectedly");
                break;
            }
            recovered = retries.next(), if !retries.is_empty() => {
                if let Some((address, listener)) = recovered {
                    info!(listen_addr = %address, "SOCKS5 proxy listener recovered");
                    accept_loops.push(accept_loop(
                        listener,
                        egress.clone(),
                        auth_state.clone(),
                        permits.clone(),
                        conn_health.clone(),
                        next_conn_id.clone(),
                        cfg.security.clone(),
                    ));
                }
            }
        }
    }
    drop(retries);
    drop(accept_loops);

    // For the Tor egress, draining the handle takes the tunnel out of the
    // shared slot; dropping it triggers `tor-ptmgr` to terminate PT
    // subprocesses and releases arti's exclusive lock on its state
    // directory. The Job Object installed at startup kills anything that
    // leaks past this point. The upstream egress holds no such resources.
    if let Egress::Tor(handle, _, _) = egress {
        info!("stopping Tor client and pluggable transports");
        // Order matters: cancel first (no producer starts a new work
        // iteration), then drain the slot (in-flight tunnel reads see
        // `None`), then wait — bounded — for the producers to finish their
        // current operations, so their final store writes land before the
        // writer closes below.
        shutdown_producers(
            producer_token,
            producers,
            async {
                drop(handle.drain().await);
            },
            PRODUCER_JOIN_TIMEOUT,
        )
        .await;
        // Give arti's reactor a brief moment to flush the shutdown.
        // Empirically this is enough for the state-dir lock to be released
        // before the next run starts. No longer needed for writer ordering
        // (the join above now guarantees the producers finished), but kept
        // for the arti/PT teardown it was introduced for.
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Wait for the writer last: flush any retained snapshot and join
        // its actor task, so a publish that only recovered after the last
        // mutation is not silently lost when the runtime tears down. With
        // the producers joined above, nobody can write after this close.
        if let Some(Err(error)) = crate::bridge_store_writer::close_global().await {
            warn!(error = %error, "bridge health store had unpublished updates at shutdown");
        }
    }
    info!("bye");
    Ok(())
}

/// Shutdown choreography for the Tor-side background producers (bridge
/// maintenance, both watchdogs, the warmer, the circuit verifier), in the
/// order the bridge-store writer's contract requires:
///
/// 1. `token.cancel()` — every producer selects against `cancelled()`
///    before its next tick, so no NEW work iteration starts after this.
/// 2. `drain` runs — production passes the step that takes the tunnel out
///    of the shared `TorHandle` slot, so late tunnel reads see `None`.
/// 3. every producer task is joined, bounded by `join_timeout`. A producer
///    caught mid-operation (a `warm_bridge` handshake, the verifier's
///    non-cancellable `spawn_blocking` probe) finishes it and its final
///    store write lands BEFORE the caller closes the writer. A producer
///    still running past the budget is abandoned with a warning instead of
///    blocking shutdown forever.
///
/// Returns `true` when every producer finished within the budget.
async fn shutdown_producers(
    token: CancellationToken,
    producers: Vec<tokio::task::JoinHandle<()>>,
    drain: impl std::future::Future<Output = ()>,
    join_timeout: Duration,
) -> bool {
    token.cancel();
    drain.await;
    let joined = tokio::time::timeout(join_timeout, futures::future::join_all(producers)).await;
    match joined {
        Ok(results) => {
            for result in results {
                if let Err(error) = result {
                    warn!(%error, "bridge-store producer task ended with a join error at shutdown");
                }
            }
            true
        }
        Err(_elapsed) => {
            warn!(
                timeout = ?join_timeout,
                "background bridge tasks did not finish in time; continuing shutdown — \
                 their final store updates may be lost"
            );
            false
        }
    }
}

// Логика выбора upstream-egress ("CLI поверх конфига") живёт в своём
// модуле; реэкспорт сохраняет существующие вызовы и видимость через `super::*`.
use crate::upstream::pick_upstream;

/// Accept connections on `listener` forever, spawning one task per
/// connection. Accept errors are logged and retried with a backoff, so the
/// loop only ends by being dropped (shutdown).
///
/// `next_conn_id` is the shared, monotonic per-connection identifier for
/// log correlation — shared across every listener's accept loop, since
/// per-loop counters would hand out colliding conn_ids once several
/// listeners are bound. Wraps only after 2^64 connections — never, in
/// practice.
async fn accept_loop(
    listener: TcpListener,
    egress: Egress,
    auth: Option<Arc<AuthState>>,
    permits: Arc<tokio::sync::Semaphore>,
    conn_health: ConnHealthCounters,
    next_conn_id: Arc<AtomicU64>,
    security: SecurityConfig,
) {
    loop {
        let (client, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!(?e, "accept failed; retrying in {ACCEPT_ERROR_BACKOFF:?}");
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                continue;
            }
        };
        // Глобальный ingress-ACL: deny до permit/spawn — drop без ответных байт.
        if !security.client_access.allowed_clients.allows(peer.ip()) {
            debug!(%peer, "client rejected by security.client_access.allowed_clients");
            drop(client);
            continue;
        }
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
                security.block_onion,
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

use crate::startup::{
    classify_conn_failure, STAGE_CONNECT_TOR, STAGE_CONNECT_UPSTREAM, STAGE_HANDSHAKE, STAGE_RELAY,
};
pub(crate) use crate::startup::{ConnErrorKind, ConnStage};

// RPITIT + Send: внутренний интерфейс без динамической диспетчеризации.
trait TorConnector {
    fn connect<'a>(
        &'a mut self,
        tor: &'a TorTunnel,
        post: Option<&'a proxy_config::EndpointOverride>,
        host: &'a str,
        port: u16,
    ) -> impl std::future::Future<Output = arti_wrapper::Result<arti_wrapper::DataStream>> + Send + 'a;
}

struct RealTorConnector;

impl TorConnector for RealTorConnector {
    fn connect<'a>(
        &'a mut self,
        tor: &'a TorTunnel,
        post: Option<&'a proxy_config::EndpointOverride>,
        host: &'a str,
        port: u16,
    ) -> impl std::future::Future<Output = arti_wrapper::Result<arti_wrapper::DataStream>> + Send + 'a
    {
        connect_tor_route(tor, post, host, port)
    }
}

/// cancel-safe: NO — partial protocol replies/prefix writes/relay are terminal;
/// dropping this handler closes its owned client and egress, with no replay.
async fn handle_client(
    client: TcpStream,
    egress: Egress,
    auth: Option<Arc<AuthState>>,
    conn_health: ConnHealthCounters,
    block_onion: bool,
    conn_id: u64,
) -> Result<()> {
    handle_client_with_connector(
        client,
        egress,
        auth,
        conn_health,
        block_onion,
        conn_id,
        RealTorConnector,
    )
    .await
}

/// cancel-safe: NO — частичный ответ или relay терминальны; отмена закрывает поток.
async fn handle_client_with_connector<C: TorConnector + Send>(
    mut client: TcpStream,
    egress: Egress,
    auth: Option<Arc<AuthState>>,
    conn_health: ConnHealthCounters,
    block_onion: bool,
    conn_id: u64,
    mut connector: C,
) -> Result<()> {
    let started_at = std::time::Instant::now();
    // Absolute deadline for the whole handshake chain — armed once here and
    // never renewed per read.
    let deadline = tokio::time::Instant::now() + HANDSHAKE_DEADLINE;
    let proto_auth = auth.clone().map(|state| Arc::new(AuthStateVerifier(state)));
    let (mut req, proof) = socks5_proto::accept_verified(&mut client, deadline, proto_auth)
        .await
        .map_err(|error| match error {
            socks5_proto::VerifiedError::Handshake(error) => anyhow::Error::new(error),
            other => anyhow::Error::new(other),
        })
        .context(STAGE_HANDSHAKE)?
        .into_parts();
    let lease = match (auth.as_ref(), proof.as_ref()) {
        (Some(state), Some(proof)) => match tokio::time::timeout_at(deadline, state.admit(proof))
            .await
            .map_err(|_| anyhow::Error::new(resocks5_net::server::ServerError::Deadline))
            .context(STAGE_HANDSHAKE)?
        {
            Some(lease) => Some(lease),
            None => {
                req.reply(&mut client, Reply::Forbidden).await.ok();
                return Ok(());
            }
        },
        (None, None) => None,
        _ => {
            req.reply(&mut client, Reply::Forbidden).await.ok();
            return Ok(());
        }
    };
    // Consume the SDK-owned prefix once. A partial write is terminal: never replay.
    let pipeline = req.take_pipeline();
    let HostPort { host, port } = HostPort::parse(req.target())
        .ok_or_else(|| anyhow!("SDK returned an invalid target authority"))
        .context(STAGE_HANDSHAKE)?;

    // Global onion gate comes first. The per-account gate below remains
    // useful for CLI deployments that grant onion access selectively.
    if block_onion && socks5_proto::is_onion(host) {
        warn!(host = %host, "refused .onion connection: blocked by security.block_onion");
        drop(lease);
        req.reply(&mut client, Reply::Forbidden).await.ok();
        return Ok(());
    }

    // Политика и маршрут берутся только из допущенного снимка.
    if socks5_proto::is_onion(host) && lease.as_ref().is_some_and(|lease| !lease.allowed_onion()) {
        drop(lease);
        req.reply(&mut client, Reply::Forbidden).await.ok();
        return Ok(());
    }
    let peer_ip = client.peer_addr().ok().map(|addr| addr.ip());
    let user_allowed = match lease.as_ref().and_then(|lease| lease.allowed_clients()) {
        Some(acl) => peer_ip.is_some_and(|ip| acl.allows(ip)),
        None => true,
    };
    if !user_allowed {
        drop(lease);
        req.reply(&mut client, Reply::Forbidden).await.ok();
        return Ok(());
    }
    let (global_post, dns, upstream) = match &egress {
        Egress::Tor(_, post, dns) => (post.as_deref(), *dns, false),
        Egress::Upstream(_) => (None, false, true),
    };
    let post = match resolve_admitted_route(global_post, lease.as_ref(), dns, upstream) {
        Ok(post) => post,
        Err(error) => {
            drop(lease);
            warn!(%error, "account route rejected");
            req.reply(&mut client, Reply::Forbidden).await.ok();
            return Ok(());
        }
    };

    match egress {
        Egress::Tor(handle, _, _) => {
            handle.bridge_refresh().request();
            info!(host = ?host, port = port, "tunneling through Tor");
            // Read the *current* tunnel through the handle: a watchdog
            // rebuild swaps the slot, and new connections must pick up the
            // replacement. Returns None only while the server is draining
            // the slot at shutdown.
            let tor = match handle.tunnel().await {
                Some(t) => t,
                None => {
                    drop(lease);
                    req.reply(&mut client, Reply::GeneralFailure).await.ok();
                    conn_health.record_connect_failed();
                    return Err(anyhow!("tor tunnel unavailable (shutting down?)")
                        .context(STAGE_CONNECT_TOR));
                }
            };
            // Feed the watchdog: every attempt bumps the counter (so it can
            // tell "no traffic" from "circuits failing"), a success stamps
            // the last-good time it compares against.
            handle.health().record_attempt();
            let tor_result = handle
                .bridge_refresh()
                .track_connection(connector.connect(&tor, post.as_ref(), host, port))
                .await;
            drop(lease);
            let tor_stream = match tor_result {
                Ok(s) => {
                    handle.health().record_success();
                    handle.health().record_success_target(host, port);
                    conn_health.record_connect_ok();
                    info!(host = ?host, port = port, "tor connection established");
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
                    req.reply(&mut client, Reply::GeneralFailure).await.ok();
                    conn_health.record_connect_failed();
                    return Err(anyhow::Error::new(e).context(STAGE_CONNECT_TOR));
                }
            };
            req.reply(&mut client, Reply::Established).await?;
            // `DataStream` implements `futures::AsyncRead/Write`; wrap it for tokio.
            let mut tor_compat = tor_stream.compat();
            tor_compat.write_all(&pipeline).await.context(STAGE_RELAY)?;
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
                        host = ?host,
                        port = port,
                        elapsed = ?started_at.elapsed(),
                        bytes_client_to_remote = sent + pipeline.len() as u64,
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
            info!(host = ?host, port = port, "forwarding through upstream SOCKS5");
            let upstream_result = up.connect(host, port).await;
            drop(lease);
            let mut upstream_stream = match upstream_result {
                Ok(s) => {
                    // Успешный upstream-connect: счётчик до Established — как в Tor-ветке.
                    conn_health.record_connect_ok();
                    s
                }
                Err(e) => {
                    req.reply(&mut client, Reply::GeneralFailure).await.ok();
                    conn_health.record_connect_failed();
                    return Err(e.context(STAGE_CONNECT_UPSTREAM));
                }
            };
            req.reply(&mut client, Reply::Established).await?;
            // See the Tor branch for the field/counter semantics.
            upstream_stream
                .write_all(&pipeline)
                .await
                .context(STAGE_RELAY)?;
            match tokio::io::copy_bidirectional(&mut client, &mut upstream_stream).await {
                Ok((sent, recv)) => {
                    conn_health.record_relay_closed();
                    info!(
                        conn_id,
                        host = ?host,
                        port = port,
                        elapsed = ?started_at.elapsed(),
                        bytes_client_to_remote = sent + pipeline.len() as u64,
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

#[path = "listen/server_binding.rs"]
mod binding;

#[cfg(test)]
#[path = "listen/server_listen_tests.rs"]
mod listen_tests;

#[cfg(test)]
#[path = "listen/server_acl_tests.rs"]
mod acl_tests;
#[cfg(test)]
#[path = "listen/server_tests.rs"]
mod tests;

#[cfg(test)]
use crate::startup::onion_permitted;
