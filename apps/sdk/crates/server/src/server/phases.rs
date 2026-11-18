//! Monotonic startup/shutdown phases of `run_server_body`: recovery, validate,
//! bootstrap, producers, dns, serve, shutdown. Shared mutable state travels in
//! [`RunContext`]; each phase is a small step called in order by the
//! orchestrator in `server.rs`.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use arti_wrapper::PostPools;
use auth::{AuthState, UsersConfig};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::dns_wiring::{convert_custom_doh_providers, convert_dns_overrides, dns_cache_path};
use crate::route::{validate_account_routes, validate_post_compatibility};
use crate::startup::{
    ensure_bridges_file, validate_pre_compatibility, warn_enabled_onion_services_with_upstream,
};
use tor_socks5_runtime::arti_observability::ObservationSink;
use tor_socks5_runtime::conn_health::ConnHealthCounters;
use tor_socks5_runtime::pt::PtBinary;
use tor_socks5_runtime::tor_watchdog::TorHandle;

/// Shared mutable state carried across the `run_server_body` phases.
/// Field declaration order matches the drop order of the original locals
/// (handler/registry/producer guards first), so teardown semantics are
/// unchanged.
pub(super) struct RunContext<'a> {
    pub(super) handler_guard: Option<super::HandlerRunGuard>,
    pub(super) registry_guard: Option<super::RegistryRunGuard>,
    pub(super) producer_guard: Option<super::producers::RunGuard>,
    pub(super) egress: Option<super::Egress>,
    pub(super) binding: Option<super::binding::BoundListeners>,
    pub(super) actual_addresses: Vec<std::net::SocketAddr>,
    pub(super) auth_state: Option<Arc<AuthState>>,
    pub(super) owner_template: Option<anyhow::Result<arti_wrapper::Settings>>,
    pub(super) pre_socks: Option<Arc<proxy_config::ProxyPool>>,
    pub(super) post_socks: Option<Arc<proxy_config::ProxyPool>>,
    pub(super) obs_sink: ObservationSink,
    pub(super) upstream_addr: Option<String>,
    pub(super) upstream_user: Option<String>,
    pub(super) upstream_pass: Option<String>,
    pub(super) no_upstream: bool,
    pub(super) pt_binary: PtBinary,
    pub(super) dns_startup_policy: crate::api::DnsStartupPolicy,
    /// Injected test hooks; always `None` in production (empty type outside
    /// test builds).
    pub(super) hooks: Option<Arc<crate::server::global_init::TestRunHooks>>,
    pub(super) cfg: Config,
    pub(super) config_path: PathBuf,
    pub(super) set_stage: &'a mut (dyn FnMut(crate::api::ServerStage) + Send),
    pub(super) on_ready: &'a mut (dyn FnMut(Vec<std::net::SocketAddr>) + Send),
    pub(super) writer_started: &'a std::sync::atomic::AtomicBool,
    pub(super) startup_cancellation: CancellationToken,
    /// Set when a phase observed the shutdown signal during startup and the
    /// run should end with `Ok(())`.
    pub(super) cancelled: bool,
    pub(super) accept_loop_exited: bool,
    pub(super) shutdown: Pin<&'a mut (dyn Future<Output = ()> + Send)>,
}

impl RunContext<'_> {
    /// Test-only: an accept loop that exits immediately.
    pub(super) fn force_accept_loop_exit(&self) -> bool {
        #[cfg(test)]
        {
            self.hooks
                .as_ref()
                .is_some_and(|hooks| hooks.force_accept_loop_exit)
        }
        #[cfg(not(test))]
        {
            false
        }
    }
}

/// Phase 1: recover a prior failed run's writer slot and join final workers.
/// Sets `cancelled` when the shutdown signal won the race against recovery.
pub(super) async fn phase_recovery(ctx: &mut RunContext<'_>) -> Result<()> {
    let recovery = super::global_init::recover_startup();
    tokio::pin!(recovery);
    let mut shutdown = ctx.shutdown.as_mut();
    let cancelled_during_recovery = tokio::select! {
        biased;
        () = &mut shutdown => { recovery.await?; true }
        result = &mut recovery => { result?; false }
    };
    // A prior failed run may have left its writer behind. It is safe to close
    // only after all retained owners have recovered successfully.
    if let Some(result) = super::global_init::close_orphaned_store_writer().await {
        result?;
    }
    super::producers::join_final_workers().await?;
    if cancelled_during_recovery {
        ctx.cancelled = true;
    }
    Ok(())
}

/// Phase 2: load/validate configuration, resolve the egress (an enabled
/// upstream SOCKS5 proxy wins over Tor) and reject incompatible combinations —
/// including `dns_server.enabled` with an upstream proxy, which must fail
/// before any listener is bound.
pub(super) async fn phase_validate(ctx: &mut RunContext<'_>) -> Result<()> {
    let cfg = ctx.cfg.clone();
    let source = format!("file: {}", ctx.config_path.display());
    let pre_socks = cfg.pre_proxies.clone().map(Arc::new);
    validate_pre_compatibility(
        pre_socks.is_some(),
        cfg.dns_server.enabled,
        cfg.onion_services.iter().any(|service| service.enabled),
        false,
    )?;
    let post_socks = cfg.post_proxies.clone().map(Arc::new);
    validate_post_compatibility(post_socks.is_some(), cfg.dns_server.enabled, false)?;

    info!(%source, "loaded configuration");
    ensure_bridges_file(&cfg, &ctx.config_path).await;

    // Load the users registry (sits next to the main config). A missing file
    // is warned about once; when absent or empty, the SOCKS5 listener falls
    // back to the legacy NO_AUTH path.
    let users_path = UsersConfig::resolve_path(&ctx.config_path);
    if !users_path.exists() {
        tracing::warn!(
            path = %users_path.display(),
            "no users file — SOCKS5 will accept anonymous clients"
        );
    }
    let users = UsersConfig::load(&users_path).context("loading users registry")?;
    let config_ref = &ctx.config_path;
    tor_socks5_runtime::tor_setup::validate_owner_routes(&cfg, &users, config_ref, &ctx.pt_binary)?;
    let owner_template =
        tor_socks5_runtime::tor_setup::restricted_owner_settings(&cfg, config_ref, &ctx.pt_binary);
    validate_account_routes(
        &users,
        cfg.pre_proxies.as_ref(),
        cfg.post_proxies.as_ref(),
        cfg.dns_server.enabled,
        false,
    )?;
    let auth_state = if users.users.is_empty() {
        // A missing file was already warned about above; keep the info line
        // for an existing-but-empty registry.
        if users_path.exists() {
            info!(
                path = %users_path.display(),
                "no users configured — SOCKS5 will accept anonymous clients"
            );
        }
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
    let upstream = crate::upstream::pick_upstream(
        &cfg.upstream,
        ctx.upstream_addr.as_deref(),
        ctx.upstream_user.as_deref(),
        ctx.upstream_pass.as_deref(),
        ctx.no_upstream,
    )?;
    // Optional local DNS listener (opt-in, default OFF). Every DoH exchange
    // it performs is tunnelled through the live Tor tunnel, so the feature
    // requires the Tor egress: behind an upstream SOCKS5 proxy the premise
    // ("client DNS leaves the machine only inside Tor") cannot be honoured,
    // and refusing to start beats silently leaking plaintext queries.
    // Checked here so it fires before any listener is bound.
    if upstream.is_some() && cfg.dns_server.enabled {
        bail!(
            "dns_server.enabled requires Tor egress, not an upstream SOCKS5 proxy — \
             disable dns_server or remove the upstream"
        );
    }
    let egress = match upstream {
        Some(up) => {
            validate_pre_compatibility(pre_socks.is_some(), false, false, true)?;
            validate_post_compatibility(post_socks.is_some(), false, true)?;
            validate_account_routes(
                &users,
                cfg.pre_proxies.as_ref(),
                cfg.post_proxies.as_ref(),
                false,
                true,
            )?;
            (ctx.set_stage)(crate::api::ServerStage::Startup);
            warn_enabled_onion_services_with_upstream(&cfg);
            info!(
                upstream = %up.address(),
                auth = up.has_auth(),
                "egress via upstream SOCKS5 proxy — Tor is disabled"
            );
            Some(super::Egress::Upstream(Arc::new(up)))
        }
        None => None,
    };

    ctx.egress = egress;
    ctx.pre_socks = pre_socks;
    ctx.post_socks = post_socks;
    ctx.owner_template = Some(owner_template);
    ctx.auth_state = auth_state;
    Ok(())
}

/// Phase 3: bootstrap Tor (skipped on the upstream egress path), install the
/// owner registry and hand the initialized client over to the runtime. Sets
/// `cancelled` when the shutdown signal arrives during bootstrap.
pub(super) async fn phase_bootstrap(
    ctx: &mut RunContext<'_>,
    producer_owner: &Arc<super::producers::ProducerTasks>,
    producer_token: &CancellationToken,
) -> Result<()> {
    if ctx.egress.is_some() {
        return Ok(());
    }
    (ctx.set_stage)(crate::api::ServerStage::Startup);
    let cfg = ctx.cfg.clone();
    if cfg.tor.circuit_hops == 2 {
        warn!(
            "tor.circuit_hops=2 reduces anonymity: onion-service circuits have no middle relay. Ordinary exit circuits stay at 3 hops. Intended for censorship circumvention, not anonymity."
        );
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
    let preparation = super::global_init::SettingsInit::start(
        cfg.clone(),
        ctx.config_path.clone(),
        ctx.startup_cancellation.clone(),
        ctx.pt_binary.clone(),
        ctx.hooks.as_deref(),
    )?;
    let shutdown = &mut ctx.shutdown;
    let Some(settings) = super::global_init::wait_startup(shutdown, preparation.wait(), || {
        super::global_init::stop_startup(ctx.hooks.as_deref())
    })
    .await?
    else {
        ctx.cancelled = true;
        return Ok(());
    };
    if settings.bridges.is_empty() {
        bail!(
            "no bridges configured in {} — add at least one `lines: [ obfs4 ... ]` entry",
            Config::bridges_path(&ctx.config_path).display()
        );
    }
    let alive = settings.bridges.len();
    info!(count = alive, "using bridges");

    // Recovery has successfully cleared any writer from an earlier run.
    // Mark before init so even a panic after installing the process slot
    // routes through this run's cleanup without closing unrelated writers.
    ctx.writer_started
        .store(true, std::sync::atomic::Ordering::Release);
    super::global_init::init_store_writer(&ctx.config_path, ctx.hooks.as_deref());

    let init = super::global_init::GlobalInit::start(settings.clone(), ctx.hooks.as_deref())?;
    let _init_guard = super::global_init::InitGuard(init.clone());
    let Some(tor) = super::global_init::wait_startup(
        &mut ctx.shutdown,
        init.wait(ctx.hooks.as_deref()),
        || async {
            init.cancel();
            super::global_init::stop_startup(ctx.hooks.as_deref()).await?;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            if let Some(result) =
                super::global_init::close_store_writer(Some(deadline), ctx.hooks.as_deref()).await
            {
                result?;
            }
            Ok(())
        },
    )
    .await
    // The input error's already-contextualized primary is retained in
    // StartupFailure::Error; the stage is added at the lifecycle API.
    .context("failed to bootstrap Tor")?
    else {
        ctx.cancelled = true;
        return Ok(());
    };

    // Single indirection point for the live `TorClient`: the accept
    // loop and the maintenance loop read the *current* tunnel
    // through this handle, so a watchdog rebuild becomes visible to
    // both without re-distribution. Cheap to clone (one
    // `Arc<RwLock<_>>` + two atomics).
    let handle = TorHandle::new_with_settings(tor, &settings);

    let template = if settings.pre_endpoint.is_some() {
        Ok(settings.clone())
    } else {
        ctx.owner_template
            .take()
            .expect("owner template set by phase_validate")
    };
    let owners = Arc::new(super::owners::OwnerRegistry::new_with_template(
        handle.clone(),
        settings.pre_endpoint.clone(),
        template,
    )?);
    owners.retain_for_shutdown()?;
    ctx.registry_guard = Some(super::RegistryRunGuard(owners.clone()));
    init.complete_handoff()?;
    if super::global_init::launch_background(ctx.hooks.as_deref()) {
        let mut launch = super::producers::LaunchGuard::new(producer_owner.clone());
        tor_socks5_runtime::bridge_producers::launch_producers(
            handle.clone(),
            ctx.config_path.clone(),
            &cfg,
            ctx.obs_sink.clone(),
            settings,
            ctx.pt_binary.clone(),
            producer_token.clone(),
            &mut launch.handles,
        );

        // Onion services from the config: one more producer (launches
        // each enabled service, forwards its virtual ports to local
        // targets, holds the onion keystore lock for their lifetime).
        // Gated on the `onion-service` feature; a build without it only
        // warns — missing support is not an error.
        #[cfg(feature = "onion-service")]
        crate::onion::service::spawn_services(
            handle.clone(),
            &cfg.onion_services,
            &ctx.config_path,
            producer_token.clone(),
            &mut launch.handles,
        );
        #[cfg(not(feature = "onion-service"))]
        {
            let enabled = cfg
                .onion_services
                .iter()
                .filter(|service| service.enabled)
                .count();
            if enabled > 0 {
                warn!(
                    "built without onion-service support; {enabled} onion service(s) not started"
                );
            }
        }

        launch.commit();
    }
    ctx.egress = Some(super::Egress::Tor(super::TorEgress {
        handle,
        global_pre: ctx.pre_socks.take(),
        global_post: ctx.post_socks.take(),
        dns_enabled: cfg.dns_server.enabled,
        registry: Some(owners),
        pools: Arc::new(PostPools::new()),
    }));
    Ok(())
}

/// Phase 4: launch the background pool probers that keep quarantined proxies
/// under observation. Only runs on the Tor egress path.
pub(super) async fn phase_launch_producers(
    ctx: &mut RunContext<'_>,
    producer_owner: &Arc<super::producers::ProducerTasks>,
    producer_token: &CancellationToken,
) {
    let Some(super::Egress::Tor(tor)) = &ctx.egress else {
        return;
    };
    // Quarantined post proxies are re-checked in the background so a revived
    // one returns to rotation; stopped by the same token as the other producers.
    let tunnel_source = tor.handle.clone();
    let pools = tor.pools.clone();
    producer_owner.add(arti_wrapper::spawn_post_prober(
        pools,
        move || {
            let handle = tunnel_source.clone();
            async move { handle.tunnel().await }
        },
        producer_token.clone(),
    ));
    // Pre pool members are Tor clients of their own. Those of the global
    // pool start in the background, and quarantined ones are probed
    // directly; both stop with the other producers.
    if let Some(registry) = tor.registry.clone() {
        producer_owner.add(super::pre_pool::spawn_prober(
            registry.clone(),
            producer_token.clone(),
        ));
        if let Some(pool) = tor.global_pre.as_deref().filter(|pool| pool.len() > 1) {
            let members = pool.members().iter().map(crate::route::pre_endpoint);
            if let Some(start) = registry.start_background(members.collect()).await {
                producer_owner.add(start);
            }
        }
    }
}

/// Phase 5: start the optional DNS-over-Tor listener and wait for its startup
/// readiness when the policy demands it. Extends `actual_addresses` with the
/// DNS listener addresses.
pub(super) async fn phase_dns(
    ctx: &mut RunContext<'_>,
    producer_owner: &Arc<super::producers::ProducerTasks>,
    producer_token: &CancellationToken,
) -> Result<()> {
    let Some(super::Egress::Tor(tor)) = &ctx.egress else {
        // Defensive: `phase_validate` rejects `dns_server.enabled` together
        // with an upstream proxy before bind, so upstream egress never
        // reaches this phase.
        bail!(
            "dns_server.enabled requires Tor egress, not an upstream SOCKS5 proxy — \
             disable dns_server or remove the upstream"
        );
    };
    let cfg = ctx.cfg.clone();
    let custom = convert_custom_doh_providers(&cfg.dns_server.custom_doh_providers);
    let pool =
        dns_server::providers::provider_pool(&custom, cfg.dns_server.disable_builtin_providers);
    let overrides = convert_dns_overrides(&cfg.dns_server.overrides);
    let cache_path = dns_cache_path(&ctx.config_path);
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
    let producer_handle = tor.handle.clone();
    let dns_token = producer_token.clone();
    let (dns_ready_tx, mut dns_ready_rx) = match ctx.dns_startup_policy {
        crate::api::DnsStartupPolicy::Required => {
            let (tx, rx) = tokio::sync::oneshot::channel();
            (Some(tx), Some(rx))
        }
        crate::api::DnsStartupPolicy::Background => (None, None),
    };
    producer_owner.add(tokio::spawn(async move {
        // The inner per-call clone makes the future 'static: the closure
        // owns its handle, and `tunnel()` snapshots the current slot so a
        // watchdog rebuild is picked up on the next query.
        let tunnel = move || {
            let handle = producer_handle.clone();
            async move { handle.tunnel().await }
        };
        let result = match dns_ready_tx {
            Some(ready) => {
                dns_server::server::run_with_client_access_and_ready(
                    &dns_listen,
                    tunnel,
                    cache,
                    pool,
                    overrides,
                    cache_path,
                    dns_token,
                    dns_client_access,
                    ready,
                )
                .await
            }
            None => {
                dns_server::server::run_with_client_access(
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
            }
        };
        if let Err(error) = result {
            error!(%error, "dns server exited");
        }
    }));
    if let Some(mut ready) = dns_ready_rx.take() {
        (ctx.set_stage)(crate::api::ServerStage::Bind);
        let mut shutdown = ctx.shutdown.as_mut();
        let result = tokio::select! {
            biased;
            result = &mut ready => result,
            () = &mut shutdown => {
                (ctx.set_stage)(crate::api::ServerStage::Cancelled);
                bail!("server startup cancelled");
            }
        };
        let dns_addresses = result
            .map_err(|_| anyhow!("DNS listener exited before reporting startup readiness"))??;
        ctx.actual_addresses.extend(dns_addresses);
    }
    Ok(())
}

/// Phase 6: start the accept loops (and listener-rebind retries) and serve
/// until shutdown or an unexpected accept-loop exit. Returns the handler
/// task set for the shutdown phase; `accept_loop_exited` records whether an
/// accept loop exited on its own.
pub(super) async fn phase_serve(
    ctx: &mut RunContext<'_>,
    producer_owner: &Arc<super::producers::ProducerTasks>,
    producer_token: &CancellationToken,
) -> Result<Arc<super::handlers::HandlerTasks>> {
    (ctx.set_stage)(crate::api::ServerStage::Startup);
    // Periodic connection-health summary: drains a rolling window of
    // accept-loop counters (attempts, established, errors by kind) into one
    // structured log line per interval. Pure observation — wired for both
    // the Tor and upstream egress paths alike. Enabled by default (unlike
    // `warm_pool`), since it changes nothing about live traffic.
    let conn_health = ConnHealthCounters::default();
    producer_owner.add(tokio::spawn(
        tor_socks5_runtime::conn_health::run_conn_health_logger(
            conn_health.clone(),
            ctx.cfg.conn_health,
            producer_token.child_token(),
        ),
    ));

    // Skip only local availability failures, visibly; fail fast if none bind
    // or an unexpected error occurs. Every successful listener shares admission.
    let binding = ctx.binding.take().expect("binding set by run_server_body");
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
    let permits = Arc::new(tokio::sync::Semaphore::new(
        super::MAX_CONCURRENT_CONNECTIONS,
    ));
    // Shared across all listeners so log-correlation conn_ids stay unique.
    let tracking = super::handlers::ConnectionTracking {
        conn_health,
        next_conn_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
    };
    let handlers = Arc::new(super::handlers::HandlerTasks::new());
    handlers.retain()?;
    ctx.handler_guard = Some(super::HandlerRunGuard(handlers.clone()));
    let mut handler_reap = tokio::time::interval(Duration::from_secs(1));
    let mut accept_loops = futures::stream::FuturesUnordered::new();
    for listener in listeners {
        accept_loops.push(super::accept_loop_future(
            handlers.clone(),
            listener,
            ctx.egress.as_ref().expect("egress set").clone(),
            ctx.auth_state.clone(),
            permits.clone(),
            tracking.clone(),
            ctx.cfg.security.clone(),
            ctx.force_accept_loop_exit(),
        ));
    }
    let mut retries = retry_addresses
        .into_iter()
        .map(|address| super::binding::retry::retry_address_with(address, TcpListener::bind))
        .collect::<futures::stream::FuturesUnordered<_>>();

    (ctx.set_stage)(crate::api::ServerStage::Runtime);
    super::global_init::server_ready(ctx.hooks.as_deref());
    (ctx.on_ready)(ctx.actual_addresses.clone());
    loop {
        let mut shutdown = ctx.shutdown.as_mut();
        tokio::select! {
            biased;
            () = &mut shutdown => break,
            _ = handler_reap.tick() => handlers.reap().await,
            _ = accept_loops.next(), if !accept_loops.is_empty() => {
                ctx.accept_loop_exited = true;
                warn!("accept loop exited unexpectedly");
                break;
            }
            recovered = retries.next(), if !retries.is_empty() => {
                if let Some((address, listener)) = recovered {
                    info!(listen_addr = %address, "SOCKS5 proxy listener recovered");
                    if let Ok(local_addr) = listener.local_addr() {
                        if !ctx.actual_addresses.contains(&local_addr) {
                            ctx.actual_addresses.push(local_addr);
                            (ctx.on_ready)(ctx.actual_addresses.clone());
                        }
                    }
                    accept_loops.push(super::accept_loop_future(
                        handlers.clone(),
                        listener,
                        ctx.egress.as_ref().expect("egress set").clone(),
                        ctx.auth_state.clone(),
                        permits.clone(),
                        tracking.clone(),
                        ctx.cfg.security.clone(),
                        ctx.force_accept_loop_exit(),
                    ));
                }
            }
        }
    }
    drop(retries);
    drop(accept_loops);
    if let Some(guard) = &ctx.registry_guard {
        guard.0.begin_close();
    }
    Ok(handlers)
}

/// Phase 7: tear the run down — handlers, producers, owner registry, Tor
/// client (with the arti-flush grace), store writer — and fold every
/// shutdown error into the final result.
pub(super) async fn phase_shutdown(
    ctx: &mut RunContext<'_>,
    producer_owner: &Arc<super::producers::ProducerTasks>,
    handlers: &Arc<super::handlers::HandlerTasks>,
) -> Result<()> {
    let egress = ctx.egress.take().expect("egress still present at shutdown");
    let mut shutdown_errors = super::producers::ProducerFailures::default();
    if let Err(error) = handlers.shutdown().await {
        shutdown_errors.push(error);
    }
    if let super::Egress::Tor(tor) = egress {
        info!("stopping Tor client and pluggable transports");
        // Join producers before shutting down their shared PT owner.
        producer_owner.cancel();
        if let Err(error) = producer_owner.join(super::PRODUCER_JOIN_TIMEOUT).await {
            warn!(%error, "producer graceful shutdown failed; aborting");
            shutdown_errors.push(error);
            producer_owner.abort();
            if let Err(error) = producer_owner.join(Duration::from_secs(5)).await {
                shutdown_errors.push(error);
            }
        }
        let mut registry_closed = true;
        if let Some(guard) = &ctx.registry_guard {
            if let Err(error) = guard
                .0
                .close_with_deadline(tokio::time::Instant::now() + Duration::from_secs(5))
                .await
            {
                registry_closed = false;
                shutdown_errors.push(error);
            }
        }
        if registry_closed {
            drop(tor.handle.drain().await);
        }
        // Give arti's reactor a brief moment to flush the shutdown.
        // Empirically this is enough for the state-dir lock to be released
        // before the next run starts. No longer needed for writer ordering
        // (the join above now guarantees the producers finished), but kept
        // for the arti/PT teardown it was introduced for.
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Close the writer last: flush any retained snapshot and join its
        // actor task, so a publish that only recovered after the last
        // mutation is not silently lost when the runtime tears down. The
        // producers are already joined above; this close is bounded — on
        // timeout the writer stays retained in its closing slot and late
        // flushes still land.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        if let Some(Err(error)) =
            super::global_init::close_store_writer(Some(deadline), ctx.hooks.as_deref()).await
        {
            warn!(error = %error, "bridge health store had unpublished updates at shutdown");
            shutdown_errors.push(error);
        }
        if let Err(error) = super::producers::join_final_workers().await {
            shutdown_errors.push(error);
        }
    } else {
        producer_owner.cancel();
        if let Err(error) = producer_owner.join(Duration::from_secs(5)).await {
            shutdown_errors.push(error);
        }
    }
    let shutdown_result = shutdown_errors.into_result();
    if ctx.accept_loop_exited {
        return Err(match shutdown_result {
            Ok(()) => anyhow!("accept loop exited unexpectedly"),
            Err(cleanup) => cleanup.context("accept loop exited unexpectedly"),
        });
    }
    shutdown_result?;
    info!("bye");
    Ok(())
}
