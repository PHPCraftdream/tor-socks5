//! The shared SOCKS5/HTTP CONNECT listener runtime: egress selection, the accept loop, and
//! the per-connection handler.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use arti_wrapper::PostPools;
#[cfg(test)]
use arti_wrapper::TorTunnel;
use auth::AuthState;
use resocks5_net::connect::HostPort;
use resocks5_net::server::Reply;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::config::SecurityConfig;
use crate::route::resolve_admitted_route;
pub(crate) use crate::route::{RealTorConnector, TorConnector};
use crate::startup::{
    classify_conn_failure, AuthStateVerifier, STAGE_CONNECT_TOR, STAGE_CONNECT_UPSTREAM,
    STAGE_HANDSHAKE, STAGE_RELAY,
};
use crate::upstream;
use crate::upstream::relay;
use crate::upstream::RelayRemote::{Tor, Upstream};
#[cfg(test)]
use tor_socks5_runtime::arti_observability::ObservationSink;
use tor_socks5_runtime::conn_health::ConnHealthCounters;
use tor_socks5_runtime::tor_watchdog::TorHandle;

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

/// Предельное время ожидания фоновых производителей после отмены.
/// Застрявшая задача прерывается, а её дескриптор сохраняется до завершения.
const PRODUCER_JOIN_TIMEOUT: Duration = Duration::from_secs(120);

/// Предельное время ожидания фоновых производителей после отмены.
/// Застрявшая задача прерывается, а её дескриптор сохраняется до завершения.
/// Tor egress: the live tunnel handle plus the global proxy pools and the
/// bookkeeping needed to route and shut down Tor-based connections.
#[derive(Clone)]
struct TorEgress {
    handle: TorHandle,
    global_pre: Option<Arc<proxy_config::ProxyPool>>,
    global_post: Option<Arc<proxy_config::ProxyPool>>,
    dns_enabled: bool,
    registry: Option<Arc<owners::OwnerRegistry>>,
    pools: Arc<PostPools>,
}

/// Where accepted connections egress. An enabled upstream SOCKS5 proxy
/// replaces Tor entirely.
#[derive(Clone)]
enum Egress {
    Tor(TorEgress),
    Upstream(Arc<upstream::Upstream>),
}

struct RegistryRunGuard(Arc<owners::OwnerRegistry>);
impl Drop for RegistryRunGuard {
    fn drop(&mut self) {
        self.0.begin_close();
    }
}

struct HandlerRunGuard(Arc<handlers::HandlerTasks>);
impl Drop for HandlerRunGuard {
    fn drop(&mut self) {
        self.0.begin_shutdown();
    }
}

async fn run_server_inner(
    set_stage: &mut (impl FnMut(crate::api::ServerStage) + Send),
    on_ready: &mut (impl FnMut(Vec<std::net::SocketAddr>) + Send),
    args: ServerArgs,
    shutdown: impl std::future::Future<Output = ()> + Send,
    writer_started: &std::sync::atomic::AtomicBool,
) -> Result<()> {
    tor_socks5_runtime::workers::begin_run_group()?;
    let result = run_server_body(set_stage, on_ready, args, shutdown, writer_started).await;
    lifecycle::finish_run_group(result).await
}
async fn run_server_body(
    set_stage: &mut (impl FnMut(crate::api::ServerStage) + Send),
    on_ready: &mut (impl FnMut(Vec<std::net::SocketAddr>) + Send),
    args: ServerArgs,
    shutdown: impl std::future::Future<Output = ()> + Send,
    writer_started: &std::sync::atomic::AtomicBool,
) -> Result<()> {
    set_stage(crate::api::ServerStage::Recovery);
    let startup_cancellation = CancellationToken::new();
    let shutdown = {
        let startup_cancellation = startup_cancellation.clone();
        async move {
            shutdown.await;
            startup_cancellation.cancel();
        }
    };
    tokio::pin!(shutdown);
    let ServerArgs {
        config,
        config_path,
        obs_sink,
        upstream_addr,
        upstream_user,
        upstream_pass,
        no_upstream,
        pt_binary,
        dns_startup_policy,
        test_hooks,
    } = args;
    let mut ctx = phases::RunContext {
        handler_guard: None,
        registry_guard: None,
        producer_guard: None,
        egress: None,
        binding: None,
        actual_addresses: Vec::new(),
        auth_state: None,
        owner_template: None,
        pre_socks: None,
        post_socks: None,
        obs_sink,
        upstream_addr,
        upstream_user,
        upstream_pass,
        no_upstream,
        pt_binary,
        dns_startup_policy,
        hooks: test_hooks,
        cfg: config,
        config_path,
        set_stage,
        on_ready,
        writer_started,
        startup_cancellation,
        cancelled: false,
        accept_loop_exited: false,
        shutdown: shutdown.as_mut(),
    };
    phases::phase_recovery(&mut ctx).await?;
    if ctx.cancelled {
        return Ok(());
    }
    phases::phase_validate(&mut ctx).await?;

    (ctx.set_stage)(crate::api::ServerStage::Bind);
    let listen = ctx.cfg.listen.clone();
    let mut shutdown = ctx.shutdown.as_mut();
    let binding = tokio::select! {
        biased;
        () = &mut shutdown => return Ok(()),
        result = binding::bind_listeners(&listen) => result?,
    };
    let actual_addresses = binding
        .listeners
        .iter()
        .map(TcpListener::local_addr)
        .collect::<std::io::Result<Vec<_>>>()
        .context("getting bound SOCKS5 listener addresses")?;
    ctx.binding = Some(binding);
    ctx.actual_addresses = actual_addresses;

    (ctx.set_stage)(crate::api::ServerStage::Config);
    // Cancellation + join plumbing for the Tor-side background producers.
    // Only the Tor egress spawns producers; the token and the collected
    // join handles stay unused (and empty) on the upstream path. Created
    // here so they outlive the egress match and are reachable from the
    // shutdown path below.
    let producer_owner = producers::ProducerTasks::retain()?;
    ctx.producer_guard = Some(producers::RunGuard(producer_owner.clone()));
    let producer_token = producer_owner.token();

    phases::phase_bootstrap(&mut ctx, &producer_owner, &producer_token).await?;
    if ctx.cancelled {
        return Ok(());
    }
    phases::phase_launch_producers(&mut ctx, &producer_owner, &producer_token).await;

    (ctx.set_stage)(crate::api::ServerStage::Config);
    if ctx.cfg.dns_server.enabled {
        phases::phase_dns(&mut ctx, &producer_owner, &producer_token).await?;
    }
    let handlers = phases::phase_serve(&mut ctx, &producer_owner, &producer_token).await?;
    phases::phase_shutdown(&mut ctx, &producer_owner, &handlers).await
}

#[cfg(test)]
pub(crate) use tor_socks5_runtime::conn_health::{ConnErrorKind, ConnStage};

#[allow(clippy::too_many_arguments)]
fn accept_loop_future(
    handlers: Arc<handlers::HandlerTasks>,
    listener: TcpListener,
    egress: Egress,
    auth: Option<Arc<AuthState>>,
    permits: Arc<tokio::sync::Semaphore>,
    tracking: handlers::ConnectionTracking,
    security: SecurityConfig,
    force_exit: bool,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    if force_exit {
        return Box::pin(async {});
    }
    Box::pin(handlers.accept_loop_tracked(listener, egress, auth, permits, tracking, security))
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
    let pools = match &egress {
        Egress::Tor(tor) => Arc::clone(&tor.pools),
        Egress::Upstream(_) => Arc::new(PostPools::new()),
    };
    handle_client_with_connector(
        client,
        egress,
        auth,
        conn_health,
        block_onion,
        conn_id,
        RealTorConnector::new(pools),
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
    let (global_pre, global_post, dns, upstream) = match &egress {
        Egress::Tor(tor) => (
            tor.global_pre.as_deref(),
            tor.global_post.as_deref(),
            tor.dns_enabled,
            false,
        ),
        Egress::Upstream(_) => (None, None, false, true),
    };
    let route = match resolve_admitted_route(global_pre, global_post, lease.as_ref(), dns, upstream)
    {
        Ok(post) => post,
        Err(error) => {
            drop(lease);
            warn!(%error, "account route rejected");
            req.reply(&mut client, Reply::Forbidden).await.ok();
            return Ok(());
        }
    };

    match &egress {
        Egress::Tor(tor) => {
            let leg = tor_branch::TorLeg {
                handle: &tor.handle,
                registry: tor.registry.as_ref(),
                global_pre,
                pre: route.pre.as_ref(),
                post: route.post.as_ref(),
                admitted: lease.is_some(),
            };
            let connected = tor_branch::connect(&leg, &mut connector, host, port).await;
            drop(lease);
            let tor_stream = match connected {
                Ok(stream) => {
                    conn_health.record_connect_ok();
                    info!(host = ?host, port = port, "tor connection established");
                    stream
                }
                Err(tor_branch::Failure::Forbidden) => {
                    warn!("account route rejected");
                    req.reply(&mut client, Reply::Forbidden).await.ok();
                    return Ok(());
                }
                Err(failure) => {
                    req.reply(&mut client, failure.reply()).await.ok();
                    conn_health.record_connect_failed();
                    return Err(failure.into_error().context(STAGE_CONNECT_TOR));
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
            match relay(&mut client, &mut tor_compat, conn_id, Tor).await {
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
            match relay(&mut client, &mut upstream_stream, conn_id, Upstream).await {
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

#[path = "phases.rs"]
mod phases;

#[path = "../tor/tor_watchdog/owners/producers.rs"]
mod producers;

#[path = "../tor/tor_watchdog/owners/handlers.rs"]
mod handlers;
#[cfg(test)]
use handlers::accept_loop;

#[path = "../tor/tor_watchdog/owners/global_init.rs"]
mod global_init;

#[path = "../tor/tor_watchdog/owners/mod.rs"]
mod owners;

#[path = "egress/pre_pool.rs"]
mod pre_pool;

#[path = "egress/tor_branch.rs"]
mod tor_branch;

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

#[path = "lifecycle.rs"]
mod lifecycle;
pub(crate) use global_init::TestRunHooks;
#[cfg(test)]
pub(crate) use lifecycle::run_server;
pub(crate) use lifecycle::{cleanup_failed_run, run_server_with_callbacks, ServerArgs};
