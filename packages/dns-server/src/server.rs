//! Plain DNS frontend. Local policy and cache hits bypass backend admission.
//! Misses share 64 slots and one absolute 30-second resolution deadline.

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use arti_wrapper::TorTunnel;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use hickory_proto::op::{Message, Query, ResponseCode};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Semaphore;
use tokio::time::{interval, timeout_at, Instant, MissedTickBehavior};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::cache::DnsCache;
use crate::doh_client::resolve_with_pool;
use crate::error::DnsServerError;
use crate::overrides::{
    find_override, resolve_via_dns_server, resolve_via_system, DnsOverride, OverrideResolver,
};
use crate::query_statistics::{QueryStatistics, RecordOutcome, StatisticsPaths, StatisticsWorker};
use crate::types::{DohProvider, ResolvedAnswer};

#[path = "server_listener.rs"]
mod listener;
#[path = "server_local.rs"]
mod local;
#[path = "server_socket_options.rs"]
mod socket_options;
#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;
#[path = "server_wire.rs"]
mod wire;

const MAX_DNS_CONCURRENT_QUERIES: usize = 64;
const RESOLUTION_TIMEOUT: Duration = Duration::from_secs(30);
const CACHE_SAVE_INTERVAL: Duration = Duration::from_secs(300);

struct QueryCtx<T> {
    tunnel: T,
    cache: Arc<DnsCache>,
    providers: Arc<Vec<DohProvider>>,
    overrides: Arc<Vec<DnsOverride>>,
    /// Actual UDP and TCP endpoints, never configured port-zero placeholders.
    endpoints: Arc<Vec<SocketAddr>>,
    route_probe: local::RouteProbe,
    statistics: Option<QueryStatistics>,
}

impl<T: Clone> Clone for QueryCtx<T> {
    fn clone(&self) -> Self {
        Self {
            tunnel: self.tunnel.clone(),
            cache: self.cache.clone(),
            providers: self.providers.clone(),
            overrides: self.overrides.clone(),
            endpoints: self.endpoints.clone(),
            route_probe: self.route_probe.clone(),
            statistics: self.statistics.clone(),
        }
    }
}

/// Serve DNS on all requested UDP/TCP endpoints until cancellation.
/// cancel-safe: NO for forced cancellation during persistence: socket work is
/// scoped and dropped, but statistics/cache publication can outlive this future.
/// Explicit shutdown stops networking, joins prefetch and drains statistics,
/// then drains active cache publication before the final save.
pub async fn run<T, F>(
    listen: &[String],
    tunnel: T,
    cache: Arc<DnsCache>,
    providers: Vec<DohProvider>,
    overrides: Vec<DnsOverride>,
    cache_path: PathBuf,
    shutdown: CancellationToken,
) -> Result<()>
where
    T: Fn() -> F + Send + Clone + 'static,
    F: Future<Output = Option<TorTunnel>> + Send + 'static,
{
    if listen.is_empty() {
        bail!("no listen addresses configured for the DNS server");
    }
    let mut udp_sockets = Vec::with_capacity(listen.len());
    let mut tcp_listeners = Vec::with_capacity(listen.len());
    let mut endpoints = Vec::with_capacity(listen.len() * 2);
    for addr in listen {
        let (udp, tcp) = bind_pair(addr).await?;
        let bound = udp.local_addr()?;
        endpoints.extend(listener_endpoints(&udp, &tcp)?);
        info!(listen_addr = %bound, "DNS server listening (UDP + TCP)");
        udp_sockets.push(Arc::new(udp));
        tcp_listeners.push(tcp);
    }
    let (statistics, worker) = match StatisticsWorker::open(StatisticsPaths::from_cache_path(
        &cache_path,
    ))
    .await
    {
        Ok((handle, worker)) => (Some(handle), Some(worker)),
        Err(error) => {
            warn!(%error, "DNS query accounting degraded: statistics unavailable; prefetch disabled");
            (None, None)
        }
    };
    let ctx = QueryCtx {
        tunnel,
        cache: cache.clone(),
        providers: Arc::new(providers),
        overrides: Arc::new(overrides),
        endpoints: Arc::new(endpoints),
        route_probe: local::route_probe(),
        statistics,
    };
    serve_owned_lifecycle(
        (udp_sockets, tcp_listeners),
        ctx,
        worker,
        shutdown,
        |worker| async move {
            if let Some(worker) = worker {
                worker.shutdown().await?;
            }
            Ok(())
        },
        || {},
        || cache.save(&cache_path),
    )
    .await
}

/// Own the production listeners, scheduler, statistics drain and cache saves.
/// The per-instance drain/observer seams expose shutdown IO, not an alternative
/// ordering implementation. Neither the tunnel factory nor these closures need Sync.
/// cancel-safe: NO — forced drop cannot await statistics or cache publication;
/// explicit cancellation stops networking, joins prefetch, then awaits the drain.
async fn serve_owned_lifecycle<T, F, Drain, Drained, Stopped, Make, Save>(
    listeners: (Vec<Arc<UdpSocket>>, Vec<TcpListener>),
    ctx: QueryCtx<T>,
    worker: Option<StatisticsWorker>,
    shutdown: CancellationToken,
    drain: Drain,
    networking_stopped: Stopped,
    save: Make,
) -> Result<()>
where
    T: Fn() -> F + Send + Clone + 'static,
    F: Future<Output = Option<TorTunnel>> + Send + 'static,
    Drain: FnOnce(Option<StatisticsWorker>) -> Drained,
    Drained: Future<Output = Result<()>>,
    Stopped: FnOnce(),
    Make: FnMut() -> Save,
    Save: Future<Output = Result<(), DnsServerError>>,
{
    let (udp_sockets, tcp_listeners) = listeners;
    let backend = Arc::new(Semaphore::new(MAX_DNS_CONCURRENT_QUERIES));
    let connections = Arc::new(Semaphore::new(listener::MAX_TCP_CONNECTIONS));
    let mut udp_loops = udp_sockets
        .into_iter()
        .map(|socket| listener::udp_loop(socket, ctx.clone(), backend.clone()))
        .collect::<FuturesUnordered<_>>();
    let mut tcp_loops = tcp_listeners
        .into_iter()
        .map(|socket| listener::tcp_loop(socket, ctx.clone(), backend.clone(), connections.clone()))
        .collect::<FuturesUnordered<_>>();
    let refresh_ctx = ctx.clone();
    let refresh_backend = backend.clone();
    serve_with_saves(
        async move {
            let networking = async move {
                tokio::select! {
                    _ = udp_loops.next() => Err(anyhow::anyhow!("UDP DNS listener loop exited unexpectedly")),
                    _ = tcp_loops.next() => Err(anyhow::anyhow!("TCP DNS listener loop exited unexpectedly")),
                }
            };
            let mut networking = Box::pin(networking);
            let stop_prefetch = CancellationToken::new();
            let mut worker = worker;
            {
                let mut scheduler_done = worker.is_none();
                let scheduler = async {
                    if let Some(worker) = worker.as_mut() {
                        crate::popular_prefetch::run(worker, move |question| {
                            refresh_question(refresh_ctx.clone(), question, refresh_backend.clone())
                        }, stop_prefetch.clone()).await
                    } else {
                        std::future::pending::<Result<()>>().await
                    }
                };
                let mut scheduler = Box::pin(scheduler);
                let result = loop {
                    tokio::select! {
                        biased;
                        () = shutdown.cancelled() => break Ok(()),
                        result = &mut networking => break result,
                        result = &mut scheduler, if !scheduler_done => {
                            scheduler_done = true;
                            if let Err(error) = result {
                                warn!(%error, "DNS statistics/prefetch worker degraded; foreground continues");
                            }
                        }
                    }
                };
                // Stop every producer before closing/draining the accepted statistics.
                drop(networking);
                networking_stopped();
                stop_prefetch.cancel();
                if !scheduler_done {
                    if let Err(error) = scheduler.as_mut().await {
                        warn!(%error, "DNS prefetch failed during cancellation");
                    }
                }
                drop(scheduler);
                if let Err(error) = drain(worker.take()).await {
                    warn!(%error, "DNS accounting degraded: final statistics drain/publication failed");
                }
                result
            }
        },
        save,
        // The lifecycle above owns cancellation and must drain before final save.
        CancellationToken::new(),
    ).await
}

/// Bind attempts for an ephemeral (port 0) UDP+TCP pair.
const EPHEMERAL_BIND_ATTEMPTS: usize = 32;

/// First port of the IANA dynamic range and its size.
const DYNAMIC_PORT_START: u16 = 49152;
const DYNAMIC_PORT_COUNT: u64 = 16384;

/// cancel-safe: yes — a failed/cancelled TCP bind drops the already bound UDP socket.
pub(crate) async fn bind_pair(addr: &str) -> Result<(UdpSocket, TcpListener)> {
    bind_pair_with(addr, TcpListener::bind).await
}

fn port_collision(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied
    )
}

/// An unpredictable port of the dynamic range. The OS hands out ephemeral
/// ports almost sequentially, so inside a wide reserved band (Windows excludes
/// whole 100-port blocks per protocol, UDP and TCP differently) retrying port 0
/// keeps landing in the same band.
fn random_dynamic_port() -> u16 {
    use std::hash::BuildHasher;
    let random = std::collections::hash_map::RandomState::new().hash_one(());
    DYNAMIC_PORT_START + (random % DYNAMIC_PORT_COUNT) as u16
}

/// Bind a UDP socket and a TCP listener on the same address. For a requested
/// port of 0 the first attempt lets the OS choose; a port collision on either
/// protocol (`AddrInUse`, or `PermissionDenied` for a reserved port, i.e.
/// `WSAEACCES`) is retried on a random dynamic port. A fixed port and any other
/// error fail at once.
/// cancel-safe: yes — each attempt owns its sockets and drops them on failure.
async fn bind_pair_with<B, Fut>(addr: &str, mut bind_tcp: B) -> Result<(UdpSocket, TcpListener)>
where
    B: FnMut(SocketAddr) -> Fut,
    Fut: Future<Output = std::io::Result<TcpListener>>,
{
    let requested = addr.parse::<SocketAddr>().ok();
    let ephemeral = requested.is_some_and(|a| a.port() == 0);
    let mut target = addr.to_owned();
    for attempt in 1..=EPHEMERAL_BIND_ATTEMPTS {
        let retry = ephemeral && attempt < EPHEMERAL_BIND_ATTEMPTS;
        let retry_with_random_port = |target: &mut String| {
            if let Some(requested) = requested {
                *target = SocketAddr::new(requested.ip(), random_dynamic_port()).to_string();
            }
        };
        let udp = match UdpSocket::bind(&target).await {
            Ok(udp) => udp,
            Err(error) if retry && port_collision(&error) => {
                retry_with_random_port(&mut target);
                continue;
            }
            Err(error) => {
                return Err(anyhow::Error::new(error)
                    .context(format!("failed to bind UDP DNS listener on {target}")))
            }
        };
        let bound = udp.local_addr()?;
        match bind_tcp(bound).await {
            Ok(tcp) => return Ok((udp, tcp)),
            Err(error) if retry && port_collision(&error) => retry_with_random_port(&mut target),
            Err(error) => {
                return Err(anyhow::Error::new(error)
                    .context(format!("failed to bind TCP DNS listener on {bound}")))
            }
        }
    }
    unreachable!("the last attempt returns its own error")
}

/// Keep backend SocketAddr APIs while recording actual per-socket coverage.
fn listener_endpoints(udp: &UdpSocket, tcp: &TcpListener) -> Result<Vec<SocketAddr>> {
    let mut endpoints = Vec::with_capacity(4);
    for (bound, socket) in [
        (udp.local_addr()?, socket2::SockRef::from(udp)),
        (tcp.local_addr()?, socket2::SockRef::from(tcp)),
    ] {
        endpoints.push(bound);
        if bound.is_ipv6() {
            let only_v6 = socket_options::only_v6(&socket)
                .with_context(|| format!("failed to read DNS listener IPV6_V6ONLY on {bound}"))?;
            if bound.ip().is_unspecified() && !only_v6 {
                endpoints.push(SocketAddr::from((
                    std::net::Ipv4Addr::UNSPECIFIED,
                    bound.port(),
                )));
            }
        }
    }
    Ok(endpoints)
}

/// cancel-safe: NO for forced cancellation during a cache publication: the
/// cache's blocking worker owns the serialization guard until publication ends.
/// Explicit shutdown stops socket work first and drains the one active save.
async fn serve_with_saves<L, S, Make>(
    listeners: L,
    mut save: Make,
    shutdown: CancellationToken,
) -> Result<()>
where
    L: Future<Output = Result<()>>,
    S: Future<Output = Result<(), DnsServerError>>,
    Make: FnMut() -> S,
{
    let mut listeners = Box::pin(listeners);
    let mut saves = FuturesUnordered::new();
    let mut ticker = interval(CACHE_SAVE_INTERVAL);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    ticker.tick().await;
    let result = loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => break Ok(()),
            result = &mut listeners => break result,
            result = saves.next(), if !saves.is_empty() => {
                if let Some(Err(error)) = result { warn!(%error, "periodic dns cache save failed"); }
            }
            _ = ticker.tick() => {
                if saves.is_empty() { saves.push(save()); }
            }
        }
    };
    drop(listeners);
    while let Some(result) = saves.next().await {
        if let Err(error) = result {
            warn!(%error, "periodic dns cache save failed during drain");
        }
    }
    if let Err(error) = save().await {
        warn!(%error, "final dns cache save failed at shutdown");
    }
    result
}

/// Local answers always precede every external route, even a wildcard override.
/// Explicit overrides only bypass the non-loopback own-address PTR suppression.
/// cancel-safe: yes — local preflight owns its bounded, payload-free probe.
fn inline_answer<'a, T>(
    ctx: &QueryCtx<T>,
    question: &'a Query,
) -> impl Future<Output = Option<ResolvedAnswer>> + Send + 'a {
    let host = wire::hostname_of(question);
    let explicit_override = find_override(&ctx.overrides, &host).is_some();
    // Snapshot only local-policy/cache state before constructing the future:
    // borrowing QueryCtx across await would require the tunnel factory to be Sync.
    let endpoints = Arc::clone(&ctx.endpoints);
    let cache = Arc::clone(&ctx.cache);
    let probe = ctx.route_probe.clone();
    async move {
        local::preflight_with_probe(question, &host, &endpoints, explicit_override, move |ip| {
            probe(ip)
        })
        .await
        .or_else(|| cache.get(question))
    }
}

/// cancel-safe: yes — timeout drops tunnel acquisition and the current owned
/// transport future. No detached resolution task exists. Cache insertion occurs
/// synchronously only after a complete DNS result, including NXDOMAIN/NODATA.
async fn resolve_miss<T, F>(
    ctx: QueryCtx<T>,
    question: Query,
    deadline: Instant,
) -> Option<ResolvedAnswer>
where
    T: Fn() -> F + Send + Clone + 'static,
    F: Future<Output = Option<TorTunnel>> + Send + 'static,
{
    finish_miss(deadline, async move {
        let host = wire::hostname_of(&question);
        let answer = if let Some(entry) = find_override(&ctx.overrides, &host) {
            match &entry.resolver {
                OverrideResolver::Dns { server } => {
                    resolve_via_dns_server(&question, *server, &ctx.endpoints).await?
                }
                OverrideResolver::System => resolve_via_system(&question, &ctx.endpoints).await?,
            }
        } else {
            let Some(answer) = acquire_then_resolve(ctx.tunnel, |tor| {
                pool_exchange(&question, tor, &ctx.providers)
            })
            .await?
            else {
                return Ok(None);
            };
            answer
        };
        ctx.cache.insert(&question, &answer);
        Ok::<_, DnsServerError>(Some(answer))
    })
    .await
}

// Erase TLS/provider future layout at the exchange boundary, not by raising
// recursion_limit. The owning box is dropped by the same absolute miss deadline.
fn pool_exchange<'a>(
    question: &'a Query,
    tor: TorTunnel,
    providers: &'a [DohProvider],
) -> futures::future::BoxFuture<'a, Result<ResolvedAnswer, DnsServerError>> {
    Box::pin(async move { resolve_with_pool(question, &tor, providers).await })
}

/// cancel-safe: yes — acquisition and exchange are owned child futures, with no
/// detached work. This composition permits deadline tests without constructing Tor.
async fn acquire_then_resolve<T, F, R, Exchange, E>(
    acquire: T,
    exchange: Exchange,
) -> Result<Option<ResolvedAnswer>, DnsServerError>
where
    T: FnOnce() -> F,
    F: Future<Output = Option<R>>,
    Exchange: FnOnce(R) -> E,
    E: Future<Output = Result<ResolvedAnswer, DnsServerError>>,
{
    let Some(resource) = acquire().await else {
        return Ok(None);
    };
    exchange(resource).await.map(Some)
}

/// cancel-safe: yes — the absolute deadline drops the whole miss future.
async fn finish_miss<F>(deadline: Instant, work: F) -> Option<ResolvedAnswer>
where
    F: Future<Output = Result<Option<ResolvedAnswer>, DnsServerError>>,
{
    let result = timeout_at(deadline, work).await;
    match result {
        Ok(Ok(answer)) => answer,
        Ok(Err(error)) => {
            warn!(%error, "dns resolution failed; answering SERVFAIL");
            None
        }
        Err(_) => None,
    }
}

fn record_question<T>(ctx: &QueryCtx<T>, question: &Query) {
    if let Some(statistics) = &ctx.statistics {
        match statistics.record(question) {
            RecordOutcome::Accepted => {}
            RecordOutcome::DroppedFull => {
                let status = statistics.status();
                // Log at exponentially spaced loss counts, never question data.
                if status.dropped_full.is_power_of_two() {
                    warn!(
                        dropped = status.dropped_full,
                        "DNS query accounting degraded: bounded ingress full"
                    );
                }
            }
            // The worker reports the root persistence/closure failure. Do not
            // amplify it into a warning for every foreground query.
            RecordOutcome::Closed => {}
        }
    }
}

/// Refresh uses the same local policy and miss routes as foreground, but never
/// reads a fresh cached answer or records a client observation.
/// cancel-safe: yes — local probe, admission retry and exchange are scoped under
/// one deadline; dropping the future releases the owned backend permit.
async fn refresh_question<T, F>(
    ctx: QueryCtx<T>,
    question: Query,
    backend: Arc<Semaphore>,
) -> Option<ResolvedAnswer>
where
    T: Fn() -> F + Send + Clone + 'static,
    F: Future<Output = Option<TorTunnel>> + Send + 'static,
{
    refresh_question_until(ctx, question, backend, Instant::now() + RESOLUTION_TIMEOUT).await
}

/// cancel-safe: yes — no detached work; all awaits are within the same terminal
/// timeout and permit release is RAII on success, failure and cancellation.
async fn refresh_question_until<T, F>(
    ctx: QueryCtx<T>,
    question: Query,
    backend: Arc<Semaphore>,
    deadline: Instant,
) -> Option<ResolvedAnswer>
where
    T: Fn() -> F + Send + Clone + 'static,
    F: Future<Output = Option<TorTunnel>> + Send + 'static,
{
    timeout_at(deadline, async move {
        let host = wire::hostname_of(&question);
        let explicit_override = find_override(&ctx.overrides, &host).is_some();
        let probe = ctx.route_probe.clone();
        if let Some(answer) = local::preflight_with_probe(
            &question,
            &host,
            &ctx.endpoints,
            explicit_override,
            move |ip| probe(ip),
        )
        .await
        {
            return Some(answer);
        }
        // Atomically require two available slots, then immediately return one:
        // background owns one and never consumes the last foreground slot.
        let permit = loop {
            if backend.available_permits() > 1 {
                if let Ok(mut reserved) = backend.clone().try_acquire_many_owned(2) {
                    let permit = reserved.split(1)?;
                    drop(reserved);
                    break permit;
                }
            }
            if backend.is_closed() {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        };
        let answer = resolve_miss(ctx, question, deadline).await;
        drop(permit);
        answer
    })
    .await
    .ok()
    .flatten()
}

fn response(request: &Message, answer: Option<ResolvedAnswer>) -> Message {
    wire::build_response(request, answer.map(|a| a.message), ResponseCode::ServFail)
}
