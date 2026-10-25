//! Admission and scoped socket ownership. No backend queue and no detached tasks.
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use arti_wrapper::TorTunnel;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use hickory_proto::op::Message;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::time::{timeout, Instant};
use tracing::debug;

use super::{inline_answer, resolve_miss, response, wire, QueryCtx, RESOLUTION_TIMEOUT};

pub(super) const MAX_TCP_CONNECTIONS: usize = 64;
const IO_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECTION_LIFETIME: Duration = Duration::from_secs(300);
type Work = Pin<Box<dyn Future<Output = ()> + Send>>;

/// cancel-safe: yes — recv_from consumes only complete datagrams; child work is
/// owned in this collection and dropped with this loop (including all permits).
pub(super) async fn udp_loop<T, F>(
    socket: Arc<UdpSocket>,
    ctx: QueryCtx<T>,
    backend: Arc<Semaphore>,
) where
    T: Fn() -> F + Send + Clone + 'static,
    F: Future<Output = Option<TorTunnel>> + Send + 'static,
{
    udp_loop_observed(socket, ctx, backend, |_| {}).await;
}

/// cancel-safe: yes — the synchronous observer cannot retain socket work.
pub(super) async fn udp_loop_observed<T, F, Observe>(
    socket: Arc<UdpSocket>,
    ctx: QueryCtx<T>,
    backend: Arc<Semaphore>,
    mut observe: Observe,
) where
    T: Fn() -> F + Send + Clone + 'static,
    F: Future<Output = Option<TorTunnel>> + Send + 'static,
    Observe: FnMut(&Message) + Send,
{
    let mut work = FuturesUnordered::<Work>::new();
    let mut buf = vec![0; 65535];
    loop {
        tokio::select! {
            biased;
            _ = work.next(), if !work.is_empty() => {},
            received = socket.recv_from(&mut buf) => {
                let Ok((len, peer)) = received else { continue; };
                // Проверка по реальному source peer до любого парсинга: молча
                // дропаем пакет (без REFUSED/FORMERR), без статистики/кэша/backend.
                if !ctx.client_access.allows(peer.ip()) {
                    debug!(%peer, "udp dns client denied by client access policy");
                    continue;
                }
                let Some(request) = wire::parse_query(&buf[..len]) else { continue; };
                observe(&request);
                if let Some(reply) = wire::unsupported_response(&request) {
                    wire::send_udp_response(&socket, peer, reply).await;
                    continue;
                }
                let Some(question) = request.queries.first().cloned() else {
                    wire::send_udp_response(&socket, peer, wire::formerr(&request)).await;
                    continue;
                };
                super::record_question(&ctx, &question);
                if let Some(answer) = inline_answer(&ctx, &question).await {
                    wire::send_udp_response(&socket, peer, response(&request, Some(answer))).await;
                    continue;
                }
                let deadline = Instant::now() + RESOLUTION_TIMEOUT;
                if work.len() >= super::MAX_DNS_CONCURRENT_QUERIES {
                    wire::send_udp_response(&socket, peer, response(&request, None)).await;
                    continue;
                }
                let Ok(permit) = backend.clone().try_acquire_owned() else {
                    wire::send_udp_response(&socket, peer, response(&request, None)).await;
                    continue;
                };
                let socket = socket.clone();
                let ctx = ctx.clone();
                work.push(Box::pin(async move {
                    let answer = resolve_miss(ctx, question, deadline).await;
                    // Release backend capacity before client output.
                    drop(permit);
                    wire::send_udp_response(&socket, peer, response(&request, answer)).await;
                }));
            }
        }
    }
}

/// cancel-safe: yes — accept is cancel-safe; all connection futures are owned
/// here and their sockets/admission guards drop on every exit.
pub(super) async fn tcp_loop<T, F>(
    listener: TcpListener,
    ctx: QueryCtx<T>,
    backend: Arc<Semaphore>,
    connections: Arc<Semaphore>,
) where
    T: Fn() -> F + Send + Clone + 'static,
    F: Future<Output = Option<TorTunnel>> + Send + 'static,
{
    tcp_loop_gated(
        listener,
        ctx,
        backend,
        connections,
        || || std::future::ready(()),
        || {},
    )
    .await;
}

/// cancel-safe: yes — accept and work.next only borrow loop-owned work;
/// cancellation drops all sockets, gates and production admission guards.
/// Each admitted connection gets its own frame gate. The completion observer
/// runs only after the production-owned connection future has finished.
pub(super) async fn tcp_loop_gated<T, F, MakeGate, Gate, G, Completed>(
    listener: TcpListener,
    ctx: QueryCtx<T>,
    backend: Arc<Semaphore>,
    connections: Arc<Semaphore>,
    mut make_gate: MakeGate,
    mut completed: Completed,
) where
    T: Fn() -> F + Send + Clone + 'static,
    F: Future<Output = Option<TorTunnel>> + Send + 'static,
    MakeGate: FnMut() -> Gate + Send,
    Gate: FnMut() -> G + Send + 'static,
    G: Future<Output = ()> + Send,
    Completed: FnMut() + Send,
{
    let mut work = FuturesUnordered::<Work>::new();
    loop {
        tokio::select! {
            biased;
            _ = work.next(), if !work.is_empty() => { completed(); },
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(error) => {
                        debug!(%error, "tcp dns accept failed");
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        continue;
                    }
                };
                // Тот же gate, что и в UDP: по source peer из accept до
                // capacity/permit/nodelay; deny — continue, стрим дропается.
                if !ctx.client_access.allows(peer.ip()) {
                    debug!(%peer, "tcp dns client denied by client access policy");
                    continue;
                }
                if work.len() >= MAX_TCP_CONNECTIONS { continue; }
                let Ok(permit) = connections.clone().try_acquire_owned() else { continue; };
                // Small request/response frames: never wait for a delayed ACK.
                let _ = stream.set_nodelay(true);
                let ctx = ctx.clone();
                let backend = backend.clone();
                let gate = make_gate();
                work.push(Box::pin(async move {
                    let _permit = permit;
                    // Finite connection lifetime also bounds peers continuously
                    // sending valid local/cache queries, not merely idle peers.
                    let _ = timeout(
                        CONNECTION_LIFETIME,
                        handle_tcp_gated(stream, ctx, backend, gate),
                    )
                    .await;
                }));
            }
        }
    }
}

// A narrow frame-start gate lets real-socket tests register the read timer only
// after pausing time. Production always uses an immediately-ready gate.
/// cancel-safe: yes for terminal cancellation only — gates, partial
/// read_exact/write_all frames and the owned stream are dropped, never resumed.
async fn handle_tcp_gated<T, F, Gate, G>(
    mut stream: TcpStream,
    ctx: QueryCtx<T>,
    backend: Arc<Semaphore>,
    mut gate: Gate,
) where
    T: Fn() -> F + Send + Clone + 'static,
    F: Future<Output = Option<TorTunnel>> + Send + 'static,
    Gate: FnMut() -> G,
    G: Future<Output = ()>,
{
    loop {
        gate().await;
        let Ok(Some(body)) = wire::read_framed_message(&mut stream, IO_TIMEOUT).await else {
            return;
        };
        let Some(request) = wire::parse_query(&body) else {
            return;
        };
        let reply = if let Some(reply) = wire::unsupported_response(&request) {
            reply
        } else if let Some(question) = request.queries.first().cloned() {
            super::record_question(&ctx, &question);
            let answer = if let Some(answer) = inline_answer(&ctx, &question).await {
                Some(answer)
            } else {
                let deadline = Instant::now() + RESOLUTION_TIMEOUT;
                match backend.clone().try_acquire_owned() {
                    Ok(permit) => {
                        let answer = resolve_miss(ctx.clone(), question, deadline).await;
                        drop(permit);
                        answer
                    }
                    Err(_) => None,
                }
            };
            response(&request, answer)
        } else {
            wire::formerr(&request)
        };
        let Ok(bytes) = reply.to_vec() else {
            return;
        };
        if wire::write_framed_message(&mut stream, &bytes, IO_TIMEOUT)
            .await
            .is_err()
        {
            return;
        }
    }
}
