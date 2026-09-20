//! The local UDP/TCP DNS listener speaking the plain DNS wire format.
//!
//! One [`run`] call binds a UDP socket and a TCP listener per configured
//! address and serves queries until `shutdown` fires. Every query follows
//! the same three-step path:
//!
//! 1. **Parse** the wire message and take its FIRST question — servers
//!    answer only the first QUESTION-section entry, which is the same
//!    convention our own DoH client is built on (one question per message).
//! 2. **Cache first**: a fresh [`DnsCache`] hit is answered inline in the
//!    receive loop — no task spawn, no semaphore permit, no Tor round trip.
//! 3. **Resolve on miss** through the DoH provider pool with every byte
//!    inside the Tor tunnel ([`resolve_with_pool`]), insert into the cache,
//!    and answer.
//!
//! Hostnames matching an operator-configured override mask
//! ([`crate::overrides::DnsOverride`]) are checked between the cache and
//! the pool and never reach the DoH pool at all: they are resolved via
//! plain DNS or the OS resolver, both DELIBERATELY outside the Tor tunnel
//! (an operator-opted exception; see the security framing in
//! [`crate::overrides`]' module docs), while every host matching no mask
//! keeps the unchanged three-step path.
//!
//! # Concurrency and shutdown
//!
//! DoH misses run in detached tasks, bounded by a
//! [`MAX_DNS_CONCURRENT_QUERIES`] permit held for the task's whole life plus
//! the per-provider timeouts inside [`resolve_with_pool`] — bounded despite
//! being fire-and-forget. UDP receive errors are per-datagram (including
//! Windows' WSAECONNRESET raised after a send to a dead port) and only skip
//! the datagram; TCP accept errors back off and retry, exactly like the
//! SOCKS5 accept loop. All listener loops live on the `run` task
//! (`FuturesUnordered`), so shutdown drops them together with their
//! sockets; a final best-effort cache save lands before `run` returns.
//!
//! # Deliberate limitations
//!
//! * **No EDNS0.** A query carrying an OPT pseudo-RR is answered normally
//!   (the OPT is ignored, not echoed). RFC 6891 asks a compliant server to
//!   echo the OPT record in its responses; that obligation is consciously
//!   not met here. UDP answers are capped at the legacy 512-byte payload
//!   with the TC=1 fallback (RFC 1035 §4.2.1) — modern stub resolvers fall
//!   back to TCP on truncation, which this server fully supports.
//! * **Answers are per-host, not per-type.** The cache stores the merged
//!   DoH answer (A + AAAA), so a response carries ALL known addresses for
//!   the host regardless of the queried type. A deliberate consequence of
//!   the per-host cache design: clients pick the address family they can
//!   use and ignore the rest.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use arti_wrapper::TorTunnel;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Semaphore;
use tokio::time::{interval, timeout, MissedTickBehavior};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::cache::DnsCache;
use crate::doh_client::resolve_with_pool;
use crate::error::DnsServerError;
use crate::overrides::{
    find_override, resolve_via_dns_server, resolve_via_system, DnsOverride, OverrideResolver,
};
use crate::types::{DohProvider, ResolvedAnswer};

/// Upper bound on in-flight query resolutions. A permit is acquired BEFORE
/// spawning a UDP datagram-resolution task or a TCP connection task and is
/// released only when that task ends, so a flood of queries saturates at
/// this many concurrent Tor/DoH exchanges (and open TCP connections)
/// instead of exhausting memory or the tunnel.
const MAX_DNS_CONCURRENT_QUERIES: usize = 64;

/// How often the cache is flushed to disk while the server runs. The
/// on-disk copy exists so a restart keeps its warm answers; five minutes
/// bounds the loss to whatever was resolved since the last tick without
/// making saves a noticeable background cost.
const CACHE_SAVE_INTERVAL: Duration = Duration::from_secs(300);

/// Pause before retrying a failed TCP `accept()`. Any accept error is
/// treated as transient: the loop logs it and retries instead of tearing
/// down the whole server. Same value and reasoning as the SOCKS5 accept
/// loop — the sleep prevents a busy-spin (and a log flood) if the error is
/// persistent.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(500);

/// Per-read deadline for a TCP DNS connection: both the 2-byte length
/// prefix and the message body must arrive within this budget, or the
/// connection is closed. Arms per read, never renewed — a peer trickling
/// valid bytes one at a time still hits it, so an untrusted client cannot
/// pin a connection task (and its semaphore permit) forever.
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Largest UDP response payload we will emit: the legacy 512-byte limit
/// every resolver must honour (RFC 1035 §4.2.1)... A larger answer is
/// truncated to a header-only TC=1 reply so the client retries over TCP.
const MAX_UDP_RESPONSE_BYTES: usize = 512;

/// UDP receive buffer size. A single DNS datagram can theoretically reach
/// 64 KiB but real queries are a few dozen bytes; anything that does not
/// fit is cut at 4096 bytes, which fails wire parsing and is dropped — the
/// client re-asks and we still served every well-formed query.
const UDP_RECV_BUFFER_SIZE: usize = 4096;

/// Shared per-loop/per-task state. Cheap to clone: one closure clone, one
/// `Arc`, and two small `Vec`s — provider descriptors and override masks.
struct QueryCtx<T> {
    /// Yields the CURRENT Tor tunnel. Called fresh per resolution: after a
    /// watchdog rebuild the previous tunnel is invalid, and `None` means
    /// shutdown/drain is in progress (the query is answered SERVFAIL).
    tunnel: T,
    cache: Arc<DnsCache>,
    providers: Vec<DohProvider>,
    overrides: Vec<DnsOverride>,
}

impl<T: Clone> Clone for QueryCtx<T> {
    fn clone(&self) -> Self {
        QueryCtx {
            tunnel: self.tunnel.clone(),
            cache: self.cache.clone(),
            providers: self.providers.clone(),
            overrides: self.overrides.clone(),
        }
    }
}

/// Serve plain wire-format DNS over UDP and TCP on every address in
/// `listen` until `shutdown` fires.
///
/// `tunnel` is a closure yielding the CURRENT [`TorTunnel`]. It is called
/// fresh for every resolution: after a watchdog rebuilds the tunnel the
/// previous one is invalid, and `None` means shutdown/drain is in progress
/// (in-flight queries are answered SERVFAIL). The closure is generic
/// rather than typed against the app's concrete handle on purpose — this
/// crate must not depend on the app's `TorHandle` — and `Clone` because
/// every spawned task carries its own copy.
///
/// `overrides` carries the operator's override masks; matching hosts
/// bypass the DoH pool entirely (see [`resolve_host`]).
///
/// `cache_path` drives the periodic (and final) best-effort cache saves;
/// see [`DnsCache::save`]. A bind failure on ANY address fails the whole
/// call: a server silently listening on only part of what was configured
/// is harder to diagnose than a clean refusal to start.
///
/// The `F: 'static` bound is one step past the conceptual minimum:
/// spawned resolution tasks hold an `F` future across an await point, and
/// `tokio::spawn` requires `'static`. Real callers hand in a closure
/// returning an owned, `'static` future (the app's handle clones the
/// tunnel out of its slot), so the bound costs call sites nothing.
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
    // Fail fast on an empty listen list: a DNS server listening on nothing
    // would silently serve no one.
    if listen.is_empty() {
        bail!("no listen addresses configured for the DNS server");
    }

    // Bind every configured address, fail on the first error (same rule as
    // the SOCKS5 bind loop). Both transports bind per address: clients may
    // be configured for either, and a UDP-only server would silently break
    // every stub that falls back to TCP on truncation.
    let mut udp_sockets = Vec::with_capacity(listen.len());
    let mut tcp_listeners = Vec::with_capacity(listen.len());
    for addr in listen {
        let udp = UdpSocket::bind(addr)
            .await
            .with_context(|| format!("failed to bind UDP DNS listener on {addr}"))?;
        let tcp = TcpListener::bind(addr)
            .await
            .with_context(|| format!("failed to bind TCP DNS listener on {addr}"))?;
        info!(listen_addr = %addr, "DNS server listening (UDP + TCP)");
        udp_sockets.push(Arc::new(udp));
        tcp_listeners.push(tcp);
    }

    let ctx = QueryCtx {
        tunnel,
        cache: cache.clone(),
        providers,
        overrides,
    };
    let permits = Arc::new(Semaphore::new(MAX_DNS_CONCURRENT_QUERIES));

    // One never-ending loop per socket/listener, polled concurrently on
    // this task — the same reasoning as the SOCKS5 accept loops: on
    // shutdown the whole FuturesUnordered is dropped, dropping every loop
    // together with its socket, where detached spawned loops would keep
    // serving through teardown and need explicit aborts. Every loop runs
    // forever, so `next()` can only complete via shutdown, never with a
    // value.
    let mut udp_loops = udp_sockets
        .into_iter()
        .map(|socket| udp_loop(socket, ctx.clone(), permits.clone(), shutdown.clone()))
        .collect::<FuturesUnordered<_>>();
    let mut tcp_loops = tcp_listeners
        .into_iter()
        .map(|listener| tcp_loop(listener, ctx.clone(), permits.clone()))
        .collect::<FuturesUnordered<_>>();

    // Periodic cache flush. `interval`'s first tick completes immediately,
    // so it is consumed here — before the loop — and the first real save
    // happens one full CACHE_SAVE_INTERVAL after startup, not instantly
    // after the startup load.
    let mut save_ticker = interval(CACHE_SAVE_INTERVAL);
    save_ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    save_ticker.tick().await;

    loop {
        tokio::select! {
            biased;
            // Shutdown outranks everything: with `biased`, a cancellation is
            // always noticed before a new datagram/connection iteration
            // starts.
            () = shutdown.cancelled() => {
                // One final best-effort save; a failure here must not turn a
                // clean shutdown into an error — the next boot simply
                // re-warms from DoH.
                if let Err(error) = cache.save(&cache_path).await {
                    warn!(%error, "final dns cache save failed at shutdown");
                }
                return Ok(());
            }
            _ = save_ticker.tick() => {
                if let Err(error) = cache.save(&cache_path).await {
                    warn!(%error, "periodic dns cache save failed");
                }
            }
            // Both arm kinds below are unreachable by construction (each
            // loop runs forever); if one ever ends, the server is half-dead
            // — fail loudly rather than serve a partial listener set.
            _ = udp_loops.next() => bail!("UDP DNS listener loop exited unexpectedly"),
            _ = tcp_loops.next() => bail!("TCP DNS listener loop exited unexpectedly"),
        }
    }
}

/// Receive UDP datagrams forever, answering each one.
///
/// Receive errors are per-datagram — logged at `debug!` and skipped, with
/// NO backoff, because they must not kill the loop: Windows raises
/// WSAECONNRESET here after a previous `send_to` hit a dead port, which is
/// meaningless for an unconnected socket. Send errors are equally
/// per-datagram: the client re-asks.
async fn udp_loop<T, F>(
    socket: Arc<UdpSocket>,
    ctx: QueryCtx<T>,
    permits: Arc<Semaphore>,
    shutdown: CancellationToken,
) where
    T: Fn() -> F + Send + Clone + 'static,
    F: Future<Output = Option<TorTunnel>> + Send + 'static,
{
    let mut buf = vec![0u8; UDP_RECV_BUFFER_SIZE];
    loop {
        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(received) => received,
            Err(error) => {
                debug!(%error, "udp dns recv failed; datagram skipped");
                continue;
            }
        };

        let (id, question) = match parse_query(&buf[..len]) {
            ParsedQuery::Query { id, question } => (id, question),
            ParsedQuery::NoQuestion { id } => {
                // Decodable but nothing to answer: FORMERR, and there is no
                // question to echo.
                let formerr = Message::error_msg(id, OpCode::Query, ResponseCode::FormErr);
                send_udp_response(&socket, peer, formerr).await;
                continue;
            }
            ParsedQuery::Garbage => {
                debug!(%peer, "undecodable udp dns datagram; dropped");
                continue;
            }
        };

        let host = hostname_of(&question);

        // Cache-first fast path, INLINE in the recv loop: no spawn, no
        // permit. A hit costs one mutex-guarded map lookup plus an encode,
        // so the common repeat-query case never touches the concurrency
        // budget.
        if let Some(answer) = ctx.cache.get(&host) {
            let response = build_response(id, &question, ResponseCode::NoError, Some(&answer));
            send_udp_response(&socket, peer, response).await;
            continue;
        }

        // Permit acquired BEFORE the spawn and moved into the task, so the
        // concurrency bound is enforced at spawn time, not after.
        let permit = permits
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore not closed");
        let ctx = ctx.clone();
        let socket = socket.clone();
        let shutdown = shutdown.clone();
        // fire-and-forget: detached by design — bounded by the
        // MAX_DNS_CONCURRENT_QUERIES permit held for the task's whole life
        // plus the per-provider timeouts inside resolve_with_pool.
        tokio::spawn(async move {
            let _permit = permit;
            // Shutdown raced the spawn: bail silently, nobody needs the
            // reply of a server that is going away.
            if shutdown.is_cancelled() {
                return;
            }
            let response = match resolve_host(
                ctx.tunnel.clone(),
                ctx.cache.clone(),
                ctx.providers.clone(),
                ctx.overrides.clone(),
                &host,
            )
            .await
            {
                Ok(Some(answer)) => {
                    build_response(id, &question, ResponseCode::NoError, Some(&answer))
                }
                // Tunnel yielded None: shutdown/drain in progress — the
                // only honest last word is SERVFAIL.
                Ok(None) => build_response(id, &question, ResponseCode::ServFail, None),
                Err(error) => {
                    warn!(%host, %error, "doh resolution failed; answering SERVFAIL");
                    build_response(id, &question, ResponseCode::ServFail, None)
                }
            };
            send_udp_response(&socket, peer, response).await;
        });
    }
}

/// Accept TCP connections forever, handling each on its own task.
///
/// Accept errors are logged at `error!` and retried after a backoff — the
/// loop never `?`s out, so it only ends by being dropped at shutdown (same
/// contract as the SOCKS5 accept loop).
async fn tcp_loop<T, F>(listener: TcpListener, ctx: QueryCtx<T>, permits: Arc<Semaphore>)
where
    T: Fn() -> F + Send + Clone + 'static,
    F: Future<Output = Option<TorTunnel>> + Send + 'static,
{
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                error!(%error, "tcp dns accept failed; retrying in {ACCEPT_ERROR_BACKOFF:?}");
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                continue;
            }
        };
        let permit = permits
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore not closed");
        let ctx = ctx.clone();
        // fire-and-forget: detached by design — bounded by the
        // MAX_DNS_CONCURRENT_QUERIES permit and by TCP_IDLE_TIMEOUT on
        // every read, so a slow-loris peer cannot pin the task (or the
        // permit) forever.
        tokio::spawn(async move {
            let _permit = permit;
            debug!(%peer, "new tcp dns connection");
            handle_tcp_connection(stream, ctx).await;
        });
    }
}

/// Serve one TCP connection: read framed queries and write framed replies,
/// sequentially, until the peer closes or misframes.
///
/// Sequential by design: a stub resolver pipelines rarely, and one
/// connection is one client, so interleaving buys nothing here. Every read
/// is wrapped in [`TCP_IDLE_TIMEOUT`] (see [`read_framed_message`]) so the
/// task cannot be held open indefinitely.
async fn handle_tcp_connection<T, F>(mut stream: tokio::net::TcpStream, ctx: QueryCtx<T>)
where
    T: Fn() -> F + Send + Clone + 'static,
    F: Future<Output = Option<TorTunnel>> + Send,
{
    loop {
        let body = match read_framed_message(&mut stream, TCP_IDLE_TIMEOUT).await {
            Ok(Some(body)) => body,
            // Clean close between messages: the normal end of a
            // conversation.
            Ok(None) => return,
            Err(error) => {
                debug!(%error, "tcp dns read failed; closing connection");
                return;
            }
        };

        match parse_query(&body) {
            ParsedQuery::Garbage => {
                debug!("undecodable tcp dns message; closing connection");
                return;
            }
            ParsedQuery::NoQuestion { id } => {
                let formerr = Message::error_msg(id, OpCode::Query, ResponseCode::FormErr);
                let bytes = match formerr.to_vec() {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        debug!(%error, "formerr failed to encode; closing connection");
                        return;
                    }
                };
                if let Err(error) =
                    write_framed_message(&mut stream, &bytes, TCP_IDLE_TIMEOUT).await
                {
                    debug!(%error, "tcp dns write failed; closing connection");
                    return;
                }
            }
            ParsedQuery::Query { id, question } => {
                let host = hostname_of(&question);
                let response = match resolve_host(
                    ctx.tunnel.clone(),
                    ctx.cache.clone(),
                    ctx.providers.clone(),
                    ctx.overrides.clone(),
                    &host,
                )
                .await
                {
                    Ok(Some(answer)) => {
                        build_response(id, &question, ResponseCode::NoError, Some(&answer))
                    }
                    Ok(None) => build_response(id, &question, ResponseCode::ServFail, None),
                    Err(error) => {
                        warn!(%host, %error, "doh resolution failed; answering SERVFAIL");
                        build_response(id, &question, ResponseCode::ServFail, None)
                    }
                };
                // No 512-byte cap on TCP (RFC 1035 §4.2.2 allows up to
                // 64 KiB); the 2-byte length prefix bounds the frame.
                let bytes = match response.to_vec() {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        debug!(%error, "dns response failed to encode; closing connection");
                        return;
                    }
                };
                if let Err(error) =
                    write_framed_message(&mut stream, &bytes, TCP_IDLE_TIMEOUT).await
                {
                    debug!(%error, "tcp dns write failed; closing connection");
                    return;
                }
            }
        }
    }
}

/// Resolve `host` cache-first, then through a matching override mask, then
/// through the DoH pool over the CURRENT tunnel.
///
/// * `Ok(Some(answer))` — resolved (cache hit, override success, or DoH
///   success; override and DoH answers are inserted into the cache on the
///   way out);
/// * `Ok(None)` — the tunnel closure yielded `None`: shutdown/drain is in
///   progress, callers answer SERVFAIL (never happens on the override
///   path);
/// * `Err(error)` — the matched override's resolver, or every DoH
///   provider, failed; callers answer SERVFAIL.
///
/// The override check sits BETWEEN cache and pool: the first matching
/// [`DnsOverride`](crate::overrides::DnsOverride) routes the lookup to
/// [`resolve_via_dns_server`] or [`resolve_via_system`], and the tunnel
/// closure is never consulted on that path — overrides deliberately leave
/// the Tor tunnel and must keep resolving while Tor is down or draining,
/// exactly when the closure would yield `None`.
///
/// Takes OWNED clones (closure + Arc + small provider and override vecs)
/// rather than references, so the returned future is self-contained `Send`
/// without needing the closure type to be `Sync` — the future holds
/// nothing by reference across its awaits.
async fn resolve_host<T, F>(
    tunnel: T,
    cache: Arc<DnsCache>,
    providers: Vec<DohProvider>,
    overrides: Vec<DnsOverride>,
    host: &str,
) -> Result<Option<ResolvedAnswer>, DnsServerError>
where
    T: Fn() -> F + Send + Clone + 'static,
    F: Future<Output = Option<TorTunnel>> + Send,
{
    if let Some(answer) = cache.get(host) {
        return Ok(Some(answer));
    }
    // Override masks sit between cache and pool (see doc): a match never
    // reaches the tunnel closure below, so overrides keep resolving even
    // while Tor is down or the server is draining.
    if let Some(override_entry) = find_override(&overrides, host) {
        let resolved = match &override_entry.resolver {
            OverrideResolver::Dns { server } => resolve_via_dns_server(host, *server).await,
            OverrideResolver::System => resolve_via_system(host).await,
        };
        return match resolved {
            Ok(answer) => {
                cache.insert(host, answer.clone());
                Ok(Some(answer))
            }
            Err(error) => Err(error),
        };
    }
    // Fresh read of the CURRENT tunnel every time: a watchdog rebuild
    // invalidates the previous tunnel, so caching one here across queries
    // would keep dialling a dead client.
    let Some(tor) = (tunnel)().await else {
        return Ok(None);
    };
    match resolve_with_pool(host, &tor, &providers).await {
        Ok(answer) => {
            cache.insert(host, answer.clone());
            Ok(Some(answer))
        }
        Err(error) => Err(error),
    }
}

/// Outcome of parsing one received DNS message.
#[derive(Debug)]
enum ParsedQuery {
    /// A decodable message with at least one question: answerable. Only
    /// the FIRST question is taken — servers answer the first
    /// QUESTION-section entry, and our own DoH client sends one question
    /// per message for the same reason.
    Query { id: u16, question: Query },
    /// Decodable but zero questions: answered with FORMERR (there is no
    /// question to echo).
    NoQuestion { id: u16 },
    /// Undecodable wire garbage: dropped (UDP) / connection closed (TCP).
    Garbage,
}

/// Parse one wire-format DNS message and classify it for answering.
///
/// An OPT pseudo-RR in the additional section is deliberately ignored —
/// see "Deliberate limitations" in the module docs.
fn parse_query(bytes: &[u8]) -> ParsedQuery {
    let Ok(message) = Message::from_vec(bytes) else {
        return ParsedQuery::Garbage;
    };
    match message.queries.first() {
        Some(question) => ParsedQuery::Query {
            id: message.metadata.id,
            question: question.clone(),
        },
        None => ParsedQuery::NoQuestion {
            id: message.metadata.id,
        },
    }
}

/// Cache/DoH key for a question: the wire name rendered as text with ONE
/// trailing dot stripped. Wire-parsed hickory names are FQDN and `Display`
/// with the root dot ("example.com."), while the rest of this crate keys
/// its cache and builds its DoH queries dot-less ("example.com").
fn hostname_of(question: &Query) -> String {
    let name = question.name().to_string();
    match name.strip_suffix('.') {
        Some(host) => host.to_owned(),
        None => name,
    }
}

/// Build a response message for one question. Pure function.
///
/// With `answer`: NOERROR carrying one record per cached address, all with
/// the SAME ttl — the cache stores one merged per-host answer, so any
/// per-record TTL distinction is gone by the time a query is served.
/// Without: `rcode` with an empty answer section (the SERVFAIL path).
/// Either way the question is echoed and RA is set: we DO recurse (via the
/// DoH pool).
fn build_response(
    id: u16,
    question: &Query,
    rcode: ResponseCode,
    answer: Option<&ResolvedAnswer>,
) -> Message {
    let mut message = Message::new(id, MessageType::Response, OpCode::Query);
    message.metadata.recursion_available = true;
    message.metadata.response_code = rcode;
    message.add_query(question.clone());
    if let Some(answer) = answer {
        // The wire TTL field is u32; an absurd cached TTL saturates at
        // u32::MAX instead of failing the whole answer.
        let ttl = u32::try_from(answer.ttl.as_secs()).unwrap_or(u32::MAX);
        for addr in &answer.addrs {
            let rdata = match addr {
                IpAddr::V4(v4) => RData::A(A(*v4)),
                IpAddr::V6(v6) => RData::AAAA(AAAA(*v6)),
            };
            message.add_answer(Record::from_rdata(question.name().clone(), ttl, rdata));
        }
    }
    message
}

/// Encode `message` for UDP, enforcing the legacy 512-byte payload cap.
///
/// An over-cap answer is re-encoded via [`Message::truncate`]: TC=1, the
/// question kept, the answer section dropped — the client is expected to
/// retry over TCP (RFC 1035 §4.2.1). `None` means the message could not be
/// encoded at all even truncated; the caller sends nothing rather than a
/// broken datagram.
fn encode_udp_response(message: Message) -> Option<Vec<u8>> {
    match message.to_vec() {
        Ok(bytes) if bytes.len() <= MAX_UDP_RESPONSE_BYTES => Some(bytes),
        Ok(_) => match message.truncate().to_vec() {
            Ok(bytes) => Some(bytes),
            Err(error) => {
                debug!(%error, "truncated dns response failed to encode");
                None
            }
        },
        Err(error) => {
            debug!(%error, "dns response failed to encode");
            None
        }
    }
}

/// Encode and send one UDP reply. Errors are per-datagram (the peer may
/// have gone away between query and reply) and are only logged at
/// `debug!`; the receive loop keeps running either way.
async fn send_udp_response(socket: &UdpSocket, peer: SocketAddr, message: Message) {
    let Some(bytes) = encode_udp_response(message) else {
        debug!(%peer, "dns response could not be encoded; dropped");
        return;
    };
    if let Err(error) = socket.send_to(&bytes, peer).await {
        debug!(%peer, %error, "udp dns send failed");
    }
}

/// Read one length-prefixed DNS message off a TCP stream (RFC 1035
/// §4.2.2): a 2-byte big-endian length prefix, then that many body bytes.
///
/// * `Ok(None)` — the peer closed the connection cleanly between messages
///   (EOF exactly on a length-prefix boundary): the normal end of a TCP
///   DNS conversation, not an error.
/// * `Ok(Some(body))` — one complete message.
/// * `Err(_)` — any protocol violation (zero-length message, EOF mid-
///   prefix, mid-body) or IO failure. The caller closes the connection,
///   which is the only sane response to an untrusted peer that cannot
///   frame.
///
/// Both the prefix read and the body read run under `idle_timeout`, so a
/// peer dribbling one byte per read (or simply stalling) cannot hold the
/// connection task — and its semaphore permit — forever.
async fn read_framed_message<R: AsyncRead + Unpin>(
    reader: &mut R,
    idle_timeout: Duration,
) -> io::Result<Option<Vec<u8>>> {
    let read_prefix = async {
        let mut prefix = [0u8; 2];
        let mut filled = 0;
        while filled < prefix.len() {
            let n = reader.read(&mut prefix[filled..]).await?;
            if n == 0 {
                if filled == 0 {
                    // EOF on a message boundary: clean close.
                    return Ok(None);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed mid length prefix",
                ));
            }
            filled += n;
        }
        Ok(Some(u16::from_be_bytes(prefix)))
    };
    let length = match timeout(idle_timeout, read_prefix).await {
        Ok(result) => result?,
        Err(_elapsed) => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "timed out reading dns message length prefix",
            ));
        }
    };
    let Some(length) = length else {
        return Ok(None);
    };
    if length == 0 {
        // A zero-length message is a framing violation, not a message.
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "zero-length dns message",
        ));
    }
    let mut body = vec![0u8; usize::from(length)];
    match timeout(idle_timeout, reader.read_exact(&mut body)).await {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => return Err(error),
        Err(_elapsed) => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "timed out reading dns message body",
            ));
        }
    }
    Ok(Some(body))
}

/// Write one length-prefixed DNS message to a TCP stream (RFC 1035
/// §4.2.2): a single `write_all` of the 2-byte big-endian prefix followed
/// by the body, then a flush — all under `idle_timeout`.
///
/// A single write keeps the frame atomic from the peer's framing
/// perspective; bodies larger than 65535 bytes simply cannot be framed by
/// the 2-byte prefix and are rejected.
async fn write_framed_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    body: &[u8],
    idle_timeout: Duration,
) -> io::Result<()> {
    let length = u16::try_from(body.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "dns message exceeds 65535 bytes",
        )
    })?;
    let mut frame = Vec::with_capacity(2 + body.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(body);
    let write = async {
        writer.write_all(&frame).await?;
        writer.flush().await
    };
    match timeout(idle_timeout, write).await {
        Ok(result) => result,
        Err(_elapsed) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "timed out writing dns message",
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use hickory_proto::rr::{Name, RecordType};
    use time::OffsetDateTime;
    use tokio::io::duplex;

    use super::*;

    fn question(name: &str, rtype: RecordType) -> Query {
        let name: Name = name.parse().expect("valid test name");
        Query::query(name, rtype)
    }

    fn answer(addrs: &[IpAddr], ttl_secs: u64) -> ResolvedAnswer {
        ResolvedAnswer {
            addrs: addrs.to_vec(),
            ttl: Duration::from_secs(ttl_secs),
            resolved_at: OffsetDateTime::now_utc(),
        }
    }

    // -- response builders ---------------------------------------------------

    #[test]
    fn success_response_echoes_id_and_answers_in_order() {
        let q = question("example.com", RecordType::A);
        let a = answer(
            &["192.0.2.7".parse().unwrap(), "2001:db8::1".parse().unwrap()],
            120,
        );
        let message = build_response(0x1F2E, &q, ResponseCode::NoError, Some(&a));

        assert_eq!(message.metadata.id, 0x1F2E);
        assert_eq!(message.metadata.message_type, MessageType::Response);
        assert_eq!(message.metadata.op_code, OpCode::Query);
        assert!(message.metadata.recursion_available);
        assert_eq!(message.metadata.response_code, ResponseCode::NoError);

        assert_eq!(message.queries.len(), 1);
        assert_eq!(message.queries[0].name(), q.name());
        assert_eq!(message.queries[0].query_type(), q.query_type());

        assert_eq!(message.answers.len(), 2, "A + AAAA, cached order kept");
        assert!(matches!(message.answers[0].data, RData::A(_)));
        assert!(matches!(message.answers[1].data, RData::AAAA(_)));
        assert_eq!(message.answers[0].ttl, 120, "same ttl on every record");
        assert_eq!(message.answers[1].ttl, 120);
    }

    #[test]
    fn servfail_response_has_empty_answers_but_echoes_question() {
        let q = question("example.com", RecordType::AAAA);
        let message = build_response(9, &q, ResponseCode::ServFail, None);

        assert_eq!(message.metadata.response_code, ResponseCode::ServFail);
        assert!(message.answers.is_empty());
        assert!(message.metadata.recursion_available, "RA set on SERVFAIL");
        assert_eq!(message.queries.len(), 1);
        assert_eq!(message.queries[0].name(), q.name());
    }

    #[test]
    fn formerr_carries_id_and_rcode() {
        let formerr = Message::error_msg(0xBEEF, OpCode::Query, ResponseCode::FormErr);
        assert_eq!(formerr.metadata.id, 0xBEEF);
        assert_eq!(formerr.metadata.response_code, ResponseCode::FormErr);
        assert_eq!(formerr.metadata.message_type, MessageType::Response);
        assert!(formerr.queries.is_empty(), "no question available to echo");
    }

    // -- UDP encode cap ------------------------------------------------------

    #[test]
    fn small_udp_answer_encodes_without_truncation() {
        let q = question("example.com", RecordType::A);
        let a = answer(
            &["192.0.2.7".parse().unwrap(), "192.0.2.8".parse().unwrap()],
            60,
        );
        let bytes = encode_udp_response(build_response(1, &q, ResponseCode::NoError, Some(&a)))
            .expect("small answer encodes");
        assert!(bytes.len() <= MAX_UDP_RESPONSE_BYTES);

        let decoded = Message::from_vec(&bytes).expect("round-trips");
        assert!(!decoded.metadata.truncation);
        assert_eq!(decoded.answers.len(), 2);
    }

    #[test]
    fn oversized_udp_answer_is_truncated_to_header_only() {
        let q = question("example.com", RecordType::A);
        // ~60 A records ≈ 60 × 16 B ≈ 960 B of answer section: far over 512.
        let addrs: Vec<IpAddr> = (0..60)
            .map(|i| IpAddr::V4(Ipv4Addr::new(192, 0, 2, (i % 255) as u8 + 1)))
            .collect();
        let a = answer(&addrs, 60);
        let message = build_response(0x0B0B, &q, ResponseCode::NoError, Some(&a));
        assert!(message.to_vec().unwrap().len() > MAX_UDP_RESPONSE_BYTES);

        let bytes = encode_udp_response(message).expect("truncated answer encodes");
        let decoded = Message::from_vec(&bytes).expect("round-trips");
        assert!(bytes.len() <= MAX_UDP_RESPONSE_BYTES);
        assert!(decoded.metadata.truncation, "TC bit set");
        assert!(decoded.answers.is_empty(), "answer section dropped");
        assert_eq!(decoded.metadata.id, 0x0B0B, "id preserved");
        assert_eq!(decoded.queries.len(), 1);
        // `q.name()` was parsed straight from a string (not FQDN-flagged);
        // `decoded.queries[0].name()` went through a wire round-trip, which
        // always yields an FQDN. Compare the rendered form, not the `Name`
        // values, matching the convention used in doh_client's own tests.
        assert_eq!(
            decoded.queries[0].name().to_string(),
            "example.com.",
            "question preserved"
        );
    }

    // -- parse_query / hostname ----------------------------------------------

    #[test]
    fn parse_query_takes_first_of_two_questions() {
        let mut message = Message::new(0x0202, MessageType::Query, OpCode::Query);
        let first = question("example.com", RecordType::A);
        let second = question("example.org", RecordType::AAAA);
        message.add_query(first.clone());
        message.add_query(second.clone());
        let bytes = message.to_vec().expect("encodes");

        match parse_query(&bytes) {
            ParsedQuery::Query { id, question } => {
                assert_eq!(id, 0x0202);
                // `question.name()` went through a wire round-trip (always
                // FQDN); `first.name()` was parsed straight from a string.
                // Compare the rendered form, not the `Name` values.
                assert_eq!(
                    question.name().to_string(),
                    "example.com.",
                    "FIRST question wins"
                );
                assert_eq!(question.query_type(), first.query_type());
            }
            other => panic!("expected a query, got {other:?}"),
        }
    }

    #[test]
    fn parse_query_reports_garbage_and_zero_questions() {
        assert!(matches!(parse_query(&[0xFF; 20]), ParsedQuery::Garbage));
        assert!(matches!(parse_query(&[]), ParsedQuery::Garbage));

        let bytes = Message::new(5, MessageType::Query, OpCode::Query)
            .to_vec()
            .expect("encodes");
        match parse_query(&bytes) {
            ParsedQuery::NoQuestion { id } => assert_eq!(id, 5),
            other => panic!("expected NoQuestion, got {other:?}"),
        }
    }

    #[test]
    fn hostname_strips_exactly_one_trailing_dot() {
        let q = question("example.com", RecordType::A);
        assert_eq!(hostname_of(&q), "example.com");
    }

    // -- TCP framing -----------------------------------------------------------

    #[tokio::test]
    async fn tcp_prefix_and_body_split_across_writes_are_reassembled() {
        let (mut writer, mut reader) = duplex(64);
        writer.write_all(&[0x00]).await.unwrap();
        writer.write_all(&[0x05]).await.unwrap();
        writer.write_all(b"hel").await.unwrap();
        writer.write_all(b"lo").await.unwrap();

        let body = read_framed_message(&mut reader, Duration::from_secs(1))
            .await
            .expect("message reassembled")
            .expect("not EOF");
        assert_eq!(body, b"hello");
    }

    #[tokio::test]
    async fn tcp_written_response_reads_back_as_prefix_and_payload() {
        let (mut writer, mut reader) = duplex(64);
        write_framed_message(&mut writer, b"abcd", Duration::from_secs(1))
            .await
            .expect("write succeeds");

        let mut framed = vec![0u8; 6];
        reader.read_exact(&mut framed).await.unwrap();
        assert_eq!(&framed[..2], &[0x00, 0x04], "big-endian length prefix");
        assert_eq!(&framed[2..], b"abcd");
    }

    #[tokio::test]
    async fn tcp_zero_length_message_is_a_protocol_error() {
        let (mut writer, mut reader) = duplex(64);
        writer.write_all(&[0x00, 0x00]).await.unwrap();
        let error = read_framed_message(&mut reader, Duration::from_secs(1))
            .await
            .expect_err("zero-length message must error");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn tcp_clean_eof_between_messages_reads_none() {
        let (writer, mut reader) = duplex(64);
        drop(writer);
        let message = read_framed_message(&mut reader, Duration::from_secs(1)).await;
        assert_eq!(message.expect("io ok"), None, "clean EOF, not an error");
    }

    #[tokio::test]
    async fn tcp_stalled_peer_hits_idle_timeout() {
        let (_writer, mut reader) = duplex(64);
        let error = read_framed_message(&mut reader, Duration::from_millis(50))
            .await
            .expect_err("no bytes within the deadline must time out");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }
}
