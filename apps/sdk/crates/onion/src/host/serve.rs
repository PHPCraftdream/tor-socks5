//! Per-service request serving: consume rendezvous requests, accept streams,
//! and forward each accepted stream to the configured local target; plus the
//! per-service manager task (launch, address wait, supervision, relaunch),
//! the status logger, and the launch helpers they need. Aborting any owner
//! drops its `JoinSet` and aborts descendants; graceful cancellation awaits
//! children before returning.
//!
//! Concurrency: each service holds an accept gate of 32 permits held ONLY for
//! the `rend.accept()` handshake — afterwards the circuit runs in its own
//! long-lived task, so idle circuits cannot block new acceptances — and a
//! per-circuit stream cap of 256 enforced by arti
//! (`max_concurrent_streams_per_circuit`; it tears down circuits exceeding
//! it). Stream permits are unchanged: per-service `Semaphore` first, then
//! process-wide (512), fairly divided per service by
//! [`per_service_stream_cap`]. Forwarding pairs carry a 5-minute idle
//! timeout, and the local target is connected BEFORE the client stream is
//! accepted (connect-before-accept).

use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use futures::{Stream, StreamExt};
use proxy_config::OnionServiceEntry;
use safelog::DisplayRedacted as _;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tokio_util::sync::CancellationToken;
use tor_cell::relaycell::msg::{Connected, End, EndReason};
use tor_hsservice::{RendRequest, RunningOnionService, StreamRequest};
use tor_proto::stream::IncomingStreamRequest;
use tor_socks5_runtime::tor_watchdog::TorHandle;
use tracing::{debug, error, info, trace, warn};

use super::start_gate;
use super::status::{ServiceState, ServiceStatus, StatusTracker};
use super::ServiceFailure;
use crate::keys;

/// Maximum concurrent forwarded connections per onion service (each is a
/// plain local pair, but unbounded spawns would exhaust fds/memory).
pub(crate) const MAX_CONCURRENT_STREAMS: usize = 256;
/// Maximum concurrent forwarded connections across ALL services together.
pub(crate) const MAX_TOTAL_CONCURRENT_STREAMS: usize = 512;
/// Max simultaneous rendezvous handshakes (rend.accept()) per service; the
/// slot is freed once the handshake completes, so idle circuits (which run
/// in their own long-lived tasks) cannot block the acceptance of new ones.
const MAX_CONCURRENT_RENDEZVOUS_HANDSHAKES: usize = 32;
/// Per-circuit open-stream cap configured in arti
/// (`max_concurrent_streams_per_circuit`); arti tears down a circuit that
/// exceeds it. Kept equal to the per-service stream cap.
const MAX_CONCURRENT_STREAMS_PER_CIRCUIT: u32 = 256;
/// Lower bound on any single service's fair share of the process-wide stream budget.
const MIN_PER_SERVICE_STREAM_SHARE: usize = 32;
/// Deadline for the local `TcpStream::connect` to a service target.
const TARGET_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// First relaunch delay; doubles up to [`RETRY_DELAY_MAX`] and stays there.
const RETRY_DELAY_INITIAL: Duration = Duration::from_secs(30);
/// Upper bound on the launch retry backoff.
const RETRY_DELAY_MAX: Duration = Duration::from_secs(300);
/// Poll interval while waiting for the `.onion` address to become available.
const ADDRESS_POLL_INTERVAL: Duration = Duration::from_secs(1);
/// Total budget for the address wait (lookup/generation: seconds, not the
/// much longer descriptor publication).
const ADDRESS_WAIT_LIMIT: Duration = Duration::from_secs(120);

/// Virtual-port → local target map for one service (e.g. `80 → 127.0.0.1:8080`).
pub(crate) type PortMap = Arc<HashMap<u16, String>>;

/// The stream-request stream of one accepted rendezvous (one client
/// circuit). `rend.accept()` returns an opaque type, so the channel boxes it.
type BoxedStreamRequests = std::pin::Pin<Box<dyn Stream<Item = StreamRequest> + Send>>;

/// Each service's fair share of the process-wide stream budget: the
/// per-service cap or the global budget divided evenly, never below
/// [`MIN_PER_SERVICE_STREAM_SHARE`].
pub(crate) fn per_service_stream_cap(enabled_services: usize) -> usize {
    let share =
        (MAX_TOTAL_CONCURRENT_STREAMS / enabled_services.max(1)).max(MIN_PER_SERVICE_STREAM_SHARE);
    MAX_CONCURRENT_STREAMS.min(share)
}

/// Build the port map for a service from its config entries.
pub(crate) fn port_map(ports: &[proxy_config::OnionServicePort]) -> PortMap {
    Arc::new(
        ports
            .iter()
            .map(|port| (port.onion_port, port.target.clone()))
            .collect(),
    )
}

/// Which local target, if any, answers a stream request for `port`; `None`
/// also covers non-BEGIN requests (BEGIN_DIR / RESOLVE) — rejected too.
fn target_for_port(map: &HashMap<u16, SocketAddr>, port: Option<u16>) -> Option<SocketAddr> {
    let port = port?;
    map.get(&port).copied()
}

/// The virtual port a stream request asks for; `None` for non-BEGIN. Only
/// BEGIN is served, matching other onion service implementations.
fn requested_port(request: &IncomingStreamRequest) -> Option<u16> {
    match request {
        IncomingStreamRequest::Begin(begin) => Some(begin.port()),
        _ => None,
    }
}

/// END reason used for every rejection: DONE, "connection closed" semantics,
/// exactly what C Tor's onion services send.
fn end_done() -> End {
    End::new_with_reason(EndReason::DONE)
}

/// Gate on the rendezvous-handshake phase (cloning shares the semaphore):
/// at most [`MAX_CONCURRENT_RENDEZVOUS_HANDSHAKES`] in flight, held only
/// while `rend.accept()` runs.
#[derive(Clone)]
pub(crate) struct AcceptGate(Arc<Semaphore>);

impl AcceptGate {
    fn new(permits: usize) -> Self {
        Self(Arc::new(Semaphore::new(permits)))
    }

    /// Free capacity right now (used to keep rendezvous requests buffered in
    /// the source stream instead of spawning a waiting task).
    fn available_permits(&self) -> usize {
        self.0.available_permits()
    }

    /// Take a handshake slot, or `None` when the token fired while waiting.
    async fn acquire(&self, token: &CancellationToken) -> Option<OwnedSemaphorePermit> {
        tokio::select! {
            biased;
            () = token.cancelled() => None,
            permit = self.0.clone().acquire_owned() => permit.ok(),
        }
    }
}

/// Resolve every target once per service launch (DNS belongs to the launch,
/// not to every connection); unresolvable targets are omitted and logged.
async fn resolve_targets(ports: &HashMap<u16, String>) -> Arc<HashMap<u16, SocketAddr>> {
    let mut targets = HashMap::new();
    for (port, target) in ports {
        match tokio::net::lookup_host(target).await {
            // The target is `host:port`; any resolved address serves it.
            Ok(mut addrs) => {
                if let Some(addr) = addrs.next() {
                    targets.insert(*port, addr);
                }
            }
            Err(error) => {
                warn!(%port, %target, %error, "onion service target does not resolve; its virtual port will be rejected");
            }
        }
    }
    Arc::new(targets)
}

fn reap(result: Option<Result<(), tokio::task::JoinError>>, message: &'static str) {
    if let Some(Err(error)) = result {
        if !error.is_cancelled() {
            warn!(%error, message);
        }
    }
}

/// Top-level serving task for one launched service: runs until the rendezvous
/// stream ends or the token fires. Handshakes run behind an [`AcceptGate`];
/// each accepted circuit gets its own long-lived task.
pub(crate) async fn serve_service(
    _service: Arc<RunningOnionService>,
    rend_requests: impl Stream<Item = RendRequest> + Unpin,
    ports: PortMap,
    semaphore: Arc<Semaphore>,
    global: Arc<Semaphore>,
    token: CancellationToken,
) {
    let mut rend_requests = rend_requests;
    let targets = resolve_targets(&ports).await;
    let children_token = token.child_token();
    let accept_gate = AcceptGate::new(MAX_CONCURRENT_RENDEZVOUS_HANDSHAKES);
    let mut handshakes = tokio::task::JoinSet::new();
    let mut circuits = tokio::task::JoinSet::new();
    let (accepted_tx, mut accepted_rx) =
        mpsc::channel::<BoxedStreamRequests>(MAX_CONCURRENT_RENDEZVOUS_HANDSHAKES);
    loop {
        tokio::select! {
            biased;
            () = token.cancelled() => break,
            result = circuits.join_next(), if !circuits.is_empty() => {
                reap(result, "onion service circuit task failed");
                continue;
            }
            result = handshakes.join_next(), if !handshakes.is_empty() => {
                reap(result, "onion service rendezvous handshake task failed");
                continue;
            }
            requests = accepted_rx.recv() => match requests {
                Some(requests) => {
                    circuits.spawn(serve_stream_requests(
                        requests,
                        targets.clone(),
                        semaphore.clone(),
                        global.clone(),
                        children_token.clone(),
                    ));
                }
                // Closes only when every handshake task is gone (shutdown);
                // the cancelled arm above ends the loop.
                None => continue,
            },
            rend = rend_requests.next(), if accept_gate.available_permits() > 0 => match rend {
                Some(rend) => {
                    let gate = accept_gate.clone();
                    let token = children_token.clone();
                    let accepted_tx = accepted_tx.clone();
                    handshakes.spawn(async move {
                        let Some(permit) = gate.acquire(&token).await else { return };
                        let accepted = tokio::select! {
                            biased;
                            () = token.cancelled() => return,
                            accepted = rend.accept() => accepted,
                        };
                        // The slot is held only for the handshake itself.
                        drop(permit);
                        match accepted {
                            Ok(requests) => {
                                // A closed channel means the supervisor is
                                // shutting down.
                                let _ = accepted_tx.send(Box::pin(requests)).await;
                            }
                            Err(error) => {
                                warn!(%error, "onion service: failed to complete rendezvous handshake");
                            }
                        }
                    });
                }
                None => {
                    debug!("onion service rendezvous stream ended");
                    break;
                }
            },
        }
    }

    // Let each parent observe cancellation and join its own forwarding tasks
    // before joining the rendezvous workers here.
    children_token.cancel();
    handshakes.shutdown().await;
    circuits.shutdown().await;
}

/// The two permits one forwarded stream holds for its whole life: the
/// per-service cap first, then the process-wide cap — always in that order,
/// so a stream its own service cannot admit never takes a global permit.
/// `None` when a semaphore is closed (process teardown only).
async fn acquire_stream_permits(
    per_service: &Arc<Semaphore>,
    global: &Arc<Semaphore>,
) -> Option<(OwnedSemaphorePermit, OwnedSemaphorePermit)> {
    let per_service = per_service.clone().acquire_owned().await.ok()?;
    let global = global.clone().acquire_owned().await.ok()?;
    Some((per_service, global))
}

/// Consume the `StreamRequest`s of one accepted rendezvous (one client
/// circuit): per request, resolve the virtual port against the pre-resolved
/// targets, take the per-service and process-wide permits, and forward.
async fn serve_stream_requests(
    mut stream_requests: impl Stream<Item = StreamRequest> + Unpin,
    targets: Arc<HashMap<u16, SocketAddr>>,
    semaphore: Arc<Semaphore>,
    global: Arc<Semaphore>,
    token: CancellationToken,
) {
    let mut forwarding_tasks = tokio::task::JoinSet::new();
    let cancelled = loop {
        let request = tokio::select! {
            biased;
            () = token.cancelled() => break true,
            Some(_) = forwarding_tasks.join_next(), if !forwarding_tasks.is_empty() => continue,
            request = stream_requests.next() => match request {
                Some(request) => request,
                None => break false, // client circuit closed
            },
        };

        let port = requested_port(request.request());
        let Some(addr) = target_for_port(&targets, port) else {
            trace!(
                ?port,
                "onion service: rejecting stream for unknown or unresolved port"
            );
            let _ = tokio::select! {
                biased;
                () = token.cancelled() => break true,
                result = request.reject(end_done()) => result,
            };
            continue;
        };

        let permits = tokio::select! {
            biased;
            () = token.cancelled() => break true,
            permits = acquire_stream_permits(&semaphore, &global) => permits,
        };
        let Some((permit, global_permit)) = permits else {
            // Semaphores closed: only happens at process teardown.
            let _ = tokio::select! {
                biased;
                () = token.cancelled() => break true,
                result = request.reject(end_done()) => result,
            };
            break false;
        };
        forwarding_tasks.spawn(handle_stream_request(request, addr, permit, global_permit));
    };

    if cancelled {
        // Cancelling a JoinSet aborts and joins every active forward.
        forwarding_tasks.shutdown().await;
    } else {
        // The circuit may close while accepted streams continue; keep them
        // owned by this parent until completion, unless shutdown wins.
        while !forwarding_tasks.is_empty() {
            tokio::select! {
                biased;
                () = token.cancelled() => {
                    forwarding_tasks.shutdown().await;
                    return;
                }
                _ = forwarding_tasks.join_next() => {}
            }
        }
    }
}

/// Connect to the local target, bounded by `timeout` (mapped to TimedOut).
async fn connect_to_target(addr: SocketAddr, timeout: Duration) -> std::io::Result<TcpStream> {
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(result) => result,
        Err(_elapsed) => Err(std::io::Error::new(
            ErrorKind::TimedOut,
            "target connect timed out",
        )),
    }
}

/// Serve one accepted stream: connect to the local target FIRST
/// (connect-before-accept), then accept the client stream (CONNECTED) and
/// copy in both directions. A failed target connect rejects the stream, so
/// CONNECTED is never sent for a dead target.
async fn handle_stream_request(
    request: StreamRequest,
    addr: SocketAddr,
    _permit: OwnedSemaphorePermit,
    _global_permit: OwnedSemaphorePermit,
) {
    let tcp = match connect_to_target(addr, TARGET_CONNECT_TIMEOUT).await {
        Ok(tcp) => tcp,
        Err(error) => {
            debug!(%addr, %error, "onion service: target connect failed; rejecting the stream");
            if let Err(error) = request.reject(end_done()).await {
                debug!(%error, "onion service: failed to send END after a failed target connect");
            }
            return;
        }
    };
    let data_stream = match request.accept(Connected::new_empty()).await {
        Ok(data_stream) => data_stream,
        Err(error) => {
            debug!(%error, "onion service: client stream vanished before accept");
            return;
        }
    };
    // DataStream speaks the futures traits; wrap it for tokio's forwarding
    // (which handles half-close and the idle timeout).
    if let Err(error) = super::forward::forward(data_stream.compat(), tcp).await {
        trace!(%addr, %error, "onion service: forwarding ended with an I/O error");
    }
}

/// Log status transitions of one service (INFO normal lifecycle, WARN when
/// degraded; every transition is published to `tracker`). `started` fires on
/// the first terminal status — the launch-phase slot release (see
/// `start_gate`). `broken` fires on a Broken report (terminal, unrecoverable)
/// — the supervision relaunch signal; the logger then returns.
pub(crate) async fn log_status_events(
    mut events: tor_hsservice::status::OnionServiceStatusStream,
    nickname: String,
    address: String,
    started: tokio::sync::oneshot::Sender<()>,
    broken: Option<tokio::sync::oneshot::Sender<()>>,
    tracker: StatusTracker,
    token: CancellationToken,
) {
    // The stream yields the current status first, then every change; dedupe.
    let mut last: Option<tor_hsservice::status::State> = None;
    // The FIRST terminal status fires the slot release; later ones find
    // `None` — exactly-once is enough here.
    let mut started = Some(started);
    let mut broken = broken;
    let release = |started: &mut Option<tokio::sync::oneshot::Sender<()>>| {
        started.take().map(|s| s.send(()));
    };
    loop {
        let status = tokio::select! {
            biased;
            () = token.cancelled() => return,
            status = events.next() => match status {
                Some(status) => status,
                None => return,
            },
        };
        let state = status.state();
        // A freshly launched service reports Shutdown before Bootstrapping.
        let initial_shutdown = last.is_none() && state == tor_hsservice::status::State::Shutdown;
        if last == Some(state) || initial_shutdown {
            last = Some(state);
            continue;
        }
        last = Some(state);
        match state {
            tor_hsservice::status::State::Running => {
                release(&mut started);
                set_status(&tracker, &nickname, ServiceStatus::Running);
                info!(nickname = %nickname, %address, "onion service reachable");
            }
            tor_hsservice::status::State::Broken => {
                release(&mut started);
                set_status(&tracker, &nickname, ServiceStatus::Broken);
                warn!(nickname = %nickname, %address, "onion service is broken");
                // Broken is terminal: fire the supervision signal and stop
                // logging; the service is relaunched by `service_manager`.
                if let Some(broken) = broken.take() {
                    let _ = broken.send(());
                }
                return;
            }
            tor_hsservice::status::State::DegradedReachable => {
                release(&mut started);
                set_status(&tracker, &nickname, ServiceStatus::DegradedReachable);
                warn!(nickname = %nickname, %address, "onion service reachable but degraded");
            }
            tor_hsservice::status::State::DegradedUnreachable
            | tor_hsservice::status::State::Recovering => {
                let status = if state == tor_hsservice::status::State::DegradedUnreachable {
                    ServiceStatus::DegradedUnreachable
                } else {
                    ServiceStatus::Recovering
                };
                set_status(&tracker, &nickname, status);
                warn!(nickname = %nickname, %address, "onion service unreachable, attempting recovery");
            }
            tor_hsservice::status::State::Bootstrapping => {
                set_status(&tracker, &nickname, ServiceStatus::Bootstrapping);
                info!(nickname = %nickname, "onion service bootstrapping");
            }
            tor_hsservice::status::State::Shutdown => {
                info!(nickname = %nickname, "onion service shut down");
            }
            _ => {
                debug!(nickname = %nickname, ?state, "onion service status changed");
            }
        }
    }
}

/// Publish one service state with no failure detail.
fn set_status(tracker: &StatusTracker, nick: &str, status: ServiceStatus) {
    tracker.set(
        nick,
        ServiceState {
            status,
            failure: None,
        },
    );
}

/// Publish a `Failed` state with a failure detail.
fn set_failure(tracker: &StatusTracker, nick: &str, failure: ServiceFailure) {
    tracker.set(
        nick,
        ServiceState {
            status: ServiceStatus::Failed,
            failure: Some(failure),
        },
    );
}

/// Why `supervise_children` returned: token fired, or a serving task failed.
enum SupervisionOutcome {
    Cancelled,
    Restart(&'static str),
}

/// Wait for shutdown or for a supervised serving task to fail. `broken`
/// fires on a terminal Broken report; a dropped sender means the status
/// stream ended without a report.
async fn supervise_children(
    children: &mut tokio::task::JoinSet<()>,
    token: &CancellationToken,
    mut broken: tokio::sync::oneshot::Receiver<()>,
) -> SupervisionOutcome {
    tokio::select! {
        biased;
        () = token.cancelled() => SupervisionOutcome::Cancelled,
        Some(result) = children.join_next(), if !children.is_empty() => match result {
            Ok(()) => SupervisionOutcome::Restart("serving task exited unexpectedly"),
            Err(e) if e.is_cancelled() => SupervisionOutcome::Restart("serving task was aborted"),
            Err(e) => {
                warn!(%e, "onion service serving task panicked");
                SupervisionOutcome::Restart("serving task panicked")
            }
        },
        result = &mut broken => match result {
            Ok(()) => SupervisionOutcome::Restart("service reports a broken state"),
            Err(_) => SupervisionOutcome::Restart("service status stream ended"),
        },
    }
}

/// Build arti's config for a (pre-validated) nickname.
pub(crate) fn build_config(
    nick: tor_hsservice::HsNickname,
) -> anyhow::Result<tor_hsservice::OnionServiceConfig> {
    tor_hsservice::config::OnionServiceConfigBuilder::default()
        .nickname(nick)
        // arti tears down a circuit that opens more streams than this;
        // kept equal to the per-service cap.
        .max_concurrent_streams_per_circuit(MAX_CONCURRENT_STREAMS_PER_CIRCUIT)
        .build()
        .context("building the onion service configuration")
}

/// The outcome of waiting for the `.onion` address.
enum AddressWait {
    Available(tor_hscrypto::pk::HsId),
    Cancelled,
    TimedOut,
}

/// Poll for the service's `.onion` address, bounded by [`ADDRESS_WAIT_LIMIT`].
/// cancel-safe: only polls `onion_address()` and a timer; cancellation leaves
/// the service owned by its caller.
async fn wait_for_address(
    service: &Arc<RunningOnionService>,
    token: &CancellationToken,
    nick: &str,
) -> AddressWait {
    let deadline = tokio::time::Instant::now() + ADDRESS_WAIT_LIMIT;
    loop {
        if let Some(address) = service.onion_address() {
            return AddressWait::Available(address);
        }
        if tokio::time::Instant::now() >= deadline {
            error!(
                nickname = %nick,
                waited = ?ADDRESS_WAIT_LIMIT,
                "onion service address never became available"
            );
            return AddressWait::TimedOut;
        }
        tokio::select! {
            biased;
            () = token.cancelled() => return AddressWait::Cancelled,
            () = tokio::time::sleep(ADDRESS_POLL_INTERVAL) => {}
        }
    }
}

/// Mark one service `Stopped` (the manager returned: shutdown/cancellation).
fn mark_stopped(tracker: &StatusTracker, nick: &str) {
    set_status(tracker, nick, ServiceStatus::Stopped);
}

/// Launch (and if necessary relaunch) one service, then keep it alive until
/// shutdown. Holding the `Arc<RunningOnionService>` keeps the service
/// published. Each attempt holds a `start_gate` slot until terminal status,
/// the 90 s cap, or shutdown; retries sleep a doubling, ±20%-spread backoff.
/// Serving tasks are supervised (`supervise_children`): a broken or failed
/// serving task tears the service down and relaunches it. cancel-safe.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn service_manager(
    handle: TorHandle,
    entry: OnionServiceEntry,
    expected_address: String,
    gate: start_gate::StartGate,
    stream_cap: usize,
    global_streams: Arc<Semaphore>,
    token: CancellationToken,
    tracker: StatusTracker,
    #[cfg(test)] service_launched: Option<Arc<super::ServiceLaunchedHook>>,
    #[cfg(test)] serve_started: Option<Arc<super::ServeStartedHook>>,
) {
    let nick = entry.nickname.clone();
    if token.is_cancelled() {
        mark_stopped(&tracker, &nick);
        return;
    }
    // `Failed` is the only status the manager pairs with a failure detail.
    let failed = |f: ServiceFailure| set_failure(&tracker, &nick, f);
    let nick_hs = match keys::nickname(&nick) {
        Ok(nick) => nick,
        Err(error) => {
            failed(ServiceFailure::InvalidNickname);
            error!(nickname = %nick, %error, "invalid onion service nickname; service not started");
            return;
        }
    };
    let config = match build_config(nick_hs) {
        Ok(config) => config,
        Err(error) => {
            failed(ServiceFailure::InvalidConfig);
            error!(nickname = %nick, %error, "invalid onion service configuration; service not started");
            return;
        }
    };
    let ports = port_map(&entry.ports);
    let semaphore = Arc::new(Semaphore::new(stream_cap));

    let mut delay = RETRY_DELAY_INITIAL;
    loop {
        set_status(&tracker, &nick, ServiceStatus::WaitingForSlot);
        let tunnel = tokio::select! {
            biased;
            () = token.cancelled() => {
                mark_stopped(&tracker, &nick);
                return;
            }
            tunnel = handle.tunnel() => tunnel,
        };
        let Some(tunnel) = tunnel else {
            debug!(nickname = %nick, "onion service launch aborted: Tor is shutting down");
            mark_stopped(&tracker, &nick);
            return;
        };

        // Hold one of at most MAX_STARTING launch slots until terminal status,
        // the 90 s slot cap, or shutdown.
        {
            let Some(slot) = gate.acquire(&token).await else {
                debug!(nickname = %nick, "onion service launch aborted: shutting down while waiting for a launch slot");
                mark_stopped(&tracker, &nick);
                return;
            };
            if token.is_cancelled() {
                mark_stopped(&tracker, &nick);
                return;
            }
            match tunnel.raw().launch_onion_service(config.clone()) {
                Ok(Some((service, rend_requests))) => {
                    #[cfg(test)]
                    if let Some(on_launch) = &service_launched {
                        on_launch(&service);
                    }
                    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
                    // The slot holder releases it at terminal status/90 s cap/shutdown.
                    let mut slot_holder = tokio::task::JoinSet::new();
                    slot_holder.spawn(slot.hold_until_started(started_rx, token.clone()));
                    match wait_for_address(&service, &token, &nick).await {
                        AddressWait::Available(address) => {
                            let actual = address.display_unredacted().to_string();
                            if actual != expected_address {
                                slot_holder.shutdown().await;
                                drop(rend_requests);
                                drop(service);
                                error!(
                                    nickname = %nick,
                                    expected_address = %expected_address,
                                    actual_address = %actual,
                                    "launched onion service address does not match prepared identity; service not served"
                                );
                                failed(ServiceFailure::AddressMismatch);
                                return;
                            }
                            set_status(&tracker, &nick, ServiceStatus::Bootstrapping);
                            info!(
                                nickname = %nick,
                                address = %address.display_unredacted(),
                                "onion service address available: onion service starting"
                            );
                            #[cfg(test)]
                            if let Some(on_serve) = &serve_started {
                                on_serve();
                            }
                            let (broken_tx, broken_rx) = tokio::sync::oneshot::channel();
                            let mut children = tokio::task::JoinSet::new();
                            children.spawn(serve_service(
                                service.clone(),
                                rend_requests,
                                ports.clone(),
                                semaphore.clone(),
                                global_streams.clone(),
                                token.clone(),
                            ));
                            children.spawn(log_status_events(
                                service.status_events(),
                                nick.clone(),
                                address.display_unredacted().to_string(),
                                started_tx,
                                Some(broken_tx),
                                tracker.clone(),
                                token.clone(),
                            ));
                            match supervise_children(&mut children, &token, broken_rx).await {
                                SupervisionOutcome::Cancelled => {
                                    children.shutdown().await;
                                    slot_holder.shutdown().await;
                                    info!(nickname = %nick, "onion service stopped");
                                    mark_stopped(&tracker, &nick);
                                    return;
                                }
                                SupervisionOutcome::Restart(reason) => {
                                    children.shutdown().await;
                                    slot_holder.shutdown().await; // releases the StartSlot
                                    drop(service); // unpublish
                                    warn!(
                                        nickname = %nick,
                                        reason,
                                        retry_in = ?delay,
                                        "onion service serving tasks failed; relaunching"
                                    );
                                    set_status(&tracker, &nick, ServiceStatus::Recovering);
                                }
                            }
                        }
                        // Shutdown while waiting: still `Stopped`, no "stopped" log.
                        AddressWait::Cancelled => {
                            slot_holder.shutdown().await;
                            mark_stopped(&tracker, &nick);
                            return;
                        }
                        AddressWait::TimedOut => {
                            slot_holder.shutdown().await;
                            failed(ServiceFailure::AddressUnavailable {
                                limit: ADDRESS_WAIT_LIMIT,
                            });
                            return;
                        }
                    }
                }
                Ok(None) => {
                    failed(ServiceFailure::RejectedByTorClient);
                    error!(nickname = %nick, "onion service was rejected by the Tor client (disabled configuration); not retried");
                    return;
                }
                Err(error) => {
                    error!(nickname = %nick, %error, retry_in = ?delay, "failed to launch onion service; retrying");
                }
            }
        }

        tokio::select! {
            biased;
            () = token.cancelled() => {
                mark_stopped(&tracker, &nick);
                return;
            }
            () = tokio::time::sleep(super::backoff_spread(delay)) => {}
        }
        delay = (delay * 2).min(RETRY_DELAY_MAX);
    }
}

#[cfg(test)]
#[cfg(test)]
#[path = "serve_tests.rs"]
mod tests;
