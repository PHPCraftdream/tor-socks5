//! Per-service request serving: consume rendezvous requests, accept streams,
//! and forward each accepted stream to the configured local target; plus a
//! Host ownership is producer → managers `JoinSet` → per-manager children
//! `JoinSet` → rendezvous/forwarding `JoinSet`s. Aborting any owner drops its
//! set and aborts descendants; graceful cancellation awaits children before
//! returning. This module owns the rendezvous and forwarding levels.
//!
//! Concurrency: one `Arc<Semaphore>` (256 permits) per service plus one
//! process-wide `Arc<Semaphore>` (512 permits) across ALL services together.
//! Every forwarded stream holds one permit of each for its whole life — the
//! per-service one acquired first, then the global one, always in that
//! order, so a stream its own service cannot admit never consumes a global
//! permit. Forwarding tasks live in their rendezvous parent's `JoinSet`; the
//! semaphores bound their count. Rendezvous workers are separately capped per
//! service, and cancellation aborts and joins active forwarding tasks. The
//! accept loops never wait for a permit without also observing cancellation.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures::Stream;
use futures::StreamExt;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tokio_util::sync::CancellationToken;
use tor_cell::relaycell::msg::{Connected, End, EndReason};
use tor_hsservice::{RendRequest, RunningOnionService, StreamRequest};
use tor_proto::stream::IncomingStreamRequest;
use tracing::{debug, info, trace, warn};

use super::status::{ServiceState, ServiceStatus, StatusTracker};

/// Maximum concurrent forwarded connections per onion service. Each is a
/// plain local TCP forwarding pair, but unbounded spawns would still let a
/// hostile client exhaust memory/file descriptors.
pub(crate) const MAX_CONCURRENT_STREAMS: usize = 256;

/// Maximum concurrent forwarded connections across ALL onion services
/// together. Bounds the process' total file-descriptor/memory footprint
/// on top of the per-service [`MAX_CONCURRENT_STREAMS`].
pub(crate) const MAX_TOTAL_CONCURRENT_STREAMS: usize = 512;

/// Maximum concurrent rendezvous workers per onion service. This bounds the
/// service's spawned handshake/circuit tasks independently of forwarded
/// stream permits; excess rendezvous requests remain in the source stream.
const MAX_CONCURRENT_RENDEZVOUS_TASKS: usize = MAX_CONCURRENT_STREAMS;

/// Deadline for the local `TcpStream::connect` to a service target.
const TARGET_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Virtual-port → local target map for one service (e.g. `80 → 127.0.0.1:8080`).
pub(crate) type PortMap = Arc<HashMap<u16, String>>;

/// Build the port map for a service from its config entries.
pub(crate) fn port_map(ports: &[proxy_config::OnionServicePort]) -> PortMap {
    Arc::new(
        ports
            .iter()
            .map(|port| (port.onion_port, port.target.clone()))
            .collect(),
    )
}

/// Which local target, if any, answers a stream request for `port`.
///
/// `None` on the request side means "not a BEGIN" (BEGIN_DIR / RESOLVE) —
/// never answered by an onion service, so it maps to a rejection too.
fn target_for_port(map: &HashMap<u16, String>, port: Option<u16>) -> Option<&String> {
    let port = port?;
    map.get(&port)
}

/// The virtual port a stream request asks for, or `None` for non-BEGIN
/// requests. Only BEGIN is served, matching other onion service
/// implementations (so we stay indistinguishable from them).
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

/// Top-level serving task for one launched service: runs until the rendezvous
/// stream ends or the shutdown token fires. Each rendezvous handshake is
/// accepted and handed its own stream-request loop (client circuits are
/// independent, so one stuck circuit cannot stall the others). `semaphore`
/// caps this service's forwarded streams; `global` caps them across all
/// services together.
pub(crate) async fn serve_service(
    _service: Arc<RunningOnionService>,
    rend_requests: impl Stream<Item = RendRequest> + Unpin,
    ports: PortMap,
    semaphore: Arc<Semaphore>,
    global: Arc<Semaphore>,
    token: CancellationToken,
) {
    let mut rend_requests = rend_requests;
    let children_token = token.child_token();
    let mut rendezvous_tasks = tokio::task::JoinSet::new();
    loop {
        let rend = tokio::select! {
            biased;
            () = token.cancelled() => break,
            Some(_) = rendezvous_tasks.join_next(), if !rendezvous_tasks.is_empty() => continue,
            rend = rend_requests.next(), if rendezvous_tasks.len() < MAX_CONCURRENT_RENDEZVOUS_TASKS => match rend {
                Some(rend) => rend,
                None => {
                    debug!("onion service rendezvous stream ended");
                    break;
                }
            },
        };
        let ports = ports.clone();
        let semaphore = semaphore.clone();
        let global = global.clone();
        let token = children_token.clone();
        rendezvous_tasks.spawn(async move {
            let accepted = tokio::select! {
                biased;
                () = token.cancelled() => return,
                accepted = rend.accept() => accepted,
            };
            match accepted {
                Ok(stream_requests) => {
                    serve_stream_requests(stream_requests, ports, semaphore, global, token).await;
                }
                Err(error) => {
                    // The client gets no notification; the rendezvous
                    // handshake simply fails on its side.
                    warn!(%error, "onion service: failed to complete rendezvous handshake");
                }
            }
        });
    }

    // Let each parent observe cancellation and join its own forwarding tasks
    // before joining the rendezvous workers here.
    children_token.cancel();
    while rendezvous_tasks.join_next().await.is_some() {}
}

/// The two permits one forwarded stream holds for its whole life: the
/// per-service cap first, then the process-wide cap — always in that
/// order, so a stream its own service cannot admit never takes a global
/// permit. `None` when a semaphore is closed (process teardown only).
///
/// Holding the per-service permit across the global wait is fine: if the
/// caller is cancelled in between, both permits drop with the future.
async fn acquire_stream_permits(
    per_service: &Arc<Semaphore>,
    global: &Arc<Semaphore>,
) -> Option<(
    tokio::sync::OwnedSemaphorePermit,
    tokio::sync::OwnedSemaphorePermit,
)> {
    let per_service = per_service.clone().acquire_owned().await.ok()?;
    let global = global.clone().acquire_owned().await.ok()?;
    Some((per_service, global))
}

/// Consume the `StreamRequest`s of one accepted rendezvous (one client
/// circuit): per request, resolve the virtual port, take the per-service
/// and process-wide concurrency permits, and forward to the local target.
async fn serve_stream_requests(
    mut stream_requests: impl Stream<Item = StreamRequest> + Unpin,
    ports: PortMap,
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
        let Some(target) = target_for_port(&ports, port).cloned() else {
            trace!(?port, "onion service: rejecting stream for unknown port");
            let rejected = tokio::select! {
                biased;
                () = token.cancelled() => break true,
                result = request.reject(end_done()) => result,
            };
            if let Err(error) = rejected {
                debug!(%error, "onion service: failed to send END for rejected stream");
            }
            continue;
        };

        // Owned permits, moved into the connection task: they cap in-flight
        // forwards and are released when the task ends.
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
        forwarding_tasks.spawn(handle_stream_request(
            request,
            target,
            permit,
            global_permit,
        ));
    };

    if cancelled {
        // Cancelling a JoinSet aborts and joins every active network forward.
        forwarding_tasks.shutdown().await;
    } else {
        // The circuit may close while already-accepted streams continue. Keep
        // them owned by this parent until completion, unless host shutdown wins.
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

/// Serve one accepted stream: accept it (CONNECTED to the client), connect
/// to the local target, then copy in both directions. Holds one per-service
/// and one process-wide permit for the stream's whole life; both are
/// released when this task ends.
async fn handle_stream_request(
    request: StreamRequest,
    target: String,
    _permit: tokio::sync::OwnedSemaphorePermit,
    _global_permit: tokio::sync::OwnedSemaphorePermit,
) {
    let data_stream = match request.accept(Connected::new_empty()).await {
        Ok(data_stream) => data_stream,
        Err(error) => {
            debug!(%error, "onion service: client stream vanished before accept");
            return;
        }
    };
    let connect = tokio::time::timeout(TARGET_CONNECT_TIMEOUT, TcpStream::connect(&target));
    match connect.await {
        Ok(Ok(tcp)) => {
            // DataStream speaks the futures traits; wrap it for tokio's
            // copy_bidirectional, which handles half-close correctly.
            let result = super::forward::forward(data_stream.compat(), tcp).await;
            if let Err(error) = result {
                trace!(%target, %error, "onion service: forwarding ended with an I/O error");
            }
        }
        Ok(Err(error)) => {
            // Already answered CONNECTED; dropping the DataStream closes the
            // stream toward the client.
            debug!(%target, %error, "onion service: target connect failed");
        }
        Err(_elapsed) => {
            debug!(%target, "onion service: target connect timed out");
        }
    }
}

/// Log status transitions of one service. INFO for normal lifecycle
/// (bootstrapping → running → shutdown), WARN when the service degrades.
/// `started` fires once the service first reports Running,
/// DegradedReachable or Broken — the launch-phase slot release signal
/// (see `start_gate`). Every logged transition is also published to the
/// shared status tracker.
pub(crate) async fn log_status_events(
    mut events: tor_hsservice::status::OnionServiceStatusStream,
    nickname: String,
    address: String,
    started: tokio::sync::oneshot::Sender<()>,
    tracker: StatusTracker,
    token: CancellationToken,
) {
    // The stream yields the current status first, then every change; dedupe
    // anyway so only real transitions log.
    let mut last: Option<tor_hsservice::status::State> = None;
    // The FIRST terminal status fires the launch-phase slot release (see
    // `start_gate`); later ones find `None` — exactly-once is enough here.
    let mut started = Some(started);
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
                // Fails harmlessly once the receiver is gone; subsequent
                // terminal states find `None` (see `started` above).
                if let Some(started) = started.take() {
                    let _ = started.send(());
                }
                tracker.set(
                    &nickname,
                    ServiceState {
                        status: ServiceStatus::Running,
                        failure: None,
                    },
                );
                info!(nickname = %nickname, %address, "onion service reachable");
            }
            tor_hsservice::status::State::Broken => {
                if let Some(started) = started.take() {
                    let _ = started.send(()); // see the Running arm
                }
                tracker.set(
                    &nickname,
                    ServiceState {
                        status: ServiceStatus::Broken,
                        failure: None,
                    },
                );
                warn!(nickname = %nickname, %address, "onion service is broken");
            }
            tor_hsservice::status::State::DegradedReachable => {
                if let Some(started) = started.take() {
                    let _ = started.send(()); // see the Running arm
                }
                tracker.set(
                    &nickname,
                    ServiceState {
                        status: ServiceStatus::DegradedReachable,
                        failure: None,
                    },
                );
                warn!(nickname = %nickname, %address, "onion service reachable but degraded");
            }
            tor_hsservice::status::State::DegradedUnreachable
            | tor_hsservice::status::State::Recovering => {
                let tracked_state = if state == tor_hsservice::status::State::DegradedUnreachable {
                    ServiceStatus::DegradedUnreachable
                } else {
                    ServiceStatus::Recovering
                };
                tracker.set(
                    &nickname,
                    ServiceState {
                        status: tracked_state,
                        failure: None,
                    },
                );
                warn!(nickname = %nickname, %address, "onion service unreachable, attempting recovery");
            }
            tor_hsservice::status::State::Bootstrapping => {
                tracker.set(
                    &nickname,
                    ServiceState {
                        status: ServiceStatus::Bootstrapping,
                        failure: None,
                    },
                );
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

#[cfg(test)]
mod tests {
    use super::*;

    fn ports(entries: &[(u16, &str)]) -> HashMap<u16, String> {
        entries
            .iter()
            .map(|(p, t)| (*p, t.to_string()))
            .collect::<HashMap<_, _>>()
    }

    #[test]
    fn target_resolves_known_port() {
        let map = ports(&[(80, "127.0.0.1:8080")]);
        assert_eq!(
            target_for_port(&map, Some(80)).map(String::as_str),
            Some("127.0.0.1:8080")
        );
    }

    #[test]
    fn target_misses_unknown_port() {
        let map = ports(&[(80, "127.0.0.1:8080")]);
        assert!(target_for_port(&map, Some(443)).is_none());
    }

    #[test]
    fn target_misses_non_begin_request() {
        let map = ports(&[(80, "127.0.0.1:8080")]);
        // Non-BEGIN requests carry no port and must be rejected.
        assert!(target_for_port(&map, None).is_none());
    }

    // StreamRequest cannot be constructed outside arti, so the permit
    // ordering is exercised through `acquire_stream_permits` directly.
    // Deterministic throughout: paused clock, explicit `advance` (the
    // semaphores use no timers), and sync `try_recv` for "not yet" checks.

    #[tokio::test(start_paused = true)]
    async fn a_stream_beyond_the_global_cap_waits_for_a_global_permit() {
        // Two per-service caps of 1 sum above the global cap of 1: the
        // process-wide limit is what holds the second stream back.
        let per_a = Arc::new(Semaphore::new(1));
        let per_b = Arc::new(Semaphore::new(1));
        let global = Arc::new(Semaphore::new(1));

        // A's own service has room, so A takes the only global permit.
        let first = acquire_stream_permits(&per_a, &global)
            .await
            .expect("A admitted");

        // B's per-service permit is free, but no global permit is left.
        let (done_tx, mut done_rx) = tokio::sync::oneshot::channel::<bool>();
        tokio::spawn(async move {
            let _ = done_tx.send(acquire_stream_permits(&per_b, &global).await.is_some());
        });
        tokio::time::advance(Duration::from_secs(60)).await;
        assert!(
            done_rx.try_recv().is_err(),
            "B must still wait: the only global permit is held"
        );

        drop(first); // frees the global permit
        assert!(
            done_rx.await.expect("oneshot"),
            "B is admitted once a global permit frees up"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_per_service_cap_is_taken_before_the_global_one() {
        // One per-service cap of 1 and a global cap of 2: A holds one global
        // permit. While B is parked behind its own service's cap, the other
        // global permit must still be free — a global-first implementation
        // would have taken it.
        let per = Arc::new(Semaphore::new(1));
        let global = Arc::new(Semaphore::new(2));

        let first = acquire_stream_permits(&per, &global)
            .await
            .expect("A admitted");

        // B targets the SAME service.
        let (done_tx, mut done_rx) = tokio::sync::oneshot::channel::<bool>();
        tokio::spawn({
            let global = global.clone();
            async move {
                let _ = done_tx.send(acquire_stream_permits(&per, &global).await.is_some());
            }
        });
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(
            done_rx.try_recv().is_err(),
            "B must still wait behind its own service's cap"
        );
        assert!(
            global.try_acquire().is_ok(),
            "the global permit stays free while B waits on the per-service cap"
        );

        drop(first); // frees both the per-service and the global permit
        assert!(
            done_rx.await.expect("oneshot"),
            "B is admitted once its service frees a permit"
        );
    }
}
