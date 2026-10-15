//! Per-service request serving: consume rendezvous requests, accept streams,
//! and forward each accepted stream to the configured local target; plus a
//! status-event logger.
//!
//! Concurrency: one `Arc<Semaphore>` (256 permits) per service caps the
//! in-flight forwarded connections. Connection tasks are spawned detached —
//! this is safe because the semaphore is acquired (owned permit moved into
//! the task) before spawning, so at most 256 connection tasks exist per
//! service at any time, and each task self-cleans (permit released on drop).
//! The accept loop itself never blocks on a permit; excess streams are
//! served as soon as a permit frees up.

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

/// Maximum concurrent forwarded connections per onion service. Each is a
/// plain local TCP forwarding pair, but unbounded spawns would still let a
/// hostile client exhaust memory/file descriptors.
pub(crate) const MAX_CONCURRENT_STREAMS: usize = 256;

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
/// independent, so one stuck circuit cannot stall the others).
pub(crate) async fn serve_service(
    _service: Arc<RunningOnionService>,
    rend_requests: impl Stream<Item = RendRequest> + Unpin,
    ports: PortMap,
    semaphore: Arc<Semaphore>,
    token: CancellationToken,
) {
    let mut rend_requests = rend_requests;
    loop {
        let rend = tokio::select! {
            biased;
            () = token.cancelled() => return,
            rend = rend_requests.next() => match rend {
                Some(rend) => rend,
                None => {
                    debug!("onion service rendezvous stream ended");
                    return;
                }
            },
        };
        let ports = ports.clone();
        let semaphore = semaphore.clone();
        let token = token.clone();
        tokio::spawn(async move {
            match rend.accept().await {
                Ok(stream_requests) => {
                    serve_stream_requests(stream_requests, ports, semaphore, token).await;
                }
                Err(error) => {
                    // The client gets no notification; the rendezvous
                    // handshake simply fails on its side.
                    warn!(%error, "onion service: failed to complete rendezvous handshake");
                }
            }
        });
    }
}

/// Consume the `StreamRequest`s of one accepted rendezvous (one client
/// circuit): per request, resolve the virtual port, take a concurrency
/// permit, and forward to the local target.
async fn serve_stream_requests(
    mut stream_requests: impl Stream<Item = StreamRequest> + Unpin,
    ports: PortMap,
    semaphore: Arc<Semaphore>,
    token: CancellationToken,
) {
    loop {
        let request = tokio::select! {
            biased;
            () = token.cancelled() => return,
            request = stream_requests.next() => match request {
                Some(request) => request,
                None => return, // client circuit closed
            },
        };

        let port = requested_port(request.request());
        let Some(target) = target_for_port(&ports, port).cloned() else {
            trace!(?port, "onion service: rejecting stream for unknown port");
            if let Err(error) = request.reject(end_done()).await {
                debug!(%error, "onion service: failed to send END for rejected stream");
            }
            continue;
        };

        // Owned permit, moved into the connection task: the semaphore caps
        // in-flight forwards and the permit is released when the task ends.
        let Ok(permit) = semaphore.clone().acquire_owned().await else {
            // Semaphore closed: only happens at process teardown.
            let _ = request.reject(end_done()).await;
            return;
        };
        tokio::spawn(handle_stream_request(request, target, permit));
    }
}

/// Serve one accepted stream: accept it (CONNECTED to the client), connect
/// to the local target, then copy in both directions.
async fn handle_stream_request(
    request: StreamRequest,
    target: String,
    _permit: tokio::sync::OwnedSemaphorePermit,
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
pub(crate) async fn log_status_events(
    mut events: tor_hsservice::status::OnionServiceStatusStream,
    nickname: String,
    address: String,
    token: CancellationToken,
) {
    // The stream yields the current status first, then every change; dedupe
    // anyway so only real transitions log.
    let mut last: Option<tor_hsservice::status::State> = None;
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
        if last == Some(state) {
            continue;
        }
        last = Some(state);
        match state {
            tor_hsservice::status::State::Running => {
                info!(nickname = %nickname, %address, "onion service reachable");
            }
            tor_hsservice::status::State::Broken => {
                warn!(nickname = %nickname, %address, "onion service is broken");
            }
            tor_hsservice::status::State::DegradedReachable => {
                warn!(nickname = %nickname, %address, "onion service reachable but degraded");
            }
            tor_hsservice::status::State::DegradedUnreachable
            | tor_hsservice::status::State::Recovering => {
                warn!(nickname = %nickname, %address, "onion service unreachable, attempting recovery");
            }
            tor_hsservice::status::State::Bootstrapping => {
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
}
