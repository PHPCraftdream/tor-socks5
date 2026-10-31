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
                        #[cfg(test)]
                        tcp_diag::emit(&tcp_diag::format_accept_error(
                            &listener.local_addr().ok(),
                            &error,
                        ));
                        debug!(%error, "tcp dns accept failed");
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        continue;
                    }
                };
                // Только успешный accept: это НЕ финальный admission — возможные
                // исходы (deny/limit/permit/enqueued) эмитятся ниже по факту.
                #[cfg(test)]
                tcp_diag::emit(&tcp_diag::format_accept_state(
                    &listener.local_addr().ok(),
                    &peer,
                    "accepted",
                ));
                // Тот же gate, что и в UDP: по source peer из accept до
                // capacity/permit/nodelay; deny — continue, стрим дропается.
                if !ctx.client_access.allows(peer.ip()) {
                    debug!(%peer, "tcp dns client denied by client access policy");
                    #[cfg(test)]
                    tcp_diag::emit(&tcp_diag::format_accept_state(
                        &listener.local_addr().ok(),
                        &peer,
                        "denied_client_access",
                    ));
                    continue;
                }
                if work.len() >= MAX_TCP_CONNECTIONS {
                    #[cfg(test)]
                    tcp_diag::emit(&tcp_diag::format_accept_state(
                        &listener.local_addr().ok(),
                        &peer,
                        "dropped_connection_limit",
                    ));
                    continue;
                }
                let Ok(permit) = connections.clone().try_acquire_owned() else {
                    #[cfg(test)]
                    tcp_diag::emit(&tcp_diag::format_accept_state(
                        &listener.local_addr().ok(),
                        &peer,
                        "dropped_permit_unavailable",
                    ));
                    continue;
                };
                // Small request/response frames: never wait for a delayed ACK.
                let _ = stream.set_nodelay(true);
                let ctx = ctx.clone();
                let backend = backend.clone();
                let gate = make_gate();
                #[cfg(test)]
                let connection_local = stream.local_addr().ok();
                // enqueued — future положен в work; handler мог ещё НЕ стартовать
                // (факт старта виден только по tcp_handler state=start).
                #[cfg(test)]
                tcp_diag::emit(&tcp_diag::format_accept_state(
                    &listener.local_addr().ok(),
                    &peer,
                    "enqueued",
                ));
                let connection = async move {
                    let _permit = permit;
                    // Finite connection lifetime also bounds peers continuously
                    // sending valid local/cache queries, not merely idle peers.
                    let _ = timeout(
                        CONNECTION_LIFETIME,
                        handle_tcp_gated(stream, ctx, backend, gate),
                    )
                    .await;
                };
                // Обёртка закрывает слепую зону: дроп future до первого poll
                // даёт state=dropped_before_poll (guard создаётся лишь при poll).
                #[cfg(test)]
                work.push(Box::pin(tcp_diag::poll_observed(
                    listener.local_addr().ok(),
                    connection_local,
                    peer,
                    connection,
                )));
                #[cfg(not(test))]
                work.push(Box::pin(connection));
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
    #[cfg(test)]
    let mut diag = tcp_diag::TcpDiagGuard::new(stream.local_addr().ok(), stream.peer_addr().ok());
    loop {
        #[cfg(test)]
        diag.stage("gate");
        gate().await;
        #[cfg(test)]
        diag.stage("read");
        let framed = wire::read_framed_message(&mut stream, IO_TIMEOUT).await;
        let body = match framed {
            Ok(Some(body)) => body,
            Ok(None) => {
                #[cfg(test)]
                diag.terminal("eof");
                return;
            }
            Err(error) => {
                // Форматирование только под cfg(test); в prod error дропается
                // при return, как и прежде.
                #[cfg(test)]
                diag.terminal(&format!(
                    "read_error(kind={:?},os={:?})",
                    error.kind(),
                    error.raw_os_error()
                ));
                #[cfg(not(test))]
                drop(error);
                return;
            }
        };
        #[cfg(test)]
        diag.stage("parse");
        let Some(request) = wire::parse_query(&body) else {
            #[cfg(test)]
            diag.terminal("parse_reject");
            return;
        };
        #[cfg(test)]
        diag.stage("answer");
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
        #[cfg(test)]
        diag.stage("encode");
        let Ok(bytes) = reply.to_vec() else {
            #[cfg(test)]
            diag.terminal("encode_error");
            return;
        };
        #[cfg(test)]
        diag.stage("write");
        if let Err(error) = wire::write_framed_message(&mut stream, &bytes, IO_TIMEOUT).await {
            #[cfg(test)]
            diag.terminal(&format!(
                "write_error(kind={:?},os={:?})",
                error.kind(),
                error.raw_os_error()
            ));
            drop(error);
            return;
        }
        // Успешная запись: только stage-метка (НЕ terminal), следующая
        // итерация перезапишет её на "gate".
        #[cfg(test)]
        {
            diag.record_write();
            diag.stage("observed_write_completed");
        }
    }
}

// Test-only диагностика TCP-соединения (flaky RST/10054 в CI). В production
// модуль целиком отсутствует: ни вызовов, ни аллокаций, ни I/O.
// Реэкспорт для тестов уровня server (accept-loop emission oracle).
#[cfg(test)]
pub(super) use tcp_diag::{client_io_result, poll_observed, set_capture_mode, take_capture};
#[cfg(test)]
mod tcp_diag {
    use std::future::Future;
    use std::io;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::task::{Context, Poll};

    /// Чистая функция форматирования одной строки диагностики.
    fn format_diag(
        local: &Option<SocketAddr>,
        peer: &Option<SocketAddr>,
        stage: &str,
        terminal: &str,
        observed_writes: usize,
    ) -> String {
        format!(
            "tcp_diag: local={local:?} peer={peer:?} stage={stage} \
             terminal={terminal} observed_writes={observed_writes}"
        )
    }

    /// Одна test-only строка в stderr без содержимого пакетов.
    fn stderr_emit(line: &str) {
        eprintln!("{line}");
    }

    static OBSERVATION_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    pub(in super::super) fn client_io_result<T>(
        local: Option<SocketAddr>,
        peer: Option<SocketAddr>,
        operation: &'static str,
        offset: usize,
        result: io::Result<T>,
    ) -> io::Result<T> {
        if let Err(error) = &result {
            emit(&format!(
                "tcp_client_error: local={local:?} peer={peer:?} \
                 operation={operation} offset={offset} kind={:?} os={:?}",
                error.kind(),
                error.raw_os_error()
            ));
        }
        result
    }

    /// Единая маршрутизация: capture-режим для тестов, иначе stderr.
    fn dispatch_emit(line: &str) {
        let sequence = OBSERVATION_SEQUENCE
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                value.checked_add(1)
            })
            .ok()
            .map(|value| value + 1);
        let line = format!("{line} seq={sequence:?}");
        if CAPTURE_MODE.with(|m| m.get()) {
            capture_emit(&line);
        } else {
            stderr_emit(&line);
        }
    }

    /// Публичная обёртка: emit строк уровня accept/admission и handler'а.
    pub(super) fn emit(line: &str) {
        dispatch_emit(line);
    }

    /// Состояния приёма соединения: accepted — только успешный accept (НЕ
    /// финальный admission); denied/limit/permit — дропы; enqueued — future
    /// в work, handler мог не стартовать (см. tcp_handler state=start).
    pub(super) fn format_accept_state(
        listener: &Option<SocketAddr>,
        peer: &SocketAddr,
        state: &str,
    ) -> String {
        format!("tcp_accept: listener={listener:?} peer={peer} state={state}")
    }

    /// Ошибка accept с корреляцией по реальному listener-адресу (без
    /// вымышленных идентификаторов соединения).
    pub(super) fn format_accept_error(
        listener: &Option<SocketAddr>,
        error: &std::io::Error,
    ) -> String {
        format!(
            "tcp_accept_error: listener={listener:?} kind={:?} os={:?} error={error}",
            error.kind(),
            error.raw_os_error()
        )
    }

    /// Test-only future-обёртка: закрывает слепую зону между enqueue и первым
    /// poll — дроп до poll фиксируется как dropped_before_poll.
    pub(in super::super) struct PollObserved<F> {
        listener: Option<SocketAddr>,
        local: Option<SocketAddr>,
        peer: SocketAddr,
        polled: bool,
        inner: Pin<Box<F>>,
    }

    pub(in super::super) fn poll_observed<F: Future + Send>(
        listener: Option<SocketAddr>,
        local: Option<SocketAddr>,
        peer: SocketAddr,
        inner: F,
    ) -> PollObserved<F> {
        PollObserved {
            listener,
            local,
            peer,
            polled: false,
            inner: Box::pin(inner),
        }
    }

    impl<F: Future> Future for PollObserved<F> {
        type Output = F::Output;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            if !self.polled {
                self.polled = true;
                emit(&format!(
                    "tcp_handler: listener={:?} local={:?} peer={} state=start",
                    self.listener, self.local, self.peer
                ));
            }
            self.inner.as_mut().poll(cx)
        }
    }

    impl<F> Drop for PollObserved<F> {
        fn drop(&mut self) {
            if !self.polled {
                emit(&format!(
                    "tcp_handler: listener={:?} local={:?} peer={} state=dropped_before_poll",
                    self.listener, self.local, self.peer
                ));
            }
        }
    }

    // Буфер тестового sink изолирован по OS-потокам.
    thread_local! {
        static CAPTURE: std::cell::RefCell<Vec<String>> =
            const { std::cell::RefCell::new(Vec::new()) };
        /// По умолчанию выключен: обычные тесты продолжают печатать в stderr.
        static CAPTURE_MODE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// Включает перехват реальных loop-emissions в CAPTURE (вместо stderr).
    pub(in super::super) fn set_capture_mode(on: bool) {
        CAPTURE_MODE.with(|m| m.set(on));
    }

    fn capture_emit(s: &str) {
        CAPTURE.with(|c| c.borrow_mut().push(s.to_string()));
    }

    /// Забирает накопленные test-only строки.
    pub(in super::super) fn take_capture() -> Vec<String> {
        CAPTURE.with(|c| c.borrow_mut().drain(..).collect())
    }

    pub(super) struct TcpDiagGuard {
        local: Option<SocketAddr>,
        peer: Option<SocketAddr>,
        stage: &'static str,
        terminal: Option<String>,
        observed_writes: usize,
        emit: fn(&str),
    }

    impl TcpDiagGuard {
        pub(super) fn new(local: Option<SocketAddr>, peer: Option<SocketAddr>) -> Self {
            Self {
                local,
                peer,
                stage: "entry",
                terminal: None,
                observed_writes: 0,
                // Через dispatch_emit guard тоже уважает capture-режим.
                emit: dispatch_emit,
            }
        }

        pub(super) fn with_emit(
            local: Option<SocketAddr>,
            peer: Option<SocketAddr>,
            emit: fn(&str),
        ) -> Self {
            let mut guard = Self::new(local, peer);
            guard.emit = emit;
            guard
        }

        pub(super) fn stage(&mut self, s: &'static str) {
            self.stage = s;
        }

        /// Последний terminal непосредственно перед Drop побеждает.
        pub(super) fn terminal(&mut self, t: &str) {
            self.terminal = Some(t.to_string());
        }

        pub(super) fn record_write(&mut self) {
            self.observed_writes = self.observed_writes.saturating_add(1);
        }
    }

    impl Drop for TcpDiagGuard {
        fn drop(&mut self) {
            let terminal = match &self.terminal {
                Some(t) => t.as_str(),
                None => "unclassified_drop",
            };
            let line = format_diag(
                &self.local,
                &self.peer,
                self.stage,
                terminal,
                self.observed_writes,
            );
            (self.emit)(&line);
        }
    }

    fn endpoints() -> (Option<SocketAddr>, Option<SocketAddr>) {
        (
            Some(SocketAddr::from(([127, 0, 0, 1], 5353))),
            Some(SocketAddr::from(([127, 0, 0, 1], 44444))),
        )
    }

    #[test]
    fn lifecycle_line_contains_stage_and_terminal() {
        take_capture();
        let (local, peer) = endpoints();
        let mut guard = TcpDiagGuard::with_emit(local, peer, capture_emit);
        guard.stage("read");
        guard.terminal("eof");
        drop(guard);
        let lines = take_capture();
        assert_eq!(lines.len(), 1, "got: {lines:?}");
        let line = &lines[0];
        assert!(line.contains("local=Some(127.0.0.1:5353)"), "got: {line}");
        assert!(line.contains("peer=Some(127.0.0.1:44444)"), "got: {line}");
        assert!(line.contains("stage=read"), "got: {line}");
        assert!(line.contains("terminal=eof"), "got: {line}");
    }

    #[test]
    fn success_then_error_is_not_masked() {
        take_capture();
        let (local, peer) = endpoints();
        let mut guard = TcpDiagGuard::with_emit(local, peer, capture_emit);
        guard.stage("write");
        guard.record_write();
        guard.terminal("read_error(kind=ConnectionReset,os=Some(10054))");
        drop(guard);
        let lines = take_capture();
        assert_eq!(lines.len(), 1, "got: {lines:?}");
        let line = &lines[0];
        assert!(
            line.contains("terminal=read_error(kind=ConnectionReset,os=Some(10054))"),
            "got: {line}"
        );
        assert!(line.contains("observed_writes=1"), "got: {line}");
    }

    #[test]
    fn accept_state_line_contains_listener_peer_state() {
        let (local, peer) = endpoints();
        let line = format_accept_state(&local, peer.as_ref().unwrap(), "denied_client_access");
        assert!(line.contains("tcp_accept:"), "got: {line}");
        assert!(
            line.contains("listener=Some(127.0.0.1:5353)"),
            "got: {line}"
        );
        assert!(line.contains("peer=127.0.0.1:44444"), "got: {line}");
        assert!(line.contains("state=denied_client_access"), "got: {line}");
    }

    #[test]
    fn accept_error_line_contains_kind() {
        let error = std::io::Error::from(std::io::ErrorKind::ConnectionReset);
        let line = format_accept_error(&Some(SocketAddr::from(([127, 0, 0, 1], 5353))), &error);
        assert!(line.contains("tcp_accept_error:"), "got: {line}");
        assert!(
            line.contains("listener=Some(127.0.0.1:5353)"),
            "got: {line}"
        );
        assert!(line.contains("kind=ConnectionReset"), "got: {line}");
    }

    #[test]
    fn accept_error_preserves_raw_os_error() {
        let error = std::io::Error::from_raw_os_error(10054);
        let line = format_accept_error(&Some(SocketAddr::from(([0, 0, 0, 0], 5353))), &error);
        assert!(line.contains("listener=Some(0.0.0.0:5353)"), "got: {line}");
        assert!(line.contains("os=Some(10054)"), "got: {line}");
    }

    #[test]
    fn queued_future_dropped_before_poll_reports_endpoints() {
        take_capture();
        set_capture_mode(true);
        let (local, peer) = endpoints();
        let queue = futures::stream::FuturesUnordered::new();
        queue.push(poll_observed(
            Some(SocketAddr::from(([0, 0, 0, 0], 5353))),
            local,
            peer.unwrap(),
            std::future::pending::<()>(),
        ));
        drop(queue);
        let lines = take_capture();
        set_capture_mode(false);
        assert_eq!(lines.len(), 1, "got: {lines:?}");
        let line = &lines[0];
        assert!(line.contains("state=dropped_before_poll"), "got: {line}");
        assert!(line.contains("listener=Some(0.0.0.0:5353)"), "got: {line}");
        assert!(line.contains("local=Some(127.0.0.1:5353)"), "got: {line}");
        assert!(line.contains("peer=127.0.0.1:44444"), "got: {line}");
        assert!(!line.contains("state=start"), "got: {line}");
    }

    #[test]
    fn cancel_after_successful_write_is_not_masked() {
        take_capture();
        let (local, peer) = endpoints();
        let mut guard = TcpDiagGuard::with_emit(local, peer, capture_emit);
        guard.record_write();
        guard.stage("observed_write_completed");
        drop(guard);
        let lines = take_capture();
        assert_eq!(lines.len(), 1, "got: {lines:?}");
        let line = &lines[0];
        assert!(line.contains("terminal=unclassified_drop"), "got: {line}");
        assert!(
            line.contains("stage=observed_write_completed"),
            "got: {line}"
        );
        assert!(line.contains("observed_writes=1"), "got: {line}");
    }

    #[test]
    fn dropped_pending_future_reports_unclassified_drop() {
        take_capture();
        let (local, peer) = endpoints();
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Box::pin(async move {
            let mut diag = TcpDiagGuard::with_emit(local, peer, capture_emit);
            diag.stage("read");
            std::future::pending::<()>().await;
            drop(diag);
        });
        let polled = pinned.as_mut().poll(&mut cx);
        assert!(matches!(polled, Poll::Pending));
        // Дроп future гарантирует дроп diag внутри async-блока.
        drop(pinned);
        let lines = take_capture();
        assert_eq!(lines.len(), 1, "got: {lines:?}");
        let line = &lines[0];
        assert!(line.contains("terminal=unclassified_drop"), "got: {line}");
        assert!(line.contains("stage=read"), "got: {line}");
        assert!(line.contains("local=Some(127.0.0.1:5353)"), "got: {line}");
        assert!(line.contains("peer=Some(127.0.0.1:44444)"), "got: {line}");
    }
}
