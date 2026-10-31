//! Независимый emission-oracle реального accept/admission пути tcp_loop_gated:
//! capture-режим перехватывает настоящие строки tcp_accept/tcp_handler (не
//! только форматтеры), поэтому мутации цикла ловятся невакуумными тестами.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::timeout;

const CASE_BUDGET: Duration = Duration::from_secs(15);
const READ_DEADLINE: Duration = Duration::from_secs(2);

/// Политика, разрешающая только точный 127.0.0.1.
fn localhost_only() -> AllowedClients {
    "127.0.0.1".parse().unwrap()
}

fn diag_ctx(
    endpoints: Vec<SocketAddr>,
    client_access: AllowedClients,
) -> QueryCtx<impl Fn() -> std::future::Ready<Option<TorTunnel>> + Clone + Send> {
    QueryCtx {
        tunnel: || std::future::ready(None),
        cache: Arc::new(DnsCache::new()),
        providers: Arc::new(vec![]),
        overrides: Arc::new(vec![]),
        endpoints: Arc::new(RwLock::new(endpoints)),
        route_probe: local::route_probe(),
        statistics: None,
        client_access: Arc::new(client_access),
    }
}

/// abort + await; listener-задача не должна завершаться сама.
async fn stop_loop(name: &str, task: tokio::task::JoinHandle<()>) {
    task.abort();
    let err = task
        .await
        .expect_err("DNS listener не должен завершаться сам");
    assert!(
        err.is_cancelled(),
        "{name} dns listener task ended by itself (not aborted): {err}"
    );
}

/// Deny-клиент с explicit source 127.0.0.2 (connect делает ядро, listener
/// дропает стрим до любого чтения).
async fn denied_tcp_stream(target: SocketAddr) -> std::io::Result<TcpStream> {
    let socket = TcpSocket::new_v4()?;
    socket.bind("127.0.0.2:0".parse().unwrap())?;
    socket.connect(target).await
}

fn spawn_tcp_diag_loop(
    tcp: TcpListener,
    ctx: QueryCtx<impl Fn() -> std::future::Ready<Option<TorTunnel>> + Clone + Send + 'static>,
    gate_creates: Arc<AtomicUsize>,
) -> tokio::task::JoinHandle<()> {
    let gc = gate_creates.clone();
    let make_gate = move || {
        gc.fetch_add(1, Ordering::Relaxed);
        || std::future::ready(())
    };
    tokio::spawn(async move {
        listener::tcp_loop_gated(
            tcp,
            ctx,
            Arc::new(Semaphore::new(64)),
            Arc::new(Semaphore::new(listener::MAX_TCP_CONNECTIONS)),
            make_gate,
            || {},
        )
        .await
    })
}

fn lines_for_peer<'a>(lines: &'a [String], peer: &SocketAddr, prefix: &str) -> Vec<&'a str> {
    lines
        .iter()
        .map(String::as_str)
        .filter(|line| line.contains(prefix) && line.contains(&format!("peer={peer}")))
        .collect()
}

/// Deny: accepted эмитится сразу после accept (НЕ финальный admission), затем
/// denied_client_access на дропе; work не создаётся, tcp_handler-строк нет.
#[tokio::test]
async fn tcp_diag_deny_emits_accepted_then_denied_without_handler() {
    timeout(CASE_BUDGET, async {
        let (udp, tcp) = bind_pair("127.0.0.1:0").await.unwrap();
        let addr = udp.local_addr().unwrap();
        let ctx = diag_ctx(vec![addr], localhost_only());

        let gate_creates = Arc::new(AtomicUsize::new(0));
        let tcp_task = spawn_tcp_diag_loop(tcp, ctx, gate_creates.clone());

        // Перехват реальных emission; дренаж до запуска клиента.
        listener::set_capture_mode(true);
        listener::take_capture();

        let mut denied = denied_tcp_stream(addr).await.unwrap();
        // EOF/сброс: deny-ветка закрывает стрим без ответа.
        let mut buf = [0u8; 16];
        match denied.read(&mut buf).await {
            Ok(0) => {}
            Ok(_) => panic!("denied TCP client received bytes"),
            Err(error) => assert!(
                matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::BrokenPipe
                ),
                "unexpected read error for denied TCP client: {error}"
            ),
        }

        // Ограниченный бюджет ожидания emission — без бесконечного busy-loop.
        let deadline = tokio::time::Instant::now() + READ_DEADLINE;
        let mut lines = Vec::new();
        loop {
            lines.extend(listener::take_capture());
            if lines
                .iter()
                .any(|line| line.contains("state=denied_client_access"))
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "denied_client_access emission not observed: {lines:?}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let accepted = lines_for_peer(&lines, &denied.local_addr().unwrap(), "tcp_accept:");
        assert!(
            accepted.iter().any(|l| l.contains("state=accepted")),
            "state=accepted line missing for peer: {lines:?}"
        );
        assert!(
            accepted
                .iter()
                .any(|l| l.contains("state=denied_client_access")),
            "state=denied_client_access line missing for peer: {lines:?}"
        );
        let accepted_at = accepted
            .iter()
            .position(|line| line.contains("state=accepted"))
            .unwrap();
        let denied_at = accepted
            .iter()
            .position(|line| line.contains("state=denied_client_access"))
            .unwrap();
        assert!(accepted_at < denied_at, "wrong deny order: {lines:?}");
        assert!(
            !lines
                .iter()
                .any(|l| l.contains("tcp_handler:") && l.contains("peer=")),
            "no tcp_handler emissions expected on deny path: {lines:?}"
        );
        assert_eq!(
            gate_creates.load(Ordering::Relaxed),
            0,
            "denied connection must not create work"
        );
        for line in lines.iter().filter(|l| l.contains("tcp_accept:")) {
            assert!(
                line.contains(&format!("listener=Some({addr})")),
                "tcp_accept line must carry the real listener addr: {line}"
            );
        }

        listener::set_capture_mode(false);
        listener::take_capture();
        stop_loop("tcp diag deny", tcp_task).await;
    })
    .await
    .expect("tcp diag deny case budget");
}

/// Allowed + EOF: полный happy-path порядок accepted → enqueued → tcp_handler
/// state=start → tcp_diag terminal=eof; dropped_before_poll отсутствует.
#[tokio::test]
async fn tcp_diag_allowed_flow_emits_enqueued_start_and_eof() {
    timeout(CASE_BUDGET, async {
        let (udp, tcp) = bind_pair("0.0.0.0:0").await.unwrap();
        let bound = udp.local_addr().unwrap();
        let addr = SocketAddr::from(([127, 0, 0, 1], bound.port()));
        let ctx = diag_ctx(vec![addr], localhost_only());

        let gate_creates = Arc::new(AtomicUsize::new(0));
        let tcp_task = spawn_tcp_diag_loop(tcp, ctx, gate_creates.clone());

        listener::set_capture_mode(true);
        listener::take_capture();

        // Клиент подключается, ничего не шлёт и закрывает соединение (EOF).
        let mut client = TcpStream::connect(addr).await.unwrap();
        // peer в строках диагностики — source клиента глазами сервера.
        let peer = client.local_addr().unwrap();
        client.shutdown().await.unwrap();
        drop(client);

        // Ограниченный бюджет: ждём терминальную строку guard'а.
        let deadline = tokio::time::Instant::now() + READ_DEADLINE;
        let mut lines = Vec::new();
        loop {
            lines.extend(listener::take_capture());
            let eof = lines
                .iter()
                .any(|l| l.contains("tcp_diag:") && l.contains("terminal=eof"));
            assert!(
                eof || tokio::time::Instant::now() < deadline,
                "terminal=eof not observed within budget: {lines:?}"
            );
            if eof {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let accept_lines = lines_for_peer(&lines, &peer, "tcp_accept:");
        assert!(
            accept_lines.iter().any(|l| l.contains("state=accepted")),
            "state=accepted missing: {lines:?}"
        );
        assert!(
            accept_lines.iter().any(|l| l.contains("state=enqueued")),
            "state=enqueued missing: {lines:?}"
        );
        // enqueued НЕ значит handler стартовал: факт старта — только по
        // tcp_handler state=start при первом poll.
        let handler_lines = lines_for_peer(&lines, &peer, "tcp_handler:");
        assert_eq!(
            handler_lines
                .iter()
                .filter(|l| l.contains("state=start"))
                .count(),
            1,
            "exactly one handler start expected: {lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("tcp_diag:")
                && l.contains(&format!("peer=Some({peer})"))
                && l.contains("terminal=eof")),
            "guard terminal=eof line missing for the pair: {lines:?}"
        );
        let event_position = |prefix: &str, marker: &str| {
            let peer_marker = format!("peer={peer}");
            let guard_peer_marker = format!("peer=Some({peer})");
            lines
                .iter()
                .position(|line| {
                    line.starts_with(prefix)
                        && line.contains(marker)
                        && (line.contains(peer_marker.as_str())
                            || line.contains(guard_peer_marker.as_str()))
                })
                .expect("событие для этого соединения")
        };
        let accepted_at = event_position("tcp_accept:", "state=accepted");
        let enqueued_at = event_position("tcp_accept:", "state=enqueued");
        let started_at = event_position("tcp_handler:", "state=start");
        let eof_at = event_position("tcp_diag:", "terminal=eof");
        assert!(
            accepted_at < enqueued_at && enqueued_at < started_at && started_at < eof_at,
            "wrong lifecycle order: {lines:?}"
        );
        let expected_listener = format!("listener=Some({bound})");
        for line in accept_lines.iter().chain(handler_lines.iter()) {
            assert!(
                line.contains(expected_listener.as_str()),
                "wildcard listener identity lost: {line}"
            );
        }
        let expected_local = format!("local=Some({addr})");
        assert!(
            handler_lines.iter().any(|line| {
                line.contains("state=start") && line.contains(expected_local.as_str())
            }),
            "accepted local endpoint missing: {lines:?}"
        );
        assert!(
            !lines.iter().any(|l| l.contains("dropped_before_poll")),
            "dropped_before_poll must be absent on the happy path: {lines:?}"
        );
        assert!(gate_creates.load(Ordering::Relaxed) > 0);

        listener::set_capture_mode(false);
        listener::take_capture();
        stop_loop("tcp diag allowed", tcp_task).await;
    })
    .await
    .expect("tcp diag allowed case budget");
}
