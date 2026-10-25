//! Независимая DNS client ACL: production UDP/TCP listener молча дропает
//! запрещённых клиентов до любого парсинга/статистики/кэша/backend/admission.
use super::tests::{request, udp_exchange};
use super::*;
use hickory_proto::op::{MessageType, OpCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record, RecordType};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::timeout;

const CASE_BUDGET: Duration = Duration::from_secs(15);
const READ_DEADLINE: Duration = Duration::from_secs(2);

/// Политика, разрешающая только точный 127.0.0.1 (валидный IP-литерал грамматики).
fn localhost_only() -> AllowedClients {
    "127.0.0.1".parse().unwrap()
}

fn acl_ctx(
    endpoints: Vec<SocketAddr>,
    client_access: AllowedClients,
) -> QueryCtx<impl Fn() -> std::future::Ready<Option<TorTunnel>> + Clone + Send> {
    QueryCtx {
        // Положительный control отвечает из кэша или локальной политики:
        // tunnel-фабрика не используется.
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

/// PTR-вопрос про собственный не-loopback IPv4 (192.0.2.8) при wildcard
/// endpoint'е в ctx.endpoints: local::answer его не отвечает, и preflight
/// ОБЯЗАТЕЛЬНО вызывает route_probe до cache.get (порядок inline_answer).
fn probe_question(id: u16) -> (Message, IpAddr) {
    let ip = IpAddr::V4("192.0.2.8".parse().unwrap());
    let host = "8.2.0.192.in-addr.arpa.";
    (request(host, RecordType::PTR, id), ip)
}

/// Контрольный ответ из кэша для одного и того же вопроса во всех кейсах.
fn cached_reply(req: &Message) -> Message {
    let mut message = Message::new(req.metadata.id, MessageType::Response, OpCode::Query);
    message.add_query(req.queries[0].clone());
    message.add_answer(Record::from_rdata(
        req.queries[0].name().clone(),
        60,
        RData::A(A("192.0.2.7".parse().unwrap())),
    ));
    message
}

fn prefill(
    ctx: &QueryCtx<impl Fn() -> std::future::Ready<Option<TorTunnel>> + Clone + Send>,
    req: &Message,
) {
    ctx.cache.insert(
        &req.queries[0],
        &ResolvedAnswer {
            message: cached_reply(req),
            ttl: Duration::from_secs(60),
            resolved_at: time::OffsetDateTime::now_utc(),
        },
    );
}

/// Deny должен давать тишину: любой полученный датаграмма — провал.
async fn expect_udp_silence(socket: &UdpSocket) {
    let mut bytes = vec![0; 65535];
    let received = timeout(READ_DEADLINE, socket.recv_from(&mut bytes)).await;
    assert!(received.is_err(), "denied UDP client received a reply");
}

/// Поднять production udp_loop_observed на реальном сокете со счётчиком
/// наблюдений. Backend создаётся внутри и НЕ возвращается наружу: ассерты по
/// свободным permit'ам вакуумны (cached query не берёт permit, deny — до
/// admission), поэтому их здесь нет.
fn spawn_udp_loop(
    udp: Arc<UdpSocket>,
    ctx: QueryCtx<impl Fn() -> std::future::Ready<Option<TorTunnel>> + Clone + Send + 'static>,
    observed: Arc<AtomicUsize>,
) -> tokio::task::JoinHandle<()> {
    let backend = Arc::new(Semaphore::new(64));
    // Клонируем backend ДО async move, чтобы не захватывать его в move-замыкание.
    let loop_backend = backend.clone();
    tokio::spawn(async move {
        listener::udp_loop_observed(udp, ctx, loop_backend, move |_| {
            observed.fetch_add(1, Ordering::Relaxed);
        })
        .await
    })
}

/// abort + await; listener-задача не должна завершаться сама (паника/выход — провал).
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

/// UDP: 127.0.0.2 (deny) получает тишину и не оставляет наблюдений/probe-вызовов;
/// затем тот же живой listener проходит gate'ом и отвечает разрешённому 127.0.0.1.
#[tokio::test]
async fn udp_denied_client_gets_silence_and_allowed_client_is_served() {
    timeout(CASE_BUDGET, async {
        let (udp, _tcp) = bind_pair("127.0.0.1:0").await.unwrap();
        let udp = Arc::new(udp);
        let addr = udp.local_addr().unwrap();
        let observed = Arc::new(AtomicUsize::new(0));
        let probe_calls = Arc::new(AtomicUsize::new(0));
        let mut ctx = acl_ctx(
            // Wildcard v4 endpoint: условие probe-ветки в preflight_with_probe.
            vec!["0.0.0.0:0".parse().unwrap()],
            localhost_only(),
        );
        let pc = probe_calls.clone();
        ctx.route_probe = Arc::new(move |ip: IpAddr| {
            pc.fetch_add(1, Ordering::Relaxed);
            Box::pin(std::future::ready(Some(ip)))
        });
        let (req, _probe_ip) = probe_question(700);
        let udp_task = spawn_udp_loop(udp.clone(), ctx, observed.clone());

        // Отрицательный control: источник 127.0.0.2 не входит в политику.
        let denied = UdpSocket::bind("127.0.0.2:0").await.unwrap();
        denied.send_to(&req.to_vec().unwrap(), addr).await.unwrap();
        expect_udp_silence(&denied).await;
        assert_eq!(
            observed.load(Ordering::Relaxed),
            0,
            "denied packet must not be observed/parsed"
        );
        assert_eq!(
            probe_calls.load(Ordering::Relaxed),
            0,
            "denied packet must not reach local preflight/route_probe"
        );

        // Положительный control: разрешённый клиент проходит gate; вопрос идёт
        // в probe-ветку (мимо кэша), поэтому оба счётчика обязаны вырасти —
        // это ловит мёртвый сервер.
        let allowed = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let reply = udp_exchange(&allowed, addr, &req).await;
        assert_eq!(reply.metadata.id, req.metadata.id);
        assert_eq!(reply.queries, req.queries);
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert!(reply.answers.is_empty(), "probe branch answers NODATA");
        assert!(
            probe_calls.load(Ordering::Relaxed) > 0,
            "allowed query must reach route_probe before the cache"
        );
        assert!(
            observed.load(Ordering::Relaxed) > 0,
            "allowed packet must pass the gate into observe"
        );

        stop_loop("udp", udp_task).await;
    })
    .await
    .expect("acl udp case budget");
}

async fn send_framed(stream: &mut TcpStream, message: &Message) -> std::io::Result<()> {
    let bytes = message.to_vec().unwrap();
    let mut frame = u16::try_from(bytes.len()).unwrap().to_be_bytes().to_vec();
    frame.extend_from_slice(&bytes);
    stream.write_all(&frame).await
}

async fn read_reply(stream: &mut TcpStream) -> std::io::Result<Message> {
    match wire::read_framed_message(stream, READ_DEADLINE).await {
        Ok(Some(body)) => Ok(Message::from_vec(&body).unwrap()),
        // EOF и любые ошибки чтения сводим к io::Error, чтобы матчить по kind.
        Ok(None) => Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "connection closed without a reply",
        )),
        Err(error) => Err(error),
    }
}

fn reset_family(kind: std::io::ErrorKind) -> bool {
    matches!(
        kind,
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::UnexpectedEof
    )
}

/// Deny-клиент с explicit source 127.0.0.2: connect прошёл (TCP handshake делает
/// ядро), но listener дропает стрим до любого чтения.
async fn denied_tcp_stream(target: SocketAddr) -> std::io::Result<TcpStream> {
    let socket = TcpSocket::new_v4()?;
    socket.bind("127.0.0.2:0".parse().unwrap())?;
    socket.connect(target).await
}

/// TCP: 127.0.0.2 (deny) — соединение закрывается без ответа (EOF/сброс/разрыв)
/// и без создания работы (make_gate не вызывался); затем тот же listener
/// отвечает разрешённому 127.0.0.1 из предзаполненного кэша.
#[tokio::test]
async fn tcp_denied_connection_is_dropped_then_allowed_client_served() {
    timeout(CASE_BUDGET, async {
        let (udp, tcp) = bind_pair("127.0.0.1:0").await.unwrap();
        let addr = udp.local_addr().unwrap();
        let ctx = acl_ctx(vec![addr], localhost_only());
        let req = request("acl.example.", RecordType::A, 701);
        prefill(&ctx, &req);

        // Счётчик make_gate: работа создаётся только для клиентов, прошедших gate.
        let gate_creates = Arc::new(AtomicUsize::new(0));
        let gc = gate_creates.clone();
        let make_gate = move || {
            gc.fetch_add(1, Ordering::Relaxed);
            || std::future::ready(())
        };
        let tcp_task = tokio::spawn(async move {
            listener::tcp_loop_gated(
                tcp,
                ctx,
                Arc::new(Semaphore::new(64)),
                Arc::new(Semaphore::new(listener::MAX_TCP_CONNECTIONS)),
                make_gate,
                || {},
            )
            .await
        });

        // Отрицательный control: connect без отправки frame; deny-ветка
        // закрывает стрим, не создавая работы.
        let mut denied = denied_tcp_stream(addr).await.unwrap();
        match read_reply(&mut denied).await {
            Ok(_) => panic!("denied TCP client received a DNS reply"),
            Err(error) => assert!(
                reset_family(error.kind()),
                "unexpected read error for denied TCP client: {error}"
            ),
        }
        assert_eq!(
            gate_creates.load(Ordering::Relaxed),
            0,
            "denied connection must be dropped before any work is created"
        );

        // Положительный control: тот же listener отвечает разрешённому клиенту
        // из кэша, и работа для него создавалась.
        let mut allowed = TcpStream::connect(addr).await.unwrap();
        send_framed(&mut allowed, &req).await.unwrap();
        let reply = read_reply(&mut allowed).await.unwrap();
        assert_eq!(reply.metadata.id, req.metadata.id);
        assert_eq!(reply.queries, req.queries);
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert_eq!(
            reply.answers[0].data,
            RData::A(A("192.0.2.7".parse().unwrap()))
        );
        assert!(
            gate_creates.load(Ordering::Relaxed) > 0,
            "allowed connection must pass the gate into work creation"
        );

        stop_loop("tcp", tcp_task).await;
    })
    .await
    .expect("acl tcp case budget");
}
