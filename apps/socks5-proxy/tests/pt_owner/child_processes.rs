use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

const PID_MARKER: &str = "owner-contract-pid";

struct Scan {
    found: Vec<(PathBuf, u32)>,
    error: Option<&'static str>,
}

#[derive(Default)]
pub(super) struct KnownChildren {
    pids: BTreeSet<u32>,
    scan_failed: bool,
}

pub(super) fn owner_pid(
    snapshot: &[(PathBuf, u32)],
    base: &Path,
    slot: usize,
) -> Result<u32, &'static str> {
    let root = base
        .join("owners-v1")
        .join(slot.to_string())
        .join("state/pt_state");
    let found: Vec<_> = snapshot
        .iter()
        .filter(|(path, _)| path.starts_with(&root))
        .collect();
    if found.len() != 1 || found[0].1 == 0 {
        return Err("owner child PID missing or ambiguous");
    }
    let pid = found[0].1;
    if snapshot
        .iter()
        .filter(|(_, candidate)| *candidate == pid)
        .count()
        != 1
    {
        return Err("owner child PID is shared across markers");
    }
    Ok(pid)
}

pub(super) fn scan_child_pids(root: &Path) -> Result<Vec<(PathBuf, u32)>, &'static str> {
    let scan = scan_child_pids_partial(root);
    match scan.error {
        Some(error) => Err(error),
        None => Ok(scan.found),
    }
}

fn scan_child_pids_partial(root: &Path) -> Scan {
    fn walk(
        dir: &Path,
        depth: usize,
        visited: &mut usize,
        out: &mut Vec<(PathBuf, u32)>,
    ) -> Option<&'static str> {
        if depth > 12 {
            return Some("глубина PID-сканирования превышена");
        }
        let read_entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(_) => return Some("ошибка чтения PID-каталога"),
        };
        let mut entries = Vec::new();
        for entry in read_entries {
            *visited += 1;
            if *visited > 512 {
                return Some("превышен лимит записей PID-сканирования");
            }
            match entry {
                Ok(entry) => entries.push(entry),
                Err(_) => return Some("ошибка записи PID-каталога"),
            }
        }
        entries.sort_by_key(|entry| entry.path());
        for entry in entries {
            let path = entry.path();
            let ty = match entry.file_type() {
                Ok(ty) => ty,
                Err(_) => return Some("ошибка типа записи PID-каталога"),
            };
            if ty.is_symlink() {
                return Some("символическая ссылка в PID-сканировании запрещена");
            }
            if ty.is_dir() {
                if let Some(error) = walk(&path, depth + 1, visited, out) {
                    return Some(error);
                }
            } else if ty.is_file() && entry.file_name() == "owner-contract-pid" {
                let text = match fs::read_to_string(&path) {
                    Ok(text) => text,
                    Err(_) => return Some("ошибка чтения PID-файла"),
                };
                let pid = match text.trim().parse() {
                    Ok(pid) => pid,
                    Err(_) => return Some("ошибка разбора PID-файла"),
                };
                out.push((path, pid));
            }
        }
        None
    }
    let mut found = Vec::new();
    let mut visited = 0;
    let error = walk(root, 0, &mut visited, &mut found);
    Scan { found, error }
}

impl KnownChildren {
    pub(super) fn refresh(&mut self, root: &Path) -> Result<(), &'static str> {
        let scan = scan_child_pids_partial(root);
        self.pids.extend(scan.found.into_iter().map(|(_, pid)| pid));
        if let Some(error) = scan.error {
            self.scan_failed = true;
            Err(error)
        } else {
            Ok(())
        }
    }
}

pub(super) async fn verify_children_gone(
    known: &mut KnownChildren,
    dir: &Path,
    total_deadline: tokio::time::Instant,
) -> Result<(), &'static str> {
    loop {
        let _ = known.refresh(dir);
        let mut alive = false;
        for pid in &known.pids {
            match fs::metadata(format!("/proc/{pid}")) {
                Ok(_) => alive = true,
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(_) => known.scan_failed = true,
            }
        }
        if !alive {
            return if known.scan_failed {
                Err("PT PID scan failed")
            } else {
                Ok(())
            };
        }
        let now = tokio::time::Instant::now();
        if now >= total_deadline {
            return Err("PT children survived shutdown");
        }
        tokio::time::sleep_until((now + Duration::from_millis(500)).min(total_deadline)).await;
    }
}

#[tokio::test]
async fn pid_scan_error_keeps_partial_and_sticky_children() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    fs::create_dir_all(&a).unwrap();
    fs::create_dir_all(&b).unwrap();
    let known_path = a.join(PID_MARKER);
    fs::write(&known_path, std::process::id().to_string()).unwrap();
    fs::write(b.join(PID_MARKER), "not-a-pid").unwrap();
    let mut known = KnownChildren::default();
    assert!(known.refresh(dir.path()).is_err());
    assert!(known.scan_failed);
    assert!(known.pids.contains(&std::process::id()));
    assert!(
        verify_children_gone(&mut known, dir.path(), tokio::time::Instant::now())
            .await
            .is_err()
    );
    fs::remove_file(known_path).unwrap();
    assert!(known.refresh(dir.path()).is_err());
    assert!(known.pids.contains(&std::process::id()));
}

pub(crate) mod wt_recorder {
    use super::super::scenario_resources::session_ledger::{
        Credential, End, Event, Ledger, Owner, Phase, Receipt, Stage,
    };
    use super::super::webtunnel_contract::{carrier, RecorderOptions, Session};
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{mpsc, watch};
    use tokio::time::{timeout_at, Duration, Instant};

    type Result<T> = std::result::Result<T, &'static str>;

    /// cancel-safe: NO — unexpected cancellation abandons any active lease and fails reconciliation.
    pub(crate) async fn record(
        listener: TcpListener,
        mut stop: watch::Receiver<()>,
        destination: SocketAddr,
        deadline: Instant,
        events: mpsc::Sender<Session>,
        options: RecorderOptions,
        ledger: Ledger,
    ) -> Result<()> {
        let mut next_id = 0usize;
        loop {
            let stream = tokio::select! {
                biased;
                changed = stop.changed() => {
                    if changed.is_err() {
                        ledger.lost();
                        return Err("recorder stop signal lost");
                    }
                    ledger.stopping()?;
                    return Ok(());
                }
                accepted = listener.accept() => {
                    accepted.map_err(|_| "recorder accept failed")?.0
                }
            };
            let id = next_id;
            let lease = ledger.accepted(id)?;
            next_id += 1;
            let completed = {
                let mut handshake = Box::pin(timeout_at(
                    deadline,
                    carrier(stream, destination, deadline, options, &lease),
                ));
                tokio::select! {
                    biased;
                    result = &mut handshake => Some(result),
                    changed = stop.changed() => {
                        if changed.is_err() {
                            ledger.lost();
                            return Err("recorder stop signal lost");
                        }
                        ledger.stopping()?;
                        None
                    }
                }
            };
            let Some(completed) = completed else {
                return Ok(());
            };
            let (stream, credential, stage) =
                completed.map_err(|_| "recorder carrier deadline")??;
            lease.apply(Event::Delivered)?;
            let session = Session {
                id,
                lease,
                stream,
                credential,
                stage,
            };
            if events.try_send(session).is_err() {
                ledger.lost();
                return Err("recorder observation lost");
            }
        }
    }

    pub(in super::super) fn consume(session: &Session) -> Result<()> {
        session.lease.apply(Event::Consumed)
    }

    /// Expected identity comes from the caller's admitted route and owner witness.
    /// Socket ownership is checked here while the exact session stream is alive.
    pub(in super::super) fn correlate(session: &Session, expected: Receipt) -> Result<()> {
        if expected.session != session.id
            || expected.stage != session.stage
            || expected.credential != session.credential
        {
            return Err("consumer receipt identity mismatch");
        }
        let pid = match expected.owner {
            Owner::Global { pid } | Owner::Alternate { pid, .. } => pid,
        };
        super::super::pt_contract::tcp_source_owned_by(&session.stream, pid)
            .map_err(|_| "consumer live socket ownership mismatch")?;
        if super::super::pt_contract::tcp_source_owned_by(&session.stream, 0).is_ok() {
            return Err("consumer wrong-PID control accepted");
        }
        session.lease.apply(Event::Bind(expected))?;
        let observed = Receipt {
            session: session.id,
            stage: session.stage,
            credential: session.credential,
            owner: expected.owner,
        };
        session.lease.apply(Event::Correlated(observed))
    }

    /// Rejected requires the caller's completed negative write, flush and exact EOF.
    pub(in super::super) fn dispose(session: Session, end: End) -> Result<()> {
        let permitted = matches!(
            (session.stage, end),
            (Stage::Raw, End::Closed) | (Stage::Auth | Stage::Connect, End::Rejected)
        );
        if !permitted {
            return Err("consumer terminal stage mismatch");
        }
        let Session { stream, lease, .. } = session;
        drop(stream);
        let result = lease.apply(Event::Terminal(end));
        drop(lease);
        result
    }

    /// Caller-retained actual admission/owner evidence, not a predicted owner.
    /// Alternate fields must retain the observed reserve/construction distinction.
    #[derive(Clone, Copy)]
    pub(in super::super) struct ExpectedOwner {
        pub(in super::super) credential: Credential,
        pub(in super::super) owner: Owner,
    }

    fn expected_pid(owner: Owner) -> u32 {
        match owner {
            Owner::Global { pid } | Owner::Alternate { pid, .. } => pid,
        }
    }

    /// cancel-safe: NO — cancellation closes the owned session and leaves its lease undisposed.
    pub(in super::super) async fn reconcile_one(
        mut session: Session,
        expected: [Option<ExpectedOwner>; 2],
        rejection: Option<Stage>,
        deadline: Instant,
    ) -> Result<()> {
        timeout_at(deadline, async move {
            consume(&session)?;
            if Instant::now() >= deadline {
                return Err("queued session deadline");
            }
            let stage = rejection.unwrap_or(Stage::Raw);
            if session.stage != stage {
                return Err("queued session stage mismatch");
            }
            let mut selected = None;
            for candidate in expected.into_iter().flatten() {
                let live = super::super::pt_contract::tcp_source_owned_by(
                    &session.stream,
                    expected_pid(candidate.owner),
                )
                .is_ok();
                if !live {
                    continue;
                }
                if candidate.credential != session.credential {
                    return Err("queued session crossed owner");
                }
                if selected.replace(candidate).is_some() {
                    return Err("queued session owner ambiguous");
                }
            }
            let selected = selected.ok_or("queued session owner unmapped")?;
            correlate(
                &session,
                Receipt {
                    session: session.id,
                    stage,
                    credential: selected.credential,
                    owner: selected.owner,
                },
            )?;
            if stage == Stage::Raw {
                return dispose(session, End::Closed);
            }
            let reply: &[u8] = match stage {
                Stage::Auth => &[1, 1],
                Stage::Connect => &[5, 2, 0, 1, 0, 0, 0, 0, 0, 0],
                Stage::Raw => return Err("queued rejection stage invalid"),
            };
            session
                .stream
                .write_all(reply)
                .await
                .map_err(|_| "queued rejection write failed")?;
            session
                .stream
                .flush()
                .await
                .map_err(|_| "queued rejection flush failed")?;
            let mut byte = [0; 1];
            if session
                .stream
                .read(&mut byte)
                .await
                .map_err(|_| "queued rejection closure read failed")?
                != 0
            {
                return Err("queued rejected session continued");
            }
            dispose(session, End::Rejected)
        })
        .await
        .map_err(|_| "queued session deadline")?
    }

    /// cancel-safe: NO — cancellation abandons the active completed lease; the caller retains
    /// the remaining queue and sessions, and must not accept an unsealed ledger.
    pub(in super::super) async fn reconcile_queue(
        sessions: &mut mpsc::Receiver<Session>,
        retained: &mut Vec<Session>,
        expected: [Option<ExpectedOwner>; 2],
        rejection: Option<Stage>,
        deadline: Instant,
        ledger: &Ledger,
    ) -> Result<()> {
        let mut failure = if sessions.is_closed() {
            None
        } else {
            Some("queued producer channel still open")
        };
        loop {
            match sessions.try_recv() {
                Ok(session) => {
                    if let Err(error) = reconcile_one(session, expected, rejection, deadline).await
                    {
                        failure.get_or_insert(error);
                    }
                }
                Err(mpsc::error::TryRecvError::Disconnected) => break,
                Err(mpsc::error::TryRecvError::Empty) => {
                    failure.get_or_insert("queued producer channel still open");
                    break;
                }
            }
        }
        for session in retained.drain(..) {
            if let Err(error) = dispose(session, End::Closed) {
                failure.get_or_insert(error);
            }
        }
        if let Err(error) = ledger.finish() {
            failure.get_or_insert(error);
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Synthetic identity uses actual loopback sockets owned by this process, not stock children.
    /// cancel-safe: NO — each timeout owns the actor, peers and queue; cancellation drops them
    /// without detaching tasks and cannot establish successful final reconciliation.
    pub(crate) async fn run_queue_integration_controls() -> Result<()> {
        for case in 0..4 {
            let deadline = Instant::now() + Duration::from_secs(3);
            timeout_at(deadline, async {
                let listener = TcpListener::bind("127.0.0.1:0")
                    .await
                    .map_err(|_| "queue integration bind failed")?;
                let address = listener
                    .local_addr()
                    .map_err(|_| "queue integration address failed")?;
                let ledger = Ledger::new();
                let (stop, stopped) = watch::channel(());
                let (sender, mut receiver) = mpsc::channel(8);
                let actor = record(
                    listener,
                    stopped,
                    address,
                    deadline,
                    sender.clone(),
                    RecorderOptions {
                        same_address: false,
                        domain: false,
                        rejection: Some(Stage::Auth),
                    },
                    ledger.clone(),
                );
                let driver = async {
                    let mut clients = Vec::new();
                    let mut delivered = Vec::new();
                    for id in 0..2 {
                        let mut client = greeting(address).await?;
                        authenticate(&mut client).await?;
                        let session = receiver
                            .recv()
                            .await
                            .ok_or("queue integration delivery missing")?;
                        if session.id != id
                            || session.stage != Stage::Auth
                            || session.credential != Credential::Global
                        {
                            return Err("queue integration delivery mismatch");
                        }
                        if case == 3 && id == 1 {
                            consume(&session)?;
                        }
                        delivered.push(session);
                        clients.push(client);
                    }
                    for session in delivered {
                        sender
                            .try_send(session)
                            .map_err(|_| "queue integration requeue failed")?;
                    }
                    drop(sender);
                    stop.send(()).map_err(|_| "queue integration stop failed")?;
                    Ok::<_, &'static str>(clients)
                };
                let (actor_result, clients) = tokio::join!(actor, driver);
                actor_result?;
                let clients = clients?;
                if !receiver.is_closed() || receiver.len() != 2 {
                    return Err("queue integration terminal delivery mismatch");
                }
                let credential = if case == 2 {
                    Credential::Account
                } else {
                    Credential::Global
                };
                let expected = [
                    if case == 1 {
                        None
                    } else {
                        Some(ExpectedOwner {
                            credential,
                            owner: Owner::Global {
                                pid: std::process::id(),
                            },
                        })
                    },
                    None,
                ];
                let mut retained = Vec::new();
                let peers = async {
                    let mut clients = clients;
                    for (id, client) in clients.iter_mut().enumerate() {
                        if case == 0 || (case == 3 && id == 0) {
                            let mut reply = [0; 2];
                            client
                                .read_exact(&mut reply)
                                .await
                                .map_err(|_| "queue integration reply missing")?;
                            if reply != [1, 1] {
                                return Err("queue integration reply mismatch");
                            }
                            client
                                .shutdown()
                                .await
                                .map_err(|_| "queue integration EOF failed")?;
                        }
                    }
                    Ok::<_, &'static str>(clients)
                };
                let (result, clients) = tokio::join!(
                    reconcile_queue(
                        &mut receiver,
                        &mut retained,
                        expected,
                        Some(Stage::Auth),
                        deadline,
                        &ledger,
                    ),
                    peers,
                );
                drop(clients?);
                let expected_result = match case {
                    0 => Ok(()),
                    1 => Err("queued session owner unmapped"),
                    2 => Err("queued session crossed owner"),
                    3 => Err("session event invalid"),
                    _ => return Err("queue integration case invalid"),
                };
                if result != expected_result || !receiver.is_empty() {
                    return Err("queue integration result mismatch");
                }
                for id in 0..2 {
                    let observed = ledger.inspect(id)?;
                    let consumed = case == 0 || case == 3 || id == 0;
                    let terminal = if case == 0 || (case == 3 && id == 0) {
                        Some(End::Rejected)
                    } else {
                        None
                    };
                    if !observed.delivered
                        || observed.consumed != consumed
                        || !observed.released
                        || observed.critical != Some((Stage::Auth, Credential::Global))
                        || observed.terminal != terminal
                    {
                        return Err("queue integration lifecycle mismatch");
                    }
                }
                if ledger.is_sealed() != (case == 0) {
                    return Err("queue integration seal state mismatch");
                }
                if ledger.finish().is_ok() != (case == 0) {
                    return Err("queue integration seal mismatch");
                }
                Ok(())
            })
            .await
            .map_err(|_| "queue integration deadline")??;
        }
        Ok(())
    }

    /// Synthetic lifecycle claims use real loopback ownership of this control process only.
    /// cancel-safe: NO — the timed region owns all sockets and both joined futures.
    pub(crate) async fn run_queued_session_controls() -> Result<()> {
        for case in 0..11 {
            let deadline = Instant::now() + Duration::from_secs(3);
            timeout_at(deadline, async {
                let listener = TcpListener::bind("127.0.0.1:0")
                    .await
                    .map_err(|_| "queued control bind failed")?;
                let address = listener
                    .local_addr()
                    .map_err(|_| "queued control address failed")?;
                let (client, accepted) =
                    tokio::join!(TcpStream::connect(address), listener.accept());
                let mut client = client.map_err(|_| "queued control connect failed")?;
                let (stream, _) = accepted.map_err(|_| "queued control accept failed")?;
                let ledger = Ledger::new();
                let lease = ledger.accepted(0)?;
                let stage = match case {
                    1 | 8 => Stage::Auth,
                    2 => Stage::Connect,
                    _ => Stage::Raw,
                };
                let credential = if case == 2 {
                    Credential::Account
                } else {
                    Credential::Global
                };
                let phases = [Phase::Greeting, Phase::Auth, Phase::Connect, Phase::Http];
                let count = match stage {
                    Stage::Auth => 2,
                    Stage::Connect => 3,
                    Stage::Raw => 4,
                };
                for phase in &phases[..count] {
                    lease.apply(Event::Progress(*phase))?;
                }
                lease.apply(Event::Critical(stage, credential))?;
                lease.apply(Event::Delivered)?;
                let session = Session {
                    id: 0,
                    lease,
                    stream,
                    credential,
                    stage,
                };
                let owner = if case == 2 {
                    Owner::Alternate {
                        reserve: 9,
                        construction: 0,
                        entry: 11,
                        slot: 2,
                        pid: std::process::id(),
                    }
                } else {
                    Owner::Global {
                        pid: std::process::id(),
                    }
                };
                let context = ExpectedOwner { credential, owner };
                let mut expected = [Some(context), None];
                match case {
                    3 => {
                        expected[0] = Some(ExpectedOwner {
                            credential: Credential::Account,
                            owner,
                        })
                    }
                    4 => {
                        expected[0] = Some(ExpectedOwner {
                            credential,
                            owner: Owner::Global { pid: 0 },
                        })
                    }
                    5 => expected[1] = Some(context),
                    6 => {
                        expected[1] = Some(ExpectedOwner {
                            credential: Credential::Account,
                            owner,
                        })
                    }
                    9 => consume(&session)?,
                    _ => {}
                }
                let rejection = match case {
                    7 => Some(Stage::Auth),
                    _ if stage != Stage::Raw => Some(stage),
                    _ => None,
                };
                let operation_deadline = if case == 10 { Instant::now() } else { deadline };
                let driver = async {
                    if stage != Stage::Raw {
                        let reply: &[u8] = match stage {
                            Stage::Auth => &[1, 1],
                            Stage::Connect => &[5, 2, 0, 1, 0, 0, 0, 0, 0, 0],
                            Stage::Raw => return Err("queued control stage invalid"),
                        };
                        let mut actual = [0; 10];
                        client
                            .read_exact(&mut actual[..reply.len()])
                            .await
                            .map_err(|_| "queued control reply read failed")?;
                        if &actual[..reply.len()] != reply {
                            return Err("queued control reply mismatch");
                        }
                        if case == 8 {
                            client
                                .write_all(&[0x7e])
                                .await
                                .map_err(|_| "queued control suffix write failed")?;
                        }
                        client
                            .shutdown()
                            .await
                            .map_err(|_| "queued control shutdown failed")?;
                    }
                    Ok::<_, &'static str>(client)
                };
                let (result, client) = tokio::join!(
                    reconcile_one(session, expected, rejection, operation_deadline),
                    driver,
                );
                drop(client?);
                let expected_result = match case {
                    0..=2 => Ok(()),
                    3 | 6 => Err("queued session crossed owner"),
                    4 => Err("queued session owner unmapped"),
                    5 => Err("queued session owner ambiguous"),
                    7 => Err("queued session stage mismatch"),
                    8 => Err("queued rejected session continued"),
                    9 => Err("session event invalid"),
                    10 => Err("queued session deadline"),
                    _ => return Err("queued control case invalid"),
                };
                if result != expected_result {
                    return Err("queued control result mismatch");
                }
                let observed = ledger.inspect(0)?;
                if !observed.released
                    || !observed.delivered
                    || observed.critical != Some((stage, credential))
                {
                    return Err("queued control lifecycle missing");
                }
                if ledger.finish().is_ok() != (case <= 2) {
                    return Err("queued control reconciliation mismatch");
                }
                Ok(())
            })
            .await
            .map_err(|_| "queued control deadline")??;
        }
        Ok(())
    }

    /// cancel-safe: NO — cancellation closes the owned synthetic client.
    async fn greeting(address: SocketAddr) -> Result<TcpStream> {
        let mut stream = TcpStream::connect(address)
            .await
            .map_err(|_| "actor client connect failed")?;
        stream
            .write_all(&[5, 1, 2])
            .await
            .map_err(|_| "actor greeting write failed")?;
        let mut reply = [0; 2];
        stream
            .read_exact(&mut reply)
            .await
            .map_err(|_| "actor greeting reply failed")?;
        if reply != [5, 2] {
            return Err("actor greeting reply mismatch");
        }
        Ok(stream)
    }

    /// cancel-safe: NO — cancellation makes the synthetic authentication exchange terminal.
    async fn authenticate(stream: &mut TcpStream) -> Result<()> {
        stream
            .write_all(b"\x01\x05alice\x06secret")
            .await
            .map_err(|_| "actor authentication write failed")
    }

    fn observation(
        ledger: &Ledger,
        phase: Phase,
        critical: Option<(Stage, Credential)>,
        delivered: bool,
        released: bool,
        terminal: Option<End>,
    ) -> Result<()> {
        let observed = ledger.inspect(0)?;
        if observed.phase != phase
            || observed.critical != critical
            || observed.delivered != delivered
            || observed.consumed
            || observed.released != released
            || observed.terminal != terminal
        {
            return Err("actor lifecycle observation mismatch");
        }
        Ok(())
    }

    /// Synthetic loopback traffic and receipts are not stock-child or live-owner evidence.
    /// cancel-safe: NO — each timeout owns both actor and driver futures; no task is detached.
    pub(crate) async fn run_controls() -> Result<()> {
        for case in 0..4 {
            let deadline = Instant::now() + Duration::from_secs(3);
            timeout_at(deadline, async {
                let listener = TcpListener::bind("127.0.0.1:0")
                    .await
                    .map_err(|_| "actor listener bind failed")?;
                let address = listener.local_addr().map_err(|_| "actor address failed")?;
                let ledger = Ledger::new();
                let (stop, stopped) = watch::channel(());
                let (sender, mut receiver) = mpsc::channel(8);
                let options = RecorderOptions {
                    same_address: false,
                    domain: false,
                    rejection: Some(Stage::Auth),
                };
                if case == 3 {
                    receiver.close();
                }
                let actor = record(
                    listener,
                    stopped,
                    address,
                    deadline,
                    sender,
                    options,
                    ledger.clone(),
                );
                if case == 2 {
                    let mut actor = Box::pin(actor);
                    let driver = greeting(address);
                    let client = tokio::select! {
                        result = &mut actor => {
                            return match result {
                                Ok(()) => Err("actor ended before cancellation control"),
                                Err(_) => Err("actor failed before cancellation control"),
                            };
                        }
                        result = driver => result?,
                    };
                    observation(&ledger, Phase::Greeting, None, false, false, None)?;
                    drop(actor);
                    observation(&ledger, Phase::Greeting, None, false, true, None)?;
                    drop(client);
                    if ledger.finish().is_ok() {
                        return Err("unexpected actor cancellation was accepted");
                    }
                    return Ok(());
                }
                let driver = async {
                    let mut client = greeting(address).await?;
                    observation(&ledger, Phase::Greeting, None, false, false, None)?;
                    if case == 0 {
                        stop.send(()).map_err(|_| "actor stop delivery failed")?;
                        return Ok(client);
                    }
                    authenticate(&mut client).await?;
                    if case == 3 {
                        let mut byte = [0; 1];
                        if client
                            .read(&mut byte)
                            .await
                            .map_err(|_| "actor loss closure failed")?
                            != 0
                        {
                            return Err("actor loss left unexpected bytes");
                        }
                        return Ok(client);
                    }
                    let session = receiver.recv().await.ok_or("actor session missing")?;
                    if session.id != 0
                        || session.stage != Stage::Auth
                        || session.credential != Credential::Global
                    {
                        return Err("actor completed session mismatch");
                    }
                    observation(
                        &ledger,
                        Phase::Auth,
                        Some((Stage::Auth, Credential::Global)),
                        true,
                        false,
                        None,
                    )?;
                    let receipt = Receipt {
                        session: session.id,
                        stage: Stage::Auth,
                        credential: Credential::Global,
                        owner: Owner::Global { pid: 123 },
                    };
                    session.lease.apply(Event::Consumed)?;
                    session.lease.apply(Event::Bind(receipt))?;
                    session.lease.apply(Event::Correlated(receipt))?;
                    session.lease.apply(Event::Terminal(End::Rejected))?;
                    drop(session);
                    stop.send(()).map_err(|_| "actor stop delivery failed")?;
                    Ok::<_, &'static str>(client)
                };
                let (actor_result, driver_result) = tokio::join!(actor, driver);
                let client = driver_result?;
                if case == 3 {
                    if actor_result != Err("recorder observation lost") {
                        return Err("actor loss result mismatch");
                    }
                    observation(
                        &ledger,
                        Phase::Auth,
                        Some((Stage::Auth, Credential::Global)),
                        true,
                        true,
                        None,
                    )?;
                    if ledger.finish().is_ok() {
                        return Err("actor lost delivery was accepted");
                    }
                } else {
                    actor_result?;
                    if case == 0 {
                        observation(
                            &ledger,
                            Phase::Greeting,
                            None,
                            false,
                            true,
                            Some(End::PartialShutdown),
                        )?;
                    }
                    ledger.finish()?;
                }
                drop(client);
                Ok(())
            })
            .await
            .map_err(|_| "actor control deadline")??;
        }
        Ok(())
    }
}
