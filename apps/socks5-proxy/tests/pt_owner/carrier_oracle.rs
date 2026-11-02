use super::child_processes::{owner_pid, scan_child_pids};
use super::pt_contract::{socks_auth, socks_connect, tcp_source_owned_by};
use crate::server::owners::{
    test_selection_probe, SelectionEvent, SelectionObservation, SelectionOutcome,
};
use proxy_config::EndpointOverride;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{timeout, Duration};

type Result<T> = std::result::Result<T, &'static str>;
pub(crate) type Ping = oneshot::Sender<()>;
static ACTIVE: Mutex<Option<Arc<State>>> = Mutex::new(None);

enum Event {
    Request(SocketAddr, String, Option<EndpointOverride>, bool),
    Reserved(SocketAddr, usize, Option<usize>, bool),
}
struct State {
    listener: SocketAddr,
    events: mpsc::Sender<Event>,
    callers: Mutex<HashMap<tokio::task::Id, SocketAddr>>,
    recorders: Mutex<HashMap<SocketAddr, mpsc::Sender<Ping>>>,
    sessions: Mutex<Vec<Session>>,
    failed: AtomicBool,
    next: AtomicUsize,
}
struct Session {
    id: usize,
    endpoint: SocketAddr,
    password: Vec<u8>,
    sender: mpsc::Sender<Check>,
}
pub(crate) struct Check {
    pid: u32,
    reply: oneshot::Sender<bool>,
}
pub(crate) struct Registration<T> {
    state: Arc<State>,
    endpoint: SocketAddr,
    id: Option<usize>,
    receiver: mpsc::Receiver<T>,
}
impl<T> Drop for Registration<T> {
    fn drop(&mut self) {
        if let Some(id) = self.id {
            self.state.sessions.lock().unwrap().retain(|s| s.id != id);
        } else {
            self.state.recorders.lock().unwrap().remove(&self.endpoint);
        }
    }
}
pub(crate) struct Oracle {
    state: Arc<State>,
    events: mpsc::Receiver<Event>,
    global: SocketAddr,
    alternate: SocketAddr,
}
impl Drop for Oracle {
    fn drop(&mut self) {
        *ACTIVE.lock().unwrap() = None;
    }
}
fn active() -> Option<Arc<State>> {
    ACTIVE.lock().unwrap().clone()
}

pub(crate) fn request(
    client: &TcpStream,
    lease: &Option<auth::AdmissionLease>,
    route: &crate::startup::AdmittedRoute,
    alternate: bool,
) {
    let Some(state) = active() else {
        return;
    };
    if client.local_addr().ok() != Some(state.listener) {
        return;
    }
    let (Ok(peer), Some(lease), Some(task)) =
        (client.peer_addr(), lease.as_ref(), tokio::task::try_id())
    else {
        state.failed.store(true, Ordering::Relaxed);
        return;
    };
    let mut callers = state.callers.lock().unwrap();
    if callers.len() >= 16 {
        state.failed.store(true, Ordering::Relaxed);
        return;
    }
    callers.insert(task, peer);
    let event = Event::Request(
        peer,
        lease.username().to_owned(),
        route.pre.clone(),
        alternate,
    );
    if state.events.try_send(event).is_err() {
        state.failed.store(true, Ordering::Relaxed);
    }
}
pub(crate) fn reserved(request_id: usize, identity: Option<usize>, ok: bool) {
    let Some(state) = active() else {
        return;
    };
    let Some(task) = tokio::task::try_id() else {
        return;
    };
    let peer = state.callers.lock().unwrap().remove(&task);
    if let Some(peer) = peer {
        if state
            .events
            .try_send(Event::Reserved(peer, request_id, identity, ok))
            .is_err()
        {
            state.failed.store(true, Ordering::Relaxed);
        }
    }
}

pub(crate) fn recorder(listener: &TcpListener) -> Option<Registration<Ping>> {
    let state = active()?;
    let endpoint = listener.local_addr().ok()?;
    let (sender, receiver) = mpsc::channel(1);
    state.recorders.lock().unwrap().insert(endpoint, sender);
    Some(Registration {
        state,
        endpoint,
        id: None,
        receiver,
    })
}
/// cancel-safe: да — recv не потребляет ping при отмене; после получения нет await.
pub(crate) async fn poll_recorder(registration: &mut Option<Registration<Ping>>) {
    if let Some(registration) = registration {
        if let Some(reply) = registration.receiver.recv().await {
            let _ = reply.send(());
            return;
        }
    }
    std::future::pending::<()>().await;
}
pub(crate) fn session(stream: &TcpStream, password: &[u8]) -> Option<Registration<Check>> {
    let state = active()?;
    let endpoint = stream.local_addr().ok()?;
    let id = state.next.fetch_add(1, Ordering::Relaxed);
    let (sender, receiver) = mpsc::channel(1);
    let mut sessions = state.sessions.lock().unwrap();
    if sessions.len() >= 16 {
        state.failed.store(true, Ordering::Relaxed);
        return None;
    }
    sessions.push(Session {
        id,
        endpoint,
        password: password.to_vec(),
        sender,
    });
    drop(sessions);
    Some(Registration {
        state,
        endpoint,
        id: Some(id),
        receiver,
    })
}
/// cancel-safe: нет — отмена завершает owned worker; прочитанные байты уже дренированы.
pub(crate) async fn drain(stream: &mut TcpStream, mut registration: Option<Registration<Check>>) {
    let mut discard = [0; 1024];
    loop {
        if let Some(registration) = registration.as_mut() {
            tokio::select! {
                result = stream.read(&mut discard) => {
                    if result.unwrap_or(0) == 0 {
                        return;
                    }
                }
                Some(check) = registration.receiver.recv() => {
                    let open = match stream.try_read(&mut discard) {
                        Ok(0) => false,
                        Ok(_) => true,
                        Err(error) => error.kind() == std::io::ErrorKind::WouldBlock,
                    };
                    let owned = tcp_source_owned_by(stream, check.pid).is_ok();
                    let _ = check.reply.send(open && owned);
                }
            }
        } else if stream.read(&mut discard).await.unwrap_or(0) == 0 {
            return;
        }
    }
}

#[derive(Clone, Copy)]
struct Expected {
    user: &'static str,
    endpoint: SocketAddr,
    password: &'static str,
    entry: Option<usize>,
    pid: u32,
}
fn route(endpoint: SocketAddr, password: &str) -> EndpointOverride {
    EndpointOverride::Endpoint(
        format!("{endpoint}|alice:{password}")
            .parse()
            .expect("фиксированный endpoint"),
    )
}
fn matches_request(event: &Event, peer: SocketAddr, expected: &Expected) -> bool {
    let pre = route(expected.endpoint, expected.password);
    matches!(event, Event::Request(actual, user, route, alternate)
        if *actual == peer && user == expected.user && route.as_ref() == Some(&pre)
        && *alternate == expected.entry.is_some())
}
fn matches_reserve(observation: &SelectionObservation, request_id: usize, identity: usize) -> bool {
    observation.request_id == request_id
        && observation.identity == Some(identity)
        && observation.event == SelectionEvent::Reserved
        && observation.outcome == SelectionOutcome::Reserved
}

/// Journal/PID correlation only; this does not establish socket ownership or bootstrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OwnerWitness {
    pub(crate) reserve_request_id: usize,
    pub(crate) construction_request_id: usize,
    pub(crate) entry: usize,
    pub(crate) slot: usize,
    pub(crate) pid: u32,
}

fn owner_route(event: &Event, peer: SocketAddr, user: &str, pre: &EndpointOverride) -> bool {
    matches!(event, Event::Request(actual, account, route, true)
        if *actual == peer && account == user && route.as_ref() == Some(pre))
}

fn owner_reserve(
    event: &Event,
    peer: SocketAddr,
    expected: Option<usize>,
) -> Result<(usize, usize)> {
    match event {
        Event::Reserved(actual, request_id, Some(entry), true)
            if *actual == peer && expected.is_none_or(|value| value == *entry) =>
        {
            Ok((*request_id, *entry))
        }
        _ => Err("owner reserve peer, outcome, or Entry mismatch"),
    }
}

fn owner_assignment(
    journal: &[SelectionObservation],
    dropped: usize,
    request_id: usize,
    entry: usize,
    route_label: &str,
) -> Result<Option<(usize, usize)>> {
    if dropped != 0 {
        return Err("owner journal lost observations");
    }
    let reserves: Vec<_> = journal
        .iter()
        .filter(|o| o.request_id == request_id && o.event != SelectionEvent::StorageAssigned)
        .collect();
    if reserves.len() != 1
        || !matches_reserve(reserves[0], request_id, entry)
        || reserves[0].route != route_label
        || reserves[0].storage_slot.is_some()
    {
        return Err("actual owner reserve journal mismatch");
    }
    let assigned: Vec<_> = journal
        .iter()
        .filter(|o| o.identity == Some(entry) && o.event == SelectionEvent::StorageAssigned)
        .collect();
    if assigned.is_empty() {
        return Ok(None);
    }
    if assigned.len() != 1 {
        return Err("ambiguous owner storage assignment");
    }
    let assigned = assigned[0];
    let slot = assigned.storage_slot.ok_or("owner storage slot missing")?;
    if !(1..=15).contains(&slot)
        || assigned.route != route_label
        || assigned.outcome != SelectionOutcome::Reserved
    {
        return Err("owner storage assignment mismatch");
    }
    let construction: Vec<_> = journal
        .iter()
        .filter(|o| {
            o.request_id == assigned.request_id && o.event != SelectionEvent::StorageAssigned
        })
        .collect();
    if construction.len() != 1
        || !matches_reserve(construction[0], assigned.request_id, entry)
        || construction[0].route != route_label
        || construction[0].storage_slot.is_some()
    {
        return Err("owner construction reserve mismatch");
    }
    if journal.iter().any(|o| {
        o.event == SelectionEvent::StorageAssigned
            && o.storage_slot == Some(slot)
            && o.identity != Some(entry)
    }) {
        return Err("owner storage slot belongs to another Entry");
    }
    Ok(Some((assigned.request_id, slot)))
}

fn owner_pre(endpoint: SocketAddr, username: &str, password: &str) -> Result<EndpointOverride> {
    let endpoint = format!("{endpoint}|{username}:{password}")
        .parse()
        .map_err(|_| "owner expected endpoint invalid")?;
    Ok(EndpointOverride::Endpoint(endpoint))
}

impl Oracle {
    pub(crate) fn arm(global: SocketAddr, alternate: SocketAddr, listener: SocketAddr) -> Self {
        let (sender, events) = mpsc::channel(32);
        let state = Arc::new(State {
            listener,
            events: sender,
            callers: Mutex::new(HashMap::new()),
            recorders: Mutex::new(HashMap::new()),
            sessions: Mutex::new(Vec::new()),
            failed: AtomicBool::new(false),
            next: AtomicUsize::new(0),
        });
        let mut slot = ACTIVE.lock().unwrap();
        assert!(slot.is_none(), "наблюдатель уже установлен");
        *slot = Some(Arc::clone(&state));
        Self {
            state,
            events,
            global,
            alternate,
        }
    }

    /// cancel-safe: NO — consumed observations are not replayed after cancellation.
    pub(crate) async fn global_request(
        &mut self,
        peer: SocketAddr,
        endpoint: SocketAddr,
        password: &'static str,
    ) -> Result<()> {
        let expected = Expected {
            user: "global",
            endpoint,
            password,
            entry: None,
            pid: 0,
        };
        loop {
            let event = self
                .events
                .recv()
                .await
                .ok_or("global request observer closed")?;
            if let Event::Request(actual, ..) = &event {
                if *actual == peer {
                    if !matches_request(&event, peer, &expected) {
                        return Err("global admitted route mismatch");
                    }
                    return self.healthy();
                }
            }
        }
    }

    /// Requires serialized requests and PID-marker readiness; missing markers fail closed.
    /// cancel-safe: NO — consumed events are not replayed; cancellation is terminal for this call.
    pub(crate) async fn owner_witness(
        &mut self,
        peer: SocketAddr,
        account: &str,
        pre: &EndpointOverride,
        expected_entry: Option<usize>,
        config: &Path,
        deadline: tokio::time::Instant,
    ) -> Result<OwnerWitness> {
        if tokio::time::Instant::now() >= deadline {
            return Err("owner witness deadline elapsed");
        }
        if !matches!(pre, EndpointOverride::Endpoint(_)) {
            return Err("alternate owner requires an endpoint");
        }
        tokio::time::timeout_at(deadline, async {
            self.healthy()?;
            let request = self
                .events
                .recv()
                .await
                .ok_or("owner request observer closed")?;
            if !owner_route(&request, peer, account, pre) {
                return Err("actual owner account or effective route mismatch");
            }
            let reserved = self
                .events
                .recv()
                .await
                .ok_or("owner reserve observer closed")?;
            let (request_id, entry) = owner_reserve(&reserved, peer, expected_entry)?;
            let probe = test_selection_probe();
            let mut changed = probe.subscribe();
            let route_label = match pre {
                EndpointOverride::Endpoint(endpoint) => endpoint.address().to_string(),
                EndpointOverride::Disabled => return Err("alternate endpoint unavailable"),
            };
            let (construction_request_id, slot) = loop {
                self.healthy()?;
                let (journal, dropped) = probe.snapshot();
                match owner_assignment(&journal, dropped, request_id, entry, &route_label)? {
                    Some(assignment) => break assignment,
                    None => {
                        changed
                            .changed()
                            .await
                            .map_err(|_| "owner journal readiness closed")?;
                    }
                }
            };
            let base = crate::tor_setup::arti_base_dir(Some(config));
            let root = base.parent().ok_or("owner PID scan root unavailable")?;
            let snapshot = scan_child_pids(root).map_err(|_| "owner PID readiness scan failed")?;
            let pid = owner_pid(&snapshot, &base, slot)?;
            self.healthy()?;
            let (journal, dropped) = probe.snapshot();
            if owner_assignment(&journal, dropped, request_id, entry, &route_label)?
                != Some((construction_request_id, slot))
            {
                return Err("owner assignment changed during PID resolution");
            }
            Ok(OwnerWitness {
                reserve_request_id: request_id,
                construction_request_id,
                entry,
                slot,
                pid,
            })
        })
        .await
        .map_err(|_| "owner witness deadline elapsed")?
    }

    pub(crate) fn healthy(&self) -> Result<()> {
        if self.state.failed.load(Ordering::Relaxed) {
            return Err("carrier oracle lost an observation");
        }
        Ok(())
    }

    /// cancel-safe: нет — отправленный одноразовый запрос не повторяется после отмены.
    async fn ping(&self, endpoint: SocketAddr) -> Result<()> {
        let sender = self
            .state
            .recorders
            .lock()
            .unwrap()
            .get(&endpoint)
            .cloned()
            .ok_or("рекордер остановлен")?;
        let (reply, receiver) = oneshot::channel();
        sender.try_send(reply).map_err(|_| "рекордер недоступен")?;
        receiver
            .await
            .map_err(|_| "рекордер не подтвердил проверку")
    }
    /// cancel-safe: нет — после отмены результат challenge не используется и не повторяется.
    async fn transport(&self, expected: &Expected) -> Result<()> {
        self.ping(expected.endpoint).await?;
        let senders = self
            .state
            .sessions
            .lock()
            .unwrap()
            .iter()
            .filter(|s| {
                s.endpoint == expected.endpoint && s.password == expected.password.as_bytes()
            })
            .map(|s| s.sender.clone())
            .collect::<Vec<_>>();
        let mut live = false;
        for sender in senders {
            let (reply, receiver) = oneshot::channel();
            if sender
                .try_send(Check {
                    pid: expected.pid,
                    reply,
                })
                .is_ok()
                && receiver.await.unwrap_or(false)
            {
                live = true;
                break;
            }
        }
        if !live {
            return Err("нет живой сессии с сокетом указанного PT");
        }
        self.ping(expected.endpoint).await
    }
    /// cancel-safe: нет — отмена закрывает клиентский сокет; CONNECT не повторяется.
    async fn repeat(&mut self, expected: &Expected, address: SocketAddr) -> Result<TcpStream> {
        let mut client = socks_auth(expected.user, "pw", address).await;
        let peer = client.local_addr().map_err(|_| "нет адреса клиента")?;
        socks_connect(&mut client).await;
        loop {
            let event = self.events.recv().await.ok_or("наблюдатель закрыт")?;
            if let Event::Request(actual, ..) = &event {
                if *actual == peer {
                    if !matches_request(&event, peer, expected) {
                        return Err("неверный фактический маршрут повторного запроса");
                    }
                    break;
                }
            }
        }
        if let Some(identity) = expected.entry {
            loop {
                if let Event::Reserved(actual, request_id, entry, ok) =
                    self.events.recv().await.ok_or("нет reserve")?
                {
                    if actual == peer {
                        if !ok || entry != Some(identity) {
                            return Err("повторный reserve вернул другую запись или ошибку");
                        }
                        let (observations, dropped) = test_selection_probe().snapshot();
                        if dropped != 0 {
                            return Err("reserve observation journal overflow");
                        }
                        if !observations
                            .iter()
                            .any(|o| matches_reserve(o, request_id, identity))
                        {
                            return Err("peer is not linked to the actual request_id and Entry");
                        }
                        break;
                    }
                }
            }
        }
        self.transport(expected).await?;
        if self.state.failed.load(Ordering::Relaxed) {
            return Err("потеря наблюдений");
        }
        Ok(client)
    }
    /// cancel-safe: нет — вложенные CONNECT/challenge терминальны; cleanup остаётся у caller.
    pub(crate) async fn verify(&mut self, address: SocketAddr, config: &Path) -> Result<()> {
        let base = crate::tor_setup::arti_base_dir(Some(config));
        let pids = scan_child_pids(base.parent().ok_or("нет корня")?)?;
        let (events, dropped) = test_selection_probe().snapshot();
        if dropped != 0 {
            return Err("переполнен журнал резервов");
        }
        let storage = events
            .iter()
            .find(|e| {
                e.event == SelectionEvent::StorageAssigned && e.route == self.alternate.to_string()
            })
            .ok_or("нет связи alt со slot")?;
        let entry = storage.identity.ok_or("нет alt Entry")?;
        let slot = storage.storage_slot.ok_or("нет alt slot")?;
        let global_root = base.join("state/pt_state");
        let alt_root = base
            .join("owners-v1")
            .join(slot.to_string())
            .join("state/pt_state");
        let pid = |root: &Path| -> Result<u32> {
            let found = pids
                .iter()
                .filter(|(path, _)| path.starts_with(root))
                .collect::<Vec<_>>();
            if found.len() != 1 {
                return Err("PID сессии неоднозначен");
            }
            Ok(found[0].1)
        };
        let global = Expected {
            user: "global",
            endpoint: self.global,
            password: "secret",
            entry: None,
            pid: pid(&global_root)?,
        };
        let alt = Expected {
            user: "alt",
            endpoint: self.alternate,
            password: "second",
            entry: Some(entry),
            pid: pid(&alt_root)?,
        };
        let _global = timeout(Duration::from_secs(8), self.repeat(&global, address))
            .await
            .map_err(|_| "повторный global не подтверждён")??;
        let _alt = timeout(Duration::from_secs(8), self.repeat(&alt, address))
            .await
            .map_err(|_| "повторный alt не подтверждён")??;
        Ok(())
    }
}

pub(crate) async fn run_reuse_and_rejection_controls() {
    tests::run_controls().await;
    eprintln!("PT reuse/rejection controls: PASS");
}

#[cfg(test)]
mod tests {
    use super::super::pt_contract::spawn_supplied_recorder;
    use super::super::scenario_resources::RecorderCounters;
    use super::*;
    use futures::FutureExt;
    use tokio::io::AsyncWriteExt;

    /// cancel-safe: нет — частичное рукопожатие терминально, сокет закрывается при отмене.
    async fn connect_session(endpoint: SocketAddr) -> TcpStream {
        let mut client = socks_auth("alice", "secret", endpoint).await;
        client
            .write_all(&[5, 1, 0, 1, 127, 0, 0, 77, 1, 187])
            .await
            .unwrap();
        let mut reply = [0; 10];
        client.read_exact(&mut reply).await.unwrap();
        client.write_all(&[0]).await.unwrap();
        client
    }

    #[tokio::test]
    async fn reuse_and_rejection_controls() {
        run_controls().await;
    }

    fn owner_witness_controls() {
        let peer: SocketAddr = "127.0.0.1:41001".parse().unwrap();
        let endpoint: SocketAddr = "127.0.0.1:41002".parse().unwrap();
        let pre = owner_pre(endpoint, "alice", "first").unwrap();
        let other = owner_pre(endpoint, "alice", "second").unwrap();
        let request = Event::Request(peer, "sameaddr".into(), Some(pre.clone()), true);
        assert!(owner_route(&request, peer, "sameaddr", &pre));
        assert!(!owner_route(&request, peer, "sameaddr", &other));
        assert!(!owner_route(&request, endpoint, "sameaddr", &pre));
        assert!(!owner_route(&request, peer, "other-account", &pre));
        let global = Event::Request(peer, "sameaddr".into(), Some(pre.clone()), false);
        assert!(!owner_route(&global, peer, "sameaddr", &pre));
        assert_eq!(
            owner_reserve(&Event::Reserved(peer, 9, Some(11), true), peer, Some(11)),
            Ok((9, 11))
        );
        assert!(owner_reserve(&Event::Reserved(peer, 9, Some(12), true), peer, Some(11)).is_err());
        assert!(owner_reserve(&Event::Reserved(peer, 9, Some(11), false), peer, Some(11)).is_err());
        assert!(owner_reserve(&Event::Reserved(endpoint, 9, Some(11), true), peer, None).is_err());
        assert!(owner_reserve(&Event::Reserved(peer, 9, None, true), peer, None).is_err());
        let original = SelectionObservation {
            request_id: 7,
            route: endpoint.to_string(),
            identity: Some(11),
            storage_slot: None,
            outcome: SelectionOutcome::Reserved,
            event: SelectionEvent::Reserved,
        };
        let repeat = SelectionObservation {
            request_id: 9,
            ..original.clone()
        };
        let assigned = SelectionObservation {
            storage_slot: Some(2),
            event: SelectionEvent::StorageAssigned,
            ..original.clone()
        };
        let journal = vec![original.clone(), repeat.clone(), assigned.clone()];
        let label = endpoint.to_string();
        assert_eq!(
            owner_assignment(&journal, 0, 9, 11, &label),
            Ok(Some((7, 2)))
        );
        assert_eq!(owner_assignment(&journal[..2], 0, 9, 11, &label), Ok(None));
        assert!(owner_assignment(&journal, 1, 9, 11, &label).is_err());
        assert!(owner_assignment(&journal, 0, 8, 11, &label).is_err());
        assert!(owner_assignment(&journal, 0, 9, 12, &label).is_err());
        assert!(owner_assignment(&journal, 0, 9, 11, "wrong-route").is_err());
        let mut wrong = journal.clone();
        wrong[2].storage_slot = None;
        assert!(owner_assignment(&wrong, 0, 9, 11, &label).is_err());
        wrong[2].storage_slot = Some(0);
        assert!(owner_assignment(&wrong, 0, 9, 11, &label).is_err());
        wrong[2].storage_slot = Some(16);
        assert!(owner_assignment(&wrong, 0, 9, 11, &label).is_err());
        wrong = journal.clone();
        wrong[2].request_id = 8;
        assert!(owner_assignment(&wrong, 0, 9, 11, &label).is_err());
        wrong = journal.clone();
        wrong[2].outcome = SelectionOutcome::ReserveFailed;
        assert!(owner_assignment(&wrong, 0, 9, 11, &label).is_err());
        wrong = journal.clone();
        wrong.push(assigned.clone());
        assert!(owner_assignment(&wrong, 0, 9, 11, &label).is_err());
        wrong = journal.clone();
        wrong.push(SelectionObservation {
            identity: Some(12),
            ..assigned.clone()
        });
        assert!(owner_assignment(&wrong, 0, 9, 11, &label).is_err());
        wrong = journal.clone();
        wrong.push(repeat);
        assert!(owner_assignment(&wrong, 0, 9, 11, &label).is_err());
        let base = Path::new("synthetic-owner-root");
        let marker = base.join("owners-v1/2/state/pt_state/transport/owner-contract-pid");
        let snapshot = vec![(marker.clone(), 123)];
        assert_eq!(owner_pid(&snapshot, base, 2), Ok(123));
        assert!(owner_pid(&snapshot, base, 3).is_err());
        assert!(owner_pid(&[], base, 2).is_err());
        assert!(owner_pid(&[(marker.clone(), 0)], base, 2).is_err());
        let duplicate = vec![(marker.clone(), 123), (marker.clone(), 124)];
        assert!(owner_pid(&duplicate, base, 2).is_err());
        let shared = vec![
            (marker, 123),
            (
                base.join("owners-v1/3/state/pt_state/owner-contract-pid"),
                123,
            ),
        ];
        assert!(owner_pid(&shared, base, 2).is_err());
    }

    /// Synthetic observations only; these controls do not establish a live owner.
    /// cancel-safe: NO — cancellation drops the pinned witness, probe guard and temporary tree.
    async fn async_owner_witness_controls() {
        use crate::server::owners::{scoped_selection_probe, SelectionProbe};
        use tokio::time::{timeout_at, Instant};

        for case in 0..6 {
            let guard_deadline = Instant::now() + Duration::from_secs(3);
            timeout_at(guard_deadline, async {
                let directory = tempfile::tempdir().expect("synthetic owner directory failed");
                let config = directory.path().join("synthetic.ktav");
                let base = crate::tor_setup::arti_base_dir(Some(&config));
                let marker_root = base.join("owners-v1/2/state/pt_state/transport");
                std::fs::create_dir_all(&marker_root).expect("synthetic PID directory failed");
                std::fs::write(marker_root.join("owner-contract-pid"), "123")
                    .expect("synthetic PID marker failed");
                let probe = Arc::new(SelectionProbe::new());
                let _restore = scoped_selection_probe(Arc::clone(&probe));
                let peer: SocketAddr = "127.0.0.1:41001".parse().unwrap();
                let endpoint: SocketAddr = "127.0.0.1:41002".parse().unwrap();
                let pre = owner_pre(endpoint, "alice", "first").unwrap();
                let original = SelectionObservation {
                    request_id: 7,
                    route: endpoint.to_string(),
                    identity: Some(11),
                    storage_slot: None,
                    outcome: SelectionOutcome::Reserved,
                    event: SelectionEvent::Reserved,
                };
                probe.publish(original.clone());
                probe.publish(SelectionObservation {
                    request_id: 9,
                    ..original.clone()
                });
                let assignment = SelectionObservation {
                    storage_slot: Some(2),
                    event: SelectionEvent::StorageAssigned,
                    ..original.clone()
                };
                let mut oracle = Oracle::arm(endpoint, endpoint, endpoint);
                let state = Arc::clone(&oracle.state);
                let deadline = Instant::now() + Duration::from_secs(1);
                let witness =
                    oracle.owner_witness(peer, "sameaddr", &pre, Some(11), &config, deadline);
                tokio::pin!(witness);
                assert!(
                    futures::poll!(witness.as_mut()).is_pending(),
                    "witness completed before receiving ordered events"
                );
                if case == 1 {
                    assert!(
                        state
                            .events
                            .try_send(Event::Reserved(peer, 9, Some(11), true))
                            .is_ok(),
                        "synthetic event queue full"
                    );
                } else {
                    assert!(
                        state
                            .events
                            .try_send(Event::Request(
                                peer,
                                "sameaddr".into(),
                                Some(pre.clone()),
                                true,
                            ))
                            .is_ok(),
                        "synthetic event queue full"
                    );
                    assert!(
                        state
                            .events
                            .try_send(Event::Reserved(peer, 9, Some(11), true))
                            .is_ok(),
                        "synthetic event queue full"
                    );
                }
                if case == 1 {
                    assert_eq!(
                        witness.as_mut().await,
                        Err("actual owner account or effective route mismatch")
                    );
                    return;
                }
                assert!(
                    futures::poll!(witness.as_mut()).is_pending(),
                    "witness did not wait for the missing construction assignment"
                );
                match case {
                    0 => {
                        probe.publish(assignment);
                        assert_eq!(
                            witness.as_mut().await,
                            Ok(OwnerWitness {
                                reserve_request_id: 9,
                                construction_request_id: 7,
                                entry: 11,
                                slot: 2,
                                pid: 123,
                            })
                        );
                    }
                    2 => {
                        assert!(
                            Instant::now() < deadline,
                            "pending control reached an already expired deadline"
                        );
                        assert_eq!(
                            witness.as_mut().await,
                            Err("owner witness deadline elapsed")
                        );
                    }
                    3 => {
                        state.failed.store(true, Ordering::Relaxed);
                        probe.publish(assignment);
                        assert_eq!(
                            witness.as_mut().await,
                            Err("carrier oracle lost an observation")
                        );
                    }
                    4 => {
                        for _ in 0..65 {
                            probe.publish(original.clone());
                        }
                        assert_eq!(
                            witness.as_mut().await,
                            Err("owner journal lost observations")
                        );
                    }
                    5 => {
                        probe.publish(SelectionObservation {
                            request_id: 8,
                            ..assignment
                        });
                        assert_eq!(
                            witness.as_mut().await,
                            Err("owner construction reserve mismatch")
                        );
                    }
                    _ => unreachable!("invalid synthetic control case"),
                }
            })
            .await
            .expect("async owner witness control guard elapsed");
        }
    }

    pub(super) async fn run_controls() {
        owner_witness_controls();
        let _serial = crate::server::owners::TEST_LIFECYCLE.lock().await;
        async_owner_witness_controls().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let oracle = Oracle::arm(endpoint, endpoint, endpoint);
        let (stop, stopped) = tokio::sync::watch::channel(());
        let (events, mut carriers) = mpsc::channel(4);
        let mut recorder = spawn_supplied_recorder(
            listener,
            stopped,
            &[b"secret"],
            "control",
            events,
            RecorderCounters::default(),
            None,
        );
        let body = async {
            let client = connect_session(endpoint).await;
            assert_eq!(carriers.recv().await.unwrap().len(), 6);
            let expected = Expected {
                user: "global",
                endpoint,
                password: "secret",
                entry: None,
                pid: std::process::id(),
            };
            oracle.transport(&expected).await.unwrap();
            oracle.transport(&expected).await.unwrap();
            assert!(carriers.try_recv().is_err());
            let peer = client.local_addr().unwrap();
            let event = Event::Request(
                peer,
                "global".into(),
                Some(route(endpoint, "secret")),
                false,
            );
            assert!(matches_request(&event, peer, &expected));
            let wrong =
                Event::Request(peer, "global".into(), Some(route(endpoint, "wrong")), false);
            assert!(!matches_request(&wrong, peer, &expected));
            assert!(!matches_request(&event, endpoint, &expected));
            let wrong_branch =
                Event::Request(peer, "global".into(), Some(route(endpoint, "secret")), true);
            assert!(!matches_request(&wrong_branch, peer, &expected));
            let reserve = SelectionObservation {
                request_id: 7,
                route: endpoint.to_string(),
                identity: Some(11),
                storage_slot: None,
                outcome: SelectionOutcome::Reserved,
                event: SelectionEvent::Reserved,
            };
            assert!(matches_reserve(&reserve, 7, 11));
            assert!(!matches_reserve(&reserve, 8, 11));
            assert!(!matches_reserve(&reserve, 7, 12));
            let storage = SelectionObservation {
                event: SelectionEvent::StorageAssigned,
                ..reserve.clone()
            };
            assert!(!matches_reserve(&storage, 7, 11));
            let failed = SelectionObservation {
                outcome: SelectionOutcome::ReserveFailed,
                ..reserve
            };
            assert!(!matches_reserve(&failed, 7, 11));
            let wrong_pid = Expected { pid: 0, ..expected };
            assert!(oracle.transport(&wrong_pid).await.is_err());
            let session = oracle.state.sessions.lock().unwrap()[0].sender.clone();
            drop(client);
            session.closed().await;
            assert!(oracle.transport(&expected).await.is_err());
            let live = connect_session(endpoint).await;
            carriers.recv().await.unwrap();
            oracle.transport(&expected).await.unwrap();
            let accept = oracle
                .state
                .recorders
                .lock()
                .unwrap()
                .get(&endpoint)
                .unwrap()
                .clone();
            let session = oracle.state.sessions.lock().unwrap()[0].sender.clone();
            stop.send(()).unwrap();
            accept.closed().await;
            assert!(!session.is_closed());
            assert!(oracle.transport(&expected).await.is_err());
            drop(live);
        };
        let outcome = timeout(
            Duration::from_secs(8),
            std::panic::AssertUnwindSafe(body).catch_unwind(),
        )
        .await;
        let _ = stop.send(());
        let joined = timeout(Duration::from_secs(15), &mut recorder.0).await;
        let joined = match joined {
            Ok(result) => result,
            Err(_) => (&mut recorder.0).await,
        };
        assert!(joined.is_ok());
        outcome.unwrap().unwrap();
    }
}
