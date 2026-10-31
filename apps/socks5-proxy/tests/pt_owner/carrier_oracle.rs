use super::child_processes::scan_child_pids;
use super::pt_contract::{socks_auth, socks_connect, tcp_source_owned_by};
use crate::server::owners::{test_selection_probe, SelectionEvent};
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
    Reserved(SocketAddr, Option<usize>, bool),
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
pub(crate) fn reserved(identity: Option<usize>, ok: bool) {
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
            .try_send(Event::Reserved(peer, identity, ok))
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
                if let Event::Reserved(actual, entry, ok) =
                    self.events.recv().await.ok_or("нет reserve")?
                {
                    if actual == peer {
                        if !ok || entry != Some(identity) {
                            return Err("повторный reserve вернул другую запись или ошибку");
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
        let _serial = crate::server::owners::TEST_LIFECYCLE.lock().await;
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
