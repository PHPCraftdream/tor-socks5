use super::carrier_oracle::Oracle;
use super::child_processes::wt_recorder::{
    consume, correlate, dispose, reconcile_queue, record, ExpectedOwner,
};
use super::child_processes::{scan_child_pids, verify_children_gone, KnownChildren};
use super::http_peer;
use super::pt_contract::{drain_trap_backlog, socks_auth, socks_connect, tcp_source_owned_by};
use super::scenario_resources::session_ledger::{
    Credential, End, Event, Lease, Ledger, Owner, Phase, Receipt, Stage,
};
use arti_wrapper::Settings;
use futures::FutureExt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::{timeout_at, Duration, Instant};

type Result<T> = std::result::Result<T, &'static str>;
const TARGET: &str = "/owner-contract?phase=106";
const PASSWORD: &str = "secret";
const DOMAIN: &str = "owner-contract.invalid";

#[derive(Clone, Copy)]
pub(super) struct RecorderOptions {
    pub(super) same_address: bool,
    pub(super) domain: bool,
    pub(super) rejection: Option<Stage>,
}

/// The consumer must report consumption, truthful live correlation and terminal ownership.
pub(super) struct Session {
    pub(super) id: usize,
    pub(super) lease: Lease,
    pub(super) stream: TcpStream,
    pub(super) credential: Credential,
    pub(super) stage: Stage,
}

fn session_owned(session: &Session, credential: Credential, pid: u32) -> bool {
    session.credential == credential && tcp_source_owned_by(&session.stream, pid).is_ok()
}

fn session_matches(session: &Session, stage: Stage, credential: Credential) -> bool {
    session.stage == stage && session.credential == credential
}

struct Setup {
    config: PathBuf,
    application: SocketAddr,
    proxy: TcpListener,
    direct: TcpListener,
    destination: SocketAddr,
}

/// cancel-safe: NO — cancellation drops all locally owned setup listeners.
async fn setup(root: &Path, domain: bool) -> Result<Setup> {
    let proxy = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|_| "proxy bind failed")?;
    let pre = proxy
        .local_addr()
        .map_err(|_| "proxy address unavailable")?;
    let direct = TcpListener::bind("127.0.0.77:0")
        .await
        .map_err(|_| "trap bind failed")?;
    let destination = direct
        .local_addr()
        .map_err(|_| "trap address unavailable")?;
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|_| "application bind failed")?;
    let application = listener
        .local_addr()
        .map_err(|_| "application address unavailable")?;
    drop(listener);
    let config = root.join("global.ktav");
    let mut cfg = crate::config::Config {
        listen: vec![application.to_string()],
        pre_socks5: Some(proxy_config::EndpointOverride::Endpoint(
            format!("{pre}|alice:{PASSWORD}")
                .parse()
                .map_err(|_| "fixture pre endpoint invalid")?,
        )),
        ..Default::default()
    };
    cfg.log.ansi = true;
    cfg.bridges.use_seeds = false;
    cfg.bridges.auto_fetch = false;
    let url = if domain {
        format!("http://{DOMAIN}:{}{TARGET}", destination.port())
    } else {
        format!("http://{destination}{TARGET}")
    };
    cfg.bridges.lines = vec![format!(
        "webtunnel {destination} ABCDEF0123456789ABCDEF0123456789ABCDEF01 url={url}"
    )];
    let text = ktav::to_string(&cfg).map_err(|_| "fixture config serialization failed")?;
    std::fs::write(&config, text).map_err(|_| "fixture config write failed")?;
    cfg.write_bridges(&config)
        .map_err(|_| "fixture bridges write failed")?;
    let loaded = crate::config::Config::load_with_override(Some(&config))
        .map_err(|_| "fixture config reload failed")?
        .into_config();
    if loaded.listen != cfg.listen
        || loaded.pre_socks5 != cfg.pre_socks5
        || loaded.bridges.lines != cfg.bridges.lines
        || loaded.bridges.use_seeds
        || loaded.bridges.auto_fetch
    {
        return Err("persisted global WebTunnel configuration mismatch");
    }
    let users = auth::UsersConfig {
        users: vec![auth::User {
            name: "global".into(),
            hash: auth::compute_hash("pw").map_err(|_| "fixture password hash failed")?,
            is_enabled: true,
            allowed_onion: false,
            allowed_clients: None,
            pre_socks5: None,
            post_socks5: None,
        }],
    };
    users
        .save(&auth::UsersConfig::resolve_path(Some(&config)))
        .map_err(|_| "fixture users write failed")?;
    Ok(Setup {
        config,
        application,
        proxy,
        direct,
        destination,
    })
}

/// cancel-safe: NO — the owned socket is terminal on any partial SOCKS exchange.
pub(super) async fn carrier(
    mut stream: TcpStream,
    destination: SocketAddr,
    deadline: Instant,
    options: RecorderOptions,
    lease: &Lease,
) -> Result<(TcpStream, Credential, Stage)> {
    let RecorderOptions {
        same_address,
        domain,
        rejection,
    } = options;
    let mut header = [0; 2];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|_| "proxy greeting failed")?;
    if header[0] != 5 {
        return Err("proxy greeting version mismatch");
    }
    let mut methods = vec![0; usize::from(header[1])];
    stream
        .read_exact(&mut methods)
        .await
        .map_err(|_| "proxy methods failed")?;
    if !methods.contains(&2) {
        return Err("proxy authentication method missing");
    }
    lease.apply(Event::Progress(Phase::Greeting))?;
    stream
        .write_all(&[5, 2])
        .await
        .map_err(|_| "proxy method reply failed")?;
    stream
        .read_exact(&mut header)
        .await
        .map_err(|_| "proxy auth header failed")?;
    if header[0] != 1 {
        return Err("proxy authentication version mismatch");
    }
    let mut user = vec![0; usize::from(header[1])];
    stream
        .read_exact(&mut user)
        .await
        .map_err(|_| "proxy username read failed")?;
    let length = stream
        .read_u8()
        .await
        .map_err(|_| "proxy password length failed")?;
    let mut password = vec![0; usize::from(length)];
    stream
        .read_exact(&mut password)
        .await
        .map_err(|_| "proxy password read failed")?;
    if user != b"alice" {
        return Err("proxy credentials mismatch");
    }
    let credential = if password == PASSWORD.as_bytes() {
        Credential::Global
    } else if same_address && password == b"secret2" {
        Credential::Account
    } else {
        return Err("proxy credentials mismatch");
    };
    lease.apply(Event::Progress(Phase::Auth))?;
    if rejection == Some(Stage::Auth) {
        lease.apply(Event::Critical(Stage::Auth, credential))?;
        return Ok((stream, credential, Stage::Auth));
    }
    stream
        .write_all(&[1, 0])
        .await
        .map_err(|_| "proxy authentication reply failed")?;
    if domain {
        let mut header = [0; 5];
        stream
            .read_exact(&mut header)
            .await
            .map_err(|_| "proxy CONNECT domain header read failed")?;
        let length = u8::try_from(DOMAIN.len()).map_err(|_| "fixture domain length invalid")?;
        if header != [5, 1, 0, 3, length] {
            return Err("proxy CONNECT domain header mismatch");
        }
        let mut address = [0; DOMAIN.len() + 2];
        stream
            .read_exact(&mut address)
            .await
            .map_err(|_| "proxy CONNECT domain read failed")?;
        if &address[..DOMAIN.len()] != DOMAIN.as_bytes()
            || address[DOMAIN.len()..] != destination.port().to_be_bytes()
        {
            return Err("proxy CONNECT domain destination mismatch");
        }
    } else {
        let mut connect = [0; 10];
        stream
            .read_exact(&mut connect)
            .await
            .map_err(|_| "proxy CONNECT read failed")?;
        let expected_ip = match destination.ip() {
            std::net::IpAddr::V4(ip) => ip.octets(),
            std::net::IpAddr::V6(_) => return Err("fixture destination is not IPv4"),
        };
        if connect[..4] != [5, 1, 0, 1]
            || connect[4..8] != expected_ip
            || connect[8..] != destination.port().to_be_bytes()
        {
            return Err("proxy CONNECT destination mismatch");
        }
    }
    lease.apply(Event::Progress(Phase::Connect))?;
    if rejection == Some(Stage::Connect) {
        lease.apply(Event::Critical(Stage::Connect, credential))?;
        return Ok((stream, credential, Stage::Connect));
    }
    stream
        .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .map_err(|_| "proxy CONNECT reply failed")?;
    lease.apply(Event::Progress(Phase::Http))?;
    let host = if domain {
        format!("{DOMAIN}:{}", destination.port())
    } else {
        destination.to_string()
    };
    let observed = http_peer::observe(stream, TARGET, &host, deadline)
        .await
        .map_err(|_| "WebTunnel HTTP exchange failed")?;
    if observed.raw.is_none() {
        return Err("WebTunnel closed without raw activity");
    }
    lease.apply(Event::Critical(Stage::Raw, credential))?;
    Ok((observed.stream, credential, Stage::Raw))
}

/// cancel-safe: NO — abort drops the accepted socket; the listener remains retained by the caller.
async fn trap(listener: Arc<TcpListener>, accepts: Arc<AtomicUsize>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                accepts.fetch_add(1, Ordering::Relaxed);
                drop(stream);
            }
            Err(_) => {
                accepts.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
    }
}

fn global_pid(root: &Path, config: &Path) -> Result<u32> {
    let global = crate::tor_setup::arti_base_dir(Some(config)).join("state/pt_state");
    let snapshot = scan_child_pids(root).map_err(|_| "global PID scan failed")?;
    if snapshot.len() != 1 || !snapshot[0].0.starts_with(global) {
        return Err("global child PID is ambiguous");
    }
    Ok(snapshot[0].1)
}

/// cancel-safe: NO — callers retain the handle until this function reports its terminal outcome.
async fn finish<T>(
    handle: &mut tokio::task::JoinHandle<T>,
    graceful: Instant,
    terminal: Instant,
) -> Option<T> {
    match timeout_at(graceful, &mut *handle).await {
        Ok(Ok(value)) => Some(value),
        Ok(Err(_)) => None,
        Err(_) => {
            handle.abort();
            if timeout_at(terminal, &mut *handle).await.is_err() {
                let _ = (&mut *handle).await;
            }
            None
        }
    }
}

/// Source contract only: global admission and a stock-child carrier, not completed Tor CONNECT.
/// cancel-safe: NO — the harness must retain this scenario through terminal cleanup.
pub(crate) async fn run_global() {
    run_case(false, false, false, None).await;
}

/// One supplied alternate owner and a repeat reserve using its retained carrier.
/// cancel-safe: NO — the harness must retain this scenario through terminal cleanup.
pub(crate) async fn run_alternate() {
    run_case(true, false, false, None).await;
}

/// Same SOCKS address, distinct credentials, two retained stock-child carriers.
/// cancel-safe: NO — the harness retains the case through terminal cleanup.
pub(crate) async fn run_same_address() {
    run_case(false, true, false, None).await;
}

/// cancel-safe: NO — the harness retains the domain case through terminal cleanup.
pub(crate) async fn run_domain() {
    run_case(true, false, true, None).await;
}

/// cancel-safe: NO — the harness retains the rejection case through terminal cleanup.
pub(crate) async fn run_auth_rejection() {
    run_case(true, false, false, Some(Stage::Auth)).await;
}

/// cancel-safe: NO — the harness retains the rejection case through terminal cleanup.
pub(crate) async fn run_connect_rejection() {
    run_case(true, false, false, Some(Stage::Connect)).await;
}

/// Parameters select internal fixture cases, not application configuration modes.
/// cancel-safe: NO — cancellation before terminal cleanup is not supported by the harness.
async fn run_case(alternate: bool, same_address: bool, domain: bool, rejection: Option<Stage>) {
    let _serial = crate::server::owners::TEST_LIFECYCLE.lock().await;
    let total = Instant::now() + Duration::from_secs(55);
    let body_deadline = total - Duration::from_secs(18);
    let graceful = total - Duration::from_secs(7);
    let terminal = total - Duration::from_secs(5);
    let _ = rustls::crypto::ring::default_provider().install_default();
    let directory = tempfile::tempdir().expect("global fixture directory failed");
    let setup = setup(directory.path(), domain)
        .await
        .expect("global fixture setup failed");
    let global_pre = setup
        .proxy
        .local_addr()
        .expect("global fixture proxy address failed");
    let alternate_proxy = if alternate {
        Some(
            TcpListener::bind("127.0.0.1:0")
                .await
                .expect("alternate fixture proxy bind failed"),
        )
    } else {
        None
    };
    let pre = alternate_proxy
        .as_ref()
        .map(|listener| {
            listener
                .local_addr()
                .expect("alternate proxy address unavailable")
        })
        .unwrap_or(global_pre);
    let account_password = if same_address { "secret2" } else { PASSWORD };
    let effective_pre = proxy_config::EndpointOverride::Endpoint(
        format!("{pre}|alice:{account_password}")
            .parse()
            .expect("fixture effective endpoint invalid"),
    );
    if alternate || same_address {
        if alternate {
            assert_ne!(
                pre, global_pre,
                "alternate address must replace the global address"
            );
        } else {
            assert_eq!(pre, global_pre, "same-address fixture address changed");
            let global_endpoint = proxy_config::EndpointOverride::Endpoint(
                format!("{global_pre}|alice:{PASSWORD}")
                    .parse()
                    .expect("fixture global endpoint invalid"),
            );
            assert!(
                effective_pre != global_endpoint,
                "credential routes collapsed"
            );
        }
        let account = if same_address {
            "sameaddr"
        } else {
            "alternate"
        };
        let users = auth::UsersConfig {
            users: vec![auth::User {
                name: account.into(),
                hash: auth::compute_hash("pw").expect("alternate fixture password hash failed"),
                is_enabled: true,
                allowed_onion: false,
                allowed_clients: None,
                pre_socks5: Some(effective_pre.clone()),
                post_socks5: None,
            }],
        };
        let mut users = users;
        if same_address {
            users.users.push(auth::User {
                name: "global".into(),
                hash: auth::compute_hash("pw").expect("global fixture password hash failed"),
                is_enabled: true,
                allowed_onion: false,
                allowed_clients: None,
                pre_socks5: None,
                post_socks5: None,
            });
        }
        users
            .save(&auth::UsersConfig::resolve_path(Some(&setup.config)))
            .expect("credential isolation users write failed");
    }
    let account = if same_address {
        "sameaddr"
    } else if alternate {
        "alternate"
    } else {
        "global"
    };
    let selected_owner = alternate || same_address;
    let expected_credential = if same_address {
        Credential::Account
    } else {
        Credential::Global
    };
    let recorder_listener = match alternate_proxy {
        Some(listener) => {
            drop(setup.proxy);
            listener
        }
        None => setup.proxy,
    };
    let mut known = KnownChildren::default();
    known
        .refresh(directory.path())
        .expect("initial PID scan failed");
    assert!(
        scan_child_pids(directory.path())
            .expect("initial PID snapshot failed")
            .is_empty(),
        "unexpected initial child"
    );
    http_peer::trap_control(&setup.direct, setup.destination, body_deadline)
        .await
        .expect("trap control failed");
    assert!(
        Instant::now() < body_deadline,
        "global fixture setup exceeded deadline"
    );
    let mut oracle = Oracle::arm(global_pre, pre, setup.application);
    let ledger = Ledger::new();
    let (events, mut sessions) = mpsc::channel(8);
    let (stop, stopped) = watch::channel(());
    let (ready, readiness) = oneshot::channel();
    let (shutdown, shutdown_requested) = oneshot::channel();
    let accepts = Arc::new(AtomicUsize::new(0));
    let trap_listener = Arc::new(setup.direct);
    let writer = crate::bridge_store_writer::StoreWriter::spawn(
        bridge_store::BridgeStore::resolve_path(Some(&setup.config)),
        Arc::new(|_| Ok(())),
        Duration::from_secs(3600),
    );
    let hook = Arc::new(super::super::super::global_init::ShutdownHook {
        settings: Settings::default(),
        writer,
        ready: std::sync::Mutex::new(Some(ready)),
    });
    let args = super::super::super::ServerArgs {
        config_override: Some(setup.config.clone()),
        upstream_addr: None,
        upstream_user: None,
        upstream_pass: None,
        no_upstream: false,
    };
    let mut recorder = tokio::spawn(record(
        recorder_listener,
        stopped,
        setup.destination,
        body_deadline,
        events,
        RecorderOptions {
            same_address,
            domain,
            rejection,
        },
        ledger.clone(),
    ));
    let mut direct = tokio::spawn(trap(trap_listener.clone(), accepts.clone()));
    let mut server = tokio::spawn(async move {
        super::super::super::global_init::RUN_SERVER_CONFIG
            .scope((), async {
                super::super::super::global_init::RUN_SERVER_SHUTDOWN
                    .scope(hook, async {
                        super::super::super::run_server(args, async {
                            let _ = shutdown_requested.await;
                        })
                        .await
                    })
                    .await
            })
            .await
    });
    let mut expected = [None, None];
    let mut retained = Vec::new();
    let mut applications = Vec::new();
    let body = async {
        readiness
            .await
            .map_err(|_| "global server readiness lost")?;
        known
            .refresh(directory.path())
            .map_err(|_| "pre-request PID scan failed")?;
        if !scan_child_pids(directory.path())
            .map_err(|_| "pre-request PID snapshot failed")?
            .is_empty()
        {
            return Err("global child existed before the admitted request");
        }
        let mut application = socks_auth(account, "pw", setup.application).await;
        let peer = application
            .local_addr()
            .map_err(|_| "application peer unavailable")?;
        let mut global_application = None;
        let mut global_session = None;
        let mut global_child = None;
        let mut additional_global = Vec::new();
        if same_address {
            let mut client = socks_auth("global", "pw", setup.application).await;
            let peer = client
                .local_addr()
                .map_err(|_| "global isolation peer unavailable")?;
            socks_connect(&mut client).await;
            oracle
                .global_request(peer, global_pre, PASSWORD)
                .await
                .map_err(|_| "global isolation request mismatch")?;
            let session = sessions
                .recv()
                .await
                .ok_or("global isolation carrier missing")?;
            consume(&session)?;
            known
                .refresh(directory.path())
                .map_err(|_| "global isolation PID scan failed")?;
            let pid = global_pid(directory.path(), &setup.config)?;
            if !session_owned(&session, Credential::Global, pid)
                || session_owned(&session, Credential::Account, pid)
                || session_owned(&session, Credential::Global, 0)
            {
                return Err("global isolation session calibration failed");
            }
            let (journal, dropped) = crate::server::owners::test_selection_probe().snapshot();
            if dropped != 0 || !journal.is_empty() {
                return Err("global isolation request acquired an alternate Entry");
            }
            correlate(
                &session,
                Receipt {
                    session: session.id,
                    stage: Stage::Raw,
                    credential: Credential::Global,
                    owner: Owner::Global { pid },
                },
            )?;
            expected[0] = Some(ExpectedOwner {
                credential: Credential::Global,
                owner: Owner::Global { pid },
            });
            global_application = Some(client);
            global_session = Some(session);
            global_child = Some(pid);
        }

        socks_connect(&mut application).await;
        if !selected_owner {
            oracle
                .global_request(peer, pre, PASSWORD)
                .await
                .map_err(|_| "actual global request mismatch")?;
        }
        let mut session = loop {
            let session = sessions
                .recv()
                .await
                .ok_or("recorder closed without a carrier")?;
            consume(&session)?;
            if session.credential == expected_credential {
                break session;
            }
            if same_address
                && global_child.is_some_and(|pid| session_owned(&session, Credential::Global, pid))
            {
                if additional_global.len() >= 8 {
                    return Err("additional global session limit exceeded");
                }
                let pid = global_child.ok_or("additional global owner identity missing")?;
                correlate(
                    &session,
                    Receipt {
                        session: session.id,
                        stage: Stage::Raw,
                        credential: Credential::Global,
                        owner: Owner::Global { pid },
                    },
                )?;
                additional_global.push(session);
            } else {
                return Err("recorded session credentials do not match the account");
            }
        };
        let expected_stage = rejection.unwrap_or(Stage::Raw);
        let wrong_stage = if expected_stage == Stage::Auth {
            Stage::Connect
        } else {
            Stage::Auth
        };
        let wrong_credential = if expected_credential == Credential::Global {
            Credential::Account
        } else {
            Credential::Global
        };
        if !session_matches(&session, expected_stage, expected_credential)
            || session_matches(&session, wrong_stage, expected_credential)
            || session_matches(&session, expected_stage, wrong_credential)
        {
            return Err("recorded protocol stage or credential calibration failed");
        }
        known
            .refresh(directory.path())
            .map_err(|_| "carrier PID scan failed")?;
        let owner = if selected_owner {
            Some(
                oracle
                    .owner_witness(
                        peer,
                        account,
                        &effective_pre,
                        None,
                        &setup.config,
                        body_deadline,
                    )
                    .await
                    .map_err(|_| "initial alternate owner correlation failed")?,
            )
        } else {
            None
        };
        let pid = match owner {
            Some(witness) => witness.pid,
            None => global_pid(directory.path(), &setup.config)?,
        };
        let expected_owner = match owner {
            Some(witness) => Owner::Alternate {
                reserve: witness.reserve_request_id,
                construction: witness.construction_request_id,
                entry: witness.entry,
                slot: witness.slot,
                pid: witness.pid,
            },
            None => Owner::Global { pid },
        };
        correlate(
            &session,
            Receipt {
                session: session.id,
                stage: expected_stage,
                credential: expected_credential,
                owner: expected_owner,
            },
        )?;
        expected[usize::from(same_address)] = Some(ExpectedOwner {
            credential: expected_credential,
            owner: expected_owner,
        });
        let stream = &mut session.stream;
        tcp_source_owned_by(stream, pid)
            .map_err(|_| "carrier is not owned by the selected child")?;
        if session.credential != expected_credential {
            return Err("selected session credential mismatch");
        }
        if let (Some(global), Some(global_pid)) = (global_session.as_ref(), global_child) {
            if global_pid == pid
                || !session_owned(global, Credential::Global, global_pid)
                || session_owned(global, Credential::Account, global_pid)
                || session_owned(global, Credential::Global, pid)
                || tcp_source_owned_by(stream, global_pid).is_ok()
            {
                return Err("same-address child or session isolation failed");
            }
            let base = crate::tor_setup::arti_base_dir(Some(&setup.config));
            let account_root = base.join("owners-v1");
            let snapshot =
                scan_child_pids(directory.path()).map_err(|_| "isolation marker scan failed")?;
            if snapshot
                .iter()
                .filter(|(path, _)| path.starts_with(&account_root))
                .count()
                != 1
            {
                return Err("same-address alternate storage isolation failed");
            }
        }
        if let Some(stage) = rejection {
            let first = owner.ok_or("rejection owner witness missing")?;
            if tcp_source_owned_by(stream, 0).is_ok() {
                return Err("rejection wrong-PID control accepted");
            }
            let (journal, dropped) = crate::server::owners::test_selection_probe().snapshot();
            if dropped != 0 || journal.len() != 2 {
                return Err("rejection selection journal mismatch");
            }
            let snapshot =
                scan_child_pids(directory.path()).map_err(|_| "rejection child snapshot failed")?;
            if snapshot.len() != 1 || snapshot[0].1 != first.pid {
                return Err("rejection child identity mismatch");
            }
            let reply: &[u8] = match stage {
                Stage::Auth => &[1, 1],
                Stage::Connect => &[5, 2, 0, 1, 0, 0, 0, 0, 0, 0],
                Stage::Raw => return Err("raw activity is not a rejection stage"),
            };
            stream
                .write_all(reply)
                .await
                .map_err(|_| "rejection reply write failed")?;
            stream
                .flush()
                .await
                .map_err(|_| "rejection reply flush failed")?;
            let mut byte = [0; 1];
            if stream
                .read(&mut byte)
                .await
                .map_err(|_| "rejected child closure read failed")?
                != 0
            {
                return Err("child continued after configured pre-proxy rejection");
            }
            let (terminal, lost) = crate::server::owners::test_selection_probe().snapshot();
            if lost != 0 || terminal != journal {
                return Err("rejection selection observations changed or were lost");
            }
            oracle
                .healthy()
                .map_err(|_| "rejection observations lost")?;
            if accepts.load(Ordering::Relaxed) != 0 {
                return Err("direct fallback after pre-proxy rejection");
            }
            dispose(session, End::Rejected)?;
            applications.push(application);
            return Ok::<(), &'static str>(());
        }
        let mut repeated_application = None;
        if let Some(first) = owner {
            let mut repeated = socks_auth(account, "pw", setup.application).await;
            let repeated_peer = repeated
                .local_addr()
                .map_err(|_| "repeat application peer unavailable")?;
            socks_connect(&mut repeated).await;
            let current = oracle
                .owner_witness(
                    repeated_peer,
                    account,
                    &effective_pre,
                    Some(first.entry),
                    &setup.config,
                    body_deadline,
                )
                .await
                .map_err(|_| "repeat alternate owner correlation failed")?;
            if current.reserve_request_id == first.reserve_request_id
                || current.entry != first.entry
                || current.construction_request_id != first.construction_request_id
                || current.slot != first.slot
                || current.pid != first.pid
            {
                return Err("repeat did not retain the original owner construction");
            }
            repeated_application = Some(repeated);
        }
        if tcp_source_owned_by(stream, 0).is_ok() {
            return Err("wrong-PID ownership control accepted");
        }
        let mut discard = [0; 1024];
        match stream.try_read(&mut discard) {
            Ok(0) => return Err("observed carrier is already closed"),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => return Err("carrier liveness check failed"),
        }
        tcp_source_owned_by(stream, pid).map_err(|_| "current carrier ownership lost")?;
        if let (Some(global), Some(global_pid)) = (global_session.as_mut(), global_child) {
            let mut byte = [0; 1];
            match global.stream.try_read(&mut byte) {
                Ok(0) => return Err("retained global isolation carrier closed"),
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => return Err("retained global isolation carrier read failed"),
            }
            if !session_owned(global, Credential::Global, global_pid)
                || tcp_source_owned_by(stream, global_pid).is_ok()
                || tcp_source_owned_by(&global.stream, pid).is_ok()
            {
                return Err("retained isolation session ownership changed");
            }
        }
        let (journal, dropped) = crate::server::owners::test_selection_probe().snapshot();
        if dropped != 0 {
            return Err("selection journal lost observations");
        }
        if !selected_owner && !journal.is_empty() {
            return Err("global request unexpectedly selected an alternate owner");
        }
        if let Some(first) = owner {
            let snapshot = scan_child_pids(directory.path())
                .map_err(|_| "alternate isolation PID snapshot failed")?;
            let expected_children = if same_address { 2 } else { 1 };
            if snapshot.len() != expected_children
                || snapshot.iter().filter(|(_, pid)| *pid == first.pid).count() != 1
                || global_child.is_some_and(|pid| {
                    snapshot.iter().filter(|(_, child)| *child == pid).count() != 1
                })
            {
                return Err("alternate request created an unexpected child");
            }
            let assignments = journal
                .iter()
                .filter(|observation| {
                    observation.event == crate::server::owners::SelectionEvent::StorageAssigned
                })
                .count();
            if assignments != 1 {
                return Err("repeat created an additional storage assignment");
            }
        }
        oracle
            .healthy()
            .map_err(|_| "global request observations lost")?;
        if accepts.load(Ordering::Relaxed) != 0 {
            return Err("direct fallback detected");
        }
        retained.push(session);
        if let Some(global) = global_session {
            retained.push(global);
        }
        retained.extend(additional_global);
        applications.push(application);
        applications.extend(repeated_application);
        applications.extend(global_application);
        Ok::<(), &'static str>(())
    };
    let outcome = timeout_at(
        body_deadline,
        std::panic::AssertUnwindSafe(body).catch_unwind(),
    )
    .await;
    let _ = known.refresh(directory.path());
    let stop_ok = stop.send(()).is_ok();
    let recorder_result = finish(&mut recorder, graceful, terminal).await;
    let recorder_ok = matches!(recorder_result, Some(Ok(())));
    let queue_result = reconcile_queue(
        &mut sessions,
        &mut retained,
        expected,
        rejection,
        graceful,
        &ledger,
    )
    .await;
    drop(applications);
    let _ = shutdown.send(());
    let server_result = finish(&mut server, graceful, terminal).await;
    let server_ok = matches!(server_result, Some(Ok(())));
    let recovery_ok = if server_ok {
        true
    } else {
        let early = super::super::super::global_init::recover_contract_all().await;
        let late = super::super::super::global_init::recover_contract_terminal().await;
        early.is_empty() && late.is_empty()
    };
    direct.abort();
    let trap_joined = matches!((&mut direct).await, Err(error) if error.is_cancelled());
    let backlog_overrun = AtomicUsize::new(0);
    let backlog_ok = drain_trap_backlog(&trap_listener, &accepts, &backlog_overrun)
        .await
        .is_ok();
    drop(trap_listener);
    let _ = known.refresh(directory.path());
    let children_gone = verify_children_gone(&mut known, directory.path(), total)
        .await
        .is_ok();
    let drained = sessions.is_closed() && sessions.is_empty();
    let (_, journal_dropped) = crate::server::owners::test_selection_probe().snapshot();
    let healthy = oracle.healthy().is_ok() && journal_dropped == 0;
    assert!(
        server_ok && recorder_ok && stop_ok && recovery_ok,
        "global fixture terminal task failure"
    );
    assert!(
        trap_joined && backlog_ok,
        "global fixture trap cleanup failed"
    );
    assert!(children_gone, "global fixture child cleanup failed");
    assert!(
        drained && healthy && queue_result.is_ok(),
        "global fixture observation cleanup failed: {queue_result:?}"
    );
    assert_eq!(
        accepts.load(Ordering::Relaxed),
        0,
        "direct fallback detected"
    );
    assert_eq!(
        backlog_overrun.load(Ordering::Relaxed),
        0,
        "direct backlog detected"
    );
    assert!(
        matches!(outcome, Ok(Ok(Ok(())))),
        "global WebTunnel body failed"
    );
}
