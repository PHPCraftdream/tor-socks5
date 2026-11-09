//! Launching pluggable transport binaries and communicating with them.
//!
//! This module contains utilities to launch pluggable transports supporting pt-spec.txt
//! version 1, and communicate with them in order to specify configuration parameters and
//! receive updates as to the current state of the PT.

use crate::PtClientMethod;
use crate::err;
use crate::err::PtError;
use futures::StreamExt;
use futures::channel::mpsc::Receiver;
use itertools::Itertools;
use std::borrow::Cow;
use std::collections::HashMap;
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::sync::Arc;
use std::{io, thread};
use tor_basic_utils::PathExt as _;

use tor_linkspec::PtTransportName;
use tor_rtcompat::{Runtime, SleepProviderExt};
use tor_socksproto::SocksVersion;
use tracing::{debug, error, info, trace, warn};
use web_time_compat::{Duration, Instant, InstantExt};

/// Amount of time we give a pluggable transport child process to exit gracefully.
const GRACEFUL_EXIT_TIME: Duration = Duration::from_secs(5);
/// Default timeout for PT binary startup.
const PT_START_TIMEOUT: Duration = Duration::from_secs(30);
/// Size for the buffer storing pluggable transport stdout lines.
const PT_STDIO_BUFFER: usize = 64;

/// An arbitrary key/value status update from a pluggable transport.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct PtStatus {
    /// Arbitrary key-value data about the state of this transport, from the binary running
    /// said transport.
    // NOTE(eta): This is assumed to not have duplicate keys.
    data: HashMap<String, String>,
}

/// A message sent from a pluggable transport child process.
///
/// For more in-depth information about these messages, consult pt-spec.txt.
#[derive(PartialEq, Eq, Debug, Clone)]
#[non_exhaustive]
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub enum PtMessage {
    /// `VERSION-ERROR`: No compatible pluggable transport specification version was provided.
    VersionError(String),
    /// `VERSION`: Specifies the version the binary is using for the IPC protocol.
    Version(String),
    /// `ENV-ERROR`: Reports an error with the provided environment variables.
    EnvError(String),
    /// `PROXY DONE`: The configured proxy was correctly initialised.
    ProxyDone,
    /// `PROXY-ERROR`: An error was encountered setting up the configured proxy.
    ProxyError(String),
    /// `CMETHOD`: A client transport has been launched.
    ClientTransportLaunched {
        /// The name of the launched transport.
        transport: PtTransportName,
        /// The protocol used ('socks4' or 'socks5').
        protocol: String,
        /// An address to connect via this transport.
        /// (This should be localhost.)
        endpoint: SocketAddr,
    },
    /// `CMETHOD-ERROR`: An error was encountered setting up a client transport.
    ClientTransportFailed {
        /// The name of the transport.
        transport: PtTransportName,
        /// The error message.
        message: String,
    },
    /// `CMETHODS DONE`: All client transports that are supported have been launched.
    ClientTransportsDone,
    /// `SMETHOD`: A server transport has been launched.
    ServerTransportLaunched {
        /// The name of the launched transport.
        transport: PtTransportName,
        /// The endpoint clients should use the reach the transport.
        endpoint: SocketAddr,
        /// Additional per-transport information.
        // NOTE(eta): This assumes it actually is k/v and repeated keys aren't allowed...
        options: HashMap<String, String>,
    },
    /// `SMETHOD-ERROR`: An error was encountered setting up a server transport.
    ServerTransportFailed {
        /// The name of the transport.
        transport: PtTransportName,
        /// The error message.
        message: String,
    },
    /// `SMETHODS DONE`: All server transports that are supported have been launched.
    ServerTransportsDone,
    /// `LOG`: A log message.
    Log {
        /// The severity (one of 'error', 'warning', 'notice', 'info', 'debug').
        severity: String,
        /// The log message.
        message: String,
    },
    /// `STATUS`: Arbitrary key/value status messages.
    Status(PtStatus),
    /// A line containing an unknown command.
    Unknown(String),
}

/// Parse a value (something on the RHS of an =), which could be a CString as defined by
/// control-spec.txt §2. Returns (value, unparsed rest of string).
fn parse_one_value(from: &str) -> Result<(String, &str), &'static str> {
    let first_char = from.chars().next();
    Ok(if first_char.is_none() {
        (String::new(), "")
    } else if let Some('"') = first_char {
        // This is a CString, so we're going to need to parse it char-by-char.
        // FIXME(eta): This currently doesn't parse octal escape codes, even though the spec says
        //             we should. That's finicky, though, and probably not used.
        let mut ret = String::new();
        let mut chars = from.chars();
        assert_eq!(chars.next(), Some('"')); // discard "
        loop {
            let ch = chars.next().ok_or("ran out of input parsing CString")?;
            match ch {
                '\\' => match chars
                    .next()
                    .ok_or("encountered trailing backslash in CString")?
                {
                    'n' => ret.push('\n'),
                    'r' => ret.push('\r'),
                    't' => ret.push('\t'),
                    '0'..='8' => return Err("attempted unsupported octal escape code"),
                    ch2 => ret.push(ch2),
                },
                '"' => break,
                _ => ret.push(ch),
            }
        }
        (ret, chars.as_str())
    } else {
        // Simple: just find the space
        if let Some((start, rest)) = from.split_once(' ') {
            (start.to_string(), rest)
        } else {
            (from.to_string(), "")
        }
    })
}

/// Chomp one key/value pair off a list of smethod args.
/// Returns (k, v, unparsed rest of string).
/// Will also chomp the comma at the end, if there is one.
fn parse_one_smethod_arg(args: &str) -> Result<(String, String, &str), &'static str> {
    // NOTE(eta): Apologies for this looking a bit gnarly. Ideally, this is what you'd use
    //            something like `nom` for, but I didn't want to bring in a dep just for this.

    let mut key = String::new();
    let mut val = String::new();
    // If true, we're reading the value, not the key.
    let mut reading_val = false;
    let mut chars = args.chars();
    while let Some(c) = chars.next() {
        let target = if reading_val { &mut val } else { &mut key };
        match c {
            '\\' => {
                let c = chars
                    .next()
                    .ok_or("smethod arg terminates with backslash")?;
                target.push(c);
            }
            '=' => {
                if reading_val {
                    return Err("encountered = while parsing value");
                }
                reading_val = true;
            }
            ',' => break,
            c => target.push(c),
        }
    }
    if !reading_val {
        return Err("ran out of chars parsing smethod arg");
    }
    Ok((key, val, chars.as_str()))
}

impl FromStr for PtMessage {
    type Err = Cow<'static, str>;

    // NOTE(eta): This, of course, implies that the PT IPC communications are valid UTF-8.
    //            This assumption might turn out to be false.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // TODO(eta): Maybe tolerate additional whitespace (using `split_whitespace`)?.
        //            This requires modified words.join() logic, though.
        let mut words = s.split(' ');
        let first_word = words.next().ok_or_else(|| Cow::from("empty line"))?;
        Ok(match first_word {
            "VERSION-ERROR" => {
                let rest = words.join(" ");
                Self::VersionError(rest)
            }
            "VERSION" => {
                let vers = words.next().ok_or_else(|| Cow::from("no version"))?;
                Self::Version(vers.into())
            }
            "ENV-ERROR" => {
                let rest = words.join(" ");
                Self::EnvError(rest)
            }
            "PROXY" => match words.next() {
                Some("DONE") => Self::ProxyDone,
                _ => Self::Unknown(s.into()),
            },
            "PROXY-ERROR" => {
                let rest = words.join(" ");
                Self::ProxyError(rest)
            }
            "CMETHOD" => {
                let transport = words.next().ok_or_else(|| Cow::from("no transport"))?;
                let protocol = words.next().ok_or_else(|| Cow::from("no protocol"))?;
                let endpoint = words
                    .next()
                    .ok_or_else(|| Cow::from("no endpoint"))?
                    .parse::<SocketAddr>()
                    .map_err(|e| Cow::from(format!("failed to parse endpoint: {}", e)))?;
                if !endpoint.ip().is_loopback() {
                    return Err(Cow::from(format!(
                        "CMETHOD endpoint {endpoint} was not localhost"
                    )));
                }
                Self::ClientTransportLaunched {
                    transport: transport
                        .parse()
                        .map_err(|_| Cow::from("bad transport ID"))?,
                    protocol: protocol.to_string(),
                    endpoint,
                }
            }
            "CMETHOD-ERROR" => {
                let transport = words.next().ok_or_else(|| Cow::from("no transport"))?;
                let rest = words.join(" ");
                Self::ClientTransportFailed {
                    transport: transport
                        .parse()
                        .map_err(|_| Cow::from("bad transport ID"))?,
                    message: rest,
                }
            }
            "CMETHODS" => match words.next() {
                Some("DONE") => Self::ClientTransportsDone,
                _ => Self::Unknown(s.into()),
            },
            "SMETHOD" => {
                let transport = words.next().ok_or_else(|| Cow::from("no transport"))?;
                let endpoint = words
                    .next()
                    .ok_or_else(|| Cow::from("no endpoint"))?
                    .parse::<SocketAddr>()
                    .map_err(|e| Cow::from(format!("failed to parse endpoint: {}", e)))?;
                // The SMETHOD endpoint is the place where _clients_ connect, and it shouldn't be localhost.
                let mut parsed_args = HashMap::new();

                // NOTE(eta): pt-spec.txt seems to imply these options can't contain spaces, so
                //            we work under that assumption.
                //            It also doesn't actually parse them out -- but seeing as the API to
                //            feed these back in will want them as separated k/v pairs, I think
                //            it makes sense to here.
                for option in words {
                    if let Some(mut args) = option.strip_prefix("ARGS:") {
                        while !args.is_empty() {
                            let (k, v, rest) = parse_one_smethod_arg(args).map_err(|e| {
                                Cow::from(format!("failed to parse SMETHOD ARGS: {}", e))
                            })?;
                            if parsed_args.contains_key(&k) {
                                // At least check our assumption that this is actually k/v
                                // and not Vec<(String, String)>.
                                warn!("PT SMETHOD arguments contain repeated key {}!", k);
                            }
                            parsed_args.insert(k, v);
                            args = rest;
                        }
                    }
                }
                Self::ServerTransportLaunched {
                    transport: transport
                        .parse()
                        .map_err(|_| Cow::from("bad transport ID"))?,
                    endpoint,
                    options: parsed_args,
                }
            }
            "SMETHOD-ERROR" => {
                let transport = words.next().ok_or_else(|| Cow::from("no transport"))?;
                let rest = words.join(" ");
                Self::ServerTransportFailed {
                    transport: transport
                        .parse()
                        .map_err(|_| Cow::from("bad transport ID"))?,
                    message: rest,
                }
            }
            "SMETHODS" => match words.next() {
                Some("DONE") => Self::ServerTransportsDone,
                _ => Self::Unknown(s.into()),
            },
            "LOG" => {
                let severity = words
                    .next()
                    .ok_or_else(|| Cow::from("no severity"))?
                    .strip_prefix("SEVERITY=")
                    .ok_or_else(|| Cow::from("badly formatted severity"))?;
                let message = words.join(" ");
                let message = parse_one_value(
                    message
                        .strip_prefix("MESSAGE=")
                        .ok_or_else(|| Cow::from("no or badly formatted message"))?,
                )
                .map_err(Cow::from)?
                .0;
                Self::Log {
                    severity: severity.into(),
                    message,
                }
            }
            "STATUS" => {
                let mut ret = HashMap::new();
                let message = words.join(" ");
                let mut message = &message as &str;
                while !message.is_empty() {
                    let (k, rest) = message
                        .split_once('=')
                        .ok_or_else(|| Cow::from(format!("failed to find = in '{}'", message)))?;
                    if rest.is_empty() {
                        return Err(Cow::from("key with no value"));
                    }
                    let (v, rest) = parse_one_value(rest).map_err(Cow::from)?;
                    if ret.contains_key(k) {
                        // At least check our assumption that this is actually k/v
                        // and not Vec<(String, String)>.
                        warn!("STATUS contains repeated key {}!", k);
                    }
                    ret.insert(k.to_owned(), v);
                    message = rest;
                    if let Some(remainder) = message.strip_prefix(" ") {
                        message = remainder;
                    }
                }
                Self::Status(PtStatus { data: ret })
            }
            _ => Self::Unknown(s.into()),
        })
    }
}

pub use sealed::ShutdownHandle;
use sealed::*;
/// Sealed trait to protect private types and default trait implementations
pub(crate) mod sealed {
    use super::*;

    /// Возможность независимо запросить остановку процесса.
    #[derive(Clone, Debug)]
    pub struct ShutdownHandle {
        /// Канал для запроса завершения с подтверждением.
        sender: std::sync::mpsc::Sender<futures::channel::oneshot::Sender<io::Result<()>>>,
        /// Общий признак, что supervisor завершил ожидание дочернего процесса.
        reaped: Arc<std::sync::atomic::AtomicBool>,
    }

    impl ShutdownHandle {
        /// Отправляет запрос и возвращает подтверждение завершения.
        pub fn request(&self) -> io::Result<futures::channel::oneshot::Receiver<io::Result<()>>> {
            let (tx, rx) = futures::channel::oneshot::channel();
            if self.reaped.load(std::sync::atomic::Ordering::Acquire) {
                let _ = tx.send(Ok(()));
                return Ok(rx);
            }
            if self.sender.send(tx).is_err() {
                if self.reaped.load(std::sync::atomic::Ordering::Acquire) {
                    let (tx, rx) = futures::channel::oneshot::channel();
                    let _ = tx.send(Ok(()));
                    return Ok(rx);
                }
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "PT supervisor stopped",
                ));
            }
            Ok(rx)
        }
    }

    /// Владение процессом и асинхронным каналом его вывода.
    #[derive(Debug)]
    pub struct AsyncPtChild {
        /// Асинхронный поток строк stdout дочернего процесса.
        stdout: Receiver<io::Result<String>>,
        /// Идентификатор процесса для диагностики.
        pub identifier: String,
        /// Канал передачи запросов supervisor-потоку.
        shutdown: std::sync::mpsc::Sender<futures::channel::oneshot::Sender<io::Result<()>>>,
        /// Ожидание подтверждения для уже отправленного запроса остановки.
        pending: Option<futures::channel::oneshot::Receiver<io::Result<()>>>,
        /// Отмечает полученное подтверждение reaping.
        reaped: bool,
        /// Совместный флаг завершения supervisor-потока.
        completion: Arc<std::sync::atomic::AtomicBool>,
        /// Ошибка, полученная при запуске/инициализации процесса.
        startup_error: Option<Arc<io::Error>>,
        /// Требуется ли этому процессу настроенный прокси.
        proxy_sensitive: bool,
        /// Разрешённые методы транспорта для дочернего процесса.
        allowed_methods: Vec<PtTransportName>,
        /// Ошибка, которую нужно однократно внедрить в следующий вызов `shutdown()` в тестах.
        #[cfg(all(test, unix))]
        test_shutdown_error_once: bool,
    }

    /// Поток supervisor'а сохраняет владение процессом до подтверждённого wait.
    fn supervise(
        mut command: Command,
        launch: &std::sync::mpsc::SyncSender<io::Result<std::process::ChildStdout>>,
        requests: &std::sync::mpsc::Receiver<futures::channel::oneshot::Sender<io::Result<()>>>,
        ident: &str,
        completion: &Arc<std::sync::atomic::AtomicBool>,
    ) {
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(e) => {
                let _ = launch.send(Err(e));
                return;
            }
        };
        let mut disconnected = false;
        let mut receipts: Vec<futures::channel::oneshot::Sender<io::Result<()>>> = Vec::new();
        let mut stopping = false;
        let mut deadline = None;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let stdout = child.stdout.take();
            if child.stdin.is_none() {
                let _ = launch.send(Err(io::Error::other("missing stdin pipe")));
                stopping = true;
            } else if let Some(stdout) = stdout {
                if launch.send(Ok(stdout)).is_err() {
                    stopping = true;
                }
            } else {
                let _ = launch.send(Err(io::Error::other("missing stdout pipe")));
                stopping = true;
            }
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => {
                        completion.store(true, std::sync::atomic::Ordering::Release);
                        for tx in receipts.drain(..) {
                            let _ = tx.send(Ok(()));
                        }
                        return;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        warn!("PT {} try_wait failed: {}", ident, e);
                    }
                }
                if stopping && deadline.is_none() {
                    drop(child.stdin.take());
                    deadline = Some(std::time::Instant::now() + GRACEFUL_EXIT_TIME);
                }
                if deadline.is_some_and(|d| std::time::Instant::now() >= d) {
                    let result = child.kill().and_then(|()| child.wait().map(|_| ()));
                    match result {
                        Ok(()) => {
                            completion.store(true, std::sync::atomic::Ordering::Release);
                            for tx in receipts.drain(..) {
                                let _ = tx.send(Ok(()));
                            }
                            return;
                        }
                        Err(e) => {
                            warn!("PT {} cleanup failed; child retained: {}", ident, e);
                            for tx in receipts.drain(..) {
                                let _ = tx.send(Err(io::Error::new(e.kind(), e.to_string())));
                            }
                            stopping = disconnected;
                            deadline = None;
                        }
                    }
                }
                if disconnected {
                    thread::sleep(std::time::Duration::from_millis(100));
                    continue;
                }
                match requests.recv_timeout(std::time::Duration::from_millis(100)) {
                    Ok(tx) => {
                        receipts.push(tx);
                        stopping = true;
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        disconnected = true;
                        stopping = true;
                    }
                }
            }
        }));
        if outcome.is_err() {
            for tx in receipts.drain(..) {
                let _ = tx.send(Err(io::Error::other("PT supervisor panicked")));
            }
            drop(child.stdin.take());
            loop {
                let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    if child.try_wait()?.is_some() {
                        return Ok(());
                    }
                    child.kill()?;
                    child.wait().map(|_| ())
                }));
                if matches!(attempt, Ok(Ok(()))) {
                    completion.store(true, std::sync::atomic::Ordering::Release);
                    while let Ok(tx) = requests.try_recv() {
                        let _ = tx.send(Ok(()));
                    }
                    break;
                }
                while let Ok(tx) = requests.try_recv() {
                    let _ = tx.send(Err(io::Error::other("PT cleanup retry failed")));
                }
                thread::sleep(std::time::Duration::from_secs(1));
            }
        }
    }

    impl Drop for AsyncPtChild {
        fn drop(&mut self) {
            let (tx, _rx) = futures::channel::oneshot::channel();
            let _ = self.shutdown.send(tx);
        }
    }

    impl AsyncPtChild {
        /// Запускает процесс только внутри потока, который отвечает за его завершение.
        pub fn new(
            command: Command,
            path: PathBuf,
            identifier: String,
            proxy_sensitive: bool,
            allowed_methods: Vec<PtTransportName>,
        ) -> Result<Self, PtError> {
            let (launch_tx, launch_rx) = std::sync::mpsc::sync_channel(1);
            let (shutdown, requests) = std::sync::mpsc::channel();
            let ident = identifier.clone();
            let completion = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let worker_completion = completion.clone();
            thread::Builder::new()
                .name("pt-supervisor".into())
                .spawn(move || {
                    supervise(command, &launch_tx, &requests, &ident, &worker_completion);
                })
                .map_err(|e| PtError::ChildSpawnFailed {
                    path: path.clone(),
                    error: Arc::new(e),
                })?;
            let stdout = launch_rx
                .recv()
                .map_err(|_| PtError::ChildGone)?
                .map_err(|e| PtError::ChildSpawnFailed {
                    path,
                    error: Arc::new(e),
                })?;
            let (mut tx, rx) = tor_async_utils::mpsc_channel_no_memquota(PT_STDIO_BUFFER);
            let mut owner = AsyncPtChild {
                stdout: rx,
                identifier: identifier.clone(),
                shutdown,
                pending: None,
                reaped: false,
                completion,
                startup_error: None,
                proxy_sensitive,
                allowed_methods,
                #[cfg(all(test, unix))]
                test_shutdown_error_once: false,
            };
            let reader_result = thread::Builder::new()
                .name("pt-stdout".into())
                .spawn(move || {
                    let mut reader = BufReader::new(stdout);
                    loop {
                        let mut line = Vec::new();
                        let result = (&mut reader).take(65537).read_until(b'\n', &mut line);
                        let result = match result {
                            Ok(0) => break,
                            Ok(_) if line.len() > 65536 => Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "PT line too long",
                            )),
                            Ok(_) => String::from_utf8(line)
                                .map(|s| s.trim_end_matches(&['\r', '\n'][..]).to_owned())
                                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
                            Err(e) => Err(e),
                        };
                        let failed = result.is_err();
                        if let Err(e) = tx.try_send(result) {
                            if e.is_disconnected() {
                                break;
                            }
                            warn!("PT {} stdout queue full; dropping line", identifier);
                        }
                        if failed {
                            break;
                        }
                    }
                });
            if let Err(e) = reader_result {
                owner.startup_error = Some(Arc::new(e));
                let _ = owner.begin_shutdown();
            }
            Ok(owner)
        }

        /// Возвращает независимый контроллер остановки.
        pub fn shutdown_handle(&self) -> ShutdownHandle {
            ShutdownHandle {
                sender: self.shutdown.clone(),
                reaped: self.completion.clone(),
            }
        }

        /// Отправляет запрос без ожидания и сохраняет подтверждение.
        pub fn begin_shutdown(&mut self) -> io::Result<()> {
            // Test-only seam: при активном флаге ошибки запрос остановки
            // детерминированно НЕ доставляется supervisor'у — child заведомо
            // остаётся жив, поэтому последующий shutdown() с тем же флагом
            // возвращает Err как нижнюю boundary-ошибку cleanup-запроса,
            // сохраняя retained-семантику (reap ещё не случился).
            #[cfg(all(test, unix))]
            if self.test_shutdown_error_once {
                return Ok(());
            }
            if !self.reaped && self.pending.is_none() {
                self.pending = Some(self.shutdown_handle().request()?);
            }
            Ok(())
        }

        /// Test-only seam: форсирует одну детерминированную ошибку следующего
        /// вызова shutdown() (флаг сбрасывается сам). Реальный путь остановки
        /// не затрагивается: запрос supervisor'у не отправляется, процесс
        /// остаётся жив. Нужен тестам реактора для проверки ветки
        /// complete_task -> Cleaned(Err) -> fail_cleanup.
        #[cfg(all(test, unix))]
        pub(crate) fn force_next_shutdown_error(&mut self) {
            self.test_shutdown_error_once = true;
        }

        /// Test-only seam: клон флага завершения процесса supervisor-потоком
        /// (доступное извне наблюдение reaping вместо /proc/<pid>):
        /// true — процесс дожит и wait-нут supervisor'ом.
        #[cfg(all(test, unix))]
        pub(crate) fn test_completion(&self) -> Arc<std::sync::atomic::AtomicBool> {
            self.completion.clone()
        }

        /// Ожидает подтверждение завершения; отмена ожидания не теряет запрос.
        pub async fn shutdown(&mut self) -> io::Result<()> {
            if self.reaped {
                return Ok(());
            }
            #[cfg(all(test, unix))]
            if std::mem::take(&mut self.test_shutdown_error_once) {
                // Единственная тестовая ошибка до begin_shutdown: запрос
                // остановки не отправляется, процесс продолжает жить.
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "test-forced shutdown error",
                ));
            }
            self.begin_shutdown()?;
            let result = self.pending.as_mut().expect("pending receipt").await;
            self.pending = None;
            match result {
                Ok(Ok(())) => {
                    self.reaped = true;
                    Ok(())
                }
                Ok(Err(e)) => Err(e),
                Err(_) if self.completion.load(std::sync::atomic::Ordering::Acquire) => {
                    self.reaped = true;
                    Ok(())
                }
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "PT supervisor stopped without receipt",
                )),
            }
        }

        /// Receive a message from the pluggable transport binary asynchronously.
        ///
        /// Note: This will convert `PtMessage::Log` into a tracing log call automatically.
        pub async fn recv(&mut self) -> err::Result<PtMessage> {
            if let Some(e) = &self.startup_error {
                return Err(PtError::ChildReadFailed(e.clone()));
            }
            loop {
                match self.stdout.next().await {
                    None => return Err(PtError::ChildGone),
                    Some(Ok(line)) => {
                        if self.proxy_sensitive
                            && (line.starts_with("LOG ")
                                || line.starts_with("STATUS ")
                                || line == "LOG"
                                || line == "STATUS")
                        {
                            continue;
                        }
                        if self.proxy_sensitive
                            && !(line.starts_with("VERSION ")
                                || line.starts_with("CMETHOD ")
                                || line == "CMETHODS DONE"
                                || line == "PROXY DONE")
                        {
                            return Err(PtError::ChildProtocolViolation(
                                "invalid PT message".into(),
                            ));
                        }
                        let line =
                            line.parse::<PtMessage>()
                                .map_err(|e| PtError::IpcParseFailed {
                                    line: if self.proxy_sensitive {
                                        "[redacted]".into()
                                    } else {
                                        line
                                    },
                                    error: if self.proxy_sensitive {
                                        "invalid PT message".into()
                                    } else {
                                        e.into()
                                    },
                                })?;
                        if self.proxy_sensitive {
                            match &line {
                                PtMessage::Log { .. } | PtMessage::Status(_) => continue,
                                PtMessage::ClientTransportLaunched {
                                    transport,
                                    protocol,
                                    ..
                                } if !self.allowed_methods.contains(transport)
                                    || (protocol != "socks4" && protocol != "socks5") =>
                                {
                                    return Err(PtError::ProtocolViolation(
                                        "invalid client method".into(),
                                    ));
                                }
                                PtMessage::ClientTransportFailed { .. }
                                | PtMessage::ServerTransportFailed { .. } => {
                                    return Err(PtError::ChildProtocolViolation(
                                        "PT reported transport failure".into(),
                                    ));
                                }
                                PtMessage::ProxyError(_) => {
                                    return Err(PtError::ProxyError(
                                        "PT reported proxy failure".into(),
                                    ));
                                }
                                PtMessage::EnvError(_)
                                | PtMessage::VersionError(_)
                                | PtMessage::Unknown(_) => {
                                    return Err(PtError::ChildProtocolViolation(
                                        "PT reported invalid startup message".into(),
                                    ));
                                }
                                PtMessage::Version(v) if v != "1" => {
                                    return Err(PtError::UnsupportedVersion);
                                }
                                _ => {}
                            }
                        }
                        if let PtMessage::Log { severity, message } = line {
                            // FIXME(eta): I wanted to make this integrate with `tracing` more nicely,
                            //             but gave up after 15 minutes of clicking through spaghetti.
                            match &severity as &str {
                                "error" => error!("[pt {}] {}", self.identifier, message),
                                "warning" => warn!("[pt {}] {}", self.identifier, message),
                                "notice" => info!("[pt {}] {}", self.identifier, message),
                                "info" => debug!("[pt {}] {}", self.identifier, message),
                                "debug" => trace!("[pt {}] {}", self.identifier, message),
                                x => warn!("[pt] {} {} {}", self.identifier, x, message),
                            }
                        } else {
                            return Ok(line);
                        }
                    }
                    Some(Err(e)) => {
                        return Err(PtError::ChildReadFailed(Arc::new(e)));
                    }
                }
            }
        }
    }

    /// Defines some helper methods that are required later on
    // async_trait добавляет #[must_use] сгенерированным методам, возвращающим Future,
    // что вызывает double_must_use для двух методов, возвращающих уже помеченные значения.
    #[allow(clippy::double_must_use)]
    #[async_trait::async_trait]
    pub trait PluggableTransportPrivate {
        /// Return the [`AsyncPtChild`] if it exists
        fn inner(&mut self) -> Result<&mut AsyncPtChild, PtError>;

        /// Set the [`AsyncPtChild`]
        fn set_inner(&mut self, newval: Option<AsyncPtChild>);

        /// Return a loggable identifier for this transport.
        fn identifier(&self) -> &str;

        /// Checks whether a transport is specified in our specific parameters
        fn specific_params_contains(&self, transport: &PtTransportName) -> bool;

        /// Common handler for `ClientTransportLaunched` and `ServerTransportLaunched`
        fn common_transport_launched_handler(
            &self,
            protocol: Option<String>,
            transport: PtTransportName,
            endpoint: SocketAddr,
            methods: &mut HashMap<PtTransportName, PtClientMethod>,
        ) -> Result<(), PtError> {
            if !self.specific_params_contains(&transport) {
                return Err(PtError::ProtocolViolation(format!(
                    "binary launched unwanted transport '{}'",
                    transport
                )));
            }
            let protocol = match protocol {
                Some(protocol_str) => match &protocol_str as &str {
                    "socks4" => SocksVersion::V4,
                    "socks5" => SocksVersion::V5,
                    x => {
                        return Err(PtError::ProtocolViolation(format!(
                            "unknown CMETHOD protocol '{}'",
                            x
                        )));
                    }
                },
                None => SocksVersion::V5,
            };
            let method = PtClientMethod {
                kind: protocol,
                endpoint,
            };
            info!("Transport '{}' uses method {:?}", transport, method);
            methods.insert(transport, method);
            Ok(())
        }

        /// Attempt to launch the PT and return the corresponding `[AsyncPtChild]`
        fn get_child_from_pt_launch(
            inner: &Option<AsyncPtChild>,
            transports: &Vec<PtTransportName>,
            binary_path: &PathBuf,
            arguments: &[String],
            all_env_vars: HashMap<OsString, OsString>,
        ) -> Result<AsyncPtChild, PtError> {
            if inner.is_some() {
                let warning_msg =
                    format!("Attempted to launch PT binary for {:?} twice.", transports);
                warn!("{warning_msg}");
                // WARN: this may not be the correct error to throw here
                return Err(PtError::ChildProtocolViolation(warning_msg));
            }
            info!(
                "Launching pluggable transport at {} for {:?}",
                binary_path.display_lossy(),
                transports
            );
            let identifier = crate::managed::pt_identifier(binary_path)?;
            let proxy_sensitive = all_env_vars.contains_key(std::ffi::OsStr::new("TOR_PT_PROXY"));
            let mut command = Command::new(binary_path);
            for (key, _) in std::env::vars_os() {
                if key
                    .to_string_lossy()
                    .to_ascii_uppercase()
                    .starts_with("TOR_PT_")
                {
                    command.env_remove(key);
                }
            }
            for key in [
                "TOR_PT_PROXY",
                "TOR_PT_CLIENT_TRANSPORTS",
                "TOR_PT_SERVER_TRANSPORTS",
                "TOR_PT_SERVER_TRANSPORT_OPTIONS",
                "TOR_PT_SERVER_BINDADDR",
                "TOR_PT_ORPORT",
                "TOR_PT_EXTENDED_SERVER_PORT",
                "TOR_PT_OUTBOUND_BIND_ADDRESS_V4",
                "TOR_PT_OUTBOUND_BIND_ADDRESS_V6",
                "TOR_PT_STATE_LOCATION",
                "TOR_PT_MANAGED_TRANSPORT_VER",
                "TOR_PT_EXIT_ON_STDIN_CLOSE",
            ] {
                command.env_remove(key);
            }
            command
                .args(arguments.iter())
                .envs(all_env_vars)
                .stdout(Stdio::piped())
                .stdin(Stdio::piped());
            AsyncPtChild::new(
                command,
                binary_path.clone(),
                identifier,
                proxy_sensitive,
                transports.clone(),
            )
        }

        /// Consolidates some of the [`PtMessage`] potential matches to
        /// deduplicate code
        ///
        /// Note that getting a [`PtMessage`] from this method implies that
        /// the method was unable to match it and thus you should continue handling
        /// the message. Getting [`None`] after error handling means that a match
        /// was found and the appropriate action was successfully taken, and you don't
        /// need to worry about it.
        async fn try_match_common_messages<R: Runtime>(
            rt: &R,
            deadline: Instant,
            async_child: &mut AsyncPtChild,
        ) -> Result<Option<PtMessage>, PtError> {
            match rt
                .timeout(
                    // FIXME(eta): It'd be nice if SleepProviderExt took an `Instant` natively.
                    deadline.saturating_duration_since(Instant::get()),
                    async_child.recv(),
                )
                .await
                .map_err(|_| PtError::Timeout)??
            {
                PtMessage::ClientTransportFailed { transport, message }
                | PtMessage::ServerTransportFailed { transport, message } => {
                    warn!(
                        "PT {} unable to launch {}. It said: {:?}",
                        async_child.identifier, transport, message
                    );
                    return Err(PtError::TransportGaveError {
                        transport: transport.to_string(),
                        message,
                    });
                }
                PtMessage::VersionError(e) => {
                    if e != "no-version" {
                        warn!("weird VERSION-ERROR: {}", e);
                    }
                    return Err(PtError::UnsupportedVersion);
                }
                PtMessage::Version(vers) => {
                    if vers != "1" {
                        return Err(PtError::ProtocolViolation(format!(
                            "stated version is {}, asked for 1",
                            vers
                        )));
                    }
                    Ok(None)
                }
                PtMessage::EnvError(e) => return Err(PtError::ChildProtocolViolation(e)),
                PtMessage::ProxyError(e) => return Err(PtError::ProxyError(e)),
                // TODO(eta): We don't do anything with these right now!
                PtMessage::Status(_) => Ok(None),
                PtMessage::Unknown(_) => {
                    Err(PtError::ProtocolViolation("unknown PT message".into()))
                }
                // Return the PtMessage as it is for further processing
                // TODO: handle [`PtError::ProtocolViolation`] here somehow
                x => {
                    return Ok(Some(x));
                }
            }
        }
    }
}

/// Common parameters passed to a pluggable transport.
#[derive(PartialEq, Eq, Clone, Debug, derive_builder::Builder)]
pub struct PtCommonParameters {
    /// A path where the launched PT can store state.
    state_location: PathBuf,
    /// An IPv4 address to bind outgoing connections to (if specified).
    ///
    /// Leaving this out will mean the PT uses a sane default.
    #[builder(default)]
    outbound_bind_v4: Option<Ipv4Addr>,
    /// An IPv6 address to bind outgoing connections to (if specified).
    ///
    /// Leaving this out will mean the PT uses a sane default.
    #[builder(default)]
    outbound_bind_v6: Option<Ipv6Addr>,
    /// The maximum time we should wait for a pluggable transport binary to report successful
    /// initialization. If `None`, a default value is used.
    #[builder(default)]
    timeout: Option<Duration>,
}

impl PtCommonParameters {
    /// Return a new `PtCommonParametersBuilder` for constructing a set of parameters.
    pub fn builder() -> PtCommonParametersBuilder {
        PtCommonParametersBuilder::default()
    }

    /// Convert these parameters into a set of environment variables to be passed to the PT binary
    /// in accordance with the specification.
    fn common_environment_variables(&self) -> HashMap<OsString, OsString> {
        let mut ret = HashMap::new();
        ret.insert("TOR_PT_MANAGED_TRANSPORT_VER".into(), "1".into());
        ret.insert(
            "TOR_PT_STATE_LOCATION".into(),
            self.state_location.clone().into_os_string(),
        );
        ret.insert("TOR_PT_EXIT_ON_STDIN_CLOSE".into(), "1".into());
        if let Some(v4) = self.outbound_bind_v4 {
            ret.insert(
                "TOR_PT_OUTBOUND_BIND_ADDRESS_V4".into(),
                v4.to_string().into(),
            );
        }
        if let Some(v6) = self.outbound_bind_v6 {
            // pt-spec.txt: "IPv6 addresses MUST always be wrapped in square brackets."
            ret.insert(
                "TOR_PT_OUTBOUND_BIND_ADDRESS_V6".into(),
                format!("[{}]", v6).into(),
            );
        }
        ret
    }
}

/// Parameters passed only to a pluggable transport client.
#[derive(PartialEq, Eq, Clone, derive_builder::Builder)]
pub struct PtClientParameters {
    /// A SOCKS URI specifying a proxy to use.
    #[builder(default)]
    proxy_uri: Option<String>,
    /// A list of transports to initialise.
    ///
    /// The PT launch will fail if all transports are not successfully initialised.
    transports: Vec<PtTransportName>,
}

impl std::fmt::Debug for PtClientParameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PtClientParameters")
            .field("proxy_uri", &self.proxy_uri.as_ref().map(|_| "[redacted]"))
            .field("transports", &self.transports)
            .finish()
    }
}

impl PtClientParameters {
    /// Return a new `PtClientParametersBuilder` for constructing a set of parameters.
    pub fn builder() -> PtClientParametersBuilder {
        PtClientParametersBuilder::default()
    }

    /// Convert these parameters into a set of environment variables to be passed to the PT binary
    /// in accordance with the specification.
    fn environment_variables(
        &self,
        common_params: &PtCommonParameters,
    ) -> HashMap<OsString, OsString> {
        let mut ret = common_params.common_environment_variables();
        if let Some(ref proxy_uri) = self.proxy_uri {
            ret.insert("TOR_PT_PROXY".into(), proxy_uri.clone().into());
        }
        ret.insert(
            "TOR_PT_CLIENT_TRANSPORTS".into(),
            self.transports.iter().join(",").into(),
        );
        ret
    }
}

/// Parameters passed only to a pluggable transport server.
#[derive(PartialEq, Eq, Clone, Debug, derive_builder::Builder)]
pub struct PtServerParameters {
    /// A list of transports to initialise.
    ///
    /// The PT launch will fail if all transports are not successfully initialised.
    transports: Vec<PtTransportName>,
    /// Transport options for each server transport
    #[builder(default)]
    server_transport_options: String,
    /// Set host:port on which the server transport should listen for connections
    #[builder(default)]
    server_bindaddr: String,
    /// Set host:port on which the server transport should forward requests
    #[builder(default)]
    server_orport: Option<String>,
    /// Set host:port on which the server transport should forward requests (extended ORPORT)
    #[builder(default)]
    server_extended_orport: Option<String>,
}

impl PtServerParameters {
    /// Return a new `PtServerParametersBuilder` for constructing a set of parameters.
    pub fn builder() -> PtServerParametersBuilder {
        PtServerParametersBuilder::default()
    }

    /// Convert these parameters into a set of environment variables to be passed to the PT binary
    /// in accordance with the specification.
    fn environment_variables(
        &self,
        common_params: &PtCommonParameters,
    ) -> HashMap<OsString, OsString> {
        let mut ret = common_params.common_environment_variables();
        ret.insert(
            "TOR_PT_SERVER_TRANSPORTS".into(),
            self.transports.iter().join(",").into(),
        );
        ret.insert(
            "TOR_PT_SERVER_TRANSPORT_OPTIONS".into(),
            self.server_transport_options.clone().into(),
        );
        ret.insert(
            "TOR_PT_SERVER_BINDADDR".into(),
            self.server_bindaddr.clone().into(),
        );
        if let Some(ref server_orport) = self.server_orport {
            ret.insert("TOR_PT_ORPORT".into(), server_orport.into());
        }
        if let Some(ref server_extended_orport) = self.server_extended_orport {
            ret.insert(
                "TOR_PT_EXTENDED_SERVER_PORT".into(),
                server_extended_orport.into(),
            );
        }
        ret
    }
}

/// Common functionality implemented to allow code reuse
/// Общая функциональность интерфейса реализации async_trait добавляет #[must_use]
/// сгенерированным Future; подавление относится только к этому trait.
#[allow(clippy::double_must_use)]
#[async_trait::async_trait]
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub trait PluggableTransport: PluggableTransportPrivate {
    /// Get all client methods returned by the binary, if it has been launched.
    ///
    /// If it hasn't been launched, the returned map will be empty.
    // TODO(eta): Actually figure out a way to expose this more stably.
    fn transport_methods(&self) -> &HashMap<PtTransportName, PtClientMethod>;

    /// Get the next [`PtMessage`] from the running transport. It is recommended to call this
    /// in a loop once a PT has been launched, in order to forward log messages and find out about
    /// status updates.
    //
    // FIXME(eta): This API will probably go away and get replaced with something better.
    //             In particular, we'd want to cache `Status` messages from before this method
    //             was called.
    async fn next_message(&mut self) -> err::Result<PtMessage> {
        let inner = self.inner()?;
        let ret = inner.recv().await;
        if let Err(PtError::ChildGone) | Err(PtError::ChildReadFailed { .. }) = &ret {
            // FIXME(eta): Currently this lets the caller still think the methods work by calling
            //             transport_methods.
            debug!(
                "PT {}: Received {:?}; shutting down.",
                self.identifier(),
                ret
            );
            // Владение сохраняется для явного подтверждения завершения.
            let _ = self.inner()?.begin_shutdown();
        }
        ret
    }
}
/// A pluggable transport binary in a child process.
///
/// These start out inert, and must be launched with [`PluggableClientTransport::launch`] in order
/// to be useful.
#[derive(Debug)]
pub struct PluggableClientTransport {
    /// The currently running child, if there is one.
    inner: Option<AsyncPtChild>,
    /// The path to the binary to run.
    pub(crate) binary_path: PathBuf,
    /// Arguments to pass to the binary.
    arguments: Vec<String>,
    /// Configured parameters.
    common_params: PtCommonParameters,
    /// Configured client-only parameters.
    client_params: PtClientParameters,
    /// Information about client methods obtained from the PT.
    cmethods: HashMap<PtTransportName, PtClientMethod>,
}

impl PluggableTransport for PluggableClientTransport {
    fn transport_methods(&self) -> &HashMap<PtTransportName, PtClientMethod> {
        &self.cmethods
    }
}

impl PluggableTransportPrivate for PluggableClientTransport {
    fn inner(&mut self) -> Result<&mut AsyncPtChild, PtError> {
        self.inner.as_mut().ok_or(PtError::ChildGone)
    }
    fn set_inner(&mut self, newval: Option<AsyncPtChild>) {
        self.inner = newval;
    }
    fn identifier(&self) -> &str {
        match &self.inner {
            Some(child) => &child.identifier,
            None => "<not yet launched>",
        }
    }
    fn specific_params_contains(&self, transport: &PtTransportName) -> bool {
        self.client_params.transports.contains(transport)
    }
}

impl PluggableClientTransport {
    /// Create a new pluggable transport wrapper, wrapping the binary at `binary_path` and passing
    /// the `params` to it.
    ///
    /// You must call [`PluggableClientTransport::launch`] to actually run the PT.
    pub fn new(
        binary_path: PathBuf,
        arguments: Vec<String>,
        common_params: PtCommonParameters,
        client_params: PtClientParameters,
    ) -> Self {
        Self {
            common_params,
            client_params,
            arguments,
            binary_path,
            inner: None,
            cmethods: Default::default(),
        }
    }

    /// Тестовый конструктор: обёртка вокруг уже запущенного дочернего процесса.
    /// Нужен проверкам реактора, чтобы подложить реальный процесс напрямую,
    /// минуя протокол запуска launch().
    #[cfg(all(test, unix))]
    pub(crate) fn with_pre_spawned_child(
        child: AsyncPtChild,
        common_params: PtCommonParameters,
        client_params: PtClientParameters,
    ) -> Self {
        Self {
            common_params,
            client_params,
            arguments: Vec::new(),
            binary_path: PathBuf::from("sh"),
            inner: Some(child),
            cmethods: Default::default(),
        }
    }

    /// Запрашивает остановку без ожидания подтверждения.
    pub fn begin_shutdown(&mut self) -> err::Result<()> {
        if let Some(child) = self.inner.as_mut() {
            child
                .begin_shutdown()
                .map_err(|e| PtError::ChildReadFailed(Arc::new(e)))?;
        }
        self.cmethods.clear();
        Ok(())
    }

    /// Возвращает контроллер для независимого запроса остановки.
    pub fn shutdown_handle(&self) -> Option<ShutdownHandle> {
        self.inner.as_ref().map(AsyncPtChild::shutdown_handle)
    }

    /// Ожидает подтверждённого завершения дочернего процесса.
    pub async fn shutdown(&mut self) -> err::Result<()> {
        self.cmethods.clear();
        if let Some(child) = self.inner.as_mut() {
            child
                .shutdown()
                .await
                .map_err(|e| PtError::ChildReadFailed(Arc::new(e)))?;
            self.inner = None;
        }
        Ok(())
    }

    /// Launch the pluggable transport, executing the binary.
    ///
    /// Will return an error if the launch fails, one of the transports fail, not all transports
    /// were launched, or the launch times out.
    pub async fn launch<R: Runtime>(&mut self, rt: R) -> err::Result<()> {
        let all_env_vars = self
            .client_params
            .environment_variables(&self.common_params);

        let async_child =
            <PluggableClientTransport as PluggableTransportPrivate>::get_child_from_pt_launch(
                &self.inner,
                &self.client_params.transports,
                &self.binary_path,
                &self.arguments,
                all_env_vars,
            )?;

        self.inner = Some(async_child);
        let result = async {
            let deadline = Instant::get() + self.common_params.timeout.unwrap_or(PT_START_TIMEOUT);
            let mut cmethods = HashMap::new();
            let mut proxy_done = self.client_params.proxy_uri.is_none();

            loop {
                match Self::try_match_common_messages(&rt, deadline, self.inner()?).await {
                    Ok(maybe_message) => {
                        if let Some(message) = maybe_message {
                            match message {
                                PtMessage::ClientTransportLaunched {
                                    transport,
                                    protocol,
                                    endpoint,
                                } => {
                                    if !proxy_done {
                                        return Err(PtError::ProtocolViolation(
                                            "client method before proxy confirmation".into(),
                                        ));
                                    }
                                    self.common_transport_launched_handler(
                                        Some(protocol),
                                        transport,
                                        endpoint,
                                        &mut cmethods,
                                    )?;
                                }
                                PtMessage::ProxyDone => {
                                    if proxy_done {
                                        return Err(PtError::ProtocolViolation(
                                            "binary initiated proxy when not asked (or twice)"
                                                .into(),
                                        ));
                                    }
                                    info!("PT binary now proxying connections via supplied URI");
                                    proxy_done = true;
                                }
                                // TODO: unify most of the handling of ClientTransportsDone with ServerTransportsDone
                                PtMessage::ClientTransportsDone => {
                                    if !proxy_done {
                                        return Err(PtError::ProtocolViolation(
                                            "client methods completed before proxy confirmation"
                                                .into(),
                                        ));
                                    }
                                    let unsupported = self
                                        .client_params
                                        .transports
                                        .iter()
                                        .filter(|&x| !cmethods.contains_key(x))
                                        .map(|x| x.to_string())
                                        .collect::<Vec<_>>();
                                    if !unsupported.is_empty() {
                                        warn!(
                                            "PT binary failed to initialise transports: {:?}",
                                            unsupported
                                        );
                                        return Err(PtError::ClientTransportsUnsupported(
                                            unsupported,
                                        ));
                                    }
                                    info!("PT binary initialisation done");
                                    break;
                                }
                                _ => {
                                    return Err(PtError::ProtocolViolation(
                                        "unexpected PT message".into(),
                                    ));
                                }
                            }
                        }
                    }
                    Err(e) => return Err(e),
                }
            }
            self.cmethods = cmethods;
            Ok(())
        }
        .await;
        if result.is_err() {
            let _ = self.begin_shutdown();
        }
        // TODO(eta): We need to expose the log and status messages after this function exits!
        result
    }
}

/// A pluggable transport server binary in a child process.
///
/// These start out inert, and must be launched with [`PluggableServerTransport::launch`] in order
/// to be useful.
#[derive(Debug)]
pub struct PluggableServerTransport {
    /// The currently running child, if there is one.
    inner: Option<AsyncPtChild>,
    /// The path to the binary to run.
    pub(crate) binary_path: PathBuf,
    /// Arguments to pass to the binary.
    arguments: Vec<String>,
    /// Configured parameters.
    common_params: PtCommonParameters,
    /// Configured server-only parameters.
    server_params: PtServerParameters,
    /// Information about server methods obtained from the PT.
    smethods: HashMap<PtTransportName, PtClientMethod>,
}

impl PluggableTransportPrivate for PluggableServerTransport {
    fn inner(&mut self) -> Result<&mut AsyncPtChild, PtError> {
        self.inner.as_mut().ok_or(PtError::ChildGone)
    }
    fn set_inner(&mut self, newval: Option<AsyncPtChild>) {
        self.inner = newval;
    }
    fn identifier(&self) -> &str {
        match &self.inner {
            Some(child) => &child.identifier,
            None => "<not yet launched>",
        }
    }
    fn specific_params_contains(&self, transport: &PtTransportName) -> bool {
        self.server_params.transports.contains(transport)
    }
}

impl PluggableTransport for PluggableServerTransport {
    fn transport_methods(&self) -> &HashMap<PtTransportName, PtClientMethod> {
        &self.smethods
    }
}

impl PluggableServerTransport {
    /// Create a new pluggable transport wrapper, wrapping the binary at `binary_path` and passing
    /// the `params` to it.
    ///
    /// You must call [`PluggableServerTransport::launch`] to actually run the PT.
    pub fn new(
        binary_path: PathBuf,
        arguments: Vec<String>,
        common_params: PtCommonParameters,
        server_params: PtServerParameters,
    ) -> Self {
        Self {
            common_params,
            server_params,
            arguments,
            binary_path,
            inner: None,
            smethods: Default::default(),
        }
    }

    /// Launch the pluggable transport, executing the binary.
    ///
    /// Will return an error if the launch fails, one of the transports fail, not all transports
    /// were launched, or the launch times out.
    pub async fn launch<R: Runtime>(&mut self, rt: R) -> err::Result<()> {
        let all_env_vars = self
            .server_params
            .environment_variables(&self.common_params);

        let mut async_child =
            <PluggableServerTransport as PluggableTransportPrivate>::get_child_from_pt_launch(
                &self.inner,
                &self.server_params.transports,
                &self.binary_path,
                &self.arguments,
                all_env_vars,
            )?;

        let deadline = Instant::get() + self.common_params.timeout.unwrap_or(PT_START_TIMEOUT);
        let mut smethods = HashMap::new();

        loop {
            match Self::try_match_common_messages(&rt, deadline, &mut async_child).await {
                Ok(maybe_message) => {
                    if let Some(message) = maybe_message {
                        match message {
                            PtMessage::ServerTransportLaunched {
                                transport,
                                endpoint,
                                options: _,
                            } => {
                                self.common_transport_launched_handler(
                                    None,
                                    transport,
                                    endpoint,
                                    &mut smethods,
                                )?;
                            }
                            PtMessage::ServerTransportsDone => {
                                let unsupported = self
                                    .server_params
                                    .transports
                                    .iter()
                                    .filter(|&x| !smethods.contains_key(x))
                                    .map(|x| x.to_string())
                                    .collect::<Vec<_>>();
                                if !unsupported.is_empty() {
                                    warn!(
                                        "PT binary failed to initialise transports: {:?}",
                                        unsupported
                                    );
                                    return Err(PtError::ClientTransportsUnsupported(unsupported));
                                }
                                info!("PT binary initialisation done");
                                break;
                            }
                            x => {
                                return Err(PtError::ProtocolViolation(format!(
                                    "received unexpected {:?}",
                                    x
                                )));
                            }
                        }
                    }
                }
                Err(e) => return Err(e),
            }
        }
        self.smethods = smethods;
        self.inner = Some(async_child);
        // TODO(eta): We need to expose the log and status messages after this function exits!
        Ok(())
    }
}

// Проверки процессов предназначены только для CI и не запускаются локально.
#[cfg(all(test, unix))]
mod lifecycle_process_tests {
    use super::*;
    use tor_rtcompat::PreferredRuntime;

    #[test]
    fn shutdown_retains_receipt_and_reaps_quiet_child() {
        if std::env::var_os("CI").is_none() {
            return;
        }
        let mut command = Command::new("sh");
        command
            .args(["-c", "while read line; do :; done"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        let mut child =
            AsyncPtChild::new(command, PathBuf::from("sh"), "ci".into(), false, Vec::new())
                .expect("launch");
        child.begin_shutdown().expect("request");
        child.begin_shutdown().expect("same request");
        futures::executor::block_on(child.shutdown()).expect("reaped");
        futures::executor::block_on(child.shutdown()).expect("idempotent");
    }

    #[test]
    fn proxy_parameters_debug_hides_credentials() {
        if std::env::var_os("CI").is_none() {
            return;
        }
        let params = PtClientParameters {
            proxy_uri: Some("socks5://user:secret@localhost:1234".into()),
            transports: Vec::new(),
        };
        assert!(!format!("{params:?}").contains("secret"));
    }

    // Собирает клиентскую обёртку вокруг /bin/sh, который выводит заданный
    // сценарий строк PT-протокола; proxy имитирует TOR_PT_PROXY.
    fn script_pt(script: &str, proxy: Option<&str>) -> PluggableClientTransport {
        let common = PtCommonParameters::builder()
            .state_location(std::env::temp_dir().join("tor-ptmgr-negative-ack-tests"))
            .build()
            .expect("common parameters");
        let transports = vec!["obfs4".parse::<PtTransportName>().expect("transport")];
        let client = PtClientParameters::builder()
            .transports(transports)
            .proxy_uri(proxy.map(ToString::to_string))
            .build()
            .expect("client parameters");
        PluggableClientTransport::new(
            PathBuf::from("/bin/sh"),
            vec!["-c".into(), script.to_string()],
            common,
            client,
        )
    }

    // Отрицательная проверка: запуск обязан завершиться указанным нарушением.
    // Запуск требует контекста рантайма (таймеры rt.timeout, сеть), поэтому
    // тесты исполняются в #[tokio::test] с доказанным PreferredRuntime::current()
    // (vendor/tor-ptmgr/examples/run-pt.rs:23), а не через
    // futures::executor::block_on, который не входит в контекст tokio.
    async fn assert_violation(pt: &mut PluggableClientTransport, needle: &str) {
        let rt = PreferredRuntime::current().expect("runtime");
        let result = pt.launch(rt).await;
        let error = result.expect_err("launch must fail on broken PT protocol");
        let matched = match &error {
            PtError::ProtocolViolation(message) | PtError::ChildProtocolViolation(message) => {
                message.contains(needle)
            }
            _ => false,
        };
        assert!(matched, "неожиданная ошибка: {error:?}");
        // Ошибочный запуск уже запросил остановку; подтверждаем завершение.
        pt.shutdown().await.expect("reaped");
    }

    #[tokio::test]
    async fn launch_rejects_cmethod_before_proxy_done() {
        if std::env::var_os("CI").is_none() {
            return;
        }
        let mut pt = script_pt(
            "echo 'VERSION 1'; \
             echo 'CMETHOD obfs4 socks5 127.0.0.1:12345'; \
             echo 'CMETHODS DONE'",
            Some("socks5://127.0.0.1:1080"),
        );
        assert_violation(&mut pt, "client method before proxy confirmation").await;
    }

    #[tokio::test]
    async fn launch_rejects_duplicate_proxy_done() {
        if std::env::var_os("CI").is_none() {
            return;
        }
        let mut pt = script_pt(
            "echo 'VERSION 1'; \
             echo 'PROXY DONE'; \
             echo 'PROXY DONE'; \
             echo 'CMETHOD obfs4 socks5 127.0.0.1:12345'; \
             echo 'CMETHODS DONE'",
            Some("socks5://127.0.0.1:1080"),
        );
        assert_violation(&mut pt, "binary initiated proxy when not asked (or twice)").await;
    }

    #[tokio::test]
    async fn launch_rejects_unrequested_proxy_done() {
        if std::env::var_os("CI").is_none() {
            return;
        }
        // Прокси не сконфигурирован: любое PROXY DONE от бинарника — нарушение.
        let mut pt = script_pt(
            "echo 'VERSION 1'; \
             echo 'PROXY DONE'; \
             echo 'CMETHOD obfs4 socks5 127.0.0.1:12345'; \
             echo 'CMETHODS DONE'",
            None,
        );
        assert_violation(&mut pt, "binary initiated proxy when not asked (or twice)").await;
    }

    #[tokio::test]
    async fn launch_rejects_cmethods_done_before_proxy_done() {
        if std::env::var_os("CI").is_none() {
            return;
        }
        let mut pt = script_pt(
            "echo 'VERSION 1'; \
             echo 'CMETHODS DONE'",
            Some("socks5://127.0.0.1:1080"),
        );
        assert_violation(
            &mut pt,
            "client methods completed before proxy confirmation",
        )
        .await;
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    #![allow(clippy::string_slice)] // See arti#2571
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use crate::ipc::{PtMessage, PtStatus};
    use std::borrow::Cow;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn it_parses_spec_examples() {
        assert_eq!(
            "VERSION-ERROR no-version".parse(),
            Ok(PtMessage::VersionError("no-version".into()))
        );
        assert_eq!("VERSION 1".parse(), Ok(PtMessage::Version("1".into())));
        assert_eq!(
            "ENV-ERROR No TOR_PT_AUTH_COOKIE_FILE when TOR_PT_EXTENDED_SERVER_PORT set".parse(),
            Ok(PtMessage::EnvError(
                "No TOR_PT_AUTH_COOKIE_FILE when TOR_PT_EXTENDED_SERVER_PORT set".into()
            ))
        );
        assert_eq!("PROXY DONE".parse(), Ok(PtMessage::ProxyDone));
        assert_eq!(
            "PROXY-ERROR SOCKS 4 upstream proxies unsupported".parse(),
            Ok(PtMessage::ProxyError(
                "SOCKS 4 upstream proxies unsupported".into()
            ))
        );
        assert_eq!(
            "CMETHOD trebuchet socks5 127.0.0.1:19999".parse(),
            Ok(PtMessage::ClientTransportLaunched {
                transport: "trebuchet".parse().unwrap(),
                protocol: "socks5".to_string(),
                endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 19999)
            })
        );
        assert_eq!(
            "CMETHOD-ERROR trebuchet no rocks available".parse(),
            Ok(PtMessage::ClientTransportFailed {
                transport: "trebuchet".parse().unwrap(),
                message: "no rocks available".to_string()
            })
        );
        assert_eq!("CMETHODS DONE".parse(), Ok(PtMessage::ClientTransportsDone));
        assert_eq!(
            "SMETHOD trebuchet 198.51.100.1:19999".parse(),
            Ok(PtMessage::ServerTransportLaunched {
                transport: "trebuchet".parse().unwrap(),
                endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 19999),
                options: Default::default()
            })
        );
        let mut map = HashMap::new();
        map.insert("N".to_string(), "13".to_string());
        assert_eq!(
            "SMETHOD rot_by_N 198.51.100.1:2323 ARGS:N=13".parse(),
            Ok(PtMessage::ServerTransportLaunched {
                transport: "rot_by_N".parse().unwrap(),
                endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 2323),
                options: map
            })
        );
        let mut map = HashMap::new();
        map.insert(
            "cert".to_string(),
            "HszPy3vWfjsESCEOo9ZBkRv6zQ/1mGHzc8arF0y2SpwFr3WhsMu8rK0zyaoyERfbz3ddFw".to_string(),
        );
        map.insert("iat-mode".to_string(), "0".to_string());
        assert_eq!(
            "SMETHOD obfs4 198.51.100.1:43734 ARGS:cert=HszPy3vWfjsESCEOo9ZBkRv6zQ/1mGHzc8arF0y2SpwFr3WhsMu8rK0zyaoyERfbz3ddFw,iat-mode=0".parse(),
            Ok(PtMessage::ServerTransportLaunched {
                transport: "obfs4".parse().unwrap(),
                endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 43734),
                options: map
            })
        );
        assert_eq!(
            "SMETHOD-ERROR trebuchet no cows available".parse(),
            Ok(PtMessage::ServerTransportFailed {
                transport: "trebuchet".parse().unwrap(),
                message: "no cows available".to_string()
            })
        );
        assert_eq!(
            "LOG SEVERITY=debug MESSAGE=\"Connected to bridge A\"".parse(),
            Ok(PtMessage::Log {
                severity: "debug".to_string(),
                message: "Connected to bridge A".to_string()
            })
        );
        assert_eq!(
            "LOG SEVERITY=debug MESSAGE=\"\\r\\n\\t\"".parse(),
            Ok(PtMessage::Log {
                severity: "debug".to_string(),
                message: "\r\n\t".to_string()
            })
        );
        assert_eq!(
            "LOG SEVERITY=debug MESSAGE=".parse(),
            Ok(PtMessage::Log {
                severity: "debug".to_string(),
                message: "".to_string()
            })
        );
        assert_eq!(
            "LOG SEVERITY=debug MESSAGE=\"\\a\"".parse::<PtMessage>(),
            Ok(PtMessage::Log {
                severity: "debug".to_string(),
                message: "a".to_string()
            })
        );

        for i in 0..9 {
            let msg = format!("LOG SEVERITY=debug MESSAGE=\"\\{i}\"");
            assert_eq!(
                msg.parse::<PtMessage>(),
                Err(Cow::from("attempted unsupported octal escape code"))
            );
        }
        assert_eq!(
            "SMETHOD obfs4 198.51.100.1:43734 ARGS:iat-mode=0\\".parse::<PtMessage>(),
            Err(Cow::from(
                "failed to parse SMETHOD ARGS: smethod arg terminates with backslash"
            ))
        );
        assert_eq!(
            "SMETHOD obfs4 198.51.100.1:43734 ARGS:iat-mode=fo=o".parse::<PtMessage>(),
            Err(Cow::from(
                "failed to parse SMETHOD ARGS: encountered = while parsing value"
            ))
        );
        assert_eq!(
            "SMETHOD obfs4 198.51.100.1:43734 ARGS:iat-mode".parse::<PtMessage>(),
            Err(Cow::from(
                "failed to parse SMETHOD ARGS: ran out of chars parsing smethod arg"
            ))
        );

        let mut map = HashMap::new();
        map.insert("ADDRESS".to_string(), "198.51.100.123:1234".to_string());
        map.insert("CONNECT".to_string(), "Success".to_string());
        assert_eq!(
            "STATUS ADDRESS=198.51.100.123:1234 CONNECT=Success".parse(),
            Ok(PtMessage::Status(PtStatus { data: map }))
        );

        let mut map = HashMap::new();
        map.insert("ADDRESS".to_string(), "198.51.100.123:1234".to_string());
        map.insert("CONNECT".to_string(), "Success".to_string());
        map.insert("TRANSPORT".to_string(), "obfs4".to_string());
        assert_eq!(
            "STATUS TRANSPORT=obfs4 ADDRESS=198.51.100.123:1234 CONNECT=Success".parse(),
            Ok(PtMessage::Status(PtStatus { data: map }))
        );

        let mut map = HashMap::new();
        map.insert("ADDRESS".to_string(), "198.51.100.222:2222".to_string());
        map.insert("CONNECT".to_string(), "Failed".to_string());
        map.insert("FINGERPRINT".to_string(), "<Fingerprint>".to_string());
        map.insert("ERRSTR".to_string(), "Connection refused".to_string());
        assert_eq!(
            "STATUS ADDRESS=198.51.100.222:2222 CONNECT=Failed FINGERPRINT=<Fingerprint> ERRSTR=\"Connection refused\"".parse(),
            Ok(PtMessage::Status(PtStatus {
                data: map
            }))
        );
    }
}
