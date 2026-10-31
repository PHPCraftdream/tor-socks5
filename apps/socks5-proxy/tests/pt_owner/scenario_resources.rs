use super::AbortOnDrop;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;

#[derive(Default)]
pub(crate) struct RecorderCounters {
    pub(crate) accept_overrun: Arc<AtomicUsize>,
    pub(crate) events_overrun: Arc<AtomicUsize>,
    pub(crate) panic_count: Arc<AtomicUsize>,
    pub(crate) panic_messages: Arc<Mutex<Vec<String>>>,
    pub(crate) worker_timeouts: Arc<AtomicUsize>,
    pub(crate) worker_errors: Arc<AtomicUsize>,
    pub(crate) aborted_workers: Arc<AtomicUsize>,
}

pub(crate) struct ScenarioCleanup<'a> {
    pub(crate) shutdown_tx: Option<oneshot::Sender<()>>,
    pub(crate) stop1_tx: watch::Sender<()>,
    pub(crate) stop2_tx: watch::Sender<()>,
    pub(crate) server: &'a mut AbortOnDrop<anyhow::Result<()>>,
    pub(crate) recorder1: &'a mut AbortOnDrop<()>,
    pub(crate) recorder2: &'a mut AbortOnDrop<()>,
    pub(crate) trap: &'a mut AbortOnDrop<()>,
    pub(crate) trap_listener: Arc<TcpListener>,
    pub(crate) trap_accepts: &'a AtomicUsize,
    pub(crate) trap_overrun: &'a AtomicUsize,
    pub(crate) events1_rx: mpsc::Receiver<Vec<u8>>,
    pub(crate) events2_rx: mpsc::Receiver<Vec<u8>>,
    pub(crate) traps_rx: mpsc::Receiver<TcpStream>,
    pub(crate) graceful_deadline: Instant,
    pub(crate) terminal_deadline: Instant,
}
