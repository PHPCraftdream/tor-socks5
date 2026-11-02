use std::future::{poll_fn, Future};
use std::net::SocketAddr;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{anyhow, ensure, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout_at, Instant};
use tokio_util::sync::CancellationToken;

use super::construction_consumer::Delivery;
use super::construction_wire::Operation;
use super::{SelectionEvent, SelectionOutcome};

const MAX_PATH: usize = 2048;
const MAX_REQUEST: usize = MAX_PATH * 2 + 7;
const CAPACITY: usize = 32;
pub(crate) const OWNER_ADDRESS: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 19054);
const SUPERVISOR_ADDRESS: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 19053);

type Incoming = Pin<Box<dyn Future<Output = Result<Request>>>>;
type Transaction = Pin<Box<dyn Future<Output = Result<()>>>>;

pub(super) struct Request {
    stream: TcpStream,
    leaf: PathBuf,
}

struct Allocation {
    delivery: Delivery,
    phase: u8,
    used: bool,
}

/// Owns partial request/INTENT futures; no spawned actor or detached handle.
pub(super) struct Coordinator {
    listener: Arc<TcpListener>,
    incoming: Option<Incoming>,
    active: Option<Transaction>,
    allocations: Vec<Allocation>,
    executable: PathBuf,
    supervisor: SocketAddr,
    stop: CancellationToken,
    failure: bool,
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        result.push(DIGITS[usize::from(byte >> 4)] as char);
        result.push(DIGITS[usize::from(byte & 15)] as char);
    }
    result
}

fn decode(bytes: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_PATH * 2 && bytes.len() % 2 == 0,
        "owner readiness path bound"
    );
    let nibble = |byte| match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(anyhow!("owner readiness requires lowercase hex")),
    };
    let mut raw = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let byte = (nibble(pair[0])? << 4) | nibble(pair[1])?;
        ensure!(byte != 0, "owner readiness path NUL");
        raw.push(byte);
    }
    Ok(raw)
}

/// cancel-safe: NO — the owning future retains this socket and framing state.
async fn line(stream: &mut TcpStream, deadline: Instant, bound: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    loop {
        ensure!(bytes.len() < bound, "owner readiness line bound");
        let byte = timeout_at(deadline, stream.read_u8()).await??;
        bytes.push(byte);
        if byte == b'\n' {
            return Ok(bytes);
        }
    }
}

fn canonical(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute() && std::fs::canonicalize(path)? == path,
        "owner intent requires canonical path"
    );
    Ok(())
}

fn eligible(delivery: &Delivery) -> bool {
    let evidence = &delivery.evidence;
    evidence.event == SelectionEvent::StorageAssigned
        && evidence.outcome == SelectionOutcome::Reserved
        && evidence.explicit_disabled
        && evidence.effective_none == Some(true)
}

fn intent_frame(delivery: &Delivery, leaf: &Path, executable: &Path) -> Result<Vec<u8>> {
    ensure!(
        eligible(delivery),
        "construction does not authorize direct intent"
    );
    let evidence = &delivery.evidence;
    let receipt = delivery
        .receipt
        .as_ref()
        .ok_or_else(|| anyhow!("missing construction receipt"))?;
    ensure!(
        delivery.producer_ack_sent
            && delivery.failure.is_none()
            && receipt.operation == Operation::Assigned
            && receipt.registry > 0
            && receipt.transaction > 0
            && receipt.journal_sequence == evidence.journal_sequence
            && evidence.journal_sequence > 0
            && evidence.identity.is_some_and(|value| value > 0),
        "owner intent requires acknowledged matching construction receipt"
    );
    let storage = evidence
        .storage
        .as_ref()
        .ok_or_else(|| anyhow!("missing assigned storage"))?;
    ensure!(
        (1..=15).contains(&storage.slot)
            && storage.allocated
                == storage
                    .base
                    .join("owners-v1")
                    .join(storage.slot.to_string()),
        "owner intent slot mismatch"
    );
    canonical(&storage.allocated)?;
    let filename = executable
        .file_name()
        .ok_or_else(|| anyhow!("missing executable filename"))?;
    let expected = storage
        .allocated
        .join("state")
        .join("pt_state")
        .join(filename);
    ensure!(leaf == expected, "owner intent leaf mismatch");
    canonical(leaf)?;
    let allocated = storage.allocated.as_os_str().as_bytes();
    let leaf = leaf.as_os_str().as_bytes();
    ensure!(
        !allocated.is_empty()
            && allocated.len() <= MAX_PATH
            && leaf.len() <= MAX_PATH
            && !allocated.contains(&0)
            && !leaf.contains(&0),
        "owner intent path bound"
    );
    Ok(format!(
        "INTENT {} {}\n{} {}\n",
        allocated.len(),
        leaf.len(),
        hex(allocated),
        hex(leaf)
    )
    .into_bytes())
}

impl Coordinator {
    pub(super) fn new(listener: TcpListener, executable: PathBuf, supervisor: SocketAddr) -> Self {
        Self {
            listener: Arc::new(listener),
            incoming: None,
            active: None,
            allocations: Vec::new(),
            executable,
            supervisor,
            stop: CancellationToken::new(),
            failure: false,
        }
    }

    pub(super) async fn bind(deadline: Instant) -> Result<Self> {
        let listener = timeout_at(deadline, TcpListener::bind(OWNER_ADDRESS)).await??;
        Ok(Self::new(
            listener,
            std::env::current_exe()?,
            SUPERVISOR_ADDRESS,
        ))
    }

    pub(super) fn observe(&mut self, delivery: &Delivery, phase: u8) -> Result<()> {
        if !eligible(delivery) {
            return Ok(());
        }
        ensure!(
            !self.failure && !self.stop.is_cancelled() && self.allocations.len() < CAPACITY,
            "owner intent allocation capacity/lifecycle"
        );
        let receipt = delivery
            .receipt
            .as_ref()
            .ok_or_else(|| anyhow!("missing assignment receipt"))?;
        ensure!(
            !self.allocations.iter().any(|old| old
                .delivery
                .receipt
                .as_ref()
                .is_some_and(|old| old.registry == receipt.registry
                    && old.journal_sequence == receipt.journal_sequence)),
            "duplicate owner assignment"
        );
        self.allocations.push(Allocation {
            delivery: delivery.clone(),
            phase,
            used: false,
        });
        Ok(())
    }

    pub(super) fn pause_requests(&mut self) {
        self.incoming.take();
    }

    pub(super) fn stop(&mut self) {
        self.stop.cancel();
        // An idle accept/read owns no authorization transaction. Closing denies its child.
        self.incoming.take();
    }

    pub(super) fn has_active(&self) -> bool {
        self.active.is_some()
    }

    pub(super) fn poll_request(
        &mut self,
        cx: &mut Context<'_>,
        deadline: Instant,
    ) -> Poll<Result<Request>> {
        if self.failure || self.stop.is_cancelled() {
            return Poll::Pending;
        }
        if self.incoming.is_none() {
            let listener = Arc::clone(&self.listener);
            self.incoming = Some(Box::pin(async move {
                let (mut stream, _) = timeout_at(deadline, listener.accept()).await??;
                let frame = line(&mut stream, deadline, MAX_REQUEST).await?;
                let body = frame
                    .strip_prefix(b"READY ")
                    .and_then(|body| body.strip_suffix(b"\n"))
                    .ok_or_else(|| anyhow!("owner readiness request frame"))?;
                let leaf = PathBuf::from(std::ffi::OsString::from_vec(decode(body)?));
                Ok(Request { stream, leaf })
            }));
        }
        match self
            .incoming
            .as_mut()
            .expect("request retained")
            .as_mut()
            .poll(cx)
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.incoming.take();
                Poll::Ready(result)
            }
        }
    }

    /// Starts only while the evidence Client is idle; caller serializes all CE I/O.
    pub(super) fn start(&mut self, request: Request, phase: u8, deadline: Instant) -> Result<()> {
        ensure!(
            self.active.is_none() && !self.failure && !self.stop.is_cancelled(),
            "owner intent transaction lifecycle"
        );
        let allocation = self
            .allocations
            .iter_mut()
            .find(|item| !item.used)
            .ok_or_else(|| anyhow!("unregistered child readiness"))?;
        ensure!(allocation.phase == phase, "owner intent phase mismatch");
        let frame = intent_frame(&allocation.delivery, &request.leaf, &self.executable)?;
        // Never retry a possibly delivered INTENT, even if its reply is lost.
        allocation.used = true;
        let address = self.supervisor;
        let stop = self.stop.clone();
        self.active = Some(Box::pin(async move {
            let mut child = request.stream;
            let mut supervisor = timeout_at(deadline, TcpStream::connect(address)).await??;
            timeout_at(deadline, supervisor.write_all(&frame)).await??;
            ensure!(
                line(&mut supervisor, deadline, 128).await? == b"OK\n",
                "owner INTENT denied"
            );
            ensure!(
                !stop.is_cancelled(),
                "owner intent stopped before child readiness"
            );
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| anyhow!("owner intent deadline"))?
                .as_millis();
            ensure!(remaining > 0, "owner intent exhausted budget");
            let response = format!("READY {remaining}\n");
            timeout_at(deadline, child.write_all(response.as_bytes())).await??;
            Ok(())
        }));
        Ok(())
    }

    pub(super) fn poll_active(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let Some(active) = self.active.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        match active.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.active.take();
                if result.is_err() {
                    self.failure = true;
                }
                Poll::Ready(result)
            }
        }
    }

    /// cancel-safe: NO — retain this coordinator and resume the exact transaction.
    pub(super) async fn settle(&mut self) -> Result<()> {
        self.stop();
        poll_fn(|cx| self.poll_active(cx)).await?;
        ensure!(!self.failure, "owner intent retained failure");
        Ok(())
    }

    pub(super) fn phase_complete(&self, phase: u8) -> bool {
        self.active.is_none()
            && !self.failure
            && self
                .allocations
                .iter()
                .filter(|item| item.phase == phase)
                .all(|item| item.used)
    }
}

/// cancel-safe: NO — retain until completion; an error must terminate this child.
/// Absence of TOR_PT_PROXY selects coordination, never authorization.
pub(crate) async fn gate_from_environment() -> Result<()> {
    let Some(deadline) = super::owner_budget::from_environment()? else {
        return Ok(());
    };
    if std::env::var_os("TOR_PT_PROXY").is_some() {
        return Ok(());
    }
    let started = Instant::now();
    let leaf = PathBuf::from(
        std::env::var_os("TOR_PT_STATE_LOCATION")
            .ok_or_else(|| anyhow!("child managed leaf missing"))?,
    );
    canonical(&leaf)?;
    let raw = leaf.as_os_str().as_bytes();
    ensure!(
        !raw.is_empty() && raw.len() <= MAX_PATH && !raw.contains(&0),
        "child leaf bound"
    );
    let mut stream = timeout_at(deadline, TcpStream::connect(OWNER_ADDRESS)).await??;
    timeout_at(
        deadline,
        stream.write_all(format!("READY {}\n", hex(raw)).as_bytes()),
    )
    .await??;
    let response = line(&mut stream, deadline, 64).await?;
    let text = std::str::from_utf8(&response)?;
    let milliseconds = text
        .strip_prefix("READY ")
        .and_then(|text| text.strip_suffix('\n'))
        .filter(|text| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|text| text.parse::<u64>().ok())
        .filter(|value| *value > 0 && *value <= 240_000)
        .ok_or_else(|| anyhow!("child readiness denied"))?;
    // Anchor to before the request: network/owner time can only shorten this budget.
    let deadline = deadline.min(started + std::time::Duration::from_millis(milliseconds));
    super::direct_child_gate::direct_child_gate(SUPERVISOR_ADDRESS, deadline).await?;
    Ok(())
}

#[cfg(test)]
#[path = "owner_intent_tests.rs"]
mod tests;
