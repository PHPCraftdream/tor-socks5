use std::cell::Cell;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use futures::io::{AsyncRead, AsyncWrite};
use futures::Future;
use tokio::net::UnixStream;

use super::ProofControl;
use super::{exchange, protocol, terminal_proof};

const NONCE: &str = "0123456789abcdef0123456789abcdef";

fn fixture() -> String {
    let mut result = String::from("TOR_OWNED_STREAM_V2\nPARENT 42 1000\n");
    for index in 1_u8..=3 {
        result.push_str(&format!(
            "AUTH local{index} {}\nFALLBACK {} {} 127.0.0.{} {}\n",
            format!("{:02X}", index).repeat(20),
            format!("{:02X}", index + 10).repeat(20),
            format!("{:02X}", index + 20).repeat(32),
            index + 1,
            21000 + u16::from(index),
        ));
    }
    result.push_str(&format!("TARGET 127.0.0.1 23000\nNONCE {NONCE}\nEND\n"));
    result
}

#[test]
fn capabilities_preserve_authority_relay_and_target_fields() {
    let input = fixture();
    let capabilities = protocol::parse(input.as_bytes(), 42, 1000).unwrap();
    assert_eq!(capabilities.authorities.len(), 3);
    assert_eq!(capabilities.relays.len(), 3);
    assert_eq!(capabilities.authorities[0].identity, [1; 20]);
    assert_eq!(capabilities.relays[0].rsa, [11; 20]);
    assert_eq!(capabilities.relays[0].ed, [21; 32]);
    assert_eq!(capabilities.relays[0].address.octets(), [127, 0, 0, 2]);
    assert_eq!(capabilities.relays[0].port, 21001);
    assert_eq!(capabilities.target_address.octets(), [127, 0, 0, 1]);
    assert_eq!(capabilities.target_port, 23000);
    assert_eq!(capabilities.nonce, NONCE);
}

#[test]
fn credentials_require_both_kernel_identity_fields() {
    assert!(protocol::authenticate(42, 1000, 42, 1000).is_ok());
    assert!(protocol::authenticate(43, 1000, 42, 1000).is_err());
    assert!(protocol::authenticate(42, 1001, 42, 1000).is_err());
    assert!(protocol::authenticate(0, 1000, 0, 1000).is_err());
    assert!(protocol::parse(fixture().as_bytes(), 43, 1000).is_err());
}

#[test]
fn malformed_records_and_capability_expansion_are_rejected() {
    let valid = fixture();
    let cases = [
        valid.replace("PARENT 42", "PARENT 042"),
        valid.replace("AUTH local1", "UNKNOWN local1"),
        valid.replace("AUTH local2", "AUTH local1"),
        valid.replace(&"02".repeat(20), &"01".repeat(20)),
        valid.replace(&"0C".repeat(20), &"0B".repeat(20)),
        valid.replace(&"16".repeat(32), &"15".repeat(32)),
        valid.replace(&"01".repeat(20), &"0B".repeat(20)),
        valid.replace("127.0.0.3", "127.0.0.2"),
        valid.replace("127.0.0.2", "192.0.2.2"),
        valid.replace("TARGET 127.0.0.1", "TARGET localhost"),
        valid.replace("23000", "0"),
        valid.replace("23000", "65536"),
        valid.replace("NONCE 0", "NONCE A"),
        valid.replace("PARENT ", "PARENT  "),
        valid.replace('\n', "\r\n"),
        format!("{valid}END\n"),
        valid.trim_end().to_owned(),
    ];
    for input in cases {
        assert!(protocol::parse(input.as_bytes(), 42, 1000).is_err());
    }
    let mut nul = valid.into_bytes();
    nul[0] = 0;
    assert!(protocol::parse(&nul, 42, 1000).is_err());
}

#[test]
fn input_and_line_limits_fail_closed() {
    assert!(protocol::parse(&vec![b'x'; 4097], 42, 1000).is_err());
    let input = fixture().replace("local1", &"x".repeat(513));
    assert!(protocol::parse(input.as_bytes(), 42, 1000).is_err());
    let input = fixture().replace("AUTH local1", "FALLBACK local1");
    assert!(protocol::parse(input.as_bytes(), 42, 1000).is_err());
}

struct Wire {
    response: Vec<u8>,
    read: usize,
    written: Vec<u8>,
    flushed: bool,
    closed: bool,
    pending: bool,
    pending_eof: bool,
    eof_reads: usize,
}

impl Wire {
    fn new(response: Vec<u8>) -> Self {
        Self {
            response,
            read: 0,
            written: Vec::new(),
            flushed: false,
            closed: false,
            pending: false,
            pending_eof: false,
            eof_reads: 0,
        }
    }
}

impl AsyncRead for Wire {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        assert!(self.flushed);
        assert!(!self.closed);

        if self.pending {
            return Poll::Pending;
        }
        if self.read == self.response.len() {
            self.eof_reads += 1;
            if self.pending_eof {
                return Poll::Pending;
            }
            return Poll::Ready(Ok(0));
        }

        let count = output.len().min(2).min(self.response.len() - self.read);
        output[..count].copy_from_slice(&self.response[self.read..self.read + count]);
        self.read += count;
        Poll::Ready(Ok(count))
    }
}

impl AsyncWrite for Wire {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        assert!(!self.closed);
        let count = input.len().min(3);
        self.written.extend_from_slice(&input[..count]);
        Poll::Ready(Ok(count))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flushed = true;
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.closed = true;
        Poll::Ready(Ok(()))
    }
}

#[test]
fn complete_distinct_response_precedes_close_despite_partial_io() {
    let expected = format!("owned-response:{NONCE}\n");
    let mut wire = Wire::new(expected.into_bytes());

    futures::executor::block_on(exchange(&mut wire, NONCE)).unwrap();

    assert_eq!(wire.written, format!("owned-request:{NONCE}\n").as_bytes(),);
    assert!(wire.closed);
    assert_eq!(wire.read, wire.response.len());
    assert_eq!(wire.eof_reads, 1);
}

#[test]
fn truncated_wrong_or_extended_response_never_reaches_close_success() {
    for response in [
        format!("owned-response:{NONCE}").into_bytes(),
        format!("owned-request:{NONCE}\n").into_bytes(),
        format!("owned-response:{NONCE}\nX").into_bytes(),
        format!("owned-response:{NONCE}\nEXTRA\n").into_bytes(),
    ] {
        let mut wire = Wire::new(response);
        let result = futures::executor::block_on(exchange(&mut wire, NONCE));

        assert!(result.is_err());
        assert!(!wire.closed);
    }
}

#[test]
fn cancelling_exchange_does_not_drop_the_borrowed_stream_owner() {
    let mut wire = Wire::new(format!("owned-response:{NONCE}\n").into_bytes());
    wire.pending = true;
    {
        let mut operation = Box::pin(exchange(&mut wire, NONCE));
        let waker = futures::task::noop_waker();
        let mut context = Context::from_waker(&waker);
        assert!(operation.as_mut().poll(&mut context).is_pending());
    }
    assert!(wire.flushed);
    assert!(!wire.closed);
    assert_eq!(wire.read, 0);
    assert_eq!(wire.written, format!("owned-request:{NONCE}\n").as_bytes(),);
}

#[test]
fn complete_response_without_eof_stays_pending_and_is_not_closed() {
    let mut wire = Wire::new(format!("owned-response:{NONCE}\n").into_bytes());
    wire.pending_eof = true;

    {
        let mut operation = Box::pin(exchange(&mut wire, NONCE));
        let waker = futures::task::noop_waker();
        let mut context = Context::from_waker(&waker);

        assert!(operation.as_mut().poll(&mut context).is_pending());
    }

    assert_eq!(wire.read, wire.response.len());
    assert_eq!(wire.eof_reads, 1);
    assert!(!wire.closed);
}

struct OwnerWitness {
    drops: Rc<Cell<usize>>,
}

impl Drop for OwnerWitness {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}

fn retained_owner() -> (Option<OwnerWitness>, Rc<Cell<usize>>) {
    let drops = Rc::new(Cell::new(0));
    (
        Some(OwnerWitness {
            drops: Rc::clone(&drops),
        }),
        drops,
    )
}

async fn receipt(control: &mut UnixStream, expected: &[u8]) {
    let mut actual = vec![0_u8; expected.len()];
    tokio::io::AsyncReadExt::read_exact(control, &mut actual)
        .await
        .unwrap();
    assert_eq!(actual, expected);
}

fn no_receipt(control: &UnixStream) {
    let mut byte = [0_u8; 1];
    match control.try_read(&mut byte) {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        result => panic!("unexpected control receipt: {result:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn valid_ack_releases_owners_before_consumer_done() {
    let (mut consumer, mut parent) = UnixStream::pair().unwrap();
    let (mut owners, drops) = retained_owner();
    let parent_drops = Rc::clone(&drops);

    let (result, ()) = tokio::join!(terminal_proof(&mut consumer, &mut owners), async {
        receipt(&mut parent, b"STREAM_VERIFIED\n").await;
        assert_eq!(parent_drops.get(), 0);

        tokio::io::AsyncWriteExt::write_all(&mut parent, b"TARGET_TERMINATED\n")
            .await
            .unwrap();

        receipt(&mut parent, b"CONSUMER_DONE\n").await;
        assert_eq!(parent_drops.get(), 1);
    },);

    assert!(result.is_ok());
    assert!(owners.is_none());
    assert_eq!(drops.get(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_ack_retains_owners_and_emits_no_done() {
    let (mut consumer, mut parent) = UnixStream::pair().unwrap();
    let (mut owners, drops) = retained_owner();

    let (result, ()) = tokio::join!(terminal_proof(&mut consumer, &mut owners), async {
        receipt(&mut parent, b"STREAM_VERIFIED\n").await;
        assert_eq!(drops.get(), 0);

        tokio::io::AsyncWriteExt::write_all(&mut parent, b"TARGET_REJECTED!!\n")
            .await
            .unwrap();

        tokio::io::AsyncWriteExt::shutdown(&mut parent)
            .await
            .unwrap();
    },);

    assert!(result.is_err());
    assert!(owners.is_some());
    assert_eq!(drops.get(), 0);
    no_receipt(&parent);

    drop(owners.take());
    assert_eq!(drops.get(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn eof_while_waiting_for_ack_retains_owners() {
    let (mut consumer, mut parent) = UnixStream::pair().unwrap();
    let (mut owners, drops) = retained_owner();

    let (result, ()) = tokio::join!(terminal_proof(&mut consumer, &mut owners), async {
        receipt(&mut parent, b"STREAM_VERIFIED\n").await;
        assert_eq!(drops.get(), 0);

        tokio::io::AsyncWriteExt::shutdown(&mut parent)
            .await
            .unwrap();
    },);

    assert!(result.is_err());
    assert!(owners.is_some());
    assert_eq!(drops.get(), 0);
    no_receipt(&parent);

    drop(owners.take());
    assert_eq!(drops.get(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn queued_premature_ack_is_not_admitted() {
    let (mut consumer, mut parent) = UnixStream::pair().unwrap();
    let (mut owners, drops) = retained_owner();

    tokio::io::AsyncWriteExt::write_all(&mut parent, b"TARGET_TERMINATED\n")
        .await
        .unwrap();
    consumer.readable().await.unwrap();

    let result = terminal_proof(&mut consumer, &mut owners).await;

    assert!(result.is_err());
    assert!(owners.is_some());
    assert_eq!(drops.get(), 0);
    no_receipt(&parent);

    drop(owners.take());
    assert_eq!(drops.get(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn trailing_ack_data_is_not_admitted() {
    let (mut consumer, mut parent) = UnixStream::pair().unwrap();
    let (mut owners, drops) = retained_owner();

    let (result, ()) = tokio::join!(terminal_proof(&mut consumer, &mut owners), async {
        receipt(&mut parent, b"STREAM_VERIFIED\n").await;
        assert_eq!(drops.get(), 0);

        tokio::io::AsyncWriteExt::write_all(&mut parent, b"TARGET_TERMINATED\nEXTRA\n")
            .await
            .unwrap();
    },);

    assert!(result.is_err());
    assert!(owners.is_some());
    assert_eq!(drops.get(), 0);
    no_receipt(&parent);

    drop(owners.take());
    assert_eq!(drops.get(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn cancellation_while_waiting_leaves_callers_owners_available() {
    let (mut consumer, mut parent) = UnixStream::pair().unwrap();
    let (mut owners, drops) = retained_owner();

    {
        let operation = terminal_proof(&mut consumer, &mut owners);
        tokio::pin!(operation);

        tokio::select! {
            biased;
            () = receipt(&mut parent, b"STREAM_VERIFIED\n") => {
                assert_eq!(drops.get(), 0);
            }
            result = &mut operation => {
                panic!("proof completed before acknowledgment: {result:?}");
            }
        }
    }

    assert!(owners.is_some());
    assert_eq!(drops.get(), 0);
    no_receipt(&parent);

    drop(owners.take());
    assert_eq!(drops.get(), 1);
}

struct PartialPublication {
    written: Vec<u8>,
    checks: Cell<usize>,
    blocked: bool,
    reads: usize,
}

impl PartialPublication {
    fn new() -> Self {
        Self {
            written: Vec::new(),
            checks: Cell::new(0),
            blocked: false,
            reads: 0,
        }
    }
}

impl ProofControl for PartialPublication {
    fn check_pending_input(&self) -> super::Result<()> {
        self.checks.set(self.checks.get() + 1);
        Ok(())
    }
}

impl tokio::io::AsyncRead for PartialPublication {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        _output: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.reads += 1;
        Poll::Pending
    }
}

impl tokio::io::AsyncWrite for PartialPublication {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.blocked {
            return Poll::Pending;
        }

        let count = input.len().min(3);
        self.written.extend_from_slice(&input[..count]);
        self.blocked = true;
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[test]
fn cancellation_during_partial_publication_retains_callers_owners() {
    let mut control = PartialPublication::new();
    let (mut owners, drops) = retained_owner();

    {
        let mut operation = Box::pin(terminal_proof(&mut control, &mut owners));
        let waker = futures::task::noop_waker();
        let mut context = Context::from_waker(&waker);

        assert!(operation.as_mut().poll(&mut context).is_pending());
    }

    assert_eq!(control.checks.get(), 1);
    assert_eq!(control.written, b"STR");
    assert!(control.written.len() < b"STREAM_VERIFIED\n".len());
    assert_eq!(control.reads, 0);
    assert!(owners.is_some());
    assert_eq!(drops.get(), 0);

    drop(owners.take());
    assert_eq!(drops.get(), 1);
}

#[test]
fn diagnostics_emit_only_fixed_allowlisted_labels() {
    assert_eq!(super::failure_label("stream-close"), "stream-close",);
    assert_eq!(super::failure_label("client-bootstrap"), "client-bootstrap",);
    assert_eq!(
        super::failure_label("/private/path: owned-response:secret"),
        "unknown-component-failure",
    );
}

struct AckReadPending {
    written: Vec<u8>,
    reads: usize,
    checks: Cell<usize>,
}

impl AckReadPending {
    fn new() -> Self {
        Self {
            written: Vec::new(),
            reads: 0,
            checks: Cell::new(0),
        }
    }
}

impl ProofControl for AckReadPending {
    fn check_pending_input(&self) -> super::Result<()> {
        self.checks.set(self.checks.get() + 1);
        Ok(())
    }
}

impl tokio::io::AsyncRead for AckReadPending {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        _output: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.reads += 1;
        Poll::Pending
    }
}

impl tokio::io::AsyncWrite for AckReadPending {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.written.extend_from_slice(input);
        Poll::Ready(Ok(input.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[test]
fn cancellation_after_ack_read_is_entered_retains_callers_owners() {
    let mut control = AckReadPending::new();
    let (mut owners, drops) = retained_owner();

    {
        let mut operation = Box::pin(terminal_proof(&mut control, &mut owners));
        let waker = futures::task::noop_waker();
        let mut context = Context::from_waker(&waker);

        assert!(operation.as_mut().poll(&mut context).is_pending());
        assert_eq!(drops.get(), 0);
    }

    assert_eq!(control.written, b"STREAM_VERIFIED\n");
    assert_eq!(control.reads, 1);
    assert_eq!(control.checks.get(), 1);
    assert!(owners.is_some());
    assert_eq!(drops.get(), 0);

    drop(owners.take());
    assert_eq!(drops.get(), 1);
}
