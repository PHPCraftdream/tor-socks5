use super::*;
use std::collections::VecDeque;
use std::fmt;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::Mutex;
use std::task::Waker;

use futures::FutureExt;
use tokio::io::AsyncWrite;

const LOCAL: &str = "[::1]:44444";
const PEER: &str = "[::1]:5353";

#[derive(Default)]
struct State {
    read_polls: usize,
    write_polls: usize,
    offered: Vec<usize>,
    written: Vec<u8>,
    flushes: usize,
    shutdowns: usize,
    nodelays: usize,
    dropped: bool,
    waker: Option<Waker>,
    cleanup: Vec<(&'static str, Vec<String>)>,
}

struct ErrorWitness {
    token: Arc<()>,
    state: Arc<Mutex<State>>,
}

impl fmt::Debug for ErrorWitness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ErrorWitness")
    }
}

impl fmt::Display for ErrorWitness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("private-error-content")
    }
}

impl std::error::Error for ErrorWitness {}

impl Drop for ErrorWitness {
    fn drop(&mut self) {
        let lines = listener::capture_snapshot();
        self.state
            .lock()
            .unwrap()
            .cleanup
            .push(("error_drop", lines));
    }
}

enum ReadStep {
    Byte(u8),
    Error(io::Error),
    Eof,
    Pending,
}

enum WriteStep {
    Accept(usize),
    Error(io::Error),
    Interrupted,
    Pending,
    Zero,
}

struct Script {
    reads: VecDeque<ReadStep>,
    writes: VecDeque<WriteStep>,
    state: Arc<Mutex<State>>,
}

impl Script {
    fn new() -> Self {
        Self {
            reads: VecDeque::new(),
            writes: VecDeque::new(),
            state: Arc::new(Mutex::new(State::default())),
        }
    }

    fn error(&self, token: &Arc<()>) -> io::Error {
        io::Error::new(
            io::ErrorKind::ConnectionReset,
            ErrorWitness {
                token: Arc::clone(token),
                state: Arc::clone(&self.state),
            },
        )
    }
}

impl listener::TcpIo for Script {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(LOCAL.parse().unwrap())
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(PEER.parse().unwrap())
    }

    fn set_nodelay(&self, enabled: bool) -> io::Result<()> {
        assert!(enabled);
        self.state.lock().unwrap().nodelays += 1;
        Ok(())
    }
}

impl AsyncRead for Script {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.state.lock().unwrap().read_polls += 1;
        match this.reads.pop_front().unwrap_or(ReadStep::Eof) {
            ReadStep::Byte(byte) => {
                assert!(buffer.remaining() > 0);
                buffer.put_slice(&[byte]);
                Poll::Ready(Ok(()))
            }
            ReadStep::Error(error) => Poll::Ready(Err(error)),
            ReadStep::Eof => Poll::Ready(Ok(())),
            ReadStep::Pending => {
                this.reads.push_front(ReadStep::Pending);
                this.state.lock().unwrap().waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

impl AsyncWrite for Script {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        {
            let mut state = this.state.lock().unwrap();
            state.write_polls += 1;
            state.offered.push(bytes.len());
        }
        match this
            .writes
            .pop_front()
            .unwrap_or(WriteStep::Accept(bytes.len()))
        {
            WriteStep::Accept(limit) => {
                let written = bytes.len().min(limit);
                this.state
                    .lock()
                    .unwrap()
                    .written
                    .extend_from_slice(&bytes[..written]);
                Poll::Ready(Ok(written))
            }
            WriteStep::Error(error) => Poll::Ready(Err(error)),
            WriteStep::Interrupted => Poll::Ready(Err(io::ErrorKind::Interrupted.into())),
            WriteStep::Pending => {
                this.writes.push_front(WriteStep::Pending);
                this.state.lock().unwrap().waker = Some(cx.waker().clone());
                Poll::Pending
            }
            WriteStep::Zero => Poll::Ready(Ok(0)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.state.lock().unwrap().flushes += 1;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.state.lock().unwrap().shutdowns += 1;
        Poll::Ready(Ok(()))
    }
}

impl Drop for Script {
    fn drop(&mut self) {
        let lines = listener::capture_snapshot();
        let mut state = self.state.lock().unwrap();
        state.dropped = true;
        state.cleanup.push(("stream_drop", lines));
    }
}

struct Capture;

impl Capture {
    fn new() -> Self {
        listener::take_capture();
        listener::set_capture_mode(true);
        Self
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        listener::set_capture_mode(false);
        listener::take_capture();
    }
}

fn framed(bytes: &[u8]) -> VecDeque<ReadStep> {
    let prefix = u16::try_from(bytes.len()).unwrap().to_be_bytes();
    prefix
        .into_iter()
        .chain(bytes.iter().copied())
        .map(ReadStep::Byte)
        .collect()
}

fn assert_client_line(line: &str, stage: &str, written: usize, read: usize) {
    assert!(line.starts_with("tcp_client:"));
    assert!(line.contains(&format!("local=Some({LOCAL})")));
    assert!(line.contains(&format!("peer=Some({PEER})")));
    assert!(line.contains(&format!("stage={stage}")));
    assert!(line.contains(&format!("observed_written={written}")));
    assert!(line.contains(&format!("observed_read={read}")));
    assert!(!line.contains("private-error-content"));
    assert!(!line.contains("private-query.example"));
}

fn assert_handler_line(line: &str, stage: &str, terminal: &str, writes: usize) {
    assert!(line.starts_with("tcp_diag:"));
    assert!(line.contains(&format!("local=Some({LOCAL})")));
    assert!(line.contains(&format!("peer=Some({PEER})")));
    assert!(line.contains(&format!("stage={stage}")));
    assert!(line.contains(&format!("terminal={terminal}")));
    assert!(line.contains(&format!("observed_writes={writes}")));
    assert!(!line.contains("private-error-content"));
}

#[tokio::test]
async fn actual_exchange_records_each_write_failure_before_error_cleanup() {
    for case in 0..3 {
        let _capture = Capture::new();
        let mut script = Script::new();
        let state = Arc::clone(&script.state);
        let token = Arc::new(());
        let error = script.error(&token);
        let (stage, written, polls) = match case {
            0 => {
                script.writes.push_back(WriteStep::Error(error));
                ("prefix_first", 0, 1)
            }
            1 => {
                script
                    .writes
                    .extend([WriteStep::Accept(1), WriteStep::Error(error)]);
                ("prefix_second", 1, 2)
            }
            _ => {
                script.writes.extend([
                    WriteStep::Accept(1),
                    WriteStep::Accept(1),
                    WriteStep::Accept(1),
                    WriteStep::Error(error),
                ]);
                ("body", 3, 4)
            }
        };
        let request = request("private-query.example.", RecordType::A, 31);
        let result = AssertUnwindSafe(tcp_exchange(&mut script, &request))
            .catch_unwind()
            .await;
        assert!(result.is_err());
        let lines = listener::take_capture();
        assert_eq!(lines.len(), 1);
        assert_client_line(&lines[0], stage, written, 0);
        assert!(lines[0].contains("kind=ConnectionReset"));
        let state = state.lock().unwrap();
        assert_eq!(state.nodelays, 1);
        assert_eq!(state.write_polls, polls);
        assert_eq!(state.read_polls, 0);
        assert_eq!(state.written.len(), written);
        assert_eq!(state.flushes, 0);
        assert_eq!(state.shutdowns, 0);
        assert!(!state.dropped);
        assert_eq!(state.cleanup.len(), 1);
        assert_eq!(state.cleanup[0].0, "error_drop");
        assert_eq!(state.cleanup[0].1, lines);
    }
}

#[tokio::test]
async fn actual_exchange_records_partial_response_error_before_cleanup() {
    let _capture = Capture::new();
    let mut script = Script::new();
    let state = Arc::clone(&script.state);
    let token = Arc::new(());
    let error = script.error(&token);
    script
        .reads
        .extend([ReadStep::Byte(0), ReadStep::Error(error)]);
    let request = request("private-query.example.", RecordType::A, 32);
    let written = request.to_vec().unwrap().len() + 2;
    let result = AssertUnwindSafe(tcp_exchange(&mut script, &request))
        .catch_unwind()
        .await;
    assert!(result.is_err());
    let lines = listener::take_capture();
    assert_eq!(lines.len(), 1);
    assert_client_line(&lines[0], "response", written, 1);
    let state = state.lock().unwrap();
    assert_eq!(state.read_polls, 2);
    assert_eq!(state.flushes, 0);
    assert_eq!(state.shutdowns, 0);
    assert_eq!(state.cleanup.len(), 1);
    assert_eq!(state.cleanup[0].0, "error_drop");
    assert_eq!(state.cleanup[0].1, lines);
}

#[tokio::test]
async fn actual_exchange_eof_remains_terminal() {
    let _capture = Capture::new();
    let mut script = Script::new();
    script.reads.push_back(ReadStep::Eof);
    let request = request("private-query.example.", RecordType::A, 33);
    let written = request.to_vec().unwrap().len() + 2;
    let result = AssertUnwindSafe(tcp_exchange(&mut script, &request))
        .catch_unwind()
        .await;
    assert!(result.is_err());
    let lines = listener::take_capture();
    assert_eq!(lines.len(), 1);
    assert_client_line(&lines[0], "response", written, 0);
    assert!(lines[0].contains("outcome=eof"));
}

#[tokio::test]
async fn actual_exchange_preserves_fragmentation_without_error_log() {
    let _capture = Capture::new();
    let mut script = Script::new();
    let request = request("private-query.example.", RecordType::A, 34);
    let request_bytes = request.to_vec().unwrap();
    let reply = Message::new(34, MessageType::Response, OpCode::Query);
    let reply_bytes = reply.to_vec().unwrap();
    script.reads = framed(&reply_bytes);

    let actual = tcp_exchange(&mut script, &request).await;

    assert!(actual.to_vec().unwrap() == reply_bytes);
    assert!(listener::take_capture().is_empty());

    let state = script.state.lock().unwrap();
    let mut expected_offered = vec![1, 1];
    expected_offered.extend(request_bytes.chunks(3).map(<[u8]>::len));
    assert_eq!(state.offered, expected_offered);
    assert_eq!(state.write_polls, expected_offered.len());

    let prefix = u16::try_from(request_bytes.len()).unwrap().to_be_bytes();
    let expected_written: Vec<_> = prefix
        .into_iter()
        .chain(request_bytes.iter().copied())
        .collect();
    assert!(state.written == expected_written);
    assert_eq!(state.read_polls, reply_bytes.len() + 2);
    assert_eq!(state.nodelays, 1);
    assert_eq!(state.flushes, 0);
    assert_eq!(state.shutdowns, 0);
    assert!(!state.dropped);
    assert!(state.cleanup.is_empty());
}

#[tokio::test]
async fn actual_exchange_raw_interrupted_is_terminal_without_retry() {
    let _capture = Capture::new();
    let mut script = Script::new();
    script.writes.push_back(WriteStep::Interrupted);
    let request = request("private-query.example.", RecordType::A, 37);

    let result = AssertUnwindSafe(tcp_exchange(&mut script, &request))
        .catch_unwind()
        .await;

    assert!(result.is_err());
    let lines = listener::take_capture();
    assert_eq!(lines.len(), 1);
    assert_client_line(&lines[0], "prefix_first", 0, 0);
    assert!(lines[0].contains("outcome=error"));
    assert!(lines[0].contains("kind=Interrupted"));
    assert!(lines[0].contains("os=None"));

    let state = script.state.lock().unwrap();
    assert_eq!(state.offered, vec![1]);
    assert_eq!(state.write_polls, 1);
    assert_eq!(state.read_polls, 0);
    assert!(state.written.is_empty());
    assert_eq!(state.nodelays, 1);
    assert_eq!(state.flushes, 0);
    assert_eq!(state.shutdowns, 0);
    assert!(!state.dropped);
    assert!(state.cleanup.is_empty());
}

#[tokio::test]
async fn actual_exchange_interrupted_is_recorded_before_original_error_cleanup() {
    for partial_body in [false, true] {
        let _capture = Capture::new();
        let mut script = Script::new();
        let state = Arc::clone(&script.state);
        let token = Arc::new(());
        let error = io::Error::new(
            io::ErrorKind::Interrupted,
            ErrorWitness {
                token: Arc::clone(&token),
                state: Arc::clone(&state),
            },
        );

        let request = request("private-query.example.", RecordType::A, 38);
        let request_bytes = request.to_vec().unwrap();
        let prefix = u16::try_from(request_bytes.len()).unwrap().to_be_bytes();

        let (stage, written, polls, expected_offered, expected_written) = if partial_body {
            script.writes.extend([
                WriteStep::Accept(1),
                WriteStep::Accept(1),
                WriteStep::Accept(1),
                WriteStep::Error(error),
            ]);
            (
                "body",
                3,
                4,
                vec![1, 1, 3, 2],
                vec![prefix[0], prefix[1], request_bytes[0]],
            )
        } else {
            script.writes.push_back(WriteStep::Error(error));
            ("prefix_first", 0, 1, vec![1], Vec::new())
        };

        let result = AssertUnwindSafe(tcp_exchange(&mut script, &request))
            .catch_unwind()
            .await;

        assert!(result.is_err());
        let lines = listener::take_capture();
        assert_eq!(lines.len(), 1);
        assert_client_line(&lines[0], stage, written, 0);
        assert!(lines[0].contains("outcome=error"));
        assert!(lines[0].contains("kind=Interrupted"));
        assert!(lines[0].contains("os=None"));

        let state = state.lock().unwrap();
        assert_eq!(state.offered, expected_offered);
        assert_eq!(state.write_polls, polls);
        assert_eq!(state.read_polls, 0);
        assert!(state.written == expected_written);
        assert_eq!(state.written.len(), written);
        assert_eq!(state.nodelays, 1);
        assert_eq!(state.flushes, 0);
        assert_eq!(state.shutdowns, 0);
        assert!(!state.dropped);
        assert_eq!(state.cleanup.len(), 1);
        assert_eq!(state.cleanup[0].0, "error_drop");
        assert_eq!(state.cleanup[0].1, lines);
        assert_eq!(Arc::strong_count(&token), 1);
    }
}

#[tokio::test]
async fn exchange_body_returns_original_error_and_raw_os_code() {
    let _capture = Capture::new();
    let mut script = Script::new();
    let token = Arc::new(());
    let error = script.error(&token);
    script.writes.push_back(WriteStep::Error(error));
    let returned = tcp_exchange_io::exchange_frame(
        &mut script,
        b"x",
        Some(LOCAL.parse().unwrap()),
        Some(PEER.parse().unwrap()),
    )
    .await
    .unwrap_err();
    let retained = returned
        .get_ref()
        .and_then(|error| error.downcast_ref::<ErrorWitness>())
        .expect("original error payload");
    assert!(Arc::ptr_eq(&retained.token, &token));
    assert!(script.state.lock().unwrap().cleanup.is_empty());
    assert_eq!(listener::capture_snapshot().len(), 1);
    drop(returned);
    assert_eq!(script.state.lock().unwrap().cleanup.len(), 1);

    listener::take_capture();
    let mut script = Script::new();
    script
        .writes
        .push_back(WriteStep::Error(io::Error::from_raw_os_error(10054)));
    let returned = tcp_exchange_io::exchange_frame(&mut script, b"x", None, None)
        .await
        .unwrap_err();
    assert_eq!(returned.raw_os_error(), Some(10054));
    let lines = listener::take_capture();
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("os=Some(10054)"));
}

#[tokio::test]
async fn actual_exchange_write_zero_is_not_success_or_a_read_attempt() {
    let _capture = Capture::new();
    let mut script = Script::new();
    script.writes.push_back(WriteStep::Zero);
    let request = request("private-query.example.", RecordType::A, 35);
    assert!(AssertUnwindSafe(tcp_exchange(&mut script, &request))
        .catch_unwind()
        .await
        .is_err());
    let lines = listener::take_capture();
    assert_eq!(lines.len(), 1);
    assert_client_line(&lines[0], "prefix_first", 0, 0);
    assert!(lines[0].contains("kind=WriteZero"));
    assert_eq!(script.state.lock().unwrap().read_polls, 0);
}

#[tokio::test]
async fn actual_exchange_pending_cancellation_adds_no_poll_or_terminal() {
    for pending_read in [false, true] {
        let _capture = Capture::new();
        let mut script = Script::new();
        if pending_read {
            script.reads.push_back(ReadStep::Pending);
        } else {
            script.writes.push_back(WriteStep::Pending);
        }
        let state = Arc::clone(&script.state);
        let request = request("private-query.example.", RecordType::A, 36);
        let mut exchange = Box::pin(tcp_exchange(&mut script, &request));
        {
            let state = state.lock().unwrap();
            assert_eq!(state.read_polls, 0);
            assert_eq!(state.write_polls, 0);
            assert_eq!(state.nodelays, 0);
        }
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(exchange.as_mut().poll(&mut cx).is_pending());
        let before = {
            let state = state.lock().unwrap();
            (state.read_polls, state.write_polls)
        };
        assert_eq!(before.0, usize::from(pending_read));
        if !pending_read {
            assert_eq!(before.1, 1);
        }
        drop(exchange);
        let state = state.lock().unwrap();
        assert_eq!((state.read_polls, state.write_polls), before);
        assert!(!state.dropped);
        assert_eq!(state.flushes, 0);
        assert_eq!(state.shutdowns, 0);
        assert!(listener::take_capture().is_empty());
    }
}

#[tokio::test]
async fn actual_handler_read_failure_keeps_write_fact_before_error_and_stream_cleanup() {
    let _capture = Capture::new();
    let mut script = Script::new();
    let request = request("localhost.", RecordType::A, 41);
    script.reads = framed(&request.to_vec().unwrap());
    let token = Arc::new(());
    let error = script.error(&token);
    script.reads.push_back(ReadStep::Error(error));
    let state = Arc::clone(&script.state);
    listener::handle_tcp_gated(
        script,
        ctx(vec![], vec![]),
        Arc::new(Semaphore::new(64)),
        || std::future::ready(()),
    )
    .await;
    let lines = listener::take_capture();
    assert_eq!(lines.len(), 1);
    assert_handler_line(
        &lines[0],
        "read",
        "read_error(kind=ConnectionReset,os=None)",
        1,
    );
    let state = state.lock().unwrap();
    assert_eq!(state.flushes, 1);
    assert_eq!(state.shutdowns, 0);
    assert_eq!(state.cleanup.len(), 2);
    assert_eq!(state.cleanup[0].0, "error_drop");
    assert_eq!(state.cleanup[0].1, lines);
    assert_eq!(state.cleanup[1].0, "stream_drop");
    assert_eq!(state.cleanup[1].1, lines);
}

#[tokio::test]
async fn actual_handler_partial_write_failure_is_observed_before_error_cleanup() {
    let _capture = Capture::new();
    let mut script = Script::new();
    script.reads = framed(&request("localhost.", RecordType::A, 42).to_vec().unwrap());
    let token = Arc::new(());
    let error = script.error(&token);
    script
        .writes
        .extend([WriteStep::Accept(1), WriteStep::Error(error)]);
    let state = Arc::clone(&script.state);
    listener::handle_tcp_gated(
        script,
        ctx(vec![], vec![]),
        Arc::new(Semaphore::new(64)),
        || std::future::ready(()),
    )
    .await;
    let lines = listener::take_capture();
    assert_eq!(lines.len(), 1);
    assert_handler_line(
        &lines[0],
        "write",
        "write_error(kind=ConnectionReset,os=None)",
        0,
    );
    let state = state.lock().unwrap();
    assert_eq!(state.written.len(), 1);
    assert_eq!(state.flushes, 0);
    assert_eq!(state.cleanup.len(), 2);
    assert_eq!(state.cleanup[0].0, "error_drop");
    assert_eq!(state.cleanup[0].1, lines);
    assert_eq!(state.cleanup[1].0, "stream_drop");
    assert_eq!(state.cleanup[1].1, lines);
}

#[tokio::test]
async fn actual_handler_eof_is_classified_once() {
    let _capture = Capture::new();
    let mut script = Script::new();
    script.reads.push_back(ReadStep::Eof);
    let state = Arc::clone(&script.state);
    listener::handle_tcp_gated(
        script,
        ctx(vec![], vec![]),
        Arc::new(Semaphore::new(64)),
        || std::future::ready(()),
    )
    .await;
    let lines = listener::take_capture();
    assert_eq!(lines.len(), 1);
    assert_handler_line(&lines[0], "read", "eof", 0);
    let state = state.lock().unwrap();
    assert_eq!(state.cleanup.len(), 1);
    assert_eq!(state.cleanup[0].0, "stream_drop");
    assert_eq!(state.cleanup[0].1, lines);
}

#[tokio::test]
async fn actual_handler_cancel_after_response_keeps_unclassified_drop_and_write_fact() {
    let _capture = Capture::new();
    let mut script = Script::new();
    let bytes = request("localhost.", RecordType::A, 43).to_vec().unwrap();
    script.reads = framed(&bytes);
    script.reads.push_back(ReadStep::Pending);
    let state = Arc::clone(&script.state);
    let mut handler = Box::pin(listener::handle_tcp_gated(
        script,
        ctx(vec![], vec![]),
        Arc::new(Semaphore::new(64)),
        || std::future::ready(()),
    ));
    assert_eq!(state.lock().unwrap().read_polls, 0);
    let waker = futures::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(handler.as_mut().poll(&mut cx).is_pending());
    assert!(listener::capture_snapshot().is_empty());
    let before = {
        let state = state.lock().unwrap();
        assert_eq!(state.read_polls, bytes.len() + 3);
        assert_eq!(state.flushes, 1);
        (state.read_polls, state.write_polls)
    };
    drop(handler);
    let lines = listener::take_capture();
    assert_eq!(lines.len(), 1);
    assert_handler_line(&lines[0], "read", "unclassified_drop", 1);
    let state = state.lock().unwrap();
    assert_eq!((state.read_polls, state.write_polls), before);
    assert_eq!(state.shutdowns, 0);
    assert_eq!(state.cleanup.len(), 1);
    assert_eq!(state.cleanup[0].0, "stream_drop");
    assert_eq!(state.cleanup[0].1, lines);
}
