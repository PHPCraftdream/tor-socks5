//! DNS packet projection and finite TCP framing stages.
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::RecordType;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::time::timeout;

pub(super) fn hostname_of(question: &Query) -> String {
    let mut host = question.name().to_string();
    host.make_ascii_lowercase();
    if host.ends_with('.') {
        host.truncate(host.len() - 1);
    }
    host
}

pub(super) fn parse_query(bytes: &[u8]) -> Option<Message> {
    let message = Message::from_vec(bytes).ok()?;
    if message.metadata.message_type != MessageType::Query {
        return None;
    }
    Some(message)
}

pub(super) fn unsupported_response(request: &Message) -> Option<Message> {
    let transfer = request
        .queries
        .iter()
        .any(|question| matches!(question.query_type(), RecordType::AXFR | RecordType::IXFR));
    (request.metadata.op_code != OpCode::Query || transfer)
        .then(|| build_response(request, None, ResponseCode::NotImp))
}

pub(super) fn formerr(request: &Message) -> Message {
    build_response(request, None, ResponseCode::FormErr)
}

/// RFC 1035 §4.1: preserve complete backend sections and rcode, replace the
/// transaction ID/question with the client's own values. AD is never asserted:
/// this frontend does not validate DNSSEC and modifies the packet (RFC 4035).
pub(super) fn build_response(
    request: &Message,
    answer: Option<Message>,
    failure: ResponseCode,
) -> Message {
    let mut reply =
        answer.unwrap_or_else(|| Message::error_msg(request.metadata.id, OpCode::Query, failure));
    reply.metadata.id = request.metadata.id;
    reply.metadata.message_type = MessageType::Response;
    reply.metadata.op_code = request.metadata.op_code;
    reply.metadata.recursion_available = true;
    reply.metadata.recursion_desired = request.metadata.recursion_desired;
    reply.metadata.checking_disabled = request.metadata.checking_disabled;
    reply.metadata.authentic_data = false;
    reply.queries = request.queries.first().cloned().into_iter().collect();
    reply.signature = None;
    // DEVIATION from RFC 6891 §6.1.1: EDNS is not supported by this frontend.
    reply.edns = None;
    reply
}

pub(super) fn encode_udp_response(message: Message) -> Option<Vec<u8>> {
    let bytes = message.to_vec().ok()?;
    if bytes.len() <= 512 {
        return Some(bytes);
    }
    let mut truncated = message.truncate();
    truncated.metadata.authentic_data = false;
    let bytes = truncated.to_vec().ok()?;
    (bytes.len() <= 512).then_some(bytes)
}

/// cancel-safe: yes — send_to is atomic per datagram; output is bounded and
/// best-effort, never retaining receive-loop resources indefinitely.
pub(super) async fn send_udp_response(socket: &UdpSocket, peer: SocketAddr, message: Message) {
    if let Some(bytes) = encode_udp_response(message) {
        let _ = timeout(Duration::from_millis(100), socket.send_to(&bytes, peer)).await;
    }
}

/// cancel-safe: NO for resumable use — partial framing state is discarded.
/// The caller MUST close the connection on timeout/error/cancellation.
/// RFC 1035 §4.2.2: one absolute budget covers prefix AND body, not two budgets.
pub(super) async fn read_framed_message<R: AsyncRead + Unpin>(
    reader: &mut R,
    budget: Duration,
) -> io::Result<Option<Vec<u8>>> {
    timeout(budget, async {
        let mut prefix = [0; 2];
        if reader.read(&mut prefix[..1]).await? == 0 {
            return Ok(None);
        }
        reader.read_exact(&mut prefix[1..]).await?;
        let length = usize::from(u16::from_be_bytes(prefix));
        if length == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "zero-length dns message",
            ));
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body).await?;
        Ok(Some(body))
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "dns frame deadline"))?
}

/// cancel-safe: NO for resumable use — write_all may have emitted a prefix.
/// On error/timeout the caller closes the socket; it never restarts this frame.
pub(super) async fn write_framed_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    body: &[u8],
    budget: Duration,
) -> io::Result<()> {
    let length = u16::try_from(body.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "dns message exceeds 65535 bytes",
        )
    })?;
    // One contiguous write: a separate 2-byte prefix write lets Nagle hold the
    // body until the peer's delayed ACK (about 40 ms on Linux) per response.
    let mut frame = Vec::with_capacity(2 + body.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(body);
    timeout(budget, async {
        writer.write_all(&frame).await?;
        writer.flush().await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "dns write deadline"))?
}
