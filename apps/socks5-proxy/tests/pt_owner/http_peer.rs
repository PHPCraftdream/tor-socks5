use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{timeout_at, Duration, Instant};

const LIMIT: usize = 4096;
const RESPONSE: &[u8] =
    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
const REQUEST: &[u8] = b"GET /bridge?token=x HTTP/1.1\r\nHost: example.test:443\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: fixed-test-key\r\nSec-WebSocket-Version: 13\r\n\r\n";
const TARGET: &str = "/bridge?token=x";
const HOST: &str = "example.test:443";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Deadline,
    Io,
    HeaderLimit,
    Incomplete,
    Malformed,
    WrongTarget,
    WrongHost,
    NotUpgrade,
}

/// Observation after writing and flushing the response, not proof that the client read 101.
/// None means EOF without a raw byte; the caller receives the stream for further cleanup.
pub(crate) struct RawAfterResponseWrite<S> {
    pub(crate) stream: S,
    pub(crate) raw: Option<u8>,
}

/// cancel-safe: NO — cancellation drops the owned stream; a partial exchange is not retried.
pub(crate) async fn observe<S>(
    stream: S,
    target: &str,
    host: &str,
    deadline: Instant,
) -> Result<RawAfterResponseWrite<S>, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if Instant::now() >= deadline {
        return Err(Error::Deadline);
    }
    timeout_at(deadline, exchange(stream, target, host))
        .await
        .map_err(|_| Error::Deadline)?
}

/// cancel-safe: NO — timeout drops the owned stream and its partially read request.
async fn exchange<S>(
    mut stream: S,
    target: &str,
    host: &str,
) -> Result<RawAfterResponseWrite<S>, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut request = Vec::with_capacity(512);
    loop {
        if request.len() == LIMIT {
            return Err(Error::HeaderLimit);
        }
        let mut byte = [0; 1];
        if stream.read(&mut byte).await.map_err(|_| Error::Io)? == 0 {
            return Err(Error::Incomplete);
        }
        request.push(byte[0]);
        if request.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    validate(&request, target, host)?;
    stream.write_all(RESPONSE).await.map_err(|_| Error::Io)?;
    stream.flush().await.map_err(|_| Error::Io)?;
    let mut byte = [0; 1];
    let count = stream.read(&mut byte).await.map_err(|_| Error::Io)?;
    Ok(RawAfterResponseWrite {
        stream,
        raw: (count == 1).then_some(byte[0]),
    })
}

fn validate(request: &[u8], target: &str, host: &str) -> Result<(), Error> {
    if !request.ends_with(b"\r\n\r\n") || !request.is_ascii() {
        return Err(Error::Malformed);
    }
    let text = std::str::from_utf8(request).map_err(|_| Error::Malformed)?;
    let mut lines = text[..text.len() - 4].split("\r\n");
    let first = lines.next().ok_or(Error::Malformed)?;
    if first.bytes().any(|b| b.is_ascii_control()) {
        return Err(Error::Malformed);
    }
    let mut words = first.split(' ');
    if words.next() != Some("GET")
        || words.next() != Some(target)
        || words.next() != Some("HTTP/1.1")
        || words.next().is_some()
    {
        return Err(Error::WrongTarget);
    }
    let mut seen = 0u8;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(Error::Malformed)?;
        if name.is_empty()
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || value.bytes().any(|b| b.is_ascii_control() && b != b'\t')
        {
            return Err(Error::Malformed);
        }
        let value = value.trim_matches([' ', '\t']);
        let (bit, valid) = if name.eq_ignore_ascii_case("host") {
            (1, value == host)
        } else if name.eq_ignore_ascii_case("upgrade") {
            (2, value.eq_ignore_ascii_case("websocket"))
        } else if name.eq_ignore_ascii_case("connection") {
            (4, value.eq_ignore_ascii_case("upgrade"))
        } else if name.eq_ignore_ascii_case("sec-websocket-key") {
            (
                8,
                !value.is_empty() && !value.bytes().any(|b| b.is_ascii_whitespace()),
            )
        } else if name.eq_ignore_ascii_case("sec-websocket-version") {
            (16, value == "13")
        } else {
            return Err(Error::Malformed);
        };
        if seen & bit != 0 {
            return Err(Error::Malformed);
        }
        seen |= bit;
        if !valid {
            return Err(if bit == 1 {
                Error::WrongHost
            } else {
                Error::NotUpgrade
            });
        }
    }
    if seen & 1 == 0 {
        return Err(Error::WrongHost);
    }
    if seen != 31 {
        return Err(Error::NotUpgrade);
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Client {
    Raw,
    Eof,
    Reject,
}

/// cancel-safe: NO — the timed region owns both duplex halves and drops them on cancellation.
async fn control(
    request: &[u8],
    target: &str,
    host: &str,
    mode: Client,
    expected: Result<Option<u8>, Error>,
) -> Result<(), &'static str> {
    let deadline = Instant::now() + Duration::from_secs(3);
    timeout_at(deadline, async move {
        let (server, mut client) = tokio::io::duplex(8192);
        let server_side = async move {
            observe(server, target, host, deadline)
                .await
                .map(|observation| observation.raw)
        };
        let client_side = async move {
            for fragment in request.chunks(7) {
                client.write_all(fragment).await.map_err(|_| Error::Io)?;
            }
            if matches!(mode, Client::Reject) {
                client.shutdown().await.map_err(|_| Error::Io)?;
                return Ok(());
            }
            let mut response = [0; RESPONSE.len()];
            client
                .read_exact(&mut response)
                .await
                .map_err(|_| Error::Io)?;
            if response.as_slice() != RESPONSE {
                return Err(Error::Malformed);
            }
            match mode {
                Client::Raw => client.write_all(&[0x7e]).await,
                Client::Eof | Client::Reject => client.shutdown().await,
            }
            .map_err(|_| Error::Io)
        };
        let (actual, sent) = tokio::join!(server_side, client_side);
        sent?;
        if actual != expected {
            return Err(Error::Malformed);
        }
        Ok(())
    })
    .await
    .map_err(|_| "HTTP peer control deadline")?
    .map_err(|_| "HTTP peer control mismatch")
}

/// cancel-safe: NO — cancellation by the outer guard drops both halves.
async fn deadline_control(request: &[u8], expect_response: bool) -> Result<(), &'static str> {
    let guard = Instant::now() + Duration::from_secs(3);
    timeout_at(guard, async {
        let (server, mut client) = tokio::io::duplex(8192);
        let deadline = Instant::now() + Duration::from_secs(1);
        let observed = observe(server, TARGET, HOST, deadline);
        tokio::pin!(observed);
        // The first poll must enter a pending exchange before the deadline.
        if futures::poll!(observed.as_mut()).is_ready() {
            return Err("HTTP peer did not enter pending exchange");
        }
        let sender = async move {
            client
                .write_all(request)
                .await
                .map_err(|_| "deadline request write")?;
            if expect_response {
                let mut response = [0; RESPONSE.len()];
                client
                    .read_exact(&mut response)
                    .await
                    .map_err(|_| "deadline response read")?;
                if response.as_slice() != RESPONSE {
                    return Err("deadline response mismatch");
                }
            }
            // join! keeps the returned stream open while the peer awaits its deadline.
            Ok::<_, &'static str>(client)
        };
        let (result, retained) = tokio::join!(observed, sender);
        let mut client = retained?;
        if result.err() != Some(Error::Deadline) {
            return Err("pending HTTP peer missed deadline");
        }
        let mut byte = [0; 1];
        if client
            .read(&mut byte)
            .await
            .map_err(|_| "deadline closure read")?
            != 0
        {
            return Err("deadline did not close HTTP peer");
        }
        Ok(())
    })
    .await
    .map_err(|_| "HTTP peer deadline control guard")?
}

/// Synthetic controls; integration must call this explicitly from the harness=false entrypoint.
/// cancel-safe: NO — cancellation is terminal and leaves no tasks or external resources.
pub(crate) async fn run_controls() -> Result<(), &'static str> {
    control(REQUEST, TARGET, HOST, Client::Raw, Ok(Some(0x7e))).await?;
    control(REQUEST, TARGET, HOST, Client::Eof, Ok(None)).await?;
    for (request, target, host, error) in [
        (REQUEST, "/wrong", HOST, Error::WrongTarget),
        (REQUEST, TARGET, "wrong.test", Error::WrongHost),
        (
            b"NOT HTTP\r\n\r\n".as_slice(),
            TARGET,
            HOST,
            Error::WrongTarget,
        ),
        (
            b"GET /bridge HTTP/1.1\r\n".as_slice(),
            TARGET,
            HOST,
            Error::Incomplete,
        ),
        (b"".as_slice(), TARGET, HOST, Error::Incomplete),
        (
            b"GET /bridge?token=x HTTP/1.1\r\nHost: example.test:443\r\n\r\n".as_slice(),
            TARGET,
            HOST,
            Error::NotUpgrade,
        ),
        (
            b"GET /bridge?token=x HTTP/1.1\r\nBad\r\n\r\n".as_slice(),
            TARGET,
            HOST,
            Error::Malformed,
        ),
    ] {
        control(request, target, host, Client::Reject, Err(error)).await?;
    }
    for header in [
        "Host: example.test:443\r\n",
        "Upgrade: websocket\r\n",
        "Connection: Upgrade\r\n",
        "Sec-WebSocket-Key: fixed-test-key\r\n",
        "Sec-WebSocket-Version: 13\r\n",
    ] {
        let mut duplicate = REQUEST[..REQUEST.len() - 2].to_vec();
        duplicate.extend_from_slice(header.as_bytes());
        duplicate.extend_from_slice(b"\r\n");
        control(
            &duplicate,
            TARGET,
            HOST,
            Client::Reject,
            Err(Error::Malformed),
        )
        .await?;
    }
    for bad in [0, 1, 0x7f, b'\n', b'\r'] {
        let mut malformed = REQUEST.to_vec();
        let position = malformed
            .windows(b"fixed-test-key".len())
            .position(|w| w == b"fixed-test-key")
            .ok_or("missing control marker")?;
        malformed[position] = bad;
        control(
            &malformed,
            TARGET,
            HOST,
            Client::Reject,
            Err(Error::Malformed),
        )
        .await?;
    }
    let oversized = vec![b'a'; LIMIT + 1];
    control(
        &oversized,
        TARGET,
        HOST,
        Client::Reject,
        Err(Error::HeaderLimit),
    )
    .await?;
    deadline_control(b"", false).await?;
    deadline_control(b"GET /bridge?token=x HTTP/1.1\r\n", false).await?;
    deadline_control(REQUEST, true).await?;
    let (server, _client) = tokio::io::duplex(8192);
    if observe(server, TARGET, HOST, Instant::now()).await.err() != Some(Error::Deadline) {
        return Err("expired HTTP peer deadline accepted");
    }
    Ok(())
}

/// cancel-safe: NO — cancellation drops the owned audit and trap-control sockets.
pub(crate) async fn trap_control(
    listener: &tokio::net::TcpListener,
    destination: std::net::SocketAddr,
    deadline: Instant,
) -> Result<(), &'static str> {
    async fn exchange(
        channel: &mut tokio::net::TcpStream,
        message: &str,
    ) -> Result<(), &'static str> {
        channel
            .write_all(message.as_bytes())
            .await
            .map_err(|_| "trap audit request failed")?;
        let mut reply = [0; 3];
        channel
            .read_exact(&mut reply)
            .await
            .map_err(|_| "trap audit response failed")?;
        if &reply != b"OK\n" {
            return Err("trap audit response mismatch");
        }
        Ok(())
    }

    timeout_at(deadline, async {
        let socket = tokio::net::TcpSocket::new_v4().map_err(|_| "trap control socket failed")?;
        socket
            .bind("127.0.0.1:0".parse().unwrap())
            .map_err(|_| "trap control bind failed")?;
        let source = socket
            .local_addr()
            .map_err(|_| "trap control source failed")?;
        let mut channel = tokio::net::TcpStream::connect("127.0.0.1:19053")
            .await
            .map_err(|_| "trap audit connection failed")?;
        exchange(
            &mut channel,
            &format!("BEGIN {} {}\n", source.port(), destination.port()),
        )
        .await?;
        let (connected, accepted) = tokio::join!(socket.connect(destination), listener.accept());
        let mut client = connected.map_err(|_| "trap positive connection failed")?;
        let (mut server, peer) = accepted.map_err(|_| "trap positive accept failed")?;
        if peer != source
            || client
                .local_addr()
                .map_err(|_| "trap client source failed")?
                != source
            || server
                .local_addr()
                .map_err(|_| "trap server address failed")?
                != destination
        {
            return Err("trap control tuple mismatch");
        }
        super::pt_contract::tcp_source_owned_by(&server, std::process::id())
            .map_err(|_| "trap positive ownership failed")?;
        client
            .shutdown()
            .await
            .map_err(|_| "trap client shutdown failed")?;
        let mut byte = [0; 1];
        if server
            .read(&mut byte)
            .await
            .map_err(|_| "trap server EOF failed")?
            != 0
        {
            return Err("trap control unexpected client byte");
        }
        server
            .shutdown()
            .await
            .map_err(|_| "trap server shutdown failed")?;
        if client
            .read(&mut byte)
            .await
            .map_err(|_| "trap client EOF failed")?
            != 0
        {
            return Err("trap control unexpected server byte");
        }
        drop((client, server));
        exchange(&mut channel, "END\n").await?;
        Ok(())
    })
    .await
    .map_err(|_| "trap positive control deadline")?
}

/// cancel-safe: NO — cancellation drops the owned checkpoint socket; no retry.
pub(crate) async fn audit_phase(label: &'static str) {
    let deadline = Instant::now() + Duration::from_secs(1);
    timeout_at(deadline, async {
        let mut channel = tokio::net::TcpStream::connect("127.0.0.1:19053")
            .await
            .map_err(|_| "audit phase connection failed")?;
        channel
            .write_all(format!("PHASE {label}\n").as_bytes())
            .await
            .map_err(|_| "audit phase request failed")?;
        let mut reply = [0; 3];
        channel
            .read_exact(&mut reply)
            .await
            .map_err(|_| "audit phase response failed")?;
        if &reply != b"OK\n" {
            return Err("audit phase response mismatch");
        }
        Ok::<(), &'static str>(())
    })
    .await
    .expect("audit phase deadline elapsed")
    .expect("audit phase exchange failed");
}
