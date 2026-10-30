//! TLS + HTTP Upgrade handshake for webtunnel.
//!
//! Confirmed from the Go reference implementation (pkg.go.dev and GitHub
//! mirror at blackyblack/webtunnel):
//!
//! - **ALPN**: Go client does NOT set ALPN (`NextProtos` is nil).
//!   We leave ALPN empty for maximum camouflage.
//!
//! - **Sec-WebSocket-Accept**: server does NOT return it — only sends
//!   `Connection: upgrade` + `Upgrade: websocket`. Parser is lenient.
//!
//! - **Sec-WebSocket-Key**: server does NOT validate it. We generate a
//!   proper one (16 random bytes, base64-encoded) for camouflage.

use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;

use crate::dns::{DohMode, DohResolver};
use crate::{
    Error, PrefixStream, PreparedConfig, ResolverCache, TlsContext, WebTunnelConfig,
    WebTunnelStream,
};

/// Generate a Sec-WebSocket-Key (16 random bytes, base64-encoded).
pub fn generate_websocket_key() -> String {
    let mut buf = [0u8; 16];
    // getrandom only fails when the system RNG is unavailable — fatal
    // for a transport that depends on randomness.
    getrandom::getrandom(&mut buf)
        .expect("system RNG unavailable — cannot generate Sec-WebSocket-Key");
    base64::engine::general_purpose::STANDARD.encode(buf)
}

/// Build the HTTP/1.1 Upgrade request bytes.
pub fn build_upgrade_request(config: &WebTunnelConfig) -> String {
    let prepared = config.prepare().expect("url already validated");
    build_upgrade_request_prepared(&prepared)
}

fn build_upgrade_request_prepared(config: &PreparedConfig) -> String {
    let parsed = &config.url;
    let request_target = &config.request_target;

    // Include the query string in the request-target (RFC 7230 §5.3.1).
    // The Go reference implementation sends path?query; omitting the query
    // silently breaks bridges that embed auth tokens / routing in it.
    let host = config.sni.clone();
    let host = if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host
    };
    let host = match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    };
    let key = generate_websocket_key();

    format!(
        "GET {request_target} HTTP/1.1\r\n\
Host: {host}\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Key: {key}\r\n\
Sec-WebSocket-Version: 13\r\n\
\r\n"
    )
}

/// Parse a complete HTTP response from a byte slice.
///
/// Returns `Ok((status_code, leftover_bytes))` on 101, or an error for
/// any other status / parse failure. Lenient: only checks the status code.
pub fn parse_response(buf: &[u8]) -> Result<(u16, &[u8]), Error> {
    let (code, body_offset) = parse_response_complete(buf)?
        .ok_or_else(|| Error::HttpParse("incomplete HTTP response".into()))?;
    Ok((code, &buf[body_offset..]))
}

fn parse_response_complete(buf: &[u8]) -> Result<Option<(u16, usize)>, Error> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut headers);

    let body_offset = match resp.parse(buf) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => return Ok(None),
        Err(e) => return Err(Error::HttpParse(e.to_string())),
    };

    let code = resp
        .code
        .ok_or_else(|| Error::HttpParse("no status code".into()))?;

    if code != 101 {
        let reason = resp.reason.unwrap_or("(no reason)");
        return Err(Error::Non101(format!("{code} {reason}")));
    }

    Ok(Some((code, body_offset)))
}

/// Perform the full webtunnel handshake: TCP → (optional TLS) → HTTP Upgrade.
///
/// # Cancel safety
///
/// Cancellation closes the owned connection. The complete operation has a
/// 30-second budget, including DNS, TCP, TLS, and HTTP Upgrade.
pub async fn connect(config: &WebTunnelConfig) -> Result<PrefixStream<WebTunnelStream>, Error> {
    connect_with_timeout(config, crate::DEFAULT_HANDSHAKE_TIMEOUT).await
}

pub(crate) async fn connect_with_timeout(
    config: &WebTunnelConfig,
    timeout: Duration,
) -> Result<PrefixStream<WebTunnelStream>, Error> {
    let resolver = crate::resolver_cache();
    let tls = crate::tls_context();
    connect_with_timeout_context(config, timeout, &resolver, &tls).await
}

pub(crate) async fn connect_with_timeout_context(
    config: &WebTunnelConfig,
    timeout: Duration,
    resolver: &ResolverCache,
    tls: &TlsContext,
) -> Result<PrefixStream<WebTunnelStream>, Error> {
    connect_with_timeout_context_bound(config, timeout, resolver, tls, None, None).await
}

pub(crate) async fn connect_with_timeout_context_bound(
    config: &WebTunnelConfig,
    timeout: Duration,
    resolver: &ResolverCache,
    tls: &TlsContext,
    v4_bind: Option<SocketAddrV4>,
    v6_bind: Option<SocketAddrV6>,
) -> Result<PrefixStream<WebTunnelStream>, Error> {
    let deadline = crate::deadline_for(timeout)?;
    tokio::time::timeout_at(
        deadline,
        connect_inner(config, resolver, tls, deadline, v4_bind, v6_bind),
    )
    .await
    .map_err(|_| crate::timeout_error())?
}

async fn connect_inner(
    config: &WebTunnelConfig,
    resolver: &ResolverCache,
    tls: &TlsContext,
    deadline: Instant,
    v4_bind: Option<SocketAddrV4>,
    v6_bind: Option<SocketAddrV6>,
) -> Result<PrefixStream<WebTunnelStream>, Error> {
    let prepared = config.prepare()?;
    let tcp = open_tcp(&prepared, resolver, deadline, v4_bind, v6_bind).await?;

    if prepared.use_tls {
        let tls_stream = tls_connect(&prepared, tcp, tls).await?;
        upgrade_tls_and_return(tls_stream, &prepared).await
    } else {
        upgrade_and_return(tcp, &prepared).await
    }
}

pub(crate) async fn upgrade_with_stream<S>(
    io: S,
    config: &PreparedConfig,
    tls: &TlsContext,
) -> Result<PrefixStream<WebTunnelStream<S>>, Error>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    if config.use_tls {
        let tls_stream = tls_connect(config, io, tls).await?;
        upgrade_tls_and_return(tls_stream, config).await
    } else {
        upgrade_and_return(io, config).await
    }
}

/// Decide how to resolve the bridge URL into a TCP connection. The
/// decision matrix matches the issue-#74-adjacent design captured in
/// the project notes:
///
/// |               | `addr=` literal IP     | hostname, `doh_mode=Off` | hostname, `doh_mode=Strict` | hostname, `doh_mode=Fallback` |
/// |---------------|------------------------|--------------------------------|----------------------------------|------------------------------------|
/// | path          | direct connect to IP   | system DNS via tokio           | DoH-only — `Err` on pool failure | DoH first → system DNS on failure  |
///
/// Literal IP overrides bypass DNS. Hostname overrides honor `doh_mode`.
/// `doh_mode=Off` keeps backwards-compatible behaviour for anyone who
/// explicitly opts out.
async fn open_tcp(
    config: &PreparedConfig,
    resolver_cache: &ResolverCache,
    deadline: Instant,
    v4_bind: Option<SocketAddrV4>,
    v6_bind: Option<SocketAddrV6>,
) -> Result<TcpStream, Error> {
    let host = &config.host;
    let port = config.port;

    // Literal addresses need neither encrypted nor system DNS.
    if let Ok(ip) = host.parse::<IpAddr>() {
        return connect_first_until(&[SocketAddr::new(ip, port)], deadline, |addr| {
            connect_bound(addr, v4_bind, v6_bind)
        })
        .await
        .map_err(Error::from);
    }

    match config.doh_mode {
        DohMode::Off => {
            connect_system_with(host, port, deadline, |addr| {
                connect_bound(addr, v4_bind, v6_bind)
            })
            .await
        }
        DohMode::Strict => {
            let resolver = get_resolver(resolver_cache).map_err(Error::from)?;
            connect_via_doh_strict_until(&resolver, host, port, deadline, |addr| {
                connect_bound(addr, v4_bind, v6_bind)
            })
            .await
        }
        DohMode::Fallback => {
            let resolver = get_resolver(resolver_cache).ok();
            connect_via_doh_fallback_until(resolver.as_deref(), host, port, deadline, |addr| {
                connect_bound(addr, v4_bind, v6_bind)
            })
            .await
        }
    }
}

fn get_resolver(cache: &ResolverCache) -> io::Result<Arc<DohResolver>> {
    get_resolver_with(cache, || DohResolver::with_default_pool().map(Arc::new))
}

fn get_resolver_with<F>(cache: &ResolverCache, build: F) -> io::Result<Arc<DohResolver>>
where
    F: FnOnce() -> io::Result<Arc<DohResolver>>,
{
    cache.get_or_try_init(build)
}

async fn lookup_system(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    let addrs = tokio::net::lookup_host((host, port)).await?;
    let addrs: Vec<_> = addrs.collect();
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "system resolver returned no addresses",
        ));
    }
    Ok(addrs)
}

async fn connect_system_with<F, Fut>(
    host: &str,
    port: u16,
    deadline: Instant,
    dial: F,
) -> Result<TcpStream, Error>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = io::Result<TcpStream>>,
{
    let addrs = lookup_until(deadline, lookup_system(host, port))
        .await
        .map_err(Error::from)?;
    connect_first_until(&addrs, deadline, dial)
        .await
        .map_err(Error::from)
}

async fn connect_bound(
    addr: SocketAddr,
    v4_bind: Option<SocketAddrV4>,
    v6_bind: Option<SocketAddrV6>,
) -> io::Result<TcpStream> {
    let socket = match addr {
        SocketAddr::V4(_) => {
            let socket = tokio::net::TcpSocket::new_v4()?;
            if let Some(bind) = v4_bind {
                socket.bind(SocketAddr::V4(bind))?;
            }
            socket
        }
        SocketAddr::V6(_) => {
            let socket = tokio::net::TcpSocket::new_v6()?;
            if let Some(bind) = v6_bind {
                socket.bind(SocketAddr::V6(bind))?;
            }
            socket
        }
    };
    socket.connect(addr).await
}

async fn lookup_until<F, T>(deadline: Instant, future: F) -> io::Result<T>
where
    F: std::future::Future<Output = io::Result<T>>,
{
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "connection deadline elapsed",
        ));
    }
    tokio::time::timeout(remaining, future)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "resolution attempt timed out"))?
}

/// Strict path: DoH only. On any failure (lookup error or every
/// connect attempt failing) return an error — never silently fall back
/// to the system resolver. This is the §F1 invariant the
/// censorship-resistance use case depends on.
///
async fn connect_via_doh_strict_until<F, Fut>(
    resolver: &DohResolver,
    host: &str,
    port: u16,
    deadline: Instant,
    dial: F,
) -> Result<TcpStream, Error>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = io::Result<TcpStream>>,
{
    connect_strict_with(
        || resolver.resolve(host, port),
        || lookup_system(host, port),
        deadline,
        dial,
    )
    .await
    .map_err(Error::from)
}

async fn connect_strict_with<R, RFut, S, SFut, F, Fut>(
    resolve: R,
    _system: S,
    deadline: Instant,
    mut dial: F,
) -> io::Result<TcpStream>
where
    R: FnOnce() -> RFut,
    RFut: std::future::Future<Output = io::Result<Vec<SocketAddr>>>,
    S: FnOnce() -> SFut,
    SFut: std::future::Future<Output = io::Result<Vec<SocketAddr>>>,
    F: FnMut(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = io::Result<TcpStream>>,
{
    let addrs = lookup_until(deadline, resolve()).await?;
    connect_first_until(&addrs, deadline, &mut dial).await
}

const FALLBACK_SYSTEM_RESERVE: Duration = Duration::from_secs(5);

async fn connect_fallback_with<D, DFut, S, SFut, F, Fut>(
    doh: Option<D>,
    system: S,
    deadline: Instant,
    mut dial: F,
) -> io::Result<TcpStream>
where
    D: FnOnce() -> DFut,
    DFut: std::future::Future<Output = io::Result<Vec<SocketAddr>>>,
    S: FnOnce() -> SFut,
    SFut: std::future::Future<Output = io::Result<Vec<SocketAddr>>>,
    F: FnMut(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = io::Result<TcpStream>>,
{
    let remaining = deadline.saturating_duration_since(Instant::now());
    let reserve = FALLBACK_SYSTEM_RESERVE.min(remaining / 2);
    let doh_deadline = deadline - reserve;

    if let Some(resolve) = doh {
        if doh_deadline > Instant::now() {
            if let Ok(addrs) = lookup_until(doh_deadline, resolve()).await {
                if let Ok(stream) = connect_first_until(&addrs, doh_deadline, &mut dial).await {
                    return Ok(stream);
                }
            }
        }
    }

    let addrs = lookup_until(deadline, system()).await?;
    let stream = connect_first_until(&addrs, deadline, &mut dial).await?;
    Ok(stream)
}

/// Fallback path: DoH first, system DNS on full DoH failure. A
/// connect-time failure to a resolved DoH address is treated the same
/// as a DoH lookup failure: try the system resolver before giving up,
/// so a partially-blocked DoH pool does not break webtunnel for a
/// caller who explicitly opted into "best-effort hardening".
///
/// `resolver` is `Option` so the caller can pass `None` when the
/// resolver itself failed to build — fallback still tries the system
/// resolver in that case, matching the "best-effort" contract.
#[cfg(test)]
pub(crate) async fn connect_via_doh_fallback(
    resolver: Option<&DohResolver>,
    host: &str,
    port: u16,
) -> Result<TcpStream, Error> {
    connect_via_doh_fallback_until(
        resolver,
        host,
        port,
        crate::deadline_for(crate::DEFAULT_HANDSHAKE_TIMEOUT)?,
        TcpStream::connect,
    )
    .await
}

async fn connect_via_doh_fallback_until<F, Fut>(
    resolver: Option<&DohResolver>,
    host: &str,
    port: u16,
    deadline: Instant,
    dial: F,
) -> Result<TcpStream, Error>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = io::Result<TcpStream>>,
{
    connect_fallback_with(
        resolver.map(|r| move || r.resolve(host, port)),
        || lookup_system(host, port),
        deadline,
        dial,
    )
    .await
    .map_err(Error::from)
}

/// Try each `SocketAddr` in order, returning the first successful TCP
/// connection. If every attempt fails, return the last error.
///
/// Bound earlier attempts so a silent peer cannot starve later addresses.
/// The last address may use the remaining handshake budget.
const CONNECT_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(test)]
async fn connect_first(addrs: &[SocketAddr]) -> io::Result<TcpStream> {
    connect_first_until(
        addrs,
        Instant::now() + crate::DEFAULT_HANDSHAKE_TIMEOUT,
        TcpStream::connect,
    )
    .await
}

async fn connect_first_until<F, Fut>(
    addrs: &[SocketAddr],
    deadline: Instant,
    mut dial: F,
) -> io::Result<TcpStream>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = io::Result<TcpStream>>,
{
    let mut last_err: Option<io::Error> = None;
    for (index, &addr) in addrs.iter().enumerate() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "connection deadline elapsed",
            ));
        }
        let attempt = if index + 1 == addrs.len() {
            remaining
        } else {
            remaining.min(CONNECT_ATTEMPT_TIMEOUT)
        };
        match tokio::time::timeout(attempt, dial(addr)).await {
            Err(_) => {
                last_err = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("connection attempt to {addr} timed out"),
                ))
            }
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no addresses to connect to",
        )
    }))
}

async fn tls_connect<S>(
    config: &PreparedConfig,
    tcp: S,
    tls: &TlsContext,
) -> Result<tokio_rustls::client::TlsStream<S>, Error>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let server_name = rustls::pki_types::ServerName::try_from(config.sni.clone())
        .map_err(|e| Error::Tls(format!("invalid SNI: {e}")))?;

    let client_config = tls_config(tls);
    let connector = tokio_rustls::TlsConnector::from(client_config);
    let tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| Error::Tls(e.to_string()))?;
    Ok(tls)
}

fn tls_config(tls: &TlsContext) -> Arc<rustls::ClientConfig> {
    tls.get_or_init(|| Arc::new(build_tls_config()))
}

fn build_tls_config() -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // No ALPN set — matches the Go client which leaves NextProtos empty.
    let mut client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    // Keep the old per-connection privacy behavior: sharing a config must not
    // enable TLS ticket resumption across otherwise independent handshakes.
    client_config.resumption = rustls::client::Resumption::disabled();

    client_config
}

/// Send the HTTP Upgrade request, read the 101 response, return the stream.
async fn read_upgrade<S>(mut stream: S, config: &PreparedConfig) -> Result<(S, Vec<u8>), Error>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    let request = build_upgrade_request_prepared(config);
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| Error::Handshake(format!("write upgrade request: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| Error::Handshake(format!("flush: {e}")))?;

    // Read the 101 response. The response is small (a few headers), so
    // a 4096-byte buffer is generous. We loop until httparse reports
    // Status::Complete.
    let mut buf = vec![0u8; 4096];
    let mut total = 0usize;
    let mut boundary = HeaderBoundary::default();
    loop {
        if total >= buf.len() {
            return Err(Error::Handshake("response headers too large".into()));
        }
        let n = stream
            .read(&mut buf[total..])
            .await
            .map_err(|e| Error::Handshake(format!("read response: {e}")))?;
        if n == 0 {
            return Err(Error::Handshake("connection closed before 101".into()));
        }
        total += n;

        let Some(header_end) = boundary.find(&buf[..total]) else {
            continue;
        };
        let (_code, leftover_slice) = parse_response(&buf[..total])?;
        let body_offset = total - leftover_slice.len();
        if body_offset < header_end {
            return Err(Error::HttpParse("invalid HTTP response boundary".into()));
        }
        let leftover: Vec<u8> = buf[body_offset..total].to_vec();
        if !leftover.is_empty() {
            crate::warn!(
                "webtunnel: {} trailing bytes after 101 — preserving in stream prefix",
                leftover.len()
            );
        }

        return Ok((stream, leftover));
    }
}

async fn upgrade_and_return<S>(
    stream: S,
    config: &PreparedConfig,
) -> Result<PrefixStream<WebTunnelStream<S>>, Error>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    let (stream, leftover) = read_upgrade(stream, config).await?;
    Ok(PrefixStream::new(WebTunnelStream::Plain(stream), leftover))
}

async fn upgrade_tls_and_return<S>(
    stream: tokio_rustls::client::TlsStream<S>,
    config: &PreparedConfig,
) -> Result<PrefixStream<WebTunnelStream<S>>, Error>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (stream, leftover) = read_upgrade(stream, config).await?;
    Ok(PrefixStream::new(
        WebTunnelStream::Tls(Box::new(stream)),
        leftover,
    ))
}

/// Incremental framing only; httparse validates the complete header.
#[derive(Default)]
struct HeaderBoundary {
    scanned: usize,
    line_start: usize,
    saw_status_line: bool,
}

impl HeaderBoundary {
    fn find(&mut self, bytes: &[u8]) -> Option<usize> {
        while self.scanned < bytes.len() {
            let index = self.scanned;
            self.scanned += 1;
            if bytes[index] != b'\n' {
                continue;
            }
            let line = &bytes[self.line_start..index];
            self.line_start = self.scanned;
            let empty = line.is_empty() || line == b"\r";
            if empty && self.saw_status_line {
                return Some(self.scanned);
            }
            self.saw_status_line |= !empty;
        }
        None
    }
}

#[cfg(test)]
mod tests;
