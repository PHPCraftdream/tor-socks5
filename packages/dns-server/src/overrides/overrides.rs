//! Runtime DNS overrides: operator-listed host masks resolved OUTSIDE the
//! Tor tunnel.
//!
//! # Security framing
//!
//! The default path of this server resolves EVERY hostname through
//! DoH-over-Tor ([`crate::doh_client`]), so no DNS query ever leaves the
//! machine as plaintext and none is linkable to the operator's real
//! network. This module is the deliberate, operator-opted escape hatch:
//! only host masks explicitly configured as [`DnsOverride`] entries take
//! the escape routes, and both [`resolve_via_dns_server`] and
//! [`resolve_via_system`] purposefully leave the Tor tunnel -- the former
//! speaks plain UDP/TCP DNS straight to the configured server, the latter
//! reads the current OS nameservers and exchanges original DNS packets. Every hostname that matches
//! no mask keeps going through the tunnel; a mask is an operator decision
//! that leak-ability is acceptable (or preferable) for those names.
//!
//! Matching is a small, dependency-free hostname glob ([`matches()`]) and
//! lookup is a first-match scan in list order ([`find_override`]) -- the
//! same fixed-order convention as the DoH provider pool.

use crate::doh_client::{
    build_query, parse_response, temporary_response, validate_response, DnsQuery,
    MAX_DNS_RESPONSE_BYTES,
};
use crate::error::DnsServerError;
use crate::ResolvedAnswer;
use hickory_proto::op::Query;
use hickory_resolver::config::ProtocolConfig;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// Total direct exchange budget, including validated TC retry.
pub const PLAIN_DNS_TIMEOUT: Duration = Duration::from_secs(5);
/// Total configured-system-nameserver traversal budget.
pub const SYSTEM_RESOLVER_TIMEOUT: Duration = Duration::from_secs(10);

/// One configured override: a hostname glob plus the resolver that should
/// handle matching hosts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsOverride {
    /// Hostname glob; `*` matches any run of characters (see [`matches()`]).
    pub pattern: String,
    /// Which escape route matching hosts take.
    pub resolver: OverrideResolver,
}

/// The resolver an override routes matching hosts to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverrideResolver {
    /// The operating-system resolver (hickory-resolver reading
    /// `/etc/resolv.conf` / the Windows registry).
    System,
    /// A specific DNS server reached directly (plain UDP, TCP retry on
    /// truncation) -- NOT through Tor, NOT DoH.
    Dns {
        /// Address of the DNS server to query.
        server: SocketAddr,
    },
}

/// Whether `host` matches the hostname glob `pattern`.
///
/// `*` matches any run of characters including none; matching is
/// case-insensitive and always against the WHOLE host (not per-label), so
/// `foo*.com` matches `foobar.com` and the bare `*` matches everything.
///
/// Deliberate edge case: `*.example.com` does NOT match `example.com`. The
/// pattern's literal `.` must appear in the host, so a mask for the
/// children of a domain never captures the bare parent domain itself; an
/// operator who wants both lists both entries.
///
/// Both inputs are lowercased with [`str::to_ascii_lowercase`] and then
/// compared as ASCII bytes. Hostnames are ASCII on the wire -- international
/// names arrive punycode-encoded (`xn--...`) -- so byte-wise ASCII matching
/// is exact, not an approximation.
///
/// Implementation: the classic greedy single-`*` backtracking walk over the
/// two byte slices (two pointers; on a mismatch after a star, extend the
/// star's match by one and retry). No regex or glob crates.
pub fn matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let host = host.to_ascii_lowercase();
    let pattern = pattern.as_bytes();
    let host = host.as_bytes();

    let mut pattern_index = 0usize;
    let mut host_index = 0usize;
    // The star seen so far and the host offset where its match currently
    // starts; on a later mismatch the star's match is extended by one byte
    // and the scan resumes from there.
    let mut star_index: Option<usize> = None;
    let mut star_match_start = 0usize;

    while host_index < host.len() {
        if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
            // `*` first tries to match zero characters: only the pattern
            // cursor advances here, so the very next byte of `host` is
            // re-checked against whatever follows the star.
            star_index = Some(pattern_index);
            star_match_start = host_index;
            pattern_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == host[host_index] {
            pattern_index += 1;
            host_index += 1;
        } else if let Some(star) = star_index {
            pattern_index = star + 1;
            star_match_start += 1;
            host_index = star_match_start;
        } else {
            return false;
        }
    }
    while pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

/// Find the first override whose pattern matches `host`.
///
/// Linear scan in list order; the FIRST match wins. This is the same
/// fixed-order convention as
/// [`providers::provider_pool`](crate::providers::provider_pool) and
/// [`doh_client::resolve_with_pool`](crate::doh_client::resolve_with_pool):
/// position is priority -- no scoring, no racing -- so an operator who
/// prepends an entry knows exactly when it is used.
pub fn find_override<'a>(overrides: &'a [DnsOverride], host: &str) -> Option<&'a DnsOverride> {
    overrides.iter().find(|entry| matches(&entry.pattern, host))
}

/// Resolve exactly one original question, outside Tor, only when opted in.
/// `listeners` must contain the actual bound UDP/TCP endpoints, not requested
/// port-zero addresses. A wildcard listener covers local addresses, not every
/// remote resolver sharing its port. Each entry covers only its canonical IP
/// family; the listener owner must add an IPv4 wildcard for an IPv6 wildcard
/// only when the actual bound socket is dual-stack (IPV6_V6ONLY is false).
/// cancel-safe: yes — ephemeral sockets and TCP framing are owned by the
/// attempt; timeout closes them rather than resuming partial reads/writes.
pub async fn resolve_via_dns_server(
    question: &Query,
    server: SocketAddr,
    listeners: &[SocketAddr],
) -> Result<ResolvedAnswer, DnsServerError> {
    tokio::time::timeout(
        PLAIN_DNS_TIMEOUT,
        resolve_with_server(question, server, listeners),
    )
    .await
    .map_err(|_| DnsServerError::Timeout(PLAIN_DNS_TIMEOUT))?
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        IpAddr::V4(_) => ip,
    }
}

/// `route_local` comes from a connected ephemeral socket's local_addr; the
/// probe sends no DNS packet. This detects the machine's routed local IP.
fn self_reference(server: SocketAddr, listeners: &[SocketAddr], route_local: IpAddr) -> bool {
    let target = canonical_ip(server.ip());
    let local = canonical_ip(route_local);
    listeners.iter().any(|listener| {
        if listener.port() != server.port() {
            return false;
        }
        let bound = canonical_ip(listener.ip());
        // Exact loopback binds do not cover other loopback aliases or families.
        // Mapped IPv4 addresses have already been normalized above.
        bound == target
            || (bound.is_unspecified()
                && (target.is_unspecified() || target.is_loopback() || target == local)
                // Family coverage is supplied by the listener owner. A dual-stack
                // IPv6 wildcard must also be represented by an IPv4 wildcard.
                && bound.is_ipv4() == target.is_ipv4())
    })
}

/// Exercise the production recursion guard with actual listener coverage.
#[cfg(test)]
pub(super) fn self_reference_for_test(
    server: SocketAddr,
    listeners: &[SocketAddr],
    route_local: IpAddr,
) -> bool {
    self_reference(server, listeners, route_local)
}

/// Probe failures are classified structurally: recursion is terminal, while
/// ordinary bind/connect/local-address failures only disqualify that server.
#[derive(Debug)]
enum ProbeError {
    SelfReference(SocketAddr),
    Transport(DnsServerError),
}

impl ProbeError {
    fn into_dns_error(self) -> DnsServerError {
        match self {
            Self::SelfReference(server) => DnsServerError::PlainDns(format!(
                "override upstream {server} refers to this listener"
            )),
            Self::Transport(error) => error,
        }
    }
}

/// Connect an ephemeral UDP socket without sending a DNS packet. Shared by
/// direct exchanges and the all-destinations system configuration preflight.
/// cancel-safe: yes — bind/connect state is owned and dropped on cancellation.
async fn probe_upstream(
    server: SocketAddr,
    listeners: &[SocketAddr],
) -> Result<(SocketAddr, UdpSocket), ProbeError> {
    // Catch exact, mapped, loopback and unspecified targets before routing.
    if self_reference(server, listeners, IpAddr::V4(Ipv4Addr::UNSPECIFIED)) {
        return Err(ProbeError::SelfReference(server));
    }
    let bind = if canonical_ip(server.ip()).is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let server = match canonical_ip(server.ip()) {
        IpAddr::V4(ip) => SocketAddr::new(IpAddr::V4(ip), server.port()),
        IpAddr::V6(_) => server,
    };
    let socket = UdpSocket::bind(bind).await.map_err(|e| {
        ProbeError::Transport(DnsServerError::PlainDns(format!(
            "bind ephemeral socket: {e}"
        )))
    })?;
    // RFC 5452 §9.1: the connected socket accepts datagrams only from this
    // upstream address/port. Connecting UDP does not transmit a DNS query.
    socket.connect(server).await.map_err(|e| {
        ProbeError::Transport(DnsServerError::PlainDns(format!("connect UDP socket: {e}")))
    })?;
    let local = socket.local_addr().map_err(|e| {
        ProbeError::Transport(DnsServerError::PlainDns(format!(
            "probe local address: {e}"
        )))
    })?;
    if self_reference(server, listeners, local.ip()) {
        return Err(ProbeError::SelfReference(server));
    }
    Ok((server, socket))
}

/// cancel-safe: yes — bind/connect/send/receive own only a disposable UDP
/// socket; TCP retries own their stream and are terminal on cancellation.
async fn resolve_with_server(
    question: &Query,
    server: SocketAddr,
    listeners: &[SocketAddr],
) -> Result<ResolvedAnswer, DnsServerError> {
    let query = build_query(question).map_err(DnsServerError::Wire)?;
    let (server, socket) = probe_upstream(server, listeners)
        .await
        .map_err(ProbeError::into_dns_error)?;
    socket
        .send(&query.bytes)
        .await
        .map_err(|e| DnsServerError::PlainDns(format!("send DNS query: {e}")))?;
    let mut buf = vec![0; MAX_DNS_RESPONSE_BYTES];
    loop {
        let n = socket
            .recv(&mut buf)
            .await
            .map_err(|e| DnsServerError::PlainDns(format!("receive DNS response: {e}")))?;
        // Invalid or spoofed packets cannot trigger TCP or complete lookup.
        let Ok(message) = validate_response(&query, &buf[..n]) else {
            continue;
        };
        if message.metadata.truncation {
            let body = tcp_exchange(server, &query).await?;
            return parse_response(&query, &body).map_err(plain_error);
        }
        return parse_response(&query, &buf[..n]).map_err(plain_error);
    }
}

/// RFC 1035 §4.2.2: two-byte network-order frame length.
/// cancel-safe: yes — NOT resumable: partial write_all/read_exact framing is
/// discarded with the owned stream on any timeout, error or cancellation.
async fn tcp_exchange(server: SocketAddr, query: &DnsQuery) -> Result<Vec<u8>, DnsServerError> {
    let mut stream = TcpStream::connect(server)
        .await
        .map_err(|e| DnsServerError::PlainDns(format!("TCP connect: {e}")))?;
    let length = u16::try_from(query.bytes.len())
        .map_err(|_| DnsServerError::PlainDns("query too large for TCP".into()))?;
    stream
        .write_all(&length.to_be_bytes())
        .await
        .map_err(|e| DnsServerError::PlainDns(format!("write query length: {e}")))?;
    stream
        .write_all(&query.bytes)
        .await
        .map_err(|e| DnsServerError::PlainDns(format!("write query: {e}")))?;
    let mut prefix = [0; 2];
    stream
        .read_exact(&mut prefix)
        .await
        .map_err(|e| DnsServerError::PlainDns(format!("read response length: {e}")))?;
    let mut body = vec![0; usize::from(u16::from_be_bytes(prefix))];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|e| DnsServerError::PlainDns(format!("read response body: {e}")))?;
    Ok(body)
}

fn plain_error(error: DnsServerError) -> DnsServerError {
    match error {
        DnsServerError::DohExchange(text) => DnsServerError::PlainDns(text),
        other => other,
    }
}

/// Read current configured servers on EVERY call, before sending any query.
/// Lookup exposes a Message on success in hickory 0.26.1, but resolver error
/// handling/retries can still erase terminal negative-response metadata.
/// Packet-aware exchanges preserve original QCLASS/QTYPE and negative SOAs.
/// cancel-safe: yes for network exchange — all sockets are attempt-owned.
/// OS configuration reads cannot be stopped on cancellation. Admission waits
/// within the same ten-second budget as configuration and network traversal.
/// The listener bounds backend callers at 64; this gate admits one fresh read
/// at a time, with no blocking job scheduled before admission. The blocking
/// worker (not the listener or caller) owns its permit until the read finishes,
/// even after caller cancellation. Cancelled waiters schedule no later work.
pub async fn resolve_via_system(
    question: &Query,
    listeners: &[SocketAddr],
) -> Result<ResolvedAnswer, DnsServerError> {
    static CONFIG_READ_GATE: std::sync::OnceLock<std::sync::Arc<tokio::sync::Semaphore>> =
        std::sync::OnceLock::new();
    let gate = CONFIG_READ_GATE
        .get_or_init(|| std::sync::Arc::new(tokio::sync::Semaphore::new(1)))
        .clone();
    system_with_config(
        question,
        listeners,
        schedule_config_read(gate, read_system_servers),
    )
    .await
}

/// Wait for admission inside the caller's existing system-resolution budget.
/// Every admitted lookup performs a fresh OS read; nothing is cached.
/// cancel-safe: yes for admission/resource bounds — dropping acquire_owned
/// removes a waiter without scheduling work. Once admitted, the blocking read
/// is not cancellable and owns its permit until actual worker completion.
async fn schedule_config_read<R>(
    gate: std::sync::Arc<tokio::sync::Semaphore>,
    read: R,
) -> Result<Vec<SocketAddr>, DnsServerError>
where
    R: FnOnce() -> Result<Vec<SocketAddr>, DnsServerError> + Send + 'static,
{
    let permit = gate.acquire_owned().await.map_err(|_| {
        DnsServerError::SystemResolver("system configuration read gate closed".into())
    })?;
    // Intentional detach on caller cancellation: spawn_blocking cannot stop
    // a running OS read. The worker owns the permit even while queued, so
    // cancelled requests cannot admit or accumulate more blocking reads.
    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        read()
    });
    task.await
        .map_err(|e| DnsServerError::SystemResolver(format!("system config task: {e}")))?
}

fn read_system_servers() -> Result<Vec<SocketAddr>, DnsServerError> {
    let (config, _) = hickory_resolver::system_conf::read_system_conf()
        .map_err(|e| DnsServerError::SystemResolver(format!("read system configuration: {e}")))?;
    let mut servers = Vec::new();
    for ns in config.name_servers() {
        for connection in &ns.connections {
            if matches!(connection.protocol, ProtocolConfig::Udp) {
                let addr = SocketAddr::new(ns.ip, connection.port);
                if !servers.contains(&addr) {
                    servers.push(addr);
                }
            }
        }
    }
    Ok(servers)
}

/// Meaningful configuration seam: a freshly evaluated config future for each
/// public call; regression fixtures can change servers without OS mutation.
/// cancel-safe: yes for network traversal — no detached exchange futures.
async fn system_with_config<F>(
    question: &Query,
    listeners: &[SocketAddr],
    config: F,
) -> Result<ResolvedAnswer, DnsServerError>
where
    F: std::future::Future<Output = Result<Vec<SocketAddr>, DnsServerError>>,
{
    system_with_config_and_probe(question, listeners, config, |server| async move {
        probe_upstream(server, listeners).await.map(|_| ())
    })
    .await
}

/// Production preflight seam: tests inject a no-route result for one address
/// without changing OS routing. Successful probes never transmit DNS.
/// cancel-safe: yes — probe futures own disposable sockets; exchanges do too.
async fn system_with_config_and_probe<F, P, Fut>(
    question: &Query,
    listeners: &[SocketAddr],
    config: F,
    mut probe: P,
) -> Result<ResolvedAnswer, DnsServerError>
where
    F: std::future::Future<Output = Result<Vec<SocketAddr>, DnsServerError>>,
    P: FnMut(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = Result<(), ProbeError>>,
{
    tokio::time::timeout(SYSTEM_RESOLVER_TIMEOUT, async {
        let servers = config.await?;
        if servers.is_empty() {
            return Err(DnsServerError::SystemResolver(
                "no configured plain DNS nameservers".into(),
            ));
        }
        // Scan every destination before any DNS send. Exact/mapped and
        // wildcard-loopback recursion is recognized BEFORE routing, even if
        // that address cannot be bound or connected on this machine.
        let mut usable = Vec::new();
        let mut last_error = None;
        for server in servers {
            if self_reference(server, listeners, IpAddr::V4(Ipv4Addr::UNSPECIFIED)) {
                return Err(DnsServerError::SystemResolver(format!(
                    "configured nameserver {server} refers to this listener"
                )));
            }
            match probe(server).await {
                Ok(()) => usable.push(server),
                Err(ProbeError::SelfReference(target)) => {
                    return Err(DnsServerError::SystemResolver(format!(
                        "configured nameserver {target} refers to this listener"
                    )));
                }
                Err(ProbeError::Transport(error)) => last_error = Some(error),
            }
        }
        for server in usable {
            match resolve_via_dns_server(question, server, listeners).await {
                Ok(answer) if !temporary_response(&answer.message) => return Ok(answer),
                Ok(_) => {
                    last_error = Some(DnsServerError::SystemResolver(
                        "temporary DNS failure".into(),
                    ))
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error
            .unwrap_or_else(|| DnsServerError::SystemResolver("no usable nameservers".into())))
    })
    .await
    .map_err(|_| DnsServerError::Timeout(SYSTEM_RESOLVER_TIMEOUT))?
}

#[cfg(test)]
#[path = "system_config_resource_tests.rs"]
mod config_resource_tests;

#[cfg(test)]
#[path = "override_matching_tests.rs"]
mod matching_tests;
#[cfg(test)]
#[path = "plain_transport_tests.rs"]
mod transport_tests;
