use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use super::{Outcome, PreparedTarget};
use tokio::net::TcpStream;
use tokio::time::timeout;

use rustls::pki_types::ServerName;

/// Floor for the webtunnel probe: it has to complete a TLS handshake and an
/// HTTP round trip, not just a TCP one, so the plain TCP budget is too tight.
pub(crate) const MIN_WEBTUNNEL_TIMEOUT: Duration = Duration::from_secs(12);

/// Largest response head we will read while looking for the status line.
pub(crate) const WEBTUNNEL_HEAD_LIMIT: usize = 8 * 1024;

pub(crate) fn webtunnel_tls_config() -> std::sync::Arc<rustls::ClientConfig> {
    static CFG: OnceLock<std::sync::Arc<rustls::ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        std::sync::Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    })
    .clone()
}

/// Decide whether `addr` really serves the webtunnel bridge named by `url`.
///
/// A webtunnel bridge is reached by TLS to an ordinary-looking web server and
/// an HTTP/1.1 GET carrying WebSocket upgrade headers; only the bridge answers
/// `101 Switching Protocols`. Everything else on that host -- the site itself,
/// a CDN error page, a reverse proxy whose backend has died -- answers with a
/// normal status code.
///
/// This distinction is not cosmetic. Measured against a public collector's
/// list, 33 hosts passed a plain TCP probe and only 2 completed the upgrade;
/// the rest were live websites with no bridge behind them. Worse, those dead
/// entries sit behind CDNs and so post excellent latencies, which promoted them
/// to the top of the health ranking and pushed working bridges out of the
/// active pool entirely.
///
/// cancel-safe: NO — cancelling mid-handshake leaves partial TLS state, which
/// is fine because the connection is dropped either way.
pub(crate) async fn webtunnel_upgrade_probe(
    addrs: &[SocketAddr],
    plan: &PreparedTarget,
    budget: Duration,
) -> Outcome {
    let started = Instant::now();
    // TS5-03: every candidate gets its own slice of the budget for one COMPLETE
    // attempt -- TCP connect, TLS handshake, and the upgrade round trip -- with
    // the whole list still capped by `budget`. One shared timeout alone let a
    // first address that accepted TCP and then hung eat the entire budget, so a
    // working candidate behind it was never even tried and the bridge was filed
    // as dead. `addrs` arrives capped at `MAX_PROBE_ADDRS` (3) by
    // `order_candidates`, so a slice is never below a third of
    // `MIN_WEBTUNNEL_TIMEOUT` -- room for one full round trip.
    let per_addr_budget = budget / (addrs.len().max(1) as u32);
    let attempt = async {
        let mut last = "hostname resolved to no usable address".to_owned();
        for addr in addrs {
            match timeout(per_addr_budget, webtunnel_upgrade_inner(*addr, plan)).await {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(reason)) => last = format!("{addr}: {reason}"),
                Err(_) => last = format!("{addr}: timed out after {per_addr_budget:?}"),
            }
        }
        Err(last)
    };
    match timeout(budget, attempt).await {
        Ok(Ok(())) => Outcome::Reachable {
            latency: started.elapsed(),
        },
        Ok(Err(reason)) => Outcome::Unreachable { reason },
        Err(_) => Outcome::Unreachable {
            reason: format!("webtunnel upgrade timed out after {budget:?}"),
        },
    }
}

pub(crate) async fn webtunnel_upgrade_inner(
    addr: SocketAddr,
    plan: &PreparedTarget,
) -> Result<(), String> {
    // A fixed key is fine: nothing here verifies the server's accept hash, and
    // the probe carries no data. Host header and request-target come straight
    // from the shared plan, so the wire format matches the transport's.
    let request = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         User-Agent: Mozilla/5.0\r\n\
         \r\n",
        plan.request_target, plan.host_header
    );

    let tcp = TcpStream::connect(addr)
        .await
        .map_err(|e| format!("tcp connect: {e}"))?;
    if plan.use_tls {
        let server_name = ServerName::try_from(plan.sni.clone())
            .map_err(|e| format!("invalid SNI {:?}: {e}", plan.sni))?;
        let connector = tokio_rustls::TlsConnector::from(webtunnel_tls_config());
        let tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| format!("tls: {e}"))?;
        send_upgrade_request(tls, &request).await
    } else {
        // Plain http:// : the transport speaks cleartext too, so the probe
        // must not demand a certificate the bridge never offers.
        send_upgrade_request(tcp, &request).await
    }
}

/// Write the upgrade request and look for `101 Switching Protocols`.
///
/// Generic over the stream so the TLS and plain-http paths share this
/// verbatim without boxing or an enum wrapper.
async fn send_upgrade_request<S>(mut stream: S, request: &str) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("write request: {e}"))?;
    stream.flush().await.map_err(|e| format!("flush: {e}"))?;

    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| format!("read response: {e}"))?;
        if n == 0 {
            return Err("connection closed before a status line arrived".to_owned());
        }
        buf.extend_from_slice(&chunk[..n]);

        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut response = httparse::Response::new(&mut headers);
        match response.parse(&buf) {
            Ok(httparse::Status::Complete(_)) => {
                return match response.code {
                    Some(101) => Ok(()),
                    Some(code) => Err(format!("not a webtunnel endpoint (HTTP {code})")),
                    None => Err("response had no status code".to_owned()),
                };
            }
            Ok(httparse::Status::Partial) => {
                if buf.len() >= WEBTUNNEL_HEAD_LIMIT {
                    return Err("response head exceeded the probe limit".to_owned());
                }
            }
            Err(e) => return Err(format!("malformed HTTP response: {e}")),
        }
    }
}
