//! Minimal SOCKS5 *client*, used as an upstream egress.
//!
//! When an upstream proxy is configured (and enabled), the daemon
//! forwards each accepted CONNECT through it instead of dialing out via
//! Tor — chaining `client -> us -> upstream -> target`. We implement
//! just enough of RFC 1928 (CONNECT) and RFC 1929 (USERNAME/PASSWORD)
//! to drive a standard SOCKS5 proxy.

use std::net::IpAddr;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const VER: u8 = 0x05;
const RFC1929_VER: u8 = 0x01;
const M_NO_AUTH: u8 = 0x00;
const M_USER_PASS: u8 = 0x02;
const M_NONE: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const ATYP_V4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_V6: u8 = 0x04;
const REP_SUCCESS: u8 = 0x00;

/// A configured upstream SOCKS5 proxy used as the egress.
#[derive(Clone)]
pub struct Upstream {
    address: String,
    /// `Some((user, pass))` to authenticate via RFC 1929, `None` for an
    /// unauthenticated upstream.
    credentials: Option<(String, String)>,
}

impl std::fmt::Debug for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Upstream")
            .field("address", &self.address)
            .field("has_auth", &self.credentials.is_some())
            .finish()
    }
}

impl Upstream {
    pub fn new(address: String, credentials: Option<(String, String)>) -> Self {
        Self {
            address,
            credentials,
        }
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    pub fn has_auth(&self) -> bool {
        self.credentials.is_some()
    }

    /// Open a TCP connection to the upstream, run the SOCKS5 client
    /// handshake (with optional auth) and a CONNECT to `(host, port)`.
    /// On success the returned stream is positioned at the start of the
    /// tunnelled data and can be relayed directly to the client.
    pub async fn connect(&self, host: &str, port: u16) -> Result<TcpStream> {
        let mut s = TcpStream::connect(&self.address)
            .await
            .with_context(|| format!("connecting to upstream SOCKS5 {}", self.address))?;
        self.negotiate_method(&mut s).await?;
        send_connect(&mut s, host, port).await?;
        read_reply(&mut s).await?;
        Ok(s)
    }

    async fn negotiate_method(&self, s: &mut TcpStream) -> Result<()> {
        // Offer exactly the one method we intend to use, so the server's
        // choice is unambiguous.
        let method = if self.credentials.is_some() {
            M_USER_PASS
        } else {
            M_NO_AUTH
        };
        s.write_all(&[VER, 0x01, method])
            .await
            .context("sending upstream greeting")?;

        let mut sel = [0u8; 2];
        s.read_exact(&mut sel)
            .await
            .context("reading upstream method selection")?;
        if sel[0] != VER {
            bail!("upstream replied with non-SOCKS5 version {:#x}", sel[0]);
        }
        match sel[1] {
            M_NO_AUTH => Ok(()),
            M_USER_PASS => self.authenticate(s).await,
            M_NONE => bail!("upstream rejected all offered auth methods"),
            other => bail!("upstream selected unsupported method {other:#x}"),
        }
    }

    async fn authenticate(&self, s: &mut TcpStream) -> Result<()> {
        let (user, pass) = self
            .credentials
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("upstream asked for USER/PASS but none configured"))?;
        if user.len() > 255 || pass.len() > 255 {
            bail!("upstream credentials exceed the RFC 1929 255-byte limit");
        }
        let mut msg = Vec::with_capacity(3 + user.len() + pass.len());
        msg.push(RFC1929_VER);
        msg.push(user.len() as u8);
        msg.extend_from_slice(user.as_bytes());
        msg.push(pass.len() as u8);
        msg.extend_from_slice(pass.as_bytes());
        s.write_all(&msg)
            .await
            .context("sending upstream credentials")?;

        let mut reply = [0u8; 2];
        s.read_exact(&mut reply)
            .await
            .context("reading upstream auth reply")?;
        if reply[0] != RFC1929_VER {
            bail!("upstream auth reply has unexpected version {:#x}", reply[0]);
        }
        if reply[1] != 0x00 {
            bail!("upstream rejected our credentials (status {:#x})", reply[1]);
        }
        Ok(())
    }
}

/// Build and send the CONNECT request. `host` is sent as an IPv4/IPv6
/// literal when it parses as one, otherwise as a domain name (so DNS is
/// resolved by the upstream, not by us).
async fn send_connect(s: &mut TcpStream, host: &str, port: u16) -> Result<()> {
    let mut req = vec![VER, CMD_CONNECT, 0x00];
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            req.push(ATYP_V4);
            req.extend_from_slice(&v4.octets());
        }
        Ok(IpAddr::V6(v6)) => {
            req.push(ATYP_V6);
            req.extend_from_slice(&v6.octets());
        }
        Err(_) => {
            if host.len() > 255 {
                bail!("target host exceeds 255 bytes: {host:?}");
            }
            req.push(ATYP_DOMAIN);
            req.push(host.len() as u8);
            req.extend_from_slice(host.as_bytes());
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)
        .await
        .context("sending upstream CONNECT request")?;
    Ok(())
}

/// Read and validate the CONNECT reply. The bound address/port are
/// drained (regardless of the reply code) so a successful stream is left
/// positioned at the tunnelled payload.
async fn read_reply(s: &mut TcpStream) -> Result<()> {
    let mut head = [0u8; 4];
    s.read_exact(&mut head)
        .await
        .context("reading upstream CONNECT reply")?;
    if head[0] != VER {
        bail!("upstream reply has non-SOCKS5 version {:#x}", head[0]);
    }

    // Drain BND.ADDR + BND.PORT.
    match head[3] {
        ATYP_V4 => {
            let mut b = [0u8; 4 + 2];
            s.read_exact(&mut b)
                .await
                .context("draining upstream BND.ADDR")?;
        }
        ATYP_V6 => {
            let mut b = [0u8; 16 + 2];
            s.read_exact(&mut b)
                .await
                .context("draining upstream BND.ADDR")?;
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len)
                .await
                .context("draining upstream BND.ADDR len")?;
            let mut b = vec![0u8; len[0] as usize + 2];
            s.read_exact(&mut b)
                .await
                .context("draining upstream BND.ADDR")?;
        }
        other => bail!("upstream reply has unknown ATYP {other:#x}"),
    }

    if head[1] != REP_SUCCESS {
        bail!("upstream CONNECT failed (REP {:#x})", head[1]);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// A throwaway SOCKS5 server for one connection. `require_auth`
    /// forces USER/PASS; `accept_creds` decides the auth status; `rep`
    /// is the CONNECT reply code. Returns the address to dial and a
    /// handle yielding the `(host, port)` the client asked to reach (or
    /// `None` if the exchange aborted before CONNECT).
    async fn fake_upstream(
        require_auth: bool,
        accept_creds: bool,
        rep: u8,
    ) -> (String, tokio::task::JoinHandle<Option<(String, u16)>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let handle = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();

            // Greeting.
            let mut head = [0u8; 2];
            s.read_exact(&mut head).await.unwrap();
            let mut methods = vec![0u8; head[1] as usize];
            s.read_exact(&mut methods).await.unwrap();

            let want = if require_auth { M_USER_PASS } else { M_NO_AUTH };
            if !methods.contains(&want) {
                s.write_all(&[VER, M_NONE]).await.unwrap();
                return None;
            }
            s.write_all(&[VER, want]).await.unwrap();

            if require_auth {
                let mut h = [0u8; 2];
                s.read_exact(&mut h).await.unwrap();
                let mut user = vec![0u8; h[1] as usize];
                s.read_exact(&mut user).await.unwrap();
                let mut pl = [0u8; 1];
                s.read_exact(&mut pl).await.unwrap();
                let mut pass = vec![0u8; pl[0] as usize];
                s.read_exact(&mut pass).await.unwrap();
                let status = if accept_creds { 0x00 } else { 0x01 };
                s.write_all(&[RFC1929_VER, status]).await.unwrap();
                if !accept_creds {
                    return None;
                }
            }

            // CONNECT request.
            let mut req = [0u8; 4];
            s.read_exact(&mut req).await.unwrap();
            let host = match req[3] {
                ATYP_V4 => {
                    let mut a = [0u8; 4];
                    s.read_exact(&mut a).await.unwrap();
                    format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
                }
                ATYP_DOMAIN => {
                    let mut l = [0u8; 1];
                    s.read_exact(&mut l).await.unwrap();
                    let mut b = vec![0u8; l[0] as usize];
                    s.read_exact(&mut b).await.unwrap();
                    String::from_utf8(b).unwrap()
                }
                ATYP_V6 => {
                    let mut a = [0u8; 16];
                    s.read_exact(&mut a).await.unwrap();
                    std::net::Ipv6Addr::from(a).to_string()
                }
                other => panic!("unexpected ATYP {other}"),
            };
            let mut port = [0u8; 2];
            s.read_exact(&mut port).await.unwrap();
            let port = u16::from_be_bytes(port);

            // Reply with a zeroed BND.ADDR (IPv4).
            s.write_all(&[VER, rep, 0x00, ATYP_V4, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            Some((host, port))
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn no_auth_connect_domain_succeeds() {
        let (addr, handle) = fake_upstream(false, false, REP_SUCCESS).await;
        let up = Upstream::new(addr, None);
        let _stream = up.connect("example.com", 443).await.expect("connect ok");
        let seen = handle.await.unwrap();
        assert_eq!(seen, Some(("example.com".to_string(), 443)));
    }

    #[tokio::test]
    async fn no_auth_connect_ipv4_uses_v4_atyp() {
        let (addr, handle) = fake_upstream(false, false, REP_SUCCESS).await;
        let up = Upstream::new(addr, None);
        let _stream = up.connect("1.2.3.4", 80).await.expect("connect ok");
        let seen = handle.await.unwrap();
        assert_eq!(seen, Some(("1.2.3.4".to_string(), 80)));
    }

    #[tokio::test]
    async fn auth_connect_succeeds_with_good_credentials() {
        let (addr, handle) = fake_upstream(true, true, REP_SUCCESS).await;
        let up = Upstream::new(addr, Some(("alice".into(), "secret".into())));
        let _stream = up.connect("example.com", 8080).await.expect("connect ok");
        let seen = handle.await.unwrap();
        assert_eq!(seen, Some(("example.com".to_string(), 8080)));
    }

    #[tokio::test]
    async fn auth_rejected_credentials_errors() {
        let (addr, handle) = fake_upstream(true, false, REP_SUCCESS).await;
        let up = Upstream::new(addr, Some(("alice".into(), "WRONG".into())));
        let err = up.connect("example.com", 80).await.expect_err("must fail");
        assert!(
            format!("{err}").contains("rejected our credentials"),
            "unexpected error: {err}"
        );
        let _ = handle.await;
    }

    #[tokio::test]
    async fn server_without_acceptable_method_errors() {
        // Server insists on USER/PASS but we offer only NO_AUTH.
        let (addr, handle) = fake_upstream(true, true, REP_SUCCESS).await;
        let up = Upstream::new(addr, None);
        let err = up.connect("example.com", 80).await.expect_err("must fail");
        assert!(
            format!("{err}").contains("rejected all offered auth methods"),
            "unexpected error: {err}"
        );
        let _ = handle.await;
    }

    #[tokio::test]
    async fn connect_failure_reply_is_surfaced() {
        // 0x05 = connection refused.
        let (addr, handle) = fake_upstream(false, false, 0x05).await;
        let up = Upstream::new(addr, None);
        let err = up.connect("example.com", 80).await.expect_err("must fail");
        assert!(
            format!("{err}").contains("REP 0x5"),
            "unexpected error: {err}"
        );
        let _ = handle.await;
    }
}
