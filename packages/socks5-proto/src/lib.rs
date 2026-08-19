//! Minimal SOCKS5 server-side implementation (RFC 1928), CONNECT command
//! only. Supports either no authentication or RFC 1929 USERNAME/PASSWORD,
//! depending on whether the caller passes an `AuthState` to [`handshake`].

use std::net::Ipv6Addr;
use std::sync::Arc;

use anyhow::{bail, Result};
use auth::AuthState;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const SOCKS_VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USER_PASS: u8 = 0x02;
const METHOD_NO_ACCEPTABLE: u8 = 0xFF;

/// RFC 1929 sub-negotiation version byte. **Not** the SOCKS5 version.
const RFC1929_VERSION: u8 = 0x01;
const RFC1929_STATUS_OK: u8 = 0x00;
const RFC1929_STATUS_FAIL: u8 = 0x01;

const CMD_CONNECT: u8 = 0x01;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// SOCKS5 server reply codes.
#[allow(dead_code)] // part of the protocol — keep all codes for future use
#[derive(Clone, Copy)]
#[repr(u8)]
pub enum Reply {
    Success = 0x00,
    GeneralFailure = 0x01,
    ConnectionNotAllowed = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TtlExpired = 0x06,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

#[derive(Debug)]
pub struct ConnectRequest {
    pub host: String,
    pub port: u16,
    /// The account that authenticated this request, when RFC 1929
    /// USER/PASS was used. `None` for the anonymous (NO_AUTH) path.
    /// Carried so per-account policy (e.g. the `.onion` gate) can be
    /// applied after the handshake.
    pub authed_user: Option<String>,
}

impl ConnectRequest {
    /// True iff the destination is a Tor `.onion` hidden-service
    /// address. Matches the final DNS label case-insensitively and
    /// tolerates a trailing FQDN dot; a bare `"onion"` with no
    /// preceding label is not treated as onion.
    #[must_use]
    pub fn is_onion(&self) -> bool {
        let host = self.host.trim_end_matches('.');
        matches!(host.rsplit_once('.'), Some((_, tld)) if tld.eq_ignore_ascii_case("onion"))
    }
}

/// Perform the SOCKS5 handshake and parse the CONNECT request.
///
/// If `auth` is `Some(&state)` the server insists on RFC 1929
/// USERNAME/PASSWORD authentication (method `0x02`) and runs the sub-
/// negotiation immediately after the method selection. Failed auth is
/// signalled with `[0x01, 0x01]` and propagated as `Err`. When `auth`
/// is `None` the legacy NO_AUTH (method `0x00`) path is used.
///
/// On success the caller still has to send the SOCKS5 reply via
/// [`reply`].
pub async fn handshake<S>(stream: &mut S, auth: Option<Arc<AuthState>>) -> Result<ConnectRequest>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let require_user_pass = auth.is_some();

    // 1. Method negotiation: VER | NMETHODS | METHODS...
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != SOCKS_VERSION {
        bail!("unsupported SOCKS version: {}", head[0]);
    }
    let nmethods = head[1] as usize;
    if nmethods == 0 {
        bail!("RFC 1928: client offered NMETHODS=0, must be ≥ 1");
    }
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    let chosen = if require_user_pass {
        METHOD_USER_PASS
    } else {
        METHOD_NO_AUTH
    };
    if !methods.contains(&chosen) {
        stream
            .write_all(&[SOCKS_VERSION, METHOD_NO_ACCEPTABLE])
            .await?;
        if require_user_pass {
            bail!("client did not offer METHOD_USER_PASS (0x02)");
        } else {
            bail!("client did not offer METHOD_NO_AUTH");
        }
    }
    stream.write_all(&[SOCKS_VERSION, chosen]).await?;

    // 1a. RFC 1929 sub-negotiation when USER/PASS was selected. On
    // success we remember the account name so per-account policy (the
    // `.onion` gate) can be applied by the caller after the handshake.
    let mut authed_user: Option<String> = None;
    if let Some(state) = auth {
        let (username, password) = read_rfc1929_credentials(stream).await?;
        let ok = {
            let state = Arc::clone(&state);
            let u = username.clone();
            let p = password;
            tokio::task::spawn_blocking(move || state.verify(&u, &p))
                .await
                .unwrap_or(false)
        };
        if ok {
            stream
                .write_all(&[RFC1929_VERSION, RFC1929_STATUS_OK])
                .await?;
            authed_user = Some(username);
        } else {
            stream
                .write_all(&[RFC1929_VERSION, RFC1929_STATUS_FAIL])
                .await?;
            bail!("authentication failed for user {username:?}");
        }
    }

    // 2. Request: VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await?;
    if req[0] != SOCKS_VERSION {
        bail!("invalid version in request: {}", req[0]);
    }
    if req[1] != CMD_CONNECT {
        reply(stream, Reply::CommandNotSupported).await.ok();
        bail!("only CONNECT is supported, got: {}", req[1]);
    }

    let host = match req[3] {
        ATYP_IPV4 => {
            let mut a = [0u8; 4];
            stream.read_exact(&mut a).await?;
            format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut buf = vec![0u8; len[0] as usize];
            stream.read_exact(&mut buf).await?;
            String::from_utf8(buf)?
        }
        ATYP_IPV6 => {
            let mut a = [0u8; 16];
            stream.read_exact(&mut a).await?;
            Ipv6Addr::from(a).to_string()
        }
        other => {
            reply(stream, Reply::AddressTypeNotSupported).await.ok();
            bail!("unsupported address type: {}", other);
        }
    };

    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);

    Ok(ConnectRequest {
        host,
        port,
        authed_user,
    })
}

/// Send a SOCKS5 reply to the client. BND.ADDR/BND.PORT are zeroed —
/// this is acceptable for CONNECT, where the real egress address is hidden
/// behind Tor anyway.
pub async fn reply<S>(stream: &mut S, code: Reply) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let frame = [SOCKS_VERSION, code as u8, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0];
    stream.write_all(&frame).await?;
    Ok(())
}

/// Read an RFC 1929 USER/PASS message from the wire and return the
/// decoded `(username, password)`. UNAME and PASSWD are interpreted as
/// UTF-8 (which is what every SOCKS5 client in the wild sends).
async fn read_rfc1929_credentials<S>(stream: &mut S) -> Result<(String, String)>
where
    S: AsyncRead + Unpin,
{
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != RFC1929_VERSION {
        bail!("RFC 1929: unexpected version {}", head[0]);
    }
    let ulen = head[1] as usize;
    let mut uname = vec![0u8; ulen];
    stream.read_exact(&mut uname).await?;
    let mut plen_buf = [0u8; 1];
    stream.read_exact(&mut plen_buf).await?;
    let plen = plen_buf[0] as usize;
    let mut passwd = vec![0u8; plen];
    stream.read_exact(&mut passwd).await?;
    let username =
        String::from_utf8(uname).map_err(|_| anyhow::anyhow!("RFC 1929: UNAME is not UTF-8"))?;
    let password =
        String::from_utf8(passwd).map_err(|_| anyhow::anyhow!("RFC 1929: PASSWD is not UTF-8"))?;
    Ok((username, password))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};

    /// Run the handshake on one half of a duplex pipe, drive the client
    /// script on the other half. Returns the negotiated `ConnectRequest`
    /// plus everything the server wrote (so tests can inspect replies).
    async fn run_handshake(
        client_script: impl FnOnce(DuplexStream) -> futures::future::BoxFuture<'static, Vec<u8>>
            + Send
            + 'static,
    ) -> (Result<ConnectRequest>, Vec<u8>) {
        run_handshake_with(client_script, None).await
    }

    async fn run_handshake_with(
        client_script: impl FnOnce(DuplexStream) -> futures::future::BoxFuture<'static, Vec<u8>>
            + Send
            + 'static,
        auth: Option<AuthState>,
    ) -> (Result<ConnectRequest>, Vec<u8>) {
        let (server_half, client_half) = duplex(256);

        let client_task = tokio::spawn(client_script(client_half));
        let mut server_half = server_half;
        let auth = auth.map(std::sync::Arc::new);
        let server_res = handshake(&mut server_half, auth).await;
        // Drop the server-side half so the client side reads EOF when it
        // finishes its script.
        drop(server_half);
        let server_writes = client_task.await.expect("client task panic");
        (server_res, server_writes)
    }

    fn client_ipv4_connect(
        addr: [u8; 4],
        port: u16,
    ) -> impl FnOnce(DuplexStream) -> futures::future::BoxFuture<'static, Vec<u8>> + Send + 'static
    {
        move |mut s| {
            Box::pin(async move {
                // method neg + no-auth
                s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
                let mut method_reply = [0u8; 2];
                s.read_exact(&mut method_reply).await.unwrap();
                // CONNECT IPv4
                let mut req = vec![0x05, 0x01, 0x00, 0x01];
                req.extend_from_slice(&addr);
                req.extend_from_slice(&port.to_be_bytes());
                s.write_all(&req).await.unwrap();
                // drain whatever the server wrote (including any reply)
                let mut buf = Vec::new();
                buf.extend_from_slice(&method_reply);
                let _ = s.read_to_end(&mut buf).await;
                buf
            })
        }
    }

    #[tokio::test]
    async fn parses_ipv4_connect() {
        let (res, writes) = run_handshake(client_ipv4_connect([93, 184, 216, 34], 443)).await;
        let req = res.expect("handshake ok");
        assert_eq!(req.host, "93.184.216.34");
        assert_eq!(req.port, 443);
        assert!(
            req.authed_user.is_none(),
            "anonymous (NO_AUTH) path records no account"
        );
        // Server's method-selection reply: 0x05 0x00.
        assert_eq!(&writes[..2], &[0x05, 0x00]);
    }

    #[tokio::test]
    async fn parses_domain_connect() {
        let (res, _writes) = run_handshake(|mut s| {
            Box::pin(async move {
                s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
                let mut method_reply = [0u8; 2];
                s.read_exact(&mut method_reply).await.unwrap();
                let host = b"example.com";
                let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
                req.extend_from_slice(host);
                req.extend_from_slice(&80u16.to_be_bytes());
                s.write_all(&req).await.unwrap();
                let mut buf = method_reply.to_vec();
                let _ = s.read_to_end(&mut buf).await;
                buf
            })
        })
        .await;
        let req = res.expect("handshake ok");
        assert_eq!(req.host, "example.com");
        assert_eq!(req.port, 80);
    }

    #[tokio::test]
    async fn parses_ipv6_connect() {
        let (res, _writes) = run_handshake(|mut s| {
            Box::pin(async move {
                s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
                let mut method_reply = [0u8; 2];
                s.read_exact(&mut method_reply).await.unwrap();
                let addr = std::net::Ipv6Addr::LOCALHOST.octets();
                let mut req = vec![0x05, 0x01, 0x00, 0x04];
                req.extend_from_slice(&addr);
                req.extend_from_slice(&9050u16.to_be_bytes());
                s.write_all(&req).await.unwrap();
                let mut buf = method_reply.to_vec();
                let _ = s.read_to_end(&mut buf).await;
                buf
            })
        })
        .await;
        let req = res.expect("handshake ok");
        assert_eq!(req.host, "::1");
        assert_eq!(req.port, 9050);
    }

    #[tokio::test]
    async fn rejects_wrong_version() {
        let (res, _writes) = run_handshake(|mut s| {
            Box::pin(async move {
                s.write_all(&[0x04, 0x01, 0x00]).await.unwrap();
                let mut buf = Vec::new();
                let _ = s.read_to_end(&mut buf).await;
                buf
            })
        })
        .await;
        let err = res.expect_err("must reject");
        assert!(format!("{err}").contains("SOCKS version"));
    }

    #[tokio::test]
    async fn rejects_when_no_acceptable_method() {
        let (res, writes) = run_handshake(|mut s| {
            Box::pin(async move {
                // Only USERNAME/PASSWORD offered, we don't support that.
                s.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
                let mut buf = Vec::new();
                let _ = s.read_to_end(&mut buf).await;
                buf
            })
        })
        .await;
        res.expect_err("must reject");
        // 0xFF = no acceptable method
        assert_eq!(&writes[..2], &[0x05, 0xFF]);
    }

    #[tokio::test]
    async fn rejects_bind_with_command_not_supported() {
        let (res, writes) = run_handshake(|mut s| {
            Box::pin(async move {
                s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
                let mut method_reply = [0u8; 2];
                s.read_exact(&mut method_reply).await.unwrap();
                // CMD=BIND(0x02)
                let req = vec![0x05, 0x02, 0x00, 0x01, 1, 2, 3, 4, 0, 80];
                s.write_all(&req).await.unwrap();
                let mut buf = method_reply.to_vec();
                let _ = s.read_to_end(&mut buf).await;
                buf
            })
        })
        .await;
        res.expect_err("BIND must be refused");
        // After method-selection reply, server should have written a SOCKS5
        // error reply with REP=0x07 (Command not supported).
        let reply_frame = &writes[2..];
        assert_eq!(reply_frame[0], 0x05);
        assert_eq!(reply_frame[1], 0x07);
    }

    #[tokio::test]
    async fn rejects_unknown_atyp() {
        let (res, writes) = run_handshake(|mut s| {
            Box::pin(async move {
                s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
                let mut method_reply = [0u8; 2];
                s.read_exact(&mut method_reply).await.unwrap();
                // ATYP=0x07 (unsupported)
                s.write_all(&[0x05, 0x01, 0x00, 0x07]).await.unwrap();
                let mut buf = method_reply.to_vec();
                let _ = s.read_to_end(&mut buf).await;
                buf
            })
        })
        .await;
        res.expect_err("unknown ATYP");
        let reply_frame = &writes[2..];
        assert_eq!(reply_frame[1], 0x08);
    }

    #[tokio::test]
    async fn reply_writes_canonical_frame() {
        let (mut server, mut client) = duplex(64);
        reply(&mut server, Reply::Success).await.unwrap();
        drop(server);
        let mut buf = Vec::new();
        client.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    }

    #[tokio::test]
    async fn rejects_zero_nmethods() {
        let (res, writes) = run_handshake(|mut s| {
            Box::pin(async move {
                // VER=5, NMETHODS=0 — violates RFC 1928 §3.
                s.write_all(&[0x05, 0x00]).await.unwrap();
                let mut buf = Vec::new();
                let _ = s.read_to_end(&mut buf).await;
                buf
            })
        })
        .await;
        let err = res.expect_err("must reject NMETHODS=0");
        assert!(
            format!("{err}").contains("NMETHODS=0"),
            "error should mention NMETHODS=0: {err}"
        );
        // Server must not write anything to the stream.
        assert!(writes.is_empty(), "server should not reply for NMETHODS=0");
    }

    // -------------------------- USER/PASS auth path --------------------------

    fn one_user_state(name: &str, password: &str) -> AuthState {
        let user = auth::User {
            name: name.into(),
            hash: auth::compute_hash(password).unwrap(),
            is_enabled: true,
            allowed_onion: false,
        };
        AuthState::build(&auth::UsersConfig { users: vec![user] }).unwrap()
    }

    fn rfc1929_frame(user: &str, passwd: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(3 + user.len() + passwd.len());
        out.push(0x01); // VER
        out.push(user.len() as u8);
        out.extend_from_slice(user.as_bytes());
        out.push(passwd.len() as u8);
        out.extend_from_slice(passwd.as_bytes());
        out
    }

    fn user_pass_then_connect(
        user: String,
        passwd: String,
        addr: [u8; 4],
        port: u16,
    ) -> impl FnOnce(DuplexStream) -> futures::future::BoxFuture<'static, Vec<u8>> + Send + 'static
    {
        move |mut s| {
            Box::pin(async move {
                // Method negotiation: offer 0x02
                s.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
                let mut method_reply = [0u8; 2];
                s.read_exact(&mut method_reply).await.unwrap();

                // RFC 1929 auth sub-negotiation
                s.write_all(&rfc1929_frame(&user, &passwd)).await.unwrap();
                let mut auth_reply = [0u8; 2];
                s.read_exact(&mut auth_reply).await.unwrap();

                // CONNECT IPv4 follows only when auth accepted.
                if auth_reply[1] == 0x00 {
                    let mut req = vec![0x05, 0x01, 0x00, 0x01];
                    req.extend_from_slice(&addr);
                    req.extend_from_slice(&port.to_be_bytes());
                    s.write_all(&req).await.unwrap();
                }

                let mut buf = Vec::new();
                buf.extend_from_slice(&method_reply);
                buf.extend_from_slice(&auth_reply);
                let _ = s.read_to_end(&mut buf).await;
                buf
            })
        }
    }

    #[tokio::test]
    async fn user_pass_happy_path() {
        let state = one_user_state("alice", "secret");
        let (res, writes) = run_handshake_with(
            user_pass_then_connect("alice".into(), "secret".into(), [1, 2, 3, 4], 80),
            Some(state),
        )
        .await;
        let req = res.expect("handshake ok");
        assert_eq!(req.host, "1.2.3.4");
        assert_eq!(req.port, 80);
        assert_eq!(
            req.authed_user.as_deref(),
            Some("alice"),
            "successful auth must record the account name"
        );
        // Method-selection picked 0x02; RFC 1929 replied [0x01, 0x00].
        assert_eq!(&writes[..2], &[0x05, 0x02]);
        assert_eq!(&writes[2..4], &[0x01, 0x00]);
    }

    #[tokio::test]
    async fn user_pass_wrong_password_rejected() {
        let state = one_user_state("alice", "secret");
        let (res, writes) = run_handshake_with(
            user_pass_then_connect("alice".into(), "WRONG".into(), [1, 2, 3, 4], 80),
            Some(state),
        )
        .await;
        res.expect_err("must reject");
        assert_eq!(&writes[..2], &[0x05, 0x02]);
        assert_eq!(&writes[2..4], &[0x01, 0x01], "RFC 1929 fail status");
    }

    #[tokio::test]
    async fn user_pass_unknown_user_rejected_silently() {
        let state = one_user_state("alice", "secret");
        let (res, writes) = run_handshake_with(
            user_pass_then_connect("mallory".into(), "anything".into(), [1, 2, 3, 4], 80),
            Some(state),
        )
        .await;
        res.expect_err("must reject");
        // Same response shape as a wrong password — no info leak.
        assert_eq!(&writes[..2], &[0x05, 0x02]);
        assert_eq!(&writes[2..4], &[0x01, 0x01]);
    }

    #[tokio::test]
    async fn user_pass_required_but_client_offers_only_no_auth() {
        let state = one_user_state("alice", "secret");
        let (res, writes) = run_handshake_with(
            |mut s| {
                Box::pin(async move {
                    s.write_all(&[0x05, 0x01, 0x00]).await.unwrap(); // only NO_AUTH
                    let mut buf = Vec::new();
                    let _ = s.read_to_end(&mut buf).await;
                    buf
                })
            },
            Some(state),
        )
        .await;
        res.expect_err("must reject");
        assert_eq!(&writes[..2], &[0x05, 0xFF], "no acceptable method");
    }

    #[tokio::test]
    async fn no_auth_required_but_client_offers_only_user_pass() {
        // When auth is disabled, a client offering only 0x02 is told there is
        // no acceptable method (we don't downgrade to USER/PASS without
        // configured users — that would be a foot-gun).
        let (res, writes) = run_handshake(|mut s| {
            Box::pin(async move {
                s.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
                let mut buf = Vec::new();
                let _ = s.read_to_end(&mut buf).await;
                buf
            })
        })
        .await;
        res.expect_err("must reject");
        assert_eq!(&writes[..2], &[0x05, 0xFF]);
    }

    #[tokio::test]
    async fn user_pass_disabled_user_treated_as_failure() {
        // Disabled user with correct password should still be rejected,
        // returning the standard `[0x01, 0x01]` failure.
        let user = auth::User {
            name: "alice".into(),
            hash: auth::compute_hash("secret").unwrap(),
            is_enabled: false,
            allowed_onion: false,
        };
        let state = AuthState::build(&auth::UsersConfig { users: vec![user] }).unwrap();
        let (res, writes) = run_handshake_with(
            user_pass_then_connect("alice".into(), "secret".into(), [1, 2, 3, 4], 80),
            Some(state),
        )
        .await;
        res.expect_err("must reject");
        assert_eq!(&writes[2..4], &[0x01, 0x01]);
    }

    // ---------------------- SOCKS5 edge cases --------------------------------

    #[tokio::test]
    async fn nmethods_255_accepted() {
        let (res, _writes) = run_handshake(|mut s| {
            Box::pin(async move {
                let mut msg = vec![0x05, 0xFF]; // NMETHODS=255
                msg.extend(std::iter::repeat_n(0x02, 254));
                msg.push(0x00); // last method is NO_AUTH
                s.write_all(&msg).await.unwrap();
                let mut method_reply = [0u8; 2];
                s.read_exact(&mut method_reply).await.unwrap();
                let host = b"example.com";
                let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
                req.extend_from_slice(host);
                req.extend_from_slice(&80u16.to_be_bytes());
                s.write_all(&req).await.unwrap();
                let mut buf = method_reply.to_vec();
                let _ = s.read_to_end(&mut buf).await;
                buf
            })
        })
        .await;
        let req = res.expect("NMETHODS=255 with NO_AUTH offered should succeed");
        assert_eq!(req.host, "example.com");
    }

    #[tokio::test]
    async fn domain_max_length_255() {
        let long_domain = "a".repeat(255);
        let domain_clone = long_domain.clone();
        let (res, _writes) = run_handshake(move |mut s| {
            Box::pin(async move {
                s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
                let mut method_reply = [0u8; 2];
                s.read_exact(&mut method_reply).await.unwrap();
                let mut req = vec![0x05, 0x01, 0x00, 0x03, 0xFF]; // 0xFF = 255
                req.extend_from_slice(domain_clone.as_bytes());
                req.extend_from_slice(&443u16.to_be_bytes());
                s.write_all(&req).await.unwrap();
                let mut buf = method_reply.to_vec();
                let _ = s.read_to_end(&mut buf).await;
                buf
            })
        })
        .await;
        let req = res.expect("255-byte domain should parse");
        assert_eq!(req.host, long_domain);
        assert_eq!(req.port, 443);
    }

    #[tokio::test]
    async fn stream_closes_during_method_read() {
        let (res, _writes) = run_handshake(|mut s| {
            Box::pin(async move {
                s.write_all(&[0x05, 0x02, 0x00]).await.unwrap();
                // close before server can read second method byte
                drop(s);
                Vec::new()
            })
        })
        .await;
        // Server tries read_exact(2 bytes) for methods — might succeed
        // or might get EOF. Either is acceptable; the point is no panic.
        let _ = res;
    }

    #[tokio::test]
    async fn reply_all_codes() {
        use Reply::*;
        for code in [
            Success,
            GeneralFailure,
            ConnectionNotAllowed,
            NetworkUnreachable,
            HostUnreachable,
            ConnectionRefused,
            TtlExpired,
            CommandNotSupported,
            AddressTypeNotSupported,
        ] {
            let (mut server, mut client) = duplex(64);
            reply(&mut server, code).await.unwrap();
            drop(server);
            let mut buf = Vec::new();
            client.read_to_end(&mut buf).await.unwrap();
            assert_eq!(buf.len(), 10);
            assert_eq!(buf[0], 0x05);
            assert_eq!(buf[1], code as u8);
        }
    }

    #[tokio::test]
    async fn rfc1929_max_length_username_and_password() {
        let long_user = "u".repeat(255);
        let long_pass = "p".repeat(255);
        let state = one_user_state(&long_user, &long_pass);
        let u = long_user.clone();
        let p = long_pass.clone();
        let (res, writes) = run_handshake_with(
            user_pass_then_connect(u, p, [10, 0, 0, 1], 8080),
            Some(state),
        )
        .await;
        let req = res.expect("max-length credentials should work");
        assert_eq!(req.host, "10.0.0.1");
        assert_eq!(&writes[2..4], &[0x01, 0x00]); // auth success
    }

    #[tokio::test]
    async fn rfc1929_empty_username_rejected() {
        let state = one_user_state("alice", "secret");
        let (res, writes) = run_handshake_with(
            user_pass_then_connect(String::new(), "secret".into(), [1, 2, 3, 4], 80),
            Some(state),
        )
        .await;
        res.expect_err("empty username should fail auth");
        assert_eq!(&writes[2..4], &[0x01, 0x01], "RFC 1929 fail status");
    }

    #[tokio::test]
    async fn multiple_methods_offered_picks_correct_one() {
        let (res, writes) = run_handshake(|mut s| {
            Box::pin(async move {
                // Offer 3 methods: GSSAPI(0x01), USER/PASS(0x02), NO_AUTH(0x00)
                s.write_all(&[0x05, 0x03, 0x01, 0x02, 0x00]).await.unwrap();
                let mut method_reply = [0u8; 2];
                s.read_exact(&mut method_reply).await.unwrap();
                // CONNECT IPv4
                let host = b"example.com";
                let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
                req.extend_from_slice(host);
                req.extend_from_slice(&80u16.to_be_bytes());
                s.write_all(&req).await.unwrap();
                let mut buf = method_reply.to_vec();
                let _ = s.read_to_end(&mut buf).await;
                buf
            })
        })
        .await;
        res.expect("should succeed with NO_AUTH offered");
        assert_eq!(&writes[..2], &[0x05, 0x00], "server should pick NO_AUTH");
    }

    // ------------------------------ is_onion ---------------------------------

    fn req(host: &str) -> ConnectRequest {
        ConnectRequest {
            host: host.into(),
            port: 443,
            authed_user: None,
        }
    }

    #[test]
    fn is_onion_matches_hidden_services() {
        assert!(req("facebookcorewwwi.onion").is_onion());
        assert!(req("sub.example.onion").is_onion());
        // Case-insensitive and tolerant of a trailing FQDN dot.
        assert!(req("Example.ONION").is_onion());
        assert!(req("duckduckgo.onion.").is_onion());
    }

    #[test]
    fn is_onion_rejects_clearnet_and_edge_cases() {
        assert!(!req("example.com").is_onion());
        assert!(!req("onion.example.com").is_onion());
        // A bare label with no preceding dot is not a hidden service.
        assert!(!req("onion").is_onion());
        assert!(!req("notonion").is_onion());
        // An ".onion" embedded mid-host but not as the final label.
        assert!(!req("foo.onion.evil.com").is_onion());
        assert!(!req("1.2.3.4").is_onion());
    }
}
