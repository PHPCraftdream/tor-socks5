//! Upstream SOCKS5 egress: a thin adapter over `resocks5-net`'s client.
//!
//! When an upstream proxy is configured (and enabled), the daemon
//! forwards each accepted CONNECT through it instead of dialing out via
//! Tor — chaining `client -> us -> upstream -> target`. The RFC 1928
//! CONNECT / RFC 1929 USERNAME-PASSWORD handshake itself is
//! `resocks5-net`'s; this module only owns the endpoint and credentials,
//! the whole-setup budget and the error mapping into `anyhow`.

use std::time::Duration;

use anyhow::{bail, Result};
use resocks5_net::connect::{dial_plain, AnyUpstream, DialOptions, HostPort};
use resocks5_net::types::ProxyConfig;
use resocks5_net::{socks5_rep_description, ConnectError, Stage};

/// Whole-budget deadline for one upstream setup attempt: TCP connect
/// (including DNS), method negotiation, RFC 1929 auth and the CONNECT
/// reply. Armed once per `connect` call and never renewed. On expiry the
/// partially set-up stream is dropped (closing the socket) and an error
/// is returned; an established relay is NOT bound by this budget — once
/// `connect` returns `Ok`, the deadline no longer applies to the
/// returned stream.
///
/// cancel-safe: yes — cancelling/dropping the future mid-setup simply
/// closes the in-progress socket via RAII; no shared state is mutated.
pub(crate) const UPSTREAM_SETUP_DEADLINE: Duration = Duration::from_secs(30);

/// Slack of the per-stage budgets over [`UPSTREAM_SETUP_DEADLINE`].
/// `resocks5-net`'s defaults are 10 s per stage, which would quietly
/// squeeze the whole-setup budget (and report `Stage::Handshake`
/// instead of `Stage::Total`); both are set well above the total so the
/// total deadline is always the one that fires.
const STAGE_SLACK: Duration = Duration::from_secs(5);

/// `server.rs` relays the returned stream with
/// `tokio::io::copy_bidirectional`, which needs these bounds; asserted
/// here so a library regression breaks the build, not a live relay.
const _: fn() = || {
    fn assert_stream_bounds<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin>() {}
    assert_stream_bounds::<AnyUpstream>();
};

/// A configured upstream SOCKS5 proxy used as the egress.
#[derive(Clone)]
pub struct Upstream {
    address: String,
    /// `Some((user, pass))` to authenticate via RFC 1929, `None` for an
    /// unauthenticated upstream.
    credentials: Option<(String, String)>,
    /// `resocks5-net`'s dial configuration, built once from `address` and
    /// the credentials. `None` when `address` is not a valid `host:port`
    /// pair — `connect` refuses instead of dialing a mangled endpoint,
    /// and `pick_upstream` fails the startup on it.
    proxy: Option<ProxyConfig>,
}

impl std::fmt::Debug for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Upstream")
            .field("address", &self.address)
            .field("has_auth", &self.has_auth())
            .finish()
    }
}

impl Upstream {
    pub fn new(address: String, credentials: Option<(String, String)>) -> Self {
        let proxy = HostPort::parse(&address).map(|hp| match &credentials {
            Some((user, pass)) => ProxyConfig::socks5(hp.host, hp.port).with_auth(user, pass),
            None => ProxyConfig::socks5(hp.host, hp.port),
        });
        Self {
            address,
            credentials,
            proxy,
        }
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    pub fn has_auth(&self) -> bool {
        self.credentials.is_some()
    }

    /// Startup check for `pick_upstream`: an address that is not a valid
    /// `host:port` pair is a startup error rather than a per-connection
    /// failure (the parse result is the one cached in `proxy`).
    pub(crate) fn is_valid_address(&self) -> bool {
        self.proxy.is_some()
    }

    /// Open a TCP connection to the upstream, run the SOCKS5 client
    /// handshake (with optional auth) and a CONNECT to `(host, port)`.
    /// On success the returned stream is positioned at the start of the
    /// tunnelled data and can be relayed directly to the client.
    pub async fn connect(&self, host: &str, port: u16) -> Result<AnyUpstream> {
        let Some(proxy) = &self.proxy else {
            bail!(
                "upstream address {:?} is not a valid host:port pair",
                self.address
            );
        };
        let opts = DialOptions::new()
            .with_connect_timeout(UPSTREAM_SETUP_DEADLINE + STAGE_SLACK)
            .with_handshake_timeout(UPSTREAM_SETUP_DEADLINE + STAGE_SLACK)
            .with_total_timeout(UPSTREAM_SETUP_DEADLINE);
        dial_plain(proxy, host, port, &opts)
            .await
            .map_err(|e| describe_connect_error(&self.address, e))
    }
}

/// Translate a typed `ConnectError` into an `anyhow::Error`: the message
/// keeps the wording this crate used before the migration, and the typed
/// error stays in the chain as the source so `downcast_ref` callers still
/// see it (with the underlying `io::Error` below it for the `Io` variant).
fn describe_connect_error(address: &str, err: ConnectError) -> anyhow::Error {
    let context = match &err {
        ConnectError::AuthFailed { status } => {
            format!("upstream rejected our credentials (status 0x{status:02x})")
        }
        ConnectError::MethodUnsupported { got: 0xFF, .. } => {
            "upstream rejected all offered auth methods".to_string()
        }
        ConnectError::MethodUnsupported { got, .. } => {
            format!("upstream selected method 0x{got:02x} which was not offered")
        }
        ConnectError::ProxyRejected {
            code: Some(code), ..
        } => format!(
            "upstream CONNECT failed (REP 0x{code:x}: {})",
            socks5_rep_description(*code)
        ),
        ConnectError::ProxyRejected { .. } => {
            "upstream CONNECT failed without a REP code".to_string()
        }
        ConnectError::Timeout {
            stage: Stage::Total,
            ..
        } => format!("upstream setup deadline of {UPSTREAM_SETUP_DEADLINE:?} exceeded"),
        // Per-stage budgets sit above the total one, so a plain
        // connect/handshake timeout should be unreachable; keep a
        // readable message if the library ever reports one.
        ConnectError::Timeout { .. } => "upstream setup timed out".to_string(),
        ConnectError::Protocol(v) => format!("upstream protocol violation: {v}"),
        // `Io` (and anything a future library version adds): keep the
        // socket error in the chain below this context — which
        // `classify_conn_failure` in `server.rs` relies on.
        _ => format!("connecting to upstream SOCKS5 {address}"),
    };
    anyhow::Error::new(err).context(context)
}

#[cfg(test)]
#[path = "upstream_tests.rs"]
mod tests;
