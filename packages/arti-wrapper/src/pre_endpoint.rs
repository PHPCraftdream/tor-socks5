use resocks5_net::types::ProxyProtocol as EndpointProtocol;
use std::fmt;
use std::net::SocketAddr;

use arti_client::config::TorClientConfigBuilder;
use arti_client::TorClientConfig;
use tor_linkspec::ChannelMethod;
#[cfg(test)]
use url::Url;

#[derive(Debug, thiserror::Error)]
pub(crate) enum EndpointError {
    #[error("invalid SOCKS5 endpoint")]
    InvalidAddress,
    #[error("invalid SOCKS5 credentials")]
    InvalidCredentials,
    #[error("incomplete SOCKS5 credentials")]
    IncompleteCredentials,
}

pub(crate) fn reject_one_shot_pre_pt(settings: &crate::Settings) -> crate::Result<()> {
    if settings.pre_endpoint.is_some()
        && (settings
            .bridges
            .iter()
            .any(|bridge| bridge.transport.is_some())
            || !settings.extra_pt_protocols.is_empty()
            || settings.pt_binary.is_some())
    {
        return Err(crate::TorError::BuildConfig(
            "pre-PT one-shot bootstrap is unsupported; use create_unbootstrapped_with and retain the tunnel through shutdown".to_owned(),
        ));
    }
    Ok(())
}

/// Reject one-shot raw pre+PT setup; plain-pre and no-pre behavior is unchanged.
pub(crate) fn checked_raw(config: TorClientConfig) -> crate::Result<TorClientConfig> {
    if config.channel().outbound_proxy().is_some() && !config.transports().is_empty() {
        return Err(crate::TorError::BuildConfig(
            "pre-PT one-shot bootstrap_raw is unsupported; use create_unbootstrapped and retain the tunnel through shutdown".to_owned(),
        ));
    }
    Ok(config)
}

/// Require the trusted bundled executable and supported PT protocols.
pub(crate) fn validate_stock_pt(settings: &crate::Settings) -> crate::Result<()> {
    let protocols: Vec<&str> = settings
        .bridges
        .iter()
        .filter_map(|b| b.transport.as_deref())
        .chain(settings.extra_pt_protocols.iter().map(String::as_str))
        .collect();
    if protocols.is_empty() && settings.pt_binary.is_none() {
        return Ok(());
    }
    let current = std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok());
    let binary = settings
        .pt_binary
        .as_ref()
        .and_then(|p| p.canonicalize().ok());
    if !settings.stock_pt_proxy
        || current.is_none()
        || current != binary
        || protocols
            .iter()
            .any(|p| !matches!(*p, "obfs4" | "webtunnel"))
    {
        return Err(crate::TorError::BuildConfig(
            "pre proxy endpoint cannot guarantee routing for pluggable transports".to_owned(),
        ));
    }
    Ok(())
}

impl crate::Settings {
    /// Validate whether this configuration supports a bundled PT pre route.
    pub fn validate_stock_pt_proxy(&self) -> crate::Result<()> {
        validate_stock_pt(self)
    }
}

pub(crate) fn configure_pre_endpoint(
    builder: &mut TorClientConfigBuilder,
    settings: &crate::Settings,
) -> crate::Result<()> {
    let Some(endpoint) = settings.pre_endpoint.as_ref() else {
        return Ok(());
    };
    validate_stock_pt(settings)?;
    let uri = endpoint.proxy_uri().map_err(|_| {
        crate::TorError::BuildConfig("invalid pre proxy endpoint (details redacted)".to_owned())
    })?;
    let proxy = uri.parse().map_err(|_| {
        crate::TorError::BuildConfig("invalid pre proxy endpoint (details redacted)".to_owned())
    })?;
    if !matches!(
        proxy,
        tor_chanmgr::ProxyProtocol::Socks { .. } | tor_chanmgr::ProxyProtocol::HttpConnect { .. }
    ) {
        return Err(crate::TorError::BuildConfig(
            "pre endpoint must resolve to SOCKS5 or HTTP CONNECT".to_owned(),
        ));
    }
    builder.channel().outbound_proxy(Some(proxy));
    Ok(())
}

pub(crate) fn channel_proves_endpoint(actual: &ChannelMethod, requested: &ChannelMethod) -> bool {
    match (actual, requested) {
        (ChannelMethod::Direct(actual), ChannelMethod::Direct(requested)) => {
            actual.iter().any(|addr| requested.contains(addr))
        }
        (ChannelMethod::Pluggable(actual), ChannelMethod::Pluggable(requested)) => {
            actual == requested
        }
        _ => false,
    }
}

/// Owner's pre endpoint; the legacy name and SOCKS5 default are retained.
#[derive(Clone, PartialEq, Eq)]
pub struct Socks5PreEndpoint {
    protocol: EndpointProtocol,
    address: SocketAddr,
    username: Option<String>,
    password: Option<String>,
}

impl Socks5PreEndpoint {
    /// Construct the endpoint with optional username/password credentials.
    pub fn new(address: SocketAddr, credentials: Option<(String, String)>) -> Self {
        let (username, password) =
            credentials.map_or((None, None), |(user, pass)| (Some(user), Some(pass)));
        Self {
            protocol: EndpointProtocol::Socks5,
            address,
            username,
            password,
        }
    }

    /// The endpoint of a configured proxy pool member, protocol and credentials included.
    pub fn from_pool_member(endpoint: &client_acl::Socks5Endpoint) -> Self {
        Self::new(
            endpoint.address(),
            endpoint
                .credentials()
                .map(|(user, pass)| (user.to_owned(), pass.to_owned())),
        )
        .with_protocol(endpoint.protocol())
    }

    /// Select SOCKS5 or HTTP CONNECT; unsupported protocols fail config validation.
    pub fn with_protocol(mut self, protocol: EndpointProtocol) -> Self {
        self.protocol = protocol;
        self
    }

    pub(crate) fn proxy_uri(&self) -> Result<String, EndpointError> {
        if self.address.port() == 0 {
            return Err(EndpointError::InvalidAddress);
        }
        let scheme = match self.protocol {
            EndpointProtocol::Socks5 => "socks5",
            EndpointProtocol::Http => "http",
            EndpointProtocol::Https => return Err(EndpointError::InvalidAddress),
        };
        match (&self.username, &self.password) {
            (None, None) => {
                let mut url = url::Url::parse(&format!("{scheme}://{}", self.address))
                    .map_err(|_| EndpointError::InvalidAddress)?;
                url.set_path("");
                Ok(url.to_string())
            }
            (Some(username), Some(password)) => {
                if username.is_empty()
                    || password.is_empty()
                    || username.len() > 255
                    || password.len() > 255
                    || (self.protocol == EndpointProtocol::Http
                        && (username.contains(':')
                            || username.bytes().any(|byte| byte.is_ascii_control())
                            || password.bytes().any(|byte| byte.is_ascii_control())))
                {
                    return Err(EndpointError::InvalidCredentials);
                }
                let mut url = url::Url::parse(&format!("{scheme}://{}", self.address))
                    .map_err(|_| EndpointError::InvalidAddress)?;
                url.set_username(username)
                    .map_err(|_| EndpointError::InvalidCredentials)?;
                url.set_password(Some(password))
                    .map_err(|_| EndpointError::InvalidCredentials)?;
                Ok(url.to_string())
            }
            _ => Err(EndpointError::IncompleteCredentials),
        }
    }
}

impl fmt::Debug for Socks5PreEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Socks5PreEndpoint")
            .field("protocol", &self.protocol)
            .field("address", &self.address)
            .field("credentials", &self.username.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl crate::TorTunnel {
    /// Await PT shutdown; cancellation retains cleanup for another call.
    /// cancel-safe: yes — the client stays closed; manager-owned cleanup is retryable.
    pub async fn shutdown(&self) -> crate::Result<()> {
        self.inner
            .shutdown_pluggable_transports()
            .await
            .map_err(|_| crate::TorError::Shutdown)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_pre_preserves_protocol_identity_and_default_port() {
        let address: SocketAddr = "192.0.2.1:80".parse().unwrap();
        let socks =
            Socks5PreEndpoint::new(address, Some(("user".to_owned(), "password".to_owned())));
        let http = socks.clone().with_protocol(EndpointProtocol::Http);
        assert_ne!(socks, http);
        let uri = http.proxy_uri().unwrap();
        let parsed: tor_chanmgr::ProxyProtocol = uri.parse().unwrap();
        assert!(
            matches!(parsed, tor_chanmgr::ProxyProtocol::HttpConnect { addr, .. } if addr == address)
        );
        assert!(!format!("{http:?}").contains("password"));
        assert!(http
            .with_protocol(EndpointProtocol::Https)
            .proxy_uri()
            .is_err());
    }

    #[test]
    fn one_shot_rejects_pre_pt_without_constructing_client() {
        let mut settings = crate::Settings {
            pre_endpoint: Some(Socks5PreEndpoint::new(
                "127.0.0.1:9050".parse().unwrap(),
                None,
            )),
            extra_pt_protocols: vec!["obfs4".to_owned()],
            ..Default::default()
        };
        assert!(reject_one_shot_pre_pt(&settings).is_err());
        settings.pre_endpoint = None;
        assert!(reject_one_shot_pre_pt(&settings).is_ok());
        settings.pre_endpoint = Some(Socks5PreEndpoint::new(
            "127.0.0.1:9050".parse().unwrap(),
            None,
        ));
        settings.extra_pt_protocols.clear();
        assert!(reject_one_shot_pre_pt(&settings).is_ok());
    }

    #[test]
    fn proxy_uri_encodes_reserved_and_unicode_credentials() {
        let endpoint = Socks5PreEndpoint::new(
            "127.0.0.1:9050".parse().unwrap(),
            Some(("user:@/é".to_owned(), "p:ss/@雪".to_owned())),
        );
        let uri = endpoint.proxy_uri().unwrap();
        let encoded_uri = Url::parse(&uri).unwrap();
        assert_eq!(encoded_uri.username(), "user%3A%40%2F%C3%A9");
        assert_eq!(encoded_uri.password(), Some("p%3Ass%2F%40%E9%9B%AA"));
        assert!(!format!("{endpoint:?}").contains("雪"));
        assert!(!format!("{endpoint:?}").contains("p:ss"));
        let proxy = uri.parse::<tor_chanmgr::ProxyProtocol>().unwrap();
        let tor_chanmgr::ProxyProtocol::Socks { auth, .. } = &proxy else {
            panic!("SOCKS5 URI must parse to SOCKS protocol");
        };
        assert_eq!(
            format!("{auth:?}"),
            "Username([117, 115, 101, 114, 58, 64, 47, 195, 169], [112, 58, 115, 115, 47, 64, 233, 155, 170])"
        );
        assert_eq!(
            proxy.to_string(),
            "socks5://user%3A%40%2F%C3%A9:p%3Ass%2F%40%E9%9B%AA@127.0.0.1:9050"
        );
    }
}
