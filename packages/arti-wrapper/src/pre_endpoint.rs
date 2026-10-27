use std::fmt;
use std::net::SocketAddr;

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

/// SOCKS5 endpoint used as an owner's pre-transport.
#[derive(Clone, PartialEq, Eq)]
pub struct Socks5PreEndpoint {
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
            address,
            username,
            password,
        }
    }

    pub(crate) fn proxy_uri(&self) -> Result<String, EndpointError> {
        match (&self.username, &self.password) {
            (None, None) => {
                let mut url = url::Url::parse(&format!("socks5://{}", self.address))
                    .map_err(|_| EndpointError::InvalidAddress)?;
                url.set_path("");
                Ok(url.to_string())
            }
            (Some(username), Some(password)) => {
                if username.is_empty()
                    || password.is_empty()
                    || username.len() > 255
                    || password.len() > 255
                {
                    return Err(EndpointError::InvalidCredentials);
                }
                let mut url = url::Url::parse(&format!("socks5://{}", self.address))
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
            .field("address", &self.address)
            .field("credentials", &self.username.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let tor_chanmgr::ProxyProtocol::Socks { auth, .. } = proxy else {
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
