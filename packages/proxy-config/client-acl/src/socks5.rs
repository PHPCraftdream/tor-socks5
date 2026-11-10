use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;

use resocks5_net::types::ProxyProtocol;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Proxy endpoint with optional credentials; the legacy type name is retained.
#[derive(Clone, PartialEq, Eq)]
pub struct Socks5Endpoint {
    protocol: ProxyProtocol,
    address: SocketAddr,
    username: Option<String>,
    password: Option<String>,
}

impl Socks5Endpoint {
    /// Wire protocol selected explicitly, or SOCKS5 for the legacy format.
    pub fn protocol(&self) -> ProxyProtocol {
        self.protocol
    }

    /// Возвращает адрес прокси.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Возвращает имя и пароль, если задана аутентификация.
    pub fn credentials(&self) -> Option<(&str, &str)> {
        self.username.as_deref().zip(self.password.as_deref())
    }
}

impl fmt::Debug for Socks5Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Socks5Endpoint")
            .field("protocol", &self.protocol)
            .field("address", &self.address)
            .field("credentials", &self.credentials().map(|_| "<redacted>"))
            .finish()
    }
}

impl FromStr for Socks5Endpoint {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (protocol, value) = if let Some(value) = value.strip_prefix("socks5://") {
            (ProxyProtocol::Socks5, value)
        } else if let Some(value) = value.strip_prefix("http://") {
            (ProxyProtocol::Http, value)
        } else {
            let address = value.split_once('|').map_or(value, |(address, _)| address);
            if address.contains("://") {
                return Err("endpoint protocol must be socks5 or http".to_owned());
            }
            (ProxyProtocol::Socks5, value)
        };
        let (address, credentials) = value
            .split_once('|')
            .map_or((value, None), |(a, c)| (a, Some(c)));
        if value == "none" || value.is_empty() {
            return Err("endpoint value must not be empty or `none`".to_owned());
        }
        let address = SocketAddr::from_str(address).map_err(|_| {
            "endpoint address must be an IPv4 or bracketed IPv6 socket address".to_owned()
        })?;
        if address.port() == 0 {
            return Err("endpoint port must be nonzero".to_owned());
        }
        let (username, password) = match credentials {
            None => (None, None),
            Some(value) => {
                let (username, password) = value
                    .split_once(':')
                    .ok_or_else(|| "credentials must be username:password".to_owned())?;
                if username.contains(':')
                    || password.contains(':')
                    || username.contains('|')
                    || password.contains('|')
                    || username.is_empty()
                    || password.is_empty()
                    || username.len() > 255
                    || password.len() > 255
                    || (protocol == ProxyProtocol::Http
                        && (username.bytes().any(|byte| byte.is_ascii_control())
                            || password.bytes().any(|byte| byte.is_ascii_control())))
                {
                    return Err(
                        "credentials must be nonempty, delimiter-free, and at most 255 bytes each"
                            .to_owned(),
                    );
                }
                (Some(username.to_owned()), Some(password.to_owned()))
            }
        };
        Ok(Self {
            protocol,
            address,
            username,
            password,
        })
    }
}

impl Serialize for Socks5Endpoint {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let prefix = match self.protocol {
            ProxyProtocol::Socks5 => "",
            ProxyProtocol::Http => "http://",
            ProxyProtocol::Https => {
                return Err(serde::ser::Error::custom("unsupported proxy protocol"))
            }
        };
        let address = format!("{prefix}{}", self.address);
        match (&self.username, &self.password) {
            (Some(username), Some(password)) => {
                serializer.serialize_str(&format!("{address}|{username}:{password}"))
            }
            _ => serializer.serialize_str(&address),
        }
    }
}

impl<'de> Deserialize<'de> for Socks5Endpoint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_protocol_preserves_legacy_socks_and_separates_http_identity() {
        let legacy: Socks5Endpoint = "192.0.2.1:1080|user:password".parse().unwrap();
        let explicit: Socks5Endpoint = "socks5://192.0.2.1:1080|user:password".parse().unwrap();
        let http: Socks5Endpoint = "http://192.0.2.1:1080|user:password".parse().unwrap();
        assert_eq!(legacy, explicit);
        assert_eq!(legacy.protocol(), ProxyProtocol::Socks5);
        assert_eq!(http.protocol(), ProxyProtocol::Http);
        assert_ne!(legacy, http);
        assert!(!format!("{http:?}").contains("password"));
        assert!("https://192.0.2.1:443".parse::<Socks5Endpoint>().is_err());
    }

    #[test]
    fn http_protocol_and_credentials_round_trip_through_config() {
        #[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
        struct Record {
            endpoint: Socks5Endpoint,
        }
        for value in ["192.0.2.1:1080", "http://[2001:db8::1]:80|user:password"] {
            let record = Record {
                endpoint: value.parse().unwrap(),
            };
            let encoded = ktav::to_string(&record).unwrap();
            let decoded: Record = ktav::from_str(&encoded).unwrap();
            assert_eq!(record, decoded);
        }
    }

    #[test]
    fn parse_and_debug_redacts_credentials() {
        let endpoint: Socks5Endpoint = "[2001:db8::1]:1080|alice:secret".parse().unwrap();
        assert_eq!(endpoint.address().port(), 1080);
        assert!(!format!("{endpoint:?}").contains("secret"));
        assert!("192.0.2.1:0".parse::<Socks5Endpoint>().is_err());
        assert!("192.0.2.1:1080|user:".parse::<Socks5Endpoint>().is_err());
        assert!("192.0.2.1:1080|:pass".parse::<Socks5Endpoint>().is_err());
        assert!("192.0.2.1:1080|user:password:extra"
            .parse::<Socks5Endpoint>()
            .is_err());
    }
}
