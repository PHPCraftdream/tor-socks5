use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Адрес SOCKS5 и необязательные учётные данные.
#[derive(Clone, PartialEq, Eq)]
pub struct Socks5Endpoint {
    address: SocketAddr,
    username: Option<String>,
    password: Option<String>,
}

impl Socks5Endpoint {
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
            .field("address", &self.address)
            .field("credentials", &self.credentials().map(|_| "<redacted>"))
            .finish()
    }
}

impl FromStr for Socks5Endpoint {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
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
            address,
            username,
            password,
        })
    }
}

impl Serialize for Socks5Endpoint {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let address = self.address.to_string();
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

/// Явная отмена или замена настройки прокси.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointOverride {
    /// Отключить прокси, включая унаследованный.
    Disabled,
    /// Использовать указанный прокси.
    Endpoint(Socks5Endpoint),
}

/// Применяет настройку аккаунта поверх глобальной.
pub fn resolve_endpoint(
    global: Option<&EndpointOverride>,
    account: Option<&EndpointOverride>,
) -> Option<Socks5Endpoint> {
    match account.or(global) {
        Some(EndpointOverride::Endpoint(endpoint)) => Some(endpoint.clone()),
        Some(EndpointOverride::Disabled) | None => None,
    }
}

impl Serialize for EndpointOverride {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Disabled => serializer.serialize_str("none"),
            Self::Endpoint(endpoint) => endpoint.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for EndpointOverride {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct EndpointVisitor;

        impl<'de> serde::de::Visitor<'de> for EndpointVisitor {
            type Value = EndpointOverride;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("the literal `none` or a SOCKS5 endpoint")
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Err(E::custom("use the literal `none` scalar"))
            }

            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Err(E::custom("use the literal `none` scalar"))
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                if value == "none" {
                    Ok(EndpointOverride::Disabled)
                } else if value.is_empty() {
                    Err(E::custom("endpoint must be `none` or a SOCKS5 endpoint"))
                } else {
                    value
                        .parse()
                        .map(EndpointOverride::Endpoint)
                        .map_err(E::custom)
                }
            }
        }

        deserializer.deserialize_any(EndpointVisitor)
    }
}

/// Сериализация необязательной настройки прокси.
pub mod endpoint_field {
    use super::{Deserialize, Deserializer, EndpointOverride, Serializer};
    use serde::ser::Serialize as _;

    /// Сериализует значение настройки.
    pub fn serialize<S: Serializer>(
        value: &Option<EndpointOverride>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            None => serializer.serialize_str("inherit"),
            Some(value) => value.serialize(serializer),
        }
    }

    /// Десериализует явно заданную настройку.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<EndpointOverride>, D::Error> {
        EndpointOverride::deserialize(deserializer).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
