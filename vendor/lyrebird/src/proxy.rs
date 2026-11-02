use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use percent_encoding::percent_decode_str;
use socks5_proto::client::{self, Credentials};
use tokio::{net::TcpStream, time::Instant};
use url::Url;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

// Конфигурация принадлежит дочернему процессу и не раскрывает учётные данные.
pub(crate) struct Proxy {
    address: SocketAddr,
    credentials: Option<Credentials>,
}

impl Proxy {
    pub(crate) fn from_env() -> Result<Option<Arc<Self>>, ()> {
        match std::env::var_os("TOR_PT_PROXY") {
            None => Ok(None),
            Some(value) if value.is_empty() => Ok(None),
            Some(value) => Self::parse(value.to_str().ok_or(())?).map(|p| Some(Arc::new(p))),
        }
    }

    fn parse(input: &str) -> Result<Self, ()> {
        let authority = input.strip_prefix("socks5://").ok_or(())?;
        if authority.is_empty()
            || authority.bytes().any(|b| {
                b <= 0x20 || b == 0x7f || b == b'/' || b == b'?' || b == b'#' || b == b'\\'
            })
        {
            return Err(());
        }
        let (userinfo, hostport) = match authority.rsplit_once('@') {
            Some((user, host)) if !user.contains('@') => (Some(user), host),
            Some(_) => return Err(()),
            None => (None, authority),
        };
        let address: SocketAddr = hostport.parse().map_err(|_| ())?;
        if address.port() == 0 {
            return Err(());
        }
        let parsed = Url::parse(input).map_err(|_| ())?;
        if parsed.scheme() != "socks5"
            || parsed.host().is_none()
            || parsed.port() != Some(address.port())
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || !parsed.path().is_empty()
        {
            return Err(());
        }
        let credentials = match userinfo {
            None => None,
            Some(info) => {
                let (username, password) = info.split_once(':').ok_or(())?;
                let username = decode(username)?;
                let password = decode(password)?;
                Some(Credentials::new(username, password).map_err(|_| ())?)
            }
        };
        Ok(Self {
            address,
            credentials,
        })
    }

    pub(crate) async fn connect(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        if port == 0 {
            return Err(failure());
        }
        let deadline = Instant::now() + CONNECT_TIMEOUT;
        let mut stream = tokio::time::timeout_at(deadline, TcpStream::connect(self.address))
            .await
            .map_err(|_| failure())?
            .map_err(|_| failure())?;
        client::connect(&mut stream, host, port, self.credentials.as_ref(), deadline)
            .await
            .map_err(|_| failure())?;
        Ok(stream)
    }
}

fn failure() -> io::Error {
    io::Error::other("upstream SOCKS5 connection failed")
}

fn decode(value: &str) -> Result<String, ()> {
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len()
                || !bytes[i + 1].is_ascii_hexdigit()
                || !bytes[i + 2].is_ascii_hexdigit()
            {
                return Err(());
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    percent_decode_str(value)
        .decode_utf8()
        .map(|s| s.into_owned())
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_uri_validation() {
        for input in ["socks5://127.0.0.1:1080", "socks5://user:p%40ss@[::1]:1080"] {
            assert!(Proxy::parse(input).is_ok());
        }
        for input in [
            "http://127.0.0.1:1080",
            "socks5://example.com:1080",
            "socks5://u:%XX@127.0.0.1:1080",
            "socks5://u:@127.0.0.1:1080",
            "socks5://127.0.0.1:0",
            "socks5://127.0.0.1:1080/path",
        ] {
            assert!(Proxy::parse(input).is_err());
        }
    }
}
