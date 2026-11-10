use arti_client::{ErrorKind, HasKind};
use resocks5_net::types::ProxyProtocol;
use resocks5_net::ConnectError;

use crate::TorError;

/// Whom a failed post attempt points at; decides whether a pool rotates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostBlame {
    /// The proxy looks down or broken; counts toward its quarantine.
    ProxyHard,
    /// The proxy failed in a way that may be transient or specific to this try.
    ProxySoft,
    /// Not the proxy: the target, Tor itself, or local configuration.
    NotProxy,
}

/// A failed post attempt together with the party it points at.
#[derive(Debug)]
pub struct PostFailure {
    /// The error as the non-pool path reports it.
    pub error: TorError,
    /// Whom the failure points at.
    pub blame: PostBlame,
}

impl PostFailure {
    pub(crate) fn new(error: TorError, blame: PostBlame) -> Self {
        Self { error, blame }
    }

    pub(crate) fn local(error: TorError) -> Self {
        Self::new(error, PostBlame::NotProxy)
    }
}

/// Blame for a failure to open the Tor stream that carries the proxy dial.
pub(crate) fn blame_dial(error: &TorError) -> PostBlame {
    let TorError::Connect { source, .. } = error else {
        return PostBlame::NotProxy;
    };
    match source.kind() {
        ErrorKind::RemoteConnectionRefused
        | ErrorKind::RemoteNetworkFailed
        | ErrorKind::RemoteNetworkTimeout => PostBlame::ProxyHard,
        ErrorKind::ExitPolicyRejected
        | ErrorKind::ForbiddenStreamTarget
        | ErrorKind::RemoteStreamReset
        | ErrorKind::RemoteStreamClosed
        | ErrorKind::RemoteStreamError => PostBlame::ProxySoft,
        _ => PostBlame::NotProxy,
    }
}

/// Blame for a failure of the SOCKS5 / HTTP CONNECT handshake with the proxy.
pub(crate) fn blame_handshake(error: &ConnectError) -> PostBlame {
    match error {
        ConnectError::Timeout { .. } | ConnectError::Io { .. } => PostBlame::ProxySoft,
        ConnectError::ProxyRejected { protocol, code, .. } => match (*protocol, *code) {
            (ProxyProtocol::Socks5, Some(3..=6)) => PostBlame::NotProxy,
            (ProxyProtocol::Socks5, Some(7 | 8)) => PostBlame::ProxyHard,
            (ProxyProtocol::Http, Some(400 | 405 | 407)) => PostBlame::ProxyHard,
            (ProxyProtocol::Http, Some(502 | 504)) => PostBlame::NotProxy,
            _ => PostBlame::ProxySoft,
        },
        ConnectError::MethodUnsupported { .. }
        | ConnectError::AuthFailed { .. }
        | ConnectError::Protocol(_)
        | ConnectError::CleartextCredentialsRefused
        | ConnectError::SecureAuthUnsupported => PostBlame::ProxyHard,
        ConnectError::InvalidTarget(_) => PostBlame::NotProxy,
        _ => PostBlame::ProxySoft,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rejected(protocol: ProxyProtocol, code: u16) -> ConnectError {
        ConnectError::ProxyRejected {
            protocol,
            code: Some(code),
            response: String::new(),
        }
    }

    #[test]
    fn socks5_replies_split_target_faults_from_proxy_faults() {
        for code in 3..=6 {
            assert_eq!(
                blame_handshake(&rejected(ProxyProtocol::Socks5, code)),
                PostBlame::NotProxy
            );
        }
        for code in [7, 8] {
            assert_eq!(
                blame_handshake(&rejected(ProxyProtocol::Socks5, code)),
                PostBlame::ProxyHard
            );
        }
        for code in [1, 2] {
            assert_eq!(
                blame_handshake(&rejected(ProxyProtocol::Socks5, code)),
                PostBlame::ProxySoft
            );
        }
    }

    #[test]
    fn http_statuses_split_target_faults_from_proxy_faults() {
        for code in [400, 405, 407] {
            assert_eq!(
                blame_handshake(&rejected(ProxyProtocol::Http, code)),
                PostBlame::ProxyHard
            );
        }
        for code in [502, 504] {
            assert_eq!(
                blame_handshake(&rejected(ProxyProtocol::Http, code)),
                PostBlame::NotProxy
            );
        }
        for code in [403, 503, 500] {
            assert_eq!(
                blame_handshake(&rejected(ProxyProtocol::Http, code)),
                PostBlame::ProxySoft
            );
        }
    }

    #[test]
    fn broken_protocol_and_local_mistakes_are_classified() {
        assert_eq!(
            blame_handshake(&ConnectError::AuthFailed { status: 1 }),
            PostBlame::ProxyHard
        );
        assert_eq!(
            blame_handshake(&ConnectError::CleartextCredentialsRefused),
            PostBlame::ProxyHard
        );
        assert_eq!(
            blame_handshake(&ConnectError::InvalidTarget("x".to_owned())),
            PostBlame::NotProxy
        );
    }

    #[test]
    fn errors_that_never_reached_the_proxy_are_not_its_fault() {
        assert_eq!(
            blame_dial(&TorError::BuildConfig("x".to_owned())),
            PostBlame::NotProxy
        );
    }
}
