//! Server-side startup helpers: the first-run bridges file, the auth proof
//! verifier, onion gating and per-connection failure classification.

use std::path::Path;

use crate::config::Config;
use tor_socks5_runtime::conn_health::{ConnErrorKind, ConnStage};

/// First run on a main config the operator made by hand: create the bridges
/// file with the defaults in `cfg`, so there is a file to edit. Taken under
/// the config's path lock like every other writer of the pool, and re-checked
/// inside it. Convenience only: a failure is logged, not fatal. Returns
/// whether the file was created.
pub(crate) fn ensure_bridges_file(cfg: &Config, config_path: &Path) -> bool {
    use persist_lock::{PathLock, CLI_LOCK_WAIT};

    let bridges_path = Config::bridges_path(config_path);
    if bridges_path.exists() {
        return false;
    }
    let _lock = match PathLock::acquire_bounded(config_path, CLI_LOCK_WAIT) {
        Ok(lock) => lock,
        Err(error) => {
            tracing::warn!(%error, path = %bridges_path.display(), "could not lock the config to create the bridges file");
            return false;
        }
    };
    if bridges_path.exists() {
        return false;
    }
    match cfg.write_bridges(config_path) {
        Ok(()) => {
            tracing::info!(path = %bridges_path.display(), "created the bridges file with defaults");
            true
        }
        Err(error) => {
            tracing::warn!(%error, path = %bridges_path.display(), "could not create the bridges file");
            false
        }
    }
}

// Подтверждение выдаётся только после проверки учётных данных.
pub(crate) struct AuthStateVerifier(pub(crate) std::sync::Arc<auth::AuthState>);

impl socks5_proto::ProofVerifier for AuthStateVerifier {
    type Proof = auth::CredentialProof;

    fn verify_proof(&self, username: &str, password: &str) -> Option<Self::Proof> {
        self.0.verify_proof(username, password)
    }

    fn username<'a>(&self, proof: &'a Self::Proof) -> &'a str {
        proof.username()
    }
}

/// Decide whether a `.onion` connection is allowed for this request.
///
/// * No authenticator (anonymous proxy) → allowed: there is no account
///   to gate on.
/// * Authenticated → allowed iff the named account carries
///   `allowed_onion` (and is still enabled).
/// * Auth required but no account on the request (should not happen for
///   a completed handshake) → denied, fail-closed.
#[cfg(test)]
pub(crate) fn onion_permitted(auth: Option<&auth::AuthState>, authed_user: Option<&str>) -> bool {
    match (auth, authed_user) {
        (None, _) => true,
        (Some(state), Some(name)) => state.allowed_onion(name),
        (Some(_), None) => false,
    }
}

/// Internal, stable context tags `handle_client` attaches to each stage.
/// Classification string-matches ONLY these — never arbitrary error message
/// text (message text is not a stable classification key).
pub(crate) const STAGE_HANDSHAKE: &str = "SOCKS5 handshake";
pub(crate) const STAGE_CONNECT_TOR: &str = "tor connect";
pub(crate) const STAGE_CONNECT_UPSTREAM: &str = "upstream connect";
pub(crate) const STAGE_RELAY: &str = "relay";

/// Classify a [`handle_client`] failure into a stage and an error kind, by
/// the *type* of its root cause and the stage context tag in the chain,
/// never by string-matching arbitrary rendered error message text (only the
/// internal `STAGE_*` context tags above are matched — message text is not a
/// stable classification key).
///
/// Order of checks:
/// 1. Stage: the first chain cause matching a `STAGE_*` tag wins (relay →
///    handshake → connect → other).
/// 2. Kind: any `arti_wrapper::TorError::Connect` in the chain →
///    [`ConnErrorKind::Tor`], regardless of stage (a Tor connect failure is
///    unambiguous and takes priority over any incidental I/O wrapping).
/// 3. Otherwise by stage: handshake → Client (everything escaping the
///    handshake phase is client-side, including the deadline); relay →
///    Relay when a chain cause is a client-drop-ish `io::Error`
///    (ConnectionReset/Aborted/BrokenPipe/UnexpectedEof), else Other;
///    connect → Other (a non-Tor connect failure is not attributable to the
///    SOCKS client — the `connect_failed` counter carries the stage signal);
///    other stage → Client when a chain cause is a drop-ish `io::Error`
///    (after the stage tags the only untagged I/O escape path is the SOCKS
///    reply writes, which are client-side), else Other.
pub(crate) fn classify_conn_failure(err: &anyhow::Error) -> (ConnStage, ConnErrorKind) {
    let stage = if err.chain().any(|cause| cause.to_string() == STAGE_RELAY) {
        ConnStage::Relay
    } else if err
        .chain()
        .any(|cause| cause.to_string() == STAGE_HANDSHAKE)
    {
        ConnStage::Handshake
    } else if err.chain().any(|cause| {
        cause.to_string() == STAGE_CONNECT_TOR || cause.to_string() == STAGE_CONNECT_UPSTREAM
    }) {
        ConnStage::Connect
    } else {
        ConnStage::Other
    };

    let is_dropish_io = err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io_err| {
                matches!(
                    io_err.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::UnexpectedEof
                )
            })
    });

    for cause in err.chain() {
        if let Some(tor_err) = cause.downcast_ref::<arti_wrapper::TorError>() {
            if matches!(tor_err, arti_wrapper::TorError::Connect { .. }) {
                return (stage, ConnErrorKind::Tor);
            }
        }
    }

    let kind = match stage {
        ConnStage::Handshake => ConnErrorKind::Client,
        ConnStage::Relay => {
            if is_dropish_io {
                ConnErrorKind::Relay
            } else {
                ConnErrorKind::Other
            }
        }
        ConnStage::Connect => ConnErrorKind::Other,
        ConnStage::Other => {
            if is_dropish_io {
                ConnErrorKind::Client
            } else {
                ConnErrorKind::Other
            }
        }
    };
    (stage, kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridges_file_is_created_once_and_never_overwritten() {
        let dir = std::env::temp_dir().join(format!("tor-socks5-ensure-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("tor-socks5.ktav");
        let mut cfg = Config::default();
        assert!(ensure_bridges_file(&cfg, &config_path));
        let bridges_path = Config::bridges_path(&config_path);
        assert!(bridges_path.exists());

        // An existing file (here: the operator's own pool) is left alone.
        cfg.bridges.min_alive = 99;
        assert!(!ensure_bridges_file(&cfg, &config_path));
        let text = std::fs::read_to_string(&bridges_path).unwrap();
        assert!(!text.contains("min_alive: 99"), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
