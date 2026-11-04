use std::time::Duration;

/// Error type of every fallible operation in this crate, named for the
/// phase that failed: assembling the client config ([`TorError::BuildConfig`]),
/// parsing bridge or pluggable-transport
/// settings ([`TorError::InvalidBridge`], [`TorError::InvalidPt`]),
/// bootstrapping ([`TorError::Bootstrap`]), reconfiguring a live client
/// ([`TorError::Reconfigure`]), opening streams ([`TorError::Connect`]),
/// channel/guard management ([`TorError::ChanMgrUnavailable`],
/// [`TorError::Warm`], [`TorError::SignalFailure`]), and the two
/// reachability-check budgets ([`TorError::BridgeCheckBootstrapTimeout`],
/// [`TorError::BridgeCheckProbeTimeout`]).
#[derive(Debug, thiserror::Error)]
pub enum TorError {
    /// Pluggable transport shutdown did not complete.
    #[error("failed to shut down pluggable transports")]
    Shutdown,
    /// Creating the `TorClient` or waiting for it to reach a usable
    /// directory failed. Raised by every bootstrap path: `create_bootstrapped`,
    /// [`crate::TorTunnel::create_unbootstrapped`]'s client construction, and
    /// [`crate::TorTunnel::wait_bootstrapped`]'s directory wait. `source` is
    /// arti's own error (directory-fetch, PT-launch, or runtime
    /// failure); a caller's `timeout` around `wait_bootstrapped` cancels
    /// the future instead of producing this variant.
    #[error("failed to bootstrap Tor client: {0}")]
    Bootstrap(#[source] arti_client::Error),

    /// Applying new [`crate::Settings`] to the already-running client failed
    /// ([`crate::TorTunnel::reconfigure_bridges`]'s `TorClient::reconfigure`
    /// call). arti applies the change atomically (`Reconfigure::AllOrNothing`),
    /// so on this error the client keeps running with its previous
    /// configuration; `source` is arti's error.
    #[error("failed to reconfigure bridge order: {0}")]
    Reconfigure(#[source] arti_client::Error),

    /// Opening a stream through Tor to the requested destination failed
    /// (circuit build, exit refusal, timeout, unreachable `.onion`, ...).
    #[error("failed to connect through Tor to {host}:{port}: {source}")]
    Connect {
        /// Destination as passed to [`crate::TorTunnel::connect`] — a domain,
        /// `.onion`, or IP string, echoed verbatim (never resolved or
        /// normalised).
        host: String,
        /// Destination port as passed to [`crate::TorTunnel::connect`].
        port: u16,
        /// The underlying `arti_client::Error` for the failed stream
        /// open.
        #[source]
        source: arti_client::Error,
    },

    /// SOCKS5 CONNECT negotiation over a Tor-opened stream failed.
    #[error("post-SOCKS5 CONNECT failed: {0}")]
    PostSocks(#[source] socks5_proto::client::Error),

    /// The absolute post-SOCKS stream deadline elapsed.
    #[error("post-SOCKS5 connection deadline elapsed")]
    PostSocksTimeout,

    /// HTTP CONNECT negotiation over a Tor-opened stream failed.
    #[error("post-HTTP CONNECT failed")]
    PostHttp(#[source] resocks5_net::ConnectError),

    /// The absolute post-HTTP stream deadline elapsed.
    #[error("post-HTTP connection deadline elapsed")]
    PostHttpTimeout,

    /// A bridge line could not be turned into arti's `BridgeConfig`:
    /// either its serialised form (after any obfs4 `iat-mode` override)
    /// failed to parse as a bridge line, or the parsed builder failed
    /// validation. The payload carries the offending serialised line plus
    /// the underlying parse/build message. Raised wherever a
    /// `BridgeLine` is converted — config build, [`crate::TorTunnel::warm_bridge`],
    /// [`crate::TorTunnel::signal_bridge_failure`].
    #[error("invalid bridge configuration: {0}")]
    InvalidBridge(String),

    /// The pluggable-transport configuration is incomplete or invalid:
    /// the bridges (or [`crate::Settings::extra_pt_protocols`]) name transports
    /// but [`crate::Settings::pt_binary`] is not set, the configured binary path
    /// does not exist, or a transport name is not a parseable protocol.
    /// The payload says which of the three.
    #[error("invalid pluggable-transport configuration: {0}")]
    InvalidPt(String),

    /// The assembled `TorClientConfig` failed final validation
    /// (`TorClientConfigBuilder::build`); the payload is the builder's
    /// error message. Raised from the single config-building helper that
    /// every bootstrap and reconfigure path goes through.
    #[error("failed to build Tor client config: {0}")]
    BuildConfig(String),

    /// The client's channel manager (or, for
    /// [`crate::TorTunnel::bridge_is_disabled`], the equivalent guard-state
    /// query) could not be reached. Raised by
    /// [`crate::TorTunnel::terminate_all_channels`], [`crate::TorTunnel::warm_bridge`],
    /// and [`crate::TorTunnel::bridge_is_disabled`], so watchdog callers can
    /// tell "could not even reach the manager" from "action performed";
    /// `source` is arti's error (arti raises it when the client is not in
    /// a running state, e.g. fully dormant).
    #[error("could not access Tor client's channel manager: {0}")]
    ChanMgrUnavailable(#[source] arti_client::Error),

    /// Opening (or reusing) a channel to `bridge` failed in
    /// `ChanMgr::get_or_launch` during [`crate::TorTunnel::warm_bridge`] — the
    /// transport connection could not be established or the target failed
    /// channel-level validation. `bridge` carries the exact serialised
    /// line (after any obfs4 `iat-mode` override) that was attempted;
    /// `source` is the underlying `tor_chanmgr::Error`.
    #[error("failed to warm a channel to bridge {bridge}: {source}")]
    Warm {
        /// The serialised bridge line (iat-mode applied) whose warm-up
        /// failed.
        bridge: String,
        /// The underlying `tor_chanmgr::Error`.
        #[source]
        source: Box<tor_chanmgr::Error>,
    },

    /// Reporting an externally-observed guard failure for `bridge` to
    /// arti's guard manager failed (see
    /// [`crate::TorTunnel::signal_bridge_failure`]; raised under the same
    /// "client not in a running state" condition as
    /// [`TorError::ChanMgrUnavailable`]). `bridge` carries the exact
    /// serialised line (after any obfs4 `iat-mode` override) that was
    /// reported; `source` is arti's error.
    #[error("failed to signal guard failure for bridge {bridge}: {source}")]
    SignalFailure {
        /// The serialised bridge line (iat-mode applied) whose failure
        /// report failed.
        bridge: String,
        /// The underlying `arti_client::Error`.
        #[source]
        source: arti_client::Error,
    },

    /// [`crate::TorTunnel::verify_bridge_reachable`]'s throwaway client did not
    /// reach a usable directory within `bootstrap_timeout`; the payload
    /// is that budget, for the caller's log messages. The client is torn
    /// down either way — this is "not proven in time", not evidence the
    /// bridge is dead.
    #[error("bridge reachability check: bootstrap timed out after {0:?}")]
    BridgeCheckBootstrapTimeout(Duration),

    /// The live-traffic probe inside
    /// [`crate::TorTunnel::verify_bridge_reachable`] — a `connect` to the probe
    /// target, retried within the same budget — did not open a stream
    /// within `probe_timeout`; the payload is that budget. Same caveat as
    /// [`TorError::BridgeCheckBootstrapTimeout`]: DPI can kill a PT
    /// stream after the handshake, and the candidate's own
    /// microdescriptors may still be landing, so treat this as "not
    /// proven reachable" rather than a measured death.
    #[error("bridge reachability check: live probe timed out after {0:?}")]
    BridgeCheckProbeTimeout(Duration),
}
