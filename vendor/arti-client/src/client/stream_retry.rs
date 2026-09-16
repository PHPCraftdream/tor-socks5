use crate::config::StreamTimeoutConfig;
use crate::err::ErrorDetail;
use std::result::Result as StdResult;
use std::time::Duration;
use tor_rtcompat::{Runtime, SleepProviderExt};
use tracing::info;

/// Return whether an exit stream failure is safe to retry on another circuit.
pub(super) fn retryable_stream_error(error: &ErrorDetail) -> bool {
    match error {
        ErrorDetail::ExitTimeout => true,
        ErrorDetail::StreamFailed {
            cause: tor_circmgr::Error::Protocol { error, .. },
            ..
        } => {
            matches!(
                error,
                tor_proto::Error::NotConnected | tor_proto::Error::CircuitClosed
            )
        }
        _ => false,
    }
}

/// Snapshot the two budgets that govern one exit CONNECT request.
pub(super) fn snapshot_exit_stream_timeouts(
    config: &StreamTimeoutConfig,
) -> (Option<Duration>, Duration) {
    (config.initial_connect_timeout, config.connect_timeout)
}

/// Retry once on another circuit, before returning a stream to the application.
/// cancel-safe: yes — no application data is sent; retirement preserves existing streams.
pub(super) async fn retry_exit_stream<R, T, I, F, OpenFut, StreamFut>(
    runtime: &R,
    initial_timeout: Option<Duration>,
    ordinary_timeout: Duration,
    mut open: F,
    mut retire: impl FnMut(&I),
) -> StdResult<T, ErrorDetail>
where
    R: Runtime,
    F: FnMut() -> OpenFut,
    OpenFut: std::future::Future<Output = StdResult<(I, StreamFut), ErrorDetail>>,
    StreamFut: std::future::Future<Output = StdResult<T, ErrorDetail>>,
{
    let mut retried = false;
    loop {
        let timeout = if retried {
            ordinary_timeout
        } else {
            initial_timeout
                .map(|initial| initial.min(ordinary_timeout))
                .unwrap_or(ordinary_timeout)
        };
        let (id, stream) = open().await?;
        // Treat expiry as an ordinary retryable attempt failure. Returning
        // here would skip retirement and the one permitted retry.
        let result = match runtime.timeout(timeout, stream).await {
            Ok(result) => result,
            Err(_) => Err(ErrorDetail::ExitTimeout),
        };
        if let Err(error) = &result {
            if retryable_stream_error(error) {
                retire(&id);
                if !retried {
                    info!(%error, "stream open failed; retrying on a fresh circuit");
                    retried = true;
                    continue;
                }
            }
        }
        return result;
    }
}
