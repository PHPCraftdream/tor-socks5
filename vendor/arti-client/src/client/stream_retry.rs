// tor-socks5 local patch: exit-stream retry policy
//! Bounded single-retry policy for exit stream opens, plus the
//! `initial_connect_timeout` budget selection (see `StreamTimeoutConfig`).
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

/// Retry once before returning a stream error to the application.
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
        let (result, timed_out) = match runtime.timeout(timeout, stream).await {
            Ok(result) => (result, false),
            Err(_) => (Err(ErrorDetail::ExitTimeout), true),
        };
        if let Err(error) = &result {
            if retryable_stream_error(error) {
                // The abbreviated Android budget is an admission deadline,
                // so its expiry does not establish that the circuit is bad.
                let abbreviated_timeout =
                    !retried && initial_timeout.is_some_and(|initial| initial < ordinary_timeout);
                if !(timed_out && abbreviated_timeout) {
                    retire(&id);
                }
                if !retried {
                    info!(%error, "stream open failed; retrying stream open");
                    retried = true;
                    continue;
                }
            }
        }
        return result;
    }
}

#[cfg(test)]
// tor-socks5 local patch: exit-stream retry regression tests
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use std::cell::Cell;
    use std::cell::RefCell;

    fn paused_runtime() -> tokio_crate::runtime::Runtime {
        tokio_crate::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap()
    }

    #[test]
    fn stream_retry_retires_the_failed_circuit_before_opening_again() {
        let calls = Cell::new(0);
        let retired = RefCell::new(Vec::new());
        let tokio_runtime = paused_runtime();
        tokio_runtime.block_on(async {
            let runtime = tor_rtcompat::PreferredRuntime::current().unwrap();
            let result = retry_exit_stream(
                &runtime,
                None,
                Duration::from_secs(10),
                || {
                    let call = calls.get();
                    calls.set(call + 1);
                    let result = if call == 0 {
                        Err(ErrorDetail::ExitTimeout)
                    } else {
                        assert_eq!(*retired.borrow(), vec![0]);
                        Ok(42)
                    };
                    std::future::ready(Ok((call, std::future::ready(result))))
                },
                |id| retired.borrow_mut().push(*id),
            )
            .await;
            assert_eq!(result.unwrap(), 42);
        });
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn stream_retry_is_bounded_and_retires_the_last_failed_circuit() {
        let calls = Cell::new(0);
        let retired = RefCell::new(Vec::new());
        let tokio_runtime = paused_runtime();
        tokio_runtime.block_on(async {
            let runtime = tor_rtcompat::PreferredRuntime::current().unwrap();
            let started = tokio_crate::time::Instant::now();
            let result: StdResult<(), _> = retry_exit_stream(
                &runtime,
                Some(Duration::from_secs(4)),
                Duration::from_secs(10),
                || {
                    let call = calls.get();
                    calls.set(call + 1);
                    async move { Ok((call, std::future::pending::<StdResult<(), ErrorDetail>>())) }
                },
                |id| retired.borrow_mut().push(*id),
            )
            .await;
            assert!(matches!(result, Err(ErrorDetail::ExitTimeout)));
            assert_eq!(
                tokio_crate::time::Instant::now() - started,
                Duration::from_secs(14)
            );
        });
        assert_eq!(calls.get(), 2);
        assert_eq!(*retired.borrow(), vec![1]);
    }

    #[test]
    fn stream_retry_leaves_permanent_errors_alone() {
        let tokio_runtime = paused_runtime();
        let result: StdResult<(), _> = tokio_runtime.block_on(async {
            let runtime = tor_rtcompat::PreferredRuntime::current().unwrap();
            retry_exit_stream(
                &runtime,
                None,
                Duration::from_secs(10),
                || {
                    std::future::ready(Ok((
                        0,
                        std::future::ready(Err(ErrorDetail::OnionAddressNotSupported)),
                    )))
                },
                |_| panic!("a permanent error must not retire circuits"),
            )
            .await
        });
        assert!(matches!(result, Err(ErrorDetail::OnionAddressNotSupported)));
        let closed = ErrorDetail::StreamFailed {
            kind: "data",
            cause: tor_circmgr::Error::Protocol {
                action: "begin stream",
                peer: None,
                unique_id: None,
                error: tor_proto::Error::NotConnected,
            },
        };
        assert!(retryable_stream_error(&closed));
    }

    #[test]
    fn stream_retry_default_budget_bounds_both_attempts() {
        let attempts = Cell::new(0);
        let retired = RefCell::new(Vec::new());
        let tokio_runtime = paused_runtime();
        tokio_runtime.block_on(async {
            let runtime = tor_rtcompat::PreferredRuntime::current().unwrap();
            let started = tokio_crate::time::Instant::now();
            let result: StdResult<(), _> = retry_exit_stream(
                &runtime,
                None,
                Duration::from_secs(10),
                || {
                    let attempt = attempts.get();
                    attempts.set(attempt + 1);
                    async move {
                        Ok((
                            attempt,
                            std::future::pending::<StdResult<(), ErrorDetail>>(),
                        ))
                    }
                },
                |id| retired.borrow_mut().push(*id),
            )
            .await;
            assert!(matches!(result, Err(ErrorDetail::ExitTimeout)));
            assert_eq!(
                tokio_crate::time::Instant::now() - started,
                Duration::from_secs(20)
            );
            assert_eq!(*retired.borrow(), vec![0, 1]);
        });
    }

    #[test]
    fn request_timeout_snapshot_survives_reconfigure_during_first_attempt() {
        let attempts = Cell::new(0);
        let tokio_runtime = paused_runtime();
        tokio_runtime.block_on(async {
            use tor_config::MutCfg;
            use tor_rtcompat::SleepProvider as _;
            let runtime = tor_rtcompat::PreferredRuntime::current().unwrap();
            let config = MutCfg::new(StreamTimeoutConfig {
                connect_timeout: Duration::from_secs(10),
                initial_connect_timeout: Some(Duration::from_secs(4)),
                resolve_timeout: Duration::from_secs(10),
                resolve_ptr_timeout: Duration::from_secs(10),
            });
            let snapshot = config.get();
            let (initial_timeout, ordinary_timeout) = snapshot_exit_stream_timeouts(&snapshot);
            let result = retry_exit_stream(
                &runtime,
                initial_timeout,
                ordinary_timeout,
                || {
                    let attempt = attempts.get();
                    attempts.set(attempt + 1);
                    let config = &config;
                    let runtime = runtime.clone();
                    async move {
                        let stream = async move {
                            if attempt == 0 {
                                config.replace(StreamTimeoutConfig {
                                    connect_timeout: Duration::from_secs(1),
                                    initial_connect_timeout: Some(Duration::from_secs(1)),
                                    resolve_timeout: Duration::from_secs(10),
                                    resolve_ptr_timeout: Duration::from_secs(10),
                                });
                                std::future::pending::<()>().await;
                            } else {
                                runtime.sleep(Duration::from_secs(6)).await;
                            }
                            Ok::<_, ErrorDetail>(42)
                        };
                        Ok((attempt, stream))
                    }
                },
                |_| {},
            )
            .await;
            assert_eq!(result.unwrap(), 42);
            assert_eq!(attempts.get(), 2);
        });
    }

    #[test]
    fn stream_retry_initial_timeout_does_not_retire_circuit() {
        let attempts = Cell::new(0);
        let retired = RefCell::new(Vec::new());
        let tokio_runtime = paused_runtime();
        tokio_runtime.block_on(async {
            use tor_rtcompat::SleepProvider as _;
            let rt = tor_rtcompat::PreferredRuntime::current().unwrap();
            let started = tokio_crate::time::Instant::now();
            let result = retry_exit_stream(
                &rt,
                Some(Duration::from_secs(4)),
                Duration::from_secs(10),
                || {
                    let attempt = attempts.get();
                    attempts.set(attempt + 1);
                    let rt = rt.clone();
                    async move {
                        let stream = async move {
                            if attempt == 0 {
                                std::future::pending::<()>().await;
                            } else {
                                rt.sleep(Duration::from_secs(6)).await;
                            }
                            Ok::<_, ErrorDetail>(42)
                        };
                        Ok((attempt, stream))
                    }
                },
                |id| retired.borrow_mut().push(*id),
            )
            .await;
            assert_eq!(result.unwrap(), 42);
            assert_eq!(attempts.get(), 2);
            assert!(retired.borrow().is_empty());
            assert_eq!(
                tokio_crate::time::Instant::now() - started,
                Duration::from_secs(10)
            );
        });
    }

    #[test]
    fn stream_retry_caps_fast_timer_at_shorter_ordinary_budget() {
        let attempts = Cell::new(0);
        let tokio_runtime = paused_runtime();
        tokio_runtime.block_on(async {
            use tor_rtcompat::SleepProvider as _;
            let rt = tor_rtcompat::PreferredRuntime::current().unwrap();
            let result: StdResult<(), _> = retry_exit_stream(
                &rt,
                Some(Duration::from_secs(4)),
                Duration::from_secs(2),
                || {
                    let attempt = attempts.get();
                    attempts.set(attempt + 1);
                    let rt = rt.clone();
                    async move {
                        let stream = async move {
                            rt.sleep(Duration::from_secs(3)).await;
                            Ok::<_, ErrorDetail>(())
                        };
                        Ok((attempt, stream))
                    }
                },
                |_| {},
            )
            .await;
            assert!(matches!(result, Err(ErrorDetail::ExitTimeout)));
            assert_eq!(attempts.get(), 2);
        });
    }
}
