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

use std::time::Duration;
use tokio_crate as tokio;
use tor_config::Reconfigure;

use super::*;

fn paused_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap()
}

#[test]
fn stream_retry_retires_the_failed_circuit_before_opening_again() {
    use std::cell::{Cell, RefCell};
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
    use std::cell::{Cell, RefCell};
    let calls = Cell::new(0);
    let retired = RefCell::new(Vec::new());
    let tokio_runtime = paused_runtime();
    tokio_runtime.block_on(async {
        let runtime = tor_rtcompat::PreferredRuntime::current().unwrap();
        let started = tokio::time::Instant::now();
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
            tokio::time::Instant::now() - started,
            Duration::from_secs(14)
        );
    });
    assert_eq!(calls.get(), 2);
    assert_eq!(*retired.borrow(), vec![0, 1]);
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
    let tokio_runtime = paused_runtime();
    tokio_runtime.block_on(async {
        let runtime = tor_rtcompat::PreferredRuntime::current().unwrap();
        let started = tokio::time::Instant::now();
        let attempts = std::cell::Cell::new(0);
        let retired = std::cell::RefCell::new(Vec::new());
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
            tokio::time::Instant::now() - started,
            Duration::from_secs(20)
        );
        assert_eq!(*retired.borrow(), vec![0, 1]);
    });
}

#[test]
fn request_timeout_snapshot_survives_reconfigure_during_first_attempt() {
    let tokio_runtime = paused_runtime();
    tokio_runtime.block_on(async {
        use tor_rtcompat::SleepProvider as _;
        let runtime = tor_rtcompat::PreferredRuntime::current().unwrap();
        let config = tor_config::MutCfg::new(StreamTimeoutConfig {
            connect_timeout: Duration::from_secs(10),
            initial_connect_timeout: Some(Duration::from_secs(4)),
            resolve_timeout: Duration::from_secs(10),
            resolve_ptr_timeout: Duration::from_secs(10),
        });
        let snapshot = config.get();
        let (initial_timeout, ordinary_timeout) = snapshot_exit_stream_timeouts(&snapshot);
        let attempts = std::cell::Cell::new(0);
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
fn stream_retry_uses_fast_first_timer_and_ordinary_retry_timer() {
    let tokio_runtime = paused_runtime();
    tokio_runtime.block_on(async {
        use tor_rtcompat::SleepProvider as _;
        let rt = tor_rtcompat::PreferredRuntime::current().unwrap();
        let attempts = std::cell::Cell::new(0);
        let retired = std::cell::RefCell::new(Vec::new());
        let started = tokio::time::Instant::now();
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
        assert_eq!(*retired.borrow(), vec![0]);
        assert_eq!(
            tokio::time::Instant::now() - started,
            Duration::from_secs(10)
        );
    });
}

#[test]
fn stream_retry_caps_fast_timer_at_shorter_ordinary_budget() {
    let tokio_runtime = paused_runtime();
    tokio_runtime.block_on(async {
        use tor_rtcompat::SleepProvider as _;
        let rt = tor_rtcompat::PreferredRuntime::current().unwrap();
        let attempts = std::cell::Cell::new(0);
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
use crate::config::TorClientConfigBuilder;
use crate::{ErrorKind, HasKind};

// tor-socks5 local patch: contract tests for the fatal-protocol-error
// observability hook. A behavioral test that drives the full
// `on_fatal` closure would invoke `std::process::exit(1)` and is therefore
// impossible to run in-process; instead we unit-test the extracted seam
// (`notify_fatal_protocol_error`) that the closure calls immediately before
// exiting. The end-to-end wiring (builder -> NotConstructedInner ->
// RunningInner::new -> closure) is exercised by the workspace
// `cargo build`.

#[test]
fn fatal_protocol_error_hook_none_is_noop() {
    // With no hook installed, firing the seam must simply do nothing
    // (Arti's default `eprintln!`-only behaviour is unchanged).
    let hook: Option<Arc<dyn crate::FatalProtocolErrorHandler>> = None;
    let err = crate::Error::from(crate::err::ErrorDetail::ExitTimeout);
    notify_fatal_protocol_error(&hook, &err);
}

#[test]
fn fatal_protocol_error_hook_is_invoked_with_error() {
    // With a hook installed, firing the seam must invoke it exactly once
    // with the public `Error` view of the fatal cause, *before* the
    // process would exit. (This is the whole point of the patch: an
    // embedding application gets a structured marker it can log/alert on.)
    let recorded = Arc::new(Mutex::new(None::<ErrorKind>));
    let recorded_inner = Arc::clone(&recorded);
    let hook: Arc<dyn crate::FatalProtocolErrorHandler> = Arc::new(move |error: &crate::Error| {
        *recorded_inner.lock().unwrap() = Some(error.kind());
    });
    let err = crate::Error::from(crate::err::ErrorDetail::ExitTimeout);
    notify_fatal_protocol_error(&Some(hook), &err);
    assert_eq!(
        *recorded.lock().unwrap(),
        Some(ErrorKind::RemoteNetworkTimeout)
    );
}

// tor-socks5 local patch: contract tests for
// `TorClient::note_external_guard_failure()`. Driving the full success
// path would require a bootstrapped client with an actual guard sample,
// which needs network access; instead we check the same "not running yet"
// contract that `unbootstrapped_client_unusable` already checks for other
// accessors (`connect`, etc.), which is the behavior any embedding
// application can rely on regardless of network conditions.

#[cfg(feature = "experimental-api")]
#[test]
fn note_external_guard_failure_requires_running_client() {
    tor_rtcompat::test_with_one_runtime!(|rt| async {
        let state_dir = tempfile::tempdir().unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        let cfg = TorClientConfigBuilder::from_directories(state_dir, cache_dir)
            .build()
            .unwrap();
        let client = TorClient::with_runtime(rt)
            .config(cfg)
            .bootstrap_behavior(BootstrapBehavior::Manual)
            .create_unbootstrapped()
            .unwrap();

        let identity = tor_linkspec::RelayIds::empty();
        let result =
            client.note_external_guard_failure(&identity, tor_guardmgr::ExternalActivity::DirCache);

        assert!(result.is_err());
        assert_eq!(result.err().unwrap().kind(), ErrorKind::BootstrapRequired);
    });
}

#[test]
fn create_unbootstrapped() {
    tor_rtcompat::test_with_one_runtime!(|rt| async {
        let state_dir = tempfile::tempdir().unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        let cfg = TorClientConfigBuilder::from_directories(state_dir, cache_dir)
            .build()
            .unwrap();
        let _ = TorClient::with_runtime(rt)
            .config(cfg)
            .bootstrap_behavior(BootstrapBehavior::Manual)
            .create_unbootstrapped()
            .unwrap();
    });
    tor_rtcompat::test_with_one_runtime!(|rt| async {
        let state_dir = tempfile::tempdir().unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        let cfg = TorClientConfigBuilder::from_directories(state_dir, cache_dir)
            .build()
            .unwrap();
        let _ = TorClient::with_runtime(rt)
            .config(cfg)
            .bootstrap_behavior(BootstrapBehavior::Manual)
            .create_unbootstrapped_async()
            .await
            .unwrap();
    });
}

#[test]
fn unbootstrapped_client_unusable() {
    tor_rtcompat::test_with_one_runtime!(|rt| async {
        let state_dir = tempfile::tempdir().unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        let cfg = TorClientConfigBuilder::from_directories(state_dir, cache_dir)
            .build()
            .unwrap();
        // Test sync
        let client = TorClient::with_runtime(rt)
            .config(cfg)
            .bootstrap_behavior(BootstrapBehavior::Manual)
            .create_unbootstrapped()
            .unwrap();
        let result = client.connect("example.com:80").await;
        assert!(result.is_err());
        assert_eq!(result.err().unwrap().kind(), ErrorKind::BootstrapRequired);
    });
    // Need a separate test for async because Runtime and TorClientConfig are consumed by the
    // builder
    tor_rtcompat::test_with_one_runtime!(|rt| async {
        let state_dir = tempfile::tempdir().unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        let cfg = TorClientConfigBuilder::from_directories(state_dir, cache_dir)
            .build()
            .unwrap();
        // Test sync
        let client = TorClient::with_runtime(rt)
            .config(cfg)
            .bootstrap_behavior(BootstrapBehavior::Manual)
            .create_unbootstrapped_async()
            .await
            .unwrap();
        let result = client.connect("example.com:80").await;
        assert!(result.is_err());
        assert_eq!(result.err().unwrap().kind(), ErrorKind::BootstrapRequired);
    });
}

#[test]
fn streamprefs_isolate_every_stream() {
    let mut observed = StreamPrefs::new();
    observed.isolate_every_stream();
    match observed.isolation {
        StreamIsolationPreference::EveryStream => (),
        _ => panic!("unexpected isolation: {:?}", observed.isolation),
    };
}

#[test]
fn streamprefs_new_has_expected_defaults() {
    let observed = StreamPrefs::new();
    assert_eq!(observed.ip_ver_pref, IpVersionPreference::Ipv4Preferred);
    assert!(!observed.optimistic_stream);
    // StreamIsolationPreference does not implement Eq, check manually.
    match observed.isolation {
        StreamIsolationPreference::None => (),
        _ => panic!("unexpected isolation: {:?}", observed.isolation),
    };
}

#[test]
fn streamprefs_new_isolation_group() {
    let mut observed = StreamPrefs::new();
    observed.new_isolation_group();
    match observed.isolation {
        StreamIsolationPreference::Explicit(_) => (),
        _ => panic!("unexpected isolation: {:?}", observed.isolation),
    };
}

#[test]
fn streamprefs_ipv6_only() {
    let mut observed = StreamPrefs::new();
    observed.ipv6_only();
    assert_eq!(observed.ip_ver_pref, IpVersionPreference::Ipv6Only);
}

#[test]
fn streamprefs_ipv6_preferred() {
    let mut observed = StreamPrefs::new();
    observed.ipv6_preferred();
    assert_eq!(observed.ip_ver_pref, IpVersionPreference::Ipv6Preferred);
}

#[test]
fn streamprefs_ipv4_only() {
    let mut observed = StreamPrefs::new();
    observed.ipv4_only();
    assert_eq!(observed.ip_ver_pref, IpVersionPreference::Ipv4Only);
}

#[test]
fn streamprefs_ipv4_preferred() {
    let mut observed = StreamPrefs::new();
    observed.ipv4_preferred();
    assert_eq!(observed.ip_ver_pref, IpVersionPreference::Ipv4Preferred);
}

#[test]
fn streamprefs_optimistic() {
    let mut observed = StreamPrefs::new();
    observed.optimistic();
    assert!(observed.optimistic_stream);
}

#[test]
fn streamprefs_set_isolation() {
    let mut observed = StreamPrefs::new();
    observed.set_isolation(IsolationToken::new());
    match observed.isolation {
        StreamIsolationPreference::Explicit(_) => (),
        _ => panic!("unexpected isolation: {:?}", observed.isolation),
    };
}

#[test]
fn reconfigure_all_or_nothing() {
    tor_rtcompat::test_with_one_runtime!(|rt| async {
        let state_dir = tempfile::tempdir().unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        let cfg = TorClientConfigBuilder::from_directories(state_dir, cache_dir)
            .build()
            .unwrap();
        let tor_client = TorClient::with_runtime(rt)
            .config(cfg.clone())
            .bootstrap_behavior(BootstrapBehavior::Manual)
            .create_unbootstrapped()
            .unwrap();
        tor_client
            .reconfigure(&cfg, Reconfigure::AllOrNothing)
            .unwrap();
    });
    tor_rtcompat::test_with_one_runtime!(|rt| async {
        let state_dir = tempfile::tempdir().unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        let cfg = TorClientConfigBuilder::from_directories(state_dir, cache_dir)
            .build()
            .unwrap();
        let tor_client = TorClient::with_runtime(rt)
            .config(cfg.clone())
            .bootstrap_behavior(BootstrapBehavior::Manual)
            .create_unbootstrapped_async()
            .await
            .unwrap();
        tor_client
            .reconfigure(&cfg, Reconfigure::AllOrNothing)
            .unwrap();
    });
}
