use anyhow::{anyhow, Result};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use super::global_init;
use crate::api::DnsStartupPolicy;

/// Inputs needed to run the SOCKS5 server, gathered from the CLI (or, in
/// the Windows-service case, synthesised from the installed image path).
pub(crate) struct ServerArgs {
    pub config: crate::config::Config,
    pub config_path: Option<std::path::PathBuf>,
    pub obs_sink: tor_socks5_runtime::arti_observability::ObservationSink,
    pub upstream_addr: Option<String>,
    pub upstream_user: Option<String>,
    pub upstream_pass: Option<String>,
    pub no_upstream: bool,
    pub dns_startup_policy: DnsStartupPolicy,
}

/// Run the proxy until `shutdown` resolves. The stop future is supplied by
/// the caller (console signal or SCM notification); process-wide setup
/// (config loading, logging, signals) is done outside.
#[cfg(test)]
pub(crate) async fn run_server(
    args: ServerArgs,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    let writer_started = AtomicBool::new(false);
    super::run_server_inner(&mut |_| {}, &mut |_| {}, args, shutdown, &writer_started).await
}

pub(crate) struct RunFailure {
    pub(crate) primary: anyhow::Error,
    pub(crate) cleanup: Option<anyhow::Error>,
}

#[cfg(test)]
static CLEANUP_FAILED_RUN_STARTED: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>> =
    std::sync::Mutex::new(None);

pub(crate) async fn run_server_with_callbacks(
    args: ServerArgs,
    shutdown: impl std::future::Future<Output = ()>,
    mut set_stage: impl FnMut(crate::api::ServerStage),
    mut on_ready: impl FnMut(Vec<std::net::SocketAddr>),
    writer_started: Arc<AtomicBool>,
) -> std::result::Result<(), RunFailure> {
    let result = super::run_server_inner(
        &mut set_stage,
        &mut on_ready,
        args,
        shutdown,
        &writer_started,
    )
    .await;
    if let Err(primary) = result {
        let (primary, startup_cleanup, startup_stage) =
            extract_startup_failure(primary).unwrap_or_else(|primary| (primary, None, None));
        if let Some(stage) = startup_stage {
            set_stage(stage);
        }
        let run_cleanup = cleanup_failed_run(writer_started.load(Ordering::Acquire))
            .await
            .err();
        let cleanup = combine_cleanup_errors(startup_cleanup, run_cleanup);
        return Err(RunFailure { primary, cleanup });
    }
    Ok(())
}

fn extract_startup_failure(
    error: anyhow::Error,
) -> std::result::Result<
    (
        anyhow::Error,
        Option<anyhow::Error>,
        Option<crate::api::ServerStage>,
    ),
    anyhow::Error,
> {
    let outer_contexts = error
        .chain()
        .take_while(|cause| {
            cause
                .downcast_ref::<global_init::StartupFailure>()
                .is_none()
        })
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let failure = error.downcast::<global_init::StartupFailure>()?;
    let global_init::StartupFailure {
        primary: startup_primary,
        cleanup,
    } = failure;
    let stage = match &startup_primary {
        global_init::StartupPrimary::Cancelled => crate::api::ServerStage::Cancelled,
        global_init::StartupPrimary::Error(_) => crate::api::ServerStage::Startup,
    };
    let mut primary = match startup_primary {
        global_init::StartupPrimary::Cancelled => anyhow!("server startup cancelled"),
        global_init::StartupPrimary::Error(error) => error,
    };
    // The outer `anyhow::Context` layers are outside StartupFailure; reapply
    // them around the original primary so the public source chain keeps them.
    for context in outer_contexts.into_iter().rev() {
        if context != "server startup failed" {
            primary = primary.context(context);
        }
    }
    Ok((primary, cleanup, Some(stage)))
}

fn combine_cleanup_errors(
    initial: Option<anyhow::Error>,
    failed_run: Option<anyhow::Error>,
) -> Option<anyhow::Error> {
    match (initial, failed_run) {
        (None, None) => None,
        (Some(error), None) | (None, Some(error)) => Some(error),
        (Some(first), Some(second)) => {
            let mut failures = super::producers::ProducerFailures::default();
            failures.push(first);
            failures.push(second);
            failures.into_result().err()
        }
    }
}

pub(crate) async fn cleanup_failed_run(writer_started: bool) -> Result<()> {
    #[cfg(test)]
    if let Some(notice) = CLEANUP_FAILED_RUN_STARTED
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .take()
    {
        let _ = notice.send(());
    }
    let recovery_errors = super::global_init::recover_startup_all().await;
    let mut failures = super::producers::ProducerFailures::default();
    for error in recovery_errors {
        failures.push(error);
    }
    if writer_started {
        if let Some(Err(error)) = super::global_init::close_store_writer().await {
            failures.push(error);
        }
    }
    if let Err(error) = super::producers::join_final_workers().await {
        failures.push(error);
    }
    failures.into_result()
}

#[cfg(test)]
pub(crate) fn scope_run_server_task_locals<F>(
    future: F,
) -> impl std::future::Future<Output = F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    let startup = super::global_init::RUN_SERVER_STARTUP
        .try_with(Arc::clone)
        .ok();
    let shutdown = super::global_init::RUN_SERVER_SHUTDOWN
        .try_with(Arc::clone)
        .ok();
    async move {
        match (startup, shutdown) {
            (Some(startup), Some(shutdown)) => {
                super::global_init::RUN_SERVER_STARTUP
                    .scope(
                        startup,
                        super::global_init::RUN_SERVER_SHUTDOWN.scope(shutdown, future),
                    )
                    .await
            }
            (Some(startup), None) => {
                super::global_init::RUN_SERVER_STARTUP
                    .scope(startup, future)
                    .await
            }
            (None, Some(shutdown)) => {
                super::global_init::RUN_SERVER_SHUTDOWN
                    .scope(shutdown, future)
                    .await
            }
            (None, None) => future.await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_shutdown_hook() -> Arc<global_init::ShutdownHook> {
        Arc::new(global_init::ShutdownHook {
            settings: arti_wrapper::Settings::default(),
            writer: None,
            failure: None,
            ready: std::sync::Mutex::new(None),
        })
    }

    fn test_args(config: crate::config::Config) -> ServerArgs {
        ServerArgs {
            config,
            config_path: None,
            obs_sink: tor_socks5_runtime::arti_observability::ObservationSink::new(),
            upstream_addr: Some("127.0.0.1:1".to_owned()),
            upstream_user: None,
            upstream_pass: None,
            no_upstream: false,
            dns_startup_policy: DnsStartupPolicy::Required,
        }
    }

    #[tokio::test]
    async fn unexpected_accept_exit_is_reported_after_normal_cleanup() {
        let _serial = super::super::owners::TEST_LIFECYCLE.lock().await;
        let config = crate::config::Config {
            listen: vec!["127.0.0.1:0".to_owned()],
            ..Default::default()
        };
        let (stage_tx, stage_rx) = tokio::sync::watch::channel(crate::api::ServerStage::Recovery);
        let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ready_callback = ready.clone();
        let writer_started = Arc::new(AtomicBool::new(false));
        let result = global_init::RUN_SERVER_SHUTDOWN
            .scope(
                test_shutdown_hook(),
                super::super::FORCE_ACCEPT_LOOP_EXIT.scope(
                    true,
                    run_server_with_callbacks(
                        test_args(config),
                        std::future::pending(),
                        move |stage| {
                            stage_tx.send_replace(stage);
                        },
                        move |_| ready_callback.store(true, Ordering::Release),
                        writer_started,
                    ),
                ),
            )
            .await;
        let failure = result.expect_err("unexpected accept exit must fail the run");
        assert!(
            ready.load(Ordering::Acquire),
            "server must reach readiness first"
        );
        assert_eq!(*stage_rx.borrow(), crate::api::ServerStage::Runtime);
        assert!(format!("{:#}", failure.primary).contains("accept loop exited unexpectedly"));
        assert!(
            failure.cleanup.is_none(),
            "ordinary cleanup should still succeed"
        );
    }

    async fn assert_cancelled_start_keeps_cleanup_failure(park_global: bool) {
        let dir = tempfile::tempdir().unwrap();
        let settings = if park_global {
            arti_wrapper::Settings {
                bridges: vec!["192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01"
                    .parse()
                    .unwrap()],
                state_dir: Some(dir.path().join("global")),
                ..Default::default()
            }
        } else {
            arti_wrapper::Settings::default()
        };
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let hook = Arc::new(global_init::StartupHook {
            settings,
            park_global,
            gate: std::sync::Mutex::new(Some((entered_tx, release_rx))),
            async_gate: std::sync::Mutex::new(None),
        });
        let parent = tokio_util::sync::CancellationToken::new();
        let builder = crate::Server::builder(crate::config::Config {
            listen: vec!["127.0.0.1:0".to_owned()],
            ..Default::default()
        })
        .cancellation_token(parent.clone());
        let (cleanup_tx, cleanup_rx) = tokio::sync::oneshot::channel();
        *CLEANUP_FAILED_RUN_STARTED
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(cleanup_tx);
        let shutdown = test_shutdown_hook();
        let mut start = Box::pin(global_init::RUN_SERVER_STARTUP.scope(
            hook,
            global_init::RUN_SERVER_SHUTDOWN.scope(shutdown, builder.start()),
        ));
        tokio::select! {
            entered = entered_rx => entered.expect("startup stage entered"),
            result = &mut start => panic!("startup unexpectedly completed before its gate: {}", match result { Ok(_) => "Ok(handle)".to_owned(), Err(error) => format!("Err({error})") }),
        }
        parent.cancel();
        cleanup_rx.await.expect("failed-run cleanup must start");
        release_tx.send(()).expect("release blocked startup worker");

        let error = match start.await {
            Err(error) => error,
            Ok(handle) => {
                drop(handle);
                panic!("cancelled start unexpectedly succeeded");
            }
        };
        assert!(matches!(
            &error,
            crate::ServerError::Cleanup { error, .. }
                if matches!(error.as_ref(), crate::ServerError::Cancelled)
        ));
        assert_eq!(error.stage(), Some(crate::ServerStage::Cancelled));
        assert!(
            error.cleanup_error().is_some(),
            "initial cleanup error was lost"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn settings_and_global_cancellation_preserve_initial_cleanup_failure() {
        let _serial = super::super::owners::TEST_LIFECYCLE.lock().await;
        let _ = rustls::crypto::ring::default_provider().install_default();
        assert_cancelled_start_keeps_cleanup_failure(false).await;
        assert_cancelled_start_keeps_cleanup_failure(true).await;
    }

    #[test]
    fn initial_and_failed_run_cleanup_errors_are_both_retained() {
        let error = combine_cleanup_errors(
            Some(anyhow!("initial startup cleanup")),
            Some(anyhow!("failed-run cleanup")),
        )
        .unwrap();
        let failures = error
            .downcast_ref::<super::super::producers::ProducerFailures>()
            .expect("cleanup failures should be aggregated");
        assert_eq!(failures.errors().len(), 2);
        assert!(failures.errors()[0]
            .to_string()
            .contains("initial startup cleanup"));
        assert!(failures.errors()[1]
            .to_string()
            .contains("failed-run cleanup"));
    }
}
