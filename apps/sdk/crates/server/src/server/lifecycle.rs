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
    pub config_path: std::path::PathBuf,
    pub obs_sink: tor_socks5_runtime::arti_observability::ObservationSink,
    pub upstream_addr: Option<String>,
    pub upstream_user: Option<String>,
    pub upstream_pass: Option<String>,
    pub no_upstream: bool,
    pub pt_binary: tor_socks5_runtime::pt::PtBinary,
    pub dns_startup_policy: DnsStartupPolicy,
    /// Injectable test seam; always `None` outside test builds (the hook
    /// type is an empty struct there), so production behaviour is unchanged.
    pub test_hooks: Option<Arc<super::global_init::TestRunHooks>>,
}

/// Run the proxy until `shutdown` resolves. The stop future is supplied by
/// the caller (console signal or SCM notification); process-wide setup
/// (config loading, logging, signals) is done outside.
#[cfg(test)]
pub(crate) async fn run_server(
    args: ServerArgs,
    shutdown: impl std::future::Future<Output = ()> + Send,
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
    shutdown: impl std::future::Future<Output = ()> + Send,
    mut set_stage: impl FnMut(crate::api::ServerStage) + Send,
    mut on_ready: impl FnMut(Vec<std::net::SocketAddr>) + Send,
    writer_started: Arc<AtomicBool>,
) -> std::result::Result<(), RunFailure> {
    let hooks = args.test_hooks.clone();
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
        let run_cleanup =
            cleanup_failed_run(writer_started.load(Ordering::Acquire), hooks.as_deref())
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

/// End the run's blocking-worker group; a primary run error wins over a
/// group-join error (which is then only logged).
pub(crate) async fn finish_run_group(result: Result<()>) -> Result<()> {
    match tor_socks5_runtime::workers::end_run_group(std::time::Duration::from_secs(5)).await {
        Ok(()) => result,
        Err(group_error) => match result {
            Ok(()) => Err(group_error),
            Err(primary) => {
                tracing::warn!(error = %group_error, "run blocking workers outlived the shutdown budget");
                Err(primary)
            }
        },
    }
}

pub(crate) async fn cleanup_failed_run(
    writer_started: bool,
    hooks: Option<&global_init::TestRunHooks>,
) -> Result<()> {
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
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        if let Some(Err(error)) =
            super::global_init::close_store_writer(Some(deadline), hooks).await
        {
            failures.push(error);
        }
    }
    if let Err(error) = super::producers::join_final_workers().await {
        failures.push(error);
    }
    // Idempotent: clear a run group retained by this failed run (Ok(()) when
    // recover_startup_all already ended it).
    if let Err(error) =
        tor_socks5_runtime::workers::end_run_group(std::time::Duration::from_secs(5)).await
    {
        failures.push(error);
    }
    failures.into_result()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::global_init::{ShutdownHooks, StartupHooks, TestRunHooks};

    fn shutdown_hooks(force_accept_loop_exit: bool) -> Arc<TestRunHooks> {
        Arc::new(TestRunHooks {
            startup: None,
            shutdown: Some(ShutdownHooks {
                settings: arti_wrapper::Settings::default(),
                writer: None,
                failure: None,
                ready: std::sync::Mutex::new(None),
                launch_background: false,
            }),
            force_accept_loop_exit,
        })
    }

    fn test_args(
        config: crate::config::Config,
        config_path: std::path::PathBuf,
        test_hooks: Option<Arc<TestRunHooks>>,
    ) -> ServerArgs {
        ServerArgs {
            config,
            config_path,
            obs_sink: tor_socks5_runtime::arti_observability::ObservationSink::new(),
            upstream_addr: Some("127.0.0.1:1".to_owned()),
            upstream_user: None,
            upstream_pass: None,
            no_upstream: false,
            pt_binary: tor_socks5_runtime::pt::PtBinary::Environment,
            dns_startup_policy: DnsStartupPolicy::Required,
            test_hooks,
        }
    }

    #[tokio::test]
    async fn unexpected_accept_exit_is_reported_after_normal_cleanup() {
        let _serial = super::super::owners::TEST_LIFECYCLE.lock().await;
        // The config path is required (D-H1) and anchors on-disk state; keep
        // all file I/O inside a tempdir, never in the current directory.
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("server.ktav");
        let config = crate::config::Config {
            listen: vec!["127.0.0.1:0".to_owned()],
            ..Default::default()
        };
        let (stage_tx, stage_rx) = tokio::sync::watch::channel(crate::api::ServerStage::Recovery);
        let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ready_callback = ready.clone();
        let writer_started = Arc::new(AtomicBool::new(false));
        let result = run_server_with_callbacks(
            test_args(config, config_path, Some(shutdown_hooks(true))),
            std::future::pending(),
            move |stage| {
                stage_tx.send_replace(stage);
            },
            move |_| ready_callback.store(true, Ordering::Release),
            writer_started,
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
        let hooks = Arc::new(TestRunHooks {
            startup: Some(StartupHooks {
                settings,
                park_global,
                gate: std::sync::Mutex::new(Some((entered_tx, release_rx))),
                async_gate: std::sync::Mutex::new(None),
            }),
            shutdown: Some(ShutdownHooks {
                settings: arti_wrapper::Settings::default(),
                writer: None,
                failure: None,
                ready: std::sync::Mutex::new(None),
                launch_background: false,
            }),
            force_accept_loop_exit: false,
        });
        let parent = tokio_util::sync::CancellationToken::new();
        let builder = crate::Server::builder(crate::config::Config {
            listen: vec!["127.0.0.1:0".to_owned()],
            ..Default::default()
        })
        .config_path(dir.path().join("server.ktav"))
        .cancellation_token(parent.clone())
        .test_hooks(hooks);
        let (cleanup_tx, cleanup_rx) = tokio::sync::oneshot::channel();
        *CLEANUP_FAILED_RUN_STARTED
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(cleanup_tx);
        let mut start = Box::pin(builder.start());
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
