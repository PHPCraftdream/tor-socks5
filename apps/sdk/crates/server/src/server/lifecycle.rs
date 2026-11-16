use anyhow::Result;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

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
        let cleanup = cleanup_failed_run(writer_started.load(Ordering::Acquire))
            .await
            .err();
        return Err(RunFailure { primary, cleanup });
    }
    Ok(())
}

pub(crate) async fn cleanup_failed_run(writer_started: bool) -> Result<()> {
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
