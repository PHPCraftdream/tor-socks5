//! Orchestration of everything process-wide that must happen before the
//! server tree starts.

use std::path::PathBuf;

use anyhow::Result;
use tor_socks5_runtime::arti_observability::ObservationSink;
use tracing_appender::non_blocking::WorkerGuard;

use super::children::bind_child_processes_to_self;
use super::logging::{init_tracing, install_crypto_provider};
use crate::config::{Config, Loaded};
use tor_socks5_server::{run_server, ServerArgs};

/// Process-wide state that must outlive the server run.
pub(crate) struct ServerProcess {
    /// Keeps the non-blocking log writer flushing until dropped.
    _log_guard: WorkerGuard,
    /// Captures per-guard usability events from arti's tracing layer for
    /// the bridge maintenance loop to drain into the health store.
    pub(crate) obs_sink: ObservationSink,
}

/// Initialise the process for serving: tracing, rustls provider, Job
/// Object binding and the `NO_COLOR` propagation. Call once per process.
pub(crate) fn init_server_process(cfg: &Config) -> ServerProcess {
    let (_log_guard, obs_sink) = init_tracing(cfg);
    install_crypto_provider();
    bind_child_processes_to_self();

    // The PT child (busybox dispatch, re-exec of this same binary) inherits
    // our environment and sets up its own tracing subscriber independently
    // of `cfg.log`. Propagate our own ansi choice via the NO_COLOR
    // convention (https://no-color.org) so a `log.ansi: false` config also
    // silences the child's colored output, not just ours.
    if !cfg.log.ansi {
        std::env::set_var("NO_COLOR", "1");
    }
    ServerProcess {
        _log_guard,
        obs_sink,
    }
}

/// Load the configuration, initialise the process and run the server until
/// `shutdown` resolves. The log guard is dropped on return, so buffered
/// records are flushed before the caller reports any error.
pub(crate) async fn run_server_process(
    config_override: Option<PathBuf>,
    upstream_addr: Option<String>,
    upstream_user: Option<String>,
    upstream_pass: Option<String>,
    no_upstream: bool,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    let (config_path, config) = match Config::load_with_override(config_override.as_deref())? {
        Loaded::FromFile { path, config } => (Some(path), config),
        Loaded::Defaults(config) => (None, config),
    };
    let process = init_server_process(&config);
    run_server(
        ServerArgs {
            config,
            config_path,
            obs_sink: process.obs_sink.clone(),
            upstream_addr,
            upstream_user,
            upstream_pass,
            no_upstream,
        },
        shutdown,
    )
    .await
}
