mod arti_observability;
mod bridge_store;
mod bridges_cmd;
mod candidate_pool;
mod cli;
mod config;
mod fetch_merge;
mod help_cmd;
mod seed;
mod server;
mod service;
mod shutdown;
mod socks5;
mod startup;
mod tor_setup;
mod upstream;
mod users_cli;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::info;

use crate::cli::{Cli, Command};
use crate::users_cli::RpasswordPrompt;

fn main() -> Result<()> {
    // Windows-service dispatch: when the Service Control Manager starts
    // us, the installed image path carries a marker argument. We must
    // hand control to the SCM dispatcher *before* building a Tokio
    // runtime or parsing clap (the marker is not a valid CLI arg). The
    // dispatcher blocks this thread and runs the proxy under SCM control.
    #[cfg(windows)]
    {
        let marker = std::ffi::OsString::from(service::WINDOWS_SERVICE_RUN_ARG);
        if std::env::args_os().any(|a| a == marker) {
            return service::windows_runtime::dispatch();
        }
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        // Pin a generous worker-thread count. arti's circuit manager can churn
        // hard (many concurrent failed circuit-build attempts over flaky
        // bridges); if the default pool (= CPU count) is small, those tasks can
        // monopolise every worker and starve other arti tasks — notably the
        // bridge-descriptor fetch, which was observed to hang for minutes with
        // its own 30s timeout never even firing (a tell-tale sign the future
        // was never being polled). A larger pool keeps workers available so
        // those tasks make progress and their timeouts actually arm.
        .worker_threads(16)
        .enable_all()
        .build()
        .context("building Tokio runtime")?;
    rt.block_on(async_main())
}

async fn async_main() -> Result<()> {
    // Busybox-style dispatch: when arti spawns us as a managed pluggable
    // transport, it sets `TOR_PT_MANAGED_TRANSPORT_VER`. In that case we
    // skip the SOCKS5-proxy startup entirely and run the lyrebird PT
    // loop instead — same binary, two modes, no second executable on
    // disk. This MUST run before clap parsing because arti passes weird
    // argv to PT subprocesses that would blow up the parser.
    if std::env::var_os("TOR_PT_MANAGED_TRANSPORT_VER").is_some() {
        return lyrebird::run().await;
    }

    let cli = Cli::parse();

    match cli.command {
        Some(Command::Users { action }) => {
            return users_cli::run(action, cli.config.as_deref(), &mut RpasswordPrompt);
        }
        Some(Command::Bridges { action }) => {
            return bridges_cmd::cmd_bridges(action, cli.config.as_deref()).await;
        }
        Some(Command::Service { action, user }) => {
            return service::run(action, user, cli.config.as_deref());
        }
        Some(Command::Help { all, topic }) => {
            help_cmd::run(all, topic);
            return Ok(());
        }
        None => {}
    }

    // Normal foreground server: shut down on Ctrl-C / SIGINT / SIGTERM.
    let shutdown = async {
        let sig = shutdown::wait_for_signal().await;
        info!(%sig, "shutdown signal received");
    };
    server::run_server(
        server::ServerArgs {
            config_override: cli.config.clone(),
            upstream_addr: cli.upstream.clone(),
            upstream_user: cli.upstream_user.clone(),
            upstream_pass: cli.upstream_pass.clone(),
            no_upstream: cli.no_upstream,
        },
        shutdown,
    )
    .await
}
