mod arti_observability;
mod bridge_store;
mod bridges_cmd;
mod candidate_pool;
mod cli;
mod config;
mod daemon;
mod fetch_merge;
mod help_cmd;
mod seed;
mod server;
mod service;
mod shutdown;
mod socks5;
mod startup;
mod tor_setup;
mod tor_watchdog;
mod upstream;
mod users_cli;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::info;

use crate::cli::{Cli, Command};
use crate::users_cli::RpasswordPrompt;

fn main() -> Result<()> {
    // Ask the console host to interpret ANSI/VT escape sequences. Windows
    // Terminal already does this on its own pty layer, but classic conhost
    // (still what plain `cmd.exe` attaches to on many setups) only does it
    // if an application explicitly turns the flag on — nothing in our
    // logging stack (tracing-subscriber / nu-ansi-term) does this for us,
    // so colored log lines rendered as raw `\x1b[...m` bytes without it.
    // This sets a property of the console *object*, not just our handle, so
    // it also fixes the PT child's (lyrebird's) colored output, since that
    // child inherits and writes to the same console.
    #[cfg(windows)]
    enable_windows_ansi_support();

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

    // Busybox-style dispatch: when arti spawns us as a managed pluggable
    // transport, it sets `TOR_PT_MANAGED_TRANSPORT_VER`. In that case we
    // skip the SOCKS5-proxy startup entirely and run the lyrebird PT
    // loop instead — same binary, two modes, no second executable on
    // disk. This MUST run before clap parsing because arti passes weird
    // argv to PT subprocesses that would blow up the parser. PT mode
    // must NEVER daemonise, so it is handled here, out of the clap path
    // entirely, and returns directly.
    if std::env::var_os("TOR_PT_MANAGED_TRANSPORT_VER").is_some() {
        // arti (tor-ptmgr) sets TOR_PT_EXIT_ON_STDIN_CLOSE=1 on managed PT
        // children and, per the pluggable-transport spec, signals shutdown by
        // closing the child's stdin: the child is required to exit on EOF.
        // `ptrs-gesher-lyrebird` 0.5.1 does not honour this (the detection
        // helper exists in ptrs-gesher-core but nothing calls it — unlike
        // Go's lyrebird, which does implement it), so `lyrebird::run()` below
        // just blocks forever once launched. Every watchdog-triggered rebuild
        // that drops the parent's `TorClient` therefore leaks a permanent
        // zombie PT child (16 of them were found accumulated in production).
        // Work around it here with our own blocking stdin-EOF watcher, on a
        // plain OS thread (not a Tokio task) so it keeps running and can
        // still call `process::exit` even if the PT runtime below wedges.
        if std::env::var("TOR_PT_EXIT_ON_STDIN_CLOSE").as_deref() == Ok("1") {
            std::thread::spawn(|| {
                use std::io::Read;

                let mut buf = [0u8; 64];
                loop {
                    match std::io::stdin().read(&mut buf) {
                        Ok(0) | Err(_) => {
                            // Tracing is not guaranteed to be initialised in PT-child
                            // mode (the subscriber is set up later, in the proxy-mode
                            // startup path, which this branch never reaches), so use
                            // eprintln! here rather than `tracing::info!` to make sure
                            // the message isn't silently dropped.
                            eprintln!(
                                "stdin closed by parent — exiting per TOR_PT_EXIT_ON_STDIN_CLOSE"
                            );
                            std::process::exit(0);
                        }
                        Ok(_) => {
                            // PT stdin isn't used for data per the spec; keep draining
                            // it so we still notice the eventual EOF.
                        }
                    }
                }
            });
        }

        let rt = tokio::runtime::Builder::new_multi_thread()
            // See the matching comment on the proxy-mode runtime below: a
            // bursty client (e.g. Telegram opening dozens of simultaneous
            // connections) drives just as many concurrent obfs4/webtunnel
            // handshake attempts here, in the PT child. A small pool risks
            // the same worker-starvation pattern that once stalled the
            // bridge-descriptor fetch task.
            .worker_threads(32)
            .enable_all()
            .build()
            .context("building Tokio runtime for pluggable-transport mode")?;
        return rt.block_on(lyrebird::run());
    }

    let cli = Cli::parse();

    // `--daemon` only applies to the foreground server. Subcommands
    // (`users`, `bridges`, `service`, `help`) are short-lived CLI tools
    // that must stay attached to the terminal.
    if cli.command.is_none() && cli.daemon {
        // Before forking, warn if the configured log sink is stdout/stderr:
        // the daemon redirects both to /dev/null, so those records would be
        // silently lost. This must happen on the *original* stderr (post-fork
        // stderr is /dev/null), so it lives here, before `daemon::daemonize`.
        // If the config can't be loaded, skip the warning silently — the
        // server startup will surface the real config error.
        #[cfg(unix)]
        {
            warn_on_stdout_stderr_logging(cli.config.as_deref());
            daemon::daemonize(cli.pid_file.as_deref())?;
        }

        #[cfg(not(unix))]
        {
            anyhow::bail!(
                "--daemon is Unix-only; on Windows install as a service instead: \
                 tor-socks5 service install"
            );
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
        //
        // Raised 16 -> 32, confirmed by A/B burst-testing (a synthetic
        // Telegram-style flood of dozens of simultaneous SOCKS5 connects):
        // at 16 workers every guard was repeatedly driven to "unsuitable to
        // purpose" (dir_info_missing) — 61 occurrences in one burst, even
        // with a 22-bridge pool — reproducing the original bootstrap-time
        // starvation bug at a larger, sustained scale. At 32 workers, the
        // identical burst produced zero such occurrences.
        .worker_threads(32)
        .enable_all()
        .build()
        .context("building Tokio runtime")?;
    rt.block_on(async_main(cli))
}

/// Turn on `ENABLE_VIRTUAL_TERMINAL_PROCESSING` on the process's console, if
/// it has one, so ANSI escape sequences render as color instead of raw
/// bytes. A no-op (not an error) when stderr is redirected to a file/pipe —
/// `GetConsoleMode` simply fails for a non-console handle, which we ignore.
#[cfg(windows)]
fn enable_windows_ansi_support() {
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_VIRTUAL_TERMINAL_PROCESSING,
        STD_ERROR_HANDLE,
    };
    // SAFETY: GetStdHandle/GetConsoleMode/SetConsoleMode are plain FFI calls
    // on a well-known standard-handle constant; every return value is
    // checked before use and nothing here dereferences a pointer.
    unsafe {
        let handle = GetStdHandle(STD_ERROR_HANDLE);
        let mut mode = 0u32;
        if GetConsoleMode(handle, &mut mode) != 0 {
            SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }
}

/// If `log.output` is `stdout` or `stderr`, print a warning to the *original*
/// stderr explaining that daemonisation will redirect those to `/dev/null`.
/// No-op for any other sink (file logging survives the daemon fork just fine)
/// and on any config-load failure (the server startup owns surfacing that).
#[cfg(unix)]
fn warn_on_stdout_stderr_logging(config_override: Option<&std::path::Path>) {
    use crate::config::{Config, LogOutput};
    let Ok(loaded) = Config::load_with_override(config_override) else {
        return;
    };
    let cfg = loaded.into_config();
    let which = match cfg.log.output {
        LogOutput::Stdout => Some("stdout"),
        LogOutput::Stderr => Some("stderr"),
        LogOutput::File => None,
    };
    if let Some(name) = which {
        eprintln!(
            "warning: --daemon detached the process, but log.output is {name} — those records go \
             to /dev/null. Set log.output=file (and log.file=...) in the config to capture daemon \
             logs."
        );
    }
}

async fn async_main(cli: Cli) -> Result<()> {
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
