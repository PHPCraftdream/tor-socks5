#[path = "commands/angel.rs"]
mod angel;
#[path = "fetch/bridges_cmd.rs"]
mod bridges_cmd;
#[path = "commands/cli.rs"]
mod cli;
mod config;
#[path = "commands/config_cmd.rs"]
mod config_cmd;
#[path = "commands/help_cmd.rs"]
mod help_cmd;
#[path = "commands/onion/mod.rs"]
mod onion;
#[path = "process/mod.rs"]
mod process;
#[path = "commands/service.rs"]
mod service;
#[path = "commands/users_cli/mod.rs"]
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
    // transport (TOR_PT_MANAGED_TRANSPORT_VER), run the in-process lyrebird
    // PT loop instead of the proxy. Must run before clap parsing (arti passes
    // argv that would blow up the parser) and must never angelise.
    if let Some(result) = tor_socks5_runtime::pt::run_if_managed_transport() {
        return result;
    }

    let cli = Cli::parse();

    // `--angel` only applies to the foreground server. Subcommands
    // (`users`, `bridges`, `service`, `help`) are short-lived CLI tools
    // that must stay attached to the terminal.
    #[cfg(not(target_os = "android"))]
    if cli.command.is_none() && cli.angel {
        // Before forking, warn if the configured log sink is stdout/stderr:
        // the angel redirects both to /dev/null, so those records would be
        // silently lost. This must happen on the *original* stderr (post-fork
        // stderr is /dev/null), so it lives here, before `angel::angelize`.
        // If the config can't be loaded, skip the warning silently — the
        // server startup will surface the real config error.
        #[cfg(all(unix, not(target_os = "android")))]
        {
            warn_on_stdout_stderr_logging(cli.config.as_deref());
            angel::angelize(cli.pid_file.as_deref())?;
        }

        #[cfg(not(unix))]
        {
            anyhow::bail!(
                "--angel is Unix-only; on Windows install as a service instead: \
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
/// stderr explaining that angelisation will redirect those to `/dev/null`.
/// No-op for any other sink (file logging survives the angel fork just fine)
/// and on any config-load failure (the server startup owns surfacing that).
#[cfg(all(unix, not(target_os = "android")))]
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
            "warning: --angel detached the process, but log.output is {name} — those records go \
             to /dev/null. Set log.output=file (and log.file=...) in the config to capture angel \
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
        Some(Command::Config { action }) => {
            return config_cmd::run(action, cli.config.as_deref());
        }
        #[cfg(feature = "onion-service")]
        Some(Command::Onion { action }) => {
            return crate::onion::commands::run(action, cli.config.as_deref());
        }
        Some(Command::Help { all, topic }) => {
            help_cmd::run(all, topic);
            return Ok(());
        }
        None => {}
    }

    // Normal foreground server: shut down on Ctrl-C / SIGINT / SIGTERM.
    let shutdown = async {
        let sig = process::wait_for_signal().await;
        info!(%sig, "shutdown signal received");
    };
    process::run_server_process(
        cli.config.clone(),
        cli.upstream.clone(),
        cli.upstream_user.clone(),
        cli.upstream_pass.clone(),
        cli.no_upstream,
        shutdown,
    )
    .await
}
