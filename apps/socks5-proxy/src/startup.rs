//! Process-wide startup helpers shared by the server and the
//! `bridges fetch` command: logging setup and the rustls crypto provider.

use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};

use crate::config::{Config, LogConfig, LogOutput};

/// `rustls` 0.23 requires picking a process-wide crypto provider explicitly.
pub(crate) fn install_crypto_provider() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("CryptoProvider must be installed exactly once");
}

/// Initialise the global tracing subscriber from the config's log
/// settings and return the non-blocking writer's [`WorkerGuard`].
///
/// Logging is **non-blocking**: records are handed to a dedicated writer
/// thread, so a slow or full sink (a file on a busy disk, a piped
/// terminal) never stalls a request-handling task. The returned guard
/// must be kept alive for the lifetime of the program — dropping it
/// flushes and stops the writer thread, so bind it to a variable that
/// lives until shutdown.
///
/// `RUST_LOG` overrides the config file's level/target settings when set.
pub(crate) fn init_tracing(cfg: &Config) -> WorkerGuard {
    use tracing_subscriber::EnvFilter;

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(cfg.log.to_filter()));

    let (writer, guard, ansi) = make_writer(&cfg.log);

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(ansi)
        .with_writer(writer)
        .init();

    guard
}

/// Build the non-blocking writer for the configured sink. Returns the
/// writer, its flush guard, and whether ANSI colour should be enabled
/// (always off for a file sink). Any failure to open a file degrades to
/// stderr with a message on the original stderr (the subscriber is not
/// up yet, so `tracing` is not available here).
fn make_writer(log: &LogConfig) -> (NonBlocking, WorkerGuard, bool) {
    match log.output {
        LogOutput::Stdout => {
            let (nb, guard) = tracing_appender::non_blocking(std::io::stdout());
            (nb, guard, log.ansi)
        }
        LogOutput::Stderr => {
            let (nb, guard) = tracing_appender::non_blocking(std::io::stderr());
            (nb, guard, log.ansi)
        }
        LogOutput::File => {
            if log.file.trim().is_empty() {
                eprintln!("log.output = file but log.file is empty — falling back to stderr");
                let (nb, guard) = tracing_appender::non_blocking(std::io::stderr());
                return (nb, guard, log.ansi);
            }
            match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log.file)
            {
                Ok(file) => {
                    // No ANSI escapes in a file — they would be literal noise.
                    let (nb, guard) = tracing_appender::non_blocking(file);
                    (nb, guard, false)
                }
                Err(e) => {
                    eprintln!(
                        "could not open log file {:?}: {e} — falling back to stderr",
                        log.file
                    );
                    let (nb, guard) = tracing_appender::non_blocking(std::io::stderr());
                    (nb, guard, log.ansi)
                }
            }
        }
    }
}
