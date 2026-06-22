//! Process-wide startup helpers shared by the server and the
//! `bridges fetch` command: logging setup and the rustls crypto provider.

use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};

use crate::arti_observability::{GuardObservabilityLayer, ObservationSink};
use crate::config::{Config, LogConfig, LogOutput};

/// `rustls` 0.23 requires picking a process-wide crypto provider explicitly.
pub(crate) fn install_crypto_provider() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("CryptoProvider must be installed exactly once");
}

/// Initialise the global tracing subscriber from the config's log
/// settings and return the non-blocking writer's [`WorkerGuard`] plus
/// the [`ObservationSink`] that captures per-guard usability events
/// from arti.
///
/// Logging is **non-blocking**: records are handed to a dedicated writer
/// thread, so a slow or full sink (a file on a busy disk, a piped
/// terminal) never stalls a request-handling task. The returned guard
/// must be kept alive for the lifetime of the program — dropping it
/// flushes and stops the writer thread, so bind it to a variable that
/// lives until shutdown.
///
/// Active health observation: a second tracing layer
/// ([`GuardObservabilityLayer`]) listens on `tor_guardmgr=trace`
/// regardless of the user's main log filter. It pushes guard-usability
/// observations into the returned [`ObservationSink`] without producing
/// any log output of its own. The proxy's maintenance loop drains the
/// sink into the bridge health store; see
/// [`crate::tor_setup::update_health_and_prune`].
///
/// `RUST_LOG` overrides the config file's level/target settings for the
/// fmt layer only; the observability layer's filter is fixed.
pub(crate) fn init_tracing(cfg: &Config) -> (WorkerGuard, ObservationSink) {
    use tracing_subscriber::filter::EnvFilter;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::Layer;

    let user_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(cfg.log.to_filter()));

    let (writer, guard, ansi) = make_writer(&cfg.log);

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_ansi(ansi)
        .with_writer(writer)
        .with_filter(user_filter);

    // Active health observation: a per-layer filter on `tor_guardmgr=trace`
    // (independent of the user's fmt filter) feeds the observability layer
    // the structured events it needs without dragging arti traffic noise
    // into the user-visible log.
    let sink = ObservationSink::new();
    let observability_layer = GuardObservabilityLayer::new(sink.clone())
        .with_filter(EnvFilter::new("tor_guardmgr=trace"));

    tracing_subscriber::registry()
        .with(fmt_layer)
        .with(observability_layer)
        .init();

    (guard, sink)
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
