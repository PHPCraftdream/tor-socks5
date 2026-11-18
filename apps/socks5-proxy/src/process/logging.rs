//! Process-wide logging setup: a thin adapter over the relocated helpers in
//! `tor_socks5::runtime::log_layer`, shared by the server and the
//! `bridges fetch` command.

use tracing_appender::non_blocking::WorkerGuard;

use crate::config::Config;
use tor_socks5::runtime::{observation_layer, ObservationSink};

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
/// Active health observation: a second tracing layer —
/// `arti_observability::observation_layer` — listens on
/// `tor_guardmgr=trace` regardless of the user's main log filter. It
/// pushes guard-usability observations into the returned
/// [`ObservationSink`] without producing
/// any log output of its own. The proxy's maintenance loop drains the
/// sink into the bridge health store; see
/// tor_socks5::runtime (build_tor_settings) update_health_and_prune.
///
/// `RUST_LOG` overrides the config file's level/target settings for the
/// fmt layer only; the observability layer's filter is fixed.
pub(crate) fn init_tracing(cfg: &Config) -> (WorkerGuard, ObservationSink) {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    // Writer resolution, ANSI resolution, the `RUST_LOG`-over-config filter
    // and the `NO_COLOR` propagation to the PT child all live in the runtime
    // crate now (moved verbatim; see `host::logging::log_layer`).
    let (fmt_layer, guard) = tor_socks5::runtime::log_layer(&cfg.log);

    // Active health observation: a per-layer filter on `tor_guardmgr=trace`
    // (independent of the user's fmt filter) feeds the observability layer
    // the structured events it needs without dragging arti traffic noise
    // into the user-visible log.
    let sink = ObservationSink::new();

    tracing_subscriber::registry()
        .with(fmt_layer)
        .with(observation_layer(&sink))
        .init();

    (guard, sink)
}
