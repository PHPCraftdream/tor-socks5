//! Host-side logging: the tracing fmt layer built from a
//! [`LogConfig`](proxy_config::LogConfig), plus the colour-propagation and
//! writer-resolution helpers moved verbatim from the binary's
//! `process/logging.rs`. Unlike the binary's `init_tracing`, [`log_layer`]
//! does **not** install a global subscriber: the host composes the returned
//! layer into its own registry (e.g. together with
//! `arti_observability::observation_layer`).

use std::io::IsTerminal;

use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};

use crate::config::{LogConfig, LogOutput};

/// Build the tracing fmt layer for the configured log settings, and return
/// it together with the non-blocking writer's [`WorkerGuard`].
///
/// The user's `RUST_LOG` overrides the config file's level/target settings
/// for this layer (`EnvFilter::try_from_default_env`, falling back to
/// `LogConfig::to_filter()`).
///
/// Logging is **non-blocking**: records are handed to a dedicated writer
/// thread, so a slow or full sink (a file on a busy disk, a piped
/// terminal) never stalls a request-handling task. The returned guard
/// must be kept alive for the lifetime of the program — dropping it
/// flushes and stops the writer thread, so bind it to a variable that
/// lives until shutdown.
///
/// This does **not** install a global subscriber: the host composes the
/// returned layer into its own registry (e.g. alongside the
/// `observation_layer`), then registers that subscriber itself.
pub fn log_layer(
    log: &LogConfig,
) -> (
    impl tracing_subscriber::Layer<tracing_subscriber::Registry> + use<>,
    WorkerGuard,
) {
    use tracing_subscriber::filter::EnvFilter;

    log_layer_with_filter(
        log,
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log.to_filter())),
    )
}

/// Internal, test-deterministic variant: the caller supplies the user filter
/// directly instead of reading `RUST_LOG` from the process environment
/// (shared mutable state parallel tests must not depend on).
fn log_layer_with_filter(
    log: &LogConfig,
    user_filter: tracing_subscriber::filter::EnvFilter,
) -> (
    impl tracing_subscriber::Layer<tracing_subscriber::Registry> + use<>,
    WorkerGuard,
) {
    use tracing_subscriber::Layer;

    let (writer, guard, ansi) = make_writer(log);

    // Propagate the same stderr colour decision to the pluggable-transport
    // child process (run later via the busybox dispatch): its own
    // independent tracing layer always writes to the inherited stderr, so
    // without this it would emit raw ANSI escapes into a redirected log
    // file even though our own layer has already gone plain.
    propagate_color_preference_to_pt_child(log);

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_ansi(ansi)
        .with_writer(writer)
        .with_filter(user_filter);

    (fmt_layer, guard)
}

/// Build the non-blocking writer for the configured sink. Returns the
/// writer, its flush guard, and whether ANSI colour should be enabled —
/// resolved by [`resolve_ansi`] from the configured flag and the *actual*
/// destination's TTY status. Any failure to open a file degrades to
/// stderr with a message on the original stderr (the subscriber is not
/// up yet, so `tracing` is not available here).
fn make_writer(log: &LogConfig) -> (NonBlocking, WorkerGuard, bool) {
    // Probe the real TTY status of each standard stream once. A static
    // config flag cannot tell whether stdout/stderr is an actual terminal
    // or has been redirected to a file/pipe (e.g. `> log.err` or a
    // `Start-Process -RedirectStandardError` launch); `is_terminal()`
    // reflects the live handle, so colour is only enabled when the bytes
    // truly go to a console.
    let stdout_tty = std::io::stdout().is_terminal();
    let stderr_tty = std::io::stderr().is_terminal();
    match log.output {
        LogOutput::Stdout => {
            let (nb, guard) = tracing_appender::non_blocking(std::io::stdout());
            let ansi = resolve_ansi(log.ansi, LogOutput::Stdout, stdout_tty, stderr_tty);
            (nb, guard, ansi)
        }
        LogOutput::Stderr => {
            let (nb, guard) = tracing_appender::non_blocking(std::io::stderr());
            let ansi = resolve_ansi(log.ansi, LogOutput::Stderr, stdout_tty, stderr_tty);
            (nb, guard, ansi)
        }
        LogOutput::File => {
            if log.file.trim().is_empty() {
                eprintln!("log.output = file but log.file is empty — falling back to stderr");
                let (nb, guard) = tracing_appender::non_blocking(std::io::stderr());
                // Bytes now land on stderr, so the stderr TTY rule applies.
                let ansi = resolve_ansi(log.ansi, LogOutput::Stderr, stdout_tty, stderr_tty);
                return (nb, guard, ansi);
            }
            match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log.file)
            {
                Ok(file) => {
                    let (nb, guard) = tracing_appender::non_blocking(file);
                    // Real file output: colour is always off.
                    let ansi = resolve_ansi(log.ansi, LogOutput::File, stdout_tty, stderr_tty);
                    (nb, guard, ansi)
                }
                Err(e) => {
                    eprintln!(
                        "could not open log file {:?}: {e} — falling back to stderr",
                        log.file
                    );
                    // Bytes now land on stderr, so the stderr TTY rule applies.
                    let (nb, guard) = tracing_appender::non_blocking(std::io::stderr());
                    let ansi = resolve_ansi(log.ansi, LogOutput::Stderr, stdout_tty, stderr_tty);
                    (nb, guard, ansi)
                }
            }
        }
    }
}

/// Decide whether ANSI colour escapes should be emitted, given the user's
/// configured `ansi` flag, the *actual* destination of the log bytes, and
/// the TTY status of stdout/stderr.
///
/// `ansi` is an opt-in that only takes effect when the bytes really go to a
/// terminal:
/// - `File` → always `false`; raw escapes in a file are literal noise and
///   [`LogConfig::ansi`] documents they are forced off.
/// - `Stdout` → `configured && is_stdout_tty`.
/// - `Stderr` → `configured && is_stderr_tty`.
///
/// This is split out purely so the TTY booleans are injectable in tests —
/// `std::io::stdout().is_terminal()` cannot be mocked directly.
fn resolve_ansi(
    configured: bool,
    destination: LogOutput,
    is_stdout_tty: bool,
    is_stderr_tty: bool,
) -> bool {
    match destination {
        LogOutput::File => false,
        LogOutput::Stdout => configured && is_stdout_tty,
        LogOutput::Stderr => configured && is_stderr_tty,
    }
}

/// Pure decision extracted from [`propagate_color_preference_to_pt_child`]:
/// should the `NO_COLOR` env var be set for the pluggable-transport child?
/// The PT child always writes to its *inherited* stderr (regardless of our
/// own `LogConfig::output`), so this follows the `Stderr` rule of
/// [`resolve_ansi`] and negates it: `NO_COLOR` is wanted precisely when ANSI
/// should *not* be on for an inherited-stderr destination.
///
/// Split out so the logic is unit-testable without probing the real
/// `std::io::stderr().is_terminal()` or mutating the process-wide `NO_COLOR`
/// env var (shared state that parallel tests in one process must not touch).
fn should_set_no_color(configured: bool, is_stderr_tty: bool) -> bool {
    !resolve_ansi(configured, LogOutput::Stderr, is_stderr_tty, is_stderr_tty)
}

/// Propagate our own stderr colour decision to the pluggable-transport child
/// process (`ptrs-gesher-lyrebird`, spawned later via the busybox dispatch
/// in `crate::pt::run_if_managed_transport`). That crate sets up its own
/// independent `tracing_subscriber`, always writing straight to its
/// *inherited* stderr handle — the same OS handle as ours whenever stderr
/// has been redirected — and defaults to ANSI-on unless the `NO_COLOR` env
/// var is set (a https://no-color.org convention it already implements; its
/// own doc comment explicitly expects the parent to do exactly this).
/// Without this, a redirected/non-terminal stderr still gets raw ANSI
/// escapes from the PT child even after our own log output is already
/// correctly plain.
///
/// Keyed on `LogOutput::Stderr`'s rule regardless of our OWN
/// `LogConfig::output` target, because the PT child's writer target is fixed
/// (always stderr) and does not follow our own config. When colour should
/// stay on, the env var is left untouched — a user who already set
/// `NO_COLOR` themselves is honoured as-is (never cleared). Called once from
/// [`log_layer`], before arti/tor-ptmgr later spawns the PT child.
fn propagate_color_preference_to_pt_child(log: &LogConfig) {
    let stderr_tty = std::io::stderr().is_terminal();
    if should_set_no_color(log.ansi, stderr_tty) {
        std::env::set_var("NO_COLOR", "1");
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use tracing::Level;
    use tracing_subscriber::layer::{Context, SubscriberExt};
    use tracing_subscriber::Layer;

    use super::*;

    // (а) configured on + real terminal → colours on.
    #[test]
    fn ansi_on_when_configured_and_stdout_is_terminal() {
        assert!(resolve_ansi(true, LogOutput::Stdout, true, false));
    }

    #[test]
    fn ansi_on_when_configured_and_stderr_is_terminal() {
        assert!(resolve_ansi(true, LogOutput::Stderr, false, true));
    }

    // (б) configured on but redirected (not a terminal) → colours off, so
    // raw escape bytes never land in a redirected file/pipe.
    #[test]
    fn ansi_off_when_stdout_redirected() {
        assert!(!resolve_ansi(true, LogOutput::Stdout, false, true));
    }

    #[test]
    fn ansi_off_when_stderr_redirected() {
        assert!(!resolve_ansi(true, LogOutput::Stderr, true, false));
    }

    // (в) explicitly disabled by the user → off even on a real terminal.
    #[test]
    fn ansi_off_when_configured_off_even_on_terminal() {
        assert!(!resolve_ansi(false, LogOutput::Stdout, true, true));
        assert!(!resolve_ansi(false, LogOutput::Stderr, true, true));
    }

    // (г) file destination → always off, regardless of flag or TTY status.
    #[test]
    fn ansi_always_off_for_file_output() {
        assert!(!resolve_ansi(true, LogOutput::File, true, true));
        assert!(!resolve_ansi(false, LogOutput::File, false, false));
    }

    // A stream's decision depends only on its own TTY status: the stdout
    // rule never consults stderr's TTY bit, and vice versa.
    #[test]
    fn each_stream_uses_only_own_tty_status() {
        assert!(resolve_ansi(true, LogOutput::Stdout, true, false));
        assert!(!resolve_ansi(true, LogOutput::Stdout, false, true));
        assert!(resolve_ansi(true, LogOutput::Stderr, false, true));
        assert!(!resolve_ansi(true, LogOutput::Stderr, true, false));
    }

    // --- should_set_no_color (the PT-child colour-propagation decision) ---
    //
    // The PT child always writes to its inherited stderr, so NO_COLOR is
    // set iff ANSI would be off for a stderr destination — i.e. the exact
    // negation of `resolve_ansi(..., LogOutput::Stderr, t, t)`.

    // configured on + stderr is a real terminal → colour on → NO_COLOR NOT
    // set, so a terminal PT child still gets colours.
    #[test]
    fn no_color_not_set_when_configured_and_stderr_is_terminal() {
        assert!(!should_set_no_color(true, true));
    }

    // configured on but stderr redirected (not a terminal) → colour off →
    // NO_COLOR set, so the PT child's inherited-stderr bytes stay plain.
    #[test]
    fn no_color_set_when_stderr_redirected_even_if_configured() {
        assert!(should_set_no_color(true, false));
    }

    // explicitly disabled by the user → colour off even on a terminal →
    // NO_COLOR set, propagating the user's opt-out to the PT child too.
    #[test]
    fn no_color_set_when_configured_off_even_on_terminal() {
        assert!(should_set_no_color(false, true));
    }

    // both off: configured off and no terminal → NO_COLOR set.
    #[test]
    fn no_color_set_when_configured_off_and_redirected() {
        assert!(should_set_no_color(false, false));
    }

    // --- log_layer acceptance (H12): a layer built from a `LogConfig` at
    // INFO passes INFO/WARN events from production targets and filters out
    // DEBUG ones. A `Filtered` layer (via `with_filter`) short-circuits
    // disabled events, so a recorder placed after the fmt layer sees only
    // enabled events. Deterministic in CI (no `RUST_LOG` set): the
    // `try_from_default_env` fallback is the config's own filter.
    #[derive(Clone, Default)]
    struct RecordingLayer {
        seen: std::sync::Arc<Mutex<Vec<(Level, String)>>>,
    }

    impl<S: tracing::Subscriber> Layer<S> for RecordingLayer {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            self.seen.lock().unwrap().push((
                *event.metadata().level(),
                event.metadata().target().to_owned(),
            ));
        }
    }

    fn log_cfg() -> LogConfig {
        LogConfig {
            default: "info".to_owned(),
            targets: Default::default(),
            output: LogOutput::Stderr,
            file: String::new(),
            ansi: false,
        }
    }

    #[test]
    fn log_layer_passes_info_from_production_targets_and_filters_debug() {
        // Note on observability: in `tracing-subscriber` 0.3, a per-layer
        // filter (`with_filter`) intentionally never disables a callsite or
        // event globally, so a recorder layer placed *after* the filtered
        // fmt layer still receives every dispatched event. The DEBUG
        // assertion is therefore made on the fmt layer's own writer output
        // (a temp file) — the observable a real host sees.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("probe.log");
        let cfg = LogConfig {
            output: LogOutput::File,
            file: file.to_string_lossy().into_owned(),
            ..log_cfg()
        };
        let (layer, guard) =
            log_layer_with_filter(&cfg, tracing_subscriber::filter::EnvFilter::new("info"));
        let recorder = RecordingLayer::default();
        let subscriber = tracing_subscriber::registry()
            .with(layer)
            .with(recorder.clone());
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "tor_socks5_runtime::bridge_manager", "probe info");
            tracing::warn!(target: "tor_socks5_runtime::bridge_manager", "probe warn");
            tracing::debug!(target: "tor_socks5_runtime::bridge_manager", "probe debug");
        });

        // The recorder saw the INFO and WARN events from a production target.
        let seen = recorder.seen.lock().unwrap();
        assert!(seen.contains(&(Level::INFO, "tor_socks5_runtime::bridge_manager".to_owned())));
        assert!(seen.contains(&(Level::WARN, "tor_socks5_runtime::bridge_manager".to_owned())));
        drop(seen);

        // The fmt layer itself wrote the INFO record but not the DEBUG one.
        drop(guard); // flush + stop the non-blocking writer thread
        let written = std::fs::read_to_string(&file).unwrap();
        assert!(written.contains("probe info"));
        assert!(!written.contains("probe debug"));
    }
}
