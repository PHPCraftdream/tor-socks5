//! Process-wide startup helpers shared by the server and the
//! `bridges fetch` command: logging setup and the rustls crypto provider.

use std::io::IsTerminal;
use std::path::Path;

use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};

use auth::UsersConfig;
use proxy_config::EndpointOverride;

use crate::arti_observability::{GuardObservabilityLayer, ObservationSink};
use crate::config::{Config, LogConfig, LogOutput};

/// Отклонить неподдерживаемый SOCKS5 endpoint до запуска сети.
pub(crate) fn reject_unsupported_endpoint(
    setting: &Option<EndpointOverride>,
    scope: &str,
) -> anyhow::Result<()> {
    if matches!(setting, Some(EndpointOverride::Endpoint(_))) {
        anyhow::bail!(
            "{scope} SOCKS5 endpoint is not supported yet; remove it or set it to `none`"
        );
    }
    Ok(())
}

pub(crate) fn reject_unsupported_account_endpoints(users: &UsersConfig) -> anyhow::Result<()> {
    for user in users.users.iter().filter(|user| user.is_enabled) {
        for (scope, setting) in [
            ("enabled account pre_socks5", &user.pre_socks5),
            ("enabled account post_socks5", &user.post_socks5),
        ] {
            reject_unsupported_endpoint(setting, scope)?;
        }
    }
    Ok(())
}

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

    // Propagate the same stderr colour decision to the pluggable-transport
    // child process (run later via the busybox dispatch in `main.rs`): its
    // own independent tracing layer always writes to the inherited stderr,
    // so without this it would emit raw ANSI escapes into a redirected log
    // file even though our own layer has already gone plain.
    propagate_color_preference_to_pt_child(&cfg.log);

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

#[cfg(test)]
mod endpoint_guard_tests {
    use super::{reject_unsupported_account_endpoints, reject_unsupported_endpoint};
    use auth::{User, UsersConfig};
    use proxy_config::EndpointOverride;

    fn endpoint() -> EndpointOverride {
        EndpointOverride::Endpoint("127.0.0.1:1080".parse().unwrap())
    }

    fn user(
        is_enabled: bool,
        pre_socks5: Option<EndpointOverride>,
        post_socks5: Option<EndpointOverride>,
    ) -> User {
        User {
            name: "test".to_string(),
            hash: "unused".to_string(),
            is_enabled,
            allowed_onion: false,
            allowed_clients: None,
            pre_socks5,
            post_socks5,
        }
    }

    #[test]
    fn rejects_global_pre_and_post_endpoints() {
        for scope in ["global pre_socks5", "global post_socks5"] {
            let error = reject_unsupported_endpoint(&Some(endpoint()), scope).unwrap_err();
            assert!(error.to_string().contains(scope));
            assert!(error.to_string().contains("not supported yet"));
        }
    }

    #[test]
    fn rejects_account_endpoint_without_global_setting() {
        let users = UsersConfig {
            users: vec![
                user(true, Some(endpoint()), None),
                user(true, None, Some(endpoint())),
            ],
        };
        let error = reject_unsupported_account_endpoints(&users).unwrap_err();
        assert!(error.to_string().contains("enabled account pre_socks5"));
        assert!(error.to_string().contains("not supported yet"));
        let post_only = UsersConfig {
            users: vec![user(true, None, Some(endpoint()))],
        };
        let error = reject_unsupported_account_endpoints(&post_only).unwrap_err();
        assert!(error.to_string().contains("enabled account post_socks5"));
    }

    #[test]
    fn disabled_account_does_not_run_endpoint_guard() {
        let users = UsersConfig {
            users: vec![user(false, Some(endpoint()), Some(endpoint()))],
        };
        assert!(reject_unsupported_account_endpoints(&users).is_ok());
    }

    #[test]
    fn absent_and_explicitly_disabled_settings_are_allowed() {
        assert!(reject_unsupported_endpoint(&None, "endpoint").is_ok());
        assert!(reject_unsupported_endpoint(&Some(EndpointOverride::Disabled), "endpoint").is_ok());
    }
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
/// in `main.rs`). That crate sets up its own independent
/// `tracing_subscriber`, always writing straight to its *inherited* stderr
/// handle — the same OS handle as ours whenever stderr has been redirected —
/// and defaults to ANSI-on unless the `NO_COLOR` env var is set (a
/// https://no-color.org convention it already implements; its own doc
/// comment explicitly expects the parent to do exactly this). Without this,
/// a redirected/non-terminal stderr still gets raw ANSI escapes from the PT
/// child even after our own log output is already correctly plain.
///
/// Keyed on `LogOutput::Stderr`'s rule regardless of our OWN
/// `LogConfig::output` target, because the PT child's writer target is fixed
/// (always stderr) and does not follow our own config. When colour should
/// stay on, the env var is left untouched — a user who already set
/// `NO_COLOR` themselves is honoured as-is (never cleared). Called once from
/// [`init_tracing`], before arti/tor-ptmgr later spawns the PT child.
fn propagate_color_preference_to_pt_child(log: &LogConfig) {
    let stderr_tty = std::io::stderr().is_terminal();
    if should_set_no_color(log.ansi, stderr_tty) {
        std::env::set_var("NO_COLOR", "1");
    }
}

/// First run on a main config the operator made by hand: create the bridges
/// file with the defaults in `cfg`, so there is a file to edit. Taken under
/// the config's path lock like every other writer of the pool, and re-checked
/// inside it. Convenience only: a failure is logged, not fatal. Returns
/// whether the file was created.
pub(crate) fn ensure_bridges_file(cfg: &Config, config_path: &Path) -> bool {
    use persist_lock::{PathLock, CLI_LOCK_WAIT};

    let bridges_path = Config::bridges_path(config_path);
    if bridges_path.exists() {
        return false;
    }
    let _lock = match PathLock::acquire_bounded(config_path, CLI_LOCK_WAIT) {
        Ok(lock) => lock,
        Err(error) => {
            tracing::warn!(%error, path = %bridges_path.display(), "could not lock the config to create the bridges file");
            return false;
        }
    };
    if bridges_path.exists() {
        return false;
    }
    match cfg.write_bridges(config_path) {
        Ok(()) => {
            tracing::info!(path = %bridges_path.display(), "created the bridges file with defaults");
            true
        }
        Err(error) => {
            tracing::warn!(%error, path = %bridges_path.display(), "could not create the bridges file");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridges_file_is_created_once_and_never_overwritten() {
        let dir = std::env::temp_dir().join(format!("tor-socks5-ensure-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("tor-socks5.ktav");
        let mut cfg = Config::default();
        assert!(ensure_bridges_file(&cfg, &config_path));
        let bridges_path = Config::bridges_path(&config_path);
        assert!(bridges_path.exists());

        // An existing file (here: the operator's own pool) is left alone.
        cfg.bridges.min_alive = 99;
        assert!(!ensure_bridges_file(&cfg, &config_path));
        let text = std::fs::read_to_string(&bridges_path).unwrap();
        assert!(!text.contains("min_alive: 99"), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

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
}
