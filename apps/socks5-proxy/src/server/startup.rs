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

/// Проверить все включённые маршруты до запуска сети.
pub(crate) fn validate_account_routes(
    users: &UsersConfig,
    global_pre: Option<&EndpointOverride>,
    global_post: Option<&EndpointOverride>,
    dns: bool,
    upstream: bool,
) -> anyhow::Result<()> {
    for user in users.users.iter().filter(|user| user.is_enabled) {
        resolve_account_route(
            global_pre,
            global_post,
            user.pre_socks5.as_ref(),
            user.post_socks5.as_ref(),
            dns,
            upstream,
        )?;
    }
    Ok(())
}

/// Собственный снимок разрешённых маршрутов.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AdmittedRoute {
    pub(crate) pre: Option<EndpointOverride>,
    pub(crate) post: Option<EndpointOverride>,
}

/// Разрешить pre и post независимо.
pub(crate) fn resolve_account_route(
    global_pre: Option<&EndpointOverride>,
    global_post: Option<&EndpointOverride>,
    account_pre: Option<&EndpointOverride>,
    account_post: Option<&EndpointOverride>,
    dns: bool,
    upstream: bool,
) -> anyhow::Result<AdmittedRoute> {
    let global_pre_resolved = proxy_config::resolve_endpoint(global_pre, None);
    let pre = proxy_config::resolve_endpoint(global_pre, account_pre);
    let post = proxy_config::resolve_endpoint(global_post, account_post);
    if upstream && global_pre_resolved.is_some() {
        anyhow::bail!("global pre_socks5 cannot be combined with upstream egress");
    }
    if pre.is_some() && (dns || upstream) {
        anyhow::bail!("pre_socks5 cannot be combined with DNS listener or upstream egress");
    }
    validate_post_compatibility(post.is_some(), dns, upstream)?;
    Ok(AdmittedRoute {
        pre: pre.map(EndpointOverride::Endpoint),
        post: post.map(EndpointOverride::Endpoint),
    })
}

/// Маршрут определяется только из допущенного снимка.
pub(crate) fn resolve_admitted_route(
    global_pre: Option<&EndpointOverride>,
    global_post: Option<&EndpointOverride>,
    lease: Option<&auth::AdmissionLease>,
    dns: bool,
    upstream: bool,
) -> anyhow::Result<AdmittedRoute> {
    resolve_account_route(
        global_pre,
        global_post,
        lease.and_then(|lease| lease.pre_socks5()),
        lease.and_then(|lease| lease.post_socks5()),
        dns,
        upstream,
    )
}

/// Не допустить обход post через независимый DNS или upstream вместо Tor.
pub(crate) fn validate_post_compatibility(
    post: bool,
    dns: bool,
    upstream: bool,
) -> anyhow::Result<()> {
    if post && (dns || upstream) {
        anyhow::bail!("post_socks5 cannot be combined with DNS listener or upstream egress");
    }
    Ok(())
}

/// Выбрать один маршрут; ошибка post не запускает прямой путь.
pub(crate) async fn select_post_route<T, D, P>(use_post: bool, direct: D, post: P) -> T
where
    D: std::future::Future<Output = T>,
    P: std::future::Future<Output = T>,
{
    if use_post {
        post.await
    } else {
        direct.await
    }
}

/// Установить соединение через Tor и необязательный post SOCKS5.
///
/// cancel-safe: NO — при отмене частично открытый поток отбрасывается.
pub(crate) async fn connect_tor_route(
    tor: &arti_wrapper::TorTunnel,
    post: Option<&EndpointOverride>,
    host: &str,
    port: u16,
) -> Result<arti_wrapper::DataStream, arti_wrapper::TorError> {
    let post_connect = async {
        let Some(EndpointOverride::Endpoint(endpoint)) = post else {
            return Err(arti_wrapper::TorError::PostSocks(
                socks5_proto::client::Error::InvalidInput,
            ));
        };
        let credentials = endpoint
            .credentials()
            .map(|(username, password)| arti_wrapper::PostSocksCredentials::new(username, password))
            .transpose()
            .map_err(arti_wrapper::TorError::PostSocks)?;
        arti_wrapper::connect_post_socks(
            tor,
            &endpoint.address().ip().to_string(),
            endpoint.address().port(),
            host,
            port,
            credentials.as_ref(),
            std::time::Instant::now() + crate::upstream::UPSTREAM_SETUP_DEADLINE,
        )
        .await
    };
    select_post_route(post.is_some(), tor.connect(host, port), post_connect).await
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
    use super::{
        reject_unsupported_endpoint, resolve_account_route, resolve_admitted_route,
        select_post_route, validate_account_routes, validate_post_compatibility, AdmittedRoute,
    };
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
    fn account_validation_does_not_replace_global_startup_guard() {
        let global = endpoint();
        let mut init = user(true, None, Some(EndpointOverride::Disabled));
        init.hash = auth::INIT_SENTINEL.to_owned();
        let users = UsersConfig { users: vec![init] };
        // Проверка аккаунтов отдельно; глобальный guard всё равно запрещает запуск.
        assert!(validate_account_routes(&users, None, Some(&global), true, false).is_ok());
        assert!(validate_account_routes(&users, None, Some(&global), false, true).is_ok());
        assert!(validate_post_compatibility(true, true, false).is_err());
        assert!(validate_post_compatibility(true, false, true).is_err());
        let users = UsersConfig {
            users: vec![user(true, None, Some(endpoint()))],
        };
        assert!(validate_account_routes(&users, None, None, true, false).is_err());
        assert!(validate_account_routes(&users, None, None, false, true).is_err());
        let users = UsersConfig {
            users: vec![user(false, Some(endpoint()), Some(endpoint()))],
        };
        assert!(validate_account_routes(&users, None, None, true, true).is_ok());
    }

    #[test]
    fn account_routes_resolve_independently_and_fail_closed() {
        let global = endpoint();
        let replacement =
            EndpointOverride::Endpoint("127.0.0.1:1081|alice:secret".parse().unwrap());
        let disabled = EndpointOverride::Disabled;
        let cases = [
            (None, Some(global.clone())),
            (Some(&disabled), None),
            (Some(&replacement), Some(replacement.clone())),
        ];
        for (account, expected) in cases {
            let route =
                resolve_account_route(Some(&global), Some(&global), account, None, false, false)
                    .unwrap();
            assert_eq!(route.pre, expected);
            assert_eq!(route.post, Some(global.clone()));
            let route =
                resolve_account_route(Some(&global), Some(&global), None, account, false, false)
                    .unwrap();
            assert_eq!(route.pre, Some(global.clone()));
            assert_eq!(route.post, expected);
        }
        let route =
            resolve_account_route(None, None, Some(&replacement), Some(&global), false, false)
                .unwrap();
        assert_eq!(
            route,
            AdmittedRoute {
                pre: Some(replacement.clone()),
                post: Some(global.clone())
            }
        );
        for (dns, upstream) in [(true, false), (false, true)] {
            assert!(
                resolve_account_route(None, None, Some(&replacement), None, dns, upstream).is_err()
            );
            assert!(
                resolve_account_route(None, None, None, Some(&replacement), dns, upstream).is_err()
            );
            assert!(resolve_account_route(
                None,
                None,
                Some(&disabled),
                Some(&disabled),
                dns,
                upstream
            )
            .is_ok());
        }
        assert!(
            resolve_account_route(Some(&global), None, Some(&disabled), None, false, true).is_err()
        );
        assert!(
            resolve_account_route(Some(&global), None, Some(&disabled), None, true, false).is_ok()
        );
    }

    #[test]
    fn route_snapshot_preserves_replaced_credentials() {
        let global = EndpointOverride::Endpoint("127.0.0.1:1080|alice:secret".parse().unwrap());
        for account in [
            EndpointOverride::Endpoint("127.0.0.1:1081|alice:secret".parse().unwrap()),
            EndpointOverride::Endpoint("127.0.0.1:1080|bob:secret".parse().unwrap()),
            EndpointOverride::Endpoint("127.0.0.1:1080|alice:other".parse().unwrap()),
            endpoint(),
        ] {
            let route = resolve_account_route(
                Some(&global),
                Some(&global),
                Some(&account),
                Some(&account),
                false,
                false,
            )
            .unwrap();
            assert_eq!(route.pre, Some(account.clone()));
            assert_eq!(route.post, Some(account));
        }
    }

    #[tokio::test]
    async fn admitted_route_uses_lease_snapshot_across_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("users.ktav");
        let global = endpoint();
        let pre = EndpointOverride::Endpoint("127.0.0.1:1082|alice:secret".parse().unwrap());
        let post = EndpointOverride::Endpoint("127.0.0.1:1081|bob:secret".parse().unwrap());
        let mut account = user(true, Some(pre.clone()), Some(post.clone()));
        account.hash = auth::compute_hash("pw").unwrap();
        let mut users = UsersConfig {
            users: vec![account],
        };
        users.save(&path).unwrap();
        let state =
            std::sync::Arc::new(auth::AuthState::build_persistent(&users, path.clone()).unwrap());
        let proof = state.verify_proof("test", "pw").unwrap();
        let lease = state.admit(&proof).await.unwrap();
        let snapshot =
            resolve_admitted_route(Some(&global), None, Some(&lease), false, false).unwrap();
        assert_eq!(
            snapshot,
            AdmittedRoute {
                pre: Some(pre),
                post: Some(post)
            }
        );
        assert!(resolve_admitted_route(Some(&global), None, Some(&lease), false, true).is_err());
        users.users[0].pre_socks5 = Some(EndpointOverride::Disabled);
        users.users[0].post_socks5 = Some(EndpointOverride::Disabled);
        users.save(&path).unwrap();
        let reload_state = state.clone();
        let reload = tokio::task::spawn_blocking(move || reload_state.reload());
        assert_eq!(
            resolve_admitted_route(Some(&global), None, Some(&lease), false, false).unwrap(),
            snapshot
        );
        drop(lease);
        reload.await.unwrap().unwrap();
        assert!(state.admit(&proof).await.is_none());
        let fresh = state.verify_proof("test", "pw").unwrap();
        let lease = state.admit(&fresh).await.unwrap();
        assert_eq!(lease.pre_socks5(), Some(&EndpointOverride::Disabled));
        assert_eq!(
            resolve_admitted_route(Some(&global), Some(&global), Some(&lease), false, false)
                .unwrap(),
            AdmittedRoute {
                pre: None,
                post: None
            }
        );
        assert!(resolve_admitted_route(Some(&global), None, Some(&lease), false, true).is_err());
    }

    #[test]
    fn post_rejects_bypassing_egress_and_dns() {
        assert!(validate_post_compatibility(true, true, false).is_err());
        assert!(validate_post_compatibility(true, false, true).is_err());
        assert!(validate_post_compatibility(true, false, false).is_ok());
        assert!(validate_post_compatibility(false, true, true).is_ok());
    }

    #[tokio::test]
    async fn post_failure_never_polls_direct_route() {
        let direct_polled = std::cell::Cell::new(false);
        let direct = async {
            direct_polled.set(true);
            Ok::<_, &str>(())
        };
        let post = async { Err::<(), _>("post failed") };
        assert_eq!(
            select_post_route(true, direct, post).await,
            Err("post failed")
        );
        assert!(!direct_polled.get());
    }

    #[tokio::test]
    async fn no_post_never_polls_post_route() {
        let post_polled = std::cell::Cell::new(false);
        let direct = async { Ok::<_, &str>(()) };
        let post = async {
            post_polled.set(true);
            Err::<(), _>("unexpected post")
        };
        assert_eq!(select_post_route(false, direct, post).await, Ok(()));
        assert!(!post_polled.get());
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
    fn account_pre_is_independent_of_global_pre() {
        let users = UsersConfig {
            users: vec![user(true, Some(endpoint()), None)],
        };
        assert!(validate_account_routes(&users, None, None, false, false).is_ok());
        assert!(validate_account_routes(
            &users,
            Some(&EndpointOverride::Disabled),
            None,
            false,
            false
        )
        .is_ok());
        assert!(validate_account_routes(&users, Some(&endpoint()), None, false, false).is_ok());
        let replacement = EndpointOverride::Endpoint("127.0.0.1:1081".parse().unwrap());
        assert!(validate_account_routes(&users, Some(&replacement), None, false, false).is_ok());
        let users = UsersConfig {
            users: vec![user(true, None, Some(endpoint()))],
        };
        assert!(validate_account_routes(&users, None, None, false, false).is_ok());
    }

    #[test]
    fn restricted_owner_template_and_alternate_validation() {
        let mut cfg = crate::config::Config::default();
        cfg.bridges.use_seeds = false;
        cfg.bridges.auto_fetch = false;
        cfg.warm_pool.enabled = false;
        cfg.bridges.lines = vec!["8.8.8.8:443 1111111111111111111111111111111111111111".into()];
        let users = UsersConfig {
            users: vec![user(true, Some(endpoint()), None)],
        };
        let settings = crate::tor_setup::validate_owner_routes(&cfg, &users, None)
            .unwrap()
            .unwrap();
        assert_eq!(settings.bridges.len(), 1);
        assert!(settings.pre_endpoint.is_none());
        assert!(settings.pt_binary.is_none());
        assert!(settings.extra_pt_protocols.is_empty());
        cfg.bridges.use_seeds = true;
        assert!(crate::tor_setup::validate_owner_routes(&cfg, &users, None).is_err());
        cfg.bridges.use_seeds = false;
        cfg.bridges.auto_fetch = true;
        assert!(crate::tor_setup::restricted_owner_settings(&cfg, None).is_err());
        cfg.bridges.auto_fetch = false;
        cfg.warm_pool.enabled = true;
        assert!(crate::tor_setup::restricted_owner_settings(&cfg, None).is_err());
        cfg.warm_pool.enabled = false;
        cfg.dns_server.enabled = true;
        assert!(crate::tor_setup::restricted_owner_settings(&cfg, None).is_err());
        cfg.dns_server.enabled = false;
        cfg.upstream.enabled = true;
        assert!(crate::tor_setup::restricted_owner_settings(&cfg, None).is_ok());
        assert!(validate_account_routes(&users, None, None, false, true).is_err());
        assert!(validate_account_routes(&users, None, None, false, false).is_ok());
        cfg.upstream.enabled = false;
        cfg.bridges.lines.push(
            "obfs4 1.2.3.4:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0".into(),
        );
        assert!(crate::tor_setup::restricted_owner_settings(&cfg, None).is_err());
        cfg.bridges.lines.clear();
        assert!(crate::tor_setup::restricted_owner_settings(&cfg, None).is_err());
        cfg.pre_socks5 = Some(endpoint());
        let direct = UsersConfig {
            users: vec![user(true, Some(EndpointOverride::Disabled), None)],
        };
        assert!(crate::tor_setup::validate_owner_routes(&cfg, &direct, None)
            .unwrap()
            .is_none());
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

// Подтверждение выдаётся только после проверки учётных данных.
pub(crate) struct AuthStateVerifier(pub(crate) std::sync::Arc<auth::AuthState>);

impl socks5_proto::ProofVerifier for AuthStateVerifier {
    type Proof = auth::CredentialProof;

    fn verify_proof(&self, username: &str, password: &str) -> Option<Self::Proof> {
        self.0.verify_proof(username, password)
    }

    fn username<'a>(&self, proof: &'a Self::Proof) -> &'a str {
        proof.username()
    }
}

/// Decide whether a `.onion` connection is allowed for this request.
///
/// * No authenticator (anonymous proxy) → allowed: there is no account
///   to gate on.
/// * Authenticated → allowed iff the named account carries
///   `allowed_onion` (and is still enabled).
/// * Auth required but no account on the request (should not happen for
///   a completed handshake) → denied, fail-closed.
#[cfg(test)]
pub(crate) fn onion_permitted(auth: Option<&auth::AuthState>, authed_user: Option<&str>) -> bool {
    match (auth, authed_user) {
        (None, _) => true,
        (Some(state), Some(name)) => state.allowed_onion(name),
        (Some(_), None) => false,
    }
}

/// Coarse classification of a [`handle_client`] failure, so operators can
/// tell "the client misbehaved" from "Tor is having a bad time" from
/// "something else" without grepping the error text — see [`ConnErrorKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnErrorKind {
    /// The client side of the SOCKS5 session misbehaved or disconnected —
    /// e.g. it dropped the TCP connection mid-handshake. Not a proxy or Tor
    /// problem; normal for clients that churn through many parallel
    /// connections (Telegram and similar).
    Client,
    /// A Tor-side failure building a circuit/stream — an
    /// `arti_wrapper::TorError::Connect` anywhere in the error's cause
    /// chain. Finer-grained classification (which `tor_error::ErrorKind`)
    /// already happens in [`crate::tor_watchdog::classify_and_record`]; this
    /// variant only answers "is this Tor's problem at all".
    Tor,
    /// relay-stage I/O failure. Deliberately NOT Client:
    /// `tokio::io::copy_bidirectional` does not expose WHICH end errored, so the
    /// client-vs-Tor direction of a mid-relay reset is indeterminate; what is
    /// determinate is the stage, and a relay-stage reset must not inflate the
    /// client-misbehavior count. Per-direction byte counts exist only on
    /// success.
    Relay,
    /// Anything else: I/O errors unrelated to the SOCKS5 handshake, bugs,
    /// or failures that don't fit any bucket above.
    Other,
}

/// Which protocol stage a connection failed at. Discriminating on stage (an
/// internal, stable anyhow context tag — see the `STAGE_*` constants) rather
/// than on error text lets the same I/O condition be attributed differently:
/// a ConnectionReset during the handshake is the client's doing, while the
/// identical reset mid-relay is reported as [`ConnStage::Relay`] so it does
/// not inflate the client-misbehavior count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnStage {
    /// SOCKS5 method negotiation / auth / CONNECT request.
    Handshake,
    /// Establishing the egress (Tor circuit or upstream proxy) connection.
    Connect,
    /// Bidirectional data transfer between client and egress.
    Relay,
    /// No stage context tag found in the error chain.
    Other,
}

/// Internal, stable context tags `handle_client` attaches to each stage.
/// Classification string-matches ONLY these — never arbitrary error message
/// text (message text is not a stable classification key).
pub(crate) const STAGE_HANDSHAKE: &str = "SOCKS5 handshake";
pub(crate) const STAGE_CONNECT_TOR: &str = "tor connect";
pub(crate) const STAGE_CONNECT_UPSTREAM: &str = "upstream connect";
pub(crate) const STAGE_RELAY: &str = "relay";

/// Classify a [`handle_client`] failure into a stage and an error kind, by
/// the *type* of its root cause and the stage context tag in the chain,
/// never by string-matching arbitrary rendered error message text (only the
/// internal `STAGE_*` context tags above are matched — message text is not a
/// stable classification key).
///
/// Order of checks:
/// 1. Stage: the first chain cause matching a `STAGE_*` tag wins (relay →
///    handshake → connect → other).
/// 2. Kind: any `arti_wrapper::TorError::Connect` in the chain →
///    [`ConnErrorKind::Tor`], regardless of stage (a Tor connect failure is
///    unambiguous and takes priority over any incidental I/O wrapping).
/// 3. Otherwise by stage: handshake → Client (everything escaping the
///    handshake phase is client-side, including the deadline); relay →
///    Relay when a chain cause is a client-drop-ish `io::Error`
///    (ConnectionReset/Aborted/BrokenPipe/UnexpectedEof), else Other;
///    connect → Other (a non-Tor connect failure is not attributable to the
///    SOCKS client — the `connect_failed` counter carries the stage signal);
///    other stage → Client when a chain cause is a drop-ish `io::Error`
///    (after the stage tags the only untagged I/O escape path is the SOCKS
///    reply writes, which are client-side), else Other.
pub(crate) fn classify_conn_failure(err: &anyhow::Error) -> (ConnStage, ConnErrorKind) {
    let stage = if err.chain().any(|cause| cause.to_string() == STAGE_RELAY) {
        ConnStage::Relay
    } else if err
        .chain()
        .any(|cause| cause.to_string() == STAGE_HANDSHAKE)
    {
        ConnStage::Handshake
    } else if err.chain().any(|cause| {
        cause.to_string() == STAGE_CONNECT_TOR || cause.to_string() == STAGE_CONNECT_UPSTREAM
    }) {
        ConnStage::Connect
    } else {
        ConnStage::Other
    };

    let is_dropish_io = err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io_err| {
                matches!(
                    io_err.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::UnexpectedEof
                )
            })
    });

    for cause in err.chain() {
        if let Some(tor_err) = cause.downcast_ref::<arti_wrapper::TorError>() {
            if matches!(tor_err, arti_wrapper::TorError::Connect { .. }) {
                return (stage, ConnErrorKind::Tor);
            }
        }
    }

    let kind = match stage {
        ConnStage::Handshake => ConnErrorKind::Client,
        ConnStage::Relay => {
            if is_dropish_io {
                ConnErrorKind::Relay
            } else {
                ConnErrorKind::Other
            }
        }
        ConnStage::Connect => ConnErrorKind::Other,
        ConnStage::Other => {
            if is_dropish_io {
                ConnErrorKind::Client
            } else {
                ConnErrorKind::Other
            }
        }
    };
    (stage, kind)
}
