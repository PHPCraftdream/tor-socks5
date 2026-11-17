//! Each feature exposes its module through the facade. A feature that forgets
//! an implied one, or a module that points at the wrong crate, stops this
//! file from compiling under that feature set.
//!
//! Signatures are pinned with function-pointer annotations and full
//! `type_name` path equality, so a change in an exposed signature or a
//! re-export that starts wrapping (instead of forwarding) a type fails the
//! surface test. Everything here is compile-time: no network, no Tor client.

use std::any::type_name;

#[path = "support/runtime_use_tree_oracle.rs"]
mod runtime_use_tree_oracle;

#[test]
fn persist_is_always_on() {
    assert_eq!(
        type_name::<tor_socks5::persist::PathLock>(),
        "persist_lock::path_lock::PathLock"
    );
}

#[cfg(feature = "socks5")]
#[test]
fn proto_module() {
    assert_eq!(
        type_name::<dyn tor_socks5::proto::PasswordVerifier>(),
        "dyn socks5_proto::PasswordVerifier"
    );
}

#[cfg(feature = "acl")]
#[test]
fn acl_module() {
    assert_eq!(
        type_name::<tor_socks5::acl::ProxyPool>(),
        "client_acl::pool::ProxyPool"
    );
}

#[cfg(feature = "route")]
#[test]
fn route_module() {
    assert_eq!(
        type_name::<tor_socks5::route::ScopeMap>(),
        "route_pool::scope::ScopeMap"
    );
}

#[cfg(feature = "auth")]
#[test]
fn auth_module() {
    assert_eq!(
        type_name::<tor_socks5::auth::AuthState>(),
        "auth::state::AuthState"
    );
    assert_eq!(
        type_name::<tor_socks5::auth::Registry>(),
        "auth::registry::ops::Registry"
    );
}

#[cfg(feature = "config")]
#[test]
fn config_module() {
    use std::path::Path;

    use tor_socks5::config::MigrationOutcome;

    assert_eq!(
        type_name::<tor_socks5::config::Config>(),
        "proxy_config::Config"
    );
    // `config migrate` is the library function; the CLI only prints.
    fn expect_migrate<E>(_f: fn(&Path) -> Result<MigrationOutcome, E>) {}
    expect_migrate(tor_socks5::config::migrate_config);
}

#[cfg(feature = "bridges")]
#[test]
fn bridge_modules() {
    use std::path::Path;

    assert_eq!(
        type_name::<tor_socks5::probe::ResolverPolicy>(),
        "bridge_probe::dns::ResolverPolicy"
    );
    assert_eq!(
        type_name::<tor_socks5::store::BridgeStore>(),
        "bridge_store::BridgeStore"
    );
    let _: fn(&Path, &Path) -> std::path::PathBuf =
        tor_socks5::verify::pt_reap::pt_state_location_token;
}

#[cfg(feature = "tor")]
#[test]
fn tor_module() {
    assert_eq!(
        type_name::<tor_socks5::tor::TorTunnel>(),
        "arti_wrapper::TorTunnel"
    );
    assert_eq!(
        type_name::<tor_socks5::tor::Settings>(),
        "arti_wrapper::Settings"
    );
}

/// The circuit knobs reach the SDK user as plain fields, with the stock
/// defaults: one guard, three-hop onion circuits.
#[cfg(feature = "tor")]
#[test]
fn tor_settings_carry_the_circuit_knobs() {
    let settings = tor_socks5::tor::Settings::default();
    assert_eq!(settings.guard_spread, 1);
    assert_eq!(settings.circuit_hops, 3);
}

/// The config file side of the same knobs.
#[cfg(feature = "config")]
#[test]
fn config_carries_the_circuit_knobs() {
    let cfg = tor_socks5::config::Config::default();
    assert_eq!(cfg.tor.guard_spread, 1);
    assert_eq!(cfg.tor.circuit_hops, 3);
}

#[cfg(feature = "fetch")]
#[test]
fn fetch_module() {
    assert_eq!(
        type_name::<tor_socks5::fetch::FetchOutcome>(),
        "bridge_fetcher::fetch::FetchOutcome"
    );
}

#[cfg(feature = "dns")]
#[test]
fn dns_module() {
    assert_eq!(
        type_name::<tor_socks5::dns::DohProvider>(),
        "dns_server::types::DohProvider"
    );
}

#[cfg(feature = "onion")]
#[test]
fn onion_module() {
    use tor_socks5::onion::vanity::{SearchOptions, SearchOutcome, VanityError, VanityTarget};

    assert_eq!(
        type_name::<tor_socks5::onion::address::Keypair>(),
        "tor_socks5_onion::address::Keypair"
    );
    let _: fn(&str) -> Result<[u8; 32], tor_socks5::onion::address::ParseError> =
        tor_socks5::onion::address::parse_onion_address;
    let _: fn(&VanityTarget, &SearchOptions) -> Result<SearchOutcome, VanityError> =
        tor_socks5::onion::vanity::search;
}

/// The keys are available without the `onion` feature too: `onion-keys`
/// alone links the keystore part of the crate, no Tor client.
#[cfg(feature = "onion-keys")]
#[test]
fn onion_keys_module() {
    use std::path::Path;

    use tor_socks5::onion::keys::{self, KeysError, NewIdentity, PreparedService, Recorded};

    assert_eq!(
        type_name::<KeysError>(),
        "tor_socks5_onion::keys::store::KeysError"
    );
    assert_eq!(
        type_name::<NewIdentity>(),
        "tor_socks5_onion::keys::ops::NewIdentity<'_>"
    );

    // list/show keep their entry types internal to the caller (the entry type
    // comes from the config crate, which `onion-keys` does not expose), so
    // they are pinned by argument shape and `Ok`/`Vec` shape.
    fn expect_list<R, E>(_f: fn(&Path) -> Result<Vec<R>, E>) {}
    expect_list(keys::list_services);
    fn expect_show<R, E>(_f: fn(&Path, &str) -> Result<R, E>) {}
    expect_show(keys::show_service);
    let _: fn(&Path, &str, &Path, bool) -> Result<(), KeysError> = keys::export_identity;
    // `type_complexity` is inherent to the exact signature being pinned.
    #[allow(clippy::type_complexity)]
    fn expect_import<P>(
        _f: for<'a> fn(
            &'a Path,
            &'a Path,
            &'a str,
            &'a Path,
            P,
            bool,
        ) -> Result<Recorded, KeysError>,
    ) {
    }
    expect_import(keys::import_identity);
    let _: fn(&Path, &Path, &str) -> Result<(), KeysError> = keys::remove_service;
    #[allow(clippy::type_complexity)]
    fn expect_create<P>(
        _f: for<'a> fn(
            &'a Path,
            &'a Path,
            &'a str,
            P,
            bool,
            NewIdentity<'a>,
        ) -> Result<Recorded, KeysError>,
    ) {
    }
    expect_create(keys::create_service);
    fn expect_prepare<S>(
        _f: for<'a> fn(Option<&'a Path>, &'a Path, &'a [S]) -> Vec<PreparedService>,
    ) {
    }
    expect_prepare(keys::prepare_all);
}

/// One type is the same through every path that reaches it: the facade
/// re-exports the crates, it does not wrap them.
#[cfg(all(feature = "config", feature = "auth"))]
#[test]
fn shared_types_are_not_duplicated() {
    fn same<T>(_: &T, _: &T) {}
    let from_acl: Option<tor_socks5::acl::PoolOverride> = None;
    let from_auth: Option<tor_socks5::acl::PoolOverride> = tor_socks5::auth::User {
        name: String::new(),
        hash: String::new(),
        is_enabled: false,
        allowed_onion: false,
        allowed_clients: None,
        pre_proxies: None,
        post_proxies: None,
    }
    .post_proxies;
    same(&from_acl, &from_auth);
}

#[cfg(feature = "runtime")]
#[test]
fn runtime_module_tor_client_surface() {
    use std::future::Future;
    use std::path::{Path, PathBuf};

    use tor_socks5::config::Config;
    use tor_socks5::runtime::{
        ConnErrorKind, ConnHealthConfig, ConnHealthCounters, ConnHealthSnapshot, ConnStage,
        HealOutcome, PendingConnectionGuard, PtBinary, TorHandle, TorHealth, WatchdogConfig,
        WatchdogRun, WatchdogStatus,
    };

    assert_eq!(
        type_name::<TorHandle>(),
        "tor_socks5_runtime::tor_watchdog::health::TorHandle"
    );
    assert_eq!(
        type_name::<TorHealth>(),
        "tor_socks5_runtime::tor_watchdog::health::TorHealth"
    );
    assert_eq!(
        type_name::<WatchdogRun>(),
        "tor_socks5_runtime::tor_watchdog::status::WatchdogRun"
    );
    assert_eq!(
        type_name::<WatchdogStatus>(),
        "tor_socks5_runtime::tor_watchdog::status::WatchdogStatus"
    );
    assert_eq!(
        type_name::<HealOutcome>(),
        "tor_socks5_runtime::tor_watchdog::status::HealOutcome"
    );
    assert_eq!(
        type_name::<ConnHealthSnapshot>(),
        "tor_socks5_runtime::conn_health::ConnHealthSnapshot"
    );
    assert_eq!(
        type_name::<ConnHealthCounters>(),
        "tor_socks5_runtime::conn_health::ConnHealthCounters"
    );
    assert_eq!(
        type_name::<ConnStage>(),
        "tor_socks5_runtime::conn_health::ConnStage"
    );
    assert_eq!(
        type_name::<ConnErrorKind>(),
        "tor_socks5_runtime::conn_health::ConnErrorKind"
    );
    assert_eq!(
        type_name::<PendingConnectionGuard>(),
        "tor_socks5_runtime::conn_health::PendingConnectionGuard"
    );
    assert_eq!(type_name::<PtBinary>(), "tor_socks5_runtime::pt::PtBinary");

    let counters = ConnHealthCounters::default();
    let _: PendingConnectionGuard = counters.record_started();

    let _: fn(Option<&Path>) -> PathBuf = tor_socks5::runtime::arti_base_dir;
    let _: fn(Option<&Path>) -> PathBuf = tor_socks5::runtime::arti_keystore_dir;
    let _: fn(&tor_socks5::runtime::TorError, &TorHealth) =
        tor_socks5::runtime::classify_and_record;
    let _: fn(ConnHealthCounters, ConnHealthConfig) -> Option<tokio::task::JoinHandle<()>> =
        tor_socks5::runtime::spawn_conn_health_logger;
    let _: fn(Option<&Path>) -> tor_socks5::runtime::StoreWriter = tor_socks5::runtime::init_global;
    fn expect_close_global<F: Future>(_f: fn() -> F) {}
    expect_close_global(tor_socks5::runtime::close_global);
    // The error side of these futures is `anyhow::Error`, which the facade
    // does not re-export; the `Ok` payload is pinned instead.
    fn expect_tor_settings<'a>(
        cfg: &'a Config,
        config_path: Option<&'a Path>,
    ) -> impl Future + use<'a> {
        tor_socks5::runtime::build_tor_settings(cfg, config_path)
    }
    fn expect_tor_settings_with_pt<'a>(
        cfg: &'a Config,
        config_path: Option<&'a Path>,
        pt: PtBinary,
    ) -> impl Future + use<'a> {
        tor_socks5::runtime::build_tor_settings_with_pt(cfg, config_path, pt)
    }
    let _ = (expect_tor_settings, expect_tor_settings_with_pt);
    fn expect_tor_watchdog<H, C>(
        _f: fn(H, Option<PathBuf>, WatchdogConfig, C) -> Option<WatchdogRun>,
    ) {
    }
    expect_tor_watchdog(tor_socks5::runtime::spawn_tor_watchdog);
    fn expect_failover_watchdog<H, C>(
        _f: fn(H, Option<PathBuf>, WatchdogConfig, C) -> Option<tokio::task::JoinHandle<()>>,
    ) {
    }
    expect_failover_watchdog(tor_socks5::runtime::spawn_bridge_failover_watchdog);

    // These annotations pin the public handle-method signatures without
    // requiring a live Arti client to construct a TorHandle.
    fn assert_handle_methods(handle: &TorHandle) {
        let _: &TorHealth = handle.health();
        let _: fn(&TorHandle) -> &TorHealth = TorHandle::health;
        let _: bool = handle.route_is_settling();
        let _: fn(&TorHandle) -> bool = TorHandle::route_is_settling;
        let _: fn(&TorHandle) -> Vec<_> = TorHandle::active_bridges;
        let _: fn(&TorHandle, Vec<_>) = TorHandle::set_active_bridges;
        let _: fn(&TorHandle) -> &tor_socks5::runtime::BridgeRefresh = TorHandle::bridge_refresh;

        fn expect_tunnel_future<F>(_: F)
        where
            F: Future<Output = Option<tor_socks5::tor::TorTunnel>> + Send,
        {
        }
        expect_tunnel_future(handle.tunnel());
        expect_tunnel_future(handle.clone().drain());
        let _: fn(tor_socks5::tor::TorTunnel, &tor_socks5::tor::Settings) -> TorHandle =
            TorHandle::new_with_settings;
    }
    let _ = assert_handle_methods;

    // Config types are the actual arguments accepted by the exposed spawners.
    fn assert_config_types(_: WatchdogConfig, _: ConnHealthConfig) {}
    fn assert_config_types_pointer(_f: fn(WatchdogConfig, ConnHealthConfig)) {}
    assert_config_types_pointer(assert_config_types);
}

#[cfg(feature = "runtime")]
#[test]
fn runtime_facade_source_has_no_nested_module_reexports_or_globs() {
    let result = runtime_use_tree_oracle::check_facade(
        include_str!("../src/lib.rs"),
        include_str!("../crates/runtime/src/lib.rs"),
    );
    assert!(result.is_ok(), "{}", result.unwrap_err());
}

/// The SDK-8 runtime surface: the bridge manager (one handle owning the
/// background bridge producers) and the `bridges fetch` core.
#[cfg(feature = "runtime")]
#[test]
fn runtime_bridge_manager_surface() {
    use std::future::Future;
    use std::path::Path;

    use tor_socks5::config::Config;
    use tor_socks5::runtime::{
        fetch_bridges, BridgeManagerConfig, BridgeManagerHandle, BridgeManagerStatus,
        FetchBridgesError, FetchBridgesOutcome, FetchBridgesParams, ObservationSink, PtBinary,
        TorHandle,
    };

    assert_eq!(
        type_name::<BridgeManagerHandle>(),
        "tor_socks5_runtime::bridge_manager::BridgeManagerHandle"
    );
    assert_eq!(
        type_name::<BridgeManagerStatus>(),
        "tor_socks5_runtime::bridge_manager::BridgeManagerStatus"
    );
    assert_eq!(
        type_name::<FetchBridgesError>(),
        "tor_socks5_runtime::bridge_manager::FetchBridgesError"
    );
    assert_eq!(
        type_name::<FetchBridgesParams>(),
        "tor_socks5_runtime::bridge_manager::FetchBridgesParams"
    );
    assert_eq!(
        type_name::<FetchBridgesOutcome>(),
        "tor_socks5_runtime::bridge_manager::FetchBridgesOutcome"
    );
    fn expect_fetch<'a>(
        cfg: &'a Config,
        config_path: Option<&'a Path>,
        params: FetchBridgesParams,
    ) -> impl Future + use<'a> {
        fetch_bridges(cfg, config_path, params)
    }
    let _ = expect_fetch;
    assert_eq!(
        type_name::<BridgeManagerConfig>(),
        "tor_socks5_runtime::bridge_manager::BridgeManagerConfig"
    );
    fn assert_start_signature(
        handle: TorHandle,
        cfg: &Config,
        observations: ObservationSink,
    ) -> BridgeManagerHandle {
        let config = BridgeManagerConfig {
            settings: tor_socks5::tor::Settings::default(),
            pt_binary: PtBinary::Environment,
        };
        tor_socks5::runtime::start(handle, None, cfg, observations, config)
    }
    fn assert_parent_token_start_signature(
        manager: &BridgeManagerHandle,
        handle: TorHandle,
        cfg: &Config,
        observations: ObservationSink,
        config: BridgeManagerConfig,
    ) -> BridgeManagerHandle {
        tor_socks5::runtime::start_with_parent_token(
            handle,
            None,
            cfg,
            observations,
            config,
            manager.token(),
        )
    }
    fn assert_start_signatures(
        _f: fn(TorHandle, &Config, ObservationSink) -> BridgeManagerHandle,
        g: fn(
            &BridgeManagerHandle,
            TorHandle,
            &Config,
            ObservationSink,
            BridgeManagerConfig,
        ) -> BridgeManagerHandle,
    ) {
        let _ = (_f, g);
    }
    assert_start_signatures(assert_start_signature, assert_parent_token_start_signature);
    fn assert_clone_send_sync<T: Clone + Send + Sync + 'static>(_: &T) {}
    fn expect_shutdown(handle: BridgeManagerHandle) -> impl Future<Output = ()> {
        handle.shutdown()
    }
    fn assert_bridge_manager_methods(handle: &BridgeManagerHandle) {
        let _: BridgeManagerStatus = handle.status();
        let _: tokio::sync::watch::Receiver<BridgeManagerStatus> = handle.subscribe();
        let token = handle.token();
        assert_clone_send_sync(&token);
    }
    fn assert_bridge_manager_methods_pointer(_f: fn(&BridgeManagerHandle)) {}
    assert_bridge_manager_methods_pointer(assert_bridge_manager_methods);
    let _ = expect_shutdown;
}

/// The SDK-7 runtime surface: the bridge-health writer and the
/// guard-event observation layer for the application's own subscriber.
#[cfg(feature = "runtime")]
#[test]
fn runtime_bridge_health_and_observation() {
    use std::future::Future;

    use tracing_subscriber::prelude::*;

    use tor_socks5::runtime::{GuardObservation, ObservationSink, StoreWriter};
    use tor_socks5::store::BridgeStore;

    assert_eq!(
        type_name::<StoreWriter>(),
        "tor_socks5_runtime::bridge_store_writer::StoreWriter"
    );
    assert_eq!(
        type_name::<ObservationSink>(),
        "tor_socks5_runtime::arti_observability::ObservationSink"
    );
    assert_eq!(
        type_name::<GuardObservation>(),
        "tor_socks5_runtime::arti_observability::GuardObservation"
    );

    fn assert_store_writer_methods(writer: &StoreWriter) {
        fn expect_close<F>(_: F)
        where
            F: Future + Send,
        {
        }
        expect_close(writer.close());
        // `apply` takes the mutation closure, not a live store.
        // The mutation is never polled here; dropping it explicitly keeps
        // the future from being silently bound to `_`.
        std::mem::drop(writer.apply(|_: &mut BridgeStore| {}));
    }
    fn assert_store_writer_methods_pointer(_f: fn(&StoreWriter)) {}
    assert_store_writer_methods_pointer(assert_store_writer_methods);

    // The observation layer fits a real subscriber — the wiring the
    // proxy binary itself does in its startup.
    let sink = ObservationSink::new();
    let _subscriber =
        tracing_subscriber::registry().with(tor_socks5::runtime::observation_layer(&sink));
}

/// The bridge-manager producer hand-off: `transfer_tasks` gives the caller
/// ownership of the spawned tasks.
#[cfg(feature = "runtime")]
#[test]
fn runtime_bridge_manager_transfer_tasks_surface() {
    use tor_socks5::runtime::BridgeManagerHandle;

    let _: fn(BridgeManagerHandle, &mut Vec<tokio::task::JoinHandle<()>>) =
        BridgeManagerHandle::transfer_tasks;
}

/// The hosted-onion-service surface (SDK-5).
#[cfg(feature = "onion-host")]
#[test]
fn onion_host_module() {
    use tor_socks5::onion::host::{OnionHost, OnionHostConfig, OnionHostHandle};

    assert_eq!(
        type_name::<OnionHostHandle>(),
        "tor_socks5_onion::host::OnionHostHandle"
    );
    assert_eq!(
        type_name::<tor_socks5::onion::host::ServiceFailure>(),
        "tor_socks5_onion::host::status::ServiceFailure"
    );
    let _: fn(OnionHostConfig) -> OnionHost = OnionHost::new;
    let _: fn(
        &OnionHostHandle,
    ) -> tokio::sync::watch::Receiver<tor_socks5::onion::host::OnionHostStatus> =
        OnionHostHandle::subscribe;
}

/// The hosted-onion-service handle and config builders (SDK-5): the
/// `TorHandle` and `CancellationToken` argument types stay internal to the
/// onion crate here (`onion-host` alone does not expose them), so they are
/// pinned through inference.
#[cfg(feature = "onion-host")]
#[test]
fn onion_host_config_and_handle_surface() {
    use std::future::Future;
    use std::path::PathBuf;

    use tor_socks5::onion::host::{OnionHostConfig, OnionHostHandle, OnionHostStatus};

    fn expect_new<H, T>(_f: fn(H, PathBuf, T) -> OnionHostConfig) {}
    expect_new(OnionHostConfig::new);

    let _: fn(&OnionHostHandle) -> OnionHostStatus = OnionHostHandle::status;
    let _: fn(&OnionHostHandle) -> tokio::sync::watch::Receiver<OnionHostStatus> =
        OnionHostHandle::subscribe;
    let _: fn(OnionHostHandle) -> tokio::task::JoinHandle<()> = OnionHostHandle::detach;
    fn expect_shutdown<F: Future>(_f: fn(OnionHostHandle) -> F) {}
    expect_shutdown(OnionHostHandle::shutdown);
}

/// The SDK-11 embedded server surface: its builder future, shutdown result,
/// and inferred token/status channel traits compile through the facade.
#[cfg(feature = "server")]
#[test]
fn server_surface_signatures() {
    use std::future::Future;

    use tor_socks5::server::{
        DnsStartupPolicy, Server, ServerBuilder, ServerError, ServerHandle, ServerStatus,
    };

    fn expect_builder(_: ServerBuilder) {}
    fn expect_dns_policy(_: DnsStartupPolicy) {}
    fn expect_start<F>(_: F)
    where
        F: Future<Output = Result<ServerHandle, ServerError>>,
    {
    }
    fn expect_shutdown(handle: ServerHandle) -> impl Future<Output = Result<(), ServerError>> {
        handle.shutdown()
    }
    fn assert_clone_send_sync<T: Clone + Send + Sync + 'static>(_: &T) {}
    fn assert_send_sync<T: Send + Sync + 'static>(_: &T) {}

    let builder = Server::builder(tor_socks5::config::Config::default());
    expect_builder(builder);
    expect_dns_policy(DnsStartupPolicy::Required);
    let start = Server::builder(tor_socks5::config::Config::default())
        .dns_startup_policy(DnsStartupPolicy::Required)
        .upstream(Some("127.0.0.1:9050".into()), None, None)
        .start();
    expect_start(start);
    let _shutdown = expect_shutdown;

    fn assert_handle_channels(handle: &ServerHandle) {
        let token = handle.token();
        assert_clone_send_sync(&token);
        let status: tokio::sync::watch::Receiver<ServerStatus> = handle.subscribe();
        assert_send_sync(&status);
    }
    fn assert_handle_channels_pointer(_f: fn(&ServerHandle)) {}
    assert_handle_channels_pointer(assert_handle_channels);
}

/// The embedded-server builder configuration chain (SDK-11): every builder
/// setter returns the builder, the sink is the runtime's `ObservationSink`,
/// and the status subscription starts from the builder itself.
#[cfg(feature = "server")]
#[test]
fn server_builder_setters_surface() {
    use std::path::PathBuf;

    use tor_socks5::config::Config;
    use tor_socks5::runtime::ObservationSink;
    use tor_socks5::server::{Server, ServerBuilder, ServerStatus};

    let builder = Server::builder(Config::default())
        .config_path(Option::<PathBuf>::None)
        .observation_sink(ObservationSink::new())
        .no_upstream(true);
    // `CancellationToken` is not re-exported through the facade; pin the
    // setter's type by inference instead of naming the token type.
    fn expect_cancellation_token<B, T>(_f: fn(B, T) -> B) {}
    expect_cancellation_token(ServerBuilder::cancellation_token);
    let _: tokio::sync::watch::Receiver<ServerStatus> = builder.subscribe();
}

/// The embedded-server handle and error accessors (SDK-11): status snapshot,
/// subscription, the `wait` future, and the error's stage/cleanup probes.
#[cfg(feature = "server")]
#[test]
fn server_handle_and_error_surface() {
    use std::future::Future;

    use tor_socks5::server::{ServerError, ServerHandle, ServerStatus};
    let _: fn(&ServerHandle) -> ServerStatus = ServerHandle::status;
    let _: fn(&ServerHandle) -> tokio::sync::watch::Receiver<ServerStatus> =
        ServerHandle::subscribe;
    fn expect_wait<F: Future<Output = Result<(), ServerError>>>(_f: fn(ServerHandle) -> F) {}
    expect_wait(ServerHandle::wait);

    // `ServerError` is `#[non_exhaustive]`, so only the unit variant is
    // constructible here; the accessors are pinned through it.
    assert_eq!(ServerError::AlreadyRunning.stage(), None);
    assert!(ServerError::AlreadyRunning.cleanup_error().is_none());
}
