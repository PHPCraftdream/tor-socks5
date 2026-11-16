//! Each feature exposes its module through the facade. A feature that forgets
//! an implied one, or a module that points at the wrong crate, stops this
//! file from compiling under that feature set.

use std::any::type_name;

#[path = "support/runtime_use_tree_oracle.rs"]
mod runtime_use_tree_oracle;

fn names<T: ?Sized>() -> &'static str {
    type_name::<T>()
}

#[test]
fn persist_is_always_on() {
    assert!(names::<tor_socks5::persist::PathLock>().contains("PathLock"));
}

#[cfg(feature = "socks5")]
#[test]
fn proto_module() {
    assert!(names::<dyn tor_socks5::proto::PasswordVerifier>().contains("PasswordVerifier"));
}

#[cfg(feature = "acl")]
#[test]
fn acl_module() {
    assert!(names::<tor_socks5::acl::ProxyPool>().contains("ProxyPool"));
}

#[cfg(feature = "route")]
#[test]
fn route_module() {
    assert!(names::<tor_socks5::route::ScopeMap>().contains("ScopeMap"));
}

#[cfg(feature = "auth")]
#[test]
fn auth_module() {
    assert!(names::<tor_socks5::auth::AuthState>().contains("AuthState"));
    assert!(names::<tor_socks5::auth::Registry>().contains("Registry"));
}

#[cfg(feature = "config")]
#[test]
fn config_module() {
    assert!(names::<tor_socks5::config::Config>().contains("Config"));
    // `config migrate` is the library function; the CLI only prints.
    let _ = tor_socks5::config::migrate_config;
}

#[cfg(feature = "bridges")]
#[test]
fn bridge_modules() {
    assert!(names::<tor_socks5::probe::ResolverPolicy>().contains("ResolverPolicy"));
    assert!(names::<tor_socks5::store::BridgeStore>().contains("BridgeStore"));
    let _ = tor_socks5::verify::pt_reap::pt_state_location_token;
}

#[cfg(feature = "tor")]
#[test]
fn tor_module() {
    assert!(names::<tor_socks5::tor::TorTunnel>().contains("TorTunnel"));
    assert!(names::<tor_socks5::tor::Settings>().contains("Settings"));
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
    assert!(names::<tor_socks5::fetch::FetchOutcome>().contains("FetchOutcome"));
}

#[cfg(feature = "dns")]
#[test]
fn dns_module() {
    assert!(names::<tor_socks5::dns::DohProvider>().contains("DohProvider"));
}

#[cfg(feature = "onion")]
#[test]
fn onion_module() {
    assert!(names::<tor_socks5::onion::address::Keypair>().contains("Keypair"));
    let _ = tor_socks5::onion::address::parse_onion_address;
    let _ = tor_socks5::onion::vanity::search;
}

/// The keys are available without the `onion` feature too: `onion-keys`
/// alone links the keystore part of the crate, no Tor client.
#[cfg(feature = "onion-keys")]
#[test]
fn onion_keys_module() {
    assert!(names::<tor_socks5::onion::keys::KeysError>().contains("KeysError"));
    assert!(names::<tor_socks5::onion::keys::NewIdentity>().contains("NewIdentity"));
    let _ = tor_socks5::onion::keys::create_service;
    let _ = tor_socks5::onion::keys::prepare_all;
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

    use tor_socks5::runtime::{
        ConnErrorKind, ConnHealthConfig, ConnHealthCounters, ConnHealthSnapshot, ConnStage,
        HealOutcome, PendingConnectionGuard, PtBinary, TorHandle, TorHealth, WatchdogConfig,
        WatchdogRun, WatchdogStatus,
    };

    assert!(names::<TorHandle>().contains("TorHandle"));
    assert!(names::<TorHealth>().contains("TorHealth"));
    assert!(names::<WatchdogRun>().contains("WatchdogRun"));
    assert!(names::<WatchdogStatus>().contains("WatchdogStatus"));
    assert!(names::<HealOutcome>().contains("HealOutcome"));
    assert!(names::<ConnHealthSnapshot>().contains("ConnHealthSnapshot"));
    assert!(names::<ConnHealthCounters>().contains("ConnHealthCounters"));
    assert!(names::<ConnStage>().contains("ConnStage"));
    assert!(names::<ConnErrorKind>().contains("ConnErrorKind"));
    assert!(names::<PendingConnectionGuard>().contains("PendingConnectionGuard"));
    assert!(names::<PtBinary>().contains("PtBinary"));

    let counters = ConnHealthCounters::default();
    let _: PendingConnectionGuard = counters.record_started();

    let _ = tor_socks5::runtime::arti_base_dir;
    let _ = tor_socks5::runtime::arti_keystore_dir;
    let _ = tor_socks5::runtime::build_tor_settings;
    let _ = tor_socks5::runtime::build_tor_settings_with_pt;
    let _ = tor_socks5::runtime::spawn_tor_watchdog;
    let _ = tor_socks5::runtime::spawn_bridge_failover_watchdog;
    let _ = tor_socks5::runtime::classify_and_record;
    let _ = tor_socks5::runtime::spawn_conn_health_logger;

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
    let _ = assert_config_types;
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

    assert!(names::<tor_socks5::runtime::BridgeManagerHandle>().contains("BridgeManagerHandle"));
    assert!(names::<tor_socks5::runtime::BridgeManagerStatus>().contains("BridgeManagerStatus"));
    assert!(names::<tor_socks5::runtime::FetchBridgesParams>().contains("FetchBridgesParams"));
    assert!(names::<tor_socks5::runtime::FetchBridgesOutcome>().contains("FetchBridgesOutcome"));
    let _ = tor_socks5::runtime::fetch_bridges;
    assert!(names::<tor_socks5::runtime::BridgeManagerConfig>().contains("BridgeManagerConfig"));
    fn assert_start_signature(
        handle: tor_socks5::runtime::TorHandle,
        cfg: &tor_socks5::config::Config,
        observations: tor_socks5::runtime::ObservationSink,
    ) -> tor_socks5::runtime::BridgeManagerHandle {
        let config = tor_socks5::runtime::BridgeManagerConfig {
            settings: tor_socks5::tor::Settings::default(),
            pt_binary: tor_socks5::runtime::PtBinary::Environment,
        };
        tor_socks5::runtime::start(handle, None, cfg, observations, config)
    }
    fn assert_parent_token_start_signature(
        manager: &tor_socks5::runtime::BridgeManagerHandle,
        handle: tor_socks5::runtime::TorHandle,
        cfg: &tor_socks5::config::Config,
        observations: tor_socks5::runtime::ObservationSink,
        config: tor_socks5::runtime::BridgeManagerConfig,
    ) -> tor_socks5::runtime::BridgeManagerHandle {
        tor_socks5::runtime::start_with_parent_token(
            handle,
            None,
            cfg,
            observations,
            config,
            manager.token(),
        )
    }
    let _ = (assert_start_signature, assert_parent_token_start_signature);
    fn assert_clone_send_sync<T: Clone + Send + Sync + 'static>(_: &T) {}
    fn expect_shutdown(
        handle: tor_socks5::runtime::BridgeManagerHandle,
    ) -> impl Future<Output = ()> {
        handle.shutdown()
    }
    fn assert_bridge_manager_methods(handle: &tor_socks5::runtime::BridgeManagerHandle) {
        let _: tor_socks5::runtime::BridgeManagerStatus = handle.status();
        let _: tokio::sync::watch::Receiver<tor_socks5::runtime::BridgeManagerStatus> =
            handle.subscribe();
        let token = handle.token();
        assert_clone_send_sync(&token);
    }
    let _ = (assert_bridge_manager_methods, expect_shutdown);
}

/// The SDK-7 runtime surface: the bridge-health writer and the
/// guard-event observation layer for the application's own subscriber.
#[cfg(feature = "runtime")]
#[test]
fn runtime_bridge_health_and_observation() {
    use std::future::Future;
    use tracing_subscriber::prelude::*;

    assert!(names::<tor_socks5::runtime::StoreWriter>().contains("StoreWriter"));
    assert!(names::<tor_socks5::runtime::ObservationSink>().contains("ObservationSink"));
    assert!(names::<tor_socks5::runtime::GuardObservation>().contains("GuardObservation"));
    let _ = tor_socks5::runtime::init_global;
    let _ = tor_socks5::runtime::close_global;

    fn assert_store_writer_close(writer: &tor_socks5::runtime::StoreWriter) {
        fn expect_close<F>(_: F)
        where
            F: Future + Send,
        {
        }
        expect_close(writer.close());
    }
    let _ = assert_store_writer_close;

    // The observation layer fits a real subscriber — the wiring the
    // proxy binary itself does in its startup.
    let sink = tor_socks5::runtime::ObservationSink::new();
    let _subscriber =
        tracing_subscriber::registry().with(tor_socks5::runtime::observation_layer(&sink));
}

/// The hosted-onion-service surface (SDK-5).
#[cfg(feature = "onion-host")]
#[test]
fn onion_host_module() {
    assert!(names::<tor_socks5::onion::host::OnionHostHandle>().contains("OnionHostHandle"));
    assert!(names::<tor_socks5::onion::host::ServiceFailure>().contains("ServiceFailure"));
    let _ = tor_socks5::onion::host::OnionHost::new;
    let _ = tor_socks5::onion::host::OnionHostHandle::subscribe;
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
    let _channels = assert_handle_channels;
}
