//! Each feature exposes its module through the facade. A feature that forgets
//! an implied one, or a module that points at the wrong crate, stops this
//! file from compiling under that feature set.

use std::any::type_name;

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
}

#[cfg(feature = "config")]
#[test]
fn config_module() {
    assert!(names::<tor_socks5::config::Config>().contains("Config"));
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
