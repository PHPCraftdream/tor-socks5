use super::{global_pre_endpoint, reject_unserved_account_pre_routes};
use auth::{User, UsersConfig};
use bridge_line::BridgeLine;
use proxy_config::{BridgesConfig, Config, PoolOverride, ProxyPool, Socks5Endpoint};

fn endpoint(address: &str) -> Socks5Endpoint {
    address.parse().unwrap()
}

fn pool() -> ProxyPool {
    endpoint("127.0.0.1:9050").into()
}

fn other_pool() -> ProxyPool {
    endpoint("127.0.0.1:9051").into()
}

fn plain_bridge() -> BridgeLine {
    "192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01"
        .parse()
        .unwrap()
}

fn transport_bridge() -> BridgeLine {
    "obfs4 192.0.2.2:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=ZZZ iat-mode=0"
        .parse()
        .unwrap()
}

/// A config that asks for the global pre proxy with everything else in order.
fn pre_config() -> Config {
    Config {
        pre_proxies: Some(pool()),
        bridges: BridgesConfig {
            auto_fetch: false,
            ..Default::default()
        },
        ..Default::default()
    }
}

fn user(enabled: bool, pre: Option<PoolOverride>) -> User {
    User {
        name: "account".to_owned(),
        hash: "unused".to_owned(),
        is_enabled: enabled,
        allowed_onion: false,
        allowed_clients: None,
        pre_proxies: pre,
        post_proxies: None,
    }
}

fn users(user: User) -> UsersConfig {
    UsersConfig { users: vec![user] }
}

#[test]
fn without_a_global_pre_nothing_is_required_of_the_bridges() {
    let config = Config::default();
    assert_eq!(global_pre_endpoint(&config, &[]), Ok(None));
    assert_eq!(
        global_pre_endpoint(&config, &[transport_bridge()]),
        Ok(None)
    );
}

#[test]
fn a_single_endpoint_with_plain_bridges_is_served() {
    let served = global_pre_endpoint(&pre_config(), &[plain_bridge()]);
    assert_eq!(served, Ok(Some(endpoint("127.0.0.1:9050"))));
}

#[test]
fn a_pool_of_several_endpoints_is_refused() {
    let mut config = pre_config();
    config.pre_proxies =
        Some(ProxyPool::new(vec![endpoint("127.0.0.1:9050"), endpoint("127.0.0.1:9051")]).unwrap());
    let error = global_pre_endpoint(&config, &[plain_bridge()]).unwrap_err();
    assert!(error.contains("single endpoint"), "{error}");
}

#[test]
fn a_global_pre_without_explicit_bridges_is_refused() {
    let error = global_pre_endpoint(&pre_config(), &[]).unwrap_err();
    assert!(error.contains("at least one"), "{error}");
}

#[test]
fn a_pluggable_transport_bridge_behind_a_pre_proxy_is_refused() {
    let error =
        global_pre_endpoint(&pre_config(), &[plain_bridge(), transport_bridge()]).unwrap_err();
    assert!(error.contains("pluggable-transport"), "{error}");
}

#[test]
fn auto_fetch_is_refused_with_a_pre_proxy() {
    let mut config = pre_config();
    config.bridges.auto_fetch = true;
    let error = global_pre_endpoint(&config, &[plain_bridge()]).unwrap_err();
    assert!(error.contains("auto_fetch"), "{error}");
}

#[test]
fn an_account_may_restate_the_global_pre_route_or_leave_it() {
    let global = pool();
    for setting in [None, Some(PoolOverride::Pool(global.clone()))] {
        let accounts = users(user(true, setting));
        assert!(reject_unserved_account_pre_routes(Some(&global), &accounts).is_ok());
    }
}

#[test]
fn an_account_with_another_route_than_the_global_one_is_refused() {
    let global = pool();
    for setting in [
        Some(PoolOverride::Pool(other_pool())),
        Some(PoolOverride::Disabled),
    ] {
        let accounts = users(user(true, setting));
        assert!(
            reject_unserved_account_pre_routes(Some(&global), &accounts).is_err(),
            "a second Tor client would be needed"
        );
    }
}

#[test]
fn without_a_global_pre_only_an_account_pool_is_refused() {
    let own = users(user(true, Some(PoolOverride::Pool(pool()))));
    assert!(reject_unserved_account_pre_routes(None, &own).is_err());
    let none = users(user(true, Some(PoolOverride::Disabled)));
    assert!(reject_unserved_account_pre_routes(None, &none).is_ok());
    let mut post_only = user(true, None);
    post_only.post_proxies = Some(PoolOverride::Pool(pool()));
    assert!(reject_unserved_account_pre_routes(None, &users(post_only)).is_ok());
}

#[test]
fn disabled_accounts_are_not_checked() {
    let off = users(user(false, Some(PoolOverride::Pool(other_pool()))));
    assert!(reject_unserved_account_pre_routes(Some(&pool()), &off).is_ok());
    assert!(reject_unserved_account_pre_routes(None, &off).is_ok());
}
