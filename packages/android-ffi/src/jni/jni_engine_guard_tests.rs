use super::{
    reject_unimplemented_account_socks5_endpoints, reject_unimplemented_global_socks5_endpoints,
};
use auth::{User, UsersConfig};
use proxy_config::{Config, PoolOverride, ProxyPool, Socks5Endpoint};

fn pool() -> ProxyPool {
    "127.0.0.1:9050".parse::<Socks5Endpoint>().unwrap().into()
}

fn endpoint() -> PoolOverride {
    PoolOverride::Pool(pool())
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

#[test]
fn global_pre_is_rejected_but_post_and_absence_are_allowed() {
    let mut config = Config::default();
    assert!(reject_unimplemented_global_socks5_endpoints(&config).is_ok());
    config.post_proxies = Some(pool());
    assert!(reject_unimplemented_global_socks5_endpoints(&config).is_ok());
    config.post_proxies = None;
    assert!(reject_unimplemented_global_socks5_endpoints(&config).is_ok());
    config.pre_proxies = Some(pool());
    assert!(reject_unimplemented_global_socks5_endpoints(&config).is_err());
}

#[test]
fn enabled_account_pre_is_rejected_but_post_and_disabled_accounts_are_allowed() {
    let users = UsersConfig {
        users: vec![user(true, Some(endpoint()))],
    };
    assert!(reject_unimplemented_account_socks5_endpoints(&users).is_err());
    let mut post_only = user(true, None);
    post_only.post_proxies = Some(endpoint());
    let users = UsersConfig {
        users: vec![post_only],
    };
    assert!(reject_unimplemented_account_socks5_endpoints(&users).is_ok());
    let users = UsersConfig {
        users: vec![user(false, Some(endpoint()))],
    };
    assert!(reject_unimplemented_account_socks5_endpoints(&users).is_ok());
    let users = UsersConfig {
        users: vec![user(true, Some(PoolOverride::Disabled))],
    };
    assert!(reject_unimplemented_account_socks5_endpoints(&users).is_ok());
}
