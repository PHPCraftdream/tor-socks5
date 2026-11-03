use super::{
    reject_unimplemented_account_socks5_endpoints, reject_unimplemented_global_socks5_endpoints,
};
use auth::{User, UsersConfig};
use proxy_config::{Config, EndpointOverride};

fn endpoint() -> EndpointOverride {
    EndpointOverride::Endpoint("127.0.0.1:9050".parse().unwrap())
}

fn user(enabled: bool, pre: Option<EndpointOverride>) -> User {
    User {
        name: "account".to_owned(),
        hash: "unused".to_owned(),
        is_enabled: enabled,
        allowed_onion: false,
        allowed_clients: None,
        pre_socks5: pre,
        post_socks5: None,
    }
}

#[test]
fn global_endpoint_is_rejected_but_none_or_absence_is_allowed() {
    let mut config = Config::default();
    assert!(reject_unimplemented_global_socks5_endpoints(&config).is_ok());
    config.pre_socks5 = Some(EndpointOverride::Disabled);
    config.post_socks5 = Some(endpoint());
    assert!(reject_unimplemented_global_socks5_endpoints(&config).is_err());
    config.post_socks5 = None;
    assert!(reject_unimplemented_global_socks5_endpoints(&config).is_ok());
    config.pre_socks5 = Some(endpoint());
    assert!(reject_unimplemented_global_socks5_endpoints(&config).is_err());
}

#[test]
fn enabled_account_endpoint_is_rejected_but_disabled_account_is_ignored() {
    let users = UsersConfig {
        users: vec![user(true, Some(endpoint()))],
    };
    assert!(reject_unimplemented_account_socks5_endpoints(&users).is_err());
    let mut post_only = user(true, None);
    post_only.post_socks5 = Some(endpoint());
    let users = UsersConfig {
        users: vec![post_only],
    };
    assert!(reject_unimplemented_account_socks5_endpoints(&users).is_err());
    let users = UsersConfig {
        users: vec![user(false, Some(endpoint()))],
    };
    assert!(reject_unimplemented_account_socks5_endpoints(&users).is_ok());
    let users = UsersConfig {
        users: vec![user(true, Some(EndpointOverride::Disabled))],
    };
    assert!(reject_unimplemented_account_socks5_endpoints(&users).is_ok());
}
