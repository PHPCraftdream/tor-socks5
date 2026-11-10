use super::{
    reject_unsupported_pool, resolve_account_route, resolve_admitted_route, select_post_route,
    validate_account_routes, validate_post_compatibility, AdmittedRoute,
};
use auth::{User, UsersConfig};
use proxy_config::{PoolOverride, ProxyPool, Socks5Endpoint};

fn pool(value: &str) -> ProxyPool {
    value.parse::<Socks5Endpoint>().unwrap().into()
}

fn pool_of(values: &[&str]) -> ProxyPool {
    ProxyPool::new(values.iter().map(|value| value.parse().unwrap()).collect()).unwrap()
}

fn global_pool() -> ProxyPool {
    pool("127.0.0.1:1080")
}

fn endpoint() -> PoolOverride {
    PoolOverride::Pool(global_pool())
}

fn user(
    is_enabled: bool,
    pre_proxies: Option<PoolOverride>,
    post_proxies: Option<PoolOverride>,
) -> User {
    User {
        name: "test".to_string(),
        hash: "unused".to_string(),
        is_enabled,
        allowed_onion: false,
        allowed_clients: None,
        pre_proxies,
        post_proxies,
    }
}

#[test]
fn account_validation_does_not_replace_global_startup_guard() {
    let global = global_pool();
    let mut init = user(true, None, Some(PoolOverride::Disabled));
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
    let global = global_pool();
    let replacement_pool = pool("127.0.0.1:1081|alice:secret");
    let replacement = PoolOverride::Pool(replacement_pool.clone());
    let disabled = PoolOverride::Disabled;
    let cases = [
        (None, Some(global.clone())),
        (Some(&disabled), None),
        (Some(&replacement), Some(replacement_pool.clone())),
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
    let route = resolve_account_route(
        None,
        None,
        Some(&replacement),
        Some(&replacement),
        false,
        false,
    )
    .unwrap();
    assert_eq!(
        route,
        AdmittedRoute {
            pre: Some(replacement_pool.clone()),
            post: Some(replacement_pool)
        }
    );
    for (dns, upstream) in [(true, false), (false, true)] {
        assert!(
            resolve_account_route(None, None, Some(&replacement), None, dns, upstream).is_err()
        );
        assert!(
            resolve_account_route(None, None, None, Some(&replacement), dns, upstream).is_err()
        );
        assert!(
            resolve_account_route(None, None, Some(&disabled), Some(&disabled), dns, upstream)
                .is_ok()
        );
    }
    assert!(
        resolve_account_route(Some(&global), None, Some(&disabled), None, false, true).is_err()
    );
    assert!(resolve_account_route(Some(&global), None, Some(&disabled), None, true, false).is_ok());
}

#[test]
fn route_snapshot_preserves_replaced_credentials() {
    let global = pool("127.0.0.1:1080|alice:secret");
    for value in [
        "127.0.0.1:1081|alice:secret",
        "127.0.0.1:1080|bob:secret",
        "127.0.0.1:1080|alice:other",
        "127.0.0.1:1080",
    ] {
        let account = PoolOverride::Pool(pool(value));
        let route = resolve_account_route(
            Some(&global),
            Some(&global),
            Some(&account),
            Some(&account),
            false,
            false,
        )
        .unwrap();
        assert_eq!(route.pre, Some(pool(value)));
        assert_eq!(route.post, Some(pool(value)));
    }
}

#[test]
fn post_pools_may_hold_several_members_but_pre_pools_not_yet() {
    let several = pool_of(&["127.0.0.1:1081", "http://127.0.0.1:1082"]);
    let route = resolve_account_route(None, Some(&several), None, None, false, false).unwrap();
    assert_eq!(route.post, Some(several.clone()));
    assert!(resolve_account_route(Some(&several), None, None, None, false, false).is_err());
    let account = PoolOverride::Pool(several);
    assert!(resolve_account_route(None, None, Some(&account), None, false, false).is_err());
    assert!(resolve_account_route(None, None, None, Some(&account), false, false).is_ok());
}

#[tokio::test]
async fn admitted_route_uses_lease_snapshot_across_reload() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("users.ktav");
    let global = global_pool();
    let pre = pool("127.0.0.1:1082|alice:secret");
    let post = pool("127.0.0.1:1081|bob:secret");
    let mut account = user(
        true,
        Some(PoolOverride::Pool(pre.clone())),
        Some(PoolOverride::Pool(post.clone())),
    );
    account.hash = auth::compute_hash("pw").unwrap();
    let mut users = UsersConfig {
        users: vec![account],
    };
    users.save(&path).unwrap();
    let state =
        std::sync::Arc::new(auth::AuthState::build_persistent(&users, path.clone()).unwrap());
    let proof = state.verify_proof("test", "pw").unwrap();
    let lease = state.admit(&proof).await.unwrap();
    let snapshot = resolve_admitted_route(Some(&global), None, Some(&lease), false, false).unwrap();
    assert_eq!(
        snapshot,
        AdmittedRoute {
            pre: Some(pre),
            post: Some(post)
        }
    );
    assert!(resolve_admitted_route(Some(&global), None, Some(&lease), false, true).is_err());
    users.users[0].pre_proxies = Some(PoolOverride::Disabled);
    users.users[0].post_proxies = Some(PoolOverride::Disabled);
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
    assert_eq!(lease.pre_proxies(), Some(&PoolOverride::Disabled));
    assert_eq!(
        resolve_admitted_route(Some(&global), Some(&global), Some(&lease), false, false).unwrap(),
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
fn rejects_global_pre_and_post_pools() {
    for scope in ["global pre_proxies", "global post_proxies"] {
        let error = reject_unsupported_pool(&Some(global_pool()), scope).unwrap_err();
        assert!(error.to_string().contains(scope));
        assert!(error.to_string().contains("not supported here"));
    }
}

#[test]
fn account_pre_is_independent_of_global_pre() {
    let users = UsersConfig {
        users: vec![user(true, Some(endpoint()), None)],
    };
    assert!(validate_account_routes(&users, None, None, false, false).is_ok());
    assert!(validate_account_routes(&users, Some(&global_pool()), None, false, false).is_ok());
    let replacement = pool("127.0.0.1:1081");
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
        "unknownpt 1.2.3.4:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0".into(),
    );
    assert!(crate::tor_setup::restricted_owner_settings(&cfg, None).is_err());
    cfg.bridges.lines.clear();
    assert!(crate::tor_setup::restricted_owner_settings(&cfg, None).is_err());
    cfg.pre_proxies = Some(global_pool());
    let direct = UsersConfig {
        users: vec![user(true, Some(PoolOverride::Disabled), None)],
    };
    assert!(crate::tor_setup::validate_owner_routes(&cfg, &direct, None)
        .unwrap()
        .is_none());
}

#[test]
fn account_pre_stock_pt_template_uses_current_executable() {
    let mut cfg = crate::config::Config::default();
    cfg.bridges.use_seeds = false;
    cfg.bridges.auto_fetch = false;
    cfg.warm_pool.enabled = false;
    cfg.bridges.lines = vec![
        "1.1.1.1:443 1111111111111111111111111111111111111111".into(),
        "obfs4 8.8.4.4:443 2222222222222222222222222222222222222222 cert=AAA iat-mode=0".into(),
        "webtunnel 8.8.8.8:443 3333333333333333333333333333333333333333 url=https://example.com/x ver=0.0.3".into(),
    ];
    let users = UsersConfig {
        users: vec![user(true, Some(endpoint()), None)],
    };
    let settings = crate::tor_setup::validate_owner_routes(&cfg, &users, None)
        .unwrap()
        .unwrap();
    assert!(settings.pre_endpoint.is_none());
    assert!(settings.stock_pt_proxy);
    assert_eq!(settings.pt_binary, Some(std::env::current_exe().unwrap()));
    assert_eq!(settings.bridges, cfg.bridges.parsed().unwrap().bridges);
    settings.validate_stock_pt_proxy().unwrap();
}

#[test]
fn absent_settings_are_allowed() {
    assert!(reject_unsupported_pool(&None, "endpoint").is_ok());
}
