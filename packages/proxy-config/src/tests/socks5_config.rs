use super::*;

const POOLS: &str = "listen: 127.0.0.1:1080\n\
pre_proxies: [\n    192.0.2.4:1080|alice:pre-secret\n    http://192.0.2.5:8080\n]\n\
post_proxies: [\n    :: [2001:db8::2]:1082|bob:post-secret\n    socks5://192.0.2.6:1080\n]\n";

#[test]
fn proxy_pools_default_to_absent_and_round_trip() {
    let old: Config = ktav::from_str("listen: 127.0.0.1:1080\n").expect("config without pools");
    assert!(old.pre_proxies.is_none());
    assert!(old.post_proxies.is_none());

    let pools: Config = ktav::from_str(POOLS).expect("pools");
    assert_eq!(pools.pre_proxies.as_ref().map(|pool| pool.len()), Some(2));
    assert_eq!(pools.post_proxies.as_ref().map(|pool| pool.len()), Some(2));
    let saved = ktav::to_string(&pools).expect("serialize");
    let loaded: Config = ktav::from_str(&saved).expect("round trip");
    assert_eq!(loaded.pre_proxies, pools.pre_proxies);
    assert_eq!(loaded.post_proxies, pools.post_proxies);

    let pre_only: Config =
        ktav::from_str("listen: 127.0.0.1:1080\npre_proxies: [\n    192.0.2.8:1080\n]\n")
            .expect("pre pool without post pool");
    assert!(pre_only.pre_proxies.is_some());
    assert!(pre_only.post_proxies.is_none());
}

#[test]
fn legacy_scalar_and_invalid_pool_values_are_rejected() {
    for (name, text) in [
        ("old pre field", "pre_socks5: 192.0.2.4:1080\n"),
        ("old post field", "post_socks5: 192.0.2.4:1080\n"),
        ("scalar pre", "pre_proxies: 192.0.2.4:1080\n"),
        ("global none", "pre_proxies: none\n"),
        ("empty pool", "post_proxies: []\n"),
        ("zero port", "post_proxies: [\n    192.0.2.4:0\n]\n"),
        ("hostname", "pre_proxies: [\n    proxy.example:1080\n]\n"),
        (
            "missing password",
            "pre_proxies: [\n    192.0.2.4:1080|alice\n]\n",
        ),
        (
            "exact duplicate",
            "pre_proxies: [\n    192.0.2.4:1080\n    192.0.2.4:1080\n]\n",
        ),
    ] {
        let input = format!("listen: 127.0.0.1:1080\n{text}");
        assert!(ktav::from_str::<Config>(&input).is_err(), "{name}");
    }
}

#[test]
fn pool_debug_and_errors_never_leak_credentials() {
    let pools: Config = ktav::from_str(POOLS).expect("pools");
    let debug = format!("{pools:?}");
    for secret in ["alice", "pre-secret", "bob", "post-secret"] {
        assert!(!debug.contains(secret), "Debug leaked {secret}");
    }
    let error = ktav::from_str::<Config>(
        "listen: 127.0.0.1:1080\npost_proxies: [\n    192.0.2.4:0|bob:post-secret\n]\n",
    )
    .unwrap_err();
    let error = format!("{error}");
    assert!(!error.contains("bob"));
    assert!(!error.contains("post-secret"));
}

#[test]
fn account_pool_replaces_or_disables_the_global_pool() {
    let global: Config = ktav::from_str(POOLS).expect("pools");
    let pre = global.pre_proxies.as_ref();
    assert!(client_acl::resolve_pool(pre, None).is_some());
    assert_eq!(
        client_acl::resolve_pool(pre, Some(&client_acl::PoolOverride::Disabled)),
        None
    );
    let own: client_acl::ProxyPool = "198.51.100.5:1080"
        .parse::<client_acl::Socks5Endpoint>()
        .expect("endpoint")
        .into();
    let resolved =
        client_acl::resolve_pool(pre, Some(&client_acl::PoolOverride::Pool(own.clone())));
    assert_eq!(resolved, Some(own));
}
