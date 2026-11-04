use super::*;

#[test]
fn socks5_config_omitted_disabled_and_endpoint_roundtrip() {
    let old: Config = ktav::from_str("listen: 127.0.0.1:1080\n").expect("old config");
    assert!(old.pre_socks5.is_none());
    assert!(old.post_socks5.is_none());

    let disabled: Config =
        ktav::from_str("listen: 127.0.0.1:1080\npre_socks5: none\npost_socks5: none\n")
            .expect("explicit empty values disable proxy");
    assert_eq!(
        disabled.pre_socks5,
        Some(client_acl::EndpointOverride::Disabled)
    );
    assert_eq!(
        disabled.post_socks5,
        Some(client_acl::EndpointOverride::Disabled)
    );
    let saved = ktav::to_string(&disabled).expect("serialize");
    assert!(saved.contains("pre_socks5: none"));
    assert!(saved.contains("post_socks5: none"));
    let loaded: Config = ktav::from_str(&saved).expect("roundtrip");
    assert_eq!(loaded.pre_socks5, disabled.pre_socks5);
    assert_eq!(loaded.post_socks5, disabled.post_socks5);

    let endpoint: Config = ktav::from_str(
        "listen: 127.0.0.1:1080\npre_socks5: 192.0.2.4:1080|alice:pw\npost_socks5:: [2001:db8::1]:1081\n",
    )
    .expect("endpoint");
    let saved = ktav::to_string(&endpoint).expect("serialize");
    let loaded: Config = ktav::from_str(&saved).expect("roundtrip");
    assert_eq!(loaded.pre_socks5, endpoint.pre_socks5);
    assert_eq!(loaded.post_socks5, endpoint.post_socks5);
    let inherited_pre = endpoint.pre_socks5.clone();
    let inherited_post = endpoint.post_socks5.clone();
    assert!(client_acl::resolve_endpoint(inherited_pre.as_ref(), None).is_some());
    assert!(client_acl::resolve_endpoint(inherited_post.as_ref(), None).is_some());

    let disabled = Some(client_acl::EndpointOverride::Disabled);
    assert_eq!(
        client_acl::resolve_endpoint(inherited_pre.as_ref(), disabled.as_ref()),
        None
    );
    assert!(client_acl::resolve_endpoint(inherited_post.as_ref(), disabled.as_ref()).is_none());

    let replacement = Some(client_acl::EndpointOverride::Endpoint(
        "198.51.100.5:1080".parse().expect("endpoint"),
    ));
    assert_eq!(
        client_acl::resolve_endpoint(inherited_pre.as_ref(), replacement.as_ref())
            .unwrap()
            .address()
            .to_string(),
        "198.51.100.5:1080"
    );
    assert_eq!(
        client_acl::resolve_endpoint(inherited_post.as_ref(), None)
            .unwrap()
            .address(),
        match inherited_post.as_ref().unwrap() {
            client_acl::EndpointOverride::Endpoint(endpoint) => endpoint.address(),
            _ => unreachable!(),
        }
    );

    assert!(ktav::from_str::<Config>("listen: 127.0.0.1:1080\npre_socks5::\n").is_err());
    assert!(
        ktav::from_str::<Config>("listen: 127.0.0.1:1080\npost_socks5: 192.0.2.4:0\n").is_err()
    );
    assert!(ktav::from_str::<Config>("listen: 127.0.0.1:1080\npre_socks5: \"\"\n").is_err());
    assert!(
        ktav::from_str::<Config>("listen: 127.0.0.1:1080\npre_socks5: proxy.example:1080\n")
            .is_err()
    );
    assert!(
        ktav::from_str::<Config>("listen: 127.0.0.1:1080\npre_socks5: 192.0.2.4:1080|alice\n")
            .is_err()
    );
    let pre_only: Config = ktav::from_str("listen: 127.0.0.1:1080\npre_socks5: 192.0.2.8:1080\n")
        .expect("pre endpoint parses without post endpoint");
    assert!(pre_only.pre_socks5.is_some());
    assert!(pre_only.post_socks5.is_none());
    let post_only: Config =
        ktav::from_str("listen: 127.0.0.1:1080\npost_socks5:: [2001:db8::8]:1088\n")
            .expect("post endpoint parses without pre endpoint");
    assert!(post_only.pre_socks5.is_none());
    assert!(post_only.post_socks5.is_some());

    let independent: Config = ktav::from_str(
        "listen: 127.0.0.1:1080\npre_socks5: 192.0.2.4:1080|alice:pre-secret\npost_socks5:: [2001:db8::2]:1082|bob:post-secret\n",
    )
    .expect("independent endpoints with IPv6 literal and credentials");
    let saved = ktav::to_string(&independent).expect("serialize");
    let loaded: Config = ktav::from_str(&saved).expect("roundtrip");
    assert_eq!(loaded.pre_socks5, independent.pre_socks5);
    assert_eq!(loaded.post_socks5, independent.post_socks5);
    assert_eq!(
        client_acl::resolve_endpoint(independent.pre_socks5.as_ref(), None)
            .unwrap()
            .address()
            .to_string(),
        "192.0.2.4:1080"
    );
    assert_eq!(
        client_acl::resolve_endpoint(independent.post_socks5.as_ref(), None)
            .unwrap()
            .address()
            .to_string(),
        "[2001:db8::2]:1082"
    );
    let debug = format!("{independent:?}");
    for secret in ["alice", "pre-secret", "bob", "post-secret"] {
        assert!(!debug.contains(secret), "Debug leaked {secret}");
    }

    let credential_error = ktav::from_str::<Config>(
        "listen: 127.0.0.1:1080\npost_socks5: 192.0.2.4:0|bob:post-secret\n",
    )
    .unwrap_err();
    let error = format!("{credential_error}");
    assert!(!error.contains("bob"));
    assert!(!error.contains("post-secret"));
}
