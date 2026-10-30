use super::*;
use crate::pre_endpoint::channel_proves_endpoint;
use arti_client::config::circ::CircMgrConfig;
use std::path::PathBuf;
use std::sync::Once;
use tor_linkspec::ChannelMethod;

/// Install rustls's process-wide `CryptoProvider` exactly once for this
/// test binary, mirroring `install_crypto_provider()` in
/// `apps/socks5-proxy/src/startup.rs` (which real app startup always
/// runs before constructing any `TorTunnel`). Only needed by tests that
/// build a real `TorClientConfig` with a *fresh* (empty) state/cache dir:
/// with no cached consensus to read, `TorClientConfig::builder().build()`
/// reaches further into arti's directory-manager setup than a dir with
/// pre-existing state would, and that path expects a crypto provider to
/// already be installed. `install_default()` errors if called twice in
/// the same process (e.g. across multiple `#[tokio::test]`s here), so
/// the error is intentionally discarded.
fn ensure_crypto_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[test]
fn settings_default_is_default() {
    let s = Settings::default();
    assert!(s.pre_endpoint.is_none());
    assert!(s.is_default());
    assert!(s.bridges.is_empty());
    assert!(s.pt_binary.is_none());
    assert!(s.initial_connect_timeout.is_none());
    assert_eq!(s.circuit_hops, 3);
    assert_eq!(s.service_circuit_hops, 4);
}

#[test]
fn settings_with_two_circuit_hops_is_not_default() {
    let settings = Settings {
        circuit_hops: 2,
        ..Default::default()
    };
    assert!(!settings.is_default());
}

#[test]
fn settings_with_shorter_service_circuit_hops_is_not_default() {
    let settings = Settings {
        service_circuit_hops: 2,
        ..Default::default()
    };
    assert!(!settings.is_default());
}

#[test]
fn build_config_routes_pre_proxy_and_redacts_credentials() {
    for credentials in [None, Some(("owner".to_owned(), "top-secret".to_owned()))] {
        let expected_uri = if credentials.is_some() {
            "socks5://owner:top-secret@127.0.0.9:1087"
        } else {
            "socks5://127.0.0.9:1087"
        };
        let endpoint = Socks5PreEndpoint::new("127.0.0.9:1087".parse().unwrap(), credentials);
        let debug = format!("{endpoint:?}");
        assert!(!debug.contains("top-secret"));
        let settings = Settings {
            pre_endpoint: Some(endpoint),
            ..Default::default()
        };
        let mut builder: TorClientConfigBuilder = TorClientConfig::builder();
        pre_endpoint::configure_pre_endpoint(&mut builder, &settings)
            .expect("SOCKS5 proxy configures");
        let channel = builder.channel().build().expect("channel config builds");
        let proxy = channel.outbound_proxy();
        assert_eq!(proxy.expect("proxy configured").to_string(), expected_uri);
        assert!(!format!("{settings:?}").contains("top-secret"));
    }
}

#[test]
fn bootstrap_raw_guard_rejects_pre_pt_config_before_construction() {
    // stock-прокси пропускает PT: raw-конфигурация собирается локально,
    // без создания клиента и без сети.
    let settings = Settings {
        pre_endpoint: Some(Socks5PreEndpoint::new("127.0.0.9:1087".parse().unwrap(), None)),
        pt_binary: Some(std::env::current_exe().unwrap()),
        stock_pt_proxy: true,
        extra_pt_protocols: vec!["obfs4".to_owned()],
        ..Default::default()
    };
    let pre_pt_config = build_config(&settings).expect("stock pre-PT config builds");
    let error = pre_endpoint::checked_raw(pre_pt_config)
        .expect_err("raw pre-PT one-shot must fail closed");
    assert!(error.to_string().contains("bootstrap_raw"));

    // plain-pre без PT сохраняет прежнее поведение raw-конструктора.
    let plain = Settings {
        pre_endpoint: Some(Socks5PreEndpoint::new("127.0.0.9:1087".parse().unwrap(), None)),
        ..Default::default()
    };
    let plain_config = build_config(&plain).expect("plain pre config builds");
    assert!(pre_endpoint::checked_raw(plain_config).is_ok());

    // без pre — прежнее поведение полностью сохранено.
    assert!(pre_endpoint::checked_raw(TorClientConfig::default()).is_ok());
}

#[test]
fn build_config_rejects_unsupported_proxy_protocol_without_fallback() {
    let settings = Settings {
        pre_endpoint: Some(Socks5PreEndpoint::new(
            "127.0.0.9:1087".parse().unwrap(),
            None,
        )),
        pt_binary: Some(PathBuf::from("any-configured-pt")),
        bridges: vec![
            "obfs4 192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0"
                .parse()
                .unwrap(),
        ],
        ..Default::default()
    };
    let error = build_config(&settings).expect_err("PT combined with pre is unsupported");
    assert!(error.to_string().contains("cannot guarantee routing"));
}

#[test]
fn stock_pt_pre_guard_accepts_supported_and_rejects_untrusted() {
    let endpoint = Socks5PreEndpoint::new("127.0.0.1:1080".parse().unwrap(), None);
    let mut settings = Settings {
        pre_endpoint: Some(endpoint),
        pt_binary: Some(std::env::current_exe().unwrap()),
        stock_pt_proxy: true,
        ..Default::default()
    };
    settings.bridges = vec!["192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01"
        .parse()
        .unwrap()];
    for protocols in [vec!["obfs4"], vec!["webtunnel"], vec!["obfs4", "webtunnel"]] {
        settings.extra_pt_protocols = protocols.into_iter().map(str::to_owned).collect();
        assert!(
            pre_endpoint::configure_pre_endpoint(&mut TorClientConfig::builder(), &settings)
                .is_ok()
        );
    }
    for bridge in [
        "obfs4 192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0",
        "webtunnel 192.0.2.2:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 url=https://example.com/x ver=0.0.3",
    ] {
        let mut mixed = settings.clone();
        mixed.bridges.push(bridge.parse().unwrap());
        assert!(pre_endpoint::configure_pre_endpoint(&mut TorClientConfig::builder(), &mixed).is_ok());
    }
    settings.stock_pt_proxy = false;
    assert!(settings.validate_stock_pt_proxy().is_err());
    settings.stock_pt_proxy = true;
    settings.extra_pt_protocols.push("unknownpt".into());
    assert!(settings.validate_stock_pt_proxy().is_err());
    settings.extra_pt_protocols.pop();
    settings.pt_binary = Some(PathBuf::from("external-pt"));
    assert!(settings.validate_stock_pt_proxy().is_err());
}

#[test]
fn build_config_redacts_invalid_pre_proxy_credentials() {
    let settings = Settings {
        pre_endpoint: Some(Socks5PreEndpoint::new(
            "127.0.0.9:1087".parse().unwrap(),
            Some(("user".to_owned(), "x".repeat(256))),
        )),
        ..Default::default()
    };
    let error = build_config(&settings).expect_err("invalid URI userinfo is rejected");
    assert!(!error.to_string().contains(&"x".repeat(256)));
}

#[test]
fn settings_initial_connect_timeout_is_an_explicit_opt_in() {
    let settings = Settings {
        initial_connect_timeout: Some(std::time::Duration::from_secs(4)),
        ..Default::default()
    };
    assert!(!settings.is_default());
    let config = build_config(&settings).unwrap();
    assert_eq!(
        config.stream_timeouts().initial_connect_timeout(),
        Some(std::time::Duration::from_secs(4))
    );
}

#[test]
fn settings_with_bridges_is_not_default() {
    let bridge: BridgeLine = "192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01"
        .parse()
        .unwrap();
    let s = Settings {
        bridges: vec![bridge],
        pt_binary: None,
        state_dir: None,
        ..Default::default()
    };
    assert!(!s.is_default());
}

#[test]
fn build_config_applies_circuit_hops_to_path_config() {
    for (hops, settings) in [
        (
            2,
            Settings {
                circuit_hops: 2,
                ..Default::default()
            },
        ),
        (3, Settings::default()),
    ] {
        let config = build_config(&settings).expect("valid circuit hop setting builds");
        assert_eq!(config.path_rules().circuit_hops(), hops);
    }
}

#[test]
fn build_config_applies_service_circuit_hops_to_path_config() {
    for (hops, settings) in [
        (
            2,
            Settings {
                service_circuit_hops: 2,
                ..Default::default()
            },
        ),
        (4, Settings::default()),
    ] {
        let config = build_config(&settings).expect("valid service circuit hop setting builds");
        assert_eq!(config.path_rules().service_circuit_hops(), hops);
    }
}

#[test]
fn build_config_rejects_invalid_service_circuit_hops() {
    for hops in [0, 1, 5, u8::MAX] {
        let settings = Settings {
            service_circuit_hops: hops,
            ..Default::default()
        };
        let error = build_config(&settings).expect_err("invalid hop count rejected");
        assert!(
            error.to_string().contains("service_circuit_hops"),
            "{error}"
        );
    }
}

#[test]
fn build_config_rejects_invalid_circuit_hops() {
    for hops in [0, 1, 4, u8::MAX] {
        let settings = Settings {
            circuit_hops: hops,
            ..Default::default()
        };
        let error = build_config(&settings).expect_err("invalid hop count rejected");
        assert!(error.to_string().contains("circuit_hops"), "{error}");
    }
}

#[test]
fn build_config_empty_settings_succeeds() {
    let cfg = build_config(&Settings::default());
    assert!(cfg.is_ok());
}

#[test]
fn build_config_with_separate_cache_dir_succeeds() {
    let state = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let s = Settings {
        state_dir: Some(state.path().to_path_buf()),
        cache_dir: Some(cache.path().to_path_buf()),
        ..Default::default()
    };
    assert!(
        build_config(&s).is_ok(),
        "a state_dir + separate cache_dir override must build a valid config"
    );
}

#[test]
fn build_config_cache_dir_without_state_dir_is_ignored() {
    // cache_dir only takes effect alongside state_dir (see its doc) -- setting it alone
    // must not error, just have no effect.
    let cache = tempfile::tempdir().unwrap();
    let s = Settings {
        cache_dir: Some(cache.path().to_path_buf()),
        ..Default::default()
    };
    assert!(build_config(&s).is_ok());
}

#[tokio::test]
async fn reconfigure_settings_accepts_updated_stream_timeout_profile() {
    ensure_crypto_provider();
    let dir = tempfile::tempdir().unwrap();
    let initial = Settings {
        state_dir: Some(dir.path().to_path_buf()),
        initial_connect_timeout: Some(std::time::Duration::from_secs(4)),
        ..Default::default()
    };
    let updated = Settings {
        state_dir: Some(dir.path().to_path_buf()),
        initial_connect_timeout: Some(std::time::Duration::from_secs(3)),
        ..Default::default()
    };
    let tunnel = TorTunnel::create_unbootstrapped_with(initial).unwrap();
    tunnel.reconfigure_bridges(&updated).unwrap();
}

#[test]
fn build_config_plain_bridge_without_pt_binary_succeeds() {
    let bridge: BridgeLine = "192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01"
        .parse()
        .unwrap();
    let s = Settings {
        bridges: vec![bridge],
        pt_binary: None,
        state_dir: None,
        ..Default::default()
    };
    let cfg = build_config(&s);
    assert!(
        cfg.is_ok(),
        "plain bridge (no transport) should not require pt_binary"
    );
}

#[test]
fn build_config_transport_bridge_without_pt_binary_errors() {
    let bridge: BridgeLine =
        "obfs4 192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0"
            .parse()
            .unwrap();
    let s = Settings {
        bridges: vec![bridge],
        pt_binary: None,
        state_dir: None,
        ..Default::default()
    };
    let err = build_config(&s).unwrap_err();
    assert!(
        matches!(err, TorError::InvalidPt(_)),
        "expected InvalidPt, got: {err}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("pt_binary"),
        "error must mention pt_binary: {msg}"
    );
}

#[test]
fn build_config_transport_bridge_with_nonexistent_pt_binary_errors() {
    let bridge: BridgeLine =
        "obfs4 192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0"
            .parse()
            .unwrap();
    let s = Settings {
        bridges: vec![bridge],
        pt_binary: Some(PathBuf::from("/nonexistent/path/lyrebird")),
        state_dir: None,
        ..Default::default()
    };
    let err = build_config(&s).unwrap_err();
    assert!(matches!(err, TorError::InvalidPt(_)));
    assert!(err.to_string().contains("does not exist"));
}

#[test]
fn build_config_transport_bridge_with_valid_pt_binary_succeeds() {
    let bridge: BridgeLine =
        "obfs4 192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0"
            .parse()
            .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let fake_binary = dir.path().join("fake-lyrebird");
    std::fs::write(&fake_binary, b"#!/bin/sh\n").unwrap();
    let s = Settings {
        bridges: vec![bridge],
        pt_binary: Some(fake_binary),
        state_dir: None,
        ..Default::default()
    };
    let cfg = build_config(&s);
    assert!(cfg.is_ok(), "valid pt_binary should produce a valid config");
}

#[test]
fn build_config_multiple_transports_collected() {
    let obfs4: BridgeLine =
        "obfs4 192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0"
            .parse()
            .unwrap();
    let webtunnel: BridgeLine =
        "webtunnel 192.0.2.2:1 0123456789ABCDEF0123456789ABCDEF01234567 url=https://example.com/x ver=0.0.3"
            .parse()
            .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let fake_binary = dir.path().join("fake-lyrebird");
    std::fs::write(&fake_binary, b"#!/bin/sh\n").unwrap();
    let s = Settings {
        bridges: vec![obfs4, webtunnel],
        pt_binary: Some(fake_binary),
        state_dir: None,
        ..Default::default()
    };
    let cfg = build_config(&s);
    assert!(
        cfg.is_ok(),
        "mixed transports should work with a valid pt_binary"
    );
}

#[tokio::test]
async fn signal_bridge_failure_requires_running_client() {
    // `create_unbootstrapped_with` is synchronous and does no I/O, so the
    // resulting client never reaches arti's "running" state — the same
    // property `tor_watchdog.rs`'s
    // `heal_reports_terminate_failed_on_a_client_that_is_not_running`
    // test relies on for `terminate_all_channels`. This exercises the
    // BridgeLine → BridgeConfigBuilder → BridgeConfig conversion path
    // (shared with `warm_bridge`) end to end without any network access,
    // and confirms the "not running" failure surfaces as
    // `TorError::SignalFailure` rather than panicking or being silently
    // swallowed.
    //
    // `#[tokio::test]`, not `#[test]`: `create_unbootstrapped_with` looks
    // up the current tokio runtime via `PreferredRuntime::current()` (see
    // `tor_builder`), which panics outside of an async context.
    //
    // `state_dir` must point at a fresh tempdir rather than
    // `Settings::default()`'s `None`: with `None`, arti falls back to
    // its per-user OS-default state/cache location, and constructing
    // even an "unbootstrapped" client eagerly opens that directory's
    // storage — which fails with `DirMgrSetup(ReadOnlyStorage(NoDatabase))`
    // on a fresh CI runner with no pre-existing arti state (the same
    // real-shared-OS-path fragility `tor_setup.rs` already avoids for
    // the live proxy, and that `verify_usable_skips_network_when_no_target`
    // hit for the same reason in an earlier session).
    ensure_crypto_provider();
    let dir = tempfile::tempdir().unwrap();
    let settings = Settings {
        state_dir: Some(dir.path().to_path_buf()),
        ..Default::default()
    };
    let tor = TorTunnel::create_unbootstrapped_with(settings)
        .expect("synchronous, no-I/O construction must succeed");
    let bridge: BridgeLine =
        "obfs4 192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0"
            .parse()
            .unwrap();
    let err = tor
        .signal_bridge_failure(&bridge, tor_guardmgr::ExternalActivity::DirCache)
        .unwrap_err();
    assert!(
        matches!(err, TorError::SignalFailure { .. }),
        "expected SignalFailure, got: {err}"
    );
}

#[tokio::test]
async fn signal_bridge_failure_conversion_succeeds_for_plain_bridge_without_transport() {
    // Same "not running" contract as the obfs4 case above, but with a
    // plain bridge line (no transport) — confirms the BridgeLine →
    // BridgeConfigBuilder → BridgeConfig conversion path used by
    // `signal_bridge_failure` handles both bridge shapes, same as
    // `warm_bridge`'s conversion. Same tempdir `state_dir` rationale as
    // the obfs4 case above — do not revert to `Settings::default()`.
    ensure_crypto_provider();
    let dir = tempfile::tempdir().unwrap();
    let settings = Settings {
        state_dir: Some(dir.path().to_path_buf()),
        ..Default::default()
    };
    let tor = TorTunnel::create_unbootstrapped_with(settings)
        .expect("synchronous, no-I/O construction must succeed");
    let bridge: BridgeLine = "192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01"
        .parse()
        .unwrap();
    let err = tor
        .signal_bridge_failure(&bridge, tor_guardmgr::ExternalActivity::DirCache)
        .unwrap_err();
    assert!(matches!(err, TorError::SignalFailure { .. }));
}

#[test]
fn emit_bootstrap_event_maps_default_status_to_progress() {
    // In Arti 0.47, `BootstrapStatus::default()` carries
    // `BootstrapSetting::default()` = `BootstrapBehavior::Manual` with no
    // running-inner, so `status.blocked()` reports `Some(Blockage { kind:
    // Disabled })`. `emit_bootstrap_event` therefore emits `Progress(0.0)`
    // *and* a `Blocked` event, and must still return `false`. A real
    // on-demand client never sees this Disabled blockage, so this only
    // pins the default-status mapping.
    use std::sync::Mutex;
    let events = Arc::new(Mutex::new(Vec::new()));
    let callback: BootstrapEventCallback = Arc::new({
        let events = events.clone();
        move |event| events.lock().unwrap().push(event)
    });
    let status = arti_client::status::BootstrapStatus::default();
    let ready = emit_bootstrap_event(&status, &callback);
    assert!(!ready, "default status is not ready for traffic");
    let collected = events.lock().unwrap();
    assert_eq!(collected.len(), 2, "Progress(0.0) + Blocked(Disabled)");
    assert!(
        matches!(collected[0], BootstrapEvent::Progress(f, _) if f == 0.0),
        "default status should emit Progress(0.0), got: {:?}",
        collected[0]
    );
    assert!(
        matches!(collected[1], BootstrapEvent::Blocked(_)),
        "Manual default should emit Blocked(Disabled), got: {:?}",
        collected[1]
    );
}

#[tokio::test]
async fn forward_bootstrap_events_emits_initial_progress() {
    // `forward_bootstrap_events` synchronously emits the current status
    // before spawning the background task, so the callback receives a
    // `Progress` event immediately without any network activity.
    // The event arrives because the client's default bootstrap status
    // (not yet bootstrapped, no network) is emitted on the first call.
    ensure_crypto_provider();
    let dir = tempfile::tempdir().unwrap();
    let settings = Settings {
        state_dir: Some(dir.path().to_path_buf()),
        ..Default::default()
    };
    let tor = TorTunnel::create_unbootstrapped_with(settings)
        .expect("synchronous, no-I/O construction must succeed");
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let tx = Arc::new(tx);
    let callback: BootstrapEventCallback = Arc::new({
        let tx = tx.clone();
        move |event| {
            let _ = tx.try_send(event);
        }
    });
    tor.forward_bootstrap_events(callback);
    let event = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("timeout waiting for initial event")
        .expect("channel should not close");
    assert!(
        matches!(event, BootstrapEvent::Progress(_, _)),
        "first event should be Progress, got: {:?}",
        event
    );
}

#[test]
fn iat_mode_override_rewrites_obfs4_and_leaves_others_alone() {
    let obfs4: BridgeLine =
        "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0"
            .parse()
            .expect("obfs4 line parses");
    let rewritten = with_iat_mode_override(&obfs4, Some(1));
    assert_eq!(
        rewritten.params.get("iat-mode").map(String::as_str),
        Some("1")
    );
    assert!(rewritten.to_string().contains("iat-mode=1"));

    // No override configured: line is untouched.
    assert_eq!(with_iat_mode_override(&obfs4, None), obfs4);

    // webtunnel has no iat-mode concept; it must not gain one.
    let webtunnel: BridgeLine =
        "webtunnel 192.0.2.3:1 2852538D49D7D73C1A6694FC492104983A9C4FA2 url=https://example.com/x"
            .parse()
            .expect("webtunnel line parses");
    assert_eq!(with_iat_mode_override(&webtunnel, Some(1)), webtunnel);
}

#[test]
fn iat_mode_override_adds_the_param_when_the_line_omits_it() {
    let obfs4: BridgeLine = "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA"
        .parse()
        .expect("obfs4 line parses");
    let rewritten = with_iat_mode_override(&obfs4, Some(2));
    assert_eq!(
        rewritten.params.get("iat-mode").map(String::as_str),
        Some("2")
    );
}

#[test]
fn bridge_target_applies_iat_mode_override() {
    use tor_linkspec::{ChannelMethod, HasChanMethod};

    let bridge: BridgeLine =
        "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0"
            .parse()
            .expect("obfs4 line parses");
    let (_serialized, builder) =
        build_bridge_config_builder(&bridge, Some(2)).expect("target builder builds");
    let target = builder.build().expect("target builds");
    let ChannelMethod::Pluggable(pt_target) = target.chan_method() else {
        panic!("obfs4 bridge must produce a pluggable target");
    };
    assert_eq!(
        pt_target
            .settings()
            .find(|(key, _)| *key == "iat-mode")
            .map(|(_, value)| value),
        Some("2")
    );
}

#[tokio::test]
async fn verify_bridge_reachable_reports_bootstrap_timeout_for_an_unreachable_bridge() {
    // 192.0.2.0/24 is RFC 5737 documentation space -- guaranteed to have nothing
    // listening, so bootstrap can never succeed and this exercises the timeout path
    // deterministically without any real network access. Same state_dir rationale as
    // signal_bridge_failure_requires_running_client above.
    ensure_crypto_provider();
    let state = tempfile::tempdir().unwrap();
    let bridge: BridgeLine = "192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01"
        .parse()
        .unwrap();
    let check = BridgeCheckSettings {
        bridge,
        pt_binary: None,
        cache_dir: None,
        state_dir: state.path().to_path_buf(),
    };
    let bootstrap_timeout = Duration::from_millis(500);
    let err = TorTunnel::verify_bridge_reachable(
        check,
        ("check.torproject.org", 443),
        bootstrap_timeout,
        Duration::from_secs(5),
    )
    .await
    .expect_err("an unreachable bridge must never bootstrap");
    assert!(
        matches!(err, TorError::BridgeCheckBootstrapTimeout(d) if d == bootstrap_timeout),
        "expected BridgeCheckBootstrapTimeout, got: {err}"
    );
}

#[cfg(test)]
mod endpoint_proof {
    use super::*;
    use std::net::SocketAddr;
    use tor_linkspec::{PtTarget, PtTargetAddr, PtTransportName};

    fn direct(addrs: &[&str]) -> ChannelMethod {
        ChannelMethod::Direct(
            addrs
                .iter()
                .map(|a| a.parse::<SocketAddr>().unwrap())
                .collect(),
        )
    }

    fn pluggable(transport: &str, addr: &str) -> ChannelMethod {
        ChannelMethod::Pluggable(PtTarget::new(
            transport.parse::<PtTransportName>().unwrap(),
            addr.parse::<PtTargetAddr>().unwrap(),
        ))
    }

    #[test]
    fn direct_match_on_the_actually_used_address_proves() {
        // Channel::target() reports only the address the handshake used; it
        // counts as proof when that address is among the requested ones.
        assert!(channel_proves_endpoint(
            &direct(&["192.0.2.1:443"]),
            &direct(&["192.0.2.1:443", "192.0.2.2:443"])
        ));
    }

    #[test]
    fn direct_reuse_of_a_different_address_is_not_proof() {
        assert!(!channel_proves_endpoint(
            &direct(&["192.0.2.9:443"]),
            &direct(&["192.0.2.1:443"])
        ));
    }

    #[test]
    fn pluggable_same_endpoint_proves() {
        assert!(channel_proves_endpoint(
            &pluggable("webtunnel", "192.0.2.1:443"),
            &pluggable("webtunnel", "192.0.2.1:443")
        ));
    }

    #[test]
    fn pluggable_different_endpoint_is_not_proof() {
        // TS8-02: same relay identities, different webtunnel endpoint.
        assert!(!channel_proves_endpoint(
            &pluggable("webtunnel", "192.0.2.1:443"),
            &pluggable("webtunnel", "203.0.113.7:443")
        ));
        assert!(!channel_proves_endpoint(
            &pluggable("webtunnel", "192.0.2.1:443"),
            &pluggable("obfs4", "192.0.2.1:443")
        ));
    }

    #[test]
    fn transport_class_mismatch_is_not_proof() {
        assert!(!channel_proves_endpoint(
            &direct(&["192.0.2.1:443"]),
            &pluggable("webtunnel", "192.0.2.1:443")
        ));
    }
}

#[test]
fn validate_circuit_hops_accepts_two_and_three() {
    assert!(super::validate_circuit_hops(2).is_ok());
    assert!(super::validate_circuit_hops(3).is_ok());
}

#[test]
fn validate_circuit_hops_rejects_other_values() {
    for hops in [0, 1, 4, 255] {
        let err = super::validate_circuit_hops(hops).unwrap_err();
        assert!(err.contains("tor.circuit_hops"), "{err}");
        assert!(err.contains("2 or 3"), "{err}");
    }
}

#[test]
fn validate_min_bandwidth_percentile_accepts_disabled_and_valid_range() {
    // 0 = disabled (default), accepted, matching the vendored tor-circmgr
    // builder validation (`pct <= 100` is ok).
    assert!(super::validate_min_bandwidth_percentile(0).is_ok());
    assert!(super::validate_min_bandwidth_percentile(1).is_ok());
    assert!(super::validate_min_bandwidth_percentile(50).is_ok());
    assert!(super::validate_min_bandwidth_percentile(100).is_ok());
}

#[test]
fn validate_min_bandwidth_percentile_rejects_above_100() {
    // >100 used to be silently clamped by older tor-circmgr; the vendored
    // 0.47 tor-circmgr rejects it at config build, so we reject it early
    // with a clear message.
    let err = super::validate_min_bandwidth_percentile(101).unwrap_err();
    assert!(err.contains("min_bandwidth_percentile must be in 0..=100, got 101"));
    assert!(super::validate_min_bandwidth_percentile(255).is_err());
}

#[cfg(feature = "onion-service")]
#[test]
fn onion_service_server_api_is_available() {
    // Proves the server-side API is compiled in; no network is touched.
    // nickname requires tor_hsservice::HsNickname, so build() without one
    // returns Err — that still proves the API is linked.
    use arti_client::config::onion_service::OnionServiceConfigBuilder;
    let cfg = OnionServiceConfigBuilder::default();
    let _ = cfg.build();
}

#[tokio::test(flavor = "current_thread")]
async fn nonloopback_proxy_warning_omits_credentials() {
    use std::fmt::Write;
    use std::future::Future;
    use std::sync::Mutex;
    use std::task::Context;
    use tracing::{field, span, Event, Metadata, Subscriber};

    struct Capture(Arc<Mutex<Vec<String>>>);
    struct Fields(String);
    impl field::Visit for Fields {
        fn record_debug(&mut self, field: &field::Field, value: &dyn std::fmt::Debug) {
            write!(self.0, "{}={value:?} ", field.name()).unwrap();
        }
    }
    impl Subscriber for Capture {
        fn enabled(&self, metadata: &Metadata<'_>) -> bool {
            metadata.is_event() && *metadata.level() == tracing::Level::WARN
        }
        fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
            span::Id::from_u64(1)
        }
        fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
        fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
        fn enter(&self, _: &span::Id) {}
        fn exit(&self, _: &span::Id) {}
        fn event(&self, event: &Event<'_>) {
            if event.metadata().target().starts_with("tor_chanmgr") {
                let mut fields = Fields(String::new());
                event.record(&mut fields);
                self.0.lock().unwrap().push(fields.0);
            }
        }
    }

    ensure_crypto_provider();
    let state = tempfile::tempdir().unwrap();
    let settings = Settings {
        state_dir: Some(state.path().to_path_buf()),
        pre_endpoint: Some(Socks5PreEndpoint::new(
            "192.0.2.77:1087".parse().unwrap(),
            Some(("warn-user@marker".to_owned(), "warn-pass:marker".to_owned())),
        )),
        ..Default::default()
    };
    let tunnel = TorTunnel::create_unbootstrapped_with(settings).unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    let dispatch = tracing::Dispatch::new(Capture(events.clone()));
    let mut bootstrap = Box::pin(tunnel.wait_bootstrapped());
    let waker = futures::task::noop_waker();
    let mut context = Context::from_waker(&waker);
    // Конструктор ChanMgr вызывается при опросе bootstrap; диспетчер действует только на этот опрос.
    // Current-thread runtime и отсутствие await до конца теста не дают запущенным
    // bootstrap задачам выполняться; runtime уничтожается вместе с ними без сети.
    tracing::dispatcher::with_default(&dispatch, || {
        let _ = bootstrap.as_mut().poll(&mut context);
    });
    let events = events.lock().unwrap();
    let warning = events
        .iter()
        .find(|event| event.contains("non-loopback"))
        .expect("предупреждение конструктора ChanMgr не получено");
    assert!(warning.contains("proxy_scheme=socks5 "), "{warning}");
    assert!(warning.contains("proxy_addr=192.0.2.77:1087 "), "{warning}");
    for event in events.iter() {
        for secret in [
            "warn-user@marker",
            "warn-pass:marker",
            "warn-user%40marker",
            "warn-pass%3Amarker",
            "warn-pass%3amarker",
        ] {
            assert!(
                !event.contains(secret),
                "обнаружены учётные данные: {event}"
            );
        }
    }
}

#[tokio::test]
async fn initial_bootstrap_uses_pre_proxy_without_direct_fallback_after_rejection() {
    use std::future::Future;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::timeout;

    ensure_crypto_provider();
    let state = tempfile::tempdir().unwrap();
    let direct = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = direct.local_addr().unwrap();
    // Отдельный адрес и идентификатор исключают совмещение warm с bootstrap.
    let bootstrap_direct = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bootstrap_target = bootstrap_direct.local_addr().unwrap();
    let pre = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge: BridgeLine = format!(
        "{} ABCDEF0123456789ABCDEF0123456789ABCDEF01",
        bootstrap_target
    )
    .parse()
    .unwrap();
    let warm_bridge: BridgeLine = format!("{} 2222222222222222222222222222222222222222", target)
        .parse()
        .unwrap();
    let settings = Settings {
        state_dir: Some(state.path().to_path_buf()),
        bridges: vec![bridge],
        disable_preemptive_circuits: true,
        pre_endpoint: Some(Socks5PreEndpoint::new(
            pre.local_addr().unwrap(),
            Some(("bootstrap-user".to_owned(), "bootstrap-secret".to_owned())),
        )),
        ..Default::default()
    };
    let tunnel = TorTunnel::create_unbootstrapped_with(settings.clone()).unwrap();
    tunnel.reconfigure_bridges(&settings).unwrap();

    // Один опрос создаёт менеджер; дальше наблюдаем и bootstrap, и warm.
    let mut bootstrap = Box::pin(tunnel.wait_bootstrapped());
    let waker = futures::task::noop_waker();
    assert!(bootstrap
        .as_mut()
        .poll(&mut Context::from_waker(&waker))
        .is_pending());
    let warm = tunnel.warm_bridge(&warm_bridge);
    tokio::pin!(warm);
    let mut exchanges = futures::stream::FuturesUnordered::new();
    let mut bootstrap_seen = false;
    let mut warm_seen = false;
    let mut warm_result = None;
    use futures::StreamExt;
    timeout(Duration::from_secs(20), async {
        while warm_result.is_none() || !bootstrap_seen || !warm_seen {
            tokio::select! {
                result = &mut bootstrap => panic!("неожиданное завершение bootstrap: {result:?}"),
                result = bootstrap_direct.accept() => panic!("прямое подключение bootstrap: {result:?}"),
                result = direct.accept() => panic!("прямое подключение warm: {result:?}"),
                result = &mut warm, if warm_result.is_none() => {
                    warm_result = Some(result);
                    assert!(matches!(direct.poll_accept(&mut Context::from_waker(&waker)), Poll::Pending),
                        "в очереди обнаружено прямое подключение warm");
                },
                result = pre.accept() => {
                    let (mut peer, _) = result.unwrap();
                    exchanges.push(async move {
                        let mut greeting = [0u8; 2];
                        peer.read_exact(&mut greeting).await.unwrap();
                        assert_eq!(greeting[0], 5);
                        let mut methods = vec![0; greeting[1] as usize];
                        peer.read_exact(&mut methods).await.unwrap();
                        assert!(methods.contains(&2), "SOCKS должен предложить пароль");
                        peer.write_all(&[5, 2]).await.unwrap();
                        let mut auth = [0u8; 2];
                        peer.read_exact(&mut auth).await.unwrap();
                        assert_eq!(auth[0], 1);
                        let mut user = vec![0; auth[1] as usize];
                        peer.read_exact(&mut user).await.unwrap();
                        let mut len = [0u8; 1];
                        peer.read_exact(&mut len).await.unwrap();
                        let mut password = vec![0; len[0] as usize];
                        peer.read_exact(&mut password).await.unwrap();
                        assert_eq!(user, b"bootstrap-user");
                        assert_eq!(password, b"bootstrap-secret");
                        peer.write_all(&[1, 0]).await.unwrap();
                        let mut request = [0u8; 4];
                        peer.read_exact(&mut request).await.unwrap();
                        assert_eq!(request, [5, 1, 0, 1]);
                        let mut address = [0u8; 6];
                        peer.read_exact(&mut address).await.unwrap();
                        assert_eq!(&address[..4], &[127, 0, 0, 1]);
                        let port = u16::from_be_bytes([address[4], address[5]]);
                        assert!(port == target.port() || port == bootstrap_target.port(), "неизвестный CONNECT: {port}");
                        peer.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
                        port
                    });
                },
                Some(port) = exchanges.next(), if !exchanges.is_empty() => {
                    bootstrap_seen |= port == bootstrap_target.port();
                    warm_seen |= port == target.port();
                },
            }
        }
    }).await.expect("warm или bootstrap не завершил наблюдаемую попытку до истечения срока");
    assert!(warm_seen, "нет отказа SOCKS для warm");
    // Error::Connect содержит список ошибок, а не стандартную цепочку source.
    match warm_result.unwrap() {
        Err(TorError::Warm { source, .. }) => match *source {
            tor_chanmgr::Error::Connect { addresses } => {
                let errors = format!("{addresses:?}");
                assert!(
                    errors.contains("SocksError(SocksStatus(CONNECTION_REFUSED))"),
                    "{errors}"
                );
            }
            other => panic!("ожидался отказ SOCKS, получено: {other:?}"),
        },
        other => panic!("ожидался Warm с отказом SOCKS: {other:?}"),
    }
    // get_or_launch ожидает build_channel и его повторы до возврата ошибки.
    // Это проверка очереди в момент завершения, а не бесконечного отсутствия трафика.
    assert!(
        matches!(
            direct.poll_accept(&mut Context::from_waker(&waker)),
            Poll::Pending
        ),
        "в очереди обнаружено прямое подключение warm"
    );
    assert!(matches!(
        bootstrap_direct.poll_accept(&mut Context::from_waker(&waker)),
        Poll::Pending
    ));
}

#[tokio::test]
async fn reconfigure_cannot_enable_pre_on_direct_shared_client() {
    ensure_crypto_provider();
    let state = tempfile::tempdir().unwrap();
    let initial = Settings {
        state_dir: Some(state.path().to_path_buf()),
        ..Default::default()
    };
    let tunnel = TorTunnel::create_unbootstrapped_with(initial.clone()).unwrap();
    let mut changed = initial.clone();
    changed.pre_endpoint = Some(Socks5PreEndpoint::new(
        "127.0.0.1:9050".parse().unwrap(),
        None,
    ));
    let err = tunnel.clone().reconfigure_bridges(&changed).unwrap_err();
    assert!(
        matches!(err, TorError::BuildConfig(ref message) if message == "cannot change the pre endpoint on a shared client")
    );
    tunnel.reconfigure_bridges(&initial).unwrap();
}

#[tokio::test]
async fn raw_default_configuration_can_still_be_reconfigured() {
    ensure_crypto_provider();
    let state = tempfile::tempdir().unwrap();
    let settings = Settings {
        state_dir: Some(state.path().to_path_buf()),
        ..Default::default()
    };
    let tunnel = TorTunnel::create_unbootstrapped(build_config(&settings).unwrap()).unwrap();
    tunnel.reconfigure_bridges(&settings).unwrap();
}

#[tokio::test]
async fn pre_endpoint_is_immutable_across_clones() {
    ensure_crypto_provider();
    let state = tempfile::tempdir().unwrap();
    let settings = Settings {
        state_dir: Some(state.path().to_path_buf()),
        pre_endpoint: Some(Socks5PreEndpoint::new(
            "127.0.0.1:9050".parse().unwrap(),
            None,
        )),
        ..Default::default()
    };
    let tunnel = TorTunnel::create_unbootstrapped_with(settings.clone()).unwrap();
    let mut changed = settings.clone();
    changed.pre_endpoint = None;
    let err = tunnel.clone().reconfigure_bridges(&changed).unwrap_err();
    assert!(
        matches!(err, TorError::BuildConfig(ref message) if message == "cannot change the pre endpoint on a shared client")
    );
    changed.pre_endpoint = Some(Socks5PreEndpoint::new(
        "127.0.0.1:9051".parse().unwrap(),
        None,
    ));
    let err = tunnel.clone().reconfigure_bridges(&changed).unwrap_err();
    assert!(
        matches!(err, TorError::BuildConfig(ref message) if message == "cannot change the pre endpoint on a shared client")
    );
    changed.pre_endpoint = Some(Socks5PreEndpoint::new(
        "127.0.0.1:9050".parse().unwrap(),
        Some(("user".to_owned(), "secret".to_owned())),
    ));
    let err = tunnel.clone().reconfigure_bridges(&changed).unwrap_err();
    assert!(
        matches!(err, TorError::BuildConfig(ref message) if message == "cannot change the pre endpoint on a shared client")
    );
    tunnel.reconfigure_bridges(&settings).unwrap();
}
