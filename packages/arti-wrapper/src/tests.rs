use super::*;
use std::path::PathBuf;
use std::sync::Once;

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
    assert!(s.is_default());
    assert!(s.bridges.is_empty());
    assert!(s.pt_binary.is_none());
    assert!(s.initial_connect_timeout.is_none());
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
    // `BootstrapStatus::default()` is documented by the vendored crate's
    // own tests to never be ready for traffic, so `emit_bootstrap_event`
    // must emit a `Progress` event and return `false`.
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
    assert_eq!(collected.len(), 1, "should emit exactly one event");
    assert!(
        matches!(collected[0], BootstrapEvent::Progress(f, _) if f == 0.0),
        "default status should emit Progress(0.0), got: {:?}",
        collected[0]
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
