//! With a pre proxy the engine opens no connection of its own to a bridge:
//! the decision is one predicate, used by the startup probe, the warm-up and
//! the stall watchdog, and read from the route the tunnel was built with.

use arti_wrapper::{Settings, Socks5PreEndpoint, TorTunnel};

use super::{engine_connects_to_bridges, tunnel_allows_own_bridge_checks};

const BRIDGE: &str = "192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01";

fn pre() -> Socks5PreEndpoint {
    Socks5PreEndpoint::new("127.0.0.1:9050".parse().unwrap(), None)
}

/// A tunnel that never bootstrapped: no network.
fn tunnel(dir: &std::path::Path, pre_endpoint: Option<Socks5PreEndpoint>) -> TorTunnel {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
    TorTunnel::create_manual_with(Settings {
        bridges: vec![BRIDGE.parse().unwrap()],
        state_dir: Some(dir.join("state")),
        pre_endpoint,
        ..Default::default()
    })
    .unwrap()
}

#[test]
fn without_a_pre_proxy_the_engine_checks_bridges_itself() {
    assert!(engine_connects_to_bridges(None));
}

#[test]
fn with_a_pre_proxy_the_engine_checks_no_bridge_itself() {
    assert!(!engine_connects_to_bridges(Some(&pre())));
}

#[tokio::test]
async fn a_direct_tunnel_allows_the_engines_own_checks() {
    let dir = tempfile::tempdir().unwrap();
    assert!(tunnel_allows_own_bridge_checks(&tunnel(dir.path(), None)));
}

#[tokio::test]
async fn a_tunnel_behind_a_pre_proxy_forbids_them() {
    let dir = tempfile::tempdir().unwrap();
    assert!(!tunnel_allows_own_bridge_checks(&tunnel(
        dir.path(),
        Some(pre())
    )));
}
