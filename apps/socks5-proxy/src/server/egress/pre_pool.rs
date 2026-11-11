//! Pre proxy pools: the time a member gets, mapping of rotation members to
//! Tor client endpoints, and the background probe of members taken out of
//! rotation.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arti_wrapper::{ProxyProbe, Socks5PreEndpoint};
use resocks5_net::types::ProxyConfig;
use route_pool::ProbeOutcome;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::owners::OwnerRegistry;

/// How often the background task looks for quarantined members due a probe.
const PROBE_INTERVAL: Duration = Duration::from_secs(5);

/// Longest share of the setup deadline a pre member may use while others
/// remain; a member whose client is still starting needs more than a dial.
pub(super) const ATTEMPT_BUDGET: Duration = Duration::from_secs(30);

/// The Tor client endpoint a rotation member stands for.
///
/// `None` only for a member that is not an IP address with a port, which a
/// configured pool never holds.
pub(super) fn client_endpoint(proxy: &ProxyConfig) -> Option<Socks5PreEndpoint> {
    let ip: IpAddr = proxy.host.parse().ok()?;
    let credentials = match (&proxy.user, &proxy.password) {
        (Some(user), Some(password)) => Some((user.clone(), password.clone())),
        _ => None,
    };
    Some(
        Socks5PreEndpoint::new(SocketAddr::new(ip, proxy.port), credentials)
            .with_protocol(proxy.protocol),
    )
}

/// Starts the background task that re-checks quarantined pre proxies.
///
/// A pre proxy is reached without Tor, so the probe is a direct handshake. A
/// member that answers returns to rotation, and its client is asked to retry
/// a failed start. The task stops when `cancel` fires.
pub(super) fn spawn_prober(
    registry: Arc<OwnerRegistry>,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let scopes = Arc::clone(&registry);
        route_pool::drive_probes(
            move || scopes.pre_scopes().scopes(),
            PROBE_INTERVAL,
            move |proxy, deadline| probe_once(Arc::clone(&registry), proxy, deadline),
            cancel,
        )
        .await;
    })
}

async fn probe_once(
    registry: Arc<OwnerRegistry>,
    proxy: Arc<ProxyConfig>,
    deadline: Instant,
) -> ProbeOutcome {
    match arti_wrapper::probe_proxy_direct(&proxy, deadline).await {
        ProxyProbe::Alive => {
            if let Some(endpoint) = client_endpoint(&proxy) {
                registry.revive(endpoint);
            }
            ProbeOutcome::Alive
        }
        ProxyProbe::Dead => ProbeOutcome::Dead,
        ProxyProbe::Inconclusive => ProbeOutcome::Inconclusive,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::pre_endpoint;

    #[test]
    fn a_rotation_member_maps_back_to_its_client_endpoint() {
        for value in [
            "192.0.2.4:1080",
            "http://192.0.2.5:8080",
            "[2001:db8::2]:1082|bob:secret",
            "192.0.2.6:1080|alice:pw",
        ] {
            let endpoint: proxy_config::Socks5Endpoint = value.parse().unwrap();
            let proxy = route_pool::proxy_config(&endpoint).unwrap();
            assert_eq!(client_endpoint(&proxy), Some(pre_endpoint(&endpoint)));
        }
    }

    #[test]
    fn a_member_that_is_not_an_address_has_no_client_endpoint() {
        let proxy = ProxyConfig::new(
            resocks5_net::types::ProxyProtocol::Socks5,
            "proxy.example",
            1080,
        );
        assert_eq!(client_endpoint(&proxy), None);
    }
}
