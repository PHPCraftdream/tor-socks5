//! Post proxy pools: member choice per site, failover and background probes.

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arti_wrapper::{PostBlame, PostFailure, PostProbe, RoutedStream, TorError, TorTunnel};
use proxy_config::ProxyPool;
use resocks5_net::types::ProxyConfig;
use route_pool::{PoolError, ProbeOutcome, ScopeMap, Verdict};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::tor_watchdog::TorHandle;

/// How often the background task looks for quarantined members due a probe.
const PROBE_INTERVAL: Duration = Duration::from_secs(5);

/// Rotation state of every post pool in use.
///
/// Accounts whose effective pools hold the same members share one scope, so
/// they share quarantine state and the site-to-member assignment.
#[derive(Default)]
pub(crate) struct PostPools {
    scopes: ScopeMap,
}

impl PostPools {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Opens a stream to `host:port` through a member of `pool`.
    ///
    /// cancel-safe: NO — cancellation drops the attempt in flight.
    pub(crate) async fn connect(
        &self,
        tor: &TorTunnel,
        pool: &ProxyPool,
        host: &str,
        port: u16,
        deadline: Instant,
    ) -> Result<RoutedStream, TorError> {
        self.connect_via(
            pool,
            host,
            deadline,
            move |proxy, attempt_deadline| async move {
                arti_wrapper::connect_post_proxy_blamed(tor, &proxy, host, port, attempt_deadline)
                    .await
            },
        )
        .await
    }

    /// Pool failover around an arbitrary connect step; the seam of the tests.
    async fn connect_via<T, F, Fut>(
        &self,
        pool: &ProxyPool,
        host: &str,
        deadline: Instant,
        connect: F,
    ) -> Result<T, TorError>
    where
        F: FnMut(Arc<ProxyConfig>, Instant) -> Fut,
        Fut: Future<Output = Result<T, PostFailure>>,
    {
        let scope = self
            .scopes
            .scope_for(pool)
            .map_err(|error| TorError::BuildConfig(error.to_string()))?;
        let key = route_pool::site_key(host);
        let result = route_pool::run_attempts(&scope, &key, deadline, connect, |failure| {
            verdict(failure.blame)
        })
        .await;
        match result {
            Ok(stream) => Ok(stream),
            Err(PoolError::Aborted(failure)) => Err(failure.error),
            Err(PoolError::Exhausted {
                last: Some(failure),
            }) => Err(failure.error),
            Err(PoolError::Exhausted { last: None }) => Err(TorError::PostSocksTimeout),
        }
    }
}

fn verdict(blame: PostBlame) -> Verdict {
    match blame {
        PostBlame::ProxyHard => Verdict::ProxyHard,
        PostBlame::ProxySoft => Verdict::ProxySoft,
        PostBlame::NotProxy => Verdict::NotProxy,
    }
}

/// Starts the background task that re-checks quarantined post proxies.
///
/// The probes run through the tunnel the handle currently holds, so a watchdog
/// rebuild is picked up. The task stops when `cancel` fires.
pub(crate) fn spawn_prober(
    pools: Arc<PostPools>,
    handle: TorHandle,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        route_pool::drive_probes(
            move || pools.scopes.scopes(),
            PROBE_INTERVAL,
            move |proxy, deadline| probe_once(handle.clone(), proxy, deadline),
            cancel,
        )
        .await;
    })
}

async fn probe_once(handle: TorHandle, proxy: Arc<ProxyConfig>, deadline: Instant) -> ProbeOutcome {
    let Some(tunnel) = handle.tunnel().await else {
        return ProbeOutcome::Inconclusive;
    };
    match arti_wrapper::probe_post_proxy(&tunnel, &proxy, deadline).await {
        PostProbe::Alive => ProbeOutcome::Alive,
        PostProbe::Dead => ProbeOutcome::Dead,
        PostProbe::Inconclusive => ProbeOutcome::Inconclusive,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    fn pool(members: &[&str]) -> ProxyPool {
        ProxyPool::new(members.iter().map(|m| m.parse().unwrap()).collect()).unwrap()
    }

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    fn failure(blame: PostBlame) -> PostFailure {
        PostFailure {
            error: TorError::PostSocksTimeout,
            blame,
        }
    }

    #[tokio::test]
    async fn rotates_past_a_dead_member_and_returns_the_working_stream() {
        let pools = PostPools::new();
        let pool = pool(&["192.0.2.1:1080", "192.0.2.2:1080"]);
        let tried = Mutex::new(Vec::new());
        let value = pools
            .connect_via(&pool, "www.example.com", far(), |proxy, _| {
                let first = {
                    let mut tried = tried.lock().unwrap();
                    tried.push(proxy.host.clone());
                    tried.len() == 1
                };
                async move {
                    if first {
                        Err(failure(PostBlame::ProxyHard))
                    } else {
                        Ok(proxy.host.clone())
                    }
                }
            })
            .await
            .unwrap();
        let tried = tried.into_inner().unwrap();
        assert_eq!(tried.len(), 2);
        assert_ne!(tried[0], tried[1]);
        assert_eq!(value, tried[1]);
    }

    #[tokio::test]
    async fn a_failure_that_is_not_the_proxys_is_returned_without_rotation() {
        let pools = PostPools::new();
        let pool = pool(&["192.0.2.1:1080", "192.0.2.2:1080"]);
        let calls = Mutex::new(0);
        let result: Result<(), TorError> = pools
            .connect_via(&pool, "example.com", far(), |_, _| {
                *calls.lock().unwrap() += 1;
                async { Err(failure(PostBlame::NotProxy)) }
            })
            .await;
        assert!(matches!(result, Err(TorError::PostSocksTimeout)));
        assert_eq!(*calls.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn an_exhausted_pool_fails_instead_of_going_direct() {
        let pools = PostPools::new();
        let pool = pool(&["192.0.2.1:1080", "192.0.2.2:1080", "192.0.2.3:1080"]);
        let calls = Mutex::new(0);
        let result: Result<(), TorError> = pools
            .connect_via(&pool, "example.com", far(), |_, _| {
                *calls.lock().unwrap() += 1;
                async { Err(failure(PostBlame::ProxySoft)) }
            })
            .await;
        assert!(result.is_err());
        assert_eq!(*calls.lock().unwrap(), 3, "every member is tried once");
    }

    #[tokio::test]
    async fn a_site_stays_on_the_member_that_served_it() {
        let pools = PostPools::new();
        let pool = pool(&["192.0.2.1:1080", "192.0.2.2:1080", "192.0.2.3:1080"]);
        let mut served = Vec::new();
        for _ in 0..3 {
            let host = pools
                .connect_via(&pool, "a.example.com", far(), |proxy, _| async move {
                    Ok::<_, PostFailure>(proxy.host.clone())
                })
                .await
                .unwrap();
            served.push(host);
        }
        assert!(served.windows(2).all(|pair| pair[0] == pair[1]));
        let sibling = pools
            .connect_via(&pool, "b.example.com", far(), |proxy, _| async move {
                Ok::<_, PostFailure>(proxy.host.clone())
            })
            .await
            .unwrap();
        assert_eq!(
            sibling, served[0],
            "subdomains share the registrable domain"
        );
    }

    #[tokio::test]
    async fn pools_with_the_same_members_share_rotation_state() {
        let pools = PostPools::new();
        let first = pool(&["192.0.2.1:1080", "192.0.2.2:1080"]);
        let reordered = pool(&["192.0.2.2:1080", "192.0.2.1:1080"]);
        let host = pools
            .connect_via(&first, "example.com", far(), |proxy, _| async move {
                Ok::<_, PostFailure>(proxy.host.clone())
            })
            .await
            .unwrap();
        let again = pools
            .connect_via(&reordered, "example.com", far(), |proxy, _| async move {
                Ok::<_, PostFailure>(proxy.host.clone())
            })
            .await
            .unwrap();
        assert_eq!(host, again);
        assert_eq!(pools.scopes.scopes().len(), 1);
    }
}
