//! Where an accepted connection goes: Tor, through a post proxy pool when one
//! applies to the account.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use arti_wrapper::{PostPools, RoutedStream, TorTunnel};
use proxy_config::{PoolOverride, ProxyPool};
use resocks5_net::connect::HostPort;
use tokio_util::compat::FuturesAsyncReadCompatExt;

use super::bridges::EgressConnector;

/// Budget for opening a stream through a post pool, members tried in turn.
const POST_SETUP_DEADLINE: Duration = Duration::from_secs(30);

/// Post proxy routing of the running engine.
#[derive(Clone, Default)]
pub(crate) struct PostRouting {
    /// The global post pool of the config; an account setting overrides it.
    pub global: Option<Arc<ProxyPool>>,
    /// Rotation state of the pools; `None` when no post pool can apply to any
    /// connection.
    pub pools: Option<Arc<PostPools>>,
}

/// The egress of the running engine: its Tor tunnel and the post routing.
#[derive(Clone)]
pub(super) struct RoutedTor {
    tunnel: TorTunnel,
    post: PostRouting,
}

impl RoutedTor {
    pub(super) fn new(tunnel: TorTunnel, post: PostRouting) -> Self {
        Self { tunnel, post }
    }
}

impl EgressConnector for RoutedTor {
    /// An exhausted post pool is an error: a configured post route never
    /// falls back to a direct Tor stream.
    async fn open_egress(
        self,
        target: HostPort<'_>,
        account_post: Option<&PoolOverride>,
    ) -> Result<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static> {
        let stream = match proxy_config::resolve_pool(self.post.global.as_deref(), account_post) {
            Some(pool) => {
                let pools =
                    self.post.pools.as_ref().ok_or_else(|| {
                        anyhow!("a post proxy pool applies but no pool state runs")
                    })?;
                pools
                    .connect(
                        &self.tunnel,
                        &pool,
                        target.host,
                        target.port,
                        Instant::now() + POST_SETUP_DEADLINE,
                    )
                    .await
                    .context("post proxy connect failed")?
            }
            None => RoutedStream::from(
                TorTunnel::connect(&self.tunnel, target.host, target.port)
                    .await
                    .context("Tor connect failed")?,
            ),
        };
        Ok(stream.compat())
    }
}

#[cfg(test)]
mod tests {
    use arti_wrapper::Settings;
    use proxy_config::Socks5Endpoint;

    use super::*;

    const BRIDGE: &str = "192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01";

    /// A tunnel that refuses every stream at once with `BootstrapRequired`: no network.
    fn tunnel(dir: &std::path::Path) -> TorTunnel {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
        TorTunnel::create_manual_with(Settings {
            bridges: vec![BRIDGE.parse().unwrap()],
            state_dir: Some(dir.join("state")),
            ..Default::default()
        })
        .unwrap()
    }

    fn pool() -> Arc<ProxyPool> {
        Arc::new("192.0.2.9:1080".parse::<Socks5Endpoint>().unwrap().into())
    }

    /// The error chain of a dial through `post` for an account setting.
    async fn failure(post: PostRouting, account: Option<&PoolOverride>) -> String {
        let dir = tempfile::tempdir().unwrap();
        let egress = RoutedTor::new(tunnel(dir.path()), post);
        let target = HostPort::parse("example.com:443").unwrap();
        let opened =
            tokio::time::timeout(Duration::from_secs(10), egress.open_egress(target, account))
                .await
                .expect("a manual tunnel refuses at once");
        match opened {
            Ok(_) => panic!("a tunnel that never bootstrapped cannot open a stream"),
            Err(error) => format!("{error:#}"),
        }
    }

    #[tokio::test]
    async fn an_applicable_pool_without_state_is_an_error_not_a_direct_stream() {
        let post = PostRouting {
            global: Some(pool()),
            pools: None,
        };
        let error = failure(post, None).await;
        assert!(error.contains("no pool state runs"), "{error}");
        assert!(!error.contains("Tor connect failed"), "{error}");
    }

    #[tokio::test]
    async fn a_pool_that_cannot_serve_fails_as_a_post_error_never_going_direct() {
        let post = PostRouting {
            global: Some(pool()),
            pools: Some(Arc::new(PostPools::new())),
        };
        let error = failure(post, None).await;
        assert!(error.contains("post proxy connect failed"), "{error}");
        assert!(!error.contains("Tor connect failed"), "{error}");
    }

    #[tokio::test]
    async fn an_account_pool_applies_without_a_global_one() {
        let post = PostRouting {
            global: None,
            pools: Some(Arc::new(PostPools::new())),
        };
        let own = PoolOverride::Pool((*pool()).clone());
        let error = failure(post, Some(&own)).await;
        assert!(error.contains("post proxy connect failed"), "{error}");
    }

    #[tokio::test]
    async fn no_pool_or_a_disabled_one_means_the_plain_tor_stream() {
        let none = PostRouting::default();
        assert!(failure(none, None).await.contains("Tor connect failed"));
        let with_global = PostRouting {
            global: Some(pool()),
            pools: Some(Arc::new(PostPools::new())),
        };
        let error = failure(with_global, Some(&PoolOverride::Disabled)).await;
        assert!(error.contains("Tor connect failed"), "{error}");
    }
}
