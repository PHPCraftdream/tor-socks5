//! Route resolution for the pre and post proxy pools, and the Tor connect
//! step that applies a post pool.

use std::sync::Arc;

use arti_wrapper::{PostPools, RoutedStream, Socks5PreEndpoint, TorTunnel};
use auth::UsersConfig;
use proxy_config::{PoolOverride, ProxyPool, Socks5Endpoint};

/// Отклонить пул прокси там, где он не поддерживается, до запуска сети.
pub(crate) fn reject_unsupported_pool(
    setting: &Option<ProxyPool>,
    scope: &str,
) -> anyhow::Result<()> {
    if setting.is_some() {
        anyhow::bail!("{scope} proxy pool is not supported here; remove it");
    }
    Ok(())
}

/// Tor clients that can run next to the main one, one per extra pre endpoint.
pub(crate) const MAX_PRE_OWNERS: usize = 15;

/// Client-side description of a pre pool member for the Tor client.
pub(crate) fn pre_endpoint(endpoint: &Socks5Endpoint) -> Socks5PreEndpoint {
    Socks5PreEndpoint::from_pool_member(endpoint)
}

/// Rejects pre routes that would need more Tor clients than the process hosts.
///
/// The main client uses one member of the global pool; every other distinct
/// pre endpoint needs a client of its own, and so does a direct route next to
/// a global pool.
pub(crate) fn validate_pre_capacity(
    users: &UsersConfig,
    global: Option<&ProxyPool>,
) -> anyhow::Result<()> {
    let mut distinct: Vec<Socks5Endpoint> = Vec::new();
    let mut direct_next_to_pool = false;
    let mut add = |pool: &ProxyPool| {
        for member in pool.members() {
            if !distinct.contains(member) {
                distinct.push(member.clone());
            }
        }
    };
    if let Some(pool) = global {
        add(pool);
    }
    for user in users.users.iter().filter(|user| user.is_enabled) {
        match proxy_config::resolve_pool(global, user.pre_proxies.as_ref()) {
            Some(pool) => add(&pool),
            None => direct_next_to_pool |= global.is_some(),
        }
    }
    let clients = distinct.len().saturating_sub(usize::from(global.is_some()))
        + usize::from(direct_next_to_pool);
    if clients > MAX_PRE_OWNERS {
        anyhow::bail!(
            "pre_proxies need {clients} extra Tor clients but the limit is {MAX_PRE_OWNERS} \
             (one per distinct pre endpoint besides the main client's)"
        );
    }
    Ok(())
}

/// Проверить все включённые маршруты до запуска сети.
pub(crate) fn validate_account_routes(
    users: &UsersConfig,
    global_pre: Option<&ProxyPool>,
    global_post: Option<&ProxyPool>,
    dns: bool,
    upstream: bool,
) -> anyhow::Result<()> {
    for user in users.users.iter().filter(|user| user.is_enabled) {
        resolve_account_route(
            global_pre,
            global_post,
            user.pre_proxies.as_ref(),
            user.post_proxies.as_ref(),
            dns,
            upstream,
        )?;
    }
    validate_pre_capacity(users, global_pre)
}

/// Собственный снимок разрешённых маршрутов.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AdmittedRoute {
    pub(crate) pre: Option<ProxyPool>,
    pub(crate) post: Option<ProxyPool>,
}

/// Разрешить pre и post независимо.
pub(crate) fn resolve_account_route(
    global_pre: Option<&ProxyPool>,
    global_post: Option<&ProxyPool>,
    account_pre: Option<&PoolOverride>,
    account_post: Option<&PoolOverride>,
    dns: bool,
    upstream: bool,
) -> anyhow::Result<AdmittedRoute> {
    let pre = proxy_config::resolve_pool(global_pre, account_pre);
    let post = proxy_config::resolve_pool(global_post, account_post);
    if upstream && global_pre.is_some() {
        anyhow::bail!("global pre_proxies cannot be combined with upstream egress");
    }
    if pre.is_some() && (dns || upstream) {
        anyhow::bail!("pre_proxies cannot be combined with DNS listener or upstream egress");
    }
    validate_post_compatibility(post.is_some(), dns, upstream)?;
    Ok(AdmittedRoute { pre, post })
}

/// Маршрут определяется только из допущенного снимка.
pub(crate) fn resolve_admitted_route(
    global_pre: Option<&ProxyPool>,
    global_post: Option<&ProxyPool>,
    lease: Option<&auth::AdmissionLease>,
    dns: bool,
    upstream: bool,
) -> anyhow::Result<AdmittedRoute> {
    resolve_account_route(
        global_pre,
        global_post,
        lease.and_then(|lease| lease.pre_proxies()),
        lease.and_then(|lease| lease.post_proxies()),
        dns,
        upstream,
    )
}

/// Не допустить обход post через независимый DNS или upstream вместо Tor.
pub(crate) fn validate_post_compatibility(
    post: bool,
    dns: bool,
    upstream: bool,
) -> anyhow::Result<()> {
    if post && (dns || upstream) {
        anyhow::bail!("post_proxies cannot be combined with DNS listener or upstream egress");
    }
    Ok(())
}

/// Выбрать один маршрут; ошибка post не запускает прямой путь.
pub(crate) async fn select_post_route<T, D, P>(use_post: bool, direct: D, post: P) -> T
where
    D: std::future::Future<Output = T>,
    P: std::future::Future<Output = T>,
{
    if use_post {
        post.await
    } else {
        direct.await
    }
}

/// Установить соединение через Tor и необязательный post-пул.
///
/// Члены пула перебираются по очереди в пределах общего срока; исчерпанный
/// пул — ошибка, прямой путь не используется.
///
/// cancel-safe: NO — при отмене частично открытый поток отбрасывается.
pub(crate) async fn connect_tor_route(
    tor: &arti_wrapper::TorTunnel,
    post: Option<&ProxyPool>,
    pools: &PostPools,
    host: &str,
    port: u16,
) -> Result<arti_wrapper::RoutedStream, arti_wrapper::TorError> {
    let post_connect = async {
        let Some(pool) = post else {
            return Err(arti_wrapper::TorError::PostSocks(
                socks5_proto::client::Error::InvalidInput,
            ));
        };
        pools
            .connect(
                tor,
                pool,
                host,
                port,
                std::time::Instant::now() + crate::upstream::UPSTREAM_SETUP_DEADLINE,
            )
            .await
    };
    let direct_connect = async {
        tor.connect(host, port)
            .await
            .map(arti_wrapper::RoutedStream::from)
    };
    select_post_route(post.is_some(), direct_connect, post_connect).await
}

// RPITIT + Send: внутренний интерфейс без динамической диспетчеризации.
pub(crate) trait TorConnector {
    fn connect<'a>(
        &'a mut self,
        tor: &'a TorTunnel,
        post: Option<&'a ProxyPool>,
        host: &'a str,
        port: u16,
    ) -> impl std::future::Future<Output = arti_wrapper::Result<RoutedStream>> + Send + 'a;
}

/// The connector of the running server: Tor plus the shared post pools.
pub(crate) struct RealTorConnector {
    pools: Arc<PostPools>,
}

impl RealTorConnector {
    pub(crate) fn new(pools: Arc<PostPools>) -> Self {
        Self { pools }
    }
}

impl TorConnector for RealTorConnector {
    fn connect<'a>(
        &'a mut self,
        tor: &'a TorTunnel,
        post: Option<&'a ProxyPool>,
        host: &'a str,
        port: u16,
    ) -> impl std::future::Future<Output = arti_wrapper::Result<RoutedStream>> + Send + 'a {
        connect_tor_route(tor, post, &self.pools, host, port)
    }
}

#[cfg(test)]
#[path = "route_tests.rs"]
mod endpoint_guard_tests;
