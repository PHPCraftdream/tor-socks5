//! The Tor leg of an admitted connection: picks the Tor client that carries
//! it (the main one, an owner, or a member of a pre pool) and opens the
//! stream, applying the post pool on top.

use std::sync::Arc;

use arti_wrapper::{RoutedStream, TorError};
use proxy_config::ProxyPool;
use resocks5_net::types::ProxyConfig;
use route_pool::{PoolError, Verdict};
use tokio::time::{timeout_at, Instant};
use tracing::info;

use super::owners::{self, Owner, OwnerRegistry};
use super::pre_pool;
use crate::route::{pre_endpoint, TorConnector};
use crate::tor_watchdog::TorHandle;

const TOR_TIMEOUT: &str = "истекло время подключения Tor";
const OWNER_TIMEOUT: &str = "истекло время подключения владельца";

/// What the Tor leg needs to know about one connection.
pub(super) struct TorLeg<'a> {
    pub(super) handle: &'a TorHandle,
    pub(super) registry: Option<&'a Arc<OwnerRegistry>>,
    /// The global pre pool the main client was built for.
    pub(super) global_pre: Option<&'a ProxyPool>,
    /// The pre pool of this connection once the account is applied.
    pub(super) pre: Option<&'a ProxyPool>,
    pub(super) post: Option<&'a ProxyPool>,
    /// Whether the connection carries an admission, which account routes need.
    pub(super) admitted: bool,
}

/// Why no stream was opened.
pub(super) enum Failure {
    /// The route is not allowed for this connection or its client could not start.
    Forbidden,
    /// The Tor client is gone, which only happens while shutting down.
    Unavailable,
    /// The setup deadline ran out.
    TimedOut(&'static str),
    /// The owner registry is closing.
    Closed,
    /// Tor failed to open the stream.
    Connect(TorError),
}

enum AttemptError {
    Unavailable,
    TimedOut(&'static str),
    Closed,
    Connect(TorError),
}

impl From<AttemptError> for Failure {
    fn from(error: AttemptError) -> Self {
        match error {
            AttemptError::Unavailable => Self::Unavailable,
            AttemptError::TimedOut(message) => Self::TimedOut(message),
            AttemptError::Closed => Self::Closed,
            AttemptError::Connect(error) => Self::Connect(error),
        }
    }
}

enum Plan<'a> {
    /// The main client, without a registry.
    Global,
    /// A client without a pre proxy, next to a global pre pool.
    Direct(&'a Arc<OwnerRegistry>),
    /// Members of a pre pool, one Tor client each.
    Pool(&'a Arc<OwnerRegistry>, &'a ProxyPool),
}

fn select_plan<'a>(leg: &TorLeg<'a>) -> Result<Plan<'a>, Failure> {
    let differs = leg.pre != leg.global_pre;
    // A route that differs from the global one comes from an account's
    // admission and runs on a client the registry owns.
    if differs && (leg.registry.is_none() || !leg.admitted) {
        return Err(Failure::Forbidden);
    }
    match (leg.pre, leg.registry) {
        (None, _) if leg.global_pre.is_none() => Ok(Plan::Global),
        (None, Some(registry)) => Ok(Plan::Direct(registry)),
        (Some(pool), _) if !differs && pool.sole_member().is_some() => Ok(Plan::Global),
        (Some(pool), Some(registry)) => Ok(Plan::Pool(registry, pool)),
        (_, None) => Err(Failure::Forbidden),
    }
}

/// Opens a stream to `host:port` through Tor.
///
/// The connection is closed to its pools: a pre pool is walked member by
/// member, a post pool is applied by the connector, and an exhausted pool is
/// an error, never a reason to go direct.
///
/// cancel-safe: NO — cancellation drops the attempt in flight.
pub(super) async fn connect<C: TorConnector + Send>(
    leg: &TorLeg<'_>,
    connector: &mut C,
    host: &str,
    port: u16,
) -> Result<RoutedStream, Failure> {
    let deadline = Instant::now() + owners::SETUP_DEADLINE;
    match select_plan(leg)? {
        Plan::Global => {
            let owner = Owner::global(leg.handle.clone());
            Ok(attempt(leg, &owner, connector, host, port, deadline).await?)
        }
        Plan::Direct(registry) => {
            let owner = match timeout_at(deadline, registry.select_endpoint(None)).await {
                Ok(Ok(owner)) => owner,
                _ => return Err(Failure::Forbidden),
            };
            Ok(attempt(leg, &owner, connector, host, port, deadline).await?)
        }
        Plan::Pool(registry, pool) => {
            pooled(leg, registry, pool, connector, host, port, deadline).await
        }
    }
}

/// One stream attempt on one client.
async fn attempt<C: TorConnector + Send>(
    leg: &TorLeg<'_>,
    owner: &Owner,
    connector: &mut C,
    host: &str,
    port: u16,
    deadline: Instant,
) -> Result<RoutedStream, AttemptError> {
    let handle = leg.handle;
    let global = owner.global_handle().is_some();
    if global {
        handle.bridge_refresh().request();
    }
    info!(host = ?host, port = port, "tunneling through Tor");
    // Read the *current* tunnel: a watchdog rebuild swaps the slot, and new
    // connections must pick up the replacement. None only while the server
    // is draining the slot at shutdown.
    let tor = timeout_at(deadline, owner.tunnel())
        .await
        .unwrap_or(None)
        .ok_or(AttemptError::Unavailable)?;
    // Every attempt bumps the counter so the watchdog can tell "no traffic"
    // from "circuits failing"; a success stamps the last-good time.
    if global {
        handle.health().record_attempt();
    }
    let result = if global {
        let connecting = handle
            .bridge_refresh()
            .track_connection(connector.connect(&tor, leg.post, host, port));
        match timeout_at(deadline, connecting).await {
            Ok(result) => result,
            Err(_) => return Err(AttemptError::TimedOut(TOR_TIMEOUT)),
        }
    } else {
        let Some(registry) = leg.registry else {
            return Err(AttemptError::Closed);
        };
        tokio::select! {
            biased;
            _ = registry.cancelled() => return Err(AttemptError::Closed),
            result = timeout_at(deadline, connector.connect(&tor, leg.post, host, port)) => {
                match result {
                    Ok(result) => result,
                    Err(_) => return Err(AttemptError::TimedOut(OWNER_TIMEOUT)),
                }
            }
        }
    };
    match result {
        Ok(stream) => {
            if global {
                handle.health().record_success();
                handle.health().record_success_target(host, port);
            }
            Ok(stream)
        }
        Err(error) => {
            // Data collection for the watchdog only; it needs the RAW `TorError`.
            if global {
                crate::tor_watchdog::classify_and_record(&error, handle.health());
                handle.bridge_refresh().request_after_failure(&error);
            }
            Err(AttemptError::Connect(error))
        }
    }
}

/// Why a pre pool member did not carry the connection.
enum MemberFailure {
    /// Its client is still starting while another member is ready.
    Skip,
    /// Its client did not finish starting in time.
    Waiting,
    /// Its client could not be started.
    Owner,
    /// The owner registry is closing.
    Closed,
    Attempt(AttemptError),
}

fn verdict(failure: &MemberFailure) -> Verdict {
    match failure {
        MemberFailure::Skip => Verdict::Skip,
        MemberFailure::Waiting => Verdict::ProxySoft,
        // A client that cannot start behind this proxy counts like a dead
        // proxy; the background probe brings it back.
        MemberFailure::Owner => Verdict::ProxyHard,
        MemberFailure::Closed => Verdict::NotProxy,
        MemberFailure::Attempt(AttemptError::Connect(error))
            if arti_wrapper::is_pre_path_failure(error) =>
        {
            Verdict::ProxyHard
        }
        MemberFailure::Attempt(AttemptError::TimedOut(_)) => Verdict::ProxySoft,
        MemberFailure::Attempt(_) => Verdict::NotProxy,
    }
}

impl From<MemberFailure> for Failure {
    fn from(failure: MemberFailure) -> Self {
        match failure {
            MemberFailure::Skip | MemberFailure::Waiting => Self::TimedOut(OWNER_TIMEOUT),
            MemberFailure::Owner => Self::Forbidden,
            MemberFailure::Closed => Self::Closed,
            MemberFailure::Attempt(error) => error.into(),
        }
    }
}

/// Whether some member of `pool` can carry a connection right now.
async fn any_ready(registry: &OwnerRegistry, pool: &ProxyPool) -> bool {
    for member in pool.members() {
        if registry.is_ready(&Some(pre_endpoint(member))).await {
            return true;
        }
    }
    false
}

/// Walks the members of `pool` for this site until one carries the stream.
///
/// cancel-safe: NO — cancellation drops the attempt in flight.
async fn pooled<C: TorConnector + Send>(
    leg: &TorLeg<'_>,
    registry: &Arc<OwnerRegistry>,
    pool: &ProxyPool,
    connector: &mut C,
    host: &str,
    port: u16,
    deadline: Instant,
) -> Result<RoutedStream, Failure> {
    let scope = registry
        .pre_scopes()
        .scope_for(pool)
        .map_err(|_| Failure::Forbidden)?;
    if leg.pre != leg.global_pre && pool.len() > 1 {
        // An account's own pool is brought up in the background on first use.
        // A single member needs no head start: this connection builds it.
        let members = pool.members().iter().map(pre_endpoint).collect();
        let _ = registry.start_background(members).await;
    }
    // Clients still starting are passed over only while another one is ready.
    let skip_unready = any_ready(registry, pool).await;
    let key = route_pool::site_key(host);
    let connector = tokio::sync::Mutex::new(connector);
    let connector = &connector;
    let result = route_pool::run_attempts_with_budget(
        &scope,
        &key,
        deadline.into_std(),
        pre_pool::ATTEMPT_BUDGET,
        move |proxy, attempt_deadline| async move {
            let attempt_deadline = Instant::from_std(attempt_deadline);
            member_attempt(
                leg,
                registry,
                pool,
                &proxy,
                skip_unready,
                connector,
                host,
                port,
                attempt_deadline,
            )
            .await
        },
        verdict,
    )
    .await;
    match result {
        Ok(stream) => Ok(stream),
        Err(PoolError::Aborted(failure)) => Err(failure.into()),
        Err(PoolError::Exhausted {
            last: Some(failure),
        }) => Err(failure.into()),
        Err(PoolError::Exhausted { last: None }) => Err(Failure::TimedOut(OWNER_TIMEOUT)),
    }
}

#[allow(clippy::too_many_arguments)]
async fn member_attempt<C: TorConnector + Send>(
    leg: &TorLeg<'_>,
    registry: &Arc<OwnerRegistry>,
    pool: &ProxyPool,
    proxy: &Arc<ProxyConfig>,
    skip_unready: bool,
    connector: &tokio::sync::Mutex<&mut C>,
    host: &str,
    port: u16,
    deadline: Instant,
) -> Result<RoutedStream, MemberFailure> {
    let Some(member) = route_pool::find_member(pool, proxy) else {
        return Err(MemberFailure::Skip);
    };
    let pre = Some(pre_endpoint(member));
    if skip_unready && !registry.is_ready(&pre).await {
        return Err(MemberFailure::Skip);
    }
    let owner = match timeout_at(deadline, registry.select_endpoint(pre)).await {
        Ok(Ok(owner)) => owner,
        Ok(Err(_)) if registry.is_closing() => return Err(MemberFailure::Closed),
        Ok(Err(_)) => return Err(MemberFailure::Owner),
        Err(_) => return Err(MemberFailure::Waiting),
    };
    let mut connector = connector.lock().await;
    attempt(leg, &owner, &mut **connector, host, port, deadline)
        .await
        .map_err(MemberFailure::Attempt)
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use arti_wrapper::{Settings, Socks5PreEndpoint, TorTunnel};

    use super::*;

    const BRIDGE: &str = "192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01";

    fn ensure_crypto_provider() {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    fn pool_of(values: &[&str]) -> ProxyPool {
        ProxyPool::new(values.iter().map(|value| value.parse().unwrap()).collect()).unwrap()
    }

    fn endpoint_of(value: &str) -> Socks5PreEndpoint {
        pre_endpoint(&value.parse().unwrap())
    }

    fn settings(dir: &Path, name: &str, pre: Option<Socks5PreEndpoint>) -> Settings {
        Settings {
            pre_endpoint: pre,
            bridges: vec![BRIDGE.parse().unwrap()],
            state_dir: Some(dir.join(name)),
            ..Default::default()
        }
    }

    fn tunnel(dir: &Path, name: &str, pre: Option<Socks5PreEndpoint>) -> TorTunnel {
        ensure_crypto_provider();
        TorTunnel::create_unbootstrapped_with(settings(dir, name, pre)).unwrap()
    }

    /// The main client is bootstrapped through `anchor`.
    fn setup(dir: &Path, anchor: &str) -> (Arc<OwnerRegistry>, TorHandle) {
        ensure_crypto_provider();
        let template = settings(dir, "global", Some(endpoint_of(anchor)));
        let tor = TorTunnel::create_unbootstrapped_with(template.clone()).unwrap();
        let handle = TorHandle::new(tor);
        let registry = Arc::new(OwnerRegistry::new(handle.clone(), template).unwrap());
        (registry, handle)
    }

    /// Real Tor stream errors without any network: an unbootstrapped client
    /// refuses a valid target with `BootstrapRequired` (the pre path) and an
    /// invalid one with an address error (not the pre path).
    async fn errors(dir: &Path, host: &str, count: usize) -> Vec<TorError> {
        let tunnel = tunnel(dir, "errors", None);
        let mut errors = Vec::new();
        for _ in 0..count {
            errors.push(tunnel.connect(host, 443).await.expect_err("no network"));
        }
        errors
    }

    struct Failing {
        calls: Arc<AtomicUsize>,
        errors: Vec<TorError>,
    }

    impl TorConnector for Failing {
        fn connect<'a>(
            &'a mut self,
            _tor: &'a arti_wrapper::TorTunnel,
            _post: Option<&'a ProxyPool>,
            _host: &'a str,
            _port: u16,
        ) -> impl Future<Output = arti_wrapper::Result<RoutedStream>> + Send + 'a {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let error = self.errors.pop().expect("scripted error");
            async move { Err(error) }
        }
    }

    fn leg<'a>(
        handle: &'a TorHandle,
        registry: &'a Arc<OwnerRegistry>,
        global: &'a ProxyPool,
        pre: &'a ProxyPool,
        admitted: bool,
    ) -> TorLeg<'a> {
        TorLeg {
            handle,
            registry: Some(registry),
            global_pre: Some(global),
            pre: Some(pre),
            post: None,
            admitted,
        }
    }

    #[tokio::test]
    async fn the_pre_path_error_fixture_is_what_the_classifier_expects() {
        let dir = tempfile::tempdir().unwrap();
        let pre = errors(dir.path(), "example.com", 1).await.remove(0);
        assert!(arti_wrapper::is_pre_path_failure(&pre));
        let target = errors(dir.path(), "not a valid host", 1).await.remove(0);
        assert!(!arti_wrapper::is_pre_path_failure(&target));
    }

    #[tokio::test]
    async fn unready_members_are_skipped_while_another_is_ready() {
        let dir = tempfile::tempdir().unwrap();
        let (registry, handle) = setup(dir.path(), "127.0.0.1:1080");
        let pool = pool_of(&["127.0.0.1:1080", "127.0.0.1:1081"]);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut connector = Failing {
            calls: calls.clone(),
            errors: errors(dir.path(), "example.com", 4).await,
        };
        let result = connect(
            &leg(&handle, &registry, &pool, &pool, false),
            &mut connector,
            "example.com",
            443,
        )
        .await;
        assert!(matches!(result, Err(Failure::Connect(_))));
        assert_eq!(calls.load(Ordering::SeqCst), 1, "only the main client ran");
        registry.close().await.unwrap();
    }

    #[tokio::test]
    async fn pre_path_failures_rotate_through_every_ready_member() {
        let dir = tempfile::tempdir().unwrap();
        let (registry, handle) = setup(dir.path(), "127.0.0.1:1080");
        let pool = pool_of(&["127.0.0.1:1080", "127.0.0.1:1081"]);
        let owner = tunnel(dir.path(), "second", Some(endpoint_of("127.0.0.1:1081")));
        registry
            .adopt_started(endpoint_of("127.0.0.1:1081"), owner, false)
            .await;
        let calls = Arc::new(AtomicUsize::new(0));
        let mut connector = Failing {
            calls: calls.clone(),
            errors: errors(dir.path(), "example.com", 4).await,
        };
        let result = connect(
            &leg(&handle, &registry, &pool, &pool, false),
            &mut connector,
            "example.com",
            443,
        )
        .await;
        assert!(matches!(result, Err(Failure::Connect(_))));
        assert_eq!(calls.load(Ordering::SeqCst), 2, "both members were tried");
        registry.close().await.unwrap();
    }

    #[tokio::test]
    async fn failures_that_are_not_the_pre_path_stop_the_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let (registry, handle) = setup(dir.path(), "127.0.0.1:1080");
        let pool = pool_of(&["127.0.0.1:1080", "127.0.0.1:1081"]);
        let owner = tunnel(dir.path(), "second", Some(endpoint_of("127.0.0.1:1081")));
        registry
            .adopt_started(endpoint_of("127.0.0.1:1081"), owner, false)
            .await;
        let calls = Arc::new(AtomicUsize::new(0));
        let mut connector = Failing {
            calls: calls.clone(),
            errors: errors(dir.path(), "not a valid host", 4).await,
        };
        let result = connect(
            &leg(&handle, &registry, &pool, &pool, false),
            &mut connector,
            "example.com",
            443,
        )
        .await;
        assert!(matches!(result, Err(Failure::Connect(_))));
        assert_eq!(calls.load(Ordering::SeqCst), 1, "no rotation");
        let scope = registry.pre_scopes().scope_for(&pool).unwrap();
        assert_eq!(scope.candidates("example.com").len(), 2);
        registry.close().await.unwrap();
    }

    #[tokio::test]
    async fn members_whose_clients_cannot_start_are_failed_without_dialling() {
        let dir = tempfile::tempdir().unwrap();
        let (registry, handle) = setup(dir.path(), "127.0.0.1:1080");
        let global = pool_of(&["127.0.0.1:1080"]);
        let account = pool_of(&["127.0.0.1:1081", "127.0.0.1:1082"]);
        for (index, address) in ["127.0.0.1:1081", "127.0.0.1:1082"].into_iter().enumerate() {
            let owner = tunnel(
                dir.path(),
                &format!("failed{index}"),
                Some(endpoint_of(address)),
            );
            registry
                .adopt_started(endpoint_of(address), owner, true)
                .await;
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let mut connector = Failing {
            calls: calls.clone(),
            errors: Vec::new(),
        };
        for _ in 0..3 {
            let result = connect(
                &leg(&handle, &registry, &global, &account, true),
                &mut connector,
                "example.com",
                443,
            )
            .await;
            assert!(matches!(result, Err(Failure::Forbidden)));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let scope = registry.pre_scopes().scope_for(&account).unwrap();
        for member in account.members() {
            let proxy = route_pool::proxy_config(member).unwrap();
            assert!(scope.is_quarantined(&proxy), "three failures quarantine");
        }
        registry.close().await.unwrap();
    }

    #[tokio::test]
    async fn route_plans_follow_the_pool_and_the_admission() {
        let dir = tempfile::tempdir().unwrap();
        let (registry, handle) = setup(dir.path(), "127.0.0.1:1080");
        let single = pool_of(&["127.0.0.1:1080"]);
        let several = pool_of(&["127.0.0.1:1080", "127.0.0.1:1081"]);
        let own = pool_of(&["127.0.0.1:1090"]);
        let base = |global, pre, admitted| TorLeg {
            handle: &handle,
            registry: Some(&registry),
            global_pre: global,
            pre,
            post: None,
            admitted,
        };
        assert!(matches!(
            select_plan(&base(None, None, false)),
            Ok(Plan::Global)
        ));
        assert!(matches!(
            select_plan(&base(Some(&single), Some(&single), false)),
            Ok(Plan::Global)
        ));
        assert!(matches!(
            select_plan(&base(Some(&several), Some(&several), false)),
            Ok(Plan::Pool(..))
        ));
        assert!(matches!(
            select_plan(&base(Some(&single), None, true)),
            Ok(Plan::Direct(_))
        ));
        assert!(matches!(
            select_plan(&base(Some(&single), Some(&own), true)),
            Ok(Plan::Pool(..))
        ));
        assert!(matches!(
            select_plan(&base(Some(&single), None, false)),
            Err(Failure::Forbidden)
        ));
        assert!(matches!(
            select_plan(&base(Some(&single), Some(&own), false)),
            Err(Failure::Forbidden)
        ));
        let without_registry = TorLeg {
            registry: None,
            ..base(Some(&several), Some(&several), false)
        };
        assert!(matches!(
            select_plan(&without_registry),
            Err(Failure::Forbidden)
        ));
        let single_without_registry = TorLeg {
            registry: None,
            ..base(Some(&single), Some(&single), false)
        };
        assert!(matches!(
            select_plan(&single_without_registry),
            Ok(Plan::Global)
        ));
        registry.close().await.unwrap();
    }

    #[test]
    fn member_failures_map_to_rotation_verdicts() {
        assert_eq!(verdict(&MemberFailure::Skip), Verdict::Skip);
        assert_eq!(verdict(&MemberFailure::Waiting), Verdict::ProxySoft);
        assert_eq!(verdict(&MemberFailure::Owner), Verdict::ProxyHard);
        assert_eq!(verdict(&MemberFailure::Closed), Verdict::NotProxy);
        let timed_out = MemberFailure::Attempt(AttemptError::TimedOut(OWNER_TIMEOUT));
        assert_eq!(verdict(&timed_out), Verdict::ProxySoft);
        let unavailable = MemberFailure::Attempt(AttemptError::Unavailable);
        assert_eq!(verdict(&unavailable), Verdict::NotProxy);
        let closed = MemberFailure::Attempt(AttemptError::Closed);
        assert_eq!(verdict(&closed), Verdict::NotProxy);
    }
}
