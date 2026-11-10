use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use client_acl::{ProxyPool, Socks5Endpoint};
use resocks5_net::rating::{QuarantinePolicy, RatingPolicy};
use resocks5_net::rotator::{ProxyRotator, RotatorError, UpstreamProbeClaim};
use resocks5_net::types::{ProxyConfig, ProxyProtocol};

/// How long a site stays assigned to the member that last served it.
const STICKY_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// Upper bound of remembered site assignments per pool.
const STICKY_MAX_ENTRIES: usize = 16_384;
/// Pools kept alive at once; accounts with identical pools share one scope.
const MAX_SCOPES: usize = 64;

/// A pool could not be turned into a rotation scope.
#[derive(Debug)]
pub enum ScopeError {
    /// A member carries credentials the proxy client cannot encode.
    InvalidCredentials,
    /// The rotator refused the member list or policy.
    Rotator(RotatorError),
    /// Too many distinct pools are active at the same time.
    TooManyScopes,
}

impl fmt::Display for ScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCredentials => f.write_str("invalid proxy pool credentials"),
            Self::Rotator(error) => write!(f, "proxy pool rotation setup failed: {error}"),
            Self::TooManyScopes => write!(f, "more than {MAX_SCOPES} distinct proxy pools"),
        }
    }
}

impl std::error::Error for ScopeError {}

/// Client-side proxy description of one configured pool member.
pub fn proxy_config(endpoint: &Socks5Endpoint) -> Result<ProxyConfig, ScopeError> {
    let proxy = ProxyConfig::new(
        endpoint.protocol(),
        endpoint.address().ip().to_string(),
        endpoint.address().port(),
    );
    match endpoint.credentials() {
        Some((user, password)) => proxy
            .try_with_auth(user, password)
            .map_err(|_| ScopeError::InvalidCredentials),
        None => Ok(proxy),
    }
}

/// Rotation state of one pool: ratings, quarantine and site assignments.
///
/// Assignments are shared by everything that uses the same scope, so two
/// accounts with an identical pool see the same member for the same site.
pub struct PoolScope {
    rotator: ProxyRotator,
}

impl PoolScope {
    /// Builds the scope of a pool with the default rating and quarantine policy.
    pub fn new(pool: &ProxyPool) -> Result<Self, ScopeError> {
        Self::with_quarantine(pool, QuarantinePolicy::default())
    }

    fn with_quarantine(pool: &ProxyPool, quarantine: QuarantinePolicy) -> Result<Self, ScopeError> {
        let proxies = pool
            .members()
            .iter()
            .map(proxy_config)
            .collect::<Result<Vec<_>, _>>()?;
        let rotator = ProxyRotator::try_with_quarantine(
            proxies,
            RatingPolicy::default(),
            quarantine,
            STICKY_MAX_ENTRIES,
            STICKY_TTL,
        )
        .map_err(ScopeError::Rotator)?;
        Ok(Self { rotator })
    }

    /// Number of distinct members.
    pub fn len(&self) -> usize {
        self.rotator.len()
    }

    /// Always `false`: a scope is built from a non-empty pool.
    pub fn is_empty(&self) -> bool {
        self.rotator.is_empty()
    }

    /// Members to try for `key`, best first, without repeats.
    ///
    /// Order: the member that last served the site, the site's deterministic
    /// home member, then the rotator's weighted order. Quarantined members are
    /// absent while a healthy one exists; when none is healthy the order still
    /// lists every member, so a fully failed pool keeps being retried.
    pub fn candidates(&self, key: &str) -> Vec<Arc<ProxyConfig>> {
        order_candidates(self.rotator.get_linked(key), key, self.rotator.pick_order())
    }

    /// Records a successful connection and keeps the site on this member.
    pub fn record_success(&self, proxy: &Arc<ProxyConfig>, key: &str) {
        self.rotator.record_success(proxy);
        self.rotator.link_proxy(key, Arc::clone(proxy));
    }

    /// Records a failure of the proxy itself; `hard` counts toward quarantine.
    pub fn record_failure(&self, proxy: &ProxyConfig, hard: bool) {
        if hard {
            if let Some(duration) = self.rotator.record_hard_failure(proxy) {
                tracing::warn!(
                    member = self.member_index(proxy),
                    quarantined_for = ?duration,
                    "proxy pool member quarantined"
                );
            }
        } else {
            self.rotator.record_failure(proxy);
        }
    }

    /// Position of the member in configuration order, for logs that must not
    /// carry addresses or credentials.
    fn member_index(&self, proxy: &ProxyConfig) -> usize {
        self.rotator
            .all_proxies()
            .iter()
            .position(|member| same_member(member, proxy))
            .unwrap_or(usize::MAX)
    }

    /// Claims the quarantined members whose back-off is over.
    pub fn take_probe_claims(&self) -> Vec<UpstreamProbeClaim> {
        self.rotator.take_probe_claims()
    }

    /// Applies a successful probe; stale claims change nothing.
    pub fn probe_succeeded(&self, claim: &UpstreamProbeClaim) -> bool {
        let applied = self.rotator.record_success_for(claim);
        if applied {
            tracing::info!(
                member = self.member_index(&claim.proxy),
                "proxy pool member answered a probe and returned to rotation"
            );
        }
        applied
    }

    /// Applies a failed probe; stale claims change nothing.
    pub fn probe_failed(&self, claim: &UpstreamProbeClaim) -> Option<Duration> {
        self.rotator.record_hard_failure_for(claim)
    }

    /// Whether the member is currently quarantined or on probation.
    pub fn is_quarantined(&self, proxy: &ProxyConfig) -> bool {
        self.rotator.is_quarantined(proxy)
    }

    #[cfg(test)]
    pub(crate) fn make_probe_due(&self, proxy: &Arc<ProxyConfig>) {
        use resocks5_net::rating::{Health, UpstreamState};
        use resocks5_net::rotator::UpstreamHealth;
        let health = Health::new(UpstreamState::Probation, Duration::ZERO, 1, 3);
        let restored = self
            .rotator
            .restore_health(&[UpstreamHealth::new(Arc::clone(proxy), health)]);
        assert_eq!(restored, 1);
    }
}

/// Address, port, protocol tag and credentials of one member.
type MemberIdentity = (String, u16, u8, Option<String>);

/// Shared scopes keyed by the exact member set of a pool.
#[derive(Default)]
pub struct ScopeMap {
    scopes: Mutex<HashMap<Vec<MemberIdentity>, Arc<PoolScope>>>,
}

impl ScopeMap {
    /// Creates an empty map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the scope of `pool`, creating it on first use.
    ///
    /// Pools with the same members in any order share one scope. The lock is
    /// never held across an await point.
    pub fn scope_for(&self, pool: &ProxyPool) -> Result<Arc<PoolScope>, ScopeError> {
        let mut identity: Vec<_> = pool
            .members()
            .iter()
            .map(|member| {
                (
                    member.address().ip().to_string(),
                    member.address().port(),
                    protocol_tag(member.protocol()),
                    member
                        .credentials()
                        .map(|(user, password)| format!("{user}:{password}")),
                )
            })
            .collect();
        identity.sort();
        let mut scopes = self.scopes.lock().expect("scope map lock");
        if let Some(scope) = scopes.get(&identity) {
            return Ok(Arc::clone(scope));
        }
        if scopes.len() >= MAX_SCOPES {
            return Err(ScopeError::TooManyScopes);
        }
        let scope = Arc::new(PoolScope::new(pool)?);
        scopes.insert(identity, Arc::clone(&scope));
        Ok(scope)
    }

    /// Every scope created so far; used to start background probing.
    pub fn scopes(&self) -> Vec<Arc<PoolScope>> {
        self.scopes
            .lock()
            .expect("scope map lock")
            .values()
            .cloned()
            .collect()
    }
}

fn protocol_tag(protocol: ProxyProtocol) -> u8 {
    match protocol {
        ProxyProtocol::Socks5 => 0,
        ProxyProtocol::Http => 1,
        ProxyProtocol::Https => 2,
    }
}

fn same_member(a: &ProxyConfig, b: &ProxyConfig) -> bool {
    a.host == b.host
        && a.port == b.port
        && a.protocol == b.protocol
        && a.user == b.user
        && a.password == b.password
}

/// Deterministic score of a member for a site (FNV-1a, highest score wins).
///
/// Used only to spread sites over members, so a plain non-cryptographic hash
/// is enough; the mapping is stable across restarts and Rust versions.
fn home_score(key: &str, member: &ProxyConfig) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET;
    let mut feed = |bytes: &[u8]| {
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(PRIME);
        }
    };
    feed(key.as_bytes());
    feed(&[0xff]);
    feed(member.host.as_bytes());
    feed(&member.port.to_be_bytes());
    feed(&[protocol_tag(member.protocol)]);
    feed(member.user.as_deref().unwrap_or_default().as_bytes());
    hash
}

/// The member with the highest score among `members` (first wins a tie).
fn home_member<'a>(key: &str, members: &'a [Arc<ProxyConfig>]) -> Option<&'a Arc<ProxyConfig>> {
    let mut best: Option<(u64, &Arc<ProxyConfig>)> = None;
    for member in members {
        let score = home_score(key, member);
        if best.is_none_or(|(top, _)| score > top) {
            best = Some((score, member));
        }
    }
    best.map(|(_, member)| member)
}

/// Combines the sticky member, the home member and the weighted order.
fn order_candidates(
    linked: Option<Arc<ProxyConfig>>,
    key: &str,
    weighted: Vec<Arc<ProxyConfig>>,
) -> Vec<Arc<ProxyConfig>> {
    let mut ordered: Vec<Arc<ProxyConfig>> = Vec::with_capacity(weighted.len() + 1);
    let mut push = |candidate: &Arc<ProxyConfig>| {
        if !ordered.iter().any(|seen| same_member(seen, candidate)) {
            ordered.push(Arc::clone(candidate));
        }
    };
    if let Some(linked) = &linked {
        push(linked);
    }
    if let Some(home) = home_member(key, &weighted) {
        push(home);
    }
    for candidate in &weighted {
        push(candidate);
    }
    ordered
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(members: &[&str]) -> ProxyPool {
        ProxyPool::new(members.iter().map(|m| m.parse().unwrap()).collect()).unwrap()
    }

    fn config(value: &str) -> Arc<ProxyConfig> {
        Arc::new(proxy_config(&value.parse().unwrap()).unwrap())
    }

    #[test]
    fn home_member_is_deterministic_and_spreads_sites() {
        let members = vec![
            config("192.0.2.1:1080"),
            config("192.0.2.2:1080"),
            config("192.0.2.3:1080"),
        ];
        let first = home_member("example.com", &members).unwrap();
        assert!(Arc::ptr_eq(
            first,
            home_member("example.com", &members).unwrap()
        ));
        let used: std::collections::HashSet<_> = (0..64)
            .map(|index| {
                home_member(&format!("site{index}.example"), &members)
                    .unwrap()
                    .host
                    .clone()
            })
            .collect();
        assert!(used.len() > 1, "64 sites must not all map to one member");
    }

    #[test]
    fn removing_a_member_moves_only_its_sites() {
        let all = vec![
            config("192.0.2.1:1080"),
            config("192.0.2.2:1080"),
            config("192.0.2.3:1080"),
        ];
        let without_last = all[..2].to_vec();
        for index in 0..64 {
            let key = format!("site{index}.example");
            let before = home_member(&key, &all).unwrap();
            if before.host != "192.0.2.3" {
                assert_eq!(home_member(&key, &without_last).unwrap().host, before.host);
            }
        }
    }

    #[test]
    fn candidates_put_linked_then_home_first_without_repeats() {
        let weighted = vec![
            config("192.0.2.1:1080"),
            config("192.0.2.2:1080"),
            config("192.0.2.3:1080"),
        ];
        let linked = Arc::clone(&weighted[2]);
        let ordered = order_candidates(Some(Arc::clone(&linked)), "example.com", weighted.clone());
        assert_eq!(ordered.len(), 3);
        assert!(same_member(&ordered[0], &linked));
        let home = home_member("example.com", &weighted).unwrap();
        if !same_member(home, &linked) {
            assert!(same_member(&ordered[1], home));
        }
        let none = order_candidates(None, "example.com", weighted.clone());
        assert!(same_member(
            &none[0],
            home_member("example.com", &weighted).unwrap()
        ));
    }

    #[test]
    fn members_with_other_protocol_or_credentials_stay_distinct() {
        let scope = PoolScope::new(&pool(&[
            "192.0.2.1:1080",
            "http://192.0.2.1:1080",
            "192.0.2.1:1080|alice:secret",
        ]))
        .unwrap();
        assert_eq!(scope.len(), 3);
        assert_eq!(scope.candidates("example.com").len(), 3);
    }

    #[test]
    fn success_keeps_the_site_on_the_serving_member() {
        let scope = PoolScope::new(&pool(&["192.0.2.1:1080", "192.0.2.2:1080"])).unwrap();
        let candidates = scope.candidates("example.com");
        let other = candidates.last().unwrap().clone();
        scope.record_success(&other, "example.com");
        assert!(same_member(&scope.candidates("example.com")[0], &other));
    }

    #[test]
    fn hard_failures_quarantine_a_member_while_others_stay_usable() {
        let scope = PoolScope::new(&pool(&["192.0.2.1:1080", "192.0.2.2:1080"])).unwrap();
        let bad = scope.candidates("example.com")[0].clone();
        for _ in 0..3 {
            scope.record_failure(&bad, true);
        }
        assert!(scope.is_quarantined(&bad));
        let candidates = scope.candidates("example.com");
        assert_eq!(candidates.len(), 1);
        assert!(!same_member(&candidates[0], &bad));
    }

    #[test]
    fn a_fully_quarantined_pool_still_lists_every_member() {
        let scope = PoolScope::new(&pool(&["192.0.2.1:1080", "192.0.2.2:1080"])).unwrap();
        for member in scope.candidates("example.com") {
            for _ in 0..3 {
                scope.record_failure(&member, true);
            }
        }
        assert_eq!(scope.candidates("example.com").len(), 2);
    }

    #[test]
    fn identical_pools_share_one_scope_regardless_of_order() {
        let map = ScopeMap::new();
        let first = map
            .scope_for(&pool(&["192.0.2.1:1080", "192.0.2.2:1080"]))
            .unwrap();
        let second = map
            .scope_for(&pool(&["192.0.2.2:1080", "192.0.2.1:1080"]))
            .unwrap();
        let other = map.scope_for(&pool(&["192.0.2.3:1080"])).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert!(!Arc::ptr_eq(&first, &other));
        assert_eq!(map.scopes().len(), 2);
    }
}
