use std::fmt;
use std::sync::Arc;

use serde::de::{SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::socks5::Socks5Endpoint;

/// Largest accepted pool; larger lists are an operator mistake, not a feature.
pub const MAX_POOL_SIZE: usize = 32;

/// Non-empty list of distinct proxy endpoints used as one hop (pre or post).
///
/// Members that differ only in protocol or credentials stay distinct; exact
/// duplicates are rejected because a rotator would silently merge them.
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyPool(Arc<[Socks5Endpoint]>);

impl ProxyPool {
    /// Builds a pool, rejecting empty lists, exact duplicates and oversized lists.
    pub fn new(members: Vec<Socks5Endpoint>) -> Result<Self, String> {
        if members.is_empty() {
            return Err("proxy pool must not be empty; omit the field or use `none`".to_owned());
        }
        if members.len() > MAX_POOL_SIZE {
            return Err(format!("proxy pool holds at most {MAX_POOL_SIZE} members"));
        }
        for (index, member) in members.iter().enumerate() {
            if members[..index].contains(member) {
                return Err("proxy pool contains an exact duplicate member".to_owned());
            }
        }
        Ok(Self(members.into()))
    }

    /// Pool members in configuration order.
    pub fn members(&self) -> &[Socks5Endpoint] {
        &self.0
    }

    /// Number of members; never zero.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// The only member of a one-member pool, `None` for larger pools.
    pub fn sole_member(&self) -> Option<&Socks5Endpoint> {
        match &*self.0 {
            [only] => Some(only),
            _ => None,
        }
    }

    /// Always `false`: a pool is non-empty by construction.
    pub fn is_empty(&self) -> bool {
        false
    }
}

impl From<Socks5Endpoint> for ProxyPool {
    fn from(endpoint: Socks5Endpoint) -> Self {
        Self(Arc::from(vec![endpoint]))
    }
}

impl fmt::Debug for ProxyPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.0.iter()).finish()
    }
}

impl Serialize for ProxyPool {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for member in self.0.iter() {
            seq.serialize_element(member)?;
        }
        seq.end()
    }
}

struct PoolVisitor;

impl<'de> Visitor<'de> for PoolVisitor {
    type Value = ProxyPool;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an array of proxy endpoints")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut members = Vec::new();
        while let Some(member) = seq.next_element::<Socks5Endpoint>()? {
            members.push(member);
        }
        ProxyPool::new(members).map_err(serde::de::Error::custom)
    }
}

impl<'de> Deserialize<'de> for ProxyPool {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_seq(PoolVisitor)
    }
}

/// Account-level replacement of the global pool: disabled or an explicit list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolOverride {
    /// Disable the hop, including an inherited global pool.
    Disabled,
    /// Use exactly this pool instead of the global one.
    Pool(ProxyPool),
}

/// Applies an account setting over the global one.
pub fn resolve_pool(
    global: Option<&ProxyPool>,
    account: Option<&PoolOverride>,
) -> Option<ProxyPool> {
    match account {
        Some(PoolOverride::Pool(pool)) => Some(pool.clone()),
        Some(PoolOverride::Disabled) => None,
        None => global.cloned(),
    }
}

impl Serialize for PoolOverride {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Disabled => serializer.serialize_str("none"),
            Self::Pool(pool) => pool.serialize(serializer),
        }
    }
}

struct OverrideVisitor;

impl<'de> Visitor<'de> for OverrideVisitor {
    type Value = PoolOverride;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the literal `none` or an array of proxy endpoints")
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Err(E::custom("use the literal `none` scalar or an array"))
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Err(E::custom("use the literal `none` scalar or an array"))
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        if value == "none" {
            Ok(PoolOverride::Disabled)
        } else {
            Err(E::custom(
                "a single endpoint is no longer accepted; write an array of endpoints or `none`",
            ))
        }
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Self::Value, A::Error> {
        PoolVisitor.visit_seq(seq).map(PoolOverride::Pool)
    }
}

impl<'de> Deserialize<'de> for PoolOverride {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(OverrideVisitor)
    }
}

/// Serde adapter for an account-level `Option<PoolOverride>` field.
pub mod pool_field {
    use super::{Deserialize, Deserializer, PoolOverride, Serializer};
    use serde::ser::Serialize as _;

    /// Serializes the setting; `None` is skipped by the field attribute.
    pub fn serialize<S: Serializer>(
        value: &Option<PoolOverride>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            None => serializer.serialize_str("inherit"),
            Some(value) => value.serialize(serializer),
        }
    }

    /// Deserializes an explicitly present setting.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<PoolOverride>, D::Error> {
        PoolOverride::deserialize(deserializer).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(value: &str) -> Socks5Endpoint {
        value.parse().unwrap()
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
    struct Global {
        pre_proxies: ProxyPool,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
    struct Account {
        #[serde(default, skip_serializing_if = "Option::is_none", with = "pool_field")]
        post_proxies: Option<PoolOverride>,
    }

    #[test]
    fn pool_rejects_empty_duplicate_and_oversized_lists() {
        assert!(ProxyPool::new(Vec::new()).is_err());
        let duplicate = vec![endpoint("192.0.2.1:1080"), endpoint("192.0.2.1:1080")];
        assert!(ProxyPool::new(duplicate).is_err());
        let oversized = (0..=MAX_POOL_SIZE)
            .map(|index| endpoint(&format!("192.0.2.1:{}", 1000 + index)))
            .collect();
        assert!(ProxyPool::new(oversized).is_err());
    }

    #[test]
    fn same_address_with_other_protocol_or_credentials_is_distinct() {
        let pool = ProxyPool::new(vec![
            endpoint("192.0.2.1:1080"),
            endpoint("http://192.0.2.1:1080"),
            endpoint("192.0.2.1:1080|alice:secret"),
        ])
        .unwrap();
        assert_eq!(pool.len(), 3);
        assert!(!pool.is_empty());
    }

    #[test]
    fn debug_never_prints_credentials() {
        let pool: ProxyPool = endpoint("192.0.2.1:1080|alice:secret").into();
        assert!(!format!("{pool:?}").contains("secret"));
    }

    #[test]
    fn global_pool_round_trips_through_ktav() {
        let record = Global {
            pre_proxies: ProxyPool::new(vec![
                endpoint("192.0.2.1:1080"),
                endpoint("http://[2001:db8::1]:80|user:password"),
                endpoint("[2001:db8::2]:1080|user:password"),
            ])
            .unwrap(),
        };
        let encoded = ktav::to_string(&record).unwrap();
        assert_eq!(ktav::from_str::<Global>(&encoded).unwrap(), record);
    }

    #[test]
    fn account_override_accepts_none_and_arrays_and_rejects_scalars() {
        let none: Account = ktav::from_str("post_proxies: none\n").unwrap();
        assert_eq!(none.post_proxies, Some(PoolOverride::Disabled));
        let list: Account =
            ktav::from_str("post_proxies: [\n    192.0.2.1:1080\n    http://192.0.2.2:8080\n]\n")
                .unwrap();
        let Some(PoolOverride::Pool(pool)) = &list.post_proxies else {
            panic!("expected a pool");
        };
        assert_eq!(pool.len(), 2);
        assert!(ktav::from_str::<Account>("post_proxies: 192.0.2.1:1080\n").is_err());
        assert!(ktav::from_str::<Account>("post_proxies: []\n").is_err());
        let encoded = ktav::to_string(&list).unwrap();
        assert_eq!(ktav::from_str::<Account>(&encoded).unwrap(), list);
    }

    #[test]
    fn resolve_pool_applies_account_over_global() {
        let global: ProxyPool = endpoint("192.0.2.1:1080").into();
        let own: ProxyPool = endpoint("192.0.2.2:1080").into();
        assert_eq!(resolve_pool(Some(&global), None), Some(global.clone()));
        assert_eq!(resolve_pool(None, None), None);
        assert_eq!(
            resolve_pool(Some(&global), Some(&PoolOverride::Disabled)),
            None
        );
        assert_eq!(
            resolve_pool(Some(&global), Some(&PoolOverride::Pool(own.clone()))),
            Some(own)
        );
    }
}
