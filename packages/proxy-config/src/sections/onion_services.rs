//! `onion_services`: onion services hosted through this proxy, each a
//! nickname plus a list of `onion_port=host:port` mappings forwarded to
//! local targets. Mirrors the `listen`/`dns_server.overrides` pattern:
//! a hand-written list deserializer doing cross-entry validation with
//! key-path error messages. proxy-config must not depend on
//! tor-hsservice, so the nickname check here is a lightweight duplicate
//! of the real `tor_hsservice::HsNickname` rules (re-checked at service
//! launch in the app crate).

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Maximum nickname length in bytes (same cap as `tor_hsservice::HsNickname`).
const MAX_NICKNAME_LEN: usize = 25;

/// One onion service published by this proxy (see [`crate::Config::onion_services`]).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct OnionServiceEntry {
    /// Human-readable service name: `[A-Za-z0-9_-]+`, at most 25 bytes.
    /// Validated again by `tor_hsservice::HsNickname` at launch.
    pub nickname: String,
    /// Whether the service is launched at startup. Default `true`.
    pub enabled: bool,
    /// Port mappings, at least one: `onion_port=host:port`.
    pub ports: Vec<OnionServicePort>,
}

/// One `onion_port=host:port` mapping of an [`OnionServiceEntry`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnionServicePort {
    /// Port the onion service listens on (1..=65535).
    pub onion_port: u16,
    /// Local target the port forwards to, kept in canonical
    /// `host:port` spelling (IPv6 stays bracketed: `[::1]:8443`).
    pub target: String,
}

impl Serialize for OnionServicePort {
    // Written back as the compact scalar form so `ktav::to_string`
    // reproduces `ports: [ 80=127.0.0.1:8080 ]`.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("{}={}", self.onion_port, self.target))
    }
}

impl<'de> Deserialize<'de> for OnionServicePort {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        parse_port_mapping(&raw).map_err(serde::de::Error::custom)
    }
}

/// Serde default for `enabled` (`#[serde(default = "true_fn")]`).
fn true_fn() -> bool {
    true
}

/// Lightweight nickname check (tor-hsservice re-validates at launch):
/// non-empty, at most [`MAX_NICKNAME_LEN`] bytes, only `A-Z a-z 0-9 _ -`.
pub(super) fn validate_nickname(nickname: &str) -> Result<(), String> {
    if nickname.is_empty() {
        return Err("nickname must not be empty".to_owned());
    }
    if nickname.len() > MAX_NICKNAME_LEN {
        return Err(format!(
            "nickname is {} bytes long (max {MAX_NICKNAME_LEN})",
            nickname.len()
        ));
    }
    if !nickname
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err("nickname must only contain A-Z a-z 0-9 _ -".to_owned());
    }
    Ok(())
}

/// Parse one `onion_port=host:port` scalar into an [`OnionServicePort`].
fn parse_port_mapping(raw: &str) -> Result<OnionServicePort, String> {
    let invalid = |reason: &str| {
        format!("invalid port mapping `{raw}` (expected onion_port=host:port): {reason}")
    };
    let (onion, target) = raw.split_once('=').ok_or_else(|| invalid("missing `=`"))?;
    let onion_port = onion
        .parse::<u16>()
        .map_err(|_| invalid("onion port must be a decimal port in 1..=65535"))?;
    if onion_port == 0 {
        return Err(invalid("onion port must be in 1..=65535 (not zero)"));
    }
    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| invalid("target must be host:port"))?;
    validate_target_host(host).map_err(|reason| invalid(&reason))?;
    let port = port
        .parse::<u16>()
        .map_err(|_| invalid("target port must be a decimal port in 1..=65535"))?;
    if port == 0 {
        return Err(invalid("target port must be in 1..=65535 (not zero)"));
    }
    Ok(OnionServicePort {
        onion_port,
        target: target.to_owned(),
    })
}

/// Validate the `host` half of a `host:port` target: bracketed IPv6,
/// or a hostname of letters/digits/dots/hyphens/underscores. A bare
/// (unbracketed) IPv6 address is rejected — it is indistinguishable
/// from a typo and ambiguous with `host:port`.
fn validate_target_host(host: &str) -> Result<(), String> {
    if let Some(inner) = host.strip_prefix('[') {
        let Some(inner) = inner.strip_suffix(']') else {
            return Err("bracketed IPv6 host must be [address]".to_owned());
        };
        inner
            .parse::<std::net::Ipv6Addr>()
            .map_err(|_| "invalid bracketed IPv6 host".to_owned())?;
        return Ok(());
    }
    if host.is_empty() {
        return Err("target host must not be empty".to_owned());
    }
    if host.contains(':') {
        return Err("IPv6 hosts must be bracketed ([address]:port)".to_owned());
    }
    if host
        .bytes()
        .any(|b| !(b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_'))
    {
        return Err("host must only contain A-Z a-z 0-9 . _ -".to_owned());
    }
    Ok(())
}

/// One entry exactly as written, before cross-entry validation. Kept
/// private: the public [`OnionServiceEntry`] carries parsed ports and
/// index-annotated error messages produced by [`onion_services`].
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OnionServiceEntryRaw {
    nickname: String,
    #[serde(default = "true_fn")]
    enabled: bool,
    ports: Vec<String>,
}

/// Turn raw entries into validated public entries, reporting the first
/// problem per entry with its `onion_services[i]` path.
fn validate_entries<E: serde::de::Error>(
    raw: Vec<OnionServiceEntryRaw>,
) -> Result<Vec<OnionServiceEntry>, E> {
    let mut seen_nicknames = HashSet::new();
    let mut entries = Vec::with_capacity(raw.len());
    for (idx, entry) in raw.into_iter().enumerate() {
        let path = format!("onion_services[{idx}]");
        validate_nickname(&entry.nickname).map_err(|reason| {
            E::custom(format!(
                "{path}.nickname: invalid nickname '{}' ({reason})",
                entry.nickname
            ))
        })?;
        if !seen_nicknames.insert(entry.nickname.clone()) {
            return Err(E::custom(format!(
                "onion_services: duplicate nickname '{}'",
                entry.nickname
            )));
        }
        if entry.ports.is_empty() {
            return Err(E::custom(format!(
                "{path}.ports: at least one port mapping is required"
            )));
        }
        let mut seen_ports = HashSet::new();
        let mut ports = Vec::with_capacity(entry.ports.len());
        for raw_port in entry.ports {
            let parsed = parse_port_mapping(&raw_port)
                .map_err(|reason| E::custom(format!("{path}.ports: {reason}")))?;
            if !seen_ports.insert(parsed.onion_port) {
                return Err(E::custom(format!(
                    "{path}.ports: duplicate onion port {}",
                    parsed.onion_port
                )));
            }
            ports.push(parsed);
        }
        entries.push(OnionServiceEntry {
            nickname: entry.nickname,
            enabled: entry.enabled,
            ports,
        });
    }
    Ok(entries)
}

pub(super) fn onion_services<'de, D>(deserializer: D) -> Result<Vec<OnionServiceEntry>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct OnionServices;

    impl<'de> serde::de::Visitor<'de> for OnionServices {
        type Value = Vec<OnionServiceEntry>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a list of onion service entries")
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            let mut raw = Vec::new();
            while let Some(entry) = seq.next_element::<OnionServiceEntryRaw>()? {
                raw.push(entry);
            }
            validate_entries::<A::Error>(raw)
        }
    }

    deserializer.deserialize_any(OnionServices)
}

#[cfg(test)]
#[path = "onion_services_tests.rs"]
mod tests;
