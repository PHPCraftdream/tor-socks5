//! Onion services hosted through this proxy, kept in their own file next to
//! the main config (`<stem>.onion.ktav`, see `Config::onion_path`): per
//! nickname the identity key and address, the `onion_port=host:port`
//! mappings forwarded to local targets, and whether it is launched. The
//! entries are a hand-written list deserializer doing cross-entry validation
//! with key-path error messages (the `listen`/`dns_server.overrides`
//! pattern). proxy-config must not depend on tor-hsservice, so the nickname
//! and address checks here are lightweight duplicates of the real rules
//! (re-checked at service launch in the app crate).

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;

/// Maximum nickname length in bytes (same cap as `tor_hsservice::HsNickname`).
const MAX_NICKNAME_LEN: usize = 25;

/// Default server-side onion circuit length.
const DEFAULT_CIRCUIT_HOPS: u8 = 4;

/// Length of the `<host>` part of a v3 onion address (base32 of the public key).
const ADDRESS_HOST_LEN: usize = 56;

/// The secret identity key of a service: the bytes of the Arti keystore key
/// file, as one line of base64. It is the whole identity of the service, so
/// it is never shown by `Debug` and never part of an error message.
#[derive(Clone, PartialEq, Eq)]
pub struct IdentityKey(String);

impl IdentityKey {
    /// Wrap the base64 text of a key file. Only the alphabet is checked here;
    /// the keystore code parses the key itself when the service starts.
    pub fn new(text: impl Into<String>) -> Result<Self, String> {
        let text = text.into();
        let base64 = |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=');
        if text.is_empty() || !text.bytes().all(base64) {
            return Err("the key must be a single line of base64 text".to_owned());
        }
        Ok(Self(text))
    }

    /// The base64 text, exactly as stored in the file.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for IdentityKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IdentityKey(<redacted>)")
    }
}

impl Serialize for IdentityKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

/// One onion service published by this proxy (see [`crate::Config::onion_services`]).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct OnionServiceEntry {
    /// Human-readable service name: `[A-Za-z0-9_-]+`, at most 25 bytes.
    /// Validated again by `tor_hsservice::HsNickname` at launch.
    pub nickname: String,
    /// Whether the service is launched at startup. Default `true`.
    pub enabled: bool,
    /// The `.onion` address of the service. Derived from the key, so it can
    /// only be stated, not chosen: when a key is present the launch refuses a
    /// different address. Absent until the service has a key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// The identity key (secret). When absent, the first launch generates one
    /// and writes it back here together with the address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<IdentityKey>,
    /// Server-side onion circuit length in hops (relays from the service
    /// to the introduction point, including the bridge). One length per
    /// process: all enabled services must agree. Default `4`, only
    /// `2 | 3 | 4` are permitted. Omitted when `4` on serialization.
    #[serde(skip_serializing_if = "circuit_hops_is_default")]
    pub circuit_hops: u8,
    /// Port mappings `onion_port=host:port`: at least one for an enabled
    /// service, none yet for a disabled one.
    pub ports: Vec<OnionServicePort>,
}

/// The document of the onion services file: `services: [ { .. } ]`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct OnionFile {
    #[serde(default, deserialize_with = "onion_services")]
    pub services: Vec<OnionServiceEntry>,
}

/// Serde skip predicate: the default hop count is not written back.
fn circuit_hops_is_default(circuit_hops: &u8) -> bool {
    *circuit_hops == DEFAULT_CIRCUIT_HOPS
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

impl std::str::FromStr for OnionServicePort {
    type Err = String;

    /// Parse `onion_port=host:port`, the spelling used in the file and by
    /// `onion new --port`.
    fn from_str(raw: &str) -> Result<Self, String> {
        parse_port_mapping(raw)
    }
}

/// Serde default for `enabled` (`#[serde(default = "true_fn")]`).
fn true_fn() -> bool {
    true
}

/// Serde default for `circuit_hops`.
fn default_circuit_hops() -> u8 {
    DEFAULT_CIRCUIT_HOPS
}

/// Parse `circuit_hops` following the `tor.circuit_hops` deserializer in
/// `layout/tor.rs`: an integer with a type-agnostic message; the 2..=4
/// range check happens in [`validate_entries`] so the error can carry
/// the entry path.
fn parse_circuit_hops<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: serde::Deserializer<'de>,
{
    u8::deserialize(deserializer).map_err(|_| {
        serde::de::Error::custom(
            "services[i].circuit_hops must be an integer; permitted values are 2, 3, or 4",
        )
    })
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
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    key: Option<String>,
    #[serde(
        default = "default_circuit_hops",
        deserialize_with = "parse_circuit_hops"
    )]
    circuit_hops: u8,
    ports: Vec<String>,
}

/// A v3 onion address: 56 base32 characters and `.onion`, lower case.
pub(super) fn validate_address(address: &str) -> Result<(), String> {
    let host = address
        .strip_suffix(".onion")
        .ok_or_else(|| "an onion address ends with `.onion`".to_owned())?;
    let base32 = |byte: u8| matches!(byte, b'a'..=b'z' | b'2'..=b'7');
    if host.len() != ADDRESS_HOST_LEN || !host.bytes().all(base32) {
        return Err(format!(
            "an onion address has {ADDRESS_HOST_LEN} lower-case base32 characters before `.onion`"
        ));
    }
    Ok(())
}

/// Turn raw entries into validated public entries, reporting the first
/// problem per entry with its `services[i]` path.
fn validate_entries<E: serde::de::Error>(
    raw: Vec<OnionServiceEntryRaw>,
) -> Result<Vec<OnionServiceEntry>, E> {
    let mut seen_nicknames = HashSet::new();
    let mut seen_addresses = HashSet::new();
    let mut entries = Vec::with_capacity(raw.len());
    for (idx, entry) in raw.into_iter().enumerate() {
        let path = format!("services[{idx}]");
        validate_nickname(&entry.nickname).map_err(|reason| {
            E::custom(format!(
                "{path}.nickname: invalid nickname '{}' ({reason})",
                entry.nickname
            ))
        })?;
        if !seen_nicknames.insert(entry.nickname.clone()) {
            return Err(E::custom(format!(
                "services: duplicate nickname '{}'",
                entry.nickname
            )));
        }
        if !matches!(entry.circuit_hops, 2..=4) {
            return Err(E::custom(format!(
                "{path}.circuit_hops: circuit_hops must be 2, 3, or 4 (got {})",
                entry.circuit_hops
            )));
        }
        if entry.enabled && entry.ports.is_empty() {
            return Err(E::custom(format!(
                "{path}.ports: at least one port mapping is required"
            )));
        }
        if let Some(address) = &entry.address {
            validate_address(address)
                .map_err(|reason| E::custom(format!("{path}.address: {reason}")))?;
            if !seen_addresses.insert(address.clone()) {
                return Err(E::custom(format!(
                    "services: duplicate address '{address}'"
                )));
            }
        }
        let key = entry
            .key
            .map(IdentityKey::new)
            .transpose()
            .map_err(|reason| E::custom(format!("{path}.key: {reason}")))?;
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
            address: entry.address,
            key,
            circuit_hops: entry.circuit_hops,
            ports,
        });
    }
    // One server circuit length per process (an Arti limitation): all
    // enabled services must use the same hop count.
    let mut reference: Option<(usize, u8)> = None;
    for (idx, entry) in entries.iter().enumerate() {
        if !entry.enabled {
            continue;
        }
        match reference {
            None => reference = Some((idx, entry.circuit_hops)),
            Some((ref_idx, hops)) if hops != entry.circuit_hops => {
                return Err(E::custom(format!(
                    "services: all enabled services must use the same circuit_hops \
                     (one circuit length per process): \
                     services[{ref_idx}].circuit_hops: {hops} != \
                     services[{idx}].circuit_hops: {}",
                    entry.circuit_hops
                )));
            }
            _ => {}
        }
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
