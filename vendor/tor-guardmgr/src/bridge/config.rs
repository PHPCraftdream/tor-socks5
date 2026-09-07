//! Configuration logic and types for bridges.

use std::fmt::{self, Display};
use std::iter;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use itertools::{Itertools, chain};
use serde::{Deserialize, Serialize};

use tor_basic_utils::derive_serde_raw;
use tor_config::define_list_builder_accessors;
use tor_config::{ConfigBuildError, impl_standard_builder};
use tor_linkspec::RelayId;
use tor_linkspec::TransportId;
use tor_linkspec::{ChanTarget, ChannelMethod, HasChanMethod};
use tor_linkspec::{HasAddrs, HasRelayIds, RelayIdRef, RelayIdType};
use tor_llcrypto::pk::{ed25519::Ed25519Identity, rsa::RsaIdentity};

use tor_linkspec::BridgeAddr;

#[cfg(feature = "pt-client")]
use tor_linkspec::{PtTarget, PtTargetAddr};

mod err;
pub use err::BridgeParseError;

/// A relay not listed on the main tor network, used for anticensorship.
///
/// This object represents a bridge as configured by the user or by software
/// running on the user's behalf.
///
/// # Pieces of a bridge configuration.
///
/// A bridge configuration contains:
///   * Optionally, the name of a pluggable transport (q.v.) to use.
///   * Zero or more addresses at which to contact the bridge.
///     These can either be regular IP addresses, hostnames, or arbitrary strings
///     to be interpreted by the pluggable transport.
///   * One or more cryptographic [identities](tor_linkspec::RelayId) for the bridge.
///   * Zero or more optional "key=value" string parameters to pass to the pluggable
///     transport when contacting to this bridge.
///
/// # String representation
///
/// Can be parsed from, and represented as, a "bridge line" string,
/// using the [`FromStr`] and [`Display`] implementations.
///
/// The syntax supported is a sequence of words,
/// separated by ASCII whitespace,
/// in the following order:
///
///  * Optionally, the word `Bridge` (or a case variant thereof).
///    (`Bridge` is not part of a bridge line, but is ignored here
///    for convenience when copying a line out of a C Tor `torrc`.)
///
///  * Optionally, the name of the pluggable transport to use.
///    If not supplied, Arti will make the connection directly, itself.
///
///  * The `Host:ORPort` to connect to.
///    `Host` can be an IPv4 address, or an IPv6 address in brackets `[ ]`.
///    When a pluggable transport is in use, `Host` can also be a hostname;
///    or
///    if the transport supports operating without a specified address.
///    `Host:ORPort` can be omitted and replaced with `-`.
///
///  * One or more identity key fingerprints,
///    each in one of the supported (RSA or ed25519) fingerprint formats.
///    Currently, supplying an RSA key is required; an ed25519 key is optional.
///
///  * When a pluggable transport is in use,
///    zero or more `key=value` parameters to pass to the transport
///    (smuggled in the SOCKS handshake, as described in the Tor PT specification).
///
/// This type is cheap to clone: it is a newtype around an `Arc`.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct BridgeConfig(Arc<Inner>);

/// Configuration for a bridge - actual data
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
struct Inner {
    /// Address and transport via which the bridge can be reached, and
    /// the parameters for those transports.
    ///
    /// Restriction: This `addrs` may NOT contain more than one address,
    /// and it must be a variant supported by the code in this crate:
    /// ie, currently, `Direct` or `Pluggable`.
    addrs: ChannelMethod,

    /// The RSA identity of the bridge.
    rsa_id: RsaIdentity,

    /// The Ed25519 identity of the bridge.
    ed_id: Option<Ed25519Identity>,
}

impl HasRelayIds for BridgeConfig {
    fn identity(&self, key_type: RelayIdType) -> Option<RelayIdRef<'_>> {
        match key_type {
            RelayIdType::Ed25519 => self.0.ed_id.as_ref().map(RelayIdRef::Ed25519),
            RelayIdType::Rsa => Some(RelayIdRef::Rsa(&self.0.rsa_id)),
            _ => None,
        }
    }
}

impl HasChanMethod for BridgeConfig {
    fn chan_method(&self) -> ChannelMethod {
        self.0.addrs.clone()
    }
}

impl HasAddrs for BridgeConfig {
    fn addrs(&self) -> impl Iterator<Item = SocketAddr> {
        self.0.addrs.addrs()
    }
}

impl ChanTarget for BridgeConfig {}

derive_serde_raw! {
/// Builder for a `BridgeConfig`.
///
/// Construct this with [`BridgeConfigBuilder::default()`] or [`BridgeConfig::builder()`],
/// call setter methods, and then call `build().`
//
// `BridgeConfig` contains a `ChannelMethod`.  This is convenient for its users,
// but means we can't use `#[derive(Builder)]` to autogenerate this.
#[derive(Deserialize, Serialize, Default, Clone, Debug)]
#[serde(try_from="BridgeConfigBuilderSerde", into="BridgeConfigBuilderSerde")]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct BridgeConfigBuilder = "BridgeConfigBuilder" {
    /// The `PtTransportName`, but not yet parsed or checked.
    ///
    /// `""` and `"-"` and `"bridge"` all mean "do not use a pluggable transport".
    transport: Option<String>,

    /// Host:ORPort
    ///
    /// When using a pluggable transport, only one address is allowed.
    addrs: Option<Vec<BridgeAddr>>,

    /// IDs
    ///
    /// No more than one ID of each type is permitted.
    ids: Option<Vec<RelayId>>,

    /// Settings (for the transport)
    settings: Option<Vec<(String, String)>>,
}
}
impl_standard_builder! { BridgeConfig: !Default }

/// serde representation of a `BridgeConfigBuilder`
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum BridgeConfigBuilderSerde {
    /// We understand a bridge line
    BridgeLine(String),
    /// We understand a dictionary matching BridgeConfigBuilder
    Dict(#[serde(with = "BridgeConfigBuilder_Raw")] BridgeConfigBuilder),
}

impl TryFrom<BridgeConfigBuilderSerde> for BridgeConfigBuilder {
    type Error = BridgeParseError;
    fn try_from(input: BridgeConfigBuilderSerde) -> Result<Self, Self::Error> {
        use BridgeConfigBuilderSerde::*;
        match input {
            BridgeLine(s) => s.parse(),
            Dict(d) => Ok(d),
        }
    }
}

impl From<BridgeConfigBuilder> for BridgeConfigBuilderSerde {
    fn from(input: BridgeConfigBuilder) -> BridgeConfigBuilderSerde {
        use BridgeConfigBuilderSerde::*;
        // Try to serialize as a bridge line if we can
        match input.build() {
            Ok(bridge) => BridgeLine(bridge.to_string()),
            Err(_) => Dict(input),
        }
    }
}

impl BridgeConfigBuilder {
    /// Set the transport protocol name (eg, a pluggable transport) to use.
    ///
    /// The empty string `""`, a single hyphen `"-"`, and the word `"bridge"`,
    /// all mean to connect directly;
    /// i.e., passing one of this is equivalent to
    /// calling [`direct()`](BridgeConfigBuilder::direct).
    ///
    /// The value is not checked at this point.
    pub fn transport(&mut self, transport: impl Into<String>) -> &mut Self {
        self.transport = Some(transport.into());
        self
    }

    /// Specify to use a direct connection.
    pub fn direct(&mut self) -> &mut Self {
        self.transport("")
    }

    /// Add a pluggable transport setting
    pub fn push_setting(&mut self, k: impl Into<String>, v: impl Into<String>) -> &mut Self {
        self.settings().push((k.into(), v.into()));
        self
    }

    /// Inspect the transport name (ie, the protocol)
    ///
    /// Has not necessarily been validated, so not a `PtTransportName`.
    /// If none has yet been specified, returns `None`.
    pub fn get_transport(&self) -> Option<&str> {
        self.transport.as_deref()
    }
}

impl BridgeConfigBuilder {
    /// Build a `BridgeConfig`
    pub fn build(&self) -> Result<BridgeConfig, ConfigBuildError> {
        let transport = self.transport.as_deref().unwrap_or_default();
        let addrs = self.addrs.as_deref().unwrap_or_default();
        let settings = self.settings.as_deref().unwrap_or_default();

        // Error construction helpers
        let inconsist_transp = |field: &str, problem: &str| ConfigBuildError::Inconsistent {
            fields: vec![field.into(), "transport".into()],
            problem: problem.into(),
        };
        let unsupported =
            |field: String, problem: &dyn Display| ConfigBuildError::NoCompileTimeSupport {
                field,
                problem: problem.to_string(),
            };
        #[cfg_attr(not(feature = "pt-client"), allow(unused_variables))]
        let invalid = |field: String, problem: &dyn Display| ConfigBuildError::Invalid {
            field,
            problem: problem.to_string(),
        };

        let transp: TransportId = transport
            .parse()
            .map_err(|e| invalid("transport".into(), &e))?;

        // This match seems redundant, but it allows us to apply #[cfg] to the branches,
        // which isn't possible with `if ... else ...`.
        let addrs = match () {
            () if transp.is_builtin() => {
                if !settings.is_empty() {
                    return Err(inconsist_transp(
                        "settings",
                        "Specified `settings` for a direct bridge connection",
                    ));
                }
                #[allow(clippy::unnecessary_filter_map)] // for consistency
                let addrs = addrs.iter().filter_map(|ba| {
                    #[allow(clippy::redundant_pattern_matching)] // for consistency
                    if let Some(sa) = ba.as_socketaddr() {
                        Some(Ok(*sa))
                    } else if let Some(_) = ba.as_host_port() {
                        Some(Err(
                            "`addrs` contains hostname and port, but only numeric addresses are supported for a direct bridge connection",
                        ))
                    } else {
                        unreachable!("BridgeAddr is neither addr nor named")
                    }
                }).collect::<Result<Vec<SocketAddr>,&str>>().map_err(|problem| inconsist_transp(
                    "addrs",
                    problem,
                ))?;
                if addrs.is_empty() {
                    return Err(inconsist_transp(
                        "addrs",
                        "Missing `addrs` for a direct bridge connection",
                    ));
                }
                ChannelMethod::Direct(addrs)
            }

            #[cfg(feature = "pt-client")]
            () if transp.as_pluggable().is_some() => {
                let transport = transp.into_pluggable().expect("became not pluggable!");
                let addr = match addrs {
                    [] => PtTargetAddr::None,
                    [addr] => Some(addr.clone()).into(),
                    [_, _, ..] => {
                        return Err(inconsist_transp(
                            "addrs",
                            "Transport (non-direct bridge) only supports a single nominal address",
                        ));
                    }
                };
                let mut target = PtTarget::new(transport, addr);
                for (i, (k, v)) in settings.iter().enumerate() {
                    // Using PtTargetSettings TryFrom would prevent us reporting the index i
                    target
                        .push_setting(k, v)
                        .map_err(|e| invalid(format!("settings.{}", i), &e))?;
                }
                ChannelMethod::Pluggable(target)
            }

            () => {
                // With current code, this can only happen if tor-linkspec has pluggable
                // transports enabled, but we don't.  But if `TransportId` gains other
                // inner variants, it would trigger.
                return Err(unsupported(
                    "transport".into(),
                    &format_args!(
                        "support for selected transport '{}' disabled in tor-guardmgr cargo features",
                        transp
                    ),
                ));
            }
        };

        let mut rsa_id = None;
        let mut ed_id = None;

        /// Helper to store an id in `rsa_id` or `ed_id`
        fn store_id<T: Clone>(
            u: &mut Option<T>,
            desc: &str,
            v: &T,
        ) -> Result<(), ConfigBuildError> {
            if u.is_some() {
                Err(ConfigBuildError::Invalid {
                    field: "ids".into(),
                    problem: format!("multiple different ids of the same type ({})", desc),
                })
            } else {
                *u = Some(v.clone());
                Ok(())
            }
        }

        for (i, id) in self.ids.as_deref().unwrap_or_default().iter().enumerate() {
            match id {
                RelayId::Rsa(rsa) => store_id(&mut rsa_id, "RSA", rsa)?,
                RelayId::Ed25519(ed) => store_id(&mut ed_id, "ed25519", ed)?,
                other => {
                    return Err(unsupported(
                        format!("ids.{}", i),
                        &format_args!("unsupported bridge id type {}", other.id_type()),
                    ));
                }
            }
        }

        let rsa_id = rsa_id.ok_or_else(|| ConfigBuildError::Invalid {
            field: "ids".into(),
            problem: "need an RSA identity".into(),
        })?;

        Ok(BridgeConfig(
            Inner {
                addrs,
                rsa_id,
                ed_id,
            }
            .into(),
        ))
    }
}

/// `BridgeConfigBuilder` parses the same way as `BridgeConfig`
//
// We implement it this way round (rather than having the `impl FromStr for BridgeConfig`
// call this and then `build`, because the `BridgeConfig` parser
// does a lot of bespoke checking of the syntax and semantics.
// Doing it the other way, we'd have to unwrap a supposedly-never-existing `ConfigBuildError`,
// in `BridgeConfig`'s `FromStr` impl.
impl FromStr for BridgeConfigBuilder {
    type Err = BridgeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bridge: Inner = s.parse()?;

        let (transport, addrs, settings) = match bridge.addrs {
            ChannelMethod::Direct(addrs) => (
                "".into(),
                addrs
                    .into_iter()
                    .map(BridgeAddr::new_addr_from_sockaddr)
                    .collect(),
                vec![],
            ),
            #[cfg(feature = "pt-client")]
            ChannelMethod::Pluggable(target) => {
                let (transport, addr, settings) = target.into_parts();
                let addr: Option<BridgeAddr> = addr.into();
                let addrs = addr.into_iter().collect_vec();
                // TODO transport.to_string() clones transport and then drops it
                // PtTransportName::into_inner ought to exist but was deleted
                // in 119e5f6f754251e0d2db7731f9a7044764f4653e
                (transport.to_string(), addrs, settings.into_inner())
            }
            other => {
                return Err(BridgeParseError::UnsupportedChannelMethod {
                    method: Box::new(other),
                });
            }
        };

        let ids = chain!(
            iter::once(bridge.rsa_id.into()),
            bridge.ed_id.into_iter().map(Into::into),
        )
        .collect_vec();

        Ok(BridgeConfigBuilder {
            transport: Some(transport),
            addrs: Some(addrs),
            settings: Some(settings),
            ids: Some(ids),
        })
    }
}

define_list_builder_accessors! {
    struct BridgeConfigBuilder {
        pub addrs: [BridgeAddr],
        pub ids: [RelayId],
        pub settings: [(String,String)],
    }
}

impl FromStr for BridgeConfig {
    type Err = BridgeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let inner = s.parse()?;
        Ok(BridgeConfig(Arc::new(inner)))
    }
}

impl FromStr for Inner {
    type Err = BridgeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use BridgeParseError as BPE;

        let mut s = s.trim().split_ascii_whitespace().peekable();

        // This implements the parsing of bridge lines.
        // Refer to the specification in the rustdoc comment for `Bridge`.

        //  * Optionally, the word `Bridge` ...

        let bridge_word = s.peek().ok_or(BPE::Empty)?;
        if bridge_word.eq_ignore_ascii_case("bridge") {
            s.next();
        }

        //  * Optionally, the name of the pluggable transport to use.
        //  * The `Host:ORPort` to connect to.

        #[cfg_attr(not(feature = "pt-client"), allow(unused_mut))]
        let mut method = {
            let word = s.next().ok_or(BPE::Empty)?;
            if word.contains(':') {
                // Not a PT name.  Hope it's an address:port.
                let addr = word.parse().map_err(|addr_error| BPE::InvalidIpAddrOrPt {
                    word: word.to_string(),
                    addr_error,
                })?;
                ChannelMethod::Direct(vec![addr])
            } else {
                #[cfg(not(feature = "pt-client"))]
                return Err(BPE::PluggableTransportsNotSupported {
                    word: word.to_string(),
                });

                #[cfg(feature = "pt-client")]
                {
                    let pt_name = word.parse().map_err(|pt_error| BPE::InvalidPtOrAddr {
                        word: word.to_string(),
                        pt_error,
                    })?;
                    let addr = s
                        .next()
                        .map(|s| s.parse())
                        .transpose()
                        .map_err(|source| BPE::InvalidIPtHostAddr {
                            word: word.to_string(),
                            source,
                        })?
                        .unwrap_or(PtTargetAddr::None);
                    ChannelMethod::Pluggable(PtTarget::new(pt_name, addr))
                }
            }
        };

        //  * One or more identity key fingerprints,

        let mut rsa_id = None;
        let mut ed_id = None;

        while let Some(word) = s.peek() {
            // Helper to generate the errors if the same key type is specified more than once
            let check_several = |was_some| {
                if was_some {
                    Err(BPE::MultipleIdentitiesOfSameType {
                        word: word.to_string(),
                    })
                } else {
                    Ok(())
                }
            };

            match word.parse() {
                Err(id_error) => {
                    if word.contains('=') {
                        // Not a fingerprint, then, but a key=value.
                        break;
                    }
                    return Err(BPE::InvalidIdentityOrParameter {
                        word: word.to_string(),
                        id_error,
                    });
                }
                Ok(RelayId::Ed25519(id)) => check_several(ed_id.replace(id).is_some())?,
                Ok(RelayId::Rsa(id)) => check_several(rsa_id.replace(id).is_some())?,
                Ok(_) => {
                    return Err(BPE::UnsupportedIdentityType {
                        word: word.to_string(),
                    })?;
                }
            }
            s.next();
        }

        //  * When a pluggable transport is in use,
        //    zero or more `key=value` parameters to pass to the transport

        #[cfg(not(feature = "pt-client"))]
        if s.next().is_some() {
            return Err(BPE::DirectParametersNotAllowed);
        }

        #[cfg(feature = "pt-client")]
        for word in s {
            let (k, v) = word.split_once('=').ok_or_else(|| BPE::InvalidPtKeyValue {
                word: word.to_string(),
            })?;

            match &mut method {
                ChannelMethod::Direct(_) => return Err(BPE::DirectParametersNotAllowed),
                ChannelMethod::Pluggable(t) => t.push_setting(k, v).map_err(|source| {
                    BPE::InvalidPluggableTransportSetting {
                        word: word.to_string(),
                        source,
                    }
                })?,
                other => panic!("made ourselves an unsupported ChannelMethod {:?}", other),
            }
        }

        let rsa_id = rsa_id.ok_or(BPE::NoRsaIdentity)?;
        Ok(Inner {
            addrs: method,
            rsa_id,
            ed_id,
        })
    }
}

impl Display for BridgeConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let Inner {
            addrs,
            rsa_id,
            ed_id,
        } = &*self.0;

        //  * Optionally, the name of the pluggable transport to use.
        //  * The `Host:ORPort` to connect to.

        let settings = match addrs {
            ChannelMethod::Direct(a) => {
                if a.len() == 1 {
                    write!(f, "{}", a[0])?;
                } else {
                    panic!("Somehow created a Bridge config with multiple addrs.");
                }
                None
            }

            #[cfg(feature = "pt-client")]
            ChannelMethod::Pluggable(target) => {
                write!(f, "{} {}", target.transport(), target.addr())?;
                Some(target.settings())
            }

            _ => {
                // This shouldn't happen, but panicking seems worse than outputting this
                write!(f, "[unsupported channel method, cannot display properly]")?;
                return Ok(());
            }
        };

        //  * One or more identity key fingerprints,

        write!(f, " {}", rsa_id)?;
        if let Some(ed_id) = ed_id {
            write!(f, " ed25519:{}", ed_id)?;
        }

        //  * When a pluggable transport is in use,
        //    zero or more `key=value` parameters to pass to the transport

        #[cfg(not(feature = "pt-client"))]
        let _: Option<()> = settings;

        #[cfg(feature = "pt-client")]
        for (k, v) in settings.into_iter().flatten() {
            write!(f, " {}={}", k, v)?;
        }

        Ok(())
    }
}

#[cfg(test)]
#[path = "config/tests.rs"]
mod test;
