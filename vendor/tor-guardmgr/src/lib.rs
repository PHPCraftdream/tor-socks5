#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![allow(renamed_and_removed_lints)] // @@REMOVE_WHEN(ci_arti_stable)
#![allow(unknown_lints)] // @@REMOVE_WHEN(ci_arti_nightly)
#![warn(missing_docs)]
#![warn(noop_method_call)]
#![warn(unreachable_pub)]
#![warn(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unchecked_time_subtraction)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::mod_module_files)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
#![allow(clippy::needless_lifetimes)] // See arti#1765
#![allow(mismatched_lifetime_syntaxes)] // temporary workaround for arti#2060
#![allow(clippy::collapsible_if)] // See arti#2342
#![deny(clippy::unused_async)]
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

// TODO #1645 (either remove this, or decide to have it everywhere)
#![cfg_attr(not(all(feature = "full", feature = "experimental")), allow(unused))]

// Glossary:
//     Primary guard
//     Sample
//     confirmed
//     filtered

use derive_deftly::Deftly;
use futures::channel::mpsc;
use itertools::Either;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, Weak};
#[cfg(feature = "bridge-client")]
use tor_basic_utils::iter::FilterCount;
use tor_error::internal;
use tor_linkspec::{OwnedChanTarget, OwnedCircTarget, RelayId, RelayIdSet};
use tor_netdir::NetDirProvider;
use tor_proto::ClockSkew;
use tor_rtcompat::SpawnExt;
use tor_units::BoundedInt32;
use tracing::{debug, info, instrument, trace, warn};
use web_time_compat::{Duration, Instant, SystemTime};

use tor_config::derive::prelude::*;
use tor_config::{ExplicitOrAuto, impl_standard_builder};
use tor_config::{ReconfigureError, impl_not_auto_value};
use tor_config::{define_list_builder_accessors, define_list_builder_helper};
use tor_netdir::{NetDir, Relay, params::NetParameters};
use tor_persist::{DynStorageHandle, StateMgr};
use tor_rtcompat::Runtime;

#[cfg(feature = "bridge-client")]
pub mod bridge;
mod config;
mod daemon;
mod dirstatus;
mod err;
mod events;
pub mod fallback;
mod filter;
mod guard;
mod ids;
mod pending;
mod sample;
mod skew;
mod util;
#[cfg(feature = "vanguards")]
pub mod vanguards;

#[cfg(not(feature = "bridge-client"))]
#[path = "bridge_disabled.rs"]
pub mod bridge;

#[cfg(any(test, feature = "testing"))]
pub use config::testing::TestConfig;

#[cfg(test)]
use oneshot_fused_workaround as oneshot;

pub use config::GuardMgrConfig;
pub use err::{GuardMgrConfigError, GuardMgrError, PickGuardError};
pub use events::ClockSkewEvents;
// tor-socks5 local patch: re-export the aggregated guard-usable event stream
// type (see `GuardMgr::usable_guard_events`).
pub use events::GuardUsableEvents;
pub use filter::GuardFilter;
pub use ids::FirstHopId;
pub use pending::{GuardMonitor, GuardStatus, GuardUsable};
pub use skew::SkewEstimate;

#[cfg(feature = "vanguards")]
pub use vanguards::VanguardMgrError;

use pending::{PendingRequest, RequestId};
use sample::{GuardSet, Universe, UniverseRef};

use crate::ids::{FirstHopIdInner, GuardId};

/// A "guard manager" that selects and remembers a persistent set of
/// guard nodes.
///
/// This is a "handle"; clones of it share state.
#[derive(Clone)]
pub struct GuardMgr<R: Runtime> {
    /// An asynchronous runtime object.
    ///
    /// GuardMgr uses this runtime for timing, timeouts, and spawning
    /// tasks.
    runtime: R,

    /// Internal state for the guard manager.
    inner: Arc<Mutex<GuardMgrInner>>,
}

/// Helper type that holds the data used by a [`GuardMgr`].
///
/// This would just be a [`GuardMgr`], except that it needs to sit inside
/// a `Mutex` and get accessed by daemon tasks.
struct GuardMgrInner {
    /// Last time when marked all of our primary guards as retriable.
    ///
    /// We keep track of this time so that we can rate-limit
    /// these attempts.
    last_primary_retry_time: Instant,

    /// Persistent guard manager state.
    ///
    /// This object remembers one or more persistent set of guards that we can
    /// use, along with their relative priorities and statuses.
    guards: GuardSets,

    /// The current filter that we're using to decide which guards are
    /// supported.
    //
    // TODO: This field is duplicated in the current active [`GuardSet`]; we
    // should fix that.
    filter: GuardFilter,

    /// Configuration values derived from the consensus parameters.
    ///
    /// This is updated whenever the consensus parameters change.
    params: GuardParams,

    /// A mpsc channel, used to tell the task running in
    /// [`daemon::report_status_events`] about a new event to monitor.
    ///
    /// This uses an `UnboundedSender` so that we don't have to await
    /// while sending the message, which in turn allows the GuardMgr
    /// API to be simpler.  The risk, however, is that there's no
    /// backpressure in the event that the task running
    /// [`daemon::report_status_events`] fails to read from this
    /// channel.
    ctrl: mpsc::UnboundedSender<daemon::Msg>,

    /// Information about guards that we've given out, but where we have
    /// not yet heard whether the guard was successful.
    ///
    /// Upon leaning whether the guard was successful, the pending
    /// requests in this map may be either moved to `waiting`, or
    /// discarded.
    ///
    /// There can be multiple pending requests corresponding to the
    /// same guard.
    pending: HashMap<RequestId, PendingRequest>,

    /// A list of pending requests for which we have heard that the
    /// guard was successful, but we have not yet decided whether the
    /// circuit may be used.
    ///
    /// There can be multiple waiting requests corresponding to the
    /// same guard.
    waiting: Vec<PendingRequest>,

    /// A list of fallback directories used to access the directory system
    /// when no other directory information is yet known.
    fallbacks: fallback::FallbackState,

    /// Location in which to store persistent state.
    storage: DynStorageHandle<GuardSets>,

    /// A sender object to publish changes in our estimated clock skew.
    send_skew: postage::watch::Sender<Option<SkewEstimate>>,

    /// A receiver object to hand out to observers who want to know about
    /// changes in our estimated clock skew.
    recv_skew: events::ClockSkewEvents,

    /// tor-socks5 local patch: a sender to publish changes in the aggregated
    /// "guards usable" signal (true iff at least one usable guard in the
    /// active sample has complete directory information).
    send_usable: postage::watch::Sender<bool>,

    /// tor-socks5 local patch: a receiver to hand out to observers who want to
    /// know about the aggregated "guards usable" signal.
    recv_usable: events::GuardUsableEvents,

    /// A netdir provider that we can use for adding new guards when
    /// insufficient guards are available.
    ///
    /// This has to be an Option so it can be initialized from None: at the
    /// time a GuardMgr is created, there is no NetDirProvider for it to use.
    netdir_provider: Option<Weak<dyn NetDirProvider>>,

    /// A netdir provider that we can use for discovering bridge descriptors.
    ///
    /// This has to be an Option so it can be initialized from None: at the time
    /// a GuardMgr is created, there is no BridgeDescProvider for it to use.
    #[cfg(feature = "bridge-client")]
    bridge_desc_provider: Option<Weak<dyn bridge::BridgeDescProvider>>,

    /// A list of the bridges that we are configured to use, or "None" if we are
    /// not configured to use bridges.
    #[cfg(feature = "bridge-client")]
    configured_bridges: Option<Arc<[bridge::BridgeConfig]>>,
}

/// A selector that tells us which [`GuardSet`] of several is currently in use.
#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, strum::EnumIter)]
enum GuardSetSelector {
    /// The default guard set is currently in use: that's the one that we use
    /// when we have no filter installed, or the filter permits most of the
    /// guards on the network.
    #[default]
    Default,
    /// A "restrictive" guard set is currently in use: that's the one that we
    /// use when we have a filter that excludes a large fraction of the guards
    /// on the network.
    Restricted,
    /// The "bridges" guard set is currently in use: we are selecting our guards
    /// from among the universe of configured bridges.
    #[cfg(feature = "bridge-client")]
    Bridges,
}

/// Describes the [`Universe`] that a guard sample should take its guards from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UniverseType {
    /// Take information from the network directory.
    NetDir,
    /// Take information from the configured bridges.
    #[cfg(feature = "bridge-client")]
    BridgeSet,
}

impl GuardSetSelector {
    /// Return a description of which [`Universe`] this guard sample should take
    /// its guards from.
    fn universe_type(&self) -> UniverseType {
        match self {
            GuardSetSelector::Default | GuardSetSelector::Restricted => UniverseType::NetDir,
            #[cfg(feature = "bridge-client")]
            GuardSetSelector::Bridges => UniverseType::BridgeSet,
        }
    }
}

/// Persistent state for a guard manager, as serialized to disk.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct GuardSets {
    /// Which set of guards is currently in use?
    #[serde(skip)]
    active_set: GuardSetSelector,

    /// The default set of guards to use.
    ///
    /// We use this one when there is no filter, or the filter permits most of the
    /// guards on the network.
    default: GuardSet,

    /// A guard set to use when we have a restrictive filter.
    #[serde(default)]
    restricted: GuardSet,

    /// A guard set sampled from our configured bridges.
    #[serde(default)]
    #[cfg(feature = "bridge-client")]
    bridges: GuardSet,

    /// Unrecognized fields, including (possibly) other guard sets.
    #[serde(flatten)]
    remaining: HashMap<String, tor_persist::JsonValue>,
}

/// The key (filename) we use for storing our persistent guard state in the
/// `StateMgr`.
///
/// We used to store this in a different format in a filename called
/// "default_guards" (before Arti 0.1.0).
const STORAGE_KEY: &str = "guards";

/// A description of which circuits to retire because of a configuration change.
///
/// TODO(nickm): Eventually we will want to add a "Some" here, to support
/// removing only those circuits that correspond to no-longer-usable guards.
#[derive(Clone, Debug, Eq, PartialEq)]
#[must_use]
#[non_exhaustive]
pub enum RetireCircuits {
    /// There's no need to retire any circuits.
    None,
    /// All circuits should be retired.
    All,
}

/// Guard manager API.
mod api;
/// An activity that can succeed or fail, and whose success or failure can be
/// attributed to a guard.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ExternalActivity {
    /// The activity of using the guard as a directory cache.
    DirCache,
}

/// Guard selection and lifecycle management.
mod management;
/// A possible outcome of trying to extend a guard sample.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum ExtendedStatus {
    /// The guard sample was extended. (At least one guard was added to it.)
    Yes,
    /// The guard sample was not extended.
    No,
}

/// A set of parameters, derived from the consensus document, controlling
/// the behavior of a guard manager.
#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
struct GuardParams {
    /// How long should a sampled, un-confirmed guard be kept in the sample before it expires?
    lifetime_unconfirmed: Duration,
    /// How long should a confirmed guard be kept in the sample before
    /// it expires?
    lifetime_confirmed: Duration,
    /// How long may  a guard be unlisted before we remove it from the sample?
    lifetime_unlisted: Duration,
    /// Largest number of guards we're willing to add to the sample.
    max_sample_size: usize,
    /// Largest fraction of the network's guard bandwidth that we're
    /// willing to add to the sample.
    max_sample_bw_fraction: f64,
    /// Smallest number of guards that we're willing to have in the
    /// sample, after applying a [`GuardFilter`].
    min_filtered_sample_size: usize,
    /// How many guards are considered "Primary"?
    n_primary: usize,
    /// When making a regular circuit, how many primary guards should we
    /// be willing to try?
    data_parallelism: usize,
    /// When making a one-hop directory circuit, how many primary
    /// guards should we be willing to try?
    dir_parallelism: usize,
    /// For how long does a pending attempt to connect to a guard
    /// block an attempt to use a less-favored non-primary guard?
    np_connect_timeout: Duration,
    /// How long do we allow a circuit to a successful but unfavored
    /// non-primary guard to sit around before deciding not to use it?
    np_idle_timeout: Duration,
    /// After how much time without successful activity does a
    /// successful circuit indicate that we should retry our primary
    /// guards?
    internet_down_timeout: Duration,
    /// What fraction of the guards can be can be filtered out before we
    /// decide that our filter is "very restrictive"?
    filter_threshold: f64,
    /// What fraction of the guards determine that our filter is "very
    /// restrictive"?
    extreme_threshold: f64,
}

impl Default for GuardParams {
    fn default() -> Self {
        let one_day = Duration::from_secs(86400);
        GuardParams {
            lifetime_unconfirmed: one_day * 120,
            lifetime_confirmed: one_day * 60,
            lifetime_unlisted: one_day * 20,
            max_sample_size: 60,
            max_sample_bw_fraction: 0.2,
            min_filtered_sample_size: 20,
            n_primary: 3,
            data_parallelism: 1,
            dir_parallelism: 3,
            np_connect_timeout: Duration::from_secs(15),
            np_idle_timeout: Duration::from_secs(600),
            internet_down_timeout: Duration::from_secs(600),
            filter_threshold: 0.2,
            extreme_threshold: 0.01,
        }
    }
}

impl TryFrom<&NetParameters> for GuardParams {
    type Error = tor_units::Error;
    fn try_from(p: &NetParameters) -> Result<GuardParams, Self::Error> {
        Ok(GuardParams {
            lifetime_unconfirmed: p.guard_lifetime_unconfirmed.try_into()?,
            lifetime_confirmed: p.guard_lifetime_confirmed.try_into()?,
            lifetime_unlisted: p.guard_remove_unlisted_after.try_into()?,
            max_sample_size: p.guard_max_sample_size.try_into()?,
            max_sample_bw_fraction: p.guard_max_sample_threshold.as_fraction(),
            min_filtered_sample_size: p.guard_filtered_min_sample_size.try_into()?,
            n_primary: p.guard_n_primary.try_into()?,
            data_parallelism: p.guard_use_parallelism.try_into()?,
            dir_parallelism: p.guard_dir_use_parallelism.try_into()?,
            np_connect_timeout: p.guard_nonprimary_connect_timeout.try_into()?,
            np_idle_timeout: p.guard_nonprimary_idle_timeout.try_into()?,
            internet_down_timeout: p.guard_internet_likely_down.try_into()?,
            filter_threshold: p.guard_meaningful_restriction.as_fraction(),
            extreme_threshold: p.guard_extreme_restriction.as_fraction(),
        })
    }
}

/// Representation of a guard or fallback, as returned by [`GuardMgr::select_guard()`].
#[derive(Debug, Clone)]
pub struct FirstHop {
    /// The sample from which this guard was taken, or `None` if this is a fallback.
    sample: Option<GuardSetSelector>,
    /// Information about connecting to (or through) this guard.
    inner: FirstHopInner,
}
/// The enumeration inside a FirstHop that holds information about how to
/// connect to (and possibly through) a guard or fallback.
#[derive(Debug, Clone)]
enum FirstHopInner {
    /// We have enough information to connect to a guard.
    Chan(OwnedChanTarget),
    /// We have enough information to connect to a guards _and_ to build
    /// multihop circuits through it.
    #[cfg_attr(not(feature = "bridge-client"), allow(dead_code))]
    Circ(OwnedCircTarget),
}

impl FirstHop {
    /// Return a new [`FirstHopId`] for this `FirstHop`.
    fn first_hop_id(&self) -> FirstHopId {
        match &self.sample {
            Some(sample) => {
                let guard_id = GuardId::from_relay_ids(self);
                FirstHopId::in_sample(sample.clone(), guard_id)
            }
            None => {
                let fallback_id = crate::ids::FallbackId::from_relay_ids(self);
                FirstHopId::from(fallback_id)
            }
        }
    }

    /// Look up this guard in `netdir`.
    pub fn get_relay<'a>(&self, netdir: &'a NetDir) -> Option<Relay<'a>> {
        match &self.sample {
            #[cfg(feature = "bridge-client")]
            // Always return "None" for anything that isn't in the netdir.
            Some(s) if s.universe_type() == UniverseType::BridgeSet => None,
            // Otherwise ask the netdir.
            _ => netdir.by_ids(self),
        }
    }

    /// Return true if this guard is a bridge.
    pub fn is_bridge(&self) -> bool {
        match &self.sample {
            #[cfg(feature = "bridge-client")]
            Some(s) if s.universe_type() == UniverseType::BridgeSet => true,
            _ => false,
        }
    }

    /// If possible, return a view of this object that can be used to build a circuit.
    pub fn as_circ_target(&self) -> Option<&OwnedCircTarget> {
        match &self.inner {
            FirstHopInner::Chan(_) => None,
            FirstHopInner::Circ(ct) => Some(ct),
        }
    }

    /// Return a view of this as an OwnedChanTarget.
    fn chan_target_mut(&mut self) -> &mut OwnedChanTarget {
        match &mut self.inner {
            FirstHopInner::Chan(ct) => ct,
            FirstHopInner::Circ(ct) => ct.chan_target_mut(),
        }
    }

    /// If possible and appropriate, find a circuit target in `bridges` for this
    /// `FirstHop`, and make this `FirstHop` a viable circuit target.
    ///
    /// (By default, any `FirstHop` that a `GuardSet` returns will have enough
    /// information to be a `ChanTarget`, but it will be lacking the additional
    /// network information in `CircTarget`[^1] necessary for us to build a
    /// multi-hop circuit through it.  If this FirstHop is a regular non-bridge
    /// `Relay`, then the `CircMgr` will later look up that circuit information
    /// itself from the network directory. But if this `FirstHop` *is* a bridge,
    /// then we need to find that information in the `BridgeSet`, since the
    /// CircMgr does not keep track of the `BridgeSet`.)
    ///
    /// [^1]: For example, supported protocol versions and ntor keys.
    #[cfg(feature = "bridge-client")]
    fn lookup_bridge_circ_target(&mut self, bridges: &bridge::BridgeSet) {
        use crate::sample::CandidateStatus::Present;
        if self.sample.as_ref().map(|s| s.universe_type()) == Some(UniverseType::BridgeSet)
            && matches!(self.inner, FirstHopInner::Chan(_))
        {
            if let Present(bridge_relay) = bridges.bridge_relay_by_guard(self) {
                if let Some(circ_target) = bridge_relay.as_relay_with_desc() {
                    self.inner =
                        FirstHopInner::Circ(OwnedCircTarget::from_circ_target(&circ_target));
                }
            }
        }
    }

    /// Return true if this `FirstHop` contains circuit target information.
    ///
    /// This is true if `lookup_bridge_circ_target()` has been called, and it
    /// successfully found the circuit target information.
    #[cfg(feature = "bridge-client")]
    fn contains_circ_target(&self) -> bool {
        matches!(self.inner, FirstHopInner::Circ(_))
    }
}

// This is somewhat redundant with the implementations in crate::guard::Guard.
impl tor_linkspec::HasAddrs for FirstHop {
    fn addrs(&self) -> impl Iterator<Item = SocketAddr> {
        match &self.inner {
            FirstHopInner::Chan(ct) => Either::Left(ct.addrs()),
            FirstHopInner::Circ(ct) => Either::Right(ct.addrs()),
        }
    }
}
impl tor_linkspec::HasRelayIds for FirstHop {
    fn identity(
        &self,
        key_type: tor_linkspec::RelayIdType,
    ) -> Option<tor_linkspec::RelayIdRef<'_>> {
        match &self.inner {
            FirstHopInner::Chan(ct) => ct.identity(key_type),
            FirstHopInner::Circ(ct) => ct.identity(key_type),
        }
    }
}
impl tor_linkspec::HasChanMethod for FirstHop {
    fn chan_method(&self) -> tor_linkspec::ChannelMethod {
        match &self.inner {
            FirstHopInner::Chan(ct) => ct.chan_method(),
            FirstHopInner::Circ(ct) => ct.chan_method(),
        }
    }
}
impl tor_linkspec::ChanTarget for FirstHop {}

/// The purpose for which we plan to use a guard.
///
/// This can affect the guard selection algorithm.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum GuardUsageKind {
    /// We want to use this guard for a data circuit.
    ///
    /// (This encompasses everything except the `OneHopDirectory` case.)
    #[default]
    Data,
    /// We want to use this guard for a one-hop, non-anonymous
    /// directory request.
    ///
    /// (Our algorithm allows more parallelism for the guards that we use
    /// for these circuits.)
    OneHopDirectory,
}

/// A set of parameters describing how a single guard should be selected.
///
/// Used as an argument to [`GuardMgr::select_guard`].
#[derive(Clone, Debug, derive_builder::Builder)]
#[builder(build_fn(error = "tor_config::ConfigBuildError"))]
pub struct GuardUsage {
    /// The purpose for which this guard will be used.
    #[builder(default)]
    kind: GuardUsageKind,
    /// A list of restrictions on which guard may be used.
    ///
    /// The default is the empty list.
    #[builder(sub_builder, setter(custom))]
    restrictions: GuardRestrictionList,
}

impl_standard_builder! { GuardUsage: !Deserialize }

/// List of socket restrictions, as configured
pub type GuardRestrictionList = Vec<GuardRestriction>;

define_list_builder_helper! {
    pub struct GuardRestrictionListBuilder {
        restrictions: [GuardRestriction],
    }
    built: GuardRestrictionList = restrictions;
    default = vec![];
    item_build: |restriction| Ok(restriction.clone());
    item_apply_defaults: |_| Ok::<_, tor_config::ConfigBuildError>(());
}

define_list_builder_accessors! {
    struct GuardUsageBuilder {
        pub restrictions: [GuardRestriction],
    }
}

impl GuardUsageBuilder {
    /// Create a new empty [`GuardUsageBuilder`].
    pub fn new() -> Self {
        Self::default()
    }
}

/// A restriction that applies to a single request for a guard.
///
/// Restrictions differ from filters (see [`GuardFilter`]) in that
/// they apply to single requests, not to our entire set of guards.
/// They're suitable for things like making sure that we don't start
/// and end a circuit at the same relay, or requiring a specific
/// subprotocol version for certain kinds of requests.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum GuardRestriction {
    /// Don't pick a guard with the provided identity.
    AvoidId(RelayId),
    /// Don't pick a guard with any of the provided Ed25519 identities.
    AvoidAllIds(RelayIdSet),
}

/// The kind of vanguards to use.
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)] //
#[derive(Serialize, Deserialize)] //
#[derive(derive_more::Display)] //
#[serde(rename_all = "lowercase")]
#[cfg(feature = "vanguards")]
#[non_exhaustive]
pub enum VanguardMode {
    /// "Lite" vanguards.
    #[default]
    #[display("lite")]
    Lite = 1,
    /// "Full" vanguards.
    #[display("full")]
    Full = 2,
    /// Vanguards are disabled.
    #[display("disabled")]
    Disabled = 0,
}

#[cfg(feature = "vanguards")]
impl VanguardMode {
    /// Build a `VanguardMode` from a [`NetParameters`] parameter.
    ///
    /// Used for converting [`vanguards_enabled`](NetParameters::vanguards_enabled)
    /// or [`vanguards_hs_service`](NetParameters::vanguards_hs_service)
    /// to the corresponding `VanguardMode`.
    pub(crate) fn from_net_parameter(val: BoundedInt32<0, 2>) -> Self {
        match val.get() {
            0 => VanguardMode::Disabled,
            1 => VanguardMode::Lite,
            2 => VanguardMode::Full,
            _ => unreachable!("BoundedInt32 was not bounded?!"),
        }
    }
}

impl_not_auto_value!(VanguardMode);

/// Vanguards configuration.
#[derive(Deftly, Clone, Debug, PartialEq, Eq)]
#[derive_deftly(TorConfig)]
pub struct VanguardConfig {
    /// The kind of vanguards to use.
    #[deftly(tor_config(default))]
    mode: ExplicitOrAuto<VanguardMode>,
}

impl VanguardConfig {
    /// Return the configured [`VanguardMode`].
    ///
    /// Returns the [`Default`] `VanguardMode`
    /// if the mode is [`Auto`](ExplicitOrAuto) or unspecified.
    pub fn mode(&self) -> VanguardMode {
        match self.mode {
            ExplicitOrAuto::Auto => Default::default(),
            ExplicitOrAuto::Explicit(mode) => mode,
        }
    }
}

/// The kind of vanguards to use.
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)] //
#[derive(Serialize, Deserialize)] //
#[derive(derive_more::Display)] //
#[serde(rename_all = "lowercase")]
#[cfg(not(feature = "vanguards"))]
#[non_exhaustive]
pub enum VanguardMode {
    /// Vanguards are disabled.
    #[default]
    #[display("disabled")]
    Disabled = 0,
}

#[cfg(test)]
#[path = "tests.rs"]
mod test;
