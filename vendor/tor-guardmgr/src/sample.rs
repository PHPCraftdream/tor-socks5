//! Logic for manipulating a sampled set of guards, along with various
//! orderings on that sample.

mod candidate;

use crate::filter::GuardFilter;
use crate::guard::{Guard, NewlyConfirmed, Reachable};
use crate::skew::SkewObservation;
use crate::{
    ExternalActivity, GuardParams, GuardUsage, GuardUsageKind, PickGuardError, ids::GuardId,
};
use crate::{FirstHop, GuardSetSelector};
use tor_basic_utils::iter::{FilterCount, IteratorExt as _};
use tor_linkspec::{ByRelayIds, HasRelayIds};

use itertools::Itertools;
use rand::seq::IndexedRandom;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use tracing::{debug, info};
use web_time_compat::{Instant, SystemTime};

#[allow(unused_imports)]
pub(crate) use candidate::{Candidate, CandidateStatus, Universe, UniverseRef, WeightThreshold};

/// A set of sampled guards, along with various orderings on subsets
/// of the sample.
///
/// Every guard in a `GuardSet` is considered to be "sampled": that
/// is, selected from a network directory at some point in the past.
/// The guards in the sample are ordered (roughly) by the time at
/// which they were added.  This list is persistent.
///
/// Any guard which we've successfully used at least once is
/// considered "confirmed".  Confirmed guards are ordered (roughly) by
/// the time at which we first used them.  This list is persistent.
///
/// The guards which we would prefer to use are called "primary".
/// Primary guards are ordered from most- to least-preferred.
/// This list is not persistent, and is re-derived as needed.
///
/// These lists together define a "preference order".  All primary
/// guards come first in preference order.  Then come the non-primary
/// confirmed guards, in their confirmed order.  Finally come the
/// non-primary, non-confirmed guards, in their sampled order.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(from = "GuardSample")]
pub(crate) struct GuardSet {
    /// Map from identities to guards, for every guard in this sample.
    ///
    /// The key for each entry is a set of identities which we have
    /// good (trustworthy-enough) reason to link together.
    ///
    /// When we connect to a guard we require it to demonstrate
    /// that it has *all* of these identities;
    /// and we do pinning, so that we note down the other identities we discover it has,
    /// with the intent that we will require them in future.
    ///
    /// ### Sources of linkage:
    ///
    ///  * If we connect to a relay and it proves a set of identities,
    ///    that necessarily will include at least the ones we have already.
    ///    We can add any other identities we have discovered.
    ///    Justification: the owners of the old ids have made a statement
    ///    (via the connection protocols) that these other ids are also theirs,
    ///    and should be required in future.
    ///
    ///  * If we obtain a (full) descriptor for a relay, and check the
    ///    self-signatures by all the identities we have already,
    ///    we can add any other identities listed in the descriptor.
    ///    Justification: the owners of the old ids have made an explicit statement
    ///    that these other ids are also theirs,
    ///    and should be required in future.
    ///
    ///  * For a relay in the netdir, if the netdir links some ids together,
    ///    we can combine the entries.
    ///    Justification: the netdir is authoritative for netdir-based relays.
    ///
    ///  * For a configured bridge, if our configuration links some identities,
    ///    we must insist on all those identities.
    ///    So we combine them.
    ///
    /// ### Handling of conflicting entries:
    ///
    /// `ByRelayIds` will implicitly delete conflicting entries,
    /// simply forgetting about them.
    /// This is OK for netdir relays, since we do not expect this to occur in practice.
    ///
    /// For bridges, conflicts may in fact occur,
    /// since bridge lines are not issued by a single authority,
    /// and should be afforded limited trust.
    ///
    ///  * If the configuration contains bridge lines that mutually conflict,
    ///    affected bridge lines should be disregarded,
    ///    or the configuration rejected.
    ///
    ///  * If the configuration contains information which is inconsistent with
    ///    our past experience, we should discard the past experiences which
    ///    aren't reconcilable with the configuration.
    ///
    ///  * We may discover a linkage which demonstrates that the configuration
    ///    is wrong: for example, two bridge lines for identities X and Y,
    ///    but in fact there is only one bridge with both identities.
    ///    In this situation it is OK to effectively disregard some the configuration
    ///    entries which are at variance with reality, maybe with a warning,
    ///    but keeping at least one of every usable id set (actually existing bridge)
    ///    would be good.
    guards: ByRelayIds<Guard>,
    /// Identities of all the guards in the sample, in sample order.
    ///
    /// This contains the same elements as the keys of `guards`
    sample: Vec<GuardId>,
    /// Identities of all the confirmed guards in the sample, in
    /// confirmed order.
    ///
    /// This contains a subset of the values in `sample`.
    confirmed: Vec<GuardId>,
    /// Identities of all the primary guards, in preference order
    /// (from best to worst).
    ///
    /// This contains a subset of the values in `sample`.
    primary: Vec<GuardId>,
    /// Currently active filter that restricts which guards we can use.
    ///
    /// Note that all of the lists above (with the exception of `primary`)
    /// can hold guards that the filter doesn't permit.  This behavior
    /// is meant to give good security behavior in the presence of filters
    /// that change over time.
    active_filter: GuardFilter,

    /// If true, the active filter is "very restrictive".
    filter_is_restrictive: bool,

    /// Set to 'true' whenever something changes that would force us
    /// to call 'select_primary_guards()', and cleared whenever we call it.
    primary_guards_invalidated: bool,

    /// Fields from the state file that was used to make this `GuardSet` that
    /// this version of Arti doesn't understand.
    unknown_fields: HashMap<String, JsonValue>,
}

/// Which of our lists did a given guard come from?
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum ListKind {
    /// A guard that came from the primary guard list.
    Primary,
    /// A non-primary guard that came from the confirmed guard list.
    Confirmed,
    /// A non-primary, non-confirmed guard.
    Sample,
    /// Not a guard at all, but a fallback directory.
    Fallback,
}

impl ListKind {
    /// Return true if this is a primary guard.
    pub(crate) fn is_primary(&self) -> bool {
        self == &ListKind::Primary
    }

    /// Return true if this guard's origin indicates that you can use successful
    /// circuits built through it immediately without waiting for any other
    /// circuits to succeed or fail.
    pub(crate) fn usable_immediately(&self) -> bool {
        match self {
            ListKind::Primary | ListKind::Fallback => true,
            ListKind::Confirmed | ListKind::Sample => false,
        }
    }
}

/// Guard set selection and updates.
mod guard_set;
use serde::Serializer;
use tor_persist::JsonValue;

/// State object used to serialize and deserialize a [`GuardSet`].
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub(crate) struct GuardSample<'a> {
    /// Equivalent to `GuardSet.guards.values()`, except in sample order.
    guards: Vec<Cow<'a, Guard>>,
    /// The identities for the confirmed members of `guards`, in confirmed order.
    confirmed: Cow<'a, [GuardId]>,
    /// Other data from the state file that this version of Arti doesn't recognize.
    #[serde(flatten)]
    remaining: HashMap<String, JsonValue>,
}

impl Serialize for GuardSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        GuardSample::from(self).serialize(serializer)
    }
}

impl<'a> From<&'a GuardSet> for GuardSample<'a> {
    fn from(guards: &'a GuardSet) -> Self {
        guards.get_state()
    }
}

impl<'a> From<GuardSample<'a>> for GuardSet {
    fn from(sample: GuardSample) -> Self {
        GuardSet::from_state(sample)
    }
}
