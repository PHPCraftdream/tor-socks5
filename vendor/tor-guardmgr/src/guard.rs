//! Code to represent its single guard node and track its status.

use tor_basic_utils::retry::RetryDelay;

use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use tracing::{info, trace, warn};
use web_time_compat::{Duration, Instant, InstantExt, SystemTime};

use crate::dirstatus::DirStatus;
use crate::sample::Candidate;
use crate::skew::SkewObservation;
use crate::util::randomize_time;
use crate::{ExternalActivity, GuardSetSelector, GuardUsageKind, sample};
use crate::{GuardParams, GuardRestriction, GuardUsage, ids::GuardId};

#[cfg(feature = "bridge-client")]
use safelog::Redactable as _;

use tor_linkspec::{
    ChanTarget, ChannelMethod, HasAddrs, HasChanMethod, HasRelayIds, PtTarget, RelayIds,
};
use tor_persist::{Futureproof, JsonValue};

/// Tri-state to represent whether a guard is believed to be reachable or not.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum Reachable {
    /// A guard is believed to be reachable, since we have successfully
    /// used it more recently than we've failed.
    Reachable,
    /// A guard is believed to be unreachable, since recent attempts
    /// to use it have failed, and not enough time has elapsed since then.
    Unreachable,
    /// We have never (during the lifetime of the current guard manager)
    /// tried to connect to this guard.
    #[default]
    Untried,
    /// The last time that we tried to connect to this guard, it failed,
    /// but enough time has elapsed that we think it is worth trying again.
    Retriable,
}

/// The name and version of the crate that first picked a potential
/// guard.
///
/// The C Tor implementation has found it useful to keep this information
/// about guards, to better work around any bugs discovered in the guard
/// implementation.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct CrateId {
    /// The name of the crate that added this guard.
    #[serde(rename = "crate")]
    crate_name: String,
    /// The version of the crate that added this guard.
    version: String,
}

impl CrateId {
    /// Return a new CrateId representing this crate.
    fn this_crate() -> Option<Self> {
        let crate_name = option_env!("CARGO_PKG_NAME")?.to_string();
        let version = option_env!("CARGO_PKG_VERSION")?.to_string();
        Some(CrateId {
            crate_name,
            version,
        })
    }
}

/// What rule do we use when we're displaying information about a guard?
#[derive(Clone, Default, Debug)]
pub(crate) enum DisplayRule {
    /// The guard is Sensitive; we should display it as "\[scrubbed\]".
    ///
    /// We use this for public relays on the network, since displaying even the
    /// redacted info about them can enough to identify them uniquely within the
    /// NetDir.
    ///
    /// This should not be too much of a hit for UX (we hope), since the user is
    /// not typically expected to work around issues with these guards themself.
    #[default]
    Sensitive,
    /// The guard should be Redacted; we display it as something like "192.x.x.x
    /// $ab...".
    ///
    /// We use this for bridges.
    #[cfg(feature = "bridge-client")]
    Redacted,
}

/// A single guard node, as held by the guard manager.
///
/// A Guard is a Tor relay that clients use for the first hop of their circuits.
/// It doesn't need to be a relay that's currently on the network (that is, one
/// that we could represent as a [`Relay`](tor_netdir::Relay)): guards might be
/// temporarily unlisted.
///
/// Some fields in guards are persistent; others are reset with every process.
///
/// # Identity
///
/// Every guard has at least one `RelayId`.  A guard may _gain_ identities over
/// time, as we learn more about it, but it should never _lose_ or _change_ its
/// identities of a given type.
///
/// # TODO
///
/// This structure uses [`Instant`] to represent non-persistent points in time,
/// and [`SystemTime`] to represent points in time that need to be persistent.
/// That's possibly undesirable; maybe we should come up with a better solution.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Guard {
    /// The identity keys for this guard.
    id: GuardId,

    /// The most recently seen addresses for this guard.  If `pt_targets` is
    /// empty, these are the addresses we use for making OR connections to this
    /// guard directly.  If `pt_targets` is nonempty, these are addresses at
    /// which the server is "located" (q.v. [`HasAddrs`]), but not ways to
    /// connect to it.
    orports: Vec<SocketAddr>,

    /// Any `PtTarget` instances that we know about for connecting to this guard
    /// over a pluggable transport.
    ///
    /// If this is empty, then this guard only supports direct connections, at
    /// the locations in `orports`.
    ///
    /// (Currently, this is always empty, or a singleton.  If we find more than
    /// one, we only look at the first. It is a vector only for forward
    /// compatibility.)
    //
    // TODO: We may want to replace pt_targets and orports with a new structure;
    // maybe a PtAddress and a list of SocketAddr.  But we'll keep them like
    // this for now to keep backward compatibility.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pt_targets: Vec<PtTarget>,

    /// When, approximately, did we first add this guard to our sample?
    #[serde(with = "humantime_serde")]
    added_at: SystemTime,

    /// What version of this crate added this guard to our sample?
    added_by: Option<CrateId>,

    /// If present, this guard is permanently disabled, and this
    /// object tells us why.
    #[serde(default)]
    disabled: Option<Futureproof<GuardDisabled>>,

    /// When, approximately, did we first successfully use this guard?
    ///
    /// (We call a guard "confirmed" if we have successfully used it at
    /// least once.)
    #[serde(with = "humantime_serde")]
    confirmed_at: Option<SystemTime>,

    /// If this guard is not listed in the current-consensus, this is the
    /// `valid_after` date of the oldest consensus in which it was not listed.
    ///
    /// A guard counts as "unlisted" if it is absent, unusable, or
    /// doesn't have the Guard flag.
    #[serde(with = "humantime_serde")]
    unlisted_since: Option<SystemTime>,

    /// True if this guard is listed in the latest consensus, but we don't
    /// have a microdescriptor for it.
    #[serde(skip)]
    dir_info_missing: bool,

    /// When did we last give out this guard in response to a request?
    #[serde(skip)]
    last_tried_to_connect_at: Option<Instant>,

    /// If this guard is currently Unreachable, when should we next
    /// retry it?
    ///
    /// (Retrying a guard involves clearing this field, and setting
    /// `reachable`)
    #[serde(skip)]
    retry_at: Option<Instant>, // derived from retry_schedule.

    /// Schedule use to determine when we can next attempt to connect to this
    /// guard.
    #[serde(skip)]
    retry_schedule: Option<RetryDelay>,

    /// Current reachability status for this guard.
    #[serde(skip)]
    reachable: Reachable,

    /// If true, then the last time we saw a relay entry for this
    /// guard, it seemed like a valid directory cache.
    #[serde(skip)]
    is_dir_cache: bool,

    /// Status for this guard, when used as a directory cache.
    ///
    /// (This is separate from `Reachable` and `retry_schedule`, since being
    /// usable for circuit construction does not necessarily mean that the guard
    /// will have good, timely cache information.  If it were not separate, then
    /// circuit success would clear directory failures.)
    #[serde(skip, default = "guard_dirstatus")]
    dir_status: DirStatus,

    /// If true, we have given this guard out for an exploratory circuit,
    /// and that exploratory circuit is still pending.
    ///
    /// A circuit is "exploratory" if we launched it on a non-primary guard.
    // TODO: Maybe this should be an integer that counts a number of such
    // circuits?
    #[serde(skip)]
    exploratory_circ_pending: bool,

    /// A count of all the circuit statuses we've seen on this guard.
    ///
    /// Used to implement a lightweight version of path-bias detection.
    #[serde(skip)]
    circ_history: CircHistory,

    /// True if we have warned about this guard behaving suspiciously.
    #[serde(skip)]
    suspicious_behavior_warned: bool,

    /// Latest clock skew (if any) we have observed from this guard.
    #[serde(skip)]
    clock_skew: Option<SkewObservation>,

    /// How should we display information about this guard?
    #[serde(skip)]
    sensitivity: DisplayRule,

    /// Fields from the state file that was used to make this `Guard` that
    /// this version of Arti doesn't understand.
    #[serde(flatten)]
    unknown_fields: HashMap<String, JsonValue>,
}

/// Lower bound for delay after get a failure using a guard as a directory
/// cache.
const GUARD_DIR_RETRY_FLOOR: Duration = Duration::from_secs(60);

/// Return a DirStatus entry for a guard.
fn guard_dirstatus() -> DirStatus {
    DirStatus::new(GUARD_DIR_RETRY_FLOOR)
}

/// Wrapper to declare whether a given successful use of a guard is the
/// _first_ successful use of the guard.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum NewlyConfirmed {
    /// This was the first successful use of a guard.
    Yes,
    /// This guard has been used successfully before.
    No,
}

impl Guard {
    /// Create a new unused [`Guard`] from a [`Candidate`].
    pub(crate) fn from_candidate(
        candidate: Candidate,
        now: SystemTime,
        params: &GuardParams,
    ) -> Self {
        let Candidate {
            is_dir_cache,
            full_dir_info,
            owned_target,
            ..
        } = candidate;

        Guard {
            is_dir_cache,
            dir_info_missing: !full_dir_info,
            ..Self::from_chan_target(&owned_target, now, params)
        }
    }

    /// Create a new unused [`Guard`] from a [`ChanTarget`].
    ///
    /// This function doesn't check whether the provided relay is a
    /// suitable guard node or not: that's up to the caller to decide.
    fn from_chan_target<T>(relay: &T, now: SystemTime, params: &GuardParams) -> Self
    where
        T: ChanTarget,
    {
        let added_at = randomize_time(&mut rand::rng(), now, params.lifetime_unconfirmed / 10);

        let pt_target = match relay.chan_method() {
            #[cfg(feature = "pt-client")]
            ChannelMethod::Pluggable(pt) => Some(pt),
            _ => None,
        };

        Self::new(
            GuardId::from_relay_ids(relay),
            relay.addrs().collect_vec(),
            pt_target,
            added_at,
        )
    }

    /// Return a new, manually constructed [`Guard`].
    fn new(
        id: GuardId,
        orports: Vec<SocketAddr>,
        pt_target: Option<PtTarget>,
        added_at: SystemTime,
    ) -> Self {
        Guard {
            id,
            orports,
            pt_targets: pt_target.into_iter().collect(),
            added_at,
            added_by: CrateId::this_crate(),
            disabled: None,
            confirmed_at: None,
            unlisted_since: None,
            dir_info_missing: false,
            last_tried_to_connect_at: None,
            reachable: Reachable::Untried,
            retry_at: None,
            dir_status: guard_dirstatus(),
            retry_schedule: None,
            is_dir_cache: true,
            exploratory_circ_pending: false,
            circ_history: CircHistory::default(),
            suspicious_behavior_warned: false,
            clock_skew: None,
            unknown_fields: Default::default(),
            sensitivity: DisplayRule::Sensitive,
        }
    }

    /// Return the identity of this Guard.
    pub(crate) fn guard_id(&self) -> &GuardId {
        &self.id
    }

    /// Return the reachability status for this guard.
    pub(crate) fn reachable(&self) -> Reachable {
        self.reachable
    }

    /// Return the next time at which this guard will be retriable for a given
    /// usage.
    ///
    /// (Return None if we think this guard might be reachable right now.)
    pub(crate) fn next_retry(&self, usage: &GuardUsage) -> Option<Instant> {
        match &usage.kind {
            GuardUsageKind::Data => self.retry_at,
            GuardUsageKind::OneHopDirectory => [self.retry_at, self.dir_status.next_retriable()]
                .iter()
                .flatten()
                .max()
                .copied(),
        }
    }

    /// Return true if this guard is usable and working according to our latest
    /// configuration and directory information, and hasn't been turned off for
    /// some other reason.
    pub(crate) fn usable(&self) -> bool {
        self.unlisted_since.is_none() && self.disabled.is_none()
    }

    /// Whether guard security policy has disabled this identity.
    pub(crate) fn is_disabled(&self) -> bool {
        self.disabled.is_some()
    }

    /// tor-socks5 local patch: return true if we have complete directory
    /// information (a microdescriptor) for this guard — i.e. its
    /// `dir_info_missing` flag is false, so it is eligible for multi-hop data
    /// circuits. Exposed crate-visible so the aggregated guard-usable signal
    /// (`GuardSet::any_guard_usable_for_traffic`) can inspect it directly
    /// instead of synthesizing a `GuardUsage`.
    pub(crate) fn has_complete_dir_info(&self) -> bool {
        !self.dir_info_missing
    }

    /// tor-socks5 local patch: test-only setter to drive the aggregated
    /// guard-usable signal in unit tests without standing up a full NetDir that
    /// omits microdescriptors.
    #[cfg(test)]
    pub(crate) fn set_dir_info_missing_for_test(&mut self, missing: bool) {
        self.dir_info_missing = missing;
    }

    /// Return true if this guard is ready (with respect to any timeouts) for
    /// the given `usage` at `now`.
    pub(crate) fn ready_for_usage(&self, usage: &GuardUsage, now: Instant) -> bool {
        if let Some(retry_at) = self.retry_at {
            if retry_at > now {
                return false;
            }
        }

        match usage.kind {
            GuardUsageKind::Data => true,
            GuardUsageKind::OneHopDirectory => self.dir_status.usable_at(now),
        }
    }

    /// Copy all _non-persistent_ status from `other` to self.
    ///
    /// We do this when we were not the owner of our persistent state, and we
    /// have just reloaded it (as `self`), but we have some ephemeral knowledge
    /// about this guard (as `other`).
    ///
    /// You should not invent new uses for this function; instead we should come
    /// up with alternatives.
    ///
    /// # Panics
    ///
    /// Panics if the identities in `self` are not exactly the same as the
    /// identities in `other`.
    pub(crate) fn copy_ephemeral_status_into_newly_loaded_state(self, other: Guard) -> Guard {
        // It is not safe to copy failure information unless these identities
        // are a superset of those in `other`; but it is not safe to copy success
        // information unless these identities are a subset of those in `other`.
        //
        // To simplify matters, we just insist that the identities have to be the same.
        assert!(self.same_relay_ids(&other));

        Guard {
            // All other persistent fields are taken from `self`.
            id: self.id,
            pt_targets: self.pt_targets,
            orports: self.orports,
            added_at: self.added_at,
            added_by: self.added_by,
            disabled: self.disabled,
            confirmed_at: self.confirmed_at,
            unlisted_since: self.unlisted_since,
            unknown_fields: self.unknown_fields,

            // All non-persistent fields get taken from `other`.
            last_tried_to_connect_at: other.last_tried_to_connect_at,
            retry_at: other.retry_at,
            retry_schedule: other.retry_schedule,
            reachable: other.reachable,
            is_dir_cache: other.is_dir_cache,
            exploratory_circ_pending: other.exploratory_circ_pending,
            dir_info_missing: other.dir_info_missing,
            circ_history: other.circ_history,
            suspicious_behavior_warned: other.suspicious_behavior_warned,
            dir_status: other.dir_status,
            clock_skew: other.clock_skew,
            sensitivity: other.sensitivity,
            // Note that we _could_ remove either of the above blocks and add
            // `..self` or `..other`, but that would be risky: it would increase
            // the odds that we would forget to add some persistent or
            // non-persistent field to the right group in the future.
        }
    }

    /// Change the reachability status for this guard.
    #[allow(clippy::cognitive_complexity)]
    fn set_reachable(&mut self, r: Reachable) {
        use Reachable as R;

        if self.reachable != r {
            // High-level logs, if change is interesting to user.
            match (self.reachable, r) {
                (_, R::Reachable) => info!("We have found that guard {} is usable.", self),
                (R::Untried | R::Reachable, R::Unreachable) => match self.retry_at {
                    Some(retry_at) => warn!(
                        "Could not connect to guard {}. Retrying in {}.",
                        self,
                        humantime::format_duration(retry_at - Instant::get()),
                    ),
                    None => warn!(
                        "Could not connect to guard {}. Next retry time unknown.",
                        self
                    ),
                },
                (_, _) => {} // not interesting.
            }
            //
            trace!(guard_id = ?self.id, old=?self.reachable, new=?r, "Guard status changed.");
            self.reachable = r;
        }
    }

    /// Return true if at least one exploratory circuit is pending to this
    /// guard.
    ///
    /// A circuit is "exploratory" if launched on a non-primary guard.
    ///
    /// # TODO
    ///
    /// The "exploratory" definition doesn't quite match up with the behavior
    /// in the spec, but it is what Tor does.
    pub(crate) fn exploratory_circ_pending(&self) -> bool {
        self.exploratory_circ_pending
    }

    /// Note that an exploratory circuit is pending (if `pending` is true),
    /// or not pending (if `pending` is false.
    pub(crate) fn note_exploratory_circ(&mut self, pending: bool) {
        self.exploratory_circ_pending = pending;
    }

    /// Possibly mark this guard as retriable, if it has been down for
    /// long enough.
    ///
    /// Specifically, if the guard is to be Unreachable, and our last attempt
    /// to connect to it is far enough in the past from `now`, we change its
    /// status to Unknown.
    pub(crate) fn consider_retry(&mut self, now: Instant) {
        if let Some(retry_at) = self.retry_at {
            debug_assert!(self.reachable == Reachable::Unreachable);
            if retry_at <= now {
                self.mark_retriable();
            }
        }
    }

    /// If this guard is marked Unreachable, clear its unreachability status
    /// and mark it as Retriable.
    pub(crate) fn mark_retriable(&mut self) {
        if self.reachable == Reachable::Unreachable {
            self.set_reachable(Reachable::Retriable);
            self.retry_at = None;
            self.retry_schedule = None;
        }
    }

    /// Return true if this guard obeys all of the given restrictions.
    fn obeys_restrictions(&self, restrictions: &[GuardRestriction]) -> bool {
        restrictions.iter().all(|r| self.obeys_restriction(r))
    }

    /// Return true if this guard obeys a single restriction.
    fn obeys_restriction(&self, r: &GuardRestriction) -> bool {
        match r {
            GuardRestriction::AvoidId(avoid_id) => !self.id.0.has_identity(avoid_id.as_ref()),
            GuardRestriction::AvoidAllIds(avoid_ids) => {
                self.id.0.identities().all(|id| !avoid_ids.contains(id))
            }
        }
    }

    /// Return true if this guard is suitable to use for the provided `usage`.
    pub(crate) fn conforms_to_usage(&self, usage: &GuardUsage) -> bool {
        match usage.kind {
            GuardUsageKind::OneHopDirectory => {
                if !self.is_dir_cache {
                    return false;
                }
            }
            GuardUsageKind::Data => {
                // We need a "definitely listed" guard to build a multihop
                // circuit.
                if self.dir_info_missing {
                    return false;
                }
            }
        }
        self.obeys_restrictions(&usage.restrictions[..])
    }

    /// Check whether this guard is listed in the provided [`sample::Universe`].
    ///
    /// Returns `Some(true)` if it is definitely listed, and `Some(false)` if it
    /// is definitely not listed.  A `None` return indicates that we need to
    /// download more directory information about this guard before we can be
    /// certain whether this guard is listed or not.
    pub(crate) fn listed_in<U: sample::Universe>(&self, universe: &U) -> Option<bool> {
        universe.contains(self)
    }

    /// Change this guard's status based on a newly received or newly updated
    /// [`sample::Universe`].
    ///
    /// A guard may become "listed" or "unlisted": a listed guard is one that
    /// appears in the consensus with the Guard flag.
    ///
    /// A guard may acquire additional identities if we learned them from the
    /// guard, either directly or via an authenticated directory document.
    ///
    /// Additionally, a guard's `orports` or `pt_targets` may change, if the
    /// `universe` lists a new address for the relay.
    pub(crate) fn update_from_universe<U: sample::Universe>(&mut self, universe: &U) {
        // This is a tricky check, since if we're missing directory information
        // for the guard, we won't know its full set of identities.
        use sample::CandidateStatus::*;
        let listed_as_guard = match universe.status(self) {
            Present(Candidate {
                listed_as_guard,
                is_dir_cache,
                full_dir_info,
                owned_target,
                sensitivity,
            }) => {
                // Update address information.
                self.orports = owned_target.addrs().collect_vec();
                // Update Pt information.
                self.pt_targets = match owned_target.chan_method() {
                    #[cfg(feature = "pt-client")]
                    ChannelMethod::Pluggable(pt) => vec![pt],
                    _ => Vec::new(),
                };
                // Check whether we can currently use it as a directory cache.
                self.is_dir_cache = is_dir_cache;
                // Update our IDs: the Relay will have strictly more.
                assert!(owned_target.has_all_relay_ids_from(self));
                self.id = GuardId(RelayIds::from_relay_ids(&owned_target));
                self.dir_info_missing = !full_dir_info;
                self.sensitivity = sensitivity;

                listed_as_guard
            }
            Absent => false, // Definitely not listed.
            Uncertain => {
                // We can't tell if this is listed without more directory information.
                self.dir_info_missing = true;
                return;
            }
        };

        if listed_as_guard {
            // Definitely listed, so clear unlisted_since.
            self.mark_listed();
        } else {
            // Unlisted or not a guard; mark it unlisted.
            self.mark_unlisted(universe.timestamp());
        }
    }

    /// Mark this guard as currently listed in the directory.
    fn mark_listed(&mut self) {
        if self.unlisted_since.is_some() {
            trace!(guard_id = ?self.id, "Guard is now listed again.");
            self.unlisted_since = None;
        }
    }

    /// Mark this guard as having been unlisted since `now`, if it is not
    /// already so marked.
    fn mark_unlisted(&mut self, now: SystemTime) {
        if self.unlisted_since.is_none() {
            trace!(guard_id = ?self.id, "Guard is now unlisted.");
            self.unlisted_since = Some(now);
        }
    }

    /// Return true if we should remove this guard from the current guard
    /// sample.
    ///
    /// Guards may be ready for removal because they have been
    /// confirmed too long ago, if they have been sampled too long ago
    /// (if they are not confirmed), or if they have been unlisted for
    /// too long.
    pub(crate) fn is_expired(&self, params: &GuardParams, now: SystemTime) -> bool {
        /// Helper: Return true if `t2` is after `t1` by at least `d`.
        fn expired_by(t1: SystemTime, d: Duration, t2: SystemTime) -> bool {
            if let Ok(elapsed) = t2.duration_since(t1) {
                elapsed > d
            } else {
                false
            }
        }
        if self.disabled.is_some() {
            // We never forget a guard that we've disabled: we've disabled
            // it for a reason.
            return false;
        }
        if let Some(confirmed_at) = self.confirmed_at {
            if expired_by(confirmed_at, params.lifetime_confirmed, now) {
                return true;
            }
        } else if expired_by(self.added_at, params.lifetime_unconfirmed, now) {
            return true;
        }

        if let Some(unlisted_since) = self.unlisted_since {
            if expired_by(unlisted_since, params.lifetime_unlisted, now) {
                return true;
            }
        }

        false
    }

    /// Record that a failure has happened for this guard.
    ///
    /// If `is_primary` is true, this is a primary guard (q.v.).
    pub(crate) fn record_failure(&mut self, now: Instant, is_primary: bool) {
        let mut rng = rand::rng();
        let retry_interval = self
            .retry_schedule
            .get_or_insert_with(|| retry_schedule(is_primary))
            .next_delay(&mut rng);

        // TODO-SPEC: Document this behavior in guard-spec.
        self.retry_at = Some(now + retry_interval);

        self.set_reachable(Reachable::Unreachable);
        self.exploratory_circ_pending = false;

        self.circ_history.n_failures += 1;
    }

    /// Note that we have launch an attempted use of this guard.
    ///
    /// We use this time to decide when to retry failing guards, and
    /// to see if the guard has been "pending" for a long time.
    pub(crate) fn record_attempt(&mut self, connect_attempt: Instant) {
        self.last_tried_to_connect_at = self
            .last_tried_to_connect_at
            .map(|last| last.max(connect_attempt))
            .or(Some(connect_attempt));
    }

    /// Return true if this guard has an exploratory circuit pending and
    /// if the most recent attempt to connect to it is after `when`.
    ///
    /// See [`Self::exploratory_circ_pending`].
    pub(crate) fn exploratory_attempt_after(&self, when: Instant) -> bool {
        self.exploratory_circ_pending
            && self.last_tried_to_connect_at.map(|t| t > when) == Some(true)
    }

    /// Note that a guard has been used successfully.
    ///
    /// Updates that guard's status to reachable, clears any failing status
    /// information for it, and decides whether the guard is newly confirmed.
    ///
    /// If the guard is newly confirmed, the caller must add it to the
    /// list of confirmed guards.
    #[must_use = "You need to check whether a succeeding guard is confirmed."]
    pub(crate) fn record_success(
        &mut self,
        now: SystemTime,
        params: &GuardParams,
    ) -> NewlyConfirmed {
        self.retry_at = None;
        self.retry_schedule = None;
        self.set_reachable(Reachable::Reachable);
        self.exploratory_circ_pending = false;
        self.circ_history.n_successes += 1;

        if self.confirmed_at.is_none() {
            self.confirmed_at = Some(
                randomize_time(&mut rand::rng(), now, params.lifetime_unconfirmed / 10)
                    .max(self.added_at),
            );
            // TODO-SPEC: The "max" above isn't specified by guard-spec,
            // but I think it's wise.
            trace!(guard_id = ?self.id, "Newly confirmed");
            NewlyConfirmed::Yes
        } else {
            NewlyConfirmed::No
        }
    }

    /// Record that an external operation has succeeded on this guard.
    pub(crate) fn record_external_success(&mut self, how: ExternalActivity) {
        match how {
            ExternalActivity::DirCache => {
                self.dir_status.note_success();
            }
        }
    }

    /// Record that an external operation has failed on this guard.
    pub(crate) fn record_external_failure(&mut self, how: ExternalActivity, now: Instant) {
        match how {
            ExternalActivity::DirCache => {
                self.dir_status.note_failure(now);
            }
        }
    }

    /// Note that a circuit through this guard died in a way that we couldn't
    /// necessarily attribute to the guard.
    pub(crate) fn record_indeterminate_result(&mut self) {
        self.circ_history.n_indeterminate += 1;

        if let Some(ratio) = self.circ_history.indeterminate_ratio() {
            // TODO: These should not be hardwired, and they may be set
            // too high.
            /// If this fraction of circs are suspicious, we should disable
            /// the guard.
            const DISABLE_THRESHOLD: f64 = 0.7;
            /// If this fraction of circuits are suspicious, we should
            /// warn.
            const WARN_THRESHOLD: f64 = 0.5;

            if ratio > DISABLE_THRESHOLD {
                let reason = GuardDisabled::TooManyIndeterminateFailures {
                    history: self.circ_history.clone(),
                    failure_ratio: ratio,
                    threshold_ratio: DISABLE_THRESHOLD,
                };
                warn!(guard=?self.id, "Disabling guard: {:.1}% of circuits died under mysterious circumstances, exceeding threshold of {:.1}%", ratio*100.0, (DISABLE_THRESHOLD*100.0));
                self.disabled = Some(reason.into());
            } else if ratio > WARN_THRESHOLD && !self.suspicious_behavior_warned {
                warn!(guard=?self.id, "Questionable guard: {:.1}% of circuits died under mysterious circumstances.", ratio*100.0);
                self.suspicious_behavior_warned = true;
            }
        }
    }

    /// tor-socks5 local patch: clear this guard's `disabled` state and give it
    /// a fresh start, also resetting the circuit-failure history that produced
    /// the disable.
    ///
    /// Returns `true` if the guard was disabled (and is now re-enabled), `false`
    /// if it was already usable — in which case nothing is touched: we never
    /// wipe the observed history of a healthy guard.
    ///
    /// # Why this exists
    ///
    /// [`record_indeterminate_result`](Self::record_indeterminate_result)
    /// permanently sets `disabled` once the lifetime indeterminate-failure
    /// ratio crosses `0.7`. The `disabled` field is persisted (serialized to
    /// the state file) and nothing else in this crate ever clears it, so once a
    /// guard is disabled it stays disabled until it drops out of the sample for
    /// an unrelated reason. In a bridge-only deployment with only a handful of
    /// configured bridges, a single transient second-hop/exit failure storm
    /// (which is exactly what `GuardStatus::Indeterminate` counts) can take a
    /// bridge out of rotation for good, with no automatic recovery path.
    ///
    /// This is the manual escape hatch an application-level watchdog can invoke
    /// on its own policy — e.g. "too few usable bridges remain, do not let this
    /// one stay permanently disabled". The history is reset rather than only
    /// `disabled`, because the accumulated `n_indeterminate` would otherwise
    /// immediately re-trip the disable threshold on the very next
    /// indeterminate result.
    pub(crate) fn reset_disabled(&mut self) -> bool {
        if self.disabled.take().is_some() {
            self.circ_history = CircHistory::default();
            self.suspicious_behavior_warned = false;
            info!(guard=?self.id, "Re-enabling previously disabled guard (manual reset of indeterminate-failure history).");
            true
        } else {
            false
        }
    }

    /// Return a [`FirstHop`](crate::FirstHop) object to represent this guard.
    pub(crate) fn get_external_rep(&self, selection: GuardSetSelector) -> crate::FirstHop {
        crate::FirstHop {
            sample: Some(selection),
            inner: crate::FirstHopInner::Chan(tor_linkspec::OwnedChanTarget::from_chan_target(
                self,
            )),
        }
    }

    /// Record that a given fallback has told us about clock skew.
    pub(crate) fn note_skew(&mut self, observation: SkewObservation) {
        self.clock_skew = Some(observation);
    }

    /// Return the most recent clock skew observation for this guard, if we have
    /// made one.
    pub(crate) fn skew(&self) -> Option<&SkewObservation> {
        self.clock_skew.as_ref()
    }

    /// Testing only: Return true if this guard was ever contacted successfully.
    #[cfg(test)]
    pub(crate) fn confirmed(&self) -> bool {
        self.confirmed_at.is_some()
    }
}

impl tor_linkspec::HasAddrs for Guard {
    fn addrs(&self) -> impl Iterator<Item = SocketAddr> {
        self.orports.iter().copied()
    }
}

impl tor_linkspec::HasRelayIds for Guard {
    fn identity(
        &self,
        key_type: tor_linkspec::RelayIdType,
    ) -> Option<tor_linkspec::RelayIdRef<'_>> {
        self.id.0.identity(key_type)
    }
}

impl tor_linkspec::HasChanMethod for Guard {
    fn chan_method(&self) -> ChannelMethod {
        match &self.pt_targets[..] {
            #[cfg(feature = "pt-client")]
            [first, ..] => ChannelMethod::Pluggable(first.clone()),
            #[cfg(not(feature = "pt-client"))]
            [_first, ..] => ChannelMethod::Direct(vec![]), // can't connect to this; no pt support.
            [] => ChannelMethod::Direct(self.orports.clone()),
        }
    }
}

impl tor_linkspec::ChanTarget for Guard {}

impl std::fmt::Display for Guard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.sensitivity {
            DisplayRule::Sensitive => safelog::sensitive(self.display_chan_target()).fmt(f),
            #[cfg(feature = "bridge-client")]
            DisplayRule::Redacted => self.display_chan_target().redacted().fmt(f),
        }
    }
}

/// A reason for permanently disabling a guard.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
enum GuardDisabled {
    /// Too many attempts to use this guard failed for indeterminate reasons.
    TooManyIndeterminateFailures {
        /// Observed count of status reports about this guard.
        history: CircHistory,
        /// Observed fraction of indeterminate status reports.
        failure_ratio: f64,
        /// Threshold that was exceeded.
        threshold_ratio: f64,
    },
}

/// Return a new RetryDelay tracker for a guard.
///
/// `is_primary should be true if the guard is primary.
fn retry_schedule(is_primary: bool) -> RetryDelay {
    let minimum = if is_primary {
        Duration::from_secs(30)
    } else {
        Duration::from_secs(150)
    };

    RetryDelay::from_duration(minimum)
}

/// The recent history of circuit activity on this guard.
///
/// We keep this information so that we can tell if too many circuits are
/// winding up in "indeterminate" status.
///
/// # What's this for?
///
/// Recall that an "indeterminate" circuit failure is one that might
/// or might not be the guard's fault.  For example, if the second hop
/// of the circuit fails, we can't tell whether to blame the guard,
/// the second hop, or the internet between them.
///
/// But we don't want to allow an unbounded number of indeterminate
/// failures: if we did, it would allow a malicious guard to simply
/// reject any circuit whose second hop it didn't like, and thereby
/// filter the client's paths down to a hostile subset.
///
/// So as a workaround, and to discourage this kind of behavior, we
/// track the fraction of indeterminate circuits, and disable any guard
/// where the fraction is too high.
//
// TODO: We may eventually want to make this structure persistent.  If we
// do, however, we'll need a way to make ancient history expire.  We might
// want that anyway, to make attacks harder.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct CircHistory {
    /// How many times have we seen this guard succeed?
    n_successes: u32,
    /// How many times have we seen this guard fail?
    #[allow(dead_code)] // not actually used yet.
    n_failures: u32,
    /// How many times has this guard given us indeterminate results?
    n_indeterminate: u32,
}

impl CircHistory {
    /// If we have seen enough, return the fraction of circuits that have
    /// "died under mysterious circumstances".
    fn indeterminate_ratio(&self) -> Option<f64> {
        // TODO: This should probably not be hardwired

        /// Don't try to give a ratio unless we've seen this many observations.
        const MIN_OBSERVATIONS: u32 = 15;

        let total = self.n_successes + self.n_indeterminate;
        if total < MIN_OBSERVATIONS {
            return None;
        }

        Some(f64::from(self.n_indeterminate) / f64::from(total))
    }
}

#[cfg(test)]
#[path = "guard/tests.rs"]
mod test;
