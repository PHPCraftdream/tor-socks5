//! Abstract code to manage a set of tunnels which has underlying circuit(s).
//!
//! This module implements the real logic for deciding when and how to
//! launch tunnels, and for which tunnels to hand out in response to
//! which requests.
//!
//! For testing and abstraction purposes, this module _does not_
//! actually know anything about tunnels _per se_.  Instead,
//! everything is handled using a set of traits that are internal to this
//! crate:
//!
//!  * [`AbstractTunnel`] is a view of a tunnel.
//!  * [`AbstractTunnelBuilder`] knows how to build an `AbstractCirc`.
//!
//! Using these traits, the [`AbstractTunnelMgr`] object manages a set of
//! tunnels , launching them as necessary, and keeping track of the
//! restrictions on their use.

// TODO:
// - Testing
//    - Error from prepare_action()
//    - Error reported by restrict_mut?

use crate::config::CircuitTiming;
use crate::usage::{SupportedTunnelUsage, TargetTunnelUsage};
use crate::{DirInfo, Error, PathConfig, Result, timeouts};

use retry_error::RetryError;
use tor_async_utils::mpsc_channel_no_memquota;
use tor_basic_utils::retry::RetryDelay;
use tor_config::MutCfg;
use tor_error::{AbsRetryTime, HasRetryTime, debug_report, info_report, internal, warn_report};
#[cfg(feature = "vanguards")]
use tor_guardmgr::vanguards::VanguardMgr;
use tor_linkspec::CircTarget;
use tor_proto::circuit::UniqId;
use tor_proto::client::circuit::{CircParameters, Path};
use tor_rtcompat::{Runtime, SleepProviderExt};

use async_trait::async_trait;
use futures::channel::mpsc;
use futures::future::{FutureExt, Shared};
use futures::stream::{FuturesUnordered, StreamExt};
use oneshot_fused_workaround as oneshot;
use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;
use std::panic::AssertUnwindSafe;
use std::sync::{self, Arc, Weak};
use tor_rtcompat::SpawnExt;
use tracing::{debug, instrument, trace, warn};
use web_time_compat::{Duration, Instant};
mod streams;

/// Alias to force use of RandomState, regardless of features enabled in `weak_tables`.
///
/// See <https://github.com/tov/weak-table-rs/issues/23> for discussion.
///
/// (We could probably get away with a weaker hash function in this case, since
/// the attacker _probably_ doesn't have control over our pointers.)
type PtrWeakHashSet<T> = weak_table::PtrWeakHashSet<T, std::hash::RandomState>;

/// Description of how we got a tunnel.
#[non_exhaustive]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum TunnelProvenance {
    /// This channel was newly launched, or was in progress and finished while
    /// we were waiting.
    NewlyCreated,
    /// This channel already existed when we asked for it.
    Preexisting,
}

/// An error returned when we cannot apply circuit restriction.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RestrictionFailed {
    /// Tried to restrict a specification, but the tunnel didn't support the
    /// requested usage.
    #[error("Specification did not support desired usage")]
    NotSupported,
}

/// Minimal abstract view of a tunnel.
///
/// From this module's point of view, tunnels are simply objects
/// with unique identities, and a possible closed-state.
#[async_trait]
pub(crate) trait AbstractTunnel: Debug {
    /// Type for a unique identifier for tunnels.
    type Id: Clone + Debug + Hash + Eq + Send + Sync;
    /// Return the unique identifier for this tunnel.
    ///
    /// # Requirements
    ///
    /// The values returned by this function are unique for distinct
    /// tunnels.
    fn id(&self) -> Self::Id;

    /// Return true if this tunnel is usable for some purpose.
    ///
    /// Reasons a tunnel might be unusable include being closed.
    fn usable(&self) -> bool;

    /// Return a list of [`Path`] objects describing the only circuit in this tunnel.
    ///
    /// Returns an error if the tunnel has more than one tunnel.
    fn single_path(&self) -> tor_proto::Result<Arc<Path>>;

    /// Return the number of hops in this tunnel.
    ///
    /// Returns an error if the circuit is closed.
    ///
    /// NOTE: This function will currently return only the number of hops
    /// _currently_ in the tunnel. If there is an extend operation in progress,
    /// the currently pending hop may or may not be counted, depending on whether
    /// the extend operation finishes before this call is done.
    fn n_hops(&self) -> tor_proto::Result<usize>;

    /// Return true if this tunnel is closed and therefore unusable.
    fn is_closing(&self) -> bool;

    /// Return a process-unique identifier for this tunnel.
    fn unique_id(&self) -> UniqId;

    /// Extend the tunnel via the most appropriate handshake to a new `target` hop.
    async fn extend<T: CircTarget + Sync>(
        &self,
        target: &T,
        params: CircParameters,
    ) -> tor_proto::Result<()>;

    /// Return a time at which this tunnel is last known to be used,
    /// or None if it is in use right now (or has never been used).
    async fn last_known_to_be_used_at(&self) -> tor_proto::Result<Option<Instant>>;
}

/// A plan for an `AbstractCircBuilder` that can maybe be mutated by tests.
///
/// You should implement this trait using all default methods for all code that isn't test code.
pub(crate) trait MockablePlan {
    /// Add a reason string that was passed to `SleepProvider::block_advance()` to this object
    /// so that it knows what to pass to `::release_advance()`.
    fn add_blocked_advance_reason(&mut self, _reason: String) {}
}

/// An object that knows how to build tunnels.
///
/// This creates tunnels in two phases. First, a plan is
/// made for how to build the tunnel. This planning phase should be
/// relatively fast, and must not suspend or block.  Its purpose is to
/// get an early estimate of which operations the tunnel will be able
/// to support when it's done.
///
/// Second, the tunnel is actually built, using the plan as input.

#[async_trait]
pub(crate) trait AbstractTunnelBuilder<R: Runtime>: Send + Sync {
    /// The tunnel type that this builder knows how to build.
    type Tunnel: AbstractTunnel + Send + Sync;
    /// An opaque type describing how a given tunnel will be built.
    /// It may represent some or all of a path-or it may not.
    //
    // TODO: It would be nice to have this parameterized on a lifetime,
    // and have that lifetime depend on the lifetime of the directory.
    // But I don't think that rust can do that.
    //
    // HACK(eta): I don't like the fact that `MockablePlan` is necessary here.
    type Plan: Send + Debug + MockablePlan;

    // TODO: I'd like to have a Dir type here to represent
    // create::DirInfo, but that would need to be parameterized too,
    // and would make everything complicated.

    /// Form a plan for how to build a new tunnel that supports `usage`.
    ///
    /// Return an opaque Plan object, and a new spec describing what
    /// the tunnel will actually support when it's built.  (For
    /// example, if the input spec requests a tunnel that connect to
    /// port 80, then "planning" the tunnel might involve picking an
    /// exit that supports port 80, and the resulting spec might be
    /// the exit's complete list of supported ports.)
    ///
    /// # Requirements
    ///
    /// The resulting Spec must support `usage`.
    fn plan_tunnel(
        &self,
        usage: &TargetTunnelUsage,
        dir: DirInfo<'_>,
    ) -> Result<(Self::Plan, SupportedTunnelUsage)>;

    /// Construct a tunnel according to a given plan.
    ///
    /// On success, return a spec describing what the tunnel can be used for,
    /// and the tunnel that was just constructed.
    ///
    /// This function should implement some kind of a timeout for
    /// tunnel that are taking too long.
    ///
    /// # Requirements
    ///
    /// The spec that this function returns _must_ support the usage
    /// that was originally passed to `plan_tunnel`.  It _must_ also
    /// contain the spec that was originally returned by
    /// `plan_tunnel`.
    async fn build_tunnel(&self, plan: Self::Plan) -> Result<(SupportedTunnelUsage, Self::Tunnel)>;

    /// Return a "parallelism factor" with which tunnels should be
    /// constructed for a given purpose.
    ///
    /// If this function returns N, then whenever we launch tunnels
    /// for this purpose, then we launch N in parallel.
    ///
    /// The default implementation returns 1.  The value of 0 is
    /// treated as if it were 1.
    fn launch_parallelism(&self, usage: &TargetTunnelUsage) -> usize {
        let _ = usage; // default implementation ignores this.
        1
    }

    /// Return a "parallelism factor" for which tunnels should be
    /// used for a given purpose.
    ///
    /// If this function returns N, then whenever we select among
    /// open tunnels for this purpose, we choose at random from the
    /// best N.
    ///
    /// The default implementation returns 1.  The value of 0 is
    /// treated as if it were 1.
    // TODO: Possibly this doesn't belong in this trait.
    fn select_parallelism(&self, usage: &TargetTunnelUsage) -> usize {
        let _ = usage; // default implementation ignores this.
        1
    }

    /// Return true if we are currently attempting to learn tunnel
    /// timeouts by building testing tunnels.
    fn learning_timeouts(&self) -> bool;

    /// Flush state to the state manager if we own the lock.
    ///
    /// Return `Ok(true)` if we saved, and `Ok(false)` if we didn't hold the lock.
    fn save_state(&self) -> Result<bool>;

    /// Return this builder's [`PathConfig`].
    fn path_config(&self) -> Arc<PathConfig>;

    /// Replace this builder's [`PathConfig`].
    // TODO: This is dead_code because we only call this for the CircuitBuilder specialization of
    // CircMgr, not from the generic version, because this trait doesn't provide guardmgr, which is
    // needed by the [`CircMgr::reconfigure`] function that would be the only caller of this. We
    // should add `guardmgr` to this trait, make [`CircMgr::reconfigure`] generic, and remove this
    // dead_code marking.
    #[allow(dead_code)]
    fn set_path_config(&self, new_config: PathConfig);

    /// Return a reference to this builder's timeout estimator.
    fn estimator(&self) -> &timeouts::Estimator;

    /// Return a reference to this builder's `VanguardMgr`.
    #[cfg(feature = "vanguards")]
    fn vanguardmgr(&self) -> &Arc<VanguardMgr<R>>;

    /// Replace our state with a new owning state, assuming we have
    /// storage permission.
    fn upgrade_to_owned_state(&self) -> Result<()>;

    /// Reload persistent state from disk, if we don't have storage permission.
    fn reload_state(&self) -> Result<()>;

    /// Return a reference to this builder's `GuardMgr`.
    fn guardmgr(&self) -> &tor_guardmgr::GuardMgr<R>;

    /// Reconfigure this builder using the latest set of network parameters.
    ///
    /// (NOTE: for now, this only affects tunnel timeout estimation.)
    fn update_network_parameters(&self, p: &tor_netdir::params::NetParameters);
}

/// Enumeration to track the expiration state of a tunnel.
///
/// A tunnel an either be unused (at which point it should expire if it is
/// _still unused_ by a certain time, or dirty (at which point it should
/// expire after a certain duration).
///
/// All tunnels start out "unused" and become "dirty" when their spec
/// is first restricted -- that is, when they are first handed out to be
/// used for a request.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ExpirationInfo {
    /// The tunnel has never been used, and has never been restricted for use with a request.
    Unused {
        /// A time when the tunnel was created.
        created: Instant,
    },

    /// The tunnel is not-long-lived; we will expire by waiting until a certain amount of time
    /// after it was first used.
    Dirty {
        /// The time at which this tunnel's spec was first restricted.
        dirty_since: Instant,
    },

    /// The tunnel is long-lived; we will expire by waiting until it has passed
    /// a certain amount of time without having any streams attached to it.
    LongLived {
        /// Last time at which the tunnel was checked and found not to have any streams.
        ///
        /// (This is a bit complicated: We have to be vague here, since we need
        /// an async check to find out that a tunnel is used, or when it actually
        /// became disused.)
        last_known_to_be_used_at: Instant,
    },
}

impl ExpirationInfo {
    /// Return an ExpirationInfo for a newly created tunnel.
    fn new(now: Instant) -> Self {
        ExpirationInfo::Unused { created: now }
    }

    /// Mark this ExpirationInfo as having been in-use at `now`.
    ///
    /// If `long_lived` is false, the associated tunnel should expire a certain amount of time
    /// after it was _first_ used.
    /// If `long_lived` is true, the associated tunnel should expire a certain amount of time
    /// after it was _last_ used.
    fn mark_used(&mut self, now: Instant, long_lived: bool) {
        if long_lived {
            *self = ExpirationInfo::LongLived {
                last_known_to_be_used_at: now,
            };
        } else {
            match self {
                ExpirationInfo::Unused { .. } => {
                    // This is our first time using this circuit; mark it dirty
                    *self = ExpirationInfo::Dirty { dirty_since: now };
                }
                ExpirationInfo::Dirty { .. } => {
                    // no need to update; we're tracking the time when the circuit _first_ became
                    // dirty, so further uses don't matter.
                }
                ExpirationInfo::LongLived { .. } => {
                    // shouldn't occur: we shouldn't be able to attach a stream with non-long-lived isolation
                    // to a tunnel marked as long-lived.  In this case we leave the timestamp alone.
                    // (If there were a bug here, it would be harmless, since we would
                    // correct the timestamp the next time we tried to expire the circuit.)
                }
            }
        }
    }

    /// Return an internal error if this ExpirationInfo is not marked as long-lived.
    fn check_long_lived(&self) -> Result<()> {
        match self {
            ExpirationInfo::Unused { .. } | ExpirationInfo::Dirty { .. } => Err(internal!(
                "Tunnel was not long-lived as expected. (Expiration status: {:?})",
                self
            )
            .into()),
            ExpirationInfo::LongLived { .. } => Ok(()),
        }
    }
}

/// Settings to determine when circuits are expired.
#[derive(Clone, Debug)]
pub(crate) struct ExpirationParameters {
    /// Any unused circuit is expired this long after it was created.
    expire_unused_after: Duration,
    /// Any non long-lived dirty circuit is expired this long after it first becomes dirty.
    expire_dirty_after: Duration,
    /// Any long-lived circuit is expired after having been disused for this long.
    expire_disused_after: Duration,
}

/// An entry for an open tunnel held by an `AbstractTunnelMgr`.
#[derive(Debug, Clone)]
pub(crate) struct OpenEntry<T> {
    /// The supported usage for this tunnel.
    spec: SupportedTunnelUsage,
    /// The tunnel under management.
    tunnel: Arc<T>,
    /// When does this tunnel expire?
    ///
    /// (Note that expired tunnels are removed from the manager,
    /// which does not actually close them until there are no more
    /// references to them.)
    expiration: ExpirationInfo,
}

impl<T: AbstractTunnel> OpenEntry<T> {
    /// Make a new OpenEntry for a given tunnel and spec.
    fn new(spec: SupportedTunnelUsage, tunnel: T, expiration: ExpirationInfo) -> Self {
        OpenEntry {
            spec,
            tunnel: tunnel.into(),
            expiration,
        }
    }

    /// Return true if the underlying tunnel can be used for `usage`.
    pub(crate) fn supports(&self, usage: &TargetTunnelUsage) -> bool {
        self.tunnel.usable() && self.spec.supports(usage)
    }

    /// Change the underlying tunnel's permissible usage, based on its having
    /// been used for `usage` at time `now`.
    ///
    /// Return an error if the tunnel may not be used for `usage`.
    fn restrict_mut(&mut self, usage: &TargetTunnelUsage, now: Instant) -> Result<()> {
        self.spec.restrict_mut(usage)?;
        self.expiration.mark_used(now, self.spec.is_long_lived());
        Ok(())
    }

    /// Find the "best" entry from a slice of OpenEntry for supporting
    /// a given `usage`.
    ///
    /// If `parallelism` is some N greater than 1, we pick randomly
    /// from the best `N` tunnels.
    ///
    /// # Requirements
    ///
    /// Requires that `ents` is nonempty, and that every element of `ents`
    /// supports `spec`.
    fn find_best<'a>(
        // we do not mutate `ents`, but to return `&mut Self` we must have a mutable borrow
        ents: &'a mut [&'a mut Self],
        usage: &TargetTunnelUsage,
        parallelism: usize,
    ) -> &'a mut Self {
        let _ = usage; // not yet used.
        use rand::seq::IndexedMutRandom as _;
        let parallelism = parallelism.clamp(1, ents.len());
        // TODO: Actually look over the whole list to see which is better.
        let slice = &mut ents[0..parallelism];
        let mut rng = rand::rng();
        slice.choose_mut(&mut rng).expect("Input list was empty")
    }

    /// Return true if this tunnel should be expired given that the current time is `now`,
    /// and the current settings are `params`.
    fn should_expire(&self, now: Instant, params: &ExpirationParameters) -> ShouldExpire {
        match self.expiration {
            ExpirationInfo::Unused { created } => {
                ShouldExpire::certain(now, created + params.expire_unused_after)
            }
            ExpirationInfo::Dirty { dirty_since } => {
                ShouldExpire::certain(now, dirty_since + params.expire_dirty_after)
            }
            ExpirationInfo::LongLived {
                last_known_to_be_used_at,
            } => {
                ShouldExpire::uncertain(now, last_known_to_be_used_at + params.expire_disused_after)
            }
        }
    }
}

/// When should a tunnel expire?
///
/// Reflects possible uncertainty.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShouldExpire {
    /// The tunnel should expire now.
    Now,
    /// The circuit might expire now; we need to check.
    ///
    /// (This is the result we get when we know that this is a tunnel that should expire
    /// if it has gone for some duration D without having any streams on it,
    /// and that it definitely had a stream at time T.  It is now at least time T+D,
    /// but we don't know whether the tunnel has any streams in the intervening time.
    /// We need to call the async fn `last_known_to_be_used_at` to check.)
    PossiblyNow,
    /// The tunnel will not expire before the specified time.
    NotBefore(Instant),
}

impl ShouldExpire {
    /// Return a ShouldExpire reflecting an expiration that is known to be happening at `expiration`.
    fn certain(now: Instant, expiration: Instant) -> Self {
        if now >= expiration {
            ShouldExpire::Now
        } else {
            ShouldExpire::NotBefore(expiration)
        }
    }

    /// Return a ShouldExpire reflecting an expiration that is known to be no sooner than `expiration`,
    /// but possibly later.
    fn uncertain(now: Instant, expiration: Instant) -> Self {
        if now >= expiration {
            ShouldExpire::PossiblyNow
        } else {
            ShouldExpire::NotBefore(expiration)
        }
    }
}

/// A result type whose "Ok" value is the Id for a tunnel from B.
type PendResult<B, R> = Result<<<B as AbstractTunnelBuilder<R>>::Tunnel as AbstractTunnel>::Id>;

/// An in-progress tunnel request tracked by an `AbstractTunnelMgr`.
///
/// (In addition to tracking tunnels, `AbstractTunnelMgr` tracks
/// _requests_ for tunnels.  The manager uses these entries if it
/// finds that some tunnel created _after_ a request first launched
/// might meet the request's requirements.)
struct PendingRequest<B: AbstractTunnelBuilder<R>, R: Runtime> {
    /// Usage for the operation requested by this request
    usage: TargetTunnelUsage,
    /// A channel to use for telling this request about tunnels that it
    /// might like.
    notify: mpsc::Sender<PendResult<B, R>>,
}

impl<B: AbstractTunnelBuilder<R>, R: Runtime> PendingRequest<B, R> {
    /// Return true if this request would be supported by `spec`.
    fn supported_by(&self, spec: &SupportedTunnelUsage) -> bool {
        spec.supports(&self.usage)
    }
}

/// An entry for an under-construction in-progress tunnel tracked by
/// an `AbstractTunnelMgr`.
#[derive(Debug)]
struct PendingEntry<B: AbstractTunnelBuilder<R>, R: Runtime> {
    /// Specification that this tunnel will support, if every pending
    /// request that is waiting for it is attached to it.
    ///
    /// This spec becomes more and more restricted as more pending
    /// requests are waiting for this tunnel.
    ///
    /// This spec is contained by circ_spec, and must support the usage
    /// of every pending request that's waiting for this tunnel.
    tentative_assignment: sync::Mutex<SupportedTunnelUsage>,
    /// A shared future for requests to use when waiting for
    /// notification of this tunnel's success.
    receiver: Shared<oneshot::Receiver<PendResult<B, R>>>,
}

impl<B: AbstractTunnelBuilder<R>, R: Runtime> PendingEntry<B, R> {
    /// Make a new PendingEntry that starts out supporting a given
    /// spec.  Return that PendingEntry, along with a Sender to use to
    /// report the result of building this tunnel.
    fn new(spec: &SupportedTunnelUsage) -> (Self, oneshot::Sender<PendResult<B, R>>) {
        let tentative_assignment = sync::Mutex::new(spec.clone());
        let (sender, receiver) = oneshot::channel();
        let receiver = receiver.shared();
        let entry = PendingEntry {
            tentative_assignment,
            receiver,
        };
        (entry, sender)
    }

    /// Return true if this tunnel's current tentative assignment
    /// supports `usage`.
    fn supports(&self, usage: &TargetTunnelUsage) -> bool {
        let assignment = self.tentative_assignment.lock().expect("poisoned lock");
        assignment.supports(usage)
    }

    /// Try to change the tentative assignment of this tunnel by
    /// restricting it for use with `usage`.
    ///
    /// Return an error if the current tentative assignment didn't
    /// support `usage` in the first place.
    fn tentative_restrict_mut(&self, usage: &TargetTunnelUsage) -> Result<()> {
        if let Ok(mut assignment) = self.tentative_assignment.lock() {
            assignment.restrict_mut(usage)?;
        }
        Ok(())
    }

    /// Find the best PendingEntry values from a slice for use with
    /// `usage`.
    ///
    /// # Requirements
    ///
    /// The `ents` slice must not be empty.  Every element of `ents`
    /// must support the given spec.
    fn find_best(ents: &[Arc<Self>], usage: &TargetTunnelUsage) -> Vec<Arc<Self>> {
        // TODO: Actually look over the whole list to see which is better.
        let _ = usage; // currently unused
        vec![Arc::clone(&ents[0])]
    }
}

/// Wrapper type to represent the state between planning to build a
/// tunnel and constructing it.
#[derive(Debug)]
struct TunnelBuildPlan<B: AbstractTunnelBuilder<R>, R: Runtime> {
    /// The Plan object returned by [`AbstractTunnelBuilder::plan_tunnel`].
    plan: B::Plan,
    /// A sender to notify any pending requests when this tunnel is done.
    sender: oneshot::Sender<PendResult<B, R>>,
    /// A strong entry to the PendingEntry for this tunnel build attempt.
    pending: Arc<PendingEntry<B, R>>,
}

/// The inner state of an [`AbstractTunnelMgr`].
struct TunnelList<B: AbstractTunnelBuilder<R>, R: Runtime> {
    /// A map from tunnel ID to [`OpenEntry`] values for all managed
    /// open tunnels.
    ///
    /// A tunnel is added here from [`AbstractTunnelMgr::do_launch`] when we find
    /// that it completes successfully, and has not been cancelled.
    /// When we decide that such a tunnel should no longer be handed out for
    /// any new requests, we "retire" the tunnel by removing it from this map.
    #[allow(clippy::type_complexity)]
    open_tunnels: HashMap<<B::Tunnel as AbstractTunnel>::Id, OpenEntry<B::Tunnel>>,
    /// Weak-set of PendingEntry for tunnels that are being built.
    ///
    /// Because this set only holds weak references, and the only strong
    /// reference to the PendingEntry is held by the task building the tunnel,
    /// this set's members are lazily removed after the tunnel is either built
    /// or fails to build.
    ///
    /// This set is used for two purposes:
    ///
    /// 1. When a tunnel request finds that there is no open tunnel for its
    ///    purposes, it checks here to see if there is a pending tunnel that it
    ///    could wait for.
    /// 2. When a pending tunnel finishes building, it checks here to make sure
    ///    that it has not been cancelled. (Removing an entry from this set marks
    ///    it as cancelled.)
    ///
    /// An entry is added here in [`AbstractTunnelMgr::prepare_action`] when we
    /// decide that a tunnel needs to be launched.
    ///
    /// Later, in [`AbstractTunnelMgr::do_launch`], once the tunnel has finished
    /// (or failed), we remove the entry (by pointer identity).
    /// If we cannot find the entry, we conclude that the request has been
    /// _cancelled_, and so we discard any tunnel that was created.
    pending_tunnels: PtrWeakHashSet<Weak<PendingEntry<B, R>>>,
    /// Weak-set of PendingRequest for requests that are waiting for a
    /// tunnel to be built.
    ///
    /// Because this set only holds weak references, and the only
    /// strong reference to the PendingRequest is held by the task
    /// waiting for the tunnel to be built, this set's members are
    /// lazily removed after the request succeeds or fails.
    pending_requests: PtrWeakHashSet<Weak<PendingRequest<B, R>>>,
}

impl<B: AbstractTunnelBuilder<R>, R: Runtime> TunnelList<B, R> {
    /// Make a new empty `CircList`
    fn new() -> Self {
        TunnelList {
            open_tunnels: HashMap::new(),
            pending_tunnels: PtrWeakHashSet::new(),
            pending_requests: PtrWeakHashSet::new(),
        }
    }

    /// Add `e` to the list of open tunnels.
    fn add_open(&mut self, e: OpenEntry<B::Tunnel>) {
        let id = e.tunnel.id();
        self.open_tunnels.insert(id, e);
    }

    /// Find all the usable open tunnels that support `usage`.
    ///
    /// Return None if there are no such tunnels.
    fn find_open(&mut self, usage: &TargetTunnelUsage) -> Option<Vec<&mut OpenEntry<B::Tunnel>>> {
        let list = self.open_tunnels.values_mut();
        let v = SupportedTunnelUsage::find_supported(list, usage);
        if v.is_empty() { None } else { Some(v) }
    }

    /// Find an open tunnel by ID.
    ///
    /// Return None if no such tunnels exists in this list.
    fn get_open_mut(
        &mut self,
        id: &<B::Tunnel as AbstractTunnel>::Id,
    ) -> Option<&mut OpenEntry<B::Tunnel>> {
        self.open_tunnels.get_mut(id)
    }

    /// Extract an open tunnel by ID, removing it from this list.
    ///
    /// Return None if no such tunnel exists in this list.
    fn take_open(
        &mut self,
        id: &<B::Tunnel as AbstractTunnel>::Id,
    ) -> Option<OpenEntry<B::Tunnel>> {
        self.open_tunnels.remove(id)
    }

    /// Remove tunnels based on expiration times.
    ///
    /// We remove every unused tunnel that is set to expire by
    /// `unused_cutoff`, and every dirty tunnel that has been dirty
    /// since before `dirty_cutoff`.
    ///
    /// Return the next time at which anything will definitely expire,
    /// and a list of long-lived tunnels where we need to check their usage status
    /// before we can be sure if they are expired.
    #[must_use]
    fn expire_tunnels(
        &mut self,
        now: Instant,
        params: &ExpirationParameters,
    ) -> (Option<Instant>, Vec<Weak<B::Tunnel>>) {
        let mut need_check = Vec::new();
        let mut earliest_expiration = None;
        self.open_tunnels
            .retain(|_k, v| match v.should_expire(now, params) {
                // Expires now: Do not retain.
                ShouldExpire::Now => false,

                // Will expire at `when`: keep, but update `earliest_expiration`.
                ShouldExpire::NotBefore(when) => {
                    earliest_expiration = match earliest_expiration {
                        Some(t) if t < when => Some(t),
                        _ => Some(when),
                    };
                    true
                }

                // Need to check tunnel to see if/when it is disused.
                ShouldExpire::PossiblyNow => {
                    need_check.push(Arc::downgrade(&v.tunnel));
                    true
                }
            });
        (earliest_expiration, need_check)
    }

    /// Return the time when the tunnel with given `id`, should expire.
    ///
    /// Return None if no such tunnel exists.
    fn tunnel_should_expire(
        &mut self,
        id: &<B::Tunnel as AbstractTunnel>::Id,
        now: Instant,
        params: &ExpirationParameters,
    ) -> Option<ShouldExpire> {
        self.open_tunnels
            .get(id)
            .map(|v| v.should_expire(now, params))
    }

    /// Update the "last known to be in use" time of a long-lived tunnel with ID `id`,
    /// based on learning when it was last used.
    ///
    /// Expire the tunnel if appropriate.
    ///
    /// If the tunnel is still part of the map, return the next instant at which it might expire.
    ///
    /// Returns an error if the tunnel was present but was _not_ already marked as long-lived.
    fn update_long_lived_tunnel_last_used(
        &mut self,
        id: &<B::Tunnel as AbstractTunnel>::Id,
        now: Instant,
        params: &ExpirationParameters,
        disused_since: &tor_proto::Result<Option<Instant>>,
    ) -> crate::Result<Option<Instant>> {
        let Ok(disused_since) = disused_since else {
            // got an error looking up disused time: discard the circuit.
            let discard = self.take_open(id);
            if let Some(ent) = discard {
                ent.expiration.check_long_lived()?;
            }
            return Ok(None);
        };
        let Some(tun) = self.open_tunnels.get_mut(id) else {
            // Circuit isn't there. Return.
            return Ok(None);
        };
        tun.expiration.check_long_lived()?;
        let last_known_in_use_at = disused_since.unwrap_or(now);

        tun.expiration.mark_used(last_known_in_use_at, true);
        match tun.should_expire(now, params) {
            ShouldExpire::Now | ShouldExpire::PossiblyNow => {
                let _discard = self.take_open(id);
                Ok(None)
            }
            ShouldExpire::NotBefore(instant) => Ok(Some(instant)),
        }
    }

    /// Add `pending` to the set of in-progress tunnels.
    fn add_pending_tunnel(&mut self, pending: Arc<PendingEntry<B, R>>) {
        self.pending_tunnels.insert(pending);
    }

    /// Find all pending tunnels that support `usage`.
    ///
    /// If no such tunnels are currently being built, return None.
    fn find_pending_tunnels(
        &self,
        usage: &TargetTunnelUsage,
    ) -> Option<Vec<Arc<PendingEntry<B, R>>>> {
        let result: Vec<_> = self
            .pending_tunnels
            .iter()
            .filter(|p| p.supports(usage))
            .filter(|p| !matches!(p.receiver.peek(), Some(Err(_))))
            .collect();

        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }

    /// Return true if `circ` is still pending.
    ///
    /// A tunnel will become non-pending when finishes (successfully or not), or when it's
    /// removed from this list via `clear_all_tunnels()`.
    fn tunnel_is_pending(&self, circ: &Arc<PendingEntry<B, R>>) -> bool {
        self.pending_tunnels.contains(circ)
    }

    /// Construct and add a new entry to the set of request waiting
    /// for a tunnel.
    ///
    /// Return the request, and a new receiver stream that it should
    /// use for notification of possible tunnels to use.
    fn add_pending_request(&mut self, pending: &Arc<PendingRequest<B, R>>) {
        self.pending_requests.insert(Arc::clone(pending));
    }

    /// Return all pending requests that would be satisfied by a tunnel
    /// that supports `circ_spec`.
    fn find_pending_requests(
        &self,
        circ_spec: &SupportedTunnelUsage,
    ) -> Vec<Arc<PendingRequest<B, R>>> {
        self.pending_requests
            .iter()
            .filter(|pend| pend.supported_by(circ_spec))
            .collect()
    }

    /// Clear all pending and open tunnels.
    ///
    /// Calling `clear_all_tunnels` ensures that any request that is answered _after
    /// this method runs_ will receive a tunnels that was launched _after this
    /// method runs_.
    fn clear_all_tunnels(&mut self) {
        // Note that removing entries from pending_circs will also cause the
        // tunnel tasks to realize that they are cancelled when they
        // go to tell anybody about their results.
        self.pending_tunnels.clear();
        self.open_tunnels.clear();
    }
}

/// Timing information for tunnels that have been built but never used.
///
/// Currently taken from the network parameters.
struct UnusedTimings {
    /// Minimum lifetime of a tunnel created while learning
    /// tunnel timeouts.
    learning: Duration,
    /// Minimum lifetime of a tunnel created while not learning
    /// tunnel timeouts.
    not_learning: Duration,
}

// This isn't really fallible, given the definitions of the underlying
// types.
#[allow(clippy::fallible_impl_from)]
impl From<&tor_netdir::params::NetParameters> for UnusedTimings {
    fn from(v: &tor_netdir::params::NetParameters) -> Self {
        // These try_into() calls can't fail, so unwrap() can't panic.
        #[allow(clippy::unwrap_used)]
        UnusedTimings {
            learning: v
                .unused_client_circ_timeout_while_learning_cbt
                .try_into()
                .unwrap(),
            not_learning: v.unused_client_circ_timeout.try_into().unwrap(),
        }
    }
}

/// Abstract implementation for tunnel management.
///
/// The algorithm provided here is fairly simple. In its simplest form:
///
/// When somebody asks for a tunnel for a given operation: if we find
/// one open already, we return it.  If we find in-progress tunnels
/// that would meet our needs, we wait for one to finish (or for all
/// to fail).  And otherwise, we launch one or more tunnels to meet the
/// request's needs.
///
/// If this process fails, then we retry it, up to a timeout or a
/// numerical limit.
///
/// If a tunnel not previously considered for a given request
/// finishes before the request is satisfied, and if the tunnel would
/// satisfy the request, we try to give that tunnel as an answer to
/// that request even if it was not one of the tunnels that request
/// was waiting for.
pub(crate) struct AbstractTunnelMgr<B: AbstractTunnelBuilder<R>, R: Runtime> {
    /// Builder used to construct tunnels.
    builder: B,
    /// An asynchronous runtime to use for launching tasks and
    /// checking timeouts.
    runtime: R,
    /// A CircList to manage our list of tunnels, requests, and
    /// pending tunnels.
    tunnels: sync::Mutex<TunnelList<B, R>>,

    /// Configured information about when to expire tunnels and requests.
    circuit_timing: MutCfg<CircuitTiming>,

    /// Minimum lifetime of an unused tunnel.
    ///
    /// Derived from the network parameters.
    unused_timing: sync::Mutex<UnusedTimings>,
}

/// An action to take in order to satisfy a request for a tunnel.
enum Action<B: AbstractTunnelBuilder<R>, R: Runtime> {
    /// We found an open tunnel: return immediately.
    Open(Arc<B::Tunnel>),
    /// We found one or more pending tunnels: wait until one succeeds,
    /// or all fail.
    Wait(FuturesUnordered<Shared<oneshot::Receiver<PendResult<B, R>>>>),
    /// We should launch tunnels: here are the instructions for how
    /// to do so.
    Build(Vec<TunnelBuildPlan<B, R>>),
}

/// Tunnel scheduling and lifecycle management.
mod manager;
/// Spawn an expiration task that expires a tunnel at given instant.
///
/// When the timeout occurs, if the tunnel manager is still present,
/// the task will ask the manager to expire the tunnel, if the tunnel
/// is ready to expire.
fn spawn_expiration_task<B, R>(
    runtime: &R,
    circmgr: Weak<AbstractTunnelMgr<B, R>>,
    circ_id: <<B as AbstractTunnelBuilder<R>>::Tunnel as AbstractTunnel>::Id,
    exp_inst: Instant,
) where
    R: Runtime,
    B: 'static + AbstractTunnelBuilder<R>,
{
    let now = runtime.now();
    let rt_copy = runtime.clone();
    let mut duration = exp_inst.saturating_duration_since(now);

    // NOTE: Once there was an optimization here that ran the expiration immediately if
    // `duration` was zero.
    // I discarded that optimization when I made `consider_expiring_tunnel` async,
    // since we really want this function _not_ to be async,
    // because we run it in contexts where we hold a Mutex on the tunnel list.

    // Spawn a timer expiration task with given expiration instant.
    if let Err(e) = runtime.spawn(async move {
        loop {
            rt_copy.sleep(duration).await;
            let cm = if let Some(cm) = Weak::upgrade(&circmgr) {
                cm
            } else {
                return;
            };
            match cm.consider_expiring_tunnel(&circ_id, exp_inst).await {
                Ok(None) => return,
                Ok(Some(when)) => {
                    duration = when.saturating_duration_since(rt_copy.now());
                }
                Err(e) => {
                    warn_report!(
                        e,
                        "Error while considering expiration for tunnel {:?}",
                        circ_id
                    );
                    return;
                }
            }
        }
    }) {
        warn_report!(e, "Unable to launch expiration task");
    }
}

#[cfg(test)]
#[path = "mgr/tests.rs"]
mod test;
