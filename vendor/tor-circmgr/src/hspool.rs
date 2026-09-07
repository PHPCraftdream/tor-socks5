//! Manage a pool of circuits for usage with onion services.
//
// TODO HS TEST: We need tests here. First, though, we need a testing strategy.
mod config;
mod pool;

use std::{
    ops::Deref,
    sync::{Arc, Mutex, Weak},
};

use crate::{
    AbstractTunnel, CircMgr, CircMgrInner, ClientOnionServiceDataTunnel,
    ClientOnionServiceDirTunnel, ClientOnionServiceIntroTunnel, Error, Result,
    ServiceOnionServiceDataTunnel, ServiceOnionServiceDirTunnel, ServiceOnionServiceIntroTunnel,
    build::{TunnelBuilder, onion_circparams_from_netparams},
    mgr::AbstractTunnelBuilder,
    path::hspath::hs_stem_terminal_hop_usage,
    timeouts,
};
use futures::{StreamExt, TryFutureExt};
use once_cell::sync::OnceCell;
use tor_error::{Bug, debug_report};
use tor_error::{bad_api_usage, internal};
use tor_guardmgr::VanguardMode;
use tor_linkspec::{
    CircTarget, HasRelayIds as _, IntoOwnedChanTarget, OwnedChanTarget, OwnedCircTarget,
};
use tor_netdir::{NetDir, NetDirProvider, Relay};
use tor_proto::client::circuit::{self, CircParameters};
use tor_relay_selection::{LowLevelRelayPredicate, RelayExclusion};
use tor_rtcompat::{
    Runtime, SleepProviderExt, SpawnExt,
    scheduler::{TaskHandle, TaskSchedule},
};
use tracing::{debug, instrument, trace, warn};
use web_time_compat::{Duration, Instant, SystemTime};

use std::result::Result as StdResult;

pub use config::HsCircPoolConfig;

use self::pool::HsCircPrefs;

#[cfg(all(feature = "vanguards", feature = "hs-common"))]
use crate::path::hspath::select_middle_for_vanguard_circ;

/// The (onion-service-related) purpose for which a given circuit is going to be
/// used.
///
/// We will use this to tell how the path for a given circuit is to be
/// constructed.
#[cfg(feature = "hs-common")]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum HsCircKind {
    /// Circuit from an onion service to an HsDir.
    SvcHsDir,
    /// Circuit from an onion service to an Introduction Point.
    SvcIntro,
    /// Circuit from an onion service to a Rendezvous Point.
    SvcRend,
    /// Circuit from an onion service client to an HsDir.
    ClientHsDir,
    /// Circuit from an onion service client to an Introduction Point.
    ClientIntro,
    /// Circuit from an onion service client to a Rendezvous Point.
    ClientRend,
}

impl HsCircKind {
    /// Return the [`HsCircStemKind`] needed to build this type of circuit.
    fn stem_kind(&self) -> HsCircStemKind {
        match self {
            HsCircKind::SvcIntro => HsCircStemKind::Naive,
            HsCircKind::SvcHsDir => {
                // TODO: we might want this to be GUARDED
                HsCircStemKind::Naive
            }
            HsCircKind::ClientRend => {
                // NOTE: Technically, client rendezvous circuits don't need a "guarded"
                // stem kind, because the rendezvous point is selected by the client,
                // so it cannot easily be controlled by an attacker.
                //
                // However, to keep the implementation simple, we use "guarded" circuit stems,
                // and designate the last hop of the stem as the rendezvous point.
                HsCircStemKind::Guarded
            }
            HsCircKind::SvcRend | HsCircKind::ClientHsDir | HsCircKind::ClientIntro => {
                HsCircStemKind::Guarded
            }
        }
    }
}

/// A hidden service circuit stem.
///
/// This represents a hidden service circuit that has not yet been extended to a target.
///
/// See [HsCircStemKind].
pub(crate) struct HsCircStem<C: AbstractTunnel> {
    /// The circuit.
    pub(crate) circ: C,
    /// Whether the circuit is NAIVE  or GUARDED.
    pub(crate) kind: HsCircStemKind,
}

impl<C: AbstractTunnel> HsCircStem<C> {
    /// Whether this circuit satisfies _all_ the [`HsCircPrefs`].
    ///
    /// Returns `false` if any of the `prefs` are not satisfied.
    fn satisfies_prefs(&self, prefs: &HsCircPrefs) -> bool {
        let HsCircPrefs { kind_prefs } = prefs;

        match kind_prefs {
            Some(kind) => *kind == self.kind,
            None => true,
        }
    }
}

impl<C: AbstractTunnel> Deref for HsCircStem<C> {
    type Target = C;

    fn deref(&self) -> &Self::Target {
        &self.circ
    }
}

impl<C: AbstractTunnel> HsCircStem<C> {
    /// Check if this circuit stem is of the specified `kind`
    /// or can be extended to become that kind.
    ///
    /// Returns `true` if this `HsCircStem`'s kind is equal to `other`,
    /// or if its kind is [`Naive`](HsCircStemKind::Naive)
    /// and `other` is [`Guarded`](HsCircStemKind::Guarded).
    pub(crate) fn can_become(&self, other: HsCircStemKind) -> bool {
        use HsCircStemKind::*;

        match (self.kind, other) {
            (Naive, Naive) | (Guarded, Guarded) | (Naive, Guarded) => true,
            (Guarded, Naive) => false,
        }
    }
}

#[allow(rustdoc::private_intra_doc_links)]
/// A kind of hidden service circuit stem.
///
/// See [hspath](crate::path::hspath) docs for more information.
///
/// The structure of a circuit stem depends on whether vanguards are enabled:
///
///   * with vanguards disabled:
///      ```text
///         NAIVE   = G -> M -> M
///         GUARDED = G -> M -> M
///      ```
///
///   * with lite vanguards enabled:
///      ```text
///         NAIVE   = G -> L2 -> M
///         GUARDED = G -> L2 -> M
///      ```
///
///   * with full vanguards enabled:
///      ```text
///         NAIVE    = G -> L2 -> L3
///         GUARDED = G -> L2 -> L3 -> M
///      ```
#[derive(Copy, Clone, Debug, PartialEq, derive_more::Display)]
#[non_exhaustive]
pub(crate) enum HsCircStemKind {
    /// A naive circuit stem.
    ///
    /// Used for building circuits to a final hop that an adversary cannot easily control,
    /// for example if the final hop is is randomly chosen by us.
    #[display("NAIVE")]
    Naive,
    /// An guarded circuit stem.
    ///
    /// Used for building circuits to a final hop that an adversary can easily control,
    /// for example if the final hop is not chosen by us.
    #[display("GUARDED")]
    Guarded,
}

impl HsCircStemKind {
    /// Return the number of hops this `HsCircKind` ought to have when using the specified
    /// [`VanguardMode`].
    pub(crate) fn num_hops(&self, mode: VanguardMode) -> StdResult<usize, Bug> {
        use HsCircStemKind::*;
        use VanguardMode::*;

        let len = match (mode, self) {
            #[cfg(all(feature = "vanguards", feature = "hs-common"))]
            (Lite, _) => 3,
            #[cfg(all(feature = "vanguards", feature = "hs-common"))]
            (Full, Naive) => 3,
            #[cfg(all(feature = "vanguards", feature = "hs-common"))]
            (Full, Guarded) => 4,
            (Disabled, _) => 3,
            (_, _) => {
                return Err(internal!("Unsupported vanguard mode {mode}"));
            }
        };

        Ok(len)
    }
}

/// An object to provide circuits for implementing onion services.
pub struct HsCircPool<R: Runtime>(Arc<HsCircPoolInner<TunnelBuilder<R>, R>>);

impl<R: Runtime> HsCircPool<R> {
    /// Create a new `HsCircPool`.
    ///
    /// This will not work properly before "launch_background_tasks" is called.
    pub fn new(circmgr: &Arc<CircMgr<R>>) -> Self {
        Self(Arc::new(HsCircPoolInner::new(circmgr)))
    }

    /// Create a client directory circuit ending at the chosen hop `target`.
    ///
    /// Only makes  a single attempt; the caller needs to loop if they want to retry.
    #[instrument(level = "trace", skip_all)]
    pub async fn get_or_launch_client_dir<T>(
        &self,
        netdir: &NetDir,
        target: T,
    ) -> Result<ClientOnionServiceDirTunnel>
    where
        T: CircTarget + Sync,
    {
        let tunnel = self
            .0
            .get_or_launch_specific(netdir, HsCircKind::ClientHsDir, target)
            .await?;
        Ok(tunnel.into())
    }

    /// Create a client introduction circuit ending at the chosen hop `target`.
    ///
    /// Only makes  a single attempt; the caller needs to loop if they want to retry.
    #[instrument(level = "trace", skip_all)]
    pub async fn get_or_launch_client_intro<T>(
        &self,
        netdir: &NetDir,
        target: T,
    ) -> Result<ClientOnionServiceIntroTunnel>
    where
        T: CircTarget + Sync,
    {
        let tunnel = self
            .0
            .get_or_launch_specific(netdir, HsCircKind::ClientIntro, target)
            .await?;
        Ok(tunnel.into())
    }

    /// Create a service directory circuit ending at the chosen hop `target`.
    ///
    /// Only makes  a single attempt; the caller needs to loop if they want to retry.
    #[instrument(level = "trace", skip_all)]
    pub async fn get_or_launch_svc_dir<T>(
        &self,
        netdir: &NetDir,
        target: T,
    ) -> Result<ServiceOnionServiceDirTunnel>
    where
        T: CircTarget + Sync,
    {
        let tunnel = self
            .0
            .get_or_launch_specific(netdir, HsCircKind::SvcHsDir, target)
            .await?;
        Ok(tunnel.into())
    }

    /// Create a service introduction circuit ending at the chosen hop `target`.
    ///
    /// Only makes  a single attempt; the caller needs to loop if they want to retry.
    #[instrument(level = "trace", skip_all)]
    pub async fn get_or_launch_svc_intro<T>(
        &self,
        netdir: &NetDir,
        target: T,
    ) -> Result<ServiceOnionServiceIntroTunnel>
    where
        T: CircTarget + Sync,
    {
        let tunnel = self
            .0
            .get_or_launch_specific(netdir, HsCircKind::SvcIntro, target)
            .await?;
        Ok(tunnel.into())
    }

    /// Create a service rendezvous (data) circuit ending at the chosen hop `target`.
    ///
    /// Only makes  a single attempt; the caller needs to loop if they want to retry.
    #[instrument(level = "trace", skip_all)]
    pub async fn get_or_launch_svc_rend<T>(
        &self,
        netdir: &NetDir,
        target: T,
    ) -> Result<ServiceOnionServiceDataTunnel>
    where
        T: CircTarget + Sync,
    {
        let tunnel = self
            .0
            .get_or_launch_specific(netdir, HsCircKind::SvcRend, target)
            .await?;
        Ok(tunnel.into())
    }

    /// Create a circuit suitable for use as a rendezvous circuit by a client.
    ///
    /// Return the circuit, along with a [`Relay`] from `netdir` representing its final hop.
    ///
    /// Only makes  a single attempt; the caller needs to loop if they want to retry.
    #[instrument(level = "trace", skip_all)]
    pub async fn get_or_launch_client_rend<'a>(
        &self,
        netdir: &'a NetDir,
    ) -> Result<(ClientOnionServiceDataTunnel, Relay<'a>)> {
        let (tunnel, relay) = self.0.get_or_launch_client_rend(netdir).await?;
        Ok((tunnel.into(), relay))
    }

    /// Return an estimate-based delay for how long a given
    /// [`Action`](timeouts::Action) should be allowed to complete.
    ///
    /// This function has the same semantics as
    /// [`CircMgr::estimate_timeout`].
    /// See the notes there.
    ///
    /// In particular **you do not need to use this function** in order to get
    /// reasonable timeouts for the circuit-building operations provided by `HsCircPool`.
    //
    // In principle we could have made this available by making `HsCircPool` `Deref`
    // to `CircMgr`, but we don't want to do that because `CircMgr` has methods that
    // operate on *its* pool which is separate from the pool maintained by `HsCircPool`.
    //
    // We *might* want to provide a method to access the underlying `CircMgr`
    // but that has the same issues, albeit less severely.
    pub fn estimate_timeout(&self, timeout_action: &timeouts::Action) -> std::time::Duration {
        self.0.estimate_timeout(timeout_action)
    }

    /// Launch the periodic daemon tasks required by the manager to function properly.
    ///
    /// Returns a set of [`TaskHandle`]s that can be used to manage the daemon tasks.
    pub fn launch_background_tasks(
        self: &Arc<Self>,
        runtime: &R,
        netdir_provider: &Arc<dyn NetDirProvider + 'static>,
    ) -> Result<Vec<TaskHandle>> {
        HsCircPoolInner::launch_background_tasks(&self.0.clone(), runtime, netdir_provider)
    }

    /// Retire the circuits in this pool.
    ///
    /// This is used for handling vanguard configuration changes:
    /// if the [`VanguardMode`] changes, we need to empty the pool and rebuild it,
    /// because the old circuits are no longer suitable for use.
    pub fn retire_all_circuits(&self) -> StdResult<(), tor_config::ReconfigureError> {
        self.0.retire_all_circuits()
    }

    /// Return the current time instant from the runtime.
    ///
    /// This provides mockable time for use in error tracking and other
    /// time-sensitive operations.
    pub fn now(&self) -> Instant {
        self.0.circmgr.mgr.peek_runtime().now()
    }

    /// Return the current wall-clock time from the runtime.
    pub fn wallclock(&self) -> SystemTime {
        self.0.circmgr.mgr.peek_runtime().wallclock()
    }
}

/// An object to provide circuits for implementing onion services.
pub(crate) struct HsCircPoolInner<B: AbstractTunnelBuilder<R> + 'static, R: Runtime> {
    /// An underlying circuit manager, used for constructing circuits.
    circmgr: Arc<CircMgrInner<B, R>>,
    /// A task handle for making the background circuit launcher fire early.
    //
    // TODO: I think we may want to move this into the same Mutex as Pool
    // eventually.  But for now, this is fine, since it's just an implementation
    // detail.
    //
    // TODO MSRV TBD: Replace with OnceLock (#1996)
    launcher_handle: OnceCell<TaskHandle>,
    /// The mutable state of this pool.
    inner: Mutex<Inner<B::Tunnel>>,
}

/// The mutable state of an [`HsCircPool`]
struct Inner<C: AbstractTunnel> {
    /// A collection of pre-constructed circuits.
    pool: pool::Pool<C>,
}

impl<R: Runtime> HsCircPoolInner<TunnelBuilder<R>, R> {
    /// Internal implementation for [`HsCircPool::new`].
    pub(crate) fn new(circmgr: &CircMgr<R>) -> Self {
        Self::new_internal(&circmgr.0)
    }
}

/// Hidden-service circuit pool management.
mod pool_manager;
/// Return true if we can extend a pre-built circuit `circ` to `target`.
///
/// We require that the circuit is open, that every hop  in the circuit is
/// listed in `netdir`, and that no hop in the circuit shares a family with
/// `target`.
fn circuit_compatible_with_target<C: AbstractTunnel>(
    netdir: &NetDir,
    circ: &HsCircStem<C>,
    circ_kind: HsCircKind,
    exclude_target: &RelayExclusion,
) -> bool {
    let last_hop_usage = hs_stem_terminal_hop_usage(Some(circ_kind));

    // NOTE, TODO #504:
    // This uses a RelayExclusion directly, when we would be better off
    // using a RelaySelector to make sure that we had checked every relevant
    // property.
    //
    // The behavior is okay, since we already checked all the properties of the
    // circuit's relays when we first constructed the circuit.  Still, it would
    // be better to use refactor and a RelaySelector instead.
    circuit_still_useable(
        netdir,
        circ,
        |relay| exclude_target.low_level_predicate_permits_relay(relay),
        |last_hop| last_hop_usage.low_level_predicate_permits_relay(last_hop),
    )
}

/// Return true if we can extend a pre-built vanguards circuit `circ` to `target`.
///
/// We require that the circuit is open, that it can become the specified
/// kind of [`HsCircStem`], that every hop in the circuit is listed in `netdir`,
/// and that the last two hops are different from the specified target.
fn vanguards_circuit_compatible_with_target<C: AbstractTunnel, T>(
    netdir: &NetDir,
    circ: &HsCircStem<C>,
    kind: HsCircStemKind,
    circ_kind: HsCircKind,
    avoid_target: Option<&T>,
) -> bool
where
    T: CircTarget + Sync,
{
    if let Some(target) = avoid_target {
        let Ok(circ_path) = circ.circ.single_path() else {
            // Circuit is unusable, so we can't use it.
            return false;
        };
        // The last 2 hops of the circuit must be different from the circuit target, because:
        //   * a relay won't let you extend the circuit to itself
        //   * relays won't let you extend the circuit to their previous hop
        let take_n = 2;
        if circ_path
            .hops()
            .iter()
            .rev()
            .take(take_n)
            .flat_map(|hop| hop.as_chan_target())
            .any(|hop| hop.has_any_relay_id_from(target))
        {
            return false;
        }
    }

    // TODO #504: usage of low_level_predicate_permits_relay is inherently dubious.
    let last_hop_usage = hs_stem_terminal_hop_usage(Some(circ_kind));

    circ.can_become(kind)
        && circuit_still_useable(
            netdir,
            circ,
            |_relay| true,
            |last_hop| last_hop_usage.low_level_predicate_permits_relay(last_hop),
        )
}

/// Return true if we can still use a given pre-build circuit.
///
/// We require that the circuit is open, that every hop  in the circuit is
/// listed in `netdir`, and that `relay_okay` returns true for every hop on the
/// circuit.
fn circuit_still_useable<C, F1, F2>(
    netdir: &NetDir,
    circ: &HsCircStem<C>,
    relay_okay: F1,
    last_hop_ok: F2,
) -> bool
where
    C: AbstractTunnel,
    F1: Fn(&Relay<'_>) -> bool,
    F2: Fn(&Relay<'_>) -> bool,
{
    let circ = &circ.circ;
    if circ.is_closing() {
        return false;
    }

    let Ok(path) = circ.single_path() else {
        // Circuit is unusable, so we can't use it.
        return false;
    };
    let last_hop = path.hops().last().expect("No hops in circuit?!");
    match relay_for_path_ent(netdir, last_hop) {
        Err(NoRelayForPathEnt::HopWasVirtual) => {}
        Err(NoRelayForPathEnt::NoSuchRelay) => {
            return false;
        }
        Ok(r) => {
            if !last_hop_ok(&r) {
                return false;
            }
        }
    };

    path.iter().all(|ent: &circuit::PathEntry| {
        match relay_for_path_ent(netdir, ent) {
            Err(NoRelayForPathEnt::HopWasVirtual) => {
                // This is a virtual hop; it's necessarily compatible with everything.
                true
            }
            Err(NoRelayForPathEnt::NoSuchRelay) => {
                // We require that every relay in this circuit is still listed; an
                // unlisted relay means "reject".
                false
            }
            Ok(r) => {
                // Now it's all down to the predicate.
                relay_okay(&r)
            }
        }
    })
}

/// A possible error condition when trying to look up a PathEntry
//
// Only used for one module-internal function, so doesn't derive Error.
#[derive(Clone, Debug)]
enum NoRelayForPathEnt {
    /// This was a virtual hop; it doesn't have a relay.
    HopWasVirtual,
    /// The relay wasn't found in the netdir.
    NoSuchRelay,
}

/// Look up a relay in a netdir corresponding to `ent`
fn relay_for_path_ent<'a>(
    netdir: &'a NetDir,
    ent: &circuit::PathEntry,
) -> StdResult<Relay<'a>, NoRelayForPathEnt> {
    let Some(c) = ent.as_chan_target() else {
        return Err(NoRelayForPathEnt::HopWasVirtual);
    };
    let Some(relay) = netdir.by_ids(c) else {
        return Err(NoRelayForPathEnt::NoSuchRelay);
    };
    Ok(relay)
}

/// Background task to launch onion circuits as needed.
#[allow(clippy::cognitive_complexity)] // TODO #2010: Refactor, after !3007 is in.
#[instrument(level = "trace", skip_all)]
async fn launch_hs_circuits_as_needed<B: AbstractTunnelBuilder<R> + 'static, R: Runtime>(
    pool: Weak<HsCircPoolInner<B, R>>,
    netdir_provider: Weak<dyn NetDirProvider + 'static>,
    mut schedule: TaskSchedule<R>,
) {
    /// Default delay when not told to fire explicitly. Chosen arbitrarily.
    const DELAY: Duration = Duration::from_secs(30);

    while schedule.next().await.is_some() {
        let (pool, provider) = match (pool.upgrade(), netdir_provider.upgrade()) {
            (Some(x), Some(y)) => (x, y),
            _ => {
                break;
            }
        };
        let now = pool.circmgr.mgr.peek_runtime().now();
        pool.remove_closed();
        let mut circs_to_launch = {
            let mut inner = pool.inner.lock().expect("poisioned_lock");
            inner.pool.update_target_size(now);
            inner.pool.circs_to_launch()
        };
        let n_to_launch = circs_to_launch.n_to_launch();
        let mut max_attempts = n_to_launch * 2;

        if n_to_launch > 0 {
            debug!(
                "launching {} NAIVE  and {} GUARDED circuits",
                circs_to_launch.stem(),
                circs_to_launch.guarded_stem()
            );
        }

        // TODO: refactor this to launch the circuits in parallel
        'inner: while circs_to_launch.n_to_launch() > 0 {
            max_attempts -= 1;
            if max_attempts == 0 {
                // We want to avoid retrying over and over in a tight loop if all our attempts
                // are failing.
                warn!("Too many preemptive onion service circuits failed; waiting a while.");
                break 'inner;
            }
            if let Ok(netdir) = provider.netdir(tor_netdir::Timeliness::Timely) {
                // We want to launch a circuit, and we have a netdir that we can use
                // to launch it.
                //
                // TODO: Possibly we should be doing this in a background task, and
                // launching several of these in parallel.  If we do, we should think about
                // whether taking the fastest will expose us to any attacks.
                let no_target: Option<&OwnedCircTarget> = None;
                let for_launch = circs_to_launch.for_launch();

                // TODO HS: We should catch panics, here or in launch_hs_unmanaged.
                match pool
                    .circmgr
                    .launch_hs_unmanaged(no_target, &netdir, for_launch.kind(), None)
                    .await
                {
                    Ok(circ) => {
                        let kind = for_launch.kind();
                        let circ = HsCircStem { circ, kind };
                        pool.inner.lock().expect("poisoned lock").pool.insert(circ);
                        trace!("successfully launched {kind} circuit");
                        for_launch.note_circ_launched();
                    }
                    Err(err) => {
                        debug_report!(err, "Unable to build preemptive circuit for onion services");
                    }
                }
            } else {
                // We'd like to launch a circuit, but we don't have a netdir that we
                // can use.
                //
                // TODO HS possibly instead of a fixed delay we want to wait for more
                // netdir info?
                break 'inner;
            }
        }

        // We have nothing to launch now, so we'll try after a while.
        schedule.fire_in(DELAY);
    }
}

/// Background task to remove unusable circuits whenever the directory changes.
async fn remove_unusable_circuits<B: AbstractTunnelBuilder<R> + 'static, R: Runtime>(
    pool: Weak<HsCircPoolInner<B, R>>,
    netdir_provider: Weak<dyn NetDirProvider + 'static>,
) {
    let mut event_stream = match netdir_provider.upgrade() {
        Some(nd) => nd.events(),
        None => return,
    };

    // Note: We only look at the event stream here, not any kind of TaskSchedule.
    // That's fine, since this task only wants to fire when the directory changes,
    // and the directory will not change while we're dormant.
    //
    // Removing closed circuits is also handled above in launch_hs_circuits_as_needed.
    while event_stream.next().await.is_some() {
        let (pool, provider) = match (pool.upgrade(), netdir_provider.upgrade()) {
            (Some(x), Some(y)) => (x, y),
            _ => {
                break;
            }
        };
        pool.remove_closed();
        if let Ok(netdir) = provider.netdir(tor_netdir::Timeliness::Timely) {
            pool.remove_unlisted(&netdir);
        }
    }
}

#[cfg(test)]
#[path = "hspool/tests.rs"]
mod test;
