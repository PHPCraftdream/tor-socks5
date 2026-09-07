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

use build::TunnelBuilder;
use mgr::{AbstractTunnel, AbstractTunnelBuilder};
use tor_basic_utils::retry::RetryDelay;
use tor_chanmgr::ChanMgr;
use tor_dircommon::fallback::FallbackList;
use tor_error::{error_report, warn_report};
use tor_guardmgr::RetireCircuits;
use tor_linkspec::ChanTarget;
use tor_netdir::{DirEvent, NetDir, NetDirProvider, Timeliness};
use tor_proto::circuit::UniqId;
use tor_proto::client::circuit::CircParameters;
use tor_rtcompat::Runtime;

#[cfg(any(feature = "specific-relay", feature = "hs-common"))]
use tor_linkspec::IntoOwnedChanTarget;

use futures::StreamExt;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use tor_rtcompat::SpawnExt;
use tracing::{debug, info, instrument, trace, warn};

#[cfg(any(test, feature = "testing"))]
pub use config::test_config::TestConfig;

pub mod build;
mod config;
mod err;
#[cfg(feature = "hs-common")]
pub mod hspool;
mod impls;
pub mod isolation;
mod mgr;
#[cfg(test)]
mod mocks;
mod preemptive;
pub mod timeouts;
mod tunnel;
mod usage;

// Can't apply `visibility` to modules.
cfg_if::cfg_if! {
    if #[cfg(feature = "experimental-api")] {
        pub mod path;
    } else {
        pub(crate) mod path;
    }
}

pub use err::Error;
pub use isolation::IsolationToken;
pub use tor_guardmgr::{ClockSkewEvents, GuardMgrConfig, SkewEstimate};
pub use tunnel::{
    ClientDataTunnel, ClientDirTunnel, ClientOnionServiceDataTunnel, ClientOnionServiceDirTunnel,
    ClientOnionServiceIntroTunnel, ServiceOnionServiceDataTunnel, ServiceOnionServiceDirTunnel,
    ServiceOnionServiceIntroTunnel,
};
#[cfg(feature = "conflux")]
pub use tunnel::{
    ClientMultiPathDataTunnel, ClientMultiPathOnionServiceDataTunnel,
    ServiceMultiPathOnionServiceDataTunnel,
};
pub use usage::{TargetPort, TargetPorts};

pub use config::{
    CircMgrConfig, CircuitTiming, CircuitTimingBuilder, PathConfig, PathConfigBuilder,
    PreemptiveCircuitConfig, PreemptiveCircuitConfigBuilder,
};

use crate::isolation::StreamIsolation;
use crate::mgr::TunnelProvenance;
use crate::preemptive::PreemptiveCircuitPredictor;
use usage::TargetTunnelUsage;

use safelog::sensitive as sv;
#[cfg(feature = "geoip")]
use tor_geoip::CountryCode;
pub use tor_guardmgr::{ExternalActivity, FirstHopId};
use tor_persist::StateMgr;
use tor_rtcompat::scheduler::{TaskHandle, TaskSchedule};

#[cfg(feature = "hs-common")]
use crate::hspool::{HsCircKind, HsCircStemKind};
#[cfg(all(feature = "vanguards", feature = "hs-common"))]
use tor_guardmgr::vanguards::VanguardMgr;

/// A Result type as returned from this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Type alias for dynamic StorageHandle that can handle our timeout state.
type TimeoutStateHandle = tor_persist::DynStorageHandle<timeouts::pareto::ParetoTimeoutState>;

/// Key used to load timeout state information.
const PARETO_TIMEOUT_DATA_KEY: &str = "circuit_timeouts";

/// Represents what we know about the Tor network.
///
/// This can either be a complete directory, or a list of fallbacks.
///
/// Not every DirInfo can be used to build every kind of circuit:
/// if you try to build a path with an inadequate DirInfo, you'll get a
/// NeedConsensus error.
#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
pub enum DirInfo<'a> {
    /// A list of fallbacks, for use when we don't know a network directory.
    Fallbacks(&'a FallbackList),
    /// A complete network directory
    Directory(&'a NetDir),
    /// No information: we can only build one-hop paths: and that, only if the
    /// guard manager knows some guards or fallbacks.
    Nothing,
}

impl<'a> From<&'a FallbackList> for DirInfo<'a> {
    fn from(v: &'a FallbackList) -> DirInfo<'a> {
        DirInfo::Fallbacks(v)
    }
}
impl<'a> From<&'a NetDir> for DirInfo<'a> {
    fn from(v: &'a NetDir) -> DirInfo<'a> {
        DirInfo::Directory(v)
    }
}
impl<'a> DirInfo<'a> {
    /// Return a set of circuit parameters for this DirInfo.
    fn circ_params(&self, usage: &TargetTunnelUsage) -> Result<CircParameters> {
        use tor_netdir::params::NetParameters;
        // We use a common function for both cases here to be sure that
        // we look at the defaults from NetParameters code.
        let defaults = NetParameters::default();
        let net_params = match self {
            DirInfo::Directory(d) => d.params(),
            _ => &defaults,
        };
        match usage {
            #[cfg(feature = "hs-common")]
            TargetTunnelUsage::HsCircBase { .. } => {
                build::onion_circparams_from_netparams(net_params)
            }
            _ => build::exit_circparams_from_netparams(net_params),
        }
    }
}

/// A Circuit Manager (CircMgr) manages a set of circuits, returning them
/// when they're suitable, and launching them if they don't already exist.
///
/// Right now, its notion of "suitable" is quite rudimentary: it just
/// believes in two kinds of circuits: Exit circuits, and directory
/// circuits.  Exit circuits are ones that were created to connect to
/// a set of ports; directory circuits were made to talk to directory caches.
///
/// This is a "handle"; clones of it share state.
pub struct CircMgr<R: Runtime>(Arc<CircMgrInner<build::TunnelBuilder<R>, R>>);

impl<R: Runtime> CircMgr<R> {
    /// Construct a new circuit manager.
    ///
    /// # Usage note
    ///
    /// For the manager to work properly, you will need to call `CircMgr::launch_background_tasks`.
    pub fn new<SM, CFG: CircMgrConfig>(
        config: &CFG,
        storage: SM,
        runtime: &R,
        chanmgr: Arc<ChanMgr<R>>,
        guardmgr: &tor_guardmgr::GuardMgr<R>,
    ) -> Result<Self>
    where
        SM: tor_persist::StateMgr + Clone + Send + Sync + 'static,
    {
        Ok(Self(Arc::new(CircMgrInner::new(
            config, storage, runtime, chanmgr, guardmgr,
        )?)))
    }

    /// Return a circuit suitable for sending one-hop BEGINDIR streams,
    /// launching it if necessary.
    #[instrument(level = "trace", skip_all)]
    pub async fn get_or_launch_dir(&self, netdir: DirInfo<'_>) -> Result<ClientDirTunnel> {
        let tunnel = self.0.get_or_launch_dir(netdir).await?;
        Ok(tunnel.into())
    }

    /// Return a circuit suitable for exiting to all of the provided
    /// `ports`, launching it if necessary.
    ///
    /// If the list of ports is empty, then the chosen circuit will
    /// still end at _some_ exit.
    #[instrument(level = "trace", skip_all)]
    pub async fn get_or_launch_exit(
        &self,
        netdir: DirInfo<'_>, // TODO: This has to be a NetDir.
        ports: &[TargetPort],
        isolation: StreamIsolation,
        // TODO GEOIP: this cannot be stabilised like this, since Cargo features need to be
        //             additive. The function should be refactored to be builder-like.
        #[cfg(feature = "geoip")] country_code: Option<CountryCode>,
    ) -> Result<ClientDataTunnel> {
        let tunnel = self
            .0
            .get_or_launch_exit(
                netdir,
                ports,
                isolation,
                #[cfg(feature = "geoip")]
                country_code,
            )
            .await?;
        Ok(tunnel.into())
    }

    /// Return a circuit to a specific relay, suitable for using for direct
    /// (one-hop) directory downloads.
    ///
    /// This could be used, for example, to download a descriptor for a bridge.
    #[cfg(feature = "specific-relay")]
    #[instrument(level = "trace", skip_all)]
    pub async fn get_or_launch_dir_specific<T: IntoOwnedChanTarget>(
        &self,
        target: T,
    ) -> Result<ClientDirTunnel> {
        let tunnel = self.0.get_or_launch_dir_specific(target).await?;
        Ok(tunnel.into())
    }

    /// Launch the periodic daemon tasks required by the manager to function properly.
    ///
    /// Returns a set of [`TaskHandle`]s that can be used to manage the daemon tasks.
    //
    // NOTE(eta): The ?Sized on D is so we can pass a trait object in.
    #[instrument(level = "trace", skip_all)]
    pub fn launch_background_tasks<D, S>(
        self: &Arc<Self>,
        runtime: &R,
        dir_provider: &Arc<D>,
        state_mgr: S,
    ) -> Result<Vec<TaskHandle>>
    where
        D: NetDirProvider + 'static + ?Sized,
        S: StateMgr + std::marker::Send + 'static,
    {
        CircMgrInner::launch_background_tasks(&self.0.clone(), runtime, dir_provider, state_mgr)
    }

    /// Return true if `netdir` has enough information to be used for this
    /// circuit manager.
    ///
    /// (This will check whether the netdir is missing any primary guard
    /// microdescriptors)
    pub fn netdir_is_sufficient(&self, netdir: &NetDir) -> bool {
        self.0.netdir_is_sufficient(netdir)
    }

    /// If `circ_id` is the unique identifier for a circuit that we're
    /// keeping track of, don't give it out for any future requests.
    pub fn retire_circ(&self, circ_id: &UniqId) {
        self.0.retire_circ(circ_id);
    }

    /// Record that a failure occurred on a circuit with a given guard, in a way
    /// that makes us unwilling to use that guard for future circuits.
    ///
    pub fn note_external_failure(
        &self,
        target: &impl ChanTarget,
        external_failure: ExternalActivity,
    ) {
        self.0.note_external_failure(target, external_failure);
    }

    /// Record that a success occurred on a circuit with a given guard, in a way
    /// that makes us possibly willing to use that guard for future circuits.
    pub fn note_external_success(
        &self,
        target: &impl ChanTarget,
        external_activity: ExternalActivity,
    ) {
        self.0.note_external_success(target, external_activity);
    }

    /// Return a stream of events about our estimated clock skew; these events
    /// are `None` when we don't have enough information to make an estimate,
    /// and `Some(`[`SkewEstimate`]`)` otherwise.
    ///
    /// Note that this stream can be lossy: if the estimate changes more than
    /// one before you read from the stream, you might only get the most recent
    /// update.
    pub fn skew_events(&self) -> ClockSkewEvents {
        self.0.skew_events()
    }

    /// Try to change our configuration settings to `new_config`.
    ///
    /// The actual behavior here will depend on the value of `how`.
    ///
    /// Returns whether any of the circuit pools should be cleared.
    #[instrument(level = "trace", skip_all)]
    pub fn reconfigure<CFG: CircMgrConfig>(
        &self,
        new_config: &CFG,
        how: tor_config::Reconfigure,
    ) -> std::result::Result<RetireCircuits, tor_config::ReconfigureError> {
        self.0.reconfigure(new_config, how)
    }

    /// Return an estimate-based delay for how long a given
    /// [`Action`](timeouts::Action) should be allowed to complete.
    ///
    /// Note that **you do not need to use this function** in order to get
    /// reasonable timeouts for the circuit-building operations provided by the
    /// `tor-circmgr` crate: those, unless specifically noted, always use these
    /// timeouts to cancel circuit operations that have taken too long.
    ///
    /// Instead, you should only use this function when you need to estimate how
    /// long some _other_ operation should take to complete.  For example, if
    /// you are sending a request over a 3-hop circuit and waiting for a reply,
    /// you might choose to wait for `estimate_timeout(Action::RoundTrip {
    /// length: 3 })`.
    ///
    /// Note also that this function returns a _timeout_ that the operation
    /// should be permitted to complete, not an estimated Duration that the
    /// operation _will_ take to complete. Timeouts are chosen to ensure that
    /// most operations will complete, but very slow ones will not.  So even if
    /// we expect that a circuit will complete in (say) 3 seconds, we might
    /// still allow a timeout of 4.5 seconds, to ensure that most circuits can
    /// complete.
    ///
    /// Estimate-based timeouts may change over time, given observations on the
    /// actual amount of time needed for circuits to complete building.  If not
    /// enough information has been gathered, a reasonable default will be used.
    pub fn estimate_timeout(&self, timeout_action: &timeouts::Action) -> std::time::Duration {
        self.0.estimate_timeout(timeout_action)
    }

    /// Return a reference to the associated CircuitBuilder that this CircMgr
    /// will use to create its circuits.
    #[cfg(feature = "experimental-api")]
    pub fn builder(&self) -> &TunnelBuilder<R> {
        CircMgrInner::builder(&self.0)
    }
}

/// Internal object used to implement CircMgr, which allows for mocking.
#[derive(Clone)]
pub(crate) struct CircMgrInner<B: AbstractTunnelBuilder<R> + 'static, R: Runtime> {
    /// The underlying circuit manager object that implements our behavior.
    mgr: Arc<mgr::AbstractTunnelMgr<B, R>>,
    /// A preemptive circuit predictor, for, uh, building circuits preemptively.
    predictor: Arc<Mutex<PreemptiveCircuitPredictor>>,
}

impl<R: Runtime> CircMgrInner<TunnelBuilder<R>, R> {
    /// Construct a new circuit manager.
    ///
    /// # Usage note
    ///
    /// For the manager to work properly, you will need to call `CircMgr::launch_background_tasks`.
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn new<SM, CFG: CircMgrConfig>(
        config: &CFG,
        storage: SM,
        runtime: &R,
        chanmgr: Arc<ChanMgr<R>>,
        guardmgr: &tor_guardmgr::GuardMgr<R>,
    ) -> Result<Self>
    where
        SM: tor_persist::StateMgr + Clone + Send + Sync + 'static,
    {
        #[cfg(all(feature = "vanguards", feature = "hs-common"))]
        let vanguardmgr = {
            // TODO(#1382): we need a way of checking if this arti instance
            // is running an onion service or not.
            //
            // Perhaps this information should be provided by CircMgrConfig.
            let has_onion_svc = false;
            VanguardMgr::new(
                config.vanguard_config(),
                runtime.clone(),
                storage.clone(),
                has_onion_svc,
            )?
        };

        let storage_handle = storage.create_handle(PARETO_TIMEOUT_DATA_KEY);

        let builder = build::TunnelBuilder::new(
            runtime.clone(),
            chanmgr,
            config.path_rules().clone(),
            storage_handle,
            guardmgr.clone(),
            #[cfg(all(feature = "vanguards", feature = "hs-common"))]
            vanguardmgr,
        );

        Ok(Self::new_generic(config, runtime, guardmgr, builder))
    }
}

/// Circuit manager operations.
mod manager;
impl<B: AbstractTunnelBuilder<R> + 'static, R: Runtime> Drop for CircMgrInner<B, R> {
    fn drop(&mut self) {
        match self.store_persistent_state() {
            Ok(true) => info!("Flushed persistent state at exit."),
            Ok(false) => debug!("Lock not held; no state to flush."),
            Err(e) => error_report!(e, "Unable to flush state on circuit manager drop"),
        }
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod test;
