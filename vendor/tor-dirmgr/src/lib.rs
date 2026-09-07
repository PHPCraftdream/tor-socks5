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

// This clippy lint produces a false positive on `use strum`, below.
// Attempting to apply the lint to just the use statement fails to suppress
// this lint and instead produces another lint about a useless clippy attribute.
#![allow(clippy::single_component_path_imports)]

mod bootstrap;
pub mod config;
mod docid;
mod docmeta;
mod err;
mod event;
mod shared_ref;
mod state;
mod storage;

#[cfg(feature = "bridge-client")]
pub mod bridgedesc;
#[cfg(feature = "dirfilter")]
pub mod filter;

use crate::docid::{CacheUsage, ClientRequest, DocQuery};
use crate::err::BootstrapAction;
#[cfg(not(feature = "experimental-api"))]
use crate::shared_ref::SharedMutArc;
#[cfg(feature = "experimental-api")]
pub use crate::shared_ref::SharedMutArc;
use crate::storage::{DynStore, Store};
use bootstrap::AttemptId;
use event::DirProgress;
use postage::watch;
use scopeguard::ScopeGuard;
use tor_circmgr::CircMgr;
use tor_dirclient::SourceInfo;
use tor_dircommon::config::DirTolerance;
use tor_error::{info_report, into_internal, warn_report};
use tor_netdir::params::NetParameters;
use tor_netdir::{DirEvent, MdReceiver, NetDir, NetDirProvider};

use async_trait::async_trait;
use futures::stream::BoxStream;
use oneshot_fused_workaround as oneshot;
use tor_netdoc::doc::netstatus::ProtoStatuses;
use tor_rtcompat::scheduler::{TaskHandle, TaskSchedule};
use tor_rtcompat::{Runtime, SpawnExt};
use tracing::{debug, info, instrument, trace, warn};
use web_time_compat::SystemTimeExt;

use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{collections::HashMap, sync::Weak};
use std::{fmt::Debug, time::SystemTime};

use crate::state::{DirState, NetDirChange};
pub use config::DirMgrConfig;
pub use docid::DocId;
pub use err::Error;
pub use event::{DirBlockage, DirBootstrapEvents, DirBootstrapStatus};
pub use storage::DocumentText;
pub use tor_dircommon::fallback::{FallbackDir, FallbackDirBuilder};
pub use tor_netdir::Timeliness;

/// Re-export of `strum` crate for use by an internal macro
use strum;

/// A Result as returned by this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Storage manager used by [`DirMgr`] and
/// [`BridgeDescMgr`](bridgedesc::BridgeDescMgr)
///
/// Internally, this wraps up a sqlite database.
///
/// This is a handle, which is cheap to clone; clones share state.
#[derive(Clone)]
pub struct DirMgrStore<R: Runtime> {
    /// The actual store
    pub(crate) store: Arc<Mutex<crate::DynStore>>,

    /// Be parameterized by Runtime even though we don't use it right now
    pub(crate) runtime: PhantomData<R>,
}

impl<R: Runtime> DirMgrStore<R> {
    /// Open the storage, according to the specified configuration
    pub fn new(config: &DirMgrConfig, runtime: R, offline: bool) -> Result<Self> {
        let store = Arc::new(Mutex::new(config.open_store(offline)?));
        drop(runtime);
        let runtime = PhantomData;
        Ok(DirMgrStore { store, runtime })
    }
}

/// Trait for DirMgr implementations
#[async_trait]
pub trait DirProvider: NetDirProvider {
    /// Try to change our configuration to `new_config`.
    ///
    /// Actual behavior will depend on the value of `how`.
    fn reconfigure(
        &self,
        new_config: &DirMgrConfig,
        how: tor_config::Reconfigure,
    ) -> std::result::Result<(), tor_config::ReconfigureError>;

    /// Bootstrap a `DirProvider` that hasn't been bootstrapped yet.
    async fn bootstrap(&self) -> Result<()>;

    /// Return a stream of [`DirBootstrapStatus`] events to tell us about changes
    /// in the latest directory's bootstrap status.
    ///
    /// Note that this stream can be lossy: the caller will not necessarily
    /// observe every event on the stream
    fn bootstrap_events(&self) -> BoxStream<'static, DirBootstrapStatus>;

    /// Return a [`TaskHandle`] that can be used to manage the download process.
    fn download_task_handle(&self) -> Option<TaskHandle> {
        None
    }
}

// NOTE(eta): We can't implement this for Arc<DirMgr<R>> due to trait coherence rules, so instead
//            there's a blanket impl for Arc<T> in tor-netdir.
impl<R: Runtime> NetDirProvider for DirMgr<R> {
    fn netdir(&self, timeliness: Timeliness) -> tor_netdir::Result<Arc<NetDir>> {
        use tor_netdir::Error as NetDirError;
        let netdir = self.netdir.get().ok_or(NetDirError::NoInfo)?;
        let lifetime = match timeliness {
            Timeliness::Strict => netdir.lifetime().clone(),
            Timeliness::Timely => self
                .config
                .get()
                .tolerance
                .extend_lifetime(netdir.lifetime()),
            Timeliness::Unchecked => return Ok(netdir),
        };
        // TODO #2384 -- we have a runtime here; we should use it.
        let now = SystemTime::get();
        if lifetime.valid_after() > now {
            Err(NetDirError::DirNotYetValid)
        } else if lifetime.valid_until() < now {
            Err(NetDirError::DirExpired)
        } else {
            Ok(netdir)
        }
    }

    fn events(&self) -> BoxStream<'static, DirEvent> {
        Box::pin(self.events.subscribe())
    }

    fn params(&self) -> Arc<dyn AsRef<tor_netdir::params::NetParameters>> {
        if let Some(netdir) = self.netdir.get() {
            // We have a directory, so we'd like to give it out for its
            // parameters.
            //
            // We do this even if the directory is expired, since parameters
            // don't really expire on any plausible timescale.
            netdir
        } else {
            // We have no directory, so we'll give out the default parameters as
            // modified by the provided override_net_params configuration.
            //
            self.default_parameters
                .lock()
                .expect("Poisoned lock")
                .clone()
        }
        // TODO(nickm): If we felt extremely clever, we could add a third case
        // where, if we have a pending directory with a validated consensus, we
        // give out that consensus's network parameters even if we _don't_ yet
        // have a full directory.  That's significant refactoring, though, for
        // an unclear amount of benefit.
    }

    fn protocol_statuses(&self) -> Option<(SystemTime, Arc<ProtoStatuses>)> {
        self.protocols.lock().expect("Poisoned lock").clone()
    }
}

#[async_trait]
impl<R: Runtime> DirProvider for Arc<DirMgr<R>> {
    fn reconfigure(
        &self,
        new_config: &DirMgrConfig,
        how: tor_config::Reconfigure,
    ) -> std::result::Result<(), tor_config::ReconfigureError> {
        DirMgr::reconfigure(self, new_config, how)
    }

    #[instrument(level = "trace", skip_all)]
    async fn bootstrap(&self) -> Result<()> {
        DirMgr::bootstrap(self).await
    }

    fn bootstrap_events(&self) -> BoxStream<'static, DirBootstrapStatus> {
        Box::pin(DirMgr::bootstrap_events(self))
    }

    fn download_task_handle(&self) -> Option<TaskHandle> {
        Some(self.task_handle.clone())
    }
}

/// A directory manager to download, fetch, and cache a Tor directory.
///
/// A DirMgr can operate in three modes:
///   * In **offline** mode, it only reads from the cache, and can
///     only read once.
///   * In **read-only** mode, it reads from the cache, but checks
///     whether it can acquire an associated lock file.  If it can, then
///     it enters read-write mode.  If not, it checks the cache
///     periodically for new information.
///   * In **read-write** mode, it knows that no other process will be
///     writing to the cache, and it takes responsibility for fetching
///     data from the network and updating the directory with new
///     directory information.
pub struct DirMgr<R: Runtime> {
    /// Configuration information: where to find directories, how to
    /// validate them, and so on.
    config: tor_config::MutCfg<DirMgrConfig>,
    /// Handle to our sqlite cache.
    // TODO(nickm): I'd like to use an rwlock, but that's not feasible, since
    // rusqlite::Connection isn't Sync.
    // TODO is needed?
    store: Arc<Mutex<DynStore>>,
    /// Our latest sufficiently bootstrapped directory, if we have one.
    ///
    /// We use the RwLock so that we can give this out to a bunch of other
    /// users, and replace it once a new directory is bootstrapped.
    // TODO(eta): Eurgh! This is so many Arcs! (especially considering this
    //            gets wrapped in an Arc)
    netdir: Arc<SharedMutArc<NetDir>>,

    /// Our latest set of recommended protocols.
    protocols: Mutex<Option<(SystemTime, Arc<ProtoStatuses>)>>,

    /// A set of network parameters to hand out when we have no directory.
    default_parameters: Mutex<Arc<NetParameters>>,

    /// A publisher handle that we notify whenever the consensus changes.
    events: event::FlagPublisher<DirEvent>,

    /// A publisher handle that we notify whenever our bootstrapping status
    /// changes.
    send_status: Mutex<watch::Sender<event::DirBootstrapStatus>>,

    /// A receiver handle that gets notified whenever our bootstrapping status
    /// changes.
    ///
    /// We don't need to keep this drained, since `postage::watch` already knows
    /// to discard unread events.
    receive_status: DirBootstrapEvents,

    /// A circuit manager, if this DirMgr supports downloading.
    circmgr: Option<Arc<CircMgr<R>>>,

    /// Our asynchronous runtime.
    runtime: R,

    /// Whether or not we're operating in offline mode.
    offline: bool,

    /// If we're not in offline mode, stores whether or not the `DirMgr` has attempted
    /// to bootstrap yet or not.
    ///
    /// This exists in order to prevent starting two concurrent bootstrap tasks.
    ///
    /// (In offline mode, this does nothing.)
    bootstrap_started: AtomicBool,

    /// A filter that gets applied to directory objects before we use them.
    #[cfg(feature = "dirfilter")]
    filter: crate::filter::FilterConfig,

    /// A task schedule that can be used if we're bootstrapping.  If this is
    /// None, then there's currently a scheduled task in progress.
    task_schedule: Mutex<Option<TaskSchedule<R>>>,

    /// A task handle that we return to anybody who needs to manage our download process.
    task_handle: TaskHandle,
}

/// The possible origins of a document.
///
/// Used (for example) to report where we got a document from if it fails to
/// parse.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum DocSource {
    /// We loaded the document from our cache.
    LocalCache,
    /// We fetched the document from a server.
    DirServer {
        /// Information about the server we fetched the document from.
        source: Option<SourceInfo>,
    },
}

impl std::fmt::Display for DocSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DocSource::LocalCache => write!(f, "local cache"),
            DocSource::DirServer { source: None } => write!(f, "directory server"),
            DocSource::DirServer { source: Some(info) } => write!(f, "directory server {}", info),
        }
    }
}

/// Directory manager operations.
mod manager;
/// A degree of readiness for a given directory state object.
#[derive(Debug, Copy, Clone)]
enum Readiness {
    /// There is no more information to download.
    Complete,
    /// There is more information to download, but we don't need to
    Usable,
}

/// Try to upgrade a weak reference to a DirMgr, and give an error on
/// failure.
fn upgrade_weak_ref<T>(weak: &Weak<T>) -> Result<Arc<T>> {
    Weak::upgrade(weak).ok_or(Error::ManagerDropped)
}

/// Given a time `now`, and an amount of tolerated clock skew `tolerance`,
/// return the age of the oldest consensus that we should request at that time.
pub(crate) fn default_consensus_cutoff(
    now: SystemTime,
    tolerance: &DirTolerance,
) -> Result<SystemTime> {
    /// We _always_ allow at least this much age in our consensuses, to account
    /// for the fact that consensuses have some lifetime.
    const MIN_AGE_TO_ALLOW: Duration = Duration::from_secs(3 * 3600);
    let allow_skew = std::cmp::max(MIN_AGE_TO_ALLOW, tolerance.post_valid_tolerance());
    let cutoff = time::OffsetDateTime::from(now - allow_skew);
    // We now round cutoff to the next hour, so that we aren't leaking our exact
    // time to the directory cache.
    //
    // With the time crate, it's easier to calculate the "next hour" by rounding
    // _down_ then adding an hour; rounding up would sometimes require changing
    // the date too.
    let (h, _m, _s) = cutoff.to_hms();
    let cutoff = cutoff.replace_time(
        time::Time::from_hms(h, 0, 0)
            .map_err(tor_error::into_internal!("Failed clock calculation"))?,
    );
    let cutoff = cutoff + Duration::from_secs(3600);

    Ok(cutoff.into())
}

/// Return a list of the protocols [supported](tor_protover::doc_supported) by this crate
/// when running as a client.
pub fn supported_client_protocols() -> tor_protover::Protocols {
    use tor_protover::named::*;
    // WARNING: REMOVING ELEMENTS FROM THIS LIST CAN BE DANGEROUS!
    // SEE [`tor_protover::doc_changing`]
    [
        //
        DIRCACHE_CONSDIFF,
    ]
    .into_iter()
    .collect()
}

#[cfg(test)]
#[path = "tests.rs"]
mod test;
