//! Experimental support for vanguards.
//!
//! For more information, see the [vanguards spec].
//!
//! [vanguards spec]: https://spec.torproject.org/vanguards-spec/index.html.

pub mod config;
mod err;
mod set;

use std::sync::{Arc, RwLock, Weak};
use std::time::{Duration, SystemTime};

use futures::stream::BoxStream;
use futures::{FutureExt as _, future};
use futures::{StreamExt as _, select_biased};
use postage::stream::Stream as _;
use postage::watch;
use tor_rtcompat::SpawnExt as _;

use tor_async_utils::PostageWatchSenderExt as _;
use tor_config::ReconfigureError;
use tor_error::{error_report, internal, into_internal};
use tor_netdir::{DirEvent, NetDir, NetDirProvider, Timeliness};
use tor_persist::{DynStorageHandle, StateMgr};
use tor_relay_selection::RelaySelector;
use tor_rtcompat::Runtime;
use tracing::{debug, info, instrument};

use crate::{RetireCircuits, VanguardMode};

use set::VanguardSets;

use crate::VanguardConfig;
pub use config::VanguardParams;
pub use err::VanguardMgrError;
pub use set::Vanguard;

/// The key used for storing the vanguard sets to persistent storage using `StateMgr`.
const STORAGE_KEY: &str = "vanguards";

/// The vanguard manager.
pub struct VanguardMgr<R: Runtime> {
    /// The mutable state.
    inner: RwLock<Inner>,
    /// The runtime.
    runtime: R,
    /// The persistent storage handle, used for writing the vanguard sets to disk
    /// if full vanguards are enabled.
    storage: DynStorageHandle<VanguardSets>,
}

/// The mutable inner state of [`VanguardMgr`].
struct Inner {
    /// The current vanguard parameters.
    params: VanguardParams,
    /// Whether to use full, lite, or no vanguards.
    ///
    // TODO(#1382): we should derive the mode from the
    // vanguards-enabled and vanguards-hs-service consensus params.
    mode: VanguardMode,
    /// The L2 and L3 vanguards.
    ///
    /// The L3 vanguards are only used if we are running in
    /// [`Full`](VanguardMode::Full) vanguard mode.
    /// Otherwise, the L3 set is not populated, or read from.
    ///
    /// If [`Full`](VanguardMode::Full) vanguard mode is enabled,
    /// the vanguard sets will be persisted to disk whenever
    /// vanuards are rotated, added, or removed.
    ///
    /// The vanguard sets are updated and persisted to storage by
    /// [`update_vanguard_sets`](Inner::update_vanguard_sets).
    ///
    /// If the `VanguardSets` change while we are in "lite" mode,
    /// the changes will not *not* be written to storage.
    /// If we later switch to "full" vanguards, those previous changes still
    /// won't be persisted to storage: we only flush to storage if the
    /// [`VanguardSets`] change *while* we are in "full" mode
    /// (changing the [`VanguardMode`] does not constitute a change in the `VanguardSets`).
    //
    // TODO HS-VANGUARDS: the correct behaviour here might be to never switch back to lite mode
    // after enabling full vanguards. If we do that, persisting the vanguard sets will be simpler,
    // as we can just unconditionally flush to storage if the vanguard mode is switched to full.
    // Right now we can't do that, because we don't remember the "mode":
    // we derive it on the fly from `has_onion_svc` and the current `VanguardParams`.
    //
    ///
    /// This is initialized with the vanguard sets read from the vanguard state file,
    /// if the file exists, or with a [`Default`] `VanguardSets`, if it doesn't.
    ///
    /// Note: The `VanguardSets` are read from the vanguard state file
    /// even if full vanguards are not enabled. They are *not*, however, written
    /// to the state file unless full vanguards are in use.
    vanguard_sets: VanguardSets,
    /// Whether we're running an onion service.
    ///
    // TODO(#1382): This should be used for deciding whether to use the `vanguards_hs_service` or the
    // `vanguards_enabled` [`NetParameter`](tor_netdir::params::NetParameters).
    #[allow(unused)]
    has_onion_svc: bool,
    /// A channel for sending VanguardConfig changes to the vanguard maintenance task.
    config_tx: watch::Sender<VanguardConfig>,
}

/// Whether the [`VanguardMgr::maintain_vanguard_sets`] task
/// should continue running or shut down.
///
/// Returned from [`VanguardMgr::run_once`].
#[derive(Copy, Clone, Debug)]
enum ShutdownStatus {
    /// Continue calling `run_once`.
    Continue,
    /// The `VanguardMgr` was dropped, terminate the task.
    Terminate,
}

impl<R: Runtime> VanguardMgr<R> {
    /// Create a new `VanguardMgr`.
    ///
    /// The `state_mgr` handle is used for persisting the "vanguards-full" guard pools to disk.
    pub fn new<S>(
        config: &VanguardConfig,
        runtime: R,
        state_mgr: S,
        has_onion_svc: bool,
    ) -> Result<Self, VanguardMgrError>
    where
        S: StateMgr + Send + Sync + 'static,
    {
        // Note: we start out with default vanguard params, but we adjust them
        // as soon as we obtain a NetDir (see Self::run_once()).
        let params = VanguardParams::default();
        let storage: DynStorageHandle<VanguardSets> = state_mgr.create_handle(STORAGE_KEY);

        let vanguard_sets = match storage.load()? {
            Some(mut sets) => {
                info!("Loading vanguards from vanguard state file");
                // Discard the now-expired the vanguards
                let now = runtime.wallclock();
                let _ = sets.remove_expired(now);
                sets
            }
            None => {
                debug!("Vanguard state file not found, selecting new vanguards");
                // Initially, all sets have a target size of 0.
                // This is OK because the target is only used for repopulating the vanguard sets,
                // and we can't repopulate the sets without a netdir.
                // The target gets adjusted once we obtain a netdir.
                Default::default()
            }
        };

        let (config_tx, _config_rx) = watch::channel();
        let inner = Inner {
            params,
            mode: config.mode(),
            vanguard_sets,
            has_onion_svc,
            config_tx,
        };

        Ok(Self {
            inner: RwLock::new(inner),
            runtime,
            storage,
        })
    }

    /// Launch the vanguard pool management tasks.
    ///
    /// These run until the `VanguardMgr` is dropped.
    //
    // This spawns [`VanguardMgr::maintain_vanguard_sets`].
    #[instrument(level = "trace", skip_all)]
    pub fn launch_background_tasks(
        self: &Arc<Self>,
        netdir_provider: &Arc<dyn NetDirProvider>,
    ) -> Result<(), VanguardMgrError>
    where
        R: Runtime,
    {
        let netdir_provider = Arc::clone(netdir_provider);
        let config_rx = self
            .inner
            .write()
            .expect("poisoned lock")
            .config_tx
            .subscribe();
        self.runtime
            .spawn(Self::maintain_vanguard_sets(
                Arc::downgrade(self),
                Arc::downgrade(&netdir_provider),
                config_rx,
            ))
            .map_err(|e| VanguardMgrError::Spawn(Arc::new(e)))?;

        Ok(())
    }

    /// Replace the configuration in this `VanguardMgr` with the specified `config`.
    pub fn reconfigure(&self, config: &VanguardConfig) -> Result<RetireCircuits, ReconfigureError> {
        // TODO(#1382): abolish VanguardConfig and derive the mode from the VanguardParams
        // and has_onion_svc instead.
        //
        // TODO(#1382): update has_onion_svc if the new config enables onion svc usage
        //
        // Perhaps we should always escalate to Full if we start running an onion service,
        // but not decessarily downgrade to lite if we stop.
        // See <https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/2083#note_3018173>
        let mut inner = self.inner.write().expect("poisoned lock");
        let new_mode = config.mode();
        if new_mode != inner.mode {
            inner.mode = new_mode;

            // Wake up the maintenance task to replenish the vanguard pools.
            inner.config_tx.maybe_send(|_| config.clone());

            Ok(RetireCircuits::All)
        } else {
            Ok(RetireCircuits::None)
        }
    }

    /// Return a [`Vanguard`] relay for use in the specified layer.
    ///
    /// The `relay_selector` must exclude the relays that would neighbor this vanguard
    /// in the path.
    ///
    /// Specifically, it should exclude
    ///   * the last relay in the path (the one immediately preceding the vanguard): the same relay
    ///     cannot be used in consecutive positions in the path (a relay won't let you extend the
    ///     circuit to itself).
    ///   * the penultimate relay of the path, if there is one: relays don't allow extending the
    ///     circuit to their previous hop
    ///
    /// If [`Full`](VanguardMode::Full) vanguards are in use, this function can be used
    /// for selecting both [`Layer2`](Layer::Layer2) and [`Layer3`](Layer::Layer3) vanguards.
    ///
    /// If [`Lite`](VanguardMode::Lite) vanguards are in use, this function can only be used
    /// for selecting [`Layer2`](Layer::Layer2) vanguards.
    /// It will return an error if a [`Layer3`](Layer::Layer3) is requested.
    ///
    /// Returns an error if vanguards are disabled.
    ///
    /// Returns a [`NoSuitableRelay`](VanguardMgrError::NoSuitableRelay) error
    /// if none of our vanguards satisfy the `layer` and `neighbor_exclusion` requirements.
    ///
    /// Returns a [`BootstrapRequired`](VanguardMgrError::BootstrapRequired) error
    /// if called before the vanguard manager has finished bootstrapping,
    /// or if all the vanguards have become unusable
    /// (by expiring or no longer being listed in the consensus)
    /// and we are unable to replenish them.
    ///
    ///  ### Example
    ///
    ///  If the partially built path is of the form `G - L2` and we are selecting the L3 vanguard,
    ///  the `RelayExclusion` should contain `G` and `L2` (to prevent building a path of the form
    ///  `G - L2 - G`, or `G - L2 - L2`).
    ///
    ///  If the path only contains the L1 guard (`G`), then the `RelayExclusion` should only
    ///  exclude `G`.
    pub fn select_vanguard<'a, Rng: rand::Rng>(
        &self,
        rng: &mut Rng,
        netdir: &'a NetDir,
        layer: Layer,
        relay_selector: &RelaySelector<'a>,
    ) -> Result<Vanguard<'a>, VanguardMgrError> {
        use VanguardMode::*;

        let inner = self.inner.read().expect("poisoned lock");

        // All our vanguard sets are empty. This means select_vanguards() was called before
        // maintain_vanguard_sets() managed to obtain a netdir and populate the vanguard sets,
        // or all the vanguards have become unusable and we have been unable to replenish them.
        if inner.vanguard_sets.l2().is_empty() && inner.vanguard_sets.l3().is_empty() {
            return Err(VanguardMgrError::BootstrapRequired {
                action: "select vanguard",
            });
        }

        let relay =
            match (layer, inner.mode) {
                (Layer::Layer2, Full) | (Layer::Layer2, Lite) => inner
                    .vanguard_sets
                    .l2()
                    .pick_relay(rng, netdir, relay_selector),
                (Layer::Layer3, Full) => {
                    inner
                        .vanguard_sets
                        .l3()
                        .pick_relay(rng, netdir, relay_selector)
                }
                _ => {
                    return Err(VanguardMgrError::LayerNotSupported {
                        layer,
                        mode: inner.mode,
                    });
                }
            };

        relay.ok_or(VanguardMgrError::NoSuitableRelay(layer))
    }

    /// The vanguard set management task.
    ///
    /// This is a background task that:
    /// * removes vanguards from the L2 and L3 vanguard sets when they expire
    /// * ensures the vanguard sets are repopulated with new vanguards
    ///   when the number of vanguards drops below a certain threshold
    /// * handles `NetDir` changes, updating the vanguard set sizes as needed
    async fn maintain_vanguard_sets(
        mgr: Weak<Self>,
        netdir_provider: Weak<dyn NetDirProvider>,
        mut config_rx: watch::Receiver<VanguardConfig>,
    ) {
        let mut netdir_events = match netdir_provider.upgrade() {
            Some(provider) => provider.events(),
            None => {
                return;
            }
        };

        loop {
            match Self::run_once(
                Weak::clone(&mgr),
                Weak::clone(&netdir_provider),
                &mut netdir_events,
                &mut config_rx,
            )
            .await
            {
                Ok(ShutdownStatus::Continue) => continue,
                Ok(ShutdownStatus::Terminate) => {
                    debug!("Vanguard manager is shutting down");
                    break;
                }
                Err(e) => {
                    error_report!(e, "Vanguard manager crashed");
                    break;
                }
            }
        }
    }

    /// Wait until a vanguard expires or until there is a new [`NetDir`].
    ///
    /// This populates the L2 and L3 vanguard sets,
    /// and rotates the vanguards when their lifetime expires.
    ///
    /// Note: the L3 set is only populated with vanguards if
    /// [`Full`](VanguardMode::Full) vanguards are enabled.
    async fn run_once(
        mgr: Weak<Self>,
        netdir_provider: Weak<dyn NetDirProvider>,
        netdir_events: &mut BoxStream<'static, DirEvent>,
        config_rx: &mut watch::Receiver<VanguardConfig>,
    ) -> Result<ShutdownStatus, VanguardMgrError> {
        let (mgr, netdir_provider) = match (mgr.upgrade(), netdir_provider.upgrade()) {
            (Some(mgr), Some(netdir_provider)) => (mgr, netdir_provider),
            _ => return Ok(ShutdownStatus::Terminate),
        };

        let now = mgr.runtime.wallclock();
        let next_to_expire = mgr.rotate_expired(&netdir_provider, now)?;
        // A future that sleeps until the next vanguard expires
        let sleep_fut = async {
            if let Some(dur) = next_to_expire {
                let () = mgr.runtime.sleep(dur).await;
            } else {
                future::pending::<()>().await;
            }
        };

        select_biased! {
            event = netdir_events.next().fuse() => {
                if let Some(DirEvent::NewConsensus) = event {
                    let netdir = netdir_provider.netdir(Timeliness::Timely)?;
                    mgr.inner.write().expect("poisoned lock")
                        .update_vanguard_sets(&mgr.runtime, &mgr.storage, &netdir)?;
                }

                Ok(ShutdownStatus::Continue)
            },
            _config = config_rx.recv().fuse() => {
                if let Some(netdir) = Self::timely_netdir(&netdir_provider)? {
                    // If we have a NetDir, replenish the vanguard sets that don't have enough vanguards.
                    //
                    // For example, if the config change enables full vanguards for the first time,
                    // this will cause the L3 vanguard set to be populated.
                    mgr.inner.write().expect("poisoned lock")
                        .update_vanguard_sets(&mgr.runtime, &mgr.storage, &netdir)?;
                }

                Ok(ShutdownStatus::Continue)
            },
            () = sleep_fut.fuse() => {
                // A vanguard expired, time to run the cleanup
                Ok(ShutdownStatus::Continue)
            },
        }
    }

    /// Return a timely `NetDir`, if one is available.
    ///
    /// Returns `None` if no directory information is available.
    fn timely_netdir(
        netdir_provider: &Arc<dyn NetDirProvider>,
    ) -> Result<Option<Arc<NetDir>>, VanguardMgrError> {
        use tor_netdir::Error as NetDirError;

        match netdir_provider.netdir(Timeliness::Timely) {
            Ok(netdir) => Ok(Some(netdir)),
            Err(NetDirError::NoInfo) | Err(NetDirError::NotEnoughInfo) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Rotate the vanguards that have expired,
    /// returning how long until the next vanguard will expire,
    /// or `None` if there are no vanguards in any of our sets.
    fn rotate_expired(
        &self,
        netdir_provider: &Arc<dyn NetDirProvider>,
        now: SystemTime,
    ) -> Result<Option<Duration>, VanguardMgrError> {
        let mut inner = self.inner.write().expect("poisoned lock");
        let inner = &mut *inner;

        let vanguard_sets = &mut inner.vanguard_sets;
        let expired_count = vanguard_sets.remove_expired(now);

        if expired_count > 0 {
            info!("Rotating vanguards");
        }

        if let Some(netdir) = Self::timely_netdir(netdir_provider)? {
            // If we have a NetDir, replenish the vanguard sets that don't have enough vanguards.
            inner.update_vanguard_sets(&self.runtime, &self.storage, &netdir)?;
        }

        let Some(expiry) = inner.vanguard_sets.next_expiry() else {
            // Both vanguard sets are empty
            return Ok(None);
        };

        expiry
            .duration_since(now)
            .map_err(|_| internal!("when > now, but now is later than when?!").into())
            .map(Some)
    }

    /// Get the current [`VanguardMode`].
    pub fn mode(&self) -> VanguardMode {
        self.inner.read().expect("poisoned lock").mode
    }
}

impl Inner {
    /// Update the vanguard sets, handling any potential vanguard parameter changes.
    ///
    /// This updates the [`VanguardSets`]s based on the [`VanguardParams`]
    /// derived from the new `NetDir`, replenishing the sets if necessary.
    ///
    /// NOTE: if the new `VanguardParams` specify different lifetime ranges
    /// than the previous `VanguardParams`, the new lifetime requirements only
    /// apply to newly selected vanguards. They are **not** retroactively applied
    /// to our existing vanguards.
    //
    // TODO(#1352): we might want to revisit this decision.
    // We could, for example, adjust the lifetime of our existing vanguards
    // to comply with the new lifetime requirements.
    fn update_vanguard_sets<R: Runtime>(
        &mut self,
        runtime: &R,
        storage: &DynStorageHandle<VanguardSets>,
        netdir: &Arc<NetDir>,
    ) -> Result<(), VanguardMgrError> {
        let params = VanguardParams::try_from(netdir.params())
            .map_err(into_internal!("invalid NetParameters"))?;

        // Update our params with the new values.
        self.update_params(params.clone());

        self.vanguard_sets.remove_unlisted(netdir);

        // If we loaded some vanguards from persistent storage but we still need more,
        // we select them here.
        //
        // If full vanguards are not enabled and we started with an empty (default)
        // vanguard set, we populate the sets here.
        //
        // If we have already populated the vanguard sets in a previous iteration,
        // this will ensure they have enough vanguards.
        self.vanguard_sets
            .replenish_vanguards(runtime, netdir, &params, self.mode)?;

        // Flush the vanguard sets to disk.
        self.flush_to_storage(storage)?;

        Ok(())
    }

    /// Update our vanguard params.
    fn update_params(&mut self, new_params: VanguardParams) {
        self.params = new_params;
    }

    /// Flush the vanguard sets to storage, if the mode is "vanguards-full".
    fn flush_to_storage(
        &self,
        storage: &DynStorageHandle<VanguardSets>,
    ) -> Result<(), VanguardMgrError> {
        match self.mode {
            VanguardMode::Lite | VanguardMode::Disabled => Ok(()),
            VanguardMode::Full => {
                debug!("The vanguards may have changed; flushing to vanguard state file");
                Ok(storage.store(&self.vanguard_sets)?)
            }
        }
    }
}

#[cfg(any(test, feature = "testing"))]
use {
    tor_config::ExplicitOrAuto, tor_netdir::testprovider::TestNetDirProvider,
    tor_persist::TestingStateMgr, tor_rtmock::MockRuntime,
};

/// Helpers for tests involving vanguards
#[cfg(any(test, feature = "testing"))]
impl VanguardMgr<MockRuntime> {
    /// Create a new VanguardMgr for testing.
    pub fn new_testing(
        rt: &MockRuntime,
        mode: VanguardMode,
    ) -> Result<Arc<VanguardMgr<MockRuntime>>, VanguardMgrError> {
        let config = VanguardConfig {
            mode: ExplicitOrAuto::Explicit(mode),
        };
        let statemgr = TestingStateMgr::new();
        let lock = statemgr.try_lock()?;
        assert!(lock.held());
        // TODO(#1382): has_onion_svc doesn't matter right now
        let has_onion_svc = false;
        Ok(Arc::new(VanguardMgr::new(
            &config,
            rt.clone(),
            statemgr,
            has_onion_svc,
        )?))
    }

    /// Wait until the vanguardmgr has populated its vanguard sets.
    ///
    /// Returns a [`TestNetDirProvider`] that can be used to notify
    /// the `VanguardMgr` of netdir changes.
    pub async fn init_vanguard_sets(
        self: &Arc<VanguardMgr<MockRuntime>>,
        netdir: &NetDir,
    ) -> Result<Arc<TestNetDirProvider>, VanguardMgrError> {
        let netdir_provider = Arc::new(TestNetDirProvider::new());
        self.launch_background_tasks(&(netdir_provider.clone() as Arc<dyn NetDirProvider>))?;
        self.runtime.progress_until_stalled().await;

        // Call set_netdir_and_notify to trigger an event
        netdir_provider
            .set_netdir_and_notify(Arc::new(netdir.clone()))
            .await;

        // Wait until the vanguard mgr has finished handling the netdir event.
        self.runtime.progress_until_stalled().await;

        Ok(netdir_provider)
    }
}

/// The vanguard layer.
#[derive(Debug, Clone, Copy, PartialEq)] //
#[derive(derive_more::Display)] //
#[non_exhaustive]
pub enum Layer {
    /// L2 vanguard.
    #[display("layer 2")]
    Layer2,
    /// L3 vanguard.
    #[display("layer 3")]
    Layer3,
}

#[cfg(test)]
#[path = "vanguards/tests.rs"]
mod test;
