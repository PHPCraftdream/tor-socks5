//! Facilities to build circuits directly, instead of via a circuit manager.

use crate::path::{OwnedPath, TorPath};
use crate::timeouts::{self, Action};
use crate::{Error, Result};
use async_trait::async_trait;
use futures::Future;
use oneshot_fused_workaround as oneshot;
use std::sync::{
    Arc,
    atomic::{AtomicU32, Ordering},
};
use tor_chanmgr::{ChanMgr, ChanProvenance, ChannelUsage};
use tor_error::into_internal;
use tor_guardmgr::GuardStatus;
use tor_linkspec::{IntoOwnedChanTarget, OwnedChanTarget, OwnedCircTarget};
use tor_netdir::params::NetParameters;
use tor_proto::ccparams::{self, AlgorithmType};
use tor_proto::client::circuit::{CircParameters, PendingClientTunnel};
use tor_proto::{CellCount, ClientTunnel, FlowCtrlParameters};
use tor_rtcompat::SpawnExt;
use tor_rtcompat::{Runtime, SleepProviderExt};
use tor_units::Percentage;
use tracing::instrument;
use web_time_compat::{Duration, Instant};

#[cfg(all(feature = "vanguards", feature = "hs-common"))]
use tor_guardmgr::vanguards::VanguardMgr;

mod guardstatus;

pub(crate) use guardstatus::GuardStatusHandle;

/// Represents an objects that can be constructed in a circuit-like way.
///
/// This is only a separate trait for testing purposes, so that we can swap
/// our some other type when we're testing Builder.
///
/// TODO: I'd like to have a simpler testing strategy here; this one
/// complicates things a bit.
#[async_trait]
pub(crate) trait Buildable: Sized {
    /// Our equivalent to a tor_proto::Channel.
    type Chan: Send + Sync;

    /// Use a channel manager to open a new channel (or find an existing channel)
    /// to a provided [`OwnedChanTarget`].
    async fn open_channel<RT: Runtime>(
        chanmgr: &ChanMgr<RT>,
        ct: &OwnedChanTarget,
        guard_status: &GuardStatusHandle,
        usage: ChannelUsage,
    ) -> Result<Arc<Self::Chan>>;

    /// Launch a new one-hop circuit to a given relay, given only a
    /// channel target `ct` specifying that relay.
    ///
    /// (Since we don't have a CircTarget here, we can't extend the circuit
    /// to be multihop later on.)
    async fn create_chantarget<RT: Runtime>(
        chan: Arc<Self::Chan>,
        rt: &RT,
        ct: &OwnedChanTarget,
        params: CircParameters,
        timeouts: Arc<dyn tor_proto::client::circuit::TimeoutEstimator>,
    ) -> Result<Self>;

    /// Launch a new circuit through a given relay, given a circuit target
    /// `ct` specifying that relay.
    async fn create<RT: Runtime>(
        chan: Arc<Self::Chan>,
        rt: &RT,
        ct: &OwnedCircTarget,
        params: CircParameters,
        timeouts: Arc<dyn tor_proto::client::circuit::TimeoutEstimator>,
    ) -> Result<Self>;

    /// Extend this circuit-like object by one hop, to the location described
    /// in `ct`.
    async fn extend<RT: Runtime>(
        &self,
        rt: &RT,
        ct: &OwnedCircTarget,
        params: CircParameters,
    ) -> Result<()>;
}

/// Try to make a [`PendingClientTunnel`] to a given relay, and start its
/// reactor.
///
/// This is common code, shared by all the first-hop functions in the
/// implementation of `Buildable` for `ClientTunnel`.
#[instrument(level = "trace", skip_all)]
async fn create_common<RT: Runtime>(
    chan: Arc<tor_proto::channel::Channel>,
    timeouts: Arc<dyn tor_proto::client::circuit::TimeoutEstimator>,
    rt: &RT,
) -> Result<PendingClientTunnel> {
    // Construct the (zero-hop) circuit.
    let (pending_tunnel, reactor) =
        chan.new_tunnel(timeouts)
            .await
            .map_err(|error| Error::Protocol {
                error,
                peer: None, // we don't blame the peer, because new_tunnel() does no networking.
                action: "initializing circuit",
                unique_id: None,
            })?;

    tracing::debug!("Spawning reactor...");

    rt.spawn(async {
        let _ = reactor.run().await;
    })
    .map_err(|e| Error::from_spawn("circuit reactor task", e))?;

    Ok(pending_tunnel)
}

#[async_trait]
impl Buildable for ClientTunnel {
    type Chan = tor_proto::channel::Channel;

    #[instrument(level = "trace", skip_all)]
    async fn open_channel<RT: Runtime>(
        chanmgr: &ChanMgr<RT>,
        target: &OwnedChanTarget,
        guard_status: &GuardStatusHandle,
        usage: ChannelUsage,
    ) -> Result<Arc<Self::Chan>> {
        // If we fail now, it's the guard's fault.
        guard_status.pending(GuardStatus::Failure);

        // Get or construct the channel.
        let result = chanmgr.get_or_launch(target, usage).await;

        // Report the clock skew if appropriate, and exit if there has been an error.
        match result {
            Ok((chan, ChanProvenance::NewlyCreated)) => {
                guard_status.skew(chan.clock_skew());
                Ok(chan)
            }
            Ok((chan, _)) => Ok(chan),
            Err(cause) => {
                if let Some(skew) = cause.clock_skew() {
                    guard_status.skew(skew);
                }
                Err(Error::Channel {
                    peer: target.to_logged(),
                    cause,
                })
            }
        }
    }

    #[instrument(level = "trace", skip_all)]
    async fn create_chantarget<RT: Runtime>(
        chan: Arc<Self::Chan>,
        rt: &RT,
        ct: &OwnedChanTarget,
        params: CircParameters,
        timeouts: Arc<dyn tor_proto::client::circuit::TimeoutEstimator>,
    ) -> Result<Self> {
        let pending_tunnel = create_common(chan, timeouts, rt).await?;
        let unique_id = Some(pending_tunnel.peek_unique_id());
        pending_tunnel
            .create_firsthop_fast(params)
            .await
            .map_err(|error| Error::Protocol {
                peer: Some(ct.to_logged()),
                error,
                action: "running CREATE_FAST handshake",
                unique_id,
            })
    }
    #[instrument(level = "trace", skip_all)]
    async fn create<RT: Runtime>(
        chan: Arc<Self::Chan>,
        rt: &RT,
        ct: &OwnedCircTarget,
        params: CircParameters,
        timeouts: Arc<dyn tor_proto::client::circuit::TimeoutEstimator>,
    ) -> Result<Self> {
        let pending_tunnel = create_common(chan, timeouts, rt).await?;
        let unique_id = Some(pending_tunnel.peek_unique_id());

        let handshake_res = pending_tunnel.create_firsthop(ct, params).await;
        handshake_res.map_err(|error| Error::Protocol {
            peer: Some(ct.to_logged()),
            error,
            action: "creating first hop",
            unique_id,
        })
    }
    async fn extend<RT: Runtime>(
        &self,
        _rt: &RT,
        ct: &OwnedCircTarget,
        params: CircParameters,
    ) -> Result<()> {
        let circ = self.as_single_circ().map_err(|error| Error::Protocol {
            peer: Some(ct.to_logged()),
            error,
            action: "extend tunnel",
            unique_id: Some(self.unique_id()),
        })?;

        let res = circ.extend(ct, params).await;
        res.map_err(|error| Error::Protocol {
            error,
            // We can't know who caused the error, since it may have been
            // the hop we were extending from, or the hop we were extending
            // to.
            peer: None,
            action: "extending circuit",
            unique_id: Some(self.unique_id()),
        })
    }
}

/// An implementation type for [`TunnelBuilder`].
///
/// A `TunnelBuilder` holds references to all the objects that are needed
/// to build circuits correctly.
///
/// In general, you should not need to construct or use this object yourself,
/// unless you are choosing your own paths.
struct Builder<R: Runtime, C: Buildable + Sync + Send + 'static> {
    /// The runtime used by this circuit builder.
    runtime: R,
    /// A channel manager that this circuit builder uses to make channels.
    chanmgr: Arc<ChanMgr<R>>,
    /// An estimator to determine the correct timeouts for circuit building.
    timeouts: Arc<timeouts::Estimator>,
    /// We don't actually hold any clientcircs, so we need to put this
    /// type here so the compiler won't freak out.
    _phantom: std::marker::PhantomData<C>,
}

impl<R: Runtime, C: Buildable + Sync + Send + 'static> Builder<R, C> {
    /// Construct a new [`Builder`].
    fn new(runtime: R, chanmgr: Arc<ChanMgr<R>>, timeouts: timeouts::Estimator) -> Self {
        Builder {
            runtime,
            chanmgr,
            timeouts: Arc::new(timeouts),
            _phantom: std::marker::PhantomData,
        }
    }

    /// Build a circuit, without performing any timeout operations.
    ///
    /// After each hop is built, increments n_hops_built.  Make sure that
    /// `guard_status` has its pending status set correctly to correspond
    /// to a circuit failure at any given stage.
    ///
    /// Requires that `channel` is a channel to the first hop of `path`.
    ///
    /// (TODO: Find
    /// a better design there.)
    #[instrument(level = "trace", skip_all)]
    async fn build_notimeout(
        self: Arc<Self>,
        path: OwnedPath,
        channel: Arc<C::Chan>,
        params: CircParameters,
        start_time: Instant,
        n_hops_built: Arc<AtomicU32>,
        guard_status: Arc<GuardStatusHandle>,
    ) -> Result<C> {
        match path {
            OwnedPath::ChannelOnly(target) => {
                let timeouts = Arc::clone(&self.timeouts);
                let circ =
                    C::create_chantarget(channel, &self.runtime, &target, params, timeouts).await?;
                self.timeouts
                    .note_hop_completed(0, self.runtime.now() - start_time, true);
                n_hops_built.fetch_add(1, Ordering::SeqCst);
                Ok(circ)
            }
            OwnedPath::Normal(p) => {
                assert!(!p.is_empty());
                let n_hops = p.len() as u8;
                let timeouts = Arc::clone(&self.timeouts);
                // Each hop has its own circ parameters. This is for the first hop (CREATE).
                let circ =
                    C::create(channel, &self.runtime, &p[0], params.clone(), timeouts).await?;
                self.timeouts
                    .note_hop_completed(0, self.runtime.now() - start_time, n_hops == 0);
                // If we fail after this point, we can't tell whether it's
                // the fault of the guard or some later relay.
                guard_status.pending(GuardStatus::Indeterminate);
                n_hops_built.fetch_add(1, Ordering::SeqCst);
                for (hop_num, relay) in (1..).zip(p[1..].iter()) {
                    // Get the params per subsequent hop (EXTEND).
                    circ.extend(&self.runtime, relay, params.clone()).await?;
                    n_hops_built.fetch_add(1, Ordering::SeqCst);
                    self.timeouts.note_hop_completed(
                        hop_num,
                        self.runtime.now() - start_time,
                        hop_num == (n_hops - 1),
                    );
                }
                Ok(circ)
            }
        }
    }

    /// Build a circuit from an [`OwnedPath`].
    #[instrument(level = "trace", skip_all)]
    async fn build_owned(
        self: &Arc<Self>,
        path: OwnedPath,
        params: &CircParameters,
        guard_status: Arc<GuardStatusHandle>,
        usage: ChannelUsage,
    ) -> Result<C> {
        let action = Action::BuildCircuit { length: path.len() };
        let (timeout, abandon_timeout) = self.timeouts.timeouts(&action);

        // TODO: This is probably not the best way for build_notimeout to
        // tell us how many hops it managed to build, but at least it is
        // isolated here.
        let hops_built = Arc::new(AtomicU32::new(0));

        let self_clone = Arc::clone(self);
        let params = params.clone();

        // We open the channel separately from the rest of the circuit, since we don't want to count
        // it towards the circuit timeout.
        //
        // We don't need a separate timeout here, since ChanMgr already implements its own timeouts.
        let channel = C::open_channel(
            &self.chanmgr,
            path.first_hop_as_chantarget(),
            guard_status.as_ref(),
            usage,
        )
        .await?;

        let start_time = self.runtime.now();

        let circuit_future = self_clone.build_notimeout(
            path,
            channel,
            params,
            start_time,
            Arc::clone(&hops_built),
            guard_status,
        );

        match double_timeout(&self.runtime, circuit_future, timeout, abandon_timeout).await {
            Ok(circuit) => Ok(circuit),
            Err(Error::CircTimeout(unique_id)) => {
                let n_built = hops_built.load(Ordering::SeqCst);
                self.timeouts
                    .note_circ_timeout(n_built as u8, self.runtime.now() - start_time);
                Err(Error::CircTimeout(unique_id))
            }
            Err(e) => Err(e),
        }
    }

    /// Return a reference to this Builder runtime.
    pub(crate) fn runtime(&self) -> &R {
        &self.runtime
    }

    /// Return a reference to this Builder's timeout estimator.
    pub(crate) fn estimator(&self) -> &timeouts::Estimator {
        &self.timeouts
    }
}

/// A factory object to build circuits.
///
/// A `TunnelBuilder` holds references to all the objects that are needed
/// to build circuits correctly.
///
/// In general, you should not need to construct or use this object yourself,
/// unless you are choosing your own paths.
pub struct TunnelBuilder<R: Runtime> {
    /// The underlying [`Builder`] object
    builder: Arc<Builder<R, ClientTunnel>>,
    /// Configuration for how to choose paths for circuits.
    path_config: tor_config::MutCfg<crate::PathConfig>,
    /// State-manager object to use in storing current state.
    storage: crate::TimeoutStateHandle,
    /// Guard manager to tell us which guards nodes to use for the circuits
    /// we build.
    guardmgr: tor_guardmgr::GuardMgr<R>,
    /// The vanguard manager object used for HS circuits.
    #[cfg(all(feature = "vanguards", feature = "hs-common"))]
    vanguardmgr: Arc<VanguardMgr<R>>,
}

impl<R: Runtime> TunnelBuilder<R> {
    /// Construct a new [`TunnelBuilder`].
    // TODO: eventually I'd like to make this a public function, but
    // TimeoutStateHandle is private.
    pub(crate) fn new(
        runtime: R,
        chanmgr: Arc<ChanMgr<R>>,
        path_config: crate::PathConfig,
        storage: crate::TimeoutStateHandle,
        guardmgr: tor_guardmgr::GuardMgr<R>,
        #[cfg(all(feature = "vanguards", feature = "hs-common"))] vanguardmgr: VanguardMgr<R>,
    ) -> Self {
        let timeouts = timeouts::Estimator::from_storage(&storage);

        TunnelBuilder {
            builder: Arc::new(Builder::new(runtime, chanmgr, timeouts)),
            path_config: path_config.into(),
            storage,
            guardmgr,
            #[cfg(all(feature = "vanguards", feature = "hs-common"))]
            vanguardmgr: Arc::new(vanguardmgr),
        }
    }

    /// Return this builder's [`PathConfig`](crate::PathConfig).
    pub(crate) fn path_config(&self) -> Arc<crate::PathConfig> {
        self.path_config.get()
    }

    /// Replace this builder's [`PathConfig`](crate::PathConfig).
    pub(crate) fn set_path_config(&self, new_config: crate::PathConfig) {
        self.path_config.replace(new_config);
    }

    /// Flush state to the state manager if we own the lock.
    ///
    /// Return `Ok(true)` if we saved, and `Ok(false)` if we didn't hold the lock.
    pub(crate) fn save_state(&self) -> Result<bool> {
        if !self.storage.can_store() {
            return Ok(false);
        }
        // TODO: someday we'll want to only do this if there is something
        // changed.
        self.builder.timeouts.save_state(&self.storage)?;
        self.guardmgr.store_persistent_state()?;
        Ok(true)
    }

    /// Replace our state with a new owning state, assuming we have
    /// storage permission.
    pub(crate) fn upgrade_to_owned_state(&self) -> Result<()> {
        self.builder
            .timeouts
            .upgrade_to_owning_storage(&self.storage);
        self.guardmgr.upgrade_to_owned_persistent_state()?;
        Ok(())
    }

    /// Reload persistent state from disk, if we don't have storage permission.
    #[instrument(level = "trace", skip_all)]
    pub(crate) fn reload_state(&self) -> Result<()> {
        if !self.storage.can_store() {
            self.builder
                .timeouts
                .reload_readonly_from_storage(&self.storage);
        }
        self.guardmgr.reload_persistent_state()?;
        Ok(())
    }

    /// Reconfigure this builder using the latest set of network parameters.
    ///
    /// (NOTE: for now, this only affects circuit timeout estimation.)
    pub fn update_network_parameters(&self, p: &tor_netdir::params::NetParameters) {
        self.builder.timeouts.update_params(p);
    }

    /// Like `build`, but construct a new circuit from an [`OwnedPath`].
    #[instrument(level = "trace", skip_all)]
    pub(crate) async fn build_owned(
        &self,
        path: OwnedPath,
        params: &CircParameters,
        guard_status: Arc<GuardStatusHandle>,
        usage: ChannelUsage,
    ) -> Result<ClientTunnel> {
        self.builder
            .build_owned(path, params, guard_status, usage)
            .await
    }

    /// Try to construct a new circuit from a given path, using appropriate
    /// timeouts.
    ///
    /// This circuit is _not_ automatically registered with any
    /// circuit manager; if you don't hang on it it, it will
    /// automatically go away when the last reference is dropped.
    #[instrument(level = "trace", skip_all)]
    pub async fn build(
        &self,
        path: &TorPath<'_>,
        params: &CircParameters,
        usage: ChannelUsage,
    ) -> Result<ClientTunnel> {
        let owned = path.try_into()?;
        self.build_owned(owned, params, Arc::new(None.into()), usage)
            .await
    }

    /// Return true if this builder is currently learning timeout info.
    pub(crate) fn learning_timeouts(&self) -> bool {
        self.builder.timeouts.learning_timeouts()
    }

    /// Return a reference to this builder's `GuardMgr`.
    pub(crate) fn guardmgr(&self) -> &tor_guardmgr::GuardMgr<R> {
        &self.guardmgr
    }

    /// Return a reference to this builder's `VanguardMgr`.
    #[cfg(all(feature = "vanguards", feature = "hs-common"))]
    pub(crate) fn vanguardmgr(&self) -> &Arc<VanguardMgr<R>> {
        &self.vanguardmgr
    }

    /// Return a reference to this builder's runtime
    pub(crate) fn runtime(&self) -> &R {
        self.builder.runtime()
    }

    /// Return a reference to this builder's timeout estimator.
    pub(crate) fn estimator(&self) -> &timeouts::Estimator {
        self.builder.estimator()
    }
}

/// Return the congestion control Vegas algorithm using the given network parameters.
#[cfg(feature = "flowctl-cc")]
fn build_cc_vegas(
    inp: &NetParameters,
    vegas_queue_params: ccparams::VegasQueueParams,
) -> ccparams::Algorithm {
    ccparams::Algorithm::Vegas(
        ccparams::VegasParamsBuilder::default()
            .cell_in_queue_params(vegas_queue_params)
            .ss_cwnd_max(inp.cc_ss_max.into())
            .cwnd_full_gap(inp.cc_cwnd_full_gap.into())
            .cwnd_full_min_pct(Percentage::new(
                inp.cc_cwnd_full_minpct.as_percent().get() as u32
            ))
            .cwnd_full_per_cwnd(inp.cc_cwnd_full_per_cwnd.into())
            .build()
            .expect("Unable to build Vegas params from NetParams"),
    )
}

/// Return the congestion control FixedWindow algorithm using the given network parameters.
fn build_cc_fixedwindow(inp: &NetParameters) -> ccparams::Algorithm {
    ccparams::Algorithm::FixedWindow(build_cc_fixedwindow_params(inp))
}

/// Return the parameters for the congestion control FixedWindow algorithm
/// using the given network parameters.
fn build_cc_fixedwindow_params(inp: &NetParameters) -> ccparams::FixedWindowParams {
    ccparams::FixedWindowParamsBuilder::default()
        .circ_window_start(inp.circuit_window.get() as u16)
        .circ_window_min(inp.circuit_window.lower() as u16)
        .circ_window_max(inp.circuit_window.upper() as u16)
        .build()
        .expect("Unable to build FixedWindow params from NetParams")
}

/// Return a new circuit parameter struct using the given network parameters and algorithm to use.
fn circparameters_from_netparameters(
    inp: &NetParameters,
    alg: ccparams::Algorithm,
) -> Result<CircParameters> {
    let cwnd_params = ccparams::CongestionWindowParamsBuilder::default()
        .cwnd_init(inp.cc_cwnd_init.into())
        .cwnd_inc_pct_ss(Percentage::new(
            inp.cc_cwnd_inc_pct_ss.as_percent().get() as u32
        ))
        .cwnd_inc(inp.cc_cwnd_inc.into())
        .cwnd_inc_rate(inp.cc_cwnd_inc_rate.into())
        .cwnd_min(inp.cc_cwnd_min.into())
        .cwnd_max(inp.cc_cwnd_max.into())
        .sendme_inc(inp.cc_sendme_inc.into())
        .build()
        .map_err(into_internal!(
            "Unable to build CongestionWindow params from NetParams"
        ))?;
    let rtt_params = ccparams::RoundTripEstimatorParamsBuilder::default()
        .ewma_cwnd_pct(Percentage::new(
            inp.cc_ewma_cwnd_pct.as_percent().get() as u32
        ))
        .ewma_max(inp.cc_ewma_max.into())
        .ewma_ss_max(inp.cc_ewma_ss.into())
        .rtt_reset_pct(Percentage::new(
            inp.cc_rtt_reset_pct.as_percent().get() as u32
        ))
        .build()
        .map_err(into_internal!("Unable to build RTT params from NetParams"))?;
    let ccontrol = ccparams::CongestionControlParamsBuilder::default()
        .alg(alg)
        .fixed_window_params(build_cc_fixedwindow_params(inp))
        .cwnd_params(cwnd_params)
        .rtt_params(rtt_params)
        .build()
        .map_err(into_internal!(
            "Unable to build CongestionControl params from NetParams"
        ))?;
    let flow_ctrl_params = FlowCtrlParameters {
        cc_xoff_client: CellCount::new(inp.cc_xoff_client.get_u32()),
        cc_xoff_exit: CellCount::new(inp.cc_xoff_exit.get_u32()),
        cc_xon_rate: CellCount::new(inp.cc_xon_rate.get_u32()),
        cc_xon_change_pct: inp.cc_xon_change_pct.get_u32(),
        cc_xon_ewma_cnt: inp.cc_xon_ewma_cnt.get_u32(),
    };
    Ok(CircParameters::new(
        inp.extend_by_ed25519_id.into(),
        ccontrol,
        flow_ctrl_params,
    ))
}

/// Extract a [`CircParameters`] from the [`NetParameters`] from a consensus for an exit circuit or
/// single onion service (when implemented).
pub fn exit_circparams_from_netparams(inp: &NetParameters) -> Result<CircParameters> {
    let alg = match AlgorithmType::from(inp.cc_alg.get()) {
        #[cfg(feature = "flowctl-cc")]
        AlgorithmType::VEGAS => build_cc_vegas(
            inp,
            (
                inp.cc_vegas_alpha_exit.into(),
                inp.cc_vegas_beta_exit.into(),
                inp.cc_vegas_delta_exit.into(),
                inp.cc_vegas_gamma_exit.into(),
                inp.cc_vegas_sscap_exit.into(),
            )
                .into(),
        ),
        // Unrecognized, fallback to fixed window as in SENDME v0.
        _ => build_cc_fixedwindow(inp),
    };
    circparameters_from_netparameters(inp, alg)
}

/// Extract a [`CircParameters`] from the [`NetParameters`] from a consensus for an onion circuit
/// which also includes an onion service with Vanguard.
pub fn onion_circparams_from_netparams(inp: &NetParameters) -> Result<CircParameters> {
    let alg = match AlgorithmType::from(inp.cc_alg.get()) {
        #[cfg(feature = "flowctl-cc")]
        AlgorithmType::VEGAS => {
            // NOTE: At the time of writing, we don't yet support cc negotiation for onion services.
            // See `HopSettings::onion_circparams_from_netparams()` where we use a fallback
            // algorithm for HsV3 circuits instead, and see arti#2037.
            build_cc_vegas(
                inp,
                (
                    inp.cc_vegas_alpha_onion.into(),
                    inp.cc_vegas_beta_onion.into(),
                    inp.cc_vegas_delta_onion.into(),
                    inp.cc_vegas_gamma_onion.into(),
                    inp.cc_vegas_sscap_onion.into(),
                )
                    .into(),
            )
        }
        // Unrecognized, fallback to fixed window as in SENDME v0.
        _ => build_cc_fixedwindow(inp),
    };
    circparameters_from_netparameters(inp, alg)
}

/// Helper function: spawn a future as a background task, and run it with
/// two separate timeouts.
///
/// If the future does not complete by `timeout`, then return a
/// timeout error immediately, but keep running the future in the
/// background.
///
/// If the future does not complete by `abandon`, then abandon the
/// future completely.
async fn double_timeout<R, F, T>(
    runtime: &R,
    fut: F,
    timeout: Duration,
    abandon: Duration,
) -> Result<T>
where
    R: Runtime,
    F: Future<Output = Result<T>> + Send + 'static,
    T: Send + 'static,
{
    let (snd, rcv) = oneshot::channel();
    let rt = runtime.clone();
    // We create these futures now, since we want them to look at the current
    // time when they decide when to expire.
    let inner_timeout_future = rt.timeout(abandon, fut);
    let outer_timeout_future = rt.timeout(timeout, rcv);

    runtime
        .spawn(async move {
            let result = inner_timeout_future.await;
            let _ignore_cancelled_error = snd.send(result);
        })
        .map_err(|e| Error::from_spawn("circuit construction task", e))?;

    let outcome = outer_timeout_future.await;
    // 4 layers of error to collapse:
    //     One from the receiver being cancelled.
    //     One from the outer timeout.
    //     One from the inner timeout.
    //     One from the actual future's result.
    //
    // (Technically, we could refrain from unwrapping the future's result,
    // but doing it this way helps make it more certain that we really are
    // collapsing all the layers into one.)
    outcome
        .map_err(|_| Error::CircTimeout(None))??
        .map_err(|_| Error::CircTimeout(None))?
}

#[cfg(test)]
#[path = "build/tests.rs"]
mod test;
