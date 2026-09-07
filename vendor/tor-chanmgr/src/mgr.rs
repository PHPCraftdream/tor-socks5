//! Abstract implementation of a channel manager

use crate::factory::BootstrapReporter;
use crate::mgr::state::{ChannelForTarget, PendingChannelHandle};
use crate::{ChanProvenance, ChannelConfig, ChannelUsage, Dormancy, Error, Result};

use async_trait::async_trait;
use futures::future::Shared;
use oneshot_fused_workaround as oneshot;
use std::result::Result as StdResult;
use std::sync::Arc;
use std::time::Duration;
use tor_error::{error_report, internal};
use tor_linkspec::{HasChanMethod, HasRelayIds};
use tor_netdir::params::NetParameters;
use tor_proto::channel::kist::KistParams;
use tor_proto::channel::params::ChannelPaddingInstructionsUpdates;
use tor_proto::memquota::{ChannelAccount, SpecificAccount as _, ToplevelAccount};
use tracing::{instrument, trace};

#[cfg(feature = "relay")]
use {safelog::Sensitive, std::net::SocketAddr, tor_proto::RelayChannelAuthMaterial};

mod select;
mod state;

/// Trait to describe as much of a
/// [`Channel`](tor_proto::channel::Channel) as `AbstractChanMgr`
/// needs to use.
pub(crate) trait AbstractChannel: HasRelayIds {
    /// Return true iff this channel is considered canonical by us.
    fn is_canonical(&self) -> bool;
    /// Return true if we think the peer considers this channel as canonical.
    fn is_canonical_to_peer(&self) -> bool;
    /// Return true if this channel is usable.
    ///
    /// A channel might be unusable because it is closed, because it has
    /// hit a bug, or for some other reason.  We don't return unusable
    /// channels back to the user.
    fn is_usable(&self) -> bool;
    /// Return the amount of time a channel has not been in use.
    /// Return None if the channel is currently in use.
    fn duration_unused(&self) -> Option<Duration>;

    /// Reparameterize this channel according to the provided `ChannelPaddingInstructionsUpdates`
    ///
    /// The changed parameters may not be implemented "immediately",
    /// but this will be done "reasonably soon".
    fn reparameterize(
        &self,
        updates: Arc<ChannelPaddingInstructionsUpdates>,
    ) -> tor_proto::Result<()>;

    /// Update the KIST parameters.
    ///
    /// The changed parameters may not be implemented "immediately",
    /// but this will be done "reasonably soon".
    fn reparameterize_kist(&self, kist_params: KistParams) -> tor_proto::Result<()>;

    /// Specify that this channel should do activities related to channel padding
    ///
    /// See [`Channel::engage_padding_activities`]
    ///
    /// [`Channel::engage_padding_activities`]: tor_proto::channel::Channel::engage_padding_activities
    fn engage_padding_activities(&self);

    // tor-socks5 local patch: force-invalidate a channel from outside the
    // manager. `expire_channels()` only ever retires a channel once it has
    // been idle past its randomized `max_unused_duration`; a channel that a
    // stuck circuit is still (hopelessly) attempting to use is never "idle"
    // and so is never expired, even after the underlying network path is
    // dead (e.g. after a host network change leaves a half-open TCP/TLS
    // socket). The concrete `tor_proto::channel::Channel` already has a
    // public `terminate()` that shuts the channel (and its circuits) down
    // immediately, but nothing above it in this crate could reach it. This
    // method plumbs that primitive through the generic `AbstractChannel`
    // machinery so `ChanMgr::terminate_all_channels()` (see `lib.rs`) can
    // call it on every tracked channel.
    /// Force this channel to shut down immediately, regardless of whether it
    /// is currently in use.
    ///
    /// See [`Channel::terminate`].
    ///
    /// [`Channel::terminate`]: tor_proto::channel::Channel::terminate
    fn terminate(&self);
}

/// Trait to describe how channels-like objects are created.
///
/// This differs from [`ChannelFactory`](crate::factory::ChannelFactory) in that
/// it's a purely crate-internal type that we use to decouple the
/// AbstractChanMgr code from actual "what is a channel" concerns.
#[async_trait]
pub(crate) trait AbstractChannelFactory {
    /// The type of channel that this factory can build.
    type Channel: AbstractChannel;
    /// Type that explains how to build an outgoing channel.
    type BuildSpec: HasRelayIds + HasChanMethod;
    /// The type of byte stream that's required to build channels for incoming connections.
    type Stream;

    /// Construct a new channel to the destination described at `target`.
    ///
    /// This function must take care of all timeouts, error detection,
    /// and so on.
    ///
    /// It should not retry; that is handled at a higher level.
    async fn build_channel(
        &self,
        target: &Self::BuildSpec,
        reporter: BootstrapReporter,
        memquota: ChannelAccount,
    ) -> Result<Arc<Self::Channel>>;

    /// Construct a new channel for an incoming connection.
    #[cfg(feature = "relay")]
    async fn build_channel_using_incoming(
        &self,
        peer: Sensitive<std::net::SocketAddr>,
        stream: Self::Stream,
        memquota: ChannelAccount,
    ) -> Result<Arc<Self::Channel>>;
}

/// This is the configuration for a [`ChanMgr`](crate::ChanMgr) given to the constructor.
#[derive(Default)]
pub struct ChanMgrConfig {
    /// Channel configuration which usually comes from a configuration file.
    pub(crate) cfg: ChannelConfig,
    /// Relay authentication key material for relay channels.
    #[cfg(feature = "relay")]
    pub(crate) auth_material: Option<Arc<RelayChannelAuthMaterial>>,
    /// Our address(es). When building outgoing channel, we need our addresses in order to send
    /// them in the NETINFO cell. It will also be used to validate initiator channel target.
    #[cfg(feature = "relay")]
    pub(crate) my_addrs: Vec<SocketAddr>,
    // TODO: Would be good to add more things such as NetParameters and Dormancy maybe?
}

impl ChanMgrConfig {
    /// Constructor.
    pub fn new(cfg: ChannelConfig) -> Self {
        Self {
            cfg,
            #[cfg(feature = "relay")]
            auth_material: None,
            #[cfg(feature = "relay")]
            my_addrs: Vec::new(),
        }
    }

    /// Set the relay channel authentication key material and return itself.
    #[cfg(feature = "relay")]
    pub fn with_auth_material(mut self, auth_material: Arc<RelayChannelAuthMaterial>) -> Self {
        self.auth_material = Some(auth_material);
        self
    }

    /// Set our addresses that we advertise to the world.
    #[cfg(feature = "relay")]
    pub fn with_my_addrs(mut self, my_addrs: Vec<SocketAddr>) -> Self {
        self.my_addrs = my_addrs;
        self
    }
}

/// A type- and network-agnostic implementation for [`ChanMgr`](crate::ChanMgr).
///
/// This type does the work of keeping track of open channels and pending
/// channel requests, launching requests as needed, waiting for pending
/// requests, and so forth.
///
/// The actual job of launching connections is deferred to an
/// `AbstractChannelFactory` type.
pub(crate) struct AbstractChanMgr<CF: AbstractChannelFactory> {
    /// All internal state held by this channel manager.
    ///
    /// The most important part is the map from relay identity to channel, or
    /// to pending channel status.
    pub(crate) channels: state::MgrState<CF>,

    /// A bootstrap reporter to give out when building channels.
    pub(crate) reporter: BootstrapReporter,

    /// The memory quota account that every channel will be a child of
    pub(crate) memquota: ToplevelAccount,
}

/// Type alias for a future that we wait on to see when a pending
/// channel is done or failed.
type Pending = Shared<oneshot::Receiver<Result<()>>>;

/// Type alias for the sender we notify when we complete a channel (or fail to
/// complete it).
type Sending = oneshot::Sender<Result<()>>;

/// Keeps a pending launch entry and its waiters in sync.
///
/// Every exit path from a launch attempt must either remove the pending entry
/// or upgrade it to an open channel, and must notify all waiters with the
/// outcome. This guard makes cancellation and early returns follow the same
/// cleanup path as ordinary failures.
struct PendingLaunchGuard<'a, CF: AbstractChannelFactory> {
    /// Channel state used to remove or upgrade the pending entry.
    channels: &'a state::MgrState<CF>,
    /// Handle to the pending entry, if it has not yet been removed.
    handle: Option<PendingChannelHandle>,
    /// Sender used to notify tasks waiting on this launch.
    send: Option<Sending>,
    /// Result to report to the waiters if the launch ends here.
    result: Result<()>,
}

impl<'a, CF: AbstractChannelFactory> PendingLaunchGuard<'a, CF> {
    /// Create a new guard for a pending launch.
    fn new(channels: &'a state::MgrState<CF>, handle: PendingChannelHandle, send: Sending) -> Self {
        Self {
            channels,
            handle: Some(handle),
            send: Some(send),
            result: Err(Error::RequestCancelled),
        }
    }

    /// Record the result that should be reported to any waiters.
    fn note_result(&mut self, result: Result<()>) {
        self.result = result;
    }

    /// Replace the pending channel with an open one.
    fn upgrade_pending_channel_to_open(&mut self, channel: Arc<CF::Channel>) -> Result<()> {
        let handle = self
            .handle
            .take()
            .expect("pending launch guard lost its handle before upgrade");
        self.channels
            .upgrade_pending_channel_to_open(handle, channel)
    }
}

impl<'a, CF: AbstractChannelFactory> Drop for PendingLaunchGuard<'a, CF> {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            if let Err(e) = self.channels.remove_pending_channel(handle) {
                // Just log an error if we're unable to remove it, since there's
                // nothing else we can do here, and returning the error would
                // hide the actual error that we care about (the channel build
                // failure).
                #[allow(clippy::missing_docs_in_private_items)]
                const MSG: &str = "Unable to remove the pending channel";
                error_report!(internal!("{e}"), "{}", MSG);
            }
        }

        if let Some(send) = self.send.take() {
            // It's okay if all the receivers went away:
            // that means that nobody was waiting for this channel.
            let _ignore_err = send.send(self.result.clone());
        }
    }
}

impl<CF: AbstractChannelFactory + Clone> AbstractChanMgr<CF> {
    /// Make a new empty channel manager.
    pub(crate) fn new(
        connector: CF,
        config: ChannelConfig,
        dormancy: Dormancy,
        netparams: &NetParameters,
        reporter: BootstrapReporter,
        memquota: ToplevelAccount,
    ) -> Self {
        AbstractChanMgr {
            channels: state::MgrState::new(connector, config, dormancy, netparams),
            reporter,
            memquota,
        }
    }

    /// Run a function to modify the channel builder in this object.
    #[allow(unused)]
    pub(crate) fn with_mut_builder<F>(&self, func: F)
    where
        F: FnOnce(&mut CF),
    {
        self.channels.with_mut_builder(func);
    }

    /// Remove every unusable entry from this channel manager.
    #[cfg(test)]
    pub(crate) fn remove_unusable_entries(&self) -> Result<()> {
        self.channels.remove_unusable()
    }

    /// Build a channel for an incoming stream. See
    /// [`ChanMgr::handle_incoming`](crate::ChanMgr::handle_incoming).
    #[cfg(feature = "relay")]
    pub(crate) async fn handle_incoming(
        &self,
        src: Sensitive<std::net::SocketAddr>,
        stream: CF::Stream,
    ) -> Result<Arc<CF::Channel>> {
        let chan_builder = self.channels.builder();
        let memquota = ChannelAccount::new(&self.memquota)?;
        let channel = chan_builder
            .build_channel_using_incoming(src, stream, memquota)
            .await?;
        // Add it to our list.
        self.channels.add_open(channel.clone())?;
        Ok(channel)
    }

    /// Get a channel corresponding to the identities of `target`.
    ///
    /// If a usable channel exists with that identity, return it.
    ///
    /// If no such channel exists already, and none is in progress,
    /// launch a new request using `target`.
    ///
    /// If no such channel exists already, but we have one that's in
    /// progress, wait for it to succeed or fail.
    #[instrument(skip_all, level = "trace")]
    pub(crate) async fn get_or_launch(
        &self,
        target: CF::BuildSpec,
        usage: ChannelUsage,
    ) -> Result<(Arc<CF::Channel>, ChanProvenance)> {
        use ChannelUsage as CU;

        let chan = self.get_or_launch_internal(target).await?;

        match usage {
            CU::Dir | CU::UselessCircuit => {}
            CU::UserTraffic => chan.0.engage_padding_activities(),
        }

        Ok(chan)
    }

    /// Get a channel whose identity is `ident` - internal implementation
    #[allow(clippy::cognitive_complexity)]
    #[instrument(skip_all, level = "trace")]
    async fn get_or_launch_internal(
        &self,
        target: CF::BuildSpec,
    ) -> Result<(Arc<CF::Channel>, ChanProvenance)> {
        /// How many times do we try?
        const N_ATTEMPTS: usize = 2;
        let mut attempts_so_far = 0;
        let mut final_attempt = false;
        let mut provenance = ChanProvenance::Preexisting;

        // TODO(nickm): It would be neat to use tor_retry instead.
        let mut last_err = None;

        while attempts_so_far < N_ATTEMPTS || final_attempt {
            attempts_so_far += 1;

            // For each attempt, we _first_ look at the state of the channel map
            // to decide on an `Action`, and _then_ we execute that action.

            // First, see what state we're in, and what we should do about it.
            let action = self.choose_action(&target, final_attempt)?;

            // We are done deciding on our Action! It's time act based on the
            // Action that we chose.
            match action {
                // If this happens, we were trying to make one final check of our state, but
                // we would have had to make additional attempts.
                None => {
                    if !final_attempt {
                        return Err(Error::Internal(internal!(
                            "No action returned while not on final attempt"
                        )));
                    }
                    break;
                }
                // Easy case: we have an error or a channel to return.
                Some(Action::Return(v)) => {
                    trace!("Returning existing channel");
                    return v.map(|chan| (chan, provenance));
                }
                // There's an in-progress channel.  Wait for it.
                Some(Action::Wait(pend)) => {
                    trace!("Waiting for in-progress channel");
                    match pend.await {
                        Ok(Ok(())) => {
                            // We were waiting for a channel, and it succeeded, or it
                            // got cancelled.  But it might have gotten more
                            // identities while negotiating than it had when it was
                            // launched, or it might have failed to get all the
                            // identities we want. Check for this.
                            final_attempt = true;
                            provenance = ChanProvenance::NewlyCreated;
                            last_err.get_or_insert(Error::RequestCancelled);
                        }
                        Ok(Err(e)) => {
                            last_err = Some(e);
                        }
                        Err(_) => {
                            last_err =
                                Some(Error::Internal(internal!("channel build task disappeared")));
                        }
                    }
                }
                // We need to launch a channel.
                Some(Action::Launch((handle, send))) => {
                    trace!("Launching channel");
                    let connector = self.channels.builder();
                    let mut launch = PendingLaunchGuard::new(&self.channels, handle, send);
                    let memquota = match ChannelAccount::new(&self.memquota) {
                        Ok(memquota) => memquota,
                        Err(e) => {
                            let e: Error = e.into();
                            launch.note_result(Err(e.clone()));
                            return Err(e);
                        }
                    };

                    let outcome = connector
                        .build_channel(&target, self.reporter.clone(), memquota)
                        .await;

                    match outcome {
                        Ok(ref chan) => {
                            // Replace the pending channel with the newly built channel.
                            match launch.upgrade_pending_channel_to_open(Arc::clone(chan)) {
                                Ok(()) => launch.note_result(Ok(())),
                                Err(e) => {
                                    launch.note_result(Err(e.clone()));
                                    return Err(e);
                                }
                            }
                        }
                        Err(_) => {
                            launch.note_result(outcome.clone().map(|_| ()));
                        }
                    }

                    match outcome {
                        Ok(chan) => {
                            return Ok((chan, ChanProvenance::NewlyCreated));
                        }
                        Err(e) => last_err = Some(e),
                    }
                }
            }

            // End of this attempt. We will try again...
        }

        Err(last_err.unwrap_or_else(|| Error::Internal(internal!("no error was set!?"))))
    }

    /// Helper: based on our internal state, decide which action to take when
    /// asked for a channel, and update our internal state accordingly.
    ///
    /// If `final_attempt` is true, then we will not pick any action that does
    /// not result in an immediate result. If we would pick such an action, we
    /// instead return `Ok(None)`.  (We could instead have the caller detect
    /// such actions, but it's less efficient to construct them, insert them,
    /// and immediately revert them.)
    #[instrument(skip_all, level = "trace")]
    fn choose_action(
        &self,
        target: &CF::BuildSpec,
        final_attempt: bool,
    ) -> Result<Option<Action<CF::Channel>>> {
        // don't create new channels on the final attempt
        let response = self.channels.request_channel(
            target,
            /* add_new_entry_if_not_found= */ !final_attempt,
        );

        match response {
            Ok(Some(ChannelForTarget::Open(channel))) => Ok(Some(Action::Return(Ok(channel)))),
            Ok(Some(ChannelForTarget::Pending(pending))) => {
                if !final_attempt {
                    Ok(Some(Action::Wait(pending)))
                } else {
                    // don't return a pending channel on the final attempt
                    Ok(None)
                }
            }
            Ok(Some(ChannelForTarget::NewEntry((handle, send)))) => {
                // do not drop the handle if refactoring; see `PendingChannelHandle` for details
                Ok(Some(Action::Launch((handle, send))))
            }
            Ok(None) => Ok(None),
            Err(e @ Error::IdentityConflict) => Ok(Some(Action::Return(Err(e)))),
            Err(e) => Err(e),
        }
    }

    /// Update the netdir
    pub(crate) fn update_netparams(
        &self,
        netparams: Arc<dyn AsRef<NetParameters>>,
    ) -> StdResult<(), tor_error::Bug> {
        self.channels.reconfigure_general(None, None, netparams)
    }

    /// Notifies the chanmgr to be dormant like dormancy
    pub(crate) fn set_dormancy(
        &self,
        dormancy: Dormancy,
        netparams: Arc<dyn AsRef<NetParameters>>,
    ) -> StdResult<(), tor_error::Bug> {
        self.channels
            .reconfigure_general(None, Some(dormancy), netparams)
    }

    /// Reconfigure all channels
    pub(crate) fn reconfigure(
        &self,
        config: &ChannelConfig,
        netparams: Arc<dyn AsRef<NetParameters>>,
    ) -> StdResult<(), tor_error::Bug> {
        self.channels
            .reconfigure_general(Some(config), None, netparams)
    }

    /// Expire any channels that have been unused longer than
    /// their maximum unused duration assigned during creation.
    ///
    /// Return a duration from now until next channel expires.
    ///
    /// If all channels are in use or there are no open channels,
    /// return 180 seconds which is the minimum value of
    /// max_unused_duration.
    pub(crate) fn expire_channels(&self) -> Duration {
        self.channels.expire_channels()
    }

    // tor-socks5 local patch: unconditionally terminate every tracked
    // channel, regardless of usage/idle state. Reuses the same
    // `self.channels`-level iteration as `expire_channels()`
    // (see `state::MgrState::terminate_all_channels`), but skips the
    // `ready_to_expire` check entirely: every channel is force-closed via
    // `AbstractChannel::terminate()` and then dropped from the map. Intended
    // to be called explicitly by a caller that has already detected a stale
    // network condition (e.g. a post-network-change watchdog), not on a
    // periodic schedule.
    /// Unconditionally terminate every channel currently tracked by this
    /// manager, and remove them from the map.
    ///
    /// Unlike [`expire_channels`](Self::expire_channels), this does not check
    /// whether a channel is idle: every channel is force-closed via
    /// [`AbstractChannel::terminate`], including ones with circuits actively
    /// (if hopelessly) attached. Callers that hold a reference to a channel
    /// that gets terminated here will observe it fail the same way they would
    /// after a real network-level disconnection.
    pub(crate) fn terminate_all_channels(&self) {
        self.channels.terminate_all_channels();
    }

    /// Test only: return the open usable channels with a given `ident`.
    #[cfg(test)]
    pub(crate) fn get_nowait<'a, T>(&self, ident: T) -> Vec<Arc<CF::Channel>>
    where
        T: Into<tor_linkspec::RelayIdRef<'a>>,
    {
        use state::ChannelState::*;
        self.channels
            .with_channels(|channel_map| {
                channel_map
                    .by_id(ident)
                    .filter_map(|entry| match entry {
                        Open(ent) if ent.channel.is_usable() => Some(Arc::clone(&ent.channel)),
                        _ => None,
                    })
                    .collect()
            })
            .expect("Poisoned lock")
    }
}

/// Possible actions that we'll decide to take when asked for a channel.
#[allow(clippy::large_enum_variant)]
enum Action<C: AbstractChannel> {
    /// We found no channel.  We're going to launch a new one,
    /// then tell everybody about it.
    Launch((PendingChannelHandle, Sending)),
    /// We found an in-progress attempt at making a channel.
    /// We're going to wait for it to finish.
    Wait(Pending),
    /// We found a usable channel.  We're going to return it.
    Return(Result<Arc<C>>),
}

#[cfg(test)]
#[path = "mgr/tests.rs"]
mod test;
