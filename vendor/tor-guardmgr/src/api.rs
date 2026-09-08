use super::*;

impl<R: Runtime> GuardMgr<R> {
    /// Create a new "empty" guard manager and launch its background tasks.
    ///
    /// It won't be able to hand out any guards until a [`NetDirProvider`] has
    /// been installed.
    #[instrument(skip_all, level = "trace")]
    pub fn new<S>(
        runtime: R,
        state_mgr: S,
        config: &impl GuardMgrConfig,
    ) -> Result<Self, GuardMgrError>
    where
        S: StateMgr + Send + Sync + 'static,
    {
        let (ctrl, rcv) = mpsc::unbounded();
        let storage: DynStorageHandle<GuardSets> = state_mgr.create_handle(STORAGE_KEY);
        // TODO(nickm): We should do something about the old state in
        // `default_guards`.  Probably it would be best to delete it.  We could
        // try to migrate it instead, but that's beyond the stability guarantee
        // that we're getting at this stage of our (pre-0.1) development.
        let state = storage.load()?.unwrap_or_default();

        let (send_skew, recv_skew) = postage::watch::channel();
        let recv_skew = ClockSkewEvents { inner: recv_skew };

        // tor-socks5 local patch: channel for the aggregated "guards usable"
        // signal. Initialized to `false` (conservative: the client is not
        // ready until a positive signal arrives after the first guard-sample
        // refresh).
        let (send_usable, recv_usable) = postage::watch::channel();
        let recv_usable = GuardUsableEvents { inner: recv_usable };

        let inner = Arc::new(Mutex::new(GuardMgrInner {
            guards: state,
            filter: GuardFilter::unfiltered(),
            last_primary_retry_time: runtime.now(),
            params: GuardParams::default(),
            ctrl,
            pending: HashMap::new(),
            waiting: Vec::new(),
            fallbacks: config.fallbacks().into(),
            storage,
            send_skew,
            recv_skew,
            send_usable,
            recv_usable,
            netdir_provider: None,
            #[cfg(feature = "bridge-client")]
            bridge_desc_provider: None,
            #[cfg(feature = "bridge-client")]
            configured_bridges: None,
        }));
        #[cfg(feature = "bridge-client")]
        {
            let mut inner = inner.lock().expect("lock poisoned");
            // TODO(nickm): This calls `GuardMgrInner::update`. Will we mind doing so before any
            // providers are configured? I think not, but we should make sure.
            let _: RetireCircuits =
                inner.replace_bridge_config(config, runtime.wallclock(), runtime.now())?;
        }
        {
            let weak_inner = Arc::downgrade(&inner);
            let rt_clone = runtime.clone();
            runtime
                .spawn(daemon::report_status_events(rt_clone, weak_inner, rcv))
                .map_err(|e| GuardMgrError::from_spawn("guard status event reporter", e))?;
        }
        {
            let rt_clone = runtime.clone();
            let weak_inner = Arc::downgrade(&inner);
            runtime
                .spawn(daemon::run_periodic(rt_clone, weak_inner))
                .map_err(|e| GuardMgrError::from_spawn("periodic guard updater", e))?;
        }
        Ok(GuardMgr { runtime, inner })
    }

    /// Install a [`NetDirProvider`] for use by this guard manager.
    ///
    /// It will be used to keep the guards up-to-date with changes from the
    /// network directory, and to find new guards when no NetDir is provided to
    /// select_guard().
    ///
    /// TODO: we should eventually return some kind of a task handle from this
    /// task, even though it is not strictly speaking periodic.
    ///
    /// The guardmgr retains only a `Weak` reference to `provider`,
    /// `install_netdir_provider` downgrades it on entry,
    // TODO add ref to document when https://gitlab.torproject.org/tpo/core/arti/-/issues/624
    // is fixed.  Also, maybe take an owned `Weak` to start with.
    //
    /// # Panics
    ///
    /// Panics if a [`NetDirProvider`] is already installed.
    pub fn install_netdir_provider(
        &self,
        provider: &Arc<dyn NetDirProvider>,
    ) -> Result<(), GuardMgrError> {
        let weak_provider = Arc::downgrade(provider);
        {
            let mut inner = self.inner.lock().expect("Poisoned lock");
            assert!(inner.netdir_provider.is_none());
            inner.netdir_provider = Some(weak_provider.clone());
        }
        let weak_inner = Arc::downgrade(&self.inner);
        let rt_clone = self.runtime.clone();
        self.runtime
            .spawn(daemon::keep_netdir_updated(
                rt_clone,
                weak_inner,
                weak_provider,
            ))
            .map_err(|e| GuardMgrError::from_spawn("periodic guard netdir updater", e))?;
        Ok(())
    }

    /// Configure a new [`bridge::BridgeDescProvider`] for this [`GuardMgr`].
    ///
    /// It will be used to learn about changes in the set of available bridge
    /// descriptors; we'll inform it whenever our desired set of bridge
    /// descriptors changes.
    ///
    /// TODO: Same todo as in `install_netdir_provider` about task handles.
    ///
    /// # Panics
    ///
    /// Panics if a [`bridge::BridgeDescProvider`] is already installed.
    #[cfg(feature = "bridge-client")]
    pub fn install_bridge_desc_provider(
        &self,
        provider: &Arc<dyn bridge::BridgeDescProvider>,
    ) -> Result<(), GuardMgrError> {
        let weak_provider = Arc::downgrade(provider);
        {
            let mut inner = self.inner.lock().expect("Poisoned lock");
            assert!(inner.bridge_desc_provider.is_none());
            inner.bridge_desc_provider = Some(weak_provider.clone());
        }

        let weak_inner = Arc::downgrade(&self.inner);
        let rt_clone = self.runtime.clone();
        self.runtime
            .spawn(daemon::keep_bridge_descs_updated(
                rt_clone,
                weak_inner,
                weak_provider,
            ))
            .map_err(|e| GuardMgrError::from_spawn("periodic guard netdir updater", e))?;

        Ok(())
    }

    /// Flush our current guard state to the state manager, if there
    /// is any unsaved state.
    pub fn store_persistent_state(&self) -> Result<(), GuardMgrError> {
        let inner = self.inner.lock().expect("Poisoned lock");
        trace!("Flushing guard state to disk.");
        inner.storage.store(&inner.guards)?;
        Ok(())
    }

    /// Reload state from the state manager.
    ///
    /// We only call this method if we _don't_ have the lock on the state
    /// files.  If we have the lock, we only want to save.
    #[instrument(level = "trace", skip_all)]
    pub fn reload_persistent_state(&self) -> Result<(), GuardMgrError> {
        let mut inner = self.inner.lock().expect("Poisoned lock");
        if let Some(new_guards) = inner.storage.load()? {
            inner.replace_guards_with(new_guards, self.runtime.wallclock(), self.runtime.now());
        }
        Ok(())
    }

    /// Switch from having an unowned persistent state to having an owned one.
    ///
    /// Requires that we hold the lock on the state files.
    #[instrument(level = "trace", skip_all)]
    pub fn upgrade_to_owned_persistent_state(&self) -> Result<(), GuardMgrError> {
        let mut inner = self.inner.lock().expect("Poisoned lock");
        debug_assert!(inner.storage.can_store());
        let new_guards = inner.storage.load()?.unwrap_or_default();
        let wallclock = self.runtime.wallclock();
        let now = self.runtime.now();
        inner.replace_guards_with(new_guards, wallclock, now);
        Ok(())
    }

    /// Return true if `netdir` has enough information to safely become our new netdir.
    pub fn netdir_is_sufficient(&self, netdir: &NetDir) -> bool {
        let mut inner = self.inner.lock().expect("Poisoned lock");
        if inner.guards.active_set.universe_type() != UniverseType::NetDir {
            // If we aren't using the netdir, this isn't something we want to look at.
            return true;
        }
        inner
            .guards
            .active_guards_mut()
            .n_primary_without_id_info_in(netdir)
            == 0
    }

    /// Mark every guard as potentially retriable, regardless of how recently we
    /// failed to connect to it.
    pub fn mark_all_guards_retriable(&self) {
        let mut inner = self.inner.lock().expect("Poisoned lock");
        inner.guards.active_guards_mut().mark_all_guards_retriable();
    }

    /// Whether this identity is disabled in any known guard sample.
    pub fn guard_is_disabled<T: tor_linkspec::HasRelayIds + ?Sized>(&self, identity: &T) -> bool {
        let inner = self.inner.lock().expect("Poisoned lock");
        inner.lookup_ids(identity).iter().any(|hop| match &hop.0 {
            FirstHopIdInner::Guard(sample, id) => {
                let guards = match sample {
                    GuardSetSelector::Default => &inner.guards.default,
                    GuardSetSelector::Restricted => &inner.guards.restricted,
                    #[cfg(feature = "bridge-client")]
                    GuardSetSelector::Bridges => &inner.guards.bridges,
                };
                guards.guard_is_disabled(id)
            }
            FirstHopIdInner::Fallback(_) => false,
        })
    }

    /// tor-socks5 local patch: re-enable every guard that is currently disabled
    /// by `TooManyIndeterminateFailures` (clearing its `disabled` state and
    /// resetting the indeterminate-failure history that led to the disable),
    /// and return the number of guards that were re-enabled.
    ///
    /// `tor-guardmgr` permanently disables a guard once its lifetime
    /// indeterminate-failure ratio exceeds `0.7`, and persists that `disabled`
    /// state across restarts; nothing else in the crate ever clears it. In a
    /// bridge-only deployment with only a handful of configured bridges, a
    /// single transient second-hop/exit failure storm can therefore take a
    /// bridge out of rotation for good. This hook lets an application-level
    /// watchdog (which knows how small the bridge pool is) deliberately
    /// re-enable disabled bridges on its own policy — for example when too few
    /// usable bridges remain.
    ///
    /// Returns the number of guards that were disabled and are now
    /// re-enabled. Guards that were already usable are left untouched.
    pub fn reset_disabled_guards(&self) -> usize {
        let mut inner = self.inner.lock().expect("Poisoned lock");
        inner.guards.active_guards_mut().reset_disabled_guards()
    }

    /// Configure this guardmgr to use a fixed [`NetDir`] instead of a provider.
    ///
    /// This function is for testing only, and is exclusive with
    /// `install_netdir_provider`.
    ///
    /// # Panics
    ///
    /// Panics if any [`NetDirProvider`] has already been installed.
    #[cfg(any(test, feature = "testing"))]
    pub fn install_test_netdir(&self, netdir: &NetDir) {
        use tor_netdir::testprovider::TestNetDirProvider;
        let wallclock = self.runtime.wallclock();
        let now = self.runtime.now();
        let netdir_provider: Arc<dyn NetDirProvider> =
            Arc::new(TestNetDirProvider::from(netdir.clone()));
        self.install_netdir_provider(&netdir_provider)
            .expect("Couldn't install testing network provider");

        let mut inner = self.inner.lock().expect("Poisoned lock");
        inner.update(wallclock, now);
    }

    /// Replace the configuration in this `GuardMgr` with `config`.
    #[instrument(level = "trace", skip_all)]
    pub fn reconfigure(
        &self,
        config: &impl GuardMgrConfig,
    ) -> Result<RetireCircuits, ReconfigureError> {
        let mut inner = self.inner.lock().expect("Poisoned lock");
        // Change the set of configured fallbacks.
        {
            let mut fallbacks: fallback::FallbackState = config.fallbacks().into();
            std::mem::swap(&mut inner.fallbacks, &mut fallbacks);
            inner.fallbacks.take_status_from(fallbacks);
        }
        // If we are built to use bridges, change the bridge configuration.
        #[cfg(feature = "bridge-client")]
        {
            let wallclock = self.runtime.wallclock();
            let now = self.runtime.now();
            Ok(inner.replace_bridge_config(config, wallclock, now)?)
        }
        // If we are built to use bridges, change the bridge configuration.
        #[cfg(not(feature = "bridge-client"))]
        {
            Ok(RetireCircuits::None)
        }
    }

    /// Replace the current [`GuardFilter`] used by this `GuardMgr`.
    // TODO should this be part of the config?
    pub fn set_filter(&self, filter: GuardFilter) {
        let wallclock = self.runtime.wallclock();
        let now = self.runtime.now();
        let mut inner = self.inner.lock().expect("Poisoned lock");
        inner.set_filter(filter, wallclock, now);
    }

    /// Select a guard for a given [`GuardUsage`].
    ///
    /// On success, we return a [`FirstHop`] object to identify which
    /// guard we have picked, a [`GuardMonitor`] object that the
    /// caller can use to report whether its attempt to use the guard
    /// succeeded or failed, and a [`GuardUsable`] future that the
    /// caller can use to decide whether a circuit built through the
    /// guard is actually safe to use.
    ///
    /// That last point is important: It's okay to build a circuit
    /// through the guard returned by this function, but you can't
    /// actually use it for traffic unless the [`GuardUsable`] future
    /// yields "true".
    #[instrument(skip_all, level = "trace")]
    pub fn select_guard(
        &self,
        usage: GuardUsage,
    ) -> Result<(FirstHop, GuardMonitor, GuardUsable), PickGuardError> {
        let now = self.runtime.now();
        let wallclock = self.runtime.wallclock();

        let mut inner = self.inner.lock().expect("Poisoned lock");

        // (I am not 100% sure that we need to consider_all_retries here, but
        // it should _probably_ not hurt.)
        inner.guards.active_guards_mut().consider_all_retries(now);

        let (origin, guard) = inner.select_guard_with_expand(&usage, now, wallclock)?;
        trace!(?guard, ?usage, "Guard selected");

        let (usable, usable_sender) = if origin.usable_immediately() {
            (GuardUsable::new_usable_immediately(), None)
        } else {
            let (u, snd) = GuardUsable::new_uncertain();
            (u, Some(snd))
        };
        let request_id = pending::RequestId::next();
        let ctrl = inner.ctrl.clone();
        let monitor = GuardMonitor::new(request_id, ctrl);

        // Note that the network can be down even if all the primary guards
        // are not yet marked as unreachable.  But according to guard-spec we
        // don't want to acknowledge the net as down before that point, since
        // we don't mark all the primary guards as retriable unless
        // we've been forced to non-primary guards.
        let net_has_been_down =
            if let Some(duration) = tor_proto::time_since_last_incoming_traffic() {
                inner
                    .guards
                    .active_guards_mut()
                    .all_primary_guards_are_unreachable()
                    && duration >= inner.params.internet_down_timeout
            } else {
                // TODO: Is this the correct behavior in this case?
                false
            };

        let pending_request = pending::PendingRequest::new(
            guard.first_hop_id(),
            usage,
            usable_sender,
            net_has_been_down,
        );
        inner.pending.insert(request_id, pending_request);

        match &guard.sample {
            Some(sample) => {
                let guard_id = GuardId::from_relay_ids(&guard);
                inner
                    .guards
                    .guards_mut(sample)
                    .record_attempt(&guard_id, now);
            }
            None => {
                // We don't record attempts for fallbacks; we only care when
                // they have failed.
            }
        }

        Ok((guard, monitor, usable))
    }

    /// Record that _after_ we built a circuit with a guard, something described
    /// in `external_failure` went wrong with it.
    pub fn note_external_failure<T>(&self, identity: &T, external_failure: ExternalActivity)
    where
        T: tor_linkspec::HasRelayIds + ?Sized,
    {
        let now = self.runtime.now();
        let mut inner = self.inner.lock().expect("Poisoned lock");
        let ids = inner.lookup_ids(identity);
        for id in ids {
            match &id.0 {
                FirstHopIdInner::Guard(sample, id) => {
                    inner
                        .guards
                        .guards_mut(sample)
                        .record_failure(id, Some(external_failure), now);
                }
                FirstHopIdInner::Fallback(id) => {
                    if external_failure == ExternalActivity::DirCache {
                        inner.fallbacks.note_failure(id, now);
                    }
                }
            }
        }
    }

    /// Record that _after_ we built a circuit with a guard, some activity
    /// described in `external_activity` was successful with it.
    pub fn note_external_success<T>(&self, identity: &T, external_activity: ExternalActivity)
    where
        T: tor_linkspec::HasRelayIds + ?Sized,
    {
        let mut inner = self.inner.lock().expect("Poisoned lock");

        inner.record_external_success(identity, external_activity, self.runtime.wallclock());
    }

    /// Return a stream of events about our estimated clock skew; these events
    /// are `None` when we don't have enough information to make an estimate,
    /// and `Some(`[`SkewEstimate`]`)` otherwise.
    ///
    /// Note that this stream can be lossy: if the estimate changes more than
    /// one before you read from the stream, you might only get the most recent
    /// update.
    pub fn skew_events(&self) -> ClockSkewEvents {
        let inner = self.inner.lock().expect("Poisoned lock");
        inner.recv_skew.clone()
    }

    /// tor-socks5 local patch: return a stream of events describing whether the
    /// active guard sample is usable for traffic — `true` iff at least one
    /// usable guard currently has complete directory information. arti-client
    /// consumes this to gate `BootstrapStatus::ready_for_traffic()`.
    ///
    /// Like [`skew_events`](Self::skew_events), this stream can be lossy: if the
    /// state changes more than once before you read, you only get the latest.
    pub fn usable_guard_events(&self) -> GuardUsableEvents {
        let inner = self.inner.lock().expect("Poisoned lock");
        inner.recv_usable.clone()
    }

    /// Ensure that the message queue is flushed before proceeding to
    /// the next step.  Used for testing.
    #[cfg(test)]
    pub(super) async fn flush_msg_queue(&self) {
        let (snd, rcv) = oneshot::channel();
        let pingmsg = daemon::Msg::Ping(snd);
        {
            let inner = self.inner.lock().expect("Poisoned lock");
            inner
                .ctrl
                .unbounded_send(pingmsg)
                .expect("Guard observer task exited prematurely.");
        }
        let _ = rcv.await;
    }
}
