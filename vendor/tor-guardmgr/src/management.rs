use super::*;

impl GuardSets {
    /// Return a reference to the currently active set of guards.
    ///
    /// (That's easy enough for now, since there is never more than one set of
    /// guards.  But eventually that will change, as we add support for more
    /// complex filter types, and for bridge relays. Those will use separate
    /// `GuardSet` instances, and this accessor will choose the right one.)
    fn active_guards(&self) -> &GuardSet {
        self.guards(&self.active_set)
    }

    /// Return the set of guards corresponding to the provided selector.
    fn guards(&self, selector: &GuardSetSelector) -> &GuardSet {
        match selector {
            GuardSetSelector::Default => &self.default,
            GuardSetSelector::Restricted => &self.restricted,
            #[cfg(feature = "bridge-client")]
            GuardSetSelector::Bridges => &self.bridges,
        }
    }

    /// Return a mutable reference to the currently active set of guards.
    pub(super) fn active_guards_mut(&mut self) -> &mut GuardSet {
        self.guards_mut(&self.active_set.clone())
    }

    /// Return a mutable reference to the set of guards corresponding to the
    /// provided selector.
    pub(super) fn guards_mut(&mut self, selector: &GuardSetSelector) -> &mut GuardSet {
        match selector {
            GuardSetSelector::Default => &mut self.default,
            GuardSetSelector::Restricted => &mut self.restricted,
            #[cfg(feature = "bridge-client")]
            GuardSetSelector::Bridges => &mut self.bridges,
        }
    }

    /// Update all non-persistent state for the guards in this object with the
    /// state in `other`.
    fn copy_status_from(&mut self, mut other: GuardSets) {
        use strum::IntoEnumIterator;
        for sample in GuardSetSelector::iter() {
            self.guards_mut(&sample)
                .copy_ephemeral_status_into_newly_loaded_state(std::mem::take(
                    other.guards_mut(&sample),
                ));
        }
        self.active_set = other.active_set;
    }
}

impl GuardMgrInner {
    /// Look up the latest [`NetDir`] (if there is one) from our
    /// [`NetDirProvider`] (if we have one).
    fn timely_netdir(&self) -> Option<Arc<NetDir>> {
        self.netdir_provider
            .as_ref()
            .and_then(Weak::upgrade)
            .and_then(|np| np.timely_netdir().ok())
    }

    /// Look up the latest [`BridgeDescList`](bridge::BridgeDescList) (if there
    /// is one) from our [`BridgeDescProvider`](bridge::BridgeDescProvider) (if
    /// we have one).
    #[cfg(feature = "bridge-client")]
    fn latest_bridge_desc_list(&self) -> Option<Arc<bridge::BridgeDescList>> {
        self.bridge_desc_provider
            .as_ref()
            .and_then(Weak::upgrade)
            .map(|bp| bp.bridges())
    }

    /// Run a function that takes `&mut self` and an optional NetDir.
    ///
    /// We try to use the netdir from our [`NetDirProvider`] (if we have one).
    /// Therefore, although its _parameters_ are suitable for every
    /// [`GuardSet`], its _contents_ might not be. For those, call
    /// [`with_opt_universe`](Self::with_opt_universe) instead.
    //
    // This function exists to handle the lifetime mess where sometimes the
    // resulting NetDir will borrow from `netdir`, and sometimes it will borrow
    // from an Arc returned by `self.latest_netdir()`.
    fn with_opt_netdir<F, T>(&mut self, func: F) -> T
    where
        F: FnOnce(&mut Self, Option<&NetDir>) -> T,
    {
        if let Some(nd) = self.timely_netdir() {
            func(self, Some(nd.as_ref()))
        } else {
            func(self, None)
        }
    }

    /// Return the latest `BridgeSet` based on our `BridgeDescProvider` and our
    /// configured bridges.
    ///
    /// Returns `None` if we are not configured to use bridges.
    #[cfg(feature = "bridge-client")]
    fn latest_bridge_set(&self) -> Option<bridge::BridgeSet> {
        let bridge_config = self.configured_bridges.as_ref()?.clone();
        let bridge_descs = self.latest_bridge_desc_list();
        Some(bridge::BridgeSet::new(bridge_config, bridge_descs))
    }

    /// Run a function that takes `&mut self` and an optional [`UniverseRef`].
    ///
    /// We try to get a universe from the appropriate source for the current
    /// active guard set.
    fn with_opt_universe<F, T>(&mut self, func: F) -> T
    where
        F: FnOnce(&mut Self, Option<&UniverseRef>) -> T,
    {
        // TODO: it might be nice to make `func` take an GuardSet and a set of
        // parameters, so we can't get the active set wrong. Doing that will
        // require a fair amount of refactoring so that the borrow checker is
        // happy, however.
        match self.guards.active_set.universe_type() {
            UniverseType::NetDir => {
                if let Some(nd) = self.timely_netdir() {
                    func(self, Some(&UniverseRef::NetDir(nd)))
                } else {
                    func(self, None)
                }
            }
            #[cfg(feature = "bridge-client")]
            UniverseType::BridgeSet => func(
                self,
                self.latest_bridge_set()
                    .map(UniverseRef::BridgeSet)
                    .as_ref(),
            ),
        }
    }

    /// Update the status of all guards in the active set, based on the passage
    /// of time, our configuration, and the relevant Universe for our active
    /// set.
    #[instrument(skip_all, level = "trace")]
    pub(super) fn update(&mut self, wallclock: SystemTime, now: Instant) {
        self.with_opt_netdir(|this, netdir| {
            // Here we update our parameters from the latest NetDir, and check
            // whether we need to change to a (non)-restrictive GuardSet based
            // on those parameters and our configured filter.
            //
            // This uses a NetDir unconditionally, since we always want to take
            // the network parameters our parameters from the consensus even if
            // the guards themselves are from a BridgeSet.
            this.update_active_set_params_and_filter(netdir);
        });
        self.with_opt_universe(|this, univ| {
            // Now we update the set of guards themselves based on the
            // Universe, which is either the latest NetDir, or the latest
            // BridgeSet—depending on what the GuardSet wants.
            Self::update_guardset_internal(
                &this.params,
                wallclock,
                this.guards.active_set.universe_type(),
                this.guards.active_guards_mut(),
                univ,
            );
            #[cfg(feature = "bridge-client")]
            this.update_desired_descriptors(now);
            #[cfg(not(feature = "bridge-client"))]
            let _ = now;
        });

        // tor-socks5 local patch: recompute and publish the aggregated
        // "guards usable" signal after every guard-status refresh. Guard
        // directory information (`dir_info_missing`) is mutated inside
        // `update_status_from_dir` in the call above, so this is the point at
        // which the signal can change. arti-client gates
        // `BootstrapStatus::ready_for_traffic()` on it.
        self.update_guard_usability();
    }

    /// Replace our bridge configuration with the one from `new_config`.
    #[cfg(feature = "bridge-client")]
    #[instrument(level = "trace", skip_all)]
    pub(super) fn replace_bridge_config(
        &mut self,
        new_config: &impl GuardMgrConfig,
        wallclock: SystemTime,
        now: Instant,
    ) -> Result<RetireCircuits, GuardMgrConfigError> {
        match (&self.configured_bridges, new_config.bridges_enabled()) {
            (None, false) => {
                assert_ne!(
                    self.guards.active_set.universe_type(),
                    UniverseType::BridgeSet
                );
                return Ok(RetireCircuits::None); // nothing to do
            }
            (_, true) if !self.storage.can_store() => {
                // TODO: Ideally we would try to upgrade, obtaining an exclusive lock,
                // but `StorageHandle` currently lacks a method for that.
                return Err(GuardMgrConfigError::NoLock("bridges configured".into()));
            }
            (Some(current_bridges), true) if new_config.bridges() == current_bridges.as_ref() => {
                assert_eq!(
                    self.guards.active_set.universe_type(),
                    UniverseType::BridgeSet
                );
                return Ok(RetireCircuits::None); // nothing to do.
            }
            (_, true) => {
                self.configured_bridges = Some(new_config.bridges().into());
                self.guards.active_set = GuardSetSelector::Bridges;
            }
            (_, false) => {
                self.configured_bridges = None;
                self.guards.active_set = GuardSetSelector::Default;
            }
        }

        // If we have gotten here, we have changed the set of bridges, changed
        // which set is active, or changed them both.  We need to make sure that
        // our `GuardSet` object is up-to-date with our configuration.
        self.update(wallclock, now);

        // We also need to tell the caller that its circuits are no good any
        // more.
        //
        // TODO(nickm): Someday we can do this more judiciously by retuning
        // "Some" in the case where we're still using bridges but our new bridge
        // set contains different elements; see comment on RetireCircuits.
        //
        // TODO(nickm): We could also safely return RetireCircuits::None if we
        // are using bridges, and our new bridge list is a superset of the older
        // one.
        Ok(RetireCircuits::All)
    }

    /// Update our parameters, our selection (based on network parameters and
    /// configuration), and make sure the active GuardSet has the right
    /// configuration itself.
    ///
    /// We should call this whenever the NetDir's parameters change, or whenever
    /// our filter changes.  We do not need to call it for new elements arriving
    /// in our Universe, since those do not affect anything here.
    ///
    /// We should also call this whenever a new GuardSet becomes active for any
    /// reason _other_ than just having called this function.
    ///
    /// (This function is only invoked from `update`, which should be called
    /// under the above circumstances.)
    fn update_active_set_params_and_filter(&mut self, netdir: Option<&NetDir>) {
        // Set the parameters.  These always come from the NetDir, even if this
        // is a bridge set.
        if let Some(netdir) = netdir {
            match GuardParams::try_from(netdir.params()) {
                Ok(params) => self.params = params,
                Err(e) => warn!("Unusable guard parameters from consensus: {}", e),
            }

            self.select_guard_set_based_on_filter(netdir);
        }

        // Change the filter, if it doesn't match what the guards have.
        //
        // TODO(nickm): We could use a "dirty" flag or something to decide
        // whether we need to call set_filter, if this comparison starts to show
        // up in profiles.
        if self.guards.active_guards().filter() != &self.filter {
            let restrictive = self.guards.active_set == GuardSetSelector::Restricted;
            self.guards
                .active_guards_mut()
                .set_filter(self.filter.clone(), restrictive);
        }
    }

    /// Update the status of every guard in `active_guards`, and expand it as
    /// needed.
    ///
    /// This function doesn't take `&self`, to make sure that we are only
    /// affecting a single `GuardSet`, and to avoid confusing the borrow
    /// checker.
    ///
    /// We should call this whenever the contents of the universe have changed.
    ///
    /// We should also call this whenever a new GuardSet becomes active.
    fn update_guardset_internal<U: Universe>(
        params: &GuardParams,
        now: SystemTime,
        universe_type: UniverseType,
        active_guards: &mut GuardSet,
        universe: Option<&U>,
    ) -> ExtendedStatus {
        // Expire guards.  Do that early, in case doing so makes it clear that
        // we need to grab more guards or mark others as primary.
        active_guards.expire_old_guards(params, now);

        let extended = if let Some(universe) = universe {
            // TODO: This check here may be completely unnecessary. I inserted
            // it back in 5ac0fcb7ef603e0d14 because I was originally concerned
            // it might be undesirable to list a primary guard as "missing dir
            // info" (and therefore unusable) if we were expecting to get its
            // microdescriptor "very soon."
            //
            // But due to the other check in `netdir_is_sufficient`, we
            // shouldn't be installing a netdir until it has microdescs for all
            // of the (non-bridge) primary guards that it lists. - nickm
            let n = active_guards.n_primary_without_id_info_in(universe);
            if n > 0 && universe_type == UniverseType::NetDir {
                // We are missing the information from a NetDir needed to see
                // whether our primary guards are listed, so we shouldn't update
                // our guard status.
                //
                // We don't want to do this check if we are using bridges, since
                // a missing bridge descriptor is not guaranteed to temporary
                // problem in the same way that a missing microdescriptor is.
                // (When a bridge desc is missing, the bridge could be down or
                // unreachable, and nobody else can help us. But if a microdesc
                // is missing, we just need to find a cache that has it.)
                trace!(
                    n_primary_without_id_info = n,
                    "Not extending guardset, missing information."
                );
                return ExtendedStatus::No;
            }
            active_guards.update_status_from_dir(universe);
            active_guards.extend_sample_as_needed(now, params, universe)
        } else {
            trace!("Not extending guardset, no universe given.");
            ExtendedStatus::No
        };

        active_guards.select_primary_guards(params);

        extended
    }

    /// If using bridges, tell the BridgeDescProvider which descriptors we want.
    /// We need to check this *after* we select our primary guards.
    #[cfg(feature = "bridge-client")]
    fn update_desired_descriptors(&mut self, now: Instant) {
        if self.guards.active_set.universe_type() != UniverseType::BridgeSet {
            return;
        }

        let provider = self.bridge_desc_provider.as_ref().and_then(Weak::upgrade);
        let bridge_set = self.latest_bridge_set();
        if let (Some(provider), Some(bridge_set)) = (provider, bridge_set) {
            let desired: Vec<_> = self
                .guards
                .active_guards()
                .descriptors_to_request(now, &self.params)
                .into_iter()
                .flat_map(|guard| bridge_set.bridge_by_guard(guard))
                .cloned()
                .collect();

            provider.set_bridges(&desired);
        }
    }

    /// Replace the active guard state with `new_state`, preserving
    /// non-persistent state for any guards that are retained.
    #[instrument(level = "trace", skip_all)]
    pub(super) fn replace_guards_with(
        &mut self,
        mut new_guards: GuardSets,
        wallclock: SystemTime,
        now: Instant,
    ) {
        std::mem::swap(&mut self.guards, &mut new_guards);
        self.guards.copy_status_from(new_guards);
        self.update(wallclock, now);
    }

    /// Update which guard set is active based on the current filter and the
    /// provided netdir.
    ///
    /// After calling this function, the new guard set's filter may be
    /// out-of-date: be sure to call `set_filter` as appropriate.
    fn select_guard_set_based_on_filter(&mut self, netdir: &NetDir) {
        // In general, we'd like to use the restricted set if we're under the
        // threshold, and the default set if we're over the threshold.  But if
        // we're sitting close to the threshold, we want to avoid flapping back
        // and forth, so we only change when we're more than 5% "off" from
        // whatever our current setting is.
        //
        // (See guard-spec section 2 for more information.)
        let offset = match self.guards.active_set {
            GuardSetSelector::Default => -0.05,
            GuardSetSelector::Restricted => 0.05,
            // If we're using bridges, then we don't switch between the other guard sets based on the filter at all.
            #[cfg(feature = "bridge-client")]
            GuardSetSelector::Bridges => return,
        };
        let frac_permitted = self.filter.frac_bw_permitted(netdir);
        let threshold = self.params.filter_threshold + offset;
        let new_choice = if frac_permitted < threshold {
            GuardSetSelector::Restricted
        } else {
            GuardSetSelector::Default
        };

        if new_choice != self.guards.active_set {
            info!(
                "Guard selection changed; we are now using the {:?} guard set",
                &new_choice
            );

            self.guards.active_set = new_choice;

            if frac_permitted < self.params.extreme_threshold {
                warn!(
                    "The number of guards permitted is smaller than the recommended minimum of {:.0}%.",
                    self.params.extreme_threshold * 100.0,
                );
            }
        }
    }

    /// Mark all of our primary guards as retriable, if we haven't done
    /// so since long enough before `now`.
    ///
    /// We want to call this function whenever a guard attempt succeeds,
    /// if the internet seemed to be down when the guard attempt was
    /// first launched.
    fn maybe_retry_primary_guards(&mut self, now: Instant) {
        // We don't actually want to mark our primary guards as
        // retriable more than once per internet_down_timeout: after
        // the first time, we would just be noticing the same "coming
        // back online" event more than once.
        let interval = self.params.internet_down_timeout;
        if self.last_primary_retry_time + interval <= now {
            debug!(
                "Successfully reached a guard after a while off the internet; marking all primary guards retriable."
            );
            self.guards
                .active_guards_mut()
                .mark_primary_guards_retriable();
            self.last_primary_retry_time = now;
        }
    }

    /// Replace the current GuardFilter with `filter`.
    #[instrument(level = "trace", skip_all)]
    pub(super) fn set_filter(&mut self, filter: GuardFilter, wallclock: SystemTime, now: Instant) {
        self.filter = filter;
        self.update(wallclock, now);
    }

    /// Called when the circuit manager reports (via [`GuardMonitor`]) that
    /// a guard succeeded or failed.
    ///
    /// Changes the guard's status as appropriate, and updates the pending
    /// request as needed.
    #[allow(clippy::cognitive_complexity)]
    pub(crate) fn handle_msg(
        &mut self,
        request_id: RequestId,
        status: GuardStatus,
        skew: Option<ClockSkew>,
        runtime: &impl tor_rtcompat::SleepProvider,
    ) {
        if let Some(mut pending) = self.pending.remove(&request_id) {
            // If there was a pending request matching this RequestId, great!
            let guard_id = pending.guard_id();
            trace!(?guard_id, ?status, "Received report of guard status");

            // First, handle the skew report (if any)
            if let Some(skew) = skew {
                let now = runtime.now();
                let observation = skew::SkewObservation { skew, when: now };

                match &guard_id.0 {
                    FirstHopIdInner::Guard(_, id) => {
                        self.guards.active_guards_mut().record_skew(id, observation);
                    }
                    FirstHopIdInner::Fallback(id) => {
                        self.fallbacks.note_skew(id, observation);
                    }
                }
                // TODO: We call this whenever we receive an observed clock
                // skew. That's not the perfect timing for two reasons.  First
                // off, it might be too frequent: it does an O(n) calculation,
                // which isn't ideal.  Second, it might be too infrequent: after
                // an hour has passed, a given observation won't be up-to-date
                // any more, and we might want to recalculate the skew
                // accordingly.
                self.update_skew(now);
            }

            match (status, &guard_id.0) {
                (GuardStatus::Failure, FirstHopIdInner::Fallback(id)) => {
                    // We used a fallback, and we weren't able to build a circuit through it.
                    self.fallbacks.note_failure(id, runtime.now());
                }
                (_, FirstHopIdInner::Fallback(_)) => {
                    // We don't record any other kind of circuit activity if we
                    // took the entry from the fallback list.
                }
                (GuardStatus::Success, FirstHopIdInner::Guard(sample, id)) => {
                    // If we had gone too long without any net activity when we
                    // gave out this guard, and now we're seeing a circuit
                    // succeed, tell the primary guards that they might be
                    // retriable.
                    if pending.net_has_been_down() {
                        self.maybe_retry_primary_guards(runtime.now());
                    }

                    // The guard succeeded.  Tell the GuardSet.
                    self.guards.guards_mut(sample).record_success(
                        id,
                        &self.params,
                        None,
                        runtime.wallclock(),
                    );
                    // Either tell the request whether the guard is
                    // usable, or schedule it as a "waiting" request.
                    if let Some(usable) = self.guard_usability_status(&pending, runtime.now()) {
                        trace!(?guard_id, usable, "Known usability status");
                        pending.reply(usable);
                    } else {
                        // This is the one case where we can't use the
                        // guard yet.
                        trace!(?guard_id, "Not able to answer right now");
                        pending.mark_waiting(runtime.now());
                        self.waiting.push(pending);
                    }
                }
                (GuardStatus::Failure, FirstHopIdInner::Guard(sample, id)) => {
                    self.guards
                        .guards_mut(sample)
                        .record_failure(id, None, runtime.now());
                    pending.reply(false);
                }
                (GuardStatus::AttemptAbandoned, FirstHopIdInner::Guard(sample, id)) => {
                    self.guards.guards_mut(sample).record_attempt_abandoned(id);
                    pending.reply(false);
                }
                (GuardStatus::Indeterminate, FirstHopIdInner::Guard(sample, id)) => {
                    self.guards
                        .guards_mut(sample)
                        .record_indeterminate_result(id);
                    pending.reply(false);
                }
            };
        } else {
            warn!(
                "Got a status {:?} for a request {:?} that wasn't pending",
                status, request_id
            );
        }

        // We might need to update the primary guards based on changes in the
        // status of guards above.
        self.guards
            .active_guards_mut()
            .select_primary_guards(&self.params);

        // Some waiting request may just have become ready (usable or
        // not); we need to give them the information they're waiting
        // for.
        self.expire_and_answer_pending_requests(runtime.now());
    }

    /// Helper to implement `GuardMgr::note_external_success()`.
    ///
    /// (This has to be a separate function so that we can borrow params while
    /// we have `mut self` borrowed.)
    pub(super) fn record_external_success<T>(
        &mut self,
        identity: &T,
        external_activity: ExternalActivity,
        now: SystemTime,
    ) where
        T: tor_linkspec::HasRelayIds + ?Sized,
    {
        for id in self.lookup_ids(identity) {
            match &id.0 {
                FirstHopIdInner::Guard(sample, id) => {
                    self.guards.guards_mut(sample).record_success(
                        id,
                        &self.params,
                        Some(external_activity),
                        now,
                    );
                }
                FirstHopIdInner::Fallback(id) => {
                    if external_activity == ExternalActivity::DirCache {
                        self.fallbacks.note_success(id);
                    }
                }
            }
        }
    }

    /// Return an iterator over all of the clock skew observations we've made
    /// for guards or fallbacks.
    fn skew_observations(&self) -> impl Iterator<Item = &skew::SkewObservation> {
        self.fallbacks
            .skew_observations()
            .chain(self.guards.active_guards().skew_observations())
    }

    /// Recalculate our estimated clock skew, and publish it to anybody who
    /// cares.
    fn update_skew(&mut self, now: Instant) {
        let estimate = skew::SkewEstimate::estimate_skew(self.skew_observations(), now);
        // TODO: we might want to do this only conditionally, when the skew
        // estimate changes.
        *self.send_skew.borrow_mut() = estimate;
    }

    /// tor-socks5 local patch: recompute whether the active guard sample is
    /// usable for traffic (at least one usable guard has complete directory
    /// information) and publish the result. Called at the end of [`update`] so
    /// the signal tracks every refresh of guard directory information.
    fn update_guard_usability(&mut self) {
        let usable = self
            .guards
            .active_guards()
            .any_guard_usable_for_traffic();
        *self.send_usable.borrow_mut() = usable;
    }

    /// If the circuit built because of a given [`PendingRequest`] may
    /// now be used (or discarded), return `Some(true)` or
    /// `Some(false)` respectively.
    ///
    /// Return None if we can't yet give an answer about whether such
    /// a circuit is usable.
    fn guard_usability_status(&self, pending: &PendingRequest, now: Instant) -> Option<bool> {
        match &pending.guard_id().0 {
            FirstHopIdInner::Guard(sample, id) => self.guards.guards(sample).circ_usability_status(
                id,
                pending.usage(),
                &self.params,
                now,
            ),
            // Fallback circuits are usable immediately, since we don't have to wait to
            // see whether any _other_ circuit succeeds or fails.
            FirstHopIdInner::Fallback(_) => Some(true),
        }
    }

    /// For requests that have been "waiting" for an answer for too long,
    /// expire them and tell the circuit manager that their circuits
    /// are unusable.
    fn expire_and_answer_pending_requests(&mut self, now: Instant) {
        // A bit ugly: we use a separate Vec here to avoid borrowing issues,
        // and put it back when we're done.
        let mut waiting = Vec::new();
        std::mem::swap(&mut waiting, &mut self.waiting);

        waiting.retain_mut(|pending| {
            let expired = pending
                .waiting_since()
                .and_then(|w| now.checked_duration_since(w))
                .map(|d| d >= self.params.np_idle_timeout)
                == Some(true);
            if expired {
                trace!(?pending, "Pending request expired");
                pending.reply(false);
                return false;
            }

            // TODO-SPEC: guard_usability_status isn't what the spec says.  It
            // says instead that we should look at _circuit_ status, saying:
            //  "   Definition: In the algorithm above, C2 "blocks" C1 if:
            // * C2 obeys all the restrictions that C1 had to obey, AND
            // * C2 has higher priority than C1, AND
            // * Either C2 is <complete>, or C2 is <waiting_for_better_guard>,
            // or C2 has been <usable_if_no_better_guard> for no more than
            // {NONPRIMARY_GUARD_CONNECT_TIMEOUT} seconds."
            //
            // See comments in sample::GuardSet::circ_usability_status.

            if let Some(answer) = self.guard_usability_status(pending, now) {
                trace!(?pending, answer, "Pending request now ready");
                pending.reply(answer);
                return false;
            }
            true
        });

        // Put the waiting list back.
        std::mem::swap(&mut waiting, &mut self.waiting);
    }

    /// Return every currently extant FirstHopId for a guard or fallback
    /// directory matching (or possibly matching) the provided keys.
    ///
    /// An identity is _possibly matching_ if it contains some of the IDs in the
    /// provided identity, and it has no _contradictory_ identities, but it does
    /// not necessarily contain _all_ of those identities.
    ///
    /// # TODO
    ///
    /// This function should probably not exist; it's only used so that dirmgr
    /// can report successes or failures, since by the time it observes them it
    /// doesn't know whether its circuit came from a guard or a fallback.  To
    /// solve that, we'll need CircMgr to record and report which one it was
    /// using, which will take some more plumbing.
    ///
    /// TODO relay: we will have to make the change above when we implement
    /// relays; otherwise, it would be possible for an attacker to exploit it to
    /// mislead us about our guard status.
    pub(super) fn lookup_ids<T>(&self, identity: &T) -> Vec<FirstHopId>
    where
        T: tor_linkspec::HasRelayIds + ?Sized,
    {
        use strum::IntoEnumIterator;
        let mut vec = Vec::with_capacity(2);

        let id = ids::GuardId::from_relay_ids(identity);
        for sample in GuardSetSelector::iter() {
            let guard_id = match self.guards.guards(&sample).contains(&id) {
                Ok(true) => &id,
                Err(other) => other,
                Ok(false) => continue,
            };
            vec.push(FirstHopId(FirstHopIdInner::Guard(sample, guard_id.clone())));
        }

        let id = ids::FallbackId::from_relay_ids(identity);
        if self.fallbacks.contains(&id) {
            vec.push(id.into());
        }

        vec
    }

    /// Run any periodic events that update guard status, and return a
    /// duration after which periodic events should next be run.
    #[instrument(skip_all, level = "trace")]
    pub(crate) fn run_periodic_events(&mut self, wallclock: SystemTime, now: Instant) -> Duration {
        self.update(wallclock, now);
        self.expire_and_answer_pending_requests(now);
        Duration::from_secs(1) // TODO: Too aggressive.
    }

    /// Try to select a guard, expanding the sample if the first attempt fails.
    #[instrument(skip_all, level = "trace")]
    pub(super) fn select_guard_with_expand(
        &mut self,
        usage: &GuardUsage,
        now: Instant,
        wallclock: SystemTime,
    ) -> Result<(sample::ListKind, FirstHop), PickGuardError> {
        // Try to find a guard.
        let first_error = match self.select_guard_once(usage, now) {
            Ok(res1) => return Ok(res1),
            Err(e) => {
                trace!("Couldn't select guard on first attempt: {}", e);
                e
            }
        };

        // That didn't work. If we have a netdir, expand the sample and try again.
        let res = self.with_opt_universe(|this, univ| {
            let univ = univ?;
            trace!("No guards available, trying to extend the sample.");
            // Make sure that the status on all of our guards are accurate, and
            // expand the sample if we can.
            //
            // Our parameters and configuration did not change, so we do not
            // need to call update() or update_active_set_and_filter(). This
            // call is sufficient to  extend the sample and recompute primary
            // guards.
            let _extended = Self::update_guardset_internal(
                &this.params,
                wallclock,
                this.guards.active_set.universe_type(),
                this.guards.active_guards_mut(),
                Some(univ),
            );
            // Retry unconditionally: update_guardset_internal recomputes each
            // guard's dir_info_missing / conforms_to_usage via
            // update_from_universe, which can flip a descriptor-less bridge
            // to "unsuitable for Data" even when the sample size is unchanged
            // (ExtendedStatus::No). Gating the retry on sample growth (the
            // old `== Yes` check) discarded that freshly-computed state.
            match this.select_guard_once(usage, now) {
                Ok(res) => return Some(res),
                Err(e) => {
                    trace!("Couldn't select guard after update: {}", e);
                }
            }
            None
        });
        if let Some(res) = res {
            return Ok(res);
        }

        // Okay, that didn't work either.  If we were asked for a directory
        // guard, and we aren't using bridges, then we may be able to use a
        // fallback.
        if usage.kind == GuardUsageKind::OneHopDirectory
            && self.guards.active_set.universe_type() == UniverseType::NetDir
        {
            return self.select_fallback(now);
        }

        // Couldn't extend the sample or use a fallback; return the original error.
        Err(first_error)
    }

    /// Helper: try to pick a single guard, without retrying on failure.
    fn select_guard_once(
        &self,
        usage: &GuardUsage,
        now: Instant,
    ) -> Result<(sample::ListKind, FirstHop), PickGuardError> {
        let active_set = &self.guards.active_set;
        #[cfg_attr(not(feature = "bridge-client"), allow(unused_mut))]
        let (list_kind, mut first_hop) =
            self.guards
                .guards(active_set)
                .pick_guard(active_set, usage, &self.params, now)?;
        #[cfg(feature = "bridge-client")]
        if self.guards.active_set.universe_type() == UniverseType::BridgeSet {
            // See if we can promote first_hop to a viable CircTarget.
            let bridges = self.latest_bridge_set().ok_or_else(|| {
                PickGuardError::Internal(internal!(
                    "No bridge set available, even though this is the Bridges sample"
                ))
            })?;
            first_hop.lookup_bridge_circ_target(&bridges);

            if usage.kind == GuardUsageKind::Data && !first_hop.contains_circ_target() {
                // tor-socks5 local patch: a missing bridge descriptor is a
                // transient, recoverable condition (the descriptor is fetched
                // asynchronously by BridgeDescProvider), not a programming
                // bug. Return AllGuardsDown so HasRetryTime yields
                // RetryTime::AfterWaiting and the caller retries instead of
                // aborting the whole request after one attempt. The precise
                // per-reason rejection counts are computed inside
                // pick_guard_id and aren't available here, so report zeroed
                // FilterCounts — the retry_at: None semantics are what matter.
                return Err(PickGuardError::AllGuardsDown {
                    retry_at: None,
                    running: FilterCount::default(),
                    pending: FilterCount::default(),
                    suitable: FilterCount::default(),
                    filtered: FilterCount::default(),
                });
            }
        }
        Ok((list_kind, first_hop))
    }

    /// Helper: Select a fallback directory.
    ///
    /// Called when we have no guard information to use. Return values are as
    /// for [`GuardMgr::select_guard()`]
    fn select_fallback(
        &self,
        now: Instant,
    ) -> Result<(sample::ListKind, FirstHop), PickGuardError> {
        let filt = self.guards.active_guards().filter();

        let fallback = crate::FirstHop {
            sample: None,
            inner: crate::FirstHopInner::Chan(OwnedChanTarget::from_chan_target(
                self.fallbacks.choose(&mut rand::rng(), now, filt)?,
            )),
        };
        let fallback = filt.modify_hop(fallback)?;
        Ok((sample::ListKind::Fallback, fallback))
    }
}
