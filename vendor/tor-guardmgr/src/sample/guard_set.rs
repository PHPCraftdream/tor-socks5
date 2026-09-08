use super::*;

#[cfg(test)]
#[path = "tests.rs"]
mod test;

impl GuardSet {
    /// Return the lengths of the different elements of the guard set.
    ///
    /// Used to report bugs or corruption in consistency.
    fn inner_lengths(&self) -> (usize, usize, usize, usize) {
        (
            self.guards.len(),
            self.sample.len(),
            self.confirmed.len(),
            self.primary.len(),
        )
    }

    /// Remove all elements from this `GuardSet` that ought to be referenced by
    /// another element, but which are not.
    ///
    /// This method only removes corrupted elements and updates IDs in the ID
    /// list (possibly adding new IDs); it doesn't add guards or other data.
    /// It won't do anything if the `GuardSet` is well-formed.
    fn fix_consistency(&mut self) {
        /// Remove every element of `id_list` that does not belong to some guard
        /// in `guards`, and update the others to have any extra identities
        /// listed in `guards`.
        fn fix_id_list(guards: &ByRelayIds<Guard>, id_list: &mut Vec<GuardId>) {
            id_list.retain_mut(|id| match guards.by_all_ids(id) {
                Some(guard) => {
                    *id = guard.guard_id().clone();
                    true
                }
                None => false,
            });
        }

        let sample_set: HashSet<_> = self.sample.iter().collect();
        self.guards.retain(|g| sample_set.contains(g.guard_id()));
        fix_id_list(&self.guards, &mut self.sample);
        fix_id_list(&self.guards, &mut self.confirmed);
        fix_id_list(&self.guards, &mut self.primary);
    }

    /// Assert that this `GuardSet` is internally consistent.
    ///
    /// Incidentally fixes the consistency of this `GuardSet` if needed.
    fn assert_consistency(&mut self) {
        let len_pre = self.inner_lengths();
        self.fix_consistency();
        let len_post = self.inner_lengths();
        assert_eq!(len_pre, len_post);
    }

    /// Return the guard that has every identity in `id`, if any.
    pub(crate) fn get(&self, id: &GuardId) -> Option<&Guard> {
        self.guards.by_all_ids(id)
    }

    /// Replace the filter used by this `GuardSet` with `filter`.
    ///
    /// Removes all primary guards that the filter doesn't permit.
    ///
    /// If `restrictive` is true, this filter is treated as "extremely restrictive".
    pub(crate) fn set_filter(&mut self, filter: GuardFilter, restrictive: bool) {
        self.active_filter = filter;
        self.filter_is_restrictive = restrictive;

        self.assert_consistency();

        let guards = &self.guards; // avoid borrow issues
        let filt = &self.active_filter;
        self.primary.retain(|id| {
            guards
                .by_all_ids(id)
                .map(|g| g.usable() && filt.permits(g))
                .unwrap_or(false)
        });

        self.primary_guards_invalidated = true;
    }

    /// Return the current filter for this `GuardSet`.
    pub(crate) fn filter(&self) -> &GuardFilter {
        &self.active_filter
    }

    /// Copy non-persistent status from every guard shared with `other`.
    ///
    /// This is used as part of our reload process when we don't own our state
    /// files, and we're reloading in order to find out what the other Arti
    /// instance thinks the guards are. At that point, `self` is the set of
    /// guards that we just loaded from state, and `other` is our old guards,
    /// which we are using only for their status information.
    pub(crate) fn copy_ephemeral_status_into_newly_loaded_state(&mut self, mut other: GuardSet) {
        let old_guards = std::mem::take(&mut self.guards);
        self.guards = old_guards
            .into_values()
            .map(|guard| {
                let id = guard.guard_id();

                if let Some(other_guard) = other.guards.remove_exact(id) {
                    guard.copy_ephemeral_status_into_newly_loaded_state(other_guard)
                } else {
                    guard
                }
            })
            .collect();
    }

    /// Return a serializable state object that can be stored to disk
    /// to capture the current state of this GuardSet.
    pub(super) fn get_state(&self) -> GuardSample<'_> {
        let guards = self
            .sample
            .iter()
            .map(|id| Cow::Borrowed(self.guards.by_all_ids(id).expect("Inconsistent state")))
            .collect();

        GuardSample {
            guards,
            confirmed: Cow::Borrowed(&self.confirmed),
            remaining: self.unknown_fields.clone(),
        }
    }

    /// Reconstruct a guard state from its serialized representation.
    pub(super) fn from_state(state: GuardSample<'_>) -> Self {
        let mut guards = ByRelayIds::new();
        let mut sample = Vec::new();
        for guard in state.guards {
            sample.push(guard.guard_id().clone());
            guards.insert(guard.into_owned());
        }
        let confirmed = state.confirmed.into_owned();
        let primary = Vec::new();
        let mut guard_set = GuardSet {
            guards,
            sample,
            confirmed,
            primary,
            active_filter: GuardFilter::default(),
            filter_is_restrictive: false,
            primary_guards_invalidated: true,
            unknown_fields: state.remaining,
        };

        // Fix any inconsistencies in the stored representation.
        let len_pre = guard_set.inner_lengths();
        guard_set.fix_consistency();
        let len_post = guard_set.inner_lengths();
        if len_pre != len_post {
            info!(
                "Resolved a consistency issue in stored guard state. Diagnostic codes: {:?}, {:?}",
                len_pre, len_post
            );
        }
        debug!(
            n_guards = len_post.0,
            n_confirmed = len_post.2,
            "Guard set loaded."
        );

        guard_set
    }

    /// Return `Ok(true)` if `id` is definitely a member of this set, and
    /// `Ok(false)` if it is definitely not a member.
    ///
    /// If we cannot tell, it's because there is a guard in this sample that has
    /// a _subset_ of the IDs in `id`. In that case, we return
    /// `Err(guard_ident)`, where `guard_ident`  is the identity of that guard.
    pub(crate) fn contains(&self, id: &GuardId) -> Result<bool, &GuardId> {
        let overlapping = self.guards.all_overlapping(id);
        match &overlapping[..] {
            [singleton] => {
                if singleton.has_all_relay_ids_from(id) {
                    Ok(true)
                } else {
                    Err(singleton.guard_id())
                }
            }
            _ => Ok(false),
        }
    }

    /// If there are not enough filter-permitted usable guards in this
    /// sample (according to the current active filter), then add
    /// more, up to the limits allowed by the parameters.
    ///
    /// This is the only function that adds new guards to the sample.
    ///
    /// Guards always start out un-confirmed.
    ///
    /// Return true if any guards were added.
    pub(crate) fn extend_sample_as_needed<U: Universe>(
        &mut self,
        now: SystemTime,
        params: &GuardParams,
        dir: &U,
    ) -> crate::ExtendedStatus {
        let mut any_added = crate::ExtendedStatus::No;
        while self.extend_sample_inner(now, params, dir) {
            any_added = crate::ExtendedStatus::Yes;
        }
        any_added
    }

    /// Implementation helper for extend_sample_as_needed.
    ///
    /// # Complications
    ///
    /// For spec conformance, we only consider our filter when selecting new
    /// guards if the filter is "very restrictive". That makes it possible that
    /// this function will add fewer filter-permitted guards than we had wanted.
    /// Because of that, this is a separate function, and
    /// extend_sample_as_needed runs it in a loop until it returns false.
    fn extend_sample_inner<U: Universe>(
        &mut self,
        now: SystemTime,
        params: &GuardParams,
        dir: &U,
    ) -> bool {
        self.assert_consistency();
        let n_filtered_usable = self
            .guards
            .values()
            .filter(|g| {
                g.usable()
                    && self.active_filter.permits(*g)
                    && g.reachable() != Reachable::Unreachable
            })
            .count();
        if n_filtered_usable >= params.min_filtered_sample_size {
            return false; // We have enough usage guards in our sample.
        }
        if self.guards.len() >= params.max_sample_size {
            return false; // We can't add any more guards to our sample.
        }

        // What are the most guards we're willing to have in the sample?
        let max_to_add = params.max_sample_size - self.sample.len();
        let want_to_add = params.min_filtered_sample_size - n_filtered_usable;
        let n_to_add = std::cmp::min(max_to_add, want_to_add);

        let WeightThreshold {
            mut current_weight,
            maximum_weight,
        } = dir.weight_threshold(&self.guards, params);

        // Ask the netdir for a set of guards we could use.
        let no_filter = GuardFilter::unfiltered();
        let (n_candidates, pre_filter) =
            if self.filter_is_restrictive || self.active_filter.is_unfiltered() {
                (n_to_add, &self.active_filter)
            } else {
                // The filter will probably reject a bunch of guards, but we sample
                // before filtering, so we make this larger on an ad-hoc basis.
                (n_to_add * 3, &no_filter)
            };

        let candidates = dir.sample(&self.guards, pre_filter, n_candidates);

        // Add those candidates to the sample.
        let mut any_added = false;
        let mut n_filtered_usable = n_filtered_usable;
        for (candidate, weight) in candidates {
            // Don't add any more if we have met the minimal sample size, and we
            // have added too much weight.
            if current_weight >= maximum_weight
                && self.guards.len() >= params.min_filtered_sample_size
            {
                break;
            }
            if self.guards.len() >= params.max_sample_size {
                // Can't add any more.
                break;
            }
            if n_filtered_usable >= params.min_filtered_sample_size {
                // We've reached our target; no need to add more.
                break;
            }
            if self.active_filter.permits(&candidate.owned_target) {
                n_filtered_usable += 1;
            }
            current_weight += weight;
            self.add_guard(candidate, now, params);
            any_added = true;
        }
        self.assert_consistency();
        any_added
    }

    /// Add `relay` as a new guard.
    ///
    /// Does nothing if it is already a guard.
    fn add_guard(&mut self, relay: Candidate, now: SystemTime, params: &GuardParams) {
        let id = GuardId::from_relay_ids(&relay.owned_target);
        if self.guards.by_all_ids(&id).is_some() {
            return;
        }
        debug!(guard_id=?id, "Adding guard to sample.");
        let guard = Guard::from_candidate(relay, now, params);
        self.guards.insert(guard);
        self.sample.push(id);
        self.primary_guards_invalidated = true;
    }

    /// Return the number of our primary guards that are missing directory
    /// information in `universe`.
    ///
    /// Note that "missing directory information" is not the same as "absent":
    /// in this case, we  are counting the primary guards where we cannot tell
    /// whether they appear in the universe or not because we have not yet
    /// downloaded their descriptors.
    pub(crate) fn n_primary_without_id_info_in<U: Universe>(&mut self, universe: &U) -> usize {
        self.primary
            .iter()
            .filter(|id| {
                let g = self
                    .guards
                    .by_all_ids(*id)
                    .expect("Inconsistent guard state");
                g.listed_in(universe).is_none()
            })
            .count()
    }

    /// Update the status of every guard  in this sample from a given source.
    pub(crate) fn update_status_from_dir<U: Universe>(&mut self, dir: &U) {
        let old_guards = std::mem::take(&mut self.guards);
        self.guards = old_guards
            .into_values()
            .map(|mut guard| {
                guard.update_from_universe(dir);
                guard
            })
            .collect();
        // Call "fix consistency", in case any guards got a new ID.
        self.fix_consistency();
    }

    /// tor-socks5 local patch: return true iff at least one guard in this set is
    /// listed, enabled, potentially reachable, permitted by the active filter,
    /// and has complete directory information — i.e. we have at least one guard
    /// through which we can actually build multi-hop data circuits right now.
    ///
    /// This is the aggregate published via `GuardMgr::usable_guard_events` and
    /// required by arti-client's `BootstrapStatus::ready_for_traffic()`, so that
    /// the client no longer reports "ready for traffic" once the directory is
    /// bootstrapped while every guard still lacks a usable descriptor.
    pub(crate) fn any_guard_usable_for_traffic(&self) -> bool {
        self.preference_order().any(|(_, g)| {
            g.usable()
                && g.reachable() != Reachable::Unreachable
                && self.active_filter.permits(g)
                && g.has_complete_dir_info()
        })
    }

    /// tor-socks5 local patch: test-only helper that sets `dir_info_missing` on
    /// every guard in the set, to drive the aggregated guard-usable signal
    /// (`any_guard_usable_for_traffic`) without standing up a NetDir that omits
    /// microdescriptors. Mirrors the `mem::take`/`into_values`/`collect` pattern
    /// used by `update_status_from_dir`.
    #[cfg(test)]
    pub(crate) fn set_all_guards_dir_info_missing_for_test(&mut self, missing: bool) {
        let old = std::mem::take(&mut self.guards);
        self.guards = old
            .into_values()
            .map(|mut g| {
                g.set_dir_info_missing_for_test(missing);
                g
            })
            .collect();
    }

    /// tor-socks5 local patch: test-only helper that sets `dir_info_missing`
    /// on the single guard matching `id`, leaving every other guard
    /// untouched. Used to reproduce the narrow-vs-wide oscillation fix in
    /// [`Self::descriptors_to_request`]: exactly one guard outside the
    /// conservative top-`maximum` cutoff regains a descriptor, and the fix
    /// must keep requesting it on every subsequent (narrow) call instead of
    /// letting `tor_dirmgr::bridgedesc::set_bridges` forget it again.
    #[cfg(test)]
    pub(crate) fn set_guard_dir_info_missing_for_test(&mut self, id: &GuardId, missing: bool) {
        let old = std::mem::take(&mut self.guards);
        self.guards = old
            .into_values()
            .map(|mut g| {
                if g.guard_id() == id {
                    g.set_dir_info_missing_for_test(missing);
                }
                g
            })
            .collect();
    }

    /// tor-socks5 local patch: test-only accessor returning the number of
    /// guards currently in the sample, used by regression tests to confirm a
    /// guard was actually sampled before asserting on error variants.
    #[cfg(test)]
    pub(crate) fn n_sampled_for_test(&self) -> usize {
        self.guards.len()
    }

    /// Re-build the list of primary guards.
    ///
    /// Primary guards are chosen according to preference order over all
    /// the guards in the set, restricted by the current filter.
    ///
    /// TODO: Enumerate all the times when this function needs to be called.
    ///
    /// TODO: Make sure this is called enough.
    pub(crate) fn select_primary_guards(&mut self, params: &GuardParams) {
        // TODO-SPEC: This is not 100% what the spec says, but it does match what
        // Tor does.  We pick first from the confirmed guards,
        // then from any previous primary guards, and then from maybe-reachable
        // guards in the sample.

        // Only for logging.
        let old_primary = self.primary.clone();

        self.primary = self
            // First, we look at the confirmed guards.
            .confirmed
            .iter()
            // Then we consider existing primary guards.
            .chain(self.primary.iter())
            // Finally, we look at the rest of the sample for guards not marked
            // as "unreachable".
            .chain(self.reachable_sample_ids())
            // We only consider each guard the first time it appears.
            .unique()
            // We only consider usable guards that the filter allows.
            .filter_map(|id| {
                let g = self
                    .guards
                    .by_all_ids(id)
                    .expect("Inconsistent guard state");
                if g.usable() && self.active_filter.permits(g) {
                    Some(id.clone())
                } else {
                    None
                }
            })
            // The first n_primary guards on that list are primary!
            .take(params.n_primary)
            .collect();

        if self.primary != old_primary {
            debug!(old=?old_primary, new=?self.primary, "Updated primary guards.");
        }

        // Clear exploratory_circ_pending for all primary guards.
        for id in &self.primary {
            self.guards.modify_by_all_ids(id, |guard| {
                guard.note_exploratory_circ(false);
            });
        }

        // TODO: Recalculate retry times, perhaps, since we may have changed
        // the timeouts?

        self.assert_consistency();
        self.primary_guards_invalidated = false;
    }

    /// Remove all guards which should expire `now`, according to the settings
    /// in `params`.
    pub(crate) fn expire_old_guards(&mut self, params: &GuardParams, now: SystemTime) {
        self.assert_consistency();
        let n_pre = self.guards.len();
        self.guards.retain(|g| !g.is_expired(params, now));
        let guards = &self.guards;
        self.sample.retain(|id| guards.by_all_ids(id).is_some());
        self.confirmed.retain(|id| guards.by_all_ids(id).is_some());
        self.primary.retain(|id| guards.by_all_ids(id).is_some());
        self.assert_consistency();

        if self.guards.len() < n_pre {
            let n_expired = n_pre - self.guards.len();
            debug!(n_expired, "Expired guards as too old.");
            self.primary_guards_invalidated = true;
        }
    }

    /// Return an iterator over the Id for every Guard in the sample that
    /// is not known to be Unreachable.
    fn reachable_sample_ids(&self) -> impl Iterator<Item = &GuardId> {
        self.sample.iter().filter(move |id| {
            let g = self
                .guards
                .by_all_ids(*id)
                .expect("Inconsistent guard state");
            g.reachable() != Reachable::Unreachable
        })
    }

    /// Return an iterator that yields an element for every guard in
    /// this set, in preference order.
    ///
    /// Each element contains a `ListKind` that describes which list the
    /// guard was in, and a `&GuardId` that identifies the guard.
    ///
    /// Note that this function will return guards that are not
    /// accepted by the current active filter: the caller must apply
    /// that filter if appropriate.
    fn preference_order_ids(&self) -> impl Iterator<Item = (ListKind, &GuardId)> {
        self.primary
            .iter()
            .map(|id| (ListKind::Primary, id))
            .chain(self.confirmed.iter().map(|id| (ListKind::Confirmed, id)))
            .chain(self.sample.iter().map(|id| (ListKind::Sample, id)))
            .unique_by(|(_, id)| *id)
    }

    /// Like `preference_order_ids`, but yields `&Guard` instead of `&GuardId`.
    fn preference_order(&self) -> impl Iterator<Item = (ListKind, &Guard)> + '_ {
        self.preference_order_ids()
            .filter_map(move |(p, id)| self.guards.by_all_ids(id).map(|g| (p, g)))
    }

    /// Return true if `guard_id` is an identity subset for any primary guard in this set.
    fn guard_is_primary(&self, guard_id: &GuardId) -> bool {
        // (This could be yes/no/maybe.)

        // This is O(n), but the list is short.
        self.primary
            .iter()
            .any(|p| p.has_all_relay_ids_from(guard_id))
    }

    /// For every guard that has been marked as `Unreachable` for too long,
    /// mark it as `Unknown`.
    pub(crate) fn consider_all_retries(&mut self, now: Instant) {
        let old_guards = std::mem::take(&mut self.guards);
        self.guards = old_guards
            .into_values()
            .map(|mut guard| {
                guard.consider_retry(now);
                guard
            })
            .collect();
    }

    /// Return the earliest time at which any guard will be retriable.
    pub(crate) fn next_retry(&self, usage: &GuardUsage) -> Option<Instant> {
        self.guards
            .values()
            .filter_map(|g| g.next_retry(usage))
            .min()
    }

    /// Mark every `Unreachable` primary guard as `Unknown`.
    pub(crate) fn mark_primary_guards_retriable(&mut self) {
        for id in &self.primary {
            self.guards
                .modify_by_all_ids(id, |guard| guard.mark_retriable());
        }
    }

    /// Return true if all of our primary guards are currently marked
    /// unreachable.
    pub(crate) fn all_primary_guards_are_unreachable(&mut self) -> bool {
        self.primary
            .iter()
            .flat_map(|id| self.guards.by_all_ids(id))
            .all(|g| g.reachable() == Reachable::Unreachable)
    }

    /// Mark every `Unreachable` guard as `Unknown`.
    pub(crate) fn mark_all_guards_retriable(&mut self) {
        let old_guards = std::mem::take(&mut self.guards);
        self.guards = old_guards
            .into_values()
            .map(|mut guard| {
                guard.mark_retriable();
                guard
            })
            .collect();
    }

    /// Whether the known guard is disabled by guard security policy.
    pub(crate) fn guard_is_disabled(&self, id: &GuardId) -> bool {
        self.guards.by_all_ids(id).is_some_and(Guard::is_disabled)
    }

    /// Retry explicitly re-enabled bridges without clearing failure history.
    #[cfg(feature = "bridge-client")]
    pub(crate) fn retry_reenabled_bridges<'a>(
        &mut self,
        bridges: impl IntoIterator<Item = &'a crate::bridge::BridgeConfig>,
    ) {
        for bridge in bridges {
            self.guards
                .modify_by_all_ids(bridge, |guard| guard.mark_retriable());
        }
    }

    /// tor-socks5 local patch: re-enable every guard that is currently
    /// `disabled` (clearing its `disabled` state and resetting the
    /// indeterminate-failure history that led to the disable), returning the
    /// number of guards that were re-enabled.
    ///
    /// Guards that are not disabled are left untouched (their observed history
    /// is never wiped). See `Guard::reset_disabled` for the per-guard semantics
    /// and rationale.
    pub(crate) fn reset_disabled_guards(&mut self) -> usize {
        let old_guards = std::mem::take(&mut self.guards);
        let mut n_reset = 0_usize;
        self.guards = old_guards
            .into_values()
            .map(|mut guard| {
                if guard.reset_disabled() {
                    n_reset += 1;
                }
                guard
            })
            .collect();
        n_reset
    }

    /// Record that an attempt has begun to use the guard with
    /// `guard_id`.
    pub(crate) fn record_attempt(&mut self, guard_id: &GuardId, now: Instant) {
        let is_primary = self.guard_is_primary(guard_id);
        self.guards.modify_by_all_ids(guard_id, |guard| {
            guard.record_attempt(now);

            if !is_primary {
                guard.note_exploratory_circ(true);
            }
        });
    }

    /// Record that an attempt to use the guard with `guard_id` has just
    /// succeeded.
    ///
    /// If `how` is provided, it's an operation from outside the crate that the
    /// guard succeeded at doing.
    pub(crate) fn record_success(
        &mut self,
        guard_id: &GuardId,
        params: &GuardParams,
        how: Option<ExternalActivity>,
        now: SystemTime,
    ) {
        self.assert_consistency();
        self.guards.modify_by_all_ids(guard_id, |guard| match how {
            Some(external) => guard.record_external_success(external),
            None => {
                let newly_confirmed = guard.record_success(now, params);

                if newly_confirmed == NewlyConfirmed::Yes {
                    self.confirmed.push(guard_id.clone());
                    self.primary_guards_invalidated = true;
                }
            }
        });
        self.assert_consistency();
    }

    /// Record that an attempt to use the guard with `guard_id` has just failed.
    ///
    pub(crate) fn record_failure(
        &mut self,
        guard_id: &GuardId,
        how: Option<ExternalActivity>,
        now: Instant,
    ) {
        // TODO use instant uniformly for in-process, and systemtime for storage?
        let is_primary = self.guard_is_primary(guard_id);
        self.guards.modify_by_all_ids(guard_id, |guard| match how {
            Some(external) => guard.record_external_failure(external, now),
            None => guard.record_failure(now, is_primary),
        });
    }

    /// Record that an attempt to use the guard with `guard_id` has
    /// just been abandoned, without learning whether it succeeded or failed.
    pub(crate) fn record_attempt_abandoned(&mut self, guard_id: &GuardId) {
        self.guards
            .modify_by_all_ids(guard_id, |guard| guard.note_exploratory_circ(false));
    }

    /// Record that an attempt to use the guard with `guard_id` has
    /// just failed in a way that we could not definitively attribute to
    /// the guard.
    pub(crate) fn record_indeterminate_result(&mut self, guard_id: &GuardId) {
        self.guards.modify_by_all_ids(guard_id, |guard| {
            guard.note_exploratory_circ(false);
            guard.record_indeterminate_result();
        });
    }

    /// Record that a given guard has told us about clock skew.
    pub(crate) fn record_skew(&mut self, guard_id: &GuardId, observation: SkewObservation) {
        self.guards
            .modify_by_all_ids(guard_id, |guard| guard.note_skew(observation));
    }

    /// Return an iterator over all stored clock skew observations.
    pub(crate) fn skew_observations(&self) -> impl Iterator<Item = &SkewObservation> {
        self.guards.values().filter_map(|g| g.skew())
    }

    /// Return whether the circuit manager can be allowed to use a
    /// circuit with the `guard_id`.
    ///
    /// Return `Some(bool)` if the circuit is usable, and `None` if we
    /// cannot yet be sure.
    pub(crate) fn circ_usability_status(
        &self,
        guard_id: &GuardId,
        usage: &GuardUsage,
        params: &GuardParams,
        now: Instant,
    ) -> Option<bool> {
        // TODO-SPEC: This isn't what the spec says.  The spec is phrased
        // in terms of circuits blocking circuits, whereas this algorithm is
        // about guards blocking guards.
        //
        // Also notably, the spec also says:
        //
        // * Among guards that do not appear in {CONFIRMED_GUARDS},
        // {is_pending}==true guards have higher priority.
        // * Among those, the guard with earlier {last_tried_connect} time
        // has higher priority.
        // * Finally, among guards that do not appear in
        // {CONFIRMED_GUARDS} with {is_pending==false}, all have equal
        // priority.
        //
        // I believe this approach is fine too, but we ought to document it.

        if self.guard_is_primary(guard_id) {
            // Circuits built to primary guards are always usable immediately.
            //
            // This has to be a special case, since earlier primary guards
            // don't block later ones.
            return Some(true);
        }

        // Assuming that the guard is _not_ primary, then the rule is
        // fairly simple: we can use the guard if all the guards we'd
        // _rather_ use are either down, or have had their circuit
        // attempts pending for too long.

        let cutoff = now
            .checked_sub(params.np_connect_timeout)
            .expect("Can't subtract connect timeout from now.");

        for (src, guard) in self.preference_order() {
            if guard.guard_id() == guard_id {
                return Some(true);
            }
            if guard.usable() && self.active_filter.permits(guard) && guard.conforms_to_usage(usage)
            {
                match (src, guard.reachable()) {
                    (_, Reachable::Reachable) => return Some(false),
                    (_, Reachable::Unreachable) => (),
                    (ListKind::Primary, Reachable::Untried | Reachable::Retriable) => {
                        return Some(false);
                    }
                    (_, Reachable::Untried | Reachable::Retriable) => {
                        if guard.exploratory_attempt_after(cutoff) {
                            return None;
                        }
                    }
                }
            }
        }

        // This guard is not even listed.
        Some(false)
    }

    /// Try to select a guard for a given `usage`.
    ///
    /// On success, returns the kind of guard that we got, and its filtered
    /// representation in a form suitable for use as a first hop.
    ///
    /// Label the returned guard as having come from `sample_id`.
    //
    // NOTE (nickm): I wish that we didn't have to take sample_id as an input,
    // but the alternative would be storing it as a member of `GuardSet`, which
    // makes things very complicated.
    pub(crate) fn pick_guard(
        &self,
        sample_id: &GuardSetSelector,
        usage: &GuardUsage,
        params: &GuardParams,
        now: Instant,
    ) -> Result<(ListKind, FirstHop), PickGuardError> {
        let (list_kind, id) = self.pick_guard_id(usage, params, now)?;
        let first_hop = self
            .get(&id)
            .expect("Somehow selected a guard we don't know!")
            .get_external_rep(sample_id.clone());
        let first_hop = self.active_filter.modify_hop(first_hop)?;

        Ok((list_kind, first_hop))
    }

    /// Try to select a guard for a given `usage`.
    ///
    /// On success, returns the kind of guard that we got, and its identity.
    fn pick_guard_id(
        &self,
        usage: &GuardUsage,
        params: &GuardParams,
        now: Instant,
    ) -> Result<(ListKind, GuardId), PickGuardError> {
        debug_assert!(!self.primary_guards_invalidated);
        let n_options = match usage.kind {
            GuardUsageKind::OneHopDirectory => params.dir_parallelism,
            GuardUsageKind::Data => params.data_parallelism,
        };

        // Counts of how many elements were rejected by which of the filters
        // below.
        //
        // Note that since we use `Iterator::take`, these counts won't cover the
        // whole guard sample on the successful case: only in the failing case,
        // when we fail to find any candidates.
        let mut running = FilterCount::default();
        let mut pending = FilterCount::default();
        let mut suitable = FilterCount::default();
        let mut filtered = FilterCount::default();

        let mut options: Vec<_> = self
            .preference_order()
            // Discard the guards that are down or unusable, and see if any
            // are left.
            .filter_cnt(&mut running, |(_, g)| {
                g.usable()
                    && g.reachable() != Reachable::Unreachable
                    && g.ready_for_usage(usage, now)
            })
            // Now remove those that are excluded because we're already trying
            // them on an exploratory basis.
            .filter_cnt(&mut pending, |(_, g)| !g.exploratory_circ_pending())
            // ...or because they don't support the operation we're
            // attempting...
            .filter_cnt(&mut suitable, |(_, g)| g.conforms_to_usage(usage))
            // ... or because we specifically filtered them out.
            .filter_cnt(&mut filtered, |(_, g)| self.active_filter.permits(*g))
            // We only consider the first n_options such guards.
            .take(n_options)
            .collect();

        if options.iter().any(|(src, _)| src.is_primary()) {
            // If there are any primary guards, we only consider those.
            options.retain(|(src, _)| src.is_primary());
        } else {
            // If there are no primary guards, parallelism doesn't apply.
            options.truncate(1);
        }

        match options.choose(&mut rand::rng()) {
            Some((src, g)) => Ok((*src, g.guard_id().clone())),
            None => {
                let retry_at = if running.n_accepted == 0 {
                    self.next_retry(usage)
                } else {
                    None
                };
                Err(PickGuardError::AllGuardsDown {
                    retry_at,
                    running,
                    pending,
                    suitable,
                    filtered,
                })
            }
        }
    }

    /// Return the guards whose bridge descriptors we should request, given our
    /// current configuration and status.
    ///
    /// (The output of this function is not reasonable unless this is a Bridge
    /// sample.)
    #[cfg(feature = "bridge-client")]
    pub(crate) fn descriptors_to_request(
        &self,
        now: Instant,
        params: &GuardParams,
        is_configured: impl Fn(&Guard) -> bool,
    ) -> Vec<&Guard> {
        /// This constant is here to improve our odds that we can get a working
        /// bridge if we have any per-circuit filters that would prevent us from
        /// using our preferred bridge.
        const MINIMUM: usize = 2;

        let maximum = std::cmp::max(params.data_parallelism, MINIMUM);
        let data_usage = GuardUsage::default();

        // A re-enabled bridge can remain unlisted until its descriptor confirms
        // previously learned identities. It still needs a descriptor request.
        // Data selection remains subject to the stricter usable() check.
        let eligible: Vec<&Guard> = self
            .preference_order()
            .filter(|(_, g)| {
                !g.is_disabled()
                    && is_configured(g)
                    && g.reachable() != Reachable::Unreachable
                    && g.ready_for_usage(&data_usage, now)
                    && self.active_filter.permits(*g)
            })
            .map(|(_, g)| g)
            .collect();

        // An inactive guard's cached descriptor cannot support recovery.
        // BridgeDescMgr still bounds concurrent downloads and retry frequency.
        let take_n = if eligible
            .iter()
            .any(|g| g.usable() && g.has_complete_dir_info())
        {
            maximum
        } else {
            usize::MAX
        };

        if take_n >= eligible.len() {
            return eligible;
        }
        let mut selected = eligible[..take_n].to_vec();

        // Retain a usable descriptor outside the cutoff, avoiding a repeated
        // download/forget cycle when the request set narrows after recovery.
        if !selected
            .iter()
            .any(|g| g.usable() && g.has_complete_dir_info())
        {
            if let Some(extra) = eligible[take_n..]
                .iter()
                .find(|g| g.usable() && g.has_complete_dir_info())
            {
                selected.push(extra);
            }
        }
        selected
    }
}
