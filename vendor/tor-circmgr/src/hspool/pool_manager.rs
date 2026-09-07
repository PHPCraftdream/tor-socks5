use super::*;

impl<B: AbstractTunnelBuilder<R> + 'static, R: Runtime> HsCircPoolInner<B, R> {
    /// Create a new [`HsCircPoolInner`] from a [`CircMgrInner`].
    pub(crate) fn new_internal(circmgr: &Arc<CircMgrInner<B, R>>) -> Self {
        let circmgr = Arc::clone(circmgr);
        let pool = pool::Pool::default();
        Self {
            circmgr,
            launcher_handle: OnceCell::new(),
            inner: Mutex::new(Inner { pool }),
        }
    }

    /// Internal implementation for [`HsCircPool::launch_background_tasks`].
    #[instrument(level = "trace", skip_all)]
    pub(crate) fn launch_background_tasks(
        self: &Arc<Self>,
        runtime: &R,
        netdir_provider: &Arc<dyn NetDirProvider + 'static>,
    ) -> Result<Vec<TaskHandle>> {
        let handle = self.launcher_handle.get_or_try_init(|| {
            runtime
                .spawn(remove_unusable_circuits(
                    Arc::downgrade(self),
                    Arc::downgrade(netdir_provider),
                ))
                .map_err(|e| Error::from_spawn("preemptive onion circuit expiration task", e))?;

            let (schedule, handle) = TaskSchedule::new(runtime.clone());
            runtime
                .spawn(launch_hs_circuits_as_needed(
                    Arc::downgrade(self),
                    Arc::downgrade(netdir_provider),
                    schedule,
                ))
                .map_err(|e| Error::from_spawn("preemptive onion circuit builder task", e))?;

            Result::<TaskHandle>::Ok(handle)
        })?;

        Ok(vec![handle.clone()])
    }

    /// Internal implementation for [`HsCircPool::get_or_launch_client_rend`].
    #[instrument(level = "trace", skip_all)]
    pub(crate) async fn get_or_launch_client_rend<'a>(
        &self,
        netdir: &'a NetDir,
    ) -> Result<(B::Tunnel, Relay<'a>)> {
        // For rendezvous points, clients use 3-hop circuits.
        // Note that we aren't using any special rules for the last hop here; we
        // are relying on the fact that:
        //   * all suitable middle relays that we use in these circuit stems are
        //     suitable renedezvous points, and
        //   * the weighting rules for selecting rendezvous points are the same
        //     as those for selecting an arbitrary middle relay.
        let circ = self
            .take_or_launch_stem_circuit::<OwnedCircTarget>(netdir, None, HsCircKind::ClientRend)
            .await?;

        #[cfg(all(feature = "vanguards", feature = "hs-common"))]
        if matches!(
            self.vanguard_mode(),
            VanguardMode::Full | VanguardMode::Lite
        ) && circ.kind != HsCircStemKind::Guarded
        {
            return Err(internal!("wanted a GUARDED circuit, but got NAIVE?!").into());
        }

        let path = circ.single_path().map_err(|error| Error::Protocol {
            action: "launching a client rend circuit",
            peer: None, // Either party could be to blame.
            unique_id: Some(circ.unique_id()),
            error,
        })?;

        match path.hops().last() {
            Some(ent) => {
                let Some(ct) = ent.as_chan_target() else {
                    return Err(
                        internal!("HsPool gave us a circuit with a virtual last hop!?").into(),
                    );
                };
                match netdir.by_ids(ct) {
                    Some(relay) => Ok((circ.circ, relay)),
                    // This can't happen, since launch_hs_unmanaged() only takes relays from the netdir
                    // it is given, and circuit_compatible_with_target() ensures that
                    // every relay in the circuit is listed.
                    //
                    // TODO: Still, it's an ugly place in our API; maybe we should return the last hop
                    // from take_or_launch_stem_circuit()?  But in many cases it won't be needed...
                    None => Err(internal!("Got circuit with unknown last hop!?").into()),
                }
            }
            None => Err(internal!("Circuit with an empty path!?").into()),
        }
    }

    /// Helper for the [`HsCircPool`] functions that launch rendezvous,
    /// introduction, or directory circuits.
    #[instrument(level = "trace", skip_all)]
    pub(crate) async fn get_or_launch_specific<T>(
        &self,
        netdir: &NetDir,
        kind: HsCircKind,
        target: T,
    ) -> Result<B::Tunnel>
    where
        T: CircTarget + Sync,
    {
        if kind == HsCircKind::ClientRend {
            return Err(bad_api_usage!("get_or_launch_specific with ClientRend circuit!?").into());
        }

        let wanted_kind = kind.stem_kind();

        // For most* of these circuit types, we want to build our circuit with
        // an extra hop, since the target hop is under somebody else's control.
        //
        // * The exceptions are ClientRend, which we handle in a different
        //   method, and SvcIntro, where we will eventually  want an extra hop
        //   to avoid vanguard discovery attacks.

        // Get an unfinished circuit that's compatible with our target.
        let circ = self
            .take_or_launch_stem_circuit(netdir, Some(&target), kind)
            .await?;

        #[cfg(all(feature = "vanguards", feature = "hs-common"))]
        if matches!(
            self.vanguard_mode(),
            VanguardMode::Full | VanguardMode::Lite
        ) && circ.kind != wanted_kind
        {
            return Err(internal!(
                "take_or_launch_stem_circuit() returned {:?}, but we need {wanted_kind:?}",
                circ.kind
            )
            .into());
        }

        let mut params = onion_circparams_from_netparams(netdir.params())?;

        // If this is a HsDir circuit, establish a limit on the number of incoming cells from
        // the last hop.
        params.n_incoming_cells_permitted = match kind {
            HsCircKind::ClientHsDir => Some(netdir.params().hsdir_dl_max_reply_cells.into()),
            HsCircKind::SvcHsDir => Some(netdir.params().hsdir_ul_max_reply_cells.into()),
            HsCircKind::SvcIntro
            | HsCircKind::SvcRend
            | HsCircKind::ClientIntro
            | HsCircKind::ClientRend => None,
        };
        self.extend_circ(circ, params, target).await
    }

    /// Try to extend a circuit to the specified target hop.
    async fn extend_circ<T>(
        &self,
        circ: HsCircStem<B::Tunnel>,
        params: CircParameters,
        target: T,
    ) -> Result<B::Tunnel>
    where
        T: CircTarget + Sync,
    {
        let protocol_err = |error| Error::Protocol {
            action: "extending to chosen HS hop",
            peer: None, // Either party could be to blame.
            unique_id: Some(circ.unique_id()),
            error,
        };

        // Estimate how long it will take to extend it one more hop, and
        // construct a timeout as appropriate.
        let n_hops = circ.n_hops().map_err(protocol_err)?;
        let (extend_timeout, _) = self.circmgr.mgr.peek_builder().estimator().timeouts(
            &crate::timeouts::Action::ExtendCircuit {
                initial_length: n_hops,
                final_length: n_hops + 1,
            },
        );

        // Make a future to extend the circuit.
        let extend_future = circ.extend(&target, params).map_err(protocol_err);

        // Wait up to the timeout for the future to complete.
        self.circmgr
            .mgr
            .peek_runtime()
            .timeout(extend_timeout, extend_future)
            .await
            .map_err(|_| Error::CircTimeout(Some(circ.unique_id())))??;

        // With any luck, return the circuit.
        Ok(circ.circ)
    }

    /// Internal implementation for [`HsCircPool::retire_all_circuits`].
    pub(crate) fn retire_all_circuits(&self) -> StdResult<(), tor_config::ReconfigureError> {
        self.inner
            .lock()
            .expect("poisoned lock")
            .pool
            .retire_all_circuits()?;

        Ok(())
    }

    /// Take and return a circuit from our pool suitable for being extended to `avoid_target`.
    ///
    /// If vanguards are enabled, this will try to build a circuit stem appropriate for use
    /// as the specified `kind`.
    ///
    /// If vanguards are disabled, `kind` is unused.
    ///
    /// If there is no such circuit, build and return a new one.
    #[instrument(level = "trace", skip_all)]
    async fn take_or_launch_stem_circuit<T>(
        &self,
        netdir: &NetDir,
        avoid_target: Option<&T>,
        kind: HsCircKind,
    ) -> Result<HsCircStem<B::Tunnel>>
    where
        // TODO #504: It would be better if this were a type that had to include
        // family info.
        T: CircTarget + Sync,
    {
        let stem_kind = kind.stem_kind();
        let vanguard_mode = self.vanguard_mode();
        trace!(
            vanguards=%vanguard_mode,
            kind=%stem_kind,
            "selecting HS circuit stem"
        );

        // First, look for a circuit that is already built, if any is suitable.

        let target_exclusion = {
            let path_cfg = self.circmgr.builder().path_config();
            let cfg = path_cfg.relay_selection_config();
            match avoid_target {
                // TODO #504: This is an unaccompanied RelayExclusion, and is therefore a
                // bit suspect.  We should consider whether we like this behavior.
                Some(ct) => RelayExclusion::exclude_channel_target_family(&cfg, ct, netdir),
                None => RelayExclusion::no_relays_excluded(),
            }
        };

        let found_usable_circ = {
            let mut inner = self.inner.lock().expect("lock poisoned");

            let restrictions = |circ: &HsCircStem<B::Tunnel>| {
                // If vanguards are enabled, we no longer apply same-family or same-subnet
                // restrictions, and we allow the guard to appear as either of the last
                // two hope of the circuit.
                match vanguard_mode {
                    #[cfg(all(feature = "vanguards", feature = "hs-common"))]
                    VanguardMode::Lite | VanguardMode::Full => {
                        vanguards_circuit_compatible_with_target(
                            netdir,
                            circ,
                            stem_kind,
                            kind,
                            avoid_target,
                        )
                    }
                    VanguardMode::Disabled => {
                        circuit_compatible_with_target(netdir, circ, kind, &target_exclusion)
                    }
                    _ => {
                        warn!("unknown vanguard mode {vanguard_mode}");
                        false
                    }
                }
            };

            let mut prefs = HsCircPrefs::default();

            #[cfg(all(feature = "vanguards", feature = "hs-common"))]
            if matches!(vanguard_mode, VanguardMode::Full | VanguardMode::Lite) {
                prefs.preferred_stem_kind(stem_kind);
            }

            let found_usable_circ =
                inner
                    .pool
                    .take_one_where(&mut rand::rng(), restrictions, &prefs);

            // Tell the background task to fire immediately if we have very few circuits
            // circuits left, or if we found nothing.
            if inner.pool.very_low() || found_usable_circ.is_none() {
                let handle = self.launcher_handle.get().ok_or_else(|| {
                    Error::from(bad_api_usage!("The circuit launcher wasn't initialized"))
                })?;
                handle.fire();
            }
            found_usable_circ
        };
        // Return the circuit we found before, if any.
        if let Some(circuit) = found_usable_circ {
            let circuit = self
                .maybe_extend_stem_circuit(netdir, circuit, avoid_target, stem_kind, kind)
                .await?;
            self.ensure_suitable_circuit(&circuit, avoid_target, stem_kind)?;
            return Ok(circuit);
        }

        // TODO: There is a possible optimization here. Instead of only waiting
        // for the circuit we launch below to finish, we could also wait for any
        // of our in-progress preemptive circuits to finish.  That would,
        // however, complexify our logic quite a bit.

        // TODO: We could in launch multiple circuits in parallel here?
        let circ = self
            .circmgr
            .launch_hs_unmanaged(avoid_target, netdir, stem_kind, Some(kind))
            .await?;

        self.ensure_suitable_circuit(&circ, avoid_target, stem_kind)?;

        Ok(HsCircStem {
            circ,
            kind: stem_kind,
        })
    }

    /// Return a circuit of the specified `kind`, built from `circuit`.
    #[cfg_attr(not(feature = "vanguards"), allow(clippy::unused_async))]
    async fn maybe_extend_stem_circuit<T>(
        &self,
        netdir: &NetDir,
        circuit: HsCircStem<B::Tunnel>,
        avoid_target: Option<&T>,
        stem_kind: HsCircStemKind,
        circ_kind: HsCircKind,
    ) -> Result<HsCircStem<B::Tunnel>>
    where
        T: CircTarget + Sync,
    {
        match self.vanguard_mode() {
            #[cfg(all(feature = "vanguards", feature = "hs-common"))]
            VanguardMode::Full => {
                // NAIVE circuit stems need to be extended by one hop to become GUARDED stems
                // if we're using full vanguards.
                self.extend_full_vanguards_circuit(
                    netdir,
                    circuit,
                    avoid_target,
                    stem_kind,
                    circ_kind,
                )
                .await
            }
            _ => {
                let HsCircStem { circ, kind: _ } = circuit;

                Ok(HsCircStem {
                    circ,
                    kind: stem_kind,
                })
            }
        }
    }

    /// Extend the specified full vanguard circuit if necessary.
    #[cfg(all(feature = "vanguards", feature = "hs-common"))]
    async fn extend_full_vanguards_circuit<T>(
        &self,
        netdir: &NetDir,
        circuit: HsCircStem<B::Tunnel>,
        avoid_target: Option<&T>,
        stem_kind: HsCircStemKind,
        circ_kind: HsCircKind,
    ) -> Result<HsCircStem<B::Tunnel>>
    where
        T: CircTarget + Sync,
    {
        use crate::path::hspath::hs_stem_terminal_hop_usage;
        use tor_relay_selection::RelaySelector;

        match (circuit.kind, stem_kind) {
            (HsCircStemKind::Naive, HsCircStemKind::Guarded) => {
                debug!("Wanted GUARDED circuit, but got NAIVE; extending by 1 hop...");
                let params = crate::build::onion_circparams_from_netparams(netdir.params())?;
                let circ_path = circuit
                    .circ
                    .single_path()
                    .map_err(|error| Error::Protocol {
                        action: "extending full vanguards circuit",
                        peer: None, // Either party could be to blame.
                        unique_id: Some(circuit.unique_id()),
                        error,
                    })?;

                // A NAIVE circuit is a 3-hop circuit.
                debug_assert_eq!(circ_path.hops().len(), 3);

                let target_exclusion = if let Some(target) = &avoid_target {
                    RelayExclusion::exclude_identities(
                        target.identities().map(|id| id.to_owned()).collect(),
                    )
                } else {
                    RelayExclusion::no_relays_excluded()
                };
                let selector = RelaySelector::new(
                    hs_stem_terminal_hop_usage(Some(circ_kind)),
                    target_exclusion,
                );
                let hops = circ_path
                    .iter()
                    .flat_map(|hop| hop.as_chan_target())
                    .map(IntoOwnedChanTarget::to_owned)
                    .collect::<Vec<OwnedChanTarget>>();

                let extra_hop =
                    select_middle_for_vanguard_circ(&hops, netdir, &selector, &mut rand::rng())?;

                // Since full vanguards are enabled and the circuit we got is NAIVE,
                // we need to extend it by another hop to make it GUARDED before returning it
                let circ = self.extend_circ(circuit, params, extra_hop).await?;

                Ok(HsCircStem {
                    circ,
                    kind: stem_kind,
                })
            }
            (HsCircStemKind::Guarded, HsCircStemKind::Naive) => {
                Err(internal!("wanted a NAIVE circuit, but got GUARDED?!").into())
            }
            _ => {
                trace!("Wanted {stem_kind} circuit, got {}", circuit.kind);
                // Nothing to do: the circuit stem we got is of the kind we wanted
                Ok(circuit)
            }
        }
    }

    /// Ensure `circ` is compatible with `target`, and has the correct length for its `kind`.
    fn ensure_suitable_circuit<T>(
        &self,
        circ: &B::Tunnel,
        target: Option<&T>,
        kind: HsCircStemKind,
    ) -> Result<()>
    where
        T: CircTarget + Sync,
    {
        Self::ensure_circuit_can_extend_to_target(circ, target)?;
        self.ensure_circuit_length_valid(circ, kind)?;

        Ok(())
    }

    /// Ensure the specified circuit of type `kind` has the right length.
    fn ensure_circuit_length_valid(&self, tunnel: &B::Tunnel, kind: HsCircStemKind) -> Result<()> {
        let circ_path_len = tunnel.n_hops().map_err(|error| Error::Protocol {
            action: "validating circuit length",
            peer: None, // Either party could be to blame.
            unique_id: Some(tunnel.unique_id()),
            error,
        })?;

        let mode = self.vanguard_mode();

        // TODO(#1457): somehow unify the path length checks
        let expected_len = kind.num_hops(mode)?;

        if circ_path_len != expected_len {
            return Err(internal!(
                "invalid path length for {} {mode}-vanguard circuit (expected {} hops, got {})",
                kind,
                expected_len,
                circ_path_len
            )
            .into());
        }

        Ok(())
    }

    /// Ensure that it is possible to extend `circ` to `target`.
    ///
    /// Returns an error if either of the last 2 hops of the circuit are the same as `target`,
    /// because:
    ///   * a relay won't let you extend the circuit to itself
    ///   * relays won't let you extend the circuit to their previous hop
    fn ensure_circuit_can_extend_to_target<T>(tunnel: &B::Tunnel, target: Option<&T>) -> Result<()>
    where
        T: CircTarget + Sync,
    {
        if let Some(target) = target {
            let take_n = 2;
            if let Some(hop) = tunnel
                .single_path()
                .map_err(|error| Error::Protocol {
                    action: "validating circuit compatibility with target",
                    peer: None, // Either party could be to blame.
                    unique_id: Some(tunnel.unique_id()),
                    error,
                })?
                .hops()
                .iter()
                .rev()
                .take(take_n)
                .flat_map(|hop| hop.as_chan_target())
                .find(|hop| hop.has_any_relay_id_from(target))
            {
                return Err(internal!(
                    "invalid path: circuit target {} appears as one of the last 2 hops (matches hop {})",
                    target.display_relay_ids(),
                    hop.display_relay_ids()
                ).into());
            }
        }

        Ok(())
    }

    /// Internal: Remove every closed circuit from this pool.
    pub(super) fn remove_closed(&self) {
        let mut inner = self.inner.lock().expect("lock poisoned");
        inner.pool.retain(|circ| !circ.is_closing());
    }

    /// Internal: Remove every circuit form this pool for which any relay is not
    /// listed in `netdir`.
    pub(super) fn remove_unlisted(&self, netdir: &NetDir) {
        let mut inner = self.inner.lock().expect("lock poisoned");
        inner
            .pool
            .retain(|circ| circuit_still_useable(netdir, circ, |_relay| true, |_last_hop| true));
    }

    /// Returns the current [`VanguardMode`].
    pub(super) fn vanguard_mode(&self) -> VanguardMode {
        cfg_if::cfg_if! {
            if #[cfg(all(feature = "vanguards", feature = "hs-common"))] {
                self
                    .circmgr
                    .mgr
                    .peek_builder()
                    .vanguardmgr()
                    .mode()
            } else {
                VanguardMode::Disabled
            }
        }
    }

    /// Internal implementation for [`HsCircPool::estimate_timeout`].
    pub(crate) fn estimate_timeout(
        &self,
        timeout_action: &timeouts::Action,
    ) -> std::time::Duration {
        self.circmgr.estimate_timeout(timeout_action)
    }
}
