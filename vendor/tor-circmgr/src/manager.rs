use super::*;

impl<B: AbstractTunnelBuilder<R> + 'static, R: Runtime> CircMgrInner<B, R> {
    /// Generic implementation for [`CircMgrInner::new`]
    pub(crate) fn new_generic<CFG: CircMgrConfig>(
        config: &CFG,
        runtime: &R,
        guardmgr: &tor_guardmgr::GuardMgr<R>,
        builder: B,
    ) -> Self {
        let preemptive = Arc::new(Mutex::new(PreemptiveCircuitPredictor::new(
            config.preemptive_circuits().clone(),
        )));

        guardmgr.set_filter(config.path_rules().build_guard_filter());

        let mgr =
            mgr::AbstractTunnelMgr::new(builder, runtime.clone(), config.circuit_timing().clone());

        CircMgrInner {
            mgr: Arc::new(mgr),
            predictor: preemptive,
        }
    }

    /// Launch the periodic daemon tasks required by the manager to function properly.
    ///
    /// Returns a set of [`TaskHandle`]s that can be used to manage the daemon tasks.
    //
    // NOTE(eta): The ?Sized on D is so we can pass a trait object in.
    #[instrument(level = "trace", skip_all)]
    pub(crate) fn launch_background_tasks<D, S>(
        self: &Arc<Self>,
        runtime: &R,
        dir_provider: &Arc<D>,
        state_mgr: S,
    ) -> Result<Vec<TaskHandle>>
    where
        D: NetDirProvider + 'static + ?Sized,
        S: StateMgr + std::marker::Send + 'static,
    {
        let mut ret = vec![];

        runtime
            .spawn(Self::keep_circmgr_params_updated(
                dir_provider.events(),
                Arc::downgrade(self),
                Arc::downgrade(dir_provider),
            ))
            .map_err(|e| Error::from_spawn("circmgr parameter updater", e))?;

        let (sched, handle) = TaskSchedule::new(runtime.clone());
        ret.push(handle);

        runtime
            .spawn(Self::update_persistent_state(
                sched,
                Arc::downgrade(self),
                state_mgr,
            ))
            .map_err(|e| Error::from_spawn("persistent state updater", e))?;

        let (sched, handle) = TaskSchedule::new(runtime.clone());
        ret.push(handle);

        runtime
            .spawn(Self::continually_launch_timeout_testing_circuits(
                sched,
                Arc::downgrade(self),
                Arc::downgrade(dir_provider),
            ))
            .map_err(|e| Error::from_spawn("timeout-probe circuit launcher", e))?;

        let (sched, handle) = TaskSchedule::new(runtime.clone());
        ret.push(handle);

        runtime
            .spawn(Self::continually_preemptively_build_circuits(
                sched,
                Arc::downgrade(self),
                Arc::downgrade(dir_provider),
            ))
            .map_err(|e| Error::from_spawn("preemptive circuit launcher", e))?;

        self.mgr
            .peek_builder()
            .guardmgr()
            .install_netdir_provider(&dir_provider.clone().upcast_arc())?;

        #[cfg(all(feature = "vanguards", feature = "hs-common"))]
        {
            let () = self
                .mgr
                .peek_builder()
                .vanguardmgr()
                .launch_background_tasks(&dir_provider.clone().upcast_arc())?;
        }

        Ok(ret)
    }

    /// Return a circuit suitable for sending one-hop BEGINDIR streams,
    /// launching it if necessary.
    #[instrument(level = "trace", skip_all)]
    pub(crate) async fn get_or_launch_dir(&self, netdir: DirInfo<'_>) -> Result<Arc<B::Tunnel>> {
        self.expire_circuits().await;
        let usage = TargetTunnelUsage::Dir;
        self.mgr.get_or_launch(&usage, netdir).await.map(|(c, _)| c)
    }

    /// Return a circuit suitable for exiting to all of the provided
    /// `ports`, launching it if necessary.
    ///
    /// If the list of ports is empty, then the chosen circuit will
    /// still end at _some_ exit.
    #[instrument(level = "trace", skip_all)]
    pub(crate) async fn get_or_launch_exit(
        &self,
        netdir: DirInfo<'_>, // TODO: This has to be a NetDir.
        ports: &[TargetPort],
        isolation: StreamIsolation,
        // TODO GEOIP: this cannot be stabilised like this, since Cargo features need to be
        //             additive. The function should be refactored to be builder-like.
        #[cfg(feature = "geoip")] country_code: Option<CountryCode>,
    ) -> Result<Arc<B::Tunnel>> {
        self.expire_circuits().await;
        let time = self.mgr.peek_runtime().now();
        {
            let mut predictive = self.predictor.lock().expect("preemptive lock poisoned");
            if ports.is_empty() {
                predictive.note_usage(None, time);
            } else {
                for port in ports.iter() {
                    predictive.note_usage(Some(*port), time);
                }
            }
        }
        let require_stability = ports.iter().any(|p| {
            self.mgr
                .peek_builder()
                .path_config()
                .long_lived_ports
                .contains(&p.port)
        });
        let ports = ports.iter().map(Clone::clone).collect();
        #[cfg(not(feature = "geoip"))]
        let country_code = None;
        let usage = TargetTunnelUsage::Exit {
            ports,
            isolation,
            country_code,
            require_stability,
        };
        self.mgr.get_or_launch(&usage, netdir).await.map(|(c, _)| c)
    }

    /// Return a circuit to a specific relay, suitable for using for direct
    /// (one-hop) directory downloads.
    ///
    /// This could be used, for example, to download a descriptor for a bridge.
    #[cfg(feature = "specific-relay")]
    #[instrument(level = "trace", skip_all)]
    pub(crate) async fn get_or_launch_dir_specific<T: IntoOwnedChanTarget>(
        &self,
        target: T,
    ) -> Result<Arc<B::Tunnel>> {
        self.expire_circuits().await;
        let usage = TargetTunnelUsage::DirSpecificTarget(target.to_owned());
        self.mgr
            .get_or_launch(&usage, DirInfo::Nothing)
            .await
            .map(|(c, _)| c)
    }

    /// Try to change our configuration settings to `new_config`.
    ///
    /// The actual behavior here will depend on the value of `how`.
    ///
    /// Returns whether any of the circuit pools should be cleared.
    #[instrument(level = "trace", skip_all)]
    pub(crate) fn reconfigure<CFG: CircMgrConfig>(
        &self,
        new_config: &CFG,
        how: tor_config::Reconfigure,
    ) -> std::result::Result<RetireCircuits, tor_config::ReconfigureError> {
        let old_path_rules = self.mgr.peek_builder().path_config();
        let predictor = self.predictor.lock().expect("poisoned lock");
        let preemptive_circuits = predictor.config();
        if preemptive_circuits.initial_predicted_ports
            != new_config.preemptive_circuits().initial_predicted_ports
        {
            // This change has no effect, since the list of ports was _initial_.
            how.cannot_change("preemptive_circuits.initial_predicted_ports")?;
        }

        if how == tor_config::Reconfigure::CheckAllOrNothing {
            return Ok(RetireCircuits::None);
        }

        let retire_because_of_guardmgr =
            self.mgr.peek_builder().guardmgr().reconfigure(new_config)?;

        #[cfg(all(feature = "vanguards", feature = "hs-common"))]
        let retire_because_of_vanguardmgr = self
            .mgr
            .peek_builder()
            .vanguardmgr()
            .reconfigure(new_config.vanguard_config())?;

        let new_reachable = &new_config.path_rules().reachable_addrs;
        if new_reachable != &old_path_rules.reachable_addrs {
            let filter = new_config.path_rules().build_guard_filter();
            self.mgr.peek_builder().guardmgr().set_filter(filter);
        }

        let discard_all_circuits = !new_config
            .path_rules()
            .at_least_as_permissive_as(&old_path_rules)
            || retire_because_of_guardmgr != tor_guardmgr::RetireCircuits::None;

        #[cfg(all(feature = "vanguards", feature = "hs-common"))]
        let discard_all_circuits = discard_all_circuits
            || retire_because_of_vanguardmgr != tor_guardmgr::RetireCircuits::None;

        self.mgr
            .peek_builder()
            .set_path_config(new_config.path_rules().clone());
        self.mgr
            .set_circuit_timing(new_config.circuit_timing().clone());
        predictor.set_config(new_config.preemptive_circuits().clone());

        if discard_all_circuits {
            // TODO(nickm): Someday, we might want to take a more lenient approach, and only
            // retire those circuits that do not conform to the new path rules,
            // or do not conform to the new guard configuration.
            info!("Path configuration has become more restrictive: retiring existing circuits.");
            self.retire_all_circuits();
            return Ok(RetireCircuits::All);
        }
        Ok(RetireCircuits::None)
    }

    /// Whenever a [`DirEvent::NewConsensus`] arrives on `events`, update
    /// `circmgr` with the consensus parameters from `dirmgr`.
    ///
    /// Exit when `events` is closed, or one of `circmgr` or `dirmgr` becomes
    /// dangling.
    ///
    /// This is a daemon task: it runs indefinitely in the background.
    #[instrument(level = "trace", skip_all)]
    async fn keep_circmgr_params_updated<D>(
        mut events: impl futures::Stream<Item = DirEvent> + Unpin,
        circmgr: Weak<Self>,
        dirmgr: Weak<D>,
    ) where
        D: NetDirProvider + 'static + ?Sized,
    {
        use DirEvent::*;
        while let Some(event) = events.next().await {
            if matches!(event, NewConsensus) {
                if let (Some(cm), Some(dm)) = (Weak::upgrade(&circmgr), Weak::upgrade(&dirmgr)) {
                    if let Ok(netdir) = dm.netdir(Timeliness::Timely) {
                        cm.update_network_parameters(netdir.params());
                    }
                } else {
                    debug!("Circmgr or dirmgr has disappeared; task exiting.");
                    break;
                }
            }
        }
    }

    /// Reconfigure this circuit manager using the latest set of
    /// network parameters.
    fn update_network_parameters(&self, p: &tor_netdir::params::NetParameters) {
        self.mgr.update_network_parameters(p);
        self.mgr.peek_builder().update_network_parameters(p);
    }

    /// Run indefinitely, launching circuits as needed to get a good
    /// estimate for our circuit build timeouts.
    ///
    /// Exit when we notice that `circmgr` or `dirmgr` has been dropped.
    ///
    /// This is a daemon task: it runs indefinitely in the background.
    #[instrument(level = "trace", skip_all)]
    async fn continually_launch_timeout_testing_circuits<D>(
        mut sched: TaskSchedule<R>,
        circmgr: Weak<Self>,
        dirmgr: Weak<D>,
    ) where
        D: NetDirProvider + 'static + ?Sized,
    {
        while sched.next().await.is_some() {
            if let (Some(cm), Some(dm)) = (Weak::upgrade(&circmgr), Weak::upgrade(&dirmgr)) {
                if let Ok(netdir) = dm.netdir(Timeliness::Unchecked) {
                    if let Err(e) = cm
                        .launch_timeout_testing_circuit_if_appropriate(&netdir)
                        .await
                    {
                        warn_report!(e, "Problem launching a timeout testing circuit");
                    }
                    let delay = netdir
                        .params()
                        .cbt_testing_delay
                        .try_into()
                        .expect("Out-of-bounds value from BoundedInt32");

                    drop((cm, dm));
                    sched.fire_in(delay);
                } else {
                    // wait for the provider to announce some event, which will probably be
                    // NewConsensus; this is therefore a decent yardstick for rechecking
                    let _ = dm.events().next().await;
                    sched.fire();
                }
            } else {
                return;
            }
        }
    }

    /// If we need to launch a testing circuit to judge our circuit
    /// build timeouts timeouts, do so.
    ///
    /// # Note
    ///
    /// This function is invoked periodically from
    /// `continually_launch_timeout_testing_circuits`.
    async fn launch_timeout_testing_circuit_if_appropriate(&self, netdir: &NetDir) -> Result<()> {
        if !self.mgr.peek_builder().learning_timeouts() {
            return Ok(());
        }
        // We expire any too-old circuits here, so they don't get
        // counted towards max_circs.
        self.expire_circuits().await;
        let max_circs: u64 = netdir
            .params()
            .cbt_max_open_circuits_for_testing
            .try_into()
            .expect("Out-of-bounds result from BoundedInt32");
        if (self.mgr.n_tunnels() as u64) < max_circs {
            // Actually launch the circuit!
            let usage = TargetTunnelUsage::TimeoutTesting;
            let dirinfo = netdir.into();
            let mgr = Arc::clone(&self.mgr);
            debug!("Launching a circuit to test build times.");
            let receiver = mgr.launch_by_usage(&usage, dirinfo)?;
            // We don't actually care when this circuit is done,
            // so it's okay to drop the Receiver without awaiting it.
            drop(receiver);
        }

        Ok(())
    }

    /// Run forever, periodically telling `circmgr` to update its persistent
    /// state.
    ///
    /// Exit when we notice that `circmgr` has been dropped.
    ///
    /// This is a daemon task: it runs indefinitely in the background.
    #[allow(clippy::cognitive_complexity)] // because of tracing
    #[instrument(level = "trace", skip_all)]
    async fn update_persistent_state<S>(
        mut sched: TaskSchedule<R>,
        circmgr: Weak<Self>,
        statemgr: S,
    ) where
        S: StateMgr + std::marker::Send,
    {
        while sched.next().await.is_some() {
            if let Some(circmgr) = Weak::upgrade(&circmgr) {
                use tor_persist::LockStatus::*;

                match statemgr.try_lock() {
                    Err(e) => {
                        error_report!(e, "Problem with state lock file");
                        break;
                    }
                    Ok(NewlyAcquired) => {
                        info!("We now own the lock on our state files.");
                        if let Err(e) = circmgr.upgrade_to_owned_persistent_state() {
                            error_report!(e, "Unable to upgrade to owned state files");
                            break;
                        }
                    }
                    Ok(AlreadyHeld) => {
                        if let Err(e) = circmgr.store_persistent_state() {
                            error_report!(e, "Unable to flush circmgr state");
                            break;
                        }
                    }
                    Ok(NoLock) => {
                        if let Err(e) = circmgr.reload_persistent_state() {
                            error_report!(e, "Unable to reload circmgr state");
                            break;
                        }
                    }
                }
            } else {
                debug!("Circmgr has disappeared; task exiting.");
                return;
            }
            // TODO(nickm): This delay is probably too small.
            //
            // Also, we probably don't even want a fixed delay here.  Instead,
            // we should be updating more frequently when the data is volatile
            // or has important info to save, and not at all when there are no
            // changes.
            sched.fire_in(Duration::from_secs(60));
        }

        debug!("State update task exiting (potentially due to handle drop).");
    }

    /// Switch from having an unowned persistent state to having an owned one.
    ///
    /// Requires that we hold the lock on the state files.
    pub(crate) fn upgrade_to_owned_persistent_state(&self) -> Result<()> {
        self.mgr.peek_builder().upgrade_to_owned_state()?;
        Ok(())
    }

    /// Reload state from the state manager.
    ///
    /// We only call this method if we _don't_ have the lock on the state
    /// files.  If we have the lock, we only want to save.
    pub(crate) fn reload_persistent_state(&self) -> Result<()> {
        self.mgr.peek_builder().reload_state()?;
        Ok(())
    }

    /// Run indefinitely, launching circuits where the preemptive circuit
    /// predictor thinks it'd be a good idea to have them.
    ///
    /// Exit when we notice that `circmgr` or `dirmgr` has been dropped.
    ///
    /// This is a daemon task: it runs indefinitely in the background.
    ///
    /// # Note
    ///
    /// This would be better handled entirely within `tor-circmgr`, like
    /// other daemon tasks.
    #[instrument(level = "trace", skip_all)]
    async fn continually_preemptively_build_circuits<D>(
        mut sched: TaskSchedule<R>,
        circmgr: Weak<Self>,
        dirmgr: Weak<D>,
    ) where
        D: NetDirProvider + 'static + ?Sized,
    {
        let base_delay = Duration::from_secs(10);
        let mut retry = RetryDelay::from_duration(base_delay);

        while sched.next().await.is_some() {
            if let (Some(cm), Some(dm)) = (Weak::upgrade(&circmgr), Weak::upgrade(&dirmgr)) {
                if let Ok(netdir) = dm.netdir(Timeliness::Timely) {
                    let result = cm
                        .launch_circuits_preemptively(DirInfo::Directory(&netdir))
                        .await;

                    let delay = match result {
                        Ok(()) => {
                            retry.reset();
                            base_delay
                        }
                        Err(_) => retry.next_delay(&mut rand::rng()),
                    };

                    sched.fire_in(delay);
                } else {
                    // wait for the provider to announce some event, which will probably be
                    // NewConsensus; this is therefore a decent yardstick for rechecking
                    let _ = dm.events().next().await;
                    sched.fire();
                }
            } else {
                return;
            }
        }
    }

    /// Launch circuits preemptively, using the preemptive circuit predictor's
    /// predictions.
    ///
    /// # Note
    ///
    /// This function is invoked periodically from
    /// `continually_preemptively_build_circuits()`.
    #[allow(clippy::cognitive_complexity)]
    #[instrument(level = "trace", skip_all)]
    async fn launch_circuits_preemptively(
        &self,
        netdir: DirInfo<'_>,
    ) -> std::result::Result<(), err::PreemptiveCircError> {
        trace!("Checking preemptive circuit predictions.");
        let (circs, threshold) = {
            let path_config = self.mgr.peek_builder().path_config();
            let preemptive = self.predictor.lock().expect("preemptive lock poisoned");
            let threshold = preemptive.config().disable_at_threshold;
            (preemptive.predict(&path_config), threshold)
        };

        if self.mgr.n_tunnels() >= threshold {
            return Ok(());
        }
        let mut n_created = 0_usize;
        let mut n_errors = 0_usize;

        let futures = circs
            .iter()
            .map(|usage| self.mgr.get_or_launch(usage, netdir));
        let results = futures::future::join_all(futures).await;
        for (i, result) in results.into_iter().enumerate() {
            match result {
                Ok((t, TunnelProvenance::NewlyCreated)) => {
                    debug!(
                        tunnel_id=%t.unique_id(),
                        "Preemptive circuit was created for {:?}", circs[i]);
                    n_created += 1;
                }
                Ok((t, TunnelProvenance::Preexisting)) => {
                    trace!(
                        tunnel_id=%t.unique_id(),
                        "Circuit already existed created for {:?}", circs[i]);
                }
                Err(e) => {
                    warn_report!(e, "Failed to build preemptive circuit {:?}", sv(&circs[i]));
                    n_errors += 1;
                }
            }
        }

        if n_created > 0 || n_errors == 0 {
            // Either we successfully made a circuit, or we didn't have any
            // failures while looking for preexisting circuits.  Progress was
            // made, so there's no need to back off.
            Ok(())
        } else {
            // We didn't build any circuits and we hit at least one error:
            // We'll call this unsuccessful.
            Err(err::PreemptiveCircError)
        }
    }

    /// Create and return a new (typically anonymous) onion circuit stem
    /// of type `stem_kind`.
    ///
    /// If `circ_kind` is provided, we apply additional rules to make sure
    /// that this will be usable as a stem for the given kind of onion service circuit.
    /// Otherwise, we pick a stem that will probably be useful in general.
    ///
    /// This circuit is guaranteed not to have been used for any traffic
    /// previously, and it will not be given out for any other requests in the
    /// future unless explicitly re-registered with a circuit manager.
    ///
    /// If `planned_target` is provided, then the circuit will be built so that
    /// it does not share any family members with the provided target.  (The
    /// circuit _will not be_ extended to that target itself!)
    ///
    /// Used to implement onion service clients and services.
    #[cfg(feature = "hs-common")]
    #[instrument(level = "trace", skip_all)]
    pub(crate) async fn launch_hs_unmanaged<T>(
        &self,
        planned_target: Option<T>,
        dir: &NetDir,
        stem_kind: HsCircStemKind,
        circ_kind: Option<HsCircKind>,
    ) -> Result<B::Tunnel>
    where
        T: IntoOwnedChanTarget,
    {
        let usage = TargetTunnelUsage::HsCircBase {
            compatible_with_target: planned_target.map(IntoOwnedChanTarget::to_owned),
            stem_kind,
            circ_kind,
        };
        let (_, client_circ) = self.mgr.launch_unmanaged(&usage, dir.into()).await?;
        Ok(client_circ)
    }

    /// Return true if `netdir` has enough information to be used for this
    /// circuit manager.
    ///
    /// (This will check whether the netdir is missing any primary guard
    /// microdescriptors)
    pub(crate) fn netdir_is_sufficient(&self, netdir: &NetDir) -> bool {
        self.mgr
            .peek_builder()
            .guardmgr()
            .netdir_is_sufficient(netdir)
    }

    /// Internal implementation for [`CircMgr::estimate_timeout`].
    pub(crate) fn estimate_timeout(
        &self,
        timeout_action: &timeouts::Action,
    ) -> std::time::Duration {
        let (timeout, _abandon) = self.mgr.peek_builder().estimator().timeouts(timeout_action);
        timeout
    }

    /// Internal implementation for [`CircMgr::builder`].
    pub(crate) fn builder(&self) -> &B {
        self.mgr.peek_builder()
    }

    /// Flush state to the state manager, if there is any unsaved state and
    /// we have the lock.
    ///
    /// Return true if we saved something; false if we didn't have the lock.
    pub(crate) fn store_persistent_state(&self) -> Result<bool> {
        self.mgr.peek_builder().save_state()
    }

    /// Expire every circuit that has been dirty for too long.
    ///
    /// Expired circuits are not closed while they still have users,
    /// but they are no longer given out for new requests.
    async fn expire_circuits(&self) {
        // TODO: I would prefer not to call this at every request, but
        // it should be fine for now.  (At some point we may no longer
        // need this, or might not need to call it so often, now that
        // our circuit expiration runs on scheduled timers via
        // spawn_expiration_task.)
        let now = self.mgr.peek_runtime().now();

        // TODO: Use return value here to implement the above TODO.
        let _next_expiration = self.mgr.expire_tunnels(now).await;
    }

    /// Mark every circuit that we have launched so far as unsuitable for
    /// any future requests.  This won't close existing circuits that have
    /// streams attached to them, but it will prevent any future streams from
    /// being attached.
    ///
    /// TODO: we may want to expose this eventually.  If we do, we should
    /// be very clear that you don't want to use it haphazardly.
    pub(crate) fn retire_all_circuits(&self) {
        self.mgr.retire_all_tunnels();
    }

    /// If `circ_id` is the unique identifier for a circuit that we're
    /// keeping track of, don't give it out for any future requests.
    pub(crate) fn retire_circ(&self, circ_id: &<B::Tunnel as AbstractTunnel>::Id) {
        let _ = self.mgr.take_tunnel(circ_id);
    }

    /// Return a stream of events about our estimated clock skew; these events
    /// are `None` when we don't have enough information to make an estimate,
    /// and `Some(`[`SkewEstimate`]`)` otherwise.
    ///
    /// Note that this stream can be lossy: if the estimate changes more than
    /// one before you read from the stream, you might only get the most recent
    /// update.
    pub(crate) fn skew_events(&self) -> ClockSkewEvents {
        self.mgr.peek_builder().guardmgr().skew_events()
    }

    /// Record that a failure occurred on a circuit with a given guard, in a way
    /// that makes us unwilling to use that guard for future circuits.
    ///
    pub(crate) fn note_external_failure(
        &self,
        target: &impl ChanTarget,
        external_failure: ExternalActivity,
    ) {
        self.mgr
            .peek_builder()
            .guardmgr()
            .note_external_failure(target, external_failure);
    }

    /// Record that a success occurred on a circuit with a given guard, in a way
    /// that makes us possibly willing to use that guard for future circuits.
    pub(crate) fn note_external_success(
        &self,
        target: &impl ChanTarget,
        external_activity: ExternalActivity,
    ) {
        self.mgr
            .peek_builder()
            .guardmgr()
            .note_external_success(target, external_activity);
    }
}
