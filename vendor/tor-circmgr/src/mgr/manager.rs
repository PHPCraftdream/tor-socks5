use super::*;

impl<B: AbstractTunnelBuilder<R> + 'static, R: Runtime> AbstractTunnelMgr<B, R> {
    /// Construct a new AbstractTunnelMgr.
    pub(crate) fn new(builder: B, runtime: R, circuit_timing: CircuitTiming) -> Self {
        let circs = sync::Mutex::new(TunnelList::new());
        let dflt_params = tor_netdir::params::NetParameters::default();
        let unused_timing = (&dflt_params).into();
        AbstractTunnelMgr {
            builder,
            runtime,
            tunnels: circs,
            circuit_timing: circuit_timing.into(),
            unused_timing: sync::Mutex::new(unused_timing),
        }
    }

    /// Reconfigure this manager using the latest set of network parameters.
    pub(crate) fn update_network_parameters(&self, p: &tor_netdir::params::NetParameters) {
        let mut u = self
            .unused_timing
            .lock()
            .expect("Poisoned lock for unused_timing");
        *u = p.into();
    }

    /// Return this manager's [`CircuitTiming`].
    pub(crate) fn circuit_timing(&self) -> Arc<CircuitTiming> {
        self.circuit_timing.get()
    }

    /// Return this manager's [`CircuitTiming`].
    pub(crate) fn set_circuit_timing(&self, new_config: CircuitTiming) {
        self.circuit_timing.replace(new_config);
    }
    /// Return a circuit suitable for use with a given `usage`,
    /// creating that circuit if necessary, and restricting it
    /// under the assumption that it will be used for that spec.
    ///
    /// This is the primary entry point for AbstractTunnelMgr.
    #[allow(clippy::cognitive_complexity)] // TODO #2010: Refactor?
    #[instrument(level = "trace", skip_all)]
    pub(crate) async fn get_or_launch(
        self: &Arc<Self>,
        usage: &TargetTunnelUsage,
        dir: DirInfo<'_>,
    ) -> Result<(Arc<B::Tunnel>, TunnelProvenance)> {
        /// Largest number of "resets" that we will accept in this attempt.
        ///
        /// A "reset" is an internally generated error that does not represent a
        /// real problem; only a "whoops, got to try again" kind of a situation.
        /// For example, if we reconfigure in the middle of an attempt and need
        /// to re-launch the circuit, that counts as a "reset", since there was
        /// nothing actually _wrong_ with the circuit we were building.
        ///
        /// We accept more resets than we do real failures. However,
        /// we don't accept an unlimited number: we don't want to inadvertently
        /// permit infinite loops here. If we ever bump against this limit, we
        /// should not automatically increase it: we should instead figure out
        /// why it is happening and try to make it not happen.
        const MAX_RESETS: usize = 8;

        let circuit_timing = self.circuit_timing();
        let timeout_at = self.runtime.now() + circuit_timing.request_timeout;
        let max_tries = circuit_timing.request_max_retries;
        // We compute the maximum number of failures by dividing the maximum
        // number of circuits to attempt by the number that will be launched in
        // parallel for each iteration.
        let max_failures = usize::div_ceil(
            max_tries as usize,
            std::cmp::max(1, self.builder.launch_parallelism(usage)),
        );

        let mut retry_schedule = RetryDelay::from_msec(100);
        let mut retry_err = RetryError::<Box<Error>>::in_attempt_to("find or build a tunnel");

        let mut n_failures = 0;
        let mut n_resets = 0;

        for attempt_num in 1.. {
            // How much time is remaining?
            let remaining = match timeout_at.checked_duration_since(self.runtime.now()) {
                None => {
                    retry_err.push_timed(
                        Error::RequestTimeout,
                        self.runtime.now(),
                        Some(self.runtime.wallclock()),
                    );
                    break;
                }
                Some(t) => t,
            };

            let error = match self.prepare_action(usage, dir, true) {
                Ok(action) => {
                    // We successfully found an action: Take that action.
                    let outcome = self
                        .runtime
                        .timeout(remaining, Arc::clone(self).take_action(action, usage))
                        .await;

                    match outcome {
                        Ok(Ok(circ)) => return Ok(circ),
                        Ok(Err(e)) => {
                            debug!("Circuit attempt {} failed.", attempt_num);
                            Error::RequestFailed(e)
                        }
                        Err(_) => {
                            // We ran out of "remaining" time; there is nothing
                            // more to be done.
                            warn!("All tunnel attempts failed due to timeout");
                            retry_err.push_timed(
                                Error::RequestTimeout,
                                self.runtime.now(),
                                Some(self.runtime.wallclock()),
                            );
                            break;
                        }
                    }
                }
                Err(e) => {
                    // We couldn't pick the action!
                    debug_report!(
                        &e,
                        "Couldn't pick action for tunnel attempt {}",
                        attempt_num,
                    );
                    e
                }
            };

            // There's been an error.  See how long we wait before we retry.
            let now = self.runtime.now();
            let retry_time =
                error.abs_retry_time(now, || retry_schedule.next_delay(&mut rand::rng()));

            let (count, count_limit) = if error.is_internal_reset() {
                (&mut n_resets, MAX_RESETS)
            } else {
                (&mut n_failures, max_failures)
            };
            // Record the error, flattening it if needed.
            match error {
                // Flatten nested RetryError, using mockable time for each error
                Error::RequestFailed(e) => {
                    retry_err.extend_from_retry_error(e);
                }
                e => retry_err.push_timed(e, now, Some(self.runtime.wallclock())),
            }

            *count += 1;
            // If we have reached our limit of this kind of problem, we're done.
            if *count >= count_limit {
                warn!("Reached circuit build retry limit, exiting...");
                break;
            }

            // Wait, or not, as appropriate.
            match retry_time {
                AbsRetryTime::Immediate => {}
                AbsRetryTime::Never => break,
                AbsRetryTime::At(t) => {
                    let remaining = timeout_at.saturating_duration_since(now);
                    let delay = t.saturating_duration_since(now);
                    trace!(?delay, "Waiting to retry...");
                    self.runtime.sleep(std::cmp::min(delay, remaining)).await;
                }
            }
        }

        warn!("Request failed");
        Err(Error::RequestFailed(retry_err))
    }

    /// Make sure a circuit exists, without actually asking for it.
    ///
    /// Make sure that there is a circuit (built or in-progress) that could be
    /// used for `usage`, and launch one or more circuits in a background task
    /// if there is not.
    // TODO: This should probably take some kind of parallelism parameter.
    #[cfg(test)]
    pub(crate) fn ensure_tunnel(
        self: &Arc<Self>,
        usage: &TargetTunnelUsage,
        dir: DirInfo<'_>,
    ) -> Result<()> {
        let action = self.prepare_action(usage, dir, false)?;
        if let Action::Build(plans) = action {
            for plan in plans {
                let self_clone = Arc::clone(self);
                let _ignore_receiver = self_clone.spawn_launch(usage, plan);
            }
        }

        Ok(())
    }

    /// Choose which action we should take in order to provide a tunnel
    /// for a given `usage`.
    ///
    /// If `restrict_circ` is true, we restrict the spec of any
    /// circ we decide to use to mark that it _is_ being used for
    /// `usage`.
    #[instrument(level = "trace", skip_all)]
    fn prepare_action(
        &self,
        usage: &TargetTunnelUsage,
        dir: DirInfo<'_>,
        restrict_circ: bool,
    ) -> Result<Action<B, R>> {
        let mut list = self.tunnels.lock().expect("poisoned lock");

        if let Some(mut open) = list.find_open(usage) {
            // We have open tunnels that meet the spec: return the best one.
            let parallelism = self.builder.select_parallelism(usage);
            let best = OpenEntry::find_best(&mut open, usage, parallelism);
            if restrict_circ {
                let now = self.runtime.now();
                best.restrict_mut(usage, now)?;
            }
            // TODO: If we have fewer tunnels here than our select
            // parallelism, perhaps we should launch more?

            return Ok(Action::Open(best.tunnel.clone()));
        }

        if let Some(pending) = list.find_pending_tunnels(usage) {
            // There are pending tunnels that could meet the spec.
            // Restrict them under the assumption that they could all
            // be used for this, and then wait until one is ready (or
            // all have failed)
            let best = PendingEntry::find_best(&pending, usage);
            if restrict_circ {
                for item in &best {
                    // TODO: Do we want to tentatively restrict _all_ of these?
                    // not clear to me.
                    item.tentative_restrict_mut(usage)?;
                }
            }
            let stream = best.iter().map(|item| item.receiver.clone()).collect();
            // TODO: if we have fewer tunnels here than our launch
            // parallelism, we might want to launch more.

            return Ok(Action::Wait(stream));
        }

        // Okay, we need to launch tunnels here.
        let parallelism = std::cmp::max(1, self.builder.launch_parallelism(usage));
        let mut plans = Vec::new();
        let mut last_err = None;
        for _ in 0..parallelism {
            match self.plan_by_usage(dir, usage) {
                Ok((pending, plan)) => {
                    list.add_pending_tunnel(pending);
                    plans.push(plan);
                }
                Err(e) => {
                    debug!("Unable to make a plan for {:?}: {}", usage, e);
                    last_err = Some(e);
                }
            }
        }
        if !plans.is_empty() {
            Ok(Action::Build(plans))
        } else if let Some(last_err) = last_err {
            Err(last_err)
        } else {
            // we didn't even try to plan anything!
            Err(internal!("no plans were built, but no errors were found").into())
        }
    }

    /// Execute an action returned by pick-action, and return the
    /// resulting tunnel or error.
    #[allow(clippy::cognitive_complexity, clippy::type_complexity)] // TODO #2010: Refactor
    #[instrument(level = "trace", skip_all)]
    async fn take_action(
        self: Arc<Self>,
        act: Action<B, R>,
        usage: &TargetTunnelUsage,
    ) -> std::result::Result<(Arc<B::Tunnel>, TunnelProvenance), RetryError<Box<Error>>> {
        /// Store the error `err` into `retry_err`, as appropriate.
        fn record_error<R: Runtime>(
            retry_err: &mut RetryError<Box<Error>>,
            source: streams::Source,
            building: bool,
            mut err: Error,
            runtime: &R,
        ) {
            if source == streams::Source::Right {
                // We don't care about this error, since it is from neither a tunnel we launched
                // nor one that we're waiting on.
                return;
            }
            if !building {
                // We aren't building our own tunnels, so our errors are
                // secondary reports of other tunnels' failures.
                err = Error::PendingFailed(Box::new(err));
            }
            retry_err.push_timed(err, runtime.now(), Some(runtime.wallclock()));
        }
        /// Return a string describing what it means, within the context of this
        /// function, to have gotten an answer from `source`.
        fn describe_source(building: bool, source: streams::Source) -> &'static str {
            match (building, source) {
                (_, streams::Source::Right) => "optimistic advice",
                (true, streams::Source::Left) => "tunnel we're building",
                (false, streams::Source::Left) => "pending tunnel",
            }
        }

        // Get or make a stream of futures to wait on.
        let (building, wait_on_stream) = match act {
            Action::Open(c) => {
                // There's already a perfectly good open tunnel; we can return
                // it now.
                trace!("Returning existing tunnel.");
                return Ok((c, TunnelProvenance::Preexisting));
            }
            Action::Wait(f) => {
                // There is one or more pending tunnel that we're waiting for.
                // If any succeeds, we try to use it.  If they all fail, we
                // fail.
                trace!("Waiting for tunnel.");
                (false, f)
            }
            Action::Build(plans) => {
                // We're going to launch one or more tunnels in parallel.  We
                // report success if any succeeds, and failure of they all fail.
                trace!("Building new tunnel.");
                let futures = FuturesUnordered::new();
                for plan in plans {
                    let self_clone = Arc::clone(&self);
                    // (This is where we actually launch tunnels.)
                    futures.push(self_clone.spawn_launch(usage, plan));
                }
                (true, futures)
            }
        };

        // Insert ourself into the list of pending requests, and make a
        // stream for us to listen on for notification from pending tunnels
        // other than those we are pending on.
        let (pending_request, additional_stream) = {
            // We don't want this queue to participate in memory quota tracking.
            // There isn't any tunnel yet, so there wouldn't be anything to account it to.
            // If this queue has the oldest data, probably the whole system is badly broken.
            // Tearing down the whole tunnel manager won't help.
            let (send, recv) = mpsc_channel_no_memquota(8);
            let pending = Arc::new(PendingRequest {
                usage: usage.clone(),
                notify: send,
            });

            let mut list = self.tunnels.lock().expect("poisoned lock");
            list.add_pending_request(&pending);

            (pending, recv)
        };

        // We use our "select_biased" stream combiner here to ensure that:
        //   1) Circuits from wait_on_stream (the ones we're pending on) are
        //      preferred.
        //   2) We exit this function when those tunnels are exhausted.
        //   3) We still get notified about other tunnels that might meet our
        //      interests.
        //
        // The events from Left stream are the oes that we explicitly asked for,
        // so we'll treat errors there as real problems.  The events from the
        // Right stream are ones that we got opportunistically told about; it's
        // not a big deal if those fail.
        let mut incoming = streams::select_biased(wait_on_stream, additional_stream.map(Ok));

        let mut retry_error = RetryError::in_attempt_to("wait for tunnels");

        while let Some((src, id)) = incoming.next().await {
            match id {
                Ok(Ok(ref id)) => {
                    // Great, we have a tunnel . See if we can use it!
                    let mut list = self.tunnels.lock().expect("poisoned lock");
                    if let Some(ent) = list.get_open_mut(id) {
                        let now = self.runtime.now();
                        match ent.restrict_mut(usage, now) {
                            Ok(()) => {
                                // Great, this will work.  We drop the
                                // pending request now explicitly to remove
                                // it from the list.
                                drop(pending_request);
                                if matches!(ent.expiration, ExpirationInfo::Unused { .. }) {
                                    let try_to_expire_after = if ent.spec.is_long_lived() {
                                        self.circuit_timing().disused_circuit_timeout
                                    } else {
                                        self.circuit_timing().max_dirtiness
                                    };
                                    // Since this tunnel hasn't been used yet, schedule expiration
                                    // task after `max_dirtiness` from now.
                                    spawn_expiration_task(
                                        &self.runtime,
                                        Arc::downgrade(&self),
                                        ent.tunnel.id(),
                                        now + try_to_expire_after,
                                    );
                                }
                                return Ok((ent.tunnel.clone(), TunnelProvenance::NewlyCreated));
                            }
                            Err(e) => {
                                // In this case, a `UsageMismatched` error just means that we lost the race
                                // to restrict this tunnel.
                                let e = match e {
                                    Error::UsageMismatched(e) => Error::LostUsabilityRace(e),
                                    x => x,
                                };
                                if src == streams::Source::Left {
                                    info_report!(
                                        &e,
                                        "{} suggested we use {:?}, but restrictions failed",
                                        describe_source(building, src),
                                        id,
                                    );
                                } else {
                                    debug_report!(
                                        &e,
                                        "{} suggested we use {:?}, but restrictions failed",
                                        describe_source(building, src),
                                        id,
                                    );
                                }
                                record_error(&mut retry_error, src, building, e, &self.runtime);
                                continue;
                            }
                        }
                    }
                }
                Ok(Err(ref e)) => {
                    debug!("{} sent error {:?}", describe_source(building, src), e);
                    record_error(&mut retry_error, src, building, e.clone(), &self.runtime);
                }
                Err(oneshot::Canceled) => {
                    debug!(
                        "{} went away (Canceled), quitting take_action right away",
                        describe_source(building, src)
                    );
                    record_error(
                        &mut retry_error,
                        src,
                        building,
                        Error::PendingCanceled,
                        &self.runtime,
                    );
                    return Err(retry_error);
                }
            }

            debug!(
                "While waiting on tunnel: {:?} from {}",
                id,
                describe_source(building, src)
            );
        }

        // Nothing worked.  We drop the pending request now explicitly
        // to remove it from the list.  (We could just let it get dropped
        // implicitly, but that's a bit confusing.)
        drop(pending_request);

        Err(retry_error)
    }

    /// Given a directory and usage, compute the necessary objects to
    /// build a tunnel: A [`PendingEntry`] to keep track of the in-process
    /// tunnel, and a [`TunnelBuildPlan`] that we'll give to the thread
    /// that will build the tunnel.
    ///
    /// The caller should probably add the resulting `PendingEntry` to
    /// `self.circs`.
    ///
    /// This is an internal function that we call when we're pretty sure
    /// we want to build a tunnel.
    #[allow(clippy::type_complexity)]
    fn plan_by_usage(
        &self,
        dir: DirInfo<'_>,
        usage: &TargetTunnelUsage,
    ) -> Result<(Arc<PendingEntry<B, R>>, TunnelBuildPlan<B, R>)> {
        let (plan, bspec) = self.builder.plan_tunnel(usage, dir)?;
        let (pending, sender) = PendingEntry::new(&bspec);
        let pending = Arc::new(pending);

        let plan = TunnelBuildPlan {
            plan,
            sender,
            pending: Arc::clone(&pending),
        };

        Ok((pending, plan))
    }

    /// Launch a managed tunnel for a target usage, without checking
    /// whether one already exists or is pending.
    ///
    /// Return a listener that will be informed when the tunnel is done.
    #[instrument(level = "trace", skip_all)]
    pub(crate) fn launch_by_usage(
        self: &Arc<Self>,
        usage: &TargetTunnelUsage,
        dir: DirInfo<'_>,
    ) -> Result<Shared<oneshot::Receiver<PendResult<B, R>>>> {
        let (pending, plan) = self.plan_by_usage(dir, usage)?;

        self.tunnels
            .lock()
            .expect("Poisoned lock for tunnel list")
            .add_pending_tunnel(pending);

        Ok(Arc::clone(self).spawn_launch(usage, plan))
    }

    /// Spawn a background task to launch a tunnel, and report its status.
    ///
    /// The `usage` argument is the usage from the original request that made
    /// us build this tunnel.
    #[instrument(level = "trace", skip_all)]
    fn spawn_launch(
        self: Arc<Self>,
        usage: &TargetTunnelUsage,
        plan: TunnelBuildPlan<B, R>,
    ) -> Shared<oneshot::Receiver<PendResult<B, R>>> {
        let _ = usage; // Currently unused.
        let TunnelBuildPlan {
            mut plan,
            sender,
            pending,
        } = plan;
        let request_loyalty = self.circuit_timing().request_loyalty;

        let wait_on_future = pending.receiver.clone();
        let runtime = self.runtime.clone();
        let runtime_copy = self.runtime.clone();

        let tid = rand::random::<u64>();
        // We release this block when the tunnel builder task terminates.
        let reason = format!("tunnel builder task {}", tid);
        runtime.block_advance(reason.clone());
        // During tests, the `FakeBuilder` will need to release the block in order to fake a timeout
        // correctly.
        plan.add_blocked_advance_reason(reason);

        runtime
            .spawn(async move {
                let self_clone = Arc::clone(&self);
                let future = AssertUnwindSafe(self_clone.do_launch(plan, pending)).catch_unwind();
                let (new_spec, reply) = match future.await {
                    Ok(x) => x, // Success or regular failure
                    Err(e) => {
                        // Okay, this is a panic.  We have to tell the calling
                        // thread about it, then exit this tunnel builder task.
                        let _ = sender.send(Err(internal!("tunnel build task panicked").into()));
                        std::panic::panic_any(e);
                    }
                };

                // Tell anybody who was listening about it that this
                // tunnel is now usable or failed.
                //
                // (We ignore any errors from `send`: That just means that nobody
                // was waiting for this tunnel.)
                let _ = sender.send(reply.clone());

                if let Some(new_spec) = new_spec {
                    // Wait briefly before we notify opportunistically.  This
                    // delay will give the tunnels that were originally
                    // specifically intended for a request a little more time
                    // to finish, before we offer it this tunnel instead.
                    let sl = runtime_copy.sleep(request_loyalty);
                    runtime_copy.allow_one_advance(request_loyalty);
                    sl.await;

                    let pending = {
                        let list = self.tunnels.lock().expect("poisoned lock");
                        list.find_pending_requests(&new_spec)
                    };
                    for pending_request in pending {
                        let _ = pending_request.notify.clone().try_send(reply.clone());
                    }
                }
                runtime_copy.release_advance(format!("tunnel builder task {}", tid));
            })
            .expect("Couldn't spawn tunnel-building task");

        wait_on_future
    }

    /// Run in the background to launch a tunnel. Return a 2-tuple of the new
    /// tunnel spec and the outcome that should be sent to the initiator.
    #[instrument(level = "trace", skip_all)]
    async fn do_launch(
        self: Arc<Self>,
        plan: <B as AbstractTunnelBuilder<R>>::Plan,
        pending: Arc<PendingEntry<B, R>>,
    ) -> (Option<SupportedTunnelUsage>, PendResult<B, R>) {
        let outcome = self.builder.build_tunnel(plan).await;

        match outcome {
            Err(e) => (None, Err(e)),
            Ok((new_spec, tunnel)) => {
                let id = tunnel.id();

                let use_duration = self.pick_use_duration();
                let now = self.runtime.now();
                let exp_inst = now + use_duration;
                let runtime_copy = self.runtime.clone();
                spawn_expiration_task(&runtime_copy, Arc::downgrade(&self), tunnel.id(), exp_inst);
                // I used to call restrict_mut here, but now I'm not so
                // sure. Doing restrict_mut makes sure that this
                // tunnel will be suitable for the request that asked
                // for us in the first place, but that should be
                // ensured anyway by our tracking its tentative
                // assignment.
                //
                // new_spec.restrict_mut(&usage_copy).unwrap();
                let use_before = ExpirationInfo::new(now);
                let open_ent = OpenEntry::new(new_spec.clone(), tunnel, use_before);
                {
                    let mut list = self.tunnels.lock().expect("poisoned lock");
                    // Finally, before we return this tunnel, we need to make
                    // sure that this pending tunnel is still pending.  (If it
                    // is not pending, then it was cancelled through a call to
                    // `retire_all_tunnels`, and the configuration that we used
                    // to launch it is now sufficiently outdated that we should
                    // no longer give this tunnel to a client.)
                    if list.tunnel_is_pending(&pending) {
                        list.add_open(open_ent);
                        // We drop our reference to 'pending' here:
                        // this should make all the weak references to
                        // the `PendingEntry` become dangling.
                        drop(pending);
                        (Some(new_spec), Ok(id))
                    } else {
                        // This tunnel is no longer pending! It must have been cancelled, probably
                        // by a call to retire_all_tunnels()
                        drop(pending); // ibid
                        (None, Err(Error::CircCanceled))
                    }
                }
            }
        }
    }

    /// Return the currently configured expiration parameters.
    fn expiration_params(&self) -> ExpirationParameters {
        let expire_unused_after = self.pick_use_duration();
        let expire_dirty_after = self.circuit_timing().max_dirtiness;
        let expire_disused_after = self.circuit_timing().disused_circuit_timeout;

        ExpirationParameters {
            expire_unused_after,
            expire_dirty_after,
            expire_disused_after,
        }
    }

    /// Plan and launch a new tunnel to a given target, bypassing our managed
    /// pool of tunnels.
    ///
    /// This method will always return a new tunnel, and never return a tunnel
    /// that this CircMgr gives out for anything else.
    ///
    /// The new tunnel will participate in the guard and timeout apparatus as
    /// appropriate, no retry attempt will be made if the tunnel fails.
    #[cfg(feature = "hs-common")]
    #[instrument(level = "trace", skip_all)]
    pub(crate) async fn launch_unmanaged(
        &self,
        usage: &TargetTunnelUsage,
        dir: DirInfo<'_>,
    ) -> Result<(SupportedTunnelUsage, B::Tunnel)> {
        let (_, plan) = self.plan_by_usage(dir, usage)?;
        self.builder.build_tunnel(plan.plan).await
    }

    /// Remove the tunnel with a given `id` from this manager.
    ///
    /// After this function is called, that tunnel will no longer be handed
    /// out to any future requests.
    ///
    /// Return None if we have no tunnel with the given ID.
    pub(crate) fn take_tunnel(
        &self,
        id: &<B::Tunnel as AbstractTunnel>::Id,
    ) -> Option<Arc<B::Tunnel>> {
        let mut list = self.tunnels.lock().expect("poisoned lock");
        list.take_open(id).map(|e| e.tunnel)
    }

    /// Remove all open and pending tunnels and from this manager, to ensure
    /// they can't be given out for any more requests.
    ///
    /// Calling `retire_all_tunnels` ensures that any tunnel request that gets
    /// an  answer _after this method runs_ will receive a tunnel that was
    /// launched _after this method runs_.
    ///
    /// We call this method this when our configuration changes in such a way
    /// that we want to make sure that any new (or pending) requests will
    /// receive tunnels that are built using the new configuration.
    //
    // For more information, see documentation on [`CircuitList::open_circs`],
    // [`CircuitList::pending_circs`], and comments in `do_launch`.
    pub(crate) fn retire_all_tunnels(&self) {
        let mut list = self.tunnels.lock().expect("poisoned lock");
        list.clear_all_tunnels();
    }

    /// Expire tunnels according to the rules in `config` and the
    /// current time `now`.
    ///
    /// Expired tunnels will not be automatically closed, but they will
    /// no longer be given out for new tunnels.
    ///
    /// Return the earliest time at which any current tunnel will expire.
    pub(crate) async fn expire_tunnels(&self, now: Instant) -> Option<Instant> {
        let expiration_params = self.expiration_params();

        // While holding the lock, we call TunnelList::expire_tunnels.
        // That function will expire what it can, and return a list of the tunnels for which
        // we need to call `disused_since`.
        let (mut earliest_expiration, need_to_check) = {
            let mut list = self.tunnels.lock().expect("poisoned lock");
            list.expire_tunnels(now, &expiration_params)
        };

        // Now we've dropped the lock, and can do async checks.
        let mut last_known_usage = Vec::new();
        for tunnel in need_to_check {
            let Some(tunnel) = Weak::upgrade(&tunnel) else {
                continue; // The tunnel is already gone.
            };
            last_known_usage.push((tunnel.id(), tunnel.last_known_to_be_used_at().await));
        }

        // Now get the lock again, and tell the list what we learned.
        //
        // Note that if this function is called twice simultaneously, in some corner cases, we might
        // decide to expire something twice.  That's okay.
        {
            let mut list = self.tunnels.lock().expect("poisoned lock");
            for (id, disused_since) in last_known_usage {
                match list.update_long_lived_tunnel_last_used(
                    &id,
                    now,
                    &expiration_params,
                    &disused_since,
                ) {
                    Ok(Some(may_expire)) => {
                        earliest_expiration = match earliest_expiration {
                            Some(exp) if exp < may_expire => Some(exp),
                            _ => Some(may_expire),
                        };
                    }
                    Ok(None) => {}
                    Err(e) => warn_report!(e, "Error while updating status on tunnel {:?}", id),
                }
            }
        }

        earliest_expiration
    }

    /// Consider expiring the tunnel with given tunnel `id`,
    /// according to the rules in `config` and the current time `now`.
    ///
    /// Returns None if the circuit is expired; otherwise returns the next time at which the circuit may expire.
    pub(crate) async fn consider_expiring_tunnel(
        &self,
        tun_id: &<B::Tunnel as AbstractTunnel>::Id,
        now: Instant,
    ) -> Result<Option<Instant>> {
        let expiration_params = self.expiration_params();

        // With the lock, call TunneList::tunnel_should_expire, and expire it (or don't)
        // if the decision is obvious.
        let tunnel = {
            let mut list: sync::MutexGuard<'_, TunnelList<B, R>> =
                self.tunnels.lock().expect("poisoned lock");
            let Some(should_expire) = list.tunnel_should_expire(tun_id, now, &expiration_params)
            else {
                return Ok(None);
            };
            match should_expire {
                ShouldExpire::Now => {
                    let _discard = list.take_open(tun_id);
                    return Ok(None);
                }
                ShouldExpire::NotBefore(t) => return Ok(Some(t)),
                ShouldExpire::PossiblyNow => {
                    let Some(tunnel_ent) = list.get_open_mut(tun_id) else {
                        return Ok(None);
                    };
                    Arc::clone(&tunnel_ent.tunnel)
                }
            }
        };

        // If we get here, then we have a long-lived tunnel for which we need to check `disused_since`
        let last_known_in_use_at = tunnel.last_known_to_be_used_at().await;

        // Now we tell the TunnelList what we learned.
        {
            let mut list: sync::MutexGuard<'_, TunnelList<B, R>> =
                self.tunnels.lock().expect("poisoned lock");
            list.update_long_lived_tunnel_last_used(
                tun_id,
                now,
                &expiration_params,
                &last_known_in_use_at,
            )
        }
    }

    /// Return the number of open tunnels held by this tunnel manager.
    pub(crate) fn n_tunnels(&self) -> usize {
        let list = self.tunnels.lock().expect("poisoned lock");
        list.open_tunnels.len()
    }

    /// Return the number of pending tunnels tracked by this tunnel manager.
    #[cfg(test)]
    pub(crate) fn n_pending_tunnels(&self) -> usize {
        let list = self.tunnels.lock().expect("poisoned lock");
        list.pending_tunnels.len()
    }

    /// Get a reference to this manager's runtime.
    pub(crate) fn peek_runtime(&self) -> &R {
        &self.runtime
    }

    /// Get a reference to this manager's builder.
    pub(crate) fn peek_builder(&self) -> &B {
        &self.builder
    }

    /// Pick a duration by when a new tunnel should expire from now
    /// if it has not yet been used
    fn pick_use_duration(&self) -> Duration {
        let timings = self
            .unused_timing
            .lock()
            .expect("Poisoned lock for unused_timing");

        if self.builder.learning_timeouts() {
            timings.learning
        } else {
            // TODO: In Tor, this calculation also depends on
            // stuff related to predicted ports and channel
            // padding.
            use tor_basic_utils::RngExt as _;
            let mut rng = rand::rng();
            rng.gen_range_checked(timings.not_learning..=timings.not_learning * 2)
                .expect("T .. 2x T turned out to be an empty duration range?!")
        }
    }
}

//
// TODO: It would be good to do away with this function entirely, and have a smarter expiration
// function.  This one only exists because there is not an "expire some circuits" background task.
