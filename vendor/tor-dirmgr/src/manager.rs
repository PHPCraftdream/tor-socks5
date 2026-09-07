use super::*;

impl<R: Runtime> DirMgr<R> {
    /// Try to load the directory from disk, without launching any
    /// kind of update process.
    ///
    /// This function runs in **offline** mode: it will give an error
    /// if the result is not up-to-date, or not fully downloaded.
    ///
    /// In general, you shouldn't use this function in a long-running
    /// program; it's only suitable for command-line or batch tools.
    // TODO: I wish this function didn't have to be async or take a runtime.
    pub fn load_once(runtime: R, config: DirMgrConfig) -> Result<Arc<NetDir>> {
        let store = DirMgrStore::new(&config, runtime.clone(), true)?;
        let dirmgr = Arc::new(Self::from_config(config, runtime, store, None, true)?);

        // TODO: add some way to return a directory that isn't up-to-date
        let attempt = AttemptId::next();
        trace!(%attempt, "Trying to load a full directory from cache");
        let outcome = dirmgr.load_directory(attempt);
        trace!(%attempt, "Load result: {outcome:?}");
        let _success = outcome?;

        dirmgr
            .netdir(Timeliness::Timely)
            .map_err(|_| Error::DirectoryNotPresent)
    }

    /// Return a current netdir, either loading it or bootstrapping it
    /// as needed.
    ///
    /// Like load_once, but will try to bootstrap (or wait for another
    /// process to bootstrap) if we don't have an up-to-date
    /// bootstrapped directory.
    ///
    /// In general, you shouldn't use this function in a long-running
    /// program; it's only suitable for command-line or batch tools.
    pub async fn load_or_bootstrap_once(
        config: DirMgrConfig,
        runtime: R,
        store: DirMgrStore<R>,
        circmgr: Arc<CircMgr<R>>,
    ) -> Result<Arc<NetDir>> {
        let dirmgr = DirMgr::bootstrap_from_config(config, runtime, store, circmgr).await?;
        dirmgr
            .timely_netdir()
            .map_err(|_| Error::DirectoryNotPresent)
    }

    /// Create a new `DirMgr` in online mode, but don't bootstrap it yet.
    ///
    /// The `DirMgr` can be bootstrapped later with `bootstrap`.
    pub fn create_unbootstrapped(
        config: DirMgrConfig,
        runtime: R,
        store: DirMgrStore<R>,
        circmgr: Arc<CircMgr<R>>,
    ) -> Result<Arc<Self>> {
        Ok(Arc::new(DirMgr::from_config(
            config,
            runtime,
            store,
            Some(circmgr),
            false,
        )?))
    }

    /// Bootstrap a `DirMgr` created in online mode that hasn't been bootstrapped yet.
    ///
    /// This function will not return until the directory is bootstrapped enough to build circuits.
    /// It will also launch a background task that fetches any missing information, and that
    /// replaces the directory when a new one is available.
    ///
    /// This function is intended to be used together with `create_unbootstrapped`. There is no
    /// need to call this function otherwise.
    ///
    /// If bootstrapping has already successfully taken place, returns early with success.
    ///
    /// # Errors
    ///
    /// Returns an error if bootstrapping fails. If the error is [`Error::CantAdvanceState`],
    /// it may be possible to successfully bootstrap later on by calling this function again.
    ///
    /// # Panics
    ///
    /// Panics if the `DirMgr` passed to this function was not created in online mode, such as
    /// via `load_once`.
    #[allow(clippy::cognitive_complexity)] // TODO: Refactor
    #[instrument(level = "trace", skip_all)]
    pub async fn bootstrap(self: &Arc<Self>) -> Result<()> {
        if self.offline {
            return Err(Error::OfflineMode);
        }

        // The semantics of this are "attempt to replace a 'false' value with 'true'.
        // If the value in bootstrap_started was not 'false' when the attempt was made, returns
        // `Err`; this means another bootstrap attempt is in progress or has completed, so we
        // return early.

        // NOTE(eta): could potentially weaken the `Ordering` here in future
        if self
            .bootstrap_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            debug!("Attempted to bootstrap twice; ignoring.");
            return Ok(());
        }

        // Use a RAII guard to reset `bootstrap_started` to `false` if we return early without
        // completing bootstrap.
        let reset_bootstrap_started = scopeguard::guard(&self.bootstrap_started, |v| {
            v.store(false, Ordering::SeqCst);
        });

        let schedule = {
            let sched = self.task_schedule.lock().expect("poisoned lock").take();
            match sched {
                Some(sched) => sched,
                None => {
                    debug!("Attempted to bootstrap twice; ignoring.");
                    return Ok(());
                }
            }
        };

        // Try to load from the cache.
        let attempt_id = AttemptId::next();
        trace!(attempt=%attempt_id, "Starting to bootstrap directory");
        let have_directory = self.load_directory(attempt_id)?;

        let (mut sender, receiver) = if have_directory {
            info!("Loaded a good directory from cache.");
            (None, None)
        } else {
            info!("Didn't get usable directory from cache.");
            let (sender, receiver) = oneshot::channel();
            (Some(sender), Some(receiver))
        };

        // Whether we loaded or not, we now start downloading.
        let dirmgr_weak = Arc::downgrade(self);
        self.runtime
            .spawn(async move {
                // Use an RAII guard to make sure that when this task exits, the
                // TaskSchedule object is put back.
                //
                // TODO(nick): Putting the schedule back isn't actually useful
                // if the task exits _after_ we've bootstrapped for the first
                // time, because of how bootstrap_started works.
                let mut schedule = scopeguard::guard(schedule, |schedule| {
                    if let Some(dm) = Weak::upgrade(&dirmgr_weak) {
                        *dm.task_schedule.lock().expect("poisoned lock") = Some(schedule);
                    }
                });

                // Don't warn when these are Error::ManagerDropped: that
                // means that the DirMgr has been shut down.
                if let Err(e) =
                    Self::reload_until_owner(&dirmgr_weak, &mut schedule, attempt_id, &mut sender)
                        .await
                {
                    match e {
                        Error::ManagerDropped => {}
                        _ => warn_report!(e, "Unrecovered error while waiting for bootstrap",),
                    }
                } else if let Err(e) =
                    Self::download_forever(dirmgr_weak.clone(), &mut schedule, attempt_id, sender)
                        .await
                {
                    match e {
                        Error::ManagerDropped => {}
                        _ => warn_report!(e, "Unrecovered error while downloading"),
                    }
                }
            })
            .map_err(|e| Error::from_spawn("directory updater task", e))?;

        if let Some(receiver) = receiver {
            match receiver.await {
                Ok(()) => {
                    info!("We have enough information to build circuits.");
                    // Disarm the RAII guard, since we succeeded.  Now bootstrap_started will remain true.
                    let _ = ScopeGuard::into_inner(reset_bootstrap_started);
                }
                Err(_) => {
                    warn!("Bootstrapping task exited before finishing.");
                    return Err(Error::CantAdvanceState);
                }
            }
        }
        Ok(())
    }

    /// Returns `true` if a bootstrap attempt is in progress, or successfully completed.
    pub fn bootstrap_started(&self) -> bool {
        self.bootstrap_started.load(Ordering::SeqCst)
    }

    /// Return a new directory manager from a given configuration,
    /// bootstrapping from the network as necessary.
    #[instrument(level = "trace", skip_all)]
    pub async fn bootstrap_from_config(
        config: DirMgrConfig,
        runtime: R,
        store: DirMgrStore<R>,
        circmgr: Arc<CircMgr<R>>,
    ) -> Result<Arc<Self>> {
        let dirmgr = Self::create_unbootstrapped(config, runtime, store, circmgr)?;

        dirmgr.bootstrap().await?;

        Ok(dirmgr)
    }

    /// Try forever to either lock the storage (and thereby become the
    /// owner), or to reload the database.
    ///
    /// If we have begin to have a bootstrapped directory, send a
    /// message using `on_complete`.
    ///
    /// If we eventually become the owner, return Ok().
    #[allow(clippy::cognitive_complexity)] // TODO: Refactor?
    async fn reload_until_owner(
        weak: &Weak<Self>,
        schedule: &mut TaskSchedule<R>,
        attempt_id: AttemptId,
        on_complete: &mut Option<oneshot::Sender<()>>,
    ) -> Result<()> {
        let mut logged = false;
        let mut bootstrapped;
        {
            let dirmgr = upgrade_weak_ref(weak)?;
            bootstrapped = dirmgr.netdir.get().is_some();
        }

        loop {
            {
                let dirmgr = upgrade_weak_ref(weak)?;
                trace!("Trying to take ownership of the directory cache lock");
                if dirmgr.try_upgrade_to_readwrite()? {
                    // We now own the lock!  (Maybe we owned it before; the
                    // upgrade_to_readwrite() function is idempotent.)  We can
                    // do our own bootstrapping.
                    if logged {
                        info!(
                            "The previous owning process has given up the lock. We are now in charge of managing the directory."
                        );
                    }
                    return Ok(());
                }
            }

            if !logged {
                logged = true;
                if bootstrapped {
                    info!("Another process is managing the directory. We'll use its cache.");
                } else {
                    info!(
                        "Another process is bootstrapping the directory. Waiting till it finishes or exits."
                    );
                }
            }

            // We don't own the lock.  Somebody else owns the cache.  They
            // should be updating it.  Wait a bit, then try again.
            let pause = if bootstrapped {
                std::time::Duration::new(120, 0)
            } else {
                std::time::Duration::new(5, 0)
            };
            schedule.sleep(pause).await?;
            // TODO: instead of loading the whole thing we should have a
            // database entry that says when the last update was, or use
            // our state functions.
            {
                let dirmgr = upgrade_weak_ref(weak)?;
                trace!("Trying to load from the directory cache");
                if dirmgr.load_directory(attempt_id)? {
                    // Successfully loaded a bootstrapped directory.
                    if let Some(send_done) = on_complete.take() {
                        let _ = send_done.send(());
                    }
                    if !bootstrapped {
                        info!("The directory is now bootstrapped.");
                    }
                    bootstrapped = true;
                }
            }
        }
    }

    /// Try to fetch our directory info and keep it updated, indefinitely.
    ///
    /// If we have begin to have a bootstrapped directory, send a
    /// message using `on_complete`.
    #[allow(clippy::cognitive_complexity)] // TODO: Refactor?
    #[instrument(level = "trace", skip_all)]
    async fn download_forever(
        weak: Weak<Self>,
        schedule: &mut TaskSchedule<R>,
        mut attempt_id: AttemptId,
        mut on_complete: Option<oneshot::Sender<()>>,
    ) -> Result<()> {
        let mut state: Box<dyn DirState> = {
            let dirmgr = upgrade_weak_ref(&weak)?;
            Box::new(state::GetConsensusState::new(
                dirmgr.runtime.clone(),
                dirmgr.config.get(),
                CacheUsage::CacheOkay,
                Some(dirmgr.netdir.clone()),
                #[cfg(feature = "dirfilter")]
                dirmgr
                    .filter
                    .clone()
                    .unwrap_or_else(|| Arc::new(crate::filter::NilFilter)),
            ))
        };

        trace!("Entering download loop.");

        loop {
            let mut usable = false;

            let retry_config = {
                let dirmgr = upgrade_weak_ref(&weak)?;
                // TODO(nickm): instead of getting this every time we loop, it
                // might be a good idea to refresh it with each attempt, at
                // least at the point of checking the number of attempts.
                dirmgr.config.get().schedule.retry_bootstrap()
            };
            let mut retry_delay = retry_config.schedule();

            'retry_attempt: for try_num in retry_config.attempts() {
                trace!(attempt=%attempt_id, ?try_num, "Trying to download a directory.");
                let outcome = bootstrap::download(
                    Weak::clone(&weak),
                    &mut state,
                    schedule,
                    attempt_id,
                    &mut on_complete,
                )
                .await;
                trace!(attempt=%attempt_id, ?try_num, ?outcome, "Download is over.");

                if let Err(err) = outcome {
                    if state.is_ready(Readiness::Usable) {
                        usable = true;
                        info_report!(
                            err,
                            "Unable to completely download a directory. (Nevertheless, the directory is usable, so we'll pause for now)"
                        );
                        break 'retry_attempt;
                    }

                    match err.bootstrap_action() {
                        BootstrapAction::Nonfatal => {
                            return Err(into_internal!(
                                "Nonfatal error should not have propagated here"
                            )(err)
                            .into());
                        }
                        BootstrapAction::Reset => {}
                        BootstrapAction::Fatal => return Err(err),
                    }

                    let delay = retry_delay.next_delay(&mut rand::rng());
                    warn_report!(
                        err,
                        "Unable to download a usable directory. (We will restart in {})",
                        humantime::format_duration(delay),
                    );
                    {
                        let dirmgr = upgrade_weak_ref(&weak)?;
                        dirmgr.note_reset(attempt_id);
                    }
                    schedule.sleep(delay).await?;
                    state = state.reset();
                } else {
                    info!(attempt=%attempt_id, "Directory is complete.");
                    usable = true;
                    break 'retry_attempt;
                }
            }

            if !usable {
                // we ran out of attempts.
                warn!(
                    "We failed {} times to bootstrap a directory. We're going to give up.",
                    retry_config.n_attempts()
                );
                return Err(Error::CantAdvanceState);
            } else {
                // Report success, if appropriate.
                if let Some(send_done) = on_complete.take() {
                    let _ = send_done.send(());
                }
            }

            let reset_at = state.reset_time();
            match reset_at {
                Some(t) => {
                    trace!("Sleeping until {}", time::OffsetDateTime::from(t));
                    schedule.sleep_until_wallclock(t).await?;
                }
                None => return Ok(()),
            }
            attempt_id = bootstrap::AttemptId::next();
            trace!(attempt=%attempt_id, "Beginning new attempt to bootstrap directory");
            state = state.reset();
        }
    }

    /// Get a reference to the circuit manager, if we have one.
    pub(super) fn circmgr(&self) -> Result<Arc<CircMgr<R>>> {
        self.circmgr.clone().ok_or(Error::NoDownloadSupport)
    }

    /// Try to change our configuration to `new_config`.
    ///
    /// Actual behavior will depend on the value of `how`.
    pub fn reconfigure(
        &self,
        new_config: &DirMgrConfig,
        how: tor_config::Reconfigure,
    ) -> std::result::Result<(), tor_config::ReconfigureError> {
        let config = self.config.get();
        // We don't support changing these: doing so basically would require us
        // to abort all our in-progress downloads, since they might be based on
        // no-longer-viable information.
        // NOTE: keep this in sync with the behaviour of `DirMgrConfig::update_from_config`
        if new_config.cache_dir != config.cache_dir {
            how.cannot_change("storage.cache_dir")?;
        }
        if new_config.cache_trust != config.cache_trust {
            how.cannot_change("storage.permissions")?;
        }
        if new_config.authorities() != config.authorities() {
            how.cannot_change("network.authorities")?;
        }

        if how == tor_config::Reconfigure::CheckAllOrNothing {
            return Ok(());
        }

        let params_changed = new_config.override_net_params != config.override_net_params;

        self.config
            .map_and_replace(|cfg| cfg.update_from_config(new_config));

        if params_changed {
            let _ignore_err = self.netdir.mutate(|netdir| {
                netdir.replace_overridden_parameters(&new_config.override_net_params);
                Ok(())
            });
            {
                let mut params = self.default_parameters.lock().expect("lock failed");
                *params = Arc::new(NetParameters::from_map(&new_config.override_net_params));
            }

            // (It's okay to ignore the error, since it just means that there
            // was no current netdir.)
            self.events.publish(DirEvent::NewConsensus);
        }

        Ok(())
    }

    /// Return a stream of [`DirBootstrapStatus`] events to tell us about changes
    /// in the latest directory's bootstrap status.
    ///
    /// Note that this stream can be lossy: the caller will not necessarily
    /// observe every event on the stream
    pub fn bootstrap_events(&self) -> event::DirBootstrapEvents {
        self.receive_status.clone()
    }

    /// Replace the latest status with `progress` and broadcast to anybody
    /// watching via a [`DirBootstrapEvents`] stream.
    pub(super) fn update_progress(&self, attempt_id: AttemptId, progress: DirProgress) {
        // TODO(nickm): can I kill off this lock by having something else own the sender?
        let mut sender = self.send_status.lock().expect("poisoned lock");
        let mut status = sender.borrow_mut();

        status.update_progress(attempt_id, progress);
    }

    /// Update our status tracker to note that some number of errors has
    /// occurred.
    pub(super) fn note_errors(&self, attempt_id: AttemptId, n_errors: usize) {
        if n_errors == 0 {
            return;
        }
        let mut sender = self.send_status.lock().expect("poisoned lock");
        let mut status = sender.borrow_mut();

        status.note_errors(attempt_id, n_errors);
    }

    /// Update our status tracker to note that we've needed to reset our download attempt.
    fn note_reset(&self, attempt_id: AttemptId) {
        let mut sender = self.send_status.lock().expect("poisoned lock");
        let mut status = sender.borrow_mut();

        status.note_reset(attempt_id);
    }

    /// Try to make this a directory manager with read-write access to its
    /// storage.
    ///
    /// Return true if we got the lock, or if we already had it.
    ///
    /// Return false if another process has the lock
    fn try_upgrade_to_readwrite(&self) -> Result<bool> {
        self.store
            .lock()
            .expect("Directory storage lock poisoned")
            .upgrade_to_readwrite()
    }

    /// Return a reference to the store, if it is currently read-write.
    #[cfg(test)]
    fn store_if_rw(&self) -> Option<&Mutex<DynStore>> {
        let rw = !self
            .store
            .lock()
            .expect("Directory storage lock poisoned")
            .is_readonly();
        // A race-condition is possible here, but I believe it's harmless.
        if rw { Some(&self.store) } else { None }
    }

    /// Construct a DirMgr from a DirMgrConfig.
    ///
    /// If `offline` is set, opens the SQLite store read-only and sets the offline flag in the
    /// returned manager.
    #[allow(clippy::unnecessary_wraps)] // API compat and future-proofing
    fn from_config(
        config: DirMgrConfig,
        runtime: R,
        store: DirMgrStore<R>,
        circmgr: Option<Arc<CircMgr<R>>>,
        offline: bool,
    ) -> Result<Self> {
        let netdir = Arc::new(SharedMutArc::new());
        let events = event::FlagPublisher::new();
        let default_parameters = NetParameters::from_map(&config.override_net_params);
        let default_parameters = Mutex::new(Arc::new(default_parameters));

        let (send_status, receive_status) = postage::watch::channel();
        let send_status = Mutex::new(send_status);
        let receive_status = DirBootstrapEvents {
            inner: receive_status,
        };
        #[cfg(feature = "dirfilter")]
        let filter = config.extensions.filter.clone();

        // We create these early so the client code can access task_handle before bootstrap() returns.
        let (task_schedule, task_handle) = TaskSchedule::new(runtime.clone());
        let task_schedule = Mutex::new(Some(task_schedule));

        // We load the cached protocol recommendations unconditionally: the caller needs them even
        // if it does not try to load the reset of the cache.
        let protocols = {
            let store = store.store.lock().expect("lock poisoned");
            store
                .cached_protocol_recommendations()?
                .map(|(t, p)| (t, Arc::new(p)))
        };

        Ok(DirMgr {
            config: config.into(),
            store: store.store,
            netdir,
            protocols: Mutex::new(protocols),
            default_parameters,
            events,
            send_status,
            receive_status,
            circmgr,
            runtime,
            offline,
            bootstrap_started: AtomicBool::new(false),
            #[cfg(feature = "dirfilter")]
            filter,
            task_schedule,
            task_handle,
        })
    }

    /// Load the latest non-pending non-expired directory from the
    /// cache, if it is newer than the one we have.
    ///
    /// Return false if there is no such consensus.
    fn load_directory(self: &Arc<Self>, attempt_id: AttemptId) -> Result<bool> {
        let state = state::GetConsensusState::new(
            self.runtime.clone(),
            self.config.get(),
            CacheUsage::CacheOnly,
            None,
            #[cfg(feature = "dirfilter")]
            self.filter
                .clone()
                .unwrap_or_else(|| Arc::new(crate::filter::NilFilter)),
        );
        let _ = bootstrap::load(self, Box::new(state), attempt_id)?;

        Ok(self.netdir.get().is_some())
    }

    /// Return a new asynchronous stream that will receive notification
    /// whenever the consensus has changed.
    ///
    /// Multiple events may be batched up into a single item: each time
    /// this stream yields an event, all you can assume is that the event has
    /// occurred at least once.
    pub fn events(&self) -> impl futures::Stream<Item = DirEvent> + use<R> {
        self.events.subscribe()
    }

    /// Try to load the text of a single document described by `doc` from
    /// storage.
    pub fn text(&self, doc: &DocId) -> Result<Option<DocumentText>> {
        use itertools::Itertools;
        let mut result = HashMap::new();
        let query: DocQuery = (*doc).into();
        let store = self.store.lock().expect("store lock poisoned");
        query.load_from_store_into(&mut result, &**store)?;
        let item = result.into_iter().at_most_one().map_err(|_| {
            Error::CacheCorruption("Found more than one entry in storage for given docid")
        })?;
        if let Some((docid, doctext)) = item {
            if &docid != doc {
                return Err(Error::CacheCorruption(
                    "Item from storage had incorrect docid.",
                ));
            }
            Ok(Some(doctext))
        } else {
            Ok(None)
        }
    }

    /// Load the text for a collection of documents.
    ///
    /// If many of the documents have the same type, this can be more
    /// efficient than calling [`text`](Self::text).
    pub fn texts<T>(&self, docs: T) -> Result<HashMap<DocId, DocumentText>>
    where
        T: IntoIterator<Item = DocId>,
    {
        let partitioned = docid::partition_by_type(docs);
        let mut result = HashMap::new();
        let store = self.store.lock().expect("store lock poisoned");
        for (_, query) in partitioned.into_iter() {
            query.load_from_store_into(&mut result, &**store)?;
        }
        Ok(result)
    }

    /// Given a request we sent and the response we got from a
    /// directory server, see whether we should expand that response
    /// into "something larger".
    ///
    /// Currently, this handles expanding consensus diffs, and nothing
    /// else.  We do it at this stage of our downloading operation
    /// because it requires access to the store.
    pub(super) fn expand_response_text(&self, req: &ClientRequest, text: String) -> Result<String> {
        if let ClientRequest::Consensus(req) = req {
            if tor_consdiff::looks_like_diff(&text) {
                if let Some(old_d) = req.old_consensus_digests().next() {
                    let db_val = {
                        let s = self.store.lock().expect("Directory storage lock poisoned");
                        s.consensus_by_sha3_digest_of_signed_part(old_d)?
                    };
                    if let Some((old_consensus, meta)) = db_val {
                        info!("Applying a consensus diff");
                        let new_consensus = tor_consdiff::apply_diff(
                            old_consensus.as_str()?,
                            &text,
                            Some(*meta.sha3_256_of_signed()),
                        )?;
                        new_consensus.check_digest()?;
                        return Ok(new_consensus.to_string());
                    }
                }
                return Err(Error::Unwanted(
                    "Received a consensus diff we did not ask for",
                ));
            }
        }
        Ok(text)
    }

    /// If `state` has netdir changes to apply, apply them to our netdir.
    #[allow(clippy::cognitive_complexity)]
    pub(super) fn apply_netdir_changes(
        self: &Arc<Self>,
        state: &mut Box<dyn DirState>,
        store: &mut dyn Store,
    ) -> Result<()> {
        if let Some(change) = state.get_netdir_change() {
            match change {
                NetDirChange::AttemptReplace {
                    netdir,
                    consensus_meta,
                } => {
                    // Check the new netdir is sufficient, if we have a circmgr.
                    // (Unwraps are fine because the `Option` is `Some` until we take it.)
                    if let Some(ref cm) = self.circmgr {
                        if !cm
                            .netdir_is_sufficient(netdir.as_ref().expect("AttemptReplace had None"))
                        {
                            debug!("Got a new NetDir, but it doesn't have enough guards yet.");
                            return Ok(());
                        }
                    }
                    let is_stale = {
                        // Done inside a block to not hold a long-lived copy of the NetDir.
                        self.netdir
                            .get()
                            .map(|x| {
                                x.lifetime().valid_after()
                                    > netdir
                                        .as_ref()
                                        .expect("AttemptReplace had None")
                                        .lifetime()
                                        .valid_after()
                            })
                            .unwrap_or(false)
                    };
                    if is_stale {
                        warn!("Got a new NetDir, but it's older than the one we currently have!");
                        return Err(Error::NetDirOlder);
                    }
                    let cfg = self.config.get();
                    let mut netdir = netdir.take().expect("AttemptReplace had None");
                    netdir.replace_overridden_parameters(&cfg.override_net_params);
                    self.netdir.replace(netdir);
                    self.events.publish(DirEvent::NewConsensus);
                    self.events.publish(DirEvent::NewDescriptors);

                    info!("Marked consensus usable.");
                    if !store.is_readonly() {
                        store.mark_consensus_usable(consensus_meta)?;
                        // Now that a consensus is usable, older consensuses may
                        // need to expire.
                        store.expire_all(&crate::storage::EXPIRATION_DEFAULTS)?;
                    }
                    Ok(())
                }
                NetDirChange::AddMicrodescs(mds) => {
                    self.netdir.mutate(|netdir| {
                        for md in mds.drain(..) {
                            netdir.add_microdesc(md);
                        }
                        Ok(())
                    })?;
                    self.events.publish(DirEvent::NewDescriptors);
                    Ok(())
                }
                NetDirChange::SetRequiredProtocol { timestamp, protos } => {
                    if !store.is_readonly() {
                        store.update_protocol_recommendations(timestamp, protos.as_ref())?;
                    }
                    let mut pr = self.protocols.lock().expect("Poisoned lock");
                    *pr = Some((timestamp, protos));
                    self.events.publish(DirEvent::NewProtocolRecommendation);
                    Ok(())
                }
            }
        } else {
            Ok(())
        }
    }
}
