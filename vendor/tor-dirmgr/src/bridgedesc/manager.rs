use super::*;

impl<R: Runtime, M: Mockable<R>> BridgeDescMgr<R, M> {
    /// Actual constructor, which takes a mockable
    //
    // Allow passing `runtime` by value, which is usual API for this kind of setup function.
    #[allow(clippy::needless_pass_by_value)]
    pub(super) fn new_internal(
        runtime: R,
        circmgr: M::CircMgr,
        store: Arc<Mutex<DynStore>>,
        config: &BridgeDescDownloadConfig,
        dormancy: Dormancy,
        mockable: M,
    ) -> Result<Self, StartupError> {
        /// Convenience alias
        fn default<T: Default>() -> T {
            Default::default()
        }

        let config = config.clone().into();
        let (earliest_timeout, timeout_update) = postage::watch::channel();

        let state = Mutex::new(State {
            config,
            subscribers: default(),
            current: default(),
            running: default(),
            queued: default(),
            dormancy,
            retry_schedule: default(),
            refetch_schedule: default(),
            earliest_timeout,
        });
        let mgr = Arc::new(Manager {
            state,
            runtime: runtime.clone(),
            circmgr,
            store,
            mockable,
        });

        runtime
            .spawn(timeout_task(
                runtime.clone(),
                Arc::downgrade(&mgr),
                timeout_update,
            ))
            .map_err(|cause| StartupError::Spawn {
                spawning: "timeout task",
                cause: cause.into(),
            })?;

        Ok(BridgeDescMgr { mgr })
    }

    /// Consistency check convenience wrapper
    #[cfg(test)]
    fn check_consistency<'i, I>(&self, input_bridges: Option<I>)
    where
        I: IntoIterator<Item = &'i BridgeKey>,
    {
        self.mgr
            .lock_only()
            .check_consistency(&self.mgr.runtime, input_bridges);
    }

    /// Set whether this `BridgeDescMgr` is active
    // TODO this should instead be handled by a central mechanism; see TODO on Dormancy
    pub fn set_dormancy(&self, dormancy: Dormancy) {
        self.mgr.lock_then_process().dormancy = dormancy;
    }
}

impl<R: Runtime, M: Mockable<R>> BridgeDescProvider for BridgeDescMgr<R, M> {
    fn bridges(&self) -> Arc<BridgeDescList> {
        self.mgr.lock_only().current.clone()
    }

    fn events(&self) -> BoxStream<'static, BridgeDescEvent> {
        let stream = self.mgr.lock_only().subscribers.subscribe();
        Box::pin(stream) as _
    }

    fn set_bridges(&self, new_bridges: &[BridgeConfig]) {
        /// Helper: Called for each bridge that is currently Tracked.
        ///
        /// Checks if `new_bridges` has `bridge`.  If so, removes it from `new_bridges`,
        /// and returns `true`, indicating that this bridge should be kept.
        ///
        /// If not, returns `false`, indicating that this bridge should be removed,
        /// and logs a message.
        fn note_found_keep_p(
            new_bridges: &mut HashSet<BridgeKey>,
            bridge: &BridgeKey,
            was_state: &str,
        ) -> bool {
            let keep = new_bridges.remove(bridge);
            if !keep {
                debug!(r#"forgetting bridge ({}) "{}""#, was_state, bridge);
            }
            keep
        }

        /// Helper: filters `*_schedule` so that it contains only things in `new_bridges`,
        /// removing them as we go.
        fn filter_schedule<TT: Ord + Copy, RD>(
            new_bridges: &mut HashSet<BridgeKey>,
            schedule: &mut BinaryHeap<RefetchEntry<TT, RD>>,
            was_state: &str,
        ) {
            schedule.retain(|b| note_found_keep_p(new_bridges, &b.bridge, was_state));
        }

        let mut state = self.mgr.lock_then_process();
        let state = &mut **state;

        // We go through our own data structures, comparing them with `new_bridges`.
        // Entries in our own structures that aren't in `new_bridges` are removed.
        // Entries that *are* are removed from `new_bridges`.
        // Eventually `new_bridges` is just the list of new bridges to *add*.
        let mut new_bridges: HashSet<_> = new_bridges.iter().cloned().collect();

        // Is there anything in `current` that ought to be deleted?
        if state.current.keys().any(|b| !new_bridges.contains(b)) {
            // Found a bridge In `current` but not `new`
            // We need to remove it (and any others like it) from `current`.
            //
            // Disturbs the invariant *Schedules*:
            // After this maybe the schedules have entries they shouldn't.
            let current: BridgeDescList = state
                .current
                .iter()
                .filter(|(b, _)| new_bridges.contains(&**b))
                .map(|(b, v)| (b.clone(), v.clone()))
                .collect();
            state.set_current_and_notify(current);
        } else {
            // Nothing is being removed, so we can keep `current`.
        }
        // Bridges being newly requested will be added to `current`
        // later, after they have been fetched.

        // Is there anything in running we should abort?
        state.running.retain(|b, ri| {
            let keep = note_found_keep_p(&mut new_bridges, b, "was downloading");
            if !keep {
                ri.join.abort();
            }
            keep
        });

        // Is there anything in queued we should forget about?
        state
            .queued
            .retain(|qe| note_found_keep_p(&mut new_bridges, &qe.bridge, "was queued"));

        // Restore the invariant *Schedules*, that the schedules contain only things in current,
        // by removing the same things from the schedules that we earlier removed from current.
        filter_schedule(
            &mut new_bridges,
            &mut state.retry_schedule,
            "previously failed",
        );
        filter_schedule(
            &mut new_bridges,
            &mut state.refetch_schedule,
            "previously downloaded",
        );

        // OK now we have the list of bridges to add (if any).
        state.queued.extend(new_bridges.into_iter().map(|bridge| {
            debug!(r#" added bridge, queueing for download "{}""#, &bridge);
            QueuedEntry {
                bridge,
                retry_delay: None,
            }
        }));

        // `StateGuard`, from `lock_then_process`, gets dropped here, and runs `process`,
        // to make further progress and restore the liveness properties.
    }
}

impl<R: Runtime, M: Mockable<R>> Manager<R, M> {
    /// Obtain a lock on state, for functions that want to disrupt liveness properties
    ///
    /// When `StateGuard` is dropped, the liveness properties will be restored
    /// by making whatever progress is required.
    ///
    /// See [`State`].
    fn lock_then_process<'s>(self: &'s Arc<Self>) -> StateGuard<'s, R, M> {
        StateGuard {
            state: self.lock_only(),
            mgr: self,
        }
    }

    /// Obtains the lock on state.
    ///
    /// Caller ought not to modify state
    /// so as to invalidate invariants or liveness properties.
    /// Callers which are part of the algorithms in this crate
    /// ought to consider [`lock_then_process`](Manager::lock_then_process) instead.
    fn lock_only(&self) -> MutexGuard<State> {
        self.state.lock().expect("bridge desc manager poisoned")
    }
}

/// Writeable reference to [`State`], entitling the holder to disrupt liveness properties.
///
/// The holder must still maintain the invariants.
///
/// Obtained from [`Manager::lock_then_process`].  See [`State`].
#[derive(Educe, Deref, DerefMut)]
#[educe(Debug)]
struct StateGuard<'s, R: Runtime, M: Mockable<R>> {
    /// Reference to the mutable state
    #[deref]
    #[deref_mut]
    state: MutexGuard<'s, State>,

    /// Reference to the outer container
    ///
    /// Allows the holder to obtain a `'static` (owned) handle `Arc<Manager>`,
    /// for use by spawned tasks.
    #[educe(Debug(ignore))]
    mgr: &'s Arc<Manager<R, M>>,
}

impl<R: Runtime, M: Mockable<R>> Drop for StateGuard<'_, R, M> {
    fn drop(&mut self) {
        self.state.process(self.mgr);
    }
}

impl State {
    /// Ensure progress is made, by restoring all the liveness invariants
    ///
    /// This includes launching circuits as needed.
    fn process<R: Runtime, M: Mockable<R>>(&mut self, mgr: &Arc<Manager<R, M>>) {
        // Restore liveness property *Running*
        self.consider_launching(mgr);

        let now_wall = mgr.runtime.wallclock();

        // Mitigate clock warping
        //
        // If the earliest `SystemTime` is more than `max_refetch` away,
        // the clock must have warped.  If that happens we clamp
        // them all to `max_refetch`.
        //
        // (This is not perfect but will mitigate the worst effects by ensuring
        // that we do *something* at least every `max_refetch`, in the worst case,
        // other than just getting completely stuck.)
        let max_refetch_wall = now_wall + self.config.max_refetch;
        if self
            .refetch_schedule
            .peek()
            .map(|re| re.when > max_refetch_wall)
            == Some(true)
        {
            info!("bridge descriptor manager: clock warped, clamping refetch times");
            self.refetch_schedule = self
                .refetch_schedule
                .drain()
                .map(|mut re| {
                    re.when = max_refetch_wall;
                    re
                })
                .collect();
        }

        // Restore liveness property *Timeout**
        // postage::watch will tell up the timeout task about the new wake-up time.
        let new_earliest_timeout = [
            // First retry.  These are std Instant.
            self.retry_schedule.peek().map(|re| re.when),
            // First refetch.  These are SystemTime, so we must convert them.
            self.refetch_schedule.peek().map(|re| {
                // If duration_since gives Err, that means when is before now,
                // ie we should not be waiting: the wait duration should be 0.
                let wait = re.when.duration_since(now_wall).unwrap_or_default();

                mgr.runtime.now() + wait
            }),
        ]
        .into_iter()
        .flatten()
        .min();
        *self.earliest_timeout.borrow_mut() = new_earliest_timeout;
    }

    /// Launch download attempts if we can
    ///
    /// Specifically: if we have things in `queued`, and `running` is shorter than
    /// `effective_parallelism()`, we launch task(s) to attempt download(s).
    ///
    /// Restores liveness invariant *Running*.
    ///
    /// Idempotent.  Forms part of `process`.
    #[allow(clippy::blocks_in_conditions)]
    fn consider_launching<R: Runtime, M: Mockable<R>>(&mut self, mgr: &Arc<Manager<R, M>>) {
        let mut to_remove = vec![];

        while self.running.len() < self.effective_parallelism() {
            let QueuedEntry {
                bridge,
                retry_delay,
            } = match self.queued.pop_front() {
                Some(qe) => qe,
                None => break,
            };
            match mgr
                .runtime
                .spawn({
                    let config = self.config.clone();
                    let bridge = bridge.clone();
                    let inner = mgr.clone();
                    let mockable = inner.mockable.clone();

                    // The task which actually downloads a descriptor.
                    async move {
                        let got =
                            AssertUnwindSafe(inner.download_descriptor(mockable, &bridge, &config))
                                .catch_unwind()
                                .await
                                .unwrap_or_else(|_| {
                                    Err(internal!("download descriptor task panicked!").into())
                                });
                        match &got {
                            Ok(_) => debug!(r#"download succeeded for "{}""#, bridge),
                            Err(err) => debug!(r#"download failed for "{}": {}"#, bridge, err),
                        };
                        let mut state = inner.lock_then_process();
                        state.record_download_outcome(bridge, got);
                        // `StateGuard`, from `lock_then_process`, gets dropped here, and runs `process`,
                        // to make further progress and restore the liveness properties.
                    }
                })
                .map(|()| JoinHandle)
            {
                Ok(join) => {
                    self.running
                        .insert(bridge, RunningInfo { join, retry_delay });
                }
                Err(_) => {
                    // Spawn failed.
                    //
                    // We are going to forget about this bridge.
                    // And we're going to do that without notifying anyone.
                    // We *do* want to remove it from `current` because simply forgetting
                    // about a refetch could leave expired data there.
                    // We amortize this, so we don't do a lot of O(n^2) work on shutdown.
                    to_remove.push(bridge);
                }
            }
        }

        if !to_remove.is_empty() {
            self.modify_current(|current| {
                for bridge in to_remove {
                    current.remove(&bridge);
                }
            });
        }
    }

    /// Modify `current` and notify subscribers
    ///
    /// Helper function which modifies only `current`, not any of the rest of the state.
    /// it is the caller's responsibility to ensure that the invariants are upheld.
    ///
    /// The implementation actually involves cloning `current`,
    /// so it is best to amortize calls to this function.
    fn modify_current<T, F: FnOnce(&mut BridgeDescList) -> T>(&mut self, f: F) -> T {
        let mut current = (*self.current).clone();
        let r = f(&mut current);
        self.set_current_and_notify(current);
        r
    }

    /// Set `current` to a value and notify
    ///
    /// Helper function which modifies only `current`, not any of the rest of the state.
    /// it is the caller's responsibility to ensure that the invariants are upheld.
    fn set_current_and_notify<BDL: Into<Arc<BridgeDescList>>>(&mut self, new: BDL) {
        self.current = new.into();
        self.subscribers.publish(BridgeDescEvent::SomethingChanged);
    }

    /// Obtain the currently-desired level of parallelism
    ///
    /// Helper function.  The return value depends the mutable state and also the `config`.
    ///
    /// This is how we implement dormancy.
    fn effective_parallelism(&self) -> usize {
        match self.dormancy {
            Dormancy::Active => usize::from(u8::from(self.config.parallelism)),
            Dormancy::Dormant => 0,
        }
    }
}

impl<R: Runtime, M: Mockable<R>> StateGuard<'_, R, M> {
    /// Record a download outcome.
    ///
    /// Final act of the descriptor download task.
    /// `got` is from [`download_descriptor`](Manager::download_descriptor).
    fn record_download_outcome(&mut self, bridge: BridgeKey, got: Result<Downloaded, Error>) {
        let RunningInfo { retry_delay, .. } = match self.running.remove(&bridge) {
            Some(ri) => ri,
            None => {
                debug!("bridge descriptor download completed for no-longer-configured bridge");
                return;
            }
        };

        let insert = match got {
            Ok(Downloaded { desc, refetch }) => {
                // Successful download.  Schedule the refetch, and we'll insert Ok.

                self.refetch_schedule.push(RefetchEntry {
                    when: refetch,
                    bridge: bridge.clone(),
                    retry_delay: (),
                });

                Ok(desc)
            }
            Err(err) => {
                // Failed.  Schedule the retry, and we'll insert Err.

                let mut retry_delay =
                    retry_delay.unwrap_or_else(|| RetryDelay::from_duration(self.config.retry));

                let retry = err.retry_time();
                // We retry at least as early as
                let now = self.mgr.runtime.now();
                let retry = retry.absolute(now, || retry_delay.next_delay(&mut rand::rng()));
                // Retry at least as early as max_refetch.  That way if a bridge is
                // misconfigured we will see it be fixed eventually.
                let retry = {
                    let earliest = now;
                    let latest = || now + self.config.max_refetch;
                    match retry {
                        AbsRetryTime::Immediate => earliest,
                        AbsRetryTime::Never => latest(),
                        AbsRetryTime::At(i) => i.clamp(earliest, latest()),
                    }
                };
                self.retry_schedule.push(RefetchEntry {
                    when: retry,
                    bridge: bridge.clone(),
                    retry_delay,
                });

                Err(Box::new(err) as _)
            }
        };

        self.modify_current(|current| current.insert(bridge, insert));
    }
}

impl<R: Runtime, M: Mockable<R>> Manager<R, M> {
    /// Downloads a descriptor.
    ///
    /// The core of the descriptor download task
    /// launched by `State::consider_launching`.
    ///
    /// Uses Mockable::download to actually get the document.
    /// So most of this function is parsing and checking.
    ///
    /// The returned value is precisely the `got` input to
    /// [`record_download_outcome`](StateGuard::record_download_outcome).
    async fn download_descriptor(
        &self,
        mockable: M,
        bridge: &BridgeConfig,
        config: &BridgeDescDownloadConfig,
    ) -> Result<Downloaded, Error> {
        // convenience alias, capturing the usual parameters from our variables.
        let process_document = |text| process_document(&self.runtime, config, text);

        let store = || {
            self.store
                .lock()
                .map_err(|_| internal!("bridge descriptor store poisoned"))
        };

        let cache_entry: Option<CachedBridgeDescriptor> = (|| store()?.lookup_bridgedesc(bridge))()
            .unwrap_or_else(|err| {
                error_report!(
                    err,
                    r#"bridge descriptor cache lookup failed, for "{}""#,
                    sensitive(bridge),
                );
                None
            });

        let now = self.runtime.wallclock();
        let cached_good: Option<Downloaded> = if let Some(cached) = &cache_entry {
            if cached.fetched > now {
                // was fetched "in the future"
                None
            } else {
                // let's see if it's any use
                match process_document(&cached.document) {
                    Err(err) => {
                        // We had a doc in the cache but our attempt to use it failed
                        // We wouldn't have written a bad cache entry.
                        // So one of the following must be true:
                        //  * We were buggy or are stricter now or something
                        //  * The document was valid but its validity time has expired
                        // In any case we can't reuse it.
                        // (This happens in normal operation, when a document expires.)
                        trace!(r#"cached document for "{}" invalid: {}"#, &bridge, err);
                        None
                    }
                    Ok(got) => {
                        // The cached document looks valid.
                        // But how long ago did we fetch it?
                        // We need to enforce max_refresh even for still-valid documents.
                        if now.duration_since(cached.fetched).ok() <= Some(config.max_refetch) {
                            // Was fetched recently, too.  We can just reuse it.
                            return Ok(got);
                        }
                        Some(got)
                    }
                }
            }
        } else {
            None
        };

        // If cached_good is Some, we found a plausible cache entry; if we got here, it was
        // past its max_refresh.  So in that case we want to send a request with
        // if-modified-since.  If we get Not Modified, we can reuse it (and update the fetched time).
        let if_modified_since = cached_good
            .as_ref()
            .map(|got| got.desc.as_ref().published());

        debug!(
            r#"starting download for "{}"{}"#,
            bridge,
            match if_modified_since {
                Some(ims) => format!(
                    " if-modified-since {}",
                    humantime::format_rfc3339_seconds(ims),
                ),
                None => "".into(),
            }
        );

        let text = mockable
            .clone()
            .download(&self.runtime, &self.circmgr, bridge, if_modified_since)
            .await?;

        let (document, got) = if let Some(text) = text {
            let got = process_document(&text)?;
            (text, got)
        } else if let Some(cached) = cached_good {
            (
                cache_entry
                    .expect("cached_good but not cache_entry")
                    .document,
                cached,
            )
        } else {
            return Err(internal!("download gave None but no if-modified-since").into());
        };

        // IEFI catches cache store errors, which we log but don't do anything else with
        (|| {
            let cached = CachedBridgeDescriptor {
                document,
                fetched: now, // this is from before we started the fetch, which is correct
            };

            // Calculate when the cache should forget about this.
            // We want to add a bit of slop for the purposes of mild clock skew handling,
            // etc., and the prefetch time is a good proxy for that.
            let until = got
                .refetch
                .checked_add(config.prefetch)
                .unwrap_or(got.refetch /*uh*/);

            store()?.store_bridgedesc(bridge, cached, until)?;
            Ok(())
        })()
        .unwrap_or_else(|err: crate::Error| {
            error_report!(err, "failed to cache downloaded bridge descriptor",);
        });

        Ok(got)
    }
}

/// Processes and analyses a textual descriptor document into a `Downloaded`
///
/// Parses it, checks the signature, checks the document validity times,
/// and if that's all good, calculates when will want to refetch it.
fn process_document<R: Runtime>(
    runtime: &R,
    config: &BridgeDescDownloadConfig,
    text: &str,
) -> Result<Downloaded, Error> {
    let desc = RouterDesc::parse(text)?;

    // We *could* just trust this because we have trustworthy provenance
    // we know that the channel machinery authenticated the identity keys in `bridge`.
    // But let's do some cross-checking anyway.
    // `check_signature` checks the self-signature.
    let desc = desc.check_signature().map_err(Arc::new)?;

    let now = runtime.wallclock();
    desc.is_valid_at(&now)?;

    // Justification that use of "dangerously" is correct:
    // 1. We have checked this just above, so it is valid now.
    // 2. We are extracting the timeout and implement our own refetch logic using expires.
    let (desc, (_, expires)) = desc.dangerously_into_parts();

    // Our refetch schedule, and enforcement of descriptor expiry, is somewhat approximate.
    // The following situations can result in a nominally-expired descriptor being used:
    //
    // 1. We primarily enforce the timeout by looking at the expiry time,
    //    subtracting a configured constant, and scheduling the start of a refetch then.
    //    If it takes us longer to do the retry, than the prefetch constant,
    //    we'll still be providing the old descriptor to consumers in the meantime.
    //
    // 2. We apply a minimum time before we will refetch a descriptor.
    //    So if the validity time is unreasonably short, we'll use it beyond that time.
    //
    // 3. Clock warping could confuse this algorithm.  This is inevitable because we
    //    are relying on calendar times (SystemTime) in the descriptor, and because
    //    we don't have a mechanism for being told about clock warps rather than the
    //    passage of time.
    //
    // We think this is all OK given that a bridge descriptor is used for trying to
    // connect to the bridge itself.  In particular, we don't want to completely trust
    // bridges to control our retry logic.
    let refetch = match expires {
        Some(expires) => expires
            .checked_sub(config.prefetch)
            .ok_or(Error::ExtremeValidityTime)?,

        None => now
            .checked_add(config.max_refetch)
            .ok_or(Error::ExtremeValidityTime)?,
    };
    let refetch = refetch.clamp(now + config.min_refetch, now + config.max_refetch);

    let desc = BridgeDesc::new(Arc::new(desc));

    Ok(Downloaded { desc, refetch })
}

/// Task which waits for the timeout, and requeues bridges that need to be refetched
///
/// This task's job is to execute the wakeup instructions provided via `updates`.
///
/// `updates` is the receiving end of [`State`]'s `earliest_timeout`,
/// which is maintained to be the earliest time any of the schedules says we should wake up
/// (liveness property *Timeout*).
async fn timeout_task<R: Runtime, M: Mockable<R>>(
    runtime: R,
    inner: Weak<Manager<R, M>>,
    update: postage::watch::Receiver<Option<Instant>>,
) {
    /// Requeue things in `*_schedule` whose time for action has arrived
    ///
    /// `retry_delay_map` converts `retry_delay` from the schedule (`RetryDelay` or `()`)
    /// into the `Option` which appears in [`QueuedEntry`].
    ///
    /// Helper function.  Idempotent.
    fn requeue_as_required<TT: Ord + Copy + Debug, RD, RDM: Fn(RD) -> Option<RetryDelay>>(
        queued: &mut VecDeque<QueuedEntry>,
        schedule: &mut BinaryHeap<RefetchEntry<TT, RD>>,
        now: TT,
        retry_delay_map: RDM,
    ) {
        while let Some(ent) = schedule.peek() {
            if ent.when > now {
                break;
            }
            let re = schedule.pop().expect("schedule became empty!");
            let bridge = re.bridge;
            let retry_delay = retry_delay_map(re.retry_delay);

            queued.push_back(QueuedEntry {
                bridge,
                retry_delay,
            });
        }
    }

    let mut next_wakeup = Some(runtime.now());
    let mut update = update.fuse();
    loop {
        select! {
            // Someone modified the schedules, and sent us a new earliest timeout
            changed = update.next() => {
                // changed is Option<Option< >>.
                // The outer Option is from the Stream impl for watch::Receiver - None means EOF.
                // The inner Option is Some(wakeup_time), or None meaning "wait indefinitely"
                next_wakeup = if let Some(changed) = changed {
                    changed
                } else {
                    // Oh, actually, the watch::Receiver is EOF - we're to shut down
                    break
                }
            },

            // Wait until the specified earliest wakeup time
            () = async {
                if let Some(next_wakeup) = next_wakeup {
                    let now = runtime.now();
                    if next_wakeup > now {
                        let duration = next_wakeup - now;
                        runtime.sleep(duration).await;
                    }
                } else {
                    #[allow(clippy::semicolon_if_nothing_returned)] // rust-clippy/issues/9729
                    { future::pending().await }
                }
            }.fuse() => {
                // We have reached the pre-programmed time.  Check what needs doing.

                let inner = if let Some(i) = inner.upgrade() { i } else { break; };
                let mut state = inner.lock_then_process();
                let state = &mut **state; // Do the DerefMut once so we can borrow fields

                requeue_as_required(
                    &mut state.queued,
                    &mut state.refetch_schedule,
                    runtime.wallclock(),
                    |()| None,
                );

                requeue_as_required(
                    &mut state.queued,
                    &mut state.retry_schedule,
                    runtime.now(),
                    Some,
                );

                // `StateGuard`, from `lock_then_process`, gets dropped here, and runs `process`,
                // to make further progress and restore the liveness properties.
            }
        }
    }
}
