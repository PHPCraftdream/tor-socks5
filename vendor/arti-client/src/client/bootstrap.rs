use super::*;

impl StreamPrefs {
    /// Construct a new StreamPrefs.
    pub fn new() -> Self {
        Self::default()
    }

    /// Indicate that a stream may be made over IPv4 or IPv6, but that
    /// we'd prefer IPv6.
    pub fn ipv6_preferred(&mut self) -> &mut Self {
        self.ip_ver_pref = IpVersionPreference::Ipv6Preferred;
        self
    }

    /// Indicate that a stream may only be made over IPv6.
    ///
    /// When this option is set, we will only pick exit relays that
    /// support IPv6, and we will tell them to only give us IPv6
    /// connections.
    pub fn ipv6_only(&mut self) -> &mut Self {
        self.ip_ver_pref = IpVersionPreference::Ipv6Only;
        self
    }

    /// Indicate that a stream may be made over IPv4 or IPv6, but that
    /// we'd prefer IPv4.
    ///
    /// This is the default.
    pub fn ipv4_preferred(&mut self) -> &mut Self {
        self.ip_ver_pref = IpVersionPreference::Ipv4Preferred;
        self
    }

    /// Indicate that a stream may only be made over IPv4.
    ///
    /// When this option is set, we will only pick exit relays that
    /// support IPv4, and we will tell them to only give us IPv4
    /// connections.
    pub fn ipv4_only(&mut self) -> &mut Self {
        self.ip_ver_pref = IpVersionPreference::Ipv4Only;
        self
    }

    /// Indicate that a stream should appear to come from the given country.
    ///
    /// When this option is set, we will only pick exit relays that
    /// have an IP address that matches the country in our GeoIP database.
    #[cfg(feature = "geoip")]
    pub fn exit_country(&mut self, country_code: CountryCode) -> &mut Self {
        self.country_code = Some(country_code);
        self
    }

    /// Indicate that we don't care which country a stream appears to come from.
    ///
    /// This is available even in the case where GeoIP support is compiled out,
    /// to make things easier.
    pub fn any_exit_country(&mut self) -> &mut Self {
        #[cfg(feature = "geoip")]
        {
            self.country_code = None;
        }
        self
    }

    /// Indicate that the stream should be opened "optimistically".
    ///
    /// By default, streams are not "optimistic". When you call
    /// [`TorClient::connect()`], it won't give you a stream until the
    /// exit node has confirmed that it has successfully opened a
    /// connection to your target address.  It's safer to wait in this
    /// way, but it is slower: it takes an entire round trip to get
    /// your confirmation.
    ///
    /// If a stream _is_ configured to be "optimistic", on the other
    /// hand, then `TorClient::connect()` will return the stream
    /// immediately, without waiting for an answer from the exit.  You
    /// can start sending data on the stream right away, though of
    /// course this data will be lost if the connection is not
    /// actually successful.
    pub fn optimistic(&mut self) -> &mut Self {
        self.optimistic_stream = true;
        self
    }

    /// Return true if this stream has been configured as "optimistic".
    ///
    /// See [`StreamPrefs::optimistic`] for more info.
    pub fn is_optimistic(&self) -> bool {
        self.optimistic_stream
    }

    /// Indicate whether connection to a hidden service (`.onion` service) should be allowed
    ///
    /// If `Explicit(false)`, attempts to connect to Onion Services will be forced to fail with
    /// an error of kind [`InvalidStreamTarget`](crate::ErrorKind::InvalidStreamTarget).
    ///
    /// If `Explicit(true)`, Onion Service connections are enabled.
    ///
    /// If `Auto`, the behaviour depends on the `address_filter.allow_onion_addrs`
    /// configuration option, which is in turn enabled by default.
    #[cfg(feature = "onion-service-client")]
    pub fn connect_to_onion_services(
        &mut self,
        connect_to_onion_services: BoolOrAuto,
    ) -> &mut Self {
        self.connect_to_onion_services = connect_to_onion_services;
        self
    }
    /// Return a TargetPort to describe what kind of exit policy our
    /// target circuit needs to support.
    pub(super) fn wrap_target_port(&self, port: u16) -> TargetPort {
        match self.ip_ver_pref {
            IpVersionPreference::Ipv6Only => TargetPort::ipv6(port),
            _ => TargetPort::ipv4(port),
        }
    }

    /// Return a new StreamParameters based on this configuration.
    pub(super) fn stream_parameters(&self) -> StreamParameters {
        let mut params = StreamParameters::default();
        params
            .ip_version(self.ip_ver_pref)
            .optimistic(self.optimistic_stream);
        params
    }

    /// Indicate that connections with these preferences should have their own isolation group
    ///
    /// This is a convenience method which creates a fresh [`IsolationToken`]
    /// and sets it for these preferences.
    ///
    /// This connection preference is orthogonal to isolation established by
    /// [`TorClient::isolated_client`].  Connections made with an `isolated_client`
    ///  will not share circuits with the original client, even if the same
    /// `isolation` is specified via the `ConnectionPrefs` in force.
    pub fn new_isolation_group(&mut self) -> &mut Self {
        self.isolation = StreamIsolationPreference::Explicit(Box::new(IsolationToken::new()));
        self
    }

    /// Indicate which other connections might use the same circuit
    /// as this one.
    ///
    /// By default all connections made on a `TorClient` may share connections.
    /// Connections made with a particular `isolation` may share circuits with each other.
    ///
    /// This connection preference is orthogonal to isolation established by
    /// [`TorClient::isolated_client`].  Connections made with an `isolated_client`
    /// will not share circuits with the original client, even if the same
    /// `isolation` is specified via the `ConnectionPrefs` in force.
    pub fn set_isolation<T>(&mut self, isolation: T) -> &mut Self
    where
        T: Into<Box<dyn Isolation>>,
    {
        self.isolation = StreamIsolationPreference::Explicit(isolation.into());
        self
    }

    /// Indicate that no connection should share a circuit with any other.
    ///
    /// **Use with care:** This is likely to have poor performance, and imposes a much greater load
    /// on the Tor network.  Use this option only to make small numbers of connections each of
    /// which needs to be isolated from all other connections.
    ///
    /// (Don't just use this as a "get more privacy!!" method: the circuits
    /// that it put connections on will have no more privacy than any other
    /// circuits.  The only benefit is that these circuits will not be shared
    /// by multiple streams.)
    ///
    /// This can be undone by calling `set_isolation` or `new_isolation_group` on these
    /// preferences.
    pub fn isolate_every_stream(&mut self) -> &mut Self {
        self.isolation = StreamIsolationPreference::EveryStream;
        self
    }

    /// Return an [`Isolation`] which separates according to these `StreamPrefs` (only)
    ///
    /// This describes which connections or operations might use
    /// the same circuit(s) as this one.
    ///
    /// Since this doesn't have access to the `TorClient`,
    /// it doesn't separate streams which ought to be separated because of
    /// the way their `TorClient`s are isolated.
    /// For that, use [`TorClient::isolation`].
    pub(super) fn prefs_isolation(&self) -> Option<Box<dyn Isolation>> {
        use StreamIsolationPreference as SIP;
        match self.isolation {
            SIP::None => None,
            SIP::Explicit(ref ig) => Some(ig.clone()),
            SIP::EveryStream => Some(Box::new(IsolationToken::new())),
        }
    }

    // TODO: Add some way to be IPFlexible, and require exit to support both.
}

#[cfg(all(
    any(feature = "native-tls", feature = "rustls"),
    any(feature = "async-std", feature = "tokio")
))]
impl TorClient<PreferredRuntime> {
    /// Bootstrap a connection to the Tor network, using the provided `config`.
    ///
    /// Returns a client once there is enough directory material to
    /// connect safely over the Tor network.
    ///
    /// Consider using [`TorClient::builder`] for more fine-grained control.
    ///
    /// # Panics
    ///
    /// If Tokio is being used (the default), panics if created outside the context of a currently
    /// running Tokio runtime. See the documentation for [`PreferredRuntime::current`] for
    /// more information.
    ///
    /// If using `async-std`, either take care to ensure Arti is not compiled with Tokio support,
    /// or manually create an `async-std` runtime using [`tor_rtcompat`] and use it with
    /// [`TorClient::with_runtime`].
    ///
    /// # Do not fork
    ///
    /// The process [**may not fork**](tor_rtcompat#do-not-fork)
    /// (except, very carefully, before exec)
    /// after calling this function, because it creates a [`PreferredRuntime`].
    pub async fn create_bootstrapped(config: TorClientConfig) -> crate::Result<Arc<Self>> {
        let runtime = PreferredRuntime::current()
            .expect("TorClient could not get an asynchronous runtime; are you running in the right context?");

        Self::with_runtime(runtime)
            .config(config)
            .create_bootstrapped()
            .await
    }

    /// Return a new builder for creating TorClient objects.
    ///
    /// If you want to make a [`TorClient`] synchronously, this is what you want; call
    /// `TorClientBuilder::create_unbootstrapped` on the returned builder.
    ///
    /// # Panics
    ///
    /// If Tokio is being used (the default), panics if created outside the context of a currently
    /// running Tokio runtime. See the documentation for `tokio::runtime::Handle::current` for
    /// more information.
    ///
    /// If using `async-std`, either take care to ensure Arti is not compiled with Tokio support,
    /// or manually create an `async-std` runtime using [`tor_rtcompat`] and use it with
    /// [`TorClient::with_runtime`].
    ///
    /// # Do not fork
    ///
    /// The process [**may not fork**](tor_rtcompat#do-not-fork)
    /// (except, very carefully, before exec)
    /// after calling this function, because it creates a [`PreferredRuntime`].
    pub fn builder() -> TorClientBuilder<PreferredRuntime> {
        let runtime = PreferredRuntime::current()
            .expect("TorClient could not get an asynchronous runtime; are you running in the right context?");

        TorClientBuilder::new(runtime)
    }
}

impl<R: Runtime> TorClient<R> {
    /// Return a new builder for creating TorClient objects, with a custom provided [`Runtime`].
    ///
    /// See the [`tor_rtcompat`] crate for more information on custom runtimes.
    pub fn with_runtime(runtime: R) -> TorClientBuilder<R> {
        TorClientBuilder::new(runtime)
    }

    /// Implementation of `create_unbootstrapped`, split out in order to avoid manually specifying
    /// double error conversions.
    #[instrument(skip_all, level = "trace")]
    pub(crate) fn create_impl(
        runtime: R,
        config: &TorClientConfig,
        autobootstrap: BootstrapBehavior,
        dirmgr_builder: Arc<dyn crate::builder::DirProviderBuilder<R>>,
        dirmgr_extensions: tor_dirmgr::config::DirMgrExtensions,
        // tor-socks5 local patch: observability hook for the fatal shutdown.
        fatal_protocol_error_handler: Option<Arc<dyn crate::builder::FatalProtocolErrorHandler>>,
    ) -> StdResult<Arc<Self>, ErrorDetail> {
        if crate::util::running_as_setuid() {
            return Err(tor_error::bad_api_usage!(
                "Arti does not support running in a setuid or setgid context."
            )
            .into());
        }

        let memquota = MemoryQuotaTracker::new(&runtime, config.system.memory.clone())?;

        let path_resolver = Arc::new(config.path_resolver.clone());

        let (state_dir, mistrust) = config.state_dir()?;
        #[cfg(feature = "onion-service-service")]
        let state_directory =
            StateDirectory::new(&state_dir, mistrust).map_err(ErrorDetail::StateAccess)?;

        let dormant = DormantMode::Normal;

        let statemgr = Self::statemgr_from_config(config)?;

        // Try to take state ownership early, so we'll know if we have it.
        // Note that this `try_lock()` may return `Ok` even if we can't acquire the lock.
        // (At this point we don't yet care if we have it.)
        let _ignore_status = statemgr.try_lock().map_err(ErrorDetail::StateMgrSetup)?;

        let addr_cfg = config.address_filter.clone();

        let (status_sender, status_receiver) = postage::watch::channel();
        let status_receiver = status::BootstrapEvents {
            inner: status_receiver,
        };
        let timeout_cfg = config.stream_timeouts.clone();

        let (dormant_send, dormant_recv) = postage::watch::channel_with(Some(dormant));
        let dormant_send = DropNotifyWatchSender::new(dormant_send);
        let client_isolation = IsolationToken::new();
        let inert_client = InertTorClient::new(config)?;

        let dirmgr_store = DirMgrStore::new(&config.dir_mgr_config()?, runtime.clone(), false)
            .map_err(ErrorDetail::DirMgrSetup)?;

        let inner = Box::new(NotConstructedInner {
            config: config.clone(),
            dormant_recv,
            status_sender,
            dirmgr_builder,
            dirmgr_extensions,
            // tor-socks5 local patch: forward the observability hook.
            fatal_protocol_error_handler,
        });

        let inner = Mutex::new(Inner::NotConstructed(inner));

        let client = Arc::new(ClientShared {
            runtime,
            inner,
            memquota,
            inert_client,
            statemgr,
            dirmgr_store,
            addrcfg: addr_cfg.into(),
            timeoutcfg: timeout_cfg.into(),
            reconfigure_lock: Arc::new(Mutex::new(())),
            status_receiver,
            bootstrap_in_progress: AsyncMutex::new(()),
            should_bootstrap: autobootstrap,
            dormant: Mutex::new(dormant_send),
            #[cfg(feature = "onion-service-service")]
            state_directory,
            path_resolver,
        });

        Ok(Arc::new(TorClient {
            client_isolation,
            connect_prefs: Default::default(),
            client,
        }))
    }

    /// Construct a state manager from the client configuration.
    fn statemgr_from_config(config: &TorClientConfig) -> Result<UsingStateMgr, ErrorDetail> {
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        {
            use tor_persist::FsStateMgr;

            let (state_dir, mistrust) = config.state_dir()?;
            FsStateMgr::from_path_and_mistrust(state_dir, mistrust)
                .map_err(ErrorDetail::StateMgrSetup)
        }
        #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
        {
            unimplemented!()
        }
    }

    /// Bootstrap a connection to the Tor network, with a client created by `create_unbootstrapped`.
    ///
    /// Returns once there is enough directory material to connect safely over the Tor network.
    /// If the client has already been bootstrapped, returns immediately with
    /// success. If a bootstrap is in progress, waits for it to finish, then retries it if it
    /// failed (returning success if it succeeded).
    ///
    /// Bootstrap progress can be tracked by listening to the event receiver returned by
    /// [`bootstrap_events`](TorClient::bootstrap_events).
    ///
    /// # Failures
    ///
    /// If the bootstrapping process fails, returns an error. This function can safely be called
    /// again later to attempt to bootstrap another time.
    #[instrument(skip_all, level = "trace")]
    pub async fn bootstrap(&self) -> crate::Result<()> {
        self.client
            .bootstrap_inner()
            .await
            .map_err(ErrorDetail::into)
    }
}

impl<R: Runtime> NotConstructedInner<R> {
    /// Replace the configuration for this unconstructed client.
    ///
    /// Since most of the client's internals are not yet constructed,
    /// we can still replace nearly all of the items.
    pub(super) fn reconfigure(
        &mut self,
        new_config: &TorClientConfig,
        how: tor_config::Reconfigure,
    ) -> StdResult<(), ErrorDetail> {
        // We _do_ have to check the cache_dir, since we can't and won't change that
        // while we're running.
        // (We already checked the state_dir in ClientShared::reconfigure_inner.)
        if new_config.storage.cache_dir != self.config.storage.cache_dir {
            how.cannot_change("storage.cache_dir")?;
        }

        if how == tor_config::Reconfigure::CheckAllOrNothing {
            return Ok(());
        }

        self.config = new_config.clone();

        Ok(())
    }
}

/// tor-socks5 local patch: invoke the (optional) fatal-protocol-error hook
/// with the public [`Error`](crate::Error) view of the fatal shutdown cause.
/// Separated from the inline `on_fatal` closure above so the hook-firing
/// logic can be unit-tested without dragging in `std::process::exit`.
pub(crate) fn notify_fatal_protocol_error(
    hook: &Option<Arc<dyn crate::builder::FatalProtocolErrorHandler>>,
    error: &crate::Error,
) {
    if let Some(hook) = hook {
        hook.on_fatal_protocol_error(error);
    }
}

impl<R: Runtime> RunningInner<R> {
    /// Construct a new [`RunningInner`] and launch its associated tasks.
    pub(super) fn new(
        pending: NotConstructedInner<R>,
        client: &ClientShared<R>,
    ) -> StdResult<Arc<Self>, ErrorDetail> {
        let NotConstructedInner {
            config,
            dormant_recv,
            status_sender,
            dirmgr_builder,
            dirmgr_extensions,
            // tor-socks5 local patch: observability hook for the fatal shutdown.
            fatal_protocol_error_handler,
        } = pending;

        let runtime = client.runtime.clone();
        let dormant = dormant_recv
            .borrow()
            .expect("Client somehow dropped while creating RunningInner");
        let memquota = &client.memquota;
        let statemgr = &client.statemgr;
        let path_resolver = &client.path_resolver;
        let (state_dir, _) = config.state_dir()?;

        let chanmgr = Arc::new(
            tor_chanmgr::ChanMgr::new(
                runtime.clone(),
                ChanMgrConfig::new(config.channel.clone()),
                dormant.into(),
                &NetParameters::from_map(&config.override_net_params),
                memquota.clone(),
            )
            .map_err(ErrorDetail::ChanMgrSetup)?,
        );
        let guardmgr = tor_guardmgr::GuardMgr::new(runtime.clone(), statemgr.clone(), &config)
            .map_err(ErrorDetail::GuardMgrSetup)?;

        #[cfg(feature = "pt-client")]
        let pt_mgr = {
            let pt_state_dir = state_dir.as_path().join("pt_state");
            config.storage.permissions().make_directory(&pt_state_dir)?;

            let mgr = Arc::new(tor_ptmgr::PtMgr::new(
                config.bridges.transports.clone(),
                pt_state_dir,
                Arc::clone(path_resolver),
                config.channel.outbound_proxy().cloned(),
                runtime.clone(),
            )?);

            chanmgr.set_pt_mgr(mgr.clone());

            mgr
        };

        let circmgr = Arc::new(
            tor_circmgr::CircMgr::new(
                &config,
                statemgr.clone(),
                &runtime,
                Arc::clone(&chanmgr),
                &guardmgr,
            )
            .map_err(ErrorDetail::CircMgrSetup)?,
        );

        let dir_cfg = {
            let mut c: tor_dirmgr::DirMgrConfig = config.dir_mgr_config()?;
            c.extensions = dirmgr_extensions;
            c
        };
        let dirmgr = dirmgr_builder
            .build(
                runtime.clone(),
                client.dirmgr_store.clone(),
                Arc::clone(&circmgr),
                dir_cfg,
            )
            .map_err(crate::Error::into_detail)?;

        let mut periodic_task_handles = circmgr
            .launch_background_tasks(&runtime, &dirmgr, statemgr.clone())
            .map_err(ErrorDetail::CircMgrSetup)?;
        periodic_task_handles.extend(dirmgr.download_task_handle());

        periodic_task_handles.extend(
            chanmgr
                .launch_background_tasks(&runtime, dirmgr.clone().upcast_arc())
                .map_err(ErrorDetail::ChanMgrSetup)?,
        );

        #[cfg(feature = "bridge-client")]
        // TODO: We can just construct this.
        let bridge_desc_mgr = Arc::new(Mutex::new(None));

        #[cfg(any(feature = "onion-service-client", feature = "onion-service-service"))]
        let hs_circ_pool = {
            let circpool = Arc::new(tor_circmgr::hspool::HsCircPool::new(&circmgr));
            circpool
                .launch_background_tasks(&runtime, &dirmgr.clone().upcast_arc())
                .map_err(ErrorDetail::CircMgrSetup)?;
            circpool
        };

        #[cfg(feature = "onion-service-client")]
        let hsclient = {
            // Prompt the hs connector to do its data housekeeping when we get a new consensus.
            // That's a time we're doing a bunch of thinking anyway, and it's not very frequent.
            let housekeeping = dirmgr.events().filter_map(|event| async move {
                match event {
                    DirEvent::NewConsensus => Some(()),
                    _ => None,
                }
            });
            let housekeeping = Box::pin(housekeeping);

            HsClientConnector::new(runtime.clone(), hs_circ_pool.clone(), &config, housekeeping)?
        };
        let conn_status = chanmgr.bootstrap_events();
        let dir_status = dirmgr.bootstrap_events();
        let skew_status = circmgr.skew_events();
        // tor-socks5 local patch: aggregated "guards usable" signal from
        // tor-guardmgr (true iff at least one usable guard has complete
        // directory information), used to gate
        // `BootstrapStatus::ready_for_traffic()`.
        let guard_status = guardmgr.usable_guard_events();

        let rtclone = runtime.clone();

        // TODO: It might be a good idea to check this earlier, in `create_impl`,
        // when we have only the DirMgrStore.
        // But if we do that we need to add a method to DirMgrStore
        // to look at the protocol recommentations.
        #[allow(clippy::print_stderr)]
        crate::protostatus::enforce_protocol_recommendations(
            &runtime,
            Arc::clone(&dirmgr),
            crate::software_release_date(),
            crate::supported_protocols(),
            // TODO #1932: It would be nice to have a cleaner shutdown mechanism here,
            // but that will take some work.
            |fatal| async move {
                use tor_error::ErrorReport as _;
                // tor-socks5 local patch: give the embedding application a
                // chance to emit a structured marker (tracing::error!, an
                // alert, ...) before the intentional, non-negotiable fatal
                // shutdown, so the event is observable without an external
                // supervisor. The shutdown itself is NOT altered.
                let fatal_err = crate::err::Error::from(fatal.clone());
                notify_fatal_protocol_error(&fatal_protocol_error_handler, &fatal_err);
                // We already logged this error, but let's tell stderr too.
                eprintln!(
                    "Shutting down because of unsupported software version.\nError was:\n{}",
                    fatal.report(),
                );
                if let Some(hint) = fatal_err.hint() {
                    eprintln!("{}", hint);
                }
                // Give the tracing module a while to flush everything, since it has no built-in
                // flush function.
                rtclone.sleep(std::time::Duration::new(5, 0)).await;
                std::process::exit(1);
            },
        )?;

        runtime
            .spawn(status::report_status(
                status_sender,
                conn_status,
                dir_status,
                skew_status,
                guard_status,
            ))
            .map_err(|e| ErrorDetail::from_spawn("top-level status reporter", e))?;

        runtime
            .spawn(tasks_monitor_dormant(
                dormant_recv.clone(),
                dirmgr.clone().upcast_arc(),
                chanmgr.clone(),
                #[cfg(feature = "bridge-client")]
                bridge_desc_mgr.clone(),
                periodic_task_handles,
            ))
            .map_err(|e| ErrorDetail::from_spawn("periodic task dormant monitor", e))?;

        let running_inner = Arc::new(RunningInner {
            chanmgr,
            circmgr,
            dirmgr,
            #[cfg(feature = "bridge-client")]
            bridge_desc_mgr,
            #[cfg(feature = "pt-client")]
            pt_mgr,
            #[cfg(feature = "onion-service-client")]
            hsclient,
            #[cfg(any(feature = "onion-service-client", feature = "onion-service-service"))]
            hs_circ_pool,
            guardmgr,
        });

        Ok(running_inner)
    }

    /// Tell the parts of this [`RunningInner`] to reconfigure themselves
    /// (or to check the new configuration, if `how == CheckAllOrNothing`).
    pub(super) fn reconfigure(
        &self,
        new_config: &TorClientConfig,
        how: tor_config::Reconfigure,
    ) -> crate::Result<()> {
        let dir_cfg = new_config.dir_mgr_config().map_err(wrap_err)?;

        let retire_circuits = self
            .circmgr
            .reconfigure(new_config, how)
            .map_err(wrap_err)?;

        #[cfg(any(feature = "onion-service-client", feature = "onion-service-service"))]
        if retire_circuits != RetireCircuits::None {
            self.hs_circ_pool.retire_all_circuits().map_err(wrap_err)?;
        }

        self.dirmgr.reconfigure(&dir_cfg, how).map_err(wrap_err)?;

        let netparams = self.dirmgr.params();

        self.chanmgr
            .reconfigure(&new_config.channel, how, netparams)
            .map_err(wrap_err)?;

        #[cfg(feature = "pt-client")]
        self.pt_mgr
            .reconfigure(
                how,
                new_config.bridges.transports.clone(),
                new_config.channel.outbound_proxy().cloned(),
            )
            .map_err(wrap_err)?;

        Ok(())
    }
}
