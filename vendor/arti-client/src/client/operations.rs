use super::*;

impl<R: Runtime> TorClient<R> {
    /// Change the configuration of this TorClient to `new_config`.
    ///
    /// The `how` describes whether to perform an all-or-nothing
    /// reconfiguration: either all of the configuration changes will be
    /// applied, or none will. If you have disabled all-or-nothing changes, then
    /// only fatal errors will be reported in this function's return value.
    ///
    /// This function applies its changes to **all** TorClient instances derived
    /// from the same call to `TorClient::create_*`: even ones whose circuits
    /// are isolated from this handle.
    ///
    /// # Limitations
    ///
    /// Although most options are reconfigurable, there are some whose values
    /// can't be changed on an a running TorClient.  Those options (or their
    /// sections) are explicitly documented not to be changeable.
    /// NOTE: Currently, not all of these non-reconfigurable options are
    /// documented. See [arti#1721][arti-1721].
    ///
    /// [arti-1721]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1721
    ///
    /// Changing some options do not take effect immediately on all open streams
    /// and circuits, but rather affect only future streams and circuits.  Those
    /// are also explicitly documented.
    #[instrument(skip_all, level = "trace")]
    pub fn reconfigure(
        &self,
        new_config: &TorClientConfig,
        how: tor_config::Reconfigure,
    ) -> crate::Result<()> {
        // We need to hold this lock while we're reconfiguring the client: even
        // though the individual fields have their own synchronization, we can't
        // safely let two threads change them at once.  If we did, then we'd
        // introduce time-of-check/time-of-use bugs in checking our configuration,
        // deciding how to change it, then applying the changes.
        let guard = self.client.reconfigure_lock.lock().expect("Poisoned lock");

        match how {
            tor_config::Reconfigure::AllOrNothing => {
                // We have to check before we make any changes.
                self.client.reconfigure_inner(
                    new_config,
                    tor_config::Reconfigure::CheckAllOrNothing,
                    &guard,
                )?;
            }
            tor_config::Reconfigure::CheckAllOrNothing => {}
            tor_config::Reconfigure::WarnOnFailures => {}
            _ => {}
        }

        // Actually reconfigure
        self.client.reconfigure_inner(new_config, how, &guard)?;

        Ok(())
    }

    /// Return a new isolated `TorClient` handle.
    ///
    /// The two `TorClient`s will share internal state and configuration, but
    /// their streams will never share circuits with one another.
    ///
    /// Use this function when you want separate parts of your program to
    /// each have a TorClient handle, but where you don't want their
    /// activities to be linkable to one another over the Tor network.
    ///
    /// Calling this function is usually preferable to creating a
    /// completely separate TorClient instance, since it can share its
    /// internals with the existing `TorClient`.
    #[must_use]
    pub fn isolated_client(&self) -> Arc<TorClient<R>> {
        let result = TorClient {
            client_isolation: IsolationToken::new(),
            connect_prefs: self.connect_prefs.clone(),
            client: Arc::clone(&self.client),
        };
        Arc::new(result)
    }

    /// Launch an anonymized connection to the provided address and port over
    /// the Tor network.
    ///
    /// Note that because Tor prefers to do DNS resolution on the remote side of
    /// the network, this function takes its address as a string:
    ///
    /// ```no_run
    /// # use arti_client::*;use tor_rtcompat::Runtime;
    /// # async fn ex<R:Runtime>(tor_client: TorClient<R>) -> Result<()> {
    /// // The most usual way to connect is via an address-port tuple.
    /// let socket = tor_client.connect(("www.example.com", 443)).await?;
    ///
    /// // You can also specify an address and port as a colon-separated string.
    /// let socket = tor_client.connect("www.example.com:443").await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Hostnames are _strongly_ preferred here: if this function allowed the
    /// caller here to provide an IPAddr or [`IpAddr`] or
    /// [`SocketAddr`](std::net::SocketAddr) address, then
    ///
    /// ```no_run
    /// # use arti_client::*; use tor_rtcompat::Runtime;
    /// # async fn ex<R:Runtime>(tor_client: TorClient<R>) -> Result<()> {
    /// # use std::net::ToSocketAddrs;
    /// // BAD: We're about to leak our target address to the local resolver!
    /// let address = "www.example.com:443".to_socket_addrs().unwrap().next().unwrap();
    /// // 🤯 Oh no! Now any eavesdropper can tell where we're about to connect! 🤯
    ///
    /// // Fortunately, this won't compile, since SocketAddr doesn't implement IntoTorAddr.
    /// // let socket = tor_client.connect(address).await?;
    /// //                                 ^^^^^^^ the trait `IntoTorAddr` is not implemented for `std::net::SocketAddr`
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// If you really do need to connect to an IP address rather than a
    /// hostname, and if you're **sure** that the IP address came from a safe
    /// location, there are a few ways to do so.
    ///
    /// ```no_run
    /// # use arti_client::{TorClient,Result};use tor_rtcompat::Runtime;
    /// # use std::net::{SocketAddr,IpAddr};
    /// # async fn ex<R:Runtime>(tor_client: TorClient<R>) -> Result<()> {
    /// # use std::net::ToSocketAddrs;
    /// // ⚠️This is risky code!⚠️
    /// // (Make sure your addresses came from somewhere safe...)
    ///
    /// // If we have a fixed address, we can just provide it as a string.
    /// let socket = tor_client.connect("192.0.2.22:443").await?;
    /// let socket = tor_client.connect(("192.0.2.22", 443)).await?;
    ///
    /// // If we have a SocketAddr or an IpAddr, we can use the
    /// // DangerouslyIntoTorAddr trait.
    /// use arti_client::DangerouslyIntoTorAddr;
    /// let sockaddr = SocketAddr::from(([192, 0, 2, 22], 443));
    /// let ipaddr = IpAddr::from([192, 0, 2, 22]);
    /// let socket = tor_client.connect(sockaddr.into_tor_addr_dangerously().unwrap()).await?;
    /// let socket = tor_client.connect((ipaddr, 443).into_tor_addr_dangerously().unwrap()).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip_all, level = "trace")]
    pub async fn connect<A: IntoTorAddr>(&self, target: A) -> crate::Result<DataStream> {
        self.connect_with_prefs(target, &self.connect_prefs).await
    }

    /// Launch an anonymized connection to the provided address and
    /// port over the Tor network, with explicit connection preferences.
    ///
    /// Note that because Tor prefers to do DNS resolution on the remote
    /// side of the network, this function takes its address as a string.
    /// (See [`TorClient::connect()`] for more information.)
    #[instrument(skip_all, level = "trace")]
    pub async fn connect_with_prefs<A: IntoTorAddr>(
        &self,
        target: A,
        prefs: &StreamPrefs,
    ) -> crate::Result<DataStream> {
        // Reconfiguration affects future requests, not this request's retry budget.
        let timeout_cfg = self.client.timeoutcfg.get();
        let (initial_timeout, ordinary_timeout) = snapshot_exit_stream_timeouts(&timeout_cfg);
        let addr = target.into_tor_addr().map_err(wrap_err)?;
        let mut stream_parameters = prefs.stream_parameters();
        // This macro helps prevent code duplication in the match below.
        //
        // Ideally, the match should resolve to a tuple consisting of the
        // tunnel, and the address, port and stream params,
        // but that's not currently possible because
        // the Exit and Hs branches use different tunnel types.
        //
        // TODO: replace with an async closure (when our MSRV allows it),
        // or with a more elegant approach.
        macro_rules! begin_stream {
            ($tunnel:expr, $addr:expr, $port:expr, $stream_params:expr, $timeout:expr) => {{
                let fut = $tunnel.begin_stream($addr, $port, $stream_params);
                self.client
                    .runtime
                    .timeout($timeout, fut)
                    .await
                    .map_err(|_| ErrorDetail::ExitTimeout)?
                    .map_err(|cause| ErrorDetail::StreamFailed {
                        cause,
                        kind: "data",
                    })
            }};
        }

        let stream = match addr.into_stream_instructions(&self.client.addrcfg.get(), prefs)? {
            StreamInstructions::Exit {
                hostname: addr,
                port,
            } => {
                let exit_ports = [prefs.wrap_target_port(port)];
                retry_exit_stream(
                    &self.client.runtime,
                    initial_timeout,
                    ordinary_timeout,
                    || {
                        let addr = addr.clone();
                        let stream_parameters = stream_parameters.clone();
                        async move {
                            let tunnel = self.get_or_launch_exit_tunnel(&exit_ports, prefs).await?;
                            let id = tunnel.unique_id();
                            debug!(
                                tunnel_id = %id,
                                "Got a circuit for {}:{}",
                                sensitive(&addr),
                                port
                            );
                            let stream = async move {
                                tunnel
                                    .begin_stream(&addr, port, Some(stream_parameters))
                                    .await
                                    .map_err(|cause| ErrorDetail::StreamFailed {
                                        cause,
                                        kind: "data",
                                    })
                            };
                            Ok((id, stream))
                        }
                    },
                    |id| {
                        if let Ok(running) =
                            self.client.running_inner("retire failed stream circuit")
                        {
                            running.circmgr.retire_circ(id);
                        }
                    },
                )
                .await
            }

            #[cfg(not(feature = "onion-service-client"))]
            #[allow(unused_variables)] // for hostname and port
            StreamInstructions::Hs {
                hsid,
                hostname,
                port,
            } => void::unreachable(hsid.0),

            #[cfg(feature = "onion-service-client")]
            StreamInstructions::Hs {
                hsid,
                hostname,
                port,
            } => {
                use safelog::DisplayRedacted as _;

                let running = self
                    .client
                    .wait_for_bootstrap_running("connect to hidden service")
                    .await?;

                let netdir = self.netdir(Timeliness::Timely, "connect to a hidden service")?;

                let mut hs_client_secret_keys_builder = HsClientSecretKeysBuilder::default();

                if let Some(keymgr) = &self.client.inert_client.keymgr {
                    let desc_enc_key_spec = HsClientDescEncKeypairSpecifier::new(hsid);

                    let ks_hsc_desc_enc =
                        keymgr.get::<HsClientDescEncKeypair>(&desc_enc_key_spec)?;

                    if let Some(ks_hsc_desc_enc) = ks_hsc_desc_enc {
                        debug!(
                            "Found descriptor decryption key for {}",
                            hsid.display_redacted()
                        );
                        hs_client_secret_keys_builder.ks_hsc_desc_enc(ks_hsc_desc_enc);
                    }
                };

                let hs_client_secret_keys = hs_client_secret_keys_builder
                    .build()
                    .map_err(ErrorDetail::Configuration)?;

                let tunnel = running
                    .hsclient
                    .get_or_launch_tunnel(
                        &netdir,
                        hsid,
                        hs_client_secret_keys,
                        self.isolation(prefs),
                    )
                    .await
                    .map_err(|cause| ErrorDetail::ObtainHsCircuit { cause, hsid })?;
                // On connections to onion services, we have to suppress
                // everything except the port from the BEGIN message.  We also
                // disable optimistic data.
                stream_parameters
                    .suppress_hostname()
                    .suppress_begin_flags()
                    .optimistic(false);

                begin_stream!(
                    tunnel,
                    &hostname,
                    port,
                    Some(stream_parameters),
                    timeout_cfg.connect_timeout
                )
            }
        };

        Ok(stream?)
    }

    /// Provides a new handle on this client, but with adjusted default preferences.
    ///
    /// Connections made with e.g. [`connect`](TorClient::connect) on the returned handle will use
    /// `connect_prefs`.
    #[must_use]
    pub fn with_prefs(&self, connect_prefs: StreamPrefs) -> Arc<Self> {
        let result = TorClient {
            client_isolation: self.client_isolation,
            connect_prefs,
            client: Arc::clone(&self.client),
        };
        Arc::new(result)
    }

    /// On success, return a list of IP addresses.
    #[instrument(skip_all, level = "trace")]
    pub async fn resolve(&self, hostname: &str) -> crate::Result<Vec<IpAddr>> {
        self.resolve_with_prefs(hostname, &self.connect_prefs).await
    }

    /// On success, return a list of IP addresses, but use prefs.
    #[instrument(skip_all, level = "trace")]
    pub async fn resolve_with_prefs(
        &self,
        hostname: &str,
        prefs: &StreamPrefs,
    ) -> crate::Result<Vec<IpAddr>> {
        // TODO This dummy port is only because `address::Host` is not pub(crate),
        // but I see no reason why it shouldn't be?  Then `into_resolve_instructions`
        // should be a method on `Host`, not `TorAddr`.  -Diziet.
        let addr = (hostname, 1).into_tor_addr().map_err(wrap_err)?;

        match addr.into_resolve_instructions(&self.client.addrcfg.get(), prefs)? {
            ResolveInstructions::Exit(hostname) => {
                let circ = self.get_or_launch_exit_tunnel(&[], prefs).await?;

                let resolve_future = circ.resolve(&hostname);
                let addrs = self
                    .client
                    .runtime
                    .timeout(self.client.timeoutcfg.get().resolve_timeout, resolve_future)
                    .await
                    .map_err(|_| ErrorDetail::ExitTimeout)?
                    .map_err(|cause| ErrorDetail::StreamFailed {
                        cause,
                        kind: "DNS lookup",
                    })?;

                Ok(addrs)
            }
            ResolveInstructions::Return(addrs) => Ok(addrs),
        }
    }

    /// Perform a remote DNS reverse lookup with the provided IP address.
    ///
    /// On success, return a list of hostnames.
    #[instrument(skip_all, level = "trace")]
    pub async fn resolve_ptr(&self, addr: IpAddr) -> crate::Result<Vec<String>> {
        self.resolve_ptr_with_prefs(addr, &self.connect_prefs).await
    }

    /// Perform a remote DNS reverse lookup with the provided IP address.
    ///
    /// On success, return a list of hostnames.
    #[instrument(level = "trace", skip_all)]
    pub async fn resolve_ptr_with_prefs(
        &self,
        addr: IpAddr,
        prefs: &StreamPrefs,
    ) -> crate::Result<Vec<String>> {
        let circ = self.get_or_launch_exit_tunnel(&[], prefs).await?;

        let resolve_ptr_future = circ.resolve_ptr(addr);
        let hostnames = self
            .client
            .runtime
            .timeout(
                self.client.timeoutcfg.get().resolve_ptr_timeout,
                resolve_ptr_future,
            )
            .await
            .map_err(|_| ErrorDetail::ExitTimeout)?
            .map_err(|cause| ErrorDetail::StreamFailed {
                cause,
                kind: "reverse DNS lookup",
            })?;

        Ok(hostnames)
    }

    /// Return a reference to this client's directory manager.
    ///
    /// This function is unstable. It is only enabled if the crate was
    /// built with the `experimental-api` feature.
    #[cfg(feature = "experimental-api")]
    pub fn dirmgr(&self) -> crate::Result<Arc<dyn tor_dirmgr::DirProvider>> {
        Ok(self
            .client
            .running_inner("access internal functionality")?
            .dirmgr
            .clone())
    }

    /// Return a reference to this client's circuit manager.
    ///
    /// This function is unstable. It is only enabled if the crate was
    /// built with the `experimental-api` feature.
    #[cfg(feature = "experimental-api")]
    pub fn circmgr(&self) -> crate::Result<Arc<tor_circmgr::CircMgr<R>>> {
        Ok(self
            .client
            .running_inner("access internal functionality")?
            .circmgr
            .clone())
    }

    /// Return a reference to this client's channel manager.
    ///
    /// This function is unstable. It is only enabled if the crate was
    /// built with the `experimental-api` feature.
    #[cfg(feature = "experimental-api")]
    pub fn chanmgr(&self) -> crate::Result<Arc<tor_chanmgr::ChanMgr<R>>> {
        Ok(self
            .client
            .running_inner("access internal functionality")?
            .chanmgr
            .clone())
    }

    /// tor-socks5 local patch: re-enable every guard that the guard manager has
    /// permanently disabled via its indeterminate-failure path-bias detection,
    /// returning the number of guards that were re-enabled.
    ///
    /// `tor-guardmgr` disables a guard once its lifetime indeterminate-failure
    /// ratio exceeds 0.7, persists that `disabled` state across restarts, and
    /// never clears it. In a bridge-only deployment with only a handful of
    /// configured bridges, a single transient second-hop/exit failure storm can
    /// therefore take a bridge out of rotation for good, with no automatic
    /// recovery path. This hook lets an application-level watchdog (which knows
    /// how small the bridge pool is) deliberately re-enable disabled bridges on
    /// its own policy — for example when too few usable bridges remain.
    ///
    /// Returns an error if the client is not yet running (dormant / under
    /// construction); otherwise the count of guards that were disabled and are
    /// now re-enabled. Guards that were already usable are left untouched.
    ///
    /// This function is unstable. It is only enabled if the crate was
    /// built with the `experimental-api` feature.
    #[cfg(feature = "experimental-api")]
    pub fn reset_disabled_guards(&self) -> crate::Result<usize> {
        let inner = self.client.running_inner("reset disabled guards")?;
        Ok(inner.guardmgr.reset_disabled_guards())
    }

    /// tor-socks5 local patch: record that, _after_ a circuit was built through
    /// a guard, some activity outside of `tor-guardmgr`'s own circuit-build
    /// bookkeeping (identified by `identity`) failed in a way described by
    /// `activity`.
    ///
    /// This exposes `tor_guardmgr::GuardMgr::note_external_failure()`, which
    /// feeds directly into the same primary/confirmed/sample guard-state
    /// machine (prop271) that circuit-build failures use. It lets an
    /// application-level watchdog — which observes failures the guard
    /// manager itself cannot see, such as an unhealthy pluggable-transport
    /// bridge whose circuits build but whose traffic stalls — report that
    /// unhealthiness so the ordinary guard-selection/retirement logic can
    /// react to it (e.g. de-prioritizing that guard in favor of a healthier
    /// one), without the caller needing to re-implement any guard-state
    /// logic itself.
    ///
    /// Returns an error if the client is not yet running (dormant / under
    /// construction).
    ///
    /// This function is unstable. It is only enabled if the crate was
    /// built with the `experimental-api` feature.
    #[cfg(feature = "experimental-api")]
    pub fn note_external_guard_failure<T>(
        &self,
        identity: &T,
        activity: tor_guardmgr::ExternalActivity,
    ) -> crate::Result<()>
    where
        T: tor_linkspec::HasRelayIds + ?Sized,
    {
        let inner = self.client.running_inner("note external guard failure")?;
        inner.guardmgr.note_external_failure(identity, activity);
        Ok(())
    }

    /// Whether guard security policy has disabled this relay identity.
    /// This method is available with `experimental-api`.
    #[cfg(feature = "experimental-api")]
    pub fn guard_is_disabled<T: tor_linkspec::HasRelayIds + ?Sized>(
        &self,
        identity: &T,
    ) -> crate::Result<bool> {
        let inner = self.client.running_inner("query guard policy")?;
        Ok(inner.guardmgr.guard_is_disabled(identity))
    }

    /// Return a reference to this client's circuit pool.
    ///
    /// This function is unstable. It is only enabled if the crate was
    /// built with the `experimental-api` feature and any of `onion-service-client`
    /// or `onion-service-service` features. This method is required to invoke
    /// tor_hsservice::OnionService::launch()
    #[cfg(all(
        feature = "experimental-api",
        any(feature = "onion-service-client", feature = "onion-service-service")
    ))]
    pub fn hs_circ_pool(&self) -> crate::Result<Arc<tor_circmgr::hspool::HsCircPool<R>>> {
        Ok(self
            .client
            .running_inner("access internal functionality")?
            .hs_circ_pool
            .clone())
    }

    /// Return a reference to the runtime being used by this client.
    //
    // This API is not a hostage to fortune since we already require that R: Clone,
    // and necessarily a TorClient must have a clone of it.
    //
    // We provide it simply to save callers who have a TorClient from
    // having to separately keep their own handle,
    pub fn runtime(&self) -> &R {
        &self.client.runtime
    }

    /// Return a netdir that is timely according to the rules of `timeliness`.
    ///
    /// The `action` string is a description of what we wanted to do with the
    /// directory, to be put into the error message if we couldn't find a directory.
    fn netdir(
        &self,
        timeliness: Timeliness,
        action: &'static str,
    ) -> StdResult<Arc<tor_netdir::NetDir>, ErrorDetail> {
        use tor_netdir::Error as E;
        // TODO: Conceivably we could take a NetDir from our DirMgrStore.
        match self.client.running_inner(action)?.dirmgr.netdir(timeliness) {
            Ok(netdir) => Ok(netdir),
            Err(E::NoInfo) | Err(E::NotEnoughInfo) => {
                Err(ErrorDetail::BootstrapRequired { action })
            }
            Err(error) => Err(ErrorDetail::NoDir { error, action }),
        }
    }

    /// Get or launch an exit-suitable circuit with a given set of
    /// exit ports.
    #[instrument(skip_all, level = "trace")]
    async fn get_or_launch_exit_tunnel(
        &self,
        exit_ports: &[TargetPort],
        prefs: &StreamPrefs,
    ) -> StdResult<ClientDataTunnel, ErrorDetail> {
        let running = self
            .client
            .wait_for_bootstrap_running("build a circuit")
            .await?;
        // TODO HS probably this netdir ought to be made in connect_with_prefs
        // like for StreamInstructions::Hs.
        let dir = self.netdir(Timeliness::Timely, "build a circuit")?;

        let tunnel = running
            .circmgr
            .get_or_launch_exit(
                dir.as_ref().into(),
                exit_ports,
                self.isolation(prefs),
                #[cfg(feature = "geoip")]
                prefs.country_code,
            )
            .await
            .map_err(|cause| ErrorDetail::ObtainExitCircuit {
                cause,
                exit_ports: Sensitive::new(exit_ports.into()),
            })?;
        drop(dir); // This decreases the refcount on the netdir.

        Ok(tunnel)
    }

    /// Return an overall [`Isolation`] for this `TorClient` and a `StreamPrefs`.
    ///
    /// This describes which operations might use
    /// circuit(s) with this one.
    ///
    /// This combines isolation information from
    /// [`StreamPrefs::prefs_isolation`]
    /// and the `TorClient`'s isolation (eg from [`TorClient::isolated_client`]).
    fn isolation(&self, prefs: &StreamPrefs) -> StreamIsolation {
        let mut b = StreamIsolationBuilder::new();
        // Always consider our client_isolation.
        b.owner_token(self.client_isolation);
        // Consider stream isolation too, if it's set.
        if let Some(tok) = prefs.prefs_isolation() {
            b.stream_isolation(tok);
        }
        // Failure should be impossible with this builder.
        b.build().expect("Failed to construct StreamIsolation")
    }

    /// Try to launch an onion service with a given configuration.
    ///
    /// Returns `Ok(None)` if the service specified is disabled in the config.
    ///
    /// This onion service will not actually handle any requests on its own: you
    /// will need to
    /// pull [`RendRequest`](tor_hsservice::RendRequest) objects from the returned stream,
    /// [`accept`](tor_hsservice::RendRequest::accept) the ones that you want to
    /// answer, and then wait for them to give you [`StreamRequest`](tor_hsservice::StreamRequest)s.
    ///
    /// You may find the [`tor_hsservice::handle_rend_requests`] API helpful for
    /// translating `RendRequest`s into `StreamRequest`s.
    ///
    /// If you want to forward all the requests from an onion service to a set
    /// of local ports, you may want to use the `tor-hsrproxy` crate.
    #[cfg(feature = "onion-service-service")]
    #[instrument(skip_all, level = "trace")]
    pub fn launch_onion_service(
        &self,
        config: tor_hsservice::OnionServiceConfig,
    ) -> crate::Result<
        Option<(
            Arc<tor_hsservice::RunningOnionService>,
            impl futures::Stream<Item = tor_hsservice::RendRequest> + use<R>,
        )>,
    > {
        let nickname = config.nickname();

        if !config.enabled() {
            info!(
                nickname=%nickname,
                "Skipping onion service because it was disabled in the config"
            );
            return Ok(None);
        }

        let running = self
            .client
            .initiate_bootstrap_if_needed("launch onion service")?;

        let keymgr = self
            .client
            .inert_client
            .keymgr
            .as_ref()
            .ok_or(ErrorDetail::KeystoreRequired {
                action: "launch onion service",
            })?
            .clone();
        let state_dir = self.client.state_directory.clone();

        let service = tor_hsservice::OnionService::builder()
            .config(config) // TODO #1186: Allow override of KeyMgr for "ephemeral" operation?
            .keymgr(keymgr)
            // TODO #1186: Allow override of StateMgr for "ephemeral" operation?
            .state_dir(state_dir)
            .build()
            .map_err(ErrorDetail::LaunchOnionService)?;
        Ok(service
            .launch(
                self.client.runtime.clone(),
                running.dirmgr.clone().upcast_arc(),
                running.hs_circ_pool.clone(),
                Arc::clone(&self.client.path_resolver),
            )
            .map_err(ErrorDetail::LaunchOnionService)?)
    }

    /// Try to launch an onion service with a given configuration and provided
    /// [`HsIdKeypair`]. If an onion service with the given nickname already has an
    /// associated `HsIdKeypair`  in this `TorClient`'s `KeyMgr`, then this operation
    /// fails rather than overwriting the existing key.
    ///
    /// Returns `Ok(None)` if the service specified is disabled in the config.
    ///
    /// The specified `HsIdKeypair` will be inserted in the primary keystore.
    ///
    /// **Important**: depending on the configuration of your
    /// [primary keystore](tor_keymgr::config::PrimaryKeystoreConfig),
    /// the `HsIdKeypair` **may** get persisted to disk.
    /// By default, Arti's primary keystore is the [native](ArtiKeystoreKind::Native),
    /// disk-based keystore.
    ///
    /// This onion service will not actually handle any requests on its own: you
    /// will need to
    /// pull [`RendRequest`](tor_hsservice::RendRequest) objects from the returned stream,
    /// [`accept`](tor_hsservice::RendRequest::accept) the ones that you want to
    /// answer, and then wait for them to give you [`StreamRequest`](tor_hsservice::StreamRequest)s.
    ///
    /// You may find the [`tor_hsservice::handle_rend_requests`] API helpful for
    /// translating `RendRequest`s into `StreamRequest`s.
    ///
    /// If you want to forward all the requests from an onion service to a set
    /// of local ports, you may want to use the `tor-hsrproxy` crate.
    #[cfg(all(feature = "onion-service-service", feature = "experimental-api"))]
    #[instrument(skip_all, level = "trace")]
    pub fn launch_onion_service_with_hsid(
        &self,
        config: tor_hsservice::OnionServiceConfig,
        id_keypair: HsIdKeypair,
    ) -> crate::Result<
        Option<(
            Arc<tor_hsservice::RunningOnionService>,
            impl futures::Stream<Item = tor_hsservice::RendRequest> + use<R>,
        )>,
    > {
        let nickname = config.nickname();
        let hsid_spec = HsIdKeypairSpecifier::new(nickname.clone());
        let selector = KeystoreSelector::Primary;

        let _kp = self
            .client
            .inert_client
            .keymgr
            .as_ref()
            .ok_or(ErrorDetail::KeystoreRequired {
                action: "launch onion service ex",
            })?
            .insert::<HsIdKeypair>(id_keypair, &hsid_spec, selector, false)?;

        self.launch_onion_service(config)
    }

    /// Generate a service discovery keypair for connecting to a hidden service running in
    /// "restricted discovery" mode.
    ///
    /// The `selector` argument is used for choosing the keystore in which to generate the keypair.
    /// While most users will want to write to the [`Primary`](KeystoreSelector::Primary), if you
    /// have configured this `TorClient` with a non-default keystore and wish to generate the
    /// keypair in it, you can do so by calling this function with a [KeystoreSelector::Id]
    /// specifying the keystore ID of your keystore.
    ///
    // Note: the selector argument exists for future-proofing reasons. We don't currently support
    // configuring custom or non-default keystores (see #1106).
    ///
    /// Returns an error if the key already exists in the specified key store.
    ///
    /// Important: the public part of the generated keypair must be shared with the service, and
    /// the service needs to be configured to allow the owner of its private counterpart to
    /// discover its introduction points. The caller is responsible for sharing the public part of
    /// the key with the hidden service.
    ///
    /// This function does not require the `TorClient` to be running or bootstrapped.
    //
    // TODO: decide whether this should use get_or_generate before making it
    // non-experimental
    #[cfg(all(
        feature = "onion-service-client",
        feature = "experimental-api",
        feature = "keymgr"
    ))]
    pub fn generate_service_discovery_key(
        &self,
        selector: KeystoreSelector,
        hsid: HsId,
    ) -> crate::Result<HsClientDescEncKey> {
        self.client
            .inert_client
            .generate_service_discovery_key(selector, hsid)
    }

    /// Rotate the service discovery keypair for connecting to a hidden service running in
    /// "restricted discovery" mode.
    ///
    /// **If the specified keystore already contains a restricted discovery keypair
    /// for the service, it will be overwritten.** Otherwise, a new keypair is generated.
    ///
    /// The `selector` argument is used for choosing the keystore in which to generate the keypair.
    /// While most users will want to write to the [`Primary`](KeystoreSelector::Primary), if you
    /// have configured this `TorClient` with a non-default keystore and wish to generate the
    /// keypair in it, you can do so by calling this function with a [KeystoreSelector::Id]
    /// specifying the keystore ID of your keystore.
    ///
    // Note: the selector argument exists for future-proofing reasons. We don't currently support
    // configuring custom or non-default keystores (see #1106).
    ///
    /// Important: the public part of the generated keypair must be shared with the service, and
    /// the service needs to be configured to allow the owner of its private counterpart to
    /// discover its introduction points. The caller is responsible for sharing the public part of
    /// the key with the hidden service.
    ///
    /// This function does not require the `TorClient` to be running or bootstrapped.
    #[cfg(all(
        feature = "onion-service-client",
        feature = "experimental-api",
        feature = "keymgr"
    ))]
    #[cfg_attr(
        docsrs,
        doc(cfg(all(
            feature = "onion-service-client",
            feature = "experimental-api",
            feature = "keymgr"
        )))
    )]
    pub fn rotate_service_discovery_key(
        &self,
        selector: KeystoreSelector,
        hsid: HsId,
    ) -> crate::Result<HsClientDescEncKey> {
        self.client
            .inert_client
            .rotate_service_discovery_key(selector, hsid)
    }

    /// Insert a service discovery secret key for connecting to a hidden service running in
    /// "restricted discovery" mode
    ///
    /// The `selector` argument is used for choosing the keystore in which to generate the keypair.
    /// While most users will want to write to the [`Primary`](KeystoreSelector::Primary), if you
    /// have configured this `TorClient` with a non-default keystore and wish to insert the
    /// key in it, you can do so by calling this function with a [KeystoreSelector::Id]
    ///
    // Note: the selector argument exists for future-proofing reasons. We don't currently support
    // configuring custom or non-default keystores (see #1106).
    ///
    /// Returns an error if the key already exists in the specified key store.
    ///
    /// Important: the public part of the generated keypair must be shared with the service, and
    /// the service needs to be configured to allow the owner of its private counterpart to
    /// discover its introduction points. The caller is responsible for sharing the public part of
    /// the key with the hidden service.
    ///
    /// This function does not require the `TorClient` to be running or bootstrapped.
    #[cfg(all(
        feature = "onion-service-client",
        feature = "experimental-api",
        feature = "keymgr"
    ))]
    #[cfg_attr(
        docsrs,
        doc(cfg(all(
            feature = "onion-service-client",
            feature = "experimental-api",
            feature = "keymgr"
        )))
    )]
    pub fn insert_service_discovery_key(
        &self,
        selector: KeystoreSelector,
        hsid: HsId,
        hs_client_desc_enc_secret_key: HsClientDescEncSecretKey,
    ) -> crate::Result<HsClientDescEncKey> {
        self.client.inert_client.insert_service_discovery_key(
            selector,
            hsid,
            hs_client_desc_enc_secret_key,
        )
    }

    /// Return the service discovery public key for the service with the specified `hsid`.
    ///
    /// Returns `Ok(None)` if no such key exists.
    ///
    /// This function does not require the `TorClient` to be running or bootstrapped.
    #[cfg(all(feature = "onion-service-client", feature = "experimental-api"))]
    #[cfg_attr(
        docsrs,
        doc(cfg(all(feature = "onion-service-client", feature = "experimental-api")))
    )]
    pub fn get_service_discovery_key(
        &self,
        hsid: HsId,
    ) -> crate::Result<Option<HsClientDescEncKey>> {
        self.client.inert_client.get_service_discovery_key(hsid)
    }

    /// Removes the service discovery keypair for the service with the specified `hsid`.
    ///
    /// Returns an error if the selected keystore is not the default keystore or one of the
    /// configured secondary stores.
    ///
    /// Returns `Ok(None)` if no such keypair exists whereas `Ok(Some()) means the keypair was successfully removed.
    ///
    /// Returns `Err` if an error occurred while trying to remove the key.
    #[cfg(all(
        feature = "onion-service-client",
        feature = "experimental-api",
        feature = "keymgr"
    ))]
    #[cfg_attr(
        docsrs,
        doc(cfg(all(
            feature = "onion-service-client",
            feature = "experimental-api",
            feature = "keymgr"
        )))
    )]
    pub fn remove_service_discovery_key(
        &self,
        selector: KeystoreSelector,
        hsid: HsId,
    ) -> crate::Result<Option<()>> {
        self.client
            .inert_client
            .remove_service_discovery_key(selector, hsid)
    }

    /// Create (but do not launch) a new
    /// [`OnionService`](tor_hsservice::OnionService)
    /// using the given configuration.
    ///
    /// This is useful for managing an onion service without needing to start a `TorClient` or the
    /// onion service itself.
    /// If you only wish to run the onion service, see
    /// [`TorClient::launch_onion_service()`]
    /// which allows you to launch an onion service from a running `TorClient`.
    ///
    /// The returned `OnionService` can be launched using
    /// [`OnionService::launch()`](tor_hsservice::OnionService::launch).
    /// Note that `launch()` requires a [`NetDirProvider`],
    /// [`HsCircPool`](tor_circmgr::hspool::HsCircPool), etc,
    /// which you should obtain from a running `TorClient`.
    /// But these are only accessible from a `TorClient` if the "experimental-api" feature is
    /// enabled.
    /// The behaviour is not specified if you create the `OnionService` with
    /// `create_onion_service()` using one [`TorClientConfig`],
    /// but launch it using a `TorClient` generated from a different `TorClientConfig`.
    // TODO #2249: Look into this behaviour more, and possibly error if there is a different config.
    #[cfg(feature = "onion-service-service")]
    #[instrument(skip_all, level = "trace")]
    pub fn create_onion_service(
        config: &TorClientConfig,
        svc_config: tor_hsservice::OnionServiceConfig,
    ) -> crate::Result<tor_hsservice::OnionService> {
        let inert_client = InertTorClient::new(config)?;
        inert_client.create_onion_service(config, svc_config)
    }

    /// Return a current [`status::BootstrapStatus`] describing how close this client
    /// is to being ready for user traffic.
    pub fn bootstrap_status(&self) -> status::BootstrapStatus {
        self.client.status_receiver.inner.borrow().clone()
    }

    /// Return a stream of [`status::BootstrapStatus`] events that will be updated
    /// whenever the client's status changes.
    ///
    /// The receiver might not receive every update sent to this stream, though
    /// when it does poll the stream it should get the most recent one.
    //
    // TODO(nickm): will this also need to implement Send and 'static?
    pub fn bootstrap_events(&self) -> status::BootstrapEvents {
        self.client.status_receiver.clone()
    }

    /// Change the client's current dormant mode, putting background tasks to sleep
    /// or waking them up as appropriate.
    ///
    /// This can be used to conserve CPU usage if you aren't planning on using the
    /// client for a while, especially on mobile platforms.
    ///
    /// See the [`DormantMode`] documentation for more details.
    pub fn set_dormant(&self, mode: DormantMode) {
        *self
            .client
            .dormant
            .lock()
            .expect("dormant lock poisoned")
            .borrow_mut() = Some(mode);
    }

    /// Return a [`Future`] which resolves
    /// once this TorClient has stopped.
    #[cfg(feature = "experimental-api")]
    #[instrument(skip_all, level = "trace")]
    pub fn wait_for_stop(
        &self,
    ) -> impl futures::Future<Output = ()> + Send + Sync + 'static + use<R> {
        // We defer to the "wait for unlock" handle on our statemgr.
        //
        // The statemgr won't actually be unlocked until it is finally
        // dropped, which will happen when this TorClient is
        // dropped—which is what we want.
        self.client.statemgr.wait_for_unlock()
    }

    /// Getter for keymgr.
    #[cfg(feature = "onion-service-cli-extra")]
    pub fn keymgr(&self) -> crate::Result<&KeyMgr> {
        self.client.inert_client.keymgr()
    }
}
