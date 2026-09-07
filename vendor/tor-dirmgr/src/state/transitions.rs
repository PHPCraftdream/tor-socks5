use super::*;

impl<R: Runtime> DirState for GetCertsState<R> {
    fn describe(&self) -> String {
        use GetCertsConsensus as C;
        match &self.consensus {
            C::Unvalidated(_) => {
                let total = self.certs.len() + self.missing_certs.len();
                format!(
                    "Downloading certificates for consensus (we are missing {}/{}).",
                    self.missing_certs.len(),
                    total
                )
            }
            C::Validated(_) => "Validated consensus; about to get microdescriptors".to_string(),
            C::Failed => "Failed to validate consensus".to_string(),
        }
    }
    fn missing_docs(&self) -> Vec<DocId> {
        self.missing_certs
            .iter()
            .map(|id| DocId::AuthCert(*id))
            .collect()
    }
    fn is_ready(&self, _ready: Readiness) -> bool {
        false
    }
    fn can_advance(&self) -> bool {
        matches!(self.consensus, GetCertsConsensus::Validated(_))
    }
    fn bootstrap_progress(&self) -> DirProgress {
        let n_certs = self.certs.len();
        let n_missing_certs = self.missing_certs.len();
        let total_certs = n_missing_certs + n_certs;
        DirProgress::FetchingCerts {
            lifetime: self.consensus_meta.lifetime().clone(),
            usable_lifetime: self
                .config
                .tolerance
                .extend_lifetime(self.consensus_meta.lifetime()),

            n_certs: (n_certs as u16, total_certs as u16),
        }
    }
    fn dl_config(&self) -> DownloadSchedule {
        self.config.schedule.retry_certs()
    }
    fn add_from_cache(
        &mut self,
        docs: HashMap<DocId, DocumentText>,
        changed: &mut bool,
    ) -> Result<()> {
        // Here we iterate over the documents we want, taking them from
        // our input and remembering them.
        let source = DocSource::LocalCache;
        let mut nonfatal_error = None;
        for id in &self.missing_docs() {
            if let Some(cert) = docs.get(id) {
                let text = cert.as_str().map_err(Error::BadUtf8InCache)?;
                let parsed = AuthCert::parse(text);
                match self.check_parsed_certificate(parsed, &source, text) {
                    Ok((cert, _text)) => {
                        self.missing_certs.remove(&cert.key_ids());
                        self.certs.push(cert);
                        *changed = true;
                    }
                    Err(e) => {
                        nonfatal_error.get_or_insert(e);
                    }
                }
            }
        }
        if *changed {
            self.try_checking_sigs()?;
        }
        opt_err_to_result(nonfatal_error)
    }
    fn add_from_download(
        &mut self,
        text: &str,
        request: &ClientRequest,
        source: DocSource,
        storage: Option<&Mutex<DynStore>>,
        changed: &mut bool,
    ) -> Result<()> {
        let asked_for: HashSet<_> = match request {
            ClientRequest::AuthCert(a) => a.keys().collect(),
            _ => return Err(internal!("expected an AuthCert request").into()),
        };

        let mut nonfatal_error = None;
        let mut newcerts = Vec::new();
        for cert in
            AuthCert::parse_multiple(text).map_err(|e| Error::from_netdoc(source.clone(), e))?
        {
            match self.check_parsed_certificate(cert, &source, text) {
                Ok((cert, cert_text)) => {
                    newcerts.push((cert, cert_text));
                }
                Err(e) => {
                    warn_report!(e, "Problem with certificate received from {}", &source);
                    nonfatal_error.get_or_insert(e);
                }
            }
        }

        // Now discard any certs we didn't ask for.
        let len_orig = newcerts.len();
        newcerts.retain(|(cert, _)| asked_for.contains(&cert.key_ids()));
        if newcerts.len() != len_orig {
            warn!(
                "Discarding certificates from {} that we didn't ask for.",
                source
            );
            nonfatal_error.get_or_insert(Error::Unwanted("Certificate we didn't request"));
        }

        // We want to exit early if we aren't saving any certificates.
        if newcerts.is_empty() {
            return opt_err_to_result(nonfatal_error);
        }

        if let Some(store) = storage {
            // Write the certificates to the store.
            let v: Vec<_> = newcerts[..]
                .iter()
                .map(|(cert, s)| (AuthCertMeta::from_authcert(cert), *s))
                .collect();
            let mut w = store.lock().expect("Directory storage lock poisoned");
            w.store_authcerts(&v[..])?;
        }

        // Remember the certificates in this state, and remove them
        // from our list of missing certs.
        for (cert, _) in newcerts {
            let ids = cert.key_ids();
            if self.missing_certs.contains(&ids) {
                self.missing_certs.remove(&ids);
                self.certs.push(cert);
                *changed = true;
            }
        }

        if *changed {
            self.try_checking_sigs()?;
        }
        opt_err_to_result(nonfatal_error)
    }

    fn advance(self: Box<Self>) -> Box<dyn DirState> {
        use GetCertsConsensus::*;
        match self.consensus {
            Validated(validated) => Box::new(GetMicrodescsState::new(
                self.cache_usage,
                validated,
                self.consensus_meta,
                self.rt,
                self.config,
                self.prev_netdir,
                #[cfg(feature = "dirfilter")]
                self.filter,
            )),
            _ => self,
        }
    }

    fn get_netdir_change(&mut self) -> Option<NetDirChange<'_>> {
        self.protocol_statuses.as_ref().map(|(timestamp, protos)| {
            NetDirChange::SetRequiredProtocol {
                timestamp: *timestamp,
                protos: Arc::clone(protos),
            }
        })
    }

    fn reset_time(&self) -> Option<SystemTime> {
        Some(
            self.consensus_meta.lifetime().valid_until()
                + self.config.tolerance.post_valid_tolerance(),
        )
    }
    fn reset(self: Box<Self>) -> Box<dyn DirState> {
        let cache_usage = if self.cache_usage == CacheUsage::CacheOnly {
            // Cache only means we can't ever download.
            CacheUsage::CacheOnly
        } else {
            // If we reset in this state, we should always go to "must
            // download": Either we've failed to get the certs we needed, or we
            // have found that the consensus wasn't valid.  Either case calls
            // for a fresh consensus download attempt.
            CacheUsage::MustDownload
        };

        Box::new(GetConsensusState::new(
            self.rt,
            self.config,
            cache_usage,
            self.prev_netdir,
            #[cfg(feature = "dirfilter")]
            self.filter,
        ))
    }
}

/// Final state: we're fetching or loading microdescriptors

impl MdReceiver for PendingNetDir {
    fn missing_microdescs(&self) -> Box<dyn Iterator<Item = &MdDigest> + '_> {
        match self {
            PendingNetDir::Partial(partial) => partial.missing_microdescs(),
            PendingNetDir::Yielding {
                netdir,
                missing_microdescs,
                ..
            } => {
                if let Some(nd) = netdir.as_ref() {
                    nd.missing_microdescs()
                } else {
                    Box::new(missing_microdescs.iter())
                }
            }
            PendingNetDir::Dummy => unreachable!(),
        }
    }

    fn add_microdesc(&mut self, md: Microdesc) -> bool {
        match self {
            PendingNetDir::Partial(partial) => partial.add_microdesc(md),
            PendingNetDir::Yielding {
                netdir,
                missing_microdescs,
                collected_microdescs,
                ..
            } => {
                let wanted = missing_microdescs.remove(md.digest());
                if let Some(nd) = netdir.as_mut() {
                    let nd_wanted = nd.add_microdesc(md);
                    // This shouldn't ever happen; if it does, our invariants are violated.
                    debug_assert_eq!(wanted, nd_wanted);
                    nd_wanted
                } else {
                    collected_microdescs.push(md);
                    wanted
                }
            }
            PendingNetDir::Dummy => unreachable!(),
        }
    }

    fn n_missing(&self) -> usize {
        match self {
            PendingNetDir::Partial(partial) => partial.n_missing(),
            PendingNetDir::Yielding {
                netdir,
                missing_microdescs,
                ..
            } => {
                if let Some(nd) = netdir.as_ref() {
                    // This shouldn't ever happen; if it does, our invariants are violated.
                    debug_assert_eq!(nd.n_missing(), missing_microdescs.len());
                    nd.n_missing()
                } else {
                    missing_microdescs.len()
                }
            }
            PendingNetDir::Dummy => unreachable!(),
        }
    }
}

impl PendingNetDir {
    /// If this PendingNetDir is Partial and could not be partial, upgrade it.
    fn upgrade_if_necessary(&mut self) {
        if matches!(self, PendingNetDir::Partial(..)) {
            match mem::replace(self, PendingNetDir::Dummy) {
                PendingNetDir::Partial(p) => match p.unwrap_if_sufficient() {
                    Ok(nd) => {
                        let missing: HashSet<_> = nd.missing_microdescs().copied().collect();
                        let replace_dir_time = pick_download_time(nd.lifetime());
                        debug!(
                            "Consensus now usable, with {} microdescriptors missing. \
                                The current consensus is fresh until {}, and valid until {}. \
                                I've picked {} as the earliest time to replace it.",
                            missing.len(),
                            OffsetDateTime::from(nd.lifetime().fresh_until()),
                            OffsetDateTime::from(nd.lifetime().valid_until()),
                            OffsetDateTime::from(replace_dir_time)
                        );
                        *self = PendingNetDir::Yielding {
                            netdir: Some(nd),
                            collected_microdescs: vec![],
                            missing_microdescs: missing,
                            replace_dir_time,
                        };
                    }
                    Err(p) => {
                        *self = PendingNetDir::Partial(p);
                    }
                },
                _ => unreachable!(),
            }
        }
        assert!(!matches!(self, PendingNetDir::Dummy));
    }
}

impl<R: Runtime> GetMicrodescsState<R> {
    /// Create a new [`GetMicrodescsState`] from a provided
    /// microdescriptor consensus.
    fn new(
        cache_usage: CacheUsage,
        consensus: MdConsensus,
        meta: ConsensusMeta,
        rt: R,
        config: Arc<DirMgrConfig>,
        prev_netdir: Option<Arc<dyn PreviousNetDir>>,
        #[cfg(feature = "dirfilter")] filter: Arc<dyn crate::filter::DirFilter>,
    ) -> Self {
        let reset_time =
            consensus.lifetime().valid_until() + config.tolerance.post_valid_tolerance();
        let n_microdescs = consensus.relays().len();

        let params = &config.override_net_params;
        #[cfg(not(feature = "geoip"))]
        let mut partial_dir = PartialNetDir::new(consensus, Some(params));
        // TODO(eta): Make this embedded database configurable using the `DirMgrConfig`.
        #[cfg(feature = "geoip")]
        let mut partial_dir =
            PartialNetDir::new_with_geoip(consensus, Some(params), &GeoipDb::new_embedded());

        if let Some(old_dir) = prev_netdir.as_ref().and_then(|x| x.get_netdir()) {
            partial_dir.fill_from_previous_netdir(old_dir);
        }

        // Always upgrade at least once: otherwise, we won't notice we're ready unless we
        // add a microdescriptor.
        let mut partial = PendingNetDir::Partial(partial_dir);
        partial.upgrade_if_necessary();

        GetMicrodescsState {
            cache_usage,
            n_microdescs,
            partial,
            meta,
            newly_listed: Vec::new(),
            reset_time,
            rt,
            config,
            prev_netdir,

            #[cfg(feature = "dirfilter")]
            filter,
        }
    }

    /// Add a bunch of microdescriptors to the in-progress netdir.
    fn register_microdescs<I>(&mut self, mds: I, _source: &DocSource, changed: &mut bool)
    where
        I: IntoIterator<Item = Microdesc>,
    {
        #[cfg(feature = "dirfilter")]
        let mds: Vec<Microdesc> = mds
            .into_iter()
            .filter_map(|m| self.filter.filter_md(m).ok())
            .collect();
        let is_partial = matches!(self.partial, PendingNetDir::Partial(..));
        for md in mds {
            if is_partial {
                self.newly_listed.push(*md.digest());
            }
            self.partial.add_microdesc(md);
            *changed = true;
        }
        self.partial.upgrade_if_necessary();
    }
}

impl<R: Runtime> DirState for GetMicrodescsState<R> {
    fn describe(&self) -> String {
        format!(
            "Downloading microdescriptors (we are missing {}).",
            self.partial.n_missing()
        )
    }
    fn missing_docs(&self) -> Vec<DocId> {
        self.partial
            .missing_microdescs()
            .map(|d| DocId::Microdesc(*d))
            .collect()
    }
    fn get_netdir_change(&mut self) -> Option<NetDirChange<'_>> {
        match self.partial {
            PendingNetDir::Yielding {
                ref mut netdir,
                ref mut collected_microdescs,
                ..
            } => {
                if netdir.is_some() {
                    Some(NetDirChange::AttemptReplace {
                        netdir,
                        consensus_meta: &self.meta,
                    })
                } else {
                    collected_microdescs
                        .is_empty()
                        .then_some(NetDirChange::AddMicrodescs(collected_microdescs))
                }
            }
            _ => None,
        }
    }
    fn is_ready(&self, ready: Readiness) -> bool {
        match ready {
            Readiness::Complete => self.partial.n_missing() == 0,
            Readiness::Usable => {
                // We're "usable" if the calling code thought our netdir was usable enough to
                // steal it.
                matches!(self.partial, PendingNetDir::Yielding { ref netdir, .. } if netdir.is_none())
            }
        }
    }
    fn can_advance(&self) -> bool {
        false
    }
    fn bootstrap_progress(&self) -> DirProgress {
        let n_present = self.n_microdescs - self.partial.n_missing();
        DirProgress::Validated {
            lifetime: self.meta.lifetime().clone(),
            usable_lifetime: self.config.tolerance.extend_lifetime(self.meta.lifetime()),
            n_mds: (n_present as u32, self.n_microdescs as u32),
            usable: self.is_ready(Readiness::Usable),
        }
    }
    fn dl_config(&self) -> DownloadSchedule {
        self.config.schedule.retry_microdescs()
    }
    fn add_from_cache(
        &mut self,
        docs: HashMap<DocId, DocumentText>,
        changed: &mut bool,
    ) -> Result<()> {
        let mut microdescs = Vec::new();
        for (id, text) in docs {
            if let DocId::Microdesc(digest) = id {
                if let Ok(md) = Microdesc::parse(text.as_str().map_err(Error::BadUtf8InCache)?) {
                    if md.digest() == &digest {
                        microdescs.push(md);
                        continue;
                    }
                }
                warn!("Found a mismatched microdescriptor in cache; ignoring");
            }
        }

        self.register_microdescs(microdescs, &DocSource::LocalCache, changed);
        Ok(())
    }

    fn add_from_download(
        &mut self,
        text: &str,
        request: &ClientRequest,
        source: DocSource,
        storage: Option<&Mutex<DynStore>>,
        changed: &mut bool,
    ) -> Result<()> {
        let requested: HashSet<_> = if let ClientRequest::Microdescs(req) = request {
            req.digests().collect()
        } else {
            return Err(internal!("expected a microdesc request").into());
        };
        let mut new_mds = Vec::new();
        let mut nonfatal_err = None;

        for anno in MicrodescReader::new(text, &AllowAnnotations::AnnotationsNotAllowed)
            .map_err(|e| Error::from_netdoc(source.clone(), e))?
        {
            let anno = match anno {
                Err(e) => {
                    nonfatal_err.get_or_insert_with(|| Error::from_netdoc(source.clone(), e));
                    continue;
                }
                Ok(a) => a,
            };
            let txt = anno
                .within(text)
                .expect("microdesc not from within text as expected");
            let md = anno.into_microdesc();
            if !requested.contains(md.digest()) {
                warn!(
                    "Received microdescriptor from {} we did not ask for: {:?}",
                    source,
                    md.digest()
                );
                nonfatal_err.get_or_insert(Error::Unwanted("un-requested microdescriptor"));
                continue;
            }
            new_mds.push((txt, md));
        }

        let mark_listed = self.meta.lifetime().valid_after();
        if let Some(store) = storage {
            let mut s = store
                .lock()
                //.get_mut()
                .expect("Directory storage lock poisoned");
            if !self.newly_listed.is_empty() {
                s.update_microdescs_listed(&self.newly_listed, mark_listed)?;
                self.newly_listed.clear();
            }
            if !new_mds.is_empty() {
                s.store_microdescs(
                    &new_mds
                        .iter()
                        .map(|(text, md)| (*text, md.digest()))
                        .collect::<Vec<_>>(),
                    mark_listed,
                )?;
            }
        }

        self.register_microdescs(new_mds.into_iter().map(|(_, md)| md), &source, changed);

        opt_err_to_result(nonfatal_err)
    }
    fn advance(self: Box<Self>) -> Box<dyn DirState> {
        self
    }
    fn reset_time(&self) -> Option<SystemTime> {
        // TODO(nickm): The reset logic is a little wonky here: we don't truly
        // want to _reset_ this state at `replace_dir_time`.  In fact, we ought
        // to be able to have multiple states running in parallel: one filling
        // in the mds for an old consensus, and one trying to fetch a better
        // one.  That's likely to require some amount of refactoring of the
        // bootstrap code.

        Some(match self.partial {
            // If the client has taken a completed netdir, the netdir is now
            // usable: We can reset our download attempt when we choose to try
            // to replace this directory.
            PendingNetDir::Yielding {
                replace_dir_time,
                netdir: None,
                ..
            } => replace_dir_time,
            // We don't have a completed netdir: Keep trying to fill this one in
            // until it is _definitely_ unusable.  (Our clock might be skewed;
            // there might be no up-to-date consensus.)
            _ => self.reset_time,
        })
    }
    fn reset(self: Box<Self>) -> Box<dyn DirState> {
        let cache_usage = if self.cache_usage == CacheUsage::CacheOnly {
            // Cache only means we can't ever download.
            CacheUsage::CacheOnly
        } else if self.is_ready(Readiness::Usable) {
            // If we managed to bootstrap a usable consensus, then we won't
            // accept our next consensus from the cache.
            CacheUsage::MustDownload
        } else {
            // If we didn't manage to bootstrap a usable consensus, then we can
            // indeed try again with the one in the cache.
            // TODO(nickm) is this right?
            CacheUsage::CacheOkay
        };
        Box::new(GetConsensusState::new(
            self.rt,
            self.config,
            cache_usage,
            self.prev_netdir,
            #[cfg(feature = "dirfilter")]
            self.filter,
        ))
    }
}
